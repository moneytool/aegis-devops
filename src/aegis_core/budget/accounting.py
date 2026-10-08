"""Session and project/day usage accounting (design v1.0, §4.1).

The agents' logs are the source of truth; everything under the cache
directory is derived from them and can be rebuilt. Three rules make
updates idempotent:

* a session's usage is only ever **replaced** in the project map, never
  added to a running total;
* a replacement only wins if its **revision** is newer, and revisions come
  from a durable per-session counter outside the cache;
* a project/day total is always a **sum computed** from per-session entries.

Locks are always taken in the order session -> project, and nothing takes a
session lock while holding a project lock, so hooks and rebuilds cannot
deadlock.

Layout::

    $XDG_CACHE_HOME/aegis/budget/            (default ~/.cache; disposable)
      sessions/<agent>/<session>.json         session record
      projects/<sha256(root)>/<day>.json      project contributions for a day
    $XDG_STATE_HOME/aegis/budget/            (default ~/.local/state; durable)
      sessions/<agent>/<session>.rev, .lock   revision counter and lock
      <sha256(root)>/<day>.jsonl              session inventory for a day
      <sha256(root)>/project.json, .lock      days with an inventory; project lock
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from aegis_core.budget.logs import AgentLog, Event, Locator, LogMissing, SourceRead, parse_ts

UNKNOWN_DAY = "unknown"
CHECKPOINT_EVERY = 60.0  # seconds
_MAX_PROBLEMS = 20
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

Usage = dict[str, float]           # category -> amount
ByModel = dict[str, Usage]         # model -> usage
Buckets = dict[str, ByModel]       # day -> model -> usage


# --- small helpers -------------------------------------------------------------------


def add_usage(into: ByModel, model: str, usage: Mapping[str, float], sign: int = 1) -> None:
    slot = into.setdefault(model, {})
    for cat, n in usage.items():
        slot[cat] = slot.get(cat, 0) + sign * n
        if abs(slot[cat]) < 1e-9:
            slot[cat] = 0
    if not any(slot.values()):
        del into[model]


def sum_by_model(*parts: Mapping[str, Mapping[str, float]]) -> ByModel:
    out: ByModel = {}
    for part in parts:
        for model, usage in part.items():
            add_usage(out, model, usage)
    return out


def find_project_root(cwd: str | None) -> str | None:
    """The nearest directory at or above ``cwd`` holding ``.aegis/`` (the
    lookup the hook uses for policy); ``None`` if there is none."""
    if not cwd:
        return None
    start = Path(cwd)
    for directory in (start, *start.parents):
        if (directory / ".aegis").is_dir():
            return str(directory.resolve())
    return None


def project_key(root: str) -> str:
    return hashlib.sha256(root.encode()).hexdigest()


def day_of(ts: datetime | None, zone: ZoneInfo) -> str:
    return ts.astimezone(zone).date().isoformat() if ts else UNKNOWN_DAY


def day_start(day: str, zone: ZoneInfo) -> float:
    d = datetime.fromisoformat(day).replace(tzinfo=zone)
    return d.timestamp()


def _safe_name(session_id: str) -> str:
    if _SAFE_ID.fullmatch(session_id):
        return session_id
    return "h-" + hashlib.sha256(session_id.encode()).hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


@contextlib.contextmanager
def _flock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --- records ---------------------------------------------------------------------------


@dataclass
class SessionRecord:
    """The cached, derived state of one session (the record), plus the
    revision it was written at."""

    agent: str
    session_id: str
    locator: dict[str, str]
    tz: str
    revision: int = 0
    project_root: str | None = None
    start: str | None = None
    parent: str | None = None
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    providers: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    problem_total: int = 0
    log_missing: bool = False
    inventory_days: list[str] = field(default_factory=list)
    checkpoint_at: float = 0.0

    @property
    def key(self) -> str:
        return f"{self.agent}/{self.session_id}"

    def buckets(self) -> Buckets:
        """day -> model -> usage, summed over the session's sources."""
        out: Buckets = {}
        for src in self.sources.values():
            for day, by_model in src.get("buckets", {}).items():
                target = out.setdefault(day, {})
                for model, usage in by_model.items():
                    add_usage(target, model, usage)
        return out

    def usage_on(self, day: str) -> ByModel:
        return self.buckets().get(day, {})

    def usage_total(self) -> ByModel:
        return sum_by_model(*self.buckets().values())

    def unverified(self) -> list[str]:
        """Why this session's usage is only a lower bound (empty if it is not)."""
        reasons = []
        if self.log_missing:
            reasons.append("log-missing")
        if self.problem_total:
            reasons.append("unreadable-records")
        if self.buckets().get(UNKNOWN_DAY):
            reasons.append("unknown-time")
        return reasons

    def to_json(self) -> str:
        return json.dumps({"version": 1, **self.__dict__}, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SessionRecord:
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**d)


@dataclass
class ProjectDay:
    """One project's contributions for one day."""

    root: str
    day: str
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    completeness: str = "complete"   # complete | partial | unknown
    missing_sessions: int = 0
    known_sessions: int = 0
    history: str = "ok"              # the inventory read at the last rebuild: see read_inventory

    def usage(self) -> ByModel:
        return sum_by_model(*(e.get("usage", {}) for e in self.entries.values()))

    def providers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for e in self.entries.values():
            out.update(e.get("providers", {}))
        return out

    def unverified(self, exclude: str | None = None) -> dict[str, list[str]]:
        """Contributing sessions whose usage is only a lower bound, with why
        (each entry carries its session's verification status)."""
        return {k: list(e["unverified"]) for k, e in self.entries.items()
                if e.get("unverified") and k != exclude}

    def to_json(self) -> str:
        return json.dumps({"version": 1, **self.__dict__}, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProjectDay:
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**d)


@dataclass
class Snapshot:
    """What a hook evaluates: the session's usage over its lifetime and the
    project's usage today, with how much of either is unverifiable."""

    record: SessionRecord
    day: str
    project: ProjectDay | None
    session_usage: ByModel
    project_usage: ByModel
    providers: dict[str, str]


# --- the store -------------------------------------------------------------------------


class BudgetStore:
    """The cache and state directories, and the locks and files in them."""

    def __init__(self, cache_dir: str | Path | None = None, state_dir: str | Path | None = None,
                 env: Mapping[str, str] | None = None):
        env = os.environ if env is None else env
        home = Path(env.get("HOME") or Path.home())
        self.cache = Path(cache_dir) if cache_dir else Path(
            env.get("XDG_CACHE_HOME") or home / ".cache") / "aegis" / "budget"
        self.state = Path(state_dir) if state_dir else Path(
            env.get("XDG_STATE_HOME") or home / ".local" / "state") / "aegis" / "budget"

    # paths
    def record_path(self, agent: str, sid: str) -> Path:
        return self.cache / "sessions" / agent / f"{_safe_name(sid)}.json"

    def rev_path(self, agent: str, sid: str) -> Path:
        return self.state / "sessions" / agent / f"{_safe_name(sid)}.rev"

    def session_lock(self, agent: str, sid: str):
        return _flock(self.state / "sessions" / agent / f"{_safe_name(sid)}.lock")

    def project_dir(self, root: str) -> Path:
        return self.state / project_key(root)

    def project_lock(self, root: str):
        return _flock(self.project_dir(root) / "project.lock")

    def day_path(self, root: str, day: str) -> Path:
        return self.cache / "projects" / project_key(root) / f"{day}.json"

    def inventory_path(self, root: str, day: str) -> Path:
        return self.project_dir(root) / f"{day}.jsonl"

    def index_path(self, root: str) -> Path:
        return self.project_dir(root) / "project.json"

    # session records
    def load_record(self, agent: str, sid: str) -> SessionRecord | None:
        d = _read_json(self.record_path(agent, sid))
        if not isinstance(d, dict):
            return None
        try:
            return SessionRecord.from_dict(d)
        except TypeError:
            return None

    def save_record(self, rec: SessionRecord) -> None:
        _atomic_write(self.record_path(rec.agent, rec.session_id), rec.to_json())

    # the durable revision counter (caller holds the session lock)
    def read_revision(self, agent: str, sid: str) -> int | None:
        try:
            return int(self.rev_path(agent, sid).read_text().strip())
        except (OSError, ValueError):
            return None

    def write_revision(self, agent: str, sid: str, rev: int) -> None:
        _atomic_write(self.rev_path(agent, sid), f"{rev}\n")

    def recover_revision(self, agent: str, sid: str, root: str | None,
                         rec: SessionRecord | None) -> int:
        """The counter is missing (the state directory was deleted): one
        more than the highest revision for the session anywhere a merge
        could compare it with -- the cached record, every cached project
        map entry and every inventory checkpoint for its project."""
        key = f"{agent}/{sid}"
        best = rec.revision if rec else 0
        if root:
            for p in (self.cache / "projects" / project_key(root)).glob("*.json"):
                d = _read_json(p)
                if isinstance(d, dict):
                    best = max(best, int((d.get("entries", {}).get(key) or {}).get("revision",
                                                                                     0)))
            for p in self.project_dir(root).glob("*.jsonl"):
                for line in self._inventory_lines(p):
                    if line.get("session") == key:
                        best = max(best, int(line.get("revision", 0)))
        return best + 1

    # project maps (caller holds the project lock to write)
    def load_day(self, root: str, day: str) -> ProjectDay | None:
        d = _read_json(self.day_path(root, day))
        if not isinstance(d, dict):
            return None
        try:
            return ProjectDay.from_dict(d)
        except TypeError:
            return None

    def save_day(self, pd: ProjectDay) -> None:
        _atomic_write(self.day_path(pd.root, pd.day), pd.to_json())

    @staticmethod
    def merge_entries(pd: ProjectDay, incoming: Mapping[str, dict[str, Any]]) -> bool:
        """The merge rule: set an entry only if its revision is newer.
        Entries are merged one by one; a map is never replaced wholesale."""
        changed = False
        for key, entry in incoming.items():
            stored = pd.entries.get(key)
            if stored is None or int(entry["revision"]) > int(stored.get("revision", 0)):
                pd.entries[key] = entry
                changed = True
        return changed

    # the inventory (caller holds the project lock to write)
    @staticmethod
    def read_inventory(path: Path) -> tuple[list[dict[str, Any]], str]:
        """The valid lines of an inventory file and how the read went:
        ``ok``; ``missing`` (no file); ``unreadable`` (it exists but cannot
        be read); ``corrupt`` (some lines are not inventory records,
        including a truncated last line). Valid lines are returned whatever
        the status, so surviving checkpoints are still used."""
        if not path.exists():
            return [], "missing"
        try:
            data = path.read_bytes()
        except OSError:
            return [], "unreadable"
        out: list[dict[str, Any]] = []
        status = "ok"
        if data and not data.endswith(b"\n"):
            status = "corrupt"  # a truncated last line
        for raw in data.splitlines():
            if not raw.strip():
                continue
            try:
                d = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                status = "corrupt"
                continue
            if (isinstance(d, dict) and isinstance(d.get("session"), str)
                    and d.get("event") in ("seen", "checkpoint")):
                out.append(d)
            else:
                status = "corrupt"
        return out, status

    @classmethod
    def _inventory_lines(cls, path: Path) -> list[dict[str, Any]]:
        return cls.read_inventory(path)[0]

    def inventory(self, root: str, day: str) -> tuple[list[dict[str, Any]], str]:
        return self.read_inventory(self.inventory_path(root, day))

    def read_index(self, root: str) -> tuple[dict[str, Any] | None, str]:
        """The project's list of days with an inventory: ``ok``, ``missing``
        or ``corrupt`` (exists but unreadable or not the expected shape)."""
        path = self.index_path(root)
        if not path.exists():
            return None, "missing"
        d = _read_json(path)
        if not isinstance(d, dict) or not isinstance(d.get("days"), list):
            return None, "corrupt"
        return d, "ok"

    def append_inventory(self, root: str, day: str, line: dict[str, Any]) -> bool:
        """Appends one line; returns False if the inventory cannot be written
        (the caller tries again on a later hook; a rebuild then reports the
        damaged history as unknown)."""
        path = self.inventory_path(root, day)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as f:
                f.write(json.dumps(line, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            return False
        index = _read_json(self.index_path(root)) or {}
        days = set(index.get("days", []))
        if day not in days:
            days.add(day)
            with contextlib.suppress(OSError):
                _atomic_write(self.index_path(root),
                              json.dumps({"root": root, "days": sorted(days)}, sort_keys=True))
        return True


# --- reading a session (steps 1-3 of the update protocol) --------------------------------


def _apply(rec: SessionRecord, reads: list[SourceRead], zone: ZoneInfo) -> bool:
    """Folds new events into the record's per-source buckets. Returns
    whether anything changed."""
    start = parse_ts(rec.start)
    changed = False
    for sr in reads:
        src = rec.sources.get(sr.source)
        if src is None or sr.reset:
            src = {"buckets": {}, "keyed": {}}
            rec.sources[sr.source] = src
            changed = True
        if src.get("cursor") != sr.cursor:
            changed = True
        src["cursor"] = sr.cursor
        buckets: Buckets = src.setdefault("buckets", {})
        keyed: dict[str, list[Any]] = src.setdefault("keyed", {})
        for ev in sr.events:
            changed = True
            day = day_of(ev.ts or start, zone)
            if ev.provider:
                rec.providers[ev.model] = ev.provider
            if ev.key is not None:
                old = keyed.get(ev.key)
                if old is not None:
                    add_usage(buckets.setdefault(old[0], {}), old[1], old[2], sign=-1)
                    if not buckets[old[0]]:
                        del buckets[old[0]]
                keyed[ev.key] = [day, ev.model, ev.usage]
            add_usage(buckets.setdefault(day, {}), ev.model, ev.usage)
        if sr.problems:
            changed = True
            rec.problem_total += len(sr.problems)
            rec.problems = (rec.problems + sr.problems)[-_MAX_PROBLEMS:]
    return changed


def update_session(store: BudgetStore, log: AgentLog, loc: Locator, zone: ZoneInfo, *,
                   fallback_cwd: str | None = None) -> SessionRecord:
    """Steps 1-3 for one session. **The caller holds the session's lock.**

    Reads the log from where the record left off, folds the new usage in,
    advances the durable revision counter and writes the record at the new
    revision. A record that would not change is not rewritten (and the
    revision is not advanced)."""
    tz = str(zone.key)
    rec = store.load_record(loc.agent, loc.session_id)
    if rec is None or rec.tz != tz or rec.locator.get("path") != loc.path:
        old_rev = rec.revision if rec else 0
        rec = SessionRecord(loc.agent, loc.session_id, loc.to_dict(), tz, revision=old_rev)
    if rec.start is None and rec.project_root is None:
        info = log.info(loc)
        cwd = (info.cwd if info else None) or fallback_cwd
        rec.project_root = find_project_root(cwd)
        rec.start = info.start.isoformat() if info and info.start else None
        rec.parent = info.parent if info else None

    rev = store.read_revision(loc.agent, loc.session_id)
    if rev is None:
        rev = store.recover_revision(loc.agent, loc.session_id, rec.project_root, rec)
        store.write_revision(loc.agent, loc.session_id, rev)
    rev = max(rev, rec.revision)

    try:
        reads = log.read(loc, {name: s.get("cursor", {}) for name, s in rec.sources.items()})
        missing = False
    except LogMissing as e:
        reads, missing = [], True
        rec.problems = (rec.problems + [str(e)])[-_MAX_PROBLEMS:]
    changed = _apply(rec, reads, zone) or missing != rec.log_missing
    rec.log_missing = missing
    if changed or not store.record_path(loc.agent, loc.session_id).exists():
        rec.revision = rev + 1
        store.write_revision(loc.agent, loc.session_id, rec.revision)  # durable first
        store.save_record(rec)
    return rec


def _entry(rec: SessionRecord, day: str) -> dict[str, Any]:
    usage = rec.usage_on(day)
    return {"revision": rec.revision, "usage": usage,
            "providers": {m: p for m, p in rec.providers.items() if m in usage},
            "unverified": rec.unverified()}


# --- rebuild -------------------------------------------------------------------------


def rebuild(store: BudgetStore, logs: Mapping[str, AgentLog], root: str, day: str,
            zone: ZoneInfo, *, exclude: str | None = None) -> ProjectDay:
    """Rebuilds a project's day from the logs and the inventory.

    1. Without the project lock: the sessions to read are the ones
       ``discover`` finds for the project today plus those in the inventory.
    2. Each session is brought up to date under **its own lock alone**.
    3. Under the project lock, every entry is merged by the merge rule, so a
       newer entry written meanwhile by a hook is kept.
    """
    since = day_start(day, zone)
    candidates: dict[str, Locator] = {}
    for agent, log in logs.items():
        for loc in log.discover(since):
            key = f"{agent}/{loc.session_id}"
            info = log.info(loc)
            if info and info.parent is None and find_project_root(info.cwd) == root:
                candidates[key] = loc
    inventory, history = store.inventory(root, day)
    checkpoints: dict[str, dict[str, Any]] = {}
    in_inventory: set[str] = set()
    for line in inventory:
        key = line.get("session")
        if not isinstance(key, str):
            continue
        in_inventory.add(key)
        if line.get("event") == "seen" and key not in candidates:
            with contextlib.suppress(KeyError, TypeError):
                candidates[key] = Locator.from_dict(line["locator"])
        elif line.get("event") == "checkpoint":
            if int(line.get("revision", 0)) >= int(checkpoints.get(key, {}).get("revision", 0)):
                checkpoints[key] = line

    incoming: dict[str, dict[str, Any]] = {}
    missing = 0
    for key, loc in candidates.items():
        if key == exclude or loc.agent not in logs:
            continue
        with store.session_lock(loc.agent, loc.session_id):
            rec = update_session(store, logs[loc.agent], loc, zone)
        if rec.log_missing:
            missing += 1
        if rec.log_missing and not rec.sources:
            # Neither the log nor a cached record holds this session's usage:
            # the inventory checkpoint is all that is left.
            cp = checkpoints.get(key)
            if cp:
                incoming[key] = {"revision": int(cp.get("revision", 0)),
                                 "usage": cp.get("usage", {}), "providers": {},
                                 "unverified": ["log-missing", "from-checkpoint"]}
            continue
        # A missing log with a cached record keeps its usage as a lower bound;
        # the entry says so (its "unverified" reasons).
        incoming[key] = _entry(rec, day)

    if history in ("unreadable", "corrupt"):
        completeness = "unknown"     # the record of which sessions existed is damaged
    elif history == "ok":
        completeness = "partial" if missing else "complete"
    else:
        index, index_status = store.read_index(root)
        if index_status == "corrupt":
            completeness = "unknown"
        elif index is not None:
            completeness = "unknown" if day in index["days"] else "complete"
        else:
            others = [k for k in candidates if k != exclude]
            completeness = "unknown" if others else "complete"

    with store.project_lock(root):
        pd = store.load_day(root, day) or ProjectDay(root, day)
        store.merge_entries(pd, incoming)
        pd.completeness = completeness
        pd.missing_sessions = missing
        pd.known_sessions = len(in_inventory)
        pd.history = history
        store.save_day(pd)
    return pd


# --- the per-hook refresh ------------------------------------------------------------


def refresh(store: BudgetStore, logs: Mapping[str, AgentLog], loc: Locator, zone: ZoneInfo, *,
            now: float | None = None, fallback_cwd: str | None = None) -> Snapshot:
    """The update protocol for one hook call on session ``loc``.

    A linked sub-agent is accounted inside its parent: if the log names a
    parent session that can be located, the parent is refreshed instead.
    If the project's day file is missing, the day is rebuilt first, holding
    no lock. Then, under the session lock: read the log (steps 1-3); under
    the project lock as well: merge the session's entry and keep the
    inventory (step 4)."""
    now = time.time() if now is None else now
    log = logs[loc.agent]
    info = log.info(loc)
    if info and info.parent:
        parent = log.locate(info.parent)
        if parent is not None:
            loc, info = parent, log.info(parent)
    day = day_of(datetime.fromtimestamp(now, tz=UTC), zone)

    peek = store.load_record(loc.agent, loc.session_id)
    root = peek.project_root if peek else find_project_root(
        (info.cwd if info else None) or fallback_cwd)
    if root and store.load_day(root, day) is None:
        rebuild(store, logs, root, day, zone, exclude=f"{loc.agent}/{loc.session_id}")

    pd: ProjectDay | None = None
    with store.session_lock(loc.agent, loc.session_id):
        rec = update_session(store, log, loc, zone, fallback_cwd=fallback_cwd)
        if rec.project_root:
            with store.project_lock(rec.project_root):
                pd = store.load_day(rec.project_root, day) or ProjectDay(rec.project_root, day)
                if store.merge_entries(pd, {rec.key: _entry(rec, day)}):
                    store.save_day(pd)
                if _keep_inventory(store, rec, day, now):
                    store.save_record(rec)

    session_usage = rec.usage_total()
    project_usage = pd.usage() if pd else {}
    providers = {**(pd.providers() if pd else {}), **rec.providers}
    return Snapshot(rec, day, pd, session_usage, project_usage, providers)


def _keep_inventory(store: BudgetStore, rec: SessionRecord, day: str, now: float) -> bool:
    """Appends the session to the day's inventory the first time it is seen
    that day, and a usage checkpoint at most once a minute. **The caller
    holds the project lock.** Returns whether the record changed."""
    root = rec.project_root
    assert root
    changed = False
    if day not in rec.inventory_days and store.append_inventory(
            root, day, {"event": "seen", "session": rec.key, "locator": rec.locator,
                        "start": rec.start}):
        rec.inventory_days = sorted({*rec.inventory_days, day})[-7:]
        changed = True
    if now - rec.checkpoint_at >= CHECKPOINT_EVERY and store.append_inventory(
            root, day, {"event": "checkpoint", "session": rec.key, "revision": rec.revision,
                        "usage": rec.usage_on(day), "at": now}):
        rec.checkpoint_at = now
        changed = True
    return changed


def event_day(ev: Event, rec: SessionRecord, zone: ZoneInfo) -> str:
    """The day an event belongs to (exposed for tests and status output)."""
    return day_of(ev.ts or parse_ts(rec.start), zone)
