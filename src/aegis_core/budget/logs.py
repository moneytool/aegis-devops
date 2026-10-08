"""Reading model usage from each agent's own session logs (design v1.0, §4).

No hook payload carries token usage, so usage comes from the logs the agents
already write. One reader per agent, each recognising its format by
structure; anything it does not recognise is reported as a *problem* (an
"unknown log", handled by ``on_unknown_log``), never guessed at.

Reads are incremental. A session's log is one or more **sources** (the main
log, and a linked sub-agent's logs), each with a cursor the caller keeps:
for a JSONL file the byte offset of the last complete line plus the file's
identity (device, inode, and a hash of its first bytes). A file that was
replaced or truncated comes back with ``reset=True`` and is read again from
the start.

Usage categories (see :mod:`aegis_core.budget.pricing`): ``input`` is
uncached input, ``output`` includes reasoning, ``cache_read`` and
``cache_write``; Copilot CLI reports premium ``requests`` instead.

Field names below were read from the logs of Claude Code 2.1.281, Codex CLI
0.160.1, Gemini CLI (session JSONL, 2026-09), OpenCode (SQLite) and Copilot
CLI 1.0.89 on 2026-10-07; ``tests/fixtures/budget/`` holds redacted samples.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

HEAD_BYTES = 4096
_CLAUDE_SEEN_MAX = 512


class LogMissing(Exception):
    """The session's log cannot be found or read."""


@dataclass(frozen=True)
class Locator:
    """Where one session's log is: an agent, its session id and a path (the
    log file, or OpenCode's database)."""

    agent: str
    session_id: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return {"agent": self.agent, "session_id": self.session_id, "path": self.path}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Locator:
        return cls(str(d["agent"]), str(d["session_id"]), str(d["path"]))


@dataclass(frozen=True)
class SessionInfo:
    """What the log records about the session itself: the working directory
    it started in, its start time, and its parent session if it is a linked
    sub-agent."""

    cwd: str | None
    start: datetime | None
    parent: str | None = None


@dataclass
class Event:
    """Usage of one model request (or, with ``key``, the current usage of a
    record the agent may still rewrite: a later event with the same key
    replaces the earlier one)."""

    ts: datetime | None
    model: str
    usage: dict[str, float]
    provider: str | None = None
    key: str | None = None


@dataclass
class SourceRead:
    source: str
    cursor: dict[str, Any]
    events: list[Event] = field(default_factory=list)
    reset: bool = False
    problems: list[str] = field(default_factory=list)


def parse_ts(value: Any) -> datetime | None:
    """ISO-8601 strings and epoch milliseconds -> aware UTC datetimes."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _ts_str(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat() if dt else None


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _head_hash(path: Path, length: int) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(length)).hexdigest()


def tail_jsonl(path: Path, cursor: dict[str, Any] | None
               ) -> tuple[list[Any], list[str], dict[str, Any], bool]:
    """New complete lines of a JSONL file since ``cursor``.

    Returns ``(records, problems, new_cursor, reset)``. A half-written last
    line is left for the next read. ``reset`` means the file is not the one
    the cursor described (another inode, a different head, or shorter than
    the offset), so it was read from the start; the caller discards what it
    counted from it before. Raises :class:`LogMissing` if it cannot be read.
    """
    try:
        st = os.stat(path)
    except OSError as e:
        raise LogMissing(f"{path}: {e.strerror or e}") from None
    reset = False
    offset = 0
    if cursor:
        same = (cursor.get("dev"), cursor.get("ino")) == (st.st_dev, st.st_ino)
        if (not same or st.st_size < cursor.get("offset", 0)
                or _head_hash(path, cursor.get("head_len", 0)) != cursor.get("head")):
            reset = True
        else:
            offset = cursor.get("offset", 0)
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError as e:
        raise LogMissing(f"{path}: {e.strerror or e}") from None
    end = data.rfind(b"\n")
    complete = data[: end + 1] if end >= 0 else b""
    new_offset = offset + len(complete)
    records: list[Any] = []
    problems: list[str] = []
    for n, line in enumerate(complete.splitlines()):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except (json.JSONDecodeError, UnicodeDecodeError):
            problems.append(f"{path}: unreadable line at byte {offset}+{n}")
    head_len = min(HEAD_BYTES, new_offset)
    base = {} if reset or not cursor else dict(cursor)
    base.update({"dev": st.st_dev, "ino": st.st_ino, "offset": new_offset,
                 "head_len": head_len, "head": _head_hash(path, head_len)})
    return records, problems, base, reset


def _first_json_line(path: Path) -> Any:
    try:
        with open(path, "rb") as f:
            line = f.readline()
        return json.loads(line) if line.strip() else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _modified_since(paths: Iterator[Path], since: float) -> Iterator[Path]:
    for p in paths:
        try:
            if p.is_file() and p.stat().st_mtime >= since:
                yield p
        except OSError:
            continue


class AgentLog:
    """One agent's log reader. ``base`` is the agent's data directory
    (``~/.claude``, ``~/.codex``, ...), injectable for tests."""

    agent = ""

    def __init__(self, base: str | Path):
        self.base = Path(base)

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        raise NotImplementedError

    def info(self, loc: Locator) -> SessionInfo | None:
        raise NotImplementedError

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        """One :class:`SourceRead` per source of the session (its main log
        and linked sub-agents). Raises :class:`LogMissing` if the main log
        is gone."""
        raise NotImplementedError

    def discover(self, since: float) -> list[Locator]:
        """Top-level sessions (not linked sub-agents) whose logs changed at
        or after ``since`` (epoch seconds)."""
        raise NotImplementedError

    # -- shared JSONL source reading ----------------------------------------

    def _read_jsonl_source(self, source: str, path: Path, cursor: dict[str, Any] | None,
                           handle) -> SourceRead:
        records, problems, cur, reset = tail_jsonl(path, cursor)
        if reset:
            cur = {k: cur[k] for k in ("dev", "ino", "offset", "head_len", "head")}
        out = SourceRead(source, cur, reset=reset, problems=problems)
        last_ts = parse_ts(cur.get("last_ts"))
        for rec in records:
            if not isinstance(rec, dict):
                out.problems.append(f"{path}: a record is not a JSON object")
                continue
            first_new = len(out.events)
            ts = handle(rec, cur, out)
            if ts is not None:
                last_ts = ts
            for ev in out.events[first_new:]:
                if ev.ts is None:
                    ev.ts = last_ts  # the nearest earlier timestamp in this source
        cur["last_ts"] = _ts_str(last_ts)
        return out


# --- Claude Code ------------------------------------------------------------------


class ClaudeLog(AgentLog):
    """``~/.claude/projects/<slug>/<session>.jsonl``; sub-agents (linked) in
    ``<slug>/<session>/subagents/agent-*.jsonl``. Each response's usage is
    repeated on every content block of the message, so a request is counted
    once per ``(message.id, requestId)``."""

    agent = "claude"

    def _projects(self) -> Path:
        return self.base / "projects"

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        if transcript_path and Path(transcript_path).is_file():
            return Locator(self.agent, session_id, str(transcript_path))
        for p in self._projects().glob(f"*/{session_id}.jsonl"):
            return Locator(self.agent, session_id, str(p))
        return None

    def info(self, loc: Locator) -> SessionInfo | None:
        start = None
        try:
            with open(loc.path, "rb") as f:
                for n, line in enumerate(f):
                    if n > 200:
                        break
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    start = start or parse_ts(rec.get("timestamp"))
                    if isinstance(rec.get("cwd"), str):
                        return SessionInfo(rec["cwd"], parse_ts(rec.get("timestamp")) or start)
        except OSError:
            return None
        return SessionInfo(None, start)

    def _handle(self, rec: dict[str, Any], cur: dict[str, Any], out: SourceRead):
        ts = parse_ts(rec.get("timestamp"))
        if rec.get("type") != "assistant":
            return ts
        msg = rec.get("message")
        usage = msg.get("usage") if isinstance(msg, dict) else None
        if not isinstance(usage, dict):
            out.problems.append("claude: an assistant record without message.usage")
            return ts
        model = msg.get("model")
        if not isinstance(model, str) or model == "<synthetic>":
            return ts
        key = f"{msg.get('id')}:{rec.get('requestId')}"
        seen = cur.setdefault("seen", [])
        if key in seen:
            return ts
        seen.append(key)
        del seen[:-_CLAUDE_SEEN_MAX]
        counts = {"input": _int(usage.get("input_tokens")),
                  "output": _int(usage.get("output_tokens")),
                  "cache_read": _int(usage.get("cache_read_input_tokens")),
                  "cache_write": _int(usage.get("cache_creation_input_tokens"))}
        if any(counts.values()):
            out.events.append(Event(ts, model, counts, "anthropic"))
        return ts

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        main = Path(loc.path)
        reads = [self._read_jsonl_source("main", main, cursors.get("main"), self._handle)]
        subdir = main.with_suffix("") / "subagents"
        if subdir.is_dir():
            for p in sorted(subdir.glob("agent-*.jsonl")):
                name = f"sub:{p.name}"
                try:
                    reads.append(self._read_jsonl_source(name, p, cursors.get(name),
                                                         self._handle))
                except LogMissing:
                    continue
        return reads

    def discover(self, since: float) -> list[Locator]:
        return [Locator(self.agent, p.stem, str(p))
                for p in _modified_since(self._projects().glob("*/*.jsonl"), since)]


# --- Codex CLI --------------------------------------------------------------------


def _codex_meta(path: Path) -> dict[str, Any] | None:
    first = _first_json_line(path)
    if isinstance(first, dict) and first.get("type") == "session_meta":
        payload = first.get("payload")
        return payload if isinstance(payload, dict) else None
    return None


class CodexLog(AgentLog):
    """``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``. ``token_count``
    events carry running totals; usage is the difference between successive
    totals. The model is the latest ``turn_context`` model. A sub-agent has
    its own rollout file whose ``session_meta`` names the parent
    (``thread_source: subagent``, ``parent_thread_id``)."""

    agent = "codex"

    def _sessions(self) -> Path:
        return self.base / "sessions"

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        if transcript_path and Path(transcript_path).is_file():
            return Locator(self.agent, session_id, str(transcript_path))
        for p in self._sessions().glob(f"*/*/*/rollout-*-{session_id}.jsonl"):
            return Locator(self.agent, session_id, str(p))
        return None

    def info(self, loc: Locator) -> SessionInfo | None:
        meta = _codex_meta(Path(loc.path))
        if meta is None:
            return None
        parent = meta.get("parent_thread_id") if meta.get("thread_source") == "subagent" else None
        cwd = meta.get("cwd") if isinstance(meta.get("cwd"), str) else None
        return SessionInfo(cwd, parse_ts(meta.get("timestamp")), parent)

    def _handle(self, rec: dict[str, Any], cur: dict[str, Any], out: SourceRead):
        ts = parse_ts(rec.get("timestamp"))
        kind = rec.get("type")
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            return ts
        if kind == "session_meta" and isinstance(payload.get("model_provider"), str):
            cur["provider"] = payload["model_provider"]
        elif kind == "turn_context" and isinstance(payload.get("model"), str):
            cur["model"] = payload["model"]
        elif kind == "event_msg" and payload.get("type") == "token_count":
            info = payload.get("info")
            if info is None:
                return ts  # rate-limit only update
            total = info.get("total_token_usage") if isinstance(info, dict) else None
            if not isinstance(total, dict):
                out.problems.append("codex: a token_count event without total_token_usage")
                return ts
            cached = _int(total.get("cached_input_tokens"))
            now = {"input": max(0, _int(total.get("input_tokens")) - cached),
                   "output": _int(total.get("output_tokens")),
                   "cache_read": cached,
                   "cache_write": _int(total.get("cache_write_input_tokens"))}
            before = cur.get("totals") or {}
            delta = {c: max(0, now[c] - before.get(c, 0)) for c in now}
            cur["totals"] = now
            if any(delta.values()):
                out.events.append(Event(ts, cur.get("model") or "unknown",
                                        delta, cur.get("provider") or "openai"))
        return ts

    def _children(self, loc: Locator, main_cursor: dict[str, Any]) -> dict[str, str]:
        """Rollout files whose session_meta links them to this session, as
        ``{file name: path}`` with ``""`` for files that are not children.
        Classifications are kept in the main cursor, so each file's first
        line is read once."""
        main = Path(loc.path)
        known: dict[str, str] = dict(main_cursor.get("children") or {})
        start = parse_ts((_codex_meta(main) or {}).get("timestamp"))
        floor = (start - timedelta(days=1)).date() if start else date.min
        for day_dir in self._sessions().glob("*/*/*"):
            try:
                d = date(int(day_dir.parts[-3]), int(day_dir.parts[-2]), int(day_dir.parts[-1]))
            except (ValueError, IndexError):
                continue
            if d < floor:
                continue
            for p in day_dir.glob("rollout-*.jsonl"):
                if p == main or p.name in known:
                    continue
                meta = _codex_meta(p) or {}
                linked = (meta.get("thread_source") == "subagent"
                          and loc.session_id in (meta.get("parent_thread_id"),
                                                 meta.get("session_id")))
                known[p.name] = str(p) if linked else ""
        return known

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        main = self._read_jsonl_source("main", Path(loc.path), cursors.get("main"), self._handle)
        children = self._children(loc, cursors.get("main") or {})
        main.cursor["children"] = children
        reads = [main]
        for name, path in sorted(children.items()):
            if not path:
                continue
            source = f"child:{name}"
            try:
                reads.append(self._read_jsonl_source(source, Path(path), cursors.get(source),
                                                     self._handle))
            except LogMissing:
                continue
        return reads

    def discover(self, since: float) -> list[Locator]:
        out = []
        for p in _modified_since(self._sessions().glob("*/*/*/rollout-*.jsonl"), since):
            meta = _codex_meta(p)
            if not meta or meta.get("thread_source") == "subagent":
                continue
            sid = meta.get("id") or meta.get("session_id")
            if isinstance(sid, str):
                out.append(Locator(self.agent, sid, str(p)))
        return out


# --- Gemini CLI -------------------------------------------------------------------


class GeminiLog(AgentLog):
    """``~/.gemini/tmp/<project>/chats/session-*.jsonl``; the project's
    directory is in ``<project>/.project_root``. Messages are written more
    than once as they update, so each is keyed by its id."""

    agent = "gemini"

    def _chats(self) -> Iterator[Path]:
        return (self.base / "tmp").glob("*/chats/session-*.jsonl")

    @staticmethod
    def _header(path: Path) -> dict[str, Any] | None:
        first = _first_json_line(path)
        return first if isinstance(first, dict) and "sessionId" in first else None

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        if transcript_path and Path(transcript_path).is_file():
            return Locator(self.agent, session_id, str(transcript_path))
        for p in self._chats():
            if session_id[:8] in p.name and (self._header(p) or {}).get("sessionId") == session_id:
                return Locator(self.agent, session_id, str(p))
        return None

    def info(self, loc: Locator) -> SessionInfo | None:
        path = Path(loc.path)
        header = self._header(path) or {}
        try:
            cwd = (path.parent.parent / ".project_root").read_text().strip() or None
        except OSError:
            cwd = None
        return SessionInfo(cwd, parse_ts(header.get("startTime")))

    def _message(self, m: Any, out: SourceRead) -> None:
        if not isinstance(m, dict) or m.get("type") != "gemini" or "tokens" not in m:
            return
        t = m["tokens"]
        if not isinstance(t, dict):
            out.problems.append("gemini: a message whose tokens is not a mapping")
            return
        cached = _int(t.get("cached"))
        counts = {"input": max(0, _int(t.get("input")) - cached) + _int(t.get("tool")),
                  "output": _int(t.get("output")) + _int(t.get("thoughts")),
                  "cache_read": cached, "cache_write": 0}
        model = m.get("model") if isinstance(m.get("model"), str) else "unknown"
        out.events.append(Event(parse_ts(m.get("timestamp")), model, counts, "google",
                                key=str(m.get("id"))))

    def _handle(self, rec: dict[str, Any], cur: dict[str, Any], out: SourceRead):
        if rec.get("type") == "gemini":
            self._message(rec, out)
        elif isinstance(rec.get("$set"), dict):
            for m in rec["$set"].get("messages") or []:
                self._message(m, out)
        return parse_ts(rec.get("timestamp") or rec.get("startTime"))

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        return [self._read_jsonl_source("main", Path(loc.path), cursors.get("main"),
                                        self._handle)]

    def discover(self, since: float) -> list[Locator]:
        out = []
        for p in _modified_since(self._chats(), since):
            sid = (self._header(p) or {}).get("sessionId")
            if isinstance(sid, str):
                out.append(Locator(self.agent, sid, str(p)))
        return out


# --- OpenCode ---------------------------------------------------------------------


class OpenCodeLog(AgentLog):
    """``opencode.db`` (SQLite, opened read-only; only the ``session`` and
    ``message`` tables are read). Message rows are updated in place as a
    response completes, so each is keyed by its id; sub-agents are child
    sessions (``session.parent_id``)."""

    agent = "opencode"

    def _db(self) -> Path:
        return self.base / "opencode.db"

    def _connect(self, path: str) -> sqlite3.Connection:
        if not Path(path).is_file():
            raise LogMissing(f"{path}: no such file")
        try:
            return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
        except sqlite3.Error as e:
            raise LogMissing(f"{path}: {e}") from None

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        try:
            with self._connect(str(self._db())) as db:
                row = db.execute("SELECT id FROM session WHERE id = ?", (session_id,)).fetchone()
        except (LogMissing, sqlite3.Error):
            return None
        return Locator(self.agent, session_id, str(self._db())) if row else None

    def info(self, loc: Locator) -> SessionInfo | None:
        try:
            with self._connect(loc.path) as db:
                row = db.execute("SELECT directory, time_created, parent_id FROM session "
                                 "WHERE id = ?", (loc.session_id,)).fetchone()
        except (LogMissing, sqlite3.Error):
            return None
        if not row:
            return None
        return SessionInfo(row[0], parse_ts(row[1]), row[2])

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        cur = dict(cursors.get("db") or {})
        out = SourceRead("db", cur)
        try:
            with self._connect(loc.path) as db:
                if not db.execute("SELECT 1 FROM session WHERE id = ?",
                                  (loc.session_id,)).fetchone():
                    raise LogMissing(f"{loc.path}: session {loc.session_id} not found")
                rows = db.execute(
                    "WITH RECURSIVE tree(id) AS (SELECT ? UNION "
                    "SELECT s.id FROM session s JOIN tree ON s.parent_id = tree.id) "
                    "SELECT m.id, m.time_created, m.time_updated, m.data FROM message m "
                    "WHERE m.session_id IN (SELECT id FROM tree) AND m.time_updated >= ? "
                    "ORDER BY m.time_updated", (loc.session_id, cur.get("since", 0))).fetchall()
        except sqlite3.Error as e:
            raise LogMissing(f"{loc.path}: {e}") from None
        for mid, created, updated, data in rows:
            cur["since"] = max(cur.get("since", 0), updated)
            try:
                m = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                out.problems.append(f"opencode: message {mid} is not JSON")
                continue
            if not isinstance(m, dict) or m.get("role") != "assistant":
                continue
            t = m.get("tokens")
            if t is None:
                continue
            if not isinstance(t, dict):
                out.problems.append(f"opencode: message {mid} has malformed tokens")
                continue
            cache = t.get("cache") if isinstance(t.get("cache"), dict) else {}
            counts = {"input": _int(t.get("input")),
                      "output": _int(t.get("output")) + _int(t.get("reasoning")),
                      "cache_read": _int(cache.get("read")),
                      "cache_write": _int(cache.get("write"))}
            times = m.get("time") if isinstance(m.get("time"), dict) else {}
            ts = parse_ts(times.get("completed") or times.get("created") or created)
            model = m.get("modelID") if isinstance(m.get("modelID"), str) else "unknown"
            provider = m.get("providerID") if isinstance(m.get("providerID"), str) else None
            out.events.append(Event(ts, model, counts, provider, key=str(mid)))
        return [out]

    def discover(self, since: float) -> list[Locator]:
        try:
            with self._connect(str(self._db())) as db:
                rows = db.execute("SELECT id FROM session WHERE parent_id IS NULL AND "
                                  "time_updated >= ?", (int(since * 1000),)).fetchall()
        except (LogMissing, sqlite3.Error):
            return []
        return [Locator(self.agent, r[0], str(self._db())) for r in rows]


# --- Copilot CLI ------------------------------------------------------------------


class CopilotLog(AgentLog):
    """``~/.copilot/session-state/<session>/events.jsonl``. Copilot CLI
    writes token counts only at shutdown, but running totals of premium
    requests in ``session.usage_checkpoint`` (and ``session.shutdown``), so
    it is measured in premium requests."""

    agent = "copilot"
    MODEL = "copilot-premium-requests"

    def _state(self) -> Path:
        return self.base / "session-state"

    def locate(self, session_id: str, transcript_path: str | None = None) -> Locator | None:
        p = self._state() / session_id / "events.jsonl"
        return Locator(self.agent, session_id, str(p)) if p.is_file() else None

    def info(self, loc: Locator) -> SessionInfo | None:
        first = _first_json_line(Path(loc.path))
        if not isinstance(first, dict) or first.get("type") != "session.start":
            return None
        data = first.get("data") if isinstance(first.get("data"), dict) else {}
        ctx = data.get("context") if isinstance(data.get("context"), dict) else {}
        cwd = ctx.get("cwd") if isinstance(ctx.get("cwd"), str) else None
        return SessionInfo(cwd, parse_ts(data.get("startTime") or first.get("timestamp")))

    def _handle(self, rec: dict[str, Any], cur: dict[str, Any], out: SourceRead):
        ts = parse_ts(rec.get("timestamp"))
        if rec.get("type") in ("session.usage_checkpoint", "session.shutdown"):
            data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
            total = data.get("totalPremiumRequests")
            if isinstance(total, bool) or not isinstance(total, (int, float)):
                out.problems.append(f"copilot: {rec.get('type')} without totalPremiumRequests")
                return ts
            delta = max(0.0, float(total) - float(cur.get("premium", 0.0)))
            cur["premium"] = max(float(total), float(cur.get("premium", 0.0)))
            if delta:
                out.events.append(Event(ts, self.MODEL, {"requests": delta}, "github"))
        return ts

    def read(self, loc: Locator, cursors: dict[str, dict[str, Any]]) -> list[SourceRead]:
        return [self._read_jsonl_source("main", Path(loc.path), cursors.get("main"),
                                        self._handle)]

    def discover(self, since: float) -> list[Locator]:
        return [Locator(self.agent, p.parent.name, str(p))
                for p in _modified_since(self._state().glob("*/events.jsonl"), since)]


def default_logs(env: dict[str, str] | None = None) -> dict[str, AgentLog]:
    """The readers for this machine, honouring each agent's own location
    overrides (``CLAUDE_CONFIG_DIR``, ``CODEX_HOME``, ``XDG_DATA_HOME``)."""
    env = dict(os.environ if env is None else env)
    home = Path(env.get("HOME") or Path.home())
    data_home = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    return {
        "claude": ClaudeLog(env.get("CLAUDE_CONFIG_DIR") or home / ".claude"),
        "codex": CodexLog(env.get("CODEX_HOME") or home / ".codex"),
        "gemini": GeminiLog(home / ".gemini"),
        "opencode": OpenCodeLog(data_home / "opencode"),
        "copilot": CopilotLog(home / ".copilot"),
    }
