"""Session and project/day accounting (design v1.0 §4.1) and the validation
cases of §10 step 5: crash recovery, cache deletion with a high-revision
project entry, log replacement, a lost revision counter, rebuilds racing
hook updates, linked sub-agents, missing history and midnight rebuilds."""

import json
import os
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from test_budget_logs import CODEX_CHILD, CODEX_PARENT, home  # noqa: F401  (fixture)

from aegis_core.budget.accounting import (
    UNKNOWN_DAY,
    BudgetStore,
    ProjectDay,
    find_project_root,
    rebuild,
    refresh,
    update_session,
)
from aegis_core.budget.logs import ClaudeLog, CodexLog

UTC_ZONE = ZoneInfo("UTC")
DAY = "2026-10-07"
NOW = datetime(2026, 10, 7, 18, 0, tzinfo=UTC).timestamp()
MODEL = "claude-opus-5-5"


class World:
    """A project with ``.aegis/``, a fake ``~/.claude`` and a budget store."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.project = tmp / "project"
        (self.project / ".aegis").mkdir(parents=True)
        self.root = str(self.project.resolve())
        self.claude = ClaudeLog(tmp / "home" / ".claude")
        self.logs = {"claude": self.claude}
        self.store = BudgetStore(cache_dir=tmp / "cache", state_dir=tmp / "state")
        self._n = 0

    def path(self, sid: str) -> Path:
        return self.tmp / "home" / ".claude" / "projects" / "-project" / f"{sid}.jsonl"

    def start(self, sid: str, ts: str = f"{DAY}T09:00:00Z", cwd: Path | None = None,
              path: Path | None = None) -> Path:
        p = path or self.path(sid)
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"type": "user", "sessionId": sid, "cwd": str(cwd or self.project)}
        if ts:
            rec["timestamp"] = ts
        p.write_text(json.dumps(rec) + "\n")
        return p

    def add(self, sid: str, tokens: int = 1000, ts: str | None = f"{DAY}T12:00:00Z",
            path: Path | None = None) -> None:
        self._n += 1
        rec = {"type": "assistant", "sessionId": sid, "requestId": f"r{self._n}",
               "message": {"id": f"m{self._n}", "model": MODEL,
                           "usage": {"input_tokens": tokens, "output_tokens": 0}}}
        if ts:
            rec["timestamp"] = ts
        with open(path or self.path(sid), "a") as f:
            f.write(json.dumps(rec) + "\n")

    def loc(self, sid: str):
        return self.claude.locate(sid)

    def refresh(self, sid: str, now: float = NOW, zone=UTC_ZONE):
        return refresh(self.store, self.logs, self.loc(sid), zone, now=now)

    def project_input(self, day: str = DAY) -> float:
        pd = self.store.load_day(self.root, day)
        return sum(u.get("input", 0) for u in pd.usage().values()) if pd else 0


def _input(by_model) -> float:
    return sum(u.get("input", 0) for u in by_model.values())


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


# --- the basic protocol -------------------------------------------------------------------


def test_a_session_is_counted_once_in_its_project(world):
    world.start("s1")
    world.add("s1", 100)
    world.add("s1", 200)
    snap = world.refresh("s1")
    assert snap.record.project_root == world.root
    assert _input(snap.session_usage) == 300 and _input(snap.project_usage) == 300
    rev = snap.record.revision
    again = world.refresh("s1")
    assert _input(again.project_usage) == 300
    assert again.record.revision == rev  # nothing new: no new revision, no rewrite


def test_sessions_of_a_project_sum_and_other_projects_stay_out(world):
    world.start("s1")
    world.add("s1", 100)
    world.start("s2")
    world.add("s2", 50)
    other = world.tmp / "other"
    (other / ".aegis").mkdir(parents=True)
    world.start("s3", cwd=other)
    world.add("s3", 7)
    world.refresh("s1")
    world.refresh("s3")
    snap = world.refresh("s2")
    assert _input(snap.project_usage) == 150
    assert set(snap.project.entries) == {"claude/s1", "claude/s2"}


def test_a_session_belongs_to_the_directory_it_started_in(world):
    nested = world.project / "sub" / "deeper"
    nested.mkdir(parents=True)
    assert find_project_root(str(nested)) == world.root
    inner = world.project / "inner"
    (inner / ".aegis").mkdir(parents=True)
    assert find_project_root(str(inner / "x")) == str(inner.resolve())  # innermost wins
    assert find_project_root(str(world.tmp)) is None


# --- crash recovery -------------------------------------------------------------------------


def test_a_crash_between_the_session_write_and_the_project_merge_heals(world):
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    world.add("s1", 40)
    with world.store.session_lock("claude", "s1"):            # steps 1-3 only, then "crash"
        update_session(world.store, world.claude, world.loc("s1"), UTC_ZONE)
    assert world.project_input() == 100                       # the map is one revision behind
    snap = world.refresh("s1")
    assert _input(snap.project_usage) == 140                  # merged again, not double counted
    assert world.refresh("s1").project.entries["claude/s1"]["revision"] == snap.record.revision


# --- the durable revision counter (review round 3) -------------------------------------------


def test_deleting_only_the_session_cache_keeps_updates_flowing(world):
    """The reviewer's case: the project map holds a high-revision entry, the
    session cache is deleted, usage is appended -- the next hook updates the
    project total immediately, and a stale rebuild cannot overwrite it."""
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    # Simulate a long-lived session: its counter and project entry are at revision 100.
    world.store.write_revision("claude", "s1", 100)
    with world.store.project_lock(world.root):
        pd = world.store.load_day(world.root, DAY)
        pd.entries["claude/s1"]["revision"] = 100
        world.store.save_day(pd)
    stale = dict(pd.entries["claude/s1"])

    world.store.record_path("claude", "s1").unlink()           # only the session cache
    world.add("s1", 25)
    snap = world.refresh("s1")
    assert _input(snap.project_usage) == 125
    assert snap.project.entries["claude/s1"]["revision"] == 101

    # A rebuild holding the older snapshot of s1 merges after the hook: it is ignored.
    with world.store.project_lock(world.root):
        pd = world.store.load_day(world.root, DAY)
        assert not world.store.merge_entries(pd, {"claude/s1": stale})
    assert world.project_input() == 125


def test_a_replaced_log_restarts_the_count_but_never_the_revision(world):
    p = world.start("s1")
    world.add("s1", 100)
    world.add("s1", 100)
    first = world.refresh("s1")
    replacement = p.with_suffix(".new")
    world.start("s1", path=replacement)
    world.add("s1", 30, path=replacement)
    os.replace(replacement, p)                                  # another inode, other content
    snap = world.refresh("s1")
    assert _input(snap.session_usage) == 30 and _input(snap.project_usage) == 30
    assert snap.record.revision > first.record.revision


def test_a_lost_revision_counter_is_recovered_above_every_stored_revision(world):
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    with world.store.project_lock(world.root):
        pd = world.store.load_day(world.root, DAY)
        pd.entries["claude/s1"]["revision"] = 57
        world.store.save_day(pd)
    world.store.rev_path("claude", "s1").unlink()               # the state counter is gone
    world.store.record_path("claude", "s1").unlink()            # and so is the cache record
    world.add("s1", 1)
    snap = world.refresh("s1")
    assert snap.record.revision == 59                           # 57 + 1 recovered, + 1 written
    assert _input(snap.project_usage) == 101
    assert world.store.read_revision("claude", "s1") == 59


# --- concurrency -------------------------------------------------------------------------------


def test_rebuilds_racing_hook_updates_neither_deadlock_nor_lose_usage(world):
    sids = [f"s{i}" for i in range(4)]
    for sid in sids:
        world.start(sid)
    errors: list[BaseException] = []
    stop = threading.Event()

    def hooks(sid):
        try:
            for _ in range(15):
                world.add(sid, 10)
                world.refresh(sid)
        except BaseException as e:  # pragma: no cover - reported below
            errors.append(e)

    def rebuilds():
        try:
            while not stop.is_set():
                world.store.day_path(world.root, DAY).unlink(missing_ok=True)
                rebuild(world.store, world.logs, world.root, DAY, UTC_ZONE)
        except BaseException as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=hooks, args=(sid,)) for sid in sids]
    rb = threading.Thread(target=rebuilds)
    rb.start()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    stop.set()
    rb.join(timeout=60)
    assert not any(t.is_alive() for t in [*threads, rb]), "deadlock"
    assert not errors, errors
    for sid in sids:
        world.refresh(sid)
    assert world.project_input() == 4 * 15 * 10


# --- linked sub-agents ---------------------------------------------------------------------------


def test_a_linked_claude_subagent_is_counted_once_inside_its_parent(world):
    p = world.start("s1")
    world.add("s1", 100)
    sub = p.with_suffix("") / "subagents" / "agent-a1.jsonl"
    world.start("s1", path=sub, cwd=world.project / ".claude" / "worktrees" / "a1")
    world.add("s1", 40, path=sub)
    snap = world.refresh("s1")
    assert _input(snap.session_usage) == 140
    assert set(snap.project.entries) == {"claude/s1"}
    world.store.day_path(world.root, DAY).unlink()
    pd = rebuild(world.store, world.logs, world.root, DAY, UTC_ZONE)
    assert set(pd.entries) == {"claude/s1"} and _input(pd.usage()) == 140


def test_a_codex_subagent_hook_is_accounted_in_its_parent(home, tmp_path):  # noqa: F811
    logs = {"codex": CodexLog(home["home"] / ".codex")}
    store = BudgetStore(cache_dir=tmp_path / "c", state_dir=tmp_path / "s")
    child = logs["codex"].locate(CODEX_CHILD)
    now = datetime(2026, 10, 1, 12, tzinfo=UTC).timestamp()
    snap = refresh(store, logs, child, UTC_ZONE, now=now)
    assert snap.record.session_id == CODEX_PARENT
    assert set(snap.project.entries) == {f"codex/{CODEX_PARENT}"}
    assert any(s.startswith("child:") for s in snap.record.sources)


# --- missing history ---------------------------------------------------------------------------


def _wipe_cache(world):
    shutil.rmtree(world.store.cache, ignore_errors=True)


def test_logs_gone_with_the_inventory_present_is_partial_from_checkpoints(world):
    world.start("s1")
    world.add("s1", 100)
    world.start("s2")
    world.add("s2", 30)
    world.refresh("s1")
    world.refresh("s2")
    world.path("s2").unlink()                    # s2's log is gone ...
    _wipe_cache(world)                            # ... and so is the cache
    snap = world.refresh("s1")
    assert snap.project.completeness == "partial"
    assert snap.project.missing_sessions == 1 and snap.project.known_sessions == 2
    assert _input(snap.project_usage) == 130      # s2 from its inventory checkpoint


def test_a_deleted_inventory_makes_completeness_unknown_never_zero_missing(world):
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    world.store.inventory_path(world.root, DAY).unlink()
    _wipe_cache(world)
    snap = world.refresh("s1")
    assert snap.project.completeness == "unknown"
    assert _input(snap.project_usage) == 100


def test_first_use_with_other_sessions_today_is_unknown_and_alone_is_complete(world):
    world.start("s1")
    world.add("s1", 100)
    assert world.refresh("s1").project.completeness == "complete"
    other = World(world.tmp / "w2")
    other.start("a")
    other.add("a", 5)
    other.start("b")
    other.add("b", 6)
    snap = other.refresh("b")
    assert snap.project.completeness == "unknown"
    assert _input(snap.project_usage) == 11


def test_a_new_day_is_complete(world):
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    world.add("s1", 7, ts="2026-10-08T01:00:00Z")
    snap = world.refresh("s1", now=datetime(2026, 10, 8, 2, tzinfo=UTC).timestamp())
    assert snap.day == "2026-10-08" and snap.project.completeness == "complete"
    assert _input(snap.project_usage) == 7 and _input(snap.session_usage) == 107


# --- days ----------------------------------------------------------------------------------


def test_a_rebuild_after_midnight_keeps_old_usage_in_its_own_day(world):
    world.start("s1", ts="2026-10-06T22:00:00Z")
    world.add("s1", 100, ts="2026-10-06T23:30:00Z")
    world.refresh("s1", now=datetime(2026, 10, 6, 23, 45, tzinfo=UTC).timestamp())
    _wipe_cache(world)
    world.add("s1", 5, ts=None)                    # no timestamp: nearest earlier is 10-06
    world.add("s1", 9, ts="2026-10-07T00:10:00Z")
    snap = world.refresh("s1", now=datetime(2026, 10, 7, 0, 20, tzinfo=UTC).timestamp())
    assert snap.day == "2026-10-07"
    assert _input(snap.project_usage) == 9
    assert _input(snap.record.usage_on("2026-10-06")) == 105
    assert _input(snap.session_usage) == 114


def test_the_day_follows_the_policy_time_zone(world):
    world.start("s1")
    world.add("s1", 100, ts="2026-10-07T03:00:00Z")   # 22:00 on 10-06 in Chicago
    chicago = ZoneInfo("America/Chicago")
    snap = world.refresh("s1", now=datetime(2026, 10, 7, 4, tzinfo=UTC).timestamp(),
                         zone=chicago)
    assert snap.day == "2026-10-06" and _input(snap.project_usage) == 100


def test_usage_with_no_recorded_time_counts_for_the_session_only(world):
    p = world.path("s1")
    world.start("s1", ts=None)
    world.add("s1", 60, ts=None, path=p)
    snap = world.refresh("s1")
    assert _input(snap.record.buckets()[UNKNOWN_DAY]) == 60
    assert _input(snap.session_usage) == 60 and _input(snap.project_usage) == 0


# --- odds and ends ------------------------------------------------------------------------------


def test_a_session_outside_any_project_has_a_session_total_only(world):
    world.start("s1", cwd=world.tmp / "elsewhere")
    world.add("s1", 10)
    snap = world.refresh("s1")
    assert snap.record.project_root is None and snap.project is None
    assert _input(snap.session_usage) == 10


def test_a_missing_log_keeps_the_last_totals(world):
    world.start("s1")
    world.add("s1", 10)
    world.refresh("s1")
    loc = world.loc("s1")
    world.path("s1").unlink()
    snap = refresh(world.store, world.logs, loc, UTC_ZONE, now=NOW)
    assert snap.record.log_missing and _input(snap.session_usage) == 10


def test_unsafe_session_ids_are_hashed_into_file_names(world):
    path = world.store.record_path("claude", "../../etc/passwd")
    assert path.parent == world.store.cache / "sessions" / "claude"
    assert path.name.startswith("h-")


def test_merge_never_replaces_a_newer_entry():
    pd = ProjectDay("/p", DAY, {"a/1": {"revision": 5, "usage": {"m": {"input": 5}}}})
    assert not BudgetStore.merge_entries(pd, {"a/1": {"revision": 4, "usage": {}}})
    assert not BudgetStore.merge_entries(pd, {"a/1": {"revision": 5, "usage": {}}})
    assert BudgetStore.merge_entries(pd, {"a/1": {"revision": 6, "usage": {"m": {"input": 1}}},
                                          "b/2": {"revision": 1, "usage": {}}})
    assert pd.entries["a/1"]["revision"] == 6 and "b/2" in pd.entries


# --- verification status reaches the project (review, PR #36) ---------------------------------


def _strict_verdict(snap):
    from aegis_core.budget import price_table
    from aegis_core.budget.evaluate import evaluate
    from aegis_core.budget.policy import BudgetPolicy, Limit
    p = BudgetPolicy("budget.yaml", "admin", "tokens", Limit(10**9), Limit(10**9), "UTC",
                     ("claude",), "deny", "estimate")
    return evaluate(p, price_table(p), snap)


def test_another_sessions_missing_log_with_a_cached_record_fails_strict_closed(world):
    """Reviewer's reproduction: s2's log is deleted but its session cache
    survives; the project/day map is deleted; s1 refreshes."""
    for sid, n in (("s1", 100), ("s2", 30)):
        world.start(sid)
        world.add(sid, n)
        world.refresh(sid)
    world.path("s2").unlink()
    world.store.day_path(world.root, DAY).unlink()
    snap = world.refresh("s1")
    assert _input(snap.project_usage) == 130              # cached usage kept as a lower bound
    assert snap.project.unverified() == {"claude/s2": ["log-missing"]}
    assert snap.project.completeness == "partial"
    v = _strict_verdict(snap)
    assert v.decision == "deny" and "unknown-log" in v.reasons


@pytest.mark.parametrize("via_rebuild", [False, True])
def test_a_malformed_record_in_another_session_fails_strict_closed(world, via_rebuild):
    for sid in ("s1", "s2"):
        world.start(sid)
        world.add(sid, 10)
        world.refresh(sid)
    with open(world.path("s2"), "a") as f:
        f.write("{not json\n")
    if via_rebuild:
        world.store.day_path(world.root, DAY).unlink()
    else:
        world.refresh("s2")                                # s2's own hook records it
    snap = world.refresh("s1")
    assert snap.project.unverified(exclude="claude/s1") == {"claude/s2": ["unreadable-records"]}
    assert _strict_verdict(snap).decision == "deny"
    assert not snap.record.unverified()                    # s1 itself is fine


@pytest.mark.parametrize("damage", ["malformed", "truncated", "foreign", "unreadable"])
def test_a_damaged_inventory_is_unknown_history_not_an_empty_one(world, damage):
    """Reviewer's reproduction: s2's log is gone, the day's inventory is
    damaged, the cache is deleted, s1 refreshes."""
    for sid, n in (("s1", 100), ("s2", 30)):
        world.start(sid)
        world.add(sid, n)
        world.refresh(sid)
    world.path("s2").unlink()
    inv = world.store.inventory_path(world.root, DAY)
    good = inv.read_text()
    if damage == "malformed":
        inv.write_text("{this is not json\n" + good)
    elif damage == "truncated":
        inv.write_text(good[:-20])
    elif damage == "foreign":
        inv.write_text('{"hello": "world"}\n' + good)
    else:
        inv.unlink()
        inv.mkdir()                                          # exists, cannot be read as a file
    _wipe_cache(world)
    snap = world.refresh("s1")
    assert snap.project.completeness == "unknown"
    assert snap.project.history in ("corrupt", "unreadable")
    assert _strict_verdict(snap).decision == "deny"
    if damage in ("malformed", "foreign"):
        assert _input(snap.project_usage) == 130             # valid checkpoints still used


def test_a_corrupt_day_index_is_unknown(world):
    world.start("s1")
    world.add("s1", 100)
    world.refresh("s1")
    world.store.inventory_path(world.root, DAY).unlink()
    world.store.index_path(world.root).write_text("garbage")
    _wipe_cache(world)
    assert world.refresh("s1").project.completeness == "unknown"
