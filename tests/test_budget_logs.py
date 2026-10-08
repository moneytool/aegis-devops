"""Reading usage from each agent's logs (design v1.0 §4), against redacted
samples of real logs in tests/fixtures/budget/."""

import json
import os
import shutil
import sqlite3
from collections import defaultdict
from pathlib import Path

import pytest

from aegis_core.budget.logs import (
    ClaudeLog,
    CodexLog,
    CopilotLog,
    GeminiLog,
    LogMissing,
    OpenCodeLog,
    parse_ts,
    tail_jsonl,
)

FIX = Path(__file__).parent / "fixtures" / "budget"
CLAUDE_SID = "11111111-2222-3333-4444-555555555555"
CODEX_PARENT = "01a00000-0000-7000-8000-000000000001"
CODEX_CHILD = "01a00000-0000-7000-8000-000000000002"
GEMINI_SID = "77777777-aaaa-bbbb-cccc-000000000001"
COPILOT_SID = "cccccccc-0000-0000-0000-000000000001"


def _copy(src: Path, dest: Path, project: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(src.read_text().replace("{PROJECT}", str(project)))
    return dest


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def build_opencode_db(db_path: Path, project: Path) -> dict:
    spec = json.loads((FIX / "opencode" / "db.json").read_text().replace("{PROJECT}",
                                                                          str(project)))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.executescript("PRAGMA foreign_keys=OFF;")
    for sql in spec["schema"].values():
        db.execute(sql)
    for s in spec["session"]:
        db.execute("INSERT INTO session (id, project_id, parent_id, slug, directory, title, "
                   "version, time_created, time_updated) VALUES (?,?,?,?,?,?,?,?,?)",
                   (s["id"], s["project_id"], s["parent_id"], s["slug"], s["directory"],
                    s["title"], s["version"], s["time_created"], s["time_updated"]))
    for m in spec["message"]:
        db.execute("INSERT INTO message (id, session_id, time_created, time_updated, data) "
                   "VALUES (?,?,?,?,?)", (m["id"], m["session_id"], m["time_created"],
                                          m["time_updated"], json.dumps(m["data"])))
    db.commit()
    db.close()
    return spec


@pytest.fixture
def home(tmp_path):
    project = tmp_path / "project"
    (project / ".aegis").mkdir(parents=True)
    h = tmp_path / "home"
    claude_main = _copy(FIX / "claude" / "session.jsonl",
                        h / ".claude" / "projects" / "-project" / f"{CLAUDE_SID}.jsonl", project)
    _copy(FIX / "claude" / "subagent.jsonl", claude_main.with_suffix("") / "subagents" /
          "agent-a0000000000000001.jsonl", project)
    day = h / ".codex" / "sessions" / "2026" / "10" / "01"
    _copy(FIX / "codex" / "parent.jsonl", day / f"rollout-2026-10-01T00-29-49-{CODEX_PARENT}.jsonl",
          project)
    _copy(FIX / "codex" / "child.jsonl", day / f"rollout-2026-10-01T00-31-02-{CODEX_CHILD}.jsonl",
          project)
    chats = h / ".gemini" / "tmp" / "project" / "chats"
    _copy(FIX / "gemini" / "session.jsonl", chats / "session-2026-09-27T20-58-77777777.jsonl",
          project)
    (chats.parent / ".project_root").write_text(f"{project}\n")
    _copy(FIX / "copilot" / "events.jsonl",
          h / ".copilot" / "session-state" / COPILOT_SID / "events.jsonl", project)
    build_opencode_db(h / ".local" / "share" / "opencode" / "opencode.db", project)
    return {"home": h, "project": project}


def _totals(reads) -> dict[str, float]:
    out: dict[str, float] = defaultdict(float)
    keyed: dict[str, dict] = {}
    for sr in reads:
        for ev in sr.events:
            if ev.key is not None:
                keyed[ev.key] = ev.usage
            else:
                for k, v in ev.usage.items():
                    out[k] += v
    for usage in keyed.values():
        for k, v in usage.items():
            out[k] += v
    return dict(out)


def _cursors(reads):
    return {sr.source: sr.cursor for sr in reads}


# --- Claude Code ------------------------------------------------------------------------


def _claude_expected(*paths: Path) -> dict[str, float]:
    seen, out = set(), defaultdict(float)
    for path in paths:
        for r in _records(path):
            if r.get("type") != "assistant":
                continue
            m = r["message"]
            key = (m["id"], r.get("requestId"))
            if key in seen:
                continue
            seen.add(key)
            u = m["usage"]
            out["input"] += u.get("input_tokens", 0)
            out["output"] += u.get("output_tokens", 0)
            out["cache_read"] += u.get("cache_read_input_tokens", 0)
            out["cache_write"] += u.get("cache_creation_input_tokens", 0)
    return dict(out)


def test_claude_counts_each_request_once_and_reads_linked_subagents(home):
    log = ClaudeLog(home["home"] / ".claude")
    loc = log.locate(CLAUDE_SID)
    reads = log.read(loc, {})
    assert [sr.source for sr in reads] == ["main", "sub:agent-a0000000000000001.jsonl"]
    main = Path(loc.path)
    sub = main.with_suffix("") / "subagents" / "agent-a0000000000000001.jsonl"
    assert _totals(reads) == _claude_expected(main, sub)
    # the fixture really does repeat usage per content block
    assistant = [r for r in _records(main) if r["type"] == "assistant"]
    assert len(assistant) > len({r["message"]["id"] for r in assistant})
    assert all(not sr.problems for sr in reads)
    assert all(ev.ts is not None and ev.provider == "anthropic" for sr in reads
               for ev in sr.events)


def test_claude_info_and_discovery(home):
    log = ClaudeLog(home["home"] / ".claude")
    loc = log.locate(CLAUDE_SID)
    info = log.info(loc)
    assert info.cwd == str(home["project"]) and info.parent is None
    assert info.start == parse_ts(_records(Path(loc.path))[0]["timestamp"])
    found = log.discover(0)
    assert [x.session_id for x in found] == [CLAUDE_SID]  # sub-agent logs are not sessions
    assert log.locate("nope") is None
    assert log.locate(CLAUDE_SID, transcript_path=loc.path).path == loc.path


def test_claude_incremental_read_finds_nothing_new(home):
    log = ClaudeLog(home["home"] / ".claude")
    loc = log.locate(CLAUDE_SID)
    first = log.read(loc, {})
    again = log.read(loc, _cursors(first))
    assert _totals(again) == {} and not any(sr.reset for sr in again)


# --- the JSONL tail ------------------------------------------------------------------


def test_tail_leaves_a_half_written_line_for_next_time(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text('{"a": 1}\n{"b": ')
    recs, problems, cur, reset = tail_jsonl(p, None)
    assert recs == [{"a": 1}] and not problems and not reset
    assert cur["offset"] == len('{"a": 1}\n')
    with open(p, "a") as f:
        f.write('2}\n{"c": 3}\n')
    recs, _, cur, reset = tail_jsonl(p, cur)
    assert recs == [{"b": 2}, {"c": 3}] and not reset


def test_tail_detects_replacement_and_truncation(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text('{"a": 1}\n{"b": 2}\n')
    _, _, cur, _ = tail_jsonl(p, None)
    p.write_text('{"a": 1}\n')                      # truncated: shorter than the offset
    recs, _, cur2, reset = tail_jsonl(p, cur)
    assert reset and recs == [{"a": 1}]
    replacement = tmp_path / "new.jsonl"
    replacement.write_text('{"z": 9}\n')
    os.replace(replacement, p)                      # replaced: another inode, other head
    recs, _, _, reset = tail_jsonl(p, cur2)
    assert reset and recs == [{"z": 9}]


def test_tail_reports_unreadable_lines_and_missing_files(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text('{"a": 1}\nnot json\n')
    recs, problems, _, _ = tail_jsonl(p, None)
    assert recs == [{"a": 1}] and len(problems) == 1
    with pytest.raises(LogMissing):
        tail_jsonl(tmp_path / "gone.jsonl", None)


def test_records_without_a_timestamp_take_the_nearest_earlier_one(tmp_path):
    log = ClaudeLog(tmp_path)
    p = tmp_path / "projects" / "x" / "s.jsonl"
    p.parent.mkdir(parents=True)
    usage = {"input_tokens": 5, "output_tokens": 1}
    lines = [{"type": "user", "timestamp": "2026-10-01T10:00:00Z", "cwd": "/w"},
             {"type": "assistant", "requestId": "r1",
              "message": {"id": "m1", "model": "claude-opus-5-5", "usage": usage}}]
    p.write_text("".join(json.dumps(x) + "\n" for x in lines))
    [main] = log.read(log.locate("s"), {})
    assert main.events[0].ts == parse_ts("2026-10-01T10:00:00Z")
    # with no earlier timestamp in the source at all, the time stays unknown
    p.write_text(json.dumps(lines[1]) + "\n")
    [main] = log.read(log.locate("s"), {})
    assert main.events[0].ts is None


# --- Codex CLI ------------------------------------------------------------------------


def _codex_final_total(path: Path) -> dict[str, float]:
    total = None
    for r in _records(path):
        p = r.get("payload") or {}
        if r["type"] == "event_msg" and p.get("type") == "token_count" and p.get("info"):
            total = p["info"]["total_token_usage"]
    cached = total.get("cached_input_tokens", 0)
    return {"input": total["input_tokens"] - cached, "output": total["output_tokens"],
            "cache_read": cached, "cache_write": total.get("cache_write_input_tokens", 0)}


def test_codex_sums_differences_of_running_totals_and_links_subagents(home):
    log = CodexLog(home["home"] / ".codex")
    loc = log.locate(CODEX_PARENT)
    reads = log.read(loc, {})
    assert [sr.source for sr in reads][0] == "main"
    assert any(sr.source.startswith("child:") for sr in reads)
    parent_file = Path(loc.path)
    child_file = parent_file.with_name(f"rollout-2026-10-01T00-31-02-{CODEX_CHILD}.jsonl")
    expected = defaultdict(float)
    for f in (parent_file, child_file):
        for k, v in _codex_final_total(f).items():
            expected[k] += v
    got = _totals(reads)
    assert {k: v for k, v in got.items() if v} == {k: v for k, v in expected.items() if v}
    models = {ev.model for sr in reads for ev in sr.events}
    assert "unknown" not in models
    # the classification of other rollout files is remembered
    assert reads[0].cursor["children"]
    assert _totals(log.read(loc, _cursors(reads))) == {}


def test_codex_subagent_names_its_parent_and_is_not_discovered(home):
    log = CodexLog(home["home"] / ".codex")
    child = log.locate(CODEX_CHILD)
    assert log.info(child).parent == CODEX_PARENT
    assert [x.session_id for x in log.discover(0)] == [CODEX_PARENT]
    assert log.info(log.locate(CODEX_PARENT)).cwd == str(home["project"])


# --- Gemini CLI -----------------------------------------------------------------------


def test_gemini_keys_messages_by_id_and_reads_the_project_root(home):
    log = GeminiLog(home["home"] / ".gemini")
    loc = log.locate(GEMINI_SID)
    [main] = log.read(loc, {})
    assert all(ev.key for ev in main.events)
    keys = [ev.key for ev in main.events]
    assert len(keys) > len(set(keys))  # Gemini rewrites messages; each is counted once
    expected = defaultdict(float)
    seen = {}
    for r in _records(Path(loc.path)):
        if r.get("type") == "gemini" and "tokens" in r:
            seen[r["id"]] = r["tokens"]
    for t in seen.values():
        expected["input"] += t["input"] - t.get("cached", 0) + t.get("tool", 0)
        expected["output"] += t["output"] + t.get("thoughts", 0)
        expected["cache_read"] += t.get("cached", 0)
    assert {k: v for k, v in _totals([main]).items() if v} == \
        {k: v for k, v in expected.items() if v}
    assert log.info(loc).cwd == str(home["project"])
    assert [x.session_id for x in log.discover(0)] == [GEMINI_SID]


# --- OpenCode -------------------------------------------------------------------------


def test_opencode_reads_the_session_and_its_child_sessions(home):
    db = home["home"] / ".local" / "share" / "opencode" / "opencode.db"
    spec = json.loads((FIX / "opencode" / "db.json").read_text())
    parent = next(s["id"] for s in spec["session"] if s["parent_id"] is None)
    log = OpenCodeLog(db.parent)
    loc = log.locate(parent)
    [src] = log.read(loc, {})
    expected = defaultdict(float)
    for m in spec["message"]:
        t = m["data"].get("tokens")
        if m["data"].get("role") != "assistant" or not t:
            continue
        expected["input"] += t["input"]
        expected["output"] += t["output"] + t.get("reasoning", 0)
        expected["cache_read"] += t["cache"]["read"]
        expected["cache_write"] += t["cache"]["write"]
    assert {k: v for k, v in _totals([src]).items() if v} == \
        {k: v for k, v in expected.items() if v}
    assert [x.session_id for x in log.discover(0)] == [parent]
    child = next(s["id"] for s in spec["session"] if s["parent_id"] == parent)
    assert log.info(log.locate(child)).parent == parent


def test_opencode_rewritten_rows_replace_their_earlier_usage(home):
    db_path = home["home"] / ".local" / "share" / "opencode" / "opencode.db"
    spec = json.loads((FIX / "opencode" / "db.json").read_text())
    parent = next(s["id"] for s in spec["session"] if s["parent_id"] is None)
    log = OpenCodeLog(db_path.parent)
    loc = log.locate(parent)
    [first] = log.read(loc, {})
    msg = next(m for m in spec["message"] if m["data"].get("role") == "assistant"
               and m["session_id"] == parent)
    data = dict(msg["data"], tokens={**msg["data"]["tokens"], "output": 99999})
    db = sqlite3.connect(db_path)
    # OpenCode stamps a rewritten row with the time of the rewrite
    db.execute("UPDATE message SET data = ?, time_updated = ? WHERE id = ?",
               (json.dumps(data), first.cursor["since"] + 1, msg["id"]))
    db.commit()
    db.close()
    [second] = log.read(loc, {"db": first.cursor})
    assert [ev.key for ev in second.events] == [msg["id"]]
    assert second.events[0].usage["output"] == 99999 + data["tokens"].get("reasoning", 0)


def test_opencode_missing_database_or_session(tmp_path, home):
    assert OpenCodeLog(tmp_path / "none").locate("x") is None
    db = home["home"] / ".local" / "share" / "opencode"
    from aegis_core.budget.logs import Locator
    with pytest.raises(LogMissing):
        OpenCodeLog(db).read(Locator("opencode", "ses-gone", str(db / "opencode.db")), {})


# --- Copilot CLI ----------------------------------------------------------------------


def test_copilot_counts_premium_requests_once(home):
    log = CopilotLog(home["home"] / ".copilot")
    loc = log.locate(COPILOT_SID)
    [main] = log.read(loc, {})
    totals = [r["data"]["totalPremiumRequests"] for r in _records(Path(loc.path))
              if r["type"] in ("session.usage_checkpoint", "session.shutdown")]
    assert _totals([main]) == {"requests": max(totals)}
    assert len(totals) > len(set(totals))  # repeated totals in the fixture are not recounted
    assert log.info(loc).cwd == str(home["project"])
    assert [x.session_id for x in log.discover(0)] == [COPILOT_SID]


def test_discovery_honours_the_modified_since_filter(home):
    log = ClaudeLog(home["home"] / ".claude")
    loc = log.locate(CLAUDE_SID)
    os.utime(loc.path, (1_000_000, 1_000_000))
    assert log.discover(2_000_000) == []
    shutil.rmtree(home["home"] / ".claude")
    assert log.discover(0) == []
