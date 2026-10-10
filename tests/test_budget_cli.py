"""``aegis budget status|check|reset`` (design v1.0 §7, §4.1)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_budget_hook import BUDGET, env, write_budget  # noqa: F401  (fixture)

from aegis_core.budget.accounting import BudgetStore
from aegis_core.budget.report import reset_acknowledged, reset_path
from aegis_core.cli import main
from aegis_core.hook import run_hook

NOW = datetime.now(UTC)
TODAY = NOW.date().isoformat()


def transcript(env, sid: str, input_tokens: int, *, malformed: bool = False) -> Path:  # noqa: F811
    """A Claude Code session in the project, with usage timestamped now."""
    path = env["home"] / ".claude" / "projects" / "-project" / f"{sid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = NOW.isoformat().replace("+00:00", "Z")
    recs = [{"type": "user", "sessionId": sid, "cwd": str(env["project"]), "timestamp": ts},
            {"type": "assistant", "sessionId": sid, "requestId": f"r-{sid}", "timestamp": ts,
             "message": {"id": f"m-{sid}", "model": "claude-opus-5-5",
                         "usage": {"input_tokens": input_tokens, "output_tokens": 0}}}]
    text = "".join(json.dumps(r) + "\n" for r in recs)
    path.write_text(text + ("{broken\n" if malformed else ""))
    return path


def hook_call(env, sid: str):  # noqa: F811
    payload = {"session_id": sid, "cwd": str(env["project"]), "tool_name": "Edit",
               "tool_input": {}, "transcript_path": str(
                   env["home"] / ".claude" / "projects" / "-project" / f"{sid}.jsonl")}
    return run_hook("claude", json.dumps(payload))


DAY_BUDGET = "principal: admin\nunit: usd\nsession: {limit: 1.0}\nproject_day: {limit: 2.0}\n"


def _status(env, capsys, *extra) -> dict:  # noqa: F811
    assert main(["budget", "status", "--project", str(env["project"]), "--json", *extra]) == 0
    return json.loads(capsys.readouterr().out)


# --- status --------------------------------------------------------------------------------


def test_status_rebuilds_today_from_the_logs(env, capsys):  # noqa: F811
    write_budget(env, DAY_BUDGET)
    transcript(env, "a", 125_000)            # $0.50
    transcript(env, "b", 375_000)            # $1.50: over its session limit
    st = _status(env, capsys)
    assert st["day"] == TODAY and st["unit"] == "usd"
    assert st["project_day"]["used"] == pytest.approx(2.0)
    assert st["project_day"]["level"] == "deny"
    by_id = {s["session_id"]: s for s in st["sessions"]}
    assert by_id["a"]["today"] == pytest.approx(0.5) and by_id["a"]["level"] == "allow"
    assert by_id["b"]["level"] == "deny" and by_id["b"]["overshoot"] == pytest.approx(0.5)
    assert st["decision"] == "deny"


def test_status_for_people_and_agent_filter(env, capsys):  # noqa: F811
    write_budget(env, DAY_BUDGET)
    transcript(env, "a", 125_000)
    assert main(["budget", "status", "--project", str(env["project"])]) == 0
    out = capsys.readouterr().out
    assert "project today: $0.50 of $2.00 (25%, allow)" in out
    assert "claude    a: today $0.50, session $0.50 of $1.00" in out
    assert _status(env, capsys, "--agent", "codex")["sessions"] == []


def test_status_shows_lower_bounds(env, capsys):  # noqa: F811
    write_budget(env, DAY_BUDGET)
    transcript(env, "a", 1_000, malformed=True)
    st = _status(env, capsys)
    assert st["sessions"][0]["unverified"] == ["unreadable-records"]


# --- check ---------------------------------------------------------------------------------


def _check(env, *extra) -> int:  # noqa: F811
    return main(["budget", "check", "--project", str(env["project"]), *extra])


def test_check_exit_codes(env, capsys, tmp_path):  # noqa: F811
    assert _check(env) == 66                                  # no budget.yaml
    write_budget(env, DAY_BUDGET)
    transcript(env, "a", 125_000)
    assert _check(env) == 0
    transcript(env, "b", 500_000)                             # project now $2.50 of $2.00
    assert _check(env) == 3
    assert "project day limit reached" in capsys.readouterr().out
    assert _check(env, "--agent", "claude", "--session", "a") == 3   # project limit applies
    assert _check(env, "--agent", "claude") == 64             # --session missing
    (env["project"] / ".aegis" / "budget.yaml").write_text(DAY_BUDGET.replace("2.0", "20"))
    assert _check(env) == 65                                  # edited after signing


def test_check_a_session_against_its_own_limit(env):  # noqa: F811
    write_budget(env, "principal: admin\nunit: usd\nsession: {limit: 1.0}\n")
    transcript(env, "a", 125_000)
    transcript(env, "b", 300_000)
    assert _check(env, "--agent", "claude", "--session", "a") == 0
    assert _check(env, "--agent", "claude", "--session", "b") == 3
    assert _check(env, "--agent", "claude", "--session", "nobody") == 65


# --- reset ---------------------------------------------------------------------------------


STRICT = "principal: admin\nunit: usd\nsession: {limit: 100}\nproject_day: {limit: 100}\n" \
         "on_unknown_log: deny\n"


def test_a_signed_reset_ends_a_strict_unknown_history_day(env, capsys):  # noqa: F811
    """First use with other sessions already in today's logs: the history is
    unknown, so strict mode denies -- until a signed reset acknowledges it."""
    write_budget(env, STRICT)
    transcript(env, "earlier", 1_000)                         # ran before the budget existed
    transcript(env, "now", 1_000)
    code, _, err = hook_call(env, "now")
    assert code == 2 and "unknown" in err and "on_unknown_log: deny" in err
    assert main(["budget", "reset", "--day", "--project", str(env["project"])]) == 0
    assert TODAY in capsys.readouterr().out
    assert hook_call(env, "now")[0] == 0
    st = _status(env, capsys)
    assert st["acknowledged"] is True and st["decision"] == "allow"


def test_reset_does_not_excuse_the_sessions_own_problems(env):  # noqa: F811
    write_budget(env, STRICT)
    transcript(env, "now", 1_000, malformed=True)
    assert main(["budget", "reset", "--day", "--project", str(env["project"])]) == 0
    code, _, err = hook_call(env, "now")
    assert code == 2 and "unreadable log record" in err


def test_reset_markers_are_verified(env, capsys):  # noqa: F811
    write_budget(env, STRICT)
    transcript(env, "earlier", 1_000)
    transcript(env, "now", 1_000)
    assert main(["budget", "reset", "--day", "--project", str(env["project"])]) == 0
    store = BudgetStore()
    root = str(env["project"].resolve())
    marker = reset_path(store, root, TODAY)
    key = bytes.fromhex("".join(
        line.strip() for line in (env["project"] / ".aegis" / "example-signing.key")
        .read_text().splitlines() if not line.lstrip().startswith("#")))
    assert reset_acknowledged(store, root, TODAY, key) is not None
    doc = json.loads(marker.read_text())
    marker.write_text(json.dumps({**doc, "day": "2001-01-01"}))   # moved to another day
    assert reset_acknowledged(store, root, TODAY, key) is None
    marker.write_text(json.dumps({**doc, "mac": "0" * 64}))         # forged without the key
    assert reset_acknowledged(store, root, TODAY, key) is None
    widened = {**doc["baseline"], "missing_sessions": 99}
    marker.write_text(json.dumps({**doc, "baseline": widened}))      # baseline widened
    assert reset_acknowledged(store, root, TODAY, key) is None
    assert hook_call(env, "now")[0] == 2
    assert reset_acknowledged(store, root, TODAY, None) is None    # no key: not verified
    assert reset_acknowledged(store, root, TODAY, None, insecure=True) is not None


def test_reset_needs_the_key_and_a_project(env, capsys, tmp_path):  # noqa: F811
    write_budget(env, STRICT)
    assert main(["budget", "reset", "--day", "--insecure",
                 "--project", str(env["project"])]) == 64
    assert main(["budget", "reset", "--day", "2026-13-40",
                 "--project", str(env["project"])]) == 64
    assert main(["budget", "reset", "--day", "2026-10-01",
                 "--project", str(env["project"])]) == 0


# --- review of #40 ---------------------------------------------------------------------------


def test_a_session_check_sees_other_sessions_unhooked_spend(env, capsys):  # noqa: F811
    """check --agent/--session rebuilds the project day too: session a's
    hook recorded $0.50, then session b spent $2.00 with no hook firing."""
    write_budget(env, DAY_BUDGET)
    transcript(env, "a", 125_000)
    assert hook_call(env, "a")[0] == 0                      # the project cache now exists
    transcript(env, "b", 500_000)
    assert _check(env, "--agent", "claude", "--session", "a") == 3
    assert "project day limit reached" in capsys.readouterr().out


def test_a_reset_does_not_excuse_problems_that_appear_after_it(env, capsys):  # noqa: F811
    write_budget(env, STRICT)
    transcript(env, "a", 1_000)
    assert hook_call(env, "a")[0] == 0
    assert main(["budget", "reset", "--day", "--project", str(env["project"])]) == 0
    transcript(env, "c", 1_000, malformed=True)             # a new, unreadable session
    code, _, err = hook_call(env, "c")
    assert code == 2 and "unreadable log record" in err      # its own hook denies
    code, _, err = hook_call(env, "a")
    assert code == 2 and "lower bound" in err                # and it is not excused for a


def test_a_reset_still_excuses_what_it_acknowledged(env, capsys):  # noqa: F811
    write_budget(env, STRICT)
    transcript(env, "a", 1_000)
    transcript(env, "c", 1_000, malformed=True)
    hook_call(env, "a")
    hook_call(env, "c")
    assert hook_call(env, "a")[0] == 2                       # c is a lower bound: strict denies
    assert main(["budget", "reset", "--day", "--project", str(env["project"])]) == 0
    assert hook_call(env, "a")[0] == 0                       # acknowledged as it stood
