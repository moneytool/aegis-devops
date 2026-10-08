"""allow / warn / deny from a usage snapshot (design v1.0 §6, §11)."""

import pytest

from aegis_core.budget import price_table
from aegis_core.budget.accounting import UNKNOWN_DAY, ProjectDay, SessionRecord, Snapshot
from aegis_core.budget.evaluate import ALLOW, DENY, WARN, evaluate
from aegis_core.budget.policy import BudgetPolicy, Limit

DAY = "2026-10-07"
OPUS = "claude-opus-5-5"   # $4 in / $20 out per million


def policy(**kw) -> BudgetPolicy:
    base = dict(path="budget.yaml", principal="admin", unit="usd", session=Limit(10.0),
                project_day=Limit(50.0), tz="UTC", agents=("claude", "codex", "copilot"),
                on_unknown_log="allow", on_unknown_price="estimate", pricing={},
                copilot_premium_requests=Limit(20))
    base.update(kw)
    return BudgetPolicy(**base)


def snap(session: dict, project: dict | None = None, agent: str = "claude", *,
         completeness: str = "complete", unknown_day: dict | None = None, **rec_kw) -> Snapshot:
    buckets = {DAY: session}
    if unknown_day:
        buckets[UNKNOWN_DAY] = unknown_day
    rec = SessionRecord(agent, "s1", {"agent": agent, "session_id": "s1", "path": "x"}, "UTC",
                        sources={"main": {"buckets": buckets}}, **rec_kw)
    project = session if project is None else project
    pd = ProjectDay("/p", DAY, {f"{agent}/s1": {"revision": 1, "usage": project}},
                    completeness=completeness)
    return Snapshot(rec, DAY, pd, rec.usage_total(), pd.usage(), {})


def dollars(d: float) -> dict:
    """Opus input tokens costing ``d`` dollars."""
    return {OPUS: {"input": d / 4 * 1_000_000}}


def test_under_the_warning_threshold_is_allowed_silently():
    p = policy()
    v = evaluate(p, price_table(p), snap(dollars(5)))
    assert v.decision == ALLOW and v.messages == [] and v.reasons == []
    assert [m.name for m in v.measures] == ["session", "project_day"]
    assert v.measures[0].used == pytest.approx(5.0)


def test_crossing_warn_at_warns_with_what_is_left():
    p = policy()
    v = evaluate(p, price_table(p), snap(dollars(8.5)))
    assert v.decision == WARN and v.reasons == ["session-warn"]
    assert "85%" in v.messages[0] and "$1.50 left" in v.messages[0]


def test_reaching_a_limit_denies_and_reports_overshoot():
    p = policy()
    v = evaluate(p, price_table(p), snap(dollars(12)))
    assert v.decision == DENY and "session-over" in v.reasons
    assert v.measures[0].overshoot == pytest.approx(2.0)
    assert "overshoot $2.00" in v.messages[0]


def test_the_project_day_limit_counts_every_session():
    p = policy()
    v = evaluate(p, price_table(p), snap(dollars(1), project=dollars(60)))
    assert v.decision == DENY and v.reasons == ["project_day-over"]


def test_token_mode_counts_all_four_categories():
    p = policy(unit="tokens", session=Limit(1000), project_day=None)
    usage = {OPUS: {"input": 100, "output": 200, "cache_read": 300, "cache_write": 400}}
    v = evaluate(p, price_table(p), snap(usage))
    assert v.measures[0].used == 1000 and v.decision == DENY


def test_unpriced_models_are_estimated_or_denied():
    usage = {"claude-opus-9": {"input": 1000}}
    est = policy()
    v = evaluate(est, price_table(est), snap(usage))
    assert v.decision == WARN and "estimated-price" in v.reasons
    assert v.estimated == {"claude-opus-9": ["input"]}
    strict = policy(on_unknown_price="deny")
    v = evaluate(strict, price_table(strict), snap(usage))
    assert v.decision == DENY and "unpriced-model" in v.reasons
    assert "add it under 'pricing:'" in v.messages[-1]
    priced = policy(on_unknown_price="deny", pricing={"claude-opus-9": {
        "input": 1.0, "output": 1.0, "cache_read": 0.1, "cache_write": 1.0}})
    assert evaluate(priced, price_table(priced), snap(usage)).decision == ALLOW


@pytest.mark.parametrize("kw,fragment", [
    ({"log_missing": True}, "the session's log is missing"),
    ({"problem_total": 3}, "3 unreadable log record(s)"),
    ({"unknown_day": {OPUS: {"input": 10}}}, "no recorded time"),
    ({"completeness": "unknown"}, "today's project total is unknown"),
    ({"completeness": "partial"}, "today's project total is partial"),
])
def test_unverifiable_usage_follows_on_unknown_log(kw, fragment):
    lenient = policy()
    v = evaluate(lenient, price_table(lenient), snap(dollars(1), **kw))
    assert v.decision == WARN and "unknown-log-warn" in v.reasons
    assert fragment in v.messages[-1]
    strict = policy(on_unknown_log="deny")
    v = evaluate(strict, price_table(strict), snap(dollars(1), **kw))
    assert v.decision == DENY and "unknown-log" in v.reasons


def test_copilot_is_measured_in_premium_requests():
    p = policy()
    s = snap({"copilot-premium-requests": {"requests": 21}}, agent="copilot")
    v = evaluate(p, price_table(p), s)
    assert [m.name for m in v.measures] == ["copilot_premium_requests"]
    assert v.decision == DENY and "21.00 premium requests" in v.messages[0]


def test_unlisted_or_unmeasured_agents_are_not_evaluated():
    p = policy(agents=("claude",))
    assert evaluate(p, price_table(p), snap(dollars(99), agent="codex")).decision == ALLOW
    q = policy(copilot_premium_requests=None)
    s = snap({"copilot-premium-requests": {"requests": 99}}, agent="copilot")
    assert evaluate(q, price_table(q), s).decision == ALLOW


def test_a_session_outside_any_project_has_only_the_session_limit():
    p = policy()
    s = snap(dollars(1))
    s.project = None
    v = evaluate(p, price_table(p), s)
    assert [m.name for m in v.measures] == ["session"]
