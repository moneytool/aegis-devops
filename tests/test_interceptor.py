from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.store import Constraint, ConstraintStore

NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)

AUTHORITY = {
    "admin": {"scaling", "deletion", "configuration"},
    "sre_lead": {"scaling", "configuration"},
    "developer": {"configuration"},
}


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    defaults.update(overrides)
    return Constraint.create(**defaults)


SCALE_INTENT = InfrastructureIntent(
    resource="deployment/api-server", action="scale", provider="kubernetes"
)


def test_no_match_allows_and_reports_uncovered():
    store = ConstraintStore(authority_map=AUTHORITY)
    interceptor = AegisInterceptor(store)

    unrelated_intent = InfrastructureIntent(
        resource="service/frontend", action="get", provider="kubernetes"
    )
    decision = interceptor.intercept(unrelated_intent, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.covered is False
    assert decision.citations == []


def test_tampered_constraint_is_discarded_and_intent_allowed():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.constraints[constraint.id] = constraint
    constraint.rule_text = "attacker rewrote the rule after ingest"  # breaks the hash

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.covered is True
    assert decision.discarded == [{"id": "rule-1", "reason": "tampered"}]
    assert decision.citations == []


def test_revoked_principal_constraint_is_discarded():
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    constraint = make_constraint(principal="sre_lead")
    store.constraints[constraint.id] = constraint

    # sre_lead was authorized for 'scaling' when ingested, but authority is
    # revoked before the decision is made.
    store.authority_map = {"admin": {"scaling", "deletion", "configuration"}}

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "rule-1", "reason": "unauthorized"}]


def test_block_outranks_escalate_when_both_match():
    store = ConstraintStore(authority_map=AUTHORITY)
    block_rule = make_constraint(id="block-rule", effect="BLOCK")
    escalate_rule = make_constraint(id="escalate-rule", effect="ESCALATE")
    store.constraints[block_rule.id] = block_rule
    store.constraints[escalate_rule.id] = escalate_rule

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "BLOCK"
    assert decision.citations == ["block-rule"]


def test_escalate_when_no_block_matches():
    store = ConstraintStore(authority_map=AUTHORITY)
    escalate_rule = make_constraint(id="escalate-rule", effect="ESCALATE")
    store.constraints[escalate_rule.id] = escalate_rule

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.citations == ["escalate-rule"]


def test_latency_ms_is_populated_and_fast_for_500_constraints():
    store = ConstraintStore(authority_map=AUTHORITY)
    for i in range(500):
        c = make_constraint(
            id=f"rule-{i}",
            resource_pattern=f"deployment/unrelated-{i}",
        )
        store.constraints[c.id] = c

    interceptor = AegisInterceptor(store)
    interceptor.intercept(SCALE_INTENT, now=NOW)  # warm up fnmatch's internal cache
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.latency_ms > 0
    assert decision.latency_ms < 5
