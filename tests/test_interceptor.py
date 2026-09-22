from datetime import UTC, datetime, timedelta

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.ledger import DecisionLedger
from aegis_core.provenance import compute_provenance_hash
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


def test_tampered_constraint_is_discarded_and_intent_escalated():
    """REVIEW-4 T0.3: a discarded BLOCK rule fails closed to ESCALATE (it used
    to fail open to ALLOW), is never cited, and is explained in a note."""
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.constraints[constraint.id] = constraint
    constraint.rule_text = "attacker rewrote the rule after ingest"  # breaks the hash

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.covered is True
    assert decision.discarded == [{"id": "rule-1", "reason": "tampered"}]
    assert decision.citations == []
    assert decision.notes == ["fail-closed: rule-1 (tampered)"]


def test_revoked_principal_constraint_is_discarded_and_intent_escalated():
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    constraint = make_constraint(principal="sre_lead")
    store.constraints[constraint.id] = constraint

    # sre_lead was authorized for 'scaling' when ingested, but authority is
    # revoked before the decision is made.
    store.authority_map = {"admin": {"scaling", "deletion", "configuration"}}

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.discarded == [{"id": "rule-1", "reason": "unauthorized"}]
    assert decision.notes == ["fail-closed: rule-1 (unauthorized)"]


def test_discarded_rule_never_contributes_block_even_if_its_effect_was_block():
    store = ConstraintStore(authority_map=AUTHORITY)
    tampered = make_constraint(id="tampered-block", effect="BLOCK")
    store.constraints[tampered.id] = tampered
    tampered.rule_text = "edited"
    decision = AegisInterceptor(store).intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ESCALATE"


def test_valid_block_rule_still_outranks_a_discarded_one():
    store = ConstraintStore(authority_map=AUTHORITY)
    valid = make_constraint(id="valid-block", effect="BLOCK")
    tampered = make_constraint(id="tampered-escalate", effect="ESCALATE")
    store.constraints[valid.id] = valid
    store.constraints[tampered.id] = tampered
    tampered.rule_text = "edited"
    decision = AegisInterceptor(store).intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "BLOCK"
    assert decision.citations == ["valid-block"]
    assert decision.discarded == [{"id": "tampered-escalate", "reason": "tampered"}]


def test_quarantined_at_load_constraint_still_matches_and_escalates(tmp_path):
    """A rule quarantined by ConstraintStore.load (tampered on disk) is not
    forgotten: it is matched via store.quarantined_constraints and turns
    the decision into ESCALATE with the load-time reason."""
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="on-disk-block", effect="BLOCK"))
    path = tmp_path / "constraints.yaml"
    store.save(path)
    text = path.read_text()
    original = store.constraints["on-disk-block"].provenance_hash
    path.write_text(text.replace(original, original[:-1] + ("0" if original[-1] != "0" else "1")))

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY)
    assert reloaded.constraints == {}
    assert reloaded.quarantined == [{"id": "on-disk-block", "reason": "tampered"}]
    assert [c.id for c in reloaded.quarantined_constraints] == ["on-disk-block"]

    decision = AegisInterceptor(reloaded).intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.covered is True
    assert decision.discarded == [{"id": "on-disk-block", "reason": "tampered"}]
    assert decision.notes == ["fail-closed: on-disk-block (tampered)"]

    unrelated = InfrastructureIntent(resource="service/x", action="get", provider="kubernetes")
    assert AegisInterceptor(reloaded).intercept(unrelated, now=NOW).verdict == "ALLOW"


def test_fail_closed_escalates_uncovered_intents():
    store = ConstraintStore(authority_map=AUTHORITY)
    interceptor = AegisInterceptor(store, fail_closed=True)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.covered is False
    assert decision.notes == ["fail-closed: uncovered"]


def test_fail_closed_uncovered_dry_run_is_allowed_but_would_be_escalate():
    store = ConstraintStore(authority_map=AUTHORITY)
    interceptor = AegisInterceptor(store, fail_closed=True)
    dry = InfrastructureIntent(
        resource="deployment/x", action="scale", provider="kubernetes", params={"dry_run": True}
    )
    decision = interceptor.intercept(dry, now=NOW)
    assert decision.verdict == "ALLOW"
    assert decision.dry_run is True
    assert decision.would_be == "ESCALATE"


def test_fail_closed_does_not_change_a_covered_allow():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="other", resource_pattern="node/*"))
    interceptor = AegisInterceptor(store, fail_closed=False)
    assert interceptor.intercept(SCALE_INTENT, now=NOW).verdict == "ALLOW"


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


def test_non_dry_run_intent_has_dry_run_false_and_would_be_none():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.constraints[constraint.id] = constraint

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "BLOCK"
    assert decision.dry_run is False
    assert decision.would_be is None


def test_dry_run_intent_is_allowed_but_reports_would_be_block():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.constraints[constraint.id] = constraint

    dry_run_intent = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        params={"dry_run": True},
    )

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(dry_run_intent, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.dry_run is True
    assert decision.would_be == "BLOCK"
    assert decision.citations == ["rule-1"]
    assert decision.covered is True


def test_dry_run_intent_with_no_matching_constraint_is_allowed_and_uncovered():
    store = ConstraintStore(authority_map=AUTHORITY)
    interceptor = AegisInterceptor(store)

    dry_run_intent = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        params={"dry_run": True},
    )
    decision = interceptor.intercept(dry_run_intent, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.dry_run is True
    assert decision.would_be is None
    assert decision.covered is False


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


# --------------------------------------------------------------------------
# A2: rate/budget constraints (PLAN §7.6).
# --------------------------------------------------------------------------

RATE_INTENT_PROD = InfrastructureIntent(
    resource="deployment/api-server",
    action="scale",
    provider="kubernetes",
    metadata={"namespace": "prod"},
)

RATE_INTENT_STAGING = InfrastructureIntent(
    resource="deployment/api-server",
    action="scale",
    provider="kubernetes",
    metadata={"namespace": "staging"},
)


def make_rate_limited_constraint(**overrides) -> Constraint:
    return make_constraint(
        id="no-mass-scale",
        resource_pattern="deployment/*",
        scope={},
        rate_limit={"max": 3, "per": "1h", "key": ["namespace"]},
        **overrides,
    )


def test_first_n_matching_actions_allow_then_nth_plus_one_blocks():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    ledger = DecisionLedger()
    interceptor = AegisInterceptor(store, ledger=ledger)

    times = [NOW + timedelta(minutes=i) for i in range(4)]
    decisions = [interceptor.intercept(RATE_INTENT_PROD, now=t) for t in times]

    assert [d.verdict for d in decisions] == ["ALLOW", "ALLOW", "ALLOW", "BLOCK"]
    assert decisions[3].citations == ["no-mass-scale"]
    assert decisions[3].notes == ["rate-limit: no-mass-scale 3/3 in 1h"]
    assert decisions[0].notes == []


def test_rate_limit_is_bucketed_by_key_so_other_bucket_is_unaffected():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    ledger = DecisionLedger()
    interceptor = AegisInterceptor(store, ledger=ledger)

    for i in range(3):
        d = interceptor.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=i))
        assert d.verdict == "ALLOW"

    # 4th prod scale is blocked...
    blocked = interceptor.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=3))
    assert blocked.verdict == "BLOCK"

    # ...but a staging scale is a different bucket and is unaffected.
    allowed = interceptor.intercept(RATE_INTENT_STAGING, now=NOW + timedelta(minutes=4))
    assert allowed.verdict == "ALLOW"


def test_rate_limit_window_expires():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    ledger = DecisionLedger()
    interceptor = AegisInterceptor(store, ledger=ledger)

    base = NOW
    for i in range(3):
        d = interceptor.intercept(RATE_INTENT_PROD, now=base + timedelta(minutes=i))
        assert d.verdict == "ALLOW"

    # Well past the 1h window: the quota has reset.
    later = base + timedelta(hours=2)
    decision = interceptor.intercept(RATE_INTENT_PROD, now=later)
    assert decision.verdict == "ALLOW"


def test_rate_limit_without_ledger_never_fires():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    interceptor = AegisInterceptor(store)  # no ledger attached

    for i in range(5):
        decision = interceptor.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=i))
        assert decision.verdict == "ALLOW"
        assert decision.notes == []


def test_dry_runs_are_not_recorded_into_the_ledger():
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    ledger = DecisionLedger()
    interceptor = AegisInterceptor(store, ledger=ledger)

    dry_run_intent = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        metadata={"namespace": "prod"},
        params={"dry_run": True},
    )
    for i in range(5):
        decision = interceptor.intercept(dry_run_intent, now=NOW + timedelta(minutes=i))
        assert decision.verdict == "ALLOW"
        assert decision.dry_run is True

    assert ledger.count(since=NOW - timedelta(hours=1)) == 0


def test_non_dry_run_allow_is_recorded_blocked_actions_are_not():
    store = ConstraintStore(authority_map=AUTHORITY)
    block_all = make_constraint(
        id="block-all", resource_pattern="deployment/*", scope={}, effect="BLOCK"
    )
    store.add_constraint(block_all)
    ledger = DecisionLedger()
    interceptor = AegisInterceptor(store, ledger=ledger)

    blocked_intent = InfrastructureIntent(
        resource="deployment/api-server", action="scale", provider="kubernetes"
    )
    decision = interceptor.intercept(blocked_intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert ledger.count(since=NOW - timedelta(hours=1)) == 0

    uncovered_intent = InfrastructureIntent(
        resource="service/frontend", action="get", provider="kubernetes"
    )
    decision = interceptor.intercept(uncovered_intent, now=NOW)
    assert decision.verdict == "ALLOW"
    assert ledger.count(since=NOW - timedelta(hours=1)) == 1


def test_rate_limited_constraint_round_trips_through_save_and_load(tmp_path):
    constraint = make_rate_limited_constraint()
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(constraint)

    path = tmp_path / "constraints.yaml"
    store.save(path)

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY)
    reloaded_constraint = reloaded.constraints["no-mass-scale"]

    assert reloaded_constraint.rate_limit == {"max": 3, "per": "1h", "key": ["namespace"]}
    assert reloaded_constraint.provenance_hash == constraint.provenance_hash
    assert reloaded_constraint.verify_integrity() is True


def test_constraint_without_rate_limit_has_unchanged_hash():
    # Precomputed literal from running compute_provenance_hash() BEFORE the
    # rate_limit field/kwarg existed, for these exact source fields -- this
    # pins that adding rate_limit=None never perturbs a pre-existing hash.
    expected = (
        "eda49ce26152165fb4e061dcc01ea0025f3718ef46740da6362dd0ef29957c6e"
    )
    computed = compute_provenance_hash(
        provider="kubernetes",
        resource_pattern="node/*",
        actions={"scale"},
        scope={},
        time_window=None,
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="no-scaling",
    )
    assert computed == expected

    constraint = make_constraint(
        id="test-1",
        provider="kubernetes",
        resource_pattern="node/*",
        rule_text="no-scaling",
    )
    assert constraint.provenance_hash == expected
