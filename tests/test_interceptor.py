from datetime import UTC, datetime, timedelta

import pytest

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.ledger import DecisionLedger, JsonlLedger
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


def test_bogus_on_untrusted_match_value_raises_value_error():
    store = ConstraintStore(authority_map=AUTHORITY)
    with pytest.raises(ValueError):
        AegisInterceptor(store, on_untrusted_match="bogus")


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


def test_tampered_constraint_is_discarded_and_gets_no_vote_by_default():
    """A matching-but-tampered constraint gets no vote by default: the
    verdict is exactly what it would be with the poisoned rule absent
    (here, ALLOW -- nothing else matches), but it's still visible in
    ``discarded`` and there is no fail-closed note."""
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
    assert decision.notes == []


def test_tampered_constraint_escalates_under_on_untrusted_match_escalate():
    """REVIEW-4 T0.3's original fail-closed behaviour is still available,
    opt-in via on_untrusted_match='escalate'."""
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.constraints[constraint.id] = constraint
    constraint.rule_text = "attacker rewrote the rule after ingest"  # breaks the hash

    interceptor = AegisInterceptor(store, on_untrusted_match="escalate")
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"
    assert decision.covered is True
    assert decision.discarded == [{"id": "rule-1", "reason": "tampered"}]
    assert decision.citations == []
    assert decision.notes == ["fail-closed: rule-1 (tampered)"]


def test_decision_time_integrity_check_catches_a_post_load_in_memory_mutation(tmp_path):
    """REVIEW-4 L4: interceptor.py re-verifies each matched constraint's
    integrity at decision time even though ConstraintStore.load already did
    so for every constraint that survived loading. That is not redundant:
    a library caller holding a reference to a live Constraint object can
    mutate one of its fields *after* a successful load, and only the
    decision-time check -- which runs on every intercept() call, not just
    once at load -- can catch it. Prove it by loading a perfectly valid
    on-disk constraint (load-time verify_integrity necessarily passes,
    since nothing is wrong yet), then mutating the in-memory object
    in place before deciding."""
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="on-disk-block", effect="BLOCK"))
    path = tmp_path / "constraints.yaml"
    store.save(path)

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY)
    # Load-time verification passed: the constraint is live, not quarantined.
    assert reloaded.quarantined == []
    assert "on-disk-block" in reloaded.constraints

    # A library caller mutates the in-memory object after load -- e.g.
    # widening what it blocks -- with no further disk or load involved.
    reloaded.constraints["on-disk-block"].actions = {"scale", "delete"}

    # The default (discard) gives the mutated rule no vote, but the
    # decision-time check still CATCHES the mutation: it lands in
    # discarded[] with reason "tampered", which is what proves the check
    # ran at all -- the verdict just doesn't change because of it.
    decision = AegisInterceptor(reloaded).intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "on-disk-block", "reason": "tampered"}]
    assert decision.notes == []

    # Under on_untrusted_match="escalate" the same catch still fails closed.
    escalating = AegisInterceptor(reloaded, on_untrusted_match="escalate").intercept(
        SCALE_INTENT, now=NOW
    )
    assert escalating.verdict == "ESCALATE"
    assert escalating.discarded == [{"id": "on-disk-block", "reason": "tampered"}]
    assert escalating.notes == ["fail-closed: on-disk-block (tampered)"]


def test_revoked_principal_constraint_is_discarded_and_gets_no_vote_by_default():
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
    assert decision.notes == []


def test_revoked_principal_constraint_escalates_under_on_untrusted_match_escalate():
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    constraint = make_constraint(principal="sre_lead")
    store.constraints[constraint.id] = constraint
    store.authority_map = {"admin": {"scaling", "deletion", "configuration"}}

    interceptor = AegisInterceptor(store, on_untrusted_match="escalate")
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.discarded == [{"id": "rule-1", "reason": "unauthorized"}]
    assert decision.notes == ["fail-closed: rule-1 (unauthorized)"]


def test_discarded_rule_gets_no_vote_by_default_even_if_its_effect_was_block():
    store = ConstraintStore(authority_map=AUTHORITY)
    tampered = make_constraint(id="tampered-block", effect="BLOCK")
    store.constraints[tampered.id] = tampered
    tampered.rule_text = "edited"
    decision = AegisInterceptor(store).intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ALLOW"


def test_discarded_rule_under_escalate_mode_escalates_but_never_blocks():
    store = ConstraintStore(authority_map=AUTHORITY)
    tampered = make_constraint(id="tampered-block", effect="BLOCK")
    store.constraints[tampered.id] = tampered
    tampered.rule_text = "edited"
    decision = AegisInterceptor(store, on_untrusted_match="escalate").intercept(
        SCALE_INTENT, now=NOW
    )
    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"


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


def test_quarantined_at_load_constraint_still_matches_and_gets_no_vote_by_default(tmp_path):
    """A rule quarantined by ConstraintStore.load (tampered on disk) is not
    forgotten: it is matched via store.quarantined_constraints and reported
    in discarded[] and StoreHealth.quarantined, but by default it doesn't
    change the verdict -- the matching intent is ALLOWed exactly as if the
    poisoned rule had never existed."""
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
    assert decision.verdict == "ALLOW"
    assert decision.covered is True
    assert decision.discarded == [{"id": "on-disk-block", "reason": "tampered"}]
    assert decision.notes == []

    unrelated = InfrastructureIntent(resource="service/x", action="get", provider="kubernetes")
    assert AegisInterceptor(reloaded).intercept(unrelated, now=NOW).verdict == "ALLOW"


def test_quarantined_at_load_constraint_escalates_under_on_untrusted_match_escalate(tmp_path):
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="on-disk-block", effect="BLOCK"))
    path = tmp_path / "constraints.yaml"
    store.save(path)
    text = path.read_text()
    original = store.constraints["on-disk-block"].provenance_hash
    path.write_text(text.replace(original, original[:-1] + ("0" if original[-1] != "0" else "1")))

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY)
    assert reloaded.quarantined == [{"id": "on-disk-block", "reason": "tampered"}]

    interceptor = AegisInterceptor(reloaded, on_untrusted_match="escalate")
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"
    assert decision.covered is True
    assert decision.discarded == [{"id": "on-disk-block", "reason": "tampered"}]
    assert decision.notes == ["fail-closed: on-disk-block (tampered)"]

    unrelated = InfrastructureIntent(resource="service/x", action="get", provider="kubernetes")
    assert interceptor.intercept(unrelated, now=NOW).verdict == "ALLOW"


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


# --------------------------------------------------------------------------
# T1.9: ledger locking/rotation/resource-bucketing/chain-verification, as
# seen from the interceptor.
# --------------------------------------------------------------------------


def test_rate_limit_buckets_by_resource_key(tmp_path):
    """``key: [resource]`` must bucket on the concrete intent resource, not
    the (often shared) constraint resource_pattern -- so two resources
    matched by the same pattern get independent quotas."""
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(
        make_constraint(
            id="per-container-cap",
            resource_pattern="container/cluster/*",
            scope={},
            rate_limit={"max": 1, "per": "1h", "key": ["resource"]},
        )
    )
    ledger = JsonlLedger(tmp_path / "ledger.jsonl")
    interceptor = AegisInterceptor(store, ledger=ledger)

    intent_1 = InfrastructureIntent(
        resource="container/cluster/prod-1", action="scale", provider="kubernetes"
    )
    intent_2 = InfrastructureIntent(
        resource="container/cluster/prod-2", action="scale", provider="kubernetes"
    )

    first = interceptor.intercept(intent_1, now=NOW)
    assert first.verdict == "ALLOW"

    # Same resource again: quota (max 1) is used up.
    second = interceptor.intercept(intent_1, now=NOW + timedelta(minutes=1))
    assert second.verdict == "BLOCK"

    # A different resource is a different bucket, unaffected.
    third = interceptor.intercept(intent_2, now=NOW + timedelta(minutes=2))
    assert third.verdict == "ALLOW"


def test_broken_ledger_chain_escalates_rate_limited_constraints(tmp_path):
    """T1.9 accept: a truncated ledger sets ``chain_ok = False``, and every
    rate-limited constraint is then treated as exhausted -- ESCALATE, with
    an explanatory note, never BLOCK even when the constraint's own effect
    is BLOCK."""
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())  # effect="BLOCK" by default
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    interceptor = AegisInterceptor(store, ledger=ledger)

    # Establish some history, then truncate the file so the chain breaks.
    for i in range(2):
        d = interceptor.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=i))
        assert d.verdict == "ALLOW"

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[1:]) + "\n")  # drop the first line

    decision = interceptor.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=5))

    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"
    assert "ledger: chain-broken" in decision.notes


def test_rate_limit_survives_reload_via_jsonl_ledger(tmp_path):
    """A fresh interceptor/ledger pair backed by the same file continues
    counting where a previous process left off (load -> count -> record)."""
    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_rate_limited_constraint())
    path = tmp_path / "ledger.jsonl"

    ledger_a = JsonlLedger(path)
    interceptor_a = AegisInterceptor(store, ledger=ledger_a)
    for i in range(3):
        d = interceptor_a.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=i))
        assert d.verdict == "ALLOW"

    # A brand new process/interceptor instance, same file.
    ledger_b = JsonlLedger(path)
    interceptor_b = AegisInterceptor(store, ledger=ledger_b)
    decision = interceptor_b.intercept(RATE_INTENT_PROD, now=NOW + timedelta(minutes=3))
    assert decision.verdict == "BLOCK"


# --- REVIEW-4 T1.3 / T1.6 / T1.7: env-unresolved, resource aliases, unknown target -----


def _store_with(*constraints) -> ConstraintStore:
    store = ConstraintStore(authority_map=AUTHORITY)
    for c in constraints:
        store.constraints[c.id] = c
    return store


def test_missing_tzdata_escalates_a_time_windowed_rule_end_to_end():
    """REVIEW-4 L1: with tzdata unavailable, a time-windowed BLOCK rule
    that would otherwise match must not fail open to ALLOW -- the
    interceptor escalates via get_time_window_unresolved."""
    rule = make_constraint(
        id="peak-hours",
        actions={"scale"},
        time_window={"days": ["Mon"], "start": "09:00", "end": "17:00", "tz": "America/New_York"},
    )
    store = _store_with(rule)
    store.tzdata_available = False
    interceptor = AegisInterceptor(store)

    decision = interceptor.intercept(SCALE_INTENT, now=NOW)  # NOW is a Monday

    assert decision.verdict == "ESCALATE"
    assert decision.covered is True
    assert decision.citations == []
    assert decision.notes == ["time-window-unresolved: peak-hours"]


def test_env_scoped_rule_without_resolved_env_escalates_not_allows():
    rule = make_constraint(id="prod-only", actions={"delete"}, resource_pattern="*",
                           scope={"env": "prod"}, constraint_class="deletion",
                           principal="admin")
    interceptor = AegisInterceptor(_store_with(rule))
    intent = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes",
                                  metadata={"namespace": "prod"})
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.covered is True
    assert decision.citations == []
    assert decision.notes == ["env-unresolved: prod-only"]
    # An agent-supplied --env=prod in params does not count as a resolved env.
    intent.params["env"] = "dev"
    assert interceptor.intercept(intent, now=NOW).notes == ["env-unresolved: prod-only"]
    # With the env resolved (operator metadata) the rule matches normally ...
    intent.metadata["env"] = "prod"
    assert interceptor.intercept(intent, now=NOW).verdict == "BLOCK"
    # ... or is simply out of scope, with no note.
    intent.metadata["env"] = "dev"
    decision = interceptor.intercept(intent, now=NOW)
    assert (decision.verdict, decision.covered, decision.notes) == ("ALLOW", False, [])


def test_env_unresolved_requires_the_other_scope_keys_to_match():
    rule = make_constraint(id="prod-ns-only", actions={"delete"}, resource_pattern="*",
                           scope={"env": "prod", "namespace": "payments"},
                           constraint_class="deletion", principal="admin")
    interceptor = AegisInterceptor(_store_with(rule))
    other_ns = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes",
                                    metadata={"namespace": "scratch"})
    assert interceptor.intercept(other_ns, now=NOW).notes == []
    same_ns = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes",
                                   metadata={"namespace": "payments"})
    assert interceptor.intercept(same_ns, now=NOW).notes == ["env-unresolved: prod-ns-only"]


def test_env_unresolved_never_outranks_a_real_block_and_is_a_dry_run_would_be():
    prod_only = make_constraint(id="prod-only", actions={"delete"}, resource_pattern="*",
                                scope={"env": "prod"}, constraint_class="deletion",
                                principal="admin")
    no_nodes = make_constraint(id="no-nodes", actions={"delete"}, resource_pattern="node/*",
                               constraint_class="deletion", principal="admin")
    interceptor = AegisInterceptor(_store_with(prod_only, no_nodes))
    intent = InfrastructureIntent(resource="node/w1", action="delete", provider="kubernetes")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK" and decision.citations == ["no-nodes"]
    assert "env-unresolved: prod-only" in decision.notes
    dry = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes",
                               params={"dry_run": True})
    decision = interceptor.intercept(dry, now=NOW)
    assert (decision.verdict, decision.would_be) == ("ALLOW", "ESCALATE")


def test_unknown_target_escalates_even_when_nothing_matches():
    main_only = make_constraint(id="no-force-main", provider="git", resource_pattern="ref/main",
                                actions={"push"}, scope={"force": True},
                                constraint_class="configuration")
    interceptor = AegisInterceptor(_store_with(main_only))
    intent = InfrastructureIntent(resource="ref/*", action="push", provider="git",
                                  params={"force": True, "unknown_target": True})
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.notes == ["unknown-target"]
    assert decision.covered is False
    known = InfrastructureIntent(resource="ref/main", action="push", provider="git",
                                 params={"force": True})
    assert interceptor.intercept(known, now=NOW).verdict == "BLOCK"


def test_git_push_force_without_refspec_is_escalated_end_to_end():
    from aegis_core.parser import from_git

    main_only = make_constraint(id="no-force-main", provider="git", resource_pattern="ref/main",
                                actions={"push"}, scope={"force": True},
                                constraint_class="configuration")
    interceptor = AegisInterceptor(_store_with(main_only))
    decision = interceptor.intercept(from_git(["git", "push", "-f"]), now=NOW)
    assert (decision.verdict, decision.notes) == ("ESCALATE", ["unknown-target"])


def test_resource_pattern_matches_module_stripped_terraform_alias():
    rule = make_constraint(id="no-db-deletes", provider="terraform",
                           resource_pattern="aws_db_instance.*", actions={"delete"},
                           constraint_class="deletion", principal="admin")
    interceptor = AegisInterceptor(_store_with(rule))
    nested = InfrastructureIntent(resource="module.app.aws_db_instance.main", action="delete",
                                  provider="terraform",
                                  metadata={"type_name": "aws_db_instance.main"})
    assert interceptor.intercept(nested, now=NOW).verdict == "BLOCK"
    assert nested.resource_aliases() == ["module.app.aws_db_instance.main",
                                         "aws_db_instance.main"]
    bare = InfrastructureIntent(resource="module.app.aws_db_instance.main", action="delete",
                                provider="terraform")
    assert interceptor.intercept(bare, now=NOW).verdict == "ALLOW"
