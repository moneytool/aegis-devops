from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.plan import (
    PlanConstraint,
    PlanConstraintStore,
    compute_plan_provenance_hash,
    evaluate_plan,
)
from aegis_core.store import ConstraintStore

NOW = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)

AUTHORITY = {
    "admin": {"scaling", "deletion", "configuration"},
    "sre_lead": {"scaling", "configuration"},
    "developer": {"configuration"},
}


def make_pc(**overrides) -> PlanConstraint:
    defaults = dict(
        id="pc-1",
        provider="terraform",
        effect="BLOCK",
        constraint_class="deletion",
        principal="admin",
        source_ref="plan-9001",
        source_timestamp="2026-04-01T00:00:00+00:00",
        rule_text="Test plan constraint.",
    )
    defaults.update(overrides)
    return PlanConstraint.create(**defaults)


def tf_intent(action, resource, **params_or_meta):
    # split kwargs into params vs metadata: everything goes into params
    # unless explicitly passed as metadata=
    metadata = params_or_meta.pop("metadata", None) or {}
    return InfrastructureIntent(
        resource=resource,
        action=action,
        provider="terraform",
        params=params_or_meta,
        metadata=metadata,
    )


def k8s_intent(action, resource, **params_or_meta):
    metadata = params_or_meta.pop("metadata", None) or {}
    return InfrastructureIntent(
        resource=resource,
        action=action,
        provider="kubernetes",
        params=params_or_meta,
        metadata=metadata,
    )


def empty_interceptor():
    store = ConstraintStore(authority_map=AUTHORITY)
    return AegisInterceptor(store)


# ---------------------------------------------------------------------------
# max_intents
# ---------------------------------------------------------------------------


def test_max_intents_fires_over_boundary():
    pc = make_pc(
        effect="ESCALATE", constraint_class="configuration", principal="sre_lead", max_intents=2
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", f"aws_instance.i{i}") for i in range(3)]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.citations == ["pc-1"]
    assert decision.n_intents == 3
    assert any(n.startswith("max_intents: 3 > 2") for n in decision.notes)


def test_max_intents_does_not_fire_at_boundary():
    pc = make_pc(
        effect="ESCALATE", constraint_class="configuration", principal="sre_lead", max_intents=3
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", f"aws_instance.i{i}") for i in range(3)]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.citations == []


# ---------------------------------------------------------------------------
# max_matching
# ---------------------------------------------------------------------------


def test_max_matching_fires_when_over_limit():
    pc = make_pc(
        max_matching={
            "actions": ["delete", "replace"],
            "resource_pattern": "aws_db_instance.*",
            "max": 0,
        }
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [
        tf_intent("delete", "aws_db_instance.primary"),
        tf_intent("create", "aws_instance.web"),
    ]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "BLOCK"
    assert decision.citations == ["pc-1"]
    assert any("max_matching: 1" in n for n in decision.notes)


def test_max_matching_does_not_fire_when_no_matches():
    pc = make_pc(
        max_matching={
            "actions": ["delete", "replace"],
            "resource_pattern": "aws_db_instance.*",
            "max": 0,
        }
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.citations == []


# ---------------------------------------------------------------------------
# requires_all / forbid_together
# ---------------------------------------------------------------------------


def test_forbid_together_fires_when_all_selectors_match():
    pc = make_pc(
        forbid_together=[
            {"actions": ["delete"], "scope": {"region": "us-east-1"}},
            {"actions": ["create"]},
        ]
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [
        tf_intent("delete", "aws_instance.old", region="us-east-1"),
        tf_intent("create", "aws_instance.new"),
    ]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "BLOCK"
    assert decision.citations == ["pc-1"]


def test_forbid_together_does_not_fire_when_one_selector_unmatched():
    pc = make_pc(
        forbid_together=[
            {"actions": ["delete"], "scope": {"region": "us-east-1"}},
            {"actions": ["create"]},
        ]
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    # delete is in us-west-2, not us-east-1 -- selector 1 never matches
    intents = [
        tf_intent("delete", "aws_instance.old", region="us-west-2"),
        tf_intent("create", "aws_instance.new"),
    ]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.citations == []


def test_requires_all_alias_uses_same_code_path():
    pc = make_pc(
        requires_all=[
            {"actions": ["delete"]},
            {"actions": ["create"]},
        ]
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("delete", "aws_instance.old"), tf_intent("create", "aws_instance.new")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "BLOCK"


# ---------------------------------------------------------------------------
# ratio
# ---------------------------------------------------------------------------


def test_ratio_fires_over_boundary():
    pc = make_pc(
        provider="kubernetes",
        effect="ESCALATE",
        ratio={"numerator": {"actions": ["delete"]}, "denominator": {}, "max": 0.5},
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    # 2 of 3 = 0.667 > 0.5
    intents = [
        k8s_intent("delete", "pod/a"),
        k8s_intent("delete", "pod/b"),
        k8s_intent("get", "pod/c"),
    ]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.citations == ["pc-1"]
    assert any("ratio: 2/3" in n for n in decision.notes)


def test_ratio_does_not_fire_at_boundary():
    pc = make_pc(
        provider="kubernetes",
        effect="ESCALATE",
        ratio={"numerator": {"actions": ["delete"]}, "denominator": {}, "max": 0.5},
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    # 1 of 2 = 0.5, not > 0.5
    intents = [k8s_intent("delete", "pod/a"), k8s_intent("get", "pod/b")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"


def test_ratio_with_zero_denominator_does_not_fire():
    pc = make_pc(
        provider="kubernetes",
        effect="ESCALATE",
        ratio={
            "numerator": {"actions": ["delete"]},
            "denominator": {"actions": ["nonexistent"]},
            "max": 0.5,
        },
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [k8s_intent("delete", "pod/a")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# provider filter
# ---------------------------------------------------------------------------


def test_provider_mismatch_is_skipped_not_discarded():
    pc = make_pc(provider="kubernetes", max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.discarded == []
    assert decision.citations == []


def test_wildcard_provider_applies_to_any_provider():
    pc = make_pc(provider="*", max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "BLOCK"
    assert decision.citations == ["pc-1"]


# ---------------------------------------------------------------------------
# integrity / authority discards
# ---------------------------------------------------------------------------


def test_tampered_plan_constraint_is_discarded():
    pc = make_pc(max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.constraints[pc.id] = pc
    pc.rule_text = "attacker rewrote this after ingest"  # breaks the hash

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "pc-1", "reason": "tampered"}]
    assert decision.citations == []


def test_unauthorized_plan_constraint_is_discarded_when_revoked_after_load():
    pc = make_pc(max_intents=0, principal="admin", constraint_class="deletion")
    store = PlanConstraintStore(authority_map=dict(AUTHORITY))
    store.constraints[pc.id] = pc  # bypass add() authority check, simulating a load

    # admin was authorized for 'deletion' at ingest time, but authority is
    # revoked before the decision is made.
    store.authority_map = {"sre_lead": {"scaling", "configuration"}}

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "pc-1", "reason": "unauthorized"}]


def test_add_raises_permission_error_for_unauthorized_principal():
    pc = make_pc(principal="developer", constraint_class="deletion")
    store = PlanConstraintStore(authority_map=AUTHORITY)

    try:
        store.add(pc)
        assert False, "expected PermissionError"
    except PermissionError:
        pass


# ---------------------------------------------------------------------------
# aggregation: BLOCK > ESCALATE, per-intent + plan-level
# ---------------------------------------------------------------------------


def test_block_outranks_escalate_across_per_intent_and_plan_level():
    inner_store = ConstraintStore(authority_map=AUTHORITY)
    from aegis_core.store import Constraint

    inner_store.add_constraint(
        Constraint.create(
            id="intent-block",
            provider="terraform",
            resource_pattern="aws_db_instance.*",
            actions={"delete"},
            effect="BLOCK",
            constraint_class="deletion",
            principal="admin",
            source_ref="git-abc",
            source_timestamp="2026-01-01T00:00:00+00:00",
            rule_text="Never delete DB instances directly.",
        )
    )
    interceptor = AegisInterceptor(inner_store)

    plan_pc = make_pc(
        effect="ESCALATE", constraint_class="configuration", principal="sre_lead", max_intents=1
    )
    plan_store = PlanConstraintStore(authority_map=AUTHORITY)
    plan_store.add(plan_pc)

    intents = [
        tf_intent("delete", "aws_db_instance.primary"),
        tf_intent("create", "aws_instance.web"),
    ]
    decision = evaluate_plan(interceptor, plan_store, intents, now=NOW)

    assert decision.verdict == "BLOCK"
    assert "intent-block" in decision.citations
    assert "pc-1" in decision.citations
    assert len(decision.per_intent) == 2


# ---------------------------------------------------------------------------
# dry-run
# ---------------------------------------------------------------------------


def test_all_dry_run_batch_allows_with_would_be_note():
    pc = make_pc(max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [tf_intent("create", "aws_instance.web", dry_run=True)]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert any(n.startswith("would_be: BLOCK") for n in decision.notes)
    assert decision.citations == ["pc-1"]


def test_partial_dry_run_batch_is_not_downgraded():
    pc = make_pc(max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)

    intents = [
        tf_intent("create", "aws_instance.web", dry_run=True),
        tf_intent("create", "aws_instance.web2"),
    ]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "BLOCK"


# ---------------------------------------------------------------------------
# provenance hash / save-load round trip
# ---------------------------------------------------------------------------


def test_compute_plan_provenance_hash_is_deterministic():
    kwargs = dict(
        provider="terraform",
        effect="BLOCK",
        constraint_class="deletion",
        principal="admin",
        source_ref="plan-9001",
        source_timestamp="2026-04-01T00:00:00+00:00",
        rule_text="Test.",
        max_intents=5,
    )
    assert compute_plan_provenance_hash(**kwargs) == compute_plan_provenance_hash(**kwargs)


def test_verify_integrity_detects_tampering():
    pc = make_pc(max_intents=5)
    assert pc.verify_integrity() is True
    pc.max_intents = 6
    assert pc.verify_integrity() is False


def test_save_load_round_trip_preserves_hashes(tmp_path):
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(make_pc(id="pc-a", max_intents=10))
    store.add(make_pc(id="pc-b", max_matching={"actions": ["delete"], "max": 1}))

    path = tmp_path / "plan_constraints.yaml"
    store.save(path)

    reloaded = PlanConstraintStore.load(path, authority_map=AUTHORITY)

    assert reloaded.quarantined == []
    assert set(reloaded.constraints) == {"pc-a", "pc-b"}
    for cid, pc in reloaded.constraints.items():
        assert pc.verify_integrity() is True
        assert pc.provenance_hash == store.constraints[cid].provenance_hash


def test_example_file_loads_with_zero_quarantined():
    store = PlanConstraintStore.load("data/plan_constraints.example.yaml", authority_map=AUTHORITY)
    assert store.quarantined == []
    assert len(store.constraints) == 4
    for pc in store.constraints.values():
        assert pc.verify_integrity() is True


# ---------------------------------------------------------------------------
# end to end: 30-resource terraform plan with 2 aws_db_instance deletes
# ---------------------------------------------------------------------------


def test_end_to_end_30_resource_plan_with_db_deletes_blocks_and_cites_both_rules():
    store = PlanConstraintStore.load("data/plan_constraints.example.yaml", authority_map=AUTHORITY)
    interceptor = empty_interceptor()

    intents = [tf_intent("create", f"aws_instance.i{i}") for i in range(28)]
    intents.append(tf_intent("delete", "aws_db_instance.primary"))
    intents.append(tf_intent("delete", "aws_db_instance.replica"))
    assert len(intents) == 30

    decision = evaluate_plan(interceptor, store, intents, now=NOW)

    assert decision.verdict == "BLOCK"
    assert "plan-no-db-deletes" in decision.citations
    assert "plan-max-25-resources" in decision.citations
    assert decision.n_intents == 30
