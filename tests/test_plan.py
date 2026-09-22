from datetime import UTC, datetime

import pytest

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


def test_tampered_plan_constraint_is_discarded_and_fails_closed():
    """REVIEW-4 T0.3: a discarded BLOCK/ESCALATE plan rule whose predicate
    fires contributes ESCALATE (it used to fail open to ALLOW)."""
    pc = make_pc(max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.constraints[pc.id] = pc
    pc.rule_text = "attacker rewrote this after ingest"  # breaks the hash

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.discarded == [{"id": "pc-1", "reason": "tampered"}]
    assert decision.citations == []
    assert decision.notes == ["fail-closed: pc-1 (tampered)"]


def test_unauthorized_plan_constraint_is_discarded_when_revoked_after_load():
    pc = make_pc(max_intents=0, principal="admin", constraint_class="deletion")
    store = PlanConstraintStore(authority_map=dict(AUTHORITY))
    store.constraints[pc.id] = pc  # bypass add() authority check, simulating a load

    # admin was authorized for 'deletion' at ingest time, but authority is
    # revoked before the decision is made.
    store.authority_map = {"sre_lead": {"scaling", "configuration"}}

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ESCALATE"
    assert decision.discarded == [{"id": "pc-1", "reason": "unauthorized"}]
    assert decision.notes == ["fail-closed: pc-1 (unauthorized)"]


def test_discarded_plan_constraint_whose_predicate_does_not_fire_stays_allow():
    pc = make_pc(max_intents=10)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.constraints[pc.id] = pc
    pc.rule_text = "edited"

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), store, intents, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "pc-1", "reason": "tampered"}]
    assert decision.notes == []


def test_quarantined_at_load_plan_constraint_is_evaluated_and_fails_closed(tmp_path):
    pc = make_pc(max_intents=0)
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.constraints[pc.id] = pc
    path = tmp_path / "plan_constraints.yaml"
    store.save(path)
    text = path.read_text()
    path.write_text(text.replace(pc.provenance_hash, pc.provenance_hash[:-1] + "x"))

    reloaded = PlanConstraintStore.load(path, authority_map=AUTHORITY)
    assert reloaded.constraints == {}
    assert reloaded.quarantined == [{"id": "pc-1", "reason": "tampered"}]
    assert [q.id for q in reloaded.quarantined_constraints] == ["pc-1"]
    assert reloaded.health.loaded == 0
    assert reloaded.health.quarantined == [{"id": "pc-1", "reason": "tampered"}]
    assert len(reloaded.health.constraints_sha256) == 64

    intents = [tf_intent("create", "aws_instance.web")]
    decision = evaluate_plan(empty_interceptor(), reloaded, intents, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.notes == ["fail-closed: pc-1 (tampered)"]


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


# ---------------------------------------------------------------------------
# REVIEW-4 T1.1 / T1.8 / T1.5: signed load, validation, scope matching
# ---------------------------------------------------------------------------


def _pc_entry(**overrides):
    pc = make_pc(max_intents=25)
    entry = {
        "id": pc.id, "provider": pc.provider, "effect": pc.effect,
        "constraint_class": pc.constraint_class, "principal": pc.principal,
        "source_ref": pc.source_ref, "source_timestamp": pc.source_timestamp,
        "rule_text": pc.rule_text, "provenance_hash": pc.provenance_hash,
        "max_intents": pc.max_intents,
    }
    entry.update(overrides)
    return entry


def _load_entries(tmp_path, *entries):
    import yaml

    path = tmp_path / "plan_constraints.yaml"
    path.write_text(yaml.safe_dump({"plan_constraints": list(entries)}, sort_keys=False))
    return PlanConstraintStore.load(path, authority_map=AUTHORITY, insecure=True)


def test_plan_store_signed_load_and_signature_errors(tmp_path):
    from aegis_core.signing import SignatureError, sign_file

    key = b"k" * 32
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(make_pc(max_intents=25))
    path = tmp_path / "plan_constraints.yaml"
    store.save(path)
    with pytest.raises(SignatureError, match="unsigned"):
        PlanConstraintStore.load(path, authority_map=AUTHORITY, key=key)
    assert PlanConstraintStore.load(path, authority_map=AUTHORITY).health.warnings == [
        f"unsigned: {path}"
    ]
    sign_file(path, key)
    reloaded = PlanConstraintStore.load(path, authority_map=AUTHORITY, key=key)
    assert reloaded.health.loaded == 1 and reloaded.health.warnings == []
    path.write_text(path.read_text().replace("max_intents: 25", "max_intents: 250"))
    with pytest.raises(SignatureError, match="bad signature"):
        PlanConstraintStore.load(path, authority_map=AUTHORITY, key=key)


def test_example_plan_file_verifies_under_example_key():
    from aegis_core.signing import load_key

    key = load_key("file:data/example-signing.key")
    store = PlanConstraintStore.load(
        "data/plan_constraints.example.yaml", authority_map=AUTHORITY, key=key
    )
    assert store.health.loaded == 4 and store.health.warnings == []


def test_plan_constraint_post_init_rejects_invalid_effect():
    with pytest.raises(ValueError, match="effect must be BLOCK or ESCALATE"):
        make_pc(effect="Block")


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"effect": "Block"}, "invalid: effect must be BLOCK or ESCALATE, got 'Block'"),
        ({"provider": ""}, "invalid: provider must be a non-empty string"),
        ({"provider": None}, "invalid: missing provider"),
        ({"max_intents": "25"}, "invalid: max_intents must be a non-negative integer"),
        ({"max_intents": -1}, "invalid: max_intents must be a non-negative integer"),
        ({"max_intents": None}, "invalid: one predicate is required (max_intents, "
                                "max_matching, requires_all, forbid_together, ratio)"),
        ({"max_matching": {"actions": "delete", "max": 0}},
         "invalid: max_matching.actions must be a list of strings"),
        ({"max_matching": {"actions": ["delete"]}},
         "invalid: max_matching.max must be a non-negative integer"),
        ({"max_matching": ["delete"]}, "invalid: max_matching must be a mapping"),
        ({"requires_all": []}, "invalid: requires_all must be a non-empty list of selectors"),
        ({"forbid_together": [{"scope": "prod"}]},
         "invalid: forbid_together[0].scope must be a mapping"),
        ({"ratio": {"numerator": [], "denominator": {}}},
         "invalid: ratio.numerator must be a mapping"),
        ({"ratio": {"numerator": {}, "denominator": {}, "max": "half"}},
         "invalid: ratio.max must be a number"),
    ],
)
def test_each_invalid_plan_shape_is_quarantined(tmp_path, overrides, reason):
    store = _load_entries(tmp_path, _pc_entry(**overrides))
    assert store.constraints == {}
    assert store.quarantined_constraints == []
    assert store.quarantined == [{"id": "pc-1", "reason": reason}]


def test_plan_missing_key_and_duplicate_id_and_non_mapping(tmp_path):
    entry = _pc_entry()
    del entry["principal"]
    store = _load_entries(tmp_path, entry, "nope", _pc_entry(), _pc_entry())
    assert store.quarantined == [
        {"id": "pc-1", "reason": "invalid: missing principal"},
        {"id": "<no id>", "reason": "invalid: entry must be a mapping"},
        {"id": "pc-1", "reason": "invalid: duplicate id"},
    ]
    assert list(store.constraints) == ["pc-1"]


def test_plan_selector_scope_uses_metadata_first_and_coercion():
    """Same T1.5 semantics as the per-intent store: metadata.env beats
    params.env, ints match strings, lists are ORs, globs and dotted paths."""
    pc = make_pc(
        provider="kubernetes",
        max_matching={"actions": ["delete"], "scope": {"env": "prod"}, "max": 0},
    )
    store = PlanConstraintStore(authority_map=AUTHORITY)
    store.add(pc)
    shadowed = k8s_intent("delete", "pod/x", env="dev", metadata={"env": "prod"})
    decision = evaluate_plan(empty_interceptor(), store, [shadowed], now=NOW)
    assert decision.verdict == "BLOCK"

    pc2 = make_pc(
        id="pc-2",
        provider="kubernetes",
        max_matching={"scope": {"account": 123456789012, "set.replicaCount": ["0", 1],
                                "namespace": "prod-*"}, "max": 0},
    )
    store2 = PlanConstraintStore(authority_map=AUTHORITY)
    store2.add(pc2)
    hit = k8s_intent("scale", "deployment/x", set={"replicaCount": 0},
                     metadata={"account": "123456789012", "namespace": "prod-eu"})
    miss = k8s_intent("scale", "deployment/x", set={"replicaCount": 3},
                      metadata={"account": "123456789012", "namespace": "prod-eu"})
    assert evaluate_plan(empty_interceptor(), store2, [hit], now=NOW).verdict == "BLOCK"
    assert evaluate_plan(empty_interceptor(), store2, [miss], now=NOW).verdict == "ALLOW"


# --- REVIEW-4 T1.3 / T1.6: selector aliases and env-unresolved selectors ------------


def test_max_matching_selector_matches_module_stripped_alias():
    from aegis_core.parser import from_terraform_plan

    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "module.app.aws_db_instance.main",
                "module_address": "module.app",
                "type": "aws_db_instance",
                "name": "main",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["delete"], "before": {"region": "us-east-1"},
                           "after": None},
            }
        ],
    }
    pc = make_pc(max_matching={"actions": ["delete"], "resource_pattern": "aws_db_instance.*",
                               "max": 0})
    plan_store = PlanConstraintStore(authority_map=AUTHORITY)
    plan_store.constraints[pc.id] = pc
    intents = from_terraform_plan(plan)
    assert intents[0].metadata["plan_sha256"] and len(intents[0].metadata["plan_sha256"]) == 64
    decision = evaluate_plan(empty_interceptor(), plan_store, intents, now=NOW)
    assert decision.verdict == "BLOCK"
    assert decision.citations == [pc.id]


def test_env_scoped_selector_with_unresolved_env_escalates():
    pc = make_pc(provider="kubernetes",
                 max_matching={"actions": ["delete"], "scope": {"env": "prod"}, "max": 0})
    plan_store = PlanConstraintStore(authority_map=AUTHORITY)
    plan_store.constraints[pc.id] = pc
    unresolved = [k8s_intent("delete", "pod/x", metadata={"namespace": "prod"})]
    decision = evaluate_plan(empty_interceptor(), plan_store, unresolved, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert decision.notes == [f"env-unresolved: {pc.id}"]
    assert decision.citations == [pc.id]
    resolved = [k8s_intent("delete", "pod/x", metadata={"env": "dev"})]
    decision = evaluate_plan(empty_interceptor(), plan_store, resolved, now=NOW)
    assert decision.verdict == "ALLOW" and decision.notes == []
    prod = [k8s_intent("delete", "pod/x", metadata={"env": "prod"})]
    assert evaluate_plan(empty_interceptor(), plan_store, prod, now=NOW).verdict == "BLOCK"
