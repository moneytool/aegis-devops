from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.store import Constraint, ConstraintStore

NOON_UTC = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)  # a Monday


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


def test_action_substring_does_not_cause_a_false_match():
    """A rule about 'budget' must not match an intent with action='get'
    just because 'get' happens to be a substring of the rule text."""
    store = ConstraintStore()
    store.constraints["rule-1"] = make_constraint(
        rule_text="Track infrastructure budget carefully.",
        actions={"delete"},
        resource_pattern="deployment/*",
    )
    intent = InfrastructureIntent(resource="deployment/api", action="get", provider="kubernetes")
    assert store.get_matching_constraints(intent, NOON_UTC) == []


def test_resource_pattern_glob_matches_only_intended_resources():
    store = ConstraintStore()
    store.constraints["rule-1"] = make_constraint(resource_pattern="deployment/*")

    matching_intent = InfrastructureIntent(
        resource="deployment/api-server", action="scale", provider="kubernetes"
    )
    non_matching_intent = InfrastructureIntent(
        resource="service/api-server", action="scale", provider="kubernetes"
    )

    assert len(store.get_matching_constraints(matching_intent, NOON_UTC)) == 1
    assert store.get_matching_constraints(non_matching_intent, NOON_UTC) == []


def test_time_window_matches_inside_and_not_outside():
    store = ConstraintStore()
    store.constraints["rule-1"] = make_constraint(
        time_window={
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "start": "09:00",
            "end": "17:00",
            "tz": "UTC",
        }
    )
    intent = InfrastructureIntent(resource="deployment/api", action="scale", provider="kubernetes")

    inside = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)  # Monday, 10:00
    outside = datetime(2026, 1, 5, 3, 0, tzinfo=UTC)  # Monday, 03:00

    assert len(store.get_matching_constraints(intent, inside)) == 1
    assert store.get_matching_constraints(intent, outside) == []


def test_provider_mismatch_never_matches():
    store = ConstraintStore()
    store.constraints["rule-1"] = make_constraint(provider="terraform", resource_pattern="*")
    intent = InfrastructureIntent(resource="anything", action="scale", provider="kubernetes")
    assert store.get_matching_constraints(intent, NOON_UTC) == []


def test_scope_must_match_intent_params_or_metadata():
    store = ConstraintStore()
    store.constraints["rule-1"] = make_constraint(scope={"namespace": "prod"})

    prod_intent = InfrastructureIntent(
        resource="deployment/api", action="scale", provider="kubernetes",
        metadata={"namespace": "prod"},
    )
    staging_intent = InfrastructureIntent(
        resource="deployment/api", action="scale", provider="kubernetes",
        metadata={"namespace": "staging"},
    )

    assert len(store.get_matching_constraints(prod_intent, NOON_UTC)) == 1
    assert store.get_matching_constraints(staging_intent, NOON_UTC) == []


def test_save_load_round_trip_preserves_constraints_and_hashes(tmp_path):
    store = ConstraintStore()
    original = make_constraint(
        id="rule-rt",
        scope={"namespace": "prod"},
        time_window={"days": ["Mon"], "start": "09:00", "end": "17:00", "tz": "UTC"},
    )
    store.constraints[original.id] = original

    path = tmp_path / "constraints.yaml"
    store.save(path)

    reloaded = ConstraintStore.load(path)
    assert reloaded.quarantined == []
    round_tripped = reloaded.constraints["rule-rt"]

    assert round_tripped == original
    assert round_tripped.provenance_hash == original.provenance_hash
