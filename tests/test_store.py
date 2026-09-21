import pytest

from aegis_core.store import Constraint, ConstraintStore

AUTHORITY = {
    "admin": {"scaling", "deletion", "configuration"},
    "sre_lead": {"scaling", "configuration"},
    "developer": {"configuration"},
}


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="test-1",
        provider="kubernetes",
        resource_pattern="node/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="no-scaling",
    )
    defaults.update(overrides)
    return Constraint.create(**defaults)


def test_add_constraint_stores_it():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.add_constraint(constraint)
    assert "test-1" in store.constraints
    assert store.constraints["test-1"].principal == "sre_lead"


def test_add_constraint_by_unauthorized_principal_raises():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint(
        id="test-2", principal="developer", constraint_class="scaling"
    )
    with pytest.raises(PermissionError):
        store.add_constraint(constraint)


def test_add_constraint_denies_by_default_with_no_authority_map():
    store = ConstraintStore()  # default: empty authority map, deny all
    constraint = make_constraint(id="test-3", principal="admin")
    with pytest.raises(PermissionError):
        store.add_constraint(constraint)


def test_integrity_verification_passes_for_untouched_constraint():
    constraint = make_constraint(id="test-4")
    assert constraint.verify_integrity() is True


def test_integrity_verification_fails_after_tamper():
    constraint = make_constraint(id="test-5")
    constraint.rule_text = "an attacker rewrote this rule"
    assert constraint.verify_integrity() is False


def test_is_authorized_reflects_authority_map():
    store = ConstraintStore(authority_map=AUTHORITY)
    assert store.is_authorized("sre_lead", "scaling") is True
    assert store.is_authorized("developer", "scaling") is False
    assert store.is_authorized("unknown_principal", "scaling") is False


def test_unauthorized_principal_bypassing_add_constraint_is_still_in_store():
    """A constraint inserted directly into the store's dict, bypassing
    add_constraint, is accepted into storage -- authority is enforced again
    at decision time by the interceptor (see test_interceptor.py)."""
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint(id="test-6", principal="developer", constraint_class="scaling")
    store.constraints[constraint.id] = constraint
    assert "test-6" in store.constraints
    assert store.is_authorized(constraint.principal, constraint.constraint_class) is False
