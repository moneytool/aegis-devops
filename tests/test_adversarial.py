import json
import random
from datetime import UTC, datetime

import pytest

from aegis_core.adversarial import Attack, apply, attacks, poison_store
from aegis_core.authority import load_authority_map
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.provenance import FileSourceFetcher, verify_source
from aegis_core.store import Constraint, ConstraintStore

NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)

AUTHORITY = {
    "admin": {"scaling", "deletion", "configuration"},
    "sre_lead": {"scaling", "configuration"},
    "developer": {"configuration"},
}

EXPECTED_ATTACK_NAMES = {
    "tamper-rule-text",
    "tamper-effect-downgrade",
    "tamper-effect-upgrade",
    "tamper-widen-actions",
    "tamper-widen-pattern",
    "tamper-drop-scope",
    "tamper-drop-time-window",
    "tamper-principal-swap",
    "unauth-principal-swap-rehash",
    "unauth-class-escalation",
    "unauth-unknown-principal",
    "unauth-revoked",
    "forge-fabricated-source",
    "forge-missing-source",
    "forge-replay",
    "evade-case-variant",
    "evade-provider-mismatch",
    "evade-namespace-omitted",
}


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        scope={"namespace": "prod"},
        time_window={"days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "start": "09:00", "end": "17:00"},
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
    resource="deployment/api-server",
    action="scale",
    provider="kubernetes",
    metadata={"namespace": "prod"},
)


def by_name(name: str) -> Attack:
    return next(a for a in attacks() if a.name == name)


def _verify_source_safe(constraint, fetcher) -> bool:
    """verify_source() lets FileNotFoundError propagate for a missing
    source file; this normalises that into a plain False for tests that
    want to assert 'the source doesn't back this claim' regardless of why."""
    try:
        return verify_source(constraint, fetcher)
    except FileNotFoundError:
        return False


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def example_store() -> ConstraintStore:
    authority_map = load_authority_map("data/authority.example.yaml")
    return ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)


CLASS_PRINCIPAL = {"scaling": "sre_lead", "deletion": "admin", "configuration": "developer"}
CLASS_ACTION = {"scaling": "scale", "deletion": "delete", "configuration": "update"}


@pytest.fixture
def big_store() -> ConstraintStore:
    """~100 constraints built deterministically via Constraint.create."""
    rng = random.Random(0)
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    classes = list(CLASS_PRINCIPAL)
    for i in range(100):
        constraint_class = rng.choice(classes)
        principal = CLASS_PRINCIPAL[constraint_class]
        action = CLASS_ACTION[constraint_class]
        effect = rng.choice(["BLOCK", "ESCALATE"])
        c = Constraint.create(
            id=f"rule-{i}",
            provider="kubernetes",
            resource_pattern=f"deployment/svc{i}-*",
            actions={action},
            scope={"namespace": "prod"},
            time_window={
                "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
                "start": "09:00",
                "end": "17:00",
            },
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=f"src-{i}",
            source_timestamp="2026-01-01T00:00:00+00:00",
            rule_text=f"Synthetic rule #{i}.",
        )
        store.add_constraint(c)
    return store


def _intent_from_constraint(c: Constraint) -> InfrastructureIntent:
    pattern = c.resource_pattern
    resource = pattern.replace("*", "x") if "*" in pattern else pattern
    action = sorted(c.actions)[0]
    return InfrastructureIntent(
        resource=resource, action=action, provider=c.provider, metadata=dict(c.scope)
    )


# --------------------------------------------------------------------------
# Registry sanity
# --------------------------------------------------------------------------


def test_registry_matches_documented_attack_list():
    assert {a.name for a in attacks()} == EXPECTED_ATTACK_NAMES


def test_registry_categories_are_one_of_the_four_known_values():
    for a in attacks():
        assert a.category in {"tampered", "unauthorized", "forged", "evasion"}


def test_every_attack_runs_against_the_example_store(example_store):
    rng = random.Random(0)
    base = next(iter(example_store.constraints.values()))
    for attack in attacks():
        # Should not raise for any registered attack.
        apply(attack, base, rng=rng)


# --------------------------------------------------------------------------
# Tampered attacks: interceptor discards with reason "tampered".
# --------------------------------------------------------------------------

TAMPERED_ATTACKS = [a for a in attacks() if a.category == "tampered"]


@pytest.mark.parametrize("attack", TAMPERED_ATTACKS, ids=lambda a: a.name)
def test_tampered_attacks_are_discarded_and_intent_allowed(attack):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()
    poisoned = apply(attack, base, rng=random.Random(0))
    assert poisoned is not None
    store.constraints[poisoned.id] = poisoned

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert poisoned.id not in decision.citations
    assert {"id": poisoned.id, "reason": "tampered"} in decision.discarded
    assert decision.verdict != "BLOCK"


# --------------------------------------------------------------------------
# Unauthorized attacks: interceptor discards with reason "unauthorized".
# --------------------------------------------------------------------------

UNAUTHORIZED_ATTACKS = [a for a in attacks() if a.category == "unauthorized"]


@pytest.mark.parametrize("attack", UNAUTHORIZED_ATTACKS, ids=lambda a: a.name)
def test_unauthorized_attacks_are_discarded_and_intent_allowed(attack):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()

    if attack.name == "unauth-revoked":
        # Valid + authorized at ingest; revoked afterwards via store state.
        store.add_constraint(base)
        store.authority_map = {"admin": {"scaling", "deletion", "configuration"}}
        poisoned = base
    else:
        poisoned = apply(attack, base, rng=random.Random(0))
        assert poisoned is not None
        store.constraints[poisoned.id] = poisoned

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert poisoned.id not in decision.citations
    assert {"id": poisoned.id, "reason": "unauthorized"} in decision.discarded
    assert decision.verdict != "BLOCK"


def test_unauth_class_escalation_also_rejected_at_ingest_time():
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint(principal="developer", constraint_class="configuration")
    poisoned = apply(by_name("unauth-class-escalation"), base, rng=random.Random(0))

    assert poisoned.constraint_class == "deletion"
    assert poisoned.principal == "developer"
    with pytest.raises(PermissionError):
        store.add_constraint(poisoned)


# --------------------------------------------------------------------------
# Forged attacks: caught only by verify_source, not by the interceptor yet.
# --------------------------------------------------------------------------


def test_forge_fabricated_source_fails_verify_source(tmp_path):
    base = make_constraint(source_ref="jira-999")
    poisoned = apply(by_name("forge-fabricated-source"), base, rng=random.Random(0))
    assert poisoned.verify_integrity()  # self-consistent

    source_file = tmp_path / "jira-999.json"
    source_file.write_text(
        '{"provider": "kubernetes", "resource_pattern": "deployment/*", '
        '"actions": ["scale"], "scope": {"namespace": "prod"}, "time_window": null, '
        '"effect": "BLOCK", "constraint_class": "scaling", "principal": "sre_lead", '
        '"source_ref": "jira-999", "source_timestamp": "2026-01-01T00:00:00+00:00", '
        '"rule_text": "This is not what the constraint claims the source says."}'
    )

    fetcher = FileSourceFetcher(base_dir=tmp_path)
    assert _verify_source_safe(poisoned, fetcher) is False


def test_forge_missing_source_fails_verify_source(tmp_path):
    base = make_constraint(source_ref="jira-real")
    poisoned = apply(by_name("forge-missing-source"), base, rng=random.Random(0))
    assert poisoned.verify_integrity()  # self-consistent
    assert poisoned.source_ref != base.source_ref

    fetcher = FileSourceFetcher(base_dir=tmp_path)  # empty dir, no source file at all
    assert _verify_source_safe(poisoned, fetcher) is False


def test_forge_replay_fails_verify_source():
    store = ConstraintStore.load("data/constraints.example.yaml")
    original = store.constraints["no-scale-prod-peak"]  # source_ref jira-1001
    poisoned = apply(by_name("forge-replay"), original, rng=random.Random(0))

    assert poisoned.verify_integrity()  # self-consistent
    assert poisoned.source_ref == original.source_ref  # replayed citation
    assert poisoned.resource_pattern != original.resource_pattern

    fetcher = FileSourceFetcher(base_dir="data/sources")
    assert _verify_source_safe(poisoned, fetcher) is False


def test_without_a_fetcher_forged_constraints_are_still_honoured():
    """Forged constraints are self-consistent (valid hash, authorized
    principal), so they pass both of the interceptor's checks. Only
    verify_source() -- run at load time when a source_fetcher is supplied,
    see test_forged_constraint_is_quarantined_at_load_when_a_fetcher_is_given
    -- can catch them. This documents that the fetcher is what makes forgery
    detectable at all: add_constraint()/store.constraints assignment alone
    (no fetcher involved) never catches a forged constraint."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()
    poisoned = apply(by_name("forge-replay"), base, rng=random.Random(0))
    store.add_constraint(poisoned)  # loads fine: authorized + integrity holds

    assert poisoned.id in store.constraints

    intent = _intent_from_constraint(poisoned)
    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(intent, now=NOW)

    assert poisoned.id in decision.citations
    assert decision.discarded == []


def _write_source_file(directory, constraint) -> None:
    (directory / f"{constraint.source_ref}.json").write_text(
        json.dumps(
            {
                "provider": constraint.provider,
                "resource_pattern": constraint.resource_pattern,
                "actions": sorted(constraint.actions),
                "scope": constraint.scope,
                "time_window": constraint.time_window,
                "effect": constraint.effect,
                "constraint_class": constraint.constraint_class,
                "principal": constraint.principal,
                "source_ref": constraint.source_ref,
                "source_timestamp": constraint.source_timestamp,
                "rule_text": constraint.rule_text,
            }
        )
    )


def test_forged_constraint_is_quarantined_at_load_when_a_fetcher_is_given(tmp_path):
    """Forged constraints are self-consistent (valid hash, authorized
    principal), so verify_integrity()/is_authorized() alone can't catch
    them. But when ConstraintStore.load() is given a source_fetcher, it
    re-derives each constraint's hash from its *original* source and
    quarantines anything that doesn't match -- so a replayed citation like
    this never reaches the interceptor at all; it's quarantined with
    reason "forged" before the store is even built."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()
    poisoned = apply(by_name("forge-replay"), base, rng=random.Random(0))
    store.add_constraint(poisoned)  # loads fine: authorized + self-consistent hash

    path = tmp_path / "constraints.yaml"
    store.save(path)

    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    # The real source behind base.source_ref backs BASE's fields, not the
    # replayed/poisoned constraint's -- exactly what forge-replay exploits.
    _write_source_file(sources_dir, base)

    fetcher = FileSourceFetcher(base_dir=sources_dir)
    reloaded = ConstraintStore.load(path, authority_map=dict(AUTHORITY), source_fetcher=fetcher)

    assert poisoned.id not in reloaded.constraints
    assert {"id": poisoned.id, "reason": "forged"} in reloaded.quarantined


# --------------------------------------------------------------------------
# Evasion attacks: document current (correct, or gap) matcher behaviour.
# --------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="resource kinds should be normalised in the parser, not the matcher",
)
def test_evade_case_variant_slips_past_case_sensitive_fnmatch():
    """fnmatch (and therefore get_matching_constraints) is case-sensitive on
    POSIX. A rule written for 'deployment/*' does not match a resource
    string of 'Deployment/API-Server', even though they name the same
    Kubernetes object. This is a real gap: case normalisation belongs in
    intent/constraint parsing, not in store.py's matcher (which we were
    told not to touch)."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint(resource_pattern="deployment/*")
    store.add_constraint(base)

    evasive_intent = InfrastructureIntent(
        resource="Deployment/API-Server",
        action="scale",
        provider="kubernetes",
        metadata={"namespace": "prod"},
    )
    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(evasive_intent, now=NOW)

    # This is what SHOULD happen if case were normalised: the rule still
    # applies and the scale is blocked.
    assert decision.verdict == "BLOCK"


def test_evade_provider_mismatch_correctly_does_not_match():
    """A kubernetes-scoped rule must never apply to a terraform intent for
    the 'same' resource string, even though resource_pattern and action
    happen to line up textually. This is correct, intended behaviour."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint(
        provider="kubernetes", resource_pattern="deployment/*", actions={"scale"}
    )
    store.add_constraint(base)

    terraform_intent = InfrastructureIntent(
        resource="deployment/api-server", action="scale", provider="terraform"
    )
    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(terraform_intent, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.covered is False
    assert decision.citations == []


def test_evade_namespace_omitted_intent_does_not_match_scoped_rule():
    """_scope_matches() requires every key in the constraint's scope dict to
    be present with a matching value in the intent's merged metadata/params.
    An intent that simply omits the 'namespace' key does not match a
    namespace-scoped rule (it falls into combined.get('namespace') is None,
    which != 'prod') — it is NOT treated as 'any namespace, including
    prod'. This documents current, correct behaviour: the omission fails
    open only in the sense that the *rule* fails to apply, not that the
    action is silently allowed to bypass a rule it should have hit; there
    is simply no evidence in the intent that this action targets prod."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint(resource_pattern="deployment/*", scope={"namespace": "prod"})
    store.add_constraint(base)

    no_namespace_intent = InfrastructureIntent(
        resource="deployment/api-server", action="scale", provider="kubernetes"
    )
    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(no_namespace_intent, now=NOW)

    assert decision.verdict == "ALLOW"
    assert decision.covered is False
    assert decision.citations == []


# --------------------------------------------------------------------------
# poison_store over a large synthetic corpus.
# --------------------------------------------------------------------------

POISON_STORE_ATTACKS = [
    a
    for a in attacks()
    if a.category in {"tampered", "unauthorized"} and a.name != "unauth-revoked"
]


@pytest.mark.parametrize("attack", POISON_STORE_ATTACKS, ids=lambda a: a.name)
def test_poison_store_poisons_exact_fraction_and_all_are_discarded(big_store, attack):
    rng = random.Random(0)
    poisoned_ids = poison_store(big_store, attack, rng=rng, fraction=0.2)

    assert len(poisoned_ids) == 20
    assert len(set(poisoned_ids)) == 20

    interceptor = AegisInterceptor(big_store)
    for pid in poisoned_ids:
        c = big_store.constraints[pid]
        intent = _intent_from_constraint(c)
        decision = interceptor.intercept(intent, now=NOW)
        discarded_ids = [d["id"] for d in decision.discarded]
        assert pid in discarded_ids, f"{pid} not discarded for attack {attack.name}"
        assert pid not in decision.citations
