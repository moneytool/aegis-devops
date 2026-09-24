import json
import random
from datetime import UTC, datetime

import pytest

from aegis_core.adversarial import CATEGORIES, Attack, apply, attacks, poison_store
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
    "argv-kubectl-namespace-before-verb",
    "argv-kubectl-context-before-verb",
    "argv-git-C-before-verb",
    "argv-kubectl-glued-namespace",
    "argv-kubectl-label-selector",
    "argv-kubectl-comma-kinds",
    "argv-kubectl-namespace-cascade",
    "argv-kubectl-delete-all-in-namespace",
    "argv-helm-glued-namespace",
    "argv-helm-namespace-before-verb",
    # REVIEW-4 T1.5 / T1.7
    "argv-argocd-prune-equals-true",
    "argv-argocd-dry-run-false",
    "argv-az-resource-delete-ids",
    "argv-az-aks-delete-ids",
    "argv-gh-api-workflow-dispatch",
    "argv-gh-api-workflow-dispatch-full-url",
    # REVIEW-4 T1.2
    "shell-compound-semicolon",
    "shell-compound-and-or",
    "shell-newline-separated",
    "shell-sudo-wrapper",
    "shell-sudo-user-env-wrapper",
    "shell-timeout-nice-nohup-wrapper",
    "shell-alias-k",
    "shell-sh-c-string",
    "shell-bash-c-compound",
    "shell-helm-glued-namespace-behind-sudo",
    "shell-git-force-push-in-pipeline",
    "shell-argocd-prune-in-compound",
}


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        scope={"namespace": "prod"},
        time_window={
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "start": "09:00",
            "end": "17:00",
            "tz": "UTC",
        },
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
                "tz": "UTC",
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


def test_registry_categories_are_one_of_the_five_known_values():
    for a in attacks():
        assert a.category in CATEGORIES
    assert {a.category for a in attacks()} == set(CATEGORIES)


def test_every_attack_runs_against_the_example_store(example_store):
    rng = random.Random(0)
    base = next(iter(example_store.constraints.values()))
    for attack in attacks():
        # Should not raise for any registered attack.
        apply(attack, base, rng=rng)


# --------------------------------------------------------------------------
# Tampered attacks: interceptor discards with reason "tampered". By default
# (on_untrusted_match="discard") a tampered BLOCK/ESCALATE rule gets no vote
# at all -- the verdict is exactly what it would be with the poisoned rule
# absent (here, ALLOW, since nothing else matches SCALE_INTENT). This is
# what keeps an attacker who can write a poisoned constraint from steering
# the decision (measured: "escalate" scores the same poison-susceptibility,
# 1.000, and over-block rate, 0.600, as a verifier with no trust model at
# all; "discard" scores 0.000/0.000). The old fail-closed-to-ESCALATE
# behaviour (REVIEW-4 T0.3) is still available, opt-in, via
# on_untrusted_match="escalate".
# --------------------------------------------------------------------------

TAMPERED_ATTACKS = [a for a in attacks() if a.category == "tampered"]


@pytest.mark.parametrize("attack", TAMPERED_ATTACKS, ids=lambda a: a.name)
def test_tampered_attacks_are_discarded_and_get_no_vote_by_default(attack):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()
    poisoned = apply(attack, base, rng=random.Random(0))
    assert poisoned is not None
    store.constraints[poisoned.id] = poisoned

    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert poisoned.id not in decision.citations
    assert {"id": poisoned.id, "reason": "tampered"} in decision.discarded
    assert decision.verdict == "ALLOW"
    assert not any(n.startswith("fail-closed:") for n in decision.notes)


@pytest.mark.parametrize("attack", TAMPERED_ATTACKS, ids=lambda a: a.name)
def test_tampered_attacks_escalate_under_on_untrusted_match_escalate(attack):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()
    poisoned = apply(attack, base, rng=random.Random(0))
    assert poisoned is not None
    store.constraints[poisoned.id] = poisoned

    interceptor = AegisInterceptor(store, on_untrusted_match="escalate")
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert poisoned.id not in decision.citations
    assert {"id": poisoned.id, "reason": "tampered"} in decision.discarded
    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"
    assert f"fail-closed: {poisoned.id} (tampered)" in decision.notes


# --------------------------------------------------------------------------
# Unauthorized attacks: interceptor discards with reason "unauthorized",
# and gets no vote by default for the same reason as tampered attacks above.
# --------------------------------------------------------------------------

UNAUTHORIZED_ATTACKS = [a for a in attacks() if a.category == "unauthorized"]


@pytest.mark.parametrize("attack", UNAUTHORIZED_ATTACKS, ids=lambda a: a.name)
def test_unauthorized_attacks_are_discarded_and_get_no_vote_by_default(attack):
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
    assert decision.verdict == "ALLOW"
    assert not any(n.startswith("fail-closed:") for n in decision.notes)


@pytest.mark.parametrize("attack", UNAUTHORIZED_ATTACKS, ids=lambda a: a.name)
def test_unauthorized_attacks_escalate_under_on_untrusted_match_escalate(attack):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint()

    if attack.name == "unauth-revoked":
        store.add_constraint(base)
        store.authority_map = {"admin": {"scaling", "deletion", "configuration"}}
        poisoned = base
    else:
        poisoned = apply(attack, base, rng=random.Random(0))
        assert poisoned is not None
        store.constraints[poisoned.id] = poisoned

    interceptor = AegisInterceptor(store, on_untrusted_match="escalate")
    decision = interceptor.intercept(SCALE_INTENT, now=NOW)

    assert poisoned.id not in decision.citations
    assert {"id": poisoned.id, "reason": "unauthorized"} in decision.discarded
    assert decision.verdict == "ESCALATE"
    assert decision.verdict != "BLOCK"
    assert f"fail-closed: {poisoned.id} (unauthorized)" in decision.notes


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


def test_evade_case_variant_is_not_an_attacker_controlled_gap_any_more():
    """REVIEW-4 extras: this used to be xfail, documenting that
    fnmatch-based matching is case-sensitive so 'deployment/*' doesn't
    match 'Deployment/API-Server'. Re-checked: the parser now lower-cases
    every kubectl resource *kind* it parses (parser.py
    `_split_resource_token`, "kinds are case-insensitive in kubectl;
    patterns are lower-case"), so an intent built from real argv via the
    CLI is always lower-case -- there is no argv shape an agent or
    attacker can type that produces an upper-case kind any more. The
    matcher itself is still case-sensitive (documented below), but hitting
    it now requires either (a) a library caller building an
    InfrastructureIntent directly, bypassing the parser entirely, as this
    test does, or (b) a constraint author writing an upper-case
    resource_pattern, which is a self-inflicted authoring mistake now
    caught by a load-time warning (see the second test below) -- not an
    attacker-controlled evasion of a rule the author actually wrote
    correctly. So this stays documented, not fixed: fixing the matcher
    itself is still out of scope (store.py's matching semantics), and
    fixing it wouldn't change what a real CLI-driven attacker can do."""
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    base = make_constraint(resource_pattern="deployment/*")
    store.add_constraint(base)

    # Only reachable by constructing the intent directly -- the CLI/parser
    # path can never produce an upper-case kind (see above).
    evasive_intent = InfrastructureIntent(
        resource="Deployment/API-Server",
        action="scale",
        provider="kubernetes",
        metadata={"namespace": "prod"},
    )
    interceptor = AegisInterceptor(store)
    decision = interceptor.intercept(evasive_intent, now=NOW)

    # Documents current (still case-sensitive) matcher behaviour: the rule
    # does not fire, and the intent is reported uncovered rather than
    # silently misjudged -- there's no BLOCK/ALLOW confusion, just a miss.
    assert decision.verdict == "ALLOW"
    assert decision.covered is False


def test_upper_case_resource_pattern_gets_a_load_time_warning(tmp_path):
    """The authoring mistake side of the case-sensitivity gap above: a
    constraint whose resource_pattern isn't already lower-case will never
    match a parser-derived intent, so load-time now warns about it instead
    of leaving the author to discover a silently-dead rule."""
    from aegis_core.store import ConstraintStore as CS

    store = CS(authority_map=dict(AUTHORITY))
    store.add_constraint(make_constraint(id="c1", resource_pattern="Deployment/*"))
    path = tmp_path / "constraints.yaml"
    store.save(path)

    reloaded = CS.load(path, authority_map=dict(AUTHORITY), insecure=True)
    assert reloaded.quarantined == []
    assert any(
        "resource_pattern is matched case-sensitively" in w and "Deployment/*" in w
        for w in reloaded.warnings
    )


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
        assert decision.verdict != "BLOCK"


# --------------------------------------------------------------------------
# argv-evasion attacks (REVIEW-4 T0.1/T0.2): command-line shapes that used
# to parse into an intent nothing matched. Each must now hit the rule a
# constraint author would expect, against the stock example store.
# --------------------------------------------------------------------------

ARGV_EVASION_ATTACKS = [a for a in attacks() if a.category == "argv-evasion"]


@pytest.fixture
def example_gate():
    from aegis_core.environments import load_environment_map

    authority_map = load_authority_map("data/authority.example.yaml")
    store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
    return AegisInterceptor(store), load_environment_map("data/environments.example.yaml")


@pytest.mark.parametrize("attack", ARGV_EVASION_ATTACKS, ids=lambda a: a.name)
def test_argv_evasion_attacks_now_hit_the_expected_rule(attack, example_gate):
    from aegis_core.parser import from_argv

    interceptor, env_map = example_gate
    assert attack.argv and attack.expected_rule
    now = datetime.fromisoformat(attack.now) if attack.now else NOW

    intents = from_argv(list(attack.argv))
    for intent in intents:
        env_map.annotate(intent)
    decisions = [interceptor.intercept(intent, now=now) for intent in intents]

    hits = [d for d in decisions if attack.expected_rule in d.citations]
    assert hits, f"{attack.name}: {attack.expected_rule} never fired; got {decisions}"
    assert all(d.verdict != "ALLOW" for d in hits)
    assert all(not i.action.startswith("-") for i in intents)


def test_argv_evasion_attacks_apply_returns_base_unchanged(example_store):
    base = next(iter(example_store.constraints.values()))
    for attack in ARGV_EVASION_ATTACKS:
        assert apply(attack, base, rng=random.Random(0)) == base


# --------------------------------------------------------------------------
# REVIEW-4 T1.1 (Security C2): a forged Trusted constraint plus a matching
# source file needs *no secret* when nothing is signed -- with a key, the
# same attack is refused at load.
# --------------------------------------------------------------------------


def _c2_attack(tmp_path):
    """Attacker with write access to the policy dir: writes a self-consistent
    constraint asserting `principal: admin` and a source file that backs it,
    so integrity, authority and source verification all pass."""
    forged = make_constraint(
        id="forged-allow-nothing", principal="admin", constraint_class="deletion",
        resource_pattern="node/*", actions={"delete"}, effect="ESCALATE",
        source_ref="git-forged",
    )
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.add_constraint(forged)
    path = tmp_path / "constraints.yaml"
    store.save(path)
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    _write_source_file(sources_dir, forged)  # payload self-asserts principal: admin
    return forged, path, sources_dir


def test_c2_forged_trusted_constraint_loads_when_nothing_is_signed(tmp_path):
    forged, path, sources_dir = _c2_attack(tmp_path)
    fetcher = FileSourceFetcher(base_dir=sources_dir, insecure=True)
    reloaded = ConstraintStore.load(
        path, authority_map=dict(AUTHORITY), source_fetcher=fetcher, insecure=True
    )
    # Without a root of trust the attack succeeds (documented boundary)...
    assert forged.id in reloaded.constraints
    assert reloaded.quarantined == []
    # ... and the payload-supplied principal is at least flagged.
    assert "principal-from-payload: git-forged" in reloaded.warnings


def test_c2_forged_trusted_constraint_is_refused_when_a_key_is_supplied(tmp_path):
    from aegis_core.signing import SignatureError, sign_file, sign_tree

    forged, path, sources_dir = _c2_attack(tmp_path)
    key = b"operator-secret-key-32-bytes-xx!"[:32]

    # 1. Unsigned constraints file -> refused outright.
    with pytest.raises(SignatureError, match="unsigned"):
        ConstraintStore.load(path, authority_map=dict(AUTHORITY), key=key)

    # 2. Attacker can't sign, but suppose the operator's *signed* file is
    #    then edited in place: the stale signature no longer verifies.
    sign_file(path, key)
    path.write_text(path.read_text().replace("effect: ESCALATE", "effect: BLOCK"))
    with pytest.raises(SignatureError, match="bad signature"):
        ConstraintStore.load(path, authority_map=dict(AUTHORITY), key=key)

    # 3. Even a signed constraints file can't launder a self-asserted
    #    principal: the transport (signed PRINCIPALS.yaml) says the source
    #    belongs to `developer`, so the constraint is quarantined.
    path.write_text(path.read_text().replace("effect: BLOCK", "effect: ESCALATE"))
    sign_file(path, key)
    (sources_dir / "PRINCIPALS.yaml").write_text("principals:\n  git-forged: developer\n")
    sign_tree(sources_dir, key)
    fetcher = FileSourceFetcher(base_dir=sources_dir, key=key)
    reloaded = ConstraintStore.load(
        path, authority_map=dict(AUTHORITY), source_fetcher=fetcher, key=key
    )
    assert forged.id not in reloaded.constraints
    assert reloaded.quarantined == [{"id": forged.id, "reason": "principal-mismatch"}]
    assert reloaded.warnings and all("unsigned" not in w for w in reloaded.warnings)

    # 4. The quarantined rule is visible either way (discarded[] + the
    #    load-time warning above), but by default it gets no vote at all --
    #    the action for which it was the only match is simply ALLOWed.
    #    Fail-closed handling of a quarantined match is still available,
    #    opt-in, via on_untrusted_match="escalate".
    intent = _intent_from_constraint(forged)
    decision = AegisInterceptor(reloaded).intercept(intent, now=NOW)
    assert decision.verdict == "ALLOW"
    assert {"id": forged.id, "reason": "principal-mismatch"} in decision.discarded

    escalating = AegisInterceptor(reloaded, on_untrusted_match="escalate").intercept(
        intent, now=NOW
    )
    assert escalating.verdict == "ESCALATE"
    assert escalating.verdict != "BLOCK"
    assert {"id": forged.id, "reason": "principal-mismatch"} in escalating.discarded


# --------------------------------------------------------------------------
# shell-evasion attacks (REVIEW-4 T1.2): shell *strings* whose shape hid the
# dangerous command from an argv-only gate. Each must, once split and
# unwrapped, hit the rule a constraint author would expect.
# --------------------------------------------------------------------------

SHELL_EVASION_ATTACKS = [a for a in attacks() if a.category == "shell-evasion"]


def test_shell_evasion_attacks_are_registered():
    assert len(SHELL_EVASION_ATTACKS) >= 10
    assert all(a.command and a.expected_rule and a.argv is None for a in SHELL_EVASION_ATTACKS)


@pytest.mark.parametrize("attack", SHELL_EVASION_ATTACKS, ids=lambda a: a.name)
def test_shell_evasion_attacks_hit_the_expected_rule(attack, example_gate):
    from aegis_core.shell import intents_from_command

    interceptor, env_map = example_gate
    now = datetime.fromisoformat(attack.now) if attack.now else NOW

    intents = intents_from_command(attack.command)
    assert intents, f"{attack.name}: no intents from {attack.command!r}"
    for intent in intents:
        env_map.annotate(intent)
    decisions = [interceptor.intercept(intent, now=now) for intent in intents]

    hits = [d for d in decisions if attack.expected_rule in d.citations]
    assert hits, f"{attack.name}: {attack.expected_rule} never fired; got {decisions}"
    assert all(d.verdict != "ALLOW" for d in hits)


def test_shell_evasion_attacks_apply_returns_base_unchanged(example_store):
    base = next(iter(example_store.constraints.values()))
    for attack in SHELL_EVASION_ATTACKS:
        assert apply(attack, base, rng=random.Random(0)) == base


def test_argv_evasion_dry_run_false_is_not_downgraded(example_gate):
    # REVIEW-4 T1.5 acceptance: `argocd app sync prod-web --prune --dry-run=false`
    # -> ESCALATE with no dry-run downgrade.
    from aegis_core.parser import from_argv

    interceptor, _ = example_gate
    (intent,) = from_argv(["argocd", "app", "sync", "prod-web", "--prune", "--dry-run=false"])
    assert "dry_run" not in intent.params
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert "argocd-escalate-prod-sync-prune" in decision.citations
