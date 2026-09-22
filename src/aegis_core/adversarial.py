"""The Adversarial Test Suite: a library of attack generators that produce
poisoned constraints and evasive command lines.

Each :class:`Attack` documents one way a constraint can be poisoned — or a
command line shaped to slip past the parser — in one of five categories:

  * ``tampered``     — the constraint's fields were mutated after ingest, so
    its stored ``provenance_hash`` no longer matches. Caught by
    ``Constraint.verify_integrity`` (used both at load time and at decision
    time by :meth:`AegisInterceptor.intercept`). **Fails closed**: the
    tampered rule is discarded and, because its effect was BLOCK/ESCALATE,
    the intent is ESCALATED — never ALLOWed as if no rule existed.
  * ``unauthorized``  — the hash is internally consistent (it was
    recomputed after the mutation, or the mutation happened to the
    authority map instead of the constraint), but the asserting principal
    is not allowed to assert that constraint's class. Caught by
    ``ConstraintStore.is_authorized`` at add-time and decision-time; also
    fails closed to ESCALATE.
  * ``forged``        — the constraint is self-consistent (hash matches its
    own fields) but does not match what its cited source actually says.
    Only ``verify_source`` (cross-checking against the original source via a
    ``SourceFetcher``) can catch these, at load time when ``--sources`` is
    given; a quarantined forged rule that matches an intent also fails
    closed to ESCALATE.
  * ``evasion``       — attempts to slip a malicious constraint or intent
    past the matching logic itself (case, provider, missing scope). These
    are tests of *correct* behaviour or documented gaps, not bypasses of
    the integrity/authority checks.
  * ``argv-evasion``  — command-line shapes that used to parse into a
    garbage intent nothing matched (REVIEW-4 T0.1/T0.2): global options in
    front of the verb, glued short flags (``-nprod``), label selectors,
    comma-separated kinds, namespace deletion (which cascades to every
    object in the namespace). Each carries the ``argv`` to parse, the
    ``now`` to evaluate at, and the ``expected_rule`` from the example
    store that a constraint author would expect to fire.

Attacks in the first two categories return a poisoned :class:`Constraint`
that can be inserted directly into ``store.constraints`` (bypassing
``add_constraint``, exactly as an attacker mutating the store or replaying
a request would). Some attacks are "ingest-time": the assertion under test
is that ``store.add_constraint`` itself raises, not that a poisoned object
exists — for these, :func:`apply` returns ``None`` and the caller is
expected to construct the malicious constraint itself and call
``add_constraint``. ``argv-evasion`` attacks don't mutate a constraint at
all; :func:`apply` returns the base unchanged and the test parses
``attack.argv`` instead.
"""

import random
from collections.abc import Callable
from dataclasses import dataclass

from aegis_core.provenance import compute_provenance_hash
from aegis_core.store import Constraint

CATEGORIES = ("tampered", "unauthorized", "forged", "evasion", "argv-evasion")


@dataclass(frozen=True)
class Attack:
    name: str
    category: str  # one of CATEGORIES
    description: str
    expected_reason: str | None
    # argv-evasion only: the command line to parse, when to evaluate it, and
    # the example-store rule it must hit (see data/constraints.example.yaml).
    argv: tuple[str, ...] | None = None
    now: str | None = None
    expected_rule: str | None = None


def _rehash(c: Constraint) -> Constraint:
    """Returns a copy of ``c`` with its provenance_hash recomputed from its
    current fields — simulates an attacker who mutates a constraint and
    then re-derives a self-consistent hash before (re-)inserting it."""
    new_hash = compute_provenance_hash(
        provider=c.provider,
        resource_pattern=c.resource_pattern,
        actions=c.actions,
        scope=c.scope,
        time_window=c.time_window,
        effect=c.effect,
        constraint_class=c.constraint_class,
        principal=c.principal,
        source_ref=c.source_ref,
        source_timestamp=c.source_timestamp,
        rule_text=c.rule_text,
    )
    return _replace(c, provenance_hash=new_hash)


def _replace(c: Constraint, **overrides) -> Constraint:
    fields = dict(
        id=c.id,
        provider=c.provider,
        resource_pattern=c.resource_pattern,
        actions=set(c.actions),
        scope=dict(c.scope),
        time_window=dict(c.time_window) if c.time_window else None,
        effect=c.effect,
        constraint_class=c.constraint_class,
        principal=c.principal,
        source_ref=c.source_ref,
        source_timestamp=c.source_timestamp,
        rule_text=c.rule_text,
        provenance_hash=c.provenance_hash,
    )
    fields.update(overrides)
    return Constraint(**fields)


# --------------------------------------------------------------------------
# Tampered: post-ingest mutation, hash no longer matches.
# --------------------------------------------------------------------------

def _tamper_rule_text(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base, rule_text=base.rule_text + " [attacker-edited]")


def _tamper_effect_downgrade(base: Constraint, rng: random.Random) -> Constraint:
    if base.effect != "BLOCK":
        return _replace(base, effect="BLOCK")
    return _replace(base, effect="ESCALATE")


def _tamper_effect_upgrade(base: Constraint, rng: random.Random) -> Constraint:
    if base.effect != "ESCALATE":
        return _replace(base, effect="ESCALATE")
    return _replace(base, effect="BLOCK")


def _tamper_widen_actions(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base, actions=set(base.actions) | {"get"})


def _tamper_widen_pattern(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base, resource_pattern="*")


def _tamper_drop_scope(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base, scope={})


def _tamper_drop_time_window(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base, time_window=None)


def _tamper_principal_swap(base: Constraint, rng: random.Random) -> Constraint:
    # Attacker rewrites the principal to launder authority, but does NOT
    # recompute the hash — this stays "tampered", not "unauthorized".
    new_principal = "admin" if base.principal != "admin" else "sre_lead"
    return _replace(base, principal=new_principal)


# --------------------------------------------------------------------------
# Unauthorized: hash valid, principal lacks authority for the class.
# --------------------------------------------------------------------------

def _unauth_principal_swap_rehash(base: Constraint, rng: random.Random) -> Constraint:
    # REVIEW-3 T1.4: attacker rewrites principal to an unauthorized one AND
    # recomputes the hash, then re-inserts directly into the store dict
    # (bypassing add_constraint's ingest-time authority check).
    new_principal = "unauthorized_intern"
    c = _replace(base, principal=new_principal)
    return _rehash(c)


def _unauth_class_escalation(base: Constraint, rng: random.Random) -> Constraint:
    # Keep an authorized-for-'configuration' principal but escalate the
    # constraint_class to 'deletion', rehashed to stay self-consistent.
    c = _replace(base, principal="developer", constraint_class="deletion")
    return _rehash(c)


def _unauth_unknown_principal(base: Constraint, rng: random.Random) -> Constraint:
    c = _replace(base, principal="ghost_principal_not_in_authority_map")
    return _rehash(c)


def _unauth_revoked(base: Constraint, rng: random.Random) -> Constraint:
    # Not a constraint mutation at all — the constraint stays valid and
    # authorized at ingest time. The test mutates store.authority_map to
    # simulate revocation after the fact.
    return _replace(base)


# --------------------------------------------------------------------------
# Forged: self-consistent hash, but source doesn't back it.
# --------------------------------------------------------------------------

def _forge_fabricated_source(base: Constraint, rng: random.Random) -> Constraint:
    # The constraint itself is untouched and self-consistent; the test
    # writes a *different* source file under its source_ref so verify_source
    # fails even though verify_integrity passes.
    return _replace(base)


def _forge_missing_source(base: Constraint, rng: random.Random) -> Constraint:
    # Self-consistent constraint whose source_ref has no backing file at all.
    # Rehashed so the constraint itself still passes verify_integrity() —
    # only verify_source() (which has to fetch the now-missing file) can
    # tell anything is wrong.
    c = _replace(base, source_ref=base.source_ref + "-no-such-source")
    return _rehash(c)


def _forge_replay(base: Constraint, rng: random.Random) -> Constraint:
    # Copy an authorized constraint's fields to a "new" id with a different
    # resource_pattern, rehash for self-consistency, but keep the ORIGINAL
    # source_ref — replaying someone else's citation for a different claim.
    c = _replace(
        base,
        id=base.id + "-replayed",
        resource_pattern=base.resource_pattern.rstrip("*") + "replayed-*",
    )
    return _rehash(c)


# --------------------------------------------------------------------------
# Evasion: attempts to slip past matching. These test/document current
# behaviour of the matcher, not the integrity/authority checks.
# --------------------------------------------------------------------------

def _evade_case_variant(base: Constraint, rng: random.Random) -> Constraint:
    # No constraint mutation — the attack is in how the *intent's* resource
    # is cased relative to the constraint's pattern. Returned unchanged;
    # the test builds the mismatched-case intent itself.
    return _replace(base)


def _evade_provider_mismatch(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base)


def _evade_namespace_omitted(base: Constraint, rng: random.Random) -> Constraint:
    return _replace(base)


def _argv_evasion(base: Constraint, rng: random.Random) -> Constraint:
    # The attack is the *command line*, not the constraint: returned
    # unchanged; the test parses attack.argv and checks attack.expected_rule.
    return _replace(base)


# 2026-09-22 is a Tuesday; 14:00Z is 10:00 ET, inside no-scale-prod-peak's window.
_PEAK = "2026-09-22T14:00:00+00:00"

_ARGV_EVASION_ATTACKS: list[Attack] = [
    Attack(
        name="argv-kubectl-namespace-before-verb",
        category="argv-evasion",
        description='"kubectl -n prod delete deployment/x": the verb used to be read as "-n".',
        expected_reason=None,
        argv=("kubectl", "-n", "prod", "delete", "deployment/x"),
        expected_rule="no-delete-in-prod-namespace",
    ),
    Attack(
        name="argv-kubectl-context-before-verb",
        category="argv-evasion",
        description='"kubectl --context=prod-us-east delete node/w1": verb read as the flag.',
        expected_reason=None,
        argv=("kubectl", "--context=prod-us-east", "delete", "node/w1"),
        expected_rule="no-delete-nodes",
    ),
    Attack(
        name="argv-git-C-before-verb",
        category="argv-evasion",
        description='"git -C /repo push -f origin main": verb used to be read as "-C".',
        expected_reason=None,
        argv=("git", "-C", "/repo", "push", "-f", "origin", "main"),
        expected_rule="git-block-force-push-main",
    ),
    Attack(
        name="argv-kubectl-glued-namespace",
        category="argv-evasion",
        description='"-nprod" glued short flag used to be ignored, dropping the namespace.',
        expected_reason=None,
        argv=("kubectl", "scale", "deployment/api-server", "--replicas=5", "-nprod"),
        now=_PEAK,
        expected_rule="no-scale-prod-peak",
    ),
    Attack(
        name="argv-kubectl-label-selector",
        category="argv-evasion",
        description='"kubectl delete -l role=worker node" used to target "role=worker/node".',
        expected_reason=None,
        argv=("kubectl", "delete", "-l", "role=worker", "node"),
        expected_rule="no-delete-nodes",
    ),
    Attack(
        name="argv-kubectl-comma-kinds",
        category="argv-evasion",
        description='"kubectl delete nodes,pods --all" used to target "nodes,pods/*".',
        expected_reason=None,
        argv=("kubectl", "delete", "nodes,pods", "--all", "--context", "prod-us-east"),
        expected_rule="no-delete-nodes",
    ),
    Attack(
        name="argv-kubectl-namespace-cascade",
        category="argv-evasion",
        description="Deleting the prod namespace deletes everything in it; a "
        "namespace-scoped deletion rule must fire on the synthetic */* intent.",
        expected_reason=None,
        argv=("kubectl", "delete", "namespace", "prod"),
        expected_rule="no-delete-in-prod-namespace",
    ),
    Attack(
        name="argv-kubectl-delete-all-in-namespace",
        category="argv-evasion",
        description='"kubectl delete --all pods -n prod": --all is a bool, resource pod/*.',
        expected_reason=None,
        argv=("kubectl", "delete", "--all", "pods", "-n", "prod"),
        expected_rule="no-delete-in-prod-namespace",
    ),
    Attack(
        name="argv-helm-glued-namespace",
        category="argv-evasion",
        description='"helm uninstall web -nprod" used to drop the namespace.',
        expected_reason=None,
        argv=("helm", "uninstall", "web", "-nprod"),
        expected_rule="helm-block-release-delete-prod",
    ),
    Attack(
        name="argv-helm-namespace-before-verb",
        category="argv-evasion",
        description='"helm -n prod uninstall web": verb used to be read as "-n".',
        expected_reason=None,
        argv=("helm", "-n", "prod", "uninstall", "web"),
        expected_rule="helm-block-release-delete-prod",
    ),
]


_APPLIERS: dict[str, Callable[[Constraint, random.Random], Constraint]] = {
    **{a.name: _argv_evasion for a in _ARGV_EVASION_ATTACKS},
    "tamper-rule-text": _tamper_rule_text,
    "tamper-effect-downgrade": _tamper_effect_downgrade,
    "tamper-effect-upgrade": _tamper_effect_upgrade,
    "tamper-widen-actions": _tamper_widen_actions,
    "tamper-widen-pattern": _tamper_widen_pattern,
    "tamper-drop-scope": _tamper_drop_scope,
    "tamper-drop-time-window": _tamper_drop_time_window,
    "tamper-principal-swap": _tamper_principal_swap,
    "unauth-principal-swap-rehash": _unauth_principal_swap_rehash,
    "unauth-class-escalation": _unauth_class_escalation,
    "unauth-unknown-principal": _unauth_unknown_principal,
    "unauth-revoked": _unauth_revoked,
    "forge-fabricated-source": _forge_fabricated_source,
    "forge-missing-source": _forge_missing_source,
    "forge-replay": _forge_replay,
    "evade-case-variant": _evade_case_variant,
    "evade-provider-mismatch": _evade_provider_mismatch,
    "evade-namespace-omitted": _evade_namespace_omitted,
}


_REGISTRY: list[Attack] = [
    Attack(
        name="tamper-rule-text",
        category="tampered",
        description="Edit rule_text after hashing.",
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-effect-downgrade",
        category="tampered",
        description="Flip BLOCK to ESCALATE, weakening the rule.",
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-effect-upgrade",
        category="tampered",
        description="Flip ESCALATE to BLOCK, a denial-of-service on legitimate ops.",
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-widen-actions",
        category="tampered",
        description='Add an action (e.g. "get") so reads get blocked too.',
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-widen-pattern",
        category="tampered",
        description='Widen resource_pattern (e.g. "deployment/api-*" to "*").',
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-drop-scope",
        category="tampered",
        description="Remove namespace/region scope so a scoped rule hits everywhere.",
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-drop-time-window",
        category="tampered",
        description="Remove the time window so a time-boxed rule applies always.",
        expected_reason="tampered",
    ),
    Attack(
        name="tamper-principal-swap",
        category="tampered",
        description="Rewrite principal to an authorized one without recomputing the hash "
        "(attacker tries to launder authority).",
        expected_reason="tampered",
    ),
    Attack(
        name="unauth-principal-swap-rehash",
        category="unauthorized",
        description="Rewrite principal to an unauthorized one and recompute the hash "
        "(the 're-add through the normal path' attack from REVIEW-3 T1.4).",
        expected_reason="unauthorized",
    ),
    Attack(
        name="unauth-class-escalation",
        category="unauthorized",
        description="Keep an authorized-for-'configuration' principal but set "
        "constraint_class to 'deletion', rehashed.",
        expected_reason="unauthorized",
    ),
    Attack(
        name="unauth-unknown-principal",
        category="unauthorized",
        description="Principal not present in the authority map at all, rehashed.",
        expected_reason="unauthorized",
    ),
    Attack(
        name="unauth-revoked",
        category="unauthorized",
        description="Constraint was valid at ingest; authority is revoked afterwards "
        "(store-state mutation, not a constraint mutation).",
        expected_reason="unauthorized",
    ),
    Attack(
        name="forge-fabricated-source",
        category="forged",
        description="Self-consistent constraint whose cited source file has different "
        "content than the constraint claims.",
        expected_reason=None,
    ),
    Attack(
        name="forge-missing-source",
        category="forged",
        description="source_ref points at a source file that does not exist.",
        expected_reason=None,
    ),
    Attack(
        name="forge-replay",
        category="forged",
        description="Copy an authorized constraint's fields to a new id with a different "
        "resource_pattern, rehashed, but keep the ORIGINAL source_ref — replaying "
        "someone else's citation.",
        expected_reason=None,
    ),
    Attack(
        name="evade-case-variant",
        category="evasion",
        description='Resource "Deployment/API-Server" vs pattern "deployment/*": documents '
        "that fnmatch is case-sensitive on POSIX.",
        expected_reason=None,
    ),
    Attack(
        name="evade-provider-mismatch",
        category="evasion",
        description='Same resource/action but provider "terraform" vs a kubernetes rule — '
        "must NOT match (correct behaviour, not a hole).",
        expected_reason=None,
    ),
    Attack(
        name="evade-namespace-omitted",
        category="evasion",
        description="Intent with no namespace metadata against a scoped rule — documents "
        "what _scope_matches does today.",
        expected_reason=None,
    ),
    *_ARGV_EVASION_ATTACKS,
]


def attacks() -> list[Attack]:
    """Returns the registry of all known attacks."""
    return list(_REGISTRY)


def apply(attack: Attack, base: Constraint, *, rng: random.Random) -> Constraint | None:
    """Applies ``attack`` to ``base`` and returns the poisoned constraint.

    The result may be inserted directly into ``store.constraints`` to
    bypass ``add_constraint`` (exactly as an attacker who can write to the
    store's backing state would). Returns ``None`` only for attacks whose
    assertion is that ``add_constraint`` itself raises rather than that a
    poisoned object can be constructed (none of the attacks in this
    registry currently need that — all can be expressed as a returned
    constraint — but the hook exists for future ingest-time-only attacks).
    """
    fn = _APPLIERS.get(attack.name)
    if fn is None:
        raise KeyError(f"No applier registered for attack {attack.name!r}")
    return fn(base, rng)


def poison_store(store, attack: Attack, *, rng: random.Random, fraction: float = 0.2) -> list[str]:
    """Poisons ``fraction`` of ``store.constraints`` in-place with ``attack``.

    Returns the ids of the constraints that were poisoned (their post-attack
    id, which for most attacks equals the original id).
    """
    ids = sorted(store.constraints.keys())
    n = max(1, round(len(ids) * fraction)) if ids else 0
    chosen = rng.sample(ids, min(n, len(ids)))

    poisoned_ids: list[str] = []
    for cid in chosen:
        base = store.constraints[cid]
        result = apply(attack, base, rng=rng)
        if result is None:
            continue
        if result.id != cid:
            del store.constraints[cid]
        store.constraints[result.id] = result
        poisoned_ids.append(result.id)
    return poisoned_ids
