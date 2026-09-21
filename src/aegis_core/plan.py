"""Set-level (plan) constraints: rules evaluated over the *whole batch* of
InfrastructureIntents produced by one plan/chart/argv invocation — e.g. every
``resource_changes[]`` entry from a single ``terraform plan``, or every
resource touched by one ``kubectl delete pod a b c``.

A :class:`PlanConstraint` carries the same two independent guarantees as a
per-intent :class:`aegis_core.store.Constraint`:

  * Integrity  — ``provenance_hash`` proves the constraint's fields match
    what was originally derived from its source.
  * Authority  — the asserting ``principal`` must be authorized for the
    constraint's ``constraint_class`` at *decision* time (not just at
    ingest time — see :func:`evaluate_plan`).

Unlike a per-intent ``Constraint``, a ``PlanConstraint`` does not match a
single intent against ``(resource_pattern, actions, scope, time_window)``.
Instead it carries exactly one *batch predicate* — ``max_intents``,
``max_matching``, ``requires_all``, ``forbid_together``, or ``ratio`` — that
is evaluated against the full list of intents in the plan.
"""

import fnmatch
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor, Decision

logger = logging.getLogger(__name__)


def compute_plan_provenance_hash(
    *,
    provider: str,
    effect: str,
    constraint_class: str,
    principal: str,
    source_ref: str,
    source_timestamp: str,
    rule_text: str,
    max_intents: int | None = None,
    max_matching: dict[str, Any] | None = None,
    requires_all: list[dict[str, Any]] | None = None,
    forbid_together: list[dict[str, Any]] | None = None,
    ratio: dict[str, Any] | None = None,
) -> str:
    """SHA-256 of the canonical JSON serialisation of the source fields.

    Mirrors ``aegis_core.provenance.compute_provenance_hash``: computed only
    from the source-side fields (never ingest-time bookkeeping), over the
    predicate fields as well as the shared authority/provenance fields.
    """
    payload = {
        "provider": provider,
        "effect": effect,
        "constraint_class": constraint_class,
        "principal": principal,
        "source_ref": source_ref,
        "source_timestamp": source_timestamp,
        "rule_text": rule_text,
        "max_intents": max_intents,
        "max_matching": max_matching,
        "requires_all": requires_all,
        "forbid_together": forbid_together,
        "ratio": ratio,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class PlanConstraint:
    """A rule evaluated over an entire batch of intents from one plan.

    Exactly one of the predicate fields (``max_intents``, ``max_matching``,
    ``requires_all``, ``forbid_together``, ``ratio``) is expected to be set;
    ``forbid_together`` is an alias of ``requires_all`` that reads better in
    YAML for the "must not co-occur" case — both share the same evaluation
    code path (fires when *every* selector matches at least one intent in
    the batch).
    """

    id: str
    provider: str  # "terraform" | "kubernetes" | "*" (any)
    effect: str  # BLOCK | ESCALATE
    constraint_class: str
    principal: str
    source_ref: str
    source_timestamp: str
    rule_text: str
    provenance_hash: str
    max_intents: int | None = None
    max_matching: dict[str, Any] | None = None
    requires_all: list[dict[str, Any]] | None = None
    forbid_together: list[dict[str, Any]] | None = None
    ratio: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        *,
        id: str,
        provider: str,
        effect: str,
        constraint_class: str,
        principal: str,
        source_ref: str,
        source_timestamp: str,
        rule_text: str,
        max_intents: int | None = None,
        max_matching: dict[str, Any] | None = None,
        requires_all: list[dict[str, Any]] | None = None,
        forbid_together: list[dict[str, Any]] | None = None,
        ratio: dict[str, Any] | None = None,
    ) -> "PlanConstraint":
        """Builds a PlanConstraint and computes its provenance hash from the
        source-side fields."""
        provenance_hash = compute_plan_provenance_hash(
            provider=provider,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            max_intents=max_intents,
            max_matching=max_matching,
            requires_all=requires_all,
            forbid_together=forbid_together,
            ratio=ratio,
        )
        return cls(
            id=id,
            provider=provider,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            provenance_hash=provenance_hash,
            max_intents=max_intents,
            max_matching=max_matching,
            requires_all=requires_all,
            forbid_together=forbid_together,
            ratio=ratio,
        )

    def verify_integrity(self) -> bool:
        """Recomputes the provenance hash from the constraint's current
        fields and checks it against the stored hash."""
        expected = compute_plan_provenance_hash(
            provider=self.provider,
            effect=self.effect,
            constraint_class=self.constraint_class,
            principal=self.principal,
            source_ref=self.source_ref,
            source_timestamp=self.source_timestamp,
            rule_text=self.rule_text,
            max_intents=self.max_intents,
            max_matching=self.max_matching,
            requires_all=self.requires_all,
            forbid_together=self.forbid_together,
            ratio=self.ratio,
        )
        return expected == self.provenance_hash


def _plan_constraint_to_dict(pc: PlanConstraint) -> dict[str, Any]:
    return {
        "id": pc.id,
        "provider": pc.provider,
        "effect": pc.effect,
        "constraint_class": pc.constraint_class,
        "principal": pc.principal,
        "source_ref": pc.source_ref,
        "source_timestamp": pc.source_timestamp,
        "rule_text": pc.rule_text,
        "provenance_hash": pc.provenance_hash,
        "max_intents": pc.max_intents,
        "max_matching": pc.max_matching,
        "requires_all": pc.requires_all,
        "forbid_together": pc.forbid_together,
        "ratio": pc.ratio,
    }


def _plan_constraint_from_dict(data: dict[str, Any]) -> PlanConstraint:
    return PlanConstraint(
        id=data["id"],
        provider=data["provider"],
        effect=data["effect"],
        constraint_class=data["constraint_class"],
        principal=data["principal"],
        source_ref=data["source_ref"],
        source_timestamp=data["source_timestamp"],
        rule_text=data["rule_text"],
        provenance_hash=data["provenance_hash"],
        max_intents=data.get("max_intents"),
        max_matching=data.get("max_matching"),
        requires_all=data.get("requires_all"),
        forbid_together=data.get("forbid_together"),
        ratio=data.get("ratio"),
    )


class PlanConstraintStore:
    """A secure, integrity-verified store for :class:`PlanConstraint`\\ s.

    Mirrors ``aegis_core.store.ConstraintStore``: ``load`` quarantines any
    constraint whose provenance hash no longer matches its fields (reason
    ``"tampered"``); ``add`` enforces authority at ingest time; authority is
    re-checked at decision time by :func:`evaluate_plan`, not at load time,
    since a principal's authority may be revoked after a constraint was
    added.
    """

    def __init__(self, authority_map: dict[str, set[str]] | None = None):
        self.constraints: dict[str, PlanConstraint] = {}
        self.authority_map: dict[str, set[str]] = authority_map or {}
        self.quarantined: list[dict[str, str]] = []

    def is_authorized(self, principal: str, constraint_class: str) -> bool:
        return constraint_class in self.authority_map.get(principal, set())

    def add(self, pc: PlanConstraint) -> PlanConstraint:
        """Adds a plan constraint, enforcing authority at ingest time.

        Raises PermissionError if the constraint's principal is not
        authorized for its constraint_class.
        """
        if not self.is_authorized(pc.principal, pc.constraint_class):
            raise PermissionError(
                f"Principal '{pc.principal}' is not authorized to assert "
                f"'{pc.constraint_class}' plan constraints."
            )
        self.constraints[pc.id] = pc
        return pc

    def verify_integrity(self, pc: PlanConstraint) -> bool:
        return pc.verify_integrity()

    def save(self, path: str | Path) -> None:
        payload = {
            "plan_constraints": [_plan_constraint_to_dict(pc) for pc in self.constraints.values()]
        }
        with open(path, "w") as f:
            yaml.safe_dump(payload, f, sort_keys=False)

    @classmethod
    def load(
        cls, path: str | Path, authority_map: dict[str, set[str]] | None = None
    ) -> "PlanConstraintStore":
        """Loads plan constraints from a YAML file, verifying each one's
        provenance hash. Constraints that fail verification are quarantined
        rather than loaded."""
        store = cls(authority_map=authority_map)
        with open(path) as f:
            payload = yaml.safe_load(f) or {}
        for entry in payload.get("plan_constraints", []):
            pc = _plan_constraint_from_dict(entry)
            if pc.verify_integrity():
                store.constraints[pc.id] = pc
            else:
                store.quarantined.append({"id": pc.id, "reason": "tampered"})
                logger.warning(
                    "Quarantined plan constraint %s: provenance hash mismatch", pc.id
                )
        return store


def _selects(selector: dict[str, Any], intent: InfrastructureIntent) -> bool:
    """Whether ``intent`` matches ``selector``: ``actions`` membership
    (omitted = any action), ``resource_pattern`` via fnmatch (omitted = any
    resource), ``scope`` equality against ``metadata`` + ``params``
    (omitted = any scope). Shared by every predicate evaluator below."""
    actions = selector.get("actions")
    if actions and intent.action not in actions:
        return False
    resource_pattern = selector.get("resource_pattern")
    if resource_pattern and not fnmatch.fnmatch(intent.resource, resource_pattern):
        return False
    scope = selector.get("scope")
    if scope:
        combined = {**intent.metadata, **intent.params}
        if not all(combined.get(key) == value for key, value in scope.items()):
            return False
    return True


def _eval_max_intents(
    pc: PlanConstraint, intents: list[InfrastructureIntent]
) -> tuple[bool, str | None]:
    n = len(intents)
    if n > pc.max_intents:
        return True, f"max_intents: {n} > {pc.max_intents}"
    return False, None


def _eval_max_matching(
    pc: PlanConstraint, intents: list[InfrastructureIntent]
) -> tuple[bool, str | None]:
    spec = pc.max_matching or {}
    max_n = spec.get("max", 0)
    count = sum(1 for i in intents if _selects(spec, i))
    if count > max_n:
        label = "/".join(spec.get("actions") or []) or "matching intents"
        return True, f"max_matching: {count} {label} > {max_n}"
    return False, None


def _eval_selectors_all(
    selectors: list[dict[str, Any]], intents: list[InfrastructureIntent], label: str
) -> tuple[bool, str | None]:
    if not selectors:
        return False, None
    if all(any(_selects(sel, i) for i in intents) for sel in selectors):
        return True, f"{label}: all {len(selectors)} selectors matched"
    return False, None


def _eval_ratio(
    pc: PlanConstraint, intents: list[InfrastructureIntent]
) -> tuple[bool, str | None]:
    spec = pc.ratio or {}
    numerator_sel = spec.get("numerator", {})
    denominator_sel = spec.get("denominator", {})
    max_ratio = spec.get("max", 1.0)
    denom = sum(1 for i in intents if _selects(denominator_sel, i))
    if denom == 0:
        return False, None
    numer = sum(1 for i in intents if _selects(numerator_sel, i))
    r = numer / denom
    if r > max_ratio:
        return True, f"ratio: {numer}/{denom} = {r:.2f} > {max_ratio}"
    return False, None


def _evaluate_predicate(
    pc: PlanConstraint, intents: list[InfrastructureIntent]
) -> tuple[bool, list[str]]:
    """Runs whichever predicate field(s) are set on ``pc`` and returns
    ``(fired, notes)``."""
    fired = False
    notes: list[str] = []

    if pc.max_intents is not None:
        f, note = _eval_max_intents(pc, intents)
        fired = fired or f
        if note:
            notes.append(note)
    if pc.max_matching is not None:
        f, note = _eval_max_matching(pc, intents)
        fired = fired or f
        if note:
            notes.append(note)
    if pc.requires_all is not None:
        f, note = _eval_selectors_all(pc.requires_all, intents, "requires_all")
        fired = fired or f
        if note:
            notes.append(note)
    if pc.forbid_together is not None:
        f, note = _eval_selectors_all(pc.forbid_together, intents, "forbid_together")
        fired = fired or f
        if note:
            notes.append(note)
    if pc.ratio is not None:
        f, note = _eval_ratio(pc, intents)
        fired = fired or f
        if note:
            notes.append(note)

    return fired, notes


@dataclass
class PlanDecision:
    verdict: str  # "ALLOW" | "BLOCK" | "ESCALATE"
    citations: list[str] = field(default_factory=list)
    discarded: list[dict[str, str]] = field(default_factory=list)
    n_intents: int = 0
    per_intent: list[Decision] = field(default_factory=list)
    latency_ms: float = 0.0
    notes: list[str] = field(default_factory=list)


def _effective_verdict(decision: Decision) -> str:
    """The verdict a (possibly dry-run) per-intent Decision would drive a
    plan-level rollup with: a dry run's real-world would-be verdict when
    known, else its actual verdict."""
    if getattr(decision, "dry_run", False) and decision.would_be is not None:
        return decision.would_be
    return decision.verdict


def evaluate_plan(
    interceptor: AegisInterceptor,
    plan_store: PlanConstraintStore,
    intents: list[InfrastructureIntent],
    now: datetime | None = None,
) -> PlanDecision:
    """Evaluates a whole batch of intents from one plan/chart/argv.

    Runs ``interceptor.intercept`` on every intent (the existing per-intent
    guarantees), then evaluates every :class:`PlanConstraint` whose
    ``provider`` matches the batch (or is ``"*"``):

      * a plan constraint that fails integrity is discarded (``"tampered"``);
      * a plan constraint whose principal is no longer authorized for its
        ``constraint_class`` (re-checked against ``plan_store.authority_map``
        at decision time, not load time) is discarded (``"unauthorized"``);
      * otherwise its predicate is evaluated against the full intent batch,
        and a fired predicate contributes its ``effect``.

    The final verdict is the max over every per-intent verdict and every
    fired plan-level effect, using ``BLOCK > ESCALATE > ALLOW``. Citations
    are the union of every per-intent decision's citations and every fired
    plan constraint's id.

    If *every* intent in the batch is a dry run, the plan-level verdict is
    downgraded to ``ALLOW`` and a ``"would_be: ..."`` note records what the
    real run would have received — mirroring
    ``AegisInterceptor.intercept``'s per-intent dry-run handling.
    """
    start = time.perf_counter()
    now = now or datetime.now(UTC)

    per_intent = [interceptor.intercept(intent, now=now) for intent in intents]
    n = len(intents)

    discarded: list[dict[str, str]] = []
    fired: list[tuple[str, str]] = []  # (effect, plan_constraint_id)
    notes: list[str] = []

    for pc in plan_store.constraints.values():
        if pc.provider != "*" and not any(i.provider == pc.provider for i in intents):
            continue
        if not pc.verify_integrity():
            discarded.append({"id": pc.id, "reason": "tampered"})
            continue
        if not plan_store.is_authorized(pc.principal, pc.constraint_class):
            discarded.append({"id": pc.id, "reason": "unauthorized"})
            continue

        pc_fired, pc_notes = _evaluate_predicate(pc, intents)
        if pc_fired:
            fired.append((pc.effect, pc.id))
            notes.extend(pc_notes)

    all_dry_run = n > 0 and all(getattr(d, "dry_run", False) for d in per_intent)

    blocking = any(_effective_verdict(d) == "BLOCK" for d in per_intent) or any(
        effect == "BLOCK" for effect, _ in fired
    )
    escalating = any(_effective_verdict(d) == "ESCALATE" for d in per_intent) or any(
        effect == "ESCALATE" for effect, _ in fired
    )

    if blocking:
        raw_verdict = "BLOCK"
    elif escalating:
        raw_verdict = "ESCALATE"
    else:
        raw_verdict = "ALLOW"

    if all_dry_run:
        verdict = "ALLOW"
        if raw_verdict != "ALLOW":
            notes = [f"would_be: {raw_verdict}", *notes]
    else:
        verdict = raw_verdict

    citations: list[str] = []
    for d in per_intent:
        for c in d.citations:
            if c not in citations:
                citations.append(c)
    for _effect, pid in fired:
        if pid not in citations:
            citations.append(pid)

    latency_ms = (time.perf_counter() - start) * 1000
    return PlanDecision(
        verdict=verdict,
        citations=citations,
        discarded=discarded,
        n_intents=n,
        per_intent=per_intent,
        latency_ms=latency_ms,
        notes=notes,
    )
