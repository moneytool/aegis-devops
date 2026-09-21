"""The Aegis Interceptor: the middleware that decides whether a proposed
InfrastructureIntent may proceed.

Decision pipeline, per matching constraint, in order:
  1. Integrity  — its provenance hash still matches its current fields.
     (Forged constraints never reach this point at all: they're quarantined
     at ``ConstraintStore.load`` time — see store.py — when a
     ``source_fetcher`` was supplied.)
  2. Authority  — its principal is still authorized for its constraint_class
     (a principal's authority may have been revoked after the constraint
     was added).
  3. Rate       — constraints carrying a ``rate_limit`` (PLAN §7.6) only
     apply once the attached ``DecisionLedger`` shows their window's quota
     of matching, previously-*executed* actions has been used up; below
     quota, the constraint simply doesn't fire this time.
  4. Effect     — BLOCK outranks ESCALATE outranks ALLOW among whatever
     constraints survived steps 1-3.

Constraints that fail step 1 or 2 are discarded, not honoured. A
rate-limited constraint that hasn't hit its quota (step 3) is neither
discarded nor honoured — it's simply not a match for this decision.
"""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.ledger import DecisionLedger, parse_window
from aegis_core.store import Constraint, ConstraintStore


@dataclass
class Decision:
    verdict: str  # "ALLOW" | "BLOCK" | "ESCALATE"
    citations: list[str] = field(default_factory=list)
    discarded: list[dict[str, str]] = field(default_factory=list)
    covered: bool = False
    latency_ms: float = 0.0
    dry_run: bool = False
    would_be: str | None = None
    notes: list[str] = field(default_factory=list)


class AegisInterceptor:
    """
    The core decision engine. Intercepts InfrastructureIntents and
    evaluates them against the ConstraintStore.

    Dry runs (``intent.params["dry_run"] is True`` -- see the parsers'
    dry-run normalisation) are never blocked or escalated, because a
    rehearsal (``kubectl --dry-run=server``, ``aws ec2 ... --dry-run``, ...)
    can't change infrastructure. The interceptor still computes the verdict
    the *real* run would receive and reports it in ``would_be`` (with
    ``citations`` set to the constraints that would have driven it), so a
    human or downstream check can see what's actually at stake.
    """

    def __init__(self, store: ConstraintStore, ledger: DecisionLedger | None = None):
        self.store = store
        self.ledger = ledger

    def intercept(self, intent: InfrastructureIntent, now: datetime | None = None) -> Decision:
        """Evaluates an intent and returns a Decision.

        ``now`` is the evaluation time used for time-windowed constraints;
        it defaults to the current UTC time but should be passed explicitly
        in tests for determinism.
        """
        start = time.perf_counter()
        now = now or datetime.now(UTC)
        is_dry_run = intent.params.get("dry_run") is True

        matches = self.store.get_matching_constraints(intent, now)
        if not matches:
            decision = Decision(
                verdict="ALLOW",
                covered=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                dry_run=is_dry_run,
            )
            self._record(intent, decision, now)
            return decision

        discarded: list[dict[str, str]] = []
        verified = []
        for c in matches:
            if not c.verify_integrity():
                discarded.append({"id": c.id, "reason": "tampered"})
                continue
            if not self.store.is_authorized(c.principal, c.constraint_class):
                discarded.append({"id": c.id, "reason": "unauthorized"})
                continue
            verified.append(c)

        notes: list[str] = []
        active: list[Constraint] = []
        for c in verified:
            if c.rate_limit is None:
                active.append(c)
                continue
            count = self._rate_count(c, intent, now)
            max_ = c.rate_limit["max"]
            if count >= max_:
                active.append(c)
                notes.append(f"rate-limit: {c.id} {count}/{max_} in {c.rate_limit['per']}")

        blocking = [c for c in active if c.effect == "BLOCK"]
        escalating = [c for c in active if c.effect == "ESCALATE"]

        if blocking:
            verdict, citations = "BLOCK", [c.id for c in blocking]
        elif escalating:
            verdict, citations = "ESCALATE", [c.id for c in escalating]
        else:
            verdict, citations = "ALLOW", [c.id for c in active]

        latency_ms = (time.perf_counter() - start) * 1000
        if is_dry_run:
            decision = Decision(
                verdict="ALLOW",
                citations=citations,
                discarded=discarded,
                covered=True,
                latency_ms=latency_ms,
                dry_run=True,
                would_be=verdict,
                notes=notes,
            )
            self._record(intent, decision, now)
            return decision

        decision = Decision(
            verdict=verdict,
            citations=citations,
            discarded=discarded,
            covered=True,
            latency_ms=latency_ms,
            notes=notes,
        )
        self._record(intent, decision, now)
        return decision

    def _rate_count(self, c: Constraint, intent: InfrastructureIntent, now: datetime) -> int:
        """Counts prior executed (non-dry-run, ALLOW) actions matching
        ``c``'s rate-limit scope within its window, ending at ``now``."""
        window = parse_window(c.rate_limit["per"])
        since = now - window
        combined = {**intent.metadata, **intent.params}
        scope_filter = dict(c.scope)
        for key in c.rate_limit.get("key") or []:
            if key in combined:
                scope_filter[key] = combined[key]
        if self.ledger is None:
            return 0
        return self.ledger.count(
            since=since,
            provider=c.provider,
            action=intent.action,
            resource_pattern=c.resource_pattern,
            scope=scope_filter or None,
        )

    def _record(self, intent: InfrastructureIntent, decision: Decision, now: datetime) -> None:
        """Records every non-dry-run ALLOW decision into the ledger (when
        one is attached). Blocked/escalated actions never executed, so they
        don't count towards future rate-limit windows."""
        if self.ledger is None or decision.dry_run or decision.verdict != "ALLOW":
            return
        self.ledger.record(intent, decision.verdict, now)
