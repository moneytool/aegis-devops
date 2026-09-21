"""The Aegis Interceptor: the middleware that decides whether a proposed
InfrastructureIntent may proceed.

A constraint only gets a vote in the decision if it passes both checks at
decision time, not just at ingest time:
  1. Integrity  — its provenance hash still matches its current fields.
  2. Authority  — its principal is still authorized for its constraint_class
     (a principal's authority may have been revoked after the constraint
     was added).

Constraints that fail either check are discarded, not honoured.
"""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.store import ConstraintStore


@dataclass
class Decision:
    verdict: str  # "ALLOW" | "BLOCK" | "ESCALATE"
    citations: list[str] = field(default_factory=list)
    discarded: list[dict[str, str]] = field(default_factory=list)
    covered: bool = False
    latency_ms: float = 0.0


class AegisInterceptor:
    """
    The core decision engine. Intercepts InfrastructureIntents and
    evaluates them against the ConstraintStore.
    """

    def __init__(self, store: ConstraintStore):
        self.store = store

    def intercept(self, intent: InfrastructureIntent, now: datetime | None = None) -> Decision:
        """Evaluates an intent and returns a Decision.

        ``now`` is the evaluation time used for time-windowed constraints;
        it defaults to the current UTC time but should be passed explicitly
        in tests for determinism.
        """
        start = time.perf_counter()
        now = now or datetime.now(UTC)

        matches = self.store.get_matching_constraints(intent, now)
        if not matches:
            return Decision(
                verdict="ALLOW",
                covered=False,
                latency_ms=(time.perf_counter() - start) * 1000,
            )

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

        blocking = [c for c in verified if c.effect == "BLOCK"]
        escalating = [c for c in verified if c.effect == "ESCALATE"]

        if blocking:
            verdict, citations = "BLOCK", [c.id for c in blocking]
        elif escalating:
            verdict, citations = "ESCALATE", [c.id for c in escalating]
        else:
            verdict, citations = "ALLOW", [c.id for c in verified]

        return Decision(
            verdict=verdict,
            citations=citations,
            discarded=discarded,
            covered=True,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
