"""The common ``Verifier`` protocol every baseline (and Aegis itself)
implements, so ``scripts/benchmark.py`` can run them through one loop.

All verifiers return the *same* ``Decision`` dataclass that
``AegisInterceptor`` already produces (``aegis_core.interceptor.Decision``)
so the benchmark's metrics code never has to branch on which verifier
produced a result.
"""

from datetime import datetime
from typing import Protocol, runtime_checkable

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor, Decision
from aegis_core.store import ConstraintStore


@runtime_checkable
class Verifier(Protocol):
    """Anything that can decide ALLOW/BLOCK/ESCALATE for an intent."""

    name: str

    def decide(self, intent: InfrastructureIntent, now: datetime) -> Decision:
        ...


class AegisVerifier:
    """Wraps ``AegisInterceptor`` so it satisfies the ``Verifier`` protocol.

    This is the system under test: it is the only verifier here that
    performs the integrity + authority checks, and it only ever loads a
    ``ConstraintStore`` that has already quarantined tampered constraints
    at load time.
    """

    name = "aegis"

    def __init__(self, store: ConstraintStore):
        self._interceptor = AegisInterceptor(store)

    def decide(self, intent: InfrastructureIntent, now: datetime) -> Decision:
        return self._interceptor.intercept(intent, now=now)
