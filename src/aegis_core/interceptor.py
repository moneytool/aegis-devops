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

Constraints that fail step 1 or 2 are discarded, not honoured — but they
are not silently dropped either. **Fail closed on integrity failure:** a
matching constraint that was quarantined at load (``tampered`` /
``forged``, kept in ``store.quarantined_constraints``) or discarded at
decision time (``tampered`` / ``unauthorized``) whose ``effect`` was BLOCK
or ESCALATE contributes ESCALATE to the verdict, with
``discarded[].reason`` naming the failure and a note
``"fail-closed: <id> (<reason>)"``. Such a constraint can never contribute
BLOCK: a rule nobody can vouch for is grounds for a human look, not for
an automatic denial — and never grounds for an automatic allow.

With ``fail_closed=True`` an *uncovered* intent (no constraint matched
at all) also becomes ESCALATE (note ``"fail-closed: uncovered"``) instead
of the default ALLOW.

Two more fail-closed clauses (REVIEW-4 T1.3 / T1.7):

* **env-unresolved** -- a constraint that would match except that it
  scopes on ``env`` and the intent has no resolved ``metadata["env"]``
  (the environment map didn't recognise the context/account/project) is
  neither honoured nor dropped: it contributes ESCALATE with the note
  ``"env-unresolved: <id>"``. "Unknown environment" is never "not prod".
* **unknown-target** -- an intent whose parser could not determine what
  it targets (``params["unknown_target"]``, e.g. ``git push -f`` with no
  refspec) contributes ESCALATE with the note ``"unknown-target"``, so it
  can't sail past a rule written for the concrete target as ``ref/*``.

A rate-limited constraint that hasn't hit its quota (step 3) is neither
discarded nor honoured — it's simply not a match for this decision.
"""

import contextlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis_core.intent import InfrastructureIntent
from aegis_core.ledger import DecisionLedger, parse_window
from aegis_core.store import Constraint, ConstraintStore

# Effects that make a quarantined/discarded constraint fail closed.
_ENFORCING_EFFECTS = frozenset({"BLOCK", "ESCALATE"})


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

    def __init__(
        self,
        store: ConstraintStore,
        ledger: DecisionLedger | None = None,
        *,
        fail_closed: bool = False,
    ):
        self.store = store
        self.ledger = ledger
        self.fail_closed = fail_closed

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
        quarantined_matches = self.store.get_matching_quarantined(intent, now)
        get_env_unresolved = getattr(self.store, "get_env_unresolved", None)
        env_unresolved = get_env_unresolved(intent, now) if get_env_unresolved else []
        get_time_window_unresolved = getattr(self.store, "get_time_window_unresolved", None)
        time_window_unresolved = (
            get_time_window_unresolved(intent, now) if get_time_window_unresolved else []
        )
        unknown_target = intent.params.get("unknown_target") is True
        uncovered = (
            not matches
            and not quarantined_matches
            and not env_unresolved
            and not time_window_unresolved
        )
        if uncovered:
            verdict, notes = "ALLOW", []
            if self.fail_closed:
                verdict, notes = "ESCALATE", ["fail-closed: uncovered"]
            if unknown_target:
                verdict, notes = "ESCALATE", [*notes, "unknown-target"]
            decision = Decision(
                verdict="ALLOW" if is_dry_run else verdict,
                covered=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                dry_run=is_dry_run,
                would_be=verdict if is_dry_run and verdict != "ALLOW" else None,
                notes=notes,
            )
            self._record(intent, decision, now)
            return decision

        discarded: list[dict[str, str]] = []
        notes: list[str] = []
        fail_closed = False
        verified = []
        for c in env_unresolved:
            fail_closed = True
            notes.append(f"env-unresolved: {c.id}")
        for c in time_window_unresolved:
            fail_closed = True
            notes.append(f"time-window-unresolved: {c.id}")
        if unknown_target:
            fail_closed = True
            notes.append("unknown-target")
        for c, reason in quarantined_matches:
            discarded.append({"id": c.id, "reason": reason})
            if c.effect in _ENFORCING_EFFECTS:
                fail_closed = True
                notes.append(f"fail-closed: {c.id} ({reason})")
        for c in matches:
            # REVIEW-4 L4: re-verify integrity here even though
            # ConstraintStore.load already did it for every constraint that
            # made it into `store.constraints`. This isn't redundant: a
            # library caller can hold a reference to a live Constraint
            # object and mutate one of its fields in place (e.g. widening
            # `actions` or flipping `effect`) between load time and a later
            # `intercept()` call -- load-time verification has no way to
            # see that. The cost is bounded (~4 sha256 hashes per matched
            # rule, not per loaded rule -- see get_matching_constraints'
            # index), so we pay it on every decision instead of trusting a
            # verification result that may be stale by the time it matters.
            reason = None
            if not c.verify_integrity():
                reason = "tampered"
            elif not self.store.is_authorized(c.principal, c.constraint_class):
                reason = "unauthorized"
            if reason is not None:
                discarded.append({"id": c.id, "reason": reason})
                if c.effect in _ENFORCING_EFFECTS:
                    fail_closed = True
                    notes.append(f"fail-closed: {c.id} ({reason})")
                continue
            verified.append(c)

        # Rate-limited constraints need a consistent load -> count -> record
        # view of the ledger even when other processes are racing the same
        # decision (T1.9): everything from here through the eventual
        # ``self._record`` call below runs inside a single ledger
        # transaction (a no-op context manager when the ledger doesn't
        # support/require locking, e.g. the plain in-memory
        # ``DecisionLedger`` or when there's nothing rate-limited to check).
        has_rate_limited = any(c.rate_limit is not None for c in verified)
        with self._ledger_txn() if has_rate_limited else contextlib.nullcontext():
            if has_rate_limited and self.ledger is not None and hasattr(self.ledger, "load"):
                self.ledger.load(now)
            # A broken hash-chain means the ledger's history can't be
            # trusted -- fail closed by treating every rate-limited
            # constraint as exhausted (never as satisfied), same as a
            # tampered/unauthorized constraint: ESCALATE, never BLOCK.
            chain_ok = True
            if has_rate_limited and self.ledger is not None:
                chain_ok = getattr(self.ledger, "chain_ok", True)

            active: list[Constraint] = []
            for c in verified:
                if c.rate_limit is None:
                    active.append(c)
                    continue
                if not chain_ok:
                    fail_closed = True
                    if "ledger: chain-broken" not in notes:
                        notes.append("ledger: chain-broken")
                    continue
                exhausted, count, max_ = self._rate_limit_exhausted(c, intent, now)
                if exhausted:
                    active.append(c)
                    notes.append(f"rate-limit: {c.id} {count}/{max_} in {c.rate_limit['per']}")

            blocking = [c for c in active if c.effect == "BLOCK"]
            escalating = [c for c in active if c.effect == "ESCALATE"]

            if blocking:
                verdict, citations = "BLOCK", [c.id for c in blocking]
            elif escalating or fail_closed:
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

    def _ledger_txn(self):
        """Returns the ledger's ``transaction()`` context manager when it
        has one (``JsonlLedger``/``SqliteLedger``), else a no-op. Duck-typed
        rather than an isinstance check so any ledger implementation can
        opt in just by providing a ``transaction()`` method."""
        if self.ledger is not None and hasattr(self.ledger, "transaction"):
            return self.ledger.transaction()
        return contextlib.nullcontext()

    def _rate_limit_exhausted(
        self, c: Constraint, intent: InfrastructureIntent, now: datetime
    ) -> tuple[bool, int, int]:
        """Returns ``(exhausted, count, max)`` for ``c``'s rate-limit window,
        counting prior executed (non-dry-run, ALLOW) actions matching its
        scope. ``rate_limit.key`` may include ``"resource"`` to bucket on
        the concrete intent resource (e.g. ``container/cluster/prod-1`` vs.
        ``prod-2``) rather than only the constraint's (often shared)
        ``resource_pattern``."""
        max_ = c.rate_limit["max"]
        if self.ledger is None:
            return False, 0, max_
        window = parse_window(c.rate_limit["per"])
        since = now - window
        combined = {**intent.metadata, **intent.params, "resource": intent.resource}
        scope_filter = dict(c.scope)
        for key in c.rate_limit.get("key") or []:
            if key in combined:
                scope_filter[key] = combined[key]
        count = self.ledger.count(
            since=since,
            provider=c.provider,
            action=intent.action,
            resource_pattern=c.resource_pattern,
            scope=scope_filter or None,
        )
        return count >= max_, count, max_

    def _record(self, intent: InfrastructureIntent, decision: Decision, now: datetime) -> None:
        """Records every non-dry-run ALLOW decision into the ledger (when
        one is attached). Blocked/escalated actions never executed, so they
        don't count towards future rate-limit windows.

        Wrapped in the ledger's transaction (when it supports one) so this
        append can never race a concurrent load -> count -> record cycle in
        another process; reentrant if the caller already holds it (see
        ``intercept``'s rate-limit handling above)."""
        if self.ledger is None or decision.dry_run or decision.verdict != "ALLOW":
            return
        with self._ledger_txn():
            self.ledger.record(intent, decision.verdict, now)
