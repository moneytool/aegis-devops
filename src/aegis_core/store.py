"""The Constraint Store: a schema-strict, provenance-verified repository of
operational boundaries.

Every constraint carries two independent guarantees:
  * Integrity (``provenance_hash``) — the constraint's fields match what was
    originally derived from its source.
  * Authority (checked against an externally supplied ``authority_map``) —
    the principal asserting the constraint is allowed to assert that class
    of constraint.

Neither guarantee implies the other: integrity only proves nothing was
tampered with since ingestion, not that the source was ever allowed to set
policy in the first place.

**Load-time pipeline** (``ConstraintStore.load``): for each constraint on
disk, in order —
  1. Integrity  — ``verify_integrity()``; a mismatch quarantines the
     constraint with reason ``"tampered"``.
  2. Source     — only when a ``source_fetcher`` is supplied:
     ``verify_source()`` is re-run against the original source; ``False``
     or a missing/unreadable source (``FileNotFoundError``/``KeyError``)
     quarantines the constraint with reason ``"forged"``. Without a
     fetcher this step is skipped, so forged constraints load normally —
     the fetcher is what makes forgery detectable at all.
  3. Authority-at-decision — *not* checked at load time; a constraint may
     be authorized when ingested and have that authority revoked later, so
     authority is (re-)checked by the interceptor at decision time instead
     (see ``interceptor.py``).

``ConstraintStore.verify_sources`` runs step 2 as a standalone, post-hoc
audit over an already-loaded store, moving any newly-forged constraints
from ``constraints`` into ``quarantined``.

**Quarantine is not deletion.** A quarantined constraint's ``Constraint``
object is kept in ``quarantined_constraints`` and is still *matched*
against intents (``get_matching_quarantined``), because a rule someone
tampered with or forged is evidence that the action it covers is
contested. The interceptor turns such a match into ESCALATE — never
BLOCK, never ALLOW — so a degraded store fails closed instead of looking
like a clean allow. ``store.health`` (:class:`StoreHealth`) summarises the
load for the CLI's ``store_health`` output.
"""

import fnmatch
import hashlib
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from aegis_core.intent import InfrastructureIntent
from aegis_core.provenance import (
    CachingSourceFetcher,
    SourceFetcher,
    compute_provenance_hash,
    verify_source,
)

logger = logging.getLogger(__name__)

_WEEKDAY_ABBR = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass
class StoreHealth:
    """What the CLI reports as ``store_health`` on every output: how many
    constraints actually loaded, which were quarantined and why, how many
    principals the authority map grants anything to, and the SHA-256 of the
    raw constraints file bytes that were loaded."""

    loaded: int = 0
    quarantined: list[dict[str, str]] = field(default_factory=list)
    principals: int = 0
    constraints_sha256: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def quarantine_ratio(self) -> float:
        total = self.loaded + len(self.quarantined)
        return len(self.quarantined) / total if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256_file(path: str | Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


@dataclass
class Constraint:
    """A single, structured operational boundary.

    ``rule_text`` is the human sentence this constraint was derived from —
    it is kept for citation only and is never matched against an intent.
    """
    id: str
    provider: str
    resource_pattern: str
    actions: set[str]
    scope: dict[str, Any]
    time_window: dict[str, Any] | None
    effect: str
    constraint_class: str
    principal: str
    source_ref: str
    source_timestamp: str
    rule_text: str
    provenance_hash: str
    rate_limit: dict[str, Any] | None = None
    """Optional rate/budget rule: ``{"max": N, "per": "1h"|"24h"|"15m",
    "key": [<metadata keys to bucket by>]}`` (PLAN §7.6). ``None`` (the
    default) means this constraint is absolute, not rate-limited — and is
    also what keeps every pre-existing constraint's provenance hash
    unchanged, since it's included in the hash only when set."""

    @classmethod
    def create(
        cls,
        *,
        id: str,
        provider: str,
        resource_pattern: str,
        actions: set[str],
        effect: str,
        constraint_class: str,
        principal: str,
        source_ref: str,
        source_timestamp: str,
        rule_text: str,
        scope: dict[str, Any] | None = None,
        time_window: dict[str, Any] | None = None,
        rate_limit: dict[str, Any] | None = None,
    ) -> "Constraint":
        """Builds a Constraint and computes its provenance hash from the
        source-side fields."""
        actions = set(actions)
        scope = dict(scope or {})
        provenance_hash = compute_provenance_hash(
            provider=provider,
            resource_pattern=resource_pattern,
            actions=actions,
            scope=scope,
            time_window=time_window,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            rate_limit=rate_limit,
        )
        return cls(
            id=id,
            provider=provider,
            resource_pattern=resource_pattern,
            actions=actions,
            scope=scope,
            time_window=time_window,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            rate_limit=rate_limit,
            provenance_hash=provenance_hash,
        )

    def verify_integrity(self) -> bool:
        """Recomputes the provenance hash from the constraint's current
        fields and checks it against the stored hash."""
        expected = compute_provenance_hash(
            provider=self.provider,
            resource_pattern=self.resource_pattern,
            actions=self.actions,
            scope=self.scope,
            time_window=self.time_window,
            effect=self.effect,
            constraint_class=self.constraint_class,
            principal=self.principal,
            source_ref=self.source_ref,
            source_timestamp=self.source_timestamp,
            rule_text=self.rule_text,
            rate_limit=self.rate_limit,
        )
        return expected == self.provenance_hash


def _constraint_to_dict(c: Constraint) -> dict[str, Any]:
    data = {
        "id": c.id,
        "provider": c.provider,
        "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions),
        "scope": c.scope,
        "time_window": c.time_window,
        "effect": c.effect,
        "constraint_class": c.constraint_class,
        "principal": c.principal,
        "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp,
        "rule_text": c.rule_text,
        "provenance_hash": c.provenance_hash,
    }
    # Only written when set, so save()/load() round-trip existing (v1)
    # constraint files byte-for-byte unchanged.
    if c.rate_limit is not None:
        data["rate_limit"] = c.rate_limit
    return data


def _constraint_from_dict(data: dict[str, Any]) -> Constraint:
    return Constraint(
        id=data["id"],
        provider=data["provider"],
        resource_pattern=data["resource_pattern"],
        actions=set(data["actions"]),
        scope=data.get("scope") or {},
        time_window=data.get("time_window"),
        effect=data["effect"],
        constraint_class=data["constraint_class"],
        principal=data["principal"],
        source_ref=data["source_ref"],
        source_timestamp=data["source_timestamp"],
        rule_text=data["rule_text"],
        provenance_hash=data["provenance_hash"],
        rate_limit=data.get("rate_limit"),
    )


def _scope_matches(scope: dict[str, Any], intent: InfrastructureIntent) -> bool:
    if not scope:
        return True
    combined = {**intent.metadata, **intent.params}
    return all(combined.get(key) == value for key, value in scope.items())


def _time_window_matches(window: dict[str, Any], now: datetime) -> bool:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    tz_name = window.get("tz")
    if tz_name:
        from zoneinfo import ZoneInfo

        local = now.astimezone(ZoneInfo(tz_name))
    else:
        local = now

    days = window.get("days")
    if days and _WEEKDAY_ABBR[local.weekday()] not in days:
        return False

    start, end = window.get("start"), window.get("end")
    if start and end:
        current = local.time()
        start_t = datetime.strptime(start, "%H:%M").time()
        end_t = datetime.strptime(end, "%H:%M").time()
        if not (start_t <= current <= end_t):
            return False

    return True


def _constraint_matches(c: Constraint, intent: InfrastructureIntent, now: datetime) -> bool:
    """Whether ``c``'s (provider, resource_pattern, actions, scope,
    time_window) apply to ``intent`` at ``now``. Shared by the live and the
    quarantined match so both use exactly the same semantics."""
    if c.provider != intent.provider:
        return False
    if not fnmatch.fnmatch(intent.resource, c.resource_pattern):
        return False
    if intent.action not in c.actions:
        return False
    if not _scope_matches(c.scope, intent):
        return False
    if c.time_window and not _time_window_matches(c.time_window, now):
        return False
    return True


def _verify_source_safe(constraint: Constraint, fetcher: SourceFetcher) -> bool:
    """``verify_source`` with a missing/unreadable source normalised to
    ``False`` instead of propagating ``FileNotFoundError``/``KeyError``."""
    try:
        return verify_source(constraint, fetcher)
    except (FileNotFoundError, KeyError):
        return False


class ConstraintStore:
    """A secure, integrity-verified store for operational constraints."""

    def __init__(self, authority_map: dict[str, set[str]] | None = None):
        self.constraints: dict[str, Constraint] = {}
        # Who may assert which constraint_class. Default: empty (deny all).
        self.authority_map: dict[str, set[str]] = authority_map or {}
        # Constraints that failed integrity/source verification on load, as
        # {"id", "reason"} entries ...
        self.quarantined: list[dict[str, str]] = []
        # ... and the Constraint objects themselves, kept so the interceptor
        # can still match them (and fail closed) — see module docstring.
        self.quarantined_constraints: list[Constraint] = []
        self.constraints_sha256: str = ""
        self.warnings: list[str] = []

    @property
    def health(self) -> StoreHealth:
        """A fresh :class:`StoreHealth` snapshot of this store."""
        return StoreHealth(
            loaded=len(self.constraints),
            quarantined=[dict(q) for q in self.quarantined],
            principals=len(self.authority_map),
            constraints_sha256=self.constraints_sha256,
            warnings=list(self.warnings),
        )

    def is_authorized(self, principal: str, constraint_class: str) -> bool:
        """Whether ``principal`` may assert constraints of ``constraint_class``."""
        return constraint_class in self.authority_map.get(principal, set())

    def _quarantine(self, constraint: Constraint, reason: str, message: str) -> None:
        self.quarantined.append({"id": constraint.id, "reason": reason})
        self.quarantined_constraints.append(constraint)
        warning = f"Quarantined constraint {constraint.id}: {message}"
        self.warnings.append(warning)
        logger.warning(warning)

    def add_constraint(self, constraint: Constraint) -> Constraint:
        """Adds a constraint, enforcing authority at ingest time.

        Raises PermissionError if the constraint's principal is not
        authorized for its constraint_class.
        """
        if not self.is_authorized(constraint.principal, constraint.constraint_class):
            raise PermissionError(
                f"Principal '{constraint.principal}' is not authorized to assert "
                f"'{constraint.constraint_class}' constraints."
            )
        self.constraints[constraint.id] = constraint
        return constraint

    def get_matching_constraints(
        self, intent: InfrastructureIntent, now: datetime
    ) -> list[Constraint]:
        """Returns every constraint whose pattern applies to this intent."""
        return [c for c in self.constraints.values() if _constraint_matches(c, intent, now)]

    def get_matching_quarantined(
        self, intent: InfrastructureIntent, now: datetime
    ) -> list[tuple[Constraint, str]]:
        """Returns every *quarantined* constraint whose (current, possibly
        tampered) fields apply to this intent, paired with its quarantine
        reason. The interceptor escalates on these; see module docstring."""
        reasons = {q["id"]: q["reason"] for q in self.quarantined}
        return [
            (c, reasons.get(c.id, "quarantined"))
            for c in self.quarantined_constraints
            if _constraint_matches(c, intent, now)
        ]

    def save(self, path: str | Path) -> None:
        payload = {"constraints": [_constraint_to_dict(c) for c in self.constraints.values()]}
        with open(path, "w") as f:
            yaml.safe_dump(payload, f, sort_keys=False)

    @classmethod
    def load(
        cls,
        path: str | Path,
        authority_map: dict[str, set[str]] | None = None,
        *,
        source_fetcher: SourceFetcher | None = None,
    ) -> "ConstraintStore":
        """Loads constraints from a YAML file, verifying each one's
        provenance hash. Constraints that fail verification are quarantined
        rather than loaded.

        When ``source_fetcher`` is given, surviving constraints are also
        re-checked against their original source (see module docstring);
        constraints whose source doesn't back their claimed fields, or
        whose source can't be fetched at all, are quarantined with reason
        ``"forged"`` instead of being loaded. Fetches are cached per
        ``source_ref`` for the duration of this load.
        """
        store = cls(authority_map=authority_map)
        store.constraints_sha256 = _sha256_file(path)
        with open(path) as f:
            payload = yaml.safe_load(f) or {}
        if not isinstance(payload, dict):
            raise ValueError(f"{path}: constraints file must be a mapping with a 'constraints' key")
        caching_fetcher = CachingSourceFetcher(source_fetcher) if source_fetcher else None
        for entry in payload.get("constraints") or []:
            constraint = _constraint_from_dict(entry)
            if not constraint.verify_integrity():
                store._quarantine(constraint, "tampered", "provenance hash mismatch")
                continue
            if caching_fetcher is not None and not _verify_source_safe(
                constraint, caching_fetcher
            ):
                store._quarantine(
                    constraint, "forged", "source does not back its claimed fields"
                )
                continue
            store.constraints[constraint.id] = constraint
        return store

    def verify_sources(self, fetcher: SourceFetcher) -> list[dict]:
        """Post-hoc audit of an already-loaded store: re-checks every
        currently-loaded constraint against its original source, moving any
        that fail into ``quarantined`` (reason ``"forged"``) and removing
        them from ``constraints``.

        Returns the list of newly-quarantined ``{"id", "reason"}`` entries.
        """
        caching_fetcher = CachingSourceFetcher(fetcher)
        newly_quarantined: list[dict[str, str]] = []
        for constraint_id in list(self.constraints.keys()):
            constraint = self.constraints[constraint_id]
            if not _verify_source_safe(constraint, caching_fetcher):
                newly_quarantined.append({"id": constraint_id, "reason": "forged"})
                self._quarantine(constraint, "forged", "source does not back its claimed fields")
                del self.constraints[constraint_id]
        return newly_quarantined
