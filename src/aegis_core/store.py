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
"""

import fnmatch
import logging
from dataclasses import dataclass
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
        # Constraints that failed integrity verification on load.
        self.quarantined: list[dict[str, str]] = []

    def is_authorized(self, principal: str, constraint_class: str) -> bool:
        """Whether ``principal`` may assert constraints of ``constraint_class``."""
        return constraint_class in self.authority_map.get(principal, set())

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
        matches = []
        for c in self.constraints.values():
            if c.provider != intent.provider:
                continue
            if not fnmatch.fnmatch(intent.resource, c.resource_pattern):
                continue
            if intent.action not in c.actions:
                continue
            if not _scope_matches(c.scope, intent):
                continue
            if c.time_window and not _time_window_matches(c.time_window, now):
                continue
            matches.append(c)
        return matches

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
        with open(path) as f:
            payload = yaml.safe_load(f) or {}
        caching_fetcher = CachingSourceFetcher(source_fetcher) if source_fetcher else None
        for entry in payload.get("constraints", []):
            constraint = _constraint_from_dict(entry)
            if not constraint.verify_integrity():
                store.quarantined.append({"id": constraint.id, "reason": "tampered"})
                logger.warning(
                    "Quarantined constraint %s: provenance hash mismatch", constraint.id
                )
                continue
            if caching_fetcher is not None and not _verify_source_safe(
                constraint, caching_fetcher
            ):
                store.quarantined.append({"id": constraint.id, "reason": "forged"})
                logger.warning(
                    "Quarantined constraint %s: source does not back its claimed fields",
                    constraint.id,
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
                entry = {"id": constraint_id, "reason": "forged"}
                newly_quarantined.append(entry)
                self.quarantined.append(entry)
                del self.constraints[constraint_id]
                logger.warning(
                    "Quarantined constraint %s: source does not back its claimed fields",
                    constraint_id,
                )
        return newly_quarantined
