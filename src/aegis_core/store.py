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
"""

import fnmatch
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from aegis_core.intent import InfrastructureIntent
from aegis_core.provenance import compute_provenance_hash

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
        )
        return expected == self.provenance_hash


def _constraint_to_dict(c: Constraint) -> dict[str, Any]:
    return {
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
        cls, path: str | Path, authority_map: dict[str, set[str]] | None = None
    ) -> "ConstraintStore":
        """Loads constraints from a YAML file, verifying each one's
        provenance hash. Constraints that fail verification are quarantined
        rather than loaded."""
        store = cls(authority_map=authority_map)
        with open(path) as f:
            payload = yaml.safe_load(f) or {}
        for entry in payload.get("constraints", []):
            constraint = _constraint_from_dict(entry)
            if constraint.verify_integrity():
                store.constraints[constraint.id] = constraint
            else:
                store.quarantined.append({"id": constraint.id, "reason": "tampered"})
                logger.warning(
                    "Quarantined constraint %s: provenance hash mismatch", constraint.id
                )
        return store
