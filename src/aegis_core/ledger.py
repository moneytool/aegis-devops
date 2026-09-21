"""The Decision Ledger: an append-only record of decisions the interceptor
has made, used to enforce rate/budget constraints (PLAN §7.6).

A rate-limited constraint (``Constraint.rate_limit``) doesn't block on its
own — it only fires once the ledger shows that N matching, *executed*
(non-dry-run, ALLOW) actions have already happened within its window. The
ledger is what lets the interceptor answer "how many times has this
already happened recently?".

``DecisionLedger`` is a plain in-memory log, useful for tests and
short-lived processes. ``JsonlLedger`` is the persistent form: one JSON
line per record, appended to a file and reloadable with ``load()``.
"""

import fnmatch
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent

_WINDOW_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_window(per: str) -> timedelta:
    """Parses a rate-limit window like ``"1h"``, ``"24h"``, ``"15m"``."""
    unit = per[-1]
    if unit not in _WINDOW_UNITS:
        raise ValueError(f"Unrecognised rate window suffix in {per!r}")
    amount = int(per[:-1])
    return timedelta(**{_WINDOW_UNITS[unit]: amount})


@dataclass(frozen=True)
class LedgerRecord:
    timestamp: datetime
    intent: InfrastructureIntent
    decision: str  # the verdict that was actually acted on, e.g. "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "intent": self.intent.to_dict(),
            "decision": self.decision,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LedgerRecord":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            intent=InfrastructureIntent(
                resource=data["intent"]["resource"],
                action=data["intent"]["action"],
                provider=data["intent"]["provider"],
                params=data["intent"].get("params") or {},
                metadata=data["intent"].get("metadata") or {},
            ),
            decision=data["decision"],
        )


def _matches(
    record: LedgerRecord,
    *,
    provider: str | None,
    action: str | None,
    resource_pattern: str | None,
    scope: dict[str, Any] | None,
) -> bool:
    intent = record.intent
    if provider is not None and intent.provider != provider:
        return False
    if action is not None and intent.action != action:
        return False
    if resource_pattern is not None and not fnmatch.fnmatch(intent.resource, resource_pattern):
        return False
    if scope:
        combined = {**intent.metadata, **intent.params}
        if not all(combined.get(key) == value for key, value in scope.items()):
            return False
    return True


class DecisionLedger:
    """An append-only, in-memory log of ``(timestamp, intent, decision)``."""

    def __init__(self) -> None:
        self._records: list[LedgerRecord] = []

    def record(self, intent: InfrastructureIntent, decision: str, now: datetime) -> None:
        self._records.append(LedgerRecord(timestamp=now, intent=intent, decision=decision))

    def count(
        self,
        *,
        since: datetime,
        provider: str | None = None,
        action: str | None = None,
        resource_pattern: str | None = None,
        scope: dict[str, Any] | None = None,
    ) -> int:
        """Counts records at or after ``since`` matching the given filters."""
        total = 0
        for record in self._records:
            if record.timestamp < since:
                continue
            if _matches(
                record,
                provider=provider,
                action=action,
                resource_pattern=resource_pattern,
                scope=scope,
            ):
                total += 1
        return total

    @property
    def records(self) -> list[LedgerRecord]:
        return list(self._records)


class JsonlLedger(DecisionLedger):
    """A :class:`DecisionLedger` that also persists every record as one
    JSON line appended to ``path``, and can reload them with ``load()``."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)

    def record(self, intent: InfrastructureIntent, decision: str, now: datetime) -> None:
        super().record(intent, decision, now)
        record = self._records[-1]
        with open(self.path, "a") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def load(self) -> None:
        """Replaces the in-memory records with what's on disk."""
        self._records = []
        if not self.path.exists():
            return
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                self._records.append(LedgerRecord.from_dict(json.loads(line)))
