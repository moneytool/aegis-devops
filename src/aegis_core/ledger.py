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
``SqliteLedger`` is an alternative persistent form backed by a SQLite
database. Both expose the same interface (``record``, ``load``, ``count``,
``transaction``) so the interceptor can treat them interchangeably; the
CLI picks between them by file extension (``.jsonl`` -> ``JsonlLedger``,
``.db``/``.sqlite``/``.sqlite3`` -> ``SqliteLedger``).

**Locking.** Both persistent ledgers serialise load -> count -> record
across processes so that concurrent, racing decisions against the same
rate-limited constraint can't all squeak through: ``JsonlLedger`` takes an
``fcntl.flock(LOCK_EX)`` on a sidecar ``<path>.lock`` file for the whole
``with ledger.transaction():`` block; ``SqliteLedger`` uses a SQLite
``BEGIN IMMEDIATE`` transaction for the same purpose. ``DecisionLedger``
(the plain in-memory ledger) intentionally has no ``transaction()`` method
at all — callers duck-type with ``hasattr(ledger, "transaction")`` to
decide whether locking is available/necessary.

**Rotation.** Both persistent ledgers accept a ``max_window`` constructor
argument (default 24h) and prune records older than it on every
``load()``. The caller (typically the CLI) should pass the largest
``per`` across the loaded constraints so no live rate window is ever
pruned away. ``JsonlLedger`` rewrites its file under the lock when a
prune removes more than 10% of records; ``SqliteLedger`` just deletes the
stale rows.

**Robustness.** Malformed JSONL lines are skipped and counted in
``ledger.skipped_lines`` rather than raising. Every persisted record
carries a ``prev`` field: the SHA-256 hex digest of the previous record's
serialised line (genesis records use ``"0" * 64``). ``load()`` walks this
hash chain and sets ``ledger.chain_ok`` to ``False`` the moment a record's
declared ``prev`` doesn't match the hash of what actually precedes it —
e.g. because the file was truncated or edited by hand. A broken chain
doesn't raise either; it's a signal the interceptor uses to fail closed
on rate-limited constraints (see ``interceptor.py``).
"""

import contextlib
import fnmatch
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent

_WINDOW_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

_GENESIS_HASH = "0" * 64

# The metadata/scope vocabulary the parsers are known to emit (see T2.5),
# plus "resource" itself, which ``rate_limit.key`` may also name so a rate
# limit can bucket on the concrete intent resource rather than the (often
# shared) constraint resource_pattern. ``validate_rate_key`` warns about
# any ``key`` entry outside this set -- it's very likely a typo or a field
# no parser actually produces, which would silently make that key a no-op
# bucket dimension.
KNOWN_RATE_KEY_VOCABULARY = frozenset(
    {
        "resource",
        "namespace",
        "region",
        "zone",
        "project",
        "account",
        "subscription",
        "resource_group",
        "context",
        "cluster",
        "env",
        "profile",
    }
)


def parse_window(per: str) -> timedelta:
    """Parses a rate-limit window like ``"1h"``, ``"24h"``, ``"15m"``."""
    unit = per[-1]
    if unit not in _WINDOW_UNITS:
        raise ValueError(f"Unrecognised rate window suffix in {per!r}")
    amount = int(per[:-1])
    return timedelta(**{_WINDOW_UNITS[unit]: amount})


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


@dataclass(frozen=True)
class LedgerRecord:
    timestamp: datetime
    intent: InfrastructureIntent
    decision: str  # the verdict that was actually acted on, e.g. "ALLOW"
    prev: str = _GENESIS_HASH
    """SHA-256 of the previous persisted record's serialised line (hash-chain
    for tamper/truncation detection). Only meaningful for persisted ledgers;
    plain in-memory ``DecisionLedger`` records leave this at the default."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "intent": self.intent.to_dict(),
            "decision": self.decision,
            "prev": self.prev,
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
            prev=data.get("prev", _GENESIS_HASH),
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
        # "resource" isn't part of metadata/params -- it's the intent's own
        # field -- but rate_limit.key may still bucket on it (T1.9), so make
        # it available to scope matching alongside metadata/params.
        combined = {**intent.metadata, **intent.params, "resource": intent.resource}
        if not all(combined.get(key) == value for key, value in scope.items()):
            return False
    return True


class DecisionLedger:
    """An append-only, in-memory log of ``(timestamp, intent, decision)``.

    Deliberately has no ``transaction()`` method: there's nothing to lock
    for a process-local, in-memory ledger, and its absence is what lets
    callers duck-type (``hasattr(ledger, "transaction")``) to tell it apart
    from the persistent ledgers that do need cross-process locking.
    """

    def __init__(self) -> None:
        self._records: list[LedgerRecord] = []
        # Always present (even though only persisted ledgers can actually
        # detect a problem) so callers can read these unconditionally.
        self.chain_ok: bool = True
        self.skipped_lines: int = 0

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

    def validate_rate_key(self, key: list[str]) -> list[str]:
        """Returns human-readable warnings for any ``rate_limit.key`` entry
        that doesn't name a field in :data:`KNOWN_RATE_KEY_VOCABULARY` --
        i.e. something no parser is known to emit, which silently makes
        that key a no-op bucket dimension (T1.9). Store/CLI call this at
        load time; it performs no I/O itself."""
        return [
            f"rate_limit.key {field!r} is not in the known metadata vocabulary "
            f"({sorted(KNOWN_RATE_KEY_VOCABULARY)}) -- it will never bucket anything"
            for field in key
            if field not in KNOWN_RATE_KEY_VOCABULARY
        ]


class JsonlLedger(DecisionLedger):
    """A :class:`DecisionLedger` that also persists every record as one
    JSON line appended to ``path``, and can reload them with ``load()``.

    Serialises load -> count -> record across processes via
    ``fcntl.flock`` on a sidecar ``<path>.lock`` file (see
    :meth:`transaction`), prunes records older than ``max_window`` on
    every ``load()``, skips malformed lines instead of raising, and
    verifies a per-line hash chain (``ledger.chain_ok``) to detect
    truncation or tampering.
    """

    def __init__(self, path: str | Path, max_window: timedelta = timedelta(hours=24)) -> None:
        super().__init__()
        self.path = Path(path)
        self.max_window = max_window
        self._last_hash = _GENESIS_HASH
        self._lock_fh = None  # set while inside transaction()

    @property
    def _lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @contextlib.contextmanager
    def transaction(self):
        """Holds an exclusive ``fcntl`` lock on a sidecar ``.lock`` file for
        the whole block, so a caller can do load -> count -> record without
        another process interleaving in between. Reentrant within the same
        ledger instance/process (a nested call just reuses the held lock)."""
        if self._lock_fh is not None:
            # Already holding the lock (nested transaction()) -- reuse it.
            yield self
            return
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_fh = open(self._lock_path, "a+")
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            self._lock_fh = lock_fh
            try:
                yield self
            finally:
                self._lock_fh = None
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        finally:
            lock_fh.close()

    def record(self, intent: InfrastructureIntent, decision: str, now: datetime) -> None:
        with self.transaction():
            prev = self._last_hash
            super().record(intent, decision, now)
            record = LedgerRecord(
                timestamp=self._records[-1].timestamp,
                intent=self._records[-1].intent,
                decision=self._records[-1].decision,
                prev=prev,
            )
            self._records[-1] = record
            line = json.dumps(record.to_dict())
            with open(self.path, "a") as f:
                f.write(line + "\n")
            self._last_hash = _line_hash(line)

    def load(self, now: datetime | None = None) -> None:
        """Replaces the in-memory records with what's on disk, dropping
        anything older than ``max_window`` (relative to ``now``, defaulting
        to the current UTC time), skipping malformed lines, and verifying
        the hash chain. Rewrites the file (under the lock) when pruning
        removes more than 10% of records."""
        with self.transaction():
            now = now or datetime.now(UTC)
            cutoff = now - self.max_window

            self.skipped_lines = 0
            self.chain_ok = True
            self._last_hash = _GENESIS_HASH

            if not self.path.exists():
                self._records = []
                return

            raw_lines = [ln.strip() for ln in self.path.read_text().splitlines() if ln.strip()]

            parsed: list[LedgerRecord] = []
            expected_prev = _GENESIS_HASH
            for raw in raw_lines:
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    self.skipped_lines += 1
                    expected_prev = _line_hash(raw)
                    continue
                claimed_prev = data.get("prev", _GENESIS_HASH)
                if claimed_prev != expected_prev:
                    self.chain_ok = False
                expected_prev = _line_hash(raw)
                try:
                    parsed.append(LedgerRecord.from_dict(data))
                except (KeyError, ValueError, TypeError):
                    self.skipped_lines += 1
            self._last_hash = expected_prev

            kept = [r for r in parsed if r.timestamp >= cutoff]
            self._records = kept

            pruned = len(parsed) - len(kept)
            if parsed and pruned / len(parsed) > 0.1:
                new_lines = []
                rebuilt_prev = _GENESIS_HASH
                for rec in kept:
                    payload = LedgerRecord(
                        timestamp=rec.timestamp,
                        intent=rec.intent,
                        decision=rec.decision,
                        prev=rebuilt_prev,
                    )
                    line = json.dumps(payload.to_dict())
                    new_lines.append(line)
                    rebuilt_prev = _line_hash(line)
                self.path.write_text("".join(f"{ln}\n" for ln in new_lines))
                self._records = kept
                self._last_hash = rebuilt_prev


class SqliteLedger(DecisionLedger):
    """A :class:`DecisionLedger` persisted to a SQLite database, offering
    the same interface as :class:`JsonlLedger` (``record``, ``load``,
    ``count``, ``transaction``, ``max_window`` pruning, hash-chained
    records). Uses ``BEGIN IMMEDIATE`` to serialise load -> count -> record
    across processes instead of ``fcntl``.
    """

    def __init__(self, path: str | Path, max_window: timedelta = timedelta(hours=24)) -> None:
        super().__init__()
        self.path = Path(path)
        self.max_window = max_window
        self._last_hash = _GENESIS_HASH
        self._txn_conn: sqlite3.Connection | None = None

    def _new_connection(self) -> sqlite3.Connection:
        """Opens a connection, retrying briefly on ``database is locked``:
        the very first connections from many concurrent processes can race
        each other creating the file/table and switching on WAL, which is
        exactly the kind of transient contention ``busy_timeout`` is meant
        to smooth over, but a fresh connection's own setup statements don't
        always get the benefit before it's established."""
        import time as _time

        self.path.parent.mkdir(parents=True, exist_ok=True)
        last_exc: sqlite3.OperationalError | None = None
        for _ in range(200):
            try:
                conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
                conn.execute("PRAGMA busy_timeout=30000")
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        data TEXT NOT NULL,
                        prev TEXT NOT NULL
                    )"""
                )
                return conn
            except sqlite3.OperationalError as exc:
                last_exc = exc
                _time.sleep(0.05)
        assert last_exc is not None
        raise last_exc

    @contextlib.contextmanager
    def transaction(self):
        """Holds a ``BEGIN IMMEDIATE`` write transaction for the whole
        block. Reentrant within the same ledger instance/process."""
        if self._txn_conn is not None:
            yield self
            return
        import time as _time

        conn = self._new_connection()
        try:
            last_exc: sqlite3.OperationalError | None = None
            for _ in range(200):
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError as exc:
                    last_exc = exc
                    _time.sleep(0.05)
            else:
                assert last_exc is not None
                raise last_exc
            self._txn_conn = conn
            try:
                yield self
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            self._txn_conn = None
            conn.close()

    def record(self, intent: InfrastructureIntent, decision: str, now: datetime) -> None:
        with self.transaction():
            conn = self._txn_conn
            assert conn is not None
            prev = self._last_hash
            super().record(intent, decision, now)
            record = LedgerRecord(
                timestamp=self._records[-1].timestamp,
                intent=self._records[-1].intent,
                decision=self._records[-1].decision,
                prev=prev,
            )
            self._records[-1] = record
            data = json.dumps(record.to_dict())
            conn.execute(
                "INSERT INTO records (ts, data, prev) VALUES (?, ?, ?)",
                (now.isoformat(), data, prev),
            )
            self._last_hash = _line_hash(data)

    def load(self, now: datetime | None = None) -> None:
        with self.transaction():
            conn = self._txn_conn
            assert conn is not None
            now = now or datetime.now(UTC)
            cutoff = now - self.max_window

            self.skipped_lines = 0
            self.chain_ok = True

            cur = conn.execute("DELETE FROM records WHERE ts < ?", (cutoff.isoformat(),))
            pruned = cur.rowcount
            id_rows = conn.execute("SELECT id, data, prev FROM records ORDER BY id").fetchall()

            if pruned > 0 and id_rows:
                # Rotation removed the earliest record(s): rebuild the
                # prev-chain over what remains so a normal prune isn't
                # mistaken for tampering/truncation on the next load.
                expected_prev = _GENESIS_HASH
                data_rows = []
                for rid, data, _old_prev in id_rows:
                    conn.execute("UPDATE records SET prev=? WHERE id=?", (expected_prev, rid))
                    data_rows.append((data, expected_prev))
                    expected_prev = _line_hash(data)
            else:
                data_rows = [(data, prev) for _rid, data, prev in id_rows]

            records: list[LedgerRecord] = []
            expected_prev = _GENESIS_HASH
            for data, prev in data_rows:
                if prev != expected_prev:
                    self.chain_ok = False
                expected_prev = _line_hash(data)
                try:
                    records.append(LedgerRecord.from_dict(json.loads(data)))
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    self.skipped_lines += 1
            self._records = records
            self._last_hash = expected_prev
