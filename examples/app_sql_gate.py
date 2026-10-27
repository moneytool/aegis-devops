"""Check SQL that an LLM wrote before your application runs it (experimental).

See docs/guides/app-sql.md. Aegis classifies each statement (read, write, schema change,
permission change, unclassified) and checks it against signed, authority-checked rules,
here: reads only. It does NOT decide which tables or columns a read may touch; the
database role does that.

    gate = SqlGate("policy/", key=bytes.fromhex(os.environ["AEGIS_SIGNING_KEY"]))
    gate.check(generated_sql)        # raises SqlRejected, or returns quietly
    rows = db.execute(generated_sql)  # as a read-only role, in a read-only transaction
"""

from __future__ import annotations

from pathlib import Path

from aegis_core.authority import load_authority_map
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parsers.sql import from_sql
from aegis_core.store import ConstraintStore


class SqlRejected(PermissionError):
    """The generated SQL may not run."""


class SqlGate:
    def __init__(self, policy_dir: str | Path, *, key: bytes, dialect: str = "postgres",
                 database: str | None = None) -> None:
        # Load once, at startup: verifying signatures and hashes is the slow part.
        policy_dir = Path(policy_dir)
        authority = load_authority_map(policy_dir / "authority.yaml", key=key)
        store = ConstraintStore.load(policy_dir / "constraints.yaml",
                                     authority_map=authority, key=key)
        if not store.constraints:
            raise RuntimeError(f"no usable rules in {policy_dir}: {store.health.quarantined}")
        self._gate = AegisInterceptor(store)
        self._dialect, self._database = dialect, database

    def check(self, sql: str) -> None:
        intents = from_sql(sql, dialect=self._dialect, database=self._database)
        if not intents:
            raise SqlRejected("no SQL statement found")
        for intent in intents:
            decision = self._gate.intercept(intent)
            if decision.verdict != "ALLOW":
                why = ", ".join(decision.citations or decision.notes) or decision.verdict
                raise SqlRejected(f"{intent.action} {intent.resource}: {why}")
