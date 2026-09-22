import json
import multiprocessing as mp
from datetime import UTC, datetime, timedelta

from aegis_core.intent import InfrastructureIntent
from aegis_core.ledger import DecisionLedger, JsonlLedger, SqliteLedger, parse_window

NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)


def make_intent(**overrides) -> InfrastructureIntent:
    defaults = dict(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        metadata={"namespace": "prod"},
    )
    defaults.update(overrides)
    return InfrastructureIntent(**defaults)


def test_parse_window_units():
    assert parse_window("15m") == timedelta(minutes=15)
    assert parse_window("1h") == timedelta(hours=1)
    assert parse_window("24h") == timedelta(hours=24)


def test_record_and_count_basic():
    ledger = DecisionLedger()
    intent = make_intent()
    ledger.record(intent, "ALLOW", NOW)

    count = ledger.count(since=NOW - timedelta(hours=1), provider="kubernetes")
    assert count == 1


def test_count_filters_by_action_and_resource_pattern():
    ledger = DecisionLedger()
    ledger.record(make_intent(action="scale", resource="deployment/api-server"), "ALLOW", NOW)
    ledger.record(make_intent(action="delete", resource="deployment/api-server"), "ALLOW", NOW)
    ledger.record(make_intent(action="scale", resource="deployment/other"), "ALLOW", NOW)

    count = ledger.count(
        since=NOW - timedelta(hours=1),
        action="scale",
        resource_pattern="deployment/api-*",
    )
    assert count == 1


def test_count_filters_by_scope():
    ledger = DecisionLedger()
    ledger.record(make_intent(metadata={"namespace": "prod"}), "ALLOW", NOW)
    ledger.record(make_intent(metadata={"namespace": "staging"}), "ALLOW", NOW)

    count = ledger.count(since=NOW - timedelta(hours=1), scope={"namespace": "prod"})
    assert count == 1


def test_count_filters_by_resource_scope_key():
    """T1.9: rate_limit.key may bucket on the concrete intent ``resource``
    (not just metadata/params), so two resources sharing one constraint's
    resource_pattern can be rate-limited independently."""
    ledger = DecisionLedger()
    ledger.record(make_intent(resource="container/cluster/prod-1"), "ALLOW", NOW)
    ledger.record(make_intent(resource="container/cluster/prod-2"), "ALLOW", NOW)

    count = ledger.count(
        since=NOW - timedelta(hours=1), scope={"resource": "container/cluster/prod-1"}
    )
    assert count == 1


def test_count_respects_window_expiry():
    ledger = DecisionLedger()
    ledger.record(make_intent(), "ALLOW", NOW - timedelta(hours=2))
    ledger.record(make_intent(), "ALLOW", NOW - timedelta(minutes=10))

    count = ledger.count(since=NOW - timedelta(hours=1))
    assert count == 1


def test_validate_rate_key_warns_on_unknown_field():
    ledger = DecisionLedger()
    warnings = ledger.validate_rate_key(["namespace", "resource", "bogus_field"])
    assert len(warnings) == 1
    assert "bogus_field" in warnings[0]


def test_validate_rate_key_silent_on_known_fields():
    ledger = DecisionLedger()
    assert ledger.validate_rate_key(["namespace", "resource", "cluster"]) == []


def test_decision_ledger_has_no_transaction_method():
    """The plain in-memory ledger deliberately has no locking -- callers
    duck-type ``hasattr(ledger, "transaction")`` to tell it apart."""
    assert not hasattr(DecisionLedger(), "transaction")


# --------------------------------------------------------------------------
# JsonlLedger
# --------------------------------------------------------------------------


def test_jsonl_ledger_round_trip(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    ledger.record(make_intent(action="scale"), "ALLOW", NOW)
    ledger.record(make_intent(action="delete"), "ALLOW", NOW + timedelta(minutes=5))

    reloaded = JsonlLedger(path)
    reloaded.load(now=NOW)

    assert len(reloaded.records) == 2
    assert reloaded.count(since=NOW - timedelta(hours=1)) == 2
    assert reloaded.records[0].intent.action == "scale"
    assert reloaded.records[1].intent.action == "delete"
    assert reloaded.chain_ok is True
    assert reloaded.skipped_lines == 0


def test_jsonl_ledger_appends_one_line_per_record(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    ledger.record(make_intent(), "ALLOW", NOW)
    ledger.record(make_intent(), "ALLOW", NOW)

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2


def test_jsonl_ledger_load_on_missing_file_is_empty(tmp_path):
    ledger = JsonlLedger(tmp_path / "does-not-exist.jsonl")
    ledger.load()
    assert ledger.records == []
    assert ledger.chain_ok is True


def test_jsonl_ledger_records_carry_a_hash_chain(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    ledger.record(make_intent(), "ALLOW", NOW)
    ledger.record(make_intent(), "ALLOW", NOW)

    lines = path.read_text().strip().splitlines()
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["prev"] == "0" * 64
    assert second["prev"] != "0" * 64
    assert second["prev"] != first["prev"]


def test_jsonl_ledger_skips_malformed_lines(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    ledger.record(make_intent(), "ALLOW", NOW)
    with open(path, "a") as f:
        f.write("{not valid json\n")
    ledger.record(make_intent(), "ALLOW", NOW + timedelta(minutes=1))

    reloaded = JsonlLedger(path)
    reloaded.load(now=NOW)

    assert reloaded.skipped_lines == 1
    assert len(reloaded.records) == 2


def test_jsonl_ledger_detects_broken_chain_after_truncation(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    for i in range(3):
        ledger.record(make_intent(), "ALLOW", NOW + timedelta(minutes=i))

    # Simulate truncation: drop the first line, so the (former) second
    # line's declared ``prev`` no longer matches anything that precedes it.
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[1:]) + "\n")

    reloaded = JsonlLedger(path)
    reloaded.load(now=NOW)
    assert reloaded.chain_ok is False


def test_jsonl_ledger_prunes_records_older_than_max_window(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path, max_window=timedelta(hours=1))
    for i in range(20):
        ledger.record(make_intent(), "ALLOW", NOW - timedelta(hours=3) + timedelta(minutes=i))
    # 20 old records, none within the last hour relative to `later`.
    later = NOW
    for i in range(3):
        ledger.record(make_intent(), "ALLOW", later - timedelta(minutes=i))

    reloaded = JsonlLedger(path, max_window=timedelta(hours=1))
    reloaded.load(now=later)

    assert len(reloaded.records) == 3
    assert all(r.timestamp >= later - timedelta(hours=1) for r in reloaded.records)

    # Pruning removed most of the file (>10%): it should have been rewritten
    # to just the kept records, and a subsequent load should still work and
    # keep reporting a healthy chain.
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3
    reloaded_again = JsonlLedger(path, max_window=timedelta(hours=1))
    reloaded_again.load(now=later)
    assert len(reloaded_again.records) == 3
    assert reloaded_again.chain_ok is True


def test_jsonl_ledger_keeps_recent_records_across_reload(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path, max_window=timedelta(hours=24))
    ledger.record(make_intent(action="old"), "ALLOW", NOW - timedelta(hours=2))
    ledger.record(make_intent(action="recent"), "ALLOW", NOW - timedelta(minutes=1))

    reloaded = JsonlLedger(path, max_window=timedelta(hours=24))
    reloaded.load(now=NOW)
    assert {r.intent.action for r in reloaded.records} == {"old", "recent"}


# --------------------------------------------------------------------------
# SqliteLedger
# --------------------------------------------------------------------------


def test_sqlite_ledger_round_trip(tmp_path):
    path = tmp_path / "ledger.db"
    ledger = SqliteLedger(path)
    ledger.record(make_intent(action="scale"), "ALLOW", NOW)
    ledger.record(make_intent(action="delete"), "ALLOW", NOW + timedelta(minutes=5))

    reloaded = SqliteLedger(path)
    reloaded.load(now=NOW)

    assert len(reloaded.records) == 2
    assert reloaded.count(since=NOW - timedelta(hours=1)) == 2
    assert reloaded.chain_ok is True


def test_sqlite_ledger_records_carry_a_hash_chain(tmp_path):
    import sqlite3

    path = tmp_path / "ledger.db"
    ledger = SqliteLedger(path)
    ledger.record(make_intent(), "ALLOW", NOW)
    ledger.record(make_intent(), "ALLOW", NOW)

    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT prev FROM records ORDER BY id").fetchall()
    conn.close()
    assert rows[0][0] == "0" * 64
    assert rows[1][0] != "0" * 64


def test_sqlite_ledger_prunes_records_older_than_max_window(tmp_path):
    path = tmp_path / "ledger.db"
    ledger = SqliteLedger(path, max_window=timedelta(hours=1))
    for i in range(5):
        ledger.record(make_intent(), "ALLOW", NOW - timedelta(hours=3) + timedelta(minutes=i))
    later = NOW
    ledger.record(make_intent(), "ALLOW", later)

    reloaded = SqliteLedger(path, max_window=timedelta(hours=1))
    reloaded.load(now=later)

    assert len(reloaded.records) == 1
    assert reloaded.chain_ok is True


def test_sqlite_ledger_detects_broken_chain_after_manual_edit(tmp_path):
    import sqlite3

    path = tmp_path / "ledger.db"
    ledger = SqliteLedger(path)
    for i in range(3):
        ledger.record(make_intent(), "ALLOW", NOW + timedelta(minutes=i))

    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM records WHERE id = (SELECT MIN(id) FROM records)")
    conn.commit()
    conn.close()

    reloaded = SqliteLedger(path)
    reloaded.load(now=NOW)
    assert reloaded.chain_ok is False


# --------------------------------------------------------------------------
# T1.9 accept: 16 concurrent processes against max: 3, per: 1h -> exactly 3
# ALLOW, for both ledger backends.
# --------------------------------------------------------------------------


def _rate_limit_worker(ledger_kind: str, path: str, barrier, queue) -> None:
    from aegis_core.intent import InfrastructureIntent
    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.ledger import JsonlLedger, SqliteLedger
    from aegis_core.store import Constraint, ConstraintStore

    authority = {"sre_lead": {"scaling"}}
    constraint = Constraint.create(
        id="no-mass-scale",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments more than 3x/hour.",
        rate_limit={"max": 3, "per": "1h"},
    )
    store = ConstraintStore(authority_map=authority)
    store.add_constraint(constraint)

    ledger = JsonlLedger(path) if ledger_kind == "jsonl" else SqliteLedger(path)
    interceptor = AegisInterceptor(store, ledger=ledger)

    intent = InfrastructureIntent(
        resource="deployment/api-server", action="scale", provider="kubernetes"
    )
    now = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)

    barrier.wait()
    decision = interceptor.intercept(intent, now=now)
    queue.put(decision.verdict)


def _run_barrier_rate_limit_test(ledger_kind: str, path) -> None:
    n = 16
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(n)
    queue = ctx.Queue()
    procs = [
        ctx.Process(target=_rate_limit_worker, args=(ledger_kind, str(path), barrier, queue))
        for _ in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    for p in procs:
        assert not p.is_alive(), "worker process hung"

    verdicts = [queue.get(timeout=5) for _ in range(n)]
    assert verdicts.count("ALLOW") == 3
    assert verdicts.count("BLOCK") == 13


def test_sixteen_processes_race_a_rate_limit_jsonl(tmp_path):
    _run_barrier_rate_limit_test("jsonl", tmp_path / "ledger.jsonl")


def test_sixteen_processes_race_a_rate_limit_sqlite(tmp_path):
    _run_barrier_rate_limit_test("sqlite", tmp_path / "ledger.db")
