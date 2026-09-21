from datetime import UTC, datetime, timedelta

from aegis_core.intent import InfrastructureIntent
from aegis_core.ledger import DecisionLedger, JsonlLedger, parse_window

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


def test_count_respects_window_expiry():
    ledger = DecisionLedger()
    ledger.record(make_intent(), "ALLOW", NOW - timedelta(hours=2))
    ledger.record(make_intent(), "ALLOW", NOW - timedelta(minutes=10))

    count = ledger.count(since=NOW - timedelta(hours=1))
    assert count == 1


def test_jsonl_ledger_round_trip(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = JsonlLedger(path)
    ledger.record(make_intent(action="scale"), "ALLOW", NOW)
    ledger.record(make_intent(action="delete"), "ALLOW", NOW + timedelta(minutes=5))

    reloaded = JsonlLedger(path)
    reloaded.load()

    assert len(reloaded.records) == 2
    assert reloaded.count(since=NOW - timedelta(hours=1)) == 2
    assert reloaded.records[0].intent.action == "scale"
    assert reloaded.records[1].intent.action == "delete"


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
