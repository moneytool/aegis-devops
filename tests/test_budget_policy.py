"""budget.yaml loading (design v1.0 §3) and the price table (§5)."""

from pathlib import Path

import pytest
import yaml

from aegis_core.budget.policy import AGENTS, load_budget_policy
from aegis_core.budget.pricing import (
    CATEGORIES,
    PriceTable,
    load_builtin_table,
    normalize_model,
)
from aegis_core.signing import SignatureError, sign_file

AUTHORITY = {"admin": {"budget", "identity"}, "developer": {"configuration"}}

FULL = {
    "version": 1,
    "principal": "admin",
    "unit": "usd",
    "session": {"limit": 20, "warn_at": 0.75},
    "project_day": {"limit": 100, "tz": "America/Chicago"},
    "agents": ["claude", "codex", "copilot"],
    "on_unknown_log": "deny",
    "on_unknown_price": "estimate",
    "pricing": {"claude-opus-5-5": {"input": 4, "output": 20, "cache_read": 0.2,
                                    "cache_write": 8}},
    "copilot": {"premium_requests": 50},
}


def _write(tmp_path: Path, doc) -> Path:
    path = tmp_path / "budget.yaml"
    path.write_text(yaml.safe_dump(doc) if not isinstance(doc, str) else doc)
    return path


def _load(tmp_path, doc, **kw):
    return load_budget_policy(_write(tmp_path, doc), authority_map=AUTHORITY, insecure=True,
                              **kw)


def _with(**changes):
    doc = {**FULL, **changes}
    return {k: v for k, v in doc.items() if v is not None}


def test_full_policy_loads(tmp_path):
    p = _load(tmp_path, FULL)
    assert (p.unit, p.principal, p.tz) == ("usd", "admin", "America/Chicago")
    assert (p.session.limit, p.session.warn_at) == (20, 0.75)
    assert (p.project_day.limit, p.project_day.warn_at) == (100, 0.8)
    assert p.agents == ("claude", "codex", "copilot")
    assert p.copilot_premium_requests.limit == 50
    assert p.pricing["claude-opus-5-5"]["output"] == 20.0
    assert p.warnings == ()
    assert p.measures("claude") and p.measures("copilot") and not p.measures("gemini")


def test_defaults(tmp_path):
    p = _load(tmp_path, {"principal": "admin", "unit": "tokens", "session": {"limit": 5000}})
    assert p.agents == AGENTS
    assert (p.on_unknown_log, p.on_unknown_price, p.tz) == ("allow", "estimate", "UTC")
    assert p.project_day is None and p.session.warn_at == 0.8
    # copilot is listed by default but has no premium-request limit: not measured, said so
    assert not p.measures("copilot")
    assert any(w.startswith("copilot-unmeasured") for w in p.warnings)


@pytest.mark.parametrize("doc,match", [
    (_with(unit=None), "'unit' is required"),
    (_with(unit="eur"), "unit must be one of"),
    (_with(extra=1), r"unknown field\(s\) \['extra'\]"),
    (_with(version=2), "unsupported version"),
    (_with(principal=None), "'principal' is required"),
    (_with(principal="developer"), "does not hold the 'budget' class"),
    (_with(session={"limit": 0}), "session.limit: must be greater than 0"),
    (_with(session={"limit": -3}), "must be greater than 0"),
    (_with(session={"limit": "ten"}), "must be a number"),
    (_with(session={"limit": 5, "warn_at": 1}), "warn_at: must be a fraction"),
    (_with(session={"limit": 5, "warn_at": 0}), "warn_at: must be a fraction"),
    (_with(session={"limit": 5, "hard": True}), r"session: unknown field"),
    (_with(session={"warn_at": 0.5}), "'limit' is required"),
    (_with(project_day={"limit": 5, "tz": "Mars/Olympus"}), "unknown time zone"),
    (_with(agents=["claude", "cursor"]), r"unknown agent\(s\) \['cursor'\]"),
    (_with(agents=["claude", "claude"]), "listed twice"),
    (_with(agents=[]), "non-empty list"),
    (_with(on_unknown_log="warn"), "on_unknown_log must be one of"),
    (_with(on_unknown_price="ignore"), "on_unknown_price must be one of"),
    (_with(pricing={"m": {"input": 1, "output": 1, "cache_read": 1}}),
     r"missing price field\(s\) \['cache_write'\]"),
    (_with(pricing={"m": {"input": 1, "output": 1, "cache_read": 1, "cache_write": -1}}),
     "must be a number >= 0"),
    (_with(pricing={"m": {"input": 1, "output": 1, "cache_read": 1, "cache_write": 1,
                          "batch": 1}}), "unknown price field"),
    (_with(copilot={"limit": 5}), "'premium_requests'"),
    (_with(session=None, project_day=None, copilot=None), "set at least one limit"),
])
def test_shape_errors_are_load_errors(tmp_path, doc, match):
    with pytest.raises(ValueError, match=match):
        _load(tmp_path, doc)


def test_token_limits_are_whole_numbers(tmp_path):
    with pytest.raises(ValueError, match="whole number of tokens"):
        _load(tmp_path, {"principal": "admin", "unit": "tokens", "session": {"limit": 10.5}})
    assert _load(tmp_path, {"principal": "admin", "unit": "usd",
                            "session": {"limit": 10.5}}).session.limit == 10.5


def test_authority_map_is_required(tmp_path):
    with pytest.raises(ValueError, match="authority map is required"):
        load_budget_policy(_write(tmp_path, FULL), authority_map=None, insecure=True)


def test_token_mode_warns_that_prices_are_ignored(tmp_path):
    p = _load(tmp_path, _with(unit="tokens", session={"limit": 1000},
                              project_day={"limit": 5000}))
    assert "ignored: on_unknown_price has no effect with unit: tokens" in p.warnings
    assert "ignored: pricing has no effect with unit: tokens" in p.warnings


def test_signed_policy_verifies_and_tampering_is_refused(tmp_path):
    key = bytes(range(32))
    path = _write(tmp_path, FULL)
    sign_file(path, key)
    assert load_budget_policy(path, authority_map=AUTHORITY, key=key).session.limit == 20
    path.write_text(path.read_text().replace("limit: 20", "limit: 2000"))
    with pytest.raises(SignatureError):
        load_budget_policy(path, authority_map=AUTHORITY, key=key)


def test_unsigned_without_key_is_recorded(tmp_path):
    path = _write(tmp_path, FULL)
    p = load_budget_policy(path, authority_map=AUTHORITY)
    assert p.warnings[0] == f"unsigned: {path}"


# --- prices ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def table():
    return load_builtin_table()


@pytest.mark.parametrize("raw,key", [
    ("claude-opus-5-5", "claude-opus-5-5"),
    ("anthropic/claude-sonnet-4.5", "claude-sonnet-4-5"),
    ("claude-opus-4-6[1m]", "claude-opus-4-6"),
    ("claude-haiku-4-5-20251001", "claude-haiku-4-5"),
    ("GPT-5.5", "gpt-5-5"),
    ("gemini-2.5-pro-2026-01-15", "gemini-2-5-pro"),
])
def test_normalize_model(raw, key):
    assert normalize_model(raw) == key


def test_every_builtin_entry_is_complete_or_documented(table):
    prices = PriceTable(table)
    for vendor, spec in table["vendors"].items():
        for model, entry in spec["models"].items():
            assert prices.vendor_of(model) == vendor
            missing = [c for c in CATEGORIES if c not in entry]
            assert missing in ([], ["cache_read"]), (model, missing)
    assert table["as_of"]


def test_exact_and_override_prices(table):
    prices = PriceTable(table)
    p = prices.price("claude-opus-5-5")
    assert (p.vendor, p.estimated) == ("anthropic", frozenset())
    assert p.rates == {"input": 4.0, "output": 20.0, "cache_read": 0.2, "cache_write": 8.0}
    over = PriceTable(table, {"claude-opus-5-5": {"input": 1, "output": 2, "cache_read": 3,
                                                  "cache_write": 4}})
    assert over.price("claude-opus-5-5").rates["cache_read"] == 3


def test_unknown_model_of_a_known_vendor_takes_the_highest_rate_per_category(table):
    prices = PriceTable(table)
    p = prices.price("claude-opus-9")
    anthropic = table["vendors"]["anthropic"]["models"].values()
    for cat in CATEGORIES:
        assert p.rates[cat] == max(m[cat] for m in anthropic if cat in m)
    assert p.estimated == frozenset(CATEGORIES)
    assert p.rates == {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 30.0}


def test_fallback_rates_are_taken_per_category_not_from_one_model():
    table = {"version": 1, "vendors": {"v": {"prefixes": ["v-"], "models": {
        "v-a": {"input": 9, "output": 1, "cache_read": 1, "cache_write": 1},
        "v-b": {"input": 1, "output": 9, "cache_read": 1, "cache_write": 1},
        "v-c": {"input": 1, "output": 1, "cache_read": 9, "cache_write": 9}}}}}
    p = PriceTable(table).price("v-new")
    assert p.rates == {"input": 9, "output": 9, "cache_read": 9, "cache_write": 9}


def test_unknown_vendor_takes_the_highest_rate_in_the_whole_table(table):
    prices = PriceTable(table)
    p = prices.price("mystery-model-7")
    assert p.vendor is None
    every = [m for v in table["vendors"].values() for m in v["models"].values()]
    for cat in CATEGORIES:
        assert p.rates[cat] == max(m[cat] for m in every if cat in m)


def test_missing_category_falls_back_for_that_category_only(table):
    prices = PriceTable(table)
    p = prices.price("gpt-5.5-pro")
    assert p.estimated == frozenset({"cache_read"})
    assert p.rates["input"] == 30.0
    openai = table["vendors"]["openai"]["models"].values()
    assert p.rates["cache_read"] == max(m["cache_read"] for m in openai if "cache_read" in m)


def test_provider_field_identifies_the_vendor(table):
    prices = PriceTable(table)
    assert prices.vendor_of("some-new-model", "anthropic") == "anthropic"
    assert prices.vendor_of("claude-opus-5-5", "github-copilot") == "anthropic"
    assert prices.vendor_of("Qwen3-1.7B", "omlx") is None


def test_cost_reports_estimates_only_for_used_categories(table):
    prices = PriceTable(table)
    usage = {"gpt-5.5-pro": {"input": 1_000_000, "output": 0, "cache_read": 0}}
    cost = prices.cost(usage)
    assert cost.dollars == pytest.approx(30.0)
    assert cost.estimated == {}
    usage["gpt-5.5-pro"]["cache_read"] = 1_000_000
    assert prices.cost(usage).estimated == {"gpt-5.5-pro": ["cache_read"]}


def test_an_override_reprices_earlier_estimated_usage(table):
    usage = {"claude-new-1": {"input": 2_000_000, "output": 1_000_000}}
    before = PriceTable(table).cost(usage)
    assert before.estimated == {"claude-new-1": ["input", "output"]}
    after = PriceTable(table, {"claude-new-1": {"input": 1, "output": 2, "cache_read": 0,
                                                "cache_write": 0}}).cost(usage)
    assert after.estimated == {} and after.dollars == pytest.approx(4.0)
