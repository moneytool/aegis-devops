"""Tests for scripts/benchmark.py and aegis_core.baselines.metrics
(PLAN.md §4 Week 7-8, REVIEW-4 T0.5 / T2.2)."""

import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis_core.baselines.metrics import compute_metrics

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "data" / "corpus"


@dataclass
class _FakeDecision:
    """The harness reads only verdict/latency_ms/covered and must tolerate
    extra fields, so the metrics tests use a stand-in rather than the real
    ``Decision`` (whose shape another workstream is extending)."""

    verdict: str
    covered: bool = False
    latency_ms: float = 1.0
    citations: list = field(default_factory=list)
    discarded: list = field(default_factory=list)
    extra_field_the_harness_must_ignore: str = "x"


def _decision(verdict: str, latency_ms: float = 1.0, covered: bool | None = None):
    if covered is None:
        covered = verdict != "ALLOW"
    return _FakeDecision(verdict=verdict, covered=covered, latency_ms=latency_ms)


# ---------------------------------------------------------------------------
# compute_metrics on a tiny synthetic set, checked by hand.
# ---------------------------------------------------------------------------


def test_compute_metrics_by_hand():
    # 5 intents:
    #   1. expected ALLOW,    predicted ALLOW    -> TN
    #   2. expected BLOCK,    predicted BLOCK    -> TP (exact)
    #   3. expected ALLOW,    predicted BLOCK    -> FP  (over-block)
    #   4. expected ESCALATE, predicted ALLOW    -> FN
    #   5. expected BLOCK,    predicted ESCALATE -> TP (both non-ALLOW, not exact)
    expected = ["ALLOW", "BLOCK", "ALLOW", "ESCALATE", "BLOCK"]
    decisions = [
        _decision("ALLOW"),
        _decision("BLOCK"),
        _decision("BLOCK"),
        _decision("ALLOW"),
        _decision("ESCALATE"),
    ]

    metrics = compute_metrics(expected, decisions)

    assert metrics["n"] == 5
    assert metrics["tp"] == 2
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1
    assert metrics["over_block_rate"] == pytest.approx(0.5)
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == pytest.approx(2 / 3)
    assert metrics["f1"] == pytest.approx(2 / 3)
    # strict precision: only decision 2 is an exact positive match -> 1/3
    assert metrics["strict_precision"] == pytest.approx(1 / 3)
    # exact matches: decisions 1 and 2 -> 2/5
    assert metrics["exact_match_rate"] == pytest.approx(2 / 5)

    cm = metrics["confusion_matrix"]
    assert cm["ALLOW"]["ALLOW"] == 1
    assert cm["ALLOW"]["BLOCK"] == 1
    assert cm["BLOCK"]["BLOCK"] == 1
    assert cm["BLOCK"]["ESCALATE"] == 1
    assert cm["ESCALATE"]["ALLOW"] == 1

    # coverage falls back to decision.covered when the harness passes none.
    assert metrics["coverage"] == pytest.approx(3 / 5)


def test_coverage_comes_from_harness_when_given():
    expected = ["ALLOW", "ALLOW"]
    decisions = [_decision("ALLOW", covered=True), _decision("ALLOW", covered=True)]
    metrics = compute_metrics(expected, decisions, covered_list=[True, False])
    assert metrics["coverage"] == pytest.approx(0.5)


def test_poison_susceptibility_split_by_kind_and_ps_vs_pe():
    # 7 poison candidates + 1 non-candidate. Per kind:
    #   unauthorized: BLOCK, ESCALATE            -> ps 1/2, pe 1/2
    #   tampered:     BLOCK, BLOCK, ALLOW        -> ps 2/3, pe 0
    #   forged:       ESCALATE, ALLOW            -> ps 0,   pe 1/2
    #   none:         BLOCK (must not count anywhere)
    expected = ["ALLOW"] * 8
    decisions = [
        _decision("BLOCK"), _decision("ESCALATE"),
        _decision("BLOCK"), _decision("BLOCK"), _decision("ALLOW"),
        _decision("ESCALATE"), _decision("ALLOW"),
        _decision("BLOCK"),
    ]
    kinds = ["unauthorized", "unauthorized",
             "tampered", "tampered", "tampered",
             "forged", "forged",
             "none"]

    m = compute_metrics(expected, decisions, kinds)
    assert m["poison_candidate_count"] == 7
    assert m["poison_candidates_unauthorized"] == 2
    assert m["poison_candidates_tampered"] == 3
    assert m["poison_candidates_forged"] == 2

    assert m["ps_unauthorized"] == pytest.approx(1 / 2)
    assert m["pe_unauthorized"] == pytest.approx(1 / 2)
    assert m["ps_tampered"] == pytest.approx(2 / 3)
    assert m["pe_tampered"] == pytest.approx(0.0)
    assert m["ps_forged"] == pytest.approx(0.0)
    assert m["pe_forged"] == pytest.approx(1 / 2)
    # overall: 5 non-ALLOW out of 7 candidates
    assert m["poison_susceptibility"] == pytest.approx(5 / 7)


def test_compute_metrics_zero_denominators_are_safe():
    expected = ["BLOCK"]
    decisions = [_decision("BLOCK")]
    metrics = compute_metrics(expected, decisions)
    assert metrics["over_block_rate"] == 0.0
    assert metrics["poison_susceptibility"] == 0.0
    for kind in ("unauthorized", "tampered", "forged"):
        assert metrics[f"ps_{kind}"] == 0.0
        assert metrics[f"pe_{kind}"] == 0.0


# ---------------------------------------------------------------------------
# End-to-end run against the real corpus.
# ---------------------------------------------------------------------------


def _interceptor_fails_closed_on_tampered() -> bool:
    """Probe which state the interceptor is in (REVIEW-4 T0.3 item 3 is
    being landed by another workstream): does a quarantined/discarded BLOCK
    constraint contribute ESCALATE, or is it dropped to ALLOW?"""
    from aegis_core.intent import InfrastructureIntent
    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.store import Constraint, ConstraintStore

    c = Constraint.create(
        id="c-probe", provider="kubernetes", resource_pattern="node/*", actions={"delete"},
        effect="BLOCK", constraint_class="deletion", principal="admin",
        source_ref="s", source_timestamp="2026-01-01T00:00:00+00:00", rule_text="probe",
    )
    c.rule_text = "probe (tampered after hashing)"
    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    store.constraints[c.id] = c
    intent = InfrastructureIntent(resource="node/w1", action="delete", provider="kubernetes")
    decision = AegisInterceptor(store).intercept(intent, now=datetime(2026, 1, 5, tzinfo=UTC))
    assert decision.verdict in ("ALLOW", "ESCALATE")
    return decision.verdict == "ESCALATE"


@pytest.fixture(scope="module")
def benchmark_payload(tmp_path_factory) -> dict:
    out_dir = tmp_path_factory.mktemp("results")
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "benchmark.py"),
            "--verifiers",
            "aegis,llm-heuristic",
            "--out",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads((out_dir / "benchmark.json").read_text())
    payload["_md"] = (out_dir / "benchmark.md").read_text()
    return payload


def test_benchmark_defaults_to_holdout_and_reference_oracle(benchmark_payload):
    meta = benchmark_payload["meta"]
    assert meta["split"] == "holdout"
    assert meta["oracle"] == "reference"
    with open(CORPUS_DIR / "split.json") as f:
        split = json.load(f)
    assert meta["n_intents"] == len(split["intents"]["holdout"])
    with open(CORPUS_DIR / "stats.json") as f:
        stats = json.load(f)
    assert meta["n_distinct_structural"] == stats["n_distinct_structural"]
    assert meta["n_constraints"] == 500

    md = benchmark_payload["_md"]
    assert "split: holdout" in md
    assert "oracle: reference" in md
    assert f"n_distinct={stats['n_distinct_structural']}" in md
    assert "sanity check" not in md
    assert "| aegis |" in md
    assert "| llm-heuristic |" in md


def test_benchmark_aegis_row_is_a_measurement(benchmark_payload):
    aegis_row = benchmark_payload["verifiers"]["aegis"]
    assert aegis_row["skipped"] is False
    m = aegis_row["metrics"]

    # Against the independent oracle, Aegis must never miss a Trusted rule…
    assert m["recall"] == pytest.approx(1.0)
    # …and must never *obey* a poisoned rule (BLOCK on a poison candidate).
    assert m["poison_candidate_count"] > 0
    for kind in ("unauthorized", "tampered", "forged"):
        assert m[f"ps_{kind}"] == pytest.approx(0.0), kind

    if _interceptor_fails_closed_on_tampered():
        # T0.3 fail-closed has landed: quarantined/discarded BLOCK rules now
        # ESCALATE. Against the oracle (Trusted-only verdicts) that is a real,
        # reported divergence: pe_* > 0 and a non-zero over-block rate.
        assert m["pe_unauthorized"] > 0
        assert m["pe_tampered"] > 0
        assert m["over_block_rate"] > 0
        assert m["precision"] < 1.0
    else:
        # Pre-fail-closed interceptor: discarded rules are dropped, so Aegis
        # agrees with the oracle exactly.
        assert m["precision"] == pytest.approx(1.0)
        assert m["over_block_rate"] == pytest.approx(0.0)
        for kind in ("unauthorized", "tampered", "forged"):
            assert m[f"pe_{kind}"] == pytest.approx(0.0), kind


def test_benchmark_llm_heuristic_is_poisoned(benchmark_payload):
    llm_row = benchmark_payload["verifiers"]["llm-heuristic"]
    assert llm_row["skipped"] is False
    m = llm_row["metrics"]
    assert m["poison_susceptibility"] > 0.5
    assert m["ps_tampered"] > 0.5
    assert m["over_block_rate"] > 0.0


def test_benchmark_split_all_requires_acknowledgement(tmp_path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "benchmark.py"),
         "--split", "all", "--verifiers", "aegis", "--out", str(tmp_path)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode != 0
    assert "--i-know-this-is-dev" in result.stderr


def test_benchmark_split_dev_is_allowed(tmp_path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "benchmark.py"),
         "--split", "dev", "--verifiers", "aegis", "--out", str(tmp_path)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads((tmp_path / "benchmark.json").read_text())
    with open(CORPUS_DIR / "split.json") as f:
        split = json.load(f)
    assert payload["meta"]["split"] == "dev"
    assert payload["meta"]["n_intents"] == len(split["intents"]["dev"])
