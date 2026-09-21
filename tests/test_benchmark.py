"""Tests for scripts/benchmark.py (PLAN.md §4 Week 7-8)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core.baselines.metrics import compute_metrics
from aegis_core.interceptor import Decision

REPO_ROOT = Path(__file__).resolve().parent.parent


def _decision(verdict: str, latency_ms: float = 1.0, covered: bool | None = None) -> Decision:
    if covered is None:
        covered = verdict != "ALLOW"
    return Decision(verdict=verdict, covered=covered, latency_ms=latency_ms)


# ---------------------------------------------------------------------------
# compute_metrics on a tiny synthetic set, checked by hand.
# ---------------------------------------------------------------------------


def test_compute_metrics_by_hand():
    # 5 intents:
    #   1. expected ALLOW,    predicted ALLOW    -> TN
    #   2. expected BLOCK,    predicted BLOCK    -> TP
    #   3. expected ALLOW,    predicted BLOCK    -> FP  (over-block)
    #   4. expected ESCALATE, predicted ALLOW    -> FN
    #   5. expected BLOCK,    predicted ESCALATE -> TP (both non-ALLOW)
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

    # expected ALLOW count = 2 (indices 0, 2); FP = 1 -> over-block = 0.5
    assert metrics["over_block_rate"] == pytest.approx(0.5)

    # precision = TP / (TP + FP) = 2 / 3
    assert metrics["precision"] == pytest.approx(2 / 3)
    # recall = TP / (TP + FN) = 2 / 3
    assert metrics["recall"] == pytest.approx(2 / 3)
    # F1 = 2PR / (P+R) = 2/3
    assert metrics["f1"] == pytest.approx(2 / 3)

    cm = metrics["confusion_matrix"]
    assert cm["ALLOW"]["ALLOW"] == 1
    assert cm["ALLOW"]["BLOCK"] == 1
    assert cm["BLOCK"]["BLOCK"] == 1
    assert cm["BLOCK"]["ESCALATE"] == 1
    assert cm["ESCALATE"]["ALLOW"] == 1

    # coverage: covered defaults to verdict != ALLOW -> decisions 1,2,4 covered = 3/5
    assert metrics["coverage"] == pytest.approx(3 / 5)


def test_compute_metrics_poison_susceptibility():
    expected = ["ALLOW", "ALLOW", "ALLOW"]
    decisions = [_decision("BLOCK"), _decision("ALLOW"), _decision("ESCALATE")]
    # All three are poison candidates; 2 of 3 verifier outputs are non-ALLOW.
    poison_candidates = [True, True, True]

    metrics = compute_metrics(expected, decisions, poison_candidates)
    assert metrics["poison_candidate_count"] == 3
    assert metrics["poison_susceptibility"] == pytest.approx(2 / 3)


def test_compute_metrics_zero_denominators_are_safe():
    # No expected ALLOW at all -> over_block_rate is 0.0, not a ZeroDivisionError.
    expected = ["BLOCK"]
    decisions = [_decision("BLOCK")]
    metrics = compute_metrics(expected, decisions)
    assert metrics["over_block_rate"] == 0.0

    # No poison candidates -> poison_susceptibility is 0.0.
    assert metrics["poison_susceptibility"] == 0.0


# ---------------------------------------------------------------------------
# End-to-end run against the real corpus.
# ---------------------------------------------------------------------------


def test_benchmark_end_to_end(tmp_path):
    out_dir = tmp_path / "results"
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
    assert "aegis" in payload["verifiers"]
    assert "llm-heuristic" in payload["verifiers"]

    aegis_row = payload["verifiers"]["aegis"]
    assert aegis_row["skipped"] is False
    aegis_metrics = aegis_row["metrics"]
    # Ground truth is interceptor-derived, so Aegis re-scoring it is a
    # sanity check, not an independent accuracy measurement.
    assert aegis_metrics["poison_susceptibility"] == pytest.approx(0.0)
    assert aegis_metrics["f1"] == pytest.approx(1.0)

    llm_row = payload["verifiers"]["llm-heuristic"]
    assert llm_row["skipped"] is False
    llm_metrics = llm_row["metrics"]
    assert llm_metrics["poison_susceptibility"] > 0.5

    assert (out_dir / "benchmark.md").exists()
    md = (out_dir / "benchmark.md").read_text()
    assert "aegis" in md
    assert "llm-heuristic" in md
