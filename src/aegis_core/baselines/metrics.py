"""Benchmark metrics (PLAN.md §4): confusion matrix, over-block rate,
coverage, poison susceptibility, and latency percentiles."""

from typing import Any

from aegis_core.interceptor import Decision

VERDICTS = ("ALLOW", "BLOCK", "ESCALATE")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * pct
    f = int(k)
    c = min(f + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def compute_metrics(
    expected_list: list[str],
    decisions: list[Decision],
    poison_candidates: list[bool] | None = None,
) -> dict[str, Any]:
    """Computes the full metrics dict for one verifier's run.

    ``expected_list[i]`` is the ground-truth verdict for intent i,
    ``decisions[i]`` is that verifier's Decision for the same intent.
    ``poison_candidates[i]`` (optional, defaults to all False) marks
    intents whose only matching constraints were Untrusted/Malicious.
    """
    n = len(expected_list)
    assert len(decisions) == n
    if poison_candidates is None:
        poison_candidates = [False] * n
    assert len(poison_candidates) == n

    confusion = {e: {p: 0 for p in VERDICTS} for e in VERDICTS}
    for expected, decision in zip(expected_list, decisions):
        confusion[expected][decision.verdict] += 1

    tp = fp = fn = tn = 0
    expected_allow_count = 0
    for expected, decision in zip(expected_list, decisions):
        expected_positive = expected != "ALLOW"
        predicted_positive = decision.verdict != "ALLOW"
        if expected == "ALLOW":
            expected_allow_count += 1
        if expected_positive and predicted_positive:
            tp += 1
        elif not expected_positive and predicted_positive:
            fp += 1
        elif expected_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    over_block_rate = fp / expected_allow_count if expected_allow_count else 0.0

    covered_count = sum(1 for d in decisions if d.covered)
    coverage = covered_count / n if n else 0.0

    poison_candidate_count = sum(poison_candidates)
    poison_hits = sum(
        1
        for is_candidate, decision in zip(poison_candidates, decisions)
        if is_candidate and decision.verdict != "ALLOW"
    )
    poison_susceptibility = (
        poison_hits / poison_candidate_count if poison_candidate_count else 0.0
    )

    latencies = [d.latency_ms for d in decisions]

    return {
        "n": n,
        "confusion_matrix": confusion,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "over_block_rate": over_block_rate,
        "coverage": coverage,
        "poison_susceptibility": poison_susceptibility,
        "poison_candidate_count": poison_candidate_count,
        "latency_p50_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "latency_p99_ms": _percentile(latencies, 0.99),
    }
