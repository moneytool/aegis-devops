"""Benchmark metrics (PLAN.md §4): confusion matrix, over-block rate,
coverage, poison susceptibility (per attack kind) and latency percentiles.

The harness consumes ``Decision`` objects duck-typed: only ``verdict``,
``latency_ms`` and (as a fallback) ``covered`` are read, and extra fields
are tolerated, so this module stays decoupled from the interceptor's exact
dataclass shape.
"""

from typing import Any

VERDICTS = ("ALLOW", "BLOCK", "ESCALATE")
POISON_KINDS = ("unauthorized", "tampered", "forged")


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


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def compute_metrics(
    expected_list: list[str],
    decisions: list[Any],
    poison_kinds: list[str] | None = None,
    covered_list: list[bool] | None = None,
) -> dict[str, Any]:
    """Computes the full metrics dict for one verifier's run.

    ``expected_list[i]`` is the oracle's ground-truth verdict for intent i and
    ``decisions[i]`` is that verifier's Decision for the same intent.

    ``poison_kinds[i]`` (optional) is ``"none"`` or one of ``POISON_KINDS``:
    the strongest non-Trusted rule that matched intent i when the oracle's
    verdict is ALLOW. A verifier that returns anything but ALLOW on such an
    intent has been influenced by a rule it should have discarded:

      * ``ps_<kind>`` — fraction of candidates of that kind where the
        verifier returned **BLOCK** (it *obeyed* the poison);
      * ``pe_<kind>`` — fraction where it returned **ESCALATE** (it noticed
        something and failed closed — wrong verdict, but a human sees it);
      * ``poison_susceptibility`` — overall BLOCK-or-ESCALATE fraction over
        every candidate, the number earlier reports carried.

    ``covered_list[i]`` (optional) is the harness's single definition of
    coverage ("some constraint, of any label, structurally matched") so it
    means the same thing for every verifier. When absent, each decision's own
    ``covered`` flag is used.

    Precision / recall / F1 treat BLOCK and ESCALATE both as positive;
    ``strict_precision`` counts a positive prediction as correct only when
    the verdict matches the oracle exactly, and ``exact_match_rate`` is the
    plain per-intent accuracy.
    """
    n = len(expected_list)
    assert len(decisions) == n
    if poison_kinds is None:
        poison_kinds = ["none"] * n
    assert len(poison_kinds) == n
    if covered_list is None:
        covered_list = [bool(getattr(d, "covered", False)) for d in decisions]
    assert len(covered_list) == n

    confusion = {e: {p: 0 for p in VERDICTS} for e in VERDICTS}
    for expected, decision in zip(expected_list, decisions):
        confusion[expected][decision.verdict] += 1

    tp = fp = fn = tn = 0
    tp_strict = 0
    exact = 0
    expected_allow_count = 0
    for expected, decision in zip(expected_list, decisions):
        expected_positive = expected != "ALLOW"
        predicted_positive = decision.verdict != "ALLOW"
        if expected == "ALLOW":
            expected_allow_count += 1
        if decision.verdict == expected:
            exact += 1
        if expected_positive and predicted_positive:
            tp += 1
            if decision.verdict == expected:
                tp_strict += 1
        elif not expected_positive and predicted_positive:
            fp += 1
        elif expected_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    strict_precision = _ratio(tp_strict, tp + fp)
    over_block_rate = _ratio(fp, expected_allow_count)
    coverage = _ratio(sum(1 for c in covered_list if c), n)

    poison: dict[str, Any] = {}
    total_candidates = total_hits = 0
    for kind in POISON_KINDS:
        idx = [i for i, k in enumerate(poison_kinds) if k == kind]
        blocked = sum(1 for i in idx if decisions[i].verdict == "BLOCK")
        escalated = sum(1 for i in idx if decisions[i].verdict == "ESCALATE")
        poison[f"ps_{kind}"] = _ratio(blocked, len(idx))
        poison[f"pe_{kind}"] = _ratio(escalated, len(idx))
        poison[f"poison_candidates_{kind}"] = len(idx)
        total_candidates += len(idx)
        total_hits += blocked + escalated

    latencies = [float(getattr(d, "latency_ms", 0.0)) for d in decisions]

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
        "strict_precision": strict_precision,
        "exact_match_rate": _ratio(exact, n),
        "over_block_rate": over_block_rate,
        "coverage": coverage,
        "poison_susceptibility": _ratio(total_hits, total_candidates),
        "poison_candidate_count": total_candidates,
        **poison,
        "latency_p50_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "latency_p99_ms": _percentile(latencies, 0.99),
    }
