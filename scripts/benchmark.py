#!/usr/bin/env python3
"""The Week 7-8 benchmark harness (PLAN.md §4): "Baseline vs. Aegis".

Runs Aegis and the two baselines (LLM self-check, OPA/Rego) over the
labeled evaluation corpus and produces a confusion matrix, over-block
rate, coverage, poison-susceptibility, and p50/p95/p99 latency for each.

    venv/bin/python scripts/benchmark.py \\
        [--corpus data/corpus] [--split holdout|dev|all] \\
        [--verifiers aegis,llm-heuristic,opa,llm] \\
        [--llm-cache results/llm-cache.jsonl] [--out results/]

Deterministic and fully offline for the default verifier set
(``aegis``, ``llm-heuristic``, ``opa``) — no network calls, no ``opa``
binary required (the row is skipped with a clear note when it's missing).
The real LLM baseline (``llm``) needs ``pip install -e ".[llm]"`` and
``ANTHROPIC_API_KEY``; see the README's "## Benchmark" section.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from aegis_core.authority import load_authority_map
from aegis_core.baselines.base import AegisVerifier, Verifier
from aegis_core.baselines.llm import (
    AnthropicClient,
    HeuristicLLMClient,
    LLMVerifier,
    NullClient,
    RecordingClient,
    ReplayClient,
)
from aegis_core.baselines.metrics import compute_metrics
from aegis_core.baselines.opa import OpaVerifier
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import Decision
from aegis_core.store import Constraint, ConstraintStore, _constraint_from_dict

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_all_constraints_unquarantined(constraints_path: Path) -> list[Constraint]:
    """Reads every constraint straight from the YAML, bypassing
    ``ConstraintStore.load``'s integrity quarantine — this is what the
    baselines see: tampered and unauthorized constraints included, since
    neither OPA nor a naive LLM self-check has a provenance/authority
    concept at all."""
    with open(constraints_path) as f:
        payload = yaml.safe_load(f) or {}
    return [_constraint_from_dict(entry) for entry in payload.get("constraints", [])]


def filter_by_split(constraints: list[Constraint], split: dict, which: str) -> list[Constraint]:
    if which == "all":
        return constraints
    ids = set(split.get(which, []))
    return [c for c in constraints if c.id in ids]


def load_intents(intents_path: Path) -> list[dict]:
    records = []
    with open(intents_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_labels(labels_path: Path) -> dict[str, dict]:
    labels: dict[str, dict] = {}
    with open(labels_path) as f:
        for line in f:
            line = line.strip()
            if line:
                rec = json.loads(line)
                labels[rec["id"]] = rec
    return labels


def intent_from_record(rec: dict) -> tuple[InfrastructureIntent, datetime]:
    intent = InfrastructureIntent(
        resource=rec["resource"],
        action=rec["action"],
        provider=rec["provider"],
        params=rec.get("params") or {},
        metadata=rec.get("metadata") or {},
    )
    now = datetime.fromisoformat(rec["now"])
    return intent, now


# ---------------------------------------------------------------------------
# Poison-susceptibility candidates
# ---------------------------------------------------------------------------


def compute_poison_candidates(
    intents: list[dict], baseline_store: ConstraintStore
) -> list[bool]:
    """For each intent, True iff it matched >=1 constraint under the
    no-quarantine (full, unauthorized-and-tampered-included) load, yet its
    ground-truth expected verdict is ALLOW — i.e. the only constraints
    that *could* have applied to it were Untrusted/Malicious, and Aegis
    correctly discarded all of them down to ALLOW. These are exactly the
    intents where a verifier lacking provenance/authority checks is at
    risk of being poisoned into an incorrect BLOCK/ESCALATE."""
    candidates = []
    for rec in intents:
        intent, now = intent_from_record(rec)
        matches = baseline_store.get_matching_constraints(intent, now)
        candidates.append(bool(matches) and rec["expected_verdict"] == "ALLOW")
    return candidates


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Verifier construction
# ---------------------------------------------------------------------------


def build_verifier(
    name: str,
    *,
    aegis_store: ConstraintStore,
    baseline_constraints: list[Constraint],
    llm_cache_path: Path,
) -> tuple[Verifier | None, str | None, bool]:
    """Returns (verifier, skip_reason, stub). verifier is None iff
    skip_reason is set."""
    if name == "aegis":
        return AegisVerifier(aegis_store), None, False

    if name == "llm-heuristic":
        client = HeuristicLLMClient(baseline_constraints)
        verifier = LLMVerifier(client, baseline_constraints, name="llm-heuristic")
        return verifier, None, False

    if name == "llm":
        import os

        has_key = bool(
            os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        )
        if not has_key:
            verifier = LLMVerifier(NullClient(), baseline_constraints, name="llm")
            return verifier, None, True
        try:
            real_client = AnthropicClient()
        except RuntimeError:
            verifier = LLMVerifier(NullClient(), baseline_constraints, name="llm")
            return verifier, None, True
        client = RecordingClient(real_client, llm_cache_path)
        verifier = LLMVerifier(client, baseline_constraints, name="llm")
        return verifier, None, False

    if name == "llm-replay":
        client = ReplayClient(llm_cache_path)
        verifier = LLMVerifier(client, baseline_constraints, name="llm-replay")
        return verifier, None, False

    if name == "opa":
        opa_verifier = OpaVerifier(baseline_constraints)
        if not opa_verifier.available:
            return None, "unavailable: opa not on PATH", False
        return opa_verifier, None, False

    raise ValueError(f"Unknown verifier: {name}")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def render_markdown(results: dict[str, Any], split: str, n_constraints: int) -> str:
    lines = [
        "# Aegis Benchmark Report",
        "",
        f"Split: `{split}`  ·  Constraints loaded: {n_constraints}  ·  "
        f"Intents: {results['meta']['n_intents']}",
        "",
        "Ground truth (`expected_verdict`) is derived from the real "
        "`AegisInterceptor` run that built the corpus (see "
        "`scripts/build_corpus.py`) — so Aegis scoring a perfect F1 here is "
        "a sanity check on the harness, not an independent accuracy "
        "measurement. The interesting numbers are the baselines' "
        "over-block rate and poison-susceptibility.",
        "",
        "| verifier | n | precision | recall | F1 | over-block | "
        "poison-susceptibility | coverage | p50 (ms) | p99 (ms) | notes |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
    ]
    for name, row in results["verifiers"].items():
        if row.get("skipped"):
            lines.append(
                f"| {name} | - | - | - | - | - | - | - | - | - | {row['skip_reason']} |"
            )
            continue
        m = row["metrics"]
        notes = []
        if row.get("stub"):
            notes.append("stub")
        note = ", ".join(notes) if notes else ""
        lines.append(
            f"| {name} | {m['n']} | {m['precision']:.3f} | {m['recall']:.3f} | "
            f"{m['f1']:.3f} | {m['over_block_rate']:.3f} | "
            f"{m['poison_susceptibility']:.3f} | {m['coverage']:.3f} | "
            f"{m['latency_p50_ms']:.4f} | {m['latency_p99_ms']:.4f} | {note} |"
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=REPO_ROOT / "data" / "corpus")
    parser.add_argument("--split", choices=["holdout", "dev", "all"], default="all")
    parser.add_argument("--verifiers", default="aegis,llm-heuristic,opa")
    parser.add_argument("--llm-cache", type=Path, default=REPO_ROOT / "results" / "llm-cache.jsonl")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results")
    args = parser.parse_args()

    corpus = args.corpus
    args.out.mkdir(parents=True, exist_ok=True)

    with open(corpus / "split.json") as f:
        split_data = json.load(f)

    authority_map = load_authority_map(corpus / "authority.yaml")

    # Aegis: real quarantine-on-load store.
    aegis_store_full = ConstraintStore.load(
        corpus / "constraints.yaml", authority_map=authority_map
    )

    # Baselines: every constraint, no quarantine.
    all_baseline_constraints = load_all_constraints_unquarantined(corpus / "constraints.yaml")
    baseline_constraints = filter_by_split(all_baseline_constraints, split_data, args.split)

    # Aegis's own store also needs to reflect the requested split — filter
    # its already-verified constraints by id membership.
    if args.split != "all":
        allowed_ids = {c.id for c in baseline_constraints}
        aegis_store = ConstraintStore(authority_map=authority_map)
        for cid, c in aegis_store_full.constraints.items():
            if cid in allowed_ids:
                aegis_store.constraints[cid] = c
    else:
        aegis_store = aegis_store_full

    print(f"Split: {args.split}  ({len(baseline_constraints)} constraints loaded)")

    intents = load_intents(corpus / "intents.jsonl")
    print(f"Intents: {len(intents)}")

    # A second, unfiltered no-quarantine store is used to compute poison
    # candidates against the FULL constraint set (matching the corpus that
    # produced expected_verdict), independent of --split.
    full_baseline_store = ConstraintStore(authority_map=authority_map)
    for c in all_baseline_constraints:
        full_baseline_store.constraints[c.id] = c
    poison_candidates = compute_poison_candidates(intents, full_baseline_store)

    verifier_names = [v.strip() for v in args.verifiers.split(",") if v.strip()]

    results: dict[str, Any] = {
        "meta": {
            "split": args.split,
            "n_constraints": len(baseline_constraints),
            "n_intents": len(intents),
            "verifiers_requested": verifier_names,
        },
        "verifiers": {},
    }

    expected_list = [rec["expected_verdict"] for rec in intents]

    for name in verifier_names:
        verifier, skip_reason, stub = build_verifier(
            name,
            aegis_store=aegis_store,
            baseline_constraints=baseline_constraints,
            llm_cache_path=args.llm_cache,
        )
        if verifier is None:
            print(f"[{name}] SKIPPED: {skip_reason}")
            results["verifiers"][name] = {"skipped": True, "skip_reason": skip_reason}
            continue

        decisions: list[Decision] = []
        t0 = time.perf_counter()
        for rec in intents:
            intent, now = intent_from_record(rec)
            decisions.append(verifier.decide(intent, now))
        wall_ms = (time.perf_counter() - t0) * 1000

        metrics = compute_metrics(expected_list, decisions, poison_candidates)
        results["verifiers"][name] = {
            "skipped": False,
            "stub": stub,
            "wall_ms": wall_ms,
            "metrics": metrics,
        }
        print(
            f"[{name}] n={metrics['n']} f1={metrics['f1']:.3f} "
            f"over_block={metrics['over_block_rate']:.3f} "
            f"poison_susceptibility={metrics['poison_susceptibility']:.3f} "
            f"p50={metrics['latency_p50_ms']:.4f}ms"
            + (" (stub)" if stub else "")
        )

    (args.out / "benchmark.json").write_text(json.dumps(results, indent=2, sort_keys=True))
    markdown = render_markdown(results, args.split, len(baseline_constraints))
    (args.out / "benchmark.md").write_text(markdown)

    print()
    print(f"Wrote {args.out / 'benchmark.json'}")
    print(f"Wrote {args.out / 'benchmark.md'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
