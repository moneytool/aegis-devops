#!/usr/bin/env python3
"""Latency-vs-scale sweep (PLAN.md §4, REVIEW-4 T2.3).

For each store size in ``--sizes``, synthesises a constraint store (reusing
``scripts/build_corpus.py``'s seed-expansion helpers -- same seeds.yaml,
same variation axes, all constraints labeled Trusted and signing not
required), samples ``--decisions`` intents (half structurally matching a
constraint, half guaranteed misses), and times
``AegisInterceptor.intercept`` warm (the first 50 calls are dropped as
warm-up). Reports p50/p95/p99 with a bootstrap 95% CI (1000 resamples), plus
``ConstraintStore.load`` wall time with and without a ``--sources`` file
fetcher.

    venv/bin/python scripts/latency_sweep.py \\
        --sizes 100,500,2500,10000 --decisions 2000 --out results/latency.json

Writes ``<out>`` (JSON) and a sibling ``.md`` (same stem) with a markdown
table.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "src"))

import build_corpus as bc  # noqa: E402  (scripts/build_corpus.py)

from aegis_core.intent import InfrastructureIntent  # noqa: E402
from aegis_core.interceptor import AegisInterceptor  # noqa: E402
from aegis_core.store import Constraint, ConstraintStore  # noqa: E402

SEED = 20260920
WARMUP = 50
BOOTSTRAP_RESAMPLES = 1000
CI_LOW, CI_HIGH = 2.5, 97.5

RESOURCE_NAMES = bc.RESOURCE_NAMES


# ---------------------------------------------------------------------------
# Synthetic store construction (reuses build_corpus's seed-expansion axes)
# ---------------------------------------------------------------------------


def build_synthetic_constraints(size: int, rng: random.Random) -> list[Constraint]:
    """Builds ``size`` all-Trusted constraints by cycling through
    data/corpus/seeds.yaml with the same narrow_pattern/vary_scope/
    vary_actions/vary_effect/vary_time_window axes build_corpus.py uses for
    the evaluation corpus -- just without labels/tampering/forging, since
    this store only needs to be representative in shape and large."""
    seeds = bc.load_seeds()
    class_authorized = bc.class_to_authorized_map()
    constraints: list[Constraint] = []
    for i in range(size):
        n = i + 1
        seed = rng.choice(seeds)
        constraint_class = seed["constraint_class"]
        principal = rng.choice(class_authorized[constraint_class])
        scope = bc.vary_scope(seed.get("scope") or {}, rng)
        if not scope and rng.random() < bc.EXTRA_SCOPE_PROBABILITY:
            extra = bc.EXTRA_SCOPE_BY_PROVIDER.get(seed["provider"])
            if extra is not None:
                extra_key, extra_pool = extra
                scope = {extra_key: rng.choice(extra_pool)}
        constraint = Constraint.create(
            id=f"lat-{n:06d}",
            provider=seed["provider"],
            resource_pattern=bc.narrow_pattern(seed["resource_pattern"], rng),
            actions=bc.vary_actions(seed["actions"], rng),
            effect=bc.vary_effect(seed["effect"], rng),
            constraint_class=constraint_class,
            principal=principal,
            source_ref=f"lat-src-{n:06d}",
            source_timestamp=bc.deterministic_timestamp(n),
            rule_text=seed["rule_text"],
            scope=scope,
            time_window=bc.vary_time_window(seed.get("time_window"), rng),
        )
        constraints.append(constraint)
    return constraints


def write_source_tree(constraints: list[Constraint], sources_dir: Path) -> None:
    sources_dir.mkdir(parents=True, exist_ok=True)
    for c in constraints:
        payload = {
            "provider": c.provider,
            "resource_pattern": c.resource_pattern,
            "actions": sorted(c.actions),
            "scope": c.scope,
            "time_window": c.time_window,
            "effect": c.effect,
            "constraint_class": c.constraint_class,
            "principal": c.principal,
            "source_ref": c.source_ref,
            "source_timestamp": c.source_timestamp,
            "rule_text": c.rule_text,
        }
        with open(sources_dir / f"{c.source_ref}.json", "w") as f:
            json.dump(payload, f)


def build_store(constraints: list[Constraint]) -> ConstraintStore:
    authority_map = {p: set(classes) for p, classes in bc.AUTHORITY.items()}
    store = ConstraintStore(authority_map=authority_map)
    for c in constraints:
        store.constraints[c.id] = c
    return store


# ---------------------------------------------------------------------------
# Intent sampling
# ---------------------------------------------------------------------------


def matching_intent(
    c: Constraint, idx: int, rng: random.Random
) -> tuple[InfrastructureIntent, Any]:
    resource = bc.concretize_resource(c.resource_pattern, rng)
    action = rng.choice(sorted(c.actions))
    now = bc.now_for_time_window(c.time_window)
    return (
        InfrastructureIntent(
            resource=resource, action=action, provider=c.provider, params={}, metadata=dict(c.scope)
        ),
        now,
    )


def miss_intent(idx: int, rng: random.Random) -> tuple[InfrastructureIntent, Any]:
    from datetime import UTC, datetime

    provider = rng.choice(["kubernetes", "terraform", "aws", "azure", "gcp"])
    resource = f"unmatched-kind-{idx:06d}/{rng.choice(RESOURCE_NAMES)}"
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    return (
        InfrastructureIntent(
            resource=resource,
            action="describe-nonexistent",
            provider=provider,
            params={},
            metadata={},
        ),
        now,
    )


def sample_intents(
    constraints: list[Constraint], n: int, rng: random.Random
) -> list[tuple[InfrastructureIntent, Any]]:
    half = n // 2
    intents = []
    for i in range(half):
        c = rng.choice(constraints)
        intents.append(matching_intent(c, i, rng))
    for i in range(n - half):
        intents.append(miss_intent(i, rng))
    rng.shuffle(intents)
    return intents


# ---------------------------------------------------------------------------
# Timing / stats
# ---------------------------------------------------------------------------


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return float("nan")
    k = (len(sorted_values) - 1) * (pct / 100)
    f, c = int(k), min(int(k) + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    d = k - f
    return sorted_values[f] * (1 - d) + sorted_values[c] * d


def bootstrap_ci(values: list[float], pct: float, rng: random.Random) -> tuple[float, float, float]:
    """Returns (point_estimate, ci_low, ci_high) for the ``pct`` percentile
    of ``values`` via a 1000-resample bootstrap."""
    point = percentile(sorted(values), pct)
    n = len(values)
    resampled_percentiles = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        sample.sort()
        resampled_percentiles.append(percentile(sample, pct))
    resampled_percentiles.sort()
    lo = percentile(resampled_percentiles, CI_LOW)
    hi = percentile(resampled_percentiles, CI_HIGH)
    return point, lo, hi


def time_decisions(
    interceptor: AegisInterceptor, intents: list[tuple[InfrastructureIntent, Any]]
) -> list[float]:
    latencies_ms = []
    for intent, now in intents:
        t0 = time.perf_counter()
        interceptor.intercept(intent, now=now)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
    return latencies_ms


# ---------------------------------------------------------------------------
# Per-size run
# ---------------------------------------------------------------------------


def run_size(size: int, n_decisions: int, tmp_root: Path) -> dict[str, Any]:
    rng = random.Random(SEED + size)
    constraints = build_synthetic_constraints(size, rng)
    store = build_store(constraints)
    interceptor = AegisInterceptor(store)

    all_intents = sample_intents(constraints, n_decisions + WARMUP, rng)
    warmup_intents, measured_intents = all_intents[:WARMUP], all_intents[WARMUP:]
    time_decisions(interceptor, warmup_intents)  # discarded warm-up
    latencies = time_decisions(interceptor, measured_intents)

    ci_rng = random.Random(SEED + size + 1)
    p50, p50_lo, p50_hi = bootstrap_ci(latencies, 50, ci_rng)
    p95, p95_lo, p95_hi = bootstrap_ci(latencies, 95, ci_rng)
    p99, p99_lo, p99_hi = bootstrap_ci(latencies, 99, ci_rng)

    # ConstraintStore.load wall time, with and without a --sources fetcher.
    size_dir = tmp_root / f"size-{size}"
    size_dir.mkdir(parents=True, exist_ok=True)
    constraints_path = size_dir / "constraints.yaml"
    save_store = build_store(constraints)
    save_store.save(constraints_path)

    sources_dir = size_dir / "sources"
    write_source_tree(constraints, sources_dir)

    authority_map = {p: set(classes) for p, classes in bc.AUTHORITY.items()}

    t0 = time.perf_counter()
    ConstraintStore.load(constraints_path, authority_map=authority_map, insecure=True)
    load_no_sources_ms = (time.perf_counter() - t0) * 1000

    from aegis_core.provenance import FileSourceFetcher

    t0 = time.perf_counter()
    ConstraintStore.load(
        constraints_path,
        authority_map=authority_map,
        source_fetcher=FileSourceFetcher(sources_dir, insecure=True),
        insecure=True,
    )
    load_with_sources_ms = (time.perf_counter() - t0) * 1000

    return {
        "size": size,
        "n_decisions": len(latencies),
        "warmup_excluded": WARMUP,
        "latency_ms": {
            "p50": {"value": p50, "ci95": [p50_lo, p50_hi]},
            "p95": {"value": p95, "ci95": [p95_lo, p95_hi]},
            "p99": {"value": p99, "ci95": [p99_lo, p99_hi]},
            "mean": statistics.fmean(latencies),
            "min": min(latencies),
            "max": max(latencies),
        },
        "store_load_ms": {
            "without_sources": load_no_sources_ms,
            "with_sources": load_with_sources_ms,
        },
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_markdown(results: dict[str, Any]) -> str:
    lines = [
        "# Latency Sweep (REVIEW-4 T2.3)",
        "",
        f"`{n_decisions_line(results)}` decisions per size "
        f"(first {WARMUP} warm-up calls excluded); "
        f"p50/p95/p99 with a {BOOTSTRAP_RESAMPLES}-resample bootstrap 95% CI. Store built from "
        "the same seeds.yaml / variation axes as the evaluation corpus "
        "(scripts/build_corpus.py), "
        "all constraints Trusted, no signing required.",
        "",
        "| size | p50 (ms) | p50 95% CI | p95 (ms) | p95 95% CI | p99 (ms) | p99 95% CI | "
        "store load (ms, no sources) | store load (ms, with sources) |",
        "| ---: | ---: | :--- | ---: | :--- | ---: | :--- | ---: | ---: |",
    ]
    for row in results["sizes"]:
        lat = row["latency_ms"]

        def ci(entry):
            return f"[{entry['ci95'][0]:.4f}, {entry['ci95'][1]:.4f}]"

        lines.append(
            f"| {row['size']} | {lat['p50']['value']:.4f} | {ci(lat['p50'])} | "
            f"{lat['p95']['value']:.4f} | {ci(lat['p95'])} | "
            f"{lat['p99']['value']:.4f} | {ci(lat['p99'])} | "
            f"{row['store_load_ms']['without_sources']:.2f} | "
            f"{row['store_load_ms']['with_sources']:.2f} |"
        )
    return "\n".join(lines) + "\n"


def n_decisions_line(results: dict[str, Any]) -> str:
    sizes = results["sizes"]
    return f"n={sizes[0]['n_decisions']}" if sizes else "n=0"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sizes", default="100,500,2500,10000")
    parser.add_argument("--decisions", type=int, default=2000)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results" / "latency.json")
    args = parser.parse_args()

    sizes = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
    args.out.parent.mkdir(parents=True, exist_ok=True)

    import tempfile

    results: dict[str, Any] = {
        "meta": {
            "sizes": sizes,
            "decisions_per_size": args.decisions,
            "warmup_excluded": WARMUP,
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "seed": SEED,
        },
        "sizes": [],
    }

    with tempfile.TemporaryDirectory(prefix="aegis-latency-") as tmp:
        tmp_root = Path(tmp)
        for size in sizes:
            print(f"size={size} ...", flush=True)
            row = run_size(size, args.decisions, tmp_root)
            results["sizes"].append(row)
            lat = row["latency_ms"]
            ci_lo, ci_hi = lat["p99"]["ci95"]
            print(
                f"  p50={lat['p50']['value']:.4f}ms p95={lat['p95']['value']:.4f}ms "
                f"p99={lat['p99']['value']:.4f}ms (CI {ci_lo:.4f}-{ci_hi:.4f}) "
                f"load(no-sources)={row['store_load_ms']['without_sources']:.2f}ms "
                f"load(with-sources)={row['store_load_ms']['with_sources']:.2f}ms"
            )

    args.out.write_text(json.dumps(results, indent=2, sort_keys=True))
    md_path = args.out.with_suffix(".md")
    md_path.write_text(render_markdown(results))
    print(f"\nWrote {args.out}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
