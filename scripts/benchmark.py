#!/usr/bin/env python3
"""The Week 7-8 benchmark harness (PLAN.md §4): "Baseline vs. Aegis".

Runs Aegis and the baselines (LLM self-check, OPA/Rego, signed-bundle OPA)
over the labeled evaluation corpus and produces a confusion matrix,
over-block rate, coverage, per-kind poison-susceptibility, and p50/p95/p99
latency for each.

    venv/bin/python scripts/benchmark.py \\
        [--corpus data/corpus] [--split holdout|dev|all] \\
        [--verifiers aegis,llm-heuristic,opa,opa-signed,llm,aegis-nosources,codex,ollama,claude-cli]
        [--llm-cache results/llm-cache.jsonl] [--out results/]

Ground truth
------------
``expected_verdict`` / ``expected_covered`` / ``poison_kind`` for every
intent come from ``scripts/reference_oracle.py`` — a deliberately naive
label-driven matcher that never imports the interceptor — and the harness
re-runs that oracle here rather than trusting whatever is in
``intents.jsonl``. Aegis's precision / recall against it are therefore a
measurement, not a sanity check.

Splits
------
``--split`` selects **intents** (``split.json["intents"]``); the constraint
store is always the full 500-constraint corpus. The store is the deployed
artefact — every verifier ships with all of it — and the intents are the
test set. ``holdout`` (the default) is the 20% stratified held-out set
reported in ``results/``; ``dev`` is the rest; ``all`` is only for
debugging and must be paired with ``--i-know-this-is-dev``.

``covered`` is defined once, by the harness, from the oracle's structural
match (any constraint of any label matched) — not from each verifier's own
``Decision.covered`` flag, which means different things per verifier.

Deterministic and fully offline for the default verifier set — no network
calls; the ``opa`` / ``opa-signed`` rows are skipped with a clear note when
the ``opa`` binary is missing. The real LLM baseline (``llm``) needs
``pip install -e ".[llm]"`` and ``ANTHROPIC_API_KEY``; see the README's
"## Benchmark" section.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from aegis_core.authority import load_authority_map
from aegis_core.baselines.base import AegisVerifier, Verifier
from aegis_core.baselines.external import (
    ClaudeCliAuthError,
    ClaudeCliClient,
    CodexCliClient,
    OllamaClient,
    RetryingClient,
)
from aegis_core.baselines.llm import (
    AnthropicClient,
    AwarePromptBuilder,
    HeuristicLLMClient,
    LLMVerifier,
    RecordingClient,
    ReplayClient,
)
from aegis_core.baselines.metrics import POISON_KINDS, compute_metrics
from aegis_core.baselines.opa import OpaVerifier, signed_bundle_constraints
from aegis_core.intent import InfrastructureIntent
from aegis_core.provenance import FileSourceFetcher
from aegis_core.store import Constraint, ConstraintStore, _constraint_from_dict

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_oracle  # noqa: E402  (scripts/reference_oracle.py)

ORACLE_NAME = "reference"


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


def load_intents(intents_path: Path) -> list[dict]:
    return reference_oracle.read_jsonl(intents_path)


def load_labels(labels_path: Path) -> dict[str, dict]:
    return reference_oracle.read_labels(labels_path)


def load_stats(corpus: Path) -> dict[str, Any]:
    path = corpus / "stats.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def select_intents(intents: list[dict], split_data: dict, which: str) -> list[dict]:
    if which == "all":
        return intents
    intent_split = split_data.get("intents")
    if not intent_split or which not in intent_split:
        raise SystemExit(
            f"split.json has no intent split '{which}'; regenerate the corpus with "
            "scripts/build_corpus.py"
        )
    ids = set(intent_split[which])
    return [rec for rec in intents if rec["id"] in ids]


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
# Ground truth — recomputed from the oracle, cross-checked against the file
# ---------------------------------------------------------------------------


def oracle_ground_truth(corpus: Path, intents: list[dict]) -> list[dict]:
    constraint_dicts = reference_oracle.read_constraints(corpus / "constraints.yaml")
    labels = reference_oracle.read_labels(corpus / "labels.jsonl")
    truth = reference_oracle.oracle_verdicts_for(intents, constraint_dicts, labels)
    stale = [
        rec["id"]
        for rec, t in zip(intents, truth)
        if rec.get("expected_verdict") != t["expected_verdict"]
        or rec.get("expected_covered") != t["expected_covered"]
    ]
    if stale:
        raise SystemExit(
            f"intents.jsonl is stale: {len(stale)} intents disagree with the reference "
            f"oracle (first: {stale[:5]}); run scripts/reference_oracle.py --corpus {corpus}"
        )
    return truth


# ---------------------------------------------------------------------------
# Verifier construction
# ---------------------------------------------------------------------------


def _variant_cache_path(base: Path, variant: str) -> Path:
    """``results/llm-cache.jsonl`` -> ``results/llm-cache-naive.jsonl`` /
    ``results/llm-cache-aware.jsonl``, so a single ``--llm-cache`` flag
    still gives the naive and provenance-aware prompts separate caches
    (they hash to different keys anyway, since the system prompt differs,
    but separate files keep the two runs' costs and record counts easy to
    read independently)."""
    if base.stem.endswith(f"-{variant}"):
        return base
    return base.with_name(f"{base.stem}-{variant}{base.suffix}")


def load_holdout_constraint_subset(
    corpus: Path, baseline_constraints: list[Constraint]
) -> list[Constraint]:
    """The 100-constraint **holdout constraint split**
    (``data/corpus/split.json["holdout"]``, distinct from
    ``split.json["intents"]["holdout"]``) -- an explicit, documented
    parameter for the ``codex``/``ollama`` verifiers, never a silent
    default. The full 500-constraint corpus renders to ~69k prompt
    tokens, which is infeasible for a local model's context window and
    slow/expensive to probe against an agent harness; this 100-constraint
    subset (~14k tokens) is also what the pinned Claude rows in
    ``results/llm-external.md`` were measured against, so these rows stay
    comparable to that table. See ``aegis_core.baselines.external`` for
    the full rationale."""
    with open(corpus / "split.json") as f:
        split_data = json.load(f)
    holdout_ids = set(split_data["holdout"])
    return [c for c in baseline_constraints if c.id in holdout_ids]


def _build_llm_verifier(
    *,
    constraints: list[Constraint],
    cache_path: Path,
    name: str,
    system_prompt: str | None,
) -> tuple[Verifier | None, str | None, bool]:
    """Shared construction for the real-API ``llm-naive``/``llm-aware``
    rows: skipped (not a misleading stub row) when no API key is set."""
    import os

    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if not has_key:
        return None, "skipped: set ANTHROPIC_API_KEY", False
    try:
        real_client = AnthropicClient()
    except RuntimeError as exc:
        return None, f"skipped: set ANTHROPIC_API_KEY ({exc})", False
    client = RecordingClient(real_client, cache_path)
    verifier = LLMVerifier(client, constraints, name=name, system_prompt=system_prompt)
    return verifier, None, False


def build_verifier(
    name: str,
    *,
    aegis_store: ConstraintStore,
    aegis_store_nosources: ConstraintStore,
    baseline_constraints: list[Constraint],
    labels: dict[str, dict],
    llm_cache_path: Path,
    authority_map: dict[str, set[str]] | None = None,
    holdout_constraints: list[Constraint] | None = None,
    codex_model: str | None = None,
    codex_cache_path: Path | None = None,
    ollama_cache_path: Path | None = None,
    claude_cli_model: str | None = None,
    claude_cli_cache_path: Path | None = None,
) -> tuple[Verifier | None, str | None, bool]:
    """Returns (verifier, skip_reason, stub). verifier is None iff
    skip_reason is set."""
    if name == "aegis":
        return AegisVerifier(aegis_store), None, False

    if name == "aegis-nosources":
        # Aegis without the corpus's source files: forged constraints (valid
        # hash, fabricated citation) are honoured. Kept as an opt-in row so
        # the cost of skipping source verification is measurable, not hidden.
        return AegisVerifier(aegis_store_nosources), None, False

    if name == "llm-heuristic":
        client = HeuristicLLMClient(baseline_constraints)
        verifier = LLMVerifier(client, baseline_constraints, name="llm-heuristic")
        return verifier, None, False

    # "llm" is kept as an alias for "llm-naive" (its historical name).
    if name in ("llm", "llm-naive"):
        cache_path = _variant_cache_path(llm_cache_path, "naive")
        return _build_llm_verifier(
            constraints=baseline_constraints,
            cache_path=cache_path,
            name="llm-naive",
            system_prompt=None,
        )

    if name == "llm-aware":
        if authority_map is None:
            raise ValueError("llm-aware requires an authority_map")
        cache_path = _variant_cache_path(llm_cache_path, "aware")
        prompt = AwarePromptBuilder(baseline_constraints, authority_map).render_system_prompt()
        return _build_llm_verifier(
            constraints=baseline_constraints,
            cache_path=cache_path,
            name="llm-aware",
            system_prompt=prompt,
        )

    # "llm-replay" is kept as an alias for "llm-replay-naive".
    if name in ("llm-replay", "llm-replay-naive"):
        cache_path = _variant_cache_path(llm_cache_path, "naive")
        client = ReplayClient(cache_path)
        verifier = LLMVerifier(client, baseline_constraints, name="llm-replay-naive")
        return verifier, None, False

    if name == "llm-replay-aware":
        if authority_map is None:
            raise ValueError("llm-replay-aware requires an authority_map")
        cache_path = _variant_cache_path(llm_cache_path, "aware")
        prompt = AwarePromptBuilder(baseline_constraints, authority_map).render_system_prompt()
        client = ReplayClient(cache_path)
        verifier = LLMVerifier(
            client, baseline_constraints, name="llm-replay-aware", system_prompt=prompt
        )
        return verifier, None, False

    if name in ("codex", "codex-replay"):
        if holdout_constraints is None:
            raise ValueError(f"{name} requires holdout_constraints")
        cache_path = codex_cache_path or REPO_ROOT / "results" / "codex-cache.jsonl"
        n_c = len(holdout_constraints)
        if name == "codex-replay":
            if not cache_path.exists():
                return None, f"skipped: no cache at {cache_path}; run `codex` first", False
            client = ReplayClient(cache_path, model=codex_model)
            verifier = LLMVerifier(client, holdout_constraints, name=name)
            verifier.note = (
                f"replayed from {cache_path.name}, agent harness (codex exec), "
                f"model={codex_model or 'gpt-6-astra (account default)'}, "
                f"{n_c}-constraint holdout subset"
            )
            return verifier, None, False
        codex_client = CodexCliClient(model=codex_model)
        if not codex_client.available:
            return None, "skipped: codex not on PATH", False
        client = RecordingClient(RetryingClient(codex_client), cache_path, model=codex_model)
        verifier = LLMVerifier(client, holdout_constraints, name=name)
        verifier.note = (
            f"agent harness (codex exec), model={codex_model or 'gpt-6-astra (account default)'}, "
            f"{n_c}-constraint holdout subset"
        )
        return verifier, None, False

    if name in ("ollama", "ollama-replay"):
        if holdout_constraints is None:
            raise ValueError(f"{name} requires holdout_constraints")
        cache_path = ollama_cache_path or REPO_ROOT / "results" / "ollama-cache.jsonl"
        n_c = len(holdout_constraints)
        model = "mistral:latest"
        note = (
            f"local, {model}, num_ctx=32768, temp=0 seed=0, {n_c}-constraint holdout subset"
        )
        if name == "ollama-replay":
            if not cache_path.exists():
                return None, f"skipped: no cache at {cache_path}; run `ollama` first", False
            client = ReplayClient(cache_path, model=model)
            verifier = LLMVerifier(client, holdout_constraints, name=name)
            verifier.note = "replayed from " + cache_path.name + ", " + note
            return verifier, None, False
        ollama_client = OllamaClient(model=model)
        if not ollama_client.available:
            return None, "skipped: ollama server not reachable", False
        client = RecordingClient(RetryingClient(ollama_client), cache_path, model=model)
        verifier = LLMVerifier(client, holdout_constraints, name=name)
        verifier.note = note
        return verifier, None, False

    if name in ("claude-cli", "claude-cli-replay"):
        if holdout_constraints is None:
            raise ValueError(f"{name} requires holdout_constraints")
        cache_path = claude_cli_cache_path or REPO_ROOT / "results" / "claude-cli-cache.jsonl"
        model = claude_cli_model or "haiku"
        n_c = len(holdout_constraints)
        note = f"agent harness (claude -p), model={model}, {n_c}-constraint holdout subset"
        if name == "claude-cli-replay":
            if not cache_path.exists():
                return None, f"skipped: no cache at {cache_path}; run `claude-cli` first", False
            client = ReplayClient(cache_path, model=model)
            verifier = LLMVerifier(client, holdout_constraints, name=name)
            verifier.note = "replayed from " + cache_path.name + ", " + note
            return verifier, None, False
        claude_client = ClaudeCliClient(model=model)
        if not claude_client.available:
            return None, "skipped: claude not on PATH", False
        # A cheap (in prompt size, not necessarily in wall time -- an
        # expired OAuth session takes the CLI ~180s to surface) preflight
        # call, so an unauthenticated run is skipped cleanly with a clear
        # instruction instead of failing 100 times, once per holdout
        # intent, over the real 23.7k-token prompt.
        try:
            claude_client.complete(
                "You are a smoke test.", "Reply with exactly one word: ALLOW"
            )
        except ClaudeCliAuthError as exc:
            return None, f"skipped: {exc}", False
        except RuntimeError as exc:
            return None, f"skipped: claude -p preflight failed ({exc})", False
        client = RecordingClient(RetryingClient(claude_client), cache_path, model=model)
        verifier = LLMVerifier(client, holdout_constraints, name=name)
        verifier.note = note
        return verifier, None, False

    if name in ("opa", "opa-signed"):
        constraints = baseline_constraints
        if name == "opa-signed":
            constraints = signed_bundle_constraints(baseline_constraints, labels)
        opa_verifier = OpaVerifier(constraints, name=name)
        if not opa_verifier.available:
            return None, "unavailable: opa not on PATH", False
        return opa_verifier, None, False

    raise ValueError(f"Unknown verifier: {name}")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def render_markdown(results: dict[str, Any]) -> str:
    meta = results["meta"]
    n_distinct = meta.get("n_distinct_structural")
    n_distinct_str = str(n_distinct) if n_distinct is not None else "?"
    lines = [
        "# Aegis Benchmark Report",
        "",
        f"split: {meta['split']} · oracle: {meta['oracle']} "
        f"(scripts/reference_oracle.py) · n={meta['n_intents']} · "
        f"n_distinct={n_distinct_str}",
        "",
        f"Constraints loaded (all verifiers, every label): {meta['n_constraints']} — "
        f"{n_distinct_str} distinct `(provider, resource_pattern, actions, scope)` "
        f"structures. Intents: {meta['n_intents']} (`{meta['split']}` split), of which "
        f"{meta['poison_candidates']} are poison candidates "
        f"({meta['poison_candidates_by_kind']}).",
        "",
        "`aegis` loads the store with the corpus's `sources/` (forged constraints are "
        "quarantined at load); `aegis-nosources` (opt-in) shows the same engine without "
        "source verification. "
        "Ground truth is derived by the reference oracle from `labels.jsonl` and a naive "
        "structural matcher — only Trusted rules drive `expected_verdict` — and never "
        "from the interceptor. `covered` is the oracle's structural match (any label), "
        "computed once for every verifier. `ps_*` = fraction of poison candidates of that "
        "kind the verifier **BLOCK**ed (obeyed the poison); `pe_*` = fraction it "
        "**ESCALATE**d (failed closed on it); `poison-susceptibility` = either, overall. "
        "`strict precision` counts a positive only on an exact verdict match.",
        "",
        "| verifier | n | n_distinct | precision | strict precision | recall | F1 | "
        "over-block | poison-susceptibility | ps_unauth | ps_tampered | ps_forged | "
        "pe_unauth | pe_tampered | pe_forged | coverage | p50 (ms) | p99 (ms) | notes |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
    ]
    for name, row in results["verifiers"].items():
        if row.get("skipped"):
            dashes = " | ".join(["-"] * 17)
            lines.append(f"| {name} | {dashes} | {row['skip_reason']} |")
            continue
        m = row["metrics"]
        notes = []
        if row.get("stub"):
            notes.append("stub")
        if row.get("note"):
            notes.append(row["note"])
        note = ", ".join(notes) if notes else ""
        lines.append(
            f"| {name} | {m['n']} | {n_distinct_str} | {m['precision']:.3f} | "
            f"{m['strict_precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
            f"{m['over_block_rate']:.3f} | {m['poison_susceptibility']:.3f} | "
            f"{m['ps_unauthorized']:.3f} | {m['ps_tampered']:.3f} | {m['ps_forged']:.3f} | "
            f"{m['pe_unauthorized']:.3f} | {m['pe_tampered']:.3f} | {m['pe_forged']:.3f} | "
            f"{m['coverage']:.3f} | {m['latency_p50_ms']:.4f} | {m['latency_p99_ms']:.4f} | "
            f"{note} |"
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=REPO_ROOT / "data" / "corpus")
    parser.add_argument("--split", choices=["holdout", "dev", "all"], default="holdout",
                        help="which INTENTS to score (constraints are always all)")
    parser.add_argument("--i-know-this-is-dev", action="store_true",
                        help="required with --split all: the numbers are not held out")
    parser.add_argument("--verifiers", default="aegis,llm-heuristic,opa,opa-signed")
    parser.add_argument("--llm-cache", type=Path, default=REPO_ROOT / "results" / "llm-cache.jsonl")
    parser.add_argument("--codex-model", default=None,
                        help="Codex model to pass as -m (default: none, i.e. whatever "
                             "`codex exec` resolves to for this account -- see "
                             "scripts/probe_codex_models.py)")
    parser.add_argument("--codex-cache", type=Path,
                        default=REPO_ROOT / "results" / "codex-cache.jsonl")
    parser.add_argument("--ollama-cache", type=Path,
                        default=REPO_ROOT / "results" / "ollama-cache.jsonl")
    parser.add_argument("--claude-cli-model", default="haiku",
                        help="Claude Code CLI model alias to pass as --model (default: haiku, "
                             "the cheapest alias)")
    parser.add_argument("--claude-cli-cache", type=Path,
                        default=REPO_ROOT / "results" / "claude-cli-cache.jsonl")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results")
    args = parser.parse_args()

    if args.split == "all" and not args.i_know_this_is_dev:
        parser.error("--split all scores dev intents too; pass --i-know-this-is-dev")

    corpus = args.corpus
    args.out.mkdir(parents=True, exist_ok=True)

    with open(corpus / "split.json") as f:
        split_data = json.load(f)
    stats = load_stats(corpus)
    labels = load_labels(corpus / "labels.jsonl")
    authority_map = load_authority_map(corpus / "authority.yaml")

    # Aegis: real quarantine-on-load store, full corpus, WITH the corpus's
    # source files (the deployed artefact ships them; without a fetcher
    # forged constraints are honoured — see the opt-in `aegis-nosources` row).
    aegis_store = ConstraintStore.load(
        corpus / "constraints.yaml",
        authority_map=authority_map,
        source_fetcher=FileSourceFetcher(corpus / "sources"),
    )
    aegis_store_nosources = ConstraintStore.load(
        corpus / "constraints.yaml", authority_map=authority_map
    )
    # Baselines: every constraint, no quarantine, full corpus.
    baseline_constraints = load_all_constraints_unquarantined(corpus / "constraints.yaml")
    # codex/ollama: the 100-constraint holdout split, not the full corpus
    # (see load_holdout_constraint_subset's docstring).
    holdout_constraints = load_holdout_constraint_subset(corpus, baseline_constraints)

    intents = select_intents(load_intents(corpus / "intents.jsonl"), split_data, args.split)
    truth = oracle_ground_truth(corpus, intents)
    expected_list = [t["expected_verdict"] for t in truth]
    covered_list = [t["expected_covered"] for t in truth]
    poison_kinds = [t["poison_kind"] if t["poison_candidate"] else "none" for t in truth]
    poison_by_kind = {k: poison_kinds.count(k) for k in POISON_KINDS}

    print(f"split: {args.split} · oracle: {ORACLE_NAME} · n={len(intents)} · "
          f"n_distinct={stats.get('n_distinct_structural', '?')} · "
          f"constraints={len(baseline_constraints)}")
    print(f"poison candidates: {sum(poison_by_kind.values())} {poison_by_kind}")

    verifier_names = [v.strip() for v in args.verifiers.split(",") if v.strip()]

    results: dict[str, Any] = {
        "meta": {
            "split": args.split,
            "oracle": ORACLE_NAME,
            "oracle_path": "scripts/reference_oracle.py",
            "n_constraints": len(baseline_constraints),
            "n_distinct_structural": stats.get("n_distinct_structural"),
            "n_distinct_patterns": stats.get("n_distinct_patterns"),
            "n_distinct_rule_text": stats.get("n_distinct_rule_text"),
            "n_intents": len(intents),
            "poison_candidates": sum(poison_by_kind.values()),
            "poison_candidates_by_kind": poison_by_kind,
            "verifiers_requested": verifier_names,
        },
        "verifiers": {},
    }

    for name in verifier_names:
        verifier, skip_reason, stub = build_verifier(
            name,
            aegis_store=aegis_store,
            aegis_store_nosources=aegis_store_nosources,
            baseline_constraints=baseline_constraints,
            labels=labels,
            llm_cache_path=args.llm_cache,
            authority_map=authority_map,
            holdout_constraints=holdout_constraints,
            codex_model=args.codex_model,
            codex_cache_path=args.codex_cache,
            ollama_cache_path=args.ollama_cache,
            claude_cli_model=args.claude_cli_model,
            claude_cli_cache_path=args.claude_cli_cache,
        )
        if verifier is None:
            print(f"[{name}] SKIPPED: {skip_reason}")
            results["verifiers"][name] = {"skipped": True, "skip_reason": skip_reason}
            continue

        decisions: list[Any] = []
        t0 = time.perf_counter()
        for rec in intents:
            intent, now = intent_from_record(rec)
            decisions.append(verifier.decide(intent, now))
        wall_ms = (time.perf_counter() - t0) * 1000

        metrics = compute_metrics(expected_list, decisions, poison_kinds, covered_list)
        results["verifiers"][name] = {
            "skipped": False,
            "stub": stub,
            "wall_ms": wall_ms,
            "n_constraints_fed": len(getattr(verifier, "constraints", baseline_constraints)),
            "metrics": metrics,
            "note": getattr(verifier, "note", None),
        }
        print(
            f"[{name}] n={metrics['n']} p={metrics['precision']:.3f} r={metrics['recall']:.3f} "
            f"f1={metrics['f1']:.3f} over_block={metrics['over_block_rate']:.3f} "
            f"ps={metrics['poison_susceptibility']:.3f} "
            f"(ps u/t/f={metrics['ps_unauthorized']:.2f}/{metrics['ps_tampered']:.2f}/"
            f"{metrics['ps_forged']:.2f}; pe u/t/f={metrics['pe_unauthorized']:.2f}/"
            f"{metrics['pe_tampered']:.2f}/{metrics['pe_forged']:.2f}) "
            f"p50={metrics['latency_p50_ms']:.4f}ms"
            + (" (stub)" if stub else "")
        )

    (args.out / "benchmark.json").write_text(json.dumps(results, indent=2, sort_keys=True))
    (args.out / "benchmark.md").write_text(render_markdown(results))

    print()
    print(f"Wrote {args.out / 'benchmark.json'}")
    print(f"Wrote {args.out / 'benchmark.md'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
