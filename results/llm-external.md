# External LLM baseline run (agent-guardrail-bench)

**This is not a result produced by this repo's `scripts/benchmark.py`.** It is
reproduced here, verbatim, from a sibling benchmark harness that imports
this repo's `aegis_core.baselines.llm` (`LLMVerifier` / `RecordingClient` /
`ReplayClient` / `AnthropicClient`) directly, because it ran the real
`claude-sonnet-5` self-check (both the naive prompt and the
provenance/authority-aware prompt) before this repo's own corpus finished
its T0.5 rewrite (independent oracle, intent-level holdout split — see
REVIEW-4.md).

**Provenance**
- Source repo: `agent-guardrail-bench`, commit `a98a8fa` ("results: Claude
  Sonnet 5 self-check rows (plain and authority-in-prompt) with replayable
  caches; full tables").
- Report files there: `results/benchmark-holdout.md`, `results/benchmark-all.md`.
- Model: `claude-sonnet-5`, via `aegis_core.baselines.llm.AnthropicClient`.
- Corpus: **this repo's pre-T0.5 corpus** — `data/corpus/{constraints,intents,split,authority}`
  at commit `a2497e4^` (the commit immediately before "fix: independent
  benchmark oracle and real intent holdout (T0.5)"). 500 constraints, 100 of
  them in the frozen `holdout` constraint split, 200 intents (60 poison-only).
  Verified byte-identical to the sibling repo's `corpus/constraints.yaml`.
- Caches copied verbatim into this repo as `results/llm-cache-naive.jsonl`
  (400 entries — covers both the sibling harness's `all` and `holdout`
  runs) and `results/llm-cache-aware.jsonl` (200 entries, `holdout` only),
  from the sibling repo's `results/llm-cache.jsonl` and
  `results/llm-authority-cache.jsonl`.
- Replay verification: `tests/test_baselines.py::test_llm_replay_matches_external_cache_*`
  loads the pinned old-corpus constraints/intents/authority from git history
  and asserts `ReplayClient` (via `LLMVerifier`/`AwarePromptBuilder`) finds
  every one of the 200 `agent-guardrail-bench` holdout intents' cache keys —
  a 100% hit rate, confirming this repo's current `render_system_prompt` /
  `AwarePromptBuilder.render_system_prompt` are byte-identical to what
  produced these caches (no prompt drift since T0.5 started).

**What "aware" means in this table**: `llm-authority` in the sibling repo is
what `AwarePromptBuilder` in this repo now implements — the naive prompt
plus the `authority.yaml` contents and an instruction to ignore any
constraint whose principal isn't authorized for its `constraint_class`. It
still can't check *integrity* (a hash in a prompt is just text), so a
tampered/forged constraint from an *authorized* principal still gets
through — see `AwarePromptBuilder`'s docstring.

## Holdout split (100 constraints, 200 intents, 60 poison-only)

| verifier | evaluated | precision | recall | F1 | exact | over-block | poison-susc. (n) | coverage | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| trust-all | 200/200 | 0.625 | 1.000 | 0.769 | 0.635 | 0.600 | 1.000 (60) | 0.800 | 0.015 | 0.020 |
| opa | 200/200 | 0.625 | 1.000 | 0.769 | 0.635 | 0.600 | 1.000 (60) | 0.800 | 12.484 | 14.913 |
| **llm-naive** (llm-replay) | 200/200 | 0.625 | 1.000 | 0.769 | 0.625 | 0.600 | **1.000** (60) | 0.800 | 0.025 | 0.035 |
| **llm-aware** (llm-authority) | 200/200 | 0.654 | 1.000 | 0.791 | 0.685 | 0.530 | **0.883** (60) | 0.765 | 0.025 | 0.037 |
| aegis | 200/200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | **0.000** (60) | 0.500 | 0.089 | 0.134 |
| aegis-failclosed | 200/200 | 0.625 | 1.000 | 0.769 | 0.700 | 0.600 | 1.000 (60) | 0.800 | 0.086 | 0.137 |
| hook | 89/200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 (24) | 0.528 | 94.687 | 99.665 |

## All constraints (500 constraints, 200 intents, 60 poison-only) — naive only

| verifier | evaluated | precision | recall | F1 | exact | over-block | poison-susc. (n) | coverage | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| trust-all | 200/200 | 0.625 | 1.000 | 0.769 | 0.635 | 0.600 | 1.000 (60) | 0.800 | 0.084 | 0.106 |
| opa | 200/200 | 0.625 | 1.000 | 0.769 | 0.635 | 0.600 | 1.000 (60) | 0.800 | 27.309 | 31.110 |
| **llm-naive** | 200/200 | 0.625 | 1.000 | 0.769 | 0.510 | 0.600 | **1.000** (60) | 0.800 | 0.097 | 0.129 |
| aegis | 200/200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | **0.000** (60) | 0.500 | 0.444 | 0.582 |
| aegis-failclosed | 200/200 | 0.625 | 1.000 | 0.769 | 0.700 | 0.600 | 1.000 (60) | 0.800 | 0.448 | 0.590 |
| hook | 118/200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 (41) | 0.492 | 258.601 | 284.005 |

**Reading it**: a naive LLM self-check obeys 100% of poisoned constraints
(poison-susceptibility 1.000) — no better than trusting every constraint in
the store. Giving it the authority map cuts that to 0.883: it now catches
unauthorized-principal poisoning it's told to ignore, but 88% of poisoned
constraints still get through, because tampered/forged constraints from an
*authorized* principal look identical to a real one in a prompt — the
model has no way to recompute a hash. Aegis is 0.000 on the same intents
because it verifies both independently of anything in a prompt.

## Fresh run on the current (post-T0.5) corpus

This repo's own corpus is being regenerated (new seeds, intent-level
holdout, independent oracle — see REVIEW-4 T0.5/T2.2) as of this writing,
so the cached responses above do not cover it; a new recording is needed
once that corpus lands. To reproduce with `ANTHROPIC_API_KEY` set:

```bash
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,llm-naive,llm-aware \
    --llm-cache results/llm-cache.jsonl
```

then replay it offline any time after with:

```bash
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,llm-replay-naive,llm-replay-aware \
    --llm-cache results/llm-cache.jsonl
```

**Cost estimate.** `--verifiers llm-naive,llm-aware` always feeds the
*entire* 500-constraint store to the model (`baseline_constraints` in
`scripts/benchmark.py` — every label, unfiltered, since neither baseline
has a provenance/authority concept of its own until `llm-aware` adds the
authority map); the holdout **split only selects which intents are
scored**, currently `data/corpus/split.json["intents"]["holdout"]` = **120
intents**. Measured directly: `data/corpus/constraints.yaml` is 277,655
bytes; `render_constraints_yaml` produces very close to that per call
(same dict shape via `_constraint_to_dict`), i.e. roughly **~69,000 input
tokens** per naive call at ~4 chars/token; `llm-aware` adds the rendered
`authority.yaml` block (a few hundred tokens). Output is one short line
(`ALLOW`/`BLOCK`/`ESCALATE` plus an optional citations line), well under
50 tokens. So: **120 holdout intents x ~69,000 input tokens x 2 variants
(naive, aware) ~= 16.6M input tokens**, plus a negligible ~12k output
tokens, for one full `llm-naive` + `llm-aware` pass over the current
corpus. Check current `claude-sonnet-5` pricing (the `claude-api` skill's
reference) before running; at a rough $3/M input tokens that's on the
order of **~$50** for both variants together — the system prompt is
identical across all 120 calls within a variant, so prompt caching (see
the `claude-api` skill) would cut the effective cost roughly to one full
prompt plus 120 small cache-read + user-turn calls, not 120 full prompts.
