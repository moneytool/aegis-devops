# Benchmark methodology

Ground truth, the held-out split, verifier definitions, the full results table, real LLM
baselines, agent-harness baselines, the corpus, and the adversarial suite.

← back to the [README](../README.md)

## Benchmark

![Benchmark results](benchmark.svg)

`../scripts/benchmark.py` runs Aegis and several baselines over the labeled 500-constraint corpus in
`../data/corpus/` (built by `../scripts/build_corpus.py`) and reports precision/recall/F1, over-block
rate, coverage, per-kind poison-susceptibility, and latency for each:

```bash
venv/bin/python scripts/benchmark.py \
    --corpus data/corpus --split holdout \
    --verifiers aegis,llm-heuristic,opa,opa-signed \
    --out results/
```

**Ground truth is independent of Aegis.** Every intent's `expected_verdict` / `expected_covered`
comes from `../scripts/reference_oracle.py` — a deliberately naive matcher (`provider ==`,
`fnmatch`, `action in`, scope equality, a minimal time window) that reads `constraints.yaml`,
`labels.jsonl` and `authority.yaml` with plain loaders and never imports
`aegis_core.interceptor`, `aegis_core.store` or `aegis_core.plan`. Only constraints labelled
**Trusted** drive the verdict (BLOCK > ESCALATE > ALLOW); `covered` is "any constraint of any
label matched" and is computed once by the harness for every verifier. The harness re-runs the
oracle at benchmark time and refuses to score a stale `intents.jsonl`. The `aegis` row is
therefore a measurement against that oracle, not a sanity check on itself.

**The test set is a held-out intent split.** `split.json["intents"]["holdout"]` is 20% of the
600 intents, stratified by `expected_verdict` × `poison_candidate`, frozen with the corpus seed.
`--split holdout` is the default and the only split reported here; `--split dev` is the rest;
`--split all` requires `--i-know-this-is-dev`. The constraint store is always the full corpus —
the store is the deployed artefact, the intents are the test set.

**Verifiers.** `aegis` loads the store the way a deployment would, with the corpus's `sources/`
(so forged constraints are quarantined at load); `aegis-nosources` (opt-in) is the same engine
without source verification, kept so the cost of skipping it is measurable. `llm-heuristic` is a
deterministic, no-network stand-in for a naive LLM self-check (it blocks/escalates as soon as any
constraint matches by provider/resource/action, with no provenance or authority reasoning).
`opa` feeds every constraint to a real `opa eval`; `opa-signed` models a signed-bundle deployment
(cosign/in-toto): the bundle handed to OPA excludes `tampered` and `forged` constraints but still
contains `unauthorized` ones, because bundle signing proves integrity in transit, not that the
author was allowed to say it. Both OPA rows are skipped with a note when the `opa` binary isn't
on `PATH`.

**Columns.** `n` is the number of held-out intents; `n_distinct` is the number of distinct
`(provider, resource_pattern, actions, scope)` structures among the 500 constraints (from
`../data/corpus/stats.json`) — the honest measure of how many *different* rules the corpus
contains. `poison-susceptibility` is the headline number: of the intents whose only matching
constraints are Untrusted/Malicious (oracle verdict `ALLOW`), the fraction a verifier
blocks/escalates on anyway. It is split by the strongest poisoned rule that matched:
`ps_unauth` / `ps_tampered` / `ps_forged` count **BLOCK** verdicts (the verifier *obeyed* the
poison), `pe_*` count **ESCALATE** verdicts (it failed closed — wrong verdict, but a human sees
it). `unauthorized` is the realistic pre-ingest attacker; `tampered`/`forged` are post-ingest
attacks that bundle signing already covers, which is why the `opa-signed` → `aegis` delta on
`ps_unauth`/`pe_unauth` is the number that matters. `strict precision` counts a positive only on
an exact verdict match.

| verifier | n | precision | recall | F1 | over-block | PS | ps_unauth | ps_tamp | ps_forged | pe_unauth | pe_tamp | pe_forged |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **aegis** | 120 | **1.000** | 1.000 | **1.000** | **0.000** | **0.000** | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| opa-signed | 120 | 0.800 | 1.000 | 0.889 | 0.250 | 0.500 | 0.100 | 0.000 | 0.375 | 0.900 | 0.083 | 0.125 |
| opa | 120 | 0.667 | 1.000 | 0.800 | 0.500 | 1.000 | 0.100 | 0.750 | 0.375 | 0.900 | 0.250 | 0.625 |
| llm-heuristic | 120 | 0.667 | 1.000 | 0.800 | 0.500 | 1.000 | 0.400 | 0.833 | 0.750 | 0.600 | 0.167 | 0.250 |
| claude-cli (haiku) | 120 | 0.836 | 0.767 | 0.800 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 |
| codex (gpt-6-astra) | 120 | 0.833 | 0.750 | 0.789 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 |
| ollama (mistral 7B) | 120 | 0.500 | 1.000 | 0.667 | 1.000 | 1.000 | 0.000 | 0.083 | 0.375 | 1.000 | 0.917 | 0.625 |

(`split: holdout`, `oracle: reference`, `n_distinct=323`; 30 poison candidates — 10 unauthorized,
12 tampered, 8 forged. Full table with latency, coverage and strict precision in
`../results/benchmark.md`. The `codex` row is a full 120-intent run against `gpt-6-astra`, the
only model a ChatGPT-account Codex will serve.)

**How to read this.** Every row has recall 1.0 except `claude-cli` because the corpus's poisoned
rules are *additional* rules — a verifier that honours everything never misses a Trusted one, so
the damage shows up as over-block and `ps_*`, not as missed blocks. `ps_*` counts BLOCK verdicts
on a poison candidate (the verifier **obeyed** the poisoned rule); `pe_*` counts ESCALATE
verdicts (it acted on it, but sent it to a human). **`ps + pe` is the fraction a poisoned author
could move at all**, and that is the number the design is about:

- On the `unauthorized` kind — the realistic pre-ingest attacker — `opa` and `opa-signed` both
  score `ps + pe = 1.000`: *every* unauthorized rule steered a verdict. Signing the bundle does
  not help, because signing proves the bundle wasn't altered, not that its author was allowed to
  write the rule. Aegis scores **0.000**: an unauthorized rule has no channel to the decision.
- On `tampered`/`forged`, `opa-signed` improves (0.000 on tampered) exactly as expected — that is
  what bundle signing is for — while still leaving `forged` at 0.375, since a self-consistent
  hash says nothing about whether the cited source backs it.
- Aegis's 0.000 over-block is a consequence of the same choice: because a poisoned rule is
  discarded rather than escalated, the attacker cannot force a stall either (see
  [Store health](cli.md#store-health)). Under `escalate` those same 30 candidates all become
  ESCALATEs and the over-block rate rises to match the baselines — the earlier default, kept for
  the record in `../results/benchmark-failclosed.md`.

The two model rows are **agent harnesses**, not raw completions, and are scored on a
100-constraint subset — see the subsection below before comparing them with anything.

### Real LLM baselines: `llm-naive` and `llm-aware`

`llm-heuristic` above is a deterministic stand-in, not a measured LLM accuracy number. Two real
rows use `claude-sonnet-5` itself (see the `claude-api` skill for model IDs and pricing before
running): `llm-naive` is the plain self-check (constraints + intent, no provenance/authority
information at all); `llm-aware` (`AwarePromptBuilder` in `aegis_core/baselines/llm.py`) adds the
`authority.yaml` contents and an instruction to ignore any constraint whose principal isn't
authorized for its `constraint_class` — the strongest self-check a prompt alone can do, since it
still can't recompute a provenance hash. Run both against the current corpus once a key is set:

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,llm-naive,llm-aware --llm-cache results/llm-cache.jsonl --out results/
```

Every prompt/response pair is cached to `results/llm-cache-naive.jsonl` /
`results/llm-cache-aware.jsonl` (derived from `--llm-cache`), so a later run replays it offline
with no network calls and no key:

```bash
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,llm-replay-naive,llm-replay-aware --llm-cache results/llm-cache.jsonl \
    --out results/
```

`llm`/`llm-replay` remain accepted as aliases for `llm-naive`/`llm-replay-naive`. Without a key,
`llm-naive`/`llm-aware` are skipped with `skipped: set ANTHROPIC_API_KEY` — there is no longer a
stub row that answers `ESCALATE` on every call and gets reported as if it were data.

**Cost estimate.** Both rows feed the *entire* store (500 constraints, ~278 KB of YAML) to the
model on every call; `--split holdout` currently scores 120 intents
(`data/corpus/split.json["intents"]["holdout"]`). At ~4 chars/token that's roughly 69,000 input
tokens per `llm-naive` call (`llm-aware` adds the rendered `authority.yaml`, a few hundred more)
and under 50 output tokens. **120 intents x ~69,000 input tokens x 2 variants ~= 16.6M input
tokens** for one full pass of both rows — check current pricing with the `claude-api` skill; at a
rough $3/M input tokens that's on the order of $50 for both variants, before prompt caching
(the system prompt repeats across all 120 calls in a variant, so a cached run costs much less
than a naive per-call estimate).

**Already measured, on the pre-T0.5 corpus.** Before this corpus's T0.5 rewrite (independent
oracle, intent-level holdout — see `../REVIEW-4.md`), a sibling harness
(`agent-guardrail-bench@a98a8fa`) ran both `llm-naive` and `llm-aware` for real against the
corpus as it stood at commit `a2497e4^`, importing this repo's `aegis_core.baselines.llm`
directly. Full tables, provenance, and the replay-hit-rate verification are in
[`../results/llm-external.md`](../results/llm-external.md); the headline number is
**poison-susceptibility 1.000 for `llm-naive` vs. 0.883 for `llm-aware` vs. 0.000 for `aegis`**
on the same 200 intents — a naive self-check obeys every poisoned constraint it's handed, giving
it the authority map catches unauthorized-principal poisoning but not tampered/forged
constraints from an authorized principal, and only independent integrity + authority checking
(Aegis) catches all of it. `tests/test_baselines.py::test_llm_replay_{naive,aware}_matches_external_cache`
assert this repo's current prompt rendering still reproduces those cached prompts byte-for-byte
(100% hit rate) so the caches stay usable as a regression check even while the corpus is
regenerated.

### Agent-harness and local-model baselines: `codex`, `ollama`, and `claude-cli`

Three more rows use the SAME naive prompt `llm-naive` uses
(`aegis_core.baselines.llm.render_system_prompt`), via three more `LLMClient` implementations in
`aegis_core/baselines/external.py`, but over a smaller constraint set: `llm-naive`/`llm-aware`
feed the *entire* 500-constraint corpus (~69,000 tokens — see the cost estimate above), which is
infeasible for a local model's context window and prohibitively slow/expensive to probe
repeatedly against an agent harness. `codex`, `ollama`, and `claude-cli` instead load the
**holdout constraint split** — `data/corpus/split.json["holdout"]`, 100 constraints, distinct
from `split.json["intents"]["holdout"]` — which renders to roughly 14,000 characters-per-4 of
naive estimate, but see the token-count surprise below. This is also the same subset the pinned
`claude-sonnet-5` rows in [`../results/llm-external.md`](../results/llm-external.md) were measured
against, so these rows stay comparable to that table. The subset is threaded through explicitly
(`scripts/benchmark.py`'s `load_holdout_constraint_subset`), never a silent default.

**`codex`** shells out to `codex exec` — **an agent harness wrapped around a model**, not a raw
completion endpoint, even invoked read-only for one turn (it can plan and use tools before
answering). That distinction matters enough that the `notes` column says "agent harness (codex
exec)", not "model", for this row. Invocation:
`codex exec --ignore-user-config --skip-git-repo-check --ephemeral -s read-only --output-last-message <file> - < prompt.txt`
(`--ignore-user-config` stops a user's own `~/.codex/AGENTS.md`/config from leaking into the run;
`--output-last-message` gets a clean final answer instead of parsing the human-formatted stdout,
which echoes the prompt, an optional `warning:` line, and the answer duplicated after `tokens
used` — `CodexCliClient` falls back to robust last-matching-line stdout parsing if that file is
ever missing). **Model selection:** `scripts/probe_codex_models.py` (`probe_codex_models()` in
`external.py`) tries `gpt-5.1-codex-mini`, `gpt-5-mini`, `o4-mini`, `gpt-5.1-codex` under a hard
60s timeout each — an unsupported `-m` value doesn't fail fast, it prints an immediate `ERROR: ...
not supported` line and then *hangs* rather than exiting, so every candidate must be probed under
a timeout, never called bare. On this account (ChatGPT-plan auth) every named candidate returned
`400 ... not supported when using Codex with a ChatGPT account` immediately; the row below was run
with no `-m` at all, i.e. the account's own configured default, which the CLI's banner reports as
**`gpt-6-astra`** (`CodexCliClient.resolved_model`, parsed from that banner, records this even when
`model=None`). Measured cost: ~6s and ~2,000 tokens per call.

**`ollama`** talks to a local Ollama server's HTTP API (`POST /api/generate`, `mistral:latest`,
`temperature=0, seed=0` for reproducibility) instead of the CLI, so it's structured JSON in and
out with no stdout parsing at all. **The 100-constraint holdout prompt does not fit in 16,384
tokens of context** — the ~14k-character-per-4 estimate undercounts badly for this tokenizer:
the real prompt is **~23,700 tokens**, not ~14,000. At `num_ctx=16384` Ollama silently truncates
(confirmed here: `prompt_eval_count` came back exactly `16384`, the cap, and the model's answer
degraded into unrelated advice about writing a new Gatekeeper policy) — there is no error, no
warning, just a truncated context and a bad answer. The row below uses `num_ctx=32768`, verified
by comparing a short-prompt call (`prompt_eval_count` well under the cap) against the full-prompt
call (`prompt_eval_count` ≈ 23,700, comfortably under 32,768).

**Honest finding, not massaged:** even with the full, untruncated context, `mistral:latest` (a
local 7B model) is unreliable at following the requested format. Its 120 holdout responses
included the expected `ALLOW`/`BLOCK`/`ESCALATE` tokens, occasional `BLOCK\ncitations: <real ids>`,
but also **`BLOCK\ncitations: id1, id12`** — it echoed the system prompt's own *example* citation
placeholders (`citations: id1, id2`) instead of real constraint IDs. `tests/test_baselines.py`
does not try to rescue this with a smarter parser; `parse_llm_response` is left exactly as it was
for `llm-naive`, and the resulting metrics report what a 7B model handed this much context
actually does, unmodified.

**`claude-cli`** is the third row on the same footing: it shells out to `claude -p` (the Claude
Code CLI) — **an agent harness wrapped around a model**, just like `codex`, even with
`--allowedTools ""` denying it any tool use for the single turn — over the same 100-constraint
holdout subset. Invocation:
`claude -p --model haiku --output-format json --no-session-persistence --allowedTools "" < prompt.txt`.
`--output-format json` returns one JSON object on stdout; `ClaudeCliClient` reads the verdict from
its `result` field (fed straight into the same `parse_llm_response` every other row uses) and
token counts defensively from `modelUsage` (a dict keyed by model name, e.g.
`{"claude-haiku-4-5-20251001": {"inputTokens": ..., "outputTokens": ...}}` — shape not pinned by
any spec we control, so `ClaudeCliClient` sums whatever `*Tokens` fields it finds rather than
assuming exact keys). The row's `notes` column reads `agent harness (claude -p), model=haiku,
100-constraint holdout subset`, matching the `codex` row's honesty about what's actually being
measured. Default model is `haiku` (the cheapest alias); override with `--claude-cli-model`.

`claude -p` can fail in a way `codex`/`ollama` don't: **an expired OAuth session** — the CLI
returns exit code 0 with `is_error: true` and a `result` string containing `401` /
`OAuth access token has expired. Re-authenticate to continue.`, after ~180s of its own internal
retries. `ClaudeCliClient` detects this specific shape and raises `ClaudeCliAuthError` (a
`RuntimeError` subclass) immediately with the fix (`run 'claude login'`) rather than treating it
as a verdict or a transient failure; `RetryingClient` special-cases `ClaudeCliAuthError` to never
retry it — retrying would just re-run the CLI's own three-minute failure for the same guaranteed
outcome. `scripts/benchmark.py` runs one cheap preflight call before wiring up the real `claude-cli`
row specifically to catch this case up front and skip cleanly with
`skipped: claude CLI is not authenticated: run 'claude login'`, instead of failing 100 times (once
per holdout intent) over the full 23.7k-token prompt.

Reproduce (real calls; requires `codex` on `PATH`, `ollama serve` running with `mistral:latest`
pulled, and `claude` on `PATH` and logged in via `claude login`):

```bash
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,codex,ollama,claude-cli \
    --codex-cache results/codex-cache.jsonl --ollama-cache results/ollama-cache.jsonl \
    --claude-cli-cache results/claude-cli-cache.jsonl \
    --out results/
```

Replay from the cache recorded by the run above, fully offline:

```bash
venv/bin/python scripts/benchmark.py --split holdout \
    --verifiers aegis,codex-replay,ollama-replay,claude-cli-replay \
    --codex-cache results/codex-cache.jsonl --ollama-cache results/ollama-cache.jsonl \
    --claude-cli-cache results/claude-cli-cache.jsonl \
    --out results/
```

All three rows are skipped cleanly (`skipped: codex not on PATH` / `skipped: ollama server not
reachable` / `skipped: claude not on PATH` or `skipped: claude CLI is not authenticated: run
'claude login'`), exactly like the `opa` row, when the binary/server isn't available or not
authenticated; the `-replay` variants are skipped with a note when their cache file doesn't exist
yet.

The `opa` binary is installed separately — it isn't a Python dependency.

## Corpus

`../scripts/build_corpus.py` expands hand-derived seeds (drawn from the Kubernetes
failure-stories index and the OPA Gatekeeper policy library, not invented from scratch) into
500 labeled constraints with real, computed provenance hashes: **Trusted** (~50%, valid
provenance and authorized principal), **Untrusted** (~25%, valid provenance but unauthorized
principal), and **Malicious** (~25%, split between tampered and forged). Re-running with the
same `--seed` reproduces every file byte-for-byte.

It also emits 600 intents (300 aimed at Trusted rules, 150 aimed at poisoned rules that no
Trusted rule shadows, 150 that match nothing), labelled by `../scripts/reference_oracle.py` — never
by the interceptor — and `../data/corpus/stats.json`, which records the diversity numbers the
benchmark header reports alongside `n = 500`: `n_distinct_structural = 323`, `n_distinct_patterns = 145`, `n_distinct_rule_text = 118`. `split.json` carries two 20% holdouts: a constraint split (per label, for store-level
experiments) and the intent split (stratified by expected verdict × poison candidate) that
`scripts/benchmark.py` scores by default. To relabel intents after editing labels or
constraints by hand: `venv/bin/python scripts/reference_oracle.py --corpus data/corpus`.

## Adversarial suite

![Threat model](threat-model.svg)

`../src/aegis_core/adversarial.py` generates 28 attacks across five categories — **tampered**
(field mutated post-ingest), **unauthorized** (self-consistent but the wrong principal),
**forged** (hash valid, cited source doesn't back it), **evasion** (attempts to slip past
the matcher itself), and **argv-evasion** (command-line shapes that used to parse into an
intent nothing matched: global flags before the verb, `-nprod`, label selectors, comma kinds,
namespace deletion). `tests/test_adversarial.py` proves every tampered and unauthorized attack
is discarded and gets no vote by default (and, under `--on-untrusted-match escalate`,
contributes ESCALATE but never BLOCK), that each argv-evasion shape now hits the rule its
author would expect, and that the matcher behaves correctly under the evasion attempts.
`evade-case-variant` used to be an `xfail`; it is now a passing test, because the parser
lower-cases resource kinds and an upper-case `resource_pattern` warns at load — the
matcher itself is still case-sensitive on names.

```bash
venv/bin/python -m pytest tests/test_adversarial.py -v
```

Forged constraints are caught only by `verify_source()`, which isn't wired into `intercept()`
at decision time — see "Source verification" in [`configuration.md`](configuration.md) and
"Open gaps" in `../PLAN.md`.
