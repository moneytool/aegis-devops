# Aegis Benchmark Report

split: holdout · oracle: reference (scripts/reference_oracle.py) · n=120 · n_distinct=323

Constraints loaded (all verifiers, every label): 500 — 323 distinct `(provider, resource_pattern, actions, scope)` structures. Intents: 120 (`holdout` split), of which 30 are poison candidates ({'unauthorized': 10, 'tampered': 12, 'forged': 8}).

`aegis` loads the store with the corpus's `sources/` (forged constraints are quarantined at load); `aegis-nosources` (opt-in) shows the same engine without source verification. Ground truth is derived by the reference oracle from `labels.jsonl` and a naive structural matcher — only Trusted rules drive `expected_verdict` — and never from the interceptor. `covered` is the oracle's structural match (any label), computed once for every verifier. `ps_*` = fraction of poison candidates of that kind the verifier **BLOCK**ed (obeyed the poison); `pe_*` = fraction it **ESCALATE**d (failed closed on it); `poison-susceptibility` = either, overall. `strict precision` counts a positive only on an exact verdict match.

| verifier | n | n_distinct | precision | strict precision | recall | F1 | over-block | poison-susceptibility | ps_unauth | ps_tampered | ps_forged | pe_unauth | pe_tampered | pe_forged | coverage | p50 (ms) | p99 (ms) | notes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| aegis | 120 | 323 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.750 | 0.0467 | 0.2057 |  |
| llm-heuristic | 120 | 323 | 0.667 | 0.511 | 1.000 | 0.800 | 0.500 | 1.000 | 0.400 | 0.833 | 0.750 | 0.600 | 0.167 | 0.250 | 0.750 | 0.0280 | 0.1036 |  |
| opa | 120 | 323 | 0.667 | 0.589 | 1.000 | 0.800 | 0.500 | 1.000 | 0.100 | 0.750 | 0.375 | 0.900 | 0.250 | 0.625 | 0.750 | 26.6342 | 31.1634 |  |
| opa-signed | 120 | 323 | 0.800 | 0.773 | 1.000 | 0.889 | 0.250 | 0.500 | 0.100 | 0.000 | 0.375 | 0.900 | 0.083 | 0.125 | 0.750 | 22.6677 | 23.7487 |  |
| ollama-replay | 120 | 323 | 0.500 | 0.175 | 1.000 | 0.667 | 1.000 | 1.000 | 0.000 | 0.083 | 0.375 | 1.000 | 0.917 | 0.625 | 0.750 | 0.0255 | 0.0390 | replayed from ollama-cache.jsonl, local, mistral:latest, num_ctx=32768, temp=0 seed=0, 100-constraint holdout subset |
| claude-cli-replay | 120 | 323 | 0.836 | 0.673 | 0.767 | 0.800 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0253 | 0.0379 | replayed from claude-cli-cache.jsonl, agent harness (claude -p), model=haiku, 100-constraint holdout subset |
| claude-cli-sonnet-replay | 120 | 323 | 0.821 | 0.661 | 0.767 | 0.793 | 0.167 | 0.333 | 0.000 | 0.250 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0257 | 0.0511 | replayed from claude-cli-sonnet-cache.jsonl, agent harness (claude -p), model=sonnet, 100-constraint holdout subset |
| claude-cli-opus-replay | 120 | 323 | 0.836 | 0.673 | 0.767 | 0.800 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0254 | 0.0437 | replayed from claude-cli-opus-cache.jsonl, agent harness (claude -p), model=opus, 100-constraint holdout subset |
| claude-cli-fable-replay | 120 | 323 | 0.836 | 0.673 | 0.767 | 0.800 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0258 | 0.0446 | replayed from claude-cli-fable-cache.jsonl, agent harness (claude -p), model=fable, 100-constraint holdout subset |
| codex-replay | 120 | 323 | 0.833 | 0.667 | 0.750 | 0.789 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0240 | 0.0343 | replayed from codex-cache.jsonl, agent harness (codex exec), model=gpt-6-astra (account default), 100-constraint holdout subset |
| codex-gpt-6-sol-replay | 120 | 323 | 0.833 | 0.667 | 0.750 | 0.789 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 | 0.750 | 0.0251 | 0.0371 | replayed from codex-gpt-6-sol-cache.jsonl, agent harness (codex exec), model=gpt-6-sol, 100-constraint holdout subset |
| codex-gpt-6-luna-replay | 120 | 323 | 0.860 | 0.540 | 0.717 | 0.782 | 0.117 | 0.233 | 0.000 | 0.083 | 0.375 | 0.100 | 0.000 | 0.250 | 0.750 | 0.0251 | 0.0365 | replayed from codex-gpt-6-luna-cache.jsonl, agent harness (codex exec), model=gpt-6-luna, 100-constraint holdout subset |
