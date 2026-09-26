# Aegis Benchmark Report

split: holdout · oracle: reference (scripts/reference_oracle.py) · n=120 · n_distinct=323

Constraints loaded (all verifiers, every label): 500 — 323 distinct `(provider, resource_pattern, actions, scope)` structures. Intents: 120 (`holdout` split), of which 30 are poison candidates ({'unauthorized': 10, 'tampered': 12, 'forged': 8}).

`aegis` loads the store with the corpus's `sources/` (forged constraints are quarantined at load); `aegis-nosources` (opt-in) shows the same engine without source verification. Ground truth is derived by the reference oracle from `labels.jsonl` and a naive structural matcher — only Trusted rules drive `expected_verdict` — and never from the interceptor. `covered` is the oracle's structural match (any label), computed once for every verifier. `ps_*` = fraction of poison candidates of that kind the verifier **BLOCK**ed (obeyed the poison); `pe_*` = fraction it **ESCALATE**d (failed closed on it); `poison-susceptibility` = either, overall. `strict precision` counts a positive only on an exact verdict match.

| verifier | n | n_distinct | precision | strict precision | recall | F1 | over-block | poison-susceptibility | ps_unauth | ps_tampered | ps_forged | pe_unauth | pe_tampered | pe_forged | coverage | p50 (ms) | p99 (ms) | notes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| aegis | 120 | 323 | 0.667 | 0.667 | 1.000 | 0.800 | 0.500 | 1.000 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 | 0.750 | 0.0821 | 0.3115 |  |
| llm-heuristic | 120 | 323 | 0.667 | 0.511 | 1.000 | 0.800 | 0.500 | 1.000 | 0.400 | 0.833 | 0.750 | 0.600 | 0.167 | 0.250 | 0.750 | 0.0317 | 0.1163 |  |
| opa | 120 | 323 | 0.667 | 0.589 | 1.000 | 0.800 | 0.500 | 1.000 | 0.100 | 0.750 | 0.375 | 0.900 | 0.250 | 0.625 | 0.750 | 28.1414 | 34.7577 |  |
| opa-signed | 120 | 323 | 0.800 | 0.773 | 1.000 | 0.889 | 0.250 | 0.500 | 0.100 | 0.000 | 0.375 | 0.900 | 0.083 | 0.125 | 0.750 | 23.7258 | 65.8094 |  |
