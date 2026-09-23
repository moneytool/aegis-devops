# Latency Sweep (REVIEW-4 T2.3)

`n=2000` decisions per size (first 50 warm-up calls excluded); p50/p95/p99 with a 1000-resample bootstrap 95% CI. Store built from the same seeds.yaml / variation axes as the evaluation corpus (scripts/build_corpus.py), all constraints Trusted, no signing required.

| size | p50 (ms) | p50 95% CI | p95 (ms) | p95 95% CI | p99 (ms) | p99 95% CI | store load (ms, no sources) | store load (ms, with sources) |
| ---: | ---: | :--- | ---: | :--- | ---: | :--- | ---: | ---: |
| 100 | 0.0168 | [0.0162, 0.0177] | 0.0461 | [0.0455, 0.0488] | 0.0587 | [0.0578, 0.0591] | 5.63 | 7.31 |
| 500 | 0.0505 | [0.0442, 0.0545] | 0.2823 | [0.2766, 0.2865] | 0.3079 | [0.2991, 0.3174] | 24.35 | 37.22 |
| 2500 | 0.2441 | [0.2270, 0.2609] | 1.2052 | [1.1961, 1.2173] | 1.3928 | [1.3478, 1.4165] | 124.25 | 197.22 |
| 10000 | 0.9261 | [0.8576, 1.0060] | 5.3175 | [5.1971, 5.3923] | 5.9276 | [5.8257, 5.9966] | 650.35 | 894.60 |
