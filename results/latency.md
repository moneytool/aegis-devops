# Latency Sweep (REVIEW-4 T2.3)

`n=2000` decisions per size (first 50 warm-up calls excluded); p50/p95/p99 with a 1000-resample bootstrap 95% CI. Store built from the same seeds.yaml / variation axes as the evaluation corpus (scripts/build_corpus.py), all constraints Trusted, no signing required.

| size | p50 (ms) | p50 95% CI | p95 (ms) | p95 95% CI | p99 (ms) | p99 95% CI | store load (ms, no sources) | store load (ms, with sources) |
| ---: | ---: | :--- | ---: | :--- | ---: | :--- | ---: | ---: |
| 100 | 0.0069 | [0.0019, 0.0079] | 0.0318 | [0.0305, 0.0343] | 0.0413 | [0.0401, 0.0440] | 5.51 | 10.33 |
| 500 | 0.0085 | [0.0020, 0.0160] | 0.1850 | [0.1809, 0.1890] | 0.2182 | [0.2142, 0.2243] | 22.11 | 50.64 |
| 2500 | 0.0036 | [0.0021, 0.0625] | 0.7022 | [0.6850, 0.7174] | 0.9033 | [0.8755, 0.9212] | 116.46 | 280.15 |
| 10000 | 0.1831 | [0.0027, 0.2472] | 3.0587 | [2.9774, 3.1090] | 3.7336 | [3.6465, 3.8725] | 608.58 | 1186.97 |
