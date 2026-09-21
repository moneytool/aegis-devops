# Aegis-DevOps — Policy Verifier for AI DevOps Agents

**Provenance-backed, authority-aware guardrails that stop context poisoning and agentic drift
before an AI agent's `kubectl` or `terraform` action reaches your infrastructure.**

A lightweight, high-performance middleware layer that intercepts proposed agent actions and
validates them against an **Authority-Anchored Constraint Store**. Unlike existing tools
(HolmesGPT, RunLore) that focus on *retrieval*, Aegis focuses on *verification*: every
constraint in the store must pass an integrity check (has it been tampered with since
ingestion?) and an authority check (was its source ever allowed to assert this kind of
policy?) before it can drive a decision.

**Keywords:** AI agent security · AgentOps · prompt injection · context poisoning · policy
enforcement · policy-as-code · Kubernetes · Terraform · OPA · SRE · LLM guardrails ·
provenance · infrastructure-as-code

## Install

```bash
python -m venv venv
venv/bin/python -m pip install -e ".[dev]"
```

## Run tests

```bash
venv/bin/python -m pytest -q
```

## The five-rule example

`data/constraints.example.yaml` ships five constraints spanning both providers, all three
constraint classes, a scoped rule, and a time-windowed rule:

| id | provider | resource_pattern | actions | effect | constraint_class |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `no-scale-prod-peak` | kubernetes | `deployment/*` | scale | BLOCK | scaling |
| `no-delete-nodes` | kubernetes | `node/*` | delete | BLOCK | deletion |
| `escalate-terraform-prod-destroy` | terraform | `aws_instance.*` | delete, replace | ESCALATE | deletion |
| `escalate-configmap-changes` | kubernetes | `configmap/*` | update, delete | ESCALATE | configuration |
| `no-direct-asg-changes` | terraform | `aws_autoscaling_group.*` | update | BLOCK | scaling |

`data/authority.example.yaml` maps principals to the constraint classes they may assert
(`admin`: all three; `sre_lead`: scaling, configuration; `developer`: configuration).

Run `examples/demo.py` to see the store, the authority map, and the interceptor working
together against three intents — one allowed, one blocked, one escalated:

```bash
venv/bin/python examples/demo.py
```

## CLI

The `aegis` console script wraps the interceptor so it can sit in front of an agent's
shell and gate `kubectl`/`terraform` actions before they run. `--now` (ISO8601) makes
time-windowed constraints evaluate deterministically; it goes *before* the `--` that
separates Aegis's own flags from the wrapped `kubectl` argv.

```bash
aegis check kubectl --now 2026-03-16T10:00:00-05:00 -- \
    kubectl scale deployment/api-server --replicas=5 -n prod

aegis check terraform data/example-plan.json
```

Each matching intent prints one JSON `Decision` line (pass `--pretty` for a human-readable
summary instead). The process exit code is the worst verdict across all evaluated intents:

| exit code | verdict |
| :--- | :--- |
| `0` | ALLOW |
| `2` | ESCALATE |
| `3` | BLOCK |

## Benchmark

`scripts/benchmark.py` is the Week 7-8 deliverable from PLAN.md §4: it runs Aegis and two
baselines over the labeled 500-constraint corpus in `data/corpus/` and reports a confusion
matrix, over-block rate, coverage, poison-susceptibility, and latency for each.

```bash
venv/bin/python scripts/benchmark.py \
    --corpus data/corpus --split all \
    --verifiers aegis,llm-heuristic,opa \
    --out results/
```

This runs fully offline: `llm-heuristic` is a deterministic, no-network stand-in for a naive
LLM self-check (see below), and the `opa` row is skipped with a note if the `opa` binary isn't
on `PATH`. Results land in `results/benchmark.json` and `results/benchmark.md`.

### The three verifiers

- **`aegis`** — the system under test. Loads `data/corpus/constraints.yaml` through
  `ConstraintStore.load`, which quarantines tampered constraints at load time, and discards
  unauthorized ones at decision time. This is the only verifier with a provenance/authority
  concept.
- **`opa` (Baseline C)** — `src/aegis_core/baselines/opa.py` generates a Rego v1 policy
  (`render_rego`) with one `BLOCK`/`ESCALATE` rule per constraint and shells out to a real
  `opa eval`. It loads **every** constraint in the corpus with no quarantine — tampered,
  unauthorized, and forged included — because OPA/Gatekeeper has no provenance or authority
  concept at all. Known limitation: constraint `time_window`s are not evaluated (emitted as a
  comment); the rule is treated as always-active.
- **`llm` / `llm-heuristic` (Baseline B)** — `src/aegis_core/baselines/llm.py` implements the
  LLM self-check from PLAN §4: the full constraint list (same constraint parity as Aegis, minus
  quarantine) rendered as YAML in the system prompt, the intent as JSON in the user turn, asking
  for one of `ALLOW`/`BLOCK`/`ESCALATE`. `llm-heuristic` (`HeuristicLLMClient`) is a
  deterministic, offline stand-in that mimics a naive LLM self-check: it blocks/escalates as
  soon as *any* constraint matches by provider + resource pattern + action, with no
  provenance/authority reasoning at all — this is what the default offline run uses, and it's a
  **lower bound** on what a real LLM self-check would catch, not a measured LLM accuracy figure.

### Running the real LLM baseline

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...
venv/bin/python scripts/benchmark.py --verifiers llm --llm-cache results/llm-cache.jsonl --out results/
```

Every `(system, user)` prompt pair is content-hashed and appended to `--llm-cache` as it's
called (`RecordingClient`), so a later run can replay the exact same responses offline and
reproducibly via `ReplayClient` (pass `--verifiers llm-replay`). Without an API key or the
`anthropic` package, the `llm` row falls back to `NullClient` (always `ESCALATE`) and is marked
`stub: true` in the report rather than silently omitted.

### Reading the report

| column | meaning |
| :--- | :--- |
| `precision` / `recall` / `F1` | Binary view: positive = expected verdict is `BLOCK` or `ESCALATE`. |
| `over-block` | False positives (expected `ALLOW`, predicted non-`ALLOW`) as a fraction of all expected-`ALLOW` intents — PLAN §4's over-block rate. |
| `poison-susceptibility` | Of the intents whose *only* matching constraints are Untrusted/Malicious (so the correct verdict is `ALLOW`), the fraction a verifier still blocks/escalates on. This is the headline number: it should be ~0 for Aegis and high for both baselines, since neither has a provenance/authority filter. |
| `coverage` | Fraction of intents the verifier considers "covered" — for Aegis, whether any constraint matched at all; for the baselines, `verdict != ALLOW` (no separate coverage concept). |
| `p50` / `p99` | Decision latency in milliseconds. |

**Caveat on Aegis's own numbers:** `expected_verdict` in `data/corpus/intents.jsonl` was
produced by running the real `AegisInterceptor` over the corpus (see `scripts/build_corpus.py`).
So the `aegis` row scoring `F1 = 1.0` and `poison-susceptibility = 0.0` is a self-consistency
sanity check on the harness, not an independent measurement — the baselines' numbers, run
against the same ground truth, are the actual comparison.

## Why not OPA/Gatekeeper?

OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis
derives **unstructured human constraints** (from Slack, Jira, Git) and applies
**authority-driven validation** to the agent's intent *before* it reaches the infrastructure.

## Adversarial suite

`src/aegis_core/adversarial.py` is a library of attack generators that poison constraints,
paired with `tests/test_adversarial.py`, which proves the interceptor rejects every one. Attacks
fall into four categories: **tampered** (post-ingest field mutation that breaks the provenance
hash), **unauthorized** (a valid hash asserted by a principal without authority for that
constraint class), **forged** (a self-consistent constraint whose cited source doesn't actually
back it), and **evasion** (attempts to slip past the matcher via case, provider, or scope —
mostly proofs of correct behaviour, with one documented gap). Run it with:

```bash
venv/bin/python -m pytest tests/test_adversarial.py -v
```

Note: forged constraints are only caught by `verify_source()` today — it isn't wired into
`intercept()` yet, so the interceptor currently honours them (see the `xfail`-marked
`test_forged_constraints_are_not_caught_at_decision_time_yet`, tracked for Week 7).

## License

Apache-2.0 — see [LICENSE](LICENSE).
