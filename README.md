# Aegis-DevOps — Policy Verifier for AI DevOps Agents

**Provenance-backed, authority-aware guardrails that stop context poisoning and agentic drift
before an AI agent's `kubectl` or `terraform` action reaches your infrastructure.**

**Keywords:** AI agent security · AgentOps · prompt injection · context poisoning · policy
enforcement · policy-as-code · Kubernetes · Terraform · OPA · SRE · LLM guardrails ·
provenance · infrastructure-as-code

![Aegis demo](docs/demo.gif)

## What it does

Aegis intercepts a proposed agent action — a `kubectl`/`terraform`/`aws`/... invocation or a
plan file — and checks it against a **Constraint Store** before it runs, returning `ALLOW`,
`BLOCK`, or `ESCALATE` with citations. Unlike a naive policy engine, every constraint in the
store must independently pass an **integrity check** (has it been tampered with since
ingestion?) and an **authority check** (was its source ever allowed to assert this kind of
policy?), so a poisoned Jira ticket or a forged Slack message can't quietly become law. It
covers 20 CLI/plan targets today — Kubernetes, Terraform/OpenTofu, the three major clouds,
Helm/ArgoCD/Flux, Git/GitHub, SQL/migrations, and Pulumi — through one shared intent schema.

![Aegis architecture](docs/architecture.svg)

## Quick start

```bash
python -m venv venv
venv/bin/python -m pip install -e ".[dev]"
venv/bin/python examples/demo.py
```

`examples/demo.py` runs 15 intents across every supported tool through the interceptor and
prints each decision, starting with the store's health. To check one command yourself:

```bash
aegis check kubectl --now 2026-03-16T10:00:00-05:00 --pretty -- \
    kubectl scale deployment/api-server --replicas=5 -n prod
```

```
BLOCK: kubernetes scale deployment/api-server
  citations: no-scale-prod-peak
  covered: True  latency_ms: 0.14
PLAN BLOCK: 1 intent(s)
STORE: loaded=20 quarantined=0 principals=3
```

Global options in front of the verb (`kubectl -n prod delete …`, `git -C /repo push …`,
`helm --kube-context prod uninstall …`), glued short flags (`-nprod`), label selectors
(`-l role=worker`) and comma-separated kinds (`nodes,pods`) all parse to the same intents as
their canonical forms; a leading option Aegis does not recognise is an error (exit 65), never a
guess at where the verb starts. `kubectl delete namespace prod` additionally emits a synthetic
`*/*` delete intent scoped to that namespace, so namespace-scoped deletion rules fire on it.

### Exit codes

The exit code is the worst verdict across all evaluated intents, or a tool error. Verdict codes
depend on `--exit-style`; tool errors are identical in every style and never print a verdict.

| exit code | `--exit-style aegis` (default) | `--exit-style claude-hook` | `--exit-style ci` |
| :--- | :--- | :--- | :--- |
| `0` | ALLOW | ALLOW (prints nothing) | ALLOW |
| `1` | — | — | ESCALATE or BLOCK |
| `2` | ESCALATE | ESCALATE or BLOCK, printing `{"decision": "block", "reason": "<verdict>: <citations>"}` | — |
| `3` | BLOCK | — | — |
| `64` | usage error (unknown flag, no argv after `--`, compound shell command) | same | same |
| `65` | bad data: unparseable argv, `--now`, YAML or JSON; degraded store (see below) | same | same |
| `66` | a constraints/authority/environments/plan file does not exist or is unreadable | same | same |
| `70` | internal error; the exception class name is on stderr | same | same |

Every error is one `aegis: error: …` line on stderr, never a traceback. `claude-hook` exists
because Claude Code `PreToolUse` hooks treat exit 2 as *block* and any other non-zero code as a
non-blocking error, which would invert the default `3 = BLOCK` contract.

### Store health

Every output carries the state of the constraint store, so a degraded store can never be
mistaken for a clean allow. Each per-intent JSON line and the plan summary include a
`store_health` object — `loaded`, `quarantined: [{id, reason}]`, `principals`,
`constraints_sha256` (of the raw file bytes), `warnings` — and `--pretty` ends with a
`STORE: loaded=N quarantined=M principals=P` line plus one line per quarantined rule. Load-time
warnings also go to stderr as `aegis: WARNING …` lines.

Integrity failures **fail closed**. A constraint that was quarantined at load (`tampered`,
`forged`) or discarded at decision time (`tampered`, `unauthorized`) is still matched, and if it
was a BLOCK or ESCALATE rule its match contributes **ESCALATE** — never BLOCK (nobody can vouch
for the rule) and never ALLOW (the action it covers is contested). The decision reports it in
`discarded` and with a `fail-closed: <id> (<reason>)` note:

```bash
aegis check kubectl --constraints /tmp/oneflip.yaml --pretty -- kubectl delete node/x
```

```
aegis: WARNING Quarantined constraint no-delete-nodes: provenance hash mismatch
ESCALATE: kubernetes delete node/x
  discarded: [{'id': 'no-delete-nodes', 'reason': 'tampered'}]
  note: fail-closed: no-delete-nodes (tampered)
  covered: True  latency_ms: 0.10
STORE: loaded=19 quarantined=1 principals=3
  quarantined: no-delete-nodes (tampered)
```

Aegis refuses to decide at all (exit 65, one-line message, no verdict) when the store loaded
zero constraints, the authority map grants nothing to anyone, or more than
`--max-quarantine-ratio` (default `0.10`) of the constraints were quarantined. `--fail-closed`
additionally turns an *uncovered* intent (no rule matched) into ESCALATE with the note
`fail-closed: uncovered`.

### Claude Code hook

`examples/claude-code-hook.sh` is a `PreToolUse` hook: it reads the hook JSON from stdin, splits
`tool_input.command` with `shlex`, and runs `aegis check argv --exit-style claude-hook`. ALLOW
lets the tool call proceed; ESCALATE and BLOCK exit 2 with the reason on stderr (which Claude
Code shows to the model). Binaries Aegis cannot parse are not gated; compound commands (`;`,
`&&`, `|`, `$(…)`) are a usage error until `--split-compound` lands (REVIEW-4 T1.2), and the hook
converts any tool error into a block so it never fails open.

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
  {"type": "command", "command": "/path/to/aegis-devops/examples/claude-code-hook.sh"}]}]}}
```

## How a decision is made

![Decision pipeline](docs/decision-pipeline.svg)

At **load time**, `ConstraintStore.load` parses the constraint YAML, verifies each
`provenance_hash`, and (with `--sources`) re-fetches and checks the original source —
anything that fails either check is quarantined, not silently dropped.

At **decision time**, `AegisInterceptor.intercept` matches each intent against the surviving
constraints on `(provider, resource_pattern, action, scope, time_window)`, re-checks integrity
and authority (authority can be revoked after ingestion), applies any rate limit against the
decision ledger, downgrades a dry run to `ALLOW`, and takes the highest-precedence effect
(`BLOCK` > `ESCALATE` > `ALLOW`) among what's left. A `PlanConstraint` then runs once more over
the whole batch of intents from one plan/chart/invocation.

## Supported tools

Every target below is checked with `aegis check <target> [flags] -- <argv...>`, except
`terraform`/`tofu`/`pulumi-preview`, which take a JSON document path instead of `--`.

| target | example |
| :--- | :--- |
| `kubectl` | `aegis check kubectl -- kubectl scale deployment/api-server --replicas=5 -n prod` |
| `terraform` | `aegis check terraform plan.json` (from `terraform show -json tfplan > plan.json`) |
| `tofu` | `aegis check tofu plan.json` (identical plan schema; `provider` stays `terraform`) |
| `pulumi-preview` | `aegis check pulumi-preview preview.json` (from `pulumi preview --json`) |
| `pulumi` | `aegis check pulumi -- pulumi destroy --stack prod` |
| `aws` | `aegis check aws -- aws ec2 terminate-instances --instance-ids i-0abc --region us-east-1` |
| `az` | `aegis check az -- az aks scale --resource-group rg1 --name aks1 --node-count 5` |
| `gcloud` | `aegis check gcloud -- gcloud sql instances delete prod-db` |
| `helm` | `aegis check helm -- helm uninstall api -n prod` |
| `argocd` | `aegis check argocd -- argocd app sync prod-web --prune` |
| `flux` | `aegis check flux -- flux reconcile kustomization podinfo -n flux-system` |
| `git` | `aegis check git -- git push --force origin main` |
| `gh` | `aegis check gh -- gh workflow run deploy-prod.yml -r main` |
| `psql` | `aegis check psql -- psql -c "DROP TABLE users;"` |
| `mysql` | `aegis check mysql -- mysql -e "DROP TABLE users;"` |
| `sqlite3` | `aegis check sqlite3 -- sqlite3 app.db "DELETE FROM users;"` |
| `mongosh` | `aegis check mongosh -- mongosh --eval "db.users.drop()"` |
| `migrate` | `aegis check migrate -- alembic downgrade base` |
| `sql` | `aegis check sql -- "DROP TABLE users;"` |
| `argv` | `aegis check argv -- gcloud sql instances delete prod-db` (dispatches by binary name) |

## Writing constraints

A per-intent constraint (`data/constraints.example.yaml`) has every field below. `id` is a
free-form string; every other field feeds either matching, provenance, or authority:

```yaml
- id: no-scale-prod-peak
  provider: kubernetes            # matches Intent.provider
  resource_pattern: deployment/*  # fnmatch glob against Intent.resource
  actions: [scale]                # any of these matches Intent.action
  scope: {namespace: prod}        # every key must match intent.metadata (or metadata.env)
  time_window:                    # optional; omit or null to apply at all times
    days: [Mon, Tue, Wed, Thu, Fri]
    start: "09:00"
    end: "17:00"
    tz: America/New_York
  rate_limit:                     # optional; only fires once the ledger shows quota used
    max: 3
    per: 1h                       # "<n>m" / "<n>h" / "<n>d"
    key: [namespace]              # bucket the quota per distinct value of these metadata keys
  effect: BLOCK                   # BLOCK | ESCALATE | ALLOW-adjacent (BLOCK/ESCALATE only fire)
  constraint_class: scaling       # must be in the asserting principal's authority set
  principal: sre_lead             # who asserted this constraint
  source_ref: jira-1001           # id used to re-fetch the source for --sources verification
  source_timestamp: "2026-01-15T09:00:00+00:00"
  rule_text: "Do not scale deployments in prod during business hours."
  provenance_hash: f3af697890dc757effcf13cdfcc9e4624e32aa65dd3114c348674ddcda0f2244
```

A plan-level constraint (`data/plan_constraints.example.yaml`) carries exactly one batch
predicate instead of a per-intent match, evaluated over every intent from one plan/invocation:

```yaml
plan_constraints:
- id: plan-max-25-resources
  max_intents: 25                 # escalate/block if the plan has more than N intents
- id: plan-no-db-deletes
  max_matching:                   # escalate/block if more than `max` intents match this filter
    actions: [delete, replace]
    resource_pattern: aws_db_instance.*
    max: 0
- id: plan-no-delete-and-create-us-east-1
  forbid_together:                # escalate/block if the plan matches ALL of these filters
  - {actions: [delete], scope: {region: us-east-1}}
  - {actions: [create]}
# requires_all: same shape as forbid_together, but the effect fires when NOT all are present
- id: plan-k8s-delete-ratio
  ratio:                          # escalate/block if numerator/denominator exceeds `max`
    numerator: {actions: [delete]}
    denominator: {}               # {} matches every intent in the plan
    max: 0.5
```

## Authority policy

`data/authority.example.yaml` maps each principal to the constraint classes it may assert:

```yaml
principals:
  admin: [scaling, deletion, configuration]
  sre_lead: [scaling, configuration]
  developer: [configuration]
```

A constraint whose `principal` isn't authorized for its own `constraint_class` is discarded at
decision time with reason `unauthorized` — even if it was authorized when it was first added
(`ConstraintStore.add_constraint` checks this too, but authority can be revoked later).

## Environment mapping

Constraints can scope on `env: prod|staging|dev` instead of repeating every raw
context/account/project/subscription. `data/environments.example.yaml` maps provider-specific
identifiers to a normalised environment, and `EnvironmentMap.annotate` sets
`intent.metadata["env"]` at parse time (the CLI does this automatically via `--environments`,
defaulting to `data/environments.example.yaml` when present). An identifier that isn't in the
map resolves to no environment at all — never a default like `dev` — and, deliberately,
kubectl namespaces are never used to infer `env`, since a namespace is a string the agent (or
an attacker poisoning its context) controls.

## Dry runs

A rehearsal (`kubectl --dry-run=client|server`, `aws --dry-run`, `az --what-if|--dry-run`,
`gcloud --dry-run`) can't change infrastructure, so Aegis never blocks or escalates it — the
verdict is always `ALLOW`, with `dry_run: true` and `would_be` reporting what a real run would
have gotten:

```
ALLOW: kubernetes scale deployment/api-server (dry-run; would be BLOCK)
  citations: no-scale-prod-peak
  covered: True  latency_ms: 0.12
PLAN ALLOW: 1 intent(s)
  note: would_be: BLOCK
```

`terraform`/`tofu` plans are evaluated normally — the plan JSON *is* the proposed change, not a
rehearsal of one.

## Source verification

`--sources data/sources` points at a directory of `<source_ref>.json` files. When given, a
constraint whose cited source doesn't actually back it (missing file, or different content) is
quarantined as `forged` at load time:

```bash
aegis check kubectl --sources data/sources --pretty -- kubectl get service/frontend -n prod
```

`FileSourceFetcher` (the default behind `--sources`) is a v1 stand-in for real Git/Slack/Jira
connectors — it re-reads a flat JSON file rather than calling out to a commit, a permalink, or
a ticket API. Without `--sources`, forgery goes undetected (see "Open gaps" in `PLAN.md`).

## Rate limits & ledger

`--ledger path.jsonl` enables `rate_limit` constraints and appends one JSON line per executed
(`ALLOW`, non-dry-run) decision, bucketed by the constraint's `key` metadata fields within its
`per` window:

```bash
aegis check kubectl --ledger results/ledger.jsonl --pretty -- \
    kubectl get service/frontend -n prod
```

## Library usage

```python
from aegis_core.authority import load_authority_map
from aegis_core.store import ConstraintStore
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_kubectl

authority_map = load_authority_map("data/authority.example.yaml")
store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
interceptor = AegisInterceptor(store)

intent = from_kubectl(["kubectl", "delete", "node/worker-1"])
decision = interceptor.intercept(intent)
print(decision.verdict, decision.citations, decision.covered)
# BLOCK ['no-delete-nodes'] True
```

`Decision` also carries `discarded` (constraints that matched but were thrown out, with why),
`notes` (`fail-closed: …`, `rate-limit: …`), `latency_ms`, `dry_run`, and `would_be`.
`store.health` is the `StoreHealth` the CLI prints; `AegisInterceptor(store, fail_closed=True)`
is the library form of `--fail-closed`.

## Adversarial suite

![Threat model](docs/threat-model.svg)

`src/aegis_core/adversarial.py` generates 28 attacks across five categories — **tampered**
(field mutated post-ingest), **unauthorized** (self-consistent but the wrong principal),
**forged** (hash valid, cited source doesn't back it), **evasion** (attempts to slip past
the matcher itself), and **argv-evasion** (command-line shapes that used to parse into an
intent nothing matched: global flags before the verb, `-nprod`, label selectors, comma kinds,
namespace deletion). `tests/test_adversarial.py` proves every tampered and unauthorized attack
is discarded *and fails closed to ESCALATE* (never ALLOW, never BLOCK), that each argv-evasion
shape now hits the rule its author would expect, and that the matcher behaves correctly under
the evasion attempts, with one documented gap (`evade-case-variant`, `xfail`: `fnmatch` is
case-sensitive on POSIX).

```bash
venv/bin/python -m pytest tests/test_adversarial.py -v
```

Forged constraints are caught only by `verify_source()`, which isn't wired into `intercept()`
at decision time — see `--sources` above and "Open gaps" in `PLAN.md`.

## Benchmark

![Benchmark results](docs/benchmark.svg)

`scripts/benchmark.py` runs Aegis and three baselines over the labeled 500-constraint corpus in
`data/corpus/` (built by `scripts/build_corpus.py`) and reports precision/recall/F1, over-block
rate, coverage, per-kind poison-susceptibility, and latency for each:

```bash
venv/bin/python scripts/benchmark.py \
    --corpus data/corpus --split holdout \
    --verifiers aegis,llm-heuristic,opa,opa-signed \
    --out results/
```

**Ground truth is independent of Aegis.** Every intent's `expected_verdict` / `expected_covered`
comes from `scripts/reference_oracle.py` — a deliberately naive matcher (`provider ==`,
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
`data/corpus/stats.json`) — the honest measure of how many *different* rules the corpus
contains. `poison-susceptibility` is the headline number: of the intents whose only matching
constraints are Untrusted/Malicious (oracle verdict `ALLOW`), the fraction a verifier
blocks/escalates on anyway. It is split by the strongest poisoned rule that matched:
`ps_unauth` / `ps_tampered` / `ps_forged` count **BLOCK** verdicts (the verifier *obeyed* the
poison), `pe_*` count **ESCALATE** verdicts (it failed closed — wrong verdict, but a human sees
it). `unauthorized` is the realistic pre-ingest attacker; `tampered`/`forged` are post-ingest
attacks that bundle signing already covers, which is why the `opa-signed` → `aegis` delta on
`ps_unauth`/`pe_unauth` is the number that matters. `strict precision` counts a positive only on
an exact verdict match.

| verifier | n | n_distinct | precision | recall | F1 | over-block | PS | ps_unauth | ps_tampered | ps_forged | pe_unauth | pe_tampered | pe_forged | coverage |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| aegis | 120 | 196 | 0.711 | 1.000 | 0.831 | 0.464 | 1.000 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 | 0.750 |
| llm-heuristic | 120 | 196 | 0.711 | 1.000 | 0.831 | 0.464 | 1.000 | 0.500 | 0.846 | 0.857 | 0.500 | 0.154 | 0.143 | 0.750 |
| opa | 120 | 196 | 0.711 | 1.000 | 0.831 | 0.464 | 1.000 | 0.500 | 0.846 | 0.857 | 0.500 | 0.154 | 0.143 | 0.750 |
| opa-signed | 120 | 196 | 0.842 | 1.000 | 0.914 | 0.214 | 0.462 | 0.500 | 0.000 | 0.571 | 0.500 | 0.077 | 0.143 | 0.750 |

(`split: holdout`, `oracle: reference`; full table with latency in `results/benchmark.md`.)
Every row has recall 1.0 because the corpus's poisoned rules are *additional* rules — a verifier
that honours everything never misses a Trusted one; the cost shows up as over-block and `ps_*`.
Read the Aegis row carefully: its binary precision / over-block are the *same* as the naive
LLM's, because the interceptor fails closed (REVIEW-4 T0.3) — a quarantined or discarded
BLOCK/ESCALATE rule contributes **ESCALATE** rather than being dropped — so every poison
candidate is escalated to a human. The oracle's label semantics say those intents are `ALLOW`,
so against the oracle that is an over-block, and it is reported as one. What separates Aegis is
`ps_*` = 0 across every attack kind (it never *obeys* a poisoned rule; `pe_*` = 1.0 says it flags
all of them), versus `ps_unauth` = 0.5 for both `opa` and `opa-signed` — bundle signing removes
`tampered` but leaves the unauthorized author's rule in force. Whether "escalate everything
poisoned" is the right trade-off versus "drop it silently" is a product decision, and the two
columns let a reader make it.

To run the real LLM baseline instead of the heuristic stand-in:

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...
venv/bin/python scripts/benchmark.py --verifiers llm --llm-cache results/llm-cache.jsonl --out results/
```

Every prompt/response pair is cached so a later run can replay it offline (`--verifiers
llm-replay`); without an API key it falls back to always-`ESCALATE` and is marked `stub: true`.
The `opa` binary is installed separately — it isn't a Python dependency.

## Corpus

`scripts/build_corpus.py` expands hand-derived seeds (drawn from the Kubernetes
failure-stories index and the OPA Gatekeeper policy library, not invented from scratch) into
500 labeled constraints with real, computed provenance hashes: **Trusted** (~50%, valid
provenance and authorized principal), **Untrusted** (~25%, valid provenance but unauthorized
principal), and **Malicious** (~25%, split between tampered and forged). Re-running with the
same `--seed` reproduces every file byte-for-byte.

It also emits 600 intents (300 aimed at Trusted rules, 150 aimed at poisoned rules that no
Trusted rule shadows, 150 that match nothing), labelled by `scripts/reference_oracle.py` — never
by the interceptor — and `data/corpus/stats.json`, which records the diversity numbers the
benchmark header reports alongside `n = 500`: `n_distinct_structural = 196`, `n_distinct_patterns = 71`, `n_distinct_rule_text = 66`. `split.json` carries two 20% holdouts: a constraint split (per label, for store-level
experiments) and the intent split (stratified by expected verdict × poison candidate) that
`scripts/benchmark.py` scores by default. To relabel intents after editing labels or
constraints by hand: `venv/bin/python scripts/reference_oracle.py --corpus data/corpus`.

## Project status / roadmap

The engine (constraint store, interceptor, environment mapping, dry-run handling, rate limits,
plan-level constraints, and parsers for every tool in "Supported tools") is complete. See
`PLAN.md` for the full roadmap, backlog, and `§8` for an honest list of open gaps (forged
detection isn't wired into decision time by default, the OPA and real-LLM baselines haven't
been run yet, principal is still a bare string, and a few others).

## Why not OPA/Gatekeeper?

OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis
derives **unstructured human constraints** (from Slack, Jira, Git) and applies
**authority-driven validation** to the agent's intent *before* it reaches the infrastructure.

## Development

```bash
venv/bin/python -m pytest -q      # 613 passed, 1 xfailed
venv/bin/python -m ruff check src tests scripts examples
vhs docs/demo.tape                # regenerate docs/demo.gif
```

Adding a new parser or tool: see [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
