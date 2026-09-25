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

Requires Python 3.11+ (tested on 3.11, 3.13 and 3.14 on Linux and macOS).

```bash
pip install aegis-devops
aegis init ./.aegis
```

`aegis init` writes the example policy files (constraints, authority map, environment map,
plan constraints, signed sources) into a directory. Putting them in `./.aegis` means the CLI
finds them with no flags and no environment variable — see [Configuration](docs/configuration.md)
for the full search order. Then check a command:

```bash
aegis check kubectl --now 2026-03-16T10:00:00-05:00 --pretty -- \
    kubectl scale deployment/api-server --replicas=5 -n prod
```

```
BLOCK: kubernetes scale deployment/api-server
  citations: no-scale-prod-peak
  covered: True  latency_ms: 0.20
PLAN BLOCK: 1 intent(s)
STORE: loaded=21 quarantined=0 principals=3
  warning: using example signing key
```

The `warning` is real and deliberate: the shipped policy files are signed with a public demo
key that ships beside them, so the CLI verifies them out of the box while telling you it used
a key everyone has. `aegis init` prints the two commands that replace it with your own — see
[Signing](docs/configuration.md#signing). The example rules are a demo, not a starting policy;
replace `constraints.example.yaml` with your own `constraints.yaml` (a real file wins over the
`.example` one when both exist).

### From a clone

```bash
python -m venv venv
venv/bin/python -m pip install -e ".[dev]"
venv/bin/python examples/demo.py
```

`examples/demo.py` runs 15 intents across every supported tool through the interceptor and
prints each decision, starting with the store's health. A clone already has `data/`, so the CLI
finds its policy files without `aegis init`.

Exit codes, store health, the Claude Code hook, argv parsing, compound commands, dry runs and
library usage are all in [`docs/cli.md`](docs/cli.md).

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
| `command` | `aegis check command -- "kubectl get pods; sudo kubectl delete node/w1"` (a shell string; see [Compound commands](docs/cli.md#compound-commands)) |

## Results

![Benchmark results](docs/benchmark.svg)

`scripts/benchmark.py` runs Aegis and several baselines over the labeled 500-constraint corpus
in `data/corpus/` (323 distinct rule structures), on 120 held-out intents, scored against an
oracle that never imports Aegis's own code. The full table
(precision/recall/F1, latency, coverage) and methodology are in
[`docs/benchmark.md`](docs/benchmark.md); the columns that matter most are summarized below.

| verifier | over-block | poison-susceptibility | ps_unauth + pe_unauth |
| :--- | ---: | ---: | ---: |
| **aegis** | **0.000** | **0.000** | **0.000** |
| codex (gpt-6-astra) | 0.150 | 0.300 | 0.200 |
| claude-cli (haiku) | 0.150 | 0.300 | 0.200 |
| opa-signed | 0.250 | 0.500 | 1.000 |
| opa | 0.500 | 1.000 | 1.000 |
| llm-heuristic | 0.500 | 1.000 | 1.000 |
| ollama (mistral 7B) | 1.000 | 1.000 | 1.000 |

`poison-susceptibility` (`ps + pe`) is the fraction of poisoned rules — constraints an
unauthorized/tampered/forged author slipped in — that moved a verdict at all, split by kind;
`ps_unauth + pe_unauth` isolates the realistic pre-ingest attacker (an unauthorized principal).
It's the headline column because **signing a policy bundle proves it wasn't altered in transit,
not that its author was ever allowed to write the rule** — `opa-signed` scores `1.000` on it for
exactly that reason, while Aegis's independent authority check scores `0.000`.

The `codex` and `claude-cli` rows are **agent harnesses wrapped around a model**, not raw
completions, and — unlike the other rows — are scored against a 100-constraint holdout subset
rather than the full 500-constraint store, for context-window and cost reasons; see
[`docs/benchmark.md`](docs/benchmark.md) before comparing them with anything else in the table.

## Why not OPA/Gatekeeper?

OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis
derives **unstructured human constraints** (from Slack, Jira, Git) and applies
**authority-driven validation** to the agent's intent *before* it reaches the infrastructure.

## Project status / roadmap

The engine (constraint store, interceptor, environment mapping, dry-run handling, rate limits,
plan-level constraints, and parsers for every tool in "Supported tools") is complete, and
v0.1.0 is on PyPI as an **alpha**. Real LLM baselines have been run: Claude Sonnet 5 through
the API (cached in `results/llm-external.md`), Haiku through the Claude Code CLI, `gpt-6-astra`
through the Codex CLI, and a local `mistral:latest`.

What is *not* done is the part the threat model leans on hardest. See `PLAN.md §8`, but in
short: sources are verified against files on disk rather than real Git/Slack/Jira connectors,
signing uses a shared secret rather than per-principal public keys, and a `principal` is a
signed name rather than an identity bound to a commit signature or an SSO group. Until those
land, Aegis demonstrates that the *decision procedure* is sound; it does not yet prove the
identities feeding it are. Resource matching is also case-sensitive on names. It is not
production-ready: read `PLAN.md §8` for the full list of open gaps before putting it in front
of anything you care about.

## Documentation

| Page | Covers |
| :--- | :--- |
| [`docs/cli.md`](docs/cli.md) | Exit codes, store health, the Claude Code hook, argv forms, compound commands, dry runs, library usage |
| [`docs/constraints.md`](docs/constraints.md) | Writing constraints, metadata vocabulary, authority policy, environment mapping |
| [`docs/configuration.md`](docs/configuration.md) | Configuration/config-dir discovery, signing, source verification, rate limits & ledger |
| [`docs/benchmark.md`](docs/benchmark.md) | Benchmark methodology, full results table, real LLM baselines, agent-harness baselines, corpus, adversarial suite |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Adding a new parser or tool |
| [`PLAN.md`](PLAN.md) | Design plan and open gaps |
| [`SECURITY.md`](SECURITY.md) | Reporting a bypass |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
| [`REVIEW-4.md`](REVIEW-4.md) | Corpus/oracle rewrite (independent oracle, intent-level holdout) |

## Development

```bash
venv/bin/python -m pytest -q      # 1257 passed (last full green run; CI runs this on 3.11/3.13/3.14)
venv/bin/python -m ruff check src tests scripts examples
vhs docs/demo.tape                # regenerate docs/demo.gif
```

Adding a new parser or tool: see [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).
Reporting a bypass: see [`SECURITY.md`](SECURITY.md) — parser evasion is the largest
attack surface and the most useful thing to report. Release history is in
[`CHANGELOG.md`](CHANGELOG.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
