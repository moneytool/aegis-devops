# Aegis-DevOps — Policy Verifier for AI DevOps Agents

**Provenance-backed, authority-aware guardrails that stop context poisoning and agentic drift
before an AI agent's `kubectl` or `terraform` action reaches your infrastructure.**

> **Alpha — not production ready.** The decision engine and its tests are
> solid, but the trust roots around it are still stand-ins: sources are
> verified against files on disk rather than real Git/Slack/Jira connectors,
> signing uses a shared secret rather than per-principal keys, and a
> `principal` is a signed name rather than an identity bound to a commit
> signature or SSO group. Resource matching is case-sensitive on names. Read
> [PLAN.md §8](PLAN.md) for the full list of open gaps before putting this in
> front of anything you care about.

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
pip install aegis-devops
aegis init ./.aegis
```

`aegis init` writes the example policy files (constraints, authority map, environment map,
plan constraints, signed sources) into a directory. Putting them in `./.aegis` means the CLI
finds them with no flags and no environment variable — see "Configuration" for the full search
order. Then check a command:

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
"Signing". The example rules are a demo, not a starting policy; replace
`constraints.example.yaml` with your own `constraints.yaml` (a real file wins over the
`.example` one when both exist).

To check a whole shell command string rather than one argv — which is what an agent framework
actually hands you — use `aegis check command -- "kubectl get pods; sudo kubectl delete node/w1"`;
see "Compound commands".

### From a clone

```bash
python -m venv venv
venv/bin/python -m pip install -e ".[dev]"
venv/bin/python examples/demo.py
```

`examples/demo.py` runs 15 intents across every supported tool through the interceptor and
prints each decision, starting with the store's health. A clone already has `data/`, so the CLI
finds its policy files without `aegis init`.

### Argv forms

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
| `64` | usage error (unknown flag, no argv after `--`, compound argv without `--split-compound`, a command string Aegis refuses to evaluate statically) | same | same |
| `65` | bad data: unparseable argv, `--now`, YAML or JSON; degraded store (see below); no signing key, or a missing/bad signature | same | same |
| `66` | a constraints/authority/environments/plan/key file does not exist or is unreadable | same | same |
| `70` | internal error; the exception class name is on stderr | same | same |

Every error is one `aegis: error: …` line on stderr, never a traceback. `claude-hook` exists
because Claude Code `PreToolUse` hooks treat exit 2 as *block* and any other non-zero code as a
non-blocking error, which would invert the default `3 = BLOCK` contract.

### Store health

Every output carries the state of the constraint store, so a degraded store can never be
mistaken for a clean allow. Each per-intent JSON line and the plan summary include a
`store_health` object — `loaded`, `quarantined: [{id, reason}]`, `principals`,
`constraints_sha256` (of the raw file bytes), `warnings` — and `--pretty` ends with a
`STORE: loaded=N quarantined=M principals=P` line plus one line per quarantined rule, preceded
by one `WARNING: …` line per store warning (`using example signing key`, `insecure: signatures
not verified`, `ledger: chain-broken`, rate-limit key typos). Quarantines also go to stderr as
`aegis: WARNING …` lines.

Integrity failures **fail closed**. A constraint that was quarantined at load (`tampered`,
`forged`) or discarded at decision time (`tampered`, `unauthorized`) is still matched, and if it
was a BLOCK or ESCALATE rule its match contributes **ESCALATE** — never BLOCK (nobody can vouch
for the rule) and never ALLOW (the action it covers is contested). The decision reports it in
`discarded` and with a `fail-closed: <id> (<reason>)` note:

```bash
aegis check kubectl --constraints /tmp/oneflip.yaml --key file:data/example-signing.key \
    --pretty -- kubectl delete node/x
```

```
aegis: WARNING Quarantined constraint no-delete-nodes: provenance hash mismatch
ESCALATE: kubernetes delete node/x
  discarded: [{'id': 'no-delete-nodes', 'reason': 'tampered'}]
  note: env-unresolved: no-delete-in-prod-env
  note: fail-closed: no-delete-nodes (tampered)
  covered: True  latency_ms: 0.13
PLAN ESCALATE: 1 intent(s)
  plan citations: plan-k8s-delete-ratio
  note: ratio: 1/1 = 1.00 > 0.5
WARNING: Quarantined constraint no-delete-nodes: provenance hash mismatch
STORE: loaded=20 quarantined=1 principals=3
  quarantined: no-delete-nodes (tampered)
```

(`/tmp/oneflip.yaml` here is `data/constraints.example.yaml` with the last hex digit of
`no-delete-nodes`'s `provenance_hash` flipped and re-signed with the example key — a valid
signature, invalid content, exactly what a hand-edited rule or a one-bit storage error looks
like. `--key` is explicit because the example key normally auto-resolves next to
`--constraints`, and `/tmp` has no `example-signing.key` of its own.)

Aegis refuses to decide at all (exit 65, one-line message, no verdict) when the store loaded
zero constraints, the authority map grants nothing to anyone, or more than
`--max-quarantine-ratio` (default `0.10`) of the constraints were quarantined. `--fail-closed`
additionally turns an *uncovered* intent (no rule matched) into ESCALATE with the note
`fail-closed: uncovered`.

Two more fail-closed clauses live in the interceptor: a rule that scopes on `env` when the
intent's environment could not be resolved contributes ESCALATE with the note
`env-unresolved: <id>` (see "Environment mapping"), and an intent whose target the parser
could not pin down (`git push -f` with no refspec) contributes ESCALATE with the note
`unknown-target`, so it cannot slip past a `ref/main` rule as `ref/*`.

### Claude Code hook

`examples/claude-code-hook.sh` is a `PreToolUse` hook: it reads the hook JSON from stdin and
hands `tool_input.command` — the raw string — to `aegis check command --exit-style claude-hook`.
ALLOW lets the tool call proceed; ESCALATE and BLOCK exit 2 with the reason on stderr (which
Claude Code shows to the model). Compound commands are split and launchers unwrapped (see
"Compound commands"); binaries Aegis has no parser for are not gated unless you add
`--fail-closed` via `AEGIS_ARGS`; any tool error — including a command string Aegis refuses to
evaluate statically, such as `kubectl delete $(cat x)` — is converted into a block, so the hook
never fails open. It runs the `aegis` in the venv next to it (`AEGIS_BIN` overrides).

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
| `command` | `aegis check command -- "kubectl get pods; sudo kubectl delete node/w1"` (a shell string; see "Compound commands") |

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

### Metadata vocabulary

Every parser in `aegis_core.parser` fills `Intent.metadata` with operator-derived context (not
agent-controlled — see the scope semantics below) parsed from the argv itself. `aegis_core.environments`
fills in the rest (`env`, and any of `context`/`cluster`/`project`/`account`/`subscription`/
`resource_group`/`workspace` the argv didn't already carry) from `environments.yaml`, recording which
ones it filled in `metadata["resolved_from_environment"]`. This table is generated by grepping
`metadata["..."] = ...` in `parser.py`, not written from memory:

| Key | Emitted by | Example value |
| --- | --- | --- |
| `namespace` | kubectl (`-n`/`--namespace`), helm (`-n`/`--namespace`), flux (`-n`/`--namespace`) | `prod` |
| `context` | kubectl (`--context`), helm (`--kube-context`), argocd (`--server`/context resolution), flux (`--context`) | `gke_acme_prod` |
| `cluster` | kubectl (`--cluster`) | `prod-us-east` |
| `kubeconfig` | accepted as a global flag by kubectl/helm/flux/argocd so it never leaks into `resource`/`action`, but its value is **discarded** — not recorded in `metadata` or `params` by any parser | *(not recorded)* |
| `region` | terraform (from `values`/`planned_values`/`provider_config`), aws (`--region`), az (`-l`/`--location`), gcloud (`--region`, or derived from `--zone` — see below) | `us-east-1` |
| `zone` | gcloud (`--zone`) | `us-east1-b` |
| `project` | gcloud (`--project`) | `acme-prod` |
| `account` | not emitted by any parser directly; resolved only via `EnvironmentMap`/`--resolve-current-context` (`AWS_PROFILE`) | `123456789012` |
| `profile` | aws (`--profile`) | `prod-admin` |
| `subscription` | az (`--subscription`) | `00000000-0000-0000-0000-000000000000` |
| `resource_group` | az (`--resource-group`/`-g`, and parsed out of an ARM `--ids` path) | `rg-prod` |
| `repo` | gh (`--repo`/`-R`, or parsed from a `.../repos/<owner>/<name>/...` API path) | `acme/infra` |
| `ref` | gh (`--ref`, or parsed from a workflow-dispatch API path) | `main` |
| `env` | never emitted by a parser; set by `EnvironmentMap.apply()` from `environments.yaml` when a resolvable key (`context`/`cluster`/`project`/`account`/`subscription`/`resource_group`/`workspace`) is present and mapped | `prod` |
| `workspace` | never emitted by a parser; only resolved through `environments.yaml`'s `terraform_workspaces` table | `prod` |
| `tool` | terraform (`terraform` or `opentofu`, from `plan_json`) | `opentofu` |
| `type_name` | terraform (module-stripped `<type>.<name>`, e.g. `aws_db_instance.main` from `module.app.aws_db_instance.main`) | `aws_db_instance.main` |
| `plan_sha256` | terraform (`plan_digest()` of the plan JSON that was checked) | `f3af6978...` |
| `resolved_from_environment` | `EnvironmentMap.apply()` — the list of metadata keys it filled in that the parser hadn't already set | `["env"]` |

`kubeconfig` is listed because it's a common source of confusion: it's consumed like every other
global flag (so it never becomes a bogus resource/action) but has no scope-matching use today, so no
parser records it.

#### Scope matching semantics

A constraint's `scope: {...}` (and a plan selector's `scope`) is matched against an intent by
`aegis_core.store.scope_matches`:

- **Metadata-first.** Each scope key is looked up in `intent.metadata` before `intent.params`, and
  `params` may only supply a key `metadata` lacks entirely — an agent-controlled `--env=dev` flag can
  never shadow an operator-resolved `metadata["env"] = "prod"` (REVIEW-4 T1.5). A key absent from both
  never matches.
- **String/bool coercion.** If either side of a comparison is a bool, both are read as booleans
  (`"true"`/`"false"`/`"True"`/`"FALSE"` all count, case-insensitively). Otherwise, if either side is a
  string, both are compared as strings — so a YAML `account: 123456789012` (an int) matches an intent's
  `"123456789012"` (a string) and vice versa.
- **Lists are OR.** `scope: {namespace: [prod, prod-eu]}` matches either value.
- **Globs.** A scope value containing `*`, `?`, or `[...]` is matched with `fnmatch` (case-sensitive)
  against the intent's value, e.g. `region: us-east-*`.
- **Dotted paths.** A scope key with a `.` (e.g. `set.replicaCount`) first tries a literal key of that
  exact name, then walks the dots into nested dicts (`params["set"]["replicaCount"]`) — this is what
  makes `helm --set replicaCount=0` (parsed into `params["set"] = {"replicaCount": 0}`) expressible as
  `scope: {set.replicaCount: 0}`.
- **`actions: ["*"]`.** A per-intent constraint (or plan selector, where `actions` is already an
  "any of these" list) may include the literal string `"*"` in its `actions` set to mean "any action".
  It is otherwise an ordinary string: no special validation, and no effect on the constraint's
  provenance hash (which hashes the `actions` set exactly as given).
- **Time windows.** `time_window.tz` (or the store-level `default_tz` — see below) localises the
  evaluation instant before every other check. `days` excludes by local weekday. `start`/`end` are
  `HH:MM`; `end` is **exclusive** at minute granularity, so `09:00`–`17:00` means `[09:00, 17:00)` and
  `16:59` is inside it but `17:00` is not. `end: "24:00"` is accepted to mean "through midnight" (the
  only way to include the last minute of the day under an exclusive end). `start > end` is a
  **wrap-around** window (e.g. `22:00`–`06:00`) and matches when the local time is at/after `start` OR
  before `end`. A `time_window` with no `tz` of its own is valid only when the constraints file sets a
  top-level `default_tz:` (a store-level setting, not a constraint field — adding or changing it never
  changes any constraint's `provenance_hash`); otherwise it is quarantined at load as
  `invalid: time_window.tz missing and no default_tz`. The evaluation instant (`now`) must be
  timezone-aware everywhere in the matcher; a naive `datetime` raises `ValueError` rather than silently
  assuming UTC.

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

## Compound commands

Agent frameworks hand over a shell *string*, not an argv. `aegis check command -- "<string>"`
(and `aegis check argv --split-compound`) turns that string into the simple commands it would
run — splitting on `;`, `&&`, `||`, `|`, `&` and newlines, unwrapping `sudo`, `env VAR=…`,
`timeout`, `nice`, `nohup`, `command`, `time`, `sh -c "…"` and the `k`/`tf`/`g` aliases — and
checks every one whose binary Aegis knows. The exit code is the worst verdict across them:

```
aegis check command -- "kubectl get pods; kubectl delete node/w1"   # BLOCK, exit 3
aegis check command -- "sudo kubectl delete node/w1"                # BLOCK, exit 3
aegis check command -- "kubectl get pods | grep x"                  # ALLOW, exit 0
aegis check command -- 'kubectl delete $(cat x)'                    # exit 64: command rejected
```

Inside a pipeline an unknown binary (`| grep x`) produces nothing; on its own it produces a
synthetic `shell` / `binary/<name>` / `exec` intent that `--fail-closed` escalates. `KUBECONFIG=…`
and `env AWS_PROFILE=…` prefixes land in the intent's metadata (`kubeconfig`, `profile`, …) so
the environment map sees them. **Fail closed:** anything whose argv cannot be known without
running it is refused as a usage error (exit 64, `command rejected: <reason>`) — command
substitution (`$(…)`, backticks), `$VAR` outside single quotes, process substitution,
subshells, here-docs, `eval`/`exec`/`source`/`.`/`xargs`, and unbalanced quotes. Without the
flag, `aegis check <target>` still treats any shell metacharacter in an argv as a usage error.

## Environment mapping

Constraints can scope on `env: prod|staging|dev` instead of repeating every raw
context/account/project/subscription. `data/environments.example.yaml` maps provider-specific
identifiers to a normalised environment, and `EnvironmentMap.annotate` sets
`intent.metadata["env"]` at parse time (the CLI does this automatically via `--environments`,
defaulting to `data/environments.example.yaml` when present). Resolution is provider-agnostic:
whatever tool produced the intent, every identifier its parser recorded is looked up —
`kubernetes.contexts` / `clusters` / `kubeconfigs` (kubectl, helm `--kube-context`, flux,
argocd, `KUBECONFIG=…`), `aws.accounts` / `profiles`, `gcp.projects`, `azure.subscriptions` /
`resource_groups`, `github.repos` (`owner/repo` from `gh -R`), `argocd.apps` (globs on the app
name) and `terraform.workspaces`. An identifier that isn't in the map resolves to no
environment at all — never a default like `dev` — and, deliberately, kubectl namespaces are
never used to infer `env`, since a namespace is a string the agent (or an attacker poisoning
its context) controls.

**Unknown is not "not prod".** When a rule scoped on `env` would otherwise match and the intent
has no resolved `env`, the rule is neither honoured nor dropped: the decision is ESCALATE with
the note `env-unresolved: <id>` (a BLOCK from another rule still outranks it). So
`kubectl delete pod/x -n dev` with no `--context` escalates against `no-delete-in-prod-env`
instead of sailing through. Plan-constraint selectors with `scope: {env: …}` behave the same.

`--resolve-current-context` fills a *missing* identifier from the invoking environment: the
kubeconfig's `current-context` (and its cluster) from `$KUBECONFIG` / `~/.kube/config` (parsed,
never by running `kubectl`), `$AWS_PROFILE`, `$AWS_DEFAULT_REGION`/`$AWS_REGION`,
`$CLOUDSDK_CORE_PROJECT`, `$AZURE_SUBSCRIPTION_ID`, `$HELM_NAMESPACE`, `$ARGOCD_SERVER`. An
explicit `--context` on the argv always wins, and the keys that were filled are listed in
`metadata.resolved_from_environment`. It is opt-in because it **trusts the invoking
environment**: whoever controls the process environment controls what Aegis believes the
target is.

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

`--sources DIR` points at a directory of `<source_ref>.json` files plus a `PRINCIPALS.yaml`
that says which principal the *transport* attributes each source to. It defaults to the
`sources/` directory next to the constraints file when one exists (`--sources ''` opts out), so
with the shipped layout forgery is detected without any flag. A constraint whose cited source
doesn't back it (missing file, or different content) is quarantined as `forged` at load time; one
whose transport principal differs from the principal it claims is quarantined as
`principal-mismatch`. Both fail closed like any other quarantine.

`FileSourceFetcher` is a v1 stand-in for real Git/Slack/Jira connectors — it re-reads a flat
JSON file rather than calling out to a commit, a permalink, or a ticket API (see "Open gaps" in
`PLAN.md`).

`data/sources-forged/` is `data/sources/` with `jira-1001.json`'s `rule_text` edited after the
fact (still validly signed — signing proves the *file* wasn't touched in transit, not that its
*content* still matches what a constraint cites) so `--sources` has something real to catch:

```bash
aegis check kubectl --now 2026-03-16T10:00:00-05:00 --pretty --sources data/sources-forged -- \
    kubectl scale deployment/api-server --replicas=5 -n prod
```

```
aegis: WARNING Quarantined constraint no-scale-prod-peak: source does not back its claimed fields
ESCALATE: kubernetes scale deployment/api-server
  discarded: [{'id': 'no-scale-prod-peak', 'reason': 'forged'}]
  note: fail-closed: no-scale-prod-peak (forged)
  covered: True  latency_ms: 1.53
PLAN ESCALATE: 1 intent(s)
WARNING: using example signing key
WARNING: Quarantined constraint no-scale-prod-peak: source does not back its claimed fields
STORE: loaded=20 quarantined=1 principals=3
  quarantined: no-scale-prod-peak (forged)
```

The same `kubectl scale ...` command against the real `data/sources` (the CLI's default) is a
plain `BLOCK` — see "Quick start" above; forging the source turns a legitimate rule into a
fail-closed `ESCALATE` instead of quietly ceasing to apply.

## Signing

Every policy file — constraints, plan constraints, authority map, environment map, source
snapshots and `PRINCIPALS.yaml` — must verify under a keyed BLAKE2b MAC before the CLI will
decide with it. Single files carry a detached `<file>.sig`; a directory of sources carries one
`AEGIS-MANIFEST.sig` (a JSON manifest of `{relpath: sha256}` plus the MAC of that mapping), so
hundreds of snapshots are one signature. A file with a detached `.sig` is checked against it;
otherwise the nearest manifest above it must list it with a matching hash.

```bash
aegis sign   --key file:aegis-signing.key data/constraints.yaml data/sources   # .sig + manifest
aegis verify --key env:AEGIS_SIGNING_KEY  data/constraints.yaml data/sources
```

**`aegis verify` scope on a directory.** `sign` on a directory covers everything under it (every
`.yaml`/`.json`, recursively) — that's a deliberate "sign the whole tree" operation for a
directory you've pointed it at on purpose, e.g. `data/sources`. `verify` on a directory is
narrower on purpose: it only checks files that were *actually signed* — one with its own
`<file>.sig`, or one listed in an `AEGIS-MANIFEST.sig` found at or below that directory — never
every `.yaml`/`.json` it happens to find. A policy directory can legitimately hold unrelated,
unsigned content next to real policy files — `data/corpus/seeds.yaml`, `split.json` and
`stats.json` are corpus-generation artifacts no Aegis loader ever reads — and `aegis verify
data/corpus` must not report those as `FAILED` just because of their extension. Passing a file
directly (not discovered via a directory walk) is unaffected: it is always checked, signed or
not, so a real gap still surfaces as `FAILED` on the file itself or by naming the directory that
has — or should have — a manifest covering it.

The key is resolved from `--key SOURCE` (`env:VAR`, `file:PATH`, or raw hex), then
`$AEGIS_SIGNING_KEY`, then `<dir of --constraints>/example-signing.key` if it exists — with the
store warning `using example signing key`, because **`data/example-signing.key` is public and
demo-only**: it is committed so the shipped examples and corpus verify out of the box, and
anyone holding it can forge those files. Generate your own (`python -c 'import secrets;
print(secrets.token_hex(32))'`), re-sign, and keep it out of the agent's reach. With no key at
all the CLI exits 65 (`no signing key: pass --key, set AEGIS_SIGNING_KEY, or --insecure`);
`--insecure` loads everything unverified and says so in every `store_health.warnings`. This is a
MAC, not a public-key signature: whoever can sign can verify, which is the v1 boundary — Aegis
defends against poisoned *content* from sources you chose to trust, not against an attacker
who holds the signing key.

## Configuration

Running `aegis` from the repo checkout with no flags "just works" because `$PWD/data` already
has `constraints.example.yaml` — but installed as a wheel there is no `data/` next to the
interpreter. `--constraints`/`--authority`/`--environments`/`--plan-constraints` each default to
`None` and are resolved from a **config directory**, searched in this order, first match wins:

1. `--config-dir DIR` (explicit)
2. `$AEGIS_CONFIG_DIR`
3. `$PWD/.aegis`
4. `$PWD/data` — **only** if it already contains a `constraints*.yaml` (this is what keeps a
   repo checkout working with no setup)
5. `~/.config/aegis`
6. `/etc/aegis`

Inside that directory, a real file wins over its `.example` counterpart when both exist
(`constraints.yaml` over `constraints.example.yaml`, and likewise for `authority`/
`environments`/`plan_constraints`); `sources/` and `example-signing.key` next to the constraints
file are picked up the same way they always were. Any of `--constraints`/`--authority`/etc.
passed explicitly is used as-is and skips discovery for that one file. When none of the above
finds a directory *and* `--constraints`/`--authority` were never given either, the CLI refuses
cleanly instead of tracebacking on a relative path that doesn't exist from the current
directory:

```
$ cd /tmp && aegis check kubectl -- kubectl get pods
aegis: error: no config found (searched: /tmp/.aegis, /Users/you/.config/aegis, /etc/aegis); run 'aegis init <dir>'
```

`aegis init <dir>` seeds a fresh directory with the packaged example policy files (the same
`*.example.yaml` + `.sig` + `sources/` the repo ships in `data/`, embedded in the wheel under
`aegis_core._examples/` — see `scripts/sync_package_examples.py`, which keeps that copy in sync
with `data/` and is checked by `tests/test_config.py`) and prints next steps:

```
$ aegis init ~/.config/aegis
aegis: wrote 38 file(s) to /Users/you/.config/aegis
Next steps:
  1. Generate a real signing key:  aegis keygen --out ~/.config/aegis/aegis-signing.key
  2. Sign your policy files:       aegis sign --key file:~/.config/aegis/aegis-signing.key ~/.config/aegis/*.yaml ~/.config/aegis/sources
  3. Replace the *.example.yaml files in ~/.config/aegis with your own constraints.yaml / authority.yaml / ... (aegis prefers a real file over the .example one when both exist)
```

`aegis keygen [--out FILE]` (default `aegis-signing.key`) writes 32 random bytes, hex-encoded,
mode `0600` — a real key, distinct from the public `example-signing.key` that `init` copies in
verbatim. Once you've edited the example files into real ones and signed them with your own key,
either export `AEGIS_SIGNING_KEY` or keep using `--key file:...`; the example-key fallback only
ever fires when `example-signing.key` is the *only* key next to `--constraints`.

Other env vars: `$AEGIS_SIGNING_KEY` (see "Signing" above). There is currently no env var for
`--now`, `--ledger`, or the output flags — those stay CLI-only so a shell alias can't silently
change what gets decided.

## Rate limits & ledger

`--ledger PATH` enables `rate_limit` constraints and records every executed (`ALLOW`,
non-dry-run) decision, bucketed by the constraint's `key` metadata fields within its `per`
window. A `.jsonl` path gives an append-only JSON-lines ledger; `.db`/`.sqlite`/`.sqlite3` gives
a SQLite one. Both serialise load → count → record across processes (an `flock` on a sidecar
`.lock` file, or `BEGIN IMMEDIATE`), so sixteen racing agents against `max: 3` get exactly three
ALLOWs; both hash-chain their records, and a truncated or hand-edited ledger surfaces as the
store warning `ledger: chain-broken` and makes every rate-limited rule ESCALATE rather than
count from zero. Records older than the largest `per` window in the store (at least 24h) are
pruned on load, so a ledger never grows without bound; malformed lines are skipped and counted.
A `rate_limit.key` naming a field no parser emits is reported in `store_health.warnings` at load
instead of silently bucketing nothing (`resource` is allowed, to bucket per concrete target).

```bash
aegis check kubectl --ledger results/ledger.db --pretty -- \
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

`scripts/benchmark.py` runs Aegis and several baselines over the labeled 500-constraint corpus in
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

| verifier | n | precision | recall | F1 | over-block | PS | ps_unauth | ps_tamp | ps_forged | pe_unauth | pe_tamp | pe_forged |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **aegis** | 120 | **1.000** | 1.000 | **1.000** | **0.000** | **0.000** | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| opa-signed | 120 | 0.800 | 1.000 | 0.889 | 0.250 | 0.500 | 0.100 | 0.000 | 0.375 | 0.900 | 0.083 | 0.125 |
| opa | 120 | 0.667 | 1.000 | 0.800 | 0.500 | 1.000 | 0.100 | 0.750 | 0.375 | 0.900 | 0.250 | 0.625 |
| llm-heuristic | 120 | 0.667 | 1.000 | 0.800 | 0.500 | 1.000 | 0.400 | 0.833 | 0.750 | 0.600 | 0.167 | 0.250 |
| claude-cli (haiku) | 120 | 0.836 | 0.767 | 0.800 | 0.150 | 0.300 | 0.000 | 0.167 | 0.375 | 0.200 | 0.000 | 0.250 |
| ollama (mistral 7B) | 120 | 0.500 | 1.000 | 0.667 | 1.000 | 1.000 | 0.000 | 0.083 | 0.375 | 1.000 | 0.917 | 0.625 |

(`split: holdout`, `oracle: reference`, `n_distinct=323`; 30 poison candidates — 10 unauthorized,
12 tampered, 8 forged. Full table with latency, coverage and strict precision in
`results/benchmark.md`. A `codex` row is pending: its run hit the ChatGPT-account quota at
90/120 and is excluded until it completes.)

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
  [`--on-untrusted-match`](#store-health)). Under `escalate` those same 30 candidates all become
  ESCALATEs and the over-block rate rises to match the baselines — the earlier default, kept for
  the record in `results/benchmark-failclosed.md`.

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
oracle, intent-level holdout — see REVIEW-4.md), a sibling harness
(`agent-guardrail-bench@a98a8fa`) ran both `llm-naive` and `llm-aware` for real against the
corpus as it stood at commit `a2497e4^`, importing this repo's `aegis_core.baselines.llm`
directly. Full tables, provenance, and the replay-hit-rate verification are in
[`results/llm-external.md`](results/llm-external.md); the headline number is
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
`claude-sonnet-5` rows in [`results/llm-external.md`](results/llm-external.md) were measured
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
plan-level constraints, and parsers for every tool in "Supported tools") is complete, and
v0.1.0 is on PyPI. Real LLM baselines have now been run: Claude Sonnet 5 through the API
(cached in `results/llm-external.md`), Haiku through the Claude Code CLI, and a local
`mistral:latest`; a Codex CLI row is pending a quota reset.

What is *not* done is the part the threat model leans on hardest. See `PLAN.md §8`, but in
short: sources are verified against files on disk rather than real Git/Slack/Jira connectors,
signing uses a shared secret rather than per-principal public keys, and a `principal` is a
signed name rather than an identity bound to a commit signature or an SSO group. Until those
land, Aegis demonstrates that the *decision procedure* is sound; it does not yet prove the
identities feeding it are.

## Why not OPA/Gatekeeper?

OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis
derives **unstructured human constraints** (from Slack, Jira, Git) and applies
**authority-driven validation** to the agent's intent *before* it reaches the infrastructure.

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
