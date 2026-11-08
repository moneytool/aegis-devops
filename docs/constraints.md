# Writing constraints

The constraint file format, metadata vocabulary, authority policy, and environment mapping.

← back to the [README](https://github.com/moneytool/aegis-devops#readme)

## Writing constraints

A per-intent constraint (`../data/constraints.example.yaml`) has every field below. `id` is a
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

A plan-level constraint (`../data/plan_constraints.example.yaml`) carries exactly one batch
predicate instead of a per-intent match, evaluated over every intent from one plan/invocation.
One kubectl command can be more than one intent: `kubectl cp b web:/a` is two (`pod/web` and `b`),
`kubectl debug web` and `kubectl run web` are two (`pod/web` and `web/*`), `--copy-to` adds a third
on `debug`, `--expose` adds a third on `run`, `kubectl exec deploy/web` is two (`deployment/web` and `pod/*`), and `kubectl delete -f x.yaml -f y.yaml` is two (one per file). Each counts toward `max_intents` and
`max_matching`, so a count can rise. A `ratio` can also drop, since the extra intents join its
denominator: `kubectl cp web:/a b` under a ratio of `web:*` over all intents with `max: 0.75` went
from 1/1 to 1/2, which passes a ratio that used to fire:

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

### Kubernetes resource names

A kubectl target is normalised to `<singular kind>/<name>` before matching, so write
`resource_pattern` in that form: `pod/api-0`, `node/*`, `storageclass/fast`,
`clusterrolebinding/*`. Plural and short kind names (`pods`, `po`, `sc`, `storageclasses`,
`crd`, `netpol`, …) are all mapped to the singular. Some verbs name their target implicitly:

- `exec`, `logs`, `attach` and `port-forward` act on a **pod** by default: `kubectl exec api-0`
  is `pod/api-0`. Given another kind, they run on a pod kubectl finds behind it, so `kubectl exec
  deploy/web` is both `deployment/web` and `pod/*`, and so is `kubectl logs deploy/web`. A rule on
  one pod (`pod/payments-0`) cannot be decided from that, so it escalates with the note
  `target-unresolved: <id>`.
- `debug` takes a pod by bare name, or a kind with a name: `kubectl debug web --image=busybox` is
  `pod/web` and `kubectl debug node/n1` is `node/n1`. `--copy-to=c` also makes it `pod/c`, the new
  pod it runs in. `web/*`, the target earlier versions gave, stays beside them, so a per-intent rule on it
  keeps matching. A plan `ratio` over it can change (see plan constraints above). The action stays `debug`: a rule on `delete` or `create` does not meet `--replace`
  or `--copy-to` in the hook. The server-side policy covers those ([client
  parity](server-side.md)).
- `run` creates a pod called its first word, whatever the word says: `kubectl run web --image=x` is
  `pod/web` and `kubectl run all --image=x` is `pod/all`, with no kind from the `all` category. The
  name stays as written, so `kubectl run 001` is `pod/001`. Words after the name are arguments for
  the pod, so they name no pod. `web/*`, the target earlier versions gave, stays beside the pod, so
  a per-intent rule on it keeps matching. A plan `ratio` over it can change: `kubectl run web` under
  a ratio of `web/*` over all intents with `max: 0.75` went from 1/1 to 1/2. A word with a slash,
  such as `deploy/web`, is one the API refuses as a pod name, so it stays `deployment/web`.
  `--expose` also creates a Service of that name, so `kubectl run web --image=x --expose --port=80`
  adds `service/web`, and a `run` rule on `service/web` or `service/*` meets it. `--expose=false`
  adds nothing, and neither do `0`, `f`, `F`, `FALSE` or `False`, the other spellings kubectl reads
  as false. Any other value adds the Service, though kubectl refuses every value it cannot read
  as a boolean. A word with a slash adds no Service, because kubectl stops when the API refuses the
  pod. The action stays `run`: a rule on `create` does not meet it in the hook, and a rule on
  `delete` does not meet `--rm`. The server-side policy covers those ([client parity](server-side.md)).
- `cp` names its pod in `[namespace/]pod:path`, on either side: `kubectl cp web:/a b` and `kubectl
  cp b prod/web:/a` are both `pod/web`, and a namespace written there wins over `-n`, as it does in
  kubectl. Aegis reads the operands as kubectl does. Only the first colon counts, and what comes
  before it is `pod` or `namespace/pod`, however much it looks like a path: `./web:/a` is pod `web`.
  The first word as written (`web:/a` or `b`), the target earlier versions gave, stays beside the
  pod, so a per-intent rule on it keeps matching. A plan `ratio` over it can change. A local path with a colon and more slashes, such as
  `/tmp/a:b`, or a command with no pod at all, is one kubectl refuses, so only that word is left and
  a `pod/*` rule does not meet it.
- `drain`, `cordon` and `uncordon` act on **nodes**: `kubectl drain node1` is `node/node1`.

The categories `all` and `api-extensions` are expanded like a comma-separated list of their kinds.
`kubectl delete all --all` is one intent per kind in `kubectl api-resources --categories=all`
(`pod/*`, `service/*`, `deployment/*`, ...), plus `all/*`. A rule on one object of those kinds
(`deployment/payments`), or on a custom kind (`widget/*`), which can join a category, escalates
with `target-unresolved: <id>`. A rule on any other built-in kind (`secret/*`) is untouched, since
`all` does not reach it. A category a custom resource declares for itself looks like any other
unknown kind and is not expanded.

A kind with no name targets `kind/*`: `--all`, `-l` or `--field-selector`, and a bare kind on a verb
that takes one (`kubectl get pods`, `kubectl describe pods`, `kubectl rollout restart deploy`,
`kubectl edit deploy`). A rule on `kind/*` decides as usual. A rule on one object of that kind
(`deployment/payments`) escalates with `target-unresolved: <id>`, because the command may or may
not pick that object: `kubectl delete deploy -l a=b` asks, and so does `kubectl get pods` under a
`get` rule on `pod/payments-0`. A rule on another kind or another action is not affected, and a
namespace in the rule's scope still counts (`-n staging` passes a rule scoped to `prod`).
`kubectl taint node n1 --all` is both `node/n1` and `node/*`, since kubectl ignores the name there.
`cordon`, `uncordon` and `drain` with `-l` act on every node the selector matches (`node/*`), and
`logs -l` reads every pod it matches (`pod/*`), as kubectl 1.36 does.

The same holds where other tools pick their targets when they run: `argocd app sync -l` or
`--project` and `argocd app delete -l` (`app/*`, beside any app named), `flux suspend|resume
<kind> --all` (`<kind>/*`), `flux reconcile --with-source` (the source kinds the object can
reference), `helm install --generate-name` (`release/*`), `git filter-repo` (`history/*`) and an
aws command whose target is in `--cli-input-json` (`<service>/<kind>/*`). A rule on one of them
escalates with `target-unresolved: <id>`.

`kubectl describe TYPE NAME` describes the object called NAME, and if there is none, every object
whose name starts with NAME. So `kubectl describe pod pay` is `pod/pay`, and a `describe` rule that
can match a name starting with `pay` (`pod/payments-0`, `pod/*-0`) escalates with
`target-unresolved: <id>`, because the hook cannot tell whether a pod called `pay` exists, or which
pods start with it. A rule that cannot (`pod/api-0`, `pod/pa`) is not affected. This holds only for that
two-word form, as in kubectl: `kubectl describe pod/pay` and `kubectl describe pod a b` are exact, and
`get` never takes a prefix. Words after `--` count as words: see below.

kubectl hands words after `--` to most verbs as plain operands. `kubectl describe pod api --
payments-0` names two pods, `kubectl delete widgets foo -- bar` names two objects, and `kubectl
describe pod pay -- other` has three words, so it is exact and takes no prefix. This holds for
`annotate`, `autoscale`, `certificate`, `cordon`, `cp`, `delete`, `describe`, `drain`, `edit`,
`expose`, `get`, `label`, `patch`, `rollout`, `scale`, `set image`, `taint`, `uncordon` and `wait`,
and for `attach` when it gives the second of its two words. `exec`, `run`, `create` and `debug` treat
them as a command, and `logs`, `port-forward` and `top` take their target from what comes first. With
nothing before the `--` (`kubectl delete -- pod x`) the hook refuses the command.

A kind that is not in the built-in table may be a custom resource, written by its singular, plural
or short name, and the command alone does not say which: `widgets` may be the plural of `widget`,
and `wd` may be short for anything. Stripping an `s` would be a guess that fails on the short names
and could report a match that is not there. So on `delete`, `get`, `describe`, `edit`, `patch`,
`scale`, `autoscale`, `label`, `annotate` and `wait`, a rule on any kind outside the table escalates with
`target-unresolved: <id>`: `kubectl delete widgets --all` asks under a rule on `widget/*`, and also
under one on `gadget/*`, since `widgets` could be its short name. When the command names an object,
the rule must also be able to match that name: `kubectl delete widgets foo` asks under `widget/foo`
and `widget/*`, and passes `widget/bar`. A rule on a built-in kind is not affected, and neither is
a rule written in exactly the command's spelling, which decides as usual. `exec`, `logs`, `rollout`,
`set image` and `taint` stay as they were, since kubectl refuses a custom kind on them. A custom
kind's real names stay unresolved, since they are only in the cluster, and a custom resource whose
name is also in the built-in table counts as the built-in kind.

(Before v0.2.1 these produced `api-0` and `node1/*`, and plural kinds such as `storageclasses`
were kept plural, so a rule written for the normal form missed them. Rules written against the
old forms need updating.)

`--as`, `--as-group` and `--as-uid` are recorded in `params.impersonate`, and each impersonated
identity also becomes an intent of its own, `impersonate` on `user/<name>`, `group/<name>` or
`uid/<id>` — so `kubectl --as admin delete node w1` is two intents, the delete and
`impersonate user/admin`. The example policy blocks every impersonation
(`block-kubectl-impersonation`, `resource_pattern: "*"`, `actions: [impersonate]`).

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

## Duplicate ids

Each entry in a constraints or plan-constraints file is judged on its own, wherever it is in the
file, and a rejected entry never displaces another one. So a rejected entry written ahead of a
trusted rule with the same id changes nothing: it is quarantined with its own reason (`tampered`,
`forged`, `invalid: ...`) and the trusted rule loads. A `warnings` line names every id that
appeared more than once. Among the entries that pass:

| Entries with one id | Result |
|---|---|
| identical | one loads; each extra one is quarantined as `invalid: duplicate id` |
| differing, one authorized | it loads; those whose principal is not authorized are quarantined as `unauthorized` |
| differing, none authorized | none loads; all are quarantined as `unauthorized` |
| differing, more than one authorized | the load fails with an error, as for any unusable policy file |

The last case does not pick one because nothing says which one the policy means. `aegis check`
exits with a data error, and the agent hook denies infrastructure commands until the file is
fixed. With a source directory, the source usually settles it first, by rejecting the entries it
does not back as `forged`.

## Authority policy

`../data/authority.example.yaml` maps each principal to the constraint classes it may assert:

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
context/account/project/subscription. `../data/environments.example.yaml` maps provider-specific
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

The same holds for **`namespace`**. A kubectl or helm command without `-n` runs in the kubeconfig
context's namespace, which the argv does not show, and `-A` covers every namespace. A rule scoped
on `namespace` that would otherwise match escalates with the note `namespace-unresolved: <id>`,
instead of silently not applying: `kubectl rollout restart deploy/web` escalates against a
`namespace: prod` rule. A cluster-scoped kind (`node`, `namespace`, ...) has no namespace and is
never affected. (Until 1.0 such a rule simply did not match; reported by a reader on dev.to.)

**Manifests are not read.** `kubectl apply|create|replace|delete -f <file>` (or a directory,
`-k <kustomization>`, or `-f -` for stdin) is one intent on `manifest/<name>`, with one for each
file in `-f a -f b` or `-f a,b`; the objects inside are never parsed, since the file can change between the check and the run. A rule for the same
action written on kinds or objects (`secret/*`, `deployment/web`) might be exactly what the
manifest holds, so it escalates with the note `manifest-not-inspected: <id>`. A rule on `*`
matches the manifest intent outright (`kubectl delete -f ./manifests/ -n prod` is a BLOCK under
`no-delete-in-prod-namespace`), and a rule on `manifest/<glob>` is matched against the file name.

`--resolve-current-context` fills a *missing* identifier from the invoking environment: the
kubeconfig's `current-context` (and its cluster) from `$KUBECONFIG` / `~/.kube/config` (parsed,
never by running `kubectl`), `$AWS_PROFILE`, `$AWS_DEFAULT_REGION`/`$AWS_REGION`,
`$CLOUDSDK_CORE_PROJECT`, `$AZURE_SUBSCRIPTION_ID`, `$HELM_NAMESPACE`, `$ARGOCD_SERVER`. An
explicit `--context` on the argv always wins, and the keys that were filled are listed in
`metadata.resolved_from_environment`. For kubectl and helm it also fills a missing
namespace from the context's `namespace` (`default` when the context sets none, as kubectl does;
never for a cluster-scoped kind, with `-A`, or for a manifest that was not read, whose objects may
name their own namespace). An explicit `--kubeconfig` on the argv is the only file consulted, and
if it cannot be read nothing is filled; otherwise the files in `$KUBECONFIG` are merged as kubectl
merges them (the first to define a context wins). It is opt-in because it **trusts the invoking
environment**: whoever controls the process environment controls what Aegis believes the
target is.
