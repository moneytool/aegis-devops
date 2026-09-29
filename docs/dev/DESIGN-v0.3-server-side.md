# Design: server-side enforcement (v0.3)

Status: **revision 3, decisions recorded**, 2026-09-28 (revision 2 plus the four decisions in
§12). Revision 1 was reviewed by a council of
three models — gpt-6-astra (Codex CLI), Claude Fable 5.1 and Claude Opus 5.5 — each
independently, from the same brief; their verbatim reviews are in
[`council-v0.3/`](council-v0.3/) and §13 maps every finding to what changed. No code yet.

## 1. Problem

Every enforcement point Aegis has today runs **on the client side**: the agent hooks
(`aegis hook <agent>`), the plugins, and `aegis check` in a script or CI job. They stop what
goes through them and nothing else. An agent that writes a Python script against the
Kubernetes API, calls a cloud SDK, drives a web console through a browser tool, or runs where
no hook is installed is not checked at all.

The places that cannot be bypassed are the **control planes** every path goes through:

| Resource | Control plane every path goes through |
|---|---|
| Cloud resources (instances, buckets, databases, projects, resource groups) | the AWS / Azure / GCP API |
| Workloads and objects inside a cluster | the Kubernetes API server |
| Data in a database | the database server |
| Code, branches, releases | the Git server (GitHub, GitLab) |

This design adds enforcement at those control planes **as a second layer**. The client hook
stays: it tells the model *why* it was stopped, so it can change course, and it stops a
command before it is attempted. The server side is the backstop that holds when the client
side is absent or bypassed.

A control plane sees **credentials**, not intentions: it cannot tell an AI agent from a
script from a person by looking at a request (user agents and source IPs are set by the
caller; an agent may run inside CI). So everything server-side rests on an **identity model**
(§4) — agents act only through identities that only agents hold, and the ways an agent could
act through any other identity are closed. The council's main finding on revision 1 was that
this was assumed rather than designed; §4 is new for that reason.

## 2. Goals and non-goals

**Goals**

1. A Kubernetes **admission webhook** that decides with the same engine, the same signed
   policy and the same checks as `aegis check`, for requests made by agent identities.
2. A **policy compiler** that turns the *verified and authorised* subset of an Aegis policy
   into each cloud's native deny policies, scoped to agent identities, so the cloud enforces
   them itself. Poisoned rules are excluded before compilation and never reach the cloud.
3. **Self-protection**: every generated artifact also denies the agent the means to remove
   it, to act as another identity, or to change the policy that produced it (§4.3).
4. A **coverage report** for every enforcement point — webhook included — stating per rule
   whether it is enforced exactly, over-enforced, or not enforced (and why). No enforcement
   point may claim protection it does not give.
5. Packaging for the **Terraform/OpenTofu plan gate** (exists as
   `aegis check terraform plan.json --exit-style ci`) and generation of **GitHub rulesets**.

**Non-goals (v0.3)**

- A credential broker / API proxy for cloud calls (per-request decisions, ESCALATE with a
  human, rate limits on cloud APIs). Future work, §11.
- Database-side enforcement. Future work, §11.
- Applying anything automatically. Aegis *generates* policies and manifests; operators apply
  them through their own IaC and review, with their own credentials.
- Enforcing on human identities (humans keep their existing controls), except through the
  deny-by-default mode an operator can choose (§4.2).
- Scheduling recurring time windows into cloud policies (§6.3).

## 3. Prerequisites (must land first)

The council found that revision 1 leaned on guarantees the current code does not give. These
are prerequisites, not features of v0.3.

### 3.1 A verified snapshot, not "whatever loaded"

`ConstraintStore.load` quarantines invalid, tampered and source-failing constraints, but
**authority is checked later**, per decision, in `AegisInterceptor.intercept`
(`store.is_authorized`). A compiler that took `store.constraints` would compile rules whose
author was never allowed to write them. So:

- `ConstraintStore.verified_snapshot()` returns an immutable, versioned object: the
  constraints that pass integrity, source and **authority** checks, plus everything that was
  excluded with its reason, plus a digest over **all effective inputs** (constraints,
  authority map, signers, environment map, repos/refs resolved to commit SHAs, agents list,
  plan constraints, the Aegis version). Signatures must be enforced (a key is required; no
  `--insecure`, no "unsigned: … " warnings allowed through).
- The webhook decides against a snapshot and the compiler compiles one. The digest is what
  every generated artifact and every decision log records.

### 3.2 Fix the unresolved-condition paths (a bug in the current engine)

`intercept` turns **env-unresolved** and **time-window-unresolved** matches into ESCALATE
*before* checking those constraints' integrity or authority. An unauthorised rule scoped on
`env: prod` can therefore force ESCALATE whenever an intent's environment cannot be resolved.
That breaks "an unverified constraint gets no vote" today, client-side, and would turn into a
deny server-side. Fix in v0.2.x: only verified, authorised constraints may contribute
unresolved-condition ESCALATEs; add unauthorised and mutated cases to the adversarial suite.
(Found by gpt-6-astra; confirmed in `interceptor.py`.)

### 3.3 Fix the parser's normal forms (bugs in the current engine)

The parity work (§8) depends on the CLI and the webhook naming things the same way. The
council found, and running the current parser confirms, these existing mismatches — each is
also a client-side evasion today, since a rule written for the normal form misses them:

| Command | Parsed today | Should be |
|---|---|---|
| `kubectl drain node1` | `node1/*` | `node/node1` |
| `kubectl exec api-0 -- sh` | `api-0` | `pod/api-0` |
| `kubectl delete storageclasses fast` | `storageclasses/fast` | `storageclass/fast` (also `ingressclasses`, `endpoints`) |
| `kubectl --as admin …` | `--as` dropped | recorded as `params.impersonate` **and** an `impersonate user/admin` intent, blocked by the example policy (§12, decision 4) |

Fixed for v0.2.1 (with `kubectl drain … --ignore-daemonsets`, which was rejected as malformed),
with a note in `docs/constraints.md` where a rule's normal form changes.

### 3.4 Public-key signing before any in-cluster verifier

Policy signatures today are shared-secret BLAKE2b MACs: whoever can verify can also sign
(PLAN §8). A webhook pod that verifies policy would hold a policy-*forging* key, reachable by
anyone who can read that Secret or compromise the pod. So PLAN §9 step 2 — per-principal
public-key signatures, verifiers holding only public keys — is a **prerequisite of the
webhook** (not of the compiler, which runs in CI and can use the existing key as `aegis check`
does). Git-sourced rules already verify with public keys (v0.2.0).

## 4. Identity model

### 4.1 Agents act only through agent identities

Each platform gives agents credentials that nothing else holds:

| Platform | Agent identity | Scoping key the enforcement point checks |
|---|---|---|
| Kubernetes | a dedicated ServiceAccount per agent (namespace `aegis-agents` or listed explicitly) | `request.userInfo.username` (`system:serviceaccount:<ns>:<name>`) or the group `system:serviceaccounts:<ns>` — ServiceAccounts cannot carry custom groups |
| AWS | a dedicated IAM role per agent (or per agent class) | `aws:PrincipalArn` (the role ARN, not the session) and **`aws:SourceIdentity`**, which is set when the agent session starts and cannot be changed by later role assumptions |
| GCP | a dedicated service account | `deniedPrincipals: principal://iam.googleapis.com/projects/-/serviceAccounts/<email>` |
| Azure | a dedicated managed identity or service principal | see §6.4 — Azure cannot scope a real deny to an identity |
| CI that runs an agent (e.g. a coding agent in GitHub Actions) | that workflow's own federated identity, separate from the release/deploy workflow's | a **workflow-bound** OIDC subject in the cloud's trust policy — see below |

**GitHub OIDC is not workflow-bound by default.** The default `sub` claim of a GitHub Actions
OIDC token identifies the repository plus the branch, environment or pull-request context — not
the workflow file. An agent job and a deploy job in the same repository on the same ref present
the *same* subject, so a deploy role trusting `repo:org/app:ref:refs/heads/main` can be assumed
by the agent job directly with `AssumeRoleWithWebIdentity` (denying `sts:AssumeRole` into
non-agent roles does not cover that path). So:

- deploy and other non-agent roles must trust a **customised subject that includes the
  workflow** — GitHub's OIDC subject customisation with `job_workflow_ref`, pinned to a reusable
  deploy workflow at a protected ref — or another protected issuance boundary (a GitHub
  environment with required reviewers, trusted as `…:environment:<name>`);
- agent jobs get their own role whose trust names *their* workflow;
- `aegis audit-identity` flags any role whose trust policy accepts a repository/ref-only subject
  as `workflow-unbound`.

(Reference: GitHub Actions OIDC reference, subject claims and customisation —
https://docs.github.com/en/actions/reference/security/oidc.)

`agents.yaml` (signed, operator-held, its own constraint class in `authority.yaml`) is the
single source of this list. The webhook's `matchConditions` and the compiler's principal
lists are **generated** from it, never written by hand, so the two layers cannot disagree.

### 4.2 Deny-by-default is the default

Listing agents fails **open**: an agent running with credentials nobody listed is not
restricted, which is exactly the case server-side enforcement exists for. So the default is
the inverse: `agents.yaml` names the **trusted** identities (people, CI roles, cluster
controllers, a break-glass group) and **every other identity is treated as an agent**.
`mode: agents-only` (list agents instead) is the opt-out.

This is less drastic than it sounds: an unlisted identity is not blocked from everything, only
from what the policy blocks — in practice destructive actions. The worst case for a forgotten
human or tool is "cannot delete in prod until added to the trusted list", not an outage. Two
safeguards make it safe to turn on:

- **Report first.** Enforcement requires a prior report-only run: `aegis audit-identity
  --would-restrict` lists every existing identity the compiled policy would now restrict (from
  IAM / RBAC inventory, read-only), so legitimate automation — backup jobs, cleanup functions,
  controllers — is added to the trusted list before anything is enforced.
- **Break-glass.** A named group is always excluded and cannot be removed from `agents.yaml`
  without the same review as any policy change.

### 4.3 Closing identity escapes and protecting the controls

An agent identity must not be able to act as another identity or disable its own controls.
Every generated artifact therefore includes a **self-protection block**, listed in the
coverage report, and `aegis audit-identity` checks the live permissions (read-only) before an
operator relies on the layer:

| Escape or tamper path | Kubernetes | AWS | GCP | Azure |
|---|---|---|---|---|
| Act as another identity | `impersonate` verbs; `serviceaccounts/token` create; creating Pods/Jobs/CronJobs/Deployments whose `spec.serviceAccountName` is not the agent's own; `pods/exec`/`attach` into pods running as other identities | `sts:AssumeRole` into non-agent roles; `iam:PassRole` (Lambda, ECS, EC2, CodeBuild, CloudFormation); `iam:CreateRole`, `iam:CreateAccessKey`, `iam:CreateLoginProfile` | `iam.serviceAccounts.getAccessToken` / `actAs` / `implicitDelegation`; `iam.serviceAccountKeys.create`; Cloud Build with another SA | managed identities attached to VMs/Automation; role-assignment writes |
| Remove or weaken the control | `validatingwebhookconfigurations`/`mutatingwebhookconfigurations` writes (admission webhooks are **never called** for these objects, so this must be RBAC); the Aegis namespace's Deployment, ConfigMaps, Secrets | `iam:Detach/Delete/PutRolePolicy`, `CreatePolicyVersion`/`SetDefaultPolicyVersion` on the agent role and on the compiled policy; `organizations:*Policy*` | `iam.denypolicies.*`; `setIamPolicy` on the attachment point | `roleAssignments/write`, `roleDefinitions/write`, `locks/delete`, `policyExemptions/write` |
| Delegate to an exempt actor | GitOps controllers (Argo CD, Flux) applying agent-written changes; operators acting on agent-created CRs; garbage-collection cascades | CloudFormation / Service Catalog executing with their own roles; SSM Automation | Deployment Manager, Config Connector | Deployment scripts, Automation runbooks |

Where a path is closable by generated policy it is denied; where it is structural (a GitOps
controller that must be allowed to apply reviewed changes) the fix is procedural — agents
may only propose changes through reviewed pull requests, never push to the branch a
controller applies — and the coverage report lists it as **not enforced by this layer**.

Kubernetes RBAC cannot be generated safely from policy, so for Kubernetes the self-protection
block is (a) example RBAC for agent ServiceAccounts that omits every verb above, (b) guardrail
rules in the example policy that the webhook enforces for what admission *can* see (Pod/Job
`serviceAccountName`, token requests), and (c) `aegis audit-identity` using
`SubjectAccessReview` to report any escape verb an agent identity still holds.

## 5. Kubernetes admission webhook (later; see §5.8)

### 5.1 Shape

`aegis webhook` (same package) serves `ValidatingWebhookConfiguration` requests
(`admission.k8s.io/v1` `AdmissionReview`) over HTTPS. Requirements the council added to
revision 1's "standard library only":

- bounded concurrency and request queue; `Content-Length` cap (4 MiB); header/read deadlines;
  no chunked bodies;
- TLS certificate hot-reload (cert-manager rotation); optional verification of the API
  server's client certificate; a `NetworkPolicy` allowing only the API server;
- `/metrics` and health on a separate port;
- decision logs that never include `object`/`oldObject` (Secrets arrive in AdmissionReview);
- responses echo `request.uid`; registration sets `sideEffects: None` (required for dry-run
  requests to be sent at all) and `admissionReviewVersions: ["v1"]`.

Deployment: `Deployment` with ≥2 replicas spread across nodes, `PodDisruptionBudget`,
`minReadySeconds`, resource limits, read-only root filesystem, non-root, tzdata in the image
(time windows fail closed without it). Manifests and a Helm chart in `deploy/kubernetes/`;
image to GHCR from the release workflow.

### 5.2 Registration and scoping

- **Minimum Kubernetes 1.30** (`matchConditions` GA). No fallback: without `matchConditions`,
  `failurePolicy: Fail` turns a webhook outage into a cluster-wide write outage.
- `matchConditions` generated from `agents.yaml`, guarded against missing fields
  (`has(request.userInfo.groups) && …`) — a CEL *error* under `failurePolicy: Fail` rejects
  the request for everyone the `rules` match.
- **No `namespaceSelector` exclusions** (revision 1 excluded `kube-system` and the webhook's
  own namespace, which let an agent act there unchecked). Identity scoping already keeps
  controllers out; nothing needs excluding.
- `rules`: all resources and operations, including CONNECT and the subresources in §5.3 —
  volume is bounded by `matchConditions` — so a new rule for a new kind never silently lacks a
  registration.
- A request that reaches Aegis from an identity **not** in `agents.yaml` means the layers
  disagree: deny with a distinct reason and alert (only an explicit
  `--unknown-identity=allow` changes that).

### 5.3 From `AdmissionReview` to intents

A shared, versioned **resource registry** maps `(group, version, resource, subresource)` to
Aegis's normal form, used by both the kubectl parser and the webhook. `kind.kind` is not used
(a scale request carries kind `Scale`, exec `PodExecOptions`, eviction `Eviction`).

| Request | Intent(s) |
|---|---|
| CREATE / UPDATE / DELETE on a resource | `create` / `update` / `delete` on `<singular>/<name>`; name from `request.name`, else `object.metadata.name`/`oldObject.metadata.name`, else `<singular>/*` (`generateName`) |
| UPDATE, derived from the object diff | additional intents: `scale` (`spec.replicas` changed; `params.replicas`), `set-image` (container image changed), `cordon` (`spec.unschedulable` → true), `rollout-restart` (`restartedAt` annotation changed) |
| `*/scale` subresource | `scale` on the parent `<singular>/<name>` |
| `pods/eviction` CREATE (what `kubectl drain` does) | `delete` on `pod/<name>` (+ `drain` on the node when the node is known) |
| CONNECT `pods/exec`, `pods/attach`, `pods/portforward`, `pods/proxy`, `services/proxy`, `nodes/proxy` | `exec`, `attach`, `port-forward`, `proxy` on the parent |
| DELETE `namespaces/<n>` | `delete namespace/<n>` **and** the same synthetic `*/*` cascade intent (scoped `namespace: <n>`) the kubectl parser emits, so namespace-scoped rules decide the same way on both layers |
| any request with `dryRun: true` | evaluated; allowed with the would-be verdict as a warning (Aegis's dry-run convention; Kubernetes itself would allow denying dry runs) |

The verdict is the most restrictive across all intents for the request. Cascades performed by
controllers (the namespace controller deleting a namespace's contents, garbage collection)
**do** pass admission, but under controller identities outside the agent scope — which is why
the webhook must stop the initiating request (the namespace DELETE) itself.
`deletecollection` is admitted **per item** (`operation: DELETE`) by the generic registry;
this must be verified on `kind` for every supported minor version, and a collection delete is
**not atomic** — denied items remain, others are deleted, and the client gets an aggregate
error. Both facts go in the docs.

Client-only actions with no admission equivalent (`apply` of a manifest file as such,
`label`, `annotate`, `taint`) are listed in the coverage report; policy authors are told to
write rules on `create`/`update`/`delete` when they want both layers to hold.

### 5.4 Engine settings and response

The webhook pins interceptor settings: `on_untrusted_match="discard"` (a quarantined or
unauthorised rule must never be able to deny); `fail_closed` off by default; unresolved
env/time-window ESCALATE only from verified rules (§3.2); **rate limits not enforced**
server-side in v0.3 (a per-replica ledger would multiply limits) — reported in coverage.

| Verdict | AdmissionResponse |
|---|---|
| ALLOW | `allowed: true` |
| BLOCK | `allowed: false`, `code: 403`, message `aegis: BLOCK: <citations>` |
| ESCALATE | `allowed: false`, message `aegis: needs human approval (<citations>) — stop and hand this to a person`. It does **not** say "retry as a human", which would invite the agent to look for other credentials |
| discarded matches | short `warnings` (the API server truncates long ones) |

Audit annotations are prefixed by the API server with the webhook name
(`<webhook>/decision`) and appear at `Metadata` audit level and above.

### 5.5 Policy delivery, reload and freshness

- The webhook loads one **versioned policy bundle** (all files + signatures, Git sources
  pinned to commit SHAs) delivered as an immutable ConfigMap/Secret per version (no `subPath`
  mounts, which never update), or fetched by a sidecar into a fresh directory and swapped in
  by rename. Never a half-updated directory.
- A new bundle is verified into a snapshot (§3.1) off the request path and swapped in with one
  atomic reference update across worker threads.
- **Rollback protection**: a bundle carries a monotonically increasing version; an older
  version is refused even if validly signed.
- **Freeze protection, enforced per request**: once the running snapshot is older than
  `--max-policy-age` (no newer bundle has verified), **every AdmissionReview is rejected by the
  handler itself without evaluating the expired snapshot** (`allowed: false`, reason
  `policy-expired`). Readiness turning false and an alert are *additional* signals, not the
  mechanism: a failed readiness probe only changes endpoint routing and leaves the container and
  its HTTPS listener running, so requests on connections established before expiry, or routed
  before endpoints propagate, would otherwise still be answered from the stale snapshot. An
  attacker who can make every new bundle fail verification therefore cannot keep an old policy
  deciding past the limit. (Kubernetes probes: https://kubernetes.io/docs/concepts/workloads/pods/probes/.)
- A revocation (a rule removed or an authority withdrawn) that arrives in a *valid* newer
  bundle takes effect on swap; "keep the last good snapshot" applies only when the new bundle
  is unusable, and is bounded by the same age limit.

### 5.6 Failure behaviour

| Condition | Result |
|---|---|
| Webhook unreachable / times out (`timeoutSeconds: 5`) | `failurePolicy: Fail` → **agent** writes denied; humans and controllers unaffected (scoped by `matchConditions`) |
| No usable snapshot at startup | not Ready → same as unreachable |
| Unusable new bundle | keep serving the current snapshot until `--max-policy-age`; after that the handler rejects every request (`policy-expired`) and readiness turns false |
| Request the registry cannot map | deny with reason `unmappable` (the request came from an agent) |

Break-glass: the `ValidatingWebhookConfiguration` is owned by the platform team; deleting it
(or setting `failurePolicy: Ignore`) is the documented emergency switch, and — because agents
cannot write webhook configurations (§4.3) — only humans can pull it.

### 5.7 Observability

JSON decision records (verdict, intents, citations, discarded rules, snapshot digest,
request UID, actor) to stdout for the cluster's log pipeline; Prometheus metrics
(`aegis_decisions_total{verdict}`, latency histogram, snapshot age, reload failures, denials
caused by outage vs policy). Alert on reload failures and on snapshot age.

### 5.8 The webhook's role after decision 3

Kubernetes enforcement is primarily **compiled** (§6.6, ValidatingAdmissionPolicy), with no
service to run. The webhook in this section is for what a compiled policy cannot express —
recurring time windows, decisions that need the full engine at request time — and ships later
(§10). Everything in §5 still applies to it when it does.

## 6. Policy compiler (clouds and Kubernetes)

### 6.1 Model

`aegis compile <target> --out DIR` builds a verified snapshot (§3.1) and emits:

- the native policy documents, split to fit each platform's size and count limits (the build
  fails loudly if they cannot fit);
- `coverage.json` / `coverage.md`: every constraint in the policy with
  `exact` / `over-enforced (why)` / `not enforced (why)` and, for excluded constraints, the
  exclusion reason (tampered, forged, unauthorised, …). **Under-enforcement is never labelled
  an approximation**: it is `not enforced`. The report also lists, per rule, *same-effect
  actions not covered* (blocking `s3:DeleteBucket` does not stop emptying the bucket or
  expiring it by lifecycle rule; blocking RDS delete does not stop disabling deletion
  protection first);
- the self-protection block (§4.3) as its own statements;
- `manifest.json`: the snapshot digest (§3.1), the Aegis version, the target account/project,
  the compiled output's digest, and a map from native statement ids to rule ids (AWS `Sid`
  allows only `[A-Za-z0-9]`, so statements are `Aegis<n>`).

The output is a policy artifact: generated in CI, reviewed, signed, applied by the operator's
IaC with the operator's credentials. Aegis never holds cloud write credentials.

**Drift** is checked at two levels: `aegis compile --check DIR` (the committed output still
matches the current policy) and `aegis compile --verify-live` (read-only credentials, run by
the operator: the policy actually attached to each agent identity matches the committed
output, and the attachment itself is present). The snapshot digest is embedded in the live
policy's description/tags so a deployed policy identifies itself.

### 6.2 Environments compile exactly, from `environments.yaml`

Revision 1 compiled `scope.env` to resource tags. A tag-based Deny does not apply when the tag
is absent (untagged production resources would be unprotected) and the agent could remove the
tag first — the opposite of the CLI, where an unresolved environment escalates. Instead: the
compiler knows which account / project / subscription it is compiling for, and
`environments.yaml` already maps those to environments, so an `env: prod` rule compiles
**into the prod account's policy, unconditionally**. Tags are an operator opt-in only, and then
the compiler also emits a deny for untagged resources (`Null` condition) and a deny on
changing the env tag key, and reports each action whose API does not support the tag
condition key as not enforced.

### 6.3 What compiles

| Aegis construct | Native equivalent | Coverage |
|---|---|---|
| `effect: BLOCK` on (provider, action, resource pattern) | explicit Deny on the mapped permissions and resources | exact where the action map says so; resource *name* patterns are not expressible on GCP (§6.5) |
| `effect: ESCALATE` | Deny (clouds cannot ask) | over-enforced; the client hook's "ask" flow no longer succeeds for that action — the hook says so for compiled rules; `--escalate=omit` leaves them client-only |
| `scope.env` | the target account/project (§6.2) | exact |
| `scope.region` etc. | condition keys where the action supports them (`aws:RequestedRegion` — global services report `us-east-1`) | per the action map |
| `time_window` (recurring) | none: AWS has absolute-time conditions only; GCP deny policies support tag conditions only; Azure RBAC has none | not enforced; stays client-side. No scheduler: it would need standing IAM write credentials and fail open when it breaks |
| `rate_limit`, plan (batch) constraints | none | not enforced; client-side / CI |
| glob character classes, case-insensitive intent | no IAM/GCP equivalent | over- or not enforced as the action map decides, never silently |

### 6.4 Action map

`src/aegis_core/compile/actions/<target>.yaml`, versioned and reviewed like policy, maps each
(provider, action, resource type) the parsers produce to, per target: the native permission
names; whether the permission is deniable (GCP deny policies support only a listed subset);
the resource name/ARN form; which condition keys the action supports; and the same-effect
actions. Anything not in the map is `not enforced` — never widened silently. Validation
against the platforms' own tools (IAM Access Analyzer `validate-policy`, the IAM policy
simulator, GCP Policy Troubleshooter) and a sandbox acceptance run are required before a
mapping is marked `exact`; the offline evaluator (§8) checks consistency, not truth.

### 6.5 Per cloud

**AWS (first).** Preferred output: a **Service Control Policy** scoped with
`aws:PrincipalArn` / `aws:SourceIdentity` to agent roles — it sits above the account, so an
agent with IAM rights in the account cannot detach it. SCPs do not apply to the management
account or to service-linked roles; both go in the coverage report. Fallback (no
Organization): an identity policy or **permissions boundary** on the agent roles, with the
self-protection block denying changes to them. Limits handled by splitting: managed policy
6,144 characters, 10 managed policies per role by default, SCP 5,120 characters and 5 SCPs per
target.

**GCP (second).** An IAM **deny policy** with `deniedPrincipals` from `agents.yaml`,
`deniedPermissions` in the deny-specific form (`cloudresourcemanager.googleapis.com/projects.delete`,
not `resourcemanager.projects.delete`) and only permissions GCP supports in deny policies.
Denial conditions support **resource-tag functions only**, so a rule on a resource *name*
pattern is either over-enforced at the attachment point (project/folder) or not enforced — the
report says which. Limits: 500 deny policies and 500 deny rules per resource.

**Azure (deferred, redesigned).** Revision 1's custom-role `NotActions` output is dropped: it
is not a deny (any other role assignment grants the action back) and does not constrain an
identity with a broader role elsewhere. Azure Policy `deny`/`denyAction` cannot select the
caller, and `denyAction` covers deletes only. The one user-reachable real deny is **deployment
stacks' deny settings** (`denyDelete` / `denyWriteAndDelete`), which create deny assignments
that apply to **everyone except** up to five excluded principals (use groups) — the inverse of
agent scoping, and only for stack-managed resources. Azure support is deferred until that model
(protect named critical resources from everyone but a human group) is evaluated against real
use; locks remain an "everyone" control for named resources. Blueprints (being retired) is not
used.

### 6.6 Kubernetes: ValidatingAdmissionPolicy (the primary Kubernetes target)

`aegis compile kubernetes --cluster <name>` compiles the verified snapshot to
`ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding` objects (CEL, GA in
Kubernetes 1.30). The API server evaluates them **in-process**: no webhook service to keep up,
no network hop, and no policy key in the cluster — verification happened at compile time, as
for the clouds.

- **Scoping**: `matchConditions` on `request.userInfo` generated from `agents.yaml` (deny-by-
  default: `!(request.userInfo.username in trusted) && !(<trusted groups> …)`), guarded with
  `has()`; the break-glass group always excluded.
- **Environment**: compiled per cluster, from `environments.yaml` (a cluster/context maps to an
  env), exactly like the per-account cloud compile (§6.2).
- **What compiles**: BLOCK / ESCALATE (as deny) on operation + resource + name pattern +
  namespace, using `request.operation`, `request.resource`, `request.subResource`,
  `request.name`, `request.namespace`, `object`/`oldObject` — so the diff-derived actions of
  §5.3 (scale, set-image, cordon, restart), eviction-as-delete, `serviceAccountName` guardrails
  and the namespace cascade are all expressible. `validationActions: [Deny, Audit]`.
- **What does not**: recurring time windows, rate limits, anything that needs the full engine
  at request time. Those stay client-side or wait for the webhook. **Time, checked
  2026-09-28:** the ValidatingAdmissionPolicy CEL environment has no clock. Its variables are
  `object`, `oldObject`, `request`, `params`, `namespaceObject`, `authorizer` and `variables`
  (none carries a request time), and neither standard CEL nor any Kubernetes CEL library
  (strings, lists, regex, URL, IP/CIDR, authorizer, quantity, semver, format) provides a
  current-time function — CEL's `timestamp()` / `duration()` only operate on values supplied
  to them. (Sources: kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/,
  kubernetes.io/docs/reference/using-api/cel/.) Server-set object timestamps such as
  `metadata.creationTimestamp` are not a substitute: they exist only for some operations
  (a DELETE carries the object's *original* creation time) and are not a clock. So time windows
  are `not enforced` by the VAP target, by design; the `kind` CI job (§8) adds a test that a
  policy using a clock function is rejected by the API server, to catch a future change.

**Verified live, 2026-09-28** (a local `kind` cluster, Kubernetes v1.37.0):

| Claim in this design | Result |
|---|---|
| VAP has no clock | Confirmed. `now()` and `time.now()` → `undeclared reference to 'now'`; `request.requestTime` and `request.time` → `undefined field`; all rejected when the policy is created. A plain expression was accepted as a control. |
| Identity scoping via `matchConditions` on `request.userInfo.username` | Confirmed. A policy scoped to `system:serviceaccount:agents:claude` denied that account's `delete namespace` with the Aegis message; the same delete by an admin succeeded. |
| Admission policies cannot protect admission-policy objects; RBAC must (§4.3, §6.6) | Confirmed. A VAP denying DELETE of `validatingadmissionpolicies`/`…bindings` for everyone did **not** stop the agent deleting its own binding; five seconds later (after propagation) the agent deleted the namespace. |
| `deletecollection` is admitted per item, and `request.name` is empty (§5.3) | Confirmed. The collection DELETE was evaluated per item with `request.name` empty (the error names `"Unknown"`) and the item's name in `oldObject.metadata.name`. The compiler must read the name from `oldObject` for DELETE. |
| A collection delete is not atomic (§5.3) | Confirmed, and it stops at the first denial: with only `cm2` denied, `cm1` was deleted, `cm2` refused, and `cm3` left untouched. |
| `kubectl delete … --all` | Sends one DELETE per object (not the collection API); each was evaluated and denied separately. |
- **Self-protection**: the compiled bindings and policies are themselves cluster objects;
  agents must not be able to write `validatingadmissionpolicies`/`…bindings` (RBAC, §4.3), and
  `aegis audit-identity` checks it. Like webhook configurations, these objects are not
  subject to admission by themselves, so RBAC is the control.
- **Limits**: CEL cost budgets per expression; the compiler splits rules across policies and
  fails loudly if an expression exceeds the budget.

## 7. Terraform / OpenTofu and Git

- **Plan gate**: a GitHub Actions example that runs
  `terraform show -json plan.out | aegis check terraform - --exit-style ci`, as a required
  status check, in a workflow agents cannot edit (CODEOWNERS on `.github/workflows`, rulesets),
  binding the check to the exact saved plan that is applied. It is only a control if the
  **apply credentials exist only in that pipeline**; an agent holding apply credentials
  locally bypasses it, which the SCP of §6.5 then has to cover.
- **GitHub rulesets**: `aegis compile github` emits rulesets (block force-push and deletion of
  protected branches, require the Aegis status check) with **bypass actors** set to the human
  teams — "everyone except people", the same shape as Azure deployment stacks. Plan limits on
  private repositories are reported. Anything else in the policy is `not enforced`.

## 8. Testing

- **Parity corpus with equivalence classes.** Each case is an action expressed as a kubectl
  argv, an `AdmissionReview`, and (for cloud resources) an API call, labelled *identical*,
  *CLI-only* or *server-only*. Verdicts must agree within *identical*; the other classes must
  appear in the coverage reports. Built after the §3.3 parser fixes.
- **Webhook**: unit tests on `AdmissionReview` fixtures (every operation and subresource,
  generateName, eviction, namespace cascade, diff-derived intents, dry run, identities outside
  `agents.yaml`, unmappable requests, oversized bodies); a `kind` cluster in CI that installs
  the chart and checks: an agent ServiceAccount's `delete node` is denied and an admin's is
  not; `deletecollection` is per item; an agent cannot delete the webhook configuration or
  create a Pod under another ServiceAccount (RBAC + guardrail rules); reload with a valid,
  an invalid, an older (rollback) and a stale bundle — including a request delivered over a
  connection established *before* the snapshot expired, which must be rejected.
- **Compiler**: golden files per target; an offline evaluator for emitted AWS/GCP policies
  (consistency, not a claim of truth); size-limit splitting; every non-enforceable construct
  appears in coverage; a sandbox acceptance run per mapping before it is marked `exact`.
- **Adversarial**: tampered, forged, **unauthorised-but-loaded** and mutated rules never
  appear in any compiled output and never change a webhook decision; unresolved-condition
  paths included (§3.2).
- **Identity**: `aegis audit-identity` against a `kind` cluster with a deliberately
  over-privileged agent reports each escape verb; against an AWS trust-policy fixture it flags a
  deploy role that accepts a repository/ref-only GitHub OIDC subject (`workflow-unbound`).

## 9. Threats: what each layer stops

| Threat | Client hook | Kubernetes (compiled VAP; webhook later) | Compiled cloud policy | Remains open |
|---|---|---|---|---|
| Agent runs a blocked command through its shell | stopped | stopped | stopped | — |
| Agent calls the API directly (SDK, script, console) | not seen | stopped | stopped | — |
| Poisoned / unauthorised rule steers a decision | no vote | no vote (pinned `discard`, §3.2 fix) | never compiled | — |
| Agent acts through another identity (pod SA, assumed role, impersonation) | `--as` blocked by policy | guardrail rules + RBAC | self-protection block | whatever `aegis audit-identity` reports |
| Agent removes the control (webhook config, detaches policy) | — | RBAC (admission cannot see webhook configs) | self-protection; SCP preferred | Azure (deferred) |
| Agent proposes a change a controller applies (GitOps, CloudFormation) | — | controller identity is out of scope | out of scope | **procedural**: agents only open reviewed PRs |
| Time-windowed and rate-limited rules | enforced | time windows enforced; rate limits not | not enforced | rate limits server-side (broker) |
| Webhook down | — | agents blocked (fail closed for agents) | unaffected | availability of agent work |
| Stale or replayed policy | Git freshness (v0.2) | rollback + age limits | `--check` / `--verify-live` | — |

## 10. Phasing

Revised on the council's advice and decisions 1 and 3: fix what exists first; ship the static,
compiled layers (no service to run, no key in a cluster) before the runtime webhook.

| Release | Scope |
|---|---|
| **v0.2.1** | §3.2 interceptor fix; §3.3 parser normal-form fixes; kubectl impersonation as an `impersonate` intent, blocked by the example policy (decision 4). *(Implemented, awaiting review.)* |
| **v0.3.0** | `ConstraintStore.verified_snapshot()` (§3.1); `agents.yaml` with deny-by-default (§4.2); `aegis compile aws` (SCP-first, self-protection block, coverage with enforcement direction, `--check`, manifest, size splitting); `aegis audit-identity` for AWS incl. `--would-restrict`; Terraform plan-gate example; action map for the resource types the parsers produce |
| **v0.3.x** | `aegis compile kubernetes` → ValidatingAdmissionPolicy (§6.6); shared resource registry with the kubectl parser; `aegis audit-identity` for Kubernetes; parity corpus (CLI ↔ compiled VAP) on a `kind` cluster |
| **v0.4.0** | PLAN §9 step 2 — public-key signing |
| **v0.4.x** | `aegis webhook` for what VAP cannot express (time windows, full-engine rules); `aegis compile gcp`, `aegis compile github`, `--verify-live` |
| later | Azure (deployment-stack model, after evaluation); credential broker, JIT elevation, database, TFC run task (§11) |

## 11. Out of scope, recorded for later

- **Cloud credential broker**: agents hold no cloud credentials; a gateway executes a call
  only after an Aegis decision. The only way to get per-request decisions, ESCALATE with a
  human, and rate/batch rules on cloud APIs. Its own threat model; candidate for a separate
  repository.
- **Just-in-time elevation** as the ESCALATE path for clouds and Kubernetes.
- **Database enforcement**: generated least-privilege roles for agents, or a SQL proxy.
- **Terraform Cloud run task** endpoint.

## 12. Decisions

Revision 1's six questions were answered unanimously by the council and are now in the text:
`deletecollection` is per item and non-atomic, verified on `kind` (§5.3); ESCALATE denies in
the webhook with a hand-off message (§5.4); time windows are not compiled and there is no
scheduler (§6.3); Azure `NotActions` is dropped (§6.5); `agents.yaml` is signed, operator-held
and generates `matchConditions` (§4.1); Kubernetes ≥1.30 with no fallback (§5.2).

Revision 2's four questions, decided 2026-09-28:

1. **Phasing: compiled layers first.** AWS compiler in v0.3.0, the Kubernetes compiler to
   ValidatingAdmissionPolicy in v0.3.x, the webhook after public-key signing (§10). The AWS
   compiler closes the costliest bypass (direct cloud API calls) with no runtime risk and no new
   prerequisite; VAP gives Kubernetes the same without waiting for the webhook's prerequisites.
2. **Deny-by-default is the default** (§4.2), with a mandatory report-only run and an
   always-excluded break-glass group; `mode: agents-only` is the opt-out. Listing agents fails
   open for the agents nobody anticipated.
3. **ValidatingAdmissionPolicy is the primary Kubernetes target** (§6.6); the webhook becomes
   the add-on for rules it cannot express (§5.8).
4. **kubectl impersonation is blocked through policy, not hard-coded** (§3.3): the parser
   emits an `impersonate` intent per impersonated identity and the example policy blocks it
   (`block-kubectl-impersonation`); a team can change it to ESCALATE. ESCALATE was rejected as
   the default: on Codex, Gemini CLI and OpenCode it is a block anyway, and where it asks, an
   approval still runs the command *as the impersonated identity* — the privilege jump the rule
   exists to stop. Agent roles should not hold `impersonate` at all; `aegis audit-identity`
   checks it.

## 13. Council findings and what changed

All three reviewers returned **"revise before implementing"** and agreed on the central point:
identity scoping was assumed, not designed, and every artifact could be removed or bypassed by
the identity it constrained. Findings raised by more than one reviewer are marked ×2 or ×3.

| Finding (reviewers) | Change |
|---|---|
| Compiler would compile unauthorised rules: authority is checked at decision time, not load (×3: Astra P0-1, Fable P0-1, Opus implied) | §3.1 verified snapshot |
| Unresolved env/time-window paths let unverified rules force ESCALATE — existing bug (Astra P0-2) | §3.2 |
| Identity laundering: pods under other SAs, impersonation, AssumeRole/PassRole, SA tokens, GitOps delegation (×3) | §4.3 closure table, `audit-identity`, deny-by-default §4.2 |
| Controls removable by the constrained identity; webhooks never called on webhook configs; namespace exclusions are holes (×3) | §4.3 self-protection; §5.2 no exclusions; SCP-first §6.5 |
| Shared-MAC key in the cluster is a signing oracle (Opus P1-9, Fable P0-3) | §3.4 public-key signing before the webhook; §10 |
| `scope.env` → tags fails open on missing tags; agent can untag (×3) | §6.2 compile env from `environments.yaml` |
| Azure `NotActions` is not a deny; deployment stacks omitted; Blueprints retiring (×3) | §6.5 Azure dropped/redesigned, deferred |
| GCP deny permission format wrong; supported subset; tag-only conditions (×3) | §6.4 map fields, §6.5 GCP |
| `kind.kind` wrong for subresources; empty names on generateName (×3) | §5.3 resource registry |
| One intent per request loses scale/image changes and the namespace cascade; CLI verbs have no admission form (×3) | §5.3 diff-derived intents, cascade intent, client-only list |
| Namespace-deletion statement was wrong (controller deletes do pass admission, under a controller identity) (×3) | §5.3 corrected |
| Existing parser bugs: drain, exec, plural kinds, `--as` discarded (Opus P2-19, Fable P1-11, P0-4) | §3.3 |
| `matchConditions` example used a custom group ServiceAccounts cannot have; CEL errors reject everyone (Fable P1-5, Opus Q5) | §4.1, §5.2 |
| No fallback below 1.30 (×3) | §5.2 |
| Two identity lists can diverge; fail-open on disagreement (Astra P1-17, Fable P1-7) | §4.1 single source; §5.2 disagreement denies |
| Reload: replayed older bundle, freeze by failing verification, torn multi-file updates (×3) | §5.5 |
| Interceptor settings unspecified (`discard` pin, ledger per replica) (Opus P1-11, Astra P1-21) | §5.4 |
| Webhook hardening: body caps, timeouts, TLS rotation, NetworkPolicy, log hygiene, `sideEffects`, UID echo (×3) | §5.1 |
| ESCALATE message invited credential hunting (Opus P2-16) | §5.4 |
| ESCALATE→Deny defeats the client "ask" flow for compiled rules (Fable P1-16) | §6.3 |
| Drift checked repo-to-repo only; `constraints_sha256` covers one file (×3) | §3.1 digest over all inputs; §6.1 `--verify-live` |
| AWS `Sid` alphanumeric only; policy size and count limits; SCP limits (×3) | §6.1, §6.5 |
| Same-effect actions (empty bucket, disable deletion protection) (Opus P2-15, Astra P1-23) | §6.1 coverage field, §6.4 |
| Time-window scheduler needs write credentials and fails open (×3) | §6.3 no scheduler |
| Terraform gate bypassable if the agent holds apply credentials; workflow editable (Astra P1-27, Fable P3-26) | §7 |
| GitHub rulesets have bypass actors — use "everyone except humans" (Fable P2-23, Opus P3-21) | §7 |
| Parity must use equivalence classes; self-written evaluator is not proof (Astra P1-26, Fable P2-22) | §8 |
| ValidatingAdmissionPolicy as an in-API-server alternative (Opus P3-22) | §5.8, question 3 |
| Phasing: compile AWS first; fix existing bugs first; public-key signing before the webhook (×3) | §10 |

Review of revision 3 (PR #14): GitHub OIDC default subjects are repository/ref-scoped, not
workflow-scoped — deploy roles must trust a workflow-bound subject and `audit-identity` flags
the rest (§4.1); the snapshot age limit is enforced by the handler on every request, not only by
readiness (§5.5, §5.6, §8).
