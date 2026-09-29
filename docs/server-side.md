# Server-side enforcement

The coding-agent hook stops a destructive command **before it runs on the agent's machine**. It
cannot stop an agent that calls a cloud API some other way: an SDK, a script it wrote, a
credential it found. Server-side enforcement compiles the same verified policy into the
platform's own controls, so the platform refuses the call whatever the client.

← back to the [README](../README.md) · design: [`dev/DESIGN-v0.3-server-side.md`](dev/DESIGN-v0.3-server-side.md)

> **Status: preview.** `aegis compile aws` is implemented, and every action mapping was verified
> on 2026-09-28 in a sandbox AWS Organization: compiled SCPs denied each mapped action to an agent
> identity and allowed it to trusted, break-glass and path-qualified SSO roles, by live calls and
> the IAM policy simulator ([`dev/aws-acceptance/`](dev/aws-acceptance/README.md)). A mapping
> added later starts unverified, and the coverage report says so per rule.

## How it fits together

1. **The verified snapshot.** Compilers start from `aegis snapshot`: only constraints that are
   signed, intact, authorized and source-verified. A tampered, forged or unauthorized rule never
   reaches a compiled policy ([CLI: Verified snapshot](cli.md#verified-snapshot)).
2. **The identity model.** A cloud API sees which identity made the call, not who typed the
   command, so compiled policies apply to agent identities. `agents.yaml` says which those are —
   by default every identity you have not listed as trusted
   ([Configuration: agents.yaml](configuration.md#agentsyaml-identity-model)).
3. **The compiler** writes policy files, a coverage report and a manifest. Aegis never holds
   cloud write credentials: you review the output and apply it with your own infrastructure as
   code.

## AWS: Service Control Policies

```bash
aegis compile aws --account 123456789012 --out build/aegis-aws
```

A **Service Control Policy** sits above the account, so an agent holding IAM rights inside the
account cannot detach it. Every statement is an explicit `Deny` with the identity model's
condition:

- `deny-by-default`: applies unless `aws:PrincipalArn` is a trusted or break-glass role/user, or
  `aws:SourceIdentity` a trusted source identity;
- `agents-only`: applies when `aws:PrincipalArn` is a listed agent (or its `aws:SourceIdentity`
  is), and never to break-glass.

`--account` is the **member account** the SCPs attach to. Its environment comes from
`environments.yaml` (`aws.accounts`), so an `env: prod` rule compiles into the prod account's
policy unconditionally and is left out of the others. An account with no environment mapping
gets env-scoped rules unconditionally (over-enforced, as the CLI escalates an unresolved
environment).

### What compiles

| Policy construct | In the SCP | Coverage |
|---|---|---|
| `BLOCK` on (aws, action, resource pattern) | `Deny` on the mapped IAM actions and ARNs | exact, as far as the action map goes |
| `ESCALATE` | `Deny` (a cloud API cannot ask) | over-enforced; `--escalate omit` leaves them client-only |
| `scope.env`, `scope.account` | compiled per account | exact |
| `scope.region` | `aws:RequestedRegion` | exact; over-enforced for global services (IAM, Route 53, Organizations) |
| other scope keys (`profile`, parameters) | dropped | over-enforced: the deny applies more widely |
| resource name patterns | ARN globs; a rule covering every name denies the action on any resource | exact for `*`/`?`; a `[...]` class becomes `?` (over-enforced). "Any resource" includes another account's resources reached cross-account, which the CLI blocks too |
| recurring `time_window`, `rate_limit` | none | not enforced: stays client-side |
| a resource type or action not in the action map | none | not enforced — never widened |
| rules for other providers | none | not applicable |

The action map (`src/aegis_core/compile/actions/aws.yaml`) is keyed by what the CLI parser
produces (`ec2/instance`, `s3/bucket`, `rds/db-instance`, …), so a rule written for the CLI
compiles. For each rule the coverage report also lists **same-effect actions** it does not block
— deleting a bucket's objects through a lifecycle rule, removing a stack's resources by updating
its template — so a rule never looks stronger than it is.

### Self-protection

Every compile includes statements that stop an agent from becoming an exempt identity or
escaping the policy (design §4.3). In `deny-by-default`:

- no `sts:AssumeRole` into a trusted or break-glass role, and no `iam:PassRole` of one;
- no changes to a trusted role's trust or permissions (e.g. to let the agent assume it), and no
  new credentials for a trusted user;
- no setting an exempt source identity on a session (`sts:SetSourceIdentity` with that value);
- no `organizations:LeaveOrganization` (an account outside the organization sheds its SCPs).

`agents-only` instead restricts agents to assuming and passing agent roles, and to creating no
new users or keys (they would be unlisted, hence exempt).

What this layer **does not** enforce is listed in every coverage report: the management account
and service-linked roles (SCPs never apply to them), federated role assumption
(`AssumeRoleWithWebIdentity`/`SAML`, which depends on trust policies — keep CI subjects
workflow-bound), and delegation to services that already run with exempt roles.

### Output

```
build/aegis-aws/
  manifest.json        snapshot digest, identity-model hash, per-file sha256, Sid → rule map
  coverage.json        every constraint: exact / over-enforced / partial / not-enforced / not-applicable
  coverage.md          the same, for review
  report-only/scp-1.json   while agents.yaml says enforcement: report-only
  scp-1.json               once it says enforce
```

Statements merge exactly — same resources pool their actions, same actions pool their
resources, never creating an action/resource pair that was not compiled — so the identity
condition is repeated as little as possible. SCP files are minified and each fits the
5,120-character limit; statements are split across up
to `--max-policies` SCPs (default 4, since one of the five a target can hold is usually
`FullAWSAccess`). If the policy cannot fit, the compile fails rather than drop anything.
Statement ids are `Aegis1`, `Aegis2`, … (AWS allows only alphanumerics); `manifest.json` maps each
to its rule or self-protection entry. `policy_description` identifies the snapshot, so put it in
the SCP's description when you attach it.

### Report first, then enforce

With `enforcement: report-only` (the default) the policies land under `report-only/` and the
manifest says `"deployable": false`. Review `coverage.md`, find every existing identity the
policy would restrict (`aegis audit-identity aws --would-restrict`, see
[CLI: Identity audit](cli.md#identity-audit)) and add the
legitimate ones — backup jobs, cleanup functions, deploy roles — to `trusted`. Then set
`enforcement: enforce` in `agents.yaml`, sign it, and compile again.

### Keep it in sync

```bash
aegis compile aws --account 123456789012 --check build/aegis-aws
```

exits 1 and names every file that is missing, different or stale. Run it in CI next to the
committed output so a policy change without a recompile fails the build.

## Kubernetes: ValidatingAdmissionPolicy

```bash
aegis compile kubernetes --cluster prod-us-east --out build/aegis-k8s
kubectl apply -f build/aegis-k8s/policies.yaml
```

The API server evaluates **ValidatingAdmissionPolicies** itself (CEL, GA since Kubernetes
1.30): there is no webhook to run and no policy key in the cluster. Each compiled rule becomes
one policy and one binding, labelled `app.kubernetes.io/managed-by: aegis`. Every policy carries
a `matchConditions` expression generated from `agents.yaml`, so it applies only to agents, and
fails closed (`failurePolicy: Fail`).

`--cluster` is the cluster or kube context name; its environment comes from `environments.yaml`
(`kubernetes.clusters`, then `contexts`), so an `env: prod` rule compiles only into the prod
cluster's policies.

**The control plane is always exempt in `deny-by-default`**: `system:*` users other than
ServiceAccounts (the controller manager, scheduler, kubelets), `system:nodes` and kube-system
ServiceAccounts. Restricting them would stop the ReplicaSet controller replacing pods or the
namespace controller emptying a namespace you meant to delete. List your own controllers (Argo
CD, Flux) in `trusted`.

### What compiles

| Rule | At admission | Coverage |
|---|---|---|
| `delete` | DELETE; for pods also the eviction a `kubectl drain` sends. The name comes from `request.name`, else the object's — a `delete --all` is admitted per item with an empty `request.name` | exact |
| `create`, `run` | CREATE (an object created with `generateName` has no name yet, so a name-specific rule does not match it) | exact |
| `update`, `patch`, `edit`, `replace` | UPDATE — all the same request at the API | exact |
| `scale` | the `scale` subresource, or an UPDATE that changes `spec.replicas` | exact |
| `set-image`, `rollout-restart`, `rollout-undo`, `cordon`, `taint`, `label`, `annotate` | an UPDATE whose old and new objects differ in that field (images: containers and init containers) | exact (`rollout-undo`: any pod-template change, metadata included) |
| `drain` | its cordon; its pod evictions are not tied to the node at admission | partial — add a pod `delete` rule |
| `exec`, `attach`, `port-forward` | CONNECT on the pod subresource | exact |
| `delete` on `*/*` scoped to a namespace | also DELETE of that namespace (the client parser emits the same cascade) | exact |
| `scope.namespace` | `request.namespace`, which must be non-empty | exact; a cluster-scoped kind has no namespace, so it is not enforced there (the client never matches it either) |
| `scope.env` / `cluster` / `context` | compiled per cluster | exact |
| other scope keys | dropped | over-enforced |
| name and namespace globs | RE2 regular expressions | exact |
| a kind that is not built in (a CRD) | that resource name in any API group | over-enforced |
| `ESCALATE` | Deny (admission cannot ask) | over-enforced; `--escalate omit` leaves it client-only |
| reads, `logs`, impersonation, time windows, rate limits | never admitted, or no clock at admission | not enforced |

### Guardrails

A policy named `aegis-guardrails` stops the identity escapes admission can see: agents cannot
mint a token for another ServiceAccount (`serviceaccounts/token`), and pods or pod templates
they create or update must run as the agent's own ServiceAccount (or `default` for an agent that
is not a ServiceAccount).

Admission cannot protect the policies themselves — ValidatingAdmissionPolicies, their bindings
and webhook configurations are never admitted (verified on kind) — so agents must have no RBAC
write access to `admissionregistration.k8s.io`, and no `impersonate` verb (impersonation happens
before admission, which then sees the impersonated identity). Both are listed in every coverage
report under "not enforced by this layer".

### Report first, then enforce

With `enforcement: report-only` the bindings use `validationActions: [Warn, Audit]`: agents see a
warning and the audit log records it, but nothing is denied. After review, `enforcement:
enforce` compiles `[Deny, Audit]`. `--check DIR` reports drift, as for AWS.

### Verified

`scripts/kube_acceptance.py` applies a compiled policy to a local kind cluster and runs 21 cases
as an agent ServiceAccount, the admin and a break-glass identity, comparing the agent's result
with the client-side verdict for the same kubectl command. On Kubernetes 1.36.1: 63 of 63 as
expected, and the two layers agreed on every case that exists on both
([`dev/kube-acceptance/`](dev/kube-acceptance/README.md)).
