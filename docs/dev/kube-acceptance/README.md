# Kubernetes acceptance run, 2026-09-28

`aegis compile kubernetes` output applied to a local kind cluster (Kubernetes v1.36.1), run
with `scripts/kube_acceptance.py`. No cloud account is involved.

- **Identities**: an agent ServiceAccount (`agents:coder`, bound to `cluster-admin` so that only
  an admission policy can refuse it), the kind admin, and a break-glass group member.
- **Policy**: six rules (node delete/cordon/drain/taint; every delete in `prod`; a name-glob
  configmap rule in `staging`; pod exec; deployment scale / set-image / rollout-restart as
  `ESCALATE`; pod deletes in `staging`) plus the guardrails, `deny-by-default`, `enforce`.
- **Cases**: 18, each as all three identities (54 runs), as server-side dry runs where kubectl
  supports them. For the agent, every case that exists on both layers is also evaluated
  client-side (`aegis`'s interceptor on the same kubectl argv) and must agree.

Result: **54 of 54 as expected**; the client and the cluster agreed on all 12 shared cases,
including the namespace cascade and a `delete --all` (admitted per item). The guardrail cases
(token for another ServiceAccount, pod under another ServiceAccount) and pod eviction are
server-only by design.

Found and fixed during the run: `request.subResource` (and `request.name`,
`request.namespace`) are **absent**, not empty, when unset. Reading them directly made every
agent UPDATE of a deployment fail with `no such key`, which `failurePolicy: Fail` turns into a
deny. Every policy now reads them through guarded variables.

`results.json` has every run.
