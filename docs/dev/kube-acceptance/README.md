# Kubernetes acceptance run, 2026-09-28

`aegis compile kubernetes` output applied to a local kind cluster (Kubernetes v1.36.1), run
with `scripts/kube_acceptance.py`. No cloud account is involved.

- **Identities**: an agent ServiceAccount (`agents:coder`, bound to `cluster-admin` so that only
  an admission policy can refuse it), the kind admin, and a break-glass group member.
- **Policy**: seven rules (node delete/cordon/drain/taint; every delete in `prod`; a name-glob
  configmap rule in `staging`; pod exec; deployment scale / set-image / rollout-restart /
  rollout-undo as `ESCALATE`; pod deletes in `staging`; a `namespace: '*'` rule on a
  cluster-scoped kind) plus the guardrails, `deny-by-default`, `enforce`.
- **Cases**: 21, each as all three identities (63 runs), as server-side dry runs where kubectl
  supports them. For the agent, every case that exists on both layers is also evaluated
  client-side (`aegis`'s interceptor on the same kubectl argv) and must agree.

Result: **63 of 63 as expected**; the client and the cluster agreed on all 15 shared cases,
including the namespace cascade and a `delete --all` (admitted per item). The guardrail cases
(token for another ServiceAccount, pod under another ServiceAccount) and pod eviction are
server-only by design.

Found and fixed during the run: `request.subResource` (and `request.name`,
`request.namespace`) are **absent**, not empty, when unset. Reading them directly made every
agent UPDATE of a deployment fail with `no such key`, which `failurePolicy: Fail` turns into a
deny. Every policy now reads them through guarded variables.

Added after the review of #20: an init-container-only image update (`kubectl set image` also
changes init containers), a rollback to a revision that differs only in a template annotation (a
`rollout restart` revision), and a `namespace: '*'` rule on a cluster-scoped kind, which neither
layer may match.

`results.json` has every run.
