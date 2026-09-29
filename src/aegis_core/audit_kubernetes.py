"""``aegis audit-identity kubernetes``: what the identity model means for the
identities that exist in a cluster (design v0.3, §4.2, §4.3, §6.6).

Read-only. The inventory -- ServiceAccounts, RBAC bindings, which
ServiceAccounts pods run as, and SubjectAccessReviews for the escape
permissions -- comes from :func:`collect_inventory` (kubectl with the
operator's credentials) or a saved copy; :func:`audit` is pure.

* ``would_restrict``: every identity the compiled policies would restrict --
  ServiceAccounts, and users/groups named in RBAC bindings (the API has no
  user objects) -- with the control plane exempt as in the compiler.
* ``missing``: listed ServiceAccounts that do not exist, and a break-glass
  group or user no binding grants anything (break-glass without access).
* ``findings``: escape permissions an identity the policies restrict still
  holds. Admission cannot see impersonation or protect admission objects, so
  RBAC is the only control there.
"""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from aegis_core.identity import IdentityModel

# (id, verb, resource, why) -- each asked as a SubjectAccessReview
ESCAPE_CHECKS: tuple[tuple[str, str, str, str], ...] = (
    ("impersonate-users", "impersonate", "users",
     "can act as any user (kubectl --as); admission then sees that user"),
    ("impersonate-groups", "impersonate", "groups", "can claim any group, break-glass included"),
    ("impersonate-serviceaccounts", "impersonate", "serviceaccounts",
     "can act as any ServiceAccount"),
    ("write-admission-policies", "delete",
     "validatingadmissionpolicies.admissionregistration.k8s.io",
     "can delete the compiled policies, which admission cannot protect"),
    ("write-admission-bindings", "delete",
     "validatingadmissionpolicybindings.admissionregistration.k8s.io",
     "can delete the compiled bindings, which admission cannot protect"),
    ("write-webhooks", "delete",
     "validatingwebhookconfigurations.admissionregistration.k8s.io",
     "can remove admission webhooks"),
    ("escalate-roles", "escalate", "clusterroles.rbac.authorization.k8s.io",
     "can grant itself permissions it does not hold"),
    ("bind-roles", "bind", "clusterroles.rbac.authorization.k8s.io",
     "can bind any cluster role, cluster-admin included"),
    ("write-clusterrolebindings", "create",
     "clusterrolebindings.rbac.authorization.k8s.io",
     "can bind itself (or a group it can claim) to a cluster role"),
)
_SA_PREFIX = "system:serviceaccount:"
# every identity (or every ServiceAccount) carries these; agents.yaml refuses
# to trust them, so they are not identities to review
_UNIVERSAL_GROUPS = ("system:authenticated", "system:unauthenticated", "system:serviceaccounts")
_HINTS = {
    ("group", "system:masters"): "the super-admin group; usually break-glass",
    ("user", "kube-apiserver-kubelet-client"): "the API server's client to kubelets; trust it",
}


class InventoryError(ValueError):
    """The cluster inventory could not be collected or read."""


def _is_control_plane(username: str, groups: list[str]) -> bool:
    """The compiler's always-exempt set in deny-by-default."""
    if username.startswith("system:") and not username.startswith(_SA_PREFIX):
        return True
    return "system:nodes" in groups or "system:serviceaccounts:kube-system" in groups


def _sa_groups(namespace: str) -> list[str]:
    return ["system:serviceaccounts", f"system:serviceaccounts:{namespace}",
            "system:authenticated"]


# --- collection ------------------------------------------------------------------------------


def _kubectl(context: str | None, *args: str) -> str:
    argv = ["kubectl", *(["--context", context] if context else []), *args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise InventoryError("kubectl is not on PATH (or pass --inventory FILE)") from None
    if proc.returncode != 0 and "auth" not in args[:1]:
        raise InventoryError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _identities(sas: list[dict], bindings: list[dict]) -> list[dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for sa in sas:
        ns, name = sa["namespace"], sa["name"]
        user = f"{_SA_PREFIX}{ns}:{name}"
        out[("serviceaccount", user)] = {"kind": "serviceaccount", "id": f"{ns}:{name}",
                                         "username": user, "groups": _sa_groups(ns)}
    for b in bindings:
        for s in b.get("subjects") or []:
            if s.get("kind") == "User":
                out.setdefault(("user", s["name"]), {
                    "kind": "user", "id": s["name"], "username": s["name"],
                    "groups": ["system:authenticated"]})
            elif s.get("kind") == "Group" and not (
                    s["name"] in _UNIVERSAL_GROUPS
                    or s["name"].startswith("system:serviceaccounts:")):
                out.setdefault(("group", s["name"]), {
                    "kind": "group", "id": s["name"], "username": "aegis-audit:probe",
                    "groups": [s["name"], "system:authenticated"]})
    return sorted(out.values(), key=lambda i: (i["kind"], i["id"]))


def collect_inventory(context: str | None, model: IdentityModel) -> dict[str, Any]:
    """ServiceAccounts, bindings, pod ServiceAccounts and, for every identity
    the policies would restrict, the escape SubjectAccessReviews."""
    sa_doc = json.loads(_kubectl(context, "get", "serviceaccounts", "-A", "-o", "json"))
    sas = [{"namespace": i["metadata"]["namespace"], "name": i["metadata"]["name"]}
           for i in sa_doc.get("items", [])]
    bindings = []
    for kind in ("clusterrolebindings", "rolebindings"):
        doc = json.loads(_kubectl(context, "get", kind, "-A", "-o", "json"))
        for i in doc.get("items", []):
            bindings.append({"kind": kind, "namespace": i["metadata"].get("namespace", ""),
                             "name": i["metadata"]["name"], "role": i["roleRef"]["name"],
                             "subjects": i.get("subjects") or []})
    pods = json.loads(_kubectl(context, "get", "pods", "-A", "-o", "json"))
    pod_sas: dict[str, int] = {}
    for p in pods.get("items", []):
        key = f"{p['metadata']['namespace']}:{p['spec'].get('serviceAccountName', 'default')}"
        pod_sas[key] = pod_sas.get(key, 0) + 1

    inventory = {"serviceaccounts": sas, "bindings": bindings, "pod_serviceaccounts": pod_sas,
                 "access": {}}
    restricted = [i for i in _identities(sas, bindings) if _restricted(model, i)]

    def ask(job):
        ident, (check, verb, resource, _why) = job
        args = ["auth", "can-i", verb, resource, "--as", ident["username"]]
        for g in ident["groups"]:
            args += ["--as-group", g]
        answer = _kubectl(context, *args).strip().splitlines()
        return f"{ident['kind']}:{ident['id']}", check, bool(answer) and answer[-1] == "yes"

    jobs = [(i, c) for i in restricted for c in ESCAPE_CHECKS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, check, allowed in pool.map(ask, jobs):
            inventory["access"].setdefault(key, {})[check] = allowed
    return inventory


# --- analysis ---------------------------------------------------------------------------------


def _restricted(model: IdentityModel, ident: dict[str, Any]) -> bool:
    if model.mode == "deny-by-default" and _is_control_plane(ident["username"],
                                                              ident["groups"]):
        return False
    presented = [("user", ident["username"]), *(("group", g) for g in ident["groups"])]
    if ident["kind"] == "group":
        presented = [("group", ident["id"])]
    return model.is_agent("kubernetes", presented)


@dataclass
class KubernetesAuditResult:
    context: str
    mode: str
    enforcement: str
    would_restrict: list[dict[str, Any]] = field(default_factory=list)
    exempt: list[dict[str, Any]] = field(default_factory=list)
    control_plane: int = 0
    missing: list[dict[str, str]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def problems(self) -> bool:
        return bool(self.missing) or any(f["severity"] == "high" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {"context": self.context, "mode": self.mode, "enforcement": self.enforcement,
                "would_restrict": self.would_restrict, "exempt": self.exempt,
                "control_plane": self.control_plane, "missing": self.missing,
                "findings": self.findings}


def audit(inventory: dict[str, Any], model: IdentityModel, context: str = "") -> \
        KubernetesAuditResult:
    result = KubernetesAuditResult(context, model.mode, model.enforcement)
    sas, bindings = inventory.get("serviceaccounts", []), inventory.get("bindings", [])
    pod_sas = inventory.get("pod_serviceaccounts", {})
    access = inventory.get("access", {})
    bound: dict[tuple[str, str], list[str]] = {}
    for b in bindings:
        for s in b.get("subjects") or []:
            if s.get("kind") == "ServiceAccount":
                key = ("serviceaccount", f"{s.get('namespace', b.get('namespace', ''))}:"
                                         f"{s['name']}")
            else:
                key = (str(s.get("kind", "")).lower(), s["name"])
            bound.setdefault(key, []).append(f"{b['kind'][:-1]}/{b['name']} -> {b['role']}")

    for ident in _identities(sas, bindings):
        if model.mode == "deny-by-default" and _is_control_plane(ident["username"],
                                                                  ident["groups"]):
            result.control_plane += 1
            continue
        row = {"kind": ident["kind"], "id": ident["id"],
               "bindings": sorted(bound.get((ident["kind"], ident["id"]), []))}
        if ident["kind"] == "serviceaccount":
            row["pods"] = pod_sas.get(ident["id"], 0)
        hint = _HINTS.get((ident["kind"], ident["id"]))
        if ident["kind"] == "group" and ident["id"].startswith("system:bootstrappers:"):
            hint = "node bootstrap tokens (kubeadm join); trust it"
        if hint:
            row["hint"] = hint
        if _restricted(model, ident):
            result.would_restrict.append(row)
            granted = access.get(f"{ident['kind']}:{ident['id']}", {})
            for check, _verb, _res, why in ESCAPE_CHECKS:
                if granted.get(check):
                    result.findings.append({
                        "identity": f"{ident['kind']}/{ident['id']}", "kind": check,
                        "severity": "high", "detail": why,
                        "why": "an identity the compiled policies restrict; admission cannot "
                               "see or stop this, so RBAC must not grant it"})
        else:
            result.exempt.append(row)

    existing = {f"{s['namespace']}:{s['name']}" for s in sas}
    for ident in (*model.exempt("kubernetes"),
                  *(model.agents_for("kubernetes") if model.mode == "agents-only" else ())):
        section = ("break_glass" if ident in model.break_glass else
                   "trusted" if ident in model.trusted else "agents")
        if ident.kind == "serviceaccount" and ident.id not in existing:
            result.missing.append({"identity": f"serviceaccount/{ident.id}",
                                   "listed_as": section,
                                   "detail": "listed in agents.yaml but not in this cluster"})
        elif section == "break_glass" and ident.kind in ("user", "group") and \
                (ident.kind, ident.id) not in bound:
            result.missing.append({"identity": f"{ident.kind}/{ident.id}",
                                   "listed_as": section,
                                   "detail": "no role binding grants it anything, so "
                                             "break-glass has no access"})
    result.would_restrict.sort(key=lambda r: (r["kind"], r["id"]))
    result.exempt.sort(key=lambda r: (r["kind"], r["id"]))
    return result
