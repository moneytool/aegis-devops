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

# (id, why). Each check is asked as several SubjectAccessReviews (see
# _probes): by name where RBAC can grant by name (resourceNames), per
# namespace where a RoleBinding can grant it, and for every write verb that
# disables a control (review of #22).
ESCAPE_CHECKS: tuple[tuple[str, str], ...] = (
    ("impersonate-users", "can act as another user (kubectl --as), a trusted or break-glass "
                          "one included; admission then sees that user"),
    ("impersonate-groups", "can claim another group, break-glass included"),
    ("impersonate-serviceaccounts", "can act as another ServiceAccount"),
    ("impersonate-uids", "can claim another identity's UID"),
    ("write-admission-policies", "can update, patch or delete ValidatingAdmissionPolicies or "
                                 "their bindings (make a rule always pass, or Deny into Warn), "
                                 "which admission cannot protect"),
    ("write-webhooks", "can update, patch or delete admission webhook configurations"),
    ("create-mutating-admission", "can create a mutating webhook or mutating admission policy "
                                  "that rewrites requests before validation"),
    ("escalate-roles", "can grant itself permissions it does not hold (escalate)"),
    ("bind-roles", "can bind any cluster role, cluster-admin included"),
    ("write-clusterrolebindings", "can create or change cluster role bindings"),
)
_ADM = "admissionregistration.k8s.io"
_RBAC = "rbac.authorization.k8s.io"
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


def _run(context: str | None, *args: str) -> subprocess.CompletedProcess:
    argv = ["kubectl", *(["--context", context] if context else []), *args]
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise InventoryError("kubectl is not on PATH (or pass --inventory FILE)") from None


def _kubectl(context: str | None, *args: str) -> str:
    proc = _run(context, *args)
    if proc.returncode != 0:
        raise InventoryError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def can_i(context: str | None, args: list[str]) -> bool:
    """One SubjectAccessReview. ``kubectl auth can-i`` exits non-zero for
    "no" too, so only an explicit yes/no answer counts: a failed review (no
    right to impersonate for it, no SubjectAccessReview access, an API error)
    is an error, never a quiet "no" (review of #22)."""
    proc = _run(context, "auth", "can-i", *args)
    lines = proc.stdout.strip().splitlines()
    answer = lines[-1].strip() if lines else ""
    if answer == "yes":
        return True
    if answer == "no":
        return False
    raise InventoryError(f"SubjectAccessReview failed (kubectl auth can-i {' '.join(args)}): "
                         f"{(proc.stderr or proc.stdout).strip()[:300] or 'no answer'}")


def _probes(model: IdentityModel, namespaces: list[str]) -> list[tuple[str, list[str], str]]:
    """``(check, can-i arguments, target description)`` for every escape
    check."""
    exempt = model.exempt("kubernetes")
    users = sorted({i.id for i in exempt if i.kind == "user"})
    groups = sorted({i.id for i in exempt if i.kind == "group"} | {"system:masters"})
    sas = sorted({i.id for i in exempt if i.kind == "serviceaccount"})
    out: list[tuple[str, list[str], str]] = [
        ("impersonate-users", ["impersonate", "users"], "any user"),
        ("impersonate-groups", ["impersonate", "groups"], "any group"),
        ("impersonate-uids", ["impersonate", "uids"], "any uid"),
    ]
    out += [("impersonate-users", ["impersonate", f"users/{u}"], f"user {u}") for u in users]
    out += [("impersonate-groups", ["impersonate", f"groups/{g}"], f"group {g}") for g in groups]
    for ns in sorted(set(namespaces)):
        out.append(("impersonate-serviceaccounts", ["impersonate", "serviceaccounts", "-n", ns],
                    f"any ServiceAccount in {ns}"))
    for sa in sas:
        ns, name = sa.split(":", 1)
        out.append(("impersonate-serviceaccounts",
                    ["impersonate", f"serviceaccounts/{name}", "-n", ns],
                    f"ServiceAccount {sa}"))
    for res in ("validatingadmissionpolicies", "validatingadmissionpolicybindings"):
        for verb in ("update", "patch", "delete"):
            out.append(("write-admission-policies", [verb, f"{res}.{_ADM}"], f"{verb} {res}"))
    for res in ("validatingwebhookconfigurations", "mutatingwebhookconfigurations"):
        for verb in ("update", "patch", "delete"):
            out.append(("write-webhooks", [verb, f"{res}.{_ADM}"], f"{verb} {res}"))
    for res in ("mutatingwebhookconfigurations", "mutatingadmissionpolicies",
                "mutatingadmissionpolicybindings"):
        out.append(("create-mutating-admission", ["create", f"{res}.{_ADM}"], f"create {res}"))
    out.append(("escalate-roles", ["escalate", f"clusterroles.{_RBAC}"], "escalate clusterroles"))
    out.append(("bind-roles", ["bind", f"clusterroles.{_RBAC}"], "bind clusterroles"))
    for verb in ("create", "update", "patch"):
        out.append(("write-clusterrolebindings", [verb, f"clusterrolebindings.{_RBAC}"],
                    f"{verb} clusterrolebindings"))
    return out


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
    probes = _probes(model, [s["namespace"] for s in sas])

    def ask(job):
        ident, (check, args, target) = job
        who = ["--as", ident["username"]]
        for g in ident["groups"]:
            who += ["--as-group", g]
        return f"{ident['kind']}:{ident['id']}", check, target, can_i(context, [*args, *who])

    jobs = [(i, p) for i in restricted for p in probes]
    for ident in restricted:
        inventory["access"][f"{ident['kind']}:{ident['id']}"] = {
            c[0]: [] for c in ESCAPE_CHECKS}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, check, target, allowed in pool.map(ask, jobs):
            if allowed:
                inventory["access"][key][check].append(target)
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
            for check, why in ESCAPE_CHECKS:
                targets = granted.get(check)
                if targets:
                    detail = why + (f" ({', '.join(targets)})" if isinstance(targets, list)
                                    else "")
                    result.findings.append({
                        "identity": f"{ident['kind']}/{ident['id']}", "kind": check,
                        "severity": "high", "detail": detail,
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
