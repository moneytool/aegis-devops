"""aegis audit-identity kubernetes: agents.yaml against the identities a
cluster has (design v0.3, §4.2, §4.3). Offline, on inventory fixtures; the
collector was run against a kind cluster."""

import json
import shutil

import pytest
import yaml

from aegis_core.audit_kubernetes import ESCAPE_CHECKS, audit
from aegis_core.cli import main
from aegis_core.identity import load_identity_model
from aegis_core.signing import load_key, sign_file

ALL = {c[0]: True for c in ESCAPE_CHECKS}
NONE = {c[0]: False for c in ESCAPE_CHECKS}


def _binding(name, role, *subjects, kind="clusterrolebindings", namespace=""):
    return {"kind": kind, "namespace": namespace, "name": name, "role": role,
            "subjects": [dict(zip(("kind", "name", "namespace"), s)) for s in subjects]}


INVENTORY = {
    "serviceaccounts": [
        {"namespace": "agents", "name": "coder"},
        {"namespace": "agents", "name": "narrow"},
        {"namespace": "argocd", "name": "argocd-application-controller"},
        {"namespace": "kube-system", "name": "replicaset-controller"},
        {"namespace": "backup", "name": "velero"},
    ],
    "bindings": [
        _binding("coder-admin", "cluster-admin", ("ServiceAccount", "coder", "agents")),
        _binding("narrow-edit", "edit", ("ServiceAccount", "narrow", "agents"),
                 kind="rolebindings", namespace="staging"),
        _binding("velero", "cluster-admin", ("ServiceAccount", "velero", "backup")),
        _binding("argocd", "cluster-admin",
                 ("ServiceAccount", "argocd-application-controller", "argocd")),
        _binding("admins", "cluster-admin", ("Group", "platform-admins")),
        _binding("bg", "cluster-admin", ("Group", "aegis:break-glass")),
        _binding("masters", "cluster-admin", ("Group", "system:masters")),
        _binding("discovery", "system:discovery", ("Group", "system:authenticated")),
        _binding("sa-discovery", "x", ("Group", "system:serviceaccounts")),
        _binding("kubelet-client", "system:kubelet-api-admin",
                 ("User", "kube-apiserver-kubelet-client")),
        _binding("kcm", "system:kube-controller-manager",
                 ("User", "system:kube-controller-manager")),
    ],
    "pod_serviceaccounts": {"backup:velero": 1, "agents:coder": 2},
    "access": {
        "serviceaccount:agents:coder": ALL,
        "serviceaccount:agents:narrow": NONE,
        "serviceaccount:backup:velero": ALL,
        "group:system:masters": ALL,
        "user:kube-apiserver-kubelet-client": NONE,
    },
}


def _model(tmp_path, **fields):
    doc = {"principal": "admin",
           "break_glass": [{"platform": "kubernetes", "kind": "group", "id": "aegis:break-glass"}],
           "trusted": [{"platform": "kubernetes", "kind": "group", "id": "platform-admins"},
                       {"platform": "kubernetes", "kind": "serviceaccount",
                        "id": "argocd:argocd-application-controller"}],
           **fields}
    doc = {k: v for k, v in doc.items() if v is not None}
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(doc))
    return load_identity_model(path, authority_map={"admin": {"identity"}}, insecure=True)


def _ids(rows):
    return [f"{r['kind']}/{r['id']}" for r in rows]


def test_would_restrict_lists_unlisted_identities_for_review(tmp_path):
    r = audit(INVENTORY, _model(tmp_path), "kind-test")
    assert _ids(r.would_restrict) == [
        "group/system:masters", "serviceaccount/agents:coder", "serviceaccount/agents:narrow",
        "serviceaccount/backup:velero", "user/kube-apiserver-kubelet-client"]
    velero = next(x for x in r.would_restrict if x["id"] == "backup:velero")
    assert velero["pods"] == 1 and velero["bindings"] == [
        "clusterrolebinding/velero -> cluster-admin"]
    assert _ids(r.exempt) == ["group/aegis:break-glass", "group/platform-admins",
                              "serviceaccount/argocd:argocd-application-controller"]


def test_control_plane_and_universal_groups_are_not_reviewed(tmp_path):
    r = audit(INVENTORY, _model(tmp_path))
    ids = _ids(r.would_restrict) + _ids(r.exempt)
    assert "serviceaccount/kube-system:replicaset-controller" not in ids
    assert "user/system:kube-controller-manager" not in ids
    assert not any("system:authenticated" in i or i == "group/system:serviceaccounts"
                   for i in ids)
    assert r.control_plane == 2


def test_hints_for_built_in_identities(tmp_path):
    rows = {x["id"]: x.get("hint") for x in audit(INVENTORY, _model(tmp_path)).would_restrict}
    assert "break-glass" in rows["system:masters"]
    assert "trust it" in rows["kube-apiserver-kubelet-client"]


def test_escape_permissions_of_restricted_identities_are_problems(tmp_path):
    r = audit(INVENTORY, _model(tmp_path))
    by = {}
    for f in r.findings:
        by.setdefault(f["identity"], set()).add(f["kind"])
    assert set(by) == {"serviceaccount/agents:coder", "serviceaccount/backup:velero",
                       "group/system:masters"}
    assert by["serviceaccount/agents:coder"] == {c[0] for c in ESCAPE_CHECKS}
    assert all(f["severity"] == "high" for f in r.findings)
    assert r.problems


def test_least_privilege_agent_is_clean(tmp_path):
    inv = {**INVENTORY, "access": {"serviceaccount:agents:narrow": NONE},
           "bindings": [b for b in INVENTORY["bindings"]
                        if b["name"] in ("narrow-edit", "bg", "admins")],
           "serviceaccounts": [{"namespace": "agents", "name": "narrow"},
                               {"namespace": "argocd", "name": "argocd-application-controller"}]}
    r = audit(inv, _model(tmp_path))
    assert _ids(r.would_restrict) == ["serviceaccount/agents:narrow"]
    assert r.findings == [] and not r.problems


def test_agents_only_reviews_only_the_listed_agents(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None, agents=[
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "agents:coder"}])
    r = audit(INVENTORY, model)
    assert _ids(r.would_restrict) == ["serviceaccount/agents:coder"]
    assert {f["identity"] for f in r.findings} == {"serviceaccount/agents:coder"}


def test_missing_serviceaccounts_and_unbound_break_glass(tmp_path):
    model = _model(tmp_path, break_glass=[
        {"platform": "kubernetes", "kind": "group", "id": "oncall"}], trusted=[
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "flux-system:kustomize"}])
    r = audit(INVENTORY, model)
    got = {m["identity"]: m for m in r.missing}
    assert got["serviceaccount/flux-system:kustomize"]["listed_as"] == "trusted"
    assert "no access" in got["group/oncall"]["detail"]
    assert r.problems


def test_cli_audit_from_a_saved_inventory(tmp_path, monkeypatch, capsys):
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    shutil.copy(d / "agents.example.yaml", d / "agents.yaml")
    sign_file(d / "agents.yaml", key)
    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps(INVENTORY))
    argv = ["audit-identity", "kubernetes", "--config-dir", str(d), "--inventory", str(inv)]
    assert main([*argv, "--would-restrict"]) == 1  # escape findings exit 1
    doc = json.loads(capsys.readouterr().out)
    assert "serviceaccount" in {r["kind"] for r in doc["would_restrict"]}
    assert main([*argv, "--pretty"]) == 1
    out = capsys.readouterr().out
    assert "PROBLEM serviceaccount/agents:coder can: impersonate-users" in out
    assert "control plane, always exempt: 2" in out


@pytest.mark.parametrize("check", [c[0] for c in ESCAPE_CHECKS])
def test_every_escape_check_is_reported(tmp_path, check):
    inv = {**INVENTORY, "access": {"serviceaccount:agents:narrow": {**NONE, check: True}}}
    r = audit(inv, _model(tmp_path))
    assert [(f["identity"], f["kind"]) for f in r.findings] == [
        ("serviceaccount/agents:narrow", check)]


# --- collector (review of #22) -------------------------------------------------------------

import subprocess  # noqa: E402

from aegis_core import audit_kubernetes as ak  # noqa: E402


def _proc(stdout, rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def test_a_failed_access_review_is_an_error_not_a_no(monkeypatch):
    monkeypatch.setattr(ak, "_run", lambda ctx, *a: _proc("", 1, 'Error from server '
                        '(Forbidden): users "x" is forbidden: cannot impersonate'))
    with pytest.raises(ak.InventoryError, match="SubjectAccessReview failed"):
        ak.can_i(None, ["impersonate", "users"])
    monkeypatch.setattr(ak, "_run", lambda ctx, *a: _proc("no\n", 1))
    assert ak.can_i(None, ["impersonate", "users"]) is False
    monkeypatch.setattr(ak, "_run", lambda ctx, *a: _proc("yes\n", 0))
    assert ak.can_i(None, ["impersonate", "users"]) is True


def test_probes_cover_updates_names_and_namespaces(tmp_path):
    model = _model(tmp_path, trusted=[
        {"platform": "kubernetes", "kind": "user", "id": "alice@example.com"},
        {"platform": "kubernetes", "kind": "serviceaccount",
         "id": "argocd:argocd-application-controller"}])
    probes = {(c, " ".join(a)) for c, a, _t in ak._probes(model, ["agents", "argocd", "prod"])}
    for verb in ("update", "patch", "delete"):
        assert ("write-admission-policies",
                f"{verb} validatingadmissionpolicies.admissionregistration.k8s.io") in probes
        assert ("write-admission-policies",
                f"{verb} validatingadmissionpolicybindings.admissionregistration.k8s.io") in probes
        assert ("write-webhooks",
                f"{verb} mutatingwebhookconfigurations.admissionregistration.k8s.io") in probes
    assert ("impersonate-groups", "impersonate groups/aegis:break-glass") in probes
    assert ("impersonate-groups", "impersonate groups/system:masters") in probes
    assert ("impersonate-users", "impersonate users/alice@example.com") in probes
    assert ("impersonate-serviceaccounts", "impersonate serviceaccounts -n prod") in probes
    assert ("impersonate-serviceaccounts",
            "impersonate serviceaccounts/argocd-application-controller -n argocd") in probes


def _collect(monkeypatch, tmp_path, grants):
    """collect_inventory against a fake cluster: one agent ServiceAccount,
    granted exactly the can-i argument strings in ``grants``."""
    objects = {
        "serviceaccounts": {"items": [
            {"metadata": {"namespace": "agents", "name": "coder"}},
            {"metadata": {"namespace": "argocd", "name": "argocd-application-controller"}}]},
        "clusterrolebindings": {"items": [
            {"metadata": {"name": "bg"}, "roleRef": {"name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "aegis:break-glass"}]}]},
        "rolebindings": {"items": []},
        "pods": {"items": []},
    }
    monkeypatch.setattr(ak, "_kubectl", lambda ctx, *a: json.dumps(objects[a[1]]))

    def fake_can_i(ctx, args):
        asked = " ".join(args[:args.index("--as")])
        return asked in grants and "system:serviceaccount:agents:coder" in args
    monkeypatch.setattr(ak, "can_i", fake_can_i)
    model = _model(tmp_path)
    return ak.audit(ak.collect_inventory(None, model), model)


@pytest.mark.parametrize("grant, check, target", [
    ("update validatingadmissionpolicybindings.admissionregistration.k8s.io",
     "write-admission-policies", "update validatingadmissionpolicybindings"),
    ("patch validatingadmissionpolicies.admissionregistration.k8s.io",
     "write-admission-policies", "patch validatingadmissionpolicies"),
    ("impersonate groups/aegis:break-glass", "impersonate-groups", "group aegis:break-glass"),
    ("impersonate serviceaccounts -n argocd", "impersonate-serviceaccounts",
     "any ServiceAccount in argocd"),
    ("impersonate serviceaccounts/argocd-application-controller -n argocd",
     "impersonate-serviceaccounts", "ServiceAccount argocd:argocd-application-controller"),
])
def test_update_only_named_and_cross_namespace_grants_are_found(monkeypatch, tmp_path, grant,
                                                                 check, target):
    """Review of #22: a delete-only check missed update/patch, and an unnamed,
    current-namespace impersonation check missed resourceNames and
    RoleBinding grants in other namespaces."""
    r = _collect(monkeypatch, tmp_path, {grant})
    assert [(f["identity"], f["kind"]) for f in r.findings] == [
        ("serviceaccount/agents:coder", check)]
    assert target in r.findings[0]["detail"]


def test_collector_with_no_grants_is_clean(monkeypatch, tmp_path):
    r = _collect(monkeypatch, tmp_path, set())
    assert r.findings == [] and "serviceaccount/agents:coder" in _ids(r.would_restrict)
