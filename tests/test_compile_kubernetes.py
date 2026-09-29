"""aegis compile kubernetes: ValidatingAdmissionPolicies scoped to agent
identities (design v0.3, §6.6). Offline structure tests; the behaviour on a
real API server is checked by scripts/kube_acceptance.py on kind."""

import json
import re
import shutil

import pytest
import yaml

from aegis_core.cli import main
from aegis_core.compile.kubernetes import (
    REGISTRY,
    KubernetesTarget,
    clauses_for,
    compile_kubernetes,
    glob_to_re2,
    match_condition,
)
from aegis_core.identity import load_identity_model
from aegis_core.signing import load_key, sign_file
from aegis_core.store import Constraint, VerifiedSnapshot, _canonical, _constraint_to_dict


def _rule(id, pattern, actions, effect="BLOCK", **kw):
    return Constraint.create(
        id=id, provider=kw.pop("provider", "kubernetes"), resource_pattern=pattern,
        actions=set(actions), effect=effect, constraint_class="deletion", principal="admin",
        source_ref="t", source_timestamp="2026-09-28T00:00:00+00:00", rule_text=id, **kw)


def _snap(*rules, excluded=()):
    records = tuple(_canonical(_constraint_to_dict(c)) for c in sorted(rules, key=lambda c: c.id))
    return VerifiedSnapshot._build(records=records, excluded=tuple(excluded), authority=(),
                                   inputs=(), settings=(), aegis_version="test")


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


def _compile(tmp_path, *rules, model=None, **target):
    return compile_kubernetes(_snap(*rules), model or _model(tmp_path),
                              KubernetesTarget(**{"cluster": "prod-us-east", "env": "prod",
                                                  **target}))


def _cov(result, rule_id):
    return next(r for r in result.coverage["rules"] if r["id"] == rule_id)


def _policy(result, rule_id):
    return next(d for d in result.policies if d["kind"] == "ValidatingAdmissionPolicy"
                and d["metadata"]["annotations"]["aegis.dev/rule"] == rule_id)


def _expr(result, rule_id):
    return _policy(result, rule_id)["spec"]["validations"][0]["expression"]


# --- identity -------------------------------------------------------------------------------


def test_deny_by_default_exempts_trusted_break_glass_and_the_control_plane(tmp_path):
    cond = match_condition(_model(tmp_path))
    assert '"system:serviceaccount:argocd:argocd-application-controller"' in cond
    assert '"platform-admins"' in cond and '"aegis:break-glass"' in cond
    assert "system:nodes" in cond and "system:serviceaccounts:kube-system" in cond
    assert "has(request.userInfo.groups)" in cond  # a caller may carry no groups
    assert "startsWith('system:')" in cond


def test_agents_only_restricts_listed_agents_minus_break_glass(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None, agents=[
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "aegis-agents:coder"},
        {"platform": "kubernetes", "kind": "group", "id": "ai-agents"}])
    cond = match_condition(model)
    assert cond.startswith("(request.userInfo.username in ")
    assert '"system:serviceaccount:aegis-agents:coder"' in cond and '"ai-agents"' in cond
    assert '!(has(request.userInfo.groups) && request.userInfo.groups.exists(g, g in ' \
           '["aegis:break-glass"]))' in cond
    assert "system:nodes" not in cond  # nothing unlisted is an agent anyway


def test_every_policy_is_scoped_to_agents_and_fails_closed(tmp_path):
    r = _compile(tmp_path, _rule("n", "node/*", ["delete"]))
    for d in r.policies:
        if d["kind"] == "ValidatingAdmissionPolicy":
            assert d["spec"]["failurePolicy"] == "Fail"
            assert d["spec"]["matchConditions"][0]["name"] == "aegis-agent"
            names = [v["name"] for v in d["spec"]["variables"]]
            assert names[:3] == ["sub", "ns", "name"]


def test_request_fields_are_read_through_guarded_variables(tmp_path):
    """Found on kind: request.subResource is absent, not '', on a plain
    UPDATE, and the error failed closed (every agent deployment update
    denied)."""
    r = _compile(tmp_path, _rule("d", "deployment/*", ["scale", "delete"]),
                 _rule("ns", "*/*", ["delete"], scope={"namespace": "prod"}))
    for d in r.policies:
        spec = d.get("spec", {})
        text = json.dumps([spec.get("validations"), spec.get("matchConditions")])
        assert "request.subResource" not in text and "request.namespace" not in text
        assert "request.name" not in text
    variables = {v["name"]: v["expression"] for v in _policy(r, "d")["spec"]["variables"]}
    assert variables["sub"].startswith("has(request.subResource)")
    assert "oldObject.metadata.name" in variables["name"]  # per-item collection DELETE


# --- what compiles --------------------------------------------------------------------------


def test_delete_rules_read_the_name_and_cover_evictions(tmp_path):
    r = _compile(tmp_path, _rule("p", "pod/web-*", ["delete"], scope={"namespace": "prod"}))
    expr = _expr(r, "p")
    assert '(variables.name).matches("^web\\\\-.*$")' in expr
    assert 'variables.ns.matches("^prod$")' in expr
    assert 'variables.sub == "eviction"' in expr
    rules = _policy(r, "p")["spec"]["matchConstraints"]["resourceRules"]
    assert {tuple(x["resources"]) for x in rules} == {("pods",), ("pods/eviction",)}
    assert _cov(r, "p")["status"] == "exact"


@pytest.mark.parametrize("verb, kind, needle", [
    ("scale", "deployment", 'variables.sub == "scale"'),
    ("scale", "deployment", "object.spec.replicas != oldObject.spec.replicas"),
    ("set-image", "deployment", "object.spec.template.spec.containers.map(c, c.image)"),
    ("set-image", "cronjob", "object.spec.jobTemplate.spec.template.spec.containers"),
    ("set-image", "pod", "object.spec.containers.map(c, c.image)"),
    ("rollout-restart", "statefulset", "kubectl.kubernetes.io/restartedAt"),
    ("cordon", "node", "object.spec.unschedulable"),
    ("taint", "node", "object.spec.taints"),
    ("label", "configmap", "object.metadata.labels"),
    ("exec", "pod", 'variables.sub == "exec"'),
    ("port-forward", "pod", 'variables.sub == "portforward"'),
])
def test_diff_derived_and_connect_actions(tmp_path, verb, kind, needle):
    r = _compile(tmp_path, _rule("r", f"{kind}/*", [verb]))
    assert needle in _expr(r, "r")


@pytest.mark.parametrize("verb, kind", [
    ("get", "pod"), ("logs", "pod"), ("impersonate", "user"), ("scale", "daemonset"),
    ("exec", "deployment"), ("cordon", "pod"), ("hibernate", "pod"),
])
def test_unadmittable_actions_are_not_enforced(verb, kind):
    group, resource, ns, flags = REGISTRY.get(kind, ("*", kind + "s", True, frozenset()))
    clauses, why = clauses_for(verb, kind, flags)
    assert clauses == [] and why


def test_update_verbs_are_one_api_update(tmp_path):
    for verb in ("update", "patch", "edit", "replace"):
        clauses, _ = clauses_for(verb, "configmap", frozenset())
        assert [(c.operation, c.subresource) for c in clauses] == [("UPDATE", "*")]


def test_namespace_cascade(tmp_path):
    """`kubectl delete ns prod` is also a delete of */* in prod, on both
    layers (the parser emits the cascade intent)."""
    r = _compile(tmp_path, _rule("c", "*/*", ["delete"], scope={"namespace": "prod"}),
                 _rule("pods-only", "pod/*", ["delete"], scope={"namespace": "prod"}))
    assert '"namespaces"' in _expr(r, "c") and any(e.get("cascade") for e in
                                                  _cov(r, "c")["enforced"])
    assert '"namespaces"' not in _expr(r, "pods-only")  # the CLI cascade is */* only


def test_admission_objects_are_never_admitted(tmp_path):
    r = _compile(tmp_path, _rule("v", "validatingadmissionpolicy/*", ["delete"]))
    cov = _cov(r, "v")
    assert cov["status"] == "not-enforced" and "RBAC" in cov["not_enforced"][0]


def test_unknown_kinds_are_over_enforced_across_groups(tmp_path):
    r = _compile(tmp_path, _rule("cert", "certificate/*", ["delete"]))
    cov = _cov(r, "cert")
    assert cov["status"] == "over-enforced" and "any API group" in cov["over_enforced"][0]
    rules = _policy(r, "cert")["spec"]["matchConstraints"]["resourceRules"]
    assert rules == [{"apiGroups": ["*"], "apiVersions": ["*"], "operations": ["DELETE"],
                      "resources": ["certificates"]}]


def test_env_cluster_and_other_scopes(tmp_path):
    prod = _rule("p", "node/*", ["delete"], scope={"env": "prod"})
    assert _cov(_compile(tmp_path, prod), "p")["status"] == "exact"
    assert _cov(_compile(tmp_path, prod, env="staging"), "p")["status"] == "not-applicable"
    assert _cov(_compile(tmp_path, prod, env=None), "p")["status"] == "over-enforced"
    other = _rule("o", "node/*", ["delete"], scope={"context": "staging"})
    assert _cov(_compile(tmp_path, other), "o")["status"] == "not-applicable"
    wide = _rule("w", "pod/*", ["delete"], scope={"all": True})
    assert _cov(_compile(tmp_path, wide), "w")["status"] == "over-enforced"


def test_time_windows_rate_limits_and_escalate(tmp_path):
    r = _compile(
        tmp_path,
        _rule("tw", "node/*", ["delete"],
              time_window={"days": ["sat"], "start": "00:00", "end": "24:00", "tz": "UTC"}),
        _rule("esc", "node/*", ["cordon"], effect="ESCALATE"),
        _rule("gcp", "project/*", ["delete"], provider="gcp"))
    assert _cov(r, "tw")["status"] == "not-enforced" and "no clock" in \
        _cov(r, "tw")["not_enforced"][0]
    assert _cov(r, "esc")["status"] == "over-enforced"
    assert _cov(r, "gcp")["status"] == "not-applicable"
    omitted = _compile(tmp_path, _rule("esc", "node/*", ["cordon"], effect="ESCALATE"),
                       escalate="omit")
    assert _cov(omitted, "esc")["status"] == "not-enforced"


def test_glob_to_re2():
    for glob, yes, no in (("prod-*", "prod-web", "dev-web"), ("web-?", "web-1", "web-10"),
                          ("db[0-9]", "db1", "dbx"), ("x[!a]", "xb", "xa"), ("a.b", "a.b", "aXb")):
        rx = glob_to_re2(glob)
        assert re.fullmatch(rx, yes) and not re.fullmatch(rx, no), (glob, rx)


def test_guardrails_policy_is_always_present(tmp_path):
    r = _compile(tmp_path)
    (g,) = [d for d in r.policies if d["metadata"]["name"] == "aegis-guardrails"
            and d["kind"] == "ValidatingAdmissionPolicy"]
    texts = [v["expression"] for v in g["spec"]["validations"]]
    assert any("'token'" in t for t in texts)
    assert any("serviceAccountName" in t for t in texts)
    resources = {r for rr in g["spec"]["matchConstraints"]["resourceRules"]
                 for r in rr["resources"]}
    assert {"serviceaccounts/token", "pods", "deployments", "cronjobs"} <= resources


def test_report_only_warns_and_enforce_denies(tmp_path):
    r = _compile(tmp_path, _rule("n", "node/*", ["delete"]))
    bindings = [d for d in r.policies if d["kind"] == "ValidatingAdmissionPolicyBinding"]
    assert all(b["spec"]["validationActions"] == ["Warn", "Audit"] for b in bindings)
    e = _compile(tmp_path, _rule("n", "node/*", ["delete"]),
                 model=_model(tmp_path, enforcement="enforce"))
    bindings = [d for d in e.policies if d["kind"] == "ValidatingAdmissionPolicyBinding"]
    assert all(b["spec"]["validationActions"] == ["Deny", "Audit"] for b in bindings)


def test_refuses_without_kubernetes_break_glass(tmp_path):
    model = _model(tmp_path, break_glass=[
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/BreakGlass"}],
        trusted=None)
    with pytest.raises(ValueError, match="no break-glass identity for kubernetes"):
        _compile(tmp_path, model=model)


def test_output_is_deterministic_and_self_describing(tmp_path):
    rules = (_rule("a", "node/*", ["delete"]), _rule("b", "pod/*", ["exec"]))
    one, two = _compile(tmp_path, *rules), _compile(tmp_path, *reversed(rules))
    assert one.files == two.files
    m = one.manifest
    assert m["policies"]["aegis-a"] == "a" and m["policies"]["aegis-guardrails"] == \
        "self-protection"
    docs = list(yaml.safe_load_all(one.files["policies.yaml"]))
    assert all(d["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "aegis" for d in docs)
    assert all(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", d["metadata"]["name"]) for d in docs)


def test_policy_names_are_valid_and_unique(tmp_path):
    r = _compile(tmp_path, _rule("Block_Nodes!", "node/*", ["delete"]))
    name = _cov(r, "Block_Nodes!")["policy"]
    assert re.fullmatch(r"aegis-block-nodes-[0-9a-f]{8}", name)


# --- CLI ---------------------------------------------------------------------------------------


def test_cli_compile_kubernetes(tmp_path, monkeypatch, capsys):
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    shutil.copy(d / "agents.example.yaml", d / "agents.yaml")
    sign_file(d / "agents.yaml", key)
    out = tmp_path / "out"
    argv = ["compile", "kubernetes", "--config-dir", str(d), "--cluster", "prod-us-east"]
    assert main([*argv, "--out", str(out)]) == 0
    assert "report-only" in capsys.readouterr().out
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["env"] == "prod"  # environments.yaml kubernetes.contexts
    cov = json.loads((out / "coverage.json").read_text())
    assert _cov_status(cov, "no-delete-nodes") == "exact"
    assert main([*argv, "--check", str(out)]) == 0
    (out / "policies.yaml").write_text("edited\n")
    assert main([*argv, "--check", str(out)]) == 1


def _cov_status(cov, rule_id):
    return next(r["status"] for r in cov["rules"] if r["id"] == rule_id)



def test_set_image_covers_init_containers(tmp_path):
    """Review of #20: kubectl set image also updates init containers."""
    expr = _expr(_compile(tmp_path, _rule("i", "deployment/*", ["set-image"])), "i")
    assert "has(object.spec.template.spec.initContainers)" in expr
    assert "oldObject.spec.template.spec.initContainers.map(c, c.image)" in expr


def test_rollout_undo_compares_the_whole_template(tmp_path):
    """Review of #20: an annotation-only revision rolled back must match."""
    r = _compile(tmp_path, _rule("u", "deployment/*", ["rollout-undo"]))
    assert "object.spec.template != oldObject.spec.template" in _expr(r, "u")
    # review of #20: that also denies a restart, set image or apply of a
    # changed template, which the client allows -- over-enforced, not exact
    cov = _cov(r, "u")
    assert cov["status"] == "over-enforced" and "every template change" in \
        cov["over_enforced"][0]
    cov = _cov(_compile(tmp_path, _rule("c", "cronjob/*", ["rollout-undo"])), "c")
    assert cov["status"] == "not-enforced"


@pytest.mark.parametrize("namespace", ["*", "prod"])
def test_namespace_scope_never_matches_cluster_scoped_requests(tmp_path, namespace):
    """Review of #20: the client never matches a namespace scope when the
    intent has no namespace; a cluster-scoped request has namespace ''."""
    r = _compile(tmp_path, _rule("n", "node/*", ["delete"], scope={"namespace": namespace}),
                 _rule("all", "*/*", ["delete"], scope={"namespace": namespace}))
    n = _cov(r, "n")
    assert n["status"] == "not-enforced" and "cluster-scoped" in n["not_enforced"][0]
    assert "variables.ns != ''" in _expr(r, "all")
