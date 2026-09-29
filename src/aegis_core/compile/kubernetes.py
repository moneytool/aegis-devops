"""``aegis compile kubernetes``: the verified snapshot as
ValidatingAdmissionPolicy objects scoped to agent identities (design v0.3,
§6.6, §5.3).

The API server evaluates these in-process: no webhook to keep up and no
policy key in the cluster. Each compiled rule becomes one policy and one
binding. A policy's ``matchConditions`` restrict it to agents (generated from
``agents.yaml``); its single validation denies the requests the rule covers,
read from ``request.operation``, ``request.resource``, ``request.subResource``,
the name (``request.name``, else the object's, else the old object's -- a
collection DELETE is admitted per item with an empty ``request.name``), the
namespace, and for diff-derived actions the old and new objects.

Verified on kind (Kubernetes 1.36/1.37): identity scoping, per-item
collection deletes, CONNECT on ``pods/exec``, and that the CEL environment has
no clock -- so recurring time windows are not enforced by this target.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from aegis_core.compile import CompileError, canonical_json, pretty_json, sha256_text
from aegis_core.compile.aws import CompileResult
from aegis_core.identity import IdentityModel
from aegis_core.store import ANY_ACTION, Constraint, VerifiedSnapshot, scope_value_matches

API_VERSION = "admissionregistration.k8s.io/v1"

# kind (the parser's normal form) -> (API group, resource, namespaced, flags)
# flags: "scale" (has a scale subresource), "template" (a pod template at
# spec.template), "jobtemplate" (at spec.jobTemplate.spec.template), "pod",
# "unadmitted" (admission never sees writes to it; RBAC is the control)
REGISTRY: dict[str, tuple[str, str, bool, frozenset[str]]] = {}


def _reg(kind: str, group: str, resource: str, namespaced: bool, *flags: str) -> None:
    REGISTRY[kind] = (group, resource, namespaced, frozenset(flags))


for _k, _r in (("pod", "pods"), ("service", "services"), ("configmap", "configmaps"),
               ("secret", "secrets"), ("serviceaccount", "serviceaccounts"),
               ("persistentvolumeclaim", "persistentvolumeclaims"),
               ("endpoints", "endpoints"), ("event", "events"), ("limitrange", "limitranges"),
               ("resourcequota", "resourcequotas")):
    _reg(_k, "", _r, True, *(("pod",) if _k == "pod" else ()))
_reg("replicationcontroller", "", "replicationcontrollers", True, "scale", "template")
for _k, _r in (("node", "nodes"), ("namespace", "namespaces"),
               ("persistentvolume", "persistentvolumes")):
    _reg(_k, "", _r, False)
_reg("deployment", "apps", "deployments", True, "scale", "template")
_reg("statefulset", "apps", "statefulsets", True, "scale", "template")
_reg("replicaset", "apps", "replicasets", True, "scale", "template")
_reg("daemonset", "apps", "daemonsets", True, "template")
_reg("job", "batch", "jobs", True, "template")
_reg("cronjob", "batch", "cronjobs", True, "jobtemplate")
_reg("horizontalpodautoscaler", "autoscaling", "horizontalpodautoscalers", True)
_reg("ingress", "networking.k8s.io", "ingresses", True)
_reg("networkpolicy", "networking.k8s.io", "networkpolicies", True)
_reg("ingressclass", "networking.k8s.io", "ingressclasses", False)
_reg("poddisruptionbudget", "policy", "poddisruptionbudgets", True)
_reg("role", "rbac.authorization.k8s.io", "roles", True)
_reg("rolebinding", "rbac.authorization.k8s.io", "rolebindings", True)
_reg("clusterrole", "rbac.authorization.k8s.io", "clusterroles", False)
_reg("clusterrolebinding", "rbac.authorization.k8s.io", "clusterrolebindings", False)
_reg("storageclass", "storage.k8s.io", "storageclasses", False)
_reg("customresourcedefinition", "apiextensions.k8s.io", "customresourcedefinitions", False)
_reg("priorityclass", "scheduling.k8s.io", "priorityclasses", False)
_reg("certificatesigningrequest", "certificates.k8s.io", "certificatesigningrequests", False)
_reg("lease", "coordination.k8s.io", "leases", True)
for _k in ("validatingwebhookconfiguration", "mutatingwebhookconfiguration",
           "validatingadmissionpolicy", "validatingadmissionpolicybinding"):
    _reg(_k, "admissionregistration.k8s.io", _k + "s", False, "unadmitted")

# Updates: every client spelling of "change this object" is an UPDATE at the API.
_UPDATE_VERBS = frozenset({"update", "patch", "edit", "replace"})
# Never admitted (reads) or not a write to the named object.
_NOT_ADMITTED = {
    "get": "reads are not admitted", "read": "reads are not admitted",
    "describe": "reads are not admitted", "logs": "reading logs is not admitted",
    "top": "reads are not admitted", "wait": "reads are not admitted",
    "impersonate": "impersonation is authentication, not a request admission sees; RBAC "
                   "must not grant 'impersonate' to agents (aegis audit-identity)",
    "expose": "creates a Service named after the target, not a write to it",
    "autoscale": "creates a HorizontalPodAutoscaler, not a write to the target",
}

# The control plane is never an agent in deny-by-default: restricting the
# ReplicaSet controller's pod deletes or the kubelet would break the cluster.
_CONTROL_PLANE_GROUPS = ("system:nodes", "system:serviceaccounts:kube-system")

NOT_ENFORCED_BY_THIS_LAYER = (
    "Impersonation (kubectl --as) is authentication: admission sees the impersonated "
    "identity. Agents must not hold RBAC 'impersonate'; aegis audit-identity checks it.",
    "ValidatingAdmissionPolicies, their bindings and webhook configurations are never "
    "admitted, so these policies cannot protect themselves: agents must not have RBAC write "
    "access to admissionregistration.k8s.io.",
    "The control plane (system:* users other than ServiceAccounts, system:nodes and kube-system "
    "ServiceAccounts) is always exempt in deny-by-default; cascades it performs -- the "
    "namespace controller emptying a namespace, garbage collection -- pass. Rules stop the "
    "initiating request (a namespace DELETE is compiled from namespace-scoped delete rules).",
    "exec into a pod that runs as another ServiceAccount: CONNECT carries no pod spec.",
    "Reads (get, logs) are never admitted.",
)


def _cel(value: str) -> str:
    return json.dumps(value)  # CEL double-quoted string literal


def _cel_list(values) -> str:
    return "[" + ", ".join(_cel(v) for v in values) + "]"


def glob_to_re2(glob: str) -> str:
    """An fnmatch glob as an anchored RE2 pattern (CEL ``matches``)."""
    out, i = ["^"], 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            j = glob.find("]", i + 2 if glob[i + 1:i + 2] in ("!", "]") else i + 1)
            if j == -1:
                out.append(re.escape(ch))
            else:
                body = glob[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    return "".join(out)


# --- target --------------------------------------------------------------------------------


@dataclass(frozen=True)
class KubernetesTarget:
    cluster: str
    env: str | None = None
    escalate: str = "deny"

    def __post_init__(self) -> None:
        if not self.cluster:
            raise CompileError("--cluster is required")
        if self.escalate not in ("deny", "omit"):
            raise CompileError("--escalate must be 'deny' or 'omit'")


# --- identity -------------------------------------------------------------------------------


def match_condition(model: IdentityModel) -> str:
    """The CEL ``matchConditions`` expression that is true for agents."""
    def users(pool):
        return sorted({u for i in pool if (u := i.kubernetes_username)})

    def groups(pool):
        return sorted(i.id for i in pool if i.kind == "group")

    def in_groups(names) -> str:
        return ("(has(request.userInfo.groups) && "
                f"request.userInfo.groups.exists(g, g in {_cel_list(names)}))")

    bg = [i for i in model.break_glass if i.platform == "kubernetes"]
    if model.mode == "deny-by-default":
        exempt = model.exempt("kubernetes")
        parts = [f"!(request.userInfo.username in {_cel_list(users(exempt))})",
                 "!(request.userInfo.username.startsWith('system:') && "
                 "!request.userInfo.username.startsWith('system:serviceaccount:'))",
                 f"!{in_groups([*groups(exempt), *_CONTROL_PLANE_GROUPS])}"]
        return " && ".join(parts)
    agents = model.agents_for("kubernetes")
    is_agent = []
    if users(agents):
        is_agent.append(f"request.userInfo.username in {_cel_list(users(agents))}")
    if groups(agents):
        is_agent.append(in_groups(groups(agents)))
    if not is_agent:
        return "false"
    parts = ["(" + " || ".join(is_agent) + ")"]
    if users(bg):
        parts.append(f"!(request.userInfo.username in {_cel_list(users(bg))})")
    if groups(bg):
        parts.append(f"!{in_groups(groups(bg))}")
    return " && ".join(parts)


# --- rule compilation -------------------------------------------------------------------------

# request.subResource, .name and .namespace are *absent*, not empty, when
# unset, and an expression error fails closed (found on kind: every agent
# UPDATE of a deployment was denied). Every policy reads them through these
# guarded variables.
_VARIABLES = [
    {"name": "sub", "expression": "has(request.subResource) ? request.subResource : ''"},
    {"name": "ns", "expression": "has(request.namespace) ? request.namespace : ''"},
    {"name": "name", "expression":
        "has(request.name) && request.name != '' ? request.name : "
        "(object != null && has(object.metadata.name) ? object.metadata.name : "
        "(oldObject != null && has(oldObject.metadata.name) ? oldObject.metadata.name : ''))"},
]
_NAME = "variables.name"


def _meta_diff(field_name: str) -> str:
    return (f"(has(object.metadata.{field_name}) ? object.metadata.{field_name} : {{}}) != "
            f"(has(oldObject.metadata.{field_name}) ? oldObject.metadata.{field_name} : {{}})")


def _template(flags: frozenset[str], obj: str) -> str | None:
    if "pod" in flags:
        return f"{obj}.spec"
    if "template" in flags:
        return f"{obj}.spec.template.spec"
    if "jobtemplate" in flags:
        return f"{obj}.spec.jobTemplate.spec.template.spec"
    return None


def _template_meta(flags: frozenset[str], obj: str) -> str | None:
    if "template" in flags:
        return f"{obj}.spec.template.metadata"
    if "jobtemplate" in flags:
        return f"{obj}.spec.jobTemplate.spec.template.metadata"
    return None


@dataclass(frozen=True)
class Clause:
    """One kind of request a rule covers: operation, subresource ('' for
    the object itself, '*' for any) and an optional CEL diff condition."""

    operation: str
    subresource: str = ""
    condition: str | None = None


def clauses_for(verb: str, kind: str, flags: frozenset[str]) -> tuple[list[Clause], str | None]:
    """The admission requests an Aegis action verb on ``kind`` becomes, or a
    reason it cannot be enforced here."""
    if verb in _NOT_ADMITTED:
        return [], _NOT_ADMITTED[verb]
    if verb == ANY_ACTION:
        return [Clause(op, "*") for op in ("CREATE", "UPDATE", "DELETE", "CONNECT")], None
    if verb == "delete":
        # an eviction (what kubectl drain sends) deletes a pod
        extra = [Clause("CREATE", "eviction")] if kind in ("pod", "*") else []
        return [Clause("DELETE"), *extra], None
    if verb in ("create", "run"):
        return [Clause("CREATE")], None
    if verb in _UPDATE_VERBS:
        return [Clause("UPDATE", "*")], None
    if verb == "apply":
        return [Clause("CREATE"), Clause("UPDATE")], None
    if verb == "scale":
        if "scale" not in flags:
            return [], f"{kind} has no scale subresource"
        return [Clause("UPDATE", "scale"),
                Clause("UPDATE", "", "has(object.spec.replicas) && (!has(oldObject.spec.replicas)"
                                     " || object.spec.replicas != oldObject.spec.replicas)")], None
    if verb == "set-image":
        tpl = _template(flags, "object")
        if tpl is None:
            return [], f"{kind} has no containers"
        old = _template(flags, "oldObject")
        return [Clause("UPDATE", "", f"{tpl}.containers.map(c, c.image) != "
                                     f"{old}.containers.map(c, c.image)")], None
    if verb == "rollout-restart":
        new, old = _template_meta(flags, "object"), _template_meta(flags, "oldObject")
        if new is None:
            return [], f"{kind} has no pod template to restart"
        key = "'kubectl.kubernetes.io/restartedAt'"
        pick = ("(has({m}.annotations) && {k} in {m}.annotations ? {m}.annotations[{k}] : '')")
        return [Clause("UPDATE", "", pick.format(m=new, k=key) + " != "
                       + pick.format(m=old, k=key))], None
    if verb == "rollout-undo":
        new, old = _template(flags, "object"), _template(flags, "oldObject")
        if new is None or "pod" in flags:
            return [], f"{kind} has no rollout history"
        return [Clause("UPDATE", "", f"{new} != {old}")], None
    if verb in ("cordon", "uncordon", "drain"):
        if kind != "node":
            return [], f"{verb} applies to nodes"
        on = ("has(object.spec.unschedulable) && object.spec.unschedulable")
        was = ("has(oldObject.spec.unschedulable) && oldObject.spec.unschedulable")
        cond = f"({on}) && !({was})" if verb != "uncordon" else f"!({on}) && ({was})"
        return [Clause("UPDATE", "", cond)], None
    if verb == "label":
        return [Clause("UPDATE", "", _meta_diff("labels"))], None
    if verb == "annotate":
        return [Clause("UPDATE", "", _meta_diff("annotations"))], None
    if verb == "taint":
        if kind != "node":
            return [], "taints apply to nodes"
        taints = ("(has(object.spec.taints) ? object.spec.taints : []) != "
                  "(has(oldObject.spec.taints) ? oldObject.spec.taints : [])")
        return [Clause("UPDATE", "", taints)], None
    if verb in ("exec", "attach", "port-forward", "proxy"):
        if kind not in ("pod", "service", "node") or (verb != "proxy" and kind != "pod"):
            return [], f"{verb} applies to pods"
        sub = {"port-forward": "portforward"}.get(verb, verb)
        return [Clause("CONNECT", sub)], None
    return [], f"action {verb!r} has no admission equivalent in this compiler"


@dataclass
class _Rule:
    c: Constraint
    status: str = ""
    reason: str | None = None
    kinds: list[tuple[str, str, bool, frozenset[str], str]] = field(default_factory=list)
    namespaces: list[str] | None = None
    enforced: list[dict[str, Any]] = field(default_factory=list)
    not_enforced: list[str] = field(default_factory=list)
    over: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    policy: str | None = None
    expression: str | None = None
    resource_rules: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.c.id, "effect": self.c.effect, "status": self.status}
        if self.reason:
            d["reason"] = self.reason
        if self.enforced:
            d["enforced"] = self.enforced
            d["policy"] = self.policy
        for key, value in (("not_enforced", self.not_enforced), ("over_enforced", self.over),
                           ("notes", self.notes)):
            if value:
                d[key] = value
        return d


def _kinds_for(pattern: str) -> tuple[list[tuple[str, str, bool, frozenset[str], str]],
                                      str | None, str]:
    """``(kinds, over-note, name glob)`` for a resource pattern: each kind as
    ``(kind, group, resource, namespaced, flags)``; kind ``*`` is every
    resource."""
    kind_glob, _, name = pattern.partition("/")
    name = name or "*"
    if kind_glob == "*":
        return [("*", "*", "*", True, frozenset())], None, name
    if set("*?[") & set(kind_glob):
        hits = [(k, g, r, ns, f) for k, (g, r, ns, f) in sorted(REGISTRY.items())
                if fnmatch.fnmatchcase(k, kind_glob)]
        return hits, (f"kind pattern {kind_glob!r} is compiled for the known kinds it matches "
                      f"({', '.join(h[0] for h in hits) or 'none'}); others are client-side "
                      "only"), name
    if kind_glob in REGISTRY:
        g, r, ns, f = REGISTRY[kind_glob]
        return [(kind_glob, g, r, ns, f)], None, name
    plural = kind_glob[:-1] + "ies" if kind_glob.endswith("y") else kind_glob + "s"
    return [(kind_glob, "*", plural, True, frozenset())], (
        f"{kind_glob!r} is not a built-in kind: compiled as resource {plural!r} in any API "
        "group, which may also match another group's resource of that name"), name


def _scope(rule: _Rule, target: KubernetesTarget) -> None:
    for key, value in sorted(rule.c.scope.items()):
        if key == "env":
            if target.env is None:
                rule.over.append(f"scope env={value!r}: cluster {target.cluster} has no "
                                 "environment in environments.yaml, so the rule is compiled "
                                 "unconditionally (the CLI escalates an unresolved "
                                 "environment)")
            elif not scope_value_matches(value, target.env):
                rule.reason = (f"scope env={value!r} does not include cluster "
                               f"{target.cluster}'s environment {target.env!r}")
                return
        elif key in ("cluster", "context"):
            if not scope_value_matches(value, target.cluster):
                rule.reason = f"scope {key}={value!r} is not cluster {target.cluster}"
                return
        elif key == "namespace":
            rule.namespaces = [str(v) for v in (value if isinstance(value, list) else [value])]
        else:
            rule.over.append(f"scope {key}={value!r} is not visible at admission; the "
                             "condition is dropped, so the deny applies more widely")


def _compile_rule(c: Constraint, target: KubernetesTarget) -> _Rule:
    rule = _Rule(c)
    if c.provider != "kubernetes":
        rule.status, rule.reason = "not-applicable", (
            f"provider {c.provider}: not compiled by the kubernetes target")
        return rule
    _scope(rule, target)
    if rule.reason:
        rule.status = "not-applicable"
        return rule
    if c.time_window:
        rule.not_enforced.append("admission policies have no clock (verified on kind); the "
                                 "time window stays client-side")
    if c.rate_limit:
        rule.not_enforced.append("rate limits have no admission equivalent; client-side only")
    if c.effect == "ESCALATE":
        if target.escalate == "omit":
            rule.not_enforced.append("ESCALATE left client-only (--escalate omit)")
        else:
            rule.over.append("ESCALATE compiles to a deny: admission cannot ask")
    if rule.not_enforced:
        rule.status = "not-enforced"
        return rule
    if c.resource_pattern.startswith("manifest/"):
        rule.status = "not-enforced"
        rule.not_enforced.append("manifest files are a client-side notion; write rules on the "
                                 "kinds they contain")
        return rule

    kinds, kind_note, name = _kinds_for(c.resource_pattern)
    if kind_note:
        (rule.not_enforced if "client-side" in kind_note else rule.over).append(kind_note)
    verbs = sorted(c.actions)
    disjuncts: list[str] = []
    rules_by_group: dict[tuple[str, str], set[str]] = {}
    for kind, group, resource, namespaced, flags in kinds:
        if "unadmitted" in flags:
            rule.not_enforced.append(f"{kind}: never admitted; RBAC is the control")
            continue
        for verb in verbs:
            clauses, why = clauses_for(verb, kind, flags)
            if not clauses:
                rule.not_enforced.append(f"{kind}: {why}")
                continue
            parts, requests = [], []
            for cl in clauses:
                cg, cr = group, resource
                if cr == "*" and cl.subresource == "eviction":
                    cg, cr = "", "pods"  # evictions exist only for pods
                cond = [f"request.operation == {_cel(cl.operation)}"]
                if cr != "*":
                    cond.append(f"request.resource.resource == {_cel(cr)}")
                    if cg != "*":
                        cond.append(f"request.resource.group == {_cel(cg)}")
                if cl.subresource != "*":
                    cond.append(f"variables.sub == {_cel(cl.subresource)}")
                if cl.condition:
                    cond.append(f"({cl.condition})")
                parts.append("(" + " && ".join(cond) + ")")
                res = cr if not cl.subresource else (
                    f"{cr}/*" if cl.subresource == "*" else f"{cr}/{cl.subresource}")
                rules_by_group.setdefault((cg, res), set()).add(cl.operation)
                if cl.subresource == "*" and cr != "*":
                    rules_by_group.setdefault((cg, cr), set()).add(cl.operation)
                if cr == "*":
                    rules_by_group.setdefault((cg, "*"), set()).add(cl.operation)
                requests.append(f"{cl.operation} {res}")
            disjuncts.append("(" + " || ".join(parts) + ")")
            rule.enforced.append({"kind": kind, "action": verb, "requests": requests})
            if verb == "drain":
                rule.not_enforced.append("node: a drain's pod evictions are not tied to the "
                                         "node at admission (only its cordon is); a pod delete "
                                         "rule covers evictions")
        if rule.namespaces and not namespaced and kind != "*":
            rule.notes.append(f"{kind} is cluster-scoped: the namespace scope never matches it "
                              "at admission")

    # the namespace cascade: `kubectl delete ns x` is also a delete of */* in x,
    # so a namespace-scoped rule covering */* deletes also denies deleting x
    cascade = None
    if (("delete" in c.actions or ANY_ACTION in c.actions) and rule.namespaces
            and fnmatch.fnmatchcase("*/*", c.resource_pattern)):
        ns_match = " || ".join(f"({_NAME}).matches({_cel(glob_to_re2(n))})"
                               for n in rule.namespaces)
        cascade = ('(request.operation == "DELETE" && request.resource.resource == '
                   f'"namespaces" && request.resource.group == "" && ({ns_match}))')
        rules_by_group.setdefault(("", "namespaces"), set()).add("DELETE")
        rule.enforced.append({"kind": "namespace", "action": "delete",
                              "requests": ["DELETE namespaces"], "cascade": True})

    if not disjuncts and cascade is None:
        rule.status = "not-enforced"
        return rule
    match = []
    if disjuncts:
        body = " || ".join(disjuncts)
        if name != "*":
            body = f"({_NAME}).matches({_cel(glob_to_re2(name))}) && ({body})"
            if any(r.startswith("CREATE") for e in rule.enforced for r in e["requests"]):
                rule.notes.append("an object created with generateName has no name at "
                                  "admission, so a name-specific create rule does not match it")
        if rule.namespaces:
            ns = " || ".join(f"variables.ns.matches({_cel(glob_to_re2(n))})"
                             for n in rule.namespaces)
            body = f"({ns}) && ({body})"
        match.append(f"({body})")
    if cascade:
        match.append(cascade)
    rule.expression = "!(" + " || ".join(match) + ")"
    rule.resource_rules = [
        {"apiGroups": [g], "apiVersions": ["*"], "operations": sorted(ops), "resources": [r]}
        for (g, r), ops in sorted(rules_by_group.items())]
    if rule.not_enforced:
        rule.status = "partial"
    elif rule.over:
        rule.status = "over-enforced"
    else:
        rule.status = "exact"
    return rule


def _policy_name(rule_id: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", rule_id.lower()).strip("-")[:200] or "rule"
    if slug != rule_id:
        slug += "-" + hashlib.sha256(rule_id.encode()).hexdigest()[:8]
    return f"aegis-{slug}"


def _guardrails() -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Self-protection that admission *can* see (design §4.3): no tokens for
    other ServiceAccounts, no pods (or pod templates) under another
    ServiceAccount than the agent's own."""
    own_sa = ("request.userInfo.username.startsWith('system:serviceaccount:' + variables.ns "
              "+ ':') ? request.userInfo.username.split(':')[3] : 'default'")
    spec_sa = "(has({s}.serviceAccountName) ? {s}.serviceAccountName : 'default')"
    workload = []
    for kind, (group, resource, _ns, flags) in sorted(REGISTRY.items()):
        tpl = _template(flags, "object")
        if tpl is None:
            continue
        workload.append(f"(request.resource.resource == {_cel(resource)} && "
                        f"request.resource.group == {_cel(group)} && "
                        f"{spec_sa.format(s=tpl)} != variables.ownSA)")
    rules = [{"apiGroups": [""], "apiVersions": ["*"], "operations": ["CREATE"],
              "resources": ["serviceaccounts/token"]}]
    by_group: dict[str, list[str]] = {}
    for kind, (group, resource, _ns, flags) in sorted(REGISTRY.items()):
        if _template(flags, "object") is not None:
            by_group.setdefault(group, []).append(resource)
    rules += [{"apiGroups": [g], "apiVersions": ["*"], "operations": ["CREATE", "UPDATE"],
               "resources": sorted(rs)} for g, rs in sorted(by_group.items())]
    validations = [
        {"expression": "variables.sub != 'token' || request.userInfo.username == "
                       "'system:serviceaccount:' + variables.ns + ':' + variables.name",
         "messageExpression": "'aegis guardrail: agents may not mint tokens for "
                              "ServiceAccount ' + variables.ns + '/' + variables.name"},
        {"expression": "variables.sub != '' || !(" + " || ".join(workload) + ")",
         "messageExpression": "'aegis guardrail: agents may run pods only as their own "
                              "ServiceAccount (' + variables.ownSA + ')'"},
    ]
    doc = {"variables": [{"name": "ownSA", "expression": own_sa}],  # after _VARIABLES
           "matchConstraints": {"resourceRules": rules}, "validations": validations}
    described = [
        {"name": "serviceaccount-token", "why": "agents cannot mint a token for another "
                                                "ServiceAccount (serviceaccounts/token)"},
        {"name": "pod-serviceaccount", "why": "pods and pod templates created or updated by an "
                                              "agent must run as the agent's own ServiceAccount "
                                              "(or 'default' for a non-ServiceAccount agent)"},
    ]
    return doc, described


def compile_kubernetes(
    snapshot: VerifiedSnapshot,
    model: IdentityModel,
    target: KubernetesTarget,
    *,
    identity_sha256: str = "",
) -> CompileResult:
    model.require_platform("kubernetes")
    agent_condition = match_condition(model)
    actions = ["Deny", "Audit"] if model.enforcement == "enforce" else ["Warn", "Audit"]
    docs: list[dict[str, Any]] = []
    labels = {"app.kubernetes.io/managed-by": "aegis",
              "aegis.dev/snapshot": snapshot.digest[:16]}

    def add(name: str, spec: dict[str, Any], rule_id: str) -> None:
        docs.append({"apiVersion": API_VERSION, "kind": "ValidatingAdmissionPolicy",
                     "metadata": {"name": name, "labels": labels,
                                  "annotations": {"aegis.dev/rule": rule_id}},
                     "spec": {"failurePolicy": "Fail",
                              "matchConditions": [{"name": "aegis-agent",
                                                   "expression": agent_condition}],
                              **spec,
                              "variables": [*_VARIABLES, *spec.get("variables", [])]}})
        docs.append({"apiVersion": API_VERSION, "kind": "ValidatingAdmissionPolicyBinding",
                     "metadata": {"name": name, "labels": labels},
                     "spec": {"policyName": name, "validationActions": actions}})

    guard_spec, guard_desc = _guardrails()
    add("aegis-guardrails", guard_spec, "self-protection")

    rules = []
    policies: dict[str, str] = {"aegis-guardrails": "self-protection"}
    for c in snapshot.constraints:
        rule = _compile_rule(c, target)
        if rule.expression:
            rule.policy = _policy_name(c.id)
            if rule.policy in policies:
                raise CompileError(f"two rules compile to policy {rule.policy}")
            policies[rule.policy] = c.id
            message = f"aegis: rule {c.id} blocks this request"
            add(rule.policy, {
                "matchConstraints": {"resourceRules": rule.resource_rules},
                "validations": [{"expression": rule.expression,
                                 "messageExpression": _cel(message + ": ") +
                                 " + request.operation + ' ' + request.resource.resource"
                                 " + (variables.sub != '' ? '/' + variables.sub : '')"
                                 " + ' ' + variables.name"}],
            }, c.id)
        rules.append(rule.to_dict())

    text = yaml.safe_dump_all(docs, sort_keys=False, width=100)
    files = {"policies.yaml": text}
    counts: dict[str, int] = {}
    for r in rules:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    coverage = {
        "target": "kubernetes-vap", "cluster": target.cluster, "env": target.env,
        "mode": model.mode, "enforcement": model.enforcement,
        "validation_actions": actions,
        "summary": dict(sorted(counts.items())), "rules": rules,
        "excluded": list(snapshot.excluded),
        "self_protection": guard_desc,
        "not_enforced_by_this_layer": list(NOT_ENFORCED_BY_THIS_LAYER),
    }
    files["coverage.json"] = pretty_json(coverage)
    files["coverage.md"] = _coverage_md(coverage)
    manifest = {
        "aegis_version": snapshot.aegis_version, "target": "kubernetes-vap",
        "cluster": target.cluster, "env": target.env, "mode": model.mode,
        "enforcement": model.enforcement, "validation_actions": actions,
        "escalate": target.escalate, "snapshot_digest": snapshot.digest,
        "identity_model_sha256": identity_sha256, "policies": policies,
        "files": sorted(files),
    }
    manifest["output_digest"] = sha256_text(canonical_json(
        {rel: sha256_text(t) for rel, t in sorted(files.items())}))
    files["manifest.json"] = pretty_json(manifest)
    return CompileResult(files, coverage, manifest, docs)


def _coverage_md(cov: dict[str, Any]) -> str:
    lines = [f"# Aegis coverage: Kubernetes ValidatingAdmissionPolicy for cluster "
             f"{cov['cluster']}", "",
             f"Environment: {cov['env'] or 'not mapped'}; identity model: {cov['mode']}, "
             f"{cov['enforcement']} (validationActions {cov['validation_actions']}).", ""]
    if cov["enforcement"] != "enforce":
        lines += ["**Report only.** Bindings warn and audit instead of denying. Review the "
                  "warnings and `aegis audit-identity`, then set `enforcement: enforce` in "
                  "agents.yaml (a signed change) and compile again.", ""]
    lines += ["| status | rules |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in cov["summary"].items()]
    lines += ["", "## Rules", ""]
    for r in cov["rules"]:
        if r["status"] == "not-applicable":
            continue
        lines.append(f"### `{r['id']}`: {r['status']}"
                     + (f" (policy `{r['policy']}`)" if r.get("policy") else ""))
        for e in r.get("enforced", []):
            lines.append(f"- enforced: {e['kind']} {e['action']} ({', '.join(e['requests'])})")
        for key, label in (("not_enforced", "not enforced"), ("over_enforced", "over-enforced"),
                           ("notes", "note")):
            lines += [f"- {label}: {item}" for item in r.get(key, [])]
        lines.append("")
    skipped = [r for r in cov["rules"] if r["status"] == "not-applicable"]
    if skipped:
        lines += ["## Not applicable to this target", ""]
        lines += [f"- `{r['id']}`: {r['reason']}" for r in skipped]
        lines.append("")
    if cov["excluded"]:
        lines += ["## Excluded from the snapshot", ""]
        lines += [f"- `{e['id']}`: {e['reason']}" for e in cov["excluded"]]
        lines.append("")
    lines += ["## Self-protection (policy `aegis-guardrails`)", ""]
    lines += [f"- {s['name']}: {s['why']}" for s in cov["self_protection"]]
    lines += ["", "## Not enforced by this layer", ""]
    lines += [f"- {n}" for n in cov["not_enforced_by_this_layer"]]
    return "\n".join(lines) + "\n"
