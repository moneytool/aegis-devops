#!/usr/bin/env python3
"""Acceptance run for ``aegis compile kubernetes`` on a local kind cluster
(design v0.3, §6.6, §8): compiled ValidatingAdmissionPolicies applied to a
real API server, every case run as an agent ServiceAccount, the admin and a
break-glass identity -- and, for the agent, compared with the client-side
verdict for the same kubectl argv (the parity corpus).

    kind create cluster --name aegis-vap --image kindest/node:v1.36.1
    venv/bin/python scripts/kube_acceptance.py --context kind-aegis-vap

Writes are server-side dry runs wherever kubectl supports them, so nothing is
deleted; the exceptions (rollout restart, exec, token, eviction) touch only
throwaway objects the script creates. Local only: no cloud account.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from aegis_core.compile.kubernetes import KubernetesTarget, compile_kubernetes  # noqa: E402
from aegis_core.identity import load_identity_model  # noqa: E402
from aegis_core.interceptor import AegisInterceptor  # noqa: E402
from aegis_core.parser import from_kubectl_multi  # noqa: E402
from aegis_core.store import (  # noqa: E402
    Constraint,
    ConstraintStore,
    VerifiedSnapshot,
    _canonical,
    _constraint_to_dict,
)

AGENT_SA = "system:serviceaccount:agents:coder"
IDENTITIES = {
    "agent": ["--as", AGENT_SA, "--as-group", "system:serviceaccounts",
              "--as-group", "system:serviceaccounts:agents", "--as-group", "system:authenticated"],
    "admin": [],
    "break-glass": ["--as", "oncall", "--as-group", "aegis:break-glass",
                    "--as-group", "system:authenticated"],
}
NODE = "{node}"


def _rule(id: str, pattern: str, actions: list[str], **kw) -> Constraint:
    return Constraint.create(
        id=id, provider="kubernetes", resource_pattern=pattern, actions=set(actions),
        effect=kw.pop("effect", "BLOCK"), constraint_class="deletion", principal="admin",
        source_ref="kube-acceptance", source_timestamp="2026-09-29T00:00:00+00:00",
        rule_text=f"acceptance: {id}", **kw)


RULES = [
    _rule("no-node-changes", "node/*", ["delete", "cordon", "drain", "taint"]),
    _rule("prod-no-deletes", "*/*", ["delete"], scope={"namespace": "prod"}),
    _rule("app-config", "configmap/ap*", ["delete", "update", "patch"],
          scope={"namespace": "staging"}),
    _rule("no-exec", "pod/*", ["exec"]),
    _rule("deploy-changes", "deployment/*",
          ["scale", "set-image", "rollout-restart", "rollout-undo"], effect="ESCALATE",
          scope={"namespace": "staging"}),
    # rollout-undo is over-enforced: it also stops a restart (review of #20)
    _rule("qa-undo-only", "deployment/*", ["rollout-undo"], scope={"namespace": "qa"}),
    # a namespace scope must never match a cluster-scoped request (review of #20)
    _rule("namespaced-priorityclass", "priorityclass/*", ["create"],
          scope={"namespace": "*"}),
    _rule("no-staging-pod-deletes", "pod/*", ["delete"], scope={"namespace": "staging"}),
]

# (name, kubectl argv after the global flags, agent expected, parity class)
# parity: "identical" (the client and the cluster must agree for the agent),
# "over" (documented over-enforcement: the cluster denies, the client allows),
# "server-only" (a guardrail with no client rule), "control" (allowed for all)
CASES = [
    ("delete node", f"delete node {NODE} --dry-run=server", "deny", "identical"),
    ("cordon node", f"cordon {NODE} --dry-run=server", "deny", "identical"),
    ("taint node", f"taint nodes {NODE} aegis=probe:NoSchedule --dry-run=server", "deny",
     "identical"),
    ("delete namespace prod (cascade)", "delete ns prod --dry-run=server", "deny", "identical"),
    ("delete pod in prod", "-n prod delete pod web --dry-run=server", "deny", "identical"),
    ("delete all configmaps in prod", "-n prod delete cm --all --dry-run=server", "deny",
     "identical"),
    ("delete configmap staging/app", "-n staging delete cm app --dry-run=server", "deny",
     "identical"),
    ("delete configmap staging/other", "-n staging delete cm other --dry-run=server", "allow",
     "control"),
    ("patch configmap staging/app", "-n staging patch cm app -p '{\"data\":{\"a\":\"c\"}}' "
     "--dry-run=server", "deny", "identical"),
    ("scale deployment (ESCALATE)", "-n staging scale deploy web --replicas=3 --dry-run=server",
     "deny", "identical"),
    ("set image (ESCALATE)", "-n staging set image deploy/web "
     "pause=registry.k8s.io/pause:3.9 --dry-run=server", "deny", "identical"),
    ("rollout restart (ESCALATE)", "-n staging rollout restart deploy/web", "deny",
     "identical"),
    # after the admin's restart above, the previous revision differs only in a
    # template annotation (review of #20)
    ("rollout undo of a restart (ESCALATE)", "-n staging rollout undo deploy/web "
     "--dry-run=server", "deny", "identical"),
    ("set image, init container only", "-n staging set image deploy/web-init "
     "init=registry.k8s.io/pause:3.9 --dry-run=server", "deny", "identical"),
    ("rollout restart under an undo-only rule", "-n qa rollout restart deploy/web", "deny",
     "over"),
    ("create priorityclass, namespace '*' rule", "create priorityclass aegis-probe --value=1 "
     "--dry-run=server", "allow", "identical"),
    ("label deployment", "-n staging label deploy web aegis=probe --overwrite --dry-run=server",
     "allow", "control"),
    ("exec into pod", "-n prod exec web -- /no-such-binary", "deny", "identical"),
    ("evict a staging pod", "EVICT staging", "deny", "server-only"),
    ("token for another ServiceAccount", "-n agents create token default", "deny",
     "server-only"),
    ("pod as another ServiceAccount", "-n agents run p1 --image=registry.k8s.io/pause:3.10 "
     "--dry-run=server", "deny", "server-only"),
    ("pod as own ServiceAccount", "-n agents run p2 --image=registry.k8s.io/pause:3.10 "
     "--overrides='{\"spec\":{\"serviceAccountName\":\"coder\"}}' --dry-run=server", "allow",
     "control"),
]


def _agents_yaml(path: Path) -> None:
    path.write_text(yaml.safe_dump({
        "version": 1, "principal": "admin", "mode": "deny-by-default",
        "enforcement": "enforce",
        "break_glass": [{"platform": "kubernetes", "kind": "group", "id": "aegis:break-glass"}],
        "trusted": [{"platform": "kubernetes", "kind": "group", "id": "kubeadm:cluster-admins"},
                    {"platform": "kubernetes", "kind": "user", "id": "kubernetes-admin"}],
    }))


def _kubectl(context: str, argv: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", "--context", context, *argv], capture_output=True,
                          text=True, check=check)


def _setup(context: str) -> str:
    k = lambda *a: _kubectl(context, list(a))  # noqa: E731
    for ns in ("agents", "prod", "staging", "qa"):
        k("create", "ns", ns)
    k("-n", "agents", "create", "sa", "coder")
    k("create", "clusterrolebinding", "aegis-acc-coder", "--clusterrole=cluster-admin",
      "--serviceaccount=agents:coder")
    k("create", "clusterrolebinding", "aegis-acc-bg", "--clusterrole=cluster-admin",
      "--group=aegis:break-glass")
    k("-n", "staging", "create", "configmap", "app", "--from-literal=a=b")
    k("-n", "staging", "create", "configmap", "other", "--from-literal=a=b")
    k("-n", "prod", "create", "configmap", "app", "--from-literal=a=b")
    k("-n", "staging", "create", "deployment", "web", "--image=registry.k8s.io/pause:3.10")
    k("-n", "prod", "run", "web", "--image=registry.k8s.io/pause:3.10")
    k("-n", "qa", "create", "deployment", "web", "--image=registry.k8s.io/pause:3.10")
    k("-n", "staging", "create", "deployment", "web-init", "--image=registry.k8s.io/pause:3.10")
    k("-n", "staging", "patch", "deploy", "web-init", "--type=json", "-p", json.dumps([
        {"op": "add", "path": "/spec/template/spec/initContainers", "value": [
            {"name": "init", "image": "registry.k8s.io/pause:3.10",
             "command": ["/pause", "-v"]}]}]))
    k("-n", "staging", "wait", "--for=condition=Available", "deploy/web", "--timeout=120s")
    k("-n", "prod", "wait", "--for=condition=Ready", "pod/web", "--timeout=120s")
    out = k("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")
    return out.stdout.strip()


def _evict(context: str, identity: list[str]) -> subprocess.CompletedProcess:
    pod = _kubectl(context, ["-n", "staging", "get", "pods", "-l", "app=web", "-o",
                             "jsonpath={.items[0].metadata.name}"]).stdout.strip()
    body = json.dumps({"apiVersion": "policy/v1", "kind": "Eviction",
                       "metadata": {"name": pod, "namespace": "staging"},
                       "deleteOptions": {"dryRun": ["All"]}})
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(body)
    return _kubectl(context, [*identity, "create", "--raw",
                              f"/api/v1/namespaces/staging/pods/{pod}/eviction", "-f", f.name])


def _client_verdict(store: ConstraintStore, argv: list[str]) -> str:
    interceptor = AegisInterceptor(store)
    verdicts = []
    for intent in from_kubectl_multi(["kubectl", *argv]):
        d = interceptor.intercept(intent)
        verdicts.append(d.would_be or d.verdict)
    return "deny" if any(v in ("BLOCK", "ESCALATE") for v in verdicts) else "allow"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--context", default="kind-aegis-vap")
    ap.add_argument("--out", default="build/kube-acceptance")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    agents = out / "agents.yaml"
    _agents_yaml(agents)
    model = load_identity_model(agents, authority_map={"admin": {"identity"}}, insecure=True)
    records = tuple(_canonical(_constraint_to_dict(c)) for c in sorted(RULES, key=lambda c: c.id))
    snap = VerifiedSnapshot._build(records=records, excluded=(), authority=(), inputs=(),
                                   settings=(), aegis_version="kube-acceptance")
    result = compile_kubernetes(snap, model, KubernetesTarget(cluster=args.context))
    (out / "policies.yaml").write_text(result.files["policies.yaml"])
    (out / "coverage.json").write_text(result.files["coverage.json"])

    node = _setup(args.context)
    _kubectl(args.context, ["delete", "validatingadmissionpolicybindings,"
                            "validatingadmissionpolicies", "-l",
                            "app.kubernetes.io/managed-by=aegis"])
    applied = _kubectl(args.context, ["apply", "-f", str(out / "policies.yaml")])
    if applied.returncode != 0:
        print(applied.stderr)
        return 2
    subprocess.run(["sleep", "5"], check=True)  # policy propagation

    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    for c in RULES:
        store.constraints[c.id] = c

    rows, failed = [], 0
    for name, cmd, agent_expected, parity in CASES:
        cmd = cmd.replace(NODE, node)
        for who, identity in IDENTITIES.items():
            if cmd.startswith("EVICT"):
                proc = _evict(args.context, identity)
            else:
                proc = _kubectl(args.context, [*identity, *shlex.split(cmd)])
            text = proc.stderr + proc.stdout
            got = "deny" if "ValidatingAdmissionPolicy" in text else "allow"
            want = agent_expected if who == "agent" else "allow"
            row = {"case": name, "identity": who, "server": got, "expected": want,
                   "pass": got == want}
            if who == "agent" and parity in ("identical", "over"):
                client = _client_verdict(store, shlex.split(cmd))
                row["client"] = client
                row["parity"] = (client == got) if parity == "identical" else (
                    client == "allow" and got == "deny")
                row["pass"] = row["pass"] and row["parity"]
            if not row["pass"]:
                failed += 1
                row["detail"] = text.strip().splitlines()[-1][:300] if text.strip() else ""
            rows.append(row)
            mark = "ok" if row["pass"] else "FAIL"
            parity_note = f" client={row['client']}" if "client" in row else ""
            print(f"{mark:<5} {name:<38} {who:<12} server={got}{parity_note}")
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"{len(rows) - failed}/{len(rows)} as expected -> {out / 'results.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
