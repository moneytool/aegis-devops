"""No flag is silently dropped: every flag of every generated flag table, used on a
representative command of its tool, is recorded (in params under its long name, or in
metadata), is one of the tool's no-effect flags (parser._NO_EFFECT_FLAGS, each with why),
or the command is refused. Review round 20."""

import pytest

from aegis_core import parser as p
from aegis_core.intent import canonical_key

# Flags a parser records under another key, by design (each a documented reading).
RECORDED_AS = {
    "as": "impersonate", "as-group": "impersonate", "as-uid": "impersonate",
    "as-user-extra": "impersonate", "kube-as-user": "impersonate",
    "kube-as-group": "impersonate",  # one impersonation structure for every tool
    "filename": "file", "kustomize": "file",  # the manifest the command reads
    "set-string": "set", "set-literal": "set", "values": "values_files",  # helm values
    "kube-context": "context", "kube-apiserver": "server", "location": "region",
    "squash": "method", "merge": "method", "rebase": "method",  # gh pr merge's method
    "ids": "arm_id", "project": "project_number", "subscription": "subscription_name",
    "H": "header",
}


def _tables() -> dict[str, tuple[list[str], dict[str, str]]]:
    kubectl: dict[str, str] = {}
    for command, flags in p._KUBECTL_TABLE.items():
        if not command.startswith("_"):
            kubectl.update({name: kind for name, (kind, _letter) in flags.items()})
    gh = p._gh_flag_table()["pr merge"]
    aws = p._aws_command_table("ec2")["s"]["terminate-instances"]["o"]
    gcloud = p._gcloud_flag_table("compute instances create")
    return {
        "kubectl": (["kubectl", "delete", "pod", "x", "-n", "prod"], kubectl),
        "helm": (["helm", "upgrade", "r", "./c"],
                 {**{n: "value" for n in p._HELM_VALUE_FLAGS},
                  **{n: "bool" for n in p._HELM_BOOL_ONLY_FLAGS}}),
        "flux": (["flux", "suspend", "kustomization", "app"],
                 {**{n: "value" for n in p._FLUX_VALUE_FLAGS},
                  **{n: "bool" for n in p._FLUX_BOOL_FLAGS}}),
        "argocd": (["argocd", "app", "sync", "web"],
                   {**{n: "value" for n in p._ARGOCD_VALUE_FLAGS},
                    **{n: "bool" for n in p._ARGOCD_BOOL_FLAGS}}),
        "gh": (["gh", "pr", "merge", "42", "-s"],
               {n: "bool" if v[0] == "bool" else "value" for n, v in gh.items()}),
        "az": (["az", "vm", "delete", "-n", "v", "-g", "rg"],
               {n: "value" for n in p._az_longs(["vm", "delete"])}),
        "aws": (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1"],
                {**{n: "bool" if a == "" else "value" for n, a in aws.items()},
                 **{n: "value" if v else "bool" for n, v in p._AWS_GLOBAL_OPTIONS.items()}}),
        "gcloud": (["gcloud", "compute", "instances", "create", "vm", "--zone", "z"],
                   {**{n: "value" for n in gcloud["value"] if len(n) > 1},
                    **{n: "bool" for n in gcloud["bool"] if len(n) > 1}}),
    }


def _outcome(tool: str, base: list[str], flag: str, kind: str) -> str:
    no_effect = p._NO_EFFECT_FLAGS.get(tool, {})
    tries = [[f"--{flag}"]] if kind == "bool" else [
        [f"--{flag}", v] for v in ("1", "v", "1s", "a=b")] + [[f"--{flag}"]]
    for extra in tries:
        try:
            intents = p.from_argv([*base, *extra])
        except ValueError:
            continue
        if flag in no_effect:
            return "no-effect"
        want = {canonical_key(flag), canonical_key(flag.removeprefix("no-"))}
        if flag in RECORDED_AS:
            want.add(canonical_key(RECORDED_AS[flag]))
        for intent in intents:
            if want & {canonical_key(k) for k in (*intent.params, *intent.metadata)}:
                return "recorded"
        if flag == "no-dry-run":
            return "recorded"  # a real run: dry_run is absent, as for no flag at all
        return "dropped"
    return "refused"


@pytest.mark.parametrize("tool", ["kubectl", "helm", "flux", "argocd", "gh", "az", "aws",
                                  "gcloud"])
def test_no_flag_of_a_generated_table_is_dropped(tool):
    base, flags = _tables()[tool]
    dropped = [flag for flag, kind in sorted(flags.items())
               if _outcome(tool, base, flag, kind) == "dropped"]
    assert not dropped, dropped


def test_no_effect_flags_exclude_identity_auth_and_endpoints():
    never = ("as", "token", "password", "username", "server", "kubeconfig", "context",
             "insecure-skip-tls-verify", "certificate-authority", "client-certificate",
             "client-key", "header", "auth-token", "kube-as-user", "kube-token",
             "endpoint-url", "no-verify-ssl", "no-sign-request", "ca-bundle", "insecure",
             "grpc-web", "plaintext", "impersonate-service-account", "access-token-file")
    for tool, flags in p._NO_EFFECT_FLAGS.items():
        assert not set(flags) & set(never), tool
        assert all(isinstance(why, str) and why for why in flags.values()), tool
