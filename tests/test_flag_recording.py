"""No flag is silently dropped: every flag of every generated flag table, used on a
representative command of its tool, is recorded (in params under its long name, or in
metadata), is one of the tool's no-effect flags (parser._NO_EFFECT_FLAGS, each with why),
or the command is refused. Review round 20."""

import json
import os
import zipfile
from collections import Counter

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
    "field": "inputs", "raw-field": "inputs",  # gh -F/-f: the request's fields
    "method": "raw_action",  # gh api -X: the action, api-<method>
    "what-if": "dry_run",  # az deployment --what-if: a rehearsal
    "container": "containers",  # gcloud run: each container's own flags
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



# --- every command of the per-command tables (gh, az, aws, gcloud) -------------------

_VALUES = ["x", "1", "k=v", "{}", "[]", "true", "2026-01-01T00:00:00Z", "a,b"]


def _parses(argv: list[str]):
    try:
        return p.from_argv(argv)
    except ValueError:
        return None


def _wide_outcome(tool: str, base: list[str], flag: str, kind: str,
                  aliases: dict[str, str]) -> str:
    """``flag`` added to ``base`` with a dummy value of its kind (each candidate until one
    parses): recorded, no-effect, dropped, or refused (no value is accepted)."""
    no_effect = p._NO_EFFECT_FLAGS.get(tool, {})
    tries = [[f"--{flag}"]] if kind == "bool" else [
        [f"--{flag}", v] for v in _VALUES] + [[f"--{flag}"]]
    for extra in tries:
        intents = _parses([*base, *extra])
        if intents is None:
            continue
        if flag in no_effect:
            return "no-effect"
        want = {canonical_key(flag), canonical_key(flag.removeprefix("no-"))}
        for other in (RECORDED_AS.get(flag), aliases.get(flag)):
            if other:
                want.add(canonical_key(other))
        for intent in intents:
            keys = {canonical_key(k) for k in (*intent.params, *intent.metadata)}
            marks = {canonical_key(m) for m in intent.params.get("unresolved_scope", [])
                     if isinstance(m, str)}
            nested = {canonical_key(k) for v in intent.params.values() if isinstance(v, dict)
                      for inner in v.values() if isinstance(inner, dict) for k in inner}
            if want & (keys | marks | nested):
                return "recorded"
        return "recorded" if flag == "no-dry-run" else "dropped"
    return "refused"


def _first_parsing(candidates: list[list[str]]) -> list[str] | None:
    return next((c for c in candidates if _parses(c) is not None), None)


def _gh_commands():
    for command, flags in p._gh_flag_table().items():
        if command.startswith("_") or command == "root":
            continue
        words = command.split()
        base = _first_parsing([["gh", *words, *pos] for pos in (
            [], ["1"], ["a/b"], ["x"], ["x", "y"], ["1", "x"], ["a/b", "x"])])
        yield command, base, {n: "bool" if v[0] == "bool" else "value"
                              for n, v in flags.items()}, {}


def _az_commands():
    for command, entry in p._az_short_tables().items():
        words = command.split()
        if command.startswith("_") or not words or words[-1] not in p._AZ_VERBS:
            continue
        base = _first_parsing([["az", *words, "-n", "x", "-g", "rg"], ["az", *words, "-g", "rg"],
                               ["az", *words]])
        yield command, base, {n: "value" for n in p._az_longs(words)}, {}


def _aws_commands():
    with zipfile.ZipFile(p._AWS_OPTIONS_ARCHIVE) as archive:
        names = sorted(n for n in archive.namelist() if n.endswith(".json"))
        for name in names:
            service = name[:-5]
            for operation, spec in json.loads(archive.read(name)).get("s", {}).items():
                if "o" not in spec:
                    continue
                base = _first_parsing([["aws", service, operation],
                                       ["aws", service, operation, "x"]])
                yield (f"{service} {operation}", base,
                       {k: "bool" if a == "" else "value" for k, a in spec["o"].items()},
                       spec.get("al", {}))


def _gcloud_commands():
    for command, entry in p._gcloud_flag_tables().items():
        if command.startswith("_") or command == "root":
            continue
        words = command.split()
        base = _first_parsing([
            ["gcloud", *words, "x", "--zone", "z", "--region", "r"], ["gcloud", *words, "x"],
            ["gcloud", *words], ["gcloud", *words, "gs://b/k"],
            ["gcloud", *words, "gs://b/k", "gs://c/d"], ["gcloud", *words, "x", "--zone", "z"],
            ["gcloud", *words, "x", "--region", "r"]])
        flags = {**{n: "value" for n in entry["value"]}, **{n: "bool" for n in entry["bool"]},
                 **{n: "value" for n in entry.get("optional", [])}}
        yield command, base, {n: k for n, k in flags.items() if len(n) > 1}, entry.get("alias", {})


def _every_flag_of_every_command(tool: str) -> tuple[Counter, list[str], int, int]:
    commands = {"gh": _gh_commands, "az": _az_commands, "aws": _aws_commands,
                "gcloud": _gcloud_commands}[tool]
    counts: Counter = Counter()
    dropped: list[str] = []
    total = no_base = 0
    for command, base, flags, aliases in commands():
        total += 1
        if base is None:
            no_base += 1
            continue
        for flag, kind in flags.items():
            outcome = _wide_outcome(tool, base, flag, kind, aliases)
            counts[outcome] += 1
            if outcome == "dropped":
                dropped.append(f"{command} --{flag}")
    return counts, dropped, total, no_base


@pytest.mark.skipif(os.environ.get("AEGIS_SKIP_WIDE_FLAG_TEST") == "1",
                    reason="AEGIS_SKIP_WIDE_FLAG_TEST=1 skips the every-command flag check")
@pytest.mark.parametrize("tool", ["gh", "az", "aws", "gcloud"])
def test_no_flag_of_any_command_is_dropped(tool):
    """Every command of the tool's per-command table, and every flag of it, on a minimal
    command that parses: the flag is recorded, no-effect, or refused. (About 15s in all;
    AEGIS_SKIP_WIDE_FLAG_TEST=1 skips it.)"""
    counts, dropped, total, no_base = _every_flag_of_every_command(tool)
    assert not dropped, dropped[:50]
    assert no_base <= total // 100  # nearly every command has a minimal form that parses
