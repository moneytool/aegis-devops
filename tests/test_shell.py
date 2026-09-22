"""REVIEW-4 T1.2: shell-string front end (split, unwrap, intents)."""

from datetime import UTC, datetime

import pytest

from aegis_core.shell import (
    ShellRejected,
    SimpleCommand,
    intents_from_command,
    split_compound,
    unwrap,
)

# --- split_compound ------------------------------------------------------------


def _argvs(command: str) -> list[list[str]]:
    return [c.argv for c in split_compound(command)]


@pytest.mark.parametrize(
    "command, expected",
    [
        (
            "kubectl get pods; kubectl delete node/w1",
            [["kubectl", "get", "pods"], ["kubectl", "delete", "node/w1"]],
        ),
        (
            "kubectl get pods && kubectl delete node/w1",
            [["kubectl", "get", "pods"], ["kubectl", "delete", "node/w1"]],
        ),
        (
            "kubectl get pods || kubectl delete node/w1",
            [["kubectl", "get", "pods"], ["kubectl", "delete", "node/w1"]],
        ),
        ("kubectl get pods | grep x", [["kubectl", "get", "pods"], ["grep", "x"]]),
        ("kubectl get pods |& tee log", [["kubectl", "get", "pods"], ["tee", "log"]]),
        (
            "kubectl get pods & kubectl delete node/w1",
            [["kubectl", "get", "pods"], ["kubectl", "delete", "node/w1"]],
        ),
        (
            "kubectl get pods\nkubectl delete node/w1",
            [["kubectl", "get", "pods"], ["kubectl", "delete", "node/w1"]],
        ),
        ("kubectl get pods;", [["kubectl", "get", "pods"]]),
        ("  kubectl   get pods  ", [["kubectl", "get", "pods"]]),
    ],
    ids=lambda v: repr(v) if isinstance(v, str) else "",
)
def test_split_compound_splits_on_every_separator(command, expected):
    assert _argvs(command) == expected


@pytest.mark.parametrize(
    "command, expected",
    [
        ("helm upgrade x ./c --set 'a=b;c'", [["helm", "upgrade", "x", "./c", "--set", "a=b;c"]]),
        (
            'helm upgrade x ./c --set "a=b&&c|d"',
            [["helm", "upgrade", "x", "./c", "--set", "a=b&&c|d"]],
        ),
        (
            "kubectl exec p -- sh -c 'echo hi; ls'",
            [["kubectl", "exec", "p", "--", "sh", "-c", "echo hi; ls"]],
        ),
        ("echo 'line1\nline2'", [["echo", "line1\nline2"]]),
        (r"kubectl delete pod/a\;b", [["kubectl", "delete", "pod/a;b"]]),
    ],
    ids=lambda v: repr(v) if isinstance(v, str) else "",
)
def test_split_compound_never_splits_inside_quotes_or_escapes(command, expected):
    assert _argvs(command) == expected


def test_split_compound_strips_and_records_redirections():
    (cmd,) = split_compound("kubectl get pods 2>&1 >/tmp/x >> log.txt < in.txt &>/dev/null")
    assert cmd.argv == ["kubectl", "get", "pods"]
    assert cmd.redirects == ["2>&1", ">/tmp/x", ">>log.txt", "<in.txt", "&>/dev/null"]


def test_split_compound_fd_digit_only_recognised_when_glued_to_a_redirect():
    (cmd,) = split_compound("kubectl scale deployment/x --replicas 2 > out")
    assert cmd.argv == ["kubectl", "scale", "deployment/x", "--replicas", "2"]
    assert cmd.redirects == [">out"]


def test_split_compound_marks_both_sides_of_a_pipeline():
    cmds = split_compound("kubectl get pods | grep x | wc -l; kubectl delete node/w1")
    assert [c.in_pipeline for c in cmds] == [True, True, True, False]
    assert cmds == [
        SimpleCommand(["kubectl", "get", "pods"], [], True),
        SimpleCommand(["grep", "x"], [], True),
        SimpleCommand(["wc", "-l"], [], True),
        SimpleCommand(["kubectl", "delete", "node/w1"], [], False),
    ]


def test_split_compound_empty_and_whitespace_only():
    assert split_compound("") == []
    assert split_compound("   \n  ") == []
    assert split_compound("; ;") == []


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete $(cat targets)",
        "kubectl delete `cat targets`",
        "kubectl delete pod/$NAME",
        'kubectl delete pod/"$NAME"',
        "kubectl delete pod/${NAME}",
        "cat <(kubectl get pods)",
        "kubectl get pods > >(tee log)",
        "kubectl apply -f - <<EOF\nkind: Pod\nEOF",
        "kubectl apply -f - <<< 'kind: Pod'",
        "(kubectl delete node/w1)",
        "eval kubectl delete node/w1",
        "exec kubectl delete node/w1",
        "source ./env.sh",
        ". ./env.sh",
        "echo node/w1 | xargs kubectl delete",
        "kubectl get pods >",
        "kubectl get pods 'unbalanced",
        'kubectl get pods "unbalanced',
        "kubectl get pods ;; kubectl delete node/w1",
    ],
    ids=repr,
)
def test_split_compound_rejects_unknowable_constructs(command):
    with pytest.raises(ShellRejected):
        split_compound(command)


def test_split_compound_brace_group_and_negation_are_stripped():
    # "{ ...; }" only groups and "!" only negates the exit status: neither
    # changes what runs, so the body is checked command by command.
    assert _argvs("{ kubectl get pods; kubectl delete node/w1; }") == [
        ["kubectl", "get", "pods"],
        ["kubectl", "delete", "node/w1"],
    ]
    assert _argvs("! kubectl get pods") == [["kubectl", "get", "pods"]]
    assert _argvs("{ ! sudo kubectl delete node/w1; }") == [
        ["sudo", "kubectl", "delete", "node/w1"]
    ]


def test_single_quoted_dollar_and_backtick_are_literal():
    (cmd,) = split_compound("kubectl get pods -o jsonpath='{$.items[*]}' --selector 'a=`b`'")
    assert cmd.argv == [
        "kubectl",
        "get",
        "pods",
        "-o",
        "jsonpath={$.items[*]}",
        "--selector",
        "a=`b`",
    ]


def test_shell_rejected_is_a_value_error_with_a_reason():
    with pytest.raises(ValueError) as excinfo:
        split_compound("kubectl delete $(cat f)")
    assert isinstance(excinfo.value, ShellRejected)
    assert excinfo.value.reason == "shell expansion ($...)"


# --- unwrap ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["sudo", "kubectl", "delete", "node/w1"], ["kubectl", "delete", "node/w1"]),
        (["sudo", "-u", "root", "kubectl", "delete", "node/w1"], ["kubectl", "delete", "node/w1"]),
        (
            ["sudo", "-uroot", "-E", "-H", "-n", "kubectl", "get", "pods"],
            ["kubectl", "get", "pods"],
        ),
        (
            ["sudo", "--user=root", "--preserve-env", "kubectl", "get", "pods"],
            ["kubectl", "get", "pods"],
        ),
        (["sudo", "--user", "root", "--", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["/usr/bin/sudo", "-EH", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["env", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (
            ["env", "-i", "-u", "HOME", "--unset=PATH", "kubectl", "get", "pods"],
            ["kubectl", "get", "pods"],
        ),
        (["timeout", "30", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (
            [
                "timeout",
                "-s",
                "KILL",
                "-k",
                "5",
                "--preserve-status",
                "30s",
                "kubectl",
                "get",
                "pods",
            ],
            ["kubectl", "get", "pods"],
        ),
        (["timeout", "--signal=TERM", "1m", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["nice", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["nice", "-n", "10", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["nice", "-10", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["nice", "--adjustment=5", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["nohup", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["command", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["command", "-p", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["time", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["time", "-p", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["--", "kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["k", "get", "pods"], ["kubectl", "get", "pods"]),
        (["tf", "apply"], ["terraform", "apply"]),
        (["tofu", "apply"], ["tofu", "apply"]),
        (["g", "push", "-f"], ["git", "push", "-f"]),
        (
            [
                "sudo",
                "-u",
                "admin",
                "env",
                "X=1",
                "timeout",
                "5",
                "nice",
                "nohup",
                "k",
                "get",
                "pods",
            ],
            ["kubectl", "get", "pods"],
        ),
        (["sh", "-c", "kubectl delete node/x"], ["kubectl", "delete", "node/x"]),
        (["bash", "-ec", "kubectl delete node/x"], ["kubectl", "delete", "node/x"]),
        (["bash", "-o", "pipefail", "-c", "sudo k delete node/x"], ["kubectl", "delete", "node/x"]),
        (["sudo", "sh", "-c", "kubectl delete node/x"], ["kubectl", "delete", "node/x"]),
        (["sh", "-c", "kubectl delete node/x", "sh", "extra"], ["kubectl", "delete", "node/x"]),
        (["kubectl", "get", "pods"], ["kubectl", "get", "pods"]),
        (["bash", "deploy.sh"], ["bash", "deploy.sh"]),
        (["command", "-v", "kubectl"], ["command", "-v", "kubectl"]),
        (["sudo"], ["sudo"]),
        (["sudo", "--"], ["sudo", "--"]),
        (["env"], ["env"]),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else "",
)
def test_unwrap_strips_launchers_and_applies_aliases(argv, expected):
    result, _env = unwrap(argv)
    assert result == expected


def test_unwrap_records_env_assignments_from_env_and_leading_assignments():
    argv, env = unwrap(
        ["KUBECONFIG=/x", "env", "AWS_PROFILE=prod", "FOO=bar", "kubectl", "get", "pods"]
    )
    assert argv == ["kubectl", "get", "pods"]
    assert env == {"KUBECONFIG": "/x", "AWS_PROFILE": "prod", "FOO": "bar"}


def test_unwrap_merges_env_from_inside_sh_c():
    argv, env = unwrap(["env", "A=1", "sh", "-c", "B=2 kubectl get pods"])
    assert argv == ["kubectl", "get", "pods"]
    assert env == {"A": "1", "B": "2"}


def test_unwrap_does_not_mutate_its_argument():
    argv = ["sudo", "k", "get", "pods"]
    unwrap(argv)
    assert argv == ["sudo", "k", "get", "pods"]


@pytest.mark.parametrize(
    "argv",
    [
        ["sudo", "-i"],
        ["sudo", "-s", "kubectl", "get", "pods"],
        ["sudo", "--login"],
        ["sudo", "--typo", "kubectl", "get", "pods"],
        ["sudo", "-Z", "kubectl", "get", "pods"],
        ["env", "-S", "kubectl delete node/x"],
        ["env", "--typo", "kubectl", "get", "pods"],
        ["timeout", "--typo", "5", "kubectl", "get", "pods"],
        ["nice", "--typo", "kubectl", "get", "pods"],
        ["xargs", "kubectl", "delete"],
        ["sudo", "xargs", "kubectl", "delete"],
        ["eval", "kubectl", "delete", "node/x"],
        ["exec", "kubectl", "delete", "node/x"],
        ["source", "env.sh"],
        [".", "env.sh"],
        ["sudo", "eval", "kubectl", "delete", "node/x"],
        ["sh", "-c", "sh -c 'kubectl delete node/x'"],
        ["bash", "-c", "sudo bash -c 'kubectl delete node/x'"],
        [
            "sh",
            "-c",
            "kubectl get pods; kubectl delete node/x",
        ],  # compound: use intents_from_command
        ["sh", "-c", "kubectl delete $(cat f)"],
        ["timeout", "5"],
        ["KUBECONFIG=/x"],
    ],
    ids=lambda v: " ".join(v),
)
def test_unwrap_rejects(argv):
    with pytest.raises(ShellRejected):
        unwrap(argv)


# --- intents_from_command ---------------------------------------------------------


def _summary(command: str) -> list[tuple[str, str, str]]:
    return [(i.provider, i.action, i.resource) for i in intents_from_command(command)]


def test_compound_semicolon_yields_both_intents_including_the_delete():
    assert _summary("kubectl get pods; kubectl delete node/w1") == [
        ("kubernetes", "get", "pod/*"),
        ("kubernetes", "delete", "node/w1"),
    ]


def test_sudo_wrapper_yields_the_delete():
    (intent,) = intents_from_command("sudo kubectl delete node/w1")
    assert (intent.provider, intent.action, intent.resource) == ("kubernetes", "delete", "node/w1")
    assert intent.metadata["wrappers"] == ["sudo"]


def test_pipe_into_unknown_binary_yields_one_read_intent():
    assert _summary("kubectl get pods | grep x") == [("kubernetes", "get", "pod/*")]


def test_pipe_from_unknown_binary_into_known_binary_yields_only_the_known_intent():
    assert _summary("cat manifest.yaml | kubectl apply -f -") == [
        ("kubernetes", "apply", "manifest/-")
    ]


def test_env_wrapper_sets_env_assignments_and_kubeconfig_metadata():
    (intent,) = intents_from_command("env KUBECONFIG=/root/.kube/prod kubectl delete node/w1")
    assert intent.action == "delete"
    assert intent.metadata["env_assignments"] == {"KUBECONFIG": "/root/.kube/prod"}
    assert intent.metadata["kubeconfig"] == "/root/.kube/prod"
    assert intent.metadata["wrappers"] == ["env"]


@pytest.mark.parametrize(
    "command, key, value",
    [
        ("AWS_PROFILE=prod aws ec2 describe-instances", "profile", "prod"),
        ("AWS_DEFAULT_REGION=us-east-1 aws ec2 describe-instances", "region", "us-east-1"),
        ("AWS_REGION=us-east-1 aws ec2 describe-instances", "region", "us-east-1"),
        ("CLOUDSDK_CORE_PROJECT=acme-prod gcloud sql instances list", "project", "acme-prod"),
        ("HELM_NAMESPACE=prod helm list", "namespace", "prod"),
        ("KUBECONFIG=/k kubectl get pods", "kubeconfig", "/k"),
    ],
    ids=lambda v: v if isinstance(v, str) and " " in v else "",
)
def test_well_known_environment_variables_land_in_parser_metadata_keys(command, key, value):
    (intent,) = intents_from_command(command)
    assert intent.metadata[key] == value


def test_explicit_flag_beats_environment_variable():
    (intent,) = intents_from_command("AWS_PROFILE=dev aws ec2 describe-instances --profile prod")
    assert intent.metadata["profile"] == "prod"
    assert intent.metadata["env_assignments"] == {"AWS_PROFILE": "dev"}


def test_timeout_wrapper():
    (intent,) = intents_from_command("timeout 30 kubectl delete node/w1")
    assert intent.action == "delete" and intent.resource == "node/w1"
    assert intent.metadata["wrappers"] == ["timeout"]


def test_alias_k():
    (intent,) = intents_from_command("k delete node/w1")
    assert (intent.provider, intent.action, intent.resource) == ("kubernetes", "delete", "node/w1")


def test_sh_c_single_command():
    (intent,) = intents_from_command('sh -c "kubectl delete node/x"')
    assert (intent.action, intent.resource) == ("delete", "node/x")
    assert intent.metadata["wrappers"] == ["sh -c"]


def test_sh_c_compound_string_yields_every_intent():
    intents = intents_from_command(
        "bash -ec 'sudo kubectl delete node/w1; helm uninstall web -nprod'"
    )
    assert [(i.provider, i.action, i.resource) for i in intents] == [
        ("kubernetes", "delete", "node/w1"),
        ("helm", "delete", "release/web"),
    ]
    assert intents[0].metadata["wrappers"] == ["bash -c", "sudo"]
    assert intents[1].metadata == {"namespace": "prod", "wrappers": ["bash -c"]}


def test_sh_c_pipeline_position_propagates_into_the_string():
    # the whole `sh -c` is the left side of a pipe, so an unknown binary
    # inside its string is in a pipeline too (no synthetic intent).
    assert _summary("sh -c 'kubectl get pods; grep x' | wc -l") == [("kubernetes", "get", "pod/*")]


def test_redirections_are_recorded_and_do_not_reach_the_parser():
    (intent,) = intents_from_command("sudo -u admin -E -- k delete node/w1 2>&1 >/tmp/log")
    assert intent.resource == "node/w1"
    assert intent.metadata["redirects"] == ["2>&1", ">/tmp/log"]
    assert "2" not in intent.params


def test_quoted_metacharacters_do_not_split():
    (intent,) = intents_from_command("helm upgrade x ./chart --set 'a=b;c' -n prod")
    assert intent.params["set"] == {"a": "b;c"}
    assert intent.metadata == {"namespace": "prod"}


def test_unknown_binary_on_its_own_yields_synthetic_shell_exec_intent():
    intents = intents_from_command("kubectl get pods && rm -rf /tmp/x")
    assert [(i.provider, i.action, i.resource) for i in intents] == [
        ("kubernetes", "get", "pod/*"),
        ("shell", "exec", "binary/rm"),
    ]
    assert intents[1].params == {"argv": ["rm", "-rf", "/tmp/x"]}


def test_terraform_argv_is_an_unknown_binary_not_a_value_error():
    (intent,) = intents_from_command("tf apply -auto-approve")
    assert (intent.provider, intent.action, intent.resource) == (
        "shell",
        "exec",
        "binary/terraform",
    )


def test_unknown_binary_inside_pipeline_yields_nothing():
    assert intents_from_command("cat x | grep y | wc -l") == []


def test_synthetic_intent_carries_env_and_wrappers():
    (intent,) = intents_from_command("sudo FOO=1 rm -rf /")
    assert intent.resource == "binary/rm"
    assert intent.metadata == {"env_assignments": {"FOO": "1"}, "wrappers": ["sudo"]}


def test_known_binary_with_unparseable_argv_raises_value_error():
    with pytest.raises(ValueError):
        intents_from_command("kubectl --typo delete node/w1")


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete $(cat targets)",
        "kubectl delete `cat targets`",
        "eval kubectl delete node/w1",
        "echo node/w1 | xargs kubectl delete",
        "sh -c \"sh -c 'kubectl delete node/w1'\"",
        "sudo -i",
        "kubectl get pods; exec kubectl delete node/w1",
    ],
    ids=repr,
)
def test_intents_from_command_rejects(command):
    with pytest.raises(ShellRejected):
        intents_from_command(command)


def test_multiline_script():
    script = "set -e\nkubectl get pods\nkubectl delete node/w1 # cleanup\n"
    intents = intents_from_command(script)
    assert [(i.provider, i.action, i.resource) for i in intents] == [
        ("shell", "exec", "binary/set"),
        ("kubernetes", "get", "pod/*"),
        ("kubernetes", "delete", "node/w1"),
    ]


# --- end to end against the example store (REVIEW-4 T1.2 acceptance) --------------


@pytest.fixture
def example_gate():
    from aegis_core.authority import load_authority_map
    from aegis_core.environments import load_environment_map
    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.store import ConstraintStore

    authority_map = load_authority_map("data/authority.example.yaml")
    store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
    return AegisInterceptor(store), load_environment_map("data/environments.example.yaml")


def _verdicts(command: str, gate) -> list[tuple[str, str]]:
    interceptor, env_map = gate
    now = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
    out = []
    for intent in intents_from_command(command):
        env_map.annotate(intent)
        decision = interceptor.intercept(intent, now=now)
        out.append((intent.resource, decision.verdict))
    return out


def test_acceptance_compound_delete_is_blocked(example_gate):
    assert _verdicts("kubectl get pods; kubectl delete node/w1", example_gate) == [
        ("pod/*", "ALLOW"),
        ("node/w1", "BLOCK"),
    ]


def test_acceptance_sudo_delete_is_blocked(example_gate):
    assert _verdicts("sudo kubectl delete node/w1", example_gate) == [("node/w1", "BLOCK")]


def test_acceptance_pipe_into_non_command_is_allowed(example_gate):
    assert _verdicts("kubectl get pods | grep x", example_gate) == [("pod/*", "ALLOW")]


def test_acceptance_git_force_push_through_wrappers_and_tee(example_gate):
    verdicts = _verdicts(
        "nice -n 5 git -C /repo push -f origin main 2>&1 | tee push.log", example_gate
    )
    assert verdicts == [("ref/main", "BLOCK")]
