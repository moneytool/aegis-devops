"""The example policy's default rules for infrastructure-breaking commands,
and the terraform/tofu destroy parser they rely on."""

import json

import pytest

from aegis_core.cli import main
from aegis_core.parser import from_argv, from_terraform_argv
from aegis_core.shell import intents_from_command
from aegis_core.signing import load_key

EXAMPLE_KEY = load_key("file:data/example-signing.key")


@pytest.fixture(autouse=True)
def _signing_key_in_env(monkeypatch):
    monkeypatch.setenv("AEGIS_SIGNING_KEY", EXAMPLE_KEY.hex())


def _verdicts(command, capsys):
    code = main(["check", "command", "--config-dir", "data", "--plan-constraints", "",
                 "--", command])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    return code, [(ln["decision"]["verdict"], ln["decision"]["citations"]) for ln in lines]


@pytest.mark.parametrize(
    ("command", "rule", "verdict"),
    [
        ("terraform destroy -auto-approve", "block-terraform-destroy", "BLOCK"),
        ("tofu destroy", "block-terraform-destroy", "BLOCK"),
        ("terraform -chdir=infra apply -destroy", "block-terraform-destroy", "BLOCK"),
        ("pulumi destroy --yes", "block-pulumi-destroy", "BLOCK"),
        ("pulumi stack rm dev", "block-pulumi-destroy", "BLOCK"),
        ("kubectl delete namespace scratch --context kind-local", "block-namespace-delete",
         "BLOCK"),
        ("aws s3 rb s3://logs --force", "block-s3-bucket-delete", "BLOCK"),
        ("aws rds delete-db-instance --db-instance-identifier db1", "block-rds-delete",
         "BLOCK"),
        ("gcloud projects delete p1", "block-gcp-project-delete", "BLOCK"),
        ("az group delete -n rg1", "block-azure-resource-group-delete", "BLOCK"),
        ("argocd app delete app1", "escalate-argocd-app-delete", "ESCALATE"),
    ],
)
def test_default_rule_stops_destructive_command(command, rule, verdict, capsys):
    _code, verdicts = _verdicts(command, capsys)
    assert (verdict, [rule]) == verdicts[0]


@pytest.mark.parametrize(
    "command",
    [
        "terraform plan",
        "terraform apply",
        "tofu init",
        "pulumi preview",
        "kubectl get namespaces",
        "aws s3 ls s3://logs",
        "gcloud projects list",
        "az group list",
        "argocd app list",
    ],
)
def test_default_rules_leave_everyday_commands_alone(command, capsys):
    code, verdicts = _verdicts(command, capsys)
    assert code == 0
    assert all(v == "ALLOW" for v, _ in verdicts)


def test_terraform_argv_destroy_intent():
    [intent] = from_terraform_argv(["terraform", "destroy", "-auto-approve"])
    assert (intent.provider, intent.action, intent.resource) == (
        "terraform", "delete", "workspace/current")
    assert intent.params["auto_approve"] is True
    assert intent.metadata["tool"] == "terraform"


def test_tofu_apply_destroy_with_chdir():
    [intent] = from_terraform_argv(["tofu", "-chdir=envs/prod", "apply", "-destroy"])
    assert intent.resource == "workspace/envs/prod"
    assert intent.metadata["tool"] == "opentofu"


@pytest.mark.parametrize("argv", [["terraform", "plan"], ["terraform", "apply"],
                                  ["terraform"], ["tofu", "-version"]])
def test_terraform_argv_non_destroy_is_none(argv):
    assert from_terraform_argv(argv) is None


def test_from_argv_still_refuses_non_destroy_terraform():
    with pytest.raises(ValueError, match="plan"):
        from_argv(["terraform", "apply"])
    assert from_argv(["terraform", "destroy"])[0].action == "delete"


def test_shell_unwraps_launchers_around_terraform_destroy():
    [intent] = intents_from_command("sudo env TF_LOG=1 terraform destroy")
    assert (intent.provider, intent.action) == ("terraform", "delete")


def test_plan_json_intents_are_not_caught_by_the_workspace_rule(capsys):
    # the workspace/* rule is for argv destroys only; a plan deleting one
    # resource is judged by the plan rules, not by block-terraform-destroy
    from aegis_core.parser import from_terraform_plan

    plan = {"resource_changes": [{"address": "aws_s3_bucket.b", "type": "aws_s3_bucket",
                                  "name": "b", "change": {"actions": ["delete"]}}]}
    [intent] = from_terraform_plan(plan)
    assert not intent.resource.startswith("workspace/")
