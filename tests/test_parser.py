import pytest

from aegis_core.parser import from_kubectl, from_terraform_plan


def test_from_kubectl_scale_with_namespace_flag():
    intent = from_kubectl(["kubectl", "scale", "deployment/x", "--replicas=5", "-n", "prod"])
    assert intent.resource == "deployment/x"
    assert intent.action == "scale"
    assert intent.provider == "kubernetes"
    assert intent.params == {"replicas": 5}
    assert intent.metadata == {"namespace": "prod"}


def test_from_kubectl_delete_without_flags():
    intent = from_kubectl(["kubectl", "delete", "pod/x"])
    assert intent.resource == "pod/x"
    assert intent.action == "delete"
    assert intent.provider == "kubernetes"
    assert intent.params == {}
    assert intent.metadata == {}


def test_from_kubectl_rejects_non_kubectl_argv():
    with pytest.raises(ValueError):
        from_kubectl(["helm", "install", "x"])


def test_from_terraform_plan_maps_each_action_kind():
    plan = {
        "resource_changes": [
            {"address": "aws_instance.web", "change": {"actions": ["create"]}},
            {"address": "aws_instance.db", "change": {"actions": ["delete"]}},
            {"address": "aws_instance.cache", "change": {"actions": ["update"]}},
            {"address": "aws_instance.api", "change": {"actions": ["delete", "create"]}},
            {"address": "aws_instance.worker", "change": {"actions": ["create", "delete"]}},
            {"address": "aws_instance.idle", "change": {"actions": ["no-op"]}},
        ]
    }
    intents = from_terraform_plan(plan)

    by_address = {i.resource: i for i in intents}
    assert by_address["aws_instance.web"].action == "create"
    assert by_address["aws_instance.db"].action == "delete"
    assert by_address["aws_instance.cache"].action == "update"
    assert by_address["aws_instance.api"].action == "replace"
    assert by_address["aws_instance.worker"].action == "replace"
    assert by_address["aws_instance.idle"].action == "no-op"
    assert all(i.provider == "terraform" for i in intents)


def test_from_terraform_plan_rejects_unknown_action_combo():
    plan = {"resource_changes": [{"address": "x", "change": {"actions": ["read"]}}]}
    with pytest.raises(ValueError):
        from_terraform_plan(plan)
