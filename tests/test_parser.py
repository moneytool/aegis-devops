import pytest

from aegis_core.parser import from_kubectl, from_kubectl_multi, from_terraform_plan


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
    plan = {"resource_changes": [{"address": "x", "change": {"actions": ["import"]}}]}
    with pytest.raises(ValueError):
        from_terraform_plan(plan)


# --- kubectl: namespace forms -----------------------------------------------


def test_from_kubectl_namespace_short_flag_equals():
    intent = from_kubectl(["kubectl", "get", "pod/x", "-n=prod"])
    assert intent.metadata == {"namespace": "prod"}


def test_from_kubectl_namespace_long_flag_space():
    intent = from_kubectl(["kubectl", "get", "pod/x", "--namespace", "prod"])
    assert intent.metadata == {"namespace": "prod"}


def test_from_kubectl_namespace_long_flag_equals():
    intent = from_kubectl(["kubectl", "get", "pod/x", "--namespace=prod"])
    assert intent.metadata == {"namespace": "prod"}


def test_from_kubectl_all_namespaces_short_flag():
    intent = from_kubectl(["kubectl", "get", "pods", "-A"])
    assert intent.metadata == {"all_namespaces": True}


def test_from_kubectl_all_namespaces_long_flag():
    intent = from_kubectl(["kubectl", "get", "pods", "--all-namespaces"])
    assert intent.metadata == {"all_namespaces": True}


# --- kubectl: context/cluster/global flags ----------------------------------


def test_from_kubectl_context_and_cluster():
    intent = from_kubectl(
        ["kubectl", "get", "pod/x", "--context", "staging", "--cluster", "eu"]
    )
    assert intent.metadata == {"context": "staging", "cluster": "eu"}


def test_from_kubectl_discards_output_and_kubeconfig_and_server():
    intent = from_kubectl(
        [
            "kubectl",
            "get",
            "pod/x",
            "-o",
            "json",
            "--kubeconfig",
            "/tmp/kc",
            "--server",
            "https://x",
        ]
    )
    assert intent.params == {}
    assert intent.metadata == {}


# --- kubectl: resource form normalisation -----------------------------------


def test_from_kubectl_two_token_resource_form():
    intent = from_kubectl(["kubectl", "delete", "deployment", "x"])
    assert intent.resource == "deployment/x"


def test_from_kubectl_plural_normalisation():
    intent = from_kubectl(["kubectl", "delete", "deployments", "x"])
    assert intent.resource == "deployment/x"


def test_from_kubectl_short_name_normalisation():
    intent = from_kubectl(["kubectl", "delete", "po", "x"])
    assert intent.resource == "pod/x"


def test_from_kubectl_api_group_stripped():
    intent = from_kubectl(["kubectl", "get", "deployment.apps/x"])
    assert intent.resource == "deployment/x"


def test_from_kubectl_bare_kind_without_name_targets_all_of_kind():
    intent = from_kubectl(["kubectl", "get", "pods"])
    assert intent.resource == "pod/*"


# --- kubectl: multiple resources ---------------------------------------------


def test_from_kubectl_multi_kind_name_pairs():
    intents = from_kubectl_multi(["kubectl", "delete", "pod/a", "pod/b"])
    assert [i.resource for i in intents] == ["pod/a", "pod/b"]
    assert all(i.action == "delete" for i in intents)


def test_from_kubectl_multi_shared_kind():
    intents = from_kubectl_multi(["kubectl", "delete", "pod", "a", "b"])
    assert [i.resource for i in intents] == ["pod/a", "pod/b"]


def test_from_kubectl_rejects_multiple_resources_via_single():
    with pytest.raises(ValueError):
        from_kubectl(["kubectl", "delete", "pod/a", "pod/b"])


# --- kubectl: boolean and value flags ----------------------------------------


def test_from_kubectl_boolean_flag_does_not_consume_resource():
    intent = from_kubectl(["kubectl", "delete", "--force", "pod/x"])
    assert intent.resource == "pod/x"
    assert intent.params == {"force": True}


def test_from_kubectl_multiple_boolean_flags():
    intent = from_kubectl(["kubectl", "delete", "pod/x", "--wait", "--now", "--ignore-not-found"])
    assert intent.params == {"wait": True, "now": True, "ignore-not-found": True}


def test_from_kubectl_replicas_space_separated():
    intent = from_kubectl(["kubectl", "scale", "deployment/x", "--replicas", "5"])
    assert intent.params == {"replicas": 5}


def test_from_kubectl_replicas_equals_form():
    intent = from_kubectl(["kubectl", "scale", "deployment/x", "--replicas=5"])
    assert intent.params == {"replicas": 5}


# --- kubectl: apply/create/replace/delete via manifest -----------------------


def test_from_kubectl_apply_with_file():
    intent = from_kubectl(["kubectl", "apply", "-f", "manifests/app.yaml"])
    assert intent.resource == "manifest/app.yaml"
    assert intent.action == "apply"
    assert intent.params == {"file": "manifests/app.yaml"}


def test_from_kubectl_apply_with_stdin():
    intent = from_kubectl(["kubectl", "apply", "-f", "-"])
    assert intent.resource == "manifest/-"
    assert intent.params == {"file": "-"}


def test_from_kubectl_apply_with_kustomize_dir():
    intent = from_kubectl(["kubectl", "apply", "-k", "overlays/prod"])
    assert intent.resource == "manifest/prod"
    assert intent.params == {"file": "overlays/prod"}


def test_from_kubectl_delete_with_file():
    intent = from_kubectl(["kubectl", "delete", "-f", "manifests/app.yaml"])
    assert intent.action == "delete"
    assert intent.resource == "manifest/app.yaml"


# --- kubectl: rollout ----------------------------------------------------------


def test_from_kubectl_rollout_restart():
    intent = from_kubectl(["kubectl", "rollout", "restart", "deployment/x"])
    assert intent.action == "rollout-restart"
    assert intent.resource == "deployment/x"


def test_from_kubectl_rollout_undo():
    intent = from_kubectl(["kubectl", "rollout", "undo", "deployment/x"])
    assert intent.action == "rollout-undo"


def test_from_kubectl_rollout_status():
    intent = from_kubectl(["kubectl", "rollout", "status", "deployment", "x"])
    assert intent.action == "rollout-status"
    assert intent.resource == "deployment/x"


# --- kubectl: exec / logs / set image / label ---------------------------------


def test_from_kubectl_exec_with_command():
    intent = from_kubectl(["kubectl", "exec", "mypod", "--", "ls", "-la"])
    assert intent.action == "exec"
    assert intent.resource == "mypod"
    assert intent.params["command"] == ["ls", "-la"]


def test_from_kubectl_logs_resource():
    intent = from_kubectl(["kubectl", "logs", "mypod"])
    assert intent.action == "logs"
    assert intent.resource == "mypod"


def test_from_kubectl_set_image():
    intent = from_kubectl(["kubectl", "set", "image", "deployment/x", "app=img:2"])
    assert intent.action == "set-image"
    assert intent.resource == "deployment/x"
    assert intent.params["images"] == {"app": "img:2"}


def test_from_kubectl_label_positional_kv():
    intent = from_kubectl(["kubectl", "label", "pod/x", "env=prod"])
    assert intent.action == "label"
    assert intent.params["labels"] == {"env": "prod"}


def test_from_kubectl_annotate_positional_kv():
    intent = from_kubectl(["kubectl", "annotate", "pod/x", "note=hello"])
    assert intent.action == "annotate"
    assert intent.params["annotations"] == {"note": "hello"}


def test_from_kubectl_accepts_full_path_binary():
    intent = from_kubectl(["/usr/local/bin/kubectl", "delete", "pod/x"])
    assert intent.resource == "pod/x"


# --- terraform: metadata, params, data-source skipping, read/forget ----------


def test_from_terraform_plan_populates_metadata():
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "type": "aws_instance",
                "name": "web",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "module_address": "module.app",
                "change": {"actions": ["create"]},
            }
        ]
    }
    intent = from_terraform_plan(plan)[0]
    assert intent.metadata == {
        "type": "aws_instance",
        "name": "web",
        "mode": "managed",
        "provider_name": "aws",
        "module_address": "module.app",
    }


def test_from_terraform_plan_delete_params_region_and_tags():
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "type": "aws_instance",
                "name": "web",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["delete"],
                    "before": {"region": "us-east-1", "tags": {"env": "prod"}},
                    "replace_paths": [["ami"]],
                },
            }
        ]
    }
    intent = from_terraform_plan(plan)[0]
    assert intent.params["region"] == "us-east-1"
    assert intent.params["tags"] == {"env": "prod"}
    assert intent.params["forced_replacement"] is True


def test_from_terraform_plan_region_fallback_from_provider_config():
    plan = {
        "configuration": {
            "provider_config": {
                "aws": {"expressions": {"region": {"constant_value": "eu-west-1"}}}
            }
        },
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["update"], "before": {}, "after": {}},
            }
        ],
    }
    intent = from_terraform_plan(plan)[0]
    assert intent.params["region"] == "eu-west-1"


def test_from_terraform_plan_skips_data_source_reads_by_default():
    plan = {
        "resource_changes": [
            {
                "address": "data.aws_ami.latest",
                "mode": "data",
                "change": {"actions": ["read"]},
            }
        ]
    }
    assert from_terraform_plan(plan) == []


def test_from_terraform_plan_includes_data_source_reads_when_requested():
    plan = {
        "resource_changes": [
            {
                "address": "data.aws_ami.latest",
                "mode": "data",
                "change": {"actions": ["read"]},
            }
        ]
    }
    intents = from_terraform_plan(plan, include_data=True)
    assert len(intents) == 1
    assert intents[0].action == "read"


def test_from_terraform_plan_forget_action():
    plan = {
        "resource_changes": [
            {"address": "aws_instance.orphan", "change": {"actions": ["forget"]}}
        ]
    }
    intent = from_terraform_plan(plan)[0]
    assert intent.action == "forget"


def test_from_kubectl_normalises_kind_case():
    intent = from_kubectl(["kubectl", "delete", "Deployment/API-Server"])
    assert intent.resource == "deployment/API-Server"
