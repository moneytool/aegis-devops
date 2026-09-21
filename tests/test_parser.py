import pytest

from aegis_core.parser import (
    from_argocd,
    from_argocd_multi,
    from_argv,
    from_aws,
    from_aws_multi,
    from_az,
    from_flux,
    from_gcloud,
    from_gh,
    from_git,
    from_helm,
    from_kubectl,
    from_kubectl_multi,
    from_terraform_plan,
)


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
        "tool": "terraform",
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


# --- aws: verb normalisation / kind singularisation / id-flag targeting ------


def test_from_aws_terminate_instances_normalises_action_and_kind():
    intent = from_aws(
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-0abc", "--region", "us-east-1"]
    )
    assert intent.provider == "aws"
    assert intent.resource == "ec2/instance/i-0abc"
    assert intent.action == "delete"
    assert intent.params["raw_action"] == "terminate-instances"
    assert intent.metadata == {"region": "us-east-1"}


def test_from_aws_describe_maps_to_read_and_targets_wildcard():
    intent = from_aws(["aws", "ec2", "describe-instances", "--region", "us-west-2"])
    assert intent.action == "read"
    assert intent.resource == "ec2/instance/*"


def test_from_aws_modify_db_instance_maps_to_update():
    intent = from_aws(
        ["aws", "rds", "modify-db-instance", "--db-instance-identifier", "prod-db"]
    )
    assert intent.action == "update"
    assert intent.resource == "rds/db-instance/prod-db"


def test_from_aws_put_bucket_policy_kind_not_singularised():
    intent = from_aws(["aws", "s3api", "put-bucket-policy", "--bucket", "my-logs"])
    assert intent.action == "put"
    assert intent.resource == "s3api/bucket-policy/my-logs"


def test_from_aws_update_function_code_uses_function_name_flag():
    intent = from_aws(
        ["aws", "lambda", "update-function-code", "--function-name", "f1", "--zip-file", "fileb://x.zip"]
    )
    assert intent.resource == "lambda/function-code/f1"
    assert intent.action == "update"
    assert intent.params["zip-file"] == "fileb://x.zip"


# --- aws: s3:// path handling -------------------------------------------------


def test_from_aws_s3_rm_targets_bucket_and_key():
    intent = from_aws(["aws", "s3", "rm", "s3://my-logs/some/key"])
    assert intent.resource == "s3/bucket/my-logs"
    assert intent.action == "delete"
    assert intent.params["key"] == "some/key"


def test_from_aws_s3_mb_creates_bucket():
    intent = from_aws(["aws", "s3", "mb", "s3://new-bucket"])
    assert intent.resource == "s3/bucket/new-bucket"
    assert intent.action == "create"
    assert "key" not in intent.params


def test_from_aws_s3_ls_is_read():
    intent = from_aws(["aws", "s3", "ls", "s3://my-logs"])
    assert intent.action == "read"


def test_from_aws_s3_cp_is_put():
    intent = from_aws(["aws", "s3", "cp", "local.txt", "s3://my-logs/local.txt"])
    assert intent.action == "put"
    assert intent.resource == "s3/bucket/my-logs"


# --- aws: multiple instance ids, booleans, metadata --------------------------


def test_from_aws_multi_instance_ids_produces_one_intent_each():
    intents = from_aws_multi(
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "i-2", "i-3"]
    )
    assert [i.resource for i in intents] == [
        "ec2/instance/i-1",
        "ec2/instance/i-2",
        "ec2/instance/i-3",
    ]
    assert all(i.action == "delete" for i in intents)


def test_from_aws_rejects_multiple_targets_via_single():
    with pytest.raises(ValueError):
        from_aws(["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "i-2"])


def test_from_aws_dry_run_boolean_flag_does_not_consume_region():
    intent = from_aws(
        [
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            "i-1",
            "--dry-run",
            "--region",
            "us-east-1",
        ]
    )
    assert intent.params["dry_run"] is True
    assert intent.metadata["region"] == "us-east-1"


def test_from_aws_profile_flag_sets_metadata():
    intent = from_aws(
        ["aws", "--profile", "dev", "lambda", "update-function-code", "--function-name", "f1"]
    )
    assert intent.metadata["profile"] == "dev"


def test_from_aws_autoscaling_set_desired_capacity():
    intent = from_aws(
        [
            "aws",
            "autoscaling",
            "set-desired-capacity",
            "--auto-scaling-group-name",
            "asg1",
            "--desired-capacity",
            "3",
        ]
    )
    assert intent.action == "scale"
    assert intent.resource == "autoscaling/auto-scaling-group/asg1"
    assert intent.params["desired_capacity"] == 3


def test_from_aws_rejects_non_aws_argv():
    with pytest.raises(ValueError):
        from_aws(["helm", "install", "x"])


def test_from_aws_rejects_missing_operation():
    with pytest.raises(ValueError):
        from_aws(["aws", "ec2"])


def test_from_aws_accepts_full_path_binary():
    intent = from_aws(
        ["/usr/local/bin/aws", "ec2", "terminate-instances", "--instance-ids", "i-1"]
    )
    assert intent.resource == "ec2/instance/i-1"


# --- az: group-path mapping / verb detection / name flags --------------------


def test_from_az_vm_start_with_resource_group():
    intent = from_az(["az", "vm", "start", "--resource-group", "rg1", "--name", "vm1"])
    assert intent.provider == "azure"
    assert intent.resource == "compute/vm/vm1"
    assert intent.action == "start"
    assert intent.metadata == {"resource_group": "rg1"}


def test_from_az_deallocate_maps_to_stop():
    intent = from_az(["az", "vm", "deallocate", "-g", "rg1", "-n", "vm1"])
    assert intent.action == "stop"
    assert intent.params["raw_action"] == "deallocate"


def test_from_az_aks_scale_with_node_count():
    intent = from_az(
        ["az", "aks", "scale", "--resource-group", "rg1", "--name", "aks1", "--node-count", "5"]
    )
    assert intent.action == "scale"
    assert intent.resource == "aks/cluster/aks1"
    assert intent.params["node-count"] == 5


def test_from_az_storage_account_create_multiword_group():
    intent = from_az(
        ["az", "storage", "account", "create", "--name", "mystore", "-g", "rg1", "-l", "eastus"]
    )
    assert intent.resource == "storage/account/mystore"
    assert intent.action == "create"
    assert intent.metadata == {"resource_group": "rg1", "region": "eastus"}


def test_from_az_group_delete_uses_name_flag():
    intent = from_az(["az", "group", "delete", "--name", "rg1", "--yes"])
    assert intent.resource == "resource/group/rg1"
    assert intent.action == "delete"
    assert intent.params["yes"] is True


def test_from_az_ad_user_group_mapping():
    intent = from_az(["az", "ad", "user", "show", "--id", "alice"])
    assert intent.resource == "iam/user/*"
    assert intent.action == "read"


def test_from_az_unknown_group_path_joined_literally():
    intent = from_az(["az", "monitor", "alert", "create", "--name", "a1"])
    assert intent.resource == "monitor/alert/a1"


def test_from_az_rejects_missing_verb():
    with pytest.raises(ValueError):
        from_az(["az", "vm"])


def test_from_az_rejects_non_az_argv():
    with pytest.raises(ValueError):
        from_az(["kubectl", "get", "pods"])


def test_from_az_accepts_full_path_binary():
    intent = from_az(["/usr/bin/az", "vm", "start", "-g", "rg1", "-n", "vm1"])
    assert intent.resource == "compute/vm/vm1"


# --- gcloud: name positional / group mapping / alpha-beta / storage rm -------


def test_from_gcloud_compute_instances_start_with_zone():
    intent = from_gcloud(
        ["gcloud", "compute", "instances", "start", "web-1", "--zone", "us-central1-a"]
    )
    assert intent.provider == "gcp"
    assert intent.resource == "compute/instance/web-1"
    assert intent.action == "start"
    assert intent.metadata == {"zone": "us-central1-a", "region": "us-central1-a"}


def test_from_gcloud_container_clusters_resize_maps_to_scale():
    intent = from_gcloud(
        ["gcloud", "container", "clusters", "resize", "prod", "--num-nodes", "5"]
    )
    assert intent.action == "scale"
    assert intent.resource == "container/cluster/prod"
    assert intent.params["num-nodes"] == 5


def test_from_gcloud_sql_instances_delete():
    intent = from_gcloud(["gcloud", "sql", "instances", "delete", "prod-db"])
    assert intent.action == "delete"
    assert intent.resource == "sql/instance/prod-db"


def test_from_gcloud_unmapped_group_singularises_last_segment():
    intent = from_gcloud(["gcloud", "dns", "record-sets", "create", "rs1"])
    assert intent.resource == "dns/record-set/rs1"


def test_from_gcloud_alpha_track_recorded_in_params():
    intent = from_gcloud(
        ["gcloud", "alpha", "run", "services", "deploy", "svc1", "--image", "x"]
    )
    assert intent.params["release_track"] == "alpha"
    assert intent.action == "update"
    assert intent.resource == "run/service/svc1"


def test_from_gcloud_iam_binding_verbs_map_to_update():
    intent = from_gcloud(
        [
            "gcloud",
            "projects",
            "add-iam-policy-binding",
            "proj1",
            "--member",
            "user:x",
            "--role",
            "roles/viewer",
        ]
    )
    assert intent.action == "update"
    assert intent.resource == "project/project/proj1"


def test_from_gcloud_storage_rm_gs_uri():
    intent = from_gcloud(["gcloud", "storage", "rm", "gs://my-logs/some/key"])
    assert intent.resource == "storage/bucket/my-logs"
    assert intent.action == "delete"
    assert intent.params["key"] == "some/key"


def test_from_gcloud_legacy_gsutil_rm():
    intent = from_gcloud(["gsutil", "rm", "gs://my-logs/some/key"])
    assert intent.resource == "storage/bucket/my-logs"
    assert intent.action == "delete"
    assert intent.params["raw_action"] == "gsutil-rm"


def test_from_gcloud_quiet_and_async_boolean_flags():
    intent = from_gcloud(
        ["gcloud", "compute", "instances", "delete", "web-1", "-q", "--async"]
    )
    assert intent.params["quiet"] is True
    assert intent.params["async"] is True


def test_from_gcloud_rejects_missing_verb():
    with pytest.raises(ValueError):
        from_gcloud(["gcloud", "compute"])


def test_from_gcloud_rejects_non_gcloud_argv():
    with pytest.raises(ValueError):
        from_gcloud(["kubectl", "get", "pods"])


# --- from_argv dispatch -------------------------------------------------------


def test_from_argv_dispatches_kubectl():
    intents = from_argv(["kubectl", "get", "pods"])
    assert intents[0].provider == "kubernetes"


def test_from_argv_dispatches_aws_by_basename():
    intents = from_argv(
        ["/usr/local/bin/aws", "ec2", "terminate-instances", "--instance-ids", "i-1"]
    )
    assert intents[0].provider == "aws"
    assert intents[0].resource == "ec2/instance/i-1"


def test_from_argv_dispatches_az():
    intents = from_argv(["az", "vm", "start", "-g", "rg1", "-n", "vm1"])
    assert intents == [from_az(["az", "vm", "start", "-g", "rg1", "-n", "vm1"])]


def test_from_argv_dispatches_gcloud_and_gsutil():
    assert from_argv(["gcloud", "sql", "instances", "delete", "prod-db"])[0].provider == "gcp"
    assert from_argv(["gsutil", "rm", "gs://my-logs/key"])[0].provider == "gcp"


def test_from_argv_rejects_terraform_with_helpful_message():
    with pytest.raises(ValueError, match="plan"):
        from_argv(["terraform", "apply"])


def test_from_argv_rejects_unsupported_cli():
    with pytest.raises(ValueError):
        from_argv(["docker", "rmi", "x"])


def test_from_terraform_plan_records_tool_default_terraform():
    plan = {
        "resource_changes": [{"address": "aws_instance.web", "change": {"actions": ["delete"]}}]
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.provider == "terraform"
    assert intent.metadata["tool"] == "terraform"


def test_from_terraform_plan_opentofu_plan_keeps_terraform_provider():
    plan = {
        "terraform_version": "1.8.0-tofu",
        "resource_changes": [{"address": "aws_instance.web", "change": {"actions": ["delete"]}}],
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.provider == "terraform"
    assert intent.metadata["tool"] == "opentofu"


def test_from_terraform_plan_tool_kwarg_is_fallback_only():
    plan = {
        "resource_changes": [{"address": "aws_instance.web", "change": {"actions": ["create"]}}]
    }
    (intent,) = from_terraform_plan(plan, tool="opentofu")
    assert intent.metadata["tool"] == "opentofu"
    marked = {"opentofu": True, **plan}
    (intent2,) = from_terraform_plan(marked, tool="terraform")
    assert intent2.metadata["tool"] == "opentofu"


def test_from_argv_rejects_tofu_like_terraform():
    with pytest.raises(ValueError, match="tofu show -json"):
        from_argv(["tofu", "apply"])


# --- dry-run normalisation ------------------------------------------------


@pytest.mark.parametrize("flag", ["--dry-run", "--dry-run=client", "--dry-run=server"])
def test_from_kubectl_dry_run_variants_set_dry_run_true(flag):
    intent = from_kubectl(["kubectl", "delete", "pod/x", flag])
    assert intent.params["dry_run"] is True
    assert "dry-run" not in intent.params


def test_from_kubectl_dry_run_none_does_not_set_dry_run():
    intent = from_kubectl(["kubectl", "delete", "pod/x", "--dry-run=none"])
    assert "dry_run" not in intent.params


def test_from_kubectl_without_dry_run_flag_has_no_dry_run_key():
    intent = from_kubectl(["kubectl", "delete", "pod/x"])
    assert "dry_run" not in intent.params


def test_from_aws_dry_run_sets_dry_run_true():
    intent = from_aws(
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--dry-run"]
    )
    assert intent.params["dry_run"] is True


def test_from_aws_no_dry_run_does_not_set_dry_run():
    intent = from_aws(
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--no-dry-run"]
    )
    assert "dry_run" not in intent.params


@pytest.mark.parametrize("flag", ["--what-if", "--dry-run"])
def test_from_az_what_if_and_dry_run_set_dry_run_true(flag):
    intent = from_az(
        ["az", "deployment", "group", "create", "--resource-group", "rg1", flag]
    )
    assert intent.params["dry_run"] is True


def test_from_az_no_wait_is_not_dry_run():
    intent = from_az(
        ["az", "vm", "deallocate", "--resource-group", "rg1", "--name", "vm1", "--no-wait"]
    )
    assert "dry_run" not in intent.params


def test_from_gcloud_dry_run_sets_dry_run_true():
    intent = from_gcloud(
        ["gcloud", "compute", "instances", "delete", "web-1", "--zone", "us-central1-a",
         "--dry-run"]
    )
    assert intent.params["dry_run"] is True


def test_from_gcloud_without_dry_run_has_no_dry_run_key():
    intent = from_gcloud(
        ["gcloud", "compute", "instances", "delete", "web-1", "--zone", "us-central1-a"]
    )
    assert "dry_run" not in intent.params


# --- Helm --------------------------------------------------------------------


def test_from_helm_install_happy_path():
    intent = from_helm(["helm", "install", "api", "./chart", "-n", "prod"])
    assert intent.resource == "release/api"
    assert intent.action == "create"
    assert intent.provider == "helm"
    assert intent.params == {"raw_action": "install", "chart": "./chart"}
    assert intent.metadata == {"namespace": "prod"}


def test_from_helm_upgrade_maps_to_update_verb():
    intent = from_helm(["helm", "upgrade", "api", "./chart"])
    assert intent.action == "update"
    assert intent.params["raw_action"] == "upgrade"
    assert "install" not in intent.params


def test_from_helm_upgrade_install_flag_sets_install_true():
    intent = from_helm(["helm", "upgrade", "--install", "api", "./chart"])
    assert intent.action == "update"
    assert intent.params["install"] is True


def test_from_helm_uninstall_and_delete_map_to_delete():
    for verb in ("uninstall", "delete"):
        intent = from_helm(["helm", verb, "api"])
        assert intent.resource == "release/api"
        assert intent.action == "delete"


def test_from_helm_rollback_with_revision():
    intent = from_helm(["helm", "rollback", "api", "3"])
    assert intent.action == "rollback"
    assert intent.params["revision"] == 3


def test_from_helm_history_status_list_get_are_read():
    for argv in (
        ["helm", "history", "api"],
        ["helm", "status", "api"],
        ["helm", "list"],
        ["helm", "get", "values", "api"],
    ):
        intent = from_helm(argv)
        assert intent.action == "read"


def test_from_helm_template_is_read_and_dry_run():
    intent = from_helm(["helm", "template", "api", "./chart"])
    assert intent.action == "read"
    assert intent.params["dry_run"] is True


def test_from_helm_dry_run_flag_sets_dry_run_true():
    intent = from_helm(["helm", "upgrade", "--install", "api", "./chart", "-n", "prod",
                         "--dry-run"])
    assert intent.params["dry_run"] is True
    assert intent.params["chart"] == "./chart"
    assert intent.metadata == {"namespace": "prod"}


def test_from_helm_bool_flags_and_set_and_values():
    intent = from_helm(
        ["helm", "install", "api", "./chart", "-f", "values.yaml", "--set", "image.tag=v2",
         "--atomic", "--wait", "--create-namespace"]
    )
    assert intent.params["values_files"] == ["values.yaml"]
    assert intent.params["set"] == {"image.tag": "v2"}
    assert intent.params["atomic"] is True
    assert intent.params["wait"] is True
    assert intent.params["create_namespace"] is True


def test_from_helm_kube_context_metadata():
    intent = from_helm(["helm", "list", "--kube-context", "prod-cluster"])
    assert intent.metadata == {"context": "prod-cluster"}


def test_from_helm_rejects_non_helm_argv():
    with pytest.raises(ValueError):
        from_helm(["argocd", "app", "sync", "x"])


def test_from_helm_rejects_unsupported_subcommand():
    with pytest.raises(ValueError):
        from_helm(["helm", "completion"])


# --- ArgoCD --------------------------------------------------------------------


def test_from_argocd_sync_happy_path():
    intent = from_argocd(["argocd", "app", "sync", "prod-web"])
    assert intent.resource == "app/prod-web"
    assert intent.action == "sync"
    assert intent.provider == "argocd"
    assert intent.params == {"raw_action": "sync"}


def test_from_argocd_sync_prune_sets_prune_param():
    intent = from_argocd(["argocd", "app", "sync", "prod-web", "--prune"])
    assert intent.params["prune"] is True


def test_from_argocd_verb_mapping():
    assert from_argocd(["argocd", "app", "delete", "x"]).action == "delete"
    assert from_argocd(["argocd", "app", "create", "x"]).action == "create"
    assert from_argocd(["argocd", "app", "set", "x"]).action == "update"
    assert from_argocd(["argocd", "app", "terminate-op", "x"]).action == "stop"
    for verb in ("get", "diff", "history"):
        assert from_argocd(["argocd", "app", verb, "x"]).action == "read"


def test_from_argocd_rollback_with_id():
    intent = from_argocd(["argocd", "app", "rollback", "prod-web", "42"])
    assert intent.action == "rollback"
    assert intent.params["revision"] == 42


def test_from_argocd_dry_run_flag():
    intent = from_argocd(["argocd", "app", "sync", "prod-web", "--dry-run"])
    assert intent.params["dry_run"] is True


def test_from_argocd_project_metadata_and_discarded_flags():
    intent = from_argocd(
        ["argocd", "app", "sync", "prod-web", "--project", "platform",
         "--server", "argocd.internal", "--grpc-web", "--auth-token", "secret"]
    )
    assert intent.metadata == {"project": "platform"}
    assert "server" not in intent.params
    assert "auth_token" not in intent.params
    assert "grpc_web" not in intent.params


def test_from_argocd_actions_run():
    intent = from_argocd(["argocd", "app", "actions", "run", "prod-web", "restart"])
    assert intent.resource == "app/prod-web"
    assert intent.action == "update"
    assert intent.params["action_name"] == "restart"


def test_from_argocd_multi_targets_multiple_apps():
    intents = from_argocd_multi(["argocd", "app", "sync", "app1", "app2", "--prune"])
    assert [i.resource for i in intents] == ["app/app1", "app/app2"]
    assert all(i.action == "sync" for i in intents)
    assert all(i.params["prune"] is True for i in intents)


def test_from_argocd_rejects_non_app_invocation():
    with pytest.raises(ValueError):
        from_argocd(["argocd", "login", "argocd.internal"])


def test_from_argocd_single_rejects_multi_target():
    with pytest.raises(ValueError):
        from_argocd(["argocd", "app", "sync", "app1", "app2"])


# --- Flux --------------------------------------------------------------------


def test_from_flux_reconcile_source_git():
    intent = from_flux(["flux", "reconcile", "source", "git", "podinfo", "-n", "flux-system"])
    assert intent.resource == "source-git/podinfo"
    assert intent.action == "sync"
    assert intent.provider == "flux"
    assert intent.metadata == {"namespace": "flux-system"}


def test_from_flux_reconcile_kustomization_and_helmrelease():
    intent = from_flux(["flux", "reconcile", "kustomization", "podinfo"])
    assert intent.resource == "kustomization/podinfo"
    intent2 = from_flux(["flux", "reconcile", "helmrelease", "podinfo"])
    assert intent2.resource == "helmrelease/podinfo"


def test_from_flux_suspend_and_resume_map_to_stop_start():
    suspend = from_flux(["flux", "suspend", "kustomization", "podinfo"])
    assert suspend.action == "stop"
    resume = from_flux(["flux", "resume", "kustomization", "podinfo"])
    assert resume.action == "start"


def test_from_flux_delete_and_create():
    assert from_flux(["flux", "delete", "kustomization", "podinfo"]).action == "delete"
    assert from_flux(["flux", "create", "kustomization", "podinfo"]).action == "create"


def test_from_flux_get_logs_export_are_read():
    for argv in (
        ["flux", "get", "kustomizations"],
        ["flux", "logs"],
        ["flux", "export", "kustomization", "podinfo"],
    ):
        assert from_flux(argv).action == "read"


def test_from_flux_export_sets_dry_run():
    intent = from_flux(["flux", "export", "kustomization", "podinfo"])
    assert intent.params["dry_run"] is True


def test_from_flux_dry_run_flag():
    intent = from_flux(["flux", "reconcile", "kustomization", "podinfo", "--dry-run"])
    assert intent.params["dry_run"] is True


def test_from_flux_bootstrap_is_create():
    intent = from_flux(["flux", "bootstrap", "github", "--owner=x", "--repository=y"])
    assert intent.resource == "bootstrap/github"
    assert intent.action == "create"


def test_from_flux_context_metadata():
    intent = from_flux(["flux", "reconcile", "kustomization", "podinfo", "--context", "prod"])
    assert intent.metadata == {"context": "prod"}


def test_from_flux_rejects_non_flux_argv():
    with pytest.raises(ValueError):
        from_flux(["helm", "install", "x"])


def test_from_flux_rejects_unsupported_subcommand():
    with pytest.raises(ValueError):
        from_flux(["flux", "completion"])


# --- Git ------------------------------------------------------------------


def test_from_git_push_happy_path():
    intent = from_git(["git", "push", "origin", "main"])
    assert intent.resource == "ref/main"
    assert intent.action == "push"
    assert intent.provider == "git"
    assert intent.metadata == {"remote": "origin"}
    assert "force" not in intent.params


def test_from_git_push_force_variants_set_force():
    for argv in (
        ["git", "push", "-f", "origin", "main"],
        ["git", "push", "--force", "origin", "main"],
        ["git", "push", "origin", "+main"],
    ):
        intent = from_git(argv)
        assert intent.params["force"] is True
        assert intent.resource == "ref/main"


def test_from_git_push_force_with_lease():
    intent = from_git(["git", "push", "--force-with-lease", "origin", "main"])
    assert intent.params["force"] is True
    assert intent.params["force_with_lease"] is True


def test_from_git_push_head_refspec_resolves_to_dest_branch():
    intent = from_git(["git", "push", "-f", "origin", "HEAD:main"])
    assert intent.resource == "ref/main"
    assert intent.action == "push"
    assert intent.params["force"] is True


def test_from_git_push_delete_flag_and_colon_refspec():
    delete_flag = from_git(["git", "push", "--delete", "origin", "old-feature"])
    assert delete_flag.action == "delete"
    assert delete_flag.resource == "ref/old-feature"

    colon_refspec = from_git(["git", "push", "origin", ":old-feature"])
    assert colon_refspec.action == "delete"
    assert colon_refspec.resource == "ref/old-feature"


def test_from_git_push_no_refspec_targets_wildcard():
    intent = from_git(["git", "push"])
    assert intent.resource == "ref/*"
    assert intent.metadata == {}


def test_from_git_branch_and_tag_delete_are_local_deletes():
    branch = from_git(["git", "branch", "-D", "old-feature"])
    assert branch.resource == "branch/old-feature"
    assert branch.action == "delete"

    tag = from_git(["git", "tag", "-d", "v1.0"])
    assert tag.resource == "tag/v1.0"
    assert tag.action == "delete"


def test_from_git_rebase_reset_hard_amend_are_rewrite():
    rebase = from_git(["git", "rebase", "main"])
    assert rebase.resource == "history/main"
    assert rebase.action == "rewrite"

    reset_hard = from_git(["git", "reset", "--hard", "HEAD~1"])
    assert reset_hard.resource == "history/HEAD~1"
    assert reset_hard.action == "rewrite"

    amend = from_git(["git", "commit", "--amend", "-m", "fix"])
    assert amend.resource == "history/HEAD"
    assert amend.action == "rewrite"


def test_from_git_read_verbs():
    for argv in (
        ["git", "checkout", "main"],
        ["git", "switch", "main"],
        ["git", "log"],
        ["git", "status"],
        ["git", "diff"],
        ["git", "fetch"],
        ["git", "pull"],
    ):
        assert from_git(argv).action == "read"


def test_from_git_raw_action_preserved():
    intent = from_git(["git", "push", "origin", "main"])
    assert intent.params["raw_action"] == "push"


def test_from_git_rejects_non_git_argv():
    with pytest.raises(ValueError):
        from_git(["gh", "pr", "merge", "1"])


# --- GitHub CLI (gh) --------------------------------------------------------


def test_from_gh_workflow_run_happy_path():
    intent = from_gh(["gh", "workflow", "run", "deploy-prod.yml", "-f", "env=prod",
                       "-r", "main"])
    assert intent.resource == "workflow/deploy-prod.yml"
    assert intent.action == "run"
    assert intent.provider == "github"
    assert intent.params["inputs"] == {"env": "prod"}
    assert intent.metadata == {"ref": "main"}


def test_from_gh_release_create_and_delete():
    intent = from_gh(["gh", "release", "create", "v1.0.0"])
    assert intent.resource == "release/v1.0.0"
    assert intent.action == "create"

    intent2 = from_gh(["gh", "release", "delete", "v1.0.0"])
    assert intent2.action == "delete"


def test_from_gh_pr_merge_with_admin_and_method():
    intent = from_gh(["gh", "pr", "merge", "42", "--admin", "--squash"])
    assert intent.resource == "pr/42"
    assert intent.action == "merge"
    assert intent.params["admin"] is True
    assert intent.params["method"] == "squash"


def test_from_gh_pr_close_maps_to_stop():
    intent = from_gh(["gh", "pr", "close", "42"])
    assert intent.action == "stop"


def test_from_gh_repo_delete():
    intent = from_gh(["gh", "repo", "delete", "org/repo", "--yes"])
    assert intent.resource == "repo/org/repo"
    assert intent.action == "delete"


def test_from_gh_secret_and_variable_set_map_to_put():
    secret = from_gh(["gh", "secret", "set", "API_KEY"])
    assert secret.resource == "secret/API_KEY"
    assert secret.action == "put"

    secret_delete = from_gh(["gh", "secret", "delete", "API_KEY"])
    assert secret_delete.action == "delete"

    variable = from_gh(["gh", "variable", "set", "ENVIRONMENT"])
    assert variable.resource == "variable/ENVIRONMENT"
    assert variable.action == "put"


def test_from_gh_api_method_mapping():
    assert from_gh(["gh", "api", "-X", "DELETE", "repos/x/y"]).action == "delete"
    assert from_gh(["gh", "api", "-X", "POST", "repos/x/y"]).action == "create"
    assert from_gh(["gh", "api", "-X", "PUT", "repos/x/y"]).action == "update"
    assert from_gh(["gh", "api", "-X", "PATCH", "repos/x/y"]).action == "update"
    assert from_gh(["gh", "api", "repos/x/y"]).action == "read"


def test_from_gh_api_resource_and_provider():
    intent = from_gh(["gh", "api", "-X", "DELETE", "repos/x/y/branches/main"])
    assert intent.resource == "api/repos/x/y/branches/main"
    assert intent.provider == "github"


def test_from_gh_repo_flag_metadata():
    intent = from_gh(["gh", "workflow", "run", "deploy.yml", "-R", "org/repo"])
    assert intent.metadata["repo"] == "org/repo"


def test_from_gh_everything_else_is_read():
    intent = from_gh(["gh", "pr", "view", "42"])
    assert intent.action == "read"
    intent2 = from_gh(["gh", "issue", "list"])
    assert intent2.action == "read"


def test_from_gh_rejects_non_gh_argv():
    with pytest.raises(ValueError):
        from_gh(["git", "push", "origin", "main"])


# --- GitOps dispatcher (from_argv) ------------------------------------------


def test_from_argv_dispatches_helm():
    intents = from_argv(["helm", "uninstall", "api", "-n", "prod"])
    assert len(intents) == 1
    assert intents[0].provider == "helm"


def test_from_argv_dispatches_argocd_multi():
    intents = from_argv(["argocd", "app", "sync", "app1", "app2"])
    assert [i.resource for i in intents] == ["app/app1", "app/app2"]


def test_from_argv_dispatches_flux():
    intents = from_argv(["flux", "suspend", "kustomization", "podinfo"])
    assert intents[0].provider == "flux"
    assert intents[0].action == "stop"


def test_from_argv_dispatches_git():
    intents = from_argv(["git", "push", "--force", "origin", "main"])
    assert intents[0].provider == "git"
    assert intents[0].params["force"] is True


def test_from_argv_dispatches_gh():
    intents = from_argv(["gh", "pr", "merge", "1"])
    assert intents[0].provider == "github"
    assert intents[0].action == "merge"
