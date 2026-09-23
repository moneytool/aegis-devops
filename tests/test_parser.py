import pytest

from aegis_core.parser import (
    from_argocd,
    from_argocd_multi,
    from_argv,
    from_aws,
    from_aws_multi,
    from_az,
    from_az_multi,
    from_flux,
    from_gcloud,
    from_gh,
    from_git,
    from_helm,
    from_kubectl,
    from_kubectl_multi,
    from_terraform_plan,
    plan_digest,
    terraform_resource_aliases,
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
        "module_path": "module.app",
        "type_name": "aws_instance.web",
        "plan_sha256": plan_digest(plan),
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


def test_from_aws_s3api_put_bucket_policy_collapses_to_the_s3_bucket():
    # REVIEW-4 T1.7: s3api is the low-level spelling of s3; the resource is
    # the bucket itself, not "s3api/bucket-policy/...".
    intent = from_aws(["aws", "s3api", "put-bucket-policy", "--bucket", "my-logs"])
    assert intent.action == "put"
    assert intent.resource == "s3/bucket/my-logs"
    assert intent.params["raw_action"] == "put-bucket-policy"
    assert intent.params["raw_service"] == "s3api"


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
    # REVIEW-4 T2.5: region is derived from the zone (strip the trailing
    # "-<letter>"), not the raw zone string.
    assert intent.metadata == {"zone": "us-central1-a", "region": "us-central1"}


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


# --- REVIEW-4 T0.1: global options before the verb -----------------------------

# (parser, argv with global flags BEFORE the verb, equivalent argv with the
# flags AFTER the verb -- or, for launcher-only options like git -C, the
# plain command). The two forms must yield identical intents.
GLOBAL_FLAG_PLACEMENTS = [
    (
        "kubectl-namespace",
        from_argv,
        ["kubectl", "-n", "prod", "delete", "deployment/x"],
        ["kubectl", "delete", "deployment/x", "-n", "prod"],
    ),
    (
        "kubectl-context-cluster-kubeconfig",
        from_argv,
        ["kubectl", "--context=prod-us-east", "--cluster", "c1", "--kubeconfig", "/k",
         "delete", "node/w1"],
        ["kubectl", "delete", "node/w1", "--context=prod-us-east", "--cluster", "c1",
         "--kubeconfig", "/k"],
    ),
    (
        "kubectl-server-output-v-as-timeout-token-user",
        from_argv,
        ["kubectl", "-s", "https://x", "-o", "json", "-v", "6", "--as", "admin",
         "--as-group", "ops", "--request-timeout", "5s", "--token", "t", "--user", "u",
         "get", "pod/x"],
        ["kubectl", "get", "pod/x", "-s", "https://x", "-o", "json", "-v", "6", "--as",
         "admin", "--as-group", "ops", "--request-timeout", "5s", "--token", "t",
         "--user", "u"],
    ),
    (
        "git-C-c-git-dir-work-tree-no-pager",
        from_argv,
        ["git", "-C", "/repo", "-c", "core.pager=cat", "--git-dir=/repo/.git",
         "--work-tree", "/repo", "--no-pager", "-p", "--no-optional-locks",
         "--exec-path=/usr/lib/git", "push", "-f", "origin", "main"],
        ["git", "push", "-f", "origin", "main"],
    ),
    (
        "helm-namespace-kube-context-kubeconfig-debug",
        from_argv,
        ["helm", "-n", "prod", "--kube-context", "prod-us-east", "--kubeconfig", "/k",
         "--debug", "uninstall", "web"],
        ["helm", "uninstall", "web", "-n", "prod", "--kube-context", "prod-us-east",
         "--kubeconfig", "/k", "--debug"],
    ),
    (
        "argocd-server-grpc-web-auth-token-insecure-plaintext-config-core",
        from_argv,
        ["argocd", "--server", "argo.example", "--grpc-web", "--auth-token", "t",
         "--insecure", "--plaintext", "--config", "/c", "--core", "app", "sync",
         "prod-web", "--prune"],
        ["argocd", "app", "sync", "prod-web", "--prune", "--server", "argo.example",
         "--grpc-web", "--auth-token", "t", "--insecure", "--plaintext", "--config",
         "/c", "--core"],
    ),
    (
        "argocd-globals-between-app-and-subcommand",
        from_argv,
        ["argocd", "app", "--server", "argo.example", "sync", "prod-web", "--prune"],
        ["argocd", "app", "sync", "prod-web", "--prune"],
    ),
    (
        "flux-namespace-context-kubeconfig-timeout-verbose",
        from_argv,
        ["flux", "-n", "flux-system", "--context", "prod", "--kubeconfig", "/k",
         "--timeout", "5m", "--verbose", "reconcile", "kustomization", "podinfo"],
        ["flux", "reconcile", "kustomization", "podinfo", "-n", "flux-system",
         "--context", "prod", "--kubeconfig", "/k", "--timeout", "5m", "--verbose"],
    ),
    (
        "gh-repo-before-group",
        from_argv,
        ["gh", "-R", "org/repo", "workflow", "run", "deploy-prod.yml", "-r", "main"],
        ["gh", "workflow", "run", "deploy-prod.yml", "-r", "main", "-R", "org/repo"],
    ),
    (
        "gh-repo-between-group-and-subcommand",
        from_argv,
        ["gh", "workflow", "--repo", "org/repo", "run", "deploy-prod.yml"],
        ["gh", "workflow", "run", "deploy-prod.yml", "--repo", "org/repo"],
    ),
    (
        "aws-region-profile-output-debug-before-service",
        from_argv,
        ["aws", "--region", "us-east-1", "--profile", "prod-admin", "--output", "json",
         "--debug", "ec2", "terminate-instances", "--instance-ids", "i-1"],
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--region",
         "us-east-1", "--profile", "prod-admin", "--output", "json", "--debug"],
    ),
    (
        "az-subscription-verbose-before-group",
        from_argv,
        ["az", "--subscription", "sub-1", "--verbose", "aks", "scale", "-g", "rg1",
         "-n", "aks1", "--node-count", "5"],
        ["az", "aks", "scale", "-g", "rg1", "-n", "aks1", "--node-count", "5",
         "--subscription", "sub-1", "--verbose"],
    ),
    (
        "gcloud-project-log-http-before-group",
        from_argv,
        ["gcloud", "--project", "acme-prod", "--log-http", "sql", "instances", "delete",
         "prod-db"],
        ["gcloud", "sql", "instances", "delete", "prod-db", "--project", "acme-prod",
         "--log-http"],
    ),
]


@pytest.mark.parametrize(
    "parser, before, after",
    [(p, b, a) for _, p, b, a in GLOBAL_FLAG_PLACEMENTS],
    ids=[name for name, *_ in GLOBAL_FLAG_PLACEMENTS],
)
def test_global_flags_before_the_verb_yield_the_same_intents_as_after(parser, before, after):
    intents_before = parser(before)
    intents_after = parser(after)
    assert [i.to_dict() for i in intents_before] == [i.to_dict() for i in intents_after]
    # and the verb was actually recognised: no intent has a flag for an action
    assert all(not i.action.startswith("-") for i in intents_before)


def test_kubectl_identity_flags_before_verb_land_in_metadata():
    intent = from_kubectl(
        ["kubectl", "-n", "prod", "--context=prod-us-east", "--cluster", "c1", "delete", "pod/x"]
    )
    assert intent.metadata == {"namespace": "prod", "context": "prod-us-east", "cluster": "c1"}
    assert intent.action == "delete"
    assert intent.resource == "pod/x"


def test_git_launcher_options_are_not_recorded_in_params():
    intent = from_git(["git", "-C", "/repo", "--no-pager", "push", "-f", "origin", "main"])
    assert intent.resource == "ref/main"
    assert intent.params == {"force": True, "raw_action": "push"}


def test_helm_kube_context_before_verb_lands_in_metadata():
    intent = from_helm(["helm", "--kube-context", "prod-us-east", "-n", "prod", "uninstall", "web"])
    assert intent.metadata == {"context": "prod-us-east", "namespace": "prod"}
    assert intent.action == "delete"


def test_gh_repo_before_group_lands_in_metadata():
    intent = from_gh(["gh", "-R", "org/repo", "pr", "merge", "42", "--admin"])
    assert intent.metadata == {"repo": "org/repo"}
    assert intent.resource == "pr/42"
    assert intent.action == "merge"


@pytest.mark.parametrize(
    "argv",
    [
        ["kubectl", "--typo", "delete", "node/x"],
        ["kubectl", "-n"],  # value flag with no value
        ["kubectl", "-n", "prod"],  # options but no verb
        ["git", "--typo", "push", "-f", "origin", "main"],
        ["helm", "--typo", "uninstall", "web"],
        ["argocd", "--typo", "app", "sync", "x"],
        ["flux", "--typo", "reconcile", "kustomization", "x"],
        ["gh", "--typo", "workflow", "run", "x"],
    ],
    ids=lambda a: " ".join(a),
)
def test_unrecognised_leading_option_or_missing_verb_raises(argv):
    with pytest.raises(ValueError):
        from_argv(argv)


# --- REVIEW-4 T0.2: glued short flags, selectors, comma kinds, cascade ---------


@pytest.mark.parametrize(
    "argv, expected_metadata, expected_params",
    [
        (["kubectl", "get", "pod/x", "-nprod"], {"namespace": "prod"}, {}),
        (["kubectl", "get", "pod/x", "-n=prod"], {"namespace": "prod"}, {}),
        (["kubectl", "get", "pod/x", "-ojson", "-nprod"], {"namespace": "prod"}, {}),
        (["kubectl", "get", "pods", "-lapp=web"], {}, {"selector": "app=web"}),
        (["kubectl", "-nprod", "get", "pod/x", "-v6"], {"namespace": "prod"}, {}),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else str(v),
)
def test_kubectl_glued_short_flags_are_expanded(argv, expected_metadata, expected_params):
    intent = from_kubectl(argv)
    assert intent.metadata == expected_metadata
    assert intent.params == expected_params


def test_kubectl_glued_manifest_and_kustomize_flags():
    intent = from_kubectl(["kubectl", "apply", "-fdeploy.yaml"])
    assert intent.resource == "manifest/deploy.yaml"
    assert intent.params["file"] == "deploy.yaml"
    intent = from_kubectl(["kubectl", "apply", "-k./overlays/prod"])
    assert intent.resource == "manifest/prod"


def test_kubectl_scale_with_glued_namespace_keeps_replicas():
    intent = from_kubectl(["kubectl", "scale", "deployment/api-server", "--replicas=5", "-nprod"])
    assert intent.params == {"replicas": 5}
    assert intent.metadata == {"namespace": "prod"}


def test_kubectl_exec_command_after_double_dash_is_not_expanded():
    intent = from_kubectl(["kubectl", "exec", "mypod", "-nprod", "--", "ls", "-la"])
    assert intent.params["command"] == ["ls", "-la"]
    assert intent.metadata == {"namespace": "prod"}


@pytest.mark.parametrize(
    "argv, expected_params",
    [
        (["kubectl", "delete", "-l", "role=worker", "node"], {"selector": "role=worker"}),
        (["kubectl", "delete", "node", "--selector=role=worker"], {"selector": "role=worker"}),
        (["kubectl", "delete", "node", "--selector", "role=worker"], {"selector": "role=worker"}),
        (
            ["kubectl", "delete", "node", "--field-selector", "spec.unschedulable=true"],
            {"field_selector": "spec.unschedulable=true"},
        ),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else str(v),
)
def test_kubectl_selectors_are_value_flags_and_target_every_object_of_kind(argv, expected_params):
    intent = from_kubectl(argv)
    assert intent.resource == "node/*"
    assert intent.action == "delete"
    assert intent.params == expected_params


def test_kubectl_comma_separated_kinds_yield_one_intent_per_kind():
    intents = from_kubectl_multi(
        ["kubectl", "delete", "nodes,pods", "--all", "--context", "prod-us-east"]
    )
    assert [i.resource for i in intents] == ["node/*", "pod/*"]
    assert all(i.action == "delete" for i in intents)
    assert all(i.params == {"all": True} for i in intents)
    assert all(i.metadata == {"context": "prod-us-east"} for i in intents)


def test_kubectl_comma_separated_kinds_with_names_is_rejected():
    with pytest.raises(ValueError):
        from_kubectl_multi(["kubectl", "delete", "nodes,pods", "a", "b"])


def test_kubectl_delete_all_of_kind_in_namespace():
    intent = from_kubectl(["kubectl", "delete", "--all", "pods", "-n", "prod"])
    assert intent.resource == "pod/*"
    assert intent.params == {"all": True}
    assert intent.metadata == {"namespace": "prod"}


@pytest.mark.parametrize(
    "argv",
    [
        ["kubectl", "delete", "namespace", "prod"],
        ["kubectl", "delete", "namespace/prod"],
        ["kubectl", "delete", "ns", "prod"],
        ["kubectl", "delete", "namespaces", "prod", "--context", "prod-us-east"],
    ],
    ids=lambda a: " ".join(a),
)
def test_kubectl_delete_namespace_also_emits_cascade_intent(argv):
    intents = from_kubectl_multi(argv)
    assert [i.resource for i in intents] == ["namespace/prod", "*/*"]
    cascade = intents[1]
    assert cascade.action == "delete"
    assert cascade.provider == "kubernetes"
    assert cascade.metadata["namespace"] == "prod"
    assert cascade.params["cascade_from"] == "namespace/prod"
    # metadata from the command line is inherited by the cascade intent
    assert intents[0].metadata.get("context") == cascade.metadata.get("context")


def test_kubectl_delete_namespace_cascade_one_per_named_namespace():
    intents = from_kubectl_multi(["kubectl", "delete", "ns", "a", "b"])
    assert [i.resource for i in intents] == ["namespace/a", "namespace/b", "*/*", "*/*"]
    assert [i.metadata["namespace"] for i in intents[2:]] == ["a", "b"]


def test_kubectl_delete_namespace_wildcard_or_selector_does_not_cascade():
    assert [i.resource for i in from_kubectl_multi(["kubectl", "delete", "ns", "--all"])] == [
        "namespace/*"
    ]
    assert [
        i.resource for i in from_kubectl_multi(["kubectl", "delete", "ns", "-l", "team=x"])
    ] == ["namespace/*"]


def test_kubectl_get_namespace_does_not_cascade():
    assert [i.resource for i in from_kubectl_multi(["kubectl", "get", "ns", "prod"])] == [
        "namespace/prod"
    ]


def test_helm_and_flux_glued_namespace():
    assert from_helm(["helm", "uninstall", "web", "-nprod"]).metadata == {"namespace": "prod"}
    assert from_helm(["helm", "-nprod", "uninstall", "web"]).metadata == {"namespace": "prod"}
    assert from_flux(["flux", "suspend", "kustomization", "x", "-nflux-system"]).metadata == {
        "namespace": "flux-system"
    }


def test_helm_debug_flag_does_not_swallow_the_release_name():
    intent = from_helm(["helm", "uninstall", "--debug", "web"])
    assert intent.resource == "release/web"
    assert "debug" not in intent.params


# --- REVIEW-4 T1.5: boolean coercion; --dry-run=false is not a dry run ----------
# (argv, params key): "<flag>=false" (or =no / =0) must never set the boolean.
FALSE_FLAG_CASES = [
    (["kubectl", "delete", "pod/x", "--force=false"], "force"),
    (["kubectl", "delete", "pod/x", "--wait=no"], "wait"),
    (["kubectl", "delete", "pod/x", "--dry-run=false"], "dry_run"),
    (["kubectl", "delete", "pod/x", "--dry-run=none"], "dry_run"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--force=false"], "force"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--dry-run=false"], "dry_run"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--yes=false"], "yes"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--no-wait=0"], "no-wait"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--what-if=false"], "dry_run"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--dry-run=false"], "dry_run"),
    (["gcloud", "compute", "instances", "delete", "x", "--quiet=false"], "quiet"),
    (["gcloud", "compute", "instances", "delete", "x", "--async=false"], "async"),
    (["gcloud", "compute", "instances", "delete", "x", "--dry-run=false"], "dry_run"),
    (["gcloud", "compute", "instances", "delete", "x", "--dry-run=0"], "dry_run"),
    (["helm", "upgrade", "x", "./c", "--atomic=false"], "atomic"),
    (["helm", "upgrade", "x", "./c", "--install=false"], "install"),
    (["helm", "upgrade", "x", "./c", "--dry-run=false"], "dry_run"),
    (["helm", "upgrade", "x", "./c", "--dry-run=none"], "dry_run"),
    (["argocd", "app", "sync", "x", "--prune=false"], "prune"),
    (["argocd", "app", "sync", "x", "--force=no"], "force"),
    (["argocd", "app", "sync", "x", "--dry-run=false"], "dry_run"),
    (["flux", "reconcile", "kustomization", "x", "--dry-run=false"], "dry_run"),
    (["flux", "get", "kustomization", "x", "--export=false"], "export"),
    (["flux", "get", "kustomization", "x", "--export=false"], "dry_run"),
    (["gh", "pr", "merge", "1", "--admin=false"], "admin"),
    (["gh", "pr", "merge", "1", "--delete-branch=false"], "delete_branch"),
    (["git", "push", "origin", "main", "--dry-run=false"], "dry_run"),
]


@pytest.mark.parametrize(
    "argv, key", FALSE_FLAG_CASES, ids=[f"{a[0]}:{a[-1]}->{k}" for a, k in FALSE_FLAG_CASES]
)
def test_flag_equals_false_never_sets_the_boolean(argv, key):
    for intent in from_argv(argv):
        assert intent.params.get(key) is not True, intent.params
        assert intent.params.get(key) != "false", intent.params
        if key == "dry_run":
            assert "dry_run" not in intent.params, intent.params


TRUE_FLAG_CASES = [
    (["kubectl", "delete", "pod/x", "--force=true"], "force"),
    (["kubectl", "delete", "pod/x", "--force=1"], "force"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--force=yes"], "force"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--yes=true"], "yes"),
    (["gcloud", "compute", "instances", "delete", "x", "--quiet=true"], "quiet"),
    (["helm", "upgrade", "x", "./c", "--atomic=on"], "atomic"),
    (["argocd", "app", "sync", "x", "--prune=true"], "prune"),
    (["argocd", "app", "sync", "x", "--prune=TRUE"], "prune"),
    (["argocd", "app", "sync", "x", "--prune"], "prune"),
    (["flux", "get", "kustomization", "x", "--export=true"], "export"),
    (["flux", "get", "kustomization", "x", "--export=true"], "dry_run"),
    (["gh", "pr", "merge", "1", "--admin=true"], "admin"),
]


@pytest.mark.parametrize(
    "argv, key", TRUE_FLAG_CASES, ids=[f"{a[0]}:{a[-1]}->{k}" for a, k in TRUE_FLAG_CASES]
)
def test_flag_equals_true_sets_the_boolean_to_real_true(argv, key):
    for intent in from_argv(argv):
        assert intent.params.get(key) is True, intent.params


DRY_RUN_TRUTHY_CASES = [
    ["kubectl", "delete", "pod/x", "--dry-run=true"],
    ["kubectl", "delete", "pod/x", "--dry-run=client"],
    ["kubectl", "delete", "pod/x", "--dry-run=server"],
    ["kubectl", "delete", "pod/x", "--dry-run"],
    ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--dry-run"],
    ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--dry-run=true"],
    ["az", "vm", "delete", "-n", "x", "-g", "rg", "--what-if=true"],
    ["gcloud", "compute", "instances", "delete", "x", "--dry-run=yes"],
    ["helm", "upgrade", "x", "./c", "--dry-run"],
    ["helm", "upgrade", "x", "./c", "--dry-run=client"],
    ["helm", "upgrade", "x", "./c", "--dry-run=server"],
    ["helm", "upgrade", "x", "./c", "--dry-run=true"],
    ["argocd", "app", "sync", "x", "--dry-run"],
    ["argocd", "app", "sync", "x", "--dry-run=true"],
    ["flux", "reconcile", "kustomization", "x", "--dry-run"],
    ["flux", "reconcile", "kustomization", "x", "--dry-run=1"],
    ["git", "push", "-n", "origin", "main"],
]


@pytest.mark.parametrize("argv", DRY_RUN_TRUTHY_CASES, ids=lambda a: " ".join(a))
def test_dry_run_bare_or_truthy_sets_dry_run(argv):
    for intent in from_argv(argv):
        assert intent.params.get("dry_run") is True


def test_argocd_prune_with_dry_run_false_is_a_real_pruning_sync():
    # REVIEW-4 T1.5 acceptance: `argocd app sync x --prune --dry-run=false`
    intent = from_argocd(["argocd", "app", "sync", "x", "--prune", "--dry-run=false"])
    assert intent.params["prune"] is True
    assert "dry_run" not in intent.params


def test_argocd_prune_equals_true_is_boolean_true_not_the_string():
    intent = from_argocd(["argocd", "app", "sync", "prod-web", "--prune=true"])
    assert intent.params["prune"] is True
    assert intent.params["prune"] != "true"


def test_kubectl_non_boolean_spelling_of_a_boolean_flag_is_kept_verbatim():
    intent = from_kubectl(["kubectl", "delete", "pod/x", "--cascade=orphan"])
    assert intent.params["cascade"] == "orphan"


def test_bool_flag_helper_semantics():
    from aegis_core.parser import _bool_param, _coerce_bool, _is_dry_run

    assert _coerce_bool(None) is True
    assert (
        _coerce_bool("True") is True and _coerce_bool("YES") is True and _coerce_bool("1") is True
    )
    assert (
        _coerce_bool("false") is False
        and _coerce_bool("no") is False
        and _coerce_bool("0") is False
    )
    assert _coerce_bool("orphan") is None
    assert _bool_param(None) is True and _bool_param("false") is False and _bool_param("7") == 7
    assert (
        _is_dry_run(None)
        and _is_dry_run("true")
        and _is_dry_run("client", truthy=frozenset({"client"}))
    )
    assert not _is_dry_run("false") and not _is_dry_run("none") and not _is_dry_run("client")


# --- REVIEW-4 T1.7: provider-namespace aliases ----------------------------------


def test_git_push_force_without_refspec_marks_unknown_target():
    for argv in (
        ["git", "push", "-f"],
        ["git", "push", "--force", "origin"],
        ["git", "push", "--mirror", "origin"],
    ):
        intent = from_git(argv)
        assert intent.resource == "ref/*", argv
        assert intent.action == "push"
        assert intent.params["force"] is True
        assert intent.params["unknown_target"] is True


def test_git_push_without_refspec_or_force_still_marks_unknown_target():
    intent = from_git(["git", "push", "origin"])
    assert intent.resource == "ref/*"
    assert intent.params["unknown_target"] is True
    assert "force" not in intent.params
    assert intent.metadata == {"remote": "origin"}


def test_git_push_with_refspec_has_no_unknown_target():
    for argv in (["git", "push", "origin", "main"], ["git", "push", "-f", "origin", "HEAD:main"]):
        intent = from_git(argv)
        assert intent.resource == "ref/main"
        assert "unknown_target" not in intent.params


def test_git_push_mirror_does_not_swallow_the_remote_and_implies_force():
    intent = from_git(["git", "push", "--mirror", "origin"])
    assert intent.metadata == {"remote": "origin"}
    assert intent.params["mirror"] is True
    assert intent.params["force"] is True


def test_git_push_all_is_unknown_target():
    intent = from_git(["git", "push", "--all", "origin"])
    assert intent.params["all"] is True
    assert intent.params["unknown_target"] is True


@pytest.mark.parametrize(
    "argv, action, resource",
    [
        (["aws", "s3api", "delete-bucket", "--bucket", "b"], "delete", "s3/bucket/b"),
        (
            ["aws", "s3api", "create-bucket", "--bucket", "b", "--region", "us-east-1"],
            "create",
            "s3/bucket/b",
        ),
        (
            ["aws", "s3api", "put-bucket-policy", "--bucket", "b", "--policy", "file://p.json"],
            "put",
            "s3/bucket/b",
        ),
        (["aws", "s3api", "put-public-access-block", "--bucket", "b"], "put", "s3/bucket/b"),
        (["aws", "s3api", "get-bucket-location", "--bucket", "b"], "read", "s3/bucket/b"),
        (["aws", "s3api", "list-buckets"], "read", "s3/bucket/*"),
        (
            ["aws", "s3api", "delete-object", "--bucket", "b", "--key", "k/x"],
            "delete",
            "s3/object/b/k/x",
        ),
        (
            ["aws", "s3api", "put-object", "--bucket", "b", "--key", "k", "--body", "f"],
            "put",
            "s3/object/b/k",
        ),
        (
            ["aws", "s3api", "delete-objects", "--bucket", "b", "--delete", "file://d.json"],
            "delete",
            "s3/object/b/*",
        ),
        (
            ["aws", "s3control", "delete-access-point", "--account-id", "1", "--name", "ap"],
            "delete",
            "s3/access-point/ap",
        ),
        (
            ["aws", "s3control", "put-public-access-block", "--account-id", "1"],
            "put",
            "s3/public-access-block/*",
        ),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else "",
)
def test_aws_s3api_and_s3control_collapse_to_service_s3(argv, action, resource):
    intent = from_aws(argv)
    assert intent.provider == "aws"
    assert intent.action == action
    assert intent.resource == resource
    assert intent.params["raw_service"] == argv[1]
    assert intent.params["raw_action"] == argv[2]


def test_aws_s3api_object_key_recorded_in_params():
    intent = from_aws(["aws", "s3api", "delete-object", "--bucket", "b", "--key", "k/x"])
    assert intent.params["key"] == "k/x"


@pytest.mark.parametrize(
    "argv, resource",
    [
        (
            ["aws", "iam", "attach-role-policy", "--role-name", "r", "--policy-arn", "arn:x"],
            "iam/role-policy/r",
        ),
        (
            ["aws", "iam", "attach-user-policy", "--user-name", "u", "--policy-arn", "arn:x"],
            "iam/user-policy/u",
        ),
        (
            ["aws", "iam", "attach-group-policy", "--group-name", "g", "--policy-arn", "arn:x"],
            "iam/group-policy/g",
        ),
        (
            [
                "aws",
                "iam",
                "put-user-policy",
                "--user-name",
                "u",
                "--policy-name",
                "p",
                "--policy-document",
                "d",
            ],
            "iam/user-policy/u",
        ),
        (
            [
                "aws",
                "iam",
                "put-role-policy",
                "--role-name",
                "r",
                "--policy-name",
                "p",
                "--policy-document",
                "d",
            ],
            "iam/role-policy/r",
        ),
        (
            ["aws", "iam", "add-user-to-group", "--user-name", "u", "--group-name", "g"],
            "iam/user-to-group/g",
        ),
        (["aws", "iam", "create-access-key", "--user-name", "u"], "iam/access-key/u"),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else "",
)
def test_aws_iam_privilege_grants_normalise_to_update_with_privilege_flag(argv, resource):
    intent = from_aws(argv)
    assert intent.action == "update"
    assert intent.params["privilege"] is True
    assert intent.resource == resource
    assert intent.params["raw_action"] == argv[2]


def test_aws_iam_reads_and_plain_creates_are_not_privilege_grants():
    assert from_aws(["aws", "iam", "list-users"]).action == "read"
    assert "privilege" not in from_aws(["aws", "iam", "list-users"]).params
    create = from_aws(["aws", "iam", "create-user", "--user-name", "u"])
    assert create.action == "create"
    assert "privilege" not in create.params


ARM = "/subscriptions/sub-1/resourceGroups/rg-1/providers"


@pytest.mark.parametrize(
    "arm_type, expected",
    [
        ("Microsoft.ContainerService/managedClusters/c1", "aks/cluster/c1"),
        ("Microsoft.Compute/virtualMachines/vm1", "compute/vm/vm1"),
        ("Microsoft.Compute/virtualMachineScaleSets/ss1", "compute/vmss/ss1"),
        ("Microsoft.Storage/storageAccounts/sa1", "storage/account/sa1"),
        ("Microsoft.Sql/servers/srv1", "sql/server/srv1"),
        ("Microsoft.Sql/servers/srv1/databases/db1", "sql/db/db1"),
        ("Microsoft.KeyVault/vaults/kv1", "keyvault/vault/kv1"),
        ("Microsoft.Network/virtualNetworks/vn1", "network/vnet/vn1"),
        ("Microsoft.Network/networkSecurityGroups/nsg1", "network/nsg/nsg1"),
        ("Microsoft.Web/sites/app1", "web/app/app1"),
        ("Microsoft.ContainerRegistry/registries/acr1", "acr/registry/acr1"),
        ("Microsoft.Foo/bars/baz", "microsoft.foo/bars/baz"),
        (
            "Microsoft.ContainerService/managedClusters/c1/agentPools/p1",
            "aks/cluster/c1/agentpools/p1",
        ),
    ],
)
def test_az_ids_arm_path_maps_to_named_form_resource(arm_type, expected):
    intent = from_az(["az", "resource", "delete", "--ids", f"{ARM}/{arm_type}"])
    assert intent.provider == "azure"
    assert intent.action == "delete"
    assert intent.resource == expected
    assert intent.metadata["subscription"] == "sub-1"
    assert intent.metadata["resource_group"] == "rg-1"
    assert intent.metadata["arm_id"] == f"{ARM}/{arm_type}"


def test_az_ids_matches_the_named_flag_form():
    by_ids = from_az(
        [
            "az",
            "aks",
            "delete",
            "--ids",
            f"{ARM}/Microsoft.ContainerService/managedClusters/c1",
            "--yes",
        ]
    )
    by_name = from_az(
        ["az", "aks", "delete", "-n", "c1", "-g", "rg-1", "--subscription", "sub-1", "--yes"]
    )
    assert by_ids.resource == by_name.resource == "aks/cluster/c1"
    assert by_ids.action == by_name.action == "delete"
    assert by_ids.params == by_name.params
    assert by_ids.metadata["resource_group"] == by_name.metadata["resource_group"]
    assert by_ids.metadata["subscription"] == by_name.metadata["subscription"]


def test_az_ids_case_insensitive_segments_and_resource_group_id():
    intent = from_az(
        [
            "az",
            "resource",
            "delete",
            "--ids",
            "/SUBSCRIPTIONS/s/resourcegroups/rg/PROVIDERS/microsoft.compute/VIRTUALMACHINES/vm",
        ]
    )
    assert intent.resource == "compute/vm/vm"
    group = from_az(["az", "group", "delete", "--ids", "/subscriptions/s/resourceGroups/rg1"])
    assert group.resource == "resource/group/rg1"
    assert group.metadata["resource_group"] == "rg1"


def test_az_multiple_ids_yield_one_intent_each_and_single_form_rejects():
    argv = [
        "az",
        "vm",
        "deallocate",
        "--ids",
        f"{ARM}/Microsoft.Compute/virtualMachines/a",
        "/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Compute/virtualMachines/b",
        "--no-wait",
    ]
    intents = from_az_multi(argv)
    assert [i.resource for i in intents] == ["compute/vm/a", "compute/vm/b"]
    assert [i.metadata["resource_group"] for i in intents] == ["rg-1", "rg-2"]
    assert all(i.action == "stop" and i.params["no-wait"] is True for i in intents)
    with pytest.raises(ValueError):
        from_az(argv)
    assert [i.resource for i in from_argv(argv)] == ["compute/vm/a", "compute/vm/b"]


def test_az_ids_equals_form_and_explicit_flags_win_over_arm_metadata():
    intent = from_az(
        [
            "az",
            "vm",
            "start",
            f"--ids={ARM}/Microsoft.Compute/virtualMachines/a",
            "--subscription",
            "other",
        ]
    )
    assert intent.resource == "compute/vm/a"
    assert intent.metadata["subscription"] == "other"


@pytest.mark.parametrize(
    "bad",
    [
        "not-an-arm-id",
        "/subscriptions",
        "/subscriptions/s/resourceGroups",
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute",
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/a/extensions",
    ],
)
def test_az_ids_malformed_arm_path_raises(bad):
    with pytest.raises(ValueError):
        from_az(["az", "resource", "delete", "--ids", bad])


@pytest.mark.parametrize(
    "argv, resource, action",
    [
        (
            [
                "gh",
                "api",
                "-X",
                "POST",
                "repos/o/r/actions/workflows/deploy-prod.yml/dispatches",
                "-f",
                "ref=main",
            ],
            "workflow/deploy-prod.yml",
            "run",
        ),
        (
            [
                "gh",
                "api",
                "--method",
                "post",
                "/repos/o/r/actions/workflows/deploy-prod.yml/dispatches",
            ],
            "workflow/deploy-prod.yml",
            "run",
        ),
        (
            ["gh", "api", "--method=POST", "repos/o/r/releases", "-F", "tag_name=v1"],
            "release/*",
            "create",
        ),
        (["gh", "api", "-X", "DELETE", "repos/o/r/releases/12345"], "release/12345", "delete"),
        (["gh", "api", "-X", "DELETE", "repos/o/r"], "repo/o/r", "delete"),
        (["gh", "api", "-X", "DELETE", "https://api.github.com/repos/o/r"], "repo/o/r", "delete"),
        (["gh", "api", "-X", "PUT", "repos/o/r/actions/secrets/API_KEY"], "secret/API_KEY", "put"),
        (
            ["gh", "api", "-X", "DELETE", "repos/o/r/actions/secrets/API_KEY"],
            "secret/API_KEY",
            "delete",
        ),
        (
            ["gh", "api", "-X", "DELETE", "repos/o/r/branches/main/protection"],
            "branch-protection/main",
            "delete",
        ),
        (
            ["gh", "api", "-X", "PUT", "repos/o/r/branches/main/protection"],
            "branch-protection/main",
            "update",
        ),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else "",
)
def test_gh_api_rest_paths_map_to_porcelain_resources(argv, resource, action):
    intent = from_gh(argv)
    assert intent.provider == "github"
    assert intent.resource == resource
    assert intent.action == action
    assert intent.metadata["repo"] == "o/r"
    assert intent.params["api_path"].startswith("repos/o/r")


def test_gh_api_workflow_dispatch_matches_gh_workflow_run():
    via_api = from_gh(
        [
            "gh",
            "api",
            "-X",
            "POST",
            "repos/o/r/actions/workflows/deploy-prod.yml/dispatches",
            "-f",
            "ref=main",
            "-F",
            "inputs[env]=prod",
        ]
    )
    via_porcelain = from_gh(
        ["gh", "workflow", "run", "deploy-prod.yml", "-R", "o/r", "-r", "main", "-f", "env=prod"]
    )
    assert (via_api.resource, via_api.action) == (via_porcelain.resource, via_porcelain.action)
    assert via_api.metadata["repo"] == via_porcelain.metadata["repo"] == "o/r"
    assert via_api.metadata["ref"] == via_porcelain.metadata["ref"] == "main"
    assert via_api.params["inputs"] == {"ref": "main", "inputs[env]": "prod"}


def test_gh_api_unrouted_paths_and_methods_keep_the_generic_api_resource():
    read = from_gh(["gh", "api", "repos/o/r/actions/workflows/x.yml/dispatches?per_page=1"])
    assert read.action == "read"
    assert read.resource == "api/repos/o/r/actions/workflows/x.yml/dispatches"
    assert read.metadata["repo"] == "o/r"
    other = from_gh(["gh", "api", "-X", "PATCH", "repos/o/r/issues/1"])
    assert other.resource == "api/repos/o/r/issues/1" and other.action == "update"
    user = from_gh(["gh", "api", "user"])
    assert user.resource == "api/user" and "repo" not in user.metadata


def test_gh_api_explicit_repo_flag_wins_over_the_path():
    intent = from_gh(["gh", "api", "-R", "a/b", "-X", "DELETE", "repos/o/r"])
    assert intent.metadata["repo"] == "a/b"
    assert intent.resource == "repo/o/r"


# --- REVIEW-4 T1.6: terraform address aliases, region resolution, plan digest -----


def _tf_change(address, actions, **extra):
    change = {"address": address, "change": {"actions": actions, "before": {}, "after": {}}}
    change.update(extra)
    return change


def test_module_address_yields_type_name_alias():
    plan = {
        "resource_changes": [
            _tf_change(
                "module.app.aws_db_instance.main",
                ["delete"],
                type="aws_db_instance",
                name="main",
                module_address="module.app",
            )
        ]
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.resource == "module.app.aws_db_instance.main"
    assert intent.metadata["type_name"] == "aws_db_instance.main"
    assert intent.metadata["module_path"] == "module.app"
    assert terraform_resource_aliases(intent) == [
        "module.app.aws_db_instance.main",
        "aws_db_instance.main",
    ]


def test_nested_and_indexed_module_prefixes_are_stripped():
    plan = {
        "resource_changes": [
            _tf_change('module.app.module.db["primary"].aws_db_instance.main[0]', ["update"]),
            _tf_change("module.net[1].aws_vpc.this", ["create"]),
        ]
    }
    a, b = from_terraform_plan(plan)
    assert a.metadata["type_name"] == "aws_db_instance.main[0]"
    assert a.metadata["module_path"] == 'module.app.module.db["primary"]'
    assert b.metadata["type_name"] == "aws_vpc.this"
    assert b.metadata["module_path"] == "module.net[1]"


def test_root_module_resource_has_type_name_equal_to_address_and_single_alias():
    plan = {"resource_changes": [_tf_change("aws_instance.web", ["create"])]}
    (intent,) = from_terraform_plan(plan)
    assert intent.metadata["type_name"] == "aws_instance.web"
    assert "module_path" not in intent.metadata
    assert terraform_resource_aliases(intent) == ["aws_instance.web"]


def test_terraform_resource_aliases_is_safe_on_non_plan_intents():
    intent = from_kubectl(["kubectl", "delete", "pod/x"])
    assert terraform_resource_aliases(intent) == ["pod/x"]


def test_region_resolved_from_variables_when_provider_config_references_var():
    plan = {
        "variables": {"region": {"value": "eu-west-1"}},
        "configuration": {
            "provider_config": {"aws": {"expressions": {"region": {"references": ["var.region"]}}}}
        },
        "resource_changes": [
            _tf_change(
                "aws_instance.web", ["delete"], provider_name="registry.terraform.io/hashicorp/aws"
            )
        ],
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.params["region"] == "eu-west-1"
    assert intent.metadata["region"] == "eu-west-1"


def test_region_resolved_from_planned_values_before_provider_config():
    plan = {
        "configuration": {
            "provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-east-1"}}}}
        },
        "planned_values": {
            "root_module": {
                "child_modules": [
                    {
                        "resources": [
                            {
                                "address": "module.m.aws_instance.x",
                                "values": {"region": "ap-south-1"},
                            }
                        ]
                    }
                ]
            }
        },
        "resource_changes": [
            _tf_change(
                "module.m.aws_instance.x",
                ["create"],
                provider_name="registry.terraform.io/hashicorp/aws",
            )
        ],
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.params["region"] == "ap-south-1"


def test_region_resolved_from_prior_state_as_last_resort():
    plan = {
        "prior_state": {
            "values": {
                "root_module": {
                    "resources": [{"address": "aws_instance.x", "values": {"region": "sa-east-1"}}]
                }
            }
        },
        "resource_changes": [_tf_change("aws_instance.x", ["update"])],
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.params["region"] == "sa-east-1"


def test_region_uses_the_resources_provider_alias_from_configuration():
    plan = {
        "configuration": {
            "provider_config": {
                "aws": {"expressions": {"region": {"constant_value": "us-east-1"}}},
                "aws.west": {"expressions": {"region": {"constant_value": "us-west-2"}}},
            },
            "root_module": {
                "resources": [{"address": "aws_instance.west", "provider_config_key": "aws.west"}]
            },
        },
        "resource_changes": [
            _tf_change(
                "aws_instance.west", ["create"], provider_name="registry.terraform.io/hashicorp/aws"
            ),
            _tf_change(
                "aws_instance.east", ["create"], provider_name="registry.terraform.io/hashicorp/aws"
            ),
        ],
    }
    west, east = from_terraform_plan(plan)
    assert west.params["region"] == "us-west-2"
    assert east.params["region"] == "us-east-1"


def test_region_from_module_scoped_provider_config():
    plan = {
        "configuration": {
            "provider_config": {
                "module.app:aws": {"expressions": {"region": {"references": ["var.r"]}}}
            },
            "root_module": {
                "module_calls": {
                    "app": {
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_instance.x",
                                    "provider_config_key": "module.app:aws",
                                }
                            ]
                        }
                    }
                }
            },
        },
        "variables": {"r": {"value": "ca-central-1"}},
        "resource_changes": [
            _tf_change(
                "module.app.aws_instance.x",
                ["delete"],
                provider_name="registry.terraform.io/hashicorp/aws",
            )
        ],
    }
    (intent,) = from_terraform_plan(plan)
    assert intent.params["region"] == "ca-central-1"


def test_create_carries_region_and_change_values_win():
    plan = {
        "configuration": {
            "provider_config": {"aws": {"expressions": {"region": {"constant_value": "eu-west-1"}}}}
        },
        "resource_changes": [
            _tf_change(
                "aws_instance.a", ["create"], provider_name="registry.terraform.io/hashicorp/aws"
            ),
            {
                "address": "aws_instance.b",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "before": None, "after": {"region": "us-east-2"}},
            },
        ],
    }
    a, b = from_terraform_plan(plan)
    assert (
        a.action == "create"
        and a.params["region"] == "eu-west-1"
        and a.metadata["region"] == "eu-west-1"
    )
    assert b.params["region"] == "us-east-2"


def test_no_region_anywhere_leaves_both_keys_absent():
    (intent,) = from_terraform_plan(
        {"resource_changes": [_tf_change("aws_instance.a", ["create"])]}
    )
    assert "region" not in intent.params and "region" not in intent.metadata


def test_plan_digest_is_stable_canonical_and_content_sensitive():
    plan = {
        "resource_changes": [_tf_change("aws_instance.a", ["create"])],
        "terraform_version": "1.9.0",
    }
    reordered = {
        "terraform_version": "1.9.0",
        "resource_changes": [_tf_change("aws_instance.a", ["create"])],
    }
    assert plan_digest(plan) == plan_digest(plan) == plan_digest(reordered)
    assert len(plan_digest(plan)) == 64
    changed = {**plan, "terraform_version": "1.9.1"}
    assert plan_digest(changed) != plan_digest(plan)
    deleted = {
        "resource_changes": [_tf_change("aws_instance.a", ["delete"])],
        "terraform_version": "1.9.0",
    }
    assert plan_digest(deleted) != plan_digest(plan)


def test_every_plan_intent_carries_the_plan_sha256():
    plan = {
        "resource_changes": [
            _tf_change("aws_instance.a", ["create"]),
            _tf_change("aws_instance.b", ["delete"]),
        ]
    }
    intents = from_terraform_plan(plan)
    assert {i.metadata["plan_sha256"] for i in intents} == {plan_digest(plan)}
    tofu = {**plan, "opentofu": True}
    assert {i.metadata["plan_sha256"] for i in from_terraform_plan(tofu)} == {plan_digest(tofu)}
    assert plan_digest(tofu) != plan_digest(plan)


# --------------------------------------------------------------------------
# REVIEW-4 T2.5: gcloud --zone -> region derivation; helm --set family.
# --------------------------------------------------------------------------


def test_from_gcloud_zone_derives_region_by_stripping_the_zone_letter():
    intent = from_gcloud(
        ["gcloud", "compute", "instances", "start", "web-1", "--zone", "us-east1-b"]
    )
    assert intent.metadata["zone"] == "us-east1-b"
    assert intent.metadata["region"] == "us-east1"


def test_from_gcloud_explicit_region_wins_over_zone_derived_region_either_order():
    # --region after --zone.
    a = from_gcloud(
        ["gcloud", "compute", "instances", "start", "web-1",
         "--zone", "us-east1-b", "--region", "us-west1"]
    )
    assert a.metadata == {"zone": "us-east1-b", "region": "us-west1"}
    # --region before --zone -- same result regardless of argv order.
    b = from_gcloud(
        ["gcloud", "compute", "instances", "start", "web-1",
         "--region", "us-west1", "--zone", "us-east1-b"]
    )
    assert b.metadata == {"zone": "us-east1-b", "region": "us-west1"}


def test_from_gcloud_region_without_zone_is_unaffected():
    intent = from_gcloud(
        ["gcloud", "sql", "instances", "create", "prod-db", "--region", "us-central1"]
    )
    assert intent.metadata == {"region": "us-central1"}


def test_from_helm_set_splits_comma_separated_pairs():
    intent = from_helm(
        ["helm", "install", "api", "./chart", "--set", "a=1,b=2"]
    )
    assert intent.params["set"] == {"a": 1, "b": 2}


def test_from_helm_set_keeps_bracketed_and_quoted_commas_intact():
    intent = from_helm(
        ["helm", "install", "api", "./chart", "--set", 'list={a,b,c},s="x,y",c=3']
    )
    assert intent.params["set"] == {"list": "{a,b,c}", "s": '"x,y"', "c": 3}


def test_from_helm_set_string_does_not_coerce_values():
    intent = from_helm(
        ["helm", "install", "api", "./chart", "--set-string", "replicaCount=0,flag=true"]
    )
    assert intent.params["set"] == {"replicaCount": "0", "flag": "true"}


def test_from_helm_set_and_set_string_share_the_same_set_dict():
    intent = from_helm(
        ["helm", "install", "api", "./chart",
         "--set", "a=1", "--set-string", "b=2"]
    )
    assert intent.params["set"] == {"a": 1, "b": "2"}


def test_from_helm_set_file_and_set_json_are_recorded_raw():
    intent = from_helm(
        ["helm", "install", "api", "./chart",
         "--set-file", "cert=./cert.pem", "--set-json", 'labels={"team":"x"}']
    )
    assert intent.params["set_file"] == ["cert=./cert.pem"]
    assert intent.params["set_json"] == ['labels={"team":"x"}']
    assert "set" not in intent.params


def test_from_helm_nested_dotted_set_key_is_kept_as_a_single_string_key():
    intent = from_helm(
        ["helm", "upgrade", "api", "./chart", "--set", "image.tag=v2,replicaCount=0"]
    )
    assert intent.params["set"] == {"image.tag": "v2", "replicaCount": 0}


def test_helm_set_replica_count_zero_expressible_as_a_scope_rule():
    """REVIEW-4 T2.5 rule #5: 'block helm --set replicaCount=0 in prod' must
    be expressible as a dotted scope key and must fire whether or not other
    --set flags are present."""
    from aegis_core.store import scope_matches

    scope = {"set.replicaCount": 0}

    combined = from_helm(
        ["helm", "upgrade", "api", "./chart", "--set", "image.tag=v2,replicaCount=0"]
    )
    assert scope_matches(scope, combined.metadata, combined.params)

    separate = from_helm(
        ["helm", "upgrade", "api", "./chart",
         "--set", "replicaCount=0", "--set", "other=1"]
    )
    assert scope_matches(scope, separate.metadata, separate.params)

    not_zero = from_helm(
        ["helm", "upgrade", "api", "./chart", "--set", "replicaCount=3"]
    )
    assert not scope_matches(scope, not_zero.metadata, not_zero.params)
