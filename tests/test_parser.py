import time

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
    from_git_multi,
    from_helm,
    from_kubectl,
    from_kubectl_multi,
    from_terraform_plan,
    plan_digest,
    terraform_resource_aliases,
)


def _flag_params(intent):
    """An intent's params apart from the marker for targets kubectl finds when it
    runs, which the #66 tests below cover."""
    return {k: v for k, v in intent.params.items() if k != "resolved_at_runtime"}


def test_from_kubectl_scale_with_namespace_flag():
    intent = from_kubectl(["kubectl", "scale", "deployment/x", "--replicas=5", "-n", "prod"])
    assert intent.resource == "deployment/x"
    assert intent.action == "scale"
    assert intent.provider == "kubernetes"
    assert intent.params == {"replicas": 5, "value_types": {"replicas": "int"}}
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


def test_from_kubectl_discards_output_and_records_server_and_kubeconfig():
    """--kubeconfig is recorded: it decides which file the context and
    namespace come from under --resolve-current-context (review of #38). --server
    is recorded too: it overrides the context's cluster (review round 13)."""
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
    assert intent.metadata == {"kubeconfig": "/tmp/kc", "server": "https://x"}


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
    assert intent.params == {"replicas": 5, "value_types": {"replicas": "int"}}


def test_from_kubectl_replicas_equals_form():
    intent = from_kubectl(["kubectl", "scale", "deployment/x", "--replicas=5"])
    assert intent.params == {"replicas": 5, "value_types": {"replicas": "int"}}


# --- kubectl: apply/create/replace/delete via manifest -----------------------


def test_from_kubectl_apply_with_file():
    intent = from_kubectl(["kubectl", "apply", "-f", "manifests/app.yaml"])
    assert intent.resource == "manifest/app.yaml"
    assert intent.action == "apply"
    assert intent.params == {"file": "manifests/app.yaml", "manifest_not_inspected": True}


def test_from_kubectl_apply_with_stdin():
    intent = from_kubectl(["kubectl", "apply", "-f", "-"])
    assert intent.resource == "manifest/-"
    assert intent.params == {"file": "-", "manifest_not_inspected": True}


def test_from_kubectl_apply_with_kustomize_dir():
    intent = from_kubectl(["kubectl", "apply", "-k", "overlays/prod"])
    assert intent.resource == "manifest/prod"
    assert intent.params == {"file": "overlays/prod", "manifest_not_inspected": True}


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
    assert intent.resource == "pod/mypod"  # a bare name is a pod
    assert intent.params["command"] == ["ls", "-la"]


def test_from_kubectl_logs_resource():
    intent = from_kubectl(["kubectl", "logs", "mypod"])
    assert intent.action == "logs"
    assert intent.resource == "pod/mypod"


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
    assert intent.params["num-nodes"] == 5  # the SDK declares it an int


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
    expected = from_az(["az", "vm", "start", "-g", "rg1", "-n", "vm1"])
    # from_argv also marks what az takes from its configuration (subscription, location)
    assert [i.resource for i in intents] == [expected.resource]
    assert intents[0].params["unresolved_scope"] == ["subscription", "region"]


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


@pytest.mark.parametrize("flag", ["--what-if"])  # az has no --dry-run on this command
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
    assert intent.params["set"] == {"image": {"tag": "v2"}}
    assert intent.params["atomic"] is True
    assert intent.params["wait"] == "watcher"  # helm 4 waitValue; unresolved for helm 3
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
        ["argocd", "app", "create", "prod-web", "--project", "platform",
         "--server", "argocd.internal", "--grpc-web", "--auth-token", "secret"]
    )
    # the server is where the app lives, as --resolve-current-context's $ARGOCD_SERVER
    assert intent.metadata == {"project": "platform", "server": "argocd.internal"}
    assert "server" not in intent.params
    assert "auth_token" not in intent.params
    assert "grpc_web" not in intent.params


def test_argocd_sync_with_a_project_also_syncs_every_app_in_it():
    # argo-cd app.go: sync lists the project's apps and syncs them with the ones named
    intents = from_argocd_multi(
        ["argocd", "app", "sync", "prod-web", "--project", "platform", "--grpc-web"])
    assert [i.resource for i in intents] == ["app/prod-web", "app/*"]
    # --project picks the added apps; the app named keeps its own (unknown) project
    assert intents[0].metadata == {}
    assert intents[1].metadata == {"project": "platform"}
    assert intents[1].params["resolved_at_runtime"] == {"from": "app/*", "kinds": ["app"]}


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


def test_from_flux_create_export_is_a_rehearsal():
    # flux reconcile has no --dry-run; create --export only prints the object
    intent = from_flux(["flux", "create", "kustomization", "podinfo",
                        "--source=GitRepository/podinfo", "--path=./kustomize", "--export"])
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
        ["git", "log"],
        ["git", "status"],
        ["git", "diff"],
    ):
        assert from_git(argv).action == "read"
    # commands that change the local repository are never reads: the verb is the action
    for argv in (
        ["git", "checkout", "main"],
        ["git", "switch", "main"],
        ["git", "fetch"],
    ):
        assert from_git(argv).action == argv[1]
    # a pull, and the rebase pull.rebase in a config file may make of it (review round 21)
    assert [i.action for i in from_git_multi(["git", "pull"])] == ["pull", "rewrite"]


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
        ["argocd", "app", "sync", "prod-web", "--prune", "--server", "argo.example"],
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
    # a short name may be a tag, as only git knows when it runs
    assert intent.params == {"force": True, "raw_action": "push",
                             "possible_resources": ["tag/main"],
                             "resolved_at_runtime": {"from": "ref/main", "kinds": ["ref"],
                                                     "destination": True}}


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
    assert _flag_params(intent) == expected_params


def test_kubectl_glued_manifest_and_kustomize_flags():
    intent = from_kubectl(["kubectl", "apply", "-fdeploy.yaml"])
    assert intent.resource == "manifest/deploy.yaml"
    assert intent.params["file"] == "deploy.yaml"
    intent = from_kubectl(["kubectl", "apply", "-k./overlays/prod"])
    assert intent.resource == "manifest/prod"


def test_kubectl_scale_with_glued_namespace_keeps_replicas():
    intent = from_kubectl(["kubectl", "scale", "deployment/api-server", "--replicas=5", "-nprod"])
    assert intent.params == {"replicas": 5, "value_types": {"replicas": "int"}}
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
    assert _flag_params(intent) == expected_params


def test_kubectl_comma_separated_kinds_yield_one_intent_per_kind():
    intents = from_kubectl_multi(
        ["kubectl", "delete", "nodes,pods", "--all", "--context", "prod-us-east"]
    )
    assert [i.resource for i in intents] == ["node/*", "pod/*"]
    assert all(i.action == "delete" for i in intents)
    assert all(_flag_params(i) == {"all": True} for i in intents)
    assert all(i.metadata == {"context": "prod-us-east"} for i in intents)


def test_kubectl_comma_separated_kinds_with_names_is_rejected():
    with pytest.raises(ValueError):
        from_kubectl_multi(["kubectl", "delete", "nodes,pods", "a", "b"])


def test_kubectl_delete_all_of_kind_in_namespace():
    intent = from_kubectl(["kubectl", "delete", "--all", "pods", "-n", "prod"])
    assert intent.resource == "pod/*"
    assert _flag_params(intent) == {"all": True}
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
# flux reconcile has no --dry-run; create --export is the flux rehearsal
FLUX_CREATE = ["flux", "create", "kustomization", "x", "--source=GitRepository/x", "--path=./k"]

FALSE_FLAG_CASES = [
    (["kubectl", "delete", "pod/x", "--force=false"], "force"),
    (["kubectl", "delete", "pod/x", "--wait=no"], "wait"),
    (["kubectl", "delete", "pod/x", "--dry-run=false"], "dry_run"),
    (["kubectl", "delete", "pod/x", "--dry-run=none"], "dry_run"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--force=false"], "force"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--dry-run=false"], "dry_run"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--yes=false"], "yes"),
    (["az", "vm", "delete", "-n", "x", "-g", "rg", "--no-wait=0"], "no-wait"),
    (["az", "deployment", "group", "create", "-n", "x", "-g", "rg", "--what-if=false"],
     "dry_run"),
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
    ([*FLUX_CREATE, "--export=false"], "export"),
    ([*FLUX_CREATE, "--export=false"], "dry_run"),
    ([*FLUX_CREATE, "--export", "--export=false"], "dry_run"),
    (["gh", "pr", "merge", "1", "--admin=false"], "admin"),
    (["gh", "pr", "merge", "1", "--delete-branch=false"], "delete_branch"),
    # git's --dry-run takes no value (git refuses --dry-run=false); --no-dry-run is the off
    (["git", "push", "origin", "main", "--dry-run", "--no-dry-run"], "dry_run"),
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
    ([*FLUX_CREATE, "--export=true"], "export"),
    ([*FLUX_CREATE, "--export=true"], "dry_run"),
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
    ["az", "deployment", "group", "create", "-n", "x", "-g", "rg", "--what-if=true"],
    ["gcloud", "compute", "instances", "delete", "x", "--dry-run=yes"],
    ["helm", "upgrade", "x", "./c", "--dry-run"],
    ["helm", "upgrade", "x", "./c", "--dry-run=client"],
    ["helm", "upgrade", "x", "./c", "--dry-run=server"],
    ["helm", "upgrade", "x", "./c", "--dry-run=true"],
    ["argocd", "app", "sync", "x", "--dry-run"],
    ["argocd", "app", "sync", "x", "--dry-run=true"],
    [*FLUX_CREATE, "--export"],
    [*FLUX_CREATE, "--export=1"],
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
    assert _bool_param(None) is True and _bool_param("false") is False and _bool_param("7") == "7"
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
        intent = from_git_multi(argv)[0]  # --mirror also deletes: a second intent
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
    push, _tags, delete, tag_delete, _submodules = from_git_multi(
        ["git", "push", "--mirror", "origin"])
    assert (tag_delete.resource, tag_delete.action) == ("tag/*", "delete")
    assert push.metadata == {"remote": "origin"}
    assert push.params["mirror"] is True
    assert push.params["force"] is True
    # --mirror also deletes every remote ref with no local one
    assert (delete.resource, delete.action) == ("ref/*", "delete")
    assert delete.params["unknown_target"] is True


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


SUB = "0b1f6471-1bf0-4dda-aec3-000000000001"
ARM = f"/subscriptions/{SUB}/resourceGroups/rg-1/providers"


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
    assert intent.metadata["subscription"] == SUB
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
        ["az", "aks", "delete", "-n", "c1", "-g", "rg-1", "--subscription", SUB, "--yes"]
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
        f"/subscriptions/{SUB}/resourceGroups/rg-2/providers/Microsoft.Compute/virtualMachines/b",
        "--no-wait",
    ]
    intents = from_az_multi(argv)
    assert [i.resource for i in intents] == ["compute/vm/a", "compute/vm/b"]
    assert [i.metadata["resource_group"] for i in intents] == ["rg-1", "rg-2"]
    assert all(i.action == "stop" and i.params["no-wait"] is True for i in intents)
    with pytest.raises(ValueError):
        from_az(argv)
    assert [i.resource for i in from_argv(argv)] == ["compute/vm/a", "compute/vm/b"]


def test_az_ids_equals_form_and_the_id_wins_over_explicit_flags():
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
    # az ignores --subscription with --ids: the ID's subscription is used (azure-cli
    # core commands/arm.py parse_ids_arguments)
    assert intent.metadata["subscription"] == SUB
    assert "subscription_name" not in intent.metadata


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
    # gh api builds the nested body gh sends; its inputs are the porcelain's inputs
    assert via_api.params["body"] == {"ref": "main", "inputs": {"env": "prod"}}
    assert via_api.params["inputs"] == via_porcelain.params["inputs"] == {"env": "prod"}


def test_gh_api_unrouted_paths_and_methods_keep_the_generic_api_resource():
    read = from_gh(["gh", "api", "repos/o/r/actions/workflows/x.yml/dispatches?per_page=1"])
    assert read.action == "read"
    assert read.resource == "api/repos/o/r/actions/workflows/x.yml/dispatches"
    assert read.metadata["repo"] == "o/r"
    other = from_gh(["gh", "api", "-X", "PATCH", "repos/o/r/issues/1"])
    assert other.resource == "api/repos/o/r/issues/1" and other.action == "update"
    user = from_gh(["gh", "api", "user"])
    assert user.resource == "api/user" and "repo" not in user.metadata


@pytest.mark.parametrize("flag", [["-R", "a/b"], ["--repo", "a/b"], ["--repo=a/b"]])
def test_gh_api_has_no_repo_flag(flag):
    # gh api never calls EnableRepoOverride, so gh refuses -R/--repo (review round 13; this
    # test used to say -R won over the path)
    with pytest.raises(ValueError):
        from_gh(["gh", "api", *flag, "-X", "DELETE", "repos/o/r"])


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


def test_from_helm_set_reads_a_list_and_an_escaped_comma():
    # helm's strvals: {a,b,c} is a list, and a comma is kept only when escaped (quotes
    # are not special: helm refuses 's="x,y"', since 'y"' has no value)
    intent = from_helm(
        ["helm", "install", "api", "./chart", "--set", r"list={a,b,c},s=x\,y,c=3"]
    )
    assert intent.params["set"] == {"list": ["a", "b", "c"], "s": "x,y", "c": 3}
    with pytest.raises(ValueError):
        from_helm(["helm", "install", "api", "./chart", "--set", 's="x,y"'])


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
    # --set-json is read as JSON; --set-file's value is a file nobody read
    assert intent.params["set"] == {"labels": {"team": "x"}}
    assert intent.params["unresolved_scope"] == ["set.cert"]


def test_from_helm_nested_dotted_set_key_is_a_nested_map():
    # the shape helm gives the chart, which a dotted scope key (set.image.tag) walks
    intent = from_helm(
        ["helm", "upgrade", "api", "./chart", "--set", "image.tag=v2,replicaCount=0"]
    )
    assert intent.params["set"] == {"image": {"tag": "v2"}, "replicaCount": 0}


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


# --- v0.2.1: kubectl normal forms (council review of the v0.3 design) --------


@pytest.mark.parametrize("argv, expected", [
    ("kubectl drain node1", [("drain", "node/node1")]),
    ("kubectl drain node/node1 --ignore-daemonsets", [("drain", "node/node1")]),
    ("kubectl cordon node1 node2", [("cordon", "node/node1"), ("cordon", "node/node2")]),
    ("kubectl uncordon node1", [("uncordon", "node/node1")]),
    ("kubectl exec api-0 -- sh", [("exec", "pod/api-0")]),
    ("kubectl exec deploy/web -- sh", [("exec", "deployment/web"), ("exec", "pod/*")]),
    ("kubectl attach api-0", [("attach", "pod/api-0")]),
    ("kubectl port-forward svc/web 8080:80",
     [("port-forward", "service/web"), ("port-forward", "pod/*")]),
    ("kubectl port-forward api-0 8080:80", [("port-forward", "pod/api-0")]),
    ("kubectl logs api-0", [("logs", "pod/api-0")]),
    ("kubectl delete storageclasses fast", [("delete", "storageclass/fast")]),
    ("kubectl delete sc fast", [("delete", "storageclass/fast")]),
    ("kubectl delete ingressclasses nginx", [("delete", "ingressclass/nginx")]),
    ("kubectl delete clusterrolebindings admin", [("delete", "clusterrolebinding/admin")]),
    ("kubectl delete validatingwebhookconfigurations aegis",
     [("delete", "validatingwebhookconfiguration/aegis")]),
    ("kubectl delete ep web", [("delete", "endpoints/web")]),
])
def test_kubectl_normal_forms(argv, expected):
    from aegis_core.parser import from_argv

    assert [(i.action, i.resource) for i in from_argv(argv.split())] == expected


def test_kubectl_impersonation_is_recorded_not_dropped():
    from aegis_core.parser import from_argv

    intents = from_argv("kubectl delete node w1 --as=admin --as-group=system:masters "
                        "--as-group=ops --as-uid=42".split())
    assert intents[0].params["impersonate"] == {
        "user": "admin", "groups": ["system:masters", "ops"], "uid": "42"}
    # each impersonated identity is also its own intent, so policy can block it
    assert [(i.action, i.resource) for i in intents] == [
        ("delete", "node/w1"),
        ("impersonate", "user/admin"),
        ("impersonate", "group/system:masters"),
        ("impersonate", "group/ops"),
        ("impersonate", "uid/42"),
    ]
    leading = from_argv("kubectl --as admin delete node w1".split())
    assert [(i.action, i.resource) for i in leading] == [
        ("delete", "node/w1"), ("impersonate", "user/admin")]


@pytest.mark.parametrize("leading, trailing", [
    ("kubectl -n prod rollout restart deploy/web", "kubectl rollout restart deploy/web -n prod"),
    ("kubectl --as admin rollout restart deploy/web",
     "kubectl rollout restart deploy/web --as admin"),
    ("kubectl --as=admin rollout undo deploy/web", "kubectl rollout undo deploy/web --as=admin"),
    ("kubectl -n prod set image deploy/web app=x:2",
     "kubectl set image deploy/web app=x:2 -n prod"),
    ("kubectl --as=admin set image deploy/web app=x:2",
     "kubectl set image deploy/web app=x:2 --as=admin"),
    # re-review of #13: globals between the verb and its subcommand
    ("kubectl rollout --as admin restart deploy/web",
     "kubectl rollout restart deploy/web --as admin"),
    ("kubectl rollout --as=admin restart deploy/web",
     "kubectl rollout restart deploy/web --as=admin"),
    ("kubectl rollout -n prod --as-group=ops restart deploy/web",
     "kubectl rollout restart deploy/web -n prod --as-group=ops"),
    ("kubectl set --as=admin image deploy/web app=x:2",
     "kubectl set image deploy/web app=x:2 --as=admin"),
    ("kubectl -n prod set --as admin image deploy/web app=x:2",
     "kubectl set image deploy/web app=x:2 -n prod --as admin"),
])
def test_leading_globals_before_a_subcommand_verb(leading, trailing):
    """Review of #13: for rollout/set the subcommand was taken from the
    merged token list, so a leading global ("-n", "--as") became the
    subcommand and the impersonation / namespace was lost."""
    from aegis_core.parser import from_argv

    def shape(argv):
        return [(i.action, i.resource, i.metadata, i.params.get("impersonate"))
                for i in from_argv(argv.split())]

    assert shape(leading) == shape(trailing)
    assert not any(a.startswith("rollout--") for a, *_ in shape(leading))


@pytest.mark.parametrize("argv", [
    "kubectl rollout --bogus restart deploy/web",  # unknown option before the subcommand
    "kubectl rollout --as",                        # option without its value
    "kubectl rollout --as admin",                  # no subcommand after the options
    "kubectl set --as admin rollout deploy/web",   # not "set image"
])
def test_unparseable_options_before_a_subcommand_fail_closed(argv):
    from aegis_core.parser import from_argv

    with pytest.raises(ValueError):
        from_argv(argv.split())


@pytest.mark.parametrize("argv, resource, parent", [
    ("aws ec2 delete-volume --volume-id vol-1", "ec2/volume/vol-1", None),
    ("aws ec2 delete-snapshot --snapshot-id snap-1", "ec2/snapshot/snap-1", None),
    ("aws ec2 delete-vpc --vpc-id vpc-1", "ec2/vpc/vpc-1", None),
    ("aws ec2 delete-security-group --group-id sg-1", "ec2/security-group/sg-1", None),
    ("aws ec2 delete-security-group --group-name web", "ec2/security-group/web", None),
    ("aws rds delete-db-cluster --db-cluster-identifier c1", "rds/db-cluster/c1", None),
    ("aws rds delete-db-snapshot --db-snapshot-identifier s1", "rds/db-snapshot/s1", None),
    ("aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier s1",
     "rds/db-cluster-snapshot/s1", None),
    ("aws eks delete-cluster --name c", "eks/cluster/c", None),
    ("aws eks delete-nodegroup --cluster-name c --nodegroup-name ng", "eks/nodegroup/ng", "c"),
    ("aws eks delete-nodegroup --nodegroup-name ng --cluster-name c", "eks/nodegroup/ng", "c"),
    ("aws ecs delete-service --cluster c --service s", "ecs/service/s", "c"),
    ("aws ecs delete-cluster --cluster c", "ecs/cluster/c", None),
    ("aws logs delete-log-group --log-group-name g", "logs/log-group/g", None),
    ("aws route53 delete-hosted-zone --id Z1", "route53/hosted-zone/Z1", None),
    ("aws efs delete-file-system --file-system-id fs-1", "efs/file-system/fs-1", None),
    ("aws elasticache delete-cache-cluster --cache-cluster-id c", "elasticache/cache-cluster/c",
     None),
    # unchanged: the generic identifier flags
    ("aws rds delete-db-instance --db-instance-identifier db1", "rds/db-instance/db1", None),
    ("aws dynamodb delete-table --table-name t", "dynamodb/table/t", None),
])
def test_aws_target_names_come_from_the_resources_own_flag(argv, resource, parent):
    """The name of the resource an operation acts on, not '*' and not its
    parent's: a name-specific rule must match on the client as it does in the
    compiled AWS policy."""
    import shlex

    (intent,) = from_aws_multi(shlex.split(argv))
    assert intent.resource == resource
    assert intent.params.get("parent") == parent



@pytest.mark.parametrize("argv, resource", [
    ("aws logs delete-log-group --log-group-name 123", "logs/log-group/123"),
    ("aws logs delete-log-group --log-group-name 001", "logs/log-group/001"),
    ("aws logs delete-log-group --log-group-name nan", "logs/log-group/nan"),
    ("aws eks delete-cluster --name 123", "eks/cluster/123"),
    ("aws ecs delete-service --cluster prod --service 123", "ecs/service/123"),
    ("aws rds delete-db-cluster --db-cluster-identifier inf", "rds/db-cluster/inf"),
    ("aws ec2 delete-volume --volume-id=007", "ec2/volume/007"),
])
def test_aws_numeric_looking_names_stay_strings(argv, resource):
    """Review of #19: names are never coerced to numbers (leading zeroes and
    'nan'/'inf' included), so name-specific rules still match."""
    import shlex

    (intent,) = from_aws_multi(shlex.split(argv))
    assert intent.resource == resource


# --- #53: kubectl boolean flags ---------------------------------------------------


@pytest.mark.parametrize("argv, resource, params", [
    ("kubectl get pods -n prod --no-headers", "pod/*", {"no-headers": True}),
    ("kubectl get --no-headers pods -n prod", "pod/*", {"no-headers": True}),
    ("kubectl get pods --show-labels -n prod", "pod/*", {"show-labels": True}),
    ("kubectl get pods -n prod --watch", "pod/*", {"watch": True}),
    ("kubectl get --watch pods -n prod", "pod/*", {"watch": True}),
    ("kubectl get pods -n prod -w", "pod/*", {"watch": True}),
    ("kubectl get pods --all-namespaces --no-headers", "pod/*", {"no-headers": True}),
    ("kubectl get pods -A --no-headers", "pod/*", {"no-headers": True}),
    ("kubectl get pod web --ignore-not-found -n prod", "pod/web", {"ignore-not-found": True}),
    ("kubectl delete pod web --force -n prod", "pod/web", {"force": True}),
    ("kubectl delete pod web --wait -n prod", "pod/web", {"wait": True}),
    ("kubectl delete pod web --wait=false -n prod", "pod/web", {"wait": False}),
    ("kubectl delete pod web --dry-run -n prod", "pod/web", {"dry_run": True}),
    ("kubectl get pods --no-headers=false -n prod", "pod/*", {"no-headers": False}),
    ("kubectl logs -f api-0 -n prod", "pod/api-0", {"follow": True}),
    ("kubectl logs api-0 --follow -n prod", "pod/api-0", {"follow": True}),
    ("kubectl logs api-0 -f -n prod", "pod/api-0", {"follow": True}),
    ("kubectl top pod --containers --sum -n prod", "pod/*", {"containers": True, "sum": True}),
    ("kubectl apply -f x.yaml --openapi-patch --server-side", "manifest/x.yaml", None),
    # not in the table: at the end of argv it is a boolean rather than a
    # flag missing its value
    ("kubectl get pods -n prod --ignore-validation-errors", "pod/*",
     {"ignore-validation-errors": True}),
])
def test_kubectl_boolean_flags_take_no_value(argv, resource, params):
    """#53: a boolean flag never swallows the next token, and at the end of
    argv it is not 'missing its value'."""
    import shlex

    intents = from_kubectl_multi(shlex.split(argv))
    assert [i.resource for i in intents] == [resource]
    if params is not None:
        assert _flag_params(intents[0]) == params
    if "-n prod" in argv:
        assert intents[0].metadata["namespace"] == "prod"


@pytest.mark.parametrize("argv, resources", [
    ("kubectl delete ns --interactive prod staging", ["namespace/prod", "namespace/staging"]),
    ("kubectl delete ns prod staging --interactive", ["namespace/prod", "namespace/staging"]),
])
def test_kubectl_delete_interactive_is_a_boolean(argv, resources):
    """Council review of #53: --interactive (kubectl 1.27+) must not swallow
    the first name."""
    intents = from_kubectl_multi(argv.split())
    named = [i.resource for i in intents if "cascade_from" not in i.params]
    assert named == resources


@pytest.mark.parametrize("argv, resources, namespace", [
    # --resource-version takes "--context" as its value; staging is a name
    ("kubectl scale deploy web --resource-version --context staging --replicas=0",
     ["deployment/web", "deployment/staging"], None),
    # --field-manager takes "-n"; staging is a namespace being labelled
    ("kubectl label ns prod --field-manager -n staging env=x",
     ["namespace/prod", "namespace/staging"], None),
    ("kubectl annotate pods --all --field-manager -n staging a=b", ["pod/staging"], None),
    ("kubectl delete pod web --grace-period -1 -n prod", ["pod/web"], "prod"),
])
def test_kubectl_value_flags_take_the_next_token_even_a_dash_one(argv, resources, namespace):
    """Council review of #53: as pflag does, a known value flag takes the
    next token even when it starts with '-', so an option that looks like a
    scope is not mistaken for one."""
    intents = from_kubectl_multi(argv.split())
    assert [i.resource for i in intents] == resources
    assert all(i.metadata.get("namespace") == namespace for i in intents)
    assert all("context" not in i.metadata for i in intents)


@pytest.mark.parametrize("argv, key, value", [
    ("kubectl delete pod web --grace-period -1", "grace-period", -1),
    ("kubectl logs api-0 --tail -1", "tail", -1),
    ("kubectl logs api-0 --since -5m", "since", -300),  # a Duration, in seconds
    ("kubectl logs api-0 -c app", "container", "app"),
    ("kubectl logs api-0 -capp", "container", "app"),
    ("kubectl get pods -L app", "label-columns", ["app"]),  # a StringSlice
    ("kubectl patch deploy x -p {}", "patch", "{}"),
])
def test_kubectl_value_flag_values_are_kept(argv, key, value):
    intents = from_kubectl_multi(argv.split())
    assert len(intents) == 1
    assert intents[0].params[key] == value


@pytest.mark.parametrize("argv", [
    "kubectl get pods --some-new-switch -n prod",
    "kubectl delete pod web --some-new-option --context staging",
    "kubectl delete pod web --some-new-option -A",
    "kubectl delete pod web --some-new-option --dry-run",
    "kubectl get pods --some-new-switch --no-headers",
])
def test_kubectl_unknown_long_flag_before_another_option_is_refused(argv):
    """Council review of #53: whether an unknown flag takes the next option
    as its value decides the namespace/context/target, so it is refused."""
    with pytest.raises(ValueError, match="cannot tell whether"):
        from_kubectl_multi(argv.split())


@pytest.mark.parametrize("argv", [
    "kubectl get pods -n",
    "kubectl get pods --namespace",
    "kubectl get pods -l",
    "kubectl get pods --field-selector",
    "kubectl get pods -o",
    "kubectl get pods --context",
    "kubectl get pods --kubeconfig",
])
def test_kubectl_value_flags_still_need_their_value(argv):
    with pytest.raises(ValueError, match="missing its value"):
        from_kubectl_multi(argv.split())


@pytest.mark.parametrize("argv, namespace, params", [
    ("kubectl get pods --no-headers -n --watch", "--watch", {"no-headers": True}),
    ("kubectl get pods -nprod --no-headers", "prod", {"no-headers": True}),
    ("kubectl get pods --namespace=prod --no-headers", "prod", {"no-headers": True}),
    ("kubectl get pods --no-headers -l app=web -n prod", "prod",
     {"no-headers": True, "selector": "app=web"}),
    ("kubectl get pods --no-headers -o name -n prod", "prod", {"no-headers": True}),
])
def test_kubectl_value_flags_keep_their_value_next_to_booleans(argv, namespace, params):
    """A value flag still takes the next token, even one starting with '-';
    glued and '=' forms are unchanged."""
    (intent,) = from_kubectl_multi(argv.split())
    assert intent.metadata["namespace"] == namespace
    assert _flag_params(intent) == params


def test_kubectl_unknown_long_flag_before_a_word_still_takes_it_as_value():
    (intent,) = from_kubectl_multi(["kubectl", "get", "pods", "--sort-by", "name", "-n", "prod"])
    assert intent.resource == "pod/*"
    assert _flag_params(intent) == {"sort-by": "name"}


def test_kubectl_dash_f_is_still_a_manifest_outside_logs():
    (intent,) = from_kubectl_multi(["kubectl", "apply", "-f", "app.yaml"])
    assert intent.resource == "manifest/app.yaml"


# --- #54: help / version probes ---------------------------------------------------


@pytest.mark.parametrize("argv, kind", [
    ("helm --help", "help"),
    ("helm -h", "help"),
    ("helm help install", "help"),
    ("helm version --short", "version"),
    ("helm install --help", "help"),
    ("argocd version --client", "version"),
    ("argocd version --client --short", "version"),
    ("argocd app delete --help", "help"),
    ("argocd app delete payments --help", "help"),
    ("kubectl version", "version"),
    ("kubectl version --client -o json", "version"),
    ("kubectl --version", "version"),
    ("kubectl --help", "help"),
    ("kubectl help delete", "help"),
    ("kubectl delete --help", "help"),
    ("kubectl delete -h", "help"),
    ("kubectl rollout restart --help", "help"),
    ("flux version --client", "version"),
    ("flux reconcile kustomization --help", "help"),
    ("gh --version", "version"),
    ("gh version", "version"),
    ("gh pr merge --help", "help"),
    ("gh help pr", "help"),
    ("git --version", "version"),
    ("git version", "version"),
    ("git help push", "help"),
    ("git push --help", "help"),
    ("git co --help", "help"),  # rewritten to "git help co", which shows the alias
    ("git -h", "help"),
    ("kubectl create deployment --help", "help"),
    ("kubectl create deploy web --help", "help"),
    ("kubectl create secret generic --help", "help"),
    ("kubectl create svc nodeport --help", "help"),
    ("kubectl top pod --help", "help"),
    ("kubectl config use-context --help", "help"),
    ("aws --version", "version"),
    ("az --version", "version"),
    ("az version", "version"),
    ("az vm delete --help", "help"),
    ("gcloud --version", "version"),
    ("gcloud version", "version"),
    ("gcloud help compute", "help"),
    ("gcloud compute instances delete --help", "help"),
    ("gsutil version", "version"),
    ("gsutil --help", "help"),
    ("psql --version", "version"),
    ("psql -V", "version"),
    ("psql --help", "help"),
    ("mysql --version", "version"),
    ("mysql --help", "help"),
    ("sqlite3 --version", "version"),
    ("sqlite3 -help", "help"),
    ("mongosh --version", "version"),
    ("mongosh --help", "help"),
    ("pulumi version", "version"),
    ("pulumi --version", "version"),
    ("pulumi destroy --help", "help"),
    ("alembic --version", "version"),
    ("alembic --help", "help"),
    ("alembic downgrade --help", "help"),
    ("flyway --version", "version"),
    ("flyway -v", "version"),
    ("flyway version", "version"),
    ("flyway help", "help"),
    ("rails --version", "version"),
    ("rails -v", "version"),
    ("rails --help", "help"),
    ("prisma --version", "version"),
    ("prisma version", "version"),
    ("prisma migrate deploy --help", "help"),
    ("/usr/local/bin/helm --help", "help"),
])
def test_help_and_version_probes_are_informational(argv, kind):
    """#54: informational probes are one read-only cli/<tool> intent, not a
    parse error."""
    (intent,) = from_argv(argv.split())
    tool = argv.split()[0].rsplit("/", 1)[-1]
    assert intent.resource == f"cli/{tool}"
    assert intent.action == "read"
    assert intent.params["informational"] == kind


@pytest.mark.parametrize("argv", [
    # --help as the value of an option: kubectl deletes namespace prod
    "kubectl -n --help delete ns prod",
    "kubectl delete ns prod -n --help",
    # an option before the probe flag: left to the provider parser
    "kubectl delete ns prod --force --help",
    "argocd app delete payments --cascade --help",
    # after "--" the flag belongs to the wrapped command
    "kubectl exec api-0 -- rm -rf /data --help",
    # plugins / extensions / aliases receive --help themselves
    "kubectl nuke --help",
    "helm diff --help",
    "gh my-alias --help",
    # gh extension exec passes --help / -h to the extension, which runs
    "gh extension exec review-probe --help",
    "gh extension exec review-probe -h",
    "gh extension exec --help",
    # flyway runs every command word it is given
    "flyway version clean",
    "flyway help clean",
    # kubectl runs a kubectl-create-<x> plugin for an unknown create subcommand
    "kubectl create nuke --help",
    "kubectl create secret nuke --help",
    "kubectl rollout nuke --help",
    "kubectl alpha --help",
    # the vcs tool: only "<cmd> --help" directly; "-h" goes to an alias as
    # is, and is a real option of grep and ls-remote
    "git push origin main --help",
    "git push -h",
    "git co -h",
    "git grep -h",
    "git ls-remote -h",
    # an aws [toplevel] alias (~/.aws/cli/alias) can replace "help" and any
    # service name, "s3 = !cmd" included, and runs its own command
    "aws help",
    "aws help topics",
    "aws s3 help",
    "aws s3 rm help",
    "aws nuke help",
    "aws s3 cp src help extra",
    # -h is --host for psql / mysql
    "psql -h db.internal",
    "mysql -h db.internal",
])
def test_mutating_or_ambiguous_forms_are_not_informational(argv):
    try:
        intents = from_argv(argv.split())
    except ValueError:
        return  # a parse error fails closed
    assert not any(i.params.get("informational") for i in intents)


def test_aws_help_is_never_informational_an_alias_can_replace_it():
    """Council review of #54: with "[toplevel] s3 = !cmd" in
    ~/.aws/cli/alias, "aws s3 help" runs cmd. Such forms go to the aws
    parser, as before; only --version is built in."""
    for argv in ("aws s3 help", "aws s3 rm help", "aws help"):
        try:
            intents = from_argv(argv.split())
        except ValueError:
            continue  # a parse error fails closed, as on main
        assert not any(i.params.get("informational") for i in intents)
    (intent,) = from_argv(["aws", "--version"])
    assert intent.params["informational"] == "version"


@pytest.mark.parametrize("argv", [
    "gh extension exec review-probe --help",
    "gh extension exec review-probe -h",
])
def test_gh_extension_exec_help_is_still_an_extension_exec(argv):
    """PR #59 review: "extension exec" sets DisableFlagParsing, so --help
    reaches the extension and runs it. It stays extension/exec, which
    extension/* constraints match, not a cli/gh read."""
    (intent,) = from_argv(argv.split())
    assert intent.resource == "extension/exec"
    assert "informational" not in intent.params


def test_gh_extension_exec_help_is_still_blocked_by_an_extension_rule():
    """PR #59 review reproduction: BLOCK for github extension/* stays BLOCK
    when --help or -h follows the extension name."""
    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.shell import intents_from_command
    from aegis_core.store import Constraint, ConstraintStore

    store = ConstraintStore(authority_map={"admin": {"configuration"}})
    store.add_constraint(Constraint.create(
        id="block-gh-extensions", provider="github", resource_pattern="extension/*",
        actions={"*"}, effect="BLOCK", constraint_class="configuration",
        principal="admin", source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00", rule_text="No gh extensions.",
    ))
    interceptor = AegisInterceptor(store)
    for command in ("gh extension exec review-probe --help",
                    "gh extension exec review-probe -h",
                    "gh extension exec review-probe"):
        (intent,) = intents_from_command(command)
        decision = interceptor.intercept(intent)
        assert decision.verdict == "BLOCK", command
        assert "block-gh-extensions" in decision.citations


@pytest.mark.parametrize("argv", [
    "kubectl get --raw /api/v1/namespaces/prod/secrets",
    "kubectl get --raw=/api/v1/namespaces/prod/secrets",
])
def test_kubectl_get_raw_reads_the_kind_its_path_names(argv):
    """A raw URI path can read any kind (secrets included): the kind and namespace are
    read from the path (review round 14), so a kind-based rule meets it."""
    intents = from_kubectl_multi(argv.split())
    assert [(i.resource, i.action) for i in intents] == [("secret/*", "get")]
    assert intents[0].metadata["namespace"] == "prod"


def test_kubectl_get_raw_of_a_path_naming_no_kind_is_still_refused():
    """A path that names no kind stays a parse error (fail closed)."""
    with pytest.raises(ValueError, match="not one resource or collection"):
        from_kubectl_multi("kubectl get --raw /apis".split())


@pytest.mark.parametrize("argv", [
    "kubectl -n --help delete ns prod",
    "kubectl delete ns prod --force --help",
])
def test_kubectl_help_next_to_a_delete_is_still_a_delete(argv):
    intents = from_argv(argv.split())
    assert ("namespace/prod", "delete") in [(i.resource, i.action) for i in intents]


# --- names kubectl resolves when it runs (#64) ----------------------------------------------


def _kubectl_targets(command: str) -> list[str]:
    return [i.resource for i in from_kubectl_multi(command.split())]


@pytest.mark.parametrize("verb", ["exec", "attach", "port-forward"])
@pytest.mark.parametrize("spelled,named", [
    ("deploy/web", "deployment/web"), ("deployment/web", "deployment/web"),
    ("deployments/web", "deployment/web"), ("deployment.apps/web", "deployment/web"),
    ("deployments.v1.apps/web", "deployment/web"), ("Deployment/web", "deployment/web"),
    ("svc/web", "service/web"), ("service/web", "service/web"), ("services/web", "service/web"),
    ("rs/web", "replicaset/web"), ("rc/web", "replicationcontroller/web"),
    ("replicationcontrollers/web", "replicationcontroller/web"),
    ("sts/web", "statefulset/web"), ("ds/web", "daemonset/web"), ("job/web", "job/web"),
    ("jobs/web", "job/web"), ("widget.x.io/web", "widget/web"),
])
def test_a_verb_run_on_a_pod_behind_a_name(verb, spelled, named):
    named_intent, behind = from_kubectl_multi(
        ["kubectl", verb, spelled, "-n", "prod", "--context", "kind-x"])
    assert (named_intent.resource, named_intent.action) == (named, verb)
    assert "resolved_at_runtime" not in named_intent.params
    assert (behind.resource, behind.action) == ("pod/*", verb)
    assert behind.params["resolved_at_runtime"] == {"from": named, "kinds": ["pod"]}
    for intent in (named_intent, behind):
        assert intent.metadata == {"namespace": "prod", "context": "kind-x"}


@pytest.mark.parametrize("command,targets", [
    ("kubectl exec web -- ls", ["pod/web"]),
    ("kubectl exec pod/web -- ls", ["pod/web"]),
    ("kubectl exec po/web -- ls", ["pod/web"]),
    ("kubectl exec pods/web -- ls", ["pod/web"]),
    # a pod called all, and a pod called deploy with the command web
    ("kubectl exec all -- ls", ["pod/all"]),
    ("kubectl exec deploy web", ["pod/deploy"]),
    ("kubectl port-forward deploy 80 81", ["pod/deploy"]),
    # attach alone reads two words as TYPE NAME (checked on kind)
    ("kubectl attach web", ["pod/web"]),
    ("kubectl attach pod web", ["pod/web"]),
    ("kubectl attach deploy web", ["deployment/web", "pod/*"]),
    # run's word names a new pod; debug's words name pods
    ("kubectl run all --image=x", ["pod/all", "all/*"]),
    ("kubectl run all --image=x a", ["pod/all", "all/a"]),
    ("kubectl debug all --image=x", ["pod/all", "all/*"]),
    ("kubectl debug all other --image=x", ["pod/all", "pod/other", "all/other"]),
])
def test_names_that_stay_what_they_are(command, targets):
    assert _kubectl_targets(command) == targets


def test_exec_from_a_manifest_stays_refused():
    """exec -f names no pod the parser can read; with a word after it kubectl
    errors (checked on kind)."""
    with pytest.raises(ValueError, match="target resource"):
        from_kubectl_multi(["kubectl", "exec", "-f", "pod.yaml", "--", "ls"])


_ALL = ["pod/*", "replicationcontroller/*", "service/*", "daemonset/*", "deployment/*",
        "replicaset/*", "statefulset/*", "horizontalpodautoscaler/*", "cronjob/*", "job/*"]
_API_EXTENSIONS = [
    "mutatingadmissionpolicy/*", "mutatingadmissionpolicybinding/*",
    "mutatingwebhookconfiguration/*", "validatingadmissionpolicy/*",
    "validatingadmissionpolicybinding/*", "validatingwebhookconfiguration/*",
    "customresourcedefinition/*", "apiservice/*"]


@pytest.mark.parametrize("command,action,extra", [
    ("kubectl delete all --all", "delete", {"all": True}),
    ("kubectl delete all -l app=web", "delete", {"selector": "app=web"}),
    ("kubectl delete all --field-selector=metadata.name=web", "delete",
     {"field_selector": "metadata.name=web"}),
    ("kubectl get all", "get", {}),
    ("kubectl describe all", "describe", {}),
    ("kubectl label all --all a=b", "label", {"all": True, "labels": {"a": "b"}}),
    ("kubectl annotate all --all a=b", "annotate", {"all": True, "annotations": {"a": "b"}}),
    ("kubectl scale all --all --replicas=0", "scale", {"all": True, "replicas": 0}),
    ("kubectl set image all *=x --all", "set-image", {"all": True, "images": {"*": "x"}}),
    ("kubectl rollout restart all", "rollout-restart", {}),
    ("kubectl wait all --all --for=condition=x", "wait", {"all": True, "for": ["condition=x"]}),
])
def test_the_category_all_is_one_intent_per_kind(command, action, extra):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == ["all/*", *_ALL]
    assert {i.action for i in intents} == {action}
    marked = {k: v for k, v in intents[0].params.items()
              if k not in ("resolved_at_runtime", "value_types")}
    assert marked == extra
    assert intents[0].params["resolved_at_runtime"] == {
        "from": "all", "kinds": [r.removesuffix("/*") for r in _ALL], "custom_kinds": True}
    for intent in intents[1:]:
        assert {k: v for k, v in intent.params.items() if k != "value_types"} == extra


@pytest.mark.parametrize("command,targets", [
    ("kubectl delete all,secrets --all", ["all/*", *_ALL, "secret/*"]),
    ("kubectl delete secrets,all --all", ["secret/*", "all/*", *_ALL]),
    ("kubectl delete all,all --all", ["all/*", *_ALL]),
    ("kubectl delete deploy,all --all",
     ["deployment/*", "all/*", *[r for r in _ALL if r != "deployment/*"]]),
    ("kubectl delete api-extensions --all", ["api-extensions/*", *_API_EXTENSIONS]),
    ("kubectl get all,api-extensions", ["all/*", *_ALL, "api-extensions/*", *_API_EXTENSIONS]),
])
def test_a_category_in_a_comma_list(command, targets):
    assert _kubectl_targets(command) == targets


@pytest.mark.parametrize("command,key,changed,removed", [
    ("kubectl label all --all app-", "labels", {}, ["app"]),
    ("kubectl label all --all app- a=b", "labels", {"a": "b"}, ["app"]),
    ("kubectl label all a=b app- -l x=y", "labels", {"a": "b"}, ["app"]),
    ("kubectl annotate all --all description-", "annotations", {}, ["description"]),
    # a value ending in - is a value
    ("kubectl label all --all a=b-", "labels", {"a": "b-"}, None),
])
def test_label_and_annotate_operands_are_not_names(command, key, changed, removed):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == ["all/*", *_ALL]
    for intent in intents:
        assert intent.params[key] == changed
        assert intent.params.get(f"{key}_removed") == removed


@pytest.mark.parametrize("command,targets", [
    ("kubectl label deploy web app-", ["deployment/web"]),
    ("kubectl label deployment/web app- a=b", ["deployment/web"]),
    ("kubectl label deploy --all app-", ["deployment/*"]),
    ("kubectl annotate deploy web a-", ["deployment/web"]),
    ("kubectl label deploy - a=b", ["deployment/-"]),
    ("kubectl set image all c=i d=j -l app=web", ["all/*", *_ALL]),
    ("kubectl set image deploy/web c=i", ["deployment/web"]),
    ("kubectl taint nodes --all a=b:NoSchedule", ["node/*"]),
    ("kubectl taint nodes --all a-", ["node/*"]),
    ("kubectl taint nodes --all a:NoSchedule-", ["node/*"]),
    ("kubectl taint node n1 a=b:NoSchedule", ["node/n1"]),
    ("kubectl taint node/n1 a=b:NoSchedule c-", ["node/n1"]),
    ("kubectl taint all --all a=b:NoSchedule", ["all/*", *_ALL]),
    ("kubectl scale all --replicas 0 --all", ["all/*", *_ALL]),
    ("kubectl scale --current-replicas=1 --replicas=0 all --all", ["all/*", *_ALL]),
    ("kubectl rollout undo all --to-revision 1", ["all/*", *_ALL]),
    ("kubectl rollout status all --timeout 2s", ["all/*", *_ALL]),
    ("kubectl rollout history all --revision 1", ["all/*", *_ALL]),
    ("kubectl autoscale all --max 2", ["all/*", *_ALL, "horizontalpodautoscaler/*"]),
    ("kubectl patch all -p {}", ["all/*", *_ALL]),
    ("kubectl patch all --patch {}", ["all/*", *_ALL]),
    ("kubectl delete all --all --grace-period 0", ["all/*", *_ALL]),
    ("kubectl delete all --all --timeout 5s", ["all/*", *_ALL]),
    ("kubectl wait all --all --for condition=x --timeout 1s", ["all/*", *_ALL]),
    ("kubectl get all --sort-by .metadata.name", ["all/*", *_ALL]),
    ("kubectl get all --chunk-size 10", ["all/*", *_ALL]),
    ("kubectl get all -L app", ["all/*", *_ALL]),
    ("kubectl get all -o wide", ["all/*", *_ALL]),
])
def test_operands_and_flag_values_are_not_object_names(command, targets):
    assert _kubectl_targets(command) == targets


def test_a_category_keeps_namespace_and_context():
    intents = from_kubectl_multi(
        ["kubectl", "-n", "prod", "delete", "all", "--all", "--context=kind-x"])
    assert all(i.metadata == {"namespace": "prod", "context": "kind-x"} for i in intents)


@pytest.mark.parametrize("command", [
    "kubectl get all web", "kubectl delete all web", "kubectl get all/web",
    "kubectl delete all/web", "kubectl label all/web a=b", "kubectl label all web a=b",
    "kubectl patch all web -p {}", "kubectl delete api-extensions x",
    "kubectl describe all web", "kubectl wait --for=condition=x all web",
    "kubectl expose all web", "kubectl autoscale all web --max=2", "kubectl edit all web",
    "kubectl patch all {}",
])
def test_a_category_with_a_name_is_refused_as_kubectl_refuses_it(command):
    with pytest.raises(ValueError, match="category"):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("spelled,kind", [
    ("rc", "replicationcontroller"), ("replicationcontrollers", "replicationcontroller"),
    ("cj", "cronjob"), ("apiservices", "apiservice"),
    ("validatingadmissionpolicies", "validatingadmissionpolicy"),
    ("validatingadmissionpolicybindings", "validatingadmissionpolicybinding"),
    ("mutatingadmissionpolicies", "mutatingadmissionpolicy"),
    ("mutatingadmissionpolicybindings", "mutatingadmissionpolicybinding"),
])
def test_kinds_a_category_names_are_normalised_when_spelled_directly(spelled, kind):
    assert _kubectl_targets(f"kubectl delete {spelled} x") == [f"{kind}/x"]


@pytest.mark.parametrize("command", [
    "kubectl delete " + "all," * 16000 + "all --all",
    "kubectl delete " + "all,api-extensions," * 3500 + "all --all",
    "kubectl exec deploy/web -- " + "x " * 30000,
])
def test_resolving_names_stays_linear(command):
    started = time.monotonic()
    from_kubectl_multi(command.split())
    assert time.monotonic() - started < 1


# --- a kind with no name: kubectl picks the objects when it runs (#66) -----------------------


def _open_marker(kind: str) -> dict:
    return {"from": f"{kind}/*", "kinds": [kind]}


@pytest.mark.parametrize("command,kind", [
    ("kubectl delete deployments --all", "deployment"),
    ("kubectl delete deploy -l a=b", "deployment"),
    ("kubectl delete deploy --selector=a=b", "deployment"),
    ("kubectl delete deploy --field-selector=metadata.name=x", "deployment"),
    ("kubectl delete pods --all -A", "pod"),
    ("kubectl delete namespaces --all", "namespace"),
    ("kubectl label pods --all a=b", "pod"),
    ("kubectl label pods -l x=y a-", "pod"),
    ("kubectl annotate pods --all a=b", "pod"),
    ("kubectl annotate pods --field-selector=status.phase=Failed a-", "pod"),
    ("kubectl scale deploy --all --replicas=0", "deployment"),
    ("kubectl scale deploy -l a=b --replicas=0", "deployment"),
    ("kubectl taint nodes --all a-", "node"),
    ("kubectl taint nodes -l zone=a a=b:NoSchedule", "node"),
    ("kubectl set image deploy --all c=i", "deployment"),
    ("kubectl set image deploy -l a=b c=i", "deployment"),
    ("kubectl rollout restart deploy", "deployment"),
    ("kubectl rollout restart deploy -l a=b", "deployment"),
    ("kubectl rollout undo deploy", "deployment"),
    ("kubectl rollout pause deploy", "deployment"),
    ("kubectl rollout resume deploy -l a=b", "deployment"),
    ("kubectl rollout status deploy", "deployment"),
    ("kubectl rollout history deploy", "deployment"),
    ("kubectl wait pods --all --for=condition=ready", "pod"),
    ("kubectl wait pods -l a=b --for=condition=ready", "pod"),
    ("kubectl get pods", "pod"),
    ("kubectl get pods -A", "pod"),
    ("kubectl get pods -l a=b", "pod"),
    ("kubectl get pods --field-selector=status.phase=Failed", "pod"),
    ("kubectl describe pods", "pod"),
    ("kubectl describe pods -l a=b", "pod"),
    ("kubectl edit deploy", "deployment"),
    ("kubectl top pod -l a=b", "pod"),
    # kubectl errors on these; asking is harmless
    ("kubectl delete deployments", "deployment"),
    ("kubectl label deploy a=b", "deployment"),
    ("kubectl patch deploy -p {}", "deployment"),
])
def test_a_kind_with_no_name_is_marked_and_stays_one_intent(command, kind):
    """One intent, so a plan's batch counts do not grow."""
    intent = from_kubectl(command.split())
    assert intent.resource == f"{kind}/*"
    assert intent.params["resolved_at_runtime"] == _open_marker(kind)


def test_every_kind_in_a_comma_list_is_marked():
    intents = from_kubectl_multi("kubectl delete deploy,svc,secrets --all -n prod".split())
    assert [i.resource for i in intents] == ["deployment/*", "service/*", "secret/*"]
    for intent in intents:
        assert intent.params["resolved_at_runtime"] == _open_marker(
            intent.resource.removesuffix("/*"))
        assert intent.metadata == {"namespace": "prod"}


def test_a_category_keeps_its_own_mark_and_its_kinds_need_none():
    intents = from_kubectl_multi("kubectl delete all,secrets -l a=b".split())
    by_resource = {i.resource: i for i in intents}
    assert by_resource["all/*"].params["resolved_at_runtime"]["custom_kinds"] is True
    assert "resolved_at_runtime" not in by_resource["deployment/*"].params
    assert by_resource["secret/*"].params["resolved_at_runtime"] == _open_marker("secret")


@pytest.mark.parametrize("command,resource", [
    ("kubectl delete deploy web", "deployment/web"),
    ("kubectl delete deploy/web", "deployment/web"),
    ("kubectl get pod web", "pod/web"),
    # kubectl refuses this (checked on kind): the name is all there is to decide on
    ("kubectl delete deploy/web --all", "deployment/web"),
    # --all with a name acts on the name only (checked on kind)
    ("kubectl label deploy/web a=b --all", "deployment/web"),
    ("kubectl scale deploy/web --replicas=1 --all", "deployment/web"),
    ("kubectl annotate deploy/web a=b --all", "deployment/web"),
    ("kubectl cordon n1", "node/n1"),
    ("kubectl drain n1 --pod-selector=a=b", "node/n1"),
])
def test_a_named_object_is_not_marked(command, resource):
    intent = from_kubectl(command.split())
    assert intent.resource == resource
    assert "resolved_at_runtime" not in intent.params


@pytest.mark.parametrize("command", [
    "kubectl taint node decoy --all a-",
    "kubectl taint node decoy -l zone=a a=b:NoSchedule",
])
def test_taint_ignores_a_name_given_with_all_or_a_selector(command):
    decoy, every = from_kubectl_multi(command.split())
    assert decoy.resource == "node/decoy" and "resolved_at_runtime" not in decoy.params
    assert every.resource == "node/*"
    assert every.params["resolved_at_runtime"] == _open_marker("node")


def test_taint_with_a_name_alone_stays_that_name():
    for command in ("kubectl taint node n1 a-", "kubectl taint node n1 a- --all=false"):
        assert [i.resource for i in from_kubectl_multi(command.split())] == ["node/n1"]


@pytest.mark.parametrize("command", ["kubectl exec -l app=web -- ls", "kubectl attach -l a=b"])
def test_a_selector_on_a_verb_that_names_its_target_stays_refused(command):
    # exec and attach have no --selector (no -l): kubectl refuses them too
    with pytest.raises(ValueError):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("command,resource,params,metadata", [
    # checked on kubectl 1.36 against a local stub server: the pods or nodes it listed
    ("kubectl logs -l app=web", "pod/*", {"selector": "app=web"}, {}),
    ("kubectl logs -fl app=web -n dev", "pod/*", {"selector": "app=web", "follow": True},
     {"namespace": "dev"}),
    ("kubectl logs -lapp=web -c app --namespace=prod", "pod/*",
     {"selector": "app=web", "container": "app"}, {"namespace": "prod"}),
    ("kubectl logs --selector app=web --all-containers", "pod/*",
     {"selector": "app=web", "all-containers": True}, {}),
    ("kubectl cordon -l zone=a", "node/*", {"selector": "zone=a"}, {}),
    ("kubectl uncordon -l zone=a", "node/*", {"selector": "zone=a"}, {}),
    ("kubectl drain -l zone=a --ignore-daemonsets", "node/*",
     {"selector": "zone=a", "ignore-daemonsets": True}, {}),
])
def test_a_selector_is_the_target_where_kubectl_takes_one(command, resource, params, metadata):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == [resource]
    kind = resource.partition("/")[0]
    assert intents[0].params == {**params, "resolved_at_runtime": _open_marker(kind)}
    assert intents[0].metadata == metadata


@pytest.mark.parametrize("command", ["kubectl run web --image=x", "kubectl debug web --image=x"])
def test_a_word_that_names_a_new_or_given_pod_is_not_marked(command):
    assert all("resolved_at_runtime" not in i.params
               for i in from_kubectl_multi(command.split()))


# --- kubectl run: the word names a pod (#71) ----------------------------------------


@pytest.mark.parametrize("command,targets", [
    ("kubectl run web --image=x", ["pod/web", "web/*"]),
    ("kubectl run --image=x web", ["pod/web", "web/*"]),
    ("kubectl run --image x web", ["pod/web", "web/*"]),
    ("kubectl run -it --rm web --image=x", ["pod/web", "web/*"]),
    ("kubectl run --restart=Never --env A=b --port 80 web --image=x", ["pod/web", "web/*"]),
    # no category, whichever one the word spells
    ("kubectl run all --image=x", ["pod/all", "all/*"]),
    ("kubectl run api-extensions --image=x", ["pod/api-extensions", "api-extensions/*"]),
    # the word as written, with what earlier versions made of it beside it
    ("kubectl run 001 --image=x", ["pod/001", "001/*"]),
    ("kubectl run 1e5 --image=x", ["pod/1e5", "1e5/*"]),
    ("kubectl run Web --image=x", ["pod/Web", "web/*"]),
    ("kubectl run pods --image=x", ["pod/pods", "pod/*"]),
    ("kubectl run deploy --image=x", ["pod/deploy", "deployment/*"]),
    # more words are arguments for the pod (checked on kind)
    ("kubectl run web a b --image=x", ["pod/web", "web/a", "web/b"]),
    ("kubectl run pods web --image=x", ["pod/pods", "pod/web"]),
    # a pod name can't have a slash: the API refuses it (checked on kind)
    ("kubectl run pod/web --image=x", ["pod/web"]),
    ("kubectl run deploy/web --image=x", ["deployment/web"]),
    ("kubectl run all/web --image=x", ["all/web"]),
])
def test_run_names_a_pod(command, targets):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == targets
    assert {i.action for i in intents} == {"run"}


@pytest.mark.parametrize("command", [
    "kubectl run web --image=x -n prod",
    "kubectl -n prod run web --image=x",
    "kubectl run -n prod --image=x web",
    "kubectl run -nprod web --image=x",
    "kubectl run --namespace=prod web --image=x",
])
def test_run_keeps_the_namespace_on_every_intent(command):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == ["pod/web", "web/*"]
    assert [i.metadata["namespace"] for i in intents] == ["prod", "prod"]


def test_run_keeps_its_params_on_every_intent():
    command = "kubectl run 001 --image=001 --dry-run=client -- sleep 1"
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == ["pod/001", "001/*"]
    for intent in intents:
        assert intent.params == {"image": "001", "dry_run": True, "command": ["sleep", "1"]}


@pytest.mark.parametrize("command", [
    "kubectl run --image=x",
    "kubectl run --image=x -- web",
    "kubectl run a,b c --image=x",
])
def test_run_stays_refused(command):
    with pytest.raises(ValueError):
        from_kubectl_multi(command.split())


def test_from_kubectl_raises_on_run_with_two_intents():
    with pytest.raises(ValueError, match="found 2"):
        from_kubectl("kubectl run web --image=x".split())


# --- kubectl run --expose: a Service as well (#73) -----------------------------------


_WITH_SERVICE = ["pod/web", "service/web", "web/*"]
_NO_SERVICE = ["pod/web", "web/*"]


@pytest.mark.parametrize("command,targets", [
    ("kubectl run web --image=x --expose --port=80", _WITH_SERVICE),
    ("kubectl run --expose web --image=x --port=80", _WITH_SERVICE),
    # kubectl refuses --expose with no --port, and the hook still sees what it asks for
    ("kubectl run web --image=x --expose", _WITH_SERVICE),
    # every spelling Go's strconv.ParseBool reads as true
    *((f"kubectl run web --image=x --expose={w} --port=80", _WITH_SERVICE)
      for w in ("true", "True", "TRUE", "t", "T", "1")),
    # and as false
    *((f"kubectl run web --image=x --expose={w} --port=80", _NO_SERVICE)
      for w in ("false", "False", "FALSE", "f", "F", "0")),
    # kubectl refuses these, so nothing is created, and none of them reads as off
    *((f"kubectl run web --image=x --expose={w} --port=80", _WITH_SERVICE)
      for w in ("no", "off", "n", "fAlSe", "0.0", "", "maybe", "2")),
    # the last one wins, as in pflag
    ("kubectl run web --image=x --expose --expose=false --port=80", _NO_SERVICE),
    ("kubectl run web --image=x --expose=false --expose --port=80", _WITH_SERVICE),
    # a bare boolean takes no value: the next word stays a word
    ("kubectl run --expose false --image=x --port=80",
     ["pod/false", "service/false", "false/*"]),
    ("kubectl run web --expose false --image=x --port=80",
     ["pod/web", "service/web", "web/false"]),
    # the name as written, with no kind read from it
    ("kubectl run all --image=x --expose --port=80", ["pod/all", "service/all", "all/*"]),
    ("kubectl run 001 --image=x --expose --port=80", ["pod/001", "service/001", "001/*"]),
    ("kubectl run svc --image=x --expose --port=80", ["pod/svc", "service/svc", "service/*"]),
    ("kubectl run service --image=x --expose --port=80",
     ["pod/service", "service/service", "service/*"]),
    # only the first word names anything
    ("kubectl run web a --image=x --expose --port=80", ["pod/web", "service/web", "web/a"]),
    # --rm deletes what it created, under the same action
    ("kubectl run web -i --rm --image=x --expose --port=80", _WITH_SERVICE),
    # after "--" it is an argument for the pod
    ("kubectl run web --image=x -- --expose", _NO_SERVICE),
    # the API refuses the pod, and kubectl stops before the Service
    ("kubectl run pod/web --image=x --expose --port=80", ["pod/web"]),
    ("kubectl run deploy/web --image=x --expose --port=80", ["deployment/web"]),
])
def test_run_expose_targets(command, targets):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == targets
    assert {i.action for i in intents} == {"run"}


@pytest.mark.parametrize("command", [
    "kubectl run web --image=x --expose --port=80 -n prod",
    "kubectl -n prod run web --image=x --expose --port=80",
    "kubectl run -nprod --expose web --image=x --port=80",
])
def test_run_expose_keeps_the_namespace_on_every_intent(command):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == _WITH_SERVICE
    assert [i.metadata["namespace"] for i in intents] == ["prod"] * 3


def test_run_expose_keeps_its_params_on_every_intent():
    command = "kubectl run web --image=x --expose --port=80 --dry-run=client -- sleep 1"
    for intent in from_kubectl_multi(command.split()):
        assert intent.params == {"image": "x", "expose": True, "port": "80", "dry_run": True,
                                 "command": ["sleep", "1"]}
        assert "resolved_at_runtime" not in intent.params


def test_from_kubectl_raises_on_run_expose():
    with pytest.raises(ValueError, match="found 3"):
        from_kubectl("kubectl run web --image=x --expose --port=80".split())


def test_marking_kinds_stays_linear():
    command = "kubectl delete " + ",".join(f"k{i}" for i in range(11000)) + " --all"
    assert len(command) > 64 * 1024
    started = time.monotonic()
    assert len(from_kubectl_multi(command.split())) == 11000
    assert time.monotonic() - started < 1


# --- kubectl: the object a command reaches, whatever word names it (#68) -----------


@pytest.mark.parametrize("command,targets,behind_from", [
    ("kubectl logs deploy/web", ["deployment/web", "pod/*"], "deployment/web"),
    ("kubectl logs deployment.apps/web", ["deployment/web", "pod/*"], "deployment/web"),
    ("kubectl logs svc/web -f -n prod", ["service/web", "pod/*"], "service/web"),
    ("kubectl logs job/web --all-pods", ["job/web", "pod/*"], "job/web"),
    ("kubectl logs -c app sts/web", ["statefulset/web", "pod/*"], "statefulset/web"),
    # a second word is the container, not a name (kubectl's logs.go)
    ("kubectl logs deploy/web app", ["deployment/web", "pod/*"], "deployment/web"),
    ("kubectl logs web", ["pod/web"], None),
    ("kubectl logs pod/web", ["pod/web"], None),
    ("kubectl logs pod web", ["pod/pod"], None),
])
def test_logs_reads_a_pod_behind_the_name(command, targets, behind_from):
    intents = from_kubectl_multi(command.split())
    assert [(i.action, i.resource) for i in intents] == [("logs", t) for t in targets]
    assert "resolved_at_runtime" not in intents[0].params
    if behind_from:
        assert intents[1].params["resolved_at_runtime"] == {"from": behind_from, "kinds": ["pod"]}


@pytest.mark.parametrize("command,targets", [
    # the target earlier versions gave stays last
    ("kubectl debug web --image=busybox", ["pod/web", "web/*"]),
    ("kubectl debug --image=busybox -c dbg web -it", ["pod/web", "web/*"]),
    ("kubectl debug -n prod web --image=busybox -- sh", ["pod/web", "web/*"]),
    ("kubectl debug pod/web --image=busybox", ["pod/web"]),
    ("kubectl debug po/web --image=busybox", ["pod/web"]),
    ("kubectl debug a b --image=busybox", ["pod/a", "pod/b", "a/b"]),
    # kubectl reads each word alone, so these name pods
    ("kubectl debug pods web --image=busybox", ["pod/pods", "pod/web"]),
    ("kubectl debug node/n1 --image=busybox", ["node/n1"]),
    ("kubectl debug no/n1 --image=busybox", ["node/n1"]),
    # kubectl refuses this kind, and reaches no pod
    ("kubectl debug deploy/web --image=busybox", ["deployment/web"]),
    ("kubectl debug web --copy-to=c --image=busybox", ["pod/web", "pod/c", "web/*"]),
    ("kubectl debug web --copy-to c --set-image=*=x", ["pod/web", "pod/c", "web/*"]),
    ("kubectl debug web --copy-to=c --replace --image=x", ["pod/web", "pod/c", "web/*"]),
    ("kubectl debug node/n1 --copy-to=c --image=x", ["node/n1"]),
    # a name stays as it is written, and so does the flag's value
    ("kubectl debug web --copy-to=001 --image=x", ["pod/web", "pod/001", "web/*"]),
    ("kubectl debug web --copy-to 1e5 --image=x", ["pod/web", "pod/1e5", "web/*"]),
    ("kubectl debug web --copy-to=0 --image=x", ["pod/web", "pod/0", "web/*"]),
    ("kubectl debug 001 --image=x", ["pod/001", "001/*"]),
])
def test_debug_names_pods(command, targets):
    intents = from_kubectl_multi(command.split())
    assert [(i.action, i.resource) for i in intents] == [("debug", t) for t in targets]
    assert all("resolved_at_runtime" not in i.params for i in intents)


def test_debug_copy_to_is_raw_in_the_target_and_as_before_in_params():
    intents = from_kubectl_multi("kubectl debug web --copy-to=001 --image=x".split())
    assert "pod/001" in [i.resource for i in intents]
    assert all(i.params["copy-to"] == "001" for i in intents)  # a String flag: its text


def test_the_last_copy_to_wins_as_in_params():
    intents = from_kubectl_multi("kubectl debug web --copy-to=a --copy-to=b --image=x".split())
    assert [i.resource for i in intents] == ["pod/web", "pod/b", "web/*"]


def test_debug_with_a_comma_list_and_a_name_stays_refused():
    with pytest.raises(ValueError, match="comma-separated"):
        from_kubectl_multi("kubectl debug a,b c --image=x".split())


def test_debug_keeps_the_words_after_dash_as_its_command():
    intents = from_kubectl_multi("kubectl debug web --image=x -- sh -c id".split())
    assert [i.resource for i in intents] == ["pod/web", "web/*"]
    assert intents[0].params["command"] == ["sh", "-c", "id"]


@pytest.mark.parametrize("command,pods,first,namespace", [
    ("kubectl cp web:/a b", ["pod/web"], "web:/a", None),
    ("kubectl cp b web:/a", ["pod/web"], "b", None),
    ("kubectl cp web:a b", ["pod/web"], "web:a", None),
    ("kubectl cp prod/web:/a b", ["pod/web"], "prod/web:/a", "prod"),
    ("kubectl cp b prod/web:/a", ["pod/web"], "b", "prod"),
    ("kubectl cp b web:/a -n prod", ["pod/web"], "b", "prod"),
    ("kubectl -n prod cp b web:/a -c app", ["pod/web"], "b", "prod"),
    ("kubectl cp -c app --retries 3 b -nprod web:/a", ["pod/web"], "b", "prod"),
    ("kubectl cp --no-preserve b web:/a", ["pod/web"], "b", None),
    # the namespace written with the pod wins over -n (kubectl's cp.go)
    ("kubectl cp -n dev b prod/web:/a", ["pod/web"], "b", "prod"),
    # only the first colon counts, and the path may have more
    ("kubectl cp web:/a:b:c d", ["pod/web"], "web:/a:b:c", None),
    # what comes before the colon is [ns/]pod, even when it looks like a path
    ("kubectl cp ./web:/a b", ["pod/web"], "./web:/a", "."),
    ("kubectl cp b ../web:/a", ["pod/web"], "b", ".."),
    ("kubectl cp b ~/web:/a", ["pod/web"], "b", "~"),
    # an empty namespace is the one kubectl would use
    ("kubectl cp /web:a b", ["pod/web"], "/web:a", None),
    ("kubectl cp -n dev /web:a b", ["pod/web"], "/web:a", "dev"),
    # "--" ends the flags, and the word after it is still an operand
    ("kubectl cp b -- web:/a", ["pod/web"], "b", None),
    # a pod name is text
    ("kubectl cp b 001:/a", ["pod/001"], "b", None),
    # kubectl refuses these (checked with kubectl 1.36), and only the first word is left
    ("kubectl cp a b", [], "a", None),
    ("kubectl cp /tmp/x:y b", [], "/tmp/x:y", None),
    ("kubectl cp a/b/c:d e", [], "a/b/c:d", None),
    ("kubectl cp :a b", [], ":a", None),
    ("kubectl cp ns/:a b", [], "ns/:a", None),
    ("kubectl cp /:a b", [], "/:a", None),
    # as is this, with both pods kept
    ("kubectl cp a:b c:d", ["pod/a", "pod/c"], "a:b", None),
    ("kubectl cp /tmp/x:y web:/a", ["pod/web"], "/tmp/x:y", None),
])
def test_cp_finds_the_pod_as_kubectl_does(command, pods, first, namespace):
    intents = from_kubectl_multi(command.split())
    assert [(i.action, i.resource) for i in intents] == [("cp", t) for t in [*pods, first]]
    assert all(i.metadata.get("namespace") == namespace for i in intents[:-1])
    assert all("resolved_at_runtime" not in i.params for i in intents)


def test_cp_keeps_the_first_word_with_the_namespace_as_it_was():
    written = from_kubectl_multi("kubectl cp -n dev prod/web:/a b".split())[-1]
    assert (written.resource, written.metadata["namespace"]) == ("prod/web:/a", "dev")


def test_cp_with_nothing_to_copy_stays_refused():
    for command in ("kubectl cp", "kubectl cp -- a web:/b"):
        with pytest.raises(ValueError, match="target resource"):
            from_kubectl_multi(command.split())


@pytest.mark.parametrize("command,resource,marker", [
    ("kubectl describe pod pay", "pod/pay",
     {"from": "pod/pay", "kinds": ["pod"], "name_prefix": "pay"}),
    ("kubectl describe pods pay -n prod", "pod/pay",
     {"from": "pod/pay", "kinds": ["pod"], "name_prefix": "pay"}),
    ("kubectl describe widgets pay", "widgets/pay",
     {"from": "widgets/pay", "kinds": ["widgets"], "name_prefix": "pay", "custom_kinds": True}),
])
def test_describe_type_name_is_a_prefix(command, resource, marker):
    intent = from_kubectl(command.split())
    assert intent.resource == resource
    assert intent.params["resolved_at_runtime"] == marker


@pytest.mark.parametrize("command", [
    "kubectl describe pod/pay",
    "kubectl describe pods/pay",
    "kubectl get pod pay",
    "kubectl delete pod pay",
])
def test_only_describe_type_name_is_a_prefix(command):
    assert "resolved_at_runtime" not in from_kubectl(command.split()).params


@pytest.mark.parametrize("command,targets", [
    ("kubectl describe pod api -- payments-0", ["pod/api", "pod/payments-0"]),
    ("kubectl delete widgets foo -- bar", ["widgets/foo", "widgets/bar"]),
    ("kubectl delete pod -- x", ["pod/x"]),
    ("kubectl get pods a -- b", ["pod/a", "pod/b"]),
    ("kubectl edit deploy a -- b", ["deployment/a", "deployment/b"]),
    ("kubectl patch deploy a -- b", ["deployment/a", "deployment/b"]),
    ("kubectl scale deploy a -- b", ["deployment/a", "deployment/b"]),
    ("kubectl label pod a -- b x=y", ["pod/a", "pod/b"]),
    ("kubectl annotate pod a -- b x=y", ["pod/a", "pod/b"]),
    ("kubectl wait pod a -- b", ["pod/a", "pod/b"]),
    ("kubectl rollout restart deploy a -- b", ["deployment/a", "deployment/b"]),
    ("kubectl set image deploy a -- b x=y", ["deployment/a", "deployment/b"]),
    ("kubectl taint node a -- b x=y:NoSchedule", ["node/a", "node/b"]),
    ("kubectl expose deploy a -- b", ["deployment/a", "deployment/b", "service/a",
                                      "service/b"]),
    ("kubectl autoscale deploy a -- b", ["deployment/a", "deployment/b",
                                         "horizontalpodautoscaler/a",
                                         "horizontalpodautoscaler/b"]),
    ("kubectl cordon a -- b", ["node/a", "node/b"]),
    ("kubectl uncordon a -- b", ["node/a", "node/b"]),
    ("kubectl drain a -- b", ["node/a", "node/b"]),
])
def test_words_after_dash_are_operands(command, targets):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == targets
    assert all("command" not in i.params for i in intents)


@pytest.mark.parametrize("command,prefix", [
    ("kubectl describe pod -- pay", "pay"),
    ("kubectl describe pod pay -- other", None),
])
def test_a_prefix_counts_the_words_after_dash(command, prefix):
    marks = [i.params.get("resolved_at_runtime") for i in from_kubectl_multi(command.split())]
    assert [m and m["name_prefix"] for m in marks] == (
        [prefix] if prefix else [None, None])


@pytest.mark.parametrize("command,targets,kept", [
    # "--" starts a command here (ArgsLenAtDash in kubectl's source)
    ("kubectl exec web -- ls -la", ["pod/web"], ["ls", "-la"]),
    ("kubectl exec deploy/web -- ls", ["deployment/web", "pod/*"], ["ls"]),
    ("kubectl run web --image=x -- sleep 1", ["pod/web", "web/*"], ["sleep", "1"]),
    ("kubectl create deployment web --image=x -- sleep 1", ["deployment/web"], ["sleep", "1"]),
    ("kubectl create job j --image=x -- sleep 1", ["job/j"], ["sleep", "1"]),
    ("kubectl debug node/n1 --image=x -- sh", ["node/n1"], ["sh"]),
    # these take their target from the first word
    ("kubectl logs web -- app", ["pod/web"], ["app"]),
    ("kubectl port-forward web -- 80", ["pod/web"], ["80"]),
    ("kubectl top pod a -- b", ["pod/a"], ["b"]),
    # kubectl refuses three words on attach
    ("kubectl attach a b -- c", ["a/b"], ["c"]),
])
def test_the_verbs_whose_words_after_dash_stay_as_they_were(command, targets, kept):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents][:len(targets)] == targets
    assert intents[0].params["command"] == kept


@pytest.mark.parametrize("command,targets", [
    ("kubectl attach deploy -- web", ["deployment/web", "pod/*", "pod/deploy"]),
    ("kubectl attach pod -- web", ["pod/web", "pod/pod"]),
    ("kubectl attach web -- x", ["web/x", "pod/*", "pod/web"]),
])
def test_attach_reads_a_word_after_dash_as_its_name(command, targets):
    assert [i.resource for i in from_kubectl_multi(command.split())] == targets


@pytest.mark.parametrize("command", [
    "kubectl describe -- pod pay", "kubectl delete -- pod x", "kubectl get --", "kubectl cp -- a b",
])
def test_nothing_before_dash_stays_refused(command):
    with pytest.raises(ValueError):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("command", [
    "kubectl delete pods,svc -- x", "kubectl delete all -- x",
])
def test_a_kind_list_with_a_name_after_dash_is_refused(command):
    with pytest.raises(ValueError):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("command,marker_name,key", [
    ("kubectl describe pod 001", "001", "name_prefix"),
    ("kubectl delete widgets 001", "001", "name"),
])
def test_a_name_in_a_mark_is_text(command, marker_name, key):
    assert from_kubectl(command.split()).params["resolved_at_runtime"][key] == marker_name


def test_describe_with_two_names_takes_them_exactly():
    # kubectl only falls back to a prefix with exactly two words (describe.go)
    intents = from_kubectl_multi("kubectl describe pod a b".split())
    assert [i.resource for i in intents] == ["pod/a", "pod/b"]
    assert all("resolved_at_runtime" not in i.params for i in intents)


@pytest.mark.parametrize("command,resource,marker", [
    ("kubectl delete widgets --all", "widgets/*",
     {"from": "widgets/*", "kinds": ["widgets"], "custom_kinds": True}),
    ("kubectl get wd", "wd/*", {"from": "wd/*", "kinds": ["wd"], "custom_kinds": True}),
    ("kubectl delete widgets.x.io -l a=b", "widgets/*",
     {"from": "widgets/*", "kinds": ["widgets"], "custom_kinds": True}),
    ("kubectl label widgets --all a=b", "widgets/*",
     {"from": "widgets/*", "kinds": ["widgets"], "custom_kinds": True}),
    ("kubectl delete widgets foo", "widgets/foo",
     {"from": "widgets/foo", "kinds": ["widgets"], "name": "foo", "custom_kinds": True}),
    ("kubectl scale wd/foo --replicas=1", "wd/foo",
     {"from": "wd/foo", "kinds": ["wd"], "name": "foo", "custom_kinds": True}),
])
def test_a_kind_outside_the_table_may_be_any_custom_kind(command, resource, marker):
    intent = from_kubectl(command.split())
    assert intent.resource == resource
    assert intent.params["resolved_at_runtime"] == marker


@pytest.mark.parametrize("command,marker", [
    ("kubectl delete pods --all", {"from": "pod/*", "kinds": ["pod"]}),
    ("kubectl get deploy", {"from": "deployment/*", "kinds": ["deployment"]}),
    ("kubectl delete pod web", None),
    # this reaches the parser as kind/name but is not about a kind
    ("kubectl config view", {"from": "view/*", "kinds": ["view"]}),
    ("kubectl rollout restart widgets/foo", None),
    ("kubectl taint widgets foo a=b:NoSchedule", None),
])
def test_the_kinds_that_stay_as_they_were(command, marker):
    assert from_kubectl(command.split()).params.get("resolved_at_runtime") == marker


# A repeated dry-run flag: the last one decides (#75). aws and git were run, with a stub
# endpoint and a local remote. helm, argocd, flux and az are not installed here, so these
# come from their source: helm pkg/cmd/helpers.go, argocd app.go (app sync), flux create.go
# and azure-cli resource/_params.py. Flux has no --dry-run on any command the parser takes,
# and no gcloud command it takes was found with the flag, so neither has a case here.
@pytest.mark.parametrize("argv,rehearsal", [
    ("helm upgrade api ./c --dry-run=client --dry-run=none", False),
    ("helm upgrade api ./c --dry-run=none --dry-run=client", True),
    ("argocd app sync web --dry-run --dry-run=false", False),
    ("argocd app sync web --dry-run=false --dry-run", True),
    ("flux create source git a --url=https://x --branch=main --export --export=false", False),
    ("flux create source git a --url=https://x --branch=main --export=false --export", True),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-dry-run", False),
    ("aws ec2 terminate-instances --instance-ids i-1 --no-dry-run --dry-run", True),
    ("az deployment group create -g r --template-file t.json --what-if", True),
    ("git push origin main --dry-run --no-dry-run", False),
    ("git push origin main -n --no-dry-run", False),
    ("git push origin main --no-dry-run --dry-run", True),
    ("git push --no-dry-run origin main", False),
])
def test_the_last_dry_run_decides_in_the_other_tools(argv, rehearsal):
    intent = from_argv(argv.split())[0]
    assert intent.params.get("dry_run", False) is rehearsal


# Bundled short flags on helm and flux (#75). Neither is installed here, so the letters come
# from their source: helm v4.3.1 and v3.22.1, flux2 main.
@pytest.mark.parametrize("argv,resource,params,metadata", [
    # common spellings
    ("helm upgrade -i api ./c", "release/api", {"install": True, "chart": "./c"}, {}),
    ("helm upgrade api ./c -i", "release/api", {"install": True, "chart": "./c"}, {}),
    ("helm upgrade api ./c -i=false", "release/api", {"install": False, "chart": "./c"}, {}),
    ("helm upgrade -if v.yaml api ./c", "release/api",
     {"install": True, "values_files": ["v.yaml"], "chart": "./c"}, {}),
    ("helm upgrade api ./c -f v.yaml", "release/api",
     {"values_files": ["v.yaml"], "chart": "./c"}, {}),
    ("helm upgrade api ./c -fv.yaml", "release/api",
     {"values_files": ["v.yaml"], "chart": "./c"}, {}),
    ("helm upgrade api ./c -nprod", "release/api", {"chart": "./c"}, {"namespace": "prod"}),
    ("helm upgrade api ./c -n=prod", "release/api", {"chart": "./c"}, {"namespace": "prod"}),
    ("helm -nprod upgrade api ./c", "release/api", {"chart": "./c"}, {"namespace": "prod"}),
    ("helm status api -oyaml", "release/api", {"output": "yaml"}, {}),
    ("helm status -oyaml api", "release/api", {"output": "yaml"}, {}),
    ("helm status -o yaml api", "release/api", {"output": "yaml"}, {}),
    ("helm list -A", "release/*", {}, {"all_namespaces": True}),
    ("helm list -aq", "release/*", {"all": True, "short": True}, {}),
    ("helm list -l a=b", "release/*", {"selector": "a=b"}, {}),
    # a namespace in a word
    ("helm upgrade api ./c -n dev -inprod", "release/api",
     {"install": True, "chart": "./c"}, {"namespace": "prod"}),
    ("helm upgrade api ./c -n dev -qnprod", "release/api",
     {"short": True, "chart": "./c"}, {"namespace": "prod"}),
    # a flag's value is not split
    ("helm upgrade api ./c -n dev --kube-context -nprod", "release/api", {"chart": "./c"},
     {"namespace": "dev", "context": "-nprod"}),
    ("helm upgrade api ./c -n dev --description -nprod", "release/api",
     {"description": "-nprod", "chart": "./c"},
     {"namespace": "dev"}),
    # flux
    ("flux get ks -A", "kustomization/*", {}, {"all_namespaces": True}),
    ("flux get ks -A a", "kustomization/a", {}, {"all_namespaces": True}),
    ("flux get ks a -w", "kustomization/a", {"watch": True}, {}),
    ("flux get ks -Aw", "kustomization/*", {"watch": True}, {"all_namespaces": True}),
    ("flux get ks -l a=b", "kustomization/*", {"label_selector": "a=b"}, {}),
    ("flux get ks -nprod", "kustomization/*", {}, {"namespace": "prod"}),
    ("flux -nprod get ks", "kustomization/*", {}, {"namespace": "prod"}),
    ("flux get ks -n dev -wnprod", "kustomization/*", {"watch": True},
     {"namespace": "prod"}),
    ("flux delete ks -s a", "kustomization/a", {"silent": True}, {}),
    ("flux delete ks a -n dev -snprod", "kustomization/a", {"silent": True},
     {"namespace": "prod"}),
    ("flux create source git a -u -nprod -n dev", "source-git/a", {"username": "-nprod"},
     {"namespace": "dev"}),
])
def test_helm_and_flux_short_words(argv, resource, params, metadata):
    intent = from_argv(argv.split())[0]
    assert intent.resource == resource
    assert {k: v for k, v in intent.params.items()
            if k not in ("raw_action", "unresolved_scope", "resolved_at_runtime")} == params
    assert intent.metadata == metadata
    # a list of every object is marked: which objects, only the tool knows
    assert ("resolved_at_runtime" in intent.params) == resource.endswith("/*")


def test_flux_logs_f_is_follow():
    intent = from_argv("flux logs -fnprod".split())[0]
    assert intent.params["follow"] is True
    assert intent.metadata == {"namespace": "prod"}


def test_helm_a_takes_a_value_on_template_only():
    assert from_argv("helm template api ./c -av1".split())[0].params["api_versions"] == ["v1"]
    assert from_argv("helm get values api -a".split())[0].params["all"] is True


@pytest.mark.parametrize("argv", [
    "helm upgrade api ./c -xnprod",
    "helm upgrade api ./c -xA",
    "helm -inprod upgrade api ./c",
    "helm upgrade api ./c -in",
    "flux reconcile ks a -n dev -qnprod",  # flux has no -q
    "flux get ks -xnprod",
    "flux get ks -fnprod",  # -f is only on logs
    "flux -Anprod get ks",
])
def test_refused_helm_and_flux_short_words(argv):
    with pytest.raises(ValueError):
        from_argv(argv.split())


@pytest.mark.parametrize("command", [
    # a name and a selector: kubectl refuses them (kubectl 1.36: "selectors and the all
    # flag cannot be used when passing resource/name arguments"), and so does the parser
    "kubectl delete deploy web -l a=b",
    "kubectl get deploy/web -l a=b",
    "kubectl rollout restart deploy/web -l a=b",
])
def test_a_name_with_a_selector_is_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,source,created", [
    # expose and autoscale also create an object: the source's own intent stays as it was
    ("kubectl autoscale deploy --max=2", "deployment/*", "horizontalpodautoscaler/*"),
    ("kubectl expose deploy --port=80", "deployment/*", "service/*"),
    ("kubectl expose deploy web --port=80 --selector=x=y", "deployment/web", "service/web"),
    ("kubectl autoscale widgets foo --max=3", "widgets/foo", "horizontalpodautoscaler/foo"),
])
def test_expose_and_autoscale_keep_the_source_and_add_the_new_object(command, source, created):
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == [source, created]
    assert ("resolved_at_runtime" in intents[0].params) is source.endswith("/*") or \
        source == "widgets/foo"
