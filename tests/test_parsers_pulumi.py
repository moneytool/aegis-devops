from datetime import UTC, datetime

import pytest

from aegis_core.interceptor import AegisInterceptor
from aegis_core.parsers.pulumi import from_pulumi_argv, from_pulumi_preview
from aegis_core.store import ConstraintStore

EXAMPLE_STORE = "data/constraints.example.yaml"
NOW = datetime(2026, 4, 2, 12, 0, 0, tzinfo=UTC)


def _authority_map():
    return {
        "admin": {"scaling", "deletion", "configuration"},
        "sre_lead": {"scaling", "configuration"},
        "developer": {"configuration"},
    }


def _step(op, urn, **kwargs):
    step = {"op": op, "urn": urn}
    step.update(kwargs)
    return step


AWS_EC2_URN = "urn:pulumi:prod::myproj::aws:ec2/instance:Instance::web"
AWS_RDS_URN = "urn:pulumi:prod::myproj::aws:rds/instance:Instance::db1"


# --- op -> action mapping -------------------------------------------------------


@pytest.mark.parametrize(
    "op,expected_action",
    [
        ("create", "create"),
        ("update", "update"),
        ("replace", "replace"),
        ("create-replacement", "replace"),
        ("delete-replaced", "replace"),
        ("delete", "delete"),
        ("import", "create"),
        ("discard", "delete"),
    ],
)
def test_op_maps_to_expected_action(op, expected_action):
    preview = {"steps": [_step(op, AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert intent.action == expected_action
    assert intent.provider == "pulumi"


def test_import_step_sets_import_param():
    preview = {"steps": [_step("import", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert intent.params["import"] is True


def test_same_step_skipped_by_default():
    preview = {"steps": [_step("same", AWS_EC2_URN)]}
    assert from_pulumi_preview(preview) == []


def test_same_step_kept_with_include_noop():
    preview = {"steps": [_step("same", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview, include_noop=True)
    assert intent.action == "no-op"


@pytest.mark.parametrize("op", ["read", "refresh"])
def test_read_and_refresh_skipped_by_default(op):
    preview = {"steps": [_step(op, AWS_EC2_URN)]}
    assert from_pulumi_preview(preview) == []


@pytest.mark.parametrize("op", ["read", "refresh"])
def test_read_and_refresh_kept_with_include_reads(op):
    preview = {"steps": [_step(op, AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview, include_reads=True)
    assert intent.action == "read"


def test_unsupported_op_raises():
    preview = {"steps": [_step("totally-unknown-op", AWS_EC2_URN)]}
    with pytest.raises(ValueError):
        from_pulumi_preview(preview)


# --- urn parsing -----------------------------------------------------------------


def test_urn_parses_stack_project_type_resource():
    preview = {"steps": [_step("create", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert intent.metadata["stack"] == "prod"
    assert intent.metadata["project"] == "myproj"
    assert intent.metadata["type"] == "aws:ec2/instance:Instance"
    assert intent.metadata["provider_name"] == "aws"
    assert intent.resource == "aws/ec2/instance/web"


def test_urn_with_parented_type_uses_leaf_type():
    urn = "urn:pulumi:prod::myproj::aws:ec2/vpc:Vpc$aws:ec2/subnet:Subnet::subnet1"
    preview = {"steps": [_step("create", urn)]}
    (intent,) = from_pulumi_preview(preview)
    assert intent.metadata["type"] == "aws:ec2/subnet:Subnet"
    assert intent.resource == "aws/ec2/subnet/subnet1"


def test_urn_malformed_raises():
    preview = {"steps": [_step("create", "not-a-urn")]}
    with pytest.raises(ValueError):
        from_pulumi_preview(preview)


# --- region / tags / forced replacement -------------------------------------------


def test_region_pulled_from_new_state_inputs():
    preview = {
        "steps": [
            _step(
                "create",
                AWS_EC2_URN,
                newState={"inputs": {"region": "us-west-2"}},
            )
        ]
    }
    (intent,) = from_pulumi_preview(preview)
    assert intent.metadata["region"] == "us-west-2"


def test_region_falls_back_to_old_state():
    preview = {
        "steps": [
            _step(
                "delete",
                AWS_EC2_URN,
                oldState={"inputs": {"region": "eu-central-1"}},
            )
        ]
    }
    (intent,) = from_pulumi_preview(preview)
    assert intent.metadata["region"] == "eu-central-1"


def test_tags_land_in_params():
    preview = {
        "steps": [
            _step(
                "update",
                AWS_EC2_URN,
                newState={"inputs": {"tags": {"env": "prod"}}},
            )
        ]
    }
    (intent,) = from_pulumi_preview(preview)
    assert intent.params["tags"] == {"env": "prod"}


def test_no_region_or_tags_omitted():
    preview = {"steps": [_step("create", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert "region" not in intent.metadata
    assert "tags" not in intent.params


def test_forced_replacement_from_replace_reasons():
    preview = {
        "steps": [_step("replace", AWS_EC2_URN, replaceReasons=["ami changed"])]
    }
    (intent,) = from_pulumi_preview(preview)
    assert intent.params["forced_replacement"] is True


def test_forced_replacement_from_diff_reasons():
    preview = {
        "steps": [_step("create-replacement", AWS_EC2_URN, diffReasons=["ami"])]
    }
    (intent,) = from_pulumi_preview(preview)
    assert intent.params["forced_replacement"] is True


def test_no_forced_replacement_when_reasons_absent():
    preview = {"steps": [_step("replace", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert "forced_replacement" not in intent.params


def test_raw_action_preserves_original_op():
    preview = {"steps": [_step("create-replacement", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    assert intent.params["raw_action"] == "create-replacement"


# --- multi-step preview ------------------------------------------------------------


def test_multi_step_preview_produces_one_intent_per_change():
    preview = {
        "steps": [
            _step("same", AWS_EC2_URN),
            _step("create", AWS_RDS_URN),
            _step("delete", AWS_EC2_URN),
        ]
    }
    intents = from_pulumi_preview(preview)
    assert len(intents) == 2
    assert {i.action for i in intents} == {"create", "delete"}


# --- from_pulumi_argv --------------------------------------------------------------


def test_argv_up_is_update():
    intent = from_pulumi_argv(["pulumi", "up", "--stack", "prod", "-y"])
    assert intent.action == "update"
    assert intent.resource == "stack/prod"
    assert intent.params["yes"] is True
    assert intent.metadata["stack"] == "prod"


def test_argv_destroy_is_delete():
    intent = from_pulumi_argv(["pulumi", "destroy", "-s", "prod"])
    assert intent.action == "delete"
    assert intent.resource == "stack/prod"


def test_argv_stack_rm_is_delete_with_force():
    intent = from_pulumi_argv(["pulumi", "stack", "rm", "prod", "--force"])
    assert intent.action == "delete"
    assert intent.params["force"] is True


def test_argv_preview_is_read_dry_run():
    intent = from_pulumi_argv(["pulumi", "preview", "-s", "prod"])
    assert intent.action == "read"
    assert intent.params["dry_run"] is True


def test_argv_refresh_is_read():
    intent = from_pulumi_argv(["pulumi", "refresh", "-s", "prod"])
    assert intent.action == "read"
    assert "dry_run" not in intent.params


def test_argv_import_sets_import_param():
    intent = from_pulumi_argv(["pulumi", "import", "aws:ec2/instance:Instance", "web", "i-123"])
    assert intent.action == "create"
    assert intent.params["import"] is True


def test_argv_skip_preview_flag_recorded():
    intent = from_pulumi_argv(["pulumi", "up", "--yes", "--skip-preview"])
    assert intent.params["skip_preview"] is True


def test_argv_no_stack_defaults_to_wildcard():
    intent = from_pulumi_argv(["pulumi", "up"])
    assert intent.resource == "stack/*"
    assert intent.metadata == {}


def test_argv_rejects_non_pulumi_invocation():
    with pytest.raises(ValueError):
        from_pulumi_argv(["terraform", "apply"])


def test_argv_rejects_unsupported_command():
    with pytest.raises(ValueError):
        from_pulumi_argv(["pulumi", "logout"])


def test_argv_rejects_empty_command():
    with pytest.raises(ValueError):
        from_pulumi_argv(["pulumi"])


# --- end-to-end: interceptor against the example store -----------------------------


def _load_example_store():
    return ConstraintStore.load(EXAMPLE_STORE, authority_map=_authority_map())


def test_rds_delete_is_escalated_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    preview = {"steps": [_step("delete", AWS_RDS_URN)]}
    (intent,) = from_pulumi_preview(preview)
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert "pulumi-escalate-rds-delete-replace" in decision.citations


def test_rds_replace_is_escalated_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    preview = {"steps": [_step("replace", AWS_RDS_URN)]}
    (intent,) = from_pulumi_preview(preview)
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"


def test_ec2_delete_is_not_covered_by_rds_rule():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    preview = {"steps": [_step("delete", AWS_EC2_URN)]}
    (intent,) = from_pulumi_preview(preview)
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ALLOW"
    assert decision.covered is False
