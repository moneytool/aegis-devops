import json

from aegis_core.cli import main

CONSTRAINTS = "data/constraints.example.yaml"
AUTHORITY = "data/authority.example.yaml"
# 2026-03-16 is a Monday, inside the no-scale-prod-peak time window
# (09:00-17:00 ET, weekdays).
DURING_PEAK = "2026-03-16T10:00:00-05:00"
OUTSIDE_PEAK = "2026-03-16T22:00:00-05:00"


def _run(argv, capsys):
    """Returns (exit_code, per-intent decision lines). The trailing plan-level
    summary line (present whenever plan constraints are loaded) is available
    via _run_with_plan."""
    code, lines, _plan = _run_with_plan(argv, capsys)
    return code, lines


def _run_with_plan(argv, capsys):
    code = main(argv)
    out = capsys.readouterr().out.strip()
    parsed = [json.loads(line) for line in out.splitlines() if line]
    intents = [p for p in parsed if "intent" in p]
    plans = [p["plan"] for p in parsed if "plan" in p]
    return code, intents, (plans[0] if plans else None)


def test_kubectl_scale_prod_during_peak_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--now",
            DURING_PEAK,
            "--",
            "kubectl",
            "scale",
            "deployment/api-server",
            "--replicas=5",
            "-n",
            "prod",
        ],
        capsys,
    )
    assert code == 3
    assert len(lines) == 1
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "no-scale-prod-peak" in lines[0]["decision"]["citations"]


def test_kubectl_get_is_allowed(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "kubectl",
            "get",
            "service/frontend",
            "-n",
            "prod",
        ],
        capsys,
    )
    assert code == 0
    assert lines[0]["decision"]["verdict"] == "ALLOW"
    assert lines[0]["decision"]["covered"] is False


def test_kubectl_scale_prod_outside_peak_is_allowed(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--now",
            OUTSIDE_PEAK,
            "--",
            "kubectl",
            "scale",
            "deployment/api-server",
            "--replicas=5",
            "-n",
            "prod",
        ],
        capsys,
    )
    assert code == 0
    assert lines[0]["decision"]["verdict"] == "ALLOW"


def test_terraform_destroy_prod_ec2_is_escalated(capsys, tmp_path):
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "change": {"actions": ["delete"], "before": {"region": "us-east-1"}},
            }
        ]
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))

    code, lines = _run(
        [
            "check",
            "terraform",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            str(plan_path),
        ],
        capsys,
    )
    assert code == 2
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert "escalate-terraform-prod-destroy" in lines[0]["decision"]["citations"]


def test_kubectl_delete_node_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "kubectl",
            "delete",
            "node/worker-1",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"


def test_kubectl_bad_argv_returns_error_exit_code(capsys):
    code = main(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "helm",
            "install",
            "x",
        ]
    )
    assert code == 1


def test_pretty_output_is_human_readable(capsys):
    code = main(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--pretty",
            "--",
            "kubectl",
            "get",
            "service/frontend",
            "-n",
            "prod",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "ALLOW" in out


def test_check_aws_terminate_instances_in_us_east_1_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "aws",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            "i-1",
            "--region",
            "us-east-1",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "aws-no-delete-ec2-us-east-1" in lines[0]["decision"]["citations"]


def test_check_az_aks_scale_is_escalated(capsys):
    code, lines = _run(
        [
            "check",
            "az",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "az",
            "aks",
            "scale",
            "--resource-group",
            "rg1",
            "--name",
            "aks1",
            "--node-count",
            "5",
        ],
        capsys,
    )
    assert code == 2
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert "azure-escalate-aks-scale-delete" in lines[0]["decision"]["citations"]


def test_check_gcloud_sql_instances_delete_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "gcloud",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "gcloud",
            "sql",
            "instances",
            "delete",
            "prod-db",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "gcp-no-delete-sql-instance" in lines[0]["decision"]["citations"]


def test_check_argv_dispatches_by_binary_name(capsys):
    code, lines = _run(
        [
            "check",
            "argv",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "gcloud",
            "sql",
            "instances",
            "delete",
            "prod-db",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"


def test_kubectl_scale_prod_during_peak_dry_run_server_is_allowed_but_would_be_block(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--now",
            DURING_PEAK,
            "--",
            "kubectl",
            "scale",
            "deployment/api-server",
            "--replicas=5",
            "-n",
            "prod",
            "--dry-run=server",
        ],
        capsys,
    )
    assert code == 0
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ALLOW"
    assert decision["dry_run"] is True
    assert decision["would_be"] == "BLOCK"
    assert "no-scale-prod-peak" in decision["citations"]


def test_kubectl_scale_prod_during_peak_dry_run_none_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--now",
            DURING_PEAK,
            "--",
            "kubectl",
            "scale",
            "deployment/api-server",
            "--replicas=5",
            "-n",
            "prod",
            "--dry-run=none",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert lines[0]["decision"]["dry_run"] is False


def test_aws_terminate_instances_dry_run_is_allowed_but_would_be_block(capsys):
    code, lines = _run(
        [
            "check",
            "aws",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            "i-1",
            "--region",
            "us-east-1",
            "--dry-run",
        ],
        capsys,
    )
    assert code == 0
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ALLOW"
    assert decision["dry_run"] is True
    assert decision["would_be"] == "BLOCK"


def test_pretty_output_shows_dry_run_would_be(capsys):
    code = main(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--now",
            DURING_PEAK,
            "--pretty",
            "--",
            "kubectl",
            "scale",
            "deployment/api-server",
            "--replicas=5",
            "-n",
            "prod",
            "--dry-run=server",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "(dry-run; would be BLOCK)" in out


def test_kubectl_delete_pod_in_prod_context_is_blocked_by_env_rule(capsys):
    code, lines = _run(
        [
            "check",
            "kubectl",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--environments",
            "data/environments.example.yaml",
            "--",
            "kubectl",
            "delete",
            "pod/x",
            "--context",
            "prod-us-east",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "no-delete-in-prod-env" in lines[0]["decision"]["citations"]
    assert lines[0]["intent"]["metadata"]["env"] == "prod"


def test_example_constraints_load_with_zero_quarantined():
    from aegis_core.authority import load_authority_map
    from aegis_core.store import ConstraintStore

    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    assert store.quarantined == []
    assert len(store.constraints) == 19


def test_tofu_plan_is_gated_by_the_same_terraform_rule(capsys, tmp_path):
    plan = {
        "terraform_version": "1.8.0-tofu",
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "change": {"actions": ["delete"], "before": {"region": "us-east-1"}},
            }
        ],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))

    code, lines = _run(
        ["check", "tofu", "--constraints", CONSTRAINTS, "--authority", AUTHORITY, str(plan_path)],
        capsys,
    )
    assert code == 2
    assert lines[0]["intent"]["provider"] == "terraform"
    assert lines[0]["intent"]["metadata"]["tool"] == "opentofu"
    assert "escalate-terraform-prod-destroy" in lines[0]["decision"]["citations"]


# --- GitOps targets (helm, argocd, flux, git, gh) --------------------------


def test_check_helm_uninstall_release_in_prod_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "helm",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "helm",
            "uninstall",
            "api",
            "-n",
            "prod",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "helm-block-release-delete-prod" in lines[0]["decision"]["citations"]


def test_check_argocd_sync_prod_app_with_prune_is_escalated(capsys):
    code, lines = _run(
        [
            "check",
            "argocd",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "argocd",
            "app",
            "sync",
            "prod-web",
            "--prune",
        ],
        capsys,
    )
    assert code == 2
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert "argocd-escalate-prod-sync-prune" in lines[0]["decision"]["citations"]


def test_check_git_force_push_main_is_blocked(capsys):
    code, lines = _run(
        [
            "check",
            "git",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "git",
            "push",
            "--force",
            "origin",
            "main",
        ],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"
    assert "git-block-force-push-main" in lines[0]["decision"]["citations"]


def test_check_gh_workflow_run_deploy_prod_is_escalated(capsys):
    code, lines = _run(
        [
            "check",
            "gh",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "gh",
            "workflow",
            "run",
            "deploy-prod.yml",
            "-r",
            "main",
        ],
        capsys,
    )
    assert code == 2
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert "github-escalate-deploy-prod-workflow" in lines[0]["decision"]["citations"]


def test_check_helm_upgrade_dry_run_is_allowed_with_no_matching_rule(capsys):
    code, lines = _run(
        [
            "check",
            "helm",
            "--constraints",
            CONSTRAINTS,
            "--authority",
            AUTHORITY,
            "--",
            "helm",
            "upgrade",
            "--install",
            "api",
            "./chart",
            "-n",
            "prod",
            "--dry-run",
        ],
        capsys,
    )
    assert code == 0
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ALLOW"
    assert decision["dry_run"] is True
    assert decision["covered"] is False
    assert decision["would_be"] is None


def test_plan_summary_line_is_emitted_and_matches_worst_intent(capsys):
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "kubectl", "delete", "pod/x", "--context", "prod-us-east"],
        capsys,
    )
    assert code == 3
    assert plan["verdict"] == "BLOCK"
    assert plan["n_intents"] == 1
    assert "no-delete-in-prod-env" in plan["citations"]
    # a one-intent batch that is 100% deletes also trips the k8s delete-ratio rule
    assert plan["plan_citations"] == ["plan-k8s-delete-ratio"]


def test_plan_constraint_fires_on_terraform_db_delete(capsys, tmp_path):
    plan = {
        "resource_changes": [
            {"address": "aws_db_instance.main", "mode": "managed",
             "change": {"actions": ["delete"], "before": {"region": "eu-west-1"}}},
        ]
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))
    code, lines, summary = _run_with_plan(
        ["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "data/plan_constraints.example.yaml", str(plan_path)],
        capsys,
    )
    assert code == 3
    assert summary["verdict"] == "BLOCK"
    assert "plan-no-db-deletes" in summary["plan_citations"]


def test_no_plan_constraints_flag_disables_summary(capsys):
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "get", "pods"],
        capsys,
    )
    assert code == 0
    assert plan is None


def test_sources_flag_quarantines_forged_constraints(capsys, tmp_path):
    import shutil

    src_dir = tmp_path / "sources"
    shutil.copytree("data/sources", src_dir)
    (src_dir / "jira-1001.json").unlink()  # the no-scale-prod-peak source vanishes
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--sources", str(src_dir), "--now", "2026-09-22T14:00:00+00:00",
         "--", "kubectl", "scale", "deployment/api-server", "--replicas=10", "-n", "prod"],
        capsys,
    )
    assert code == 0, "forged constraint must not be honoured"
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["quarantined_at_load"]


def test_ledger_flag_records_allowed_actions(capsys, tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--ledger", str(ledger), "--", "kubectl", "get", "pods", "-n", "dev"]
    _run(argv, capsys)
    _run(argv, capsys)
    assert len(ledger.read_text().strip().splitlines()) == 2


def test_sql_target_blocks_unbounded_delete_and_allows_bounded(capsys):
    code, lines = _run(
        ["check", "sql", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "DELETE FROM users; DELETE FROM users WHERE id = 1"],
        capsys,
    )
    assert code == 3
    assert [line["decision"]["verdict"] for line in lines] == ["BLOCK", "ALLOW"]
    assert "sql-block-unbounded-table-delete" in lines[0]["decision"]["citations"]


def test_mongosh_target_blocks_unbounded_delete_many(capsys):
    code, lines = _run(
        ["check", "mongosh", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "mongosh", "--eval", "db.users.deleteMany({})"],
        capsys,
    )
    assert code == 3
    assert lines[0]["intent"]["provider"] == "mongodb"


def test_pulumi_preview_target_escalates_rds_delete(capsys, tmp_path):
    preview = {
        "steps": [
            {"op": "delete", "urn": "urn:pulumi:prod::shop::aws:rds/instance:Instance::main",
             "oldState": {"type": "aws:rds/instance:Instance", "inputs": {"region": "us-east-1"}}},
        ]
    }
    p = tmp_path / "preview.json"
    p.write_text(json.dumps(preview))
    code, lines = _run(
        ["check", "pulumi-preview", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", str(p)],
        capsys,
    )
    assert code == 2
    assert lines[0]["intent"]["resource"] == "aws/rds/instance/main"


def test_argv_target_dispatches_migration_tools(capsys):
    code, lines = _run(
        ["check", "argv", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "flyway", "clean"],
        capsys,
    )
    assert code == 3
    assert lines[0]["intent"]["provider"] == "migration"
