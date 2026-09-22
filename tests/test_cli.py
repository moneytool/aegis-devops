import json

import pytest

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


def test_kubectl_bad_argv_returns_data_error_exit_code(capsys):
    """A parser ValueError is bad input data: exit 65, one line on stderr."""
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
    captured = capsys.readouterr()
    assert code == 65
    assert captured.out == ""
    assert captured.err.startswith("aegis: error: ")
    assert len(captured.err.strip().splitlines()) == 1


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
    assert len(store.constraints) == 20


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
    # REVIEW-4 T0.3: the forged BLOCK rule is not honoured (no BLOCK, not
    # cited) but it fails closed -- the matching intent is ESCALATED, not
    # silently ALLOWed as it was before.
    assert code == 2, "forged constraint must fail closed, not open"
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert lines[0]["decision"]["citations"] == []
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in lines[0]["decision"]["discarded"]
    assert "fail-closed: no-scale-prod-peak (forged)" in lines[0]["decision"]["notes"]
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["quarantined_at_load"]
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["store_health"]["quarantined"]
    assert lines[0]["store_health"]["loaded"] == 19


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


# --- REVIEW-4 T0.1 / T0.2: bypass shapes, end to end ---------------------------


def _bit_flip(tmp_path, constraint_id: str) -> str:
    """Copies the example constraints with ONLY ``constraint_id``'s hash
    flipped in its last hex char; returns the copy's path."""
    import re

    text = open(CONSTRAINTS).read()
    m = re.search(
        rf"- id: {re.escape(constraint_id)}\n(?:.*\n)*?  provenance_hash: ([0-9a-f]{{64}})\n", text
    )
    h = m.group(1)
    path = tmp_path / "oneflip.yaml"
    path.write_text(text.replace(h, h[:-1] + ("0" if h[-1] != "0" else "1")))
    return str(path)


@pytest.mark.parametrize(
    "target, argv, expected_rule",
    [
        ("kubectl", ["kubectl", "-n", "prod", "delete", "deployment/x"],
         "no-delete-in-prod-namespace"),
        ("git", ["git", "-C", "/tmp", "push", "-f", "origin", "main"], "git-block-force-push-main"),
        ("kubectl", ["kubectl", "--context=prod-us-east", "delete", "node/w1"], "no-delete-nodes"),
        ("kubectl", ["kubectl", "delete", "-l", "role=worker", "node"], "no-delete-nodes"),
        ("kubectl", ["kubectl", "delete", "nodes,pods", "--all", "--context", "prod-us-east"],
         "no-delete-nodes"),
        ("kubectl", ["kubectl", "delete", "namespace", "prod", "--context", "prod-us-east"],
         "no-delete-in-prod-namespace"),
        ("helm", ["helm", "uninstall", "web", "-nprod"], "helm-block-release-delete-prod"),
        ("argv", ["helm", "-n", "prod", "uninstall", "web"], "helm-block-release-delete-prod"),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else str(v),
)
def test_review4_bypass_shapes_are_blocked(capsys, target, argv, expected_rule):
    code, lines = _run(
        ["check", target, "--constraints", CONSTRAINTS, "--authority", AUTHORITY, "--", *argv],
        capsys,
    )
    assert code == 3
    assert any(expected_rule in line["decision"]["citations"] for line in lines)


def test_glued_namespace_scale_during_peak_is_blocked(capsys):
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--now", "2026-09-22T14:00:00Z", "--",
         "kubectl", "scale", "deployment/api-server", "--replicas=5", "-nprod"],
        capsys,
    )
    assert code == 3
    assert "no-scale-prod-peak" in lines[0]["decision"]["citations"]


def test_namespace_delete_cascade_is_scoped_to_the_namespace(capsys):
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "kubectl", "delete", "ns", "prod"],
        capsys,
    )
    assert code == 3
    assert [line["intent"]["resource"] for line in lines] == ["namespace/prod", "*/*"]
    cascade = lines[1]
    assert cascade["intent"]["metadata"]["namespace"] == "prod"
    assert cascade["intent"]["params"]["cascade_from"] == "namespace/prod"
    assert "no-delete-in-prod-namespace" in cascade["decision"]["citations"]
    # a non-prod namespace has no namespace-scoped rule: cascade ALLOWed
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "delete", "ns", "scratch"],
        capsys,
    )
    assert code == 0


# --- REVIEW-4 T0.3: store health, fail-closed, hard fails ----------------------


def test_store_health_is_on_every_per_intent_line_and_the_plan_summary(capsys):
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "kubectl", "get", "pods", "-n", "dev"],
        capsys,
    )
    assert code == 0
    health = lines[0]["store_health"]
    assert health["loaded"] == 20
    assert health["quarantined"] == []
    assert health["principals"] == 3
    assert len(health["constraints_sha256"]) == 64
    assert health["warnings"] == []
    assert plan["store_health"] == health
    assert plan["plan_store_health"]["loaded"] == 4


def test_pretty_output_ends_with_store_line(capsys):
    code = main(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--pretty", "--", "kubectl", "get", "pods"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.strip().splitlines()[-1] == "STORE: loaded=20 quarantined=0 principals=3"


def test_single_bit_flip_escalates_and_reports_quarantine(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--", "kubectl", "delete", "node/x"])
    captured = capsys.readouterr()
    err = captured.err
    lines = [json.loads(line) for line in captured.out.splitlines() if "intent" in line]
    assert code == 2
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ESCALATE"
    assert decision["citations"] == []
    assert decision["discarded"] == [{"id": "no-delete-nodes", "reason": "tampered"}]
    assert "fail-closed: no-delete-nodes (tampered)" in decision["notes"]
    health = lines[0]["store_health"]
    assert health["quarantined"] == [{"id": "no-delete-nodes", "reason": "tampered"}]
    assert health["loaded"] == 19
    assert "aegis: WARNING Quarantined constraint no-delete-nodes" in err


def test_single_bit_flip_pretty_lists_quarantined_ids(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(
        ["check", "kubectl", "--constraints", path, "--authority", AUTHORITY, "--pretty",
         "--", "kubectl", "delete", "node/x"]
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "STORE: loaded=19 quarantined=1 principals=3" in out
    assert "  quarantined: no-delete-nodes (tampered)" in out
    assert "note: fail-closed: no-delete-nodes (tampered)" in out


def test_bit_flip_of_an_unrelated_rule_does_not_change_an_unrelated_verdict(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code, lines = _run(
        ["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
         "--", "kubectl", "get", "pods"],
        capsys,
    )
    assert code == 0
    assert lines[0]["decision"]["verdict"] == "ALLOW"
    assert lines[0]["store_health"]["quarantined"] == [
        {"id": "no-delete-nodes", "reason": "tampered"}
    ]


def _assert_hard_fail(capsys, code):
    captured = capsys.readouterr()
    assert code == 65
    assert captured.out == "", "no verdict may be printed on a hard fail"
    err_lines = [line for line in captured.err.splitlines() if line.startswith("aegis: error")]
    assert len(err_lines) == 1
    assert "Traceback" not in captured.err


def test_empty_authority_file_is_a_hard_fail(capsys, tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", str(empty),
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_authority_typo_principal_key_is_a_hard_fail(capsys, tmp_path):
    typo = tmp_path / "authority.yaml"
    typo.write_text("principal:\n  admin: [deletion]\n")  # 'principal', not 'principals'
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", str(typo),
                 "--", "kubectl", "delete", "node/x"])
    _assert_hard_fail(capsys, code)


def test_empty_constraints_file_is_a_hard_fail(capsys, tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    code = main(["check", "kubectl", "--constraints", str(empty), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_all_hashes_flipped_exceeds_quarantine_ratio_and_hard_fails(capsys, tmp_path):
    import re

    text = open(CONSTRAINTS).read()
    flipped = re.sub(r"(provenance_hash: [0-9a-f]{63})[0-9a-f]", r"\1x", text)
    path = tmp_path / "allflip.yaml"
    path.write_text(flipped)
    code = main(["check", "kubectl", "--constraints", str(path), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_max_quarantine_ratio_flag_controls_the_hard_fail(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")  # 1/20 = 0.05
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--max-quarantine-ratio", "0.01", "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--max-quarantine-ratio", "0.5", "--", "kubectl", "get", "pods"])
    capsys.readouterr()
    assert code == 0


def test_fail_closed_flag_escalates_uncovered_intents(capsys):
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--fail-closed", "--", "kubectl", "get", "pods"],
        capsys,
    )
    assert code == 2
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert lines[0]["decision"]["covered"] is False
    assert lines[0]["decision"]["notes"] == ["fail-closed: uncovered"]


def test_store_warnings_go_to_stderr_as_aegis_warning_lines(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
          "--", "kubectl", "get", "pods"])
    err = capsys.readouterr().err
    assert "aegis: WARNING Quarantined constraint no-delete-nodes: provenance hash mismatch" in err


# --- REVIEW-4 T0.4: exit-code contract ------------------------------------------


def _assert_one_line_error(capsys, code, expected_code):
    captured = capsys.readouterr()
    assert code == expected_code
    assert captured.out == ""
    assert captured.err.startswith("aegis: error: ")
    assert "Traceback" not in captured.err
    assert len(captured.err.strip().splitlines()) == 1


def test_unknown_flag_is_usage_error_64(capsys):
    code = main(["check", "kubectl", "--typo", "--", "kubectl", "get", "pods"])
    _assert_one_line_error(capsys, code, 64)


def test_missing_argv_after_separator_is_usage_error_64(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY, "--"])
    _assert_one_line_error(capsys, code, 64)


def test_no_subcommand_is_usage_error_64(capsys):
    _assert_one_line_error(capsys, main([]), 64)
    _assert_one_line_error(capsys, main(["check"]), 64)


@pytest.mark.parametrize(
    "argv",
    [
        ["kubectl", "get", "pods", ";", "kubectl", "delete", "node/w1"],
        ["kubectl", "get", "pods;", "kubectl", "delete", "node/w1"],  # plain shlex.split shape
        ["kubectl", "get", "pods", "&&", "kubectl", "delete", "node/w1"],
        ["kubectl", "get", "pods", "&"],
        ["kubectl", "get", "pods", "|", "grep", "x"],
        ["kubectl", "delete", "node/$(cat target)"],
        ["kubectl", "delete", "node/$", "(", "cat", "target", ")"],  # punctuation-aware split
        ["kubectl", "get", "pods", ">", "/tmp/out"],
    ],
    ids=lambda a: " ".join(a),
)
def test_compound_shell_commands_are_usage_error_64_until_split_compound(capsys, argv):
    code = main(["check", "argv", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--", *argv])
    _assert_one_line_error(capsys, code, 64)


def test_bad_now_is_data_error_65(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--now", "yesterday", "--", "kubectl", "get", "pods"])
    _assert_one_line_error(capsys, code, 65)


def test_trailing_value_flag_without_value_is_data_error_65(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods", "-n"])
    _assert_one_line_error(capsys, code, 65)


def test_bad_yaml_is_data_error_65(capsys, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("constraints: [\n  - id: x\n")
    code = main(["check", "kubectl", "--constraints", str(bad), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_one_line_error(capsys, code, 65)


def test_malformed_constraint_entry_is_data_error_65(capsys, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("constraints:\n  - id: x\n")  # missing every other key
    code = main(["check", "kubectl", "--constraints", str(bad), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_one_line_error(capsys, code, 65)


def test_bad_plan_json_is_data_error_65(capsys, tmp_path):
    bad = tmp_path / "plan.json"
    bad.write_text("{not json")
    code = main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 str(bad)])
    _assert_one_line_error(capsys, code, 65)


def test_missing_constraints_file_is_66(capsys):
    code = main(["check", "kubectl", "--constraints", "/no/such/file.yaml",
                 "--authority", AUTHORITY, "--", "kubectl", "get", "pods"])
    _assert_one_line_error(capsys, code, 66)


def test_missing_plan_file_is_66(capsys):
    code = main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "/no/such/plan.json"])
    _assert_one_line_error(capsys, code, 66)


def test_unexpected_exception_is_70_with_class_name(capsys, monkeypatch):
    import aegis_core.cli as cli

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "_evaluate", boom)
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    captured = capsys.readouterr()
    assert code == 70
    assert captured.err.strip() == "aegis: error: RuntimeError: kaboom"


def test_exit_style_aegis_is_the_default_0_2_3(capsys):
    base = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--plan-constraints", ""]
    assert main([*base, "--", "kubectl", "get", "pods"]) == 0
    assert main([*base, "--", "kubectl", "delete", "configmap/x"]) == 2
    assert main([*base, "--", "kubectl", "delete", "node/x"]) == 3
    capsys.readouterr()


def test_exit_style_claude_hook_block_prints_one_decision_object(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--exit-style", "claude-hook", "--", "kubectl", "delete", "node/x"])
    out = capsys.readouterr().out
    assert code == 2
    objects = [json.loads(line) for line in out.strip().splitlines()]
    assert len(objects) == 1
    assert objects[0]["decision"] == "block"
    assert objects[0]["reason"].startswith("BLOCK: no-delete-nodes")


def test_exit_style_claude_hook_escalate_is_also_2(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--plan-constraints", "", "--exit-style", "claude-hook",
                 "--", "kubectl", "delete", "configmap/x"])
    out = capsys.readouterr().out
    assert code == 2
    obj = json.loads(out.strip())
    assert obj == {"decision": "block", "reason": "ESCALATE: escalate-configmap-changes"}


def test_exit_style_claude_hook_allow_prints_nothing(capsys):
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--exit-style", "claude-hook", "--", "kubectl", "get", "pods"])
    assert code == 0
    assert capsys.readouterr().out == ""


def test_exit_style_claude_hook_fail_closed_reason_names_the_quarantined_rule(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--plan-constraints", "", "--exit-style", "claude-hook",
                 "--", "kubectl", "delete", "node/x"])
    out = capsys.readouterr().out
    assert code == 2
    assert json.loads(out) == {
        "decision": "block",
        "reason": "ESCALATE: fail-closed: no-delete-nodes (tampered)",
    }


def test_exit_style_ci_is_0_or_1(capsys):
    base = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--plan-constraints", "", "--exit-style", "ci"]
    assert main([*base, "--", "kubectl", "get", "pods"]) == 0
    assert main([*base, "--", "kubectl", "delete", "configmap/x"]) == 1
    assert main([*base, "--", "kubectl", "delete", "node/x"]) == 1
    capsys.readouterr()


@pytest.mark.parametrize("style", ["aegis", "claude-hook", "ci"])
def test_tool_errors_are_the_same_in_every_exit_style(capsys, style):
    common = ["--constraints", CONSTRAINTS, "--authority", AUTHORITY, "--exit-style", style]
    assert main(["check", "kubectl", "--typo", *common, "--", "kubectl", "get", "pods"]) == 64
    assert main(["check", "kubectl", *common, "--now", "x", "--", "kubectl", "get", "pods"]) == 65
    assert main(["check", "kubectl", "--constraints", "/nope.yaml", "--authority", AUTHORITY,
                 "--exit-style", style, "--", "kubectl", "get", "pods"]) == 66
    capsys.readouterr()


def test_help_still_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["check", "kubectl", "--help"])
    assert exc.value.code == 0


def test_compound_check_is_skipped_for_script_argument_binaries(capsys):
    """psql/mongosh carry a script string; ';' and '()' inside it are SQL/JS,
    not a compound shell command, and the SQL parsers classify them."""
    code, lines = _run(
        ["check", "argv", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "psql", "-c", "DELETE FROM users; SELECT 1"],
        capsys,
    )
    assert code == 3
    assert lines[0]["intent"]["provider"] == "sql"
    assert lines[0]["decision"]["verdict"] == "BLOCK"
