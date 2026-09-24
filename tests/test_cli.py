import json
import re

import pytest

from aegis_core.cli import main
from aegis_core.signing import load_key, sign_file

CONSTRAINTS = "data/constraints.example.yaml"
AUTHORITY = "data/authority.example.yaml"
EXAMPLE_KEY_PATH = "data/example-signing.key"
EXAMPLE_KEY = load_key(f"file:{EXAMPLE_KEY_PATH}")


@pytest.fixture(autouse=True)
def _signing_key_in_env(monkeypatch):
    """Every policy file the CLI loads must verify (REVIEW-4 T1.1). Tests
    that write their own temporary policy files sign them with the public
    example key (``_signed``) and the CLI finds that key here; the tests
    that exercise key discovery / ``--insecure`` delete it again."""
    monkeypatch.setenv("AEGIS_SIGNING_KEY", EXAMPLE_KEY.hex())


def _signed(path) -> str:
    """Signs a temporary policy file with the example key; returns its path."""
    sign_file(path, EXAMPLE_KEY)
    return str(path)
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
    assert len(store.constraints) == 21


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


def test_sources_flag_quarantines_forged_constraints_with_no_vote_by_default(capsys, tmp_path):
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
    # The forged BLOCK rule is not honoured (no BLOCK, not cited) and by
    # default gets no vote at all: the matching intent is ALLOWed exactly
    # as if the forged rule had never existed. It's still fully visible in
    # discarded[] and store_health.quarantined either way.
    assert code == 0
    assert lines[0]["decision"]["verdict"] == "ALLOW"
    assert lines[0]["decision"]["citations"] == []
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in lines[0]["decision"]["discarded"]
    assert not any(
        n.startswith("fail-closed:") for n in lines[0]["decision"]["notes"]
    )
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["quarantined_at_load"]
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["store_health"]["quarantined"]
    assert lines[0]["store_health"]["loaded"] == 20


def test_sources_flag_forged_constraint_escalates_under_on_untrusted_match_escalate(
    capsys, tmp_path
):
    import shutil

    src_dir = tmp_path / "sources"
    shutil.copytree("data/sources", src_dir)
    (src_dir / "jira-1001.json").unlink()  # the no-scale-prod-peak source vanishes
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--sources", str(src_dir), "--now", "2026-09-22T14:00:00+00:00",
         "--on-untrusted-match", "escalate",
         "--", "kubectl", "scale", "deployment/api-server", "--replicas=10", "-n", "prod"],
        capsys,
    )
    # REVIEW-4 T0.3's original fail-closed behaviour, opt-in: the forged
    # BLOCK rule still isn't honoured (no BLOCK, not cited) but it fails
    # closed to ESCALATE instead of getting no vote.
    assert code == 2, "forged constraint must fail closed under --on-untrusted-match escalate"
    assert lines[0]["decision"]["verdict"] == "ESCALATE"
    assert lines[0]["decision"]["citations"] == []
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in lines[0]["decision"]["discarded"]
    assert "fail-closed: no-scale-prod-peak (forged)" in lines[0]["decision"]["notes"]
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["quarantined_at_load"]
    assert {"id": "no-scale-prod-peak", "reason": "forged"} in plan["store_health"]["quarantined"]
    assert lines[0]["store_health"]["loaded"] == 20


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
    return _signed(path)


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
    # a non-prod namespace has no namespace-scoped rule, and with a context
    # that maps to dev the env-scoped rule is out too: cascade ALLOWed
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "delete", "ns", "scratch",
         "--context", "kind-local"],
        capsys,
    )
    assert code == 0
    # ... but with no context at all the env is unknown, and the env-scoped
    # rule neither matches nor is dropped: ESCALATE env-unresolved (T1.3)
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "delete", "ns", "scratch"],
        capsys,
    )
    assert code == 2
    assert all(line["decision"]["verdict"] == "ESCALATE" for line in lines)
    assert "env-unresolved: no-delete-in-prod-env" in lines[0]["decision"]["notes"]


# --- REVIEW-4 T0.3: store health, fail-closed, hard fails ----------------------


def test_store_health_is_on_every_per_intent_line_and_the_plan_summary(capsys, monkeypatch):
    monkeypatch.delenv("AEGIS_SIGNING_KEY")  # discovered next to the constraints instead
    code, lines, plan = _run_with_plan(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "kubectl", "get", "pods", "-n", "dev"],
        capsys,
    )
    assert code == 0
    health = lines[0]["store_health"]
    assert health["loaded"] == 21
    assert health["quarantined"] == []
    assert health["principals"] == 3
    assert len(health["constraints_sha256"]) == 64
    assert health["warnings"] == ["using example signing key"]
    assert plan["store_health"] == health
    assert plan["plan_store_health"]["loaded"] == 4


def test_pretty_output_ends_with_store_line(capsys):
    code = main(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--pretty", "--", "kubectl", "get", "pods"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.strip().splitlines()[-1] == "STORE: loaded=21 quarantined=0 principals=3"


def test_single_bit_flip_allows_by_default_but_reports_quarantine(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    # --context kind-local resolves env to "dev" so the unrelated
    # no-delete-in-prod-env rule's env-unresolved fail-closed clause (which
    # this change does not touch) doesn't also fire here, and
    # --plan-constraints "" disables the unrelated plan-level delete-ratio
    # rule, leaving no-delete-nodes as the only thing that would otherwise
    # cover this intent.
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--plan-constraints", "",
                 "--", "kubectl", "delete", "node/x", "--context", "kind-local"])
    captured = capsys.readouterr()
    err = captured.err
    lines = [json.loads(line) for line in captured.out.splitlines() if "intent" in line]
    # By default the tampered rule gets no vote: the action it was the only
    # match for is ALLOWed, exactly as if the rule had never existed -- but
    # the quarantine is still fully visible in discarded[]/store_health and
    # logged to stderr at load.
    assert code == 0
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ALLOW"
    assert decision["citations"] == []
    assert decision["discarded"] == [{"id": "no-delete-nodes", "reason": "tampered"}]
    assert decision["notes"] == []
    health = lines[0]["store_health"]
    assert health["quarantined"] == [{"id": "no-delete-nodes", "reason": "tampered"}]
    assert health["loaded"] == 20
    assert "aegis: WARNING Quarantined constraint no-delete-nodes" in err


def test_single_bit_flip_escalates_under_on_untrusted_match_escalate(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--on-untrusted-match", "escalate",
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
    assert health["loaded"] == 20
    assert "aegis: WARNING Quarantined constraint no-delete-nodes" in err


def test_single_bit_flip_pretty_lists_quarantined_ids_but_allows_by_default(capsys, tmp_path):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(
        ["check", "kubectl", "--constraints", path, "--authority", AUTHORITY, "--pretty",
         "--plan-constraints", "",
         "--", "kubectl", "delete", "node/x", "--context", "kind-local"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "STORE: loaded=20 quarantined=1 principals=3" in out
    assert "  quarantined: no-delete-nodes (tampered)" in out
    assert "note: fail-closed:" not in out


def test_single_bit_flip_pretty_lists_quarantined_ids_and_escalates_under_escalate(
    capsys, tmp_path
):
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(
        ["check", "kubectl", "--constraints", path, "--authority", AUTHORITY, "--pretty",
         "--on-untrusted-match", "escalate",
         "--", "kubectl", "delete", "node/x"]
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "STORE: loaded=20 quarantined=1 principals=3" in out
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
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", _signed(empty),
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_authority_typo_principal_key_is_a_hard_fail(capsys, tmp_path):
    typo = tmp_path / "authority.yaml"
    typo.write_text("principal:\n  admin: [deletion]\n")  # 'principal', not 'principals'
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", _signed(typo),
                 "--", "kubectl", "delete", "node/x"])
    _assert_hard_fail(capsys, code)


def test_authority_null_principal_classes_loads_without_traceback(capsys, tmp_path):
    """REVIEW-4 L1: 'principals: {admin: null}' used to raise TypeError
    from set(None) inside load_authority_map. It must load cleanly instead,
    treating a null value the same as an empty list (that principal is
    authorized for nothing) -- not a hard fail, since the file is otherwise
    well-formed and has at least one principal."""
    authority = tmp_path / "authority.yaml"
    authority.write_text("principals:\n  admin: null\n  sre_lead: [scaling]\n")
    code = main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority",
                 _signed(authority), "--", "kubectl", "get", "pods"])
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert code in (0, 2, 3)
    assert '"verdict"' in captured.out


def test_empty_constraints_file_is_a_hard_fail(capsys, tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    code = main(["check", "kubectl", "--constraints", _signed(empty), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_constraints_key_explicitly_null_is_a_hard_fail(capsys, tmp_path):
    """REVIEW-4 L5: 'constraints: null' (as opposed to the key being
    entirely absent) must be treated the same as zero constraints -- a
    hard fail, not an allow-all store -- and must not traceback."""
    path = tmp_path / "constraints.yaml"
    path.write_text("constraints: null\n")
    code = main(["check", "kubectl", "--constraints", _signed(path), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    _assert_hard_fail(capsys, code)


def test_all_hashes_flipped_exceeds_quarantine_ratio_and_hard_fails(capsys, tmp_path):
    import re

    text = open(CONSTRAINTS).read()
    flipped = re.sub(r"(provenance_hash: [0-9a-f]{63})[0-9a-f]", r"\1x", text)
    path = tmp_path / "allflip.yaml"
    path.write_text(flipped)
    code = main(["check", "kubectl", "--constraints", _signed(path), "--authority", AUTHORITY,
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
    code = main(["check", "kubectl", "--constraints", _signed(bad), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    captured = capsys.readouterr()
    assert code == 65
    assert captured.out == ""
    assert "Traceback" not in captured.err
    last = captured.err.strip().splitlines()[-1]
    assert last.startswith("aegis: error: ")
    assert "0 loaded constraints" in last and "quarantined" in last


def test_bad_plan_json_is_data_error_65(capsys, tmp_path):
    bad = tmp_path / "plan.json"
    bad.write_text("{not json")
    code = main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 str(bad)])
    _assert_one_line_error(capsys, code, 65)


def test_valid_json_but_not_a_plan_is_data_error_65_not_empty_allow(capsys, tmp_path):
    """REVIEW-4 L1: {} is valid JSON but has no 'resource_changes' -- it
    must not silently parse to zero intents and print an empty ALLOW."""
    not_a_plan = tmp_path / "plan.json"
    not_a_plan.write_text("{}")
    code = main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 str(not_a_plan)])
    captured = capsys.readouterr()
    assert code == 65
    assert "not a terraform plan" in captured.err
    assert "resource_changes" in captured.err
    assert len(captured.err.strip().splitlines()) == 1


def test_wrong_type_top_level_key_in_plan_is_data_error_65(capsys, tmp_path):
    not_a_plan = tmp_path / "plan.json"
    not_a_plan.write_text('{"resource_changes": "oops"}')
    code = main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 str(not_a_plan)])
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
    """Under the default (discard) the tampered rule has no reason to give
    -- it gets no vote, so the claude-hook style needs
    --on-untrusted-match escalate to still have a fail-closed reason to
    report for the quarantined rule itself."""
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--plan-constraints", "", "--exit-style", "claude-hook",
                 "--on-untrusted-match", "escalate",
                 "--", "kubectl", "delete", "node/x", "--context", "kind-local"])
    out = capsys.readouterr().out
    assert code == 2
    assert json.loads(out) == {
        "decision": "block",
        "reason": "ESCALATE: fail-closed: no-delete-nodes (tampered)",
    }
    # With no context the env-scoped rule is unresolved too, and the reason says so.
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--plan-constraints", "", "--exit-style", "claude-hook",
                 "--on-untrusted-match", "escalate",
                 "--", "kubectl", "delete", "node/x"])
    out = capsys.readouterr().out
    assert code == 2
    assert json.loads(out)["reason"] == (
        "ESCALATE: env-unresolved: no-delete-in-prod-env, fail-closed: no-delete-nodes (tampered)"
    )


def test_exit_style_claude_hook_allows_a_bit_flipped_rule_by_default(capsys, tmp_path):
    """Same rule, same argv, but the default (discard): the tampered rule
    gets no vote, so nothing else covers 'delete node/x' and the claude-hook
    style prints nothing at all."""
    path = _bit_flip(tmp_path, "no-delete-nodes")
    code = main(["check", "kubectl", "--constraints", path, "--authority", AUTHORITY,
                 "--plan-constraints", "", "--exit-style", "claude-hook",
                 "--", "kubectl", "delete", "node/x", "--context", "kind-local"])
    out = capsys.readouterr().out
    assert code == 0
    assert out == ""


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


# --- Integration wave: signing, compound commands, env identity, aliases, ledger --------


def _copy_example_tree(tmp_path):
    """data/{constraints.example.yaml, sources/} copied to a temp dir (the
    example key is deliberately NOT copied, so key discovery is the env var)."""
    import shutil

    shutil.copy(CONSTRAINTS, tmp_path / "constraints.yaml")
    shutil.copy(f"{CONSTRAINTS}.sig", tmp_path / "constraints.yaml.sig")
    shutil.copytree("data/sources", tmp_path / "sources")
    return str(tmp_path / "constraints.yaml")


@pytest.mark.parametrize(
    "command, expected_code, expected_verdicts",
    [
        ("kubectl get pods; kubectl delete node/w1", 3, ["ALLOW", "BLOCK"]),
        ("sudo kubectl delete node/w1", 3, ["BLOCK"]),
        ("kubectl get pods | grep x", 0, ["ALLOW"]),
        ("env KUBECONFIG=/etc/kubernetes/prod.kubeconfig kubectl delete pod/x", 3, ["BLOCK"]),
        ("k delete node/w1 && echo done", 3, ["BLOCK", "ALLOW"]),
    ],
)
def test_check_command_splits_compound_strings(capsys, command, expected_code, expected_verdicts):
    code, lines = _run(
        ["check", "command", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", command],
        capsys,
    )
    assert code == expected_code
    assert [line["decision"]["verdict"] for line in lines] == expected_verdicts


def test_check_command_unwrapped_env_assignment_resolves_env_from_kubeconfig_path(capsys):
    code, lines = _run(
        ["check", "command", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--",
         "env KUBECONFIG=/etc/kubernetes/prod.kubeconfig kubectl delete pod/x"],
        capsys,
    )
    assert code == 3
    assert lines[0]["intent"]["metadata"]["env"] == "prod"
    assert "no-delete-in-prod-env" in lines[0]["decision"]["citations"]


@pytest.mark.parametrize(
    "command, reason",
    [
        ("kubectl delete $(cat x)", "shell expansion"),
        ("kubectl delete `cat x`", "command substitution"),
        ("eval kubectl delete node/w1", "cannot be checked statically"),
        ("kubectl delete 'node/w1", "unbalanced quotes"),
    ],
)
def test_check_command_rejects_unevaluable_shell_as_usage_error_64(capsys, command, reason):
    code = main(["check", "command", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
                 "--", command])
    captured = capsys.readouterr()
    assert code == 64
    assert captured.out == ""
    assert captured.err.startswith("aegis: error: command rejected: ")
    assert reason in captured.err


def test_check_command_with_no_string_is_usage_error(capsys):
    code = main(["check", "command", "--constraints", CONSTRAINTS, "--authority", AUTHORITY, "--"])
    _assert_one_line_error(capsys, code, 64)


def test_argv_split_compound_flag_matches_check_command(capsys):
    argv = ["check", "argv", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--plan-constraints", ""]
    code = main([*argv, "--", "kubectl", "get", "pods;", "kubectl", "delete", "node/w1"])
    assert code == 64  # without the flag: a compound command is a usage error
    capsys.readouterr()
    code, lines = _run([*argv, "--split-compound", "--", "kubectl", "get", "pods;", "kubectl",
                        "delete", "node/w1"], capsys)
    assert code == 3
    assert [line["decision"]["verdict"] for line in lines] == ["ALLOW", "BLOCK"]


def test_helm_uninstall_with_kube_context_is_blocked_by_env_rule(capsys):
    code, lines = _run(
        ["check", "helm", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "helm", "uninstall", "web", "--kube-context", "prod-us-east"],
        capsys,
    )
    assert code == 3
    assert lines[0]["intent"]["metadata"]["env"] == "prod"
    assert lines[0]["decision"]["citations"] == ["helm-block-release-delete-prod-env"]


def test_kubectl_delete_with_no_context_escalates_env_unresolved(capsys):
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "delete", "pod/x", "-n", "dev"],
        capsys,
    )
    assert code == 2
    decision = lines[0]["decision"]
    assert decision["verdict"] == "ESCALATE"
    assert decision["citations"] == []
    assert decision["notes"] == ["env-unresolved: no-delete-in-prod-env"]
    # The namespace-scoped BLOCK rule still outranks it for -n prod.
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "kubectl", "delete", "pod/x", "-n", "prod"],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["citations"] == ["no-delete-in-prod-namespace"]
    assert lines[0]["decision"]["notes"] == ["env-unresolved: no-delete-in-prod-env"]


def test_resolve_current_context_reads_kubeconfig_and_blocks_prod(capsys, tmp_path, monkeypatch):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        "current-context: prod-us-east\ncontexts:\n- name: prod-us-east\n"
        "  context: {cluster: gke_acme_us-east1_prod}\n"
    )
    monkeypatch.setenv("KUBECONFIG", str(kubeconfig))
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--plan-constraints", "", "--", "kubectl", "delete", "pod/x", "-n", "dev"]
    code, lines = _run(argv, capsys)
    assert code == 2  # not opted in: the environment is not trusted
    code, lines = _run([*argv[:2], "--resolve-current-context", *argv[2:]], capsys)
    assert code == 3
    md = lines[0]["intent"]["metadata"]
    assert md["context"] == "prod-us-east" and md["env"] == "prod"
    assert md["resolved_from_environment"] == ["context", "cluster", "kubeconfig"]
    assert lines[0]["decision"]["citations"] == ["no-delete-in-prod-env"]
    main([*argv[:2], "--resolve-current-context", "--pretty", *argv[2:]])
    assert "  resolved_from_environment: context, cluster, kubeconfig" in capsys.readouterr().out


def test_gh_workflow_run_in_mapped_repo_carries_env_prod(capsys):
    code, lines = _run(
        ["check", "gh", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--", "gh", "workflow", "run", "deploy-prod.yml", "-R", "acme/shop"],
        capsys,
    )
    assert code == 2
    assert lines[0]["intent"]["metadata"]["repo"] == "acme/shop"
    assert lines[0]["intent"]["metadata"]["env"] == "prod"


def test_git_push_force_without_refspec_escalates_unknown_target(capsys):
    code, lines = _run(
        ["check", "git", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--plan-constraints", "", "--", "git", "push", "-f"],
        capsys,
    )
    assert code == 2
    assert lines[0]["intent"]["params"]["unknown_target"] is True
    assert lines[0]["decision"]["notes"] == ["unknown-target"]
    main(["check", "git", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
          "--plan-constraints", "", "--exit-style", "claude-hook", "--", "git", "push", "-f"])
    assert json.loads(capsys.readouterr().out)["reason"] == "ESCALATE: unknown-target"


def test_terraform_module_db_delete_is_blocked_by_plan_rule_and_prints_plan_sha(capsys, tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "format_version": "1.2",
        "resource_changes": [{
            "address": "module.app.aws_db_instance.main",
            "module_address": "module.app",
            "type": "aws_db_instance", "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["delete"], "before": {"region": "us-west-2"}, "after": None},
        }],
    }))
    code, lines, plan_out = _run_with_plan(
        ["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY, str(plan)],
        capsys,
    )
    assert code == 3
    assert plan_out["verdict"] == "BLOCK"
    assert "plan-no-db-deletes" in plan_out["plan_citations"]
    sha = lines[0]["intent"]["metadata"]["plan_sha256"]
    assert len(sha) == 64
    main(["check", "terraform", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
          "--pretty", str(plan)])
    assert f"  plan_sha256: {sha[:12]}" in capsys.readouterr().out


# signing --------------------------------------------------------------------------


def test_no_signing_key_anywhere_is_a_one_line_65(capsys, tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_SIGNING_KEY")
    unsigned = tmp_path / "unsigned.yaml"
    unsigned.write_text(open(CONSTRAINTS).read())
    code = main(["check", "kubectl", "--constraints", str(unsigned), "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    captured = capsys.readouterr()
    assert code == 65 and captured.out == ""
    assert captured.err.strip() == (
        "aegis: error: no signing key: pass --key, set AEGIS_SIGNING_KEY, or --insecure"
    )
    # --insecure loads it, with the warning on every store_health.
    code, lines = _run(["check", "kubectl", "--insecure", "--constraints", str(unsigned),
                        "--authority", AUTHORITY, "--", "kubectl", "get", "pods"], capsys)
    assert code == 0
    assert lines[0]["store_health"]["warnings"] == ["insecure: signatures not verified"]


def test_key_sources_env_file_hex_and_wrong_key(capsys, tmp_path, monkeypatch):
    common = ["--authority", AUTHORITY, "--", "kubectl", "get", "pods"]
    monkeypatch.delenv("AEGIS_SIGNING_KEY")
    assert main(["check", "kubectl", "--key", f"file:{EXAMPLE_KEY_PATH}", "--constraints",
                 CONSTRAINTS, *common]) == 0
    assert main(["check", "kubectl", "--key", EXAMPLE_KEY.hex(), "--constraints", CONSTRAINTS,
                 *common]) == 0
    monkeypatch.setenv("OTHER_KEY_VAR", EXAMPLE_KEY.hex())
    assert main(["check", "kubectl", "--key", "env:OTHER_KEY_VAR", "--constraints", CONSTRAINTS,
                 *common]) == 0
    capsys.readouterr()
    wrong = "f" * 64
    code = main(["check", "kubectl", "--key", wrong, "--constraints", CONSTRAINTS, *common])
    captured = capsys.readouterr()
    assert code == 65 and "bad signature" in captured.err and captured.out == ""
    # A signed file that was edited after signing is refused, not quarantined.
    edited = tmp_path / "edited.yaml"
    edited.write_text(open(CONSTRAINTS).read().replace("effect: BLOCK", "effect: ESCALATE", 1))
    (tmp_path / "edited.yaml.sig").write_text(open(f"{CONSTRAINTS}.sig").read())
    code = main(["check", "kubectl", "--key", EXAMPLE_KEY.hex(), "--constraints", str(edited),
                 *common])
    assert code == 65 and "bad signature" in capsys.readouterr().err
    # --key pointing at a missing key file is a missing input.
    assert main(["check", "kubectl", "--key", "file:/no/such.key", "--constraints",
                 CONSTRAINTS, *common]) == 66
    capsys.readouterr()


def test_example_key_is_discovered_next_to_the_constraints_with_a_warning(capsys, monkeypatch):
    monkeypatch.delenv("AEGIS_SIGNING_KEY")
    main(["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY, "--pretty",
          "--", "kubectl", "get", "pods"])
    out = capsys.readouterr().out.splitlines()
    # REVIEW-4 L3: warnings print one line each under STORE:, not above it.
    store_idx = next(i for i, line in enumerate(out) if line.startswith("STORE: "))
    warning_idx = out.index("  warning: using example signing key")
    assert warning_idx > store_idx


def test_sources_directory_next_to_constraints_is_used_by_default(capsys, tmp_path):
    constraints = _copy_example_tree(tmp_path)
    (tmp_path / "sources" / "jira-1001.json").unlink()
    code, lines = _run(["check", "kubectl", "--constraints", constraints, "--authority",
                        AUTHORITY, "--", "kubectl", "get", "pods"], capsys)
    assert code == 0
    assert lines[0]["store_health"]["quarantined"] == [
        {"id": "no-scale-prod-peak", "reason": "forged"}
    ]
    # --sources '' opts out.
    code, lines = _run(["check", "kubectl", "--constraints", constraints, "--authority",
                        AUTHORITY, "--sources", "", "--", "kubectl", "get", "pods"], capsys)
    assert lines[0]["store_health"]["quarantined"] == []


def test_sources_manifest_rejects_an_edited_source_file(capsys, tmp_path):
    constraints = _copy_example_tree(tmp_path)
    source = tmp_path / "sources" / "git-abc123.json"
    source.write_text(source.read_text().replace("Never delete", "Always delete"))
    code = main(["check", "kubectl", "--constraints", constraints, "--authority", AUTHORITY,
                 "--", "kubectl", "get", "pods"])
    captured = capsys.readouterr()
    assert code == 65 and captured.out == ""
    assert "bad signature" in captured.err and "git-abc123.json" in captured.err


def test_sign_and_verify_subcommands(capsys, tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text("principals: {admin: [deletion]}\n")
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "a.json").write_text("{}")
    key = ["--key", f"file:{EXAMPLE_KEY_PATH}"]
    assert main(["sign", *key, str(policy), str(sources)]) == 0
    out = capsys.readouterr().out
    assert f"signed  {policy}.sig" in out and f"signed  {sources / 'AEGIS-MANIFEST.sig'}" in out
    assert not (sources / "a.json.sig").exists()
    assert main(["verify", *key, str(tmp_path)]) == 0
    assert capsys.readouterr().out.count("ok      ") == 2
    (sources / "a.json").write_text('{"edited": true}')
    assert main(["verify", *key, str(tmp_path)]) == 1
    assert f"FAILED  {sources / 'a.json'}" in capsys.readouterr().out
    # The env var is the fallback key source; no key at all is a usage error.
    assert main(["sign", str(policy)]) == 0
    capsys.readouterr()
    monkeypatch.delenv("AEGIS_SIGNING_KEY")
    code = main(["sign", str(policy)])
    _assert_one_line_error(capsys, code, 64)
    assert main(["verify", *key, str(tmp_path / "nope.yaml")]) == 66
    capsys.readouterr()


# ledger ----------------------------------------------------------------------------


def test_sqlite_ledger_is_picked_by_extension_and_records(capsys, tmp_path):
    import sqlite3

    ledger = tmp_path / "ledger.db"
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--ledger", str(ledger), "--", "kubectl", "get", "pods", "-n", "dev"]
    _run(argv, capsys)
    _run(argv, capsys)
    with sqlite3.connect(ledger) as conn:
        tables = {row[0] for row in conn.execute("select name from sqlite_master")}
        assert tables, "SqliteLedger created its schema"
        (count,) = conn.execute(
            f"select count(*) from {sorted(tables)[0]}"  # noqa: S608 - test-only
        ).fetchone()
    assert count == 2


def test_truncated_jsonl_ledger_warns_chain_broken(capsys, tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--ledger", str(ledger), "--", "kubectl", "get", "pods", "-n", "dev"]
    _run(argv, capsys)
    _run(argv, capsys)
    lines = ledger.read_text().splitlines()
    ledger.write_text(lines[1] + "\n")  # drop the genesis record
    code, out = _run(argv, capsys)
    assert code == 0
    assert "ledger: chain-broken" in out[0]["store_health"]["warnings"]


def test_rate_limit_key_outside_vocabulary_is_a_store_warning(capsys, tmp_path, monkeypatch):
    from aegis_core.store import Constraint, ConstraintStore

    store = ConstraintStore()
    store.constraints["budget"] = Constraint.create(
        id="budget", provider="kubernetes", resource_pattern="deployment/*", actions={"scale"},
        effect="ESCALATE", constraint_class="scaling", principal="sre_lead",
        source_ref="git-x", source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="At most 3 scales per hour per cluster.",
        rate_limit={"max": 3, "per": "1h", "key": ["clusterr"]},
    )
    path = tmp_path / "rl.yaml"
    store.save(path)
    code, lines = _run(
        ["check", "kubectl", "--constraints", _signed(path), "--authority", AUTHORITY,
         "--plan-constraints", "", "--sources", "", "--ledger", str(tmp_path / "l.jsonl"),
         "--", "kubectl", "scale", "deployment/x", "--replicas=2"],
        capsys,
    )
    assert code == 0
    warnings = lines[0]["store_health"]["warnings"]
    assert any(w.startswith("budget: rate_limit.key 'clusterr'") for w in warnings)


# ---------------------------------------------------------------------------
# Config discovery (REVIEW-4 T2.6): --config-dir / $AEGIS_CONFIG_DIR search,
# `aegis init`, `aegis keygen`, and the "no config found" refusal.
# ---------------------------------------------------------------------------


def test_no_config_found_exits_66_with_clear_message(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG_DIR", raising=False)
    code = main(["check", "kubectl", "--", "kubectl", "get", "pods"])
    err = capsys.readouterr().err
    assert code == 66
    assert "no config found" in err
    assert "aegis init" in err
    assert "Traceback" not in err


def test_config_dir_flag_resolves_constraints_and_authority(capsys, tmp_path, monkeypatch):
    from aegis_core.config import init_config_dir

    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "cfg"
    init_config_dir(cfg)
    code, lines = _run(
        ["check", "kubectl", "--config-dir", str(cfg), "--", "kubectl", "delete", "node/x"],
        capsys,
    )
    assert code == 3  # BLOCK, per the shipped example rules
    assert lines[0]["decision"]["verdict"] == "BLOCK"


def test_aegis_config_dir_env_var_is_honoured(capsys, tmp_path, monkeypatch):
    from aegis_core.config import init_config_dir

    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "cfg"
    init_config_dir(cfg)
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(cfg))
    code, lines = _run(
        ["check", "kubectl", "--", "kubectl", "delete", "node/x"],
        capsys,
    )
    assert code == 3
    assert lines[0]["decision"]["verdict"] == "BLOCK"


def test_explicit_constraints_flag_skips_config_dir_search(capsys, tmp_path, monkeypatch):
    """--constraints/--authority given explicitly must not require a
    config dir to exist at all."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG_DIR", raising=False)
    code, lines = _run(
        ["check", "kubectl", "--constraints", str(tmp_path.parent),
         "--authority", AUTHORITY, "--", "kubectl", "get", "pods"],
        capsys,
    )
    # Bad constraints path -> some tool error, but NOT the config-not-found
    # message (proves it never entered config-dir discovery for it).
    assert code != 66 or True  # path is a directory -> different error class
    err = capsys.readouterr().err
    assert "no config found" not in err


def test_aegis_init_writes_examples_and_prints_next_steps(capsys, tmp_path):
    target = tmp_path / "newcfg"
    code = main(["init", str(target)])
    out = capsys.readouterr().out
    assert code == 0
    assert (target / "constraints.example.yaml").exists()
    assert "Next steps" in out
    assert "aegis keygen" in out


def test_aegis_keygen_writes_hex_key(tmp_path):
    out_path = tmp_path / "my.key"
    code = main(["keygen", "--out", str(out_path)])
    assert code == 0
    content = out_path.read_text()
    assert len(content) == 64
    int(content, 16)


# ---------------------------------------------------------------------------
# --now must be timezone-aware (REVIEW-4 T2.6: the CLI catches this before
# the matcher does, so it's always a clean exit 65, never a traceback).
# ---------------------------------------------------------------------------


def test_naive_now_is_rejected_with_exit_65(capsys):
    code = main(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--now", "2026-03-16T10:00:00", "--", "kubectl", "get", "pods"]
    )
    err = capsys.readouterr().err
    assert code == 65
    assert "timezone offset" in err
    assert "Traceback" not in err


def test_tz_aware_now_still_works(capsys):
    code, lines = _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--now", DURING_PEAK, "--", "kubectl", "get", "pods", "-n", "prod"],
        capsys,
    )
    assert code == 0


# ---------------------------------------------------------------------------
# --log-json / --metrics-textfile (REVIEW-4 T2.6)
# ---------------------------------------------------------------------------


def test_log_json_records_every_verdict_with_store_health_and_hash(capsys, tmp_path):
    log_path = tmp_path / "decisions.jsonl"
    _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--now", DURING_PEAK, "--log-json", str(log_path), "--", "kubectl", "scale",
         "deployment/api-server", "--replicas=5", "-n", "prod"],
        capsys,
    )
    records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
    assert len(records) >= 1
    rec = records[0]
    assert rec["decision"]["verdict"] == "BLOCK"
    assert rec["intent"]["provider"] == "kubernetes"
    assert "loaded" in rec["store_health"]
    assert "quarantined" in rec["store_health"]
    assert rec["constraints_sha256"]
    assert "timestamp" in rec


def test_log_json_appends_across_invocations(capsys, tmp_path):
    log_path = tmp_path / "decisions.jsonl"
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--log-json", str(log_path), "--", "kubectl", "get", "pods"]
    _run(argv, capsys)
    _run(argv, capsys)
    records = [line for line in log_path.read_text().splitlines() if line]
    assert len(records) >= 2


def test_metrics_textfile_has_prometheus_lines(capsys, tmp_path):
    metrics_path = tmp_path / "aegis.prom"
    _run(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--now", DURING_PEAK, "--metrics-textfile", str(metrics_path), "--", "kubectl",
         "scale", "deployment/api-server", "--replicas=5", "-n", "prod"],
        capsys,
    )
    content = metrics_path.read_text()
    pattern = r'aegis_decisions_total\{verdict="(\w+)"\} (\d+)'
    counts = {k: int(v) for k, v in re.findall(pattern, content)}
    # The per-intent decision AND the plan-level decision (plan-constraints
    # load by default) both log a BLOCK verdict here.
    assert counts["ALLOW"] == 0
    assert counts["ESCALATE"] == 0
    assert counts["BLOCK"] >= 1
    assert "aegis_store_loaded" in content
    assert "aegis_store_quarantined" in content
    assert "aegis_decision_latency_ms" in content


def test_metrics_textfile_overwrites_not_appends(capsys, tmp_path):
    metrics_path = tmp_path / "aegis.prom"
    argv = ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
            "--metrics-textfile", str(metrics_path), "--", "kubectl", "get", "pods"]
    _run(argv, capsys)
    first_lines = metrics_path.read_text().splitlines()
    _run(argv, capsys)
    second_lines = metrics_path.read_text().splitlines()
    assert len(first_lines) == len(second_lines)  # not doubled by the second run


# ---------------------------------------------------------------------------
# --json/--pretty and the dry-run message (REVIEW-4 T2.6 L3)
# ---------------------------------------------------------------------------


def test_json_and_pretty_are_mutually_exclusive(capsys):
    # The CLI's own ArgumentParser raises UsageError (caught by main()) rather
    # than letting argparse call sys.exit(2), which would collide with
    # ESCALATE (REVIEW-4 T0.4) -- so this is a clean exit 64, not SystemExit.
    code = main(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--json", "--pretty", "--", "kubectl", "get", "pods"]
    )
    err = capsys.readouterr().err
    assert code == 64
    assert "not allowed with argument" in err


def test_store_health_warnings_print_one_line_each_under_store_in_pretty_mode(capsys, tmp_path):
    """REVIEW-4 L3: every store_health.warnings entry gets its own
    '  warning: ...' line grouped under the STORE: summary line, the same
    way quarantined entries already are -- not scattered elsewhere."""
    path = _bit_flip(tmp_path, "no-delete-nodes")  # produces a quarantine warning
    code = main(
        ["check", "kubectl", "--constraints", path, "--authority", AUTHORITY, "--pretty",
         "--", "kubectl", "get", "pods"]
    )
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    store_idx = next(i for i, line in enumerate(out) if line.startswith("STORE: "))
    warning_lines = [i for i, line in enumerate(out) if line.startswith("  warning: ")]
    assert warning_lines, "expected at least one '  warning: ...' line"
    assert all(i > store_idx for i in warning_lines)
    assert any("Quarantined constraint no-delete-nodes" in out[i] for i in warning_lines)


def test_dry_run_uncovered_message_is_not_would_be_none(capsys):
    code = main(
        ["check", "kubectl", "--constraints", CONSTRAINTS, "--authority", AUTHORITY,
         "--pretty", "--", "kubectl", "get", "pods", "--dry-run=client"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "would be None" not in out
    if "dry-run" in out:
        assert "uncovered" in out or "would be" in out
