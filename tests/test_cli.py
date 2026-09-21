import json

from aegis_core.cli import main

CONSTRAINTS = "data/constraints.example.yaml"
AUTHORITY = "data/authority.example.yaml"
# 2026-03-16 is a Monday, inside the no-scale-prod-peak time window
# (09:00-17:00 ET, weekdays).
DURING_PEAK = "2026-03-16T10:00:00-05:00"
OUTSIDE_PEAK = "2026-03-16T22:00:00-05:00"


def _run(argv, capsys):
    code = main(argv)
    out = capsys.readouterr().out.strip()
    lines = [json.loads(line) for line in out.splitlines() if line]
    return code, lines


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
