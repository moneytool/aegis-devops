"""aegis compile aws: the verified snapshot as SCPs scoped to agent
identities (design v0.3, §6.1, §6.5)."""

import json
import re
import shlex
import shutil
from pathlib import Path

import pytest
import yaml

from aegis_core.cli import main
from aegis_core.compile import CompileError, check_outputs, write_outputs
from aegis_core.compile.aws import (
    AwsTarget,
    compile_aws,
    denying_statements,
    load_action_map,
)
from aegis_core.identity import load_identity_model
from aegis_core.parser import from_aws_multi
from aegis_core.signing import load_key, sign_file
from aegis_core.store import Constraint, VerifiedSnapshot, _canonical, _constraint_to_dict

ACCOUNT = "123456789012"
AGENT = f"arn:aws:iam::{ACCOUNT}:role/coding-agent"
DEPLOY = "arn:aws:iam::111122223333:role/Deploy"
BREAK_GLASS = "arn:aws:iam::111122223333:role/BreakGlass"
AUTHORITY = {"admin": {"identity"}}


def _rule(id, pattern, actions, effect="BLOCK", **kw):
    return Constraint.create(
        id=id, provider=kw.pop("provider", "aws"), resource_pattern=pattern,
        actions=set(actions), effect=effect, constraint_class="deletion", principal="admin",
        source_ref="t", source_timestamp="2026-09-28T00:00:00+00:00", rule_text=id, **kw)


def _snap(*rules, excluded=()):
    records = tuple(_canonical(_constraint_to_dict(c)) for c in sorted(rules, key=lambda c: c.id))
    return VerifiedSnapshot._build(records=records, excluded=tuple(excluded), authority=(),
                                   inputs=(), settings=(), aegis_version="test")


def _model(tmp_path, **fields):
    doc = {"principal": "admin",
           "break_glass": [{"platform": "aws", "kind": "role", "id": BREAK_GLASS}],
           "trusted": [{"platform": "aws", "kind": "role", "id": DEPLOY},
                       {"platform": "aws", "kind": "source-identity", "id": "alice"}],
           **fields}
    doc = {k: v for k, v in doc.items() if v is not None}
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(doc))
    return load_identity_model(path, authority_map=AUTHORITY, insecure=True)


def _compile(tmp_path, *rules, model=None, **target):
    target = {"account": ACCOUNT, "env": "prod", **target}
    return compile_aws(_snap(*rules), model or _model(tmp_path), AwsTarget(**target))


def _rule_cov(result, rule_id):
    return next(r for r in result.coverage["rules"] if r["id"] == rule_id)


def _denied(result, action, resource, principal=AGENT, **kw):
    return bool(denying_statements(result.policies, action=action, resource=resource,
                                   principal_arn=principal, **kw))


# --- the action map ---------------------------------------------------------------


def test_action_map_is_well_formed_and_entirely_unverified():
    amap = load_action_map()
    assert len(amap) > 30
    for tm in amap.values():
        assert tm.verified is False  # until the sandbox acceptance run
        for grants in tm.grants.values():
            for g in grants:
                assert all(re.fullmatch(r"[a-z0-9-]+:[A-Za-z0-9]+", a) for a in g.iam), g
                assert all(a == "*" or a.startswith("arn:{partition}:") for a in g.arns), g


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-ids i-1",
    "aws ec2 delete-volume --volume-id v",
    "aws s3 rb s3://b",
    "aws s3 rm s3://b/k",
    "aws s3api delete-object --bucket b --key k",
    "aws rds delete-db-instance --db-instance-identifier d",
    "aws rds delete-db-cluster --db-cluster-identifier c",
    "aws dynamodb delete-table --table-name t",
    "aws eks delete-cluster --name c",
    "aws iam delete-role --role-name r",
    "aws iam attach-role-policy --role-name r --policy-arn x",
    "aws iam update-assume-role-policy --role-name r --policy-document x",
    "aws iam create-access-key --user-name u",
    "aws lambda delete-function --function-name f",
    "aws cloudformation delete-stack --stack-name s",
    "aws kms schedule-key-deletion --key-id k",
    "aws secretsmanager delete-secret --secret-id s",
    "aws logs delete-log-group --log-group-name g",
    "aws ecr delete-repository --repository-name r",
    "aws autoscaling set-desired-capacity --auto-scaling-group-name g --desired-capacity 0",
    "aws route53 delete-hosted-zone --id Z",
    "aws organizations leave-organization",
])
def test_every_parsed_destructive_intent_has_a_mapping(command):
    """The map is keyed by what the parser produces, so a rule written for
    the CLI's normal form compiles."""
    amap = load_action_map()
    for intent in from_aws_multi(shlex.split(command)):
        rtype = "/".join(intent.resource.split("/", 2)[:2])
        assert rtype in amap, rtype
        assert intent.action in amap[rtype].grants, (rtype, intent.action)


# --- identity scoping ---------------------------------------------------------------


def test_deny_by_default_restricts_every_identity_but_the_exempt(tmp_path):
    r = _compile(tmp_path, _rule("no-ec2-delete", "ec2/instance/*", ["delete"]))
    arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert _denied(r, "ec2:TerminateInstances", arn)
    assert _denied(r, "ec2:TerminateInstances", arn, principal="arn:aws:iam::1:role/new-agent")
    assert not _denied(r, "ec2:TerminateInstances", arn, principal=DEPLOY)
    assert not _denied(r, "ec2:TerminateInstances", arn, principal=BREAK_GLASS)
    assert not _denied(r, "ec2:TerminateInstances", arn, source_identity="alice")
    assert _denied(r, "ec2:TerminateInstances", arn, source_identity="mallory")
    assert not _denied(r, "ec2:StopInstances", arn)  # not in the rule


def test_agents_only_restricts_only_listed_agents_and_never_break_glass(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None, agents=[
        {"platform": "aws", "kind": "role", "id": AGENT},
        {"platform": "aws", "kind": "source-identity", "id": "agent-7"}])
    r = _compile(tmp_path, _rule("no-ec2-delete", "ec2/instance/*", ["delete"]), model=model)
    arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert _denied(r, "ec2:TerminateInstances", arn)
    assert _denied(r, "ec2:TerminateInstances", arn, principal="arn:aws:iam::1:role/x",
                   source_identity="agent-7")
    assert not _denied(r, "ec2:TerminateInstances", arn, principal="arn:aws:iam::1:role/x")
    assert not _denied(r, "ec2:TerminateInstances", arn, principal=BREAK_GLASS,
                       source_identity="agent-7")
    # one copy of each statement per agent kind
    assert len(_rule_cov(r, "no-ec2-delete")["statements"]) == 2


def test_compile_refuses_without_aws_break_glass(tmp_path):
    model = _model(tmp_path, break_glass=[
        {"platform": "kubernetes", "kind": "group", "id": "aegis:break-glass"}])
    with pytest.raises(ValueError, match="no break-glass identity for aws"):
        _compile(tmp_path, _rule("r", "ec2/instance/*", ["delete"]), model=model)


# --- self-protection -----------------------------------------------------------------


def test_self_protection_closes_the_aws_identity_escapes(tmp_path):
    r = _compile(tmp_path)
    names = {s["name"] for s in r.coverage["self_protection"]}
    assert names == {"assume-exempt-role", "pass-exempt-role", "modify-exempt-role",
                     "set-source-identity", "leave-organization"}
    assert _denied(r, "sts:AssumeRole", DEPLOY)
    assert _denied(r, "iam:PassRole", BREAK_GLASS)
    assert _denied(r, "iam:UpdateAssumeRolePolicy", DEPLOY)
    assert not _denied(r, "sts:AssumeRole", "arn:aws:iam::1:role/another-agent-role")
    assert _denied(r, "sts:SetSourceIdentity", "*")
    assert _denied(r, "organizations:LeaveOrganization", "*")
    # the operators themselves are not restricted by it
    assert not _denied(r, "sts:AssumeRole", DEPLOY, principal=BREAK_GLASS)


def test_self_protection_for_agents_only(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None, agents=[
        {"platform": "aws", "kind": "role", "id": AGENT}])
    r = _compile(tmp_path, model=model)
    names = {s["name"] for s in r.coverage["self_protection"]}
    assert {"assume-non-agent-role", "pass-non-agent-role", "new-credentials"} <= names
    assert "set-source-identity" not in names  # no exempt source identity to take on
    assert _denied(r, "sts:AssumeRole", "arn:aws:iam::1:role/admin")
    assert not _denied(r, "sts:AssumeRole", AGENT)
    assert _denied(r, "iam:CreateUser", "arn:aws:iam::1:user/x")


def test_trusted_users_get_credential_protection(tmp_path):
    user = "arn:aws:iam::111122223333:user/ops"
    model = _model(tmp_path, trusted=[{"platform": "aws", "kind": "user", "id": user}])
    r = _compile(tmp_path, model=model)
    assert _denied(r, "iam:CreateAccessKey", user)
    assert not _denied(r, "iam:CreateAccessKey", "arn:aws:iam::111122223333:user/other")


# --- rule coverage --------------------------------------------------------------------


def test_example_rules_compile_with_honest_statuses(tmp_path):
    r = _compile(
        tmp_path,
        _rule("ec2-us-east-1", "ec2/instance/*", ["delete"], scope={"region": "us-east-1"}),
        _rule("rds", "rds/*", ["delete"]),
        _rule("k8s", "node/*", ["delete"], provider="kubernetes"),
    )
    ec2 = _rule_cov(r, "ec2-us-east-1")
    assert ec2["status"] == "exact" and ec2["mapping"] == "unverified"
    arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert _denied(r, "ec2:TerminateInstances", arn, region="us-east-1")
    assert not _denied(r, "ec2:TerminateInstances", arn, region="eu-west-1")
    rds = _rule_cov(r, "rds")
    assert rds["status"] == "partial"  # rds/* also matches types the map does not know
    assert _denied(r, "rds:DeleteDBInstance", f"arn:aws:rds:us-east-1:{ACCOUNT}:db:prod")
    assert _rule_cov(r, "k8s")["status"] == "not-applicable"


def test_env_scope_compiles_exactly_per_account(tmp_path):
    rule = _rule("prod-only", "dynamodb/table/*", ["delete"], scope={"env": "prod"})
    assert _rule_cov(_compile(tmp_path, rule), "prod-only")["status"] == "exact"
    staging = _compile(tmp_path, rule, env="staging")
    assert _rule_cov(staging, "prod-only")["status"] == "not-applicable"
    assert not _denied(staging, "dynamodb:DeleteTable",
                       f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/t")
    unmapped = _compile(tmp_path, rule, env=None)
    cov = _rule_cov(unmapped, "prod-only")
    assert cov["status"] == "over-enforced" and "unresolved environment" in cov["over_enforced"][0]


def test_account_scope(tmp_path):
    rule = _rule("acct", "ecr/repository/*", ["delete"], scope={"account": "999999999999"})
    assert _rule_cov(_compile(tmp_path, rule), "acct")["status"] == "not-applicable"


def test_escalate_is_a_deny_or_left_client_only(tmp_path):
    rule = _rule("esc", "lambda/function/*", ["delete"], effect="ESCALATE")
    cov = _rule_cov(_compile(tmp_path, rule), "esc")
    assert cov["status"] == "over-enforced" and "cannot ask" in cov["over_enforced"][0]
    omitted = _compile(tmp_path, rule, escalate="omit")
    assert _rule_cov(omitted, "esc")["status"] == "not-enforced"
    assert not _denied(omitted, "lambda:DeleteFunction",
                       f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f")


def test_time_windows_and_rate_limits_stay_client_side(tmp_path):
    r = _compile(
        tmp_path,
        _rule("tw", "ec2/instance/*", ["delete"],
              time_window={"days": ["sat"], "start": "00:00", "end": "24:00", "tz": "UTC"}),
        _rule("rl", "ec2/instance/*", ["delete"], rate_limit={"max": 1, "per": "1h"}),
    )
    assert _rule_cov(r, "tw")["status"] == "not-enforced"
    assert _rule_cov(r, "rl")["status"] == "not-enforced"
    assert not _denied(r, "ec2:TerminateInstances", f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i")


def test_name_patterns_become_arn_globs(tmp_path):
    r = _compile(tmp_path, _rule("b", "s3/bucket/prod-*", ["delete"]),
                 _rule("cls", "dynamodb/table/prod-[ab]", ["delete"]))
    assert _denied(r, "s3:DeleteBucket", "arn:aws:s3:::prod-data")
    assert _denied(r, "s3:DeleteObject", "arn:aws:s3:::prod-data/k")  # `aws s3 rm` parity
    assert not _denied(r, "s3:DeleteBucket", "arn:aws:s3:::dev-data")
    cls = _rule_cov(r, "cls")
    assert cls["status"] == "over-enforced" and "character class" in cls["over_enforced"][0]
    assert _denied(r, "dynamodb:DeleteTable", f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/prod-c")


def test_unmapped_actions_and_types_are_not_enforced_never_widened(tmp_path):
    r = _compile(tmp_path, _rule("unknown", "glacier/vault/*", ["delete"]),
                 _rule("verb", "ec2/instance/*", ["delete", "hibernate"]))
    assert _rule_cov(r, "unknown")["status"] == "not-enforced"
    verb = _rule_cov(r, "verb")
    assert verb["status"] == "partial"
    assert any("'hibernate'" in n for n in verb["not_enforced"])


def test_unexpressible_scope_keys_widen_and_say_so(tmp_path):
    r = _compile(tmp_path, _rule("p", "iam/role-policy/*", ["update"],
                                 scope={"privilege": True, "profile": "prod-admin"}))
    cov = _rule_cov(r, "p")
    assert cov["status"] == "over-enforced" and len(cov["over_enforced"]) == 2


def test_global_service_region_scope_is_over_enforced(tmp_path):
    r = _compile(tmp_path, _rule("iam", "iam/role/*", ["delete"], scope={"region": "us-east-1"}))
    cov = _rule_cov(r, "iam")
    assert cov["status"] == "over-enforced"
    assert _denied(r, "iam:DeleteRole", f"arn:aws:iam::{ACCOUNT}:role/x", region="eu-west-1")


def test_cli_missing_names_are_noted_and_wildcard_only_types_refuse_names(tmp_path):
    r = _compile(tmp_path, _rule("vol", "ec2/volume/vol-prod-*", ["delete"]),
                 _rule("q", "sqs/queue/orders", ["delete"]))
    assert "never matches" in _rule_cov(r, "vol")["notes"][0]
    assert _rule_cov(r, "q")["status"] == "not-enforced"


def test_same_effect_actions_are_reported(tmp_path):
    r = _compile(tmp_path, _rule("b", "s3/bucket/*", ["delete"]))
    assert any("PutLifecycleConfiguration" in s
               for s in _rule_cov(r, "b")["same_effect_not_covered"])


def test_excluded_constraints_are_listed_and_never_compiled(tmp_path):
    snap = _snap(excluded=(("forged-rule", "forged"), ("x", "unauthorized")))
    r = compile_aws(snap, _model(tmp_path), AwsTarget(account=ACCOUNT))
    assert r.coverage["excluded"] == [{"id": "forged-rule", "reason": "forged"},
                                      {"id": "x", "reason": "unauthorized"}]
    assert all(o.startswith("self-protection:")
               for v in r.manifest["statements"].values() for o in v)


# --- limits, output, determinism -----------------------------------------------------------


def test_statements_merge_exactly(tmp_path):
    """Same resources pool actions, same actions pool resources; no action is
    ever paired with a resource it was not compiled for."""
    rules = [_rule(f"r{i:02}", f"dynamodb/table/t{i:02}-*", ["delete"]) for i in range(40)]
    r = _compile(tmp_path, *rules)
    (st,) = [s for p in r.policies for s in p["Statement"] if "dynamodb:DeleteTable" in s["Action"]]
    assert st["Action"] == ["dynamodb:DeleteTable"] and len(st["Resource"]) == 40
    assert r.manifest["statements"][st["Sid"]] == [f"rule:r{i:02}" for i in range(40)]
    both = _compile(tmp_path, _rule("a", "s3/bucket/x", ["delete"]),
                    _rule("b", "dynamodb/table/y", ["delete"]))
    assert not _denied(both, "dynamodb:DeleteTable", "arn:aws:s3:::x")
    assert not _denied(both, "s3:DeleteBucket",
                       f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/y")


def test_rules_covering_every_name_deny_the_action_outright(tmp_path):
    r = _compile(tmp_path, _rule("all", "ecr/repository/*", ["delete"]))
    assert _denied(r, "ecr:DeleteRepository", "arn:aws:ecr:us-east-1:999999999999:repository/x")


def test_policies_split_to_fit_and_fail_loudly(tmp_path):
    amap = load_action_map()
    types = [t for t, tm in sorted(amap.items())
             if "delete" in tm.grants and tm.names in ("name", "cli-missing")]
    rules = [_rule(f"r{i:02}", f"{t}/n{i:02}-*", ["delete"]) for i, t in enumerate(types)]
    r = _compile(tmp_path, *rules)
    assert len(r.policies) > 1
    assert all(p["chars"] <= 5120 for p in r.manifest["policies"])
    with pytest.raises(CompileError, match="SCPs but at most 1"):
        _compile(tmp_path, *rules, max_policies=1)
    with pytest.raises(CompileError, match="alone exceeds"):
        _compile(tmp_path, *rules, max_chars=300)


def test_report_only_is_not_deployable_and_enforce_is(tmp_path):
    r = _compile(tmp_path)
    assert not r.deployable and all(p["file"].startswith("report-only/")
                                    for p in r.manifest["policies"])
    enforce = _compile(tmp_path, model=_model(tmp_path, enforcement="enforce"))
    assert enforce.deployable and enforce.manifest["policies"][0]["file"] == "scp-1.json"


def test_output_is_deterministic_and_self_describing(tmp_path):
    rules = (_rule("a", "s3/bucket/*", ["delete"]), _rule("b", "rds/*", ["delete"]))
    one, two = _compile(tmp_path, *rules), _compile(tmp_path, *reversed(rules))
    assert one.files == two.files
    m = one.manifest
    assert m["snapshot_digest"] and m["policy_description"].startswith("Aegis policy ")
    owners = {o for v in m["statements"].values() for o in v}
    assert owners >= {"rule:a", "rule:b"}
    assert all(re.fullmatch(r"Aegis\d+", sid) for sid in m["statements"])
    for p in m["policies"]:
        assert len(one.files[p["file"]]) - 1 <= 5120
        json.loads(one.files[p["file"]])


def test_write_and_check_detect_drift_and_stale_files(tmp_path):
    out = tmp_path / "out"
    r = _compile(tmp_path, _rule("a", "s3/bucket/*", ["delete"]))
    write_outputs(out, r.files)
    assert check_outputs(out, r.files) == []
    changed = _compile(tmp_path, _rule("a", "s3/bucket/*", ["delete", "put"]))
    assert "differs: report-only/scp-1.json" in check_outputs(out, changed.files)
    enforce = _compile(tmp_path, _rule("a", "s3/bucket/*", ["delete"]),
                       model=_model(tmp_path, enforcement="enforce"))
    assert "stale: report-only/scp-1.json" in check_outputs(out, enforce.files)
    write_outputs(out, enforce.files)
    assert not (out / "report-only" / "scp-1.json").exists()
    assert check_outputs(out, enforce.files) == []


# --- CLI -------------------------------------------------------------------------------------


@pytest.fixture
def policy_dir(tmp_path, monkeypatch):
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    shutil.copy(d / "agents.example.yaml", d / "agents.yaml")
    sign_file(d / "agents.yaml", key)
    return d


def test_cli_compile_writes_and_checks(policy_dir, tmp_path, capsys):
    out = tmp_path / "out"
    argv = ["compile", "aws", "--config-dir", str(policy_dir), "--account", "123456789012"]
    assert main([*argv, "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "report-only" in text and "exact=" in text
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["env"] == "prod"  # from environments.yaml
    cov = json.loads((out / "coverage.json").read_text())
    assert {r["id"] for r in cov["rules"]} >= {"block-s3-bucket-delete", "block-rds-delete"}
    assert main([*argv, "--check", str(out)]) == 0
    (out / "coverage.md").write_text("edited\n")
    assert main([*argv, "--check", str(out)]) == 1
    assert "differs: coverage.md" in capsys.readouterr().out


def test_cli_compile_refuses_insecure_and_missing_identity_model(policy_dir, tmp_path, capsys):
    argv = ["compile", "aws", "--config-dir", str(policy_dir), "--account", "123456789012",
            "--out", str(tmp_path / "o")]
    assert main([*argv, "--insecure"]) == 64
    (policy_dir / "agents.yaml").unlink()
    assert main(argv) == 65
    assert "identity model" in capsys.readouterr().err
    assert main([*argv[:-4], "--account", "12", "--out", str(tmp_path / "o")]) != 0


def test_package_ships_the_action_map():
    assert Path("src/aegis_core/compile/actions/aws.yaml").exists()
    pyproject = Path("pyproject.toml").read_text()
    assert "compile/actions/*" in pyproject
