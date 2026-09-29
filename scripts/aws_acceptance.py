#!/usr/bin/env python3
"""Sandbox acceptance run for ``aegis compile aws`` (design v0.3, §6.4, §8).

The action map may mark a mapping ``verified: true`` only after it has been
exercised against a real AWS Organization. This script builds the policy for
that run; nothing in it touches AWS.

    venv/bin/python scripts/aws_acceptance.py build \\
        --account 701331084529 \\
        --admin-role-arn arn:aws:iam::701331084529:role/aws-reserved/sso.amazonaws.com/<role> \\
        --out build/aws-acceptance

``build`` writes ``agents.yaml`` (enforce; the test agent restricted; the
test trusted role and the operator's admin role trusted; the test break-glass
role and OrganizationAccountAccessRole as break-glass), ``constraints.json``
(one rule per mapped type, plus scoped cases) and the compiled output under
``compiled/``. The operator attaches ``compiled/scp-*.json`` to the sandbox
account only, from the management account, and detaches them afterwards.

Test roles (created by the operator in the sandbox, each with
AdministratorAccess so that an explicit SCP deny is the only thing that can
refuse a call, and a trust policy allowing sts:AssumeRole,
sts:SetSourceIdentity and sts:TagSession from the account):
``aegis-test-agent``, ``aegis-test-trusted``, ``aegis-test-breakglass``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from aegis_core.compile import pretty_json, write_outputs  # noqa: E402
from aegis_core.compile.aws import AwsTarget, compile_aws, load_action_map  # noqa: E402
from aegis_core.identity import load_identity_model  # noqa: E402
from aegis_core.store import (  # noqa: E402
    Constraint,
    VerifiedSnapshot,
    _canonical,
    _constraint_to_dict,
)

TEST_ROLES = ("aegis-test-agent", "aegis-test-trusted", "aegis-test-breakglass")

# Types exercised by a scoped case instead of the blanket rule.
REGION_CASE = ("dynamodb/table", "us-west-2")  # denied only in us-west-2
NAME_CASE = ("s3/bucket", "aegis-prod-*")  # denied only for matching names
ESCALATE_CASE = "lambda/function"  # ESCALATE compiles to a deny


def _rule(id: str, pattern: str, actions: set[str], effect: str = "BLOCK",
          scope: dict | None = None) -> Constraint:
    return Constraint.create(
        id=id, provider="aws", resource_pattern=pattern, actions=actions, effect=effect,
        constraint_class="deletion", principal="admin", source_ref="aws-acceptance",
        source_timestamp="2026-09-29T00:00:00+00:00", rule_text=f"acceptance: {pattern}",
        scope=scope)


def acceptance_rules() -> list[Constraint]:
    amap = load_action_map()
    rules = []
    for rtype, tm in sorted(amap.items()):
        verbs = set(tm.grants)
        rid = "acc-" + rtype.replace("/", "-")
        if rtype == REGION_CASE[0]:
            rules.append(_rule(rid, f"{rtype}/*", verbs, scope={"region": REGION_CASE[1]}))
        elif rtype == NAME_CASE[0]:
            rules.append(_rule(rid, f"{rtype}/{NAME_CASE[1]}", verbs))
        elif rtype == ESCALATE_CASE:
            rules.append(_rule(rid, f"{rtype}/*", verbs, effect="ESCALATE"))
        else:
            rules.append(_rule(rid, f"{rtype}/*", verbs))
    return rules


def agents_doc(account: str, admin_role_arn: str) -> dict:
    role = f"arn:aws:iam::{account}:role/"
    return {
        "version": 1,
        "principal": "admin",
        "mode": "deny-by-default",
        "enforcement": "enforce",
        "break_glass": [
            {"platform": "aws", "kind": "role", "id": role + "aegis-test-breakglass"},
            {"platform": "aws", "kind": "role", "id": role + "OrganizationAccountAccessRole",
             "note": "the management account's way in"},
        ],
        "trusted": [
            {"platform": "aws", "kind": "role", "id": role + "aegis-test-trusted"},
            {"platform": "aws", "kind": "role", "id": admin_role_arn,
             "note": "the operator's IAM Identity Center admin role (path aws-reserved/...)"},
            {"platform": "aws", "kind": "source-identity", "id": "aegis-test-human"},
        ],
    }


def build(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    agents = out / "agents.yaml"
    agents.write_text(yaml.safe_dump(agents_doc(args.account, args.admin_role_arn),
                                     sort_keys=False))
    model = load_identity_model(agents, authority_map={"admin": {"identity"}}, insecure=True)
    rules = acceptance_rules()
    (out / "constraints.json").write_text(
        pretty_json([_constraint_to_dict(c) for c in rules]))
    records = tuple(_canonical(_constraint_to_dict(c)) for c in rules)
    snap = VerifiedSnapshot._build(records=records, excluded=(), authority=(), inputs=(),
                                   settings=(), aegis_version="aws-acceptance")
    result = compile_aws(snap, model, AwsTarget(account=args.account, env="sandbox"))
    write_outputs(out / "compiled", result.files)
    summary = ", ".join(f"{k}={v}" for k, v in result.coverage["summary"].items())
    print(f"wrote {out}: {len(result.policies)} SCP(s) "
          f"({', '.join(str(p['chars']) for p in result.manifest['policies'])} chars); "
          f"{summary}")
    for w in model.warnings:
        print(f"  warning: {w}")
    return 0


# --- probes ---------------------------------------------------------------------------
#
# One real API call per mapped IAM action, on a resource that does not exist,
# so an allowed call fails with "not found" (or a dry-run pass) and nothing is
# created. "deny-only" probes would create or change something if allowed, so
# they run only as an identity the SCP must deny, and only once it is
# attached; LeaveOrganization is never probed.

NONE = "aegis-probe-none-7013"
IID = "i-0f0000000000000a1"
TRUST = str(REPO / "build" / "aws-acceptance" / "trust.json")
POLICY_DOC = ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject",'
              '"Resource":"*"}]}')
LIFECYCLE = '{"Rules":[{"ID":"x","Status":"Enabled","Filter":{},"Expiration":{"Days":1}}]}'
SSE = '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# (iam action, argv after "aws", region, flags); {acct} is the sandbox account
PROBES: list[tuple[str, str, str, str]] = [
    ("ec2:TerminateInstances", f"ec2 terminate-instances --instance-ids {IID} --dry-run", "", ""),
    ("ec2:StopInstances", f"ec2 stop-instances --instance-ids {IID} --dry-run", "", ""),
    ("ec2:StartInstances", f"ec2 start-instances --instance-ids {IID} --dry-run", "", ""),
    ("ec2:RebootInstances", f"ec2 reboot-instances --instance-ids {IID} --dry-run", "", ""),
    ("ec2:RunInstances", "ec2 run-instances --image-id ami-00000000000000001 "
     "--instance-type t3.micro --dry-run", "", ""),
    ("ec2:ModifyInstanceAttribute", f"ec2 modify-instance-attribute --instance-id {IID} "
     "--disable-api-termination --dry-run", "", ""),
    ("ec2:DeleteVolume", "ec2 delete-volume --volume-id vol-00000000000000001 --dry-run", "", ""),
    ("ec2:DetachVolume", "ec2 detach-volume --volume-id vol-00000000000000001 --dry-run", "", ""),
    ("ec2:DeleteSnapshot", "ec2 delete-snapshot --snapshot-id snap-00000000000000001 --dry-run",
     "", ""),
    ("ec2:DeleteVpc", "ec2 delete-vpc --vpc-id vpc-00000000000000001 --dry-run", "", ""),
    ("ec2:DeleteSecurityGroup", "ec2 delete-security-group --group-id sg-00000000000000001 "
     "--dry-run", "", ""),
    # s3/bucket is scoped to aegis-prod-*: the dev bucket is the negative control
    ("s3:DeleteBucket", "s3api delete-bucket --bucket aegis-prod-probe-{acct}", "", ""),
    ("s3:DeleteBucket@dev", "s3api delete-bucket --bucket aegis-dev-probe-{acct}", "", "control"),
    ("s3:DeleteObject", "s3api delete-object --bucket aegis-prod-probe-{acct} --key k", "", ""),
    ("s3:DeleteObjectVersion", "s3api delete-object --bucket aegis-prod-probe-{acct} --key k "
     "--version-id v1", "", ""),
    ("s3:PutObject", "s3api put-object --bucket aegis-prod-probe-{acct} --key k", "", ""),
    ("s3:PutBucketPolicy", f"s3api put-bucket-policy --bucket aegis-prod-probe-{{acct}} "
     f"--policy '{POLICY_DOC}'", "", ""),
    ("s3:PutBucketAcl", "s3api put-bucket-acl --bucket aegis-prod-probe-{acct} --acl private",
     "", ""),
    ("s3:PutLifecycleConfiguration", "s3api put-bucket-lifecycle-configuration --bucket "
     f"aegis-prod-probe-{{acct}} --lifecycle-configuration '{LIFECYCLE}'", "", ""),
    ("s3:PutBucketVersioning", "s3api put-bucket-versioning --bucket aegis-prod-probe-{acct} "
     "--versioning-configuration Status=Enabled", "", ""),
    ("s3:PutEncryptionConfiguration", "s3api put-bucket-encryption --bucket "
     f"aegis-prod-probe-{{acct}} --server-side-encryption-configuration '{SSE}'", "", ""),
    ("s3:PutBucketPublicAccessBlock", "s3api put-public-access-block --bucket "
     "aegis-prod-probe-{acct} --public-access-block-configuration BlockPublicAcls=true", "", ""),
    ("s3:CreateBucket", "s3api create-bucket --bucket aegis-prod-probe-{acct}", "", "deny-only"),
    ("rds:DeleteDBInstance", f"rds delete-db-instance --db-instance-identifier {NONE} "
     "--skip-final-snapshot", "", ""),
    ("rds:ModifyDBInstance", f"rds modify-db-instance --db-instance-identifier {NONE} "
     "--backup-retention-period 1", "", ""),
    ("rds:StopDBInstance", f"rds stop-db-instance --db-instance-identifier {NONE}", "", ""),
    ("rds:StartDBInstance", f"rds start-db-instance --db-instance-identifier {NONE}", "", ""),
    ("rds:RebootDBInstance", f"rds reboot-db-instance --db-instance-identifier {NONE}", "", ""),
    ("rds:DeleteDBCluster", f"rds delete-db-cluster --db-cluster-identifier {NONE} "
     "--skip-final-snapshot", "", ""),
    ("rds:ModifyDBCluster", f"rds modify-db-cluster --db-cluster-identifier {NONE} "
     "--backup-retention-period 1", "", ""),
    ("rds:DeleteDBSnapshot", f"rds delete-db-snapshot --db-snapshot-identifier {NONE}", "", ""),
    ("rds:DeleteDBClusterSnapshot", "rds delete-db-cluster-snapshot "
     f"--db-cluster-snapshot-identifier {NONE}", "", ""),
    # dynamodb/table is scoped to us-west-2: us-east-1 is the negative control
    ("dynamodb:DeleteTable", f"dynamodb delete-table --table-name {NONE}", "us-west-2", ""),
    ("dynamodb:DeleteTable@us-east-1", f"dynamodb delete-table --table-name {NONE}", "us-east-1",
     "control"),
    ("dynamodb:UpdateTable", f"dynamodb update-table --table-name {NONE} "
     "--billing-mode PAY_PER_REQUEST", "us-west-2", ""),
    ("eks:DeleteCluster", f"eks delete-cluster --name {NONE}", "", ""),
    ("eks:UpdateClusterConfig", f"eks update-cluster-config --name {NONE} "
     "--resources-vpc-config endpointPublicAccess=true", "", ""),
    ("eks:UpdateClusterVersion", f"eks update-cluster-version --name {NONE} "
     "--kubernetes-version 1.33", "", ""),
    ("eks:DeleteNodegroup", f"eks delete-nodegroup --cluster-name {NONE} --nodegroup-name ng",
     "", ""),
    ("eks:UpdateNodegroupConfig", f"eks update-nodegroup-config --cluster-name {NONE} "
     "--nodegroup-name ng --scaling-config minSize=0,maxSize=1,desiredSize=0", "", ""),
    ("eks:UpdateNodegroupVersion", f"eks update-nodegroup-version --cluster-name {NONE} "
     "--nodegroup-name ng", "", ""),
    ("iam:DeleteRole", f"iam delete-role --role-name {NONE}", "", ""),
    ("iam:UpdateRole", f"iam update-role --role-name {NONE} --description d", "", ""),
    ("iam:UpdateRoleDescription", f"iam update-role-description --role-name {NONE} "
     "--description d", "", ""),
    ("iam:AttachRolePolicy", f"iam attach-role-policy --role-name {NONE} --policy-arn "
     "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""),
    ("iam:PutRolePolicy", f"iam put-role-policy --role-name {NONE} --policy-name p "
     f"--policy-document '{POLICY_DOC}'", "", ""),
    ("iam:DetachRolePolicy", f"iam detach-role-policy --role-name {NONE} --policy-arn "
     "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""),
    ("iam:DeleteRolePolicy", f"iam delete-role-policy --role-name {NONE} --policy-name p", "",
     ""),
    ("iam:UpdateAssumeRolePolicy", f"iam update-assume-role-policy --role-name {NONE} "
     f"--policy-document file://{TRUST}", "", ""),
    ("iam:CreateRole", f"iam create-role --role-name {NONE} --assume-role-policy-document "
     f"file://{TRUST}", "", "deny-only"),
    ("iam:DeleteUser", f"iam delete-user --user-name {NONE}", "", ""),
    ("iam:CreateUser", f"iam create-user --user-name {NONE}", "", "deny-only"),
    ("iam:AttachUserPolicy", f"iam attach-user-policy --user-name {NONE} --policy-arn "
     "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""),
    ("iam:PutUserPolicy", f"iam put-user-policy --user-name {NONE} --policy-name p "
     f"--policy-document '{POLICY_DOC}'", "", ""),
    ("iam:DetachUserPolicy", f"iam detach-user-policy --user-name {NONE} --policy-arn "
     "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""),
    ("iam:DeleteUserPolicy", f"iam delete-user-policy --user-name {NONE} --policy-name p", "",
     ""),
    ("iam:CreateAccessKey", f"iam create-access-key --user-name {NONE}", "", ""),
    ("iam:UpdateAccessKey", f"iam update-access-key --user-name {NONE} --access-key-id "
     "AKIAAEGISPROBE000001 --status Inactive", "", ""),
    ("iam:DeleteAccessKey", f"iam delete-access-key --user-name {NONE} --access-key-id "
     "AKIAAEGISPROBE000001", "", ""),
    ("iam:UpdateLoginProfile", f"iam update-login-profile --user-name {NONE} "
     "--password-reset-required", "", ""),
    ("iam:DeleteLoginProfile", f"iam delete-login-profile --user-name {NONE}", "", ""),
    # lambda/function is an ESCALATE rule: it must compile to a deny too
    ("lambda:DeleteFunction", f"lambda delete-function --function-name {NONE}", "", ""),
    ("lambda:UpdateFunctionCode", f"lambda update-function-code --function-name {NONE} "
     "--s3-bucket aegis-probe-bkt --s3-key k", "", ""),
    ("lambda:UpdateFunctionConfiguration", "lambda update-function-configuration "
     f"--function-name {NONE} --timeout 3", "", ""),
    ("cloudformation:DeleteStack", f"cloudformation delete-stack --stack-name {NONE}", "", ""),
    ("cloudformation:UpdateStack", f"cloudformation update-stack --stack-name {NONE} "
     "--template-body {}", "", ""),
    ("kms:DisableKey", "kms disable-key --key-id 00000000-0000-0000-0000-000000000000", "", ""),
    ("kms:ScheduleKeyDeletion", "kms schedule-key-deletion --key-id "
     "00000000-0000-0000-0000-000000000000", "", ""),
    ("secretsmanager:DeleteSecret", f"secretsmanager delete-secret --secret-id {NONE}", "", ""),
    ("secretsmanager:UpdateSecret", f"secretsmanager update-secret --secret-id {NONE} "
     "--description d", "", ""),
    ("secretsmanager:PutSecretValue", f"secretsmanager put-secret-value --secret-id {NONE} "
     "--secret-string probe", "", ""),
    ("logs:DeleteLogGroup", f"logs delete-log-group --log-group-name {NONE}", "", ""),
    ("ecr:DeleteRepository", f"ecr delete-repository --repository-name {NONE}", "", ""),
    ("autoscaling:DeleteAutoScalingGroup", "autoscaling delete-auto-scaling-group "
     f"--auto-scaling-group-name {NONE}", "", ""),
    ("autoscaling:SetDesiredCapacity", "autoscaling set-desired-capacity "
     f"--auto-scaling-group-name {NONE} --desired-capacity 0", "", ""),
    ("autoscaling:UpdateAutoScalingGroup", "autoscaling update-auto-scaling-group "
     f"--auto-scaling-group-name {NONE} --max-size 1", "", ""),
    ("ecs:DeleteCluster", f"ecs delete-cluster --cluster {NONE}", "", ""),
    ("ecs:DeleteService", f"ecs delete-service --cluster {NONE} --service s", "", ""),
    ("ecs:UpdateService", f"ecs update-service --cluster {NONE} --service s --desired-count 0",
     "", ""),
    ("elasticloadbalancing:DeleteLoadBalancer", "elbv2 delete-load-balancer --load-balancer-arn "
     "arn:aws:elasticloadbalancing:us-east-1:{acct}:loadbalancer/app/aegis-probe/"
     "0000000000000000", "", ""),
    ("route53:DeleteHostedZone", "route53 delete-hosted-zone --id Z0000000000AEGISPROBE", "",
     ""),
    ("elasticfilesystem:DeleteFileSystem", "efs delete-file-system --file-system-id "
     "fs-00000000", "", ""),
    ("sns:DeleteTopic", f"sns delete-topic --topic-arn arn:aws:sns:us-east-1:{{acct}}:{NONE}",
     "", ""),
    ("sqs:DeleteQueue", "sqs delete-queue --queue-url "
     f"https://sqs.us-east-1.amazonaws.com/{{acct}}/{NONE}", "", ""),
    ("elasticache:DeleteCacheCluster", f"elasticache delete-cache-cluster --cache-cluster-id "
     f"{NONE}", "", ""),
    # self-protection
    ("sts:AssumeRole@trusted", "sts assume-role --role-arn "
     "arn:aws:iam::{acct}:role/aegis-test-trusted --role-session-name probe", "", "deny-only"),
    ("sts:AssumeRole@breakglass", "sts assume-role --role-arn "
     "arn:aws:iam::{acct}:role/aegis-test-breakglass --role-session-name probe", "",
     "deny-only"),
    ("sts:AssumeRole@agent", "sts assume-role --role-arn "
     "arn:aws:iam::{acct}:role/aegis-test-agent --role-session-name probe", "", "control"),
    ("sts:SetSourceIdentity", "sts assume-role --role-arn "
     "arn:aws:iam::{acct}:role/aegis-test-agent --role-session-name probe "
     "--source-identity aegis-test-human", "", "deny-only"),
    ("iam:UpdateAssumeRolePolicy@trusted", "iam update-assume-role-policy --role-name "
     f"aegis-test-trusted --policy-document file://{TRUST}", "", "deny-only"),
]

DENIED_CODES = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                "AuthorizationError", "AuthorizationErrorException", "UnauthorizedException")


def _classify(returncode: int, stderr: str) -> tuple[str, str]:
    import re

    m = re.search(r"An error occurred \(([^)]+)\)", stderr)
    code = m.group(1) if m else ("ok" if returncode == 0 else "error")
    if code == "DryRunOperation":
        return "allowed", code
    if code in DENIED_CODES or "not authorized to perform" in stderr:
        return "denied", code
    return "allowed", code


def _session(profile: str, role_arn: str | None, source_identity: str | None) -> dict:
    """Environment for a probe identity: the profile itself, or a role
    assumed from it (optionally with a source identity)."""
    import os
    import subprocess

    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["AWS_PAGER"] = ""
    env["AWS_PROFILE"] = profile
    if role_arn is None:
        return env
    argv = ["aws", "sts", "assume-role", "--role-arn", role_arn, "--role-session-name",
            "aegis-probe", "--output", "json"]
    if source_identity:
        argv += ["--source-identity", source_identity]
    out = subprocess.run(argv, env=env, capture_output=True, text=True, check=True)
    creds = json.loads(out.stdout)["Credentials"]
    env.pop("AWS_PROFILE")
    env.update(AWS_ACCESS_KEY_ID=creds["AccessKeyId"],
               AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
               AWS_SESSION_TOKEN=creds["SessionToken"])
    return env


def probe(args: argparse.Namespace) -> int:
    import shlex
    import subprocess
    from concurrent.futures import ThreadPoolExecutor

    acct, role = args.account, f"arn:aws:iam::{args.account}:role/"
    # name -> (role to assume or None for the profile, source identity, expected-denied)
    identities = {
        "agent": (role + "aegis-test-agent", None, True),
        "agent+untrusted-si": (role + "aegis-test-agent", "aegis-test-mallory", True),
        "agent+trusted-si": (role + "aegis-test-agent", "aegis-test-human", False),
        "trusted": (role + "aegis-test-trusted", None, False),
        "breakglass": (role + "aegis-test-breakglass", None, False),
        "admin-sso": (None, None, False),
    }
    envs = {name: _session(args.profile, r, si) for name, (r, si, _) in identities.items()}
    attached = args.phase == "attached"
    jobs = []
    for action, cmd, region, flag in PROBES:
        for name, (_, _, restricted) in identities.items():
            if flag == "deny-only" and not (attached and restricted):
                continue
            expect_denied = attached and restricted and flag != "control"
            jobs.append((action, cmd, region or "us-east-1", name, expect_denied))

    def run(job):
        action, cmd, region, name, expect_denied = job
        argv = ["aws", *shlex.split(cmd.replace("{acct}", acct)), "--region", region,
                "--output", "json", "--cli-read-timeout", "20"]
        proc = subprocess.run(argv, env=envs[name], capture_output=True, text=True)
        outcome, code = _classify(proc.returncode, proc.stderr)
        scp = "service control policy" in proc.stderr
        return {"action": action, "identity": name, "region": region, "outcome": outcome,
                "code": code, "scp_named": scp, "expected": "denied" if expect_denied
                else "allowed", "pass": (outcome == "denied") == expect_denied,
                "stderr": proc.stderr.strip()[:400]}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, jobs))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"probe-{args.phase}.json"
    path.write_text(pretty_json(results))
    failed = [r for r in results if not r["pass"]]
    print(f"{args.phase}: {len(results)} probes, {len(results) - len(failed)} as expected, "
          f"{len(failed)} not -> {path}")
    for r in failed:
        print(f"  UNEXPECTED {r['action']:<42} {r['identity']:<20} {r['outcome']:<8} "
              f"{r['code']}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="write agents.yaml, the test rules and compiled SCPs")
    b.add_argument("--account", required=True)
    b.add_argument("--admin-role-arn", required=True)
    b.add_argument("--out", default="build/aws-acceptance")
    pr = sub.add_parser("probe", help="run the probes against the sandbox (read the "
                        "module docstring first); --phase baseline before attaching")
    pr.add_argument("--account", required=True)
    pr.add_argument("--profile", required=True, help="the sandbox admin profile")
    pr.add_argument("--phase", choices=("baseline", "attached"), required=True)
    pr.add_argument("--out", default="build/aws-acceptance")
    args = ap.parse_args(argv)
    return build(args) if args.cmd == "build" else probe(args)


if __name__ == "__main__":
    sys.exit(main())
