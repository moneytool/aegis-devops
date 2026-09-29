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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="write agents.yaml, the test rules and compiled SCPs")
    b.add_argument("--account", required=True)
    b.add_argument("--admin-role-arn", required=True)
    b.add_argument("--out", default="build/aws-acceptance")
    args = ap.parse_args(argv)
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
