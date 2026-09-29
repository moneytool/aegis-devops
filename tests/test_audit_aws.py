"""aegis audit-identity aws: agents.yaml against the IAM identities that
exist (design v0.3, §4.2, §4.3). Offline, on inventory fixtures shaped like
``aws iam get-account-authorization-details``."""

import json
import shutil

import pytest
import yaml

from aegis_core.audit_aws import audit, github_trust_findings
from aegis_core.cli import main
from aegis_core.identity import load_identity_model
from aegis_core.signing import load_key, sign_file

ACCT = "123456789012"
ROLE = f"arn:aws:iam::{ACCT}:role/"
SSO = ROLE + "aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef"


def _trust(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(principal):
    return {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}


def _github(condition=None):
    st = {"Effect": "Allow",
          "Principal": {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/"
                                     "token.actions.githubusercontent.com"},
          "Action": "sts:AssumeRoleWithWebIdentity"}
    if condition:
        st["Condition"] = condition
    return st


def _role(name, trust=None, path="/", last_used=None):
    arn = f"arn:aws:iam::{ACCT}:role{path}{name}"
    d = {"Arn": arn, "RoleName": name, "Path": path,
         "AssumeRolePolicyDocument": trust or _trust(_allow({"Service": "ec2.amazonaws.com"}))}
    if last_used:
        d["RoleLastUsed"] = {"LastUsedDate": last_used}
    return d


def _inventory(*roles, users=()):
    return {"RoleDetailList": list(roles),
            "UserDetailList": [{"Arn": f"arn:aws:iam::{ACCT}:user/{u}", "UserName": u,
                                "Path": "/"} for u in users]}


def _model(tmp_path, **fields):
    doc = {"principal": "admin",
           "break_glass": [{"platform": "aws", "kind": "role", "id": ROLE + "BreakGlass"}],
           "trusted": [{"platform": "aws", "kind": "role", "id": ROLE + "Deploy"},
                       {"platform": "aws", "kind": "role", "id": SSO}],
           **fields}
    doc = {k: v for k, v in doc.items() if v is not None}
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(doc))
    return load_identity_model(path, authority_map={"admin": {"identity"}}, insecure=True)


BASE = (
    _role("BreakGlass"),
    _role("Deploy"),
    _role("AWSReservedSSO_Admin_0123456789abcdef", path="/aws-reserved/sso.amazonaws.com/"),
    _role("nightly-backup", last_used="2026-09-27T02:00:00+00:00"),
    _role("coding-agent"),
    _role("AWSServiceRoleForSupport", path="/aws-service-role/support.amazonaws.com/"),
)


def test_would_restrict_lists_every_unlisted_identity_for_review(tmp_path):
    r = audit(_inventory(*BASE, users=["ops-bot"]), _model(tmp_path))
    assert r.account == ACCT
    assert [x["arn"] for x in r.would_restrict] == [
        ROLE + "coding-agent", ROLE + "nightly-backup", f"arn:aws:iam::{ACCT}:user/ops-bot"]
    backup = next(x for x in r.would_restrict if x["arn"].endswith("nightly-backup"))
    assert backup["last_used"] == "2026-09-27T02:00:00+00:00"  # legitimate automation to trust
    assert {x["arn"] for x in r.exempt} == {ROLE + "BreakGlass", ROLE + "Deploy", SSO}
    assert r.service_linked == [f"{ROLE}aws-service-role/support.amazonaws.com/"
                                "AWSServiceRoleForSupport"]
    assert not r.problems


def test_hints_for_sso_and_org_access_roles(tmp_path):
    model = _model(tmp_path, trusted=[{"platform": "aws", "kind": "role", "id": ROLE + "Deploy"}])
    r = audit(_inventory(*BASE, _role("OrganizationAccountAccessRole")), model)
    hints = {x["arn"]: x.get("hint") for x in r.would_restrict}
    assert "Identity Center" in hints[SSO]
    assert "break-glass" in hints[ROLE + "OrganizationAccountAccessRole"]


def test_agents_only_restricts_only_listed_agents(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None,
                   agents=[{"platform": "aws", "kind": "role", "id": ROLE + "coding-agent"}])
    r = audit(_inventory(*BASE), model)
    assert [x["arn"] for x in r.would_restrict] == [ROLE + "coding-agent"]


def test_missing_break_glass_is_a_problem(tmp_path):
    model = _model(tmp_path, break_glass=[
        {"platform": "aws", "kind": "role", "id": ROLE + "BreakGlas"},  # typo
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::999999999999:role/Other"}])
    r = audit(_inventory(*BASE), model)
    assert [m["arn"] for m in r.missing] == [ROLE + "BreakGlas"]  # other accounts not judged
    assert "no working break-glass" in r.missing[0]["detail"]
    assert r.problems


def test_missing_agent_in_agents_only_is_reported(tmp_path):
    model = _model(tmp_path, mode="agents-only", trusted=None,
                   agents=[{"platform": "aws", "kind": "role", "id": ROLE + "coding-agnet"}])
    r = audit(_inventory(*BASE), model)
    assert r.missing[0]["listed_as"] == "agents" and r.problems


@pytest.mark.parametrize("condition, kind", [
    (None, "oidc-no-subject"),
    ({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
     "oidc-no-subject"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*:*"}},
     "oidc-wildcard-subject"),
    ({"StringEquals": {"token.actions.githubusercontent.com:sub":
                       "repo:acme/app:ref:refs/heads/main"}}, "workflow-unbound"),
])
def test_github_trust_problems(condition, kind):
    (f,) = github_trust_findings(_trust(_github(condition)))
    assert f["kind"] == kind


@pytest.mark.parametrize("condition, kind", [
    # review of #18: negated / optional / vacuous operators never bind
    ({"StringNotEquals": {"token.actions.githubusercontent.com:sub":
                          "repo:acme/app:environment:prod"}}, "oidc-unsafe-condition"),
    ({"StringLikeIfExists": {"token.actions.githubusercontent.com:sub":
                             "repo:acme/app:environment:prod"}}, "oidc-unsafe-condition"),
    ({"ForAllValues:StringEquals": {"token.actions.githubusercontent.com:sub":
                                    "repo:acme/app:environment:prod"}},
     "oidc-unsafe-condition"),
    ({"Null": {"token.actions.githubusercontent.com:sub": "false"}}, "oidc-unsafe-condition"),
    # review of #18: wildcard bindings expand past the protected boundary
    ({"StringLike": {"token.actions.githubusercontent.com:sub":
                     "repo:acme/app:environment:*"}}, "wildcard-binding"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub":
                     "repo:acme/app:job_workflow_ref:acme/app/.github/workflows/*"
                     "@refs/heads/main"}}, "wildcard-binding"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub":
                     "repo:acme/app:job_workflow_ref:acme/app/.github/workflows/deploy.yml"
                     "@refs/heads/*"}}, "wildcard-binding"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/app:ref:main",
                     "token.actions.githubusercontent.com:environment": "prod*"}},
     "wildcard-binding"),
])
def test_unsafe_operators_and_wildcard_bindings_are_findings(condition, kind):
    kinds = [f["kind"] for f in github_trust_findings(_trust(_github(condition)))]
    assert kind in kinds


def test_negated_binding_on_an_exempt_role_is_a_problem(tmp_path):
    trust = _trust(_github({"StringNotEquals": {
        "token.actions.githubusercontent.com:sub": "repo:acme/app:environment:prod"}}))
    r = audit(_inventory(_role("BreakGlass"), _role("Deploy", trust), BASE[2]),
              _model(tmp_path))
    assert [f["severity"] for f in r.findings if f["role"] == ROLE + "Deploy"] == ["high"]
    assert r.problems


@pytest.mark.parametrize("condition", [
    {"StringEquals": {"token.actions.githubusercontent.com:sub":
                      "repo:acme/app:environment:prod"}},
    {"StringEquals": {"token.actions.githubusercontent.com:sub":
                      "repo:acme/app:job_workflow_ref:acme/app/.github/workflows/deploy.yml"
                      "@refs/heads/main"}},
    {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme/app:ref:main",
                      "token.actions.githubusercontent.com:job_workflow_ref":
                      "acme/app/.github/workflows/deploy.yml@refs/heads/main"}},
])
def test_workflow_bound_github_trust_is_fine(condition):
    assert github_trust_findings(_trust(_github(condition))) == []


def test_unbound_github_trust_on_an_exempt_role_is_a_problem(tmp_path):
    unbound = _trust(_github({"StringLike": {"token.actions.githubusercontent.com:sub":
                                             "repo:acme/app:ref:refs/heads/main"}}))
    r = audit(_inventory(_role("BreakGlass"), _role("Deploy", unbound),
                         _role("coding-agent", unbound)), _model(tmp_path))
    by_role = {f["role"]: f for f in r.findings}
    assert by_role[ROLE + "Deploy"]["severity"] == "high"  # an agent job can become Deploy
    assert by_role[ROLE + "coding-agent"]["severity"] == "info"  # still restricted
    assert r.problems


def test_exempt_role_trusting_restricted_identities(tmp_path):
    trust = _trust(_allow({"AWS": [ROLE + "coding-agent", f"arn:aws:iam::{ACCT}:root"]}))
    report_only = audit(_inventory(_role("BreakGlass"), _role("Deploy", trust),
                                   _role("coding-agent")), _model(tmp_path))
    kinds = {f["kind"]: f["severity"] for f in report_only.findings}
    assert kinds == {"exempt-trusts-restricted": "high", "exempt-trusts-account": "high"}
    enforced = audit(_inventory(_role("BreakGlass"), _role("Deploy", trust),
                                _role("coding-agent"), BASE[2]),
                     _model(tmp_path, enforcement="enforce"))
    assert {f["severity"] for f in enforced.findings} == {"info"}  # the SCP closes both
    assert not enforced.problems


def test_url_encoded_trust_documents_are_read(tmp_path):
    from urllib.parse import quote

    doc = quote(json.dumps(_trust(_github())))
    r = audit(_inventory(_role("BreakGlass"), _role("Deploy", doc)), _model(tmp_path))
    assert r.findings[0]["kind"] == "oidc-no-subject"


def test_cli_audit_from_a_saved_inventory(tmp_path, monkeypatch, capsys):
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    model_doc = yaml.safe_load((d / "agents.example.yaml").read_text())
    model_doc["break_glass"][1]["id"] = ROLE + "BreakGlass"
    model_doc["trusted"] = [{"platform": "aws", "kind": "role", "id": ROLE + "Deploy"}]
    (d / "agents.yaml").write_text(yaml.safe_dump(model_doc))
    sign_file(d / "agents.yaml", key)
    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps(_inventory(*BASE)))
    assert main(["audit-identity", "aws", "--config-dir", str(d), "--inventory", str(inv),
                 "--would-restrict"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["account"] == ACCT
    assert ROLE + "nightly-backup" in [x["arn"] for x in doc["would_restrict"]]
    assert main(["audit-identity", "aws", "--config-dir", str(d), "--inventory", str(inv),
                 "--pretty"]) == 0
    out = capsys.readouterr().out
    assert "would restrict (3)" in out and "service-linked" in out
    (d / "agents.yaml").unlink()
    assert main(["audit-identity", "aws", "--config-dir", str(d), "--inventory",
                 str(inv)]) == 66


def test_negated_extra_condition_next_to_a_precise_binding_is_fine():
    """Conditions are ANDed: excluding a value on top of a precise required
    binding only narrows it."""
    condition = {
        "StringEquals": {"token.actions.githubusercontent.com:sub":
                         "repo:acme/app:environment:prod"},
        "StringNotEquals": {"token.actions.githubusercontent.com:sub":
                            "repo:acme/app:environment:staging"},
    }
    assert github_trust_findings(_trust(_github(condition))) == []
