"""agents.yaml: the identity model server-side enforcement compiles for
(design v0.3, §4)."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from aegis_core.cli import main
from aegis_core.identity import Identity, load_identity_model
from aegis_core.signing import SignatureError, load_key, sign_file

AUTHORITY = {"admin": {"deletion", "identity"}, "developer": {"configuration"}}
BREAK_GLASS = [{"platform": "kubernetes", "kind": "group", "id": "aegis:break-glass"}]


def _write(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def _load(tmp_path: Path, **fields):
    doc = {"version": 1, "principal": "admin", "break_glass": BREAK_GLASS, **fields}
    doc = {k: v for k, v in doc.items() if v is not None}
    return load_identity_model(_write(tmp_path, doc), authority_map=AUTHORITY, insecure=True)


def _error(tmp_path: Path, **fields) -> str:
    with pytest.raises(ValueError) as exc:
        _load(tmp_path, **fields)
    return str(exc.value)


# --- the example ----------------------------------------------------------------


def test_example_loads_under_the_example_key_with_no_warnings():
    key = load_key("file:data/example-signing.key")
    authority = yaml.safe_load(Path("data/authority.example.yaml").read_text())["principals"]
    model = load_identity_model("data/agents.example.yaml", key=key,
                                authority_map={p: set(c) for p, c in authority.items()})
    assert model.mode == "deny-by-default" and model.enforcement == "report-only"
    assert model.warnings == ()
    assert model.platforms == ("kubernetes", "aws", "github")
    for platform in ("kubernetes", "aws"):
        model.require_platform(platform)


def test_example_is_never_picked_up_as_the_live_file():
    """Unlike the other examples, agents.example.yaml must not become active
    by sitting in a config dir: the snapshot and compilers read agents.yaml."""
    from aegis_core import config

    fields = config.ResolvedConfig.__dataclass_fields__
    assert not any("agents" in name for name in fields)


# --- defaults and modes ---------------------------------------------------------


def test_defaults_are_deny_by_default_and_report_only(tmp_path):
    model = _load(tmp_path)
    assert (model.mode, model.enforcement) == ("deny-by-default", "report-only")


def test_deny_by_default_treats_every_unlisted_identity_as_an_agent(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "kubernetes", "kind": "user", "id": "alice@example.com"},
        {"platform": "kubernetes", "kind": "group", "id": "platform-admins"},
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "argocd:controller"},
    ])
    assert model.is_agent("kubernetes", [("user", "someone-new")])
    assert model.is_agent("kubernetes", [("user", "system:serviceaccount:agents:coder"),
                                         ("group", "system:serviceaccounts:agents")])
    assert not model.is_agent("kubernetes", [("user", "alice@example.com")])
    assert not model.is_agent("kubernetes", [("user", "bob"), ("group", "platform-admins")])
    # a ServiceAccount presents itself as a user name
    assert not model.is_agent("kubernetes", [("user", "system:serviceaccount:argocd:controller")])
    assert not model.is_agent("kubernetes", [("user", "x"), ("group", "aegis:break-glass")])
    # identities from another platform never exempt this one
    assert model.is_agent("aws", [("role", "arn:aws:iam::111122223333:role/Deploy")])


def test_agents_only_restricts_only_the_listed_agents(tmp_path):
    model = _load(tmp_path, mode="agents-only", agents=[
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "aegis-agents:coder"},
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/Agent"},
    ])
    assert model.is_agent("kubernetes", [("user", "system:serviceaccount:aegis-agents:coder")])
    assert not model.is_agent("kubernetes", [("user", "anyone-else")])
    assert model.is_agent("aws", [("role", "arn:aws:iam::111122223333:role/Agent")])
    assert [str(i) for i in model.agents_for("aws")] == [
        "aws/role arn:aws:iam::111122223333:role/Agent"]


def test_break_glass_wins_over_an_agent_listing(tmp_path):
    model = _load(tmp_path, mode="agents-only", agents=[
        {"platform": "kubernetes", "kind": "user", "id": "ops"}])
    assert not model.is_agent("kubernetes", [("user", "ops"), ("group", "aegis:break-glass")])


def test_exempt_lists_break_glass_first_then_trusted(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "kubernetes", "kind": "group", "id": "platform-admins"},
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/Deploy"}])
    assert [i.id for i in model.exempt("kubernetes")] == ["aegis:break-glass", "platform-admins"]
    only = _load(tmp_path, mode="agents-only", agents=[
        {"platform": "kubernetes", "kind": "user", "id": "coder"}])
    assert [i.id for i in only.exempt("kubernetes")] == ["aegis:break-glass"]


def test_deny_by_default_has_no_agent_list_to_fail_open_with(tmp_path):
    with pytest.raises(ValueError, match="no agent list"):
        _load(tmp_path).agents_for("kubernetes")


def test_require_platform_refuses_a_platform_with_no_break_glass(tmp_path):
    model = _load(tmp_path)
    model.require_platform("kubernetes")
    with pytest.raises(ValueError, match="no break-glass identity for aws"):
        model.require_platform("aws")
    with pytest.raises(ValueError, match="unknown platform"):
        model.require_platform("azure")


def test_model_is_immutable(tmp_path):
    model = _load(tmp_path)
    with pytest.raises(AttributeError):
        model.mode = "agents-only"  # type: ignore[misc]
    assert isinstance(model.trusted, tuple) and isinstance(model.break_glass, tuple)


# --- load errors -----------------------------------------------------------------


@pytest.mark.parametrize("fields, needle", [
    ({"mode": "allow-list"}, "mode must be one of"),
    ({"enforcement": "on"}, "enforcement must be one of"),
    ({"version": 2}, "unsupported version"),
    ({"principal": None}, "'principal' is required"),
    ({"principal": "developer"}, "does not hold the 'identity' class"),
    ({"principal": "nobody"}, "does not hold the 'identity' class"),
    ({"break_glass": []}, "'break_glass' must name at least one"),
    ({"break_glass": None}, "'break_glass' must name at least one"),
    ({"agents": [{"platform": "kubernetes", "kind": "user", "id": "a"}]},
     "list 'trusted' identities, not 'agents'"),
    ({"mode": "agents-only"}, "needs at least one entry in 'agents'"),
    ({"mode": "agents-only", "trusted": [{"platform": "kubernetes", "kind": "user", "id": "a"}],
      "agents": [{"platform": "kubernetes", "kind": "user", "id": "b"}]},
     "'trusted' has no effect"),
    ({"extra": 1}, "unknown field"),
    ({"trusted": "alice"}, "'trusted' must be a list"),
])
def test_shape_errors(tmp_path, fields, needle):
    assert needle in _error(tmp_path, **fields)


@pytest.mark.parametrize("entry, needle", [
    ({"platform": "azure", "kind": "user", "id": "a"}, "platform must be one of"),
    ({"platform": "aws", "kind": "group", "id": "a"}, "aws kind must be one of"),
    ({"platform": "aws", "kind": "role", "id": ""}, "non-empty string 'id'"),
    ({"platform": "aws", "kind": "role", "id": "Deploy"}, "not an IAM role ARN"),
    ({"platform": "aws", "kind": "role",
      "id": "arn:aws:sts::111122223333:assumed-role/Deploy/session"}, "assumed-role session"),
    ({"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/*"},
     "wildcards are not allowed"),
    ({"platform": "aws", "kind": "user", "id": "arn:aws:iam::1:user/a"}, "not an IAM user ARN"),
    ({"platform": "aws", "kind": "source-identity", "id": "a b"}, "SourceIdentity"),
    ({"platform": "kubernetes", "kind": "serviceaccount", "id": "coder"},
     "expected <namespace>:<name>"),
    ({"platform": "kubernetes", "kind": "serviceaccount", "id": "Agents:coder"},
     "expected <namespace>:<name>"),
    ({"platform": "kubernetes", "kind": "group", "id": "system:authenticated"},
     "every identity carries this group"),
    ({"platform": "kubernetes", "kind": "group", "id": "system:serviceaccounts"},
     "every identity carries this group"),
    ({"platform": "gcp", "kind": "serviceaccount", "id": "deploy@example.com"},
     "not a service account email"),
    ({"platform": "gcp", "kind": "user", "id": "alice"}, "not an email address"),
    ({"platform": "github", "kind": "oidc-subject", "id": "repo"}, "not an OIDC subject"),
    ({"platform": "github", "kind": "oidc-subject", "id": "repo:org/*:ref:refs/heads/main"},
     "wildcards"),
    ({"platform": "kubernetes", "kind": "user", "id": "a", "role": "x"}, "unknown field"),
    ("alice", "must be a mapping"),
])
def test_identity_errors(tmp_path, entry, needle):
    assert needle in _error(tmp_path, trusted=[entry])


def test_universal_groups_may_not_be_break_glass_either(tmp_path):
    msg = _error(tmp_path, break_glass=[
        {"platform": "kubernetes", "kind": "group", "id": "system:authenticated"}])
    assert "every identity carries this group" in msg


def test_a_duplicate_identity_is_a_load_error_not_a_guess(tmp_path):
    msg = _error(tmp_path, trusted=[{"platform": "kubernetes", "kind": "group",
                                     "id": "aegis:break-glass"}])
    assert "listed twice (break_glass and trusted;" in msg
    msg = _error(tmp_path, trusted=[
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/Deploy"},
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/DEPLOY"}])
    assert "listed twice" in msg
    # the ServiceAccount spelled as its user name is the same identity
    msg = _error(tmp_path, trusted=[
        {"platform": "kubernetes", "kind": "serviceaccount", "id": "ci:deployer"},
        {"platform": "kubernetes", "kind": "user", "id": "system:serviceaccount:ci:deployer"}])
    assert "listed twice" in msg


def test_serviceaccount_user_names_are_normalised(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "kubernetes", "kind": "user", "id": "system:serviceaccount:ci:deployer"}])
    (ident,) = model.trusted
    assert (ident.kind, ident.id) == ("serviceaccount", "ci:deployer")
    assert ident.kubernetes_username == "system:serviceaccount:ci:deployer"
    assert Identity("kubernetes", "group", "g").kubernetes_username is None


def test_aws_partitions_and_role_paths(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "aws", "kind": "role",
         "id": "arn:aws-us-gov:iam::111122223333:role/a/b/Deploy"},
        {"platform": "aws", "kind": "role", "id": "arn:aws-cn:iam::111122223333:role/Deploy"}])
    assert len(model.trusted) == 2


# --- warnings --------------------------------------------------------------------


def test_workflow_unbound_github_subject_is_flagged(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "github", "kind": "oidc-subject", "id": "repo:org/app:ref:refs/heads/main"},
        {"platform": "github", "kind": "oidc-subject", "id": "repo:org/app:environment:prod"},
        {"platform": "github", "kind": "oidc-subject",
         "id": "repo:org/app:job_workflow_ref:org/app/.github/workflows/d.yml@refs/heads/main"}])
    assert [w.split(" ")[0:2] for w in model.warnings] == [
        ["workflow-unbound:", "repo:org/app:ref:refs/heads/main"]]


def test_platform_listed_without_break_glass_is_flagged(tmp_path):
    model = _load(tmp_path, trusted=[
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/Deploy"},
        {"platform": "github", "kind": "oidc-subject", "id": "repo:o/a:environment:prod"}])
    assert model.warnings == (
        "no-break-glass: aws has listed identities but no break-glass identity",)


def test_unsigned_without_a_key_is_a_warning_and_a_bad_signature_is_an_error(tmp_path):
    path = _write(tmp_path, {"principal": "admin", "break_glass": BREAK_GLASS})
    model = load_identity_model(path, authority_map=AUTHORITY)
    assert model.warnings == (f"unsigned: {path}",)
    key = load_key("file:data/example-signing.key")
    sign_file(path, key)
    load_identity_model(path, authority_map=AUTHORITY, key=key)
    path.write_text(path.read_text() + "\ntrusted: [{platform: kubernetes, kind: user, id: m}]\n")
    with pytest.raises(SignatureError):
        load_identity_model(path, authority_map=AUTHORITY, key=key)


# --- aegis agents ------------------------------------------------------------------


@pytest.fixture
def policy_dir(tmp_path, monkeypatch):
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    return d, key


def _cli(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr()


def test_agents_cli_prints_the_model(policy_dir, capsys):
    d, key = policy_dir
    shutil.copy(d / "agents.example.yaml", d / "agents.yaml")
    sign_file(d / "agents.yaml", key)
    code, out = _cli(["agents", "--config-dir", str(d)], capsys)
    assert code == 0
    doc = json.loads(out.out)
    assert doc["mode"] == "deny-by-default" and doc["principal"] == "admin"
    assert {i["platform"] for i in doc["break_glass"]} == {"kubernetes", "aws"}
    code, out = _cli(["agents", "--config-dir", str(d), "--pretty"], capsys)
    assert code == 0
    assert "break-glass  group            aegis:break-glass" in out.out
    assert "every other identity is treated as an agent" in out.out


def test_agents_cli_exit_codes(policy_dir, capsys):
    d, key = policy_dir
    code, out = _cli(["agents", "--config-dir", str(d)], capsys)
    assert code == 66  # no agents.yaml: the example is never used in its place
    text = (d / "agents.example.yaml").read_text().replace(
        "job_workflow_ref:example-org/app/.github/workflows/deploy.yml@refs/heads/main",
        "ref:refs/heads/main")
    (d / "agents.yaml").write_text(text)
    code, out = _cli(["agents", "--config-dir", str(d)], capsys)
    assert code == 65  # edited after signing: the example .sig does not cover it
    sign_file(d / "agents.yaml", key)
    code, out = _cli(["agents", "--config-dir", str(d)], capsys)
    assert code == 1 and "workflow-unbound" in out.out
    code, out = _cli(["agents", "--config-dir", str(d), "--agents", str(d / "missing.yaml")],
                     capsys)
    assert code == 66


def test_agents_cli_explicit_path(policy_dir, capsys):
    d, key = policy_dir
    other = d / "elsewhere.yaml"
    shutil.copy(d / "agents.example.yaml", other)
    sign_file(other, key)
    code, out = _cli(["agents", "--config-dir", str(d), "--agents", str(other)], capsys)
    assert code == 0 and json.loads(out.out)["path"] == str(other)


def test_arn_matching_is_case_sensitive_like_the_compiled_policy(tmp_path):
    """Review of #16: ARN condition operators are case-sensitive, so a
    mis-cased entry must not exempt (or restrict) what an artifact would not."""
    model = _load(tmp_path, trusted=[
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/deploy"},
        {"platform": "aws", "kind": "user", "id": "arn:aws:iam::111122223333:user/ops"}])
    assert model.is_agent("aws", [("role", "arn:aws:iam::111122223333:role/Deploy")])
    assert model.is_agent("aws", [("user", "arn:aws:iam::111122223333:user/OPS")])
    assert not model.is_agent("aws", [("role", "arn:aws:iam::111122223333:role/deploy")])
    only = _load(tmp_path, mode="agents-only", agents=[
        {"platform": "aws", "kind": "role", "id": "arn:aws:iam::111122223333:role/agent"}])
    assert not only.is_agent("aws", [("role", "arn:aws:iam::111122223333:role/Agent")])


def test_workflow_unbound_break_glass_subject_is_rejected(tmp_path):
    """Review of #16: break-glass is the strongest exemption, so a
    repository/ref-scoped GitHub subject there is a load error, not silence."""
    msg = _error(tmp_path, break_glass=[
        *BREAK_GLASS,
        {"platform": "github", "kind": "oidc-subject", "id": "repo:org/app:ref:refs/heads/main"}])
    assert "break_glass" in msg and "repository/ref" in msg
    model = _load(tmp_path, break_glass=[
        *BREAK_GLASS,
        {"platform": "github", "kind": "oidc-subject", "id": "repo:org/app:environment:prod"}])
    assert model.warnings == ()
