"""``aegis report aws`` (PLAN §7.12): denials by the compiled SCPs, from CloudTrail.

Error messages follow the IAM user guide's "Access denied error message
examples" (checked 2026-10-08): ``with an explicit deny in a service control
policy``, sometimes followed by the policy ARN."""

import gzip
import json
import shutil
from datetime import UTC, datetime, timedelta

import pytest

from aegis_core.cli import main
from aegis_core.report_aws import (
    SCP_DENY,
    EventsError,
    load_compiled,
    read_events,
    render,
    report,
)
from aegis_core.signing import load_key, sign_file

ACCOUNT = "123456789012"
ORG_POLICY = "arn:aws:organizations::999988887777:policy/o-exampleorg/service_control_policy/"
AEGIS_ID = "p-aegis0001"
AGENT = f"arn:aws:iam::{ACCOUNT}:role/coder-agent"
TEST_ROLE = f"arn:aws:iam::{ACCOUNT}:role/aegis-test-agent"
NOW = datetime(2026, 10, 11, 12, tzinfo=UTC)


@pytest.fixture
def compiled(tmp_path, monkeypatch):
    """`aegis compile aws` of the example policy, with enforcement on (deployable)."""
    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    text = (d / "agents.example.yaml").read_text().replace("enforcement: report-only",
                                                           "enforcement: enforce")
    (d / "agents.yaml").write_text(text)
    sign_file(d / "agents.yaml", key)
    out = tmp_path / "out"
    assert main(["compile", "aws", "--config-dir", str(d), "--account", ACCOUNT,
                 "--out", str(out)]) == 0
    return out


def denial(when: datetime, source: str, name: str, *, role: str = AGENT,
           policy_id: str | None = AEGIS_ID, scp: bool = True, code: str = "AccessDenied",
           message: str | None = None) -> dict:
    session = role.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/") + "/s"
    if message is None:
        message = (f"User: {session} is not authorized to perform: "
                   f"{source.split('.')[0]}:{name}")
        if scp:
            message += " with an explicit deny in a service control policy"
            if policy_id:
                message += f": {ORG_POLICY}{policy_id}"
        else:
            message += " because no identity-based policy allows the action"
    return {
        "eventVersion": "1.09", "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source, "eventName": name, "awsRegion": "us-east-1",
        "errorCode": code, "errorMessage": message, "eventID": f"e-{name}-{when.timestamp()}",
        "recipientAccountId": ACCOUNT,
        "userIdentity": {"type": "AssumedRole", "arn": session, "accountId": ACCOUNT,
                         "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role}}},
    }


def allowed(when: datetime) -> dict:
    return {"eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets", "userIdentity": {"type": "AssumedRole", "arn": AGENT}}


def run(compiled, events, **kw):
    manifest, policies, coverage = load_compiled(compiled)
    kw.setdefault("coverage", coverage)
    kw.setdefault("policy_ids", [AEGIS_ID])
    kw.setdefault("test_principals", ["arn:aws:iam::*:role/aegis-test-*"])
    return report(events, manifest, policies, **kw)


# --- classification ---------------------------------------------------------------------


def test_the_message_pattern_matches_the_documented_forms():
    with_arn = f"... with an explicit deny in a service control policy: {ORG_POLICY}p-abc123"
    assert SCP_DENY.search(with_arn).group("id") == "p-abc123"
    bare = SCP_DENY.search("... with an explicit deny in a service control policy")
    assert bare and bare.group("id") is None
    assert not SCP_DENY.search("... with an explicit deny in an identity-based policy")


def test_an_aegis_denial_is_attributed_and_mapped_to_its_rule(compiled):
    rep = run(compiled, [denial(NOW, "s3.amazonaws.com", "DeleteBucket"),
                         allowed(NOW - timedelta(days=40))])
    [d] = rep.denials
    assert (d.kind, d.test, d.principal) == ("aegis", False, AGENT)
    # the statement pools S3 and RDS deletes; only the rule whose actions cover the call
    assert d.rules == ["block-s3-bucket-delete"] and d.statements
    assert rep.status == "ok" and rep.counts() == {"aegis": {"real": 1}}
    [row] = [r for r in rep.by_rule() if r["rule"] == "block-s3-bucket-delete"]
    assert row["real"] == 1 and row["last_real"].startswith("2026-10-11")


def test_kinds_other_than_aegis(compiled):
    events = [
        denial(NOW, "s3.amazonaws.com", "DeleteBucket", policy_id=None),          # no ARN
        denial(NOW, "s3.amazonaws.com", "DeleteBucket", policy_id="p-someoneelse"),
        denial(NOW, "iam.amazonaws.com", "DeleteRole", scp=False),                # not an SCP
        denial(NOW, "ec2.amazonaws.com", "TerminateInstances",
               code="Client.UnauthorizedOperation",
               message="You are not authorized to perform this operation. Encoded "
                       "authorization failure message: abc"),
    ]
    rep = run(compiled, events)
    assert [d.kind for d in rep.denials] == ["scp-unattributed", "other-scp", "undetermined"]
    assert rep.denials[0].rules == ["block-s3-bucket-delete"]   # the rule it would match
    assert not rep.denials[1].rules                             # someone else's policy
    assert any(w.startswith("unattributed: 1") for w in rep.warnings)
    assert any(w.startswith("undetermined") for w in rep.warnings)


def test_test_principals_are_counted_apart(compiled):
    rep = run(compiled, [denial(NOW, "s3.amazonaws.com", "DeleteBucket", role=TEST_ROLE),
                         denial(NOW - timedelta(days=45), "s3.amazonaws.com", "DeleteBucket",
                                role=TEST_ROLE)])
    assert rep.counts() == {"aegis": {"test": 2}}
    assert rep.status == "quiet"           # 45 days, only tests: no real denial
    assert any("no-real-denials" in w and "45 days" in w for w in rep.warnings)


# --- the zero-denial check ------------------------------------------------------------------


def test_zero_real_denials_over_the_quiet_window_is_a_warning(compiled):
    rep = run(compiled, [allowed(NOW), allowed(NOW - timedelta(days=31))])
    assert rep.status == "quiet"
    assert any("not proof the policy works" in w for w in rep.warnings)


def test_a_short_window_does_not_apply_the_check(compiled):
    rep = run(compiled, [allowed(NOW), allowed(NOW - timedelta(days=3))])
    assert rep.status == "ok"
    assert any(w.startswith("short-window") for w in rep.warnings)


def test_without_policy_ids_nothing_can_be_attributed(compiled):
    rep = run(compiled, [denial(NOW, "s3.amazonaws.com", "DeleteBucket")], policy_ids=[])
    assert rep.status == "unknown" and rep.denials[0].kind == "other-scp"
    assert any(w.startswith("no-policy-ids") for w in rep.warnings)


def test_a_report_only_output_says_its_scps_should_not_be_attached(compiled):
    manifest = json.loads((compiled / "manifest.json").read_text())
    manifest["deployable"] = False
    (compiled / "manifest.json").write_text(json.dumps(manifest))
    rep = run(compiled, [allowed(NOW)])
    assert any(w.startswith("report-only") for w in rep.warnings)


def test_since_bounds_the_window(compiled):
    events = [denial(NOW - timedelta(days=60), "s3.amazonaws.com", "DeleteBucket"),
              allowed(NOW)]
    rep = run(compiled, events, since=NOW - timedelta(days=40))
    assert rep.denials == [] and rep.status == "quiet" and rep.window_days == pytest.approx(40)


# --- reading events ----------------------------------------------------------------------------


def test_every_event_file_shape_reads(tmp_path):
    ev = denial(NOW, "s3.amazonaws.com", "DeleteBucket")
    lookup = tmp_path / "lookup.json"
    lookup.write_text(json.dumps({"Events": [{"EventId": "x",
                                              "CloudTrailEvent": json.dumps(ev)}]}))
    logfile = tmp_path / "log.json.gz"
    logfile.write_bytes(gzip.compress(json.dumps({"Records": [ev, ev]}).encode()))
    lines = tmp_path / "events.jsonl"
    lines.write_text(json.dumps(ev) + "\n" + json.dumps(ev) + "\n")
    assert len(read_events(lookup)) == 1
    assert len(read_events(logfile)) == 2
    assert len(read_events(lines)) == 2
    (tmp_path / "bad.json").write_text('{"foo": 1}')
    with pytest.raises(EventsError):
        read_events(tmp_path / "bad.json")


# --- CLI ------------------------------------------------------------------------------------


def test_cli_report_and_exit_codes(compiled, tmp_path, capsys):
    events = tmp_path / "events.json"
    events.write_text(json.dumps({"Records": [
        denial(NOW, "s3.amazonaws.com", "DeleteBucket"),
        denial(NOW, "s3.amazonaws.com", "DeleteBucket", role=TEST_ROLE),
        allowed(NOW - timedelta(days=35))]}))
    argv = ["report", "aws", "--compiled", str(compiled), "--events", str(events),
            "--policy-id", AEGIS_ID, "--test-principal", "arn:aws:iam::*:role/aegis-test-*"]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "denied by an Aegis SCP: 1 real, 1 test" in out and "status: ok" in out
    assert main([*argv, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"] == {"aegis": {"real": 1, "test": 1}}
    quiet = tmp_path / "quiet.json"
    quiet.write_text(json.dumps({"Records": [allowed(NOW), allowed(NOW - timedelta(days=35))]}))
    assert main(["report", "aws", "--compiled", str(compiled), "--events", str(quiet),
                 "--policy-id", AEGIS_ID]) == 1
    assert "no-real-denials" in capsys.readouterr().out
    assert main([*argv[:6], "--policy-id", "not-an-id"]) == 64
    assert main(["report", "aws", "--compiled", str(tmp_path), "--events", str(events)]) == 65


def test_render_without_denials(compiled):
    text = render(run(compiled, [allowed(NOW)]))
    assert "no SCP denials in these events" in text


def test_self_protection_denials_are_named(compiled):
    rep = run(compiled, [denial(NOW, "organizations.amazonaws.com", "LeaveOrganization")])
    [d] = rep.denials
    assert d.rules and all(r.startswith("self-protection:") for r in d.rules)
