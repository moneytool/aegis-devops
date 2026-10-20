"""``aegis report kubernetes``: requests the compiled admission policies failed,
from the API server's audit log.

``fixtures/kube-audit/`` was recorded on kind (kindest/node v1.36.1) on 2026-10-20:
the kube-acceptance rules compiled and applied, audit logging at Metadata level,
then as ``agents:coder`` a server-side dry-run delete of ``prod/configmap app``
and a cordon of the node, the same delete as ``agents:aegis-test``, and the delete
again with the binding switched to ``[Warn, Audit]``. Client certificate ids and
source IPs were removed."""

import copy
import gzip
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis_core.cli import main
from aegis_core.report_kubernetes import (
    ANNOTATION,
    AuditError,
    dedupe,
    load_compiled,
    read_audit_log,
    render,
    report,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kube-audit"
AGENT = "system:serviceaccount:agents:coder"
TEST = "system:serviceaccount:agents:aegis-test*"


@pytest.fixture
def events():
    return read_audit_log(FIXTURES / "audit.log")


@pytest.fixture
def manifest():
    return load_compiled(FIXTURES)


def _event(when: datetime, *, policy: str | None = "aegis-prod-no-deletes",
           actions=("Deny", "Audit"), user: str = AGENT, verb: str = "delete",
           audit_id: str = "a1", impersonate: bool = False) -> dict:
    e = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
         "auditID": audit_id, "stage": "ResponseComplete", "verb": verb,
         "user": {"username": user},
         "objectRef": {"resource": "configmaps", "namespace": "prod", "name": "app"},
         "responseStatus": {"code": 422 if "Deny" in actions else 200},
         "requestReceivedTimestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
         "annotations": {}}
    if impersonate:
        e["user"] = {"username": "kubernetes-admin"}
        e["impersonatedUser"] = {"username": user}
    if policy:
        e["annotations"][ANNOTATION] = json.dumps([{
            "message": "aegis: rule prod-no-deletes blocks this request", "policy": policy,
            "binding": policy, "expressionIndex": 0, "validationActions": list(actions)}])
    return e


# --- the recorded kind run ------------------------------------------------------------


def test_recorded_run_attributes_each_denial_to_its_rule(events, manifest):
    rep = report(events, manifest, test_principals=[TEST])
    assert rep.counts() == {"aegis denied": {"real": 2, "test": 1},
                            "aegis warned": {"real": 1}}
    rows = {r["rule"]: r for r in rep.by_rule()}
    assert rows["prod-no-deletes"]["real"] == 2      # one denied, one warned
    assert rows["prod-no-deletes"]["test"] == 1
    assert rows["prod-no-deletes"]["outcomes"] == {"denied": 2, "warned": 1}
    assert rows["no-node-changes"]["real"] == 1
    assert rep.status == "ok"


def test_impersonated_request_counts_as_the_impersonated_identity(events, manifest):
    rep = report(events, manifest, test_principals=[TEST])
    cordon = next(d for d in rep.denials if d.rule == "no-node-changes")
    assert cordon.principal == AGENT
    assert cordon.impersonated_by == "kubernetes-admin"
    assert (cordon.verb, cordon.resource, cordon.code) == ("patch", "nodes", 422)


def test_recorded_warn_binding_is_reported_as_drift(events, manifest):
    rep = report(events, manifest, test_principals=[TEST])
    assert any(w.startswith("binding-drift:") and "aegis-prod-no-deletes" in w
               for w in rep.warnings)


def test_without_test_principals_everything_is_real(events, manifest):
    rep = report(events, manifest, test_principals=[])
    assert rep.counts()["aegis denied"] == {"real": 3}


# --- reading ------------------------------------------------------------------------------


def test_reads_gzip_eventlist_and_cloudwatch(tmp_path, events):
    gz = tmp_path / "audit.log.gz"
    gz.write_bytes(gzip.compress((FIXTURES / "audit.log").read_bytes()))
    assert len(read_audit_log(gz)) == len(events)
    lst = tmp_path / "list.json"
    lst.write_text(json.dumps({"kind": "EventList", "items": events}))
    assert len(read_audit_log(lst)) == len(events)
    cw = tmp_path / "cw.json"
    cw.write_text(json.dumps({"events": [{"message": json.dumps(e)} for e in events]}))
    assert len(read_audit_log(cw)) == len(events)


def test_rejects_what_is_not_audit_events(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text('{"Records": []}')
    with pytest.raises(AuditError, match="not Kubernetes audit events"):
        read_audit_log(bad)
    with pytest.raises(AuditError):
        read_audit_log(tmp_path / "missing.log")


def test_dedupe_keeps_the_annotated_stage():
    t = datetime(2026, 10, 1, tzinfo=UTC)
    received = _event(t, policy=None)
    received["stage"] = "RequestReceived"
    complete = _event(t)
    assert dedupe([received, complete]) == [complete]
    assert dedupe([complete, received]) == [complete]


def test_load_compiled_refuses_an_aws_output(tmp_path):
    (tmp_path / "manifest.json").write_text('{"target": "aws-scp"}')
    with pytest.raises(AuditError, match="not an `aegis compile kubernetes` output"):
        load_compiled(tmp_path)


# --- classification and warnings -------------------------------------------------------


def test_stale_and_foreign_policies(manifest):
    t = datetime(2026, 10, 1, tzinfo=UTC)
    rep = report([_event(t, policy="aegis-old-rule", audit_id="1"),
                  _event(t, policy="kyverno-thing", audit_id="2"),
                  _event(t, audit_id="3")], manifest, test_principals=[])
    assert rep.counts() == {"aegis denied": {"real": 1}, "other denied": {"real": 1},
                            "stale-aegis denied": {"real": 1}}
    assert any(w.startswith("stale-policy: aegis-old-rule") for w in rep.warnings)


def test_quiet_over_a_long_window(manifest):
    t = datetime(2026, 9, 1, tzinfo=UTC)
    rep = report([_event(t, policy=None, audit_id="1"),
                  _event(t + timedelta(days=40), policy=None, audit_id="2"),
                  _event(t + timedelta(days=20), user="system:serviceaccount:agents:aegis-test",
                         audit_id="3")],
                 manifest, test_principals=[TEST])
    assert rep.status == "quiet"
    assert any(w.startswith("no-real-denials") for w in rep.warnings)


def test_short_window_is_not_quiet(manifest):
    t = datetime(2026, 9, 1, tzinfo=UTC)
    rep = report([_event(t, policy=None)], manifest, test_principals=[])
    assert rep.status == "ok"
    assert any(w.startswith("short-window") for w in rep.warnings)


def test_no_events_is_unknown(manifest):
    rep = report([], manifest, test_principals=[])
    assert rep.status == "unknown"
    assert rep.warnings[0].startswith("no-events")


def test_reads_only_is_flagged(manifest):
    t = datetime(2026, 9, 1, tzinfo=UTC)
    rep = report([_event(t, policy=None, verb="get")], manifest, test_principals=[])
    assert any(w.startswith("no-writes") for w in rep.warnings)


def test_report_only_output_counts_warnings_without_drift(manifest):
    m = copy.deepcopy(manifest)
    m["enforcement"], m["validation_actions"] = "report-only", ["Warn", "Audit"]
    t = datetime(2026, 10, 1, tzinfo=UTC)
    rep = report([_event(t, actions=("Warn", "Audit"), impersonate=True)], m,
                 test_principals=[])
    assert rep.counts() == {"aegis warned": {"real": 1}}
    assert not any(w.startswith("binding-drift") for w in rep.warnings)


def test_since_cuts_the_window(manifest):
    t = datetime(2026, 9, 1, tzinfo=UTC)
    rep = report([_event(t, audit_id="1"), _event(t + timedelta(days=5), audit_id="2")],
                 manifest, test_principals=[], since=t + timedelta(days=1))
    assert len(rep.denials) == 1


def test_render_lists_rules_and_status(events, manifest):
    text = render(report(events, manifest, test_principals=[TEST]))
    assert "denied by an Aegis policy: 2 real, 1 test" in text
    assert "prod-no-deletes: 2 real, 1 test" in text
    assert text.endswith("status: ok")


# --- the command ----------------------------------------------------------------------


def test_cli_json_and_exit_codes(tmp_path, capsys):
    rc = main(["report", "kubernetes", "--compiled", str(FIXTURES), "--audit-log",
               str(FIXTURES / "audit.log"), "--test-principal", TEST, "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "ok" and doc["cluster"] == "kind-aegis-audit"
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert main(["report", "kubernetes", "--compiled", str(FIXTURES),
                 "--audit-log", str(empty)]) == 1


def test_cli_bad_compiled_dir_is_a_data_error(tmp_path):
    shutil.copy(FIXTURES / "audit.log", tmp_path / "audit.log")
    assert main(["report", "kubernetes", "--compiled", str(tmp_path),
                 "--audit-log", str(tmp_path / "audit.log")]) == 65
