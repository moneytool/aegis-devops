"""``aegis report kubernetes``: have the compiled admission policies denied anything real?

The Kubernetes twin of ``aegis report aws``. ``aegis compile kubernetes`` binds
every ValidatingAdmissionPolicy with ``validationActions: [Deny, Audit]``
(``[Warn, Audit]`` when ``agents.yaml`` says report-only). The ``Audit`` action
makes the API server write each failed validation into the request's audit
event, as the annotation ``validation.policy.admission.k8s.io/validation_failure``:
a JSON list of ``{message, policy, binding, expressionIndex, validationActions}``.
This report reads the API server's audit log and answers, read-only:

* which requests the Aegis policies (the names in ``manifest.json``'s
  ``policies``) denied, or warned about in report-only mode, per rule;
* real versus deliberate tests (``--test-principal`` globs on the username;
  an impersonated request counts as the identity it impersonated);
* policies named ``aegis-*`` that the compiled output does not list (left over
  from an older compile) and bindings whose actions differ from the compiled ones.

Zero real denials over at least ``--quiet-days`` is a warning, not a success:
either nothing tried, the policies are not applied, or the audit policy does
not record these requests (it must log writes at ``Metadata`` level or above).

**Input.** Audit events as the API server writes them (``--audit-log-path``,
JSON lines, rotated ``.gz`` files fine), an ``EventList``, a JSON list, or the
output of ``aws logs filter-log-events`` on an EKS cluster's
``kube-apiserver-audit`` streams (``{"events": [{"message": "<event>"}]}``).
GKE and AKS export audit logs in their own formats; convert them to
``audit.k8s.io/v1`` events first.
"""

from __future__ import annotations

import fnmatch
import gzip
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from aegis_core.report_aws import DEFAULT_QUIET_DAYS, _parse_time

ANNOTATION = "validation.policy.admission.k8s.io/validation_failure"
_WRITE_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection"})


class AuditError(ValueError):
    """Audit events could not be read."""


# --- reading events ----------------------------------------------------------------------


def _events(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict) and doc.get("kind") == "Event":
        return [doc]
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):          # EventList
        return [e for e in doc["items"] if isinstance(e, dict)]
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):         # CloudWatch
        out = []
        for e in doc["events"]:
            message = e.get("message") if isinstance(e, dict) else None
            if isinstance(message, str):
                try:
                    out.extend(_events(json.loads(message)))
                except json.JSONDecodeError as exc:
                    raise AuditError(f"a CloudWatch message is not JSON: {exc}") from None
        return out
    if isinstance(doc, list):
        return [e for e in doc if isinstance(e, dict)]
    raise AuditError("not Kubernetes audit events: expected audit.k8s.io Event lines, an "
                     "EventList, a list, or 'aws logs filter-log-events' output")


def read_audit_log(path: str | Path) -> list[dict[str, Any]]:
    """Audit events from one file (JSON lines or one JSON document; .gz ok)."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuditError(f"{path}: {exc.strerror or exc}") from None
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8")
    try:
        return _events(json.loads(text))
    except json.JSONDecodeError:
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    out.extend(_events(json.loads(line)))
                except json.JSONDecodeError:
                    raise AuditError(f"{path}:{n}: not JSON") from None
        return out


def dedupe(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One event per request: the API server writes one per stage (RequestReceived,
    ResponseStarted, ResponseComplete) under the same ``auditID``; the annotation is
    on the later stages, so the last one seen wins."""
    by_id: dict[str, dict[str, Any]] = {}
    anonymous = []
    for e in events:
        audit_id = e.get("auditID")
        if not isinstance(audit_id, str):
            anonymous.append(e)
            continue
        prev = by_id.get(audit_id)
        if prev is None or ANNOTATION in (e.get("annotations") or {}) or \
                ANNOTATION not in (prev.get("annotations") or {}):
            by_id[audit_id] = e
    return [*by_id.values(), *anonymous]


# --- classifying -----------------------------------------------------------------------


@dataclass
class Denial:
    """One failed validation of one request."""

    time: str
    principal: str
    verb: str
    resource: str          # resource[/subresource]
    namespace: str
    name: str
    policy: str
    binding: str
    actions: list[str]
    outcome: str           # denied | warned | audited
    kind: str              # aegis | stale-aegis | other
    rule: str | None = None
    test: bool = False
    code: int | None = None
    impersonated_by: str | None = None
    message: str = ""
    audit_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], "")}


def _principal(event: dict[str, Any]) -> tuple[str, str | None]:
    """The identity admission saw (the impersonated one, when impersonating)
    and, then, who impersonated it."""
    user = (event.get("user") or {}).get("username") or "unknown"
    imp = (event.get("impersonatedUser") or {}).get("username")
    return (imp, user) if imp else (user, None)


def _failures(event: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (event.get("annotations") or {}).get(ANNOTATION)
    if not raw:
        return []
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [f for f in (doc if isinstance(doc, list) else [doc]) if isinstance(f, dict)]


def classify(event: dict[str, Any], *, policies: dict[str, str],
             test_principals: list[str]) -> list[Denial]:
    """The failed validations this event records (none for most events)."""
    out = []
    principal, by = _principal(event)
    ref = event.get("objectRef") or {}
    resource = str(ref.get("resource", ""))
    if ref.get("subresource"):
        resource += f"/{ref['subresource']}"
    code = (event.get("responseStatus") or {}).get("code")
    for f in _failures(event):
        policy = str(f.get("policy", ""))
        actions = [str(a) for a in f.get("validationActions") or []]
        if policy in policies:
            kind = "aegis"
        elif policy.startswith("aegis-"):
            kind = "stale-aegis"
        else:
            kind = "other"
        outcome = "denied" if "Deny" in actions else "warned" if "Warn" in actions \
            else "audited"
        out.append(Denial(
            time=str(event.get("requestReceivedTimestamp") or event.get("stageTimestamp")
                     or ""),
            principal=principal, verb=str(event.get("verb", "")), resource=resource,
            namespace=str(ref.get("namespace", "")), name=str(ref.get("name", "")),
            policy=policy, binding=str(f.get("binding", "")), actions=actions,
            outcome=outcome, kind=kind, rule=policies.get(policy),
            test=any(fnmatch.fnmatchcase(principal, g) for g in test_principals),
            code=code if isinstance(code, int) else None, impersonated_by=by,
            message=str(f.get("message", "")), audit_id=event.get("auditID")))
    return out


# --- the report --------------------------------------------------------------------------


@dataclass
class Report:
    window_start: str | None
    window_end: str | None
    window_days: float
    events_read: int
    writes_read: int
    cluster: str
    enforcement: str
    validation_actions: list[str]
    denials: list[Denial]
    warnings: list[str] = field(default_factory=list)
    status: str = "ok"     # ok | quiet | unknown

    def counts(self) -> dict[str, dict[str, int]]:
        c: dict[str, Counter] = defaultdict(Counter)
        for d in self.denials:
            c[f"{d.kind} {d.outcome}"]["test" if d.test else "real"] += 1
        return {k: dict(v) for k, v in sorted(c.items())}

    def by_rule(self) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for d in self.denials:
            if d.kind != "aegis":
                continue
            row = rows.setdefault(d.rule or d.policy, {
                "rule": d.rule or d.policy, "policy": d.policy, "real": 0, "test": 0,
                "last_real": None, "outcomes": Counter()})
            row["test" if d.test else "real"] += 1
            row["outcomes"][d.outcome] += 1
            if not d.test and (row["last_real"] is None or d.time > row["last_real"]):
                row["last_real"] = d.time
        for row in rows.values():
            row["outcomes"] = dict(sorted(row["outcomes"].items()))
        return sorted(rows.values(), key=lambda r: (-r["real"], r["rule"]))

    def to_dict(self) -> dict[str, Any]:
        return {"window": {"start": self.window_start, "end": self.window_end,
                           "days": round(self.window_days, 1)},
                "events_read": self.events_read, "writes_read": self.writes_read,
                "cluster": self.cluster, "enforcement": self.enforcement,
                "validation_actions": self.validation_actions, "status": self.status,
                "counts": self.counts(), "by_rule": self.by_rule(),
                "denials": [d.to_dict() for d in self.denials], "warnings": self.warnings}


def report(events: list[dict[str, Any]], manifest: dict[str, Any], *,
           test_principals: list[str], quiet_days: int = DEFAULT_QUIET_DAYS,
           since: datetime | None = None) -> Report:
    """The report over ``events`` (deduplicated here) for one compiled output."""
    events = dedupe(events)

    def when(e: dict[str, Any]) -> datetime | None:
        return _parse_time(str(e.get("requestReceivedTimestamp") or e.get("stageTimestamp")
                               or ""))

    if since:
        events = [e for e in events if (t := when(e)) and t >= since]
    times = [t for t in map(when, events) if t]
    start = since or (min(times) if times else None)
    end = max(times) if times else None
    days = (end - start).total_seconds() / 86400 if start and end else 0.0
    policies = {str(k): str(v) for k, v in (manifest.get("policies") or {}).items()}
    compiled_actions = [str(a) for a in manifest.get("validation_actions") or []]
    denials = [d for e in events
               for d in classify(e, policies=policies, test_principals=test_principals)]
    denials.sort(key=lambda d: d.time)
    rep = Report(start.isoformat() if start else None, end.isoformat() if end else None, days,
                 len(events), sum(1 for e in events if e.get("verb") in _WRITE_VERBS),
                 str(manifest.get("cluster", "")), str(manifest.get("enforcement", "")),
                 compiled_actions, denials)

    if not events:
        rep.status = "unknown"
        rep.warnings.append("no-events: the audit log is empty for this window; is audit "
                            "logging on (--audit-policy-file, --audit-log-path)?")
        return rep
    if not rep.writes_read:
        rep.warnings.append("no-writes: no create/update/patch/delete request in these events; "
                            "the audit policy must log writes at Metadata level or above, or "
                            "no denial can show up here")
    drift = sorted({d.binding for d in denials
                    if d.kind == "aegis" and sorted(d.actions) != sorted(compiled_actions)})
    if drift:
        rep.warnings.append(
            f"binding-drift: {len(drift)} binding(s) ran with other validationActions than the "
            f"compiled {compiled_actions}: {', '.join(drift)}; re-apply policies.yaml")
    stale = sorted({d.policy for d in denials if d.kind == "stale-aegis"})
    if stale:
        rep.warnings.append(
            f"stale-policy: {', '.join(stale)} denied requests but are not in this compiled "
            "output; delete them or re-compile (kubectl delete validatingadmissionpolicies,"
            "validatingadmissionpolicybindings -l app.kubernetes.io/managed-by=aegis, then "
            "apply policies.yaml)")
    real = [d for d in denials if d.kind == "aegis" and not d.test]
    if not real:
        if days >= quiet_days:
            rep.status = "quiet"
            rep.warnings.append(
                f"no-real-denials: no real request failed an Aegis policy in {days:.0f} days. "
                "That is not proof the policies work: check they are applied (kubectl get "
                "validatingadmissionpolicybindings -l app.kubernetes.io/managed-by=aegis) and "
                "that their tests still deny")
        else:
            rep.warnings.append(f"short-window: {days:.1f} days of events, under --quiet-days "
                                f"{quiet_days}; the zero-denial check was not applied")
    return rep


def render(rep: Report) -> str:
    lines = [f"aegis report kubernetes: {rep.events_read} request(s) "
             f"({rep.writes_read} writes), {rep.window_start or '?'} .. "
             f"{rep.window_end or '?'} ({rep.window_days:.1f} days)"]
    labels = {"aegis denied": "denied by an Aegis policy",
              "aegis warned": "warned by an Aegis policy (report-only)",
              "aegis audited": "audited by an Aegis policy",
              "stale-aegis denied": "denied by an aegis-* policy not in this output",
              "stale-aegis warned": "warned by an aegis-* policy not in this output",
              "other denied": "denied by another admission policy",
              "other warned": "warned by another admission policy"}
    counts = rep.counts()
    if not counts:
        lines.append("  no failed admission-policy validations in these events")
    for key in [*labels, *sorted(set(counts) - set(labels))]:
        if key in counts:
            c = counts[key]
            lines.append(f"  {labels.get(key, key)}: {c.get('real', 0)} real, "
                         f"{c.get('test', 0)} test")
    for row in rep.by_rule():
        lines.append(f"    {row['rule']}: {row['real']} real, {row['test']} test"
                     + (f", last real {row['last_real']}" if row["last_real"] else ""))
    for w in rep.warnings:
        lines.append(f"  warning: {w}")
    lines.append(f"  status: {rep.status}")
    return "\n".join(lines)


def load_compiled(directory: str | Path) -> dict[str, Any]:
    """``manifest.json`` from ``aegis compile kubernetes --out``."""
    directory = Path(directory)
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"{directory}/manifest.json: {exc}") from None
    if manifest.get("target") != "kubernetes-vap":
        raise AuditError(f"{directory}: not an `aegis compile kubernetes` output")
    return manifest
