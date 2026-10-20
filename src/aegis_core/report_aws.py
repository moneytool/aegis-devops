"""``aegis report aws``: have the compiled SCPs denied anything real? (PLAN §7.12)

``aegis compile aws --check`` says whether the committed policies are the ones
the policy compiles to. It cannot say whether the attached SCPs are doing
anything: zero denials over a long window looks the same as a policy that was
detached. This report reads CloudTrail's record of denied calls and answers
that, read-only.

**What CloudTrail can and cannot tell.** A call an SCP denied carries
``with an explicit deny in a service control policy`` in its error message,
*sometimes* followed by the policy's ARN (IAM user guide, "Access denied error
message examples"). So:

* with the ARN, and the ARN's policy id given with ``--policy-id``, the denial
  is attributed to an Aegis policy exactly;
* without the ARN it is an SCP denial that may or may not be Aegis's
  ("unattributed"), reported as such;
* the message never names the statement, so the rules a denial points to are
  the compiled statements whose actions cover the denied call (by action, not
  resource -- CloudTrail does not reliably record the resource);
* some services encode the reason (EC2 ``UnauthorizedOperation``), so those
  denials are counted as undetermined.

**Real or a test.** Denials by principals matching ``--test-principal`` (for
example the acceptance roles ``*:role/aegis-test-*``) are deliberate tests;
everything else is real. Zero *real* denials attributed to Aegis over a
window of at least ``--quiet-days`` is a warning, not a success: either
nothing tried, or the policy is not attached.

Events come from files (the JSON that ``aws cloudtrail lookup-events``
prints, CloudTrail log files with ``Records`` -- gzipped or not -- or JSON
lines), or are collected with ``aws cloudtrail lookup-events`` using the
operator's own credentials. The analysis itself is pure and tested offline.
"""

from __future__ import annotations

import fnmatch
import gzip
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCP_DENY = re.compile(
    r"with an explicit deny in a service control policy"
    r"(?::\s*(?P<arn>arn:aws[a-z-]*:organizations::\d{12}:policy/o-[a-z0-9]+/"
    r"service_control_policy/(?P<id>p-[a-z0-9]+)))?",
    re.IGNORECASE,
)
_DENIAL_CODES = re.compile(r"(AccessDenied|UnauthorizedOperation|Unauthorized|Authorization"
                           r"Error|Forbidden)", re.IGNORECASE)
# "... is not authorized to perform: s3:PutEncryptionConfiguration ..." -- the IAM action itself
_DENIED_ACTION = re.compile(r"not authorized to perform:?\s+([a-z0-9-]+:[A-Za-z0-9*]+)")
# CloudTrail event names that are not the IAM action suffix: Lambda appends an API version
# (DeleteFunction20150331, UpdateFunctionConfiguration20150331v2); S3 bucket sub-resources are
# named after the API operation, not the permission.
_API_VERSION = re.compile(r"20\d{6}(v\d+)?$")
_S3_EVENT_TO_IAM = {
    "PutBucketEncryption": "PutEncryptionConfiguration",
    "DeleteBucketEncryption": "PutEncryptionConfiguration",
    "PutBucketLifecycle": "PutLifecycleConfiguration",
    "PutBucketLifecycleConfiguration": "PutLifecycleConfiguration",
    "DeleteBucketLifecycle": "PutLifecycleConfiguration",
    "PutBucketReplication": "PutReplicationConfiguration",
    "DeleteBucketReplication": "PutReplicationConfiguration",
    "DeleteBucketPublicAccessBlock": "PutBucketPublicAccessBlock",
    "DeleteObjects": "DeleteObject",
}
_ENCODED = re.compile(r"encoded authorization failure message", re.IGNORECASE)
DEFAULT_QUIET_DAYS = 30


class EventsError(ValueError):
    """Events could not be read or collected."""


# --- reading events ----------------------------------------------------------------------


def _truncated(doc: Any) -> bool:
    """A lookup-events page the CLI stopped short of the end (``--max-items``)."""
    return isinstance(doc, dict) and bool(doc.get("NextToken"))


def _records(doc: Any) -> list[dict[str, Any]]:
    """CloudTrail records from any of the shapes we accept."""
    if isinstance(doc, dict) and isinstance(doc.get("Records"), list):      # log file
        return [r for r in doc["Records"] if isinstance(r, dict)]
    if isinstance(doc, dict) and isinstance(doc.get("Events"), list):       # lookup-events
        out = []
        for e in doc["Events"]:
            raw = e.get("CloudTrailEvent") if isinstance(e, dict) else None
            if isinstance(raw, str):
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError as exc:
                    raise EventsError(f"an event's CloudTrailEvent is not JSON: {exc}") from None
            elif isinstance(e, dict):
                out.append(e)
        return out
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict) and "eventName" in doc:
        return [doc]
    raise EventsError("not CloudTrail events: expected {'Records': [...]}, "
                      "{'Events': [...]} (lookup-events), a list, or JSON lines")


def read_events(path: str | Path) -> tuple[list[dict[str, Any]], bool]:
    """``(events, truncated)`` from a file: truncated when it is a lookup-events
    page that still carries a ``NextToken``."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EventsError(f"{path}: {exc.strerror or exc}") from None
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8")
    try:
        doc = json.loads(text)
        return _records(doc), _truncated(doc)
    except json.JSONDecodeError:
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    out.extend(_records(json.loads(line)))
                except json.JSONDecodeError:
                    raise EventsError(f"{path}:{n}: not JSON") from None
        return out, False


@dataclass
class Collected:
    """What ``collect_events`` read: the events, the window it asked for, and
    whether the CLI stopped at ``max_events`` before the window's start."""

    events: list[dict[str, Any]]
    start: datetime
    end: datetime
    truncated: bool


def collect_events(*, days: int, profile: str | None = None, region: str | None = None,
                   max_events: int = 50_000, now: datetime | None = None) -> Collected:
    """``aws cloudtrail lookup-events`` over the last ``days`` (at most 90, the
    event history CloudTrail keeps), read-only. LookupEvents cannot filter on
    the error, so every management event in the window is read, newest first,
    up to ``max_events`` (the CLI paginates); a ``NextToken`` left over means
    the older part of the window was not read."""
    if not 1 <= days <= 90:
        raise EventsError("--days must be 1..90 (CloudTrail event history keeps 90 days)")
    end = now or datetime.now(UTC)
    begin = end - timedelta(days=days)
    argv = ["aws", "cloudtrail", "lookup-events",
            "--start-time", begin.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--max-items", str(max_events), "--output", "json"]
    if profile:
        argv += ["--profile", profile]
    if region:
        argv += ["--region", region]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False,
                              env={**os.environ, "AWS_PAGER": ""})
    except FileNotFoundError:
        raise EventsError("the aws CLI is not on PATH (or pass --events FILE)") from None
    if proc.returncode != 0:
        raise EventsError(f"aws cloudtrail lookup-events failed: {proc.stderr.strip()[:500]}")
    doc = json.loads(proc.stdout) if proc.stdout.strip() else {"Events": []}
    return Collected(_records(doc), begin, end, _truncated(doc))


# --- classifying -----------------------------------------------------------------------


@dataclass
class Denial:
    """One denied call, as far as CloudTrail lets us tell."""

    time: str
    action: str
    principal: str
    source_identity: str | None
    region: str
    account: str
    kind: str              # aegis | scp-unattributed | other-scp | undetermined
    policy_id: str | None = None
    test: bool = False
    statements: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], "")}


def _principal(event: dict[str, Any]) -> str:
    """The role or user ARN the SCP condition sees as ``aws:PrincipalArn``:
    an assumed-role session is reported as its role."""
    ui = event.get("userIdentity") or {}
    issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {})
    if ui.get("type") == "AssumedRole" and isinstance(issuer.get("arn"), str):
        return issuer["arn"]
    return str(ui.get("arn") or ui.get("principalId") or "unknown")


def _action(event: dict[str, Any]) -> str:
    """The IAM action that was denied: from the error message when AWS names it
    there, else the CloudTrail operation name translated to the IAM action."""
    m = _DENIED_ACTION.search(str(event.get("errorMessage") or ""))
    if m:
        return m.group(1)
    source = str(event.get("eventSource", "")).split(".")[0]
    name = _API_VERSION.sub("", str(event.get("eventName", "")))
    if source == "s3":
        name = _S3_EVENT_TO_IAM.get(name, name)
    return f"{source}:{name}"


def _statements_for(action: str, policies: list[dict[str, Any]]) -> list[str]:
    hits = []
    for policy in policies:
        for st in policy.get("Statement", []):
            actions = st.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            if any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in actions):
                hits.append(st["Sid"])
    return hits


def _owners(action: str, statements: list[str], statement_owners: dict[str, list[str]],
            rule_actions: dict[str, set[str]]) -> list[str]:
    """The rules (and self-protection entries) behind the statements that
    cover ``action``. Merged statements pool several rules' actions, so a rule
    is kept only if its own mapped IAM actions cover the call."""
    out = set()
    for sid in statements:
        for owner in statement_owners.get(sid, []):
            kind, _, name = owner.partition(":")
            if kind == "rule":
                if any(fnmatch.fnmatchcase(action.lower(), a.lower())
                       for a in rule_actions.get(name, ())):
                    out.add(name)
            else:
                out.add(owner)
    return sorted(out)


def classify(event: dict[str, Any], *, aegis_policy_ids: set[str],
             test_principals: list[str], policies: list[dict[str, Any]],
             statement_owners: dict[str, list[str]],
             rule_actions: dict[str, set[str]] | None = None) -> Denial | None:
    """The denial this event records, or ``None`` if it is not a denied call."""
    code = str(event.get("errorCode") or "")
    message = str(event.get("errorMessage") or "")
    m = SCP_DENY.search(message)
    # An explicit SCP deny in the message decides, whatever the service calls the error
    # (SNS: AuthorizationError); otherwise only recognised denial codes are looked at.
    if not m and (not code or not _DENIAL_CODES.search(code)):
        return None
    if m and m.group("id"):
        kind = "aegis" if m.group("id") in aegis_policy_ids else "other-scp"
    elif m:
        kind = "scp-unattributed"
    elif _ENCODED.search(message) or "UnauthorizedOperation" in code:
        kind = "undetermined"
    else:
        return None       # denied by something other than an SCP (IAM, a resource policy...)
    principal = _principal(event)
    ui = event.get("userIdentity") or {}
    action = _action(event)
    d = Denial(
        time=str(event.get("eventTime", "")), action=action, principal=principal,
        source_identity=(ui.get("sessionContext") or {}).get("sourceIdentity"),
        region=str(event.get("awsRegion", "")),
        account=str(ui.get("accountId") or event.get("recipientAccountId") or ""),
        kind=kind, policy_id=m.group("id") if m else None,
        test=any(fnmatch.fnmatchcase(principal, g) or fnmatch.fnmatchcase(
            str(ui.get("arn", "")), g) for g in test_principals),
        event_id=event.get("eventID"))
    if kind in ("aegis", "scp-unattributed"):
        d.statements = _statements_for(action, policies)
        d.rules = _owners(action, d.statements, statement_owners, rule_actions or {})
    return d


# --- the report --------------------------------------------------------------------------


@dataclass
class Report:
    window_start: str | None
    window_end: str | None
    window_days: float
    events_read: int
    deployable: bool
    policy_ids: list[str]
    denials: list[Denial]
    warnings: list[str] = field(default_factory=list)
    status: str = "ok"     # ok | quiet | unknown

    def counts(self) -> dict[str, dict[str, int]]:
        c: dict[str, Counter] = defaultdict(Counter)
        for d in self.denials:
            c[d.kind]["test" if d.test else "real"] += 1
        return {k: dict(v) for k, v in sorted(c.items())}

    def by_rule(self) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for d in self.denials:
            if d.kind != "aegis":
                continue
            for r in d.rules or ["(no statement matched the action)"]:
                row = rows.setdefault(r, {"rule": r, "real": 0, "test": 0, "last_real": None})
                row["test" if d.test else "real"] += 1
                if not d.test and (row["last_real"] is None or d.time > row["last_real"]):
                    row["last_real"] = d.time
        return sorted(rows.values(), key=lambda r: (-r["real"], r["rule"]))

    def to_dict(self) -> dict[str, Any]:
        return {"window": {"start": self.window_start, "end": self.window_end,
                           "days": round(self.window_days, 1)},
                "events_read": self.events_read, "deployable": self.deployable,
                "policy_ids": self.policy_ids, "status": self.status,
                "counts": self.counts(), "by_rule": self.by_rule(),
                "denials": [d.to_dict() for d in self.denials], "warnings": self.warnings}


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def report(events: list[dict[str, Any]], manifest: dict[str, Any],
           policies: list[dict[str, Any]], *, policy_ids: list[str],
           coverage: dict[str, Any] | None = None,
           test_principals: list[str], quiet_days: int = DEFAULT_QUIET_DAYS,
           since: datetime | None = None, until: datetime | None = None,
           truncated: bool = False) -> Report:
    """The report over ``events`` for one compiled output (``manifest`` and its
    SCPs). ``since``/``until`` bound the window -- for ``--collect``, the window
    queried, so an empty or sparse collection still covers it; by default it is
    the span of the events read. ``truncated``: the events stop short of the
    window's start, so the window is cut back to the oldest event read."""
    times = [t for t in (_parse_time(str(e.get("eventTime", ""))) for e in events) if t]
    start = since or (min(times) if times else None)
    end = until or (max(times) if times else None)
    if truncated and times and (start is None or min(times) > start):
        start = min(times)
    if since or until:
        events = [e for e in events
                  if (t := _parse_time(str(e.get("eventTime", ""))))
                  and (not since or t >= since) and (not until or t <= until)]
    days = (end - start).total_seconds() / 86400 if start and end else 0.0
    owners = {sid: list(v) for sid, v in (manifest.get("statements") or {}).items()}
    rule_actions = {r["id"]: {a for e in r.get("enforced", []) for a in e.get("iam", [])}
                    for r in (coverage or {}).get("rules", [])}
    denials = [d for d in (classify(e, aegis_policy_ids=set(policy_ids),
                                    test_principals=test_principals, policies=policies,
                                    statement_owners=owners, rule_actions=rule_actions)
                           for e in events) if d]
    denials.sort(key=lambda d: d.time)
    rep = Report(start.isoformat() if start else None, end.isoformat() if end else None, days,
                 len(events), bool(manifest.get("deployable")), sorted(policy_ids), denials)

    real_aegis = [d for d in denials if d.kind == "aegis" and not d.test]
    if truncated:
        rep.warnings.append(
            f"truncated: the events stop before the requested window's start (CloudTrail "
            f"returned more than were read); the window is cut back to the oldest event read "
            f"({rep.window_start}). Raise the limit, shorten --days, or read the trail's log "
            "files from S3")
    unattributed = [d for d in denials if d.kind == "scp-unattributed"]
    if not rep.deployable:
        rep.warnings.append("report-only: this output is not deployable (agents.yaml says "
                            "enforcement: report-only), so its SCPs should not be attached and "
                            "cannot have denied anything")
    if not policy_ids:
        rep.status = "unknown"
        rep.warnings.append("no-policy-ids: pass --policy-id with the Organizations policy id "
                            "(p-...) of each attached Aegis SCP; without them no denial can be "
                            "attributed to Aegis")
    if unattributed:
        rep.warnings.append(f"unattributed: {len(unattributed)} SCP denial(s) carry no policy "
                            "ARN; they may be Aegis's (the actions they match are listed)")
    if any(d.kind == "undetermined" for d in denials):
        rep.warnings.append("undetermined: some denials have an encoded reason (EC2); decode one "
                            "with `aws sts decode-authorization-message` to see the policy type")
    if policy_ids and not real_aegis:
        if days >= quiet_days:
            rep.status = "quiet"
            rep.warnings.append(
                f"no-real-denials: no real call was denied by the Aegis SCPs in {days:.0f} days. "
                "That is not proof the policy works: check it is attached to the target "
                "(aws organizations list-policies-for-target) and that its tests still deny"
                + (f"; {len(unattributed)} unattributed SCP denial(s) may be Aegis's"
                   if unattributed else ""))
        else:
            rep.warnings.append(f"short-window: {days:.1f} days of events, under --quiet-days "
                                f"{quiet_days}; the zero-denial check was not applied")
    return rep


def render(rep: Report) -> str:
    lines = [f"aegis report aws: {rep.events_read} event(s), "
             f"{rep.window_start or '?'} .. {rep.window_end or '?'} ({rep.window_days:.1f} days)"]
    labels = {"aegis": "denied by an Aegis SCP", "scp-unattributed": "denied by an SCP "
              "(no policy ARN)", "other-scp": "denied by another SCP",
              "undetermined": "denied, reason encoded"}
    counts = rep.counts()
    if not counts:
        lines.append("  no SCP denials in these events")
    for kind, label in labels.items():
        if kind in counts:
            c = counts[kind]
            lines.append(f"  {label}: {c.get('real', 0)} real, {c.get('test', 0)} test")
    for row in rep.by_rule():
        lines.append(f"    {row['rule']}: {row['real']} real, {row['test']} test"
                     + (f", last real {row['last_real']}" if row["last_real"] else ""))
    for w in rep.warnings:
        lines.append(f"  warning: {w}")
    lines.append(f"  status: {rep.status}")
    return "\n".join(lines)


def load_compiled(directory: str | Path
                  ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """``manifest.json``, the SCPs it lists and ``coverage.json``, from
    ``aegis compile aws --out``."""
    directory = Path(directory)
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EventsError(f"{directory}/manifest.json: {exc}") from None
    if manifest.get("target") != "aws-scp":
        raise EventsError(f"{directory}: not an `aegis compile aws` output")
    policies = []
    for p in manifest.get("policies", []):
        try:
            policies.append(json.loads((directory / p["file"]).read_text()))
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            raise EventsError(f"{directory}: {p.get('file')}: {exc}") from None
    try:
        coverage = json.loads((directory / "coverage.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EventsError(f"{directory}/coverage.json: {exc}") from None
    return manifest, policies, coverage
