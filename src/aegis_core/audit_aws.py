"""``aegis audit-identity aws``: what the identity model means for the
identities that actually exist in an AWS account (design v0.3, §4.2, §4.3).

Read-only. It works on an IAM inventory -- the output of
``aws iam get-account-authorization-details`` -- which :func:`collect_inventory`
fetches with the operator's own credentials, or which the operator saves and
passes in. The analysis itself is pure, so it is tested offline.

* ``would_restrict``: every IAM role and user a compiled policy would restrict.
  In ``deny-by-default`` that is everything not listed as trusted or
  break-glass, so legitimate automation (backup jobs, cleanup functions,
  deploy roles) shows up here and must be added to ``trusted`` before
  ``enforcement: enforce``. Service-linked roles are never restricted (SCPs
  do not apply to them) and are listed separately.
* ``missing``: identities ``agents.yaml`` lists for this account that do not
  exist. A missing break-glass role means there is no break-glass.
* ``findings``: trust-policy problems that let an agent become an exempt
  identity without calling ``sts:AssumeRole`` from its own session --
  GitHub OIDC trust that is not bound to a workflow or protected
  environment, OIDC trust with no subject condition at all -- and exempt
  roles that trust a restricted identity directly (closed by the compiled
  self-protection block once enforced, open while report-only).
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

from aegis_core.identity import IdentityModel

GITHUB_OIDC = "token.actions.githubusercontent.com"
_SUB_KEY = f"{GITHUB_OIDC}:sub"
_WORKFLOW_KEYS = (f"{GITHUB_OIDC}:job_workflow_ref", f"{GITHUB_OIDC}:environment")
_BOUND_MARKERS = ("job_workflow_ref:", ":environment:")
_ARN_ACCOUNT = re.compile(r"arn:aws[a-z-]*:iam::(\d{12}):")


class InventoryError(ValueError):
    """The inventory could not be read or collected."""


def collect_inventory(profile: str | None = None) -> dict[str, Any]:
    """``aws iam get-account-authorization-details`` for roles and users,
    read-only, with the operator's credentials (the CLI paginates)."""
    argv = ["aws", "iam", "get-account-authorization-details", "--filter", "Role", "User",
            "--output", "json"]
    if profile:
        argv += ["--profile", profile]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False,
                              env=_cli_env())
    except FileNotFoundError:
        raise InventoryError("the aws CLI is not on PATH (or pass --inventory FILE)") from None
    if proc.returncode != 0:
        raise InventoryError(f"aws iam get-account-authorization-details failed: "
                             f"{proc.stderr.strip()[:500]}")
    return json.loads(proc.stdout)


def _cli_env() -> dict[str, str]:
    import os

    return {**os.environ, "AWS_PAGER": ""}


# --- trust policies ----------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _principals(statement: dict[str, Any]) -> dict[str, list[str]]:
    principal = statement.get("Principal", {})
    if principal == "*":
        return {"AWS": ["*"]}
    if not isinstance(principal, dict):
        return {}
    return {k: [str(v) for v in _as_list(vals)] for k, vals in principal.items()}


# Only these operators *require* the claim to match (review of #18): negated
# operators, ...IfExists (optional), Null and ForAllValues (vacuously true
# for a missing key) never prove a binding.
_BINDING_OPERATORS = frozenset({
    "StringEquals", "StringLike", "ForAnyValue:StringEquals", "ForAnyValue:StringLike",
})
_GLOB = frozenset("*?")


def _conditions(statement: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    out = []
    for op, kv in (statement.get("Condition") or {}).items():
        if isinstance(kv, dict):
            for key, vals in kv.items():
                out.append((str(op), str(key).lower(), [str(v) for v in _as_list(vals)]))
    return out


def _binding_value(sub: str) -> str | None:
    """The workflow or environment a ``sub`` value binds to, or None."""
    for marker in _BOUND_MARKERS:
        if marker in sub:
            return sub.split(marker, 1)[1]
    return None


def github_trust_findings(trust: dict[str, Any]) -> list[dict[str, str]]:
    """Problems with ``sts:AssumeRoleWithWebIdentity`` trust for GitHub
    Actions. A statement is bound only when a required (positive) condition
    pins it to one specific reusable workflow at one ref, or one environment:

    * ``oidc-no-subject``: no required condition on ``sub``, the workflow or
      the environment -- any repository's workflow can assume the role;
    * ``oidc-unsafe-condition``: a negated, optional (``IfExists``), ``Null``
      or ``ForAllValues`` condition on those claims, which never binds;
    * ``oidc-wildcard-subject``: a wildcard in the owner or repository;
    * ``wildcard-binding``: a wildcard in the bound workflow, its ref or the
      environment (``environment:*`` accepts an unprotected environment an
      agent job can name; ``workflows/*`` accepts the agent's own workflow);
    * ``workflow-unbound``: repository/ref-scoped, so every job in that
      repository -- an agent's included -- presents it."""
    findings = []
    claims = (_SUB_KEY.lower(), *(k.lower() for k in _WORKFLOW_KEYS))
    for st in _as_list(trust.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        federated = _principals(st).get("Federated", [])
        if not any(GITHUB_OIDC in f for f in federated):
            continue
        conds = _conditions(st)
        # conditions are ANDed: a negated or optional one next to a precise
        # required binding only narrows it, so it is reported only when
        # nothing else binds this statement
        unsafe = [{"kind": "oidc-unsafe-condition",
                   "detail": f"{op} on {key} {vals!r} does not require that value, so it "
                             "binds the role to nothing"}
                  for op, key, vals in conds if key in claims and op not in _BINDING_OPERATORS]
        statement: list[dict[str, str]] = []

        def required(key: str) -> list[str]:
            return [v for op, k, vals in conds if k == key.lower()
                    and op in _BINDING_OPERATORS for v in vals]

        subs = required(_SUB_KEY)
        bindings = [v for k in _WORKFLOW_KEYS for v in required(k)]
        if not subs and not bindings:
            if not unsafe:
                statement.append({"kind": "oidc-no-subject",
                                  "detail": "GitHub OIDC trust with no required sub, workflow "
                                            "or environment condition: any repository's "
                                            "workflow can assume this role"})
            findings += statement + unsafe
            continue
        for value in bindings:
            if _GLOB & set(value):
                statement.append({"kind": "wildcard-binding",
                                  "detail": f"workflow/environment {value!r} matches more "
                                            "than one workflow, ref or environment"})
        bound_by_key = any(not (_GLOB & set(v)) for v in bindings)
        for sub in subs:
            repo = sub.split(":", 2)[1] if sub.startswith("repo:") and ":" in sub else ""
            binding = _binding_value(sub)
            if _GLOB & set(repo):
                statement.append({"kind": "oidc-wildcard-subject",
                                  "detail": f"sub {sub!r} matches more than one repository"})
            elif binding is not None and _GLOB & set(binding):
                statement.append({"kind": "wildcard-binding",
                                  "detail": f"sub {sub!r} matches more than one workflow, ref "
                                            "or environment"})
            elif binding is None and not bound_by_key:
                statement.append({"kind": "workflow-unbound",
                                  "detail": f"sub {sub!r} is repository/ref-scoped: every job "
                                            "in that repository presents it, an agent's "
                                            "included"})
        bound = not statement and (bound_by_key or all(
            _binding_value(v) is not None for v in subs))
        findings += statement + ([] if bound else unsafe)
    return findings


def trusted_principals(trust: dict[str, Any]) -> list[str]:
    """The AWS principals an ``Allow`` statement lets assume the role."""
    out = []
    for st in _as_list(trust.get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            out += _principals(st).get("AWS", [])
    return out


# --- the audit ------------------------------------------------------------------------------


@dataclass
class AuditResult:
    account: str
    mode: str
    enforcement: str
    would_restrict: list[dict[str, Any]] = field(default_factory=list)
    exempt: list[dict[str, Any]] = field(default_factory=list)
    service_linked: list[str] = field(default_factory=list)
    missing: list[dict[str, str]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def problems(self) -> bool:
        return bool(self.missing) or any(f["severity"] == "high" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account": self.account, "mode": self.mode, "enforcement": self.enforcement,
            "would_restrict": self.would_restrict, "exempt": self.exempt,
            "service_linked": self.service_linked, "missing": self.missing,
            "findings": self.findings,
        }


def _account_of(inventory: dict[str, Any]) -> str:
    for entry in (*inventory.get("RoleDetailList", []), *inventory.get("UserDetailList", [])):
        m = _ARN_ACCOUNT.match(entry.get("Arn", ""))
        if m:
            return m.group(1)
    raise InventoryError("the inventory has no IAM role or user ARNs")


def _hint(kind: str, path: str, name: str) -> str | None:
    if path.startswith("/aws-reserved/sso.amazonaws.com/"):
        return "IAM Identity Center role: people sign in through it"
    if name == "OrganizationAccountAccessRole":
        return "the management account's way in; usually break-glass"
    return None


def audit(inventory: dict[str, Any], model: IdentityModel) -> AuditResult:
    account = _account_of(inventory)
    result = AuditResult(account, model.mode, model.enforcement)
    present: set[str] = set()
    restricted_arns: set[str] = set()

    for kind, entries in (("role", inventory.get("RoleDetailList", [])),
                          ("user", inventory.get("UserDetailList", []))):
        for entry in entries:
            arn, path = entry["Arn"], entry.get("Path", "/")
            name = entry.get("RoleName") or entry.get("UserName") or arn
            present.add(arn)
            if kind == "role" and path.startswith("/aws-service-role/"):
                result.service_linked.append(arn)
                continue
            last = (entry.get("RoleLastUsed") or {}).get("LastUsedDate") if kind == "role" \
                else entry.get("PasswordLastUsed")
            row = {"arn": arn, "kind": kind, "last_used": last}
            hint = _hint(kind, path, name)
            if hint:
                row["hint"] = hint
            if model.is_agent("aws", [(kind, arn)]):
                result.would_restrict.append(row)
                restricted_arns.add(arn)
            else:
                result.exempt.append(row)

    exempt_listed = model.exempt("aws")
    for ident in (*exempt_listed, *(model.agents_for("aws") if model.mode == "agents-only"
                                    else ())):
        if ident.kind not in ("role", "user"):
            continue
        m = _ARN_ACCOUNT.match(ident.id)
        if m and m.group(1) == account and ident.id not in present:
            section = ("break_glass" if ident in model.break_glass else
                       "trusted" if ident in model.trusted else "agents")
            result.missing.append({"arn": ident.id, "listed_as": section,
                                   "detail": "listed in agents.yaml but not in this account"
                                   + ("; there is no working break-glass for it"
                                      if section == "break_glass" else "")})

    exempt_arns = {r["arn"] for r in result.exempt}
    for entry in inventory.get("RoleDetailList", []):
        arn = entry["Arn"]
        if entry.get("Path", "/").startswith("/aws-service-role/"):
            continue
        trust = entry.get("AssumeRolePolicyDocument") or {}
        if isinstance(trust, str):
            from urllib.parse import unquote

            trust = json.loads(unquote(trust))
        exempt = arn in exempt_arns
        for f in github_trust_findings(trust):
            result.findings.append({
                "role": arn, **f,
                "severity": "high" if exempt else "info",
                "why": ("an exempt role: a GitHub job that is an agent can assume it with "
                        "AssumeRoleWithWebIdentity, which the SCP cannot see"
                        if exempt else "a restricted role: the policy still applies to it"),
            })
        if exempt:
            for principal in trusted_principals(trust):
                if principal in (f"arn:aws:iam::{account}:root", account):
                    result.findings.append({
                        "role": arn, "kind": "exempt-trusts-account",
                        "detail": "trusts the whole account: any identity in it allowed "
                                  "sts:AssumeRole can assume it, agents included",
                        "severity": "high" if model.enforcement != "enforce" else "info",
                        "why": ("blocked for agents by the compiled self-protection block "
                                "once enforced; open while report-only. Prefer trusting "
                                "named principals"),
                    })
                elif principal in restricted_arns:
                    result.findings.append({
                        "role": arn, "kind": "exempt-trusts-restricted",
                        "detail": f"trusts {principal} directly",
                        "severity": "high" if model.enforcement != "enforce" else "info",
                        "why": ("blocked by the compiled self-protection block (no "
                                "sts:AssumeRole into exempt roles) once enforced; open "
                                "while report-only"),
                    })
    result.would_restrict.sort(key=lambda r: r["arn"])
    result.exempt.sort(key=lambda r: r["arn"])
    result.service_linked.sort()
    return result
