"""The identity model (``agents.yaml``): which identities server-side
enforcement treats as agents (design v0.3, §4).

Server-side layers (compiled cloud policies, Kubernetes admission) cannot
see *who typed* a command, only which identity made the API call. So the
compiled policy applies to agent identities, and this file is the single
source of that list: compilers generate their principal lists and
Kubernetes ``matchConditions`` from it, never by hand.

Two modes:

* ``deny-by-default`` (the default): the file names the **trusted**
  identities (people, CI roles, controllers) and every other identity is
  treated as an agent. Listing agents instead fails open for the agent
  nobody listed, which is the case server-side enforcement exists for.
* ``agents-only``: the file names the agents; everything else is exempt.

Either way the **break-glass** identities are never restricted, and the
file must name at least one. ``enforcement`` starts at ``report-only``:
compilers emit audit/warn artifacts until an operator, after reviewing
``aegis audit-identity --would-restrict``, signs a change to ``enforce``.

The file is signed like every policy file, and its ``principal`` must hold
the ``identity`` class in ``authority.yaml``, so changing who is trusted is
a policy change of its own kind.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegis_core.signing import check_signature

AGENTS_FILE = "agents.yaml"
IDENTITY_CLASS = "identity"
MODES = ("deny-by-default", "agents-only")
ENFORCEMENT = ("report-only", "enforce")

_SA_USER_PREFIX = "system:serviceaccount:"
_DNS_LABEL = r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"
_DNS_SUBDOMAIN = r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?"
_K8S_SA_RE = re.compile(rf"(?P<ns>{_DNS_LABEL}):(?P<name>{_DNS_SUBDOMAIN})")
_IAM_NAME = r"[\w+=,.@-]{1,64}"
_IAM_PATH = r"(?:[\w+=,.@-]+/)*"
_AWS_ROLE_RE = re.compile(rf"arn:aws(?:-cn|-us-gov)?:iam::\d{{12}}:role/{_IAM_PATH}{_IAM_NAME}")
_AWS_USER_RE = re.compile(rf"arn:aws(?:-cn|-us-gov)?:iam::\d{{12}}:user/{_IAM_PATH}{_IAM_NAME}")
_AWS_SOURCE_IDENTITY_RE = re.compile(r"[\w+=,.@-]{2,64}")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_TOKEN_RE = re.compile(r"\S{1,512}")

# Kubernetes groups that every (or every ServiceAccount) identity carries:
# trusting one would exempt every agent at once.
_K8S_UNIVERSAL_GROUPS = frozenset(
    {"system:authenticated", "system:unauthenticated", "system:serviceaccounts"}
)

# GitHub OIDC subjects are repository/ref-scoped by default; a trusted one
# must be bound to a workflow or a protected environment (design §4.1).
_GITHUB_BOUND_MARKERS = ("job_workflow_ref:", ":environment:")


def _workflow_bound(subject: str) -> bool:
    return any(m in subject for m in _GITHUB_BOUND_MARKERS)


def _check_k8s_user(value: str) -> str | None:
    return None if _TOKEN_RE.fullmatch(value) else "not a Kubernetes user name"


def _check_k8s_sa(value: str) -> str | None:
    return None if _K8S_SA_RE.fullmatch(value) else "expected <namespace>:<name>"


def _check_aws_role(value: str) -> str | None:
    if ":sts::" in value or ":assumed-role/" in value:
        return ("an assumed-role session ARN changes per session; list the role ARN "
                "(arn:aws:iam::<account>:role/<name>) or use kind source-identity")
    return None if _AWS_ROLE_RE.fullmatch(value) else "not an IAM role ARN"


def _check_aws_user(value: str) -> str | None:
    return None if _AWS_USER_RE.fullmatch(value) else "not an IAM user ARN"


def _check_source_identity(value: str) -> str | None:
    return None if _AWS_SOURCE_IDENTITY_RE.fullmatch(value) else "not a valid sts SourceIdentity"


def _check_email(value: str) -> str | None:
    return None if _EMAIL_RE.fullmatch(value) else "not an email address"


def _check_gcp_sa(value: str) -> str | None:
    if not _EMAIL_RE.fullmatch(value) or not value.endswith(".gserviceaccount.com"):
        return "not a service account email (<name>@<project>.iam.gserviceaccount.com)"
    return None


def _check_github_subject(value: str) -> str | None:
    if not _TOKEN_RE.fullmatch(value) or ":" not in value:
        return "not an OIDC subject claim (e.g. repo:<org>/<repo>:environment:<name>)"
    return None


# platform -> kind -> validator. Kinds whose names are unique case-
# insensitively at the platform (IAM names, email addresses) are compared
# case-insensitively when looking for duplicates only: two entries that
# differ only in case cannot both exist, so one is a mistake. Matching stays
# exact, as the compiled artifacts match (AWS ARN condition operators are
# case-sensitive).
KINDS: dict[str, dict[str, Any]] = {
    "kubernetes": {"user": _check_k8s_user, "group": _check_k8s_user,
                   "serviceaccount": _check_k8s_sa},
    "aws": {"role": _check_aws_role, "user": _check_aws_user,
            "source-identity": _check_source_identity},
    "gcp": {"serviceaccount": _check_gcp_sa, "user": _check_email, "group": _check_email},
    "github": {"oidc-subject": _check_github_subject},
}
_CASE_INSENSITIVE = {("aws", "role"), ("aws", "user"), ("gcp", "serviceaccount"),
                     ("gcp", "user"), ("gcp", "group")}


@dataclass(frozen=True)
class Identity:
    """One identity on one platform, e.g. ``kubernetes/serviceaccount
    ci:deployer`` or ``aws/role arn:aws:iam::111122223333:role/Deploy``."""

    platform: str
    kind: str
    id: str
    note: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        """Exact identity, for matching: what a compiled policy compares."""
        return (self.platform, self.kind, self.id)

    @property
    def duplicate_key(self) -> tuple[str, str, str]:
        """Identity as the platform keeps it unique, for duplicate checks."""
        ident = self.id.lower() if (self.platform, self.kind) in _CASE_INSENSITIVE else self.id
        return (self.platform, self.kind, ident)

    @property
    def kubernetes_username(self) -> str | None:
        """The ``request.userInfo.username`` this identity presents, for a
        Kubernetes user or ServiceAccount (``None`` otherwise)."""
        if self.platform != "kubernetes" or self.kind == "group":
            return None
        if self.kind == "serviceaccount":
            return _SA_USER_PREFIX + self.id
        return self.id

    def to_dict(self) -> dict[str, str]:
        d = {"platform": self.platform, "kind": self.kind, "id": self.id}
        if self.note:
            d["note"] = self.note
        return d

    def __str__(self) -> str:
        return f"{self.platform}/{self.kind} {self.id}"


def _normalize(platform: str, kind: str, value: str) -> tuple[str, str]:
    """A Kubernetes user named ``system:serviceaccount:<ns>:<name>`` is that
    ServiceAccount; store it as one so duplicates and matching line up."""
    if platform == "kubernetes" and kind == "user" and value.startswith(_SA_USER_PREFIX):
        return "serviceaccount", value[len(_SA_USER_PREFIX):]
    return kind, value


def _parse_identity(path: Path, section: str, entry: Any) -> Identity:
    where = f"{path}: {section}"
    if not isinstance(entry, dict):
        raise ValueError(f"{where}: every entry must be a mapping with platform, kind and id")
    unknown = set(entry) - {"platform", "kind", "id", "note"}
    if unknown:
        raise ValueError(f"{where}: unknown field(s) {sorted(unknown)}")
    platform, kind, value = entry.get("platform"), entry.get("kind"), entry.get("id")
    note = entry.get("note", "")
    if platform not in KINDS:
        raise ValueError(f"{where}: platform must be one of {sorted(KINDS)}, got {platform!r}")
    if kind not in KINDS[platform]:
        raise ValueError(f"{where}: {platform} kind must be one of {sorted(KINDS[platform])}, "
                         f"got {kind!r}")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}: {platform}/{kind} needs a non-empty string 'id'")
    if not isinstance(note, str):
        raise ValueError(f"{where}: 'note' must be a string")
    value = value.strip()
    if "*" in value or "?" in value:
        raise ValueError(f"{where}: {platform}/{kind} {value!r}: wildcards are not allowed; "
                         "list each identity")
    kind, value = _normalize(platform, kind, value)
    problem = KINDS[platform][kind](value)
    if problem:
        raise ValueError(f"{where}: {platform}/{kind} {value!r}: {problem}")
    return Identity(platform, kind, value, note)


def _parse_section(path: Path, raw: dict, section: str) -> tuple[Identity, ...]:
    entries = raw.get(section)
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise ValueError(f"{path}: '{section}' must be a list")
    return tuple(_parse_identity(path, section, e) for e in entries)


@dataclass(frozen=True)
class IdentityModel:
    """The loaded ``agents.yaml``. Immutable; compilers read it through
    :meth:`exempt`, :meth:`agents_for` and :meth:`is_agent`."""

    path: str
    mode: str
    enforcement: str
    principal: str
    trusted: tuple[Identity, ...]
    break_glass: tuple[Identity, ...]
    agents: tuple[Identity, ...]
    warnings: tuple[str, ...] = ()

    @property
    def platforms(self) -> tuple[str, ...]:
        seen = {i.platform for i in (*self.trusted, *self.break_glass, *self.agents)}
        return tuple(p for p in KINDS if p in seen)

    def require_platform(self, platform: str) -> None:
        """Compilers call this first: in ``deny-by-default`` a platform with
        no break-glass identity would restrict every operator too."""
        if platform not in KINDS:
            raise ValueError(f"unknown platform {platform!r}")
        if not any(i.platform == platform for i in self.break_glass):
            raise ValueError(f"{self.path}: no break-glass identity for {platform}; add one "
                             "before compiling a policy for it")

    def exempt(self, platform: str) -> tuple[Identity, ...]:
        """The identities a compiled policy on ``platform`` must never
        restrict: the break-glass identities, plus (``deny-by-default``) the
        trusted ones. Break-glass first."""
        pool = self.break_glass + (self.trusted if self.mode == "deny-by-default" else ())
        return tuple(i for i in pool if i.platform == platform)

    def agents_for(self, platform: str) -> tuple[Identity, ...]:
        """``agents-only``: the listed agents on ``platform``.
        ``deny-by-default`` has no agent list (every non-exempt identity is
        one), so this raises rather than return a list that fails open."""
        if self.mode != "agents-only":
            raise ValueError("deny-by-default has no agent list: restrict every identity "
                             "except exempt(platform)")
        return tuple(i for i in self.agents if i.platform == platform)

    def is_agent(self, platform: str, presented: Iterable[tuple[str, str]]) -> bool:
        """Whether a caller presenting these ``(kind, id)`` identities on
        ``platform`` (e.g. a Kubernetes user plus its groups) is treated as
        an agent. Break-glass always wins."""
        keys = set()
        for kind, value in presented:
            kind, value = _normalize(platform, kind, value)
            keys.add(Identity(platform, kind, value).key)

        def hit(pool: tuple[Identity, ...]) -> bool:
            return any(i.key in keys for i in pool if i.platform == platform)

        if hit(self.break_glass):
            return False
        if self.mode == "deny-by-default":
            return not hit(self.trusted)
        return hit(self.agents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "enforcement": self.enforcement,
            "principal": self.principal,
            "trusted": [i.to_dict() for i in self.trusted],
            "break_glass": [i.to_dict() for i in self.break_glass],
            "agents": [i.to_dict() for i in self.agents],
            "warnings": list(self.warnings),
        }


def load_identity_model(
    path: str | Path,
    *,
    authority_map: dict[str, set[str]] | None,
    key: bytes | None = None,
    insecure: bool = False,
) -> IdentityModel:
    """``agents.yaml`` -> :class:`IdentityModel`. Shape::

        version: 1
        principal: admin                 # must hold the 'identity' class
        mode: deny-by-default            # or agents-only
        enforcement: report-only         # or enforce, after the report-only review
        break_glass:                     # never restricted; at least one
          - {platform: kubernetes, kind: group, id: aegis:break-glass}
        trusted:                         # deny-by-default only
          - {platform: aws, kind: role, id: "arn:aws:iam::111122223333:role/Deploy"}
        agents:                          # agents-only only
          - {platform: kubernetes, kind: serviceaccount, id: "aegis-agents:coder"}

    Any shape problem, a duplicate identity, a principal without the
    ``identity`` class or a trusted group every identity carries is a load
    error (``ValueError``), never a guess. Softer findings (an unsigned
    file without a key, a platform with no break-glass identity, a trusted
    GitHub subject not bound to a workflow) are ``warnings``."""
    path = Path(path)
    warnings: list[str] = []
    check_signature(path, key, insecure, warnings)
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: must be a mapping")
    unknown = set(raw) - {"version", "principal", "mode", "enforcement", "break_glass",
                          "trusted", "agents"}
    if unknown:
        raise ValueError(f"{path}: unknown field(s) {sorted(unknown)}")
    if raw.get("version", 1) != 1:
        raise ValueError(f"{path}: unsupported version {raw.get('version')!r} (expected 1)")

    mode = raw.get("mode", "deny-by-default")
    if mode not in MODES:
        raise ValueError(f"{path}: mode must be one of {list(MODES)}, got {mode!r}")
    enforcement = raw.get("enforcement", "report-only")
    if enforcement not in ENFORCEMENT:
        raise ValueError(f"{path}: enforcement must be one of {list(ENFORCEMENT)}, "
                         f"got {enforcement!r}")

    principal = raw.get("principal")
    if not isinstance(principal, str) or not principal:
        raise ValueError(f"{path}: 'principal' is required (who asserts this identity model)")
    if authority_map is None:
        raise ValueError(f"{path}: an authority map is required to check '{principal}'")
    if IDENTITY_CLASS not in authority_map.get(principal, set()):
        raise ValueError(f"{path}: principal {principal!r} does not hold the "
                         f"'{IDENTITY_CLASS}' class in the authority map")

    break_glass = _parse_section(path, raw, "break_glass")
    trusted = _parse_section(path, raw, "trusted")
    agents = _parse_section(path, raw, "agents")
    if not break_glass:
        raise ValueError(f"{path}: 'break_glass' must name at least one identity; it is "
                         "never restricted, so an operator can always act")
    if mode == "deny-by-default" and agents:
        raise ValueError(f"{path}: mode deny-by-default treats every untrusted identity as "
                         "an agent; list 'trusted' identities, not 'agents' (or set mode: "
                         "agents-only)")
    if mode == "agents-only":
        if trusted:
            raise ValueError(f"{path}: mode agents-only restricts only the listed agents; "
                             "'trusted' has no effect there, remove it")
        if not agents:
            raise ValueError(f"{path}: mode agents-only needs at least one entry in 'agents'")

    seen: dict[tuple[str, str, str], str] = {}
    for section, pool in (("break_glass", break_glass), ("trusted", trusted),
                          ("agents", agents)):
        for ident in pool:
            dup = ident.duplicate_key
            if dup in seen:
                raise ValueError(f"{path}: {ident} is listed twice ({seen[dup]} and "
                                 f"{section}; names differing only in case count as one)")
            seen[dup] = section

    for ident in (*break_glass, *trusted):
        if (ident.platform, ident.kind) == ("kubernetes", "group") and (
            ident.id in _K8S_UNIVERSAL_GROUPS
        ):
            raise ValueError(f"{path}: {ident}: every identity carries this group, so "
                             "exempting it would exempt every agent")

    for ident in break_glass:
        if ident.platform == "github" and not _workflow_bound(ident.id):
            raise ValueError(
                f"{path}: break_glass: {ident.id} is scoped to a repository/ref, so any job "
                "in that repository (an agent's included) would present the strongest "
                "exemption; bind it with job_workflow_ref or a protected environment")
    for ident in trusted:
        if ident.platform == "github" and not _workflow_bound(ident.id):
            warnings.append(
                f"workflow-unbound: {ident.id} is scoped to a repository/ref, so any job "
                "in that repository (an agent's included) presents it; bind it with "
                "job_workflow_ref or a protected environment")
    listed = {i.platform for i in (*trusted, *agents)}
    covered = {i.platform for i in break_glass}
    for platform in (p for p in KINDS if p in listed - covered):
        if platform == "github":
            continue  # OIDC subjects are issued to workflows; nobody breaks glass as one
        warnings.append(f"no-break-glass: {platform} has listed identities but no "
                        "break-glass identity")
    return IdentityModel(str(path), mode, enforcement, principal, trusted, break_glass,
                         agents, tuple(warnings))
