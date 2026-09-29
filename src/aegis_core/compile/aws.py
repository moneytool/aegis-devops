"""``aegis compile aws``: the verified snapshot as AWS Service Control
Policies scoped to agent identities (design §6.1, §6.5).

An SCP sits above the account: an agent holding IAM rights inside the
account cannot detach it. Every statement is an explicit Deny carrying the
identity model's principal condition, so it applies only to agents:

* ``deny-by-default``: ``ArnNotLike aws:PrincipalArn`` (exempt roles and
  users) and ``StringNotEqualsIfExists aws:SourceIdentity`` (exempt source
  identities) -- every identity not exempt is restricted;
* ``agents-only``: ``ArnLike aws:PrincipalArn`` on the agent roles/users, and
  a second copy on ``StringEquals aws:SourceIdentity`` for agent source
  identities, each still excluding break-glass.

The compiled policy is only as exact as the action map (``actions/aws.yaml``)
and every mapping is ``unverified`` until a sandbox acceptance run; the
coverage report says so per rule.
"""

from __future__ import annotations

import fnmatch
import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis_core.compile import CompileError, canonical_json, pretty_json, sha256_text
from aegis_core.identity import IdentityModel
from aegis_core.store import ANY_ACTION, Constraint, VerifiedSnapshot, scope_value_matches

SCP_MAX_CHARS = 5120
# Five SCPs may attach to a target, one of which is usually FullAWSAccess.
DEFAULT_MAX_POLICIES = 4
PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
NAME_MODES = ("name", "arn", "cli-missing", "wildcard-only")

_PROBE = "\x00aegis-probe"
_GLOB = frozenset("*?[")

_EXEMPT_ROLE_WRITES = (
    "iam:AttachRolePolicy", "iam:DeleteRole", "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary",
    "iam:PutRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy",
    "iam:UpdateRole", "iam:UpdateRoleDescription",
)
_EXEMPT_USER_CREDENTIALS = (
    "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:CreateServiceSpecificCredential", "iam:DeactivateMFADevice", "iam:DeleteUser",
    "iam:PutUserPolicy", "iam:ResetServiceSpecificCredential", "iam:UpdateAccessKey",
    "iam:UpdateLoginProfile", "iam:UploadSSHPublicKey", "iam:UploadSigningCertificate",
)
_NEW_CREDENTIALS = (
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateUser",
    "iam:UpdateLoginProfile",
)

NOT_ENFORCED_BY_THIS_LAYER = (
    "SCPs do not apply to the organization's management account: attach these only to "
    "member accounts or OUs.",
    "SCPs do not restrict service-linked roles.",
    "sts:AssumeRoleWithWebIdentity and sts:AssumeRoleWithSAML are not evaluated against the "
    "caller's identity: a role whose trust policy accepts an agent's federated subject is an "
    "escape. Bind CI subjects to workflows (agents.yaml warns on workflow-unbound ones) and "
    "check trust policies with aegis audit-identity.",
    "Delegation to exempt actors: CloudFormation stacks, Service Catalog products and SSM "
    "Automation that already run with exempt roles act for whoever starts them. Passing an "
    "exempt role is denied; roles already attached are not.",
)


# --- the action map --------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    iam: tuple[str, ...]
    arns: tuple[str, ...]


@dataclass(frozen=True)
class TypeMap:
    type: str
    regional: bool
    names: str
    grants: dict[str, tuple[Grant, ...]]
    same_effect: dict[str, tuple[str, ...]]
    verified: bool


def _as_tuple(value: Any, where: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{where}: expected a string or a non-empty list of strings")
    return tuple(value)


def load_action_map(path: str | Path | None = None) -> dict[str, TypeMap]:
    """``actions/aws.yaml`` (or ``path``) -> ``{type: TypeMap}``."""
    if path is None:
        text = (importlib.resources.files("aegis_core.compile") / "actions" / "aws.yaml"
                ).read_text()
        where = "actions/aws.yaml"
    else:
        text, where = Path(path).read_text(), str(path)
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(
        raw.get("types"), dict
    ):
        raise ValueError(f"{where}: expected version: 1 and a 'types' mapping")
    out: dict[str, TypeMap] = {}
    for rtype, spec in raw["types"].items():
        w = f"{where}: {rtype}"
        if not isinstance(spec, dict) or rtype.count("/") != 1:
            raise ValueError(f"{w}: a type is '<service>/<kind>' mapping to a spec")
        default_arns = _as_tuple(spec.get("arn"), f"{w}.arn")
        names = spec.get("names", "name")
        if names not in NAME_MODES:
            raise ValueError(f"{w}: names must be one of {NAME_MODES}")
        grants: dict[str, tuple[Grant, ...]] = {}
        for verb, value in (spec.get("actions") or {}).items():
            if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                grants[verb] = tuple(
                    Grant(_as_tuple(g.get("iam"), f"{w}.{verb}.iam"),
                          _as_tuple(g["arn"], f"{w}.{verb}.arn") if "arn" in g
                          else default_arns)
                    for g in value)
            else:
                grants[verb] = (Grant(_as_tuple(value, f"{w}.{verb}"), default_arns),)
        if not grants:
            raise ValueError(f"{w}: no actions")
        same = {verb: _as_tuple(v, f"{w}.same_effect.{verb}")
                for verb, v in (spec.get("same_effect") or {}).items()}
        out[rtype] = TypeMap(rtype, bool(spec.get("regional", True)), names, grants, same,
                             spec.get("verified") is True)
    return out


# --- target and result -------------------------------------------------------------


@dataclass(frozen=True)
class AwsTarget:
    account: str
    env: str | None = None
    partition: str = "aws"
    escalate: str = "deny"  # or "omit": ESCALATE rules stay client-only
    max_policies: int = DEFAULT_MAX_POLICIES
    max_chars: int = SCP_MAX_CHARS

    def __post_init__(self) -> None:
        if not (self.account.isdigit() and len(self.account) == 12):
            raise CompileError(f"--account must be a 12-digit AWS account id, got "
                               f"{self.account!r}")
        if self.partition not in PARTITIONS:
            raise CompileError(f"--partition must be one of {PARTITIONS}")
        if self.escalate not in ("deny", "omit"):
            raise CompileError("--escalate must be 'deny' or 'omit'")


@dataclass
class CompileResult:
    files: dict[str, str]
    coverage: dict[str, Any]
    manifest: dict[str, Any]
    policies: list[dict[str, Any]] = field(default_factory=list)

    @property
    def deployable(self) -> bool:
        return bool(self.manifest["deployable"])


# --- per-rule compilation ------------------------------------------------------------


def _types_for(pattern: str, amap: dict[str, TypeMap]) -> tuple[list[tuple[TypeMap, str]], bool]:
    """The mapped types ``pattern`` can match, each with the name glob it
    puts on that type (``*`` for every name), and whether the pattern's
    type part is itself a glob (so types the map does not know are
    matched on the client but not compiled)."""
    parts = pattern.split("/", 2)
    type_glob = bool(_GLOB & set("/".join(parts[:2]))) if len(parts) == 3 else bool(
        _GLOB & set(pattern))
    hits = []
    for rtype, tm in sorted(amap.items()):
        if fnmatch.fnmatchcase(f"{rtype}/{_PROBE}", pattern):
            hits.append((tm, "*"))
        elif len(parts) == 3 and fnmatch.fnmatchcase(rtype, f"{parts[0]}/{parts[1]}"):
            hits.append((tm, parts[2]))
    return hits, type_glob


def _arn_glob(name: str) -> tuple[str, bool]:
    """An fnmatch name glob as an IAM ARN glob. ``*`` and ``?`` carry over;
    a ``[...]`` class has no IAM equivalent and becomes ``?`` (wider)."""
    out, widened, i = [], False, 0
    while i < len(name):
        ch = name[i]
        if ch == "[":
            j = name.find("]", i + 2 if name[i + 1:i + 2] in ("!", "]") else i + 1)
            if j != -1:
                out.append("?")
                widened = True
                i = j + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out), widened


@dataclass
class _Rule:
    c: Constraint
    status: str = ""
    enforced: list[dict[str, Any]] = field(default_factory=list)
    not_enforced: list[str] = field(default_factory=list)
    over: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    same_effect: list[str] = field(default_factory=list)
    verified: bool = True
    statements: list[str] = field(default_factory=list)
    # (arns, regional) -> iam actions, for statement building
    groups: dict[tuple[tuple[str, ...], bool], set[str]] = field(default_factory=dict)
    regions: list[str] | None = None
    reason: str | None = None  # not-applicable reason

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.c.id, "effect": self.c.effect, "status": self.status}
        if self.reason:
            d["reason"] = self.reason
        if self.enforced:
            d["mapping"] = "verified" if self.verified else "unverified"
            d["enforced"] = self.enforced
            d["statements"] = self.statements
        for key, value in (("not_enforced", self.not_enforced), ("over_enforced", self.over),
                           ("notes", self.notes),
                           ("same_effect_not_covered", self.same_effect)):
            if value:
                d[key] = value
        return d


def _listify(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _apply_scope(rule: _Rule, target: AwsTarget) -> None:
    for key, value in sorted(rule.c.scope.items()):
        if key == "env":
            if target.env is None:
                rule.over.append(
                    f"scope env={value!r}: account {target.account} has no environment in "
                    "environments.yaml, so the rule is compiled unconditionally (the CLI "
                    "escalates an unresolved environment)")
            elif not scope_value_matches(value, target.env):
                rule.reason = (f"scope env={value!r} does not include account "
                               f"{target.account}'s environment {target.env!r}")
                return
        elif key == "account":
            if not scope_value_matches(value, target.account):
                rule.reason = f"scope account={value!r} is not account {target.account}"
                return
        elif key == "region":
            regions = [str(v) for v in _listify(value)]
            if any("[" in r for r in regions):
                rule.over.append(f"scope region={value!r}: character classes are not "
                                 "expressible; the region condition is dropped")
            else:
                rule.regions = regions
        else:
            rule.over.append(f"scope {key}={value!r} cannot be expressed in an SCP; the "
                             "condition is dropped, so the deny applies more widely")


def _compile_rule(c: Constraint, target: AwsTarget, amap: dict[str, TypeMap]) -> _Rule:
    rule = _Rule(c)
    if c.provider != "aws":
        rule.reason = f"provider {c.provider}: not compiled by the aws target"
        if c.provider == "terraform":
            rule.reason += " (plan rules are enforced by the plan gate)"
        rule.status = "not-applicable"
        return rule
    _apply_scope(rule, target)
    if rule.reason:
        rule.status = "not-applicable"
        return rule
    if c.time_window:
        rule.not_enforced.append("recurring time windows have no SCP equivalent; the rule "
                                 "stays client-side (a permanent deny would over-block)")
    if c.rate_limit:
        rule.not_enforced.append("rate limits have no SCP equivalent; the rule stays "
                                 "client-side")
    if c.effect == "ESCALATE":
        if target.escalate == "omit":
            rule.not_enforced.append("ESCALATE left client-only (--escalate omit)")
        else:
            rule.over.append("ESCALATE compiles to a deny: a cloud API cannot ask, so the "
                             "client hook's approval no longer lets the action through")
    if rule.not_enforced:
        rule.status = "not-enforced"
        return rule

    hits, type_glob = _types_for(c.resource_pattern, amap)
    if not hits:
        rule.not_enforced.append(f"no action map entry matches {c.resource_pattern!r}")
    elif type_glob:
        rule.not_enforced.append(
            f"{c.resource_pattern!r} also matches resource types the action map does not "
            f"know; only {', '.join(tm.type for tm, _ in hits)} are enforced")
    for tm, name in hits:
        arn_name, widened = _arn_glob(name)
        if widened:
            rule.over.append(f"{tm.type}: name pattern {name!r} uses a character class; "
                             f"compiled as {arn_name!r}")
        if tm.names == "wildcard-only" and arn_name != "*":
            rule.not_enforced.append(f"{tm.type}: names cannot be translated to ARNs for "
                                     f"this type; only rules covering every name compile")
            continue
        if tm.names == "arn" and arn_name != "*" and not arn_name.startswith("arn:"):
            rule.not_enforced.append(f"{tm.type}: the CLI names this type by ARN; "
                                     f"{name!r} is not an ARN")
            continue
        if tm.names == "cli-missing" and arn_name != "*":
            rule.notes.append(f"{tm.type}: the client-side parser does not extract a name "
                              f"for this type, so the CLI check never matches {name!r}; the "
                              "compiled policy does")
        if rule.regions is not None and not tm.regional:
            rule.over.append(f"{tm.type} is a global service: the region condition "
                             "cannot apply, so it is denied in every region")
        if ANY_ACTION in c.actions:
            verbs = sorted(tm.grants)
            rule.notes.append(f"{tm.type}: actions '*' compiles the mapped actions "
                              f"({', '.join(verbs)}); others are client-side only")
        else:
            verbs = sorted(c.actions)
        for verb in verbs:
            grants = tm.grants.get(verb)
            if not grants:
                rule.not_enforced.append(f"{tm.type}: action {verb!r} is not in the action map")
                continue
            if not tm.verified:
                rule.verified = False
            iam: list[str] = []
            for g in grants:
                if arn_name == "*":
                    # every name: the action is denied outright, as the CLI
                    # blocks it whoever owns the resource (and statements that
                    # share a condition can then merge exactly)
                    arns = ("*",)
                elif tm.names == "arn":
                    arns = (arn_name,)
                else:
                    arns = tuple(a.replace("{partition}", target.partition)
                                 .replace("{account}", target.account)
                                 .replace("{name}", arn_name) for a in g.arns)
                arns = tuple(dict.fromkeys(arns))
                rule.groups.setdefault((arns, tm.regional), set()).update(g.iam)
                iam.extend(g.iam)
            rule.enforced.append({"type": tm.type, "action": verb, "name": arn_name,
                                  "iam": sorted(set(iam))})
            for effect in tm.same_effect.get(verb, ()):
                rule.same_effect.append(f"{tm.type} {verb}: {effect}")

    if not rule.enforced:
        rule.status = "not-enforced"
    elif rule.not_enforced:
        rule.status = "partial"
    elif rule.over:
        rule.status = "over-enforced"
    else:
        rule.status = "exact"
    return rule


# --- identity conditions and self-protection ------------------------------------------


def _principal_conditions(model: IdentityModel) -> list[dict[str, Any]]:
    """One condition block per statement copy (see the module docstring)."""
    model.require_platform("aws")
    exempt = model.exempt("aws")
    ex_arns = sorted(i.id for i in exempt if i.kind in ("role", "user"))
    ex_si = sorted(i.id for i in exempt if i.kind == "source-identity")
    if model.mode == "deny-by-default":
        cond: dict[str, Any] = {}
        if ex_arns:
            cond["ArnNotLike"] = {"aws:PrincipalArn": ex_arns}
        if ex_si:
            cond["StringNotEqualsIfExists"] = {"aws:SourceIdentity": ex_si}
        return [cond]
    agents = model.agents_for("aws")
    ag_arns = sorted(i.id for i in agents if i.kind in ("role", "user"))
    ag_si = sorted(i.id for i in agents if i.kind == "source-identity")
    variants = []
    if ag_arns:
        cond = {"ArnLike": {"aws:PrincipalArn": ag_arns}}
        if ex_si:
            cond["StringNotEqualsIfExists"] = {"aws:SourceIdentity": ex_si}
        variants.append(cond)
    if ag_si:
        cond = {"StringEquals": {"aws:SourceIdentity": ag_si}}
        if ex_arns:
            cond["ArnNotLike"] = {"aws:PrincipalArn": ex_arns}
        variants.append(cond)
    return variants


def _self_protection(model: IdentityModel) -> list[tuple[str, dict[str, Any], str]]:
    """``(name, statement body without Sid/Condition, why)`` per §4.3 (AWS)."""
    exempt = model.exempt("aws")
    roles = sorted(i.id for i in exempt if i.kind == "role")
    users = sorted(i.id for i in exempt if i.kind == "user")
    has_si = any(i.kind == "source-identity" for i in exempt)
    out = []
    if model.mode == "deny-by-default":
        if roles:
            out.append(("assume-exempt-role", {"Action": ["sts:AssumeRole"], "Resource": roles},
                        "agents cannot assume a trusted or break-glass role"))
            out.append(("pass-exempt-role", {"Action": ["iam:PassRole"], "Resource": roles},
                        "agents cannot hand a trusted role to Lambda, ECS, EC2, "
                        "CloudFormation or another service to act for them"))
            out.append(("modify-exempt-role", {"Action": list(_EXEMPT_ROLE_WRITES),
                                               "Resource": roles},
                        "agents cannot change a trusted role's trust or permissions "
                        "(e.g. to let themselves assume it)"))
        if users:
            out.append(("exempt-user-credentials", {"Action": list(_EXEMPT_USER_CREDENTIALS),
                                                    "Resource": users},
                        "agents cannot mint credentials for, or change, a trusted user"))
    else:
        agent_roles = sorted(i.id for i in model.agents_for("aws") if i.kind == "role")
        if agent_roles:
            out.append(("assume-non-agent-role", {"Action": ["sts:AssumeRole"],
                                                  "NotResource": agent_roles},
                        "agents-only: every unlisted role is exempt, so agents may assume "
                        "only agent roles"))
            out.append(("pass-non-agent-role", {"Action": ["iam:PassRole"],
                                                "NotResource": agent_roles},
                        "agents-only: agents may pass only agent roles to services"))
        out.append(("new-credentials", {"Action": list(_NEW_CREDENTIALS), "Resource": "*"},
                    "agents-only: a new user or key is unlisted, hence exempt"))
    if has_si:
        out.append(("set-source-identity", {"Action": ["sts:SetSourceIdentity"],
                                            "Resource": "*"},
                    "a source identity is exempt, so agents cannot set one (a session's "
                    "source identity persists through role chaining without it)"))
    out.append(("leave-organization", {"Action": ["organizations:LeaveOrganization"],
                                       "Resource": "*"},
                "an account that leaves the organization sheds its SCPs"))
    return out


def _merge(protos: list[tuple[list[str], dict[str, Any], dict[str, Any]]]
           ) -> list[tuple[list[str], dict[str, Any], dict[str, Any]]]:
    """Exact merges only: statements with the same extra condition and the
    same resources pool their actions; then those with the same actions
    pool their resources. (Action x resource cross products that were not
    in the input are never created.)"""
    def by(key_field: str, pool_field: str, items):
        out: dict[str, tuple[list[str], dict[str, Any], dict[str, Any]]] = {}
        for owners, body, extra in items:
            key = canonical_json([extra, body[key_field]])
            if key in out:
                o_owners, o_body, _ = out[key]
                o_owners.extend(o for o in owners if o not in o_owners)
                o_body[pool_field] = sorted(set(o_body[pool_field]) | set(body[pool_field]))
            else:
                out[key] = (list(owners), {**body, pool_field: sorted(set(body[pool_field]))},
                            extra)
        return list(out.values())

    return by("Action", "Resource", by("Resource", "Action", protos))


# --- packing -----------------------------------------------------------------------------


def _policy(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def _pack(statements: list[dict[str, Any]], target: AwsTarget) -> list[list[dict[str, Any]]]:
    """First-fit, in order, into policies of at most ``max_chars``
    (minified). Fails loudly rather than drop a statement."""
    policies: list[list[dict[str, Any]]] = []
    for st in statements:
        if len(canonical_json(_policy([st]))) > target.max_chars:
            raise CompileError(f"statement {st['Sid']} alone exceeds the {target.max_chars}-"
                               "character SCP limit; narrow the rule or the identity lists")
        for bucket in policies:
            if len(canonical_json(_policy([*bucket, st]))) <= target.max_chars:
                bucket.append(st)
                break
        else:
            policies.append([st])
    if len(policies) > target.max_policies:
        raise CompileError(f"the compiled policy needs {len(policies)} SCPs but at most "
                           f"{target.max_policies} can attach (--max-policies); split the "
                           "policy or narrow its rules")
    return policies


# --- the compiler -------------------------------------------------------------------------


def compile_aws(
    snapshot: VerifiedSnapshot,
    model: IdentityModel,
    target: AwsTarget,
    action_map: dict[str, TypeMap] | None = None,
    *,
    identity_sha256: str = "",
) -> CompileResult:
    amap = action_map if action_map is not None else load_action_map()
    conditions = _principal_conditions(model)

    # Statement bodies before identity conditions: (owners, body, extra condition).
    protos: list[tuple[list[str], dict[str, Any], dict[str, Any]]] = []
    self_protection = []
    for name, body, why in _self_protection(model):
        protos.append(([f"self-protection:{name}"], body, {}))
        self_protection.append({"name": name, "why": why, "mapping": "unverified"})

    compiled = []
    rule_protos: list[tuple[list[str], dict[str, Any], dict[str, Any]]] = []
    for c in snapshot.constraints:
        rule = _compile_rule(c, target, amap)
        compiled.append(rule)
        for (arns, regional), iam in sorted(rule.groups.items()):
            extra = ({"StringLike": {"aws:RequestedRegion": rule.regions}}
                     if rule.regions and regional else {})
            rule_protos.append(([f"rule:{c.id}"], {"Action": sorted(iam),
                                                   "Resource": list(arns)}, extra))
    protos += _merge(rule_protos)

    statements: list[dict[str, Any]] = []
    sid_map: dict[str, list[str]] = {}
    sids_by_owner: dict[str, list[str]] = {}
    for owners, body, extra in protos:
        for cond in conditions:
            sid = f"Aegis{len(statements) + 1}"
            merged = {k: dict(v) for k, v in cond.items()}
            for op, kv in extra.items():
                merged.setdefault(op, {}).update(kv)
            statements.append({"Sid": sid, "Effect": "Deny", **body, "Condition": merged})
            sid_map[sid] = owners
            for owner in owners:
                sids_by_owner.setdefault(owner, []).append(sid)
    for sp in self_protection:
        sp["statements"] = sids_by_owner[f"self-protection:{sp['name']}"]
    rules = []
    for rule in compiled:
        rule.statements = sids_by_owner.get(f"rule:{rule.c.id}", [])
        rules.append(rule.to_dict())

    packed = _pack(statements, target)
    deployable = model.enforcement == "enforce"
    prefix = "" if deployable else "report-only/"
    files: dict[str, str] = {}
    policies = []
    for n, bucket in enumerate(packed, 1):
        rel = f"{prefix}scp-{n}.json"
        text = canonical_json(_policy(bucket)) + "\n"
        files[rel] = text
        policies.append({"file": rel, "sha256": sha256_text(text), "chars": len(text) - 1,
                         "statements": [st["Sid"] for st in bucket]})

    counts: dict[str, int] = {}
    for r in rules:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    coverage = {
        "target": "aws-scp",
        "account": target.account,
        "env": target.env,
        "mode": model.mode,
        "enforcement": model.enforcement,
        "summary": dict(sorted(counts.items())),
        "rules": rules,
        "excluded": list(snapshot.excluded),
        "self_protection": self_protection,
        "not_enforced_by_this_layer": list(NOT_ENFORCED_BY_THIS_LAYER),
    }
    files["coverage.json"] = pretty_json(coverage)
    files["coverage.md"] = _coverage_md(coverage)
    digest = snapshot.digest
    manifest = {
        "aegis_version": snapshot.aegis_version,
        "target": "aws-scp",
        "account": target.account,
        "partition": target.partition,
        "env": target.env,
        "mode": model.mode,
        "enforcement": model.enforcement,
        "deployable": deployable,
        "escalate": target.escalate,
        "snapshot_digest": digest,
        "identity_model_sha256": identity_sha256,
        "policy_description": f"Aegis policy {digest[:16]} (aegis {snapshot.aegis_version})",
        "policies": policies,
        "statements": {sid: sid_map[sid] for sid in sorted(sid_map, key=lambda k: int(k[5:]))},
        "files": sorted(files),
    }
    manifest["output_digest"] = sha256_text(canonical_json(
        {rel: sha256_text(text) for rel, text in sorted(files.items())}))
    files["manifest.json"] = pretty_json(manifest)
    return CompileResult(files, coverage, manifest, [_policy(b) for b in packed])


def _coverage_md(cov: dict[str, Any]) -> str:
    lines = [
        f"# Aegis coverage: AWS SCP for account {cov['account']}",
        "",
        f"Environment: {cov['env'] or 'not mapped'}; identity model: {cov['mode']}, "
        f"{cov['enforcement']}.",
        "",
    ]
    if cov["enforcement"] != "enforce":
        lines += [
            "**Report only.** The policies are under `report-only/` and are not meant to be "
            "attached. Review `aegis audit-identity --would-restrict`, then set "
            "`enforcement: enforce` in agents.yaml (a signed change) and compile again.",
            "",
        ]
    lines += ["| status | rules |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in cov["summary"].items()]
    lines += ["", "## Rules", ""]
    for r in cov["rules"]:
        if r["status"] == "not-applicable":
            continue
        mapping = f", mapping {r['mapping']}" if "mapping" in r else ""
        lines.append(f"### `{r['id']}`: {r['status']}{mapping}")
        if r.get("reason"):
            lines.append(f"- {r['reason']}")
        for e in r.get("enforced", []):
            lines.append(f"- enforced: {e['type']} {e['action']} "
                         f"(`{', '.join(e['iam'])}`, name `{e['name']}`)")
        for key, label in (("not_enforced", "not enforced"), ("over_enforced", "over-enforced"),
                           ("notes", "note"), ("same_effect_not_covered",
                                               "same effect, not covered")):
            for item in r.get(key, []):
                lines.append(f"- {label}: {item}")
        lines.append("")
    skipped = [r for r in cov["rules"] if r["status"] == "not-applicable"]
    if skipped:
        lines += ["## Not applicable to this target", ""]
        lines += [f"- `{r['id']}`: {r['reason']}" for r in skipped]
        lines.append("")
    if cov["excluded"]:
        lines += ["## Excluded from the snapshot", ""]
        lines += [f"- `{e['id']}`: {e['reason']}" for e in cov["excluded"]]
        lines.append("")
    lines += ["## Self-protection", ""]
    lines += [f"- {s['name']} ({', '.join(s['statements'])}): {s['why']}"
              for s in cov["self_protection"]]
    lines += ["", "## Not enforced by this layer", ""]
    lines += [f"- {n}" for n in cov["not_enforced_by_this_layer"]]
    return "\n".join(lines) + "\n"


# --- offline evaluator (consistency, not truth: design §8) ----------------------------------


def _glob(value: str, pattern: str, *, case: bool = True) -> bool:
    # IAM globs know only * and ?; escape [ so fnmatch does not read a class
    pattern = pattern.replace("[", "[[]")
    if not case:
        return fnmatch.fnmatchcase(value.lower(), pattern.lower())
    return fnmatch.fnmatchcase(value, pattern)


def _condition_holds(op: str, values: list[str], actual: str | None) -> bool:
    base, if_exists = (op[:-8], True) if op.endswith("IfExists") else (op, False)
    if actual is None:
        return if_exists or base.startswith(("StringNot", "ArnNot"))
    if base in ("StringEquals",):
        return actual in values
    if base in ("StringNotEquals",):
        return actual not in values
    if base in ("StringLike", "ArnLike", "ArnEquals"):
        return any(_glob(actual, v) for v in values)
    if base in ("StringNotLike", "ArnNotLike", "ArnNotEquals"):
        return not any(_glob(actual, v) for v in values)
    raise ValueError(f"offline evaluator: unsupported condition operator {op}")


def denying_statements(
    policies: list[dict[str, Any]],
    *,
    action: str,
    resource: str,
    principal_arn: str,
    source_identity: str | None = None,
    region: str = "us-east-1",
) -> list[str]:
    """The Sids of every compiled Deny that matches this request. A model of
    the subset of IAM evaluation the compiler emits, for tests and dry runs;
    the IAM policy simulator and a sandbox run are the ground truth."""
    context = {"aws:PrincipalArn": principal_arn, "aws:SourceIdentity": source_identity,
               "aws:RequestedRegion": region}
    hits = []
    for policy in policies:
        for st in policy["Statement"]:
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if not any(_glob(action, a, case=False) for a in actions):
                continue
            if "Resource" in st:
                res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                if not any(_glob(resource, r) for r in res):
                    continue
            else:
                res = st["NotResource"]
                res = res if isinstance(res, list) else [res]
                if any(_glob(resource, r) for r in res):
                    continue
            if all(_condition_holds(op, vals if isinstance(vals, list) else [vals],
                                    context.get(key))
                   for op, kv in st.get("Condition", {}).items()
                   for key, vals in kv.items()):
                hits.append(st["Sid"])
    return hits
