"""The Constraint Store: a schema-strict, provenance-verified repository of
operational boundaries.

Every constraint carries two independent guarantees:
  * Integrity (``provenance_hash``) — the constraint's fields match what was
    originally derived from its source.
  * Authority (checked against an externally supplied ``authority_map``) —
    the principal asserting the constraint is allowed to assert that class
    of constraint.

Neither guarantee implies the other: integrity only proves nothing was
tampered with since ingestion, not that the source was ever allowed to set
policy in the first place.

**Load-time pipeline** (``ConstraintStore.load``): for each constraint on
disk, in order —
  1. Integrity  — ``verify_integrity()``; a mismatch quarantines the
     constraint with reason ``"tampered"``.
  2. Source     — only when a ``source_fetcher`` is supplied:
     ``verify_source()`` is re-run against the original source; ``False``
     or a missing/unreadable source (``FileNotFoundError``/``KeyError``)
     quarantines the constraint with reason ``"forged"``. Without a
     fetcher this step is skipped, so forged constraints load normally —
     the fetcher is what makes forgery detectable at all.
  3. Authority-at-decision — *not* checked at load time; a constraint may
     be authorized when ingested and have that authority revoked later, so
     authority is (re-)checked by the interceptor at decision time instead
     (see ``interceptor.py``).

``ConstraintStore.verify_sources`` runs step 2 as a standalone, post-hoc
audit over an already-loaded store, moving any newly-forged constraints
from ``constraints`` into ``quarantined``.

**Validation (REVIEW-4 T1.8).** Before any of the above, each entry is
shape-checked (:func:`validate_constraint_dict`); a malformed entry --
missing key, ``effect: Block``, ``days: [Friday]``, ``start: 10:00``
unquoted (YAML reads it as the integer 600), unknown ``tz``, duplicate
``id`` -- is quarantined with reason ``"invalid: <why>"`` and never
constructed, so a typo can neither traceback nor be cited as a reason to
ALLOW. Invalid entries have no ``Constraint`` object and so are not
matched, but they do count towards ``StoreHealth.quarantine_ratio``.

**Signatures (REVIEW-4 T1.1).** ``load(..., key=K)`` refuses a constraints
file without a valid ``<path>.sig`` (:class:`aegis_core.signing.SignatureError`);
``load()`` without a key records ``"unsigned: <path>"`` in ``warnings``
unless ``insecure=True``.

**Quarantine is not deletion.** A quarantined constraint's ``Constraint``
object is kept in ``quarantined_constraints`` and is still *matched*
against intents (``get_matching_quarantined``), because a rule someone
tampered with or forged is evidence that the action it covers is
contested. The interceptor turns such a match into ESCALATE — never
BLOCK, never ALLOW — so a degraded store fails closed instead of looking
like a clean allow. ``store.health`` (:class:`StoreHealth`) summarises the
load for the CLI's ``store_health`` output.
"""

import fnmatch
import hashlib
import json
import logging
import re
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from aegis_core.intent import InfrastructureIntent
from aegis_core.provenance import (
    CachingSourceFetcher,
    SourceFetcher,
    compute_provenance_hash,
    verify_source,
    verify_source_reason,
)
from aegis_core.signing import check_signature

logger = logging.getLogger(__name__)

# REVIEW-4 T2.3: the C-accelerated loader is 6x faster at 10k constraints;
# fall back to the pure-Python SafeLoader when libyaml isn't available.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_WEEKDAY_ABBR = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
VALID_EFFECTS = frozenset({"BLOCK", "ESCALATE"})
_HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_END_OF_DAY = "24:00"  # REVIEW-4 T2.4: the only valid end-of-window spelling of midnight
_RATE_PER = re.compile(r"^[1-9][0-9]*[mhd]$")
_REQUIRED_KEYS = (
    "id", "provider", "resource_pattern", "actions", "effect", "constraint_class",
    "principal", "source_ref", "source_timestamp", "rule_text", "provenance_hash",
)
# REVIEW-4 T2.3: "*" in a constraint's actions means "any action" -- it is
# otherwise an ordinary string (no special validation, no effect on the
# provenance hash, which already hashes the actions set as given).
ANY_ACTION = "*"


@dataclass
class StoreHealth:
    """What the CLI reports as ``store_health`` on every output: how many
    constraints actually loaded, which were quarantined and why, how many
    principals the authority map grants anything to, and the SHA-256 of the
    raw constraints file bytes that were loaded."""

    loaded: int = 0
    quarantined: list[dict[str, str]] = field(default_factory=list)
    principals: int = 0
    constraints_sha256: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def quarantine_ratio(self) -> float:
        total = self.loaded + len(self.quarantined)
        return len(self.quarantined) / total if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256_file(path: str | Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


@dataclass
class Constraint:
    """A single, structured operational boundary.

    ``rule_text`` is the human sentence this constraint was derived from —
    it is kept for citation only and is never matched against an intent.
    """
    id: str
    provider: str
    resource_pattern: str
    actions: set[str]
    scope: dict[str, Any]
    time_window: dict[str, Any] | None
    effect: str
    constraint_class: str
    principal: str
    source_ref: str
    source_timestamp: str
    rule_text: str
    provenance_hash: str
    rate_limit: dict[str, Any] | None = None
    """Optional rate/budget rule: ``{"max": N, "per": "1h"|"24h"|"15m",
    "key": [<metadata keys to bucket by>]}`` (PLAN §7.6). ``None`` (the
    default) means this constraint is absolute, not rate-limited — and is
    also what keeps every pre-existing constraint's provenance hash
    unchanged, since it's included in the hash only when set."""

    def __post_init__(self) -> None:
        if self.effect not in VALID_EFFECTS:
            raise ValueError(
                f"constraint {self.id!r}: effect must be BLOCK or ESCALATE, got {self.effect!r}"
            )

    @classmethod
    def create(
        cls,
        *,
        id: str,
        provider: str,
        resource_pattern: str,
        actions: set[str],
        effect: str,
        constraint_class: str,
        principal: str,
        source_ref: str,
        source_timestamp: str,
        rule_text: str,
        scope: dict[str, Any] | None = None,
        time_window: dict[str, Any] | None = None,
        rate_limit: dict[str, Any] | None = None,
    ) -> "Constraint":
        """Builds a Constraint and computes its provenance hash from the
        source-side fields."""
        actions = set(actions)
        scope = dict(scope or {})
        provenance_hash = compute_provenance_hash(
            provider=provider,
            resource_pattern=resource_pattern,
            actions=actions,
            scope=scope,
            time_window=time_window,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            rate_limit=rate_limit,
        )
        return cls(
            id=id,
            provider=provider,
            resource_pattern=resource_pattern,
            actions=actions,
            scope=scope,
            time_window=time_window,
            effect=effect,
            constraint_class=constraint_class,
            principal=principal,
            source_ref=source_ref,
            source_timestamp=source_timestamp,
            rule_text=rule_text,
            rate_limit=rate_limit,
            provenance_hash=provenance_hash,
        )

    def verify_integrity(self) -> bool:
        """Recomputes the provenance hash from the constraint's current
        fields and checks it against the stored hash."""
        expected = compute_provenance_hash(
            provider=self.provider,
            resource_pattern=self.resource_pattern,
            actions=self.actions,
            scope=self.scope,
            time_window=self.time_window,
            effect=self.effect,
            constraint_class=self.constraint_class,
            principal=self.principal,
            source_ref=self.source_ref,
            source_timestamp=self.source_timestamp,
            rule_text=self.rule_text,
            rate_limit=self.rate_limit,
        )
        return expected == self.provenance_hash


def _constraint_to_dict(c: Constraint) -> dict[str, Any]:
    data = {
        "id": c.id,
        "provider": c.provider,
        "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions),
        "scope": c.scope,
        "time_window": c.time_window,
        "effect": c.effect,
        "constraint_class": c.constraint_class,
        "principal": c.principal,
        "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp,
        "rule_text": c.rule_text,
        "provenance_hash": c.provenance_hash,
    }
    # Only written when set, so save()/load() round-trip existing (v1)
    # constraint files byte-for-byte unchanged.
    if c.rate_limit is not None:
        data["rate_limit"] = c.rate_limit
    return data


def _valid_edge(edge: str, value: str) -> bool:
    """``start``/``end`` are ``HH:MM``; ``end`` alone may also be ``24:00``
    (REVIEW-4 T2.4) -- the only way to say "through midnight" now that
    ``end`` is exclusive at minute granularity."""
    if _HHMM.match(value):
        return True
    return edge == "end" and value == _END_OF_DAY


def _tzdata_available() -> bool:
    """Probes whether the ``tzdata`` database is usable at all (REVIEW-4
    L1) -- distinct from a single unresolvable ``tz`` name. A slim
    container with no IANA database installed makes *every* ``ZoneInfo(...)``
    call raise ``ZoneInfoNotFoundError``, including for ``"UTC"``; treating
    that the same as "this one constraint names a bad tz" would quarantine
    every time-windowed constraint in the store as individually ``invalid``,
    which is misleading (it's an environment problem, not a policy one) and
    can trip the quarantine-ratio hard fail for reasons that have nothing
    to do with the policy files. Called fresh (never cached at import time)
    so tests can simulate the missing-tzdata case by monkeypatching
    ``zoneinfo.ZoneInfo``."""
    try:
        ZoneInfo("UTC")
        return True
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return False


def _validate_time_window(
    window: Any, default_tz: str | None = None, tzdata_available: bool = True
) -> str | None:
    """Shape-checks one ``time_window`` mapping.

    ``default_tz`` is the store-level fallback (REVIEW-4 T2.4): a window
    with no ``tz`` of its own is valid only when the store carries one.

    ``tzdata_available=False`` (REVIEW-4 L1) skips the ``ZoneInfo(tz)``
    resolvability check -- every name would fail identically when the
    tzdata database itself is missing, so that check would misreport a
    system problem as "unknown tz" on every time-windowed constraint. The
    interceptor instead fails closed on these at decision time (see
    ``ConstraintStore.get_time_window_unresolved``).
    """
    if window is None:
        return None
    if not isinstance(window, dict):
        return "time_window must be a mapping"
    days = window.get("days")
    if days is not None:
        if not isinstance(days, list) or not all(d in _WEEKDAY_ABBR for d in days):
            return "days must be Mon..Sun"
    for edge in ("start", "end"):
        value = window.get(edge)
        if value is not None and not (isinstance(value, str) and _valid_edge(edge, value)):
            return f"{edge} must be HH:MM (quote it in YAML)"
    if (window.get("start") is None) != (window.get("end") is None):
        return "start and end must be given together"
    tz = window.get("tz")
    if tz is not None:
        if not isinstance(tz, str):
            return "tz must be a string"
        if tzdata_available:
            try:
                ZoneInfo(tz)
            except (ZoneInfoNotFoundError, ValueError, OSError):
                return f"unknown tz {tz!r}"
    elif default_tz is None:
        return "time_window.tz missing and no default_tz"
    return None


def _validate_default_tz(default_tz: Any, tzdata_available: bool = True) -> str | None:
    """Shape-checks the store-level ``default_tz`` key. Returns a short
    reason (no prefix) when invalid, else ``None``. See
    :func:`_validate_time_window` for ``tzdata_available``."""
    if default_tz is None:
        return None
    if not isinstance(default_tz, str):
        return "default_tz must be a string"
    if tzdata_available:
        try:
            ZoneInfo(default_tz)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            return f"unknown default_tz {default_tz!r}"
    return None


def _validate_rate_limit(rate_limit: Any) -> str | None:
    if rate_limit is None:
        return None
    if not isinstance(rate_limit, dict):
        return "rate_limit must be a mapping"
    max_ = rate_limit.get("max")
    if isinstance(max_, bool) or not isinstance(max_, int) or max_ < 0:
        return "rate_limit.max must be a non-negative integer"
    per = rate_limit.get("per")
    if not isinstance(per, str) or not _RATE_PER.match(per):
        return "rate_limit.per must look like 15m, 1h or 24h"
    key = rate_limit.get("key")
    if key is not None and (
        not isinstance(key, list) or not all(isinstance(k, str) and k for k in key)
    ):
        return "rate_limit.key must be a list of field names"
    return None


def validate_constraint_dict(
    data: Any,
    default_tz: str | None = None,
    tzdata_available: bool = True,
    warnings: list[str] | None = None,
) -> str | None:
    """Shape-checks one raw constraint entry. Returns ``None`` when it is
    well-formed, else a short reason (without the ``"invalid: "`` prefix).

    ``default_tz`` is the store-level fallback used to validate a
    ``time_window`` with no ``tz`` of its own (REVIEW-4 T2.4).
    ``tzdata_available`` see :func:`_validate_time_window` (REVIEW-4 L1).
    ``warnings``, if given, collects non-fatal load-time notes (e.g. an
    upper-case ``resource_pattern``) for a *well-formed* entry -- it is
    never appended to for a malformed one, which reports its reason via
    the return value instead."""
    if not isinstance(data, dict):
        return "entry must be a mapping"
    for key in _REQUIRED_KEYS:
        if key not in data or data[key] is None:
            return f"missing {key}"
    for key in ("id", "provider", "resource_pattern", "constraint_class", "principal",
                "source_ref", "source_timestamp", "rule_text", "provenance_hash"):
        if not isinstance(data[key], str) or not data[key].strip():
            return f"{key} must be a non-empty string"
    if data["effect"] not in VALID_EFFECTS:
        return f"effect must be BLOCK or ESCALATE, got {data['effect']!r}"
    actions = data["actions"]
    if (
        not isinstance(actions, list)
        or not actions
        or not all(isinstance(a, str) and a for a in actions)
    ):
        return "actions must be a non-empty list of strings"
    if data.get("scope") is not None and not isinstance(data["scope"], dict):
        return "scope must be a mapping"
    resource_pattern = data["resource_pattern"]
    if resource_pattern != resource_pattern.lower() and warnings is not None:
        # REVIEW-4 extras / adversarial 'evade-case-variant': the parser
        # normalises a kubectl resource *kind* to lower-case (parser.py
        # `_split_resource_token`), so an intent built via the CLI never
        # carries an upper-case kind. But `resource_matches` uses a
        # case-sensitive fnmatch, so a constraint author who writes
        # `resource_pattern: "Deployment/*"` writes a rule that then never
        # fires against any CLI-derived intent (which is always
        # lower-case) -- a self-inflicted authoring mistake, not an
        # attacker-controlled evasion, but worth a load-time nudge.
        warnings.append(f"resource_pattern is matched case-sensitively: {resource_pattern!r}")
    reason = _validate_time_window(data.get("time_window"), default_tz, tzdata_available)
    if reason:
        return reason
    return _validate_rate_limit(data.get("rate_limit"))


def _constraint_from_dict(data: dict[str, Any]) -> Constraint:
    """Builds a :class:`Constraint` from an already-validated entry (see
    :func:`validate_constraint_dict`)."""
    return Constraint(
        id=data["id"],
        provider=data["provider"],
        resource_pattern=data["resource_pattern"],
        actions=set(data["actions"]),
        scope=data.get("scope") or {},
        time_window=data.get("time_window"),
        effect=data["effect"],
        constraint_class=data["constraint_class"],
        principal=data["principal"],
        source_ref=data["source_ref"],
        source_timestamp=data["source_timestamp"],
        rule_text=data["rule_text"],
        provenance_hash=data["provenance_hash"],
        rate_limit=data.get("rate_limit"),
    )


# ---------------------------------------------------------------------------
# Scope matching (REVIEW-4 T1.5 / T2.5)
# ---------------------------------------------------------------------------

_GLOB_CHARS = frozenset("*?[")


def _dig(mapping: dict[str, Any], key: str) -> tuple[bool, Any]:
    """``(found, value)`` for ``key`` in ``mapping`` -- a literal key first,
    then a dotted path (``set.replicaCount`` -> ``mapping["set"]["replicaCount"]``)."""
    if key in mapping:
        return True, mapping[key]
    if "." in key:
        current: Any = mapping
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                return False, None
            current = current[part]
        return True, current
    return False, None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def scope_value_matches(expected: Any, actual: Any) -> bool:
    """One scope value against one intent value:

    * a list of expected values is an OR;
    * if either side is a bool, both are read as booleans (``"true"``/
      ``"false"`` strings, any case, count);
    * if either side is a string, both are compared as strings, with
      ``*``/``?``/``[...]`` in the expected side as an fnmatch glob (so YAML
      ``account: 123456789012`` matches ``"123456789012"``).
    """
    if isinstance(expected, list):
        return any(scope_value_matches(e, actual) for e in expected)
    if isinstance(expected, bool) or isinstance(actual, bool):
        e, a = _as_bool(expected), _as_bool(actual)
        return e is not None and e == a
    if isinstance(expected, str) or isinstance(actual, str):
        if actual is None or isinstance(actual, (dict, list)):
            return False
        e, a = str(expected), str(actual)
        if _GLOB_CHARS & set(e):
            return fnmatch.fnmatchcase(a, e)
        return a == e
    return expected == actual


def scope_matches(
    scope: dict[str, Any], metadata: dict[str, Any], params: dict[str, Any]
) -> bool:
    """Whether every ``scope`` key is satisfied by the intent. Each key is
    looked up in ``metadata`` first -- operator-derived context (resolved
    ``env``, ``context``, ``account`` ...) that an agent-supplied ``--env``
    flag in ``params`` must never shadow (REVIEW-4 H4) -- and only in
    ``params`` when ``metadata`` lacks it entirely. A key absent from both
    never matches."""
    for key, expected in scope.items():
        found, actual = _dig(metadata, key)
        if not found:
            found, actual = _dig(params, key)
        if not found or not scope_value_matches(expected, actual):
            return False
    return True


def _scope_matches(scope: dict[str, Any], intent: InfrastructureIntent) -> bool:
    if not scope:
        return True
    return scope_matches(scope, intent.metadata, intent.params)


def _require_tz_aware(now: datetime) -> None:
    """REVIEW-4 T2.4: a naive ``now`` used to silently be treated as UTC,
    which quietly miscomputed every time-windowed decision for a caller
    who forgot ``tzinfo``. Fail loudly instead."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")


def _minutes_since_midnight(value: str) -> int:
    if value == _END_OF_DAY:
        return 24 * 60
    hh, mm = value.split(":")
    return int(hh) * 60 + int(mm)


def _time_window_matches(
    window: dict[str, Any], now: datetime, default_tz: str | None = None
) -> bool:
    """Whether ``now`` falls inside ``window``.

    * ``tz`` (or the store's ``default_tz``) localises ``now`` before any
      comparison; both are validated at load time, so one of them is
      always present for a constraint that reaches this function.
    * ``days`` excludes by the *local* weekday.
    * ``start``/``end`` support wrap-around (``start > end``, e.g.
      ``22:00``-``06:00``) -- match when ``t >= start or t < end`` --  and
      ``end`` is exclusive at minute granularity: ``09:00``-``17:00`` means
      ``[09:00, 17:00)``. ``24:00`` is accepted as ``end`` to mean
      "through midnight". Seconds on ``now`` are truncated before the
      comparison.
    """
    _require_tz_aware(now)

    tz_name = window.get("tz") or default_tz
    local = now.astimezone(ZoneInfo(tz_name)) if tz_name else now

    days = window.get("days")
    if days and _WEEKDAY_ABBR[local.weekday()] not in days:
        return False

    start, end = window.get("start"), window.get("end")
    if start and end:
        current_min = local.hour * 60 + local.minute
        start_min = _minutes_since_midnight(start)
        end_min = _minutes_since_midnight(end)
        if start_min <= end_min:
            if not (start_min <= current_min < end_min):
                return False
        else:
            # Wrap-around window (e.g. 22:00-06:00): inside if at/after
            # start OR before end.
            if not (current_min >= start_min or current_min < end_min):
                return False

    return True


def resource_matches(pattern: str, intent: InfrastructureIntent) -> bool:
    """``fnmatch`` of ``pattern`` against every alias of the intent's
    resource (:meth:`InfrastructureIntent.resource_aliases`), so
    ``aws_db_instance.*`` matches ``module.app.aws_db_instance.main``."""
    return any(fnmatch.fnmatch(alias, pattern) for alias in intent.resource_aliases())


def _matches_except_scope(
    c: Constraint,
    intent: InfrastructureIntent,
    now: datetime,
    default_tz: str | None = None,
    tzdata_available: bool = True,
) -> bool:
    if c.provider != intent.provider:
        return False
    if not resource_matches(c.resource_pattern, intent):
        return False
    if intent.action not in c.actions and ANY_ACTION not in c.actions:
        return False
    if c.time_window:
        # REVIEW-4 L1: when tzdata itself is missing, the window can't be
        # evaluated at all -- neither "matches" nor "doesn't match" is
        # honest. Never fall through to ALLOW here: report "doesn't match"
        # so this constraint isn't honoured, and let
        # ConstraintStore.get_time_window_unresolved flag it separately so
        # the interceptor can fail closed to ESCALATE instead of silently
        # never matching (see module docstring / interceptor.py).
        if not tzdata_available:
            return False
        if not _time_window_matches(c.time_window, now, default_tz):
            return False
    return True


def _constraint_matches(
    c: Constraint,
    intent: InfrastructureIntent,
    now: datetime,
    default_tz: str | None = None,
    tzdata_available: bool = True,
) -> bool:
    """Whether ``c``'s (provider, resource_pattern, actions, scope,
    time_window) apply to ``intent`` at ``now``. Shared by the live and the
    quarantined match so both use exactly the same semantics."""
    return _matches_except_scope(
        c, intent, now, default_tz, tzdata_available
    ) and _scope_matches(c.scope, intent)


def env_unresolved(scope: dict[str, Any], intent: InfrastructureIntent) -> bool:
    """Whether ``scope`` names ``env`` while the intent carries no resolved
    ``metadata["env"]`` -- and every *other* scope key does match. Such a
    rule can neither be honoured nor dismissed: the environment map didn't
    recognise the target, so the interceptor escalates (REVIEW-4 T1.3)
    instead of treating "unknown env" as "not prod"."""
    if "env" not in scope or "env" in intent.metadata:
        return False
    rest = {k: v for k, v in scope.items() if k != "env"}
    return scope_matches(rest, intent.metadata, {k: v for k, v in intent.params.items()
                                                  if k != "env"})


def time_window_unresolved(
    c: Constraint,
    intent: InfrastructureIntent,
    now: datetime,
    default_tz: str | None,
    tzdata_available: bool,
) -> bool:
    """Whether ``c`` carries a ``time_window`` that can't be evaluated
    because tzdata is missing entirely, while everything else about ``c``
    (provider, resource, action, scope) matches ``intent`` (REVIEW-4 L1).
    Mirrors :func:`env_unresolved`'s shape: the interceptor turns this into
    an ESCALATE with a ``time-window-unresolved: <id>`` note instead of
    treating an unevaluable window as "doesn't apply"."""
    if tzdata_available or not c.time_window:
        return False
    if c.provider != intent.provider:
        return False
    if not resource_matches(c.resource_pattern, intent):
        return False
    if intent.action not in c.actions and ANY_ACTION not in c.actions:
        return False
    return _scope_matches(c.scope, intent)


def _source_failure_reason(
    constraint: Constraint, fetcher: SourceFetcher, warnings: list[str] | None = None
) -> str | None:
    """``verify_source_reason`` with a missing/unreadable/malformed source
    normalised to a quarantine reason instead of propagating an exception
    (REVIEW-4 L1): one bad source file must not crash the whole load.

    * a source file that exists but isn't the JSON object
      ``verify_source_reason`` expects -- ``{not json`` (``JSONDecodeError``,
      a ``ValueError`` subclass) or a JSON array instead of an object
      (``TypeError`` when it's indexed by field name) -- quarantines as
      ``"invalid-source"``: the file is broken, not necessarily an
      adversarial forgery;
    * a missing file or a well-formed-but-wrong-content source quarantines
      as ``"forged"``, as before.
    """
    try:
        return verify_source_reason(constraint, fetcher, warnings)
    except (json.JSONDecodeError, TypeError):
        return "invalid-source"
    except (FileNotFoundError, KeyError, ValueError):
        return "forged"


def _verify_source_safe(constraint: Constraint, fetcher: SourceFetcher) -> bool:
    """``verify_source`` with a missing/unreadable source normalised to
    ``False`` instead of propagating ``FileNotFoundError``/``KeyError``."""
    try:
        return verify_source(constraint, fetcher)
    except (FileNotFoundError, KeyError, ValueError, TypeError):
        return False


_SOURCE_FAILURE_MESSAGES = {
    "forged": "source does not back its claimed fields",
    "principal-mismatch": "source transport attributes it to a different principal",
    "invalid-source": "source file is not readable JSON (bad content or wrong shape)",
}


# REVIEW-4 T2.3: process-wide LRU for ConstraintStore.load_cached, keyed by
# (path, mtime_ns, size). Module-level (not per-instance) so unrelated
# callers in the same process share the benefit.
_LOAD_CACHE_SIZE = 4
_LOAD_CACHE: "OrderedDict[tuple[str, int, int], ConstraintStore]" = OrderedDict()


class _IndexedConstraints(dict):
    """``dict[str, Constraint]`` that keeps a ``(provider, action)`` index
    in sync with *itself* on every mutation (REVIEW-4 T2.3) -- assignment,
    deletion, ``pop``, ``update`` -- so ``get_matching_constraints`` stays
    O(k) regardless of whether entries arrive through
    :meth:`ConstraintStore.add_constraint`, :meth:`ConstraintStore.load`,
    or a test/attack helper writing ``store.constraints[id] = c`` directly.
    ``constraints`` remains the source of truth; this index is a derived,
    always-consistent view of it, never edited on its own."""

    def __init__(self, index: dict[tuple[str, str], list[Constraint]]):
        super().__init__()
        self._index = index

    def _index_add(self, constraint: Constraint) -> None:
        for action in constraint.actions:
            self._index.setdefault((constraint.provider, action), []).append(constraint)

    def _index_remove(self, constraint: Constraint) -> None:
        for action in constraint.actions:
            bucket = self._index.get((constraint.provider, action))
            if not bucket:
                continue
            for i, existing in enumerate(bucket):
                if existing is constraint:
                    del bucket[i]
                    break

    def __setitem__(self, key: str, value: Constraint) -> None:
        old = self.get(key)
        if old is not None:
            self._index_remove(old)
        super().__setitem__(key, value)
        self._index_add(value)

    def __delitem__(self, key: str) -> None:
        old = self.get(key)
        super().__delitem__(key)
        if old is not None:
            self._index_remove(old)

    def pop(self, key, *args):  # type: ignore[override]
        old = self.get(key)
        result = super().pop(key, *args)
        if old is not None:
            self._index_remove(old)
        return result

    def clear(self) -> None:
        super().clear()
        self._index.clear()

    def update(self, *args, **kwargs) -> None:  # type: ignore[override]
        other = dict(*args, **kwargs)
        for k, v in other.items():
            self[k] = v


class ConstraintStore:
    """A secure, integrity-verified store for operational constraints."""

    def __init__(
        self,
        authority_map: dict[str, set[str]] | None = None,
        default_tz: str | None = None,
    ):
        # REVIEW-4 T2.3: (provider, action) -> constraints whose actions
        # contain that action (or ANY_ACTION), kept live by `constraints`
        # itself -- see _IndexedConstraints.
        self._index: dict[tuple[str, str], list[Constraint]] = {}
        self.constraints: dict[str, Constraint] = _IndexedConstraints(self._index)
        # Who may assert which constraint_class. Default: empty (deny all).
        self.authority_map: dict[str, set[str]] = authority_map or {}
        # Constraints that failed integrity/source verification on load, as
        # {"id", "reason"} entries ...
        self.quarantined: list[dict[str, str]] = []
        # ... and the Constraint objects themselves, kept so the interceptor
        # can still match them (and fail closed) — see module docstring.
        self.quarantined_constraints: list[Constraint] = []
        self.constraints_sha256: str = ""
        self.warnings: list[str] = []
        # REVIEW-4 T2.4: store-level fallback for a time_window with no tz
        # of its own. Not part of any constraint's provenance hash (it's a
        # store-level setting, not a constraint field) -- see the YAML
        # loader/saver docstrings.
        self.default_tz: str | None = default_tz
        # REVIEW-4 L1: whether the tzdata database is usable at all -- set
        # from a fresh probe by `load()`; a store built directly (as most
        # unit tests do) assumes it's available, matching prior behaviour.
        self.tzdata_available: bool = True

    @property
    def health(self) -> StoreHealth:
        """A fresh :class:`StoreHealth` snapshot of this store."""
        return StoreHealth(
            loaded=len(self.constraints),
            quarantined=[dict(q) for q in self.quarantined],
            principals=len(self.authority_map),
            constraints_sha256=self.constraints_sha256,
            warnings=list(self.warnings),
        )

    def is_authorized(self, principal: str, constraint_class: str) -> bool:
        """Whether ``principal`` may assert constraints of ``constraint_class``."""
        return constraint_class in self.authority_map.get(principal, set())

    def _quarantine(self, constraint: Constraint, reason: str, message: str) -> None:
        self.quarantined.append({"id": constraint.id, "reason": reason})
        self.quarantined_constraints.append(constraint)
        warning = f"Quarantined constraint {constraint.id}: {message}"
        self.warnings.append(warning)
        logger.warning(warning)

    def add_constraint(self, constraint: Constraint) -> Constraint:
        """Adds a constraint, enforcing authority at ingest time.

        Raises PermissionError if the constraint's principal is not
        authorized for its constraint_class.
        """
        if not self.is_authorized(constraint.principal, constraint.constraint_class):
            raise PermissionError(
                f"Principal '{constraint.principal}' is not authorized to assert "
                f"'{constraint.constraint_class}' constraints."
            )
        self.constraints[constraint.id] = constraint
        return constraint

    def _candidates(self, intent: InfrastructureIntent) -> list[Constraint]:
        """Every loaded constraint that could possibly apply to ``intent``: the
        ``(provider, action)`` and ``(provider, "*")`` buckets of the index.

        Each matcher below rejects a constraint unless its provider equals the
        intent's and its actions contain the intent's action or ``"*"``, which is
        exactly the index key -- so these buckets are a superset of anything any
        of them can return. All three draw from here so they cannot drift apart,
        and a decision costs O(k) in the plausible constraints, not O(n) in the
        store (REVIEW-4 T2.3)."""
        candidates = self._index.get((intent.provider, intent.action), [])
        wildcard = self._index.get((intent.provider, ANY_ACTION), [])
        if wildcard:
            seen = {id(c) for c in candidates}
            candidates = candidates + [c for c in wildcard if id(c) not in seen]
        return candidates

    def get_matching_constraints(
        self, intent: InfrastructureIntent, now: datetime
    ) -> list[Constraint]:
        """Returns every constraint whose pattern applies to this intent.

        REVIEW-4 T2.3: only the (provider, action) and (provider, "*")
        buckets of the index are scanned -- O(k) in the number of
        constraints that could plausibly match, not O(n) in the whole
        store -- rather than every loaded constraint."""
        _require_tz_aware(now)
        return [
            c
            for c in self._candidates(intent)
            if _constraint_matches(c, intent, now, self.default_tz, self.tzdata_available)
        ]

    def get_env_unresolved(self, intent: InfrastructureIntent, now: datetime) -> list[Constraint]:
        """Every loaded constraint that would apply to this intent except
        that it scopes on ``env`` and the intent has no resolved ``env``
        (see :func:`env_unresolved`). The interceptor turns each into an
        ESCALATE with an ``env-unresolved: <id>`` note."""
        _require_tz_aware(now)
        return [
            c
            for c in self._candidates(intent)
            if _matches_except_scope(c, intent, now, self.default_tz, self.tzdata_available)
            and env_unresolved(c.scope, intent)
        ]

    def get_time_window_unresolved(
        self, intent: InfrastructureIntent, now: datetime
    ) -> list[Constraint]:
        """Every loaded constraint whose ``time_window`` can't be evaluated
        because tzdata is missing entirely, but which otherwise applies to
        this intent (see :func:`time_window_unresolved`, REVIEW-4 L1). The
        interceptor turns each into an ESCALATE with a
        ``time-window-unresolved: <id>`` note instead of silently never
        matching it."""
        _require_tz_aware(now)
        return [
            c
            for c in self._candidates(intent)
            if time_window_unresolved(c, intent, now, self.default_tz, self.tzdata_available)
        ]

    def get_matching_quarantined(
        self, intent: InfrastructureIntent, now: datetime
    ) -> list[tuple[Constraint, str]]:
        """Returns every *quarantined* constraint whose (current, possibly
        tampered) fields apply to this intent, paired with its quarantine
        reason. The interceptor escalates on these; see module docstring."""
        _require_tz_aware(now)
        reasons = {q["id"]: q["reason"] for q in self.quarantined}
        return [
            (c, reasons.get(c.id, "quarantined"))
            for c in self.quarantined_constraints
            if _constraint_matches(c, intent, now, self.default_tz, self.tzdata_available)
        ]

    def save(self, path: str | Path) -> None:
        payload: dict[str, Any] = {}
        # Written only when set, so save()/load() round-trip existing (v1)
        # constraint files byte-for-byte unchanged (REVIEW-4 T2.4).
        if self.default_tz is not None:
            payload["default_tz"] = self.default_tz
        payload["constraints"] = [_constraint_to_dict(c) for c in self.constraints.values()]
        with open(path, "w") as f:
            yaml.safe_dump(payload, f, sort_keys=False)

    def _quarantine_invalid(self, entry: Any, reason: str) -> None:
        cid = entry.get("id") if isinstance(entry, dict) else None
        cid = cid if isinstance(cid, str) and cid else "<no id>"
        self.quarantined.append({"id": cid, "reason": f"invalid: {reason}"})
        warning = f"Quarantined constraint {cid}: invalid: {reason}"
        self.warnings.append(warning)
        logger.warning(warning)

    def _absorb_warnings(self, source: Any) -> None:
        for w in getattr(source, "warnings", None) or []:
            if w not in self.warnings:
                self.warnings.append(w)

    @classmethod
    def load(
        cls,
        path: str | Path,
        authority_map: dict[str, set[str]] | None = None,
        *,
        source_fetcher: SourceFetcher | None = None,
        key: bytes | None = None,
        insecure: bool = False,
    ) -> "ConstraintStore":
        """Loads constraints from a YAML file, validating each entry's
        shape and verifying each one's provenance hash. Entries that fail
        are quarantined (``invalid: ...`` / ``tampered``) rather than loaded.

        When ``source_fetcher`` is given, surviving constraints are also
        re-checked against their original source (see module docstring):
        a source whose transport principal differs from the constraint's
        quarantines it as ``"principal-mismatch"``; a source that doesn't
        back the claimed fields, or can't be fetched at all, as
        ``"forged"``. Fetches are cached per ``source_ref`` for the
        duration of this load.

        ``key`` enforces the file's ``.sig`` (``SignatureError`` when
        missing or wrong); with no key, ``"unsigned: <path>"`` is recorded
        in ``warnings`` unless ``insecure=True``. The authority map's and
        fetcher's own load warnings are folded in too.
        """
        store = cls(authority_map=authority_map)
        check_signature(path, key, insecure, store.warnings)
        store._absorb_warnings(authority_map)
        store.constraints_sha256 = _sha256_file(path)
        store.tzdata_available = _tzdata_available()
        if not store.tzdata_available:
            # REVIEW-4 L1: one clear warning, not one "unknown tz" per
            # time-windowed constraint -- see _tzdata_available's docstring.
            warning = "tzdata missing: time-windowed constraints cannot be evaluated"
            store.warnings.append(warning)
            logger.warning(warning)
        with open(path) as f:
            payload = yaml.load(f, Loader=_YAML_LOADER) or {}
        if not isinstance(payload, dict):
            raise ValueError(f"{path}: constraints file must be a mapping with a 'constraints' key")
        default_tz = payload.get("default_tz")
        tz_reason = _validate_default_tz(default_tz, store.tzdata_available)
        if tz_reason:
            raise ValueError(f"{path}: {tz_reason}")
        store.default_tz = default_tz
        entries = payload.get("constraints") or []
        if not isinstance(entries, list):
            raise ValueError(f"{path}: 'constraints' must be a list")
        caching_fetcher = CachingSourceFetcher(source_fetcher) if source_fetcher else None
        seen: set[str] = set()
        for entry in entries:
            reason = validate_constraint_dict(
                entry, default_tz, store.tzdata_available, store.warnings
            )
            if reason is None and entry["id"] in seen:
                reason = "duplicate id"
            if reason is not None:
                store._quarantine_invalid(entry, reason)
                continue
            seen.add(entry["id"])
            constraint = _constraint_from_dict(entry)
            if not constraint.verify_integrity():
                store._quarantine(constraint, "tampered", "provenance hash mismatch")
                continue
            if caching_fetcher is not None:
                failure = _source_failure_reason(constraint, caching_fetcher, store.warnings)
                if failure is not None:
                    store._quarantine(constraint, failure, _SOURCE_FAILURE_MESSAGES[failure])
                    continue
            store.constraints[constraint.id] = constraint
        store._absorb_warnings(source_fetcher)
        return store

    @classmethod
    def load_cached(
        cls,
        path: str | Path,
        authority_map: dict[str, set[str]] | None = None,
        *,
        source_fetcher: SourceFetcher | None = None,
        key: bytes | None = None,
        insecure: bool = False,
    ) -> "ConstraintStore":
        """``load()``, memoised by ``(path, mtime_ns, size)`` in a
        process-wide LRU of size 4 (REVIEW-4 T2.3). A second call for the
        same untouched file returns the *same* ``ConstraintStore`` object
        instead of re-parsing and re-verifying it; touching the file (a
        new mtime or size) misses the cache and reloads. Callers that pass
        a different ``authority_map``/``source_fetcher``/``key`` for the
        same path still hit the cache keyed only on the file identity --
        that tradeoff is the caller's to make (see module docstring)."""
        p = Path(path)
        stat = p.stat()
        cache_key = (str(p), stat.st_mtime_ns, stat.st_size)
        cached = _LOAD_CACHE.get(cache_key)
        if cached is not None:
            _LOAD_CACHE.move_to_end(cache_key)
            return cached
        store = cls.load(
            path, authority_map, source_fetcher=source_fetcher, key=key, insecure=insecure
        )
        _LOAD_CACHE[cache_key] = store
        if len(_LOAD_CACHE) > _LOAD_CACHE_SIZE:
            _LOAD_CACHE.popitem(last=False)
        return store

    def verify_sources(self, fetcher: SourceFetcher) -> list[dict]:
        """Post-hoc audit of an already-loaded store: re-checks every
        currently-loaded constraint against its original source, moving any
        that fail into ``quarantined`` (reason ``"forged"`` or
        ``"principal-mismatch"``) and removing them from ``constraints``.

        Returns the list of newly-quarantined ``{"id", "reason"}`` entries.
        """
        caching_fetcher = CachingSourceFetcher(fetcher)
        newly_quarantined: list[dict[str, str]] = []
        for constraint_id in list(self.constraints.keys()):
            constraint = self.constraints[constraint_id]
            failure = _source_failure_reason(constraint, caching_fetcher, self.warnings)
            if failure is not None:
                newly_quarantined.append({"id": constraint_id, "reason": failure})
                self._quarantine(constraint, failure, _SOURCE_FAILURE_MESSAGES[failure])
                del self.constraints[constraint_id]
        self._absorb_warnings(fetcher)
        return newly_quarantined
