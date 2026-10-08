"""The budget policy (``budget.yaml``, design v1.0 §3).

Signed like every policy file; its ``principal`` must hold the ``budget``
class in ``authority.yaml``, so raising a limit is a policy change an agent
cannot make by editing a file. Any shape problem is a load error, never a
guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from aegis_core.budget.pricing import check_override
from aegis_core.signing import check_signature

BUDGET_FILE = "budget.yaml"
BUDGET_CLASS = "budget"
AGENTS = ("claude", "codex", "gemini", "opencode", "copilot")
UNITS = ("usd", "tokens")
ON_UNKNOWN_LOG = ("allow", "deny")
ON_UNKNOWN_PRICE = ("estimate", "deny")
DEFAULT_WARN_AT = 0.8

_TOP_LEVEL = {"version", "principal", "unit", "session", "project_day", "agents",
              "on_unknown_log", "on_unknown_price", "pricing", "copilot"}


@dataclass(frozen=True)
class Limit:
    limit: float
    warn_at: float = DEFAULT_WARN_AT


@dataclass(frozen=True)
class BudgetPolicy:
    path: str
    principal: str
    unit: str
    session: Limit | None
    project_day: Limit | None
    tz: str
    agents: tuple[str, ...]
    on_unknown_log: str
    on_unknown_price: str
    pricing: dict[str, dict[str, float]] = field(default_factory=dict)
    copilot_premium_requests: Limit | None = None
    warnings: tuple[str, ...] = ()

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.tz)

    def measures(self, agent: str) -> bool:
        """Only listed agents are measured and enforced (§11, decision 4).
        Copilot CLI has no token data, so it is measured only when a
        premium-request limit is set."""
        if agent not in self.agents:
            return False
        if agent == "copilot":
            return self.copilot_premium_requests is not None
        return self.session is not None or self.project_day is not None

    def to_dict(self) -> dict[str, Any]:
        def lim(x: Limit | None) -> dict[str, float] | None:
            return None if x is None else {"limit": x.limit, "warn_at": x.warn_at}

        return {"path": self.path, "principal": self.principal, "unit": self.unit,
                "session": lim(self.session), "project_day": lim(self.project_day),
                "tz": self.tz, "agents": list(self.agents),
                "on_unknown_log": self.on_unknown_log,
                "on_unknown_price": self.on_unknown_price, "pricing": self.pricing,
                "copilot_premium_requests": lim(self.copilot_premium_requests),
                "warnings": list(self.warnings)}


def _number(where: str, value: Any, *, integer: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where}: must be a number")
    if integer and value != int(value):
        raise ValueError(f"{where}: must be a whole number of tokens")
    if value <= 0:
        raise ValueError(f"{where}: must be greater than 0")
    return float(value)


def _limit(path: Path, name: str, raw: Any, *, integer: bool,
           extra: frozenset[str] = frozenset()) -> tuple[Limit, dict[str, Any]]:
    where = f"{path}: {name}"
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: must be a mapping with 'limit' (and optional 'warn_at')")
    allowed = {"limit", "warn_at"} | extra
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"{where}: unknown field(s) {sorted(unknown)}")
    if "limit" not in raw:
        raise ValueError(f"{where}: 'limit' is required")
    limit = _number(f"{where}.limit", raw["limit"], integer=integer)
    warn_at = raw.get("warn_at", DEFAULT_WARN_AT)
    if isinstance(warn_at, bool) or not isinstance(warn_at, (int, float)) or not (
        0 < warn_at < 1
    ):
        raise ValueError(f"{where}.warn_at: must be a fraction between 0 and 1 (e.g. 0.8)")
    return Limit(limit, float(warn_at)), {k: raw[k] for k in extra if k in raw}


def load_budget_policy(
    path: str | Path,
    *,
    authority_map: dict[str, set[str]] | None,
    key: bytes | None = None,
    insecure: bool = False,
) -> BudgetPolicy:
    """``budget.yaml`` -> :class:`BudgetPolicy`. Shape::

        version: 1
        principal: admin            # must hold the 'budget' class
        unit: usd                   # usd | tokens; required
        session:     {limit: 20,  warn_at: 0.8}
        project_day: {limit: 100, warn_at: 0.8, tz: America/Chicago}
        agents: [claude, codex, gemini, opencode, copilot]
        on_unknown_log: allow       # allow | deny
        on_unknown_price: estimate  # estimate | deny (usd only)
        pricing:                    # overrides, USD per million tokens
          claude-opus-5-5: {input: 4, output: 20, cache_read: 0.2, cache_write: 8}
        copilot: {premium_requests: 50, warn_at: 0.8}
    """
    path = Path(path)
    warnings: list[str] = []
    check_signature(path, key, insecure, warnings)
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: must be a mapping")
    unknown = set(raw) - _TOP_LEVEL
    if unknown:
        raise ValueError(f"{path}: unknown field(s) {sorted(unknown)}")
    if raw.get("version", 1) != 1:
        raise ValueError(f"{path}: unsupported version {raw.get('version')!r} (expected 1)")

    principal = raw.get("principal")
    if not isinstance(principal, str) or not principal:
        raise ValueError(f"{path}: 'principal' is required (who asserts this budget)")
    if authority_map is None:
        raise ValueError(f"{path}: an authority map is required to check '{principal}'")
    if BUDGET_CLASS not in authority_map.get(principal, set()):
        raise ValueError(f"{path}: principal {principal!r} does not hold the "
                         f"'{BUDGET_CLASS}' class in the authority map")

    if "unit" not in raw:
        raise ValueError(f"{path}: 'unit' is required: usd (estimated dollars) or tokens")
    unit = raw["unit"]
    if unit not in UNITS:
        raise ValueError(f"{path}: unit must be one of {list(UNITS)}, got {unit!r}")
    integer = unit == "tokens"

    session = None
    if raw.get("session") is not None:
        session, _ = _limit(path, "session", raw["session"], integer=integer)
    project_day, tz = None, "UTC"
    if raw.get("project_day") is not None:
        project_day, extra = _limit(path, "project_day", raw["project_day"], integer=integer,
                                    extra=frozenset({"tz"}))
        tz = extra.get("tz", "UTC")
        if not isinstance(tz, str):
            raise ValueError(f"{path}: project_day.tz must be a time zone name")
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(f"{path}: project_day.tz: unknown time zone {tz!r}") from None

    copilot = None
    if raw.get("copilot") is not None:
        c = raw["copilot"]
        if not isinstance(c, dict) or "premium_requests" not in c:
            raise ValueError(f"{path}: copilot must be a mapping with 'premium_requests'")
        unknown_c = set(c) - {"premium_requests", "warn_at"}
        if unknown_c:
            raise ValueError(f"{path}: copilot: unknown field(s) {sorted(unknown_c)}")
        copilot, _ = _limit(path, "copilot", {"limit": c["premium_requests"],
                                              **({"warn_at": c["warn_at"]} if "warn_at" in c
                                                 else {})}, integer=True)

    if session is None and project_day is None and copilot is None:
        raise ValueError(f"{path}: set at least one limit: session, project_day or "
                         "copilot.premium_requests")

    agents_raw = raw.get("agents", list(AGENTS))
    if not isinstance(agents_raw, list) or not agents_raw or not all(
        isinstance(a, str) for a in agents_raw
    ):
        raise ValueError(f"{path}: agents must be a non-empty list of {list(AGENTS)}")
    bad = [a for a in agents_raw if a not in AGENTS]
    if bad:
        raise ValueError(f"{path}: unknown agent(s) {bad}; supported: {list(AGENTS)}")
    if len(set(agents_raw)) != len(agents_raw):
        raise ValueError(f"{path}: an agent is listed twice in 'agents'")
    agents = tuple(a for a in AGENTS if a in agents_raw)

    on_unknown_log = raw.get("on_unknown_log", "allow")
    if on_unknown_log not in ON_UNKNOWN_LOG:
        raise ValueError(f"{path}: on_unknown_log must be one of {list(ON_UNKNOWN_LOG)}")
    on_unknown_price = raw.get("on_unknown_price", "estimate")
    if on_unknown_price not in ON_UNKNOWN_PRICE:
        raise ValueError(f"{path}: on_unknown_price must be one of {list(ON_UNKNOWN_PRICE)}")

    pricing_raw = raw.get("pricing") or {}
    if not isinstance(pricing_raw, dict):
        raise ValueError(f"{path}: pricing must be a mapping of model id to prices")
    pricing = {str(model): check_override(f"{path}: pricing.{model}", entry)
               for model, entry in pricing_raw.items()}

    if unit == "tokens":
        if "on_unknown_price" in raw:
            warnings.append("ignored: on_unknown_price has no effect with unit: tokens")
        if pricing:
            warnings.append("ignored: pricing has no effect with unit: tokens")
    if "copilot" in agents and copilot is None:
        warnings.append("copilot-unmeasured: copilot is listed but copilot.premium_requests "
                        "is not set; Copilot CLI reports no tokens, so its sessions are not "
                        "measured")
    if copilot is not None and "copilot" not in agents:
        warnings.append("ignored: copilot.premium_requests is set but copilot is not in agents")
    if session is None and project_day is None and any(a != "copilot" for a in agents):
        warnings.append("token-agents-unmeasured: no session or project_day limit, so only "
                        "Copilot CLI is measured")

    return BudgetPolicy(str(path), principal, unit, session, project_day, tz, agents,
                        on_unknown_log, on_unknown_price, pricing, copilot, tuple(warnings))
