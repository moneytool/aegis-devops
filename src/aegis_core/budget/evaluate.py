"""Deciding allow / warn / deny from a usage snapshot (design v1.0, §6).

The guarantee is exactly the design's (§6.1): covered tool calls and
prompts are denied when the usage *available at that hook* reaches a limit.
Spend Aegis cannot see in time is not bounded; usage above a limit is
reported as observed overshoot.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aegis_core.budget.accounting import UNKNOWN_DAY, ProjectDay, Snapshot
from aegis_core.budget.policy import BudgetPolicy, Limit
from aegis_core.budget.pricing import CATEGORIES, PriceTable

ALLOW, WARN, DENY = "allow", "warn", "deny"


@dataclass
class Measure:
    """One limit, measured: ``used`` against ``limit`` in ``unit``."""

    name: str      # session | project_day | copilot_premium_requests
    unit: str      # usd | tokens | requests
    used: float
    limit: float
    warn_at: float

    @property
    def fraction(self) -> float:
        return self.used / self.limit if self.limit else 0.0

    @property
    def level(self) -> str:
        if self.used >= self.limit:
            return DENY
        if self.used >= self.warn_at * self.limit:
            return WARN
        return ALLOW

    @property
    def overshoot(self) -> float:
        return max(0.0, self.used - self.limit)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "unit": self.unit, "used": self.used, "limit": self.limit,
                "warn_at": self.warn_at, "fraction": self.fraction, "level": self.level,
                "overshoot": self.overshoot}


@dataclass
class Verdict:
    decision: str                                  # allow | warn | deny
    measures: list[Measure] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)   # codes, for deny or warn
    messages: list[str] = field(default_factory=list)  # one line each, for people
    estimated: dict[str, list[str]] = field(default_factory=dict)  # model -> categories

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "measures": [m.to_dict() for m in self.measures],
                "reasons": self.reasons, "messages": self.messages,
                "estimated": self.estimated}


def tokens_of(usage_by_model: Mapping[str, Mapping[str, float]]) -> float:
    return float(sum(u.get(c, 0) for u in usage_by_model.values() for c in CATEGORIES))


def _fmt(unit: str, amount: float) -> str:
    if unit == "usd":
        return f"${amount:,.2f}"
    if unit == "tokens":
        return f"{amount:,.0f} tokens"
    return f"{amount:,.2f} premium requests"


class _Builder:
    """Collects measures, price flags and unverifiable usage into a Verdict."""

    def __init__(self, policy: BudgetPolicy, prices: PriceTable, providers: Mapping[str, str]):
        self.policy, self.prices, self.providers = policy, prices, providers
        self.verdict = Verdict(ALLOW)
        self.levels: list[str] = []
        self.unknown: list[str] = []

    def amount(self, usage: Mapping[str, Mapping[str, float]]) -> float:
        if self.policy.unit == "tokens":
            return tokens_of(usage)
        cost = self.prices.cost(usage, self.providers)
        for model, cats in cost.estimated.items():
            merged = set(self.verdict.estimated.get(model, [])) | set(cats)
            self.verdict.estimated[model] = sorted(merged)
        return cost.dollars

    def measure(self, name: str, unit: str, used: float, lim: Limit) -> None:
        self.verdict.measures.append(Measure(name, unit, used, lim.limit, lim.warn_at))

    def project_history(self, pd: ProjectDay, exclude: str | None, acknowledged: bool) -> None:
        """A project day whose history is incomplete, or whose other
        sessions are only a lower bound, is unverifiable -- unless a signed
        ``aegis budget reset --day`` acknowledged that day."""
        if acknowledged:
            return
        if pd.completeness != "complete":
            detail = (f"{pd.missing_sessions} session(s) without a log" if pd.history == "ok"
                      else f"session inventory {pd.history}")
            self.unknown.append(f"today's project total is {pd.completeness} ({detail})")
        others = pd.unverified(exclude=exclude)
        if others:
            reasons = sorted({r for rs in others.values() for r in rs})
            who = "other session(s)" if exclude else "session(s)"
            self.unknown.append(f"{len(others)} {who} in the project are a lower bound "
                                f"({', '.join(reasons)})")

    def finish(self) -> Verdict:
        verdict, policy = self.verdict, self.policy
        for m in verdict.measures:
            self.levels.append(m.level)
            if m.level == DENY:
                verdict.reasons.append(f"{m.name}-over")
                verdict.messages.append(
                    f"budget: {m.name.replace('_', ' ')} limit reached: {_fmt(m.unit, m.used)} "
                    f"of {_fmt(m.unit, m.limit)}" + (
                        f" (overshoot {_fmt(m.unit, m.overshoot)})" if m.overshoot else ""))
            elif m.level == WARN:
                verdict.reasons.append(f"{m.name}-warn")
                verdict.messages.append(
                    f"budget: {m.name.replace('_', ' ')} at {m.fraction:.0%}: "
                    f"{_fmt(m.unit, m.used)} of {_fmt(m.unit, m.limit)}, "
                    f"{_fmt(m.unit, m.limit - m.used)} left")
        # Unpriced models: estimated in 'estimate' mode, refused in 'deny' mode.
        if policy.unit == "usd" and verdict.estimated:
            names = ", ".join(sorted(verdict.estimated))
            if policy.on_unknown_price == "deny":
                self.levels.append(DENY)
                verdict.reasons.append("unpriced-model")
                verdict.messages.append(f"budget: no explicit price for {names}; add it under "
                                        "'pricing:' in budget.yaml and sign it")
            else:
                verdict.reasons.append("estimated-price")
                verdict.messages.append(f"budget: estimated, unpriced model(s): {names}")
        # Usage Aegis could not read or place: an unknown log.
        if self.unknown:
            if policy.on_unknown_log == "deny":
                self.levels.append(DENY)
                verdict.reasons.append("unknown-log")
                verdict.messages.append("budget: usage cannot be verified ("
                                        + "; ".join(self.unknown) + "); on_unknown_log: deny")
            else:
                verdict.reasons.append("unknown-log-warn")
                verdict.messages.append("budget: usage may be under-counted: "
                                        + "; ".join(self.unknown))
        if DENY in self.levels:
            verdict.decision = DENY
        elif WARN in self.levels or verdict.reasons:
            verdict.decision = WARN
        return verdict


def evaluate(policy: BudgetPolicy, prices: PriceTable, snap: Snapshot, *,
             acknowledged: bool = False) -> Verdict:
    """The decision for one session at one hook. ``acknowledged``: a signed
    ``aegis budget reset --day`` covers today, so an incomplete project
    history no longer counts as unverifiable (the session's own log problems
    still do)."""
    agent = snap.record.agent
    if not policy.measures(agent):
        return Verdict(ALLOW)
    b = _Builder(policy, prices, snap.providers)
    if agent == "copilot":
        assert policy.copilot_premium_requests
        used = sum(u.get("requests", 0) for u in snap.session_usage.values())
        b.measure("copilot_premium_requests", "requests", used, policy.copilot_premium_requests)
    else:
        if policy.session:
            b.measure("session", policy.unit, b.amount(snap.session_usage), policy.session)
        if policy.project_day and snap.project is not None:
            b.measure("project_day", policy.unit, b.amount(snap.project_usage),
                      policy.project_day)
    rec = snap.record
    if rec.log_missing:
        b.unknown.append("the session's log is missing")
    if rec.problem_total:
        b.unknown.append(f"{rec.problem_total} unreadable log record(s)")
    if rec.buckets().get(UNKNOWN_DAY):
        b.unknown.append("usage with no recorded time (counted for the session only)")
    if snap.project is not None:
        b.project_history(snap.project, rec.key, acknowledged)
    return b.finish()


def evaluate_project(policy: BudgetPolicy, prices: PriceTable, pd: ProjectDay, *,
                     acknowledged: bool = False) -> Verdict:
    """The project/day limit alone, for ``aegis budget check`` without a
    session: the day's total against ``project_day``, with every
    contributing session's verification status."""
    b = _Builder(policy, prices, pd.providers())
    if policy.project_day:
        token_usage = {m: u for m, u in pd.usage().items() if "requests" not in u}
        b.measure("project_day", policy.unit, b.amount(token_usage), policy.project_day)
    b.project_history(pd, None, acknowledged)
    return b.finish()
