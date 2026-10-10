"""``aegis budget status|check|reset`` (design v1.0 §7, §4.1).

``status`` and ``check`` rebuild today's project total from the logs before
reporting, so they show the usage the logs hold now, not only what hooks
have seen. ``reset --day`` is the strict-recovery path of §4.1: it writes a
marker **signed with the policy key** that acknowledges one day's history
as it stands, so an incomplete or unverifiable project total stops denying
under ``on_unknown_log: deny``. An agent without the key cannot write one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_core.budget.accounting import BudgetStore, day_of, rebuild
from aegis_core.budget.evaluate import (
    ALLOW,
    DENY,
    Acknowledgement,
    Measure,
    evaluate_project,
    tokens_of,
)
from aegis_core.budget.logs import AgentLog
from aegis_core.budget.policy import BudgetPolicy
from aegis_core.budget.pricing import PriceTable

RESET_HEADER = "aegis-budget-reset-v1"


# --- signed reset markers ------------------------------------------------------------


def _mac(data: bytes, key: bytes) -> str:
    return hashlib.blake2b(data, key=key, digest_size=32).hexdigest()


def _canonical(fields: Mapping[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def reset_path(store: BudgetStore, root: str, day: str) -> Path:
    return store.project_dir(root) / f"reset-{day}.json"


def write_reset(store: BudgetStore, root: str, day: str, key: bytes, baseline: Acknowledgement,
                now: float | None = None) -> Path:
    """Acknowledges ``day``'s project history as it stands -- ``baseline``,
    the day's verification state now -- signed with ``key`` (the policy
    signing key). Later problems are not covered."""
    fields = {"header": RESET_HEADER, "root": root, "day": day,
              "at": datetime.fromtimestamp(time.time() if now is None else now,
                                           tz=UTC).isoformat(),
              "baseline": baseline.to_dict()}
    path = reset_path(store, root, day)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**fields, "mac": _mac(_canonical(fields), key)}, indent=2))
    return path


def reset_acknowledged(store: BudgetStore, root: str, day: str, key: bytes | None,
                       insecure: bool = False) -> Acknowledgement | None:
    """What a valid reset marker for ``day`` in project ``root``
    acknowledged, or ``None``. Without a key (``--insecure``) nothing is
    verified, so a marker is taken as it is, like every other policy file
    then."""
    try:
        doc = json.loads(reset_path(store, root, day).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    fields = {k: doc.get(k) for k in ("header", "root", "day", "at", "baseline")}
    if fields["header"] != RESET_HEADER or fields["root"] != root or fields["day"] != day:
        return None
    if key is None:
        if not insecure:
            return None
    else:
        mac = doc.get("mac")
        if not (isinstance(mac, str)
                and hmac.compare_digest(mac, _mac(_canonical(fields), key))):
            return None
    try:
        return Acknowledgement.from_dict(fields["baseline"])
    except (KeyError, TypeError, ValueError):
        return None


# --- status / check --------------------------------------------------------------------


def _amount(policy: BudgetPolicy, prices: PriceTable, usage: Mapping[str, Mapping[str, float]],
            providers: Mapping[str, str]) -> tuple[float, dict[str, list[str]]]:
    if policy.unit == "tokens":
        return tokens_of(usage), {}
    cost = prices.cost(usage, providers)
    return cost.dollars, cost.estimated


def project_status(policy: BudgetPolicy, prices: PriceTable, store: BudgetStore,
                   logs: Mapping[str, AgentLog], root: str, *, now: float | None = None,
                   key: bytes | None = None, insecure: bool = False,
                   agent: str | None = None) -> dict[str, Any]:
    """Today's project total (rebuilt from the logs) and each session that
    contributed to it, as a JSON-ready mapping."""
    now = time.time() if now is None else now
    zone = policy.zone
    day = day_of(datetime.fromtimestamp(now, tz=UTC), zone)
    measured = {a: lg for a, lg in logs.items() if policy.measures(a)}
    pd = rebuild(store, measured, root, day, zone)
    ack = reset_acknowledged(store, root, day, key, insecure)
    verdict = evaluate_project(policy, prices, pd, ack=ack)

    sessions = []
    for entry_key, entry in sorted(pd.entries.items()):
        a, _, sid = entry_key.partition("/")
        if agent and a != agent:
            continue
        rec = store.load_record(a, sid)
        total_usage = rec.usage_total() if rec else entry.get("usage", {})
        providers = {**entry.get("providers", {}), **(rec.providers if rec else {})}
        if a == "copilot":
            unit = "requests"
            today = sum(u.get("requests", 0) for u in entry.get("usage", {}).values())
            total = sum(u.get("requests", 0) for u in total_usage.values())
            limit = policy.copilot_premium_requests
            estimated: dict[str, list[str]] = {}
        else:
            unit = policy.unit
            today, _ = _amount(policy, prices, entry.get("usage", {}), providers)
            total, estimated = _amount(policy, prices, total_usage, providers)
            limit = policy.session
        m = Measure("session", unit, total, limit.limit, limit.warn_at) if limit else None
        sessions.append({
            "agent": a, "session_id": sid, "unit": unit, "today": today, "total": total,
            "limit": limit.limit if limit else None,
            "level": m.level if m else ALLOW, "overshoot": m.overshoot if m else 0.0,
            "unverified": entry.get("unverified", []), "estimated": estimated,
        })
    project = next((m.to_dict() for m in verdict.measures if m.name == "project_day"), None)
    return {
        "project": root, "day": day, "tz": policy.tz, "unit": policy.unit,
        "project_day": project, "completeness": pd.completeness, "history": pd.history,
        "missing_sessions": pd.missing_sessions, "acknowledged": ack is not None,
        "decision": verdict.decision, "messages": verdict.messages,
        "estimated": verdict.estimated, "sessions": sessions,
        "warnings": list(policy.warnings),
    }


def _fmt(unit: str, amount: float | None) -> str:
    if amount is None:
        return "—"
    if unit == "usd":
        return f"${amount:,.2f}"
    if unit == "tokens":
        return f"{amount:,.0f} tokens"
    return f"{amount:,.2f} premium requests"


def render_status(status: Mapping[str, Any]) -> str:
    """``aegis budget status`` for people."""
    unit = status["unit"]
    lines = [f"budget: {status['project']} — {status['day']} ({status['tz']}), unit {unit}"]
    pdm = status["project_day"]
    if pdm:
        lines.append(f"  project today: {_fmt(unit, pdm['used'])} of {_fmt(unit, pdm['limit'])} "
                     f"({pdm['fraction']:.0%}, {pdm['level']})"
                     + (f", overshoot {_fmt(unit, pdm['overshoot'])}" if pdm["overshoot"]
                        else ""))
    else:
        lines.append("  project today: no project_day limit")
    if status["completeness"] != "complete":
        note = " — acknowledged by a signed reset" if status["acknowledged"] else ""
        lines.append(f"  history: {status['completeness']} (inventory {status['history']}, "
                     f"{status['missing_sessions']} session(s) without a log){note}")
    if not status["sessions"]:
        lines.append("  no sessions today")
    for s in status["sessions"]:
        flag = f"  [{s['level']}]" if s["level"] != ALLOW else ""
        lower = f"  lower bound: {', '.join(s['unverified'])}" if s["unverified"] else ""
        lines.append(f"  {s['agent']:9} {s['session_id']}: today {_fmt(s['unit'], s['today'])}, "
                     f"session {_fmt(s['unit'], s['total'])} of {_fmt(s['unit'], s['limit'])}"
                     f"{flag}{lower}")
    if status["estimated"]:
        lines.append("  estimated prices for: " + ", ".join(sorted(status["estimated"])))
    for w in status["warnings"]:
        lines.append(f"  warning: {w}")
    return "\n".join(lines)


EXIT_UNDER, EXIT_OVER = 0, 3


def check_exit(decision: str) -> int:
    """``aegis budget check``: 0 under budget (a warning included), 3 over."""
    return EXIT_OVER if decision == DENY else EXIT_UNDER
