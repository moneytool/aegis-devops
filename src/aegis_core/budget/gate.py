"""The budget check inside ``aegis hook`` (design v1.0, §6).

``aegis hook <agent>`` first decides the command against the infrastructure
policy, as it always has; a BLOCK stands whatever the budget says. Then,
in a project whose policy directory holds a ``budget.yaml``, this module
brings the session's usage up to date from the agent's logs and decides:

* **deny** once the usage available at this hook reaches a limit -- every
  covered tool call, and new prompts where the agent has a prompt hook;
* **warn** once per session per threshold (not on every call);
* **allow** otherwise, silently.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_core.budget.accounting import BudgetStore, refresh
from aegis_core.budget.evaluate import ALLOW, DENY, WARN, evaluate
from aegis_core.budget.logs import AgentLog, default_logs
from aegis_core.budget.policy import BudgetPolicy
from aegis_core.budget.pricing import PriceTable, load_builtin_table
from aegis_core.budget.report import reset_acknowledged

# Hook events that come before a new prompt rather than a tool call.
PROMPT_EVENTS = frozenset({"UserPromptSubmit", "BeforeAgent"})

_HOW_TO_CONTINUE = {
    "session": "start a new session",
    "project_day": "wait for the next day",
    "copilot_premium_requests": "start a new session",
}


@dataclass
class Outcome:
    decision: str        # allow | warn | deny
    message: str = ""    # the deny reason, or the warning to show ("" = nothing to show)


def session_ref(payload: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """``(session id, transcript path)`` from any agent's hook payload."""
    sid = payload.get("session_id") or payload.get("sessionId") or payload.get("sessionID")
    transcript = payload.get("transcript_path")
    return (sid if isinstance(sid, str) and sid else None,
            transcript if isinstance(transcript, str) and transcript else None)


def _warned_path(store: BudgetStore, agent: str, sid: str) -> Path:
    return store.record_path(agent, sid).with_suffix(".warned.json")


def _first_time(store: BudgetStore, agent: str, sid: str, keys: list[str]) -> list[str]:
    """The warning keys not yet shown in this session; records them as
    shown. Best effort: a lost file means a warning is shown again."""
    path = _warned_path(store, agent, sid)
    try:
        shown = set(json.loads(path.read_text()))
    except (OSError, ValueError, TypeError):
        shown = set()
    new = [k for k in keys if k not in shown]
    if new:
        with contextlib.suppress(OSError):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(sorted(shown | set(new))))
    return new


def check(agent: str, payload: Mapping[str, Any], cwd: str | None, policy: BudgetPolicy, *,
          store: BudgetStore | None = None, logs: Mapping[str, AgentLog] | None = None,
          now: float | None = None, key: bytes | None = None,
          insecure: bool = False) -> Outcome:
    """The budget decision for one hook call. Raises on internal errors;
    the caller fails closed inside an opted-in project."""
    if not policy.measures(agent):
        return Outcome(ALLOW)
    store = store or BudgetStore()
    all_logs = logs or default_logs()
    logs = {a: all_logs[a] for a in policy.agents if a in all_logs and policy.measures(a)}
    sid, transcript = session_ref(payload)
    loc = logs[agent].locate(sid, transcript) if sid else None
    if loc is None:
        what = (f"cannot find the log of {agent} session {sid}" if sid
                else "the hook payload names no session")
        if policy.on_unknown_log == "deny":
            return Outcome(DENY, f"aegis budget: {what}, so its usage cannot be measured "
                                 "(on_unknown_log: deny)")
        if sid and not _first_time(store, agent, sid, ["log-not-found"]):
            return Outcome(WARN)
        return Outcome(WARN, f"aegis budget: {what}; this session is not being measured")

    snap = refresh(store, logs, loc, policy.zone, now=time.time() if now is None else now,
                   fallback_cwd=cwd)
    prices = PriceTable(load_builtin_table(), policy.pricing)
    ack = reset_acknowledged(store, snap.record.project_root, snap.day, key, insecure) \
        if snap.record.project_root else None
    verdict = evaluate(policy, prices, snap, ack=ack)
    if verdict.decision == DENY:
        over = [m.name for m in verdict.measures if m.level == DENY]
        ways = sorted({_HOW_TO_CONTINUE[n] for n in over})
        ways.append("raise the limit in budget.yaml (it must be re-signed)")
        reason = "; ".join(m.removeprefix("budget: ") for m in verdict.messages
                           if not m.endswith("left"))
        return Outcome(DENY, f"aegis budget: {reason}. To continue: {', or '.join(ways)}.")
    if verdict.decision == WARN:
        keys = []
        for reason in verdict.reasons:
            key = reason
            if reason.startswith("project_day"):
                key += f":{snap.day}"
            elif reason == "estimated-price":
                key += ":" + ",".join(sorted(verdict.estimated))
            keys.append(key)
        new = set(_first_time(store, snap.record.agent, snap.record.session_id, keys))
        shown = [msg for key, msg in zip(keys, verdict.messages, strict=False) if key in new]
        return Outcome(WARN, "aegis " + "; ".join(m.removeprefix("budget: ") for m in shown)
                       if shown else "")
    return Outcome(ALLOW)
