"""Aegis-DevOps demo: loads the five example constraints and the example
authority map, then runs three intents through the interceptor -- one that
is allowed, one that is blocked, and one that is escalated.

Run with:
    venv/bin/python examples/demo.py
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from aegis_core.authority import load_authority_map
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_kubectl, from_terraform_plan
from aegis_core.store import ConstraintStore


def print_decision(label: str, intent, decision) -> None:
    print(f"\n--- {label} ---")
    print(f"intent:   {intent.provider} {intent.action} {intent.resource}")
    print(f"verdict:  {decision.verdict}")
    print(f"covered:  {decision.covered}")
    print(f"citations: {decision.citations}")
    print(f"discarded: {decision.discarded}")
    print(f"latency_ms: {decision.latency_ms:.4f}")


def main() -> None:
    authority_map = load_authority_map("data/authority.example.yaml")
    store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
    interceptor = AegisInterceptor(store)

    if store.quarantined:
        print(f"Quarantined constraints (failed integrity check): {store.quarantined}")

    # 1. ALLOW -- a read-only action nothing in the store has an opinion about.
    allow_intent = from_kubectl(["kubectl", "get", "service/frontend", "-n", "prod"])
    allow_decision = interceptor.intercept(allow_intent)
    print_decision("Read-only action, no matching constraint", allow_intent, allow_decision)

    # 2. BLOCK -- scaling a prod deployment during business hours (09:00-17:00 ET, weekdays)
    # is blocked by the "no-scale-prod-peak" constraint.
    block_intent = from_kubectl(
        ["kubectl", "scale", "deployment/api-server", "--replicas=5", "-n", "prod"]
    )
    # 2026-03-16 is a Monday.
    during_peak_hours = datetime(2026, 3, 16, 10, 0, tzinfo=ZoneInfo("America/New_York"))
    block_decision = interceptor.intercept(block_intent, now=during_peak_hours)
    print_decision("Scale a prod deployment during business hours", block_intent, block_decision)

    # 3. ESCALATE -- destroying a prod EC2 instance in us-east-1 is escalated for human
    # review by the "escalate-terraform-prod-destroy" constraint.
    plan = {
        "resource_changes": [
            {"address": "aws_instance.web", "change": {"actions": ["delete"]}},
        ]
    }
    escalate_intent = from_terraform_plan(plan)[0]
    escalate_intent.metadata["region"] = "us-east-1"
    escalate_decision = interceptor.intercept(escalate_intent)
    print_decision(
        "Destroy a prod EC2 instance in us-east-1", escalate_intent, escalate_decision
    )


if __name__ == "__main__":
    main()
