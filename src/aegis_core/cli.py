"""``aegis`` -- a command-line front end for the Aegis Interceptor, so it can
sit in front of an agent's shell and gate kubectl/terraform actions before
they run.

Usage:
    aegis check kubectl [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- kubectl <argv...>
    aegis check terraform [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] <plan.json>

Exit codes: 0 = ALLOW, 2 = ESCALATE, 3 = BLOCK (the max across all intents
produced by the command).
"""

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime

from aegis_core.authority import load_authority_map
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor, Decision
from aegis_core.parser import from_kubectl_multi, from_terraform_plan
from aegis_core.store import ConstraintStore

DEFAULT_CONSTRAINTS = "data/constraints.example.yaml"
DEFAULT_AUTHORITY = "data/authority.example.yaml"

_EXIT_CODE = {"ALLOW": 0, "ESCALATE": 2, "BLOCK": 3}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Evaluate a proposed action")
    check_sub = check.add_subparsers(dest="target", required=True)

    kubectl_parser = check_sub.add_parser("kubectl", help="Evaluate a kubectl invocation")
    kubectl_parser.add_argument("--constraints", default=DEFAULT_CONSTRAINTS)
    kubectl_parser.add_argument("--authority", default=DEFAULT_AUTHORITY)
    kubectl_parser.add_argument("--now", default=None, help="ISO8601 evaluation timestamp")
    output_group = kubectl_parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", default=True)
    output_group.add_argument("--pretty", action="store_true", default=False)
    kubectl_parser.add_argument("kubectl_argv", nargs=argparse.REMAINDER)

    terraform_parser = check_sub.add_parser("terraform", help="Evaluate a terraform plan JSON")
    terraform_parser.add_argument("--constraints", default=DEFAULT_CONSTRAINTS)
    terraform_parser.add_argument("--authority", default=DEFAULT_AUTHORITY)
    terraform_parser.add_argument("--now", default=None, help="ISO8601 evaluation timestamp")
    tf_output_group = terraform_parser.add_mutually_exclusive_group()
    tf_output_group.add_argument("--json", action="store_true", default=True)
    tf_output_group.add_argument("--pretty", action="store_true", default=False)
    terraform_parser.add_argument("plan_path")

    return parser


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _print_decision(intent: InfrastructureIntent, decision: Decision, *, pretty: bool) -> None:
    if pretty:
        print(f"{decision.verdict}: {intent.provider} {intent.action} {intent.resource}")
        if decision.citations:
            print(f"  citations: {', '.join(decision.citations)}")
        if decision.discarded:
            print(f"  discarded: {decision.discarded}")
        print(f"  covered: {decision.covered}  latency_ms: {decision.latency_ms:.4f}")
    else:
        payload = {"intent": intent.to_dict(), "decision": asdict(decision)}
        print(json.dumps(payload))


def _evaluate(
    intents: list[InfrastructureIntent],
    *,
    constraints_path: str,
    authority_path: str,
    now: datetime | None,
    pretty: bool,
) -> int:
    authority_map = load_authority_map(authority_path)
    store = ConstraintStore.load(constraints_path, authority_map=authority_map)
    interceptor = AegisInterceptor(store)

    worst = 0
    for intent in intents:
        decision = interceptor.intercept(intent, now=now)
        _print_decision(intent, decision, pretty=pretty)
        worst = max(worst, _EXIT_CODE[decision.verdict])
    return worst


def _strip_leading_kubectl_separator(argv: list[str]) -> list[str]:
    """argparse.REMAINDER captures a leading "--" as part of the remainder
    when it's used to separate our own flags from the wrapped command; drop
    it if present."""
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "check":
        parser.error("unknown command")

    pretty = bool(args.pretty)
    now = _parse_now(args.now)

    if args.target == "kubectl":
        kubectl_argv = _strip_leading_kubectl_separator(args.kubectl_argv)
        if not kubectl_argv:
            parser.error("no kubectl argv given after --")
        try:
            intents = from_kubectl_multi(kubectl_argv)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _evaluate(
            intents,
            constraints_path=args.constraints,
            authority_path=args.authority,
            now=now,
            pretty=pretty,
        )

    if args.target == "terraform":
        try:
            with open(args.plan_path) as f:
                plan_json = json.load(f)
            intents = from_terraform_plan(plan_json)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _evaluate(
            intents,
            constraints_path=args.constraints,
            authority_path=args.authority,
            now=now,
            pretty=pretty,
        )

    parser.error("unknown check target")
    return 1


if __name__ == "__main__":
    sys.exit(main())
