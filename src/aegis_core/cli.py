"""``aegis`` -- a command-line front end for the Aegis Interceptor, so it can
sit in front of an agent's shell and gate kubectl/terraform/tofu/aws/az/gcloud/
helm/argocd/flux/git/gh actions before they run.

Usage:
    aegis check kubectl [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- kubectl <argv...>
    aegis check aws     [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- aws <argv...>
    aegis check az      [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- az <argv...>
    aegis check gcloud  [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- gcloud <argv...>
    aegis check helm    [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- helm <argv...>
    aegis check argocd  [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- argocd <argv...>
    aegis check flux    [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- flux <argv...>
    aegis check git     [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- git <argv...>
    aegis check gh      [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- gh <argv...>
    aegis check argv    [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] -- <any supported CLI argv...>
    aegis check terraform [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] <plan.json>
    aegis check tofu      (same as terraform; OpenTofu plans use the same schema)

Every subcommand also takes ``--environments PATH`` (default
data/environments.example.yaml if present) to annotate each intent's
``metadata["env"]`` before evaluation -- see aegis_core.environments.

Exit codes: 0 = ALLOW, 2 = ESCALATE, 3 = BLOCK (the max across all intents
produced by the command).
"""

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime

from aegis_core.authority import load_authority_map
from aegis_core.environments import EnvironmentMap, load_environment_map
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor, Decision
from aegis_core.ledger import JsonlLedger
from aegis_core.parser import (
    from_argocd_multi,
    from_argv,
    from_aws_multi,
    from_az,
    from_flux,
    from_gcloud,
    from_gh,
    from_git,
    from_helm,
    from_kubectl_multi,
    from_terraform_plan,
)
from aegis_core.parsers.pulumi import from_pulumi_argv, from_pulumi_preview
from aegis_core.parsers.sql import (
    from_migration_argv,
    from_mongosh,
    from_mysql,
    from_psql,
    from_sql,
    from_sqlite3,
)
from aegis_core.plan import PlanConstraintStore, evaluate_plan
from aegis_core.provenance import FileSourceFetcher
from aegis_core.store import ConstraintStore

DEFAULT_CONSTRAINTS = "data/constraints.example.yaml"
DEFAULT_AUTHORITY = "data/authority.example.yaml"
DEFAULT_ENVIRONMENTS = "data/environments.example.yaml"
DEFAULT_PLAN_CONSTRAINTS = "data/plan_constraints.example.yaml"

_EXIT_CODE = {"ALLOW": 0, "ESCALATE": 2, "BLOCK": 3}

# Targets whose argv is parsed straight from the wrapped command line (as
# opposed to "terraform", which reads a plan JSON file instead). Each maps
# to the parser that turns its argv into a list of InfrastructureIntents.
_ARGV_TARGET_PARSERS = {
    "kubectl": from_kubectl_multi,
    "aws": from_aws_multi,
    "az": lambda argv: [from_az(argv)],
    "gcloud": lambda argv: [from_gcloud(argv)],
    "helm": lambda argv: [from_helm(argv)],
    "argocd": from_argocd_multi,
    "flux": lambda argv: [from_flux(argv)],
    "git": lambda argv: [from_git(argv)],
    "gh": lambda argv: [from_gh(argv)],
    "psql": from_psql,
    "mysql": from_mysql,
    "sqlite3": from_sqlite3,
    "mongosh": from_mongosh,
    "migrate": from_migration_argv,
    "pulumi": lambda argv: [from_pulumi_argv(argv)],
    "argv": from_argv,
}


def _add_common_options(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--constraints", default=DEFAULT_CONSTRAINTS)
    subparser.add_argument("--authority", default=DEFAULT_AUTHORITY)
    default_environments = DEFAULT_ENVIRONMENTS if os.path.exists(DEFAULT_ENVIRONMENTS) else None
    subparser.add_argument(
        "--environments",
        default=default_environments,
        help="path to an environment identity map (data/environments.example.yaml shape); "
        "omit to skip env annotation",
    )
    default_plan = DEFAULT_PLAN_CONSTRAINTS if os.path.exists(DEFAULT_PLAN_CONSTRAINTS) else None
    subparser.add_argument(
        "--plan-constraints",
        default=default_plan,
        help="path to set-level plan constraints evaluated over the whole intent batch; "
        "omit to skip",
    )
    subparser.add_argument(
        "--sources",
        default=None,
        help="directory of <source_ref>.json files; when given, constraints whose cited "
        "source does not back them are quarantined as forged at load time",
    )
    subparser.add_argument(
        "--ledger",
        default=None,
        help="JSONL decision ledger path; enables rate-limited constraints and records "
        "every executed (ALLOW, non-dry-run) action",
    )
    subparser.add_argument("--now", default=None, help="ISO8601 evaluation timestamp")
    output_group = subparser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", default=True)
    output_group.add_argument("--pretty", action="store_true", default=False)


def _add_argv_target(check_sub: argparse._SubParsersAction, name: str, help_text: str) -> None:
    """Adds a "check <name> -- <argv...>" subparser sharing the common
    options and REMAINDER argv-capture pattern used by kubectl/aws/az/gcloud/argv."""
    subparser = check_sub.add_parser(name, help=help_text)
    _add_common_options(subparser)
    subparser.add_argument("target_argv", nargs=argparse.REMAINDER)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Evaluate a proposed action")
    check_sub = check.add_subparsers(dest="target", required=True)

    _add_argv_target(check_sub, "kubectl", "Evaluate a kubectl invocation")
    _add_argv_target(check_sub, "aws", "Evaluate an aws CLI invocation")
    _add_argv_target(check_sub, "az", "Evaluate an az CLI invocation")
    _add_argv_target(check_sub, "gcloud", "Evaluate a gcloud CLI invocation")
    _add_argv_target(check_sub, "helm", "Evaluate a helm invocation")
    _add_argv_target(check_sub, "argocd", "Evaluate an argocd CLI invocation")
    _add_argv_target(check_sub, "flux", "Evaluate a flux CLI invocation")
    _add_argv_target(check_sub, "git", "Evaluate a git invocation")
    _add_argv_target(check_sub, "gh", "Evaluate a gh (GitHub CLI) invocation")
    _add_argv_target(
        check_sub, "argv", "Evaluate any supported CLI invocation, dispatched by binary name"
    )

    for tool, help_text in (
        ("terraform", "Evaluate a terraform plan JSON"),
        ("tofu", "Evaluate an OpenTofu plan JSON (same schema as terraform)"),
        ("pulumi-preview", "Evaluate a 'pulumi preview --json' document"),
    ):
        plan_parser = check_sub.add_parser(tool, help=help_text)
        _add_common_options(plan_parser)
        plan_parser.add_argument("plan_path")

    for name, help_text in (
        ("psql", "Evaluate a psql invocation (-c SQL / -f file)"),
        ("mysql", "Evaluate a mysql invocation (-e SQL)"),
        ("sqlite3", "Evaluate a sqlite3 invocation"),
        ("mongosh", "Evaluate a mongosh invocation (--eval)"),
        ("migrate", "Evaluate alembic/flyway/rails/prisma migration commands"),
        ("pulumi", "Evaluate a pulumi up/destroy/refresh/stack rm invocation"),
    ):
        _add_argv_target(check_sub, name, help_text)

    sql_parser = check_sub.add_parser("sql", help="Evaluate raw SQL text (one or more statements)")
    _add_common_options(sql_parser)
    sql_parser.add_argument("--database", default=None)
    sql_parser.add_argument("--dialect", default="generic")
    sql_parser.add_argument("sql", help="SQL text, or '-' to read from stdin")

    return parser


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _print_decision(intent: InfrastructureIntent, decision: Decision, *, pretty: bool) -> None:
    if pretty:
        dry_run_suffix = f" (dry-run; would be {decision.would_be})" if decision.dry_run else ""
        print(
            f"{decision.verdict}: {intent.provider} {intent.action} {intent.resource}"
            f"{dry_run_suffix}"
        )
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
    environments_path: str | None,
    plan_constraints_path: str | None = None,
    sources_path: str | None = None,
    ledger_path: str | None = None,
    now: datetime | None,
    pretty: bool,
) -> int:
    authority_map = load_authority_map(authority_path)
    fetcher = FileSourceFetcher(sources_path) if sources_path else None
    store = ConstraintStore.load(
        constraints_path, authority_map=authority_map, source_fetcher=fetcher
    )
    ledger = None
    if ledger_path:
        ledger = JsonlLedger(ledger_path)
        ledger.load()
    interceptor = AegisInterceptor(store, ledger=ledger)
    env_map = load_environment_map(environments_path) if environments_path else EnvironmentMap()
    for intent in intents:
        env_map.annotate(intent)

    if plan_constraints_path:
        plan_store = PlanConstraintStore.load(plan_constraints_path, authority_map=authority_map)
        plan_decision = evaluate_plan(interceptor, plan_store, intents, now=now)
        for intent, decision in zip(intents, plan_decision.per_intent):
            _print_decision(intent, decision, pretty=pretty)
        _print_plan_decision(plan_decision, quarantined=store.quarantined, pretty=pretty)
        return _EXIT_CODE[plan_decision.verdict]

    worst = 0
    for intent in intents:
        decision = interceptor.intercept(intent, now=now)
        _print_decision(intent, decision, pretty=pretty)
        worst = max(worst, _EXIT_CODE[decision.verdict])
    return worst


def _print_plan_decision(plan_decision, *, quarantined: list[dict], pretty: bool) -> None:
    """Prints the batch-level verdict once, after the per-intent lines."""
    plan_citations = [
        c for c in plan_decision.citations
        if not any(c in d.citations for d in plan_decision.per_intent)
    ]
    if pretty:
        print(f"PLAN {plan_decision.verdict}: {plan_decision.n_intents} intent(s)")
        if plan_citations:
            print(f"  plan citations: {', '.join(plan_citations)}")
        for note in plan_decision.notes:
            print(f"  note: {note}")
        if plan_decision.discarded:
            print(f"  discarded: {plan_decision.discarded}")
        if quarantined:
            print(f"  quarantined at load: {quarantined}")
    else:
        payload = {
            "plan": {
                "verdict": plan_decision.verdict,
                "n_intents": plan_decision.n_intents,
                "citations": plan_decision.citations,
                "plan_citations": plan_citations,
                "discarded": plan_decision.discarded,
                "notes": plan_decision.notes,
                "latency_ms": plan_decision.latency_ms,
                "quarantined_at_load": quarantined,
            }
        }
        print(json.dumps(payload))


def _strip_leading_separator(argv: list[str]) -> list[str]:
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

    if args.target in _ARGV_TARGET_PARSERS:
        target_argv = _strip_leading_separator(args.target_argv)
        if not target_argv:
            parser.error(f"no {args.target} argv given after --")
        try:
            intents = _ARGV_TARGET_PARSERS[args.target](target_argv)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _evaluate(
            intents,
            constraints_path=args.constraints,
            authority_path=args.authority,
            environments_path=args.environments,
            plan_constraints_path=args.plan_constraints,
            sources_path=args.sources,
            ledger_path=args.ledger,
            now=now,
            pretty=pretty,
        )

    if args.target == "sql":
        sql_text = sys.stdin.read() if args.sql == "-" else args.sql
        try:
            intents = from_sql(sql_text, dialect=args.dialect, database=args.database)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _evaluate(
            intents,
            constraints_path=args.constraints,
            authority_path=args.authority,
            environments_path=args.environments,
            plan_constraints_path=args.plan_constraints,
            sources_path=args.sources,
            ledger_path=args.ledger,
            now=now,
            pretty=pretty,
        )

    if args.target in ("terraform", "tofu", "pulumi-preview"):
        try:
            with open(args.plan_path) as f:
                plan_json = json.load(f)
            if args.target == "pulumi-preview":
                intents = from_pulumi_preview(plan_json)
            else:
                intents = from_terraform_plan(plan_json, tool=args.target)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _evaluate(
            intents,
            constraints_path=args.constraints,
            authority_path=args.authority,
            environments_path=args.environments,
            plan_constraints_path=args.plan_constraints,
            sources_path=args.sources,
            ledger_path=args.ledger,
            now=now,
            pretty=pretty,
        )

    parser.error("unknown check target")
    return 1


if __name__ == "__main__":
    sys.exit(main())
