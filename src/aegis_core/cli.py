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

Every output carries a ``store_health`` object (``loaded``, ``quarantined``,
``principals``, ``constraints_sha256``, ``warnings``): a degraded store must
never look like a clean ALLOW. The CLI refuses to decide at all (exit 65)
when the store loaded zero constraints, the authority map grants nothing to
anyone, or more than ``--max-quarantine-ratio`` (default 0.10) of the
constraints were quarantined.

Exit codes (``--exit-style aegis``, the default):
    0   ALLOW               2   ESCALATE            3   BLOCK
    64  usage error         65  bad data (YAML/JSON/argv/--now, degraded store)
    66  missing input file  70  internal error (exception class on stderr)
``--exit-style claude-hook``: 0 for ALLOW (prints nothing); 2 for ESCALATE
and BLOCK, printing one ``{"decision": "block", "reason": ...}`` object.
``--exit-style ci``: 0 for ALLOW, 1 otherwise. Tool errors (64/65/66/70) are
identical in every style. A verdict's exit code is the max across all
intents produced by the command.
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from datetime import datetime

import yaml

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
from aegis_core.store import ConstraintStore, StoreHealth

DEFAULT_CONSTRAINTS = "data/constraints.example.yaml"
DEFAULT_AUTHORITY = "data/authority.example.yaml"
DEFAULT_ENVIRONMENTS = "data/environments.example.yaml"
DEFAULT_PLAN_CONSTRAINTS = "data/plan_constraints.example.yaml"
DEFAULT_MAX_QUARANTINE_RATIO = 0.10

# sysexits.h
EX_USAGE = 64
EX_DATAERR = 65
EX_NOINPUT = 66
EX_SOFTWARE = 70

_VERDICT_RANK = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
_EXIT_CODES = {
    "aegis": {"ALLOW": 0, "ESCALATE": 2, "BLOCK": 3},
    "claude-hook": {"ALLOW": 0, "ESCALATE": 2, "BLOCK": 2},
    "ci": {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 1},
}

# Shell metacharacters that mean the argv is really a compound shell command,
# which the argv parsers cannot evaluate safely (REVIEW-4 T1.2 will add
# --split-compound); until then such input is a usage error. Checked as
# substrings, because a plain shlex.split leaves "pods;" as one token, while
# a punctuation-aware split turns "$(cat x)" into "$", "(", ... -- so the
# parentheses and redirections are rejected on their own as well.
_SHELL_CONTROL_TOKENS = {"&"}
_SHELL_CONTROL_MARKERS = (";", "|", "&&", "$(", "`", "\n", "(", ")", "<", ">")

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


class UsageError(Exception):
    """A command-line usage error (exit 64)."""


class DataError(Exception):
    """Bad input data or a store too degraded to decide with (exit 65)."""


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors, which collides with ESCALATE; raise
    instead so ``main`` can map it to EX_USAGE (64)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        prefix = f"{self.prog}: " if self.prog != "aegis" else ""
        raise UsageError(f"{prefix}{message}")


class _StderrHandler(logging.Handler):
    """Writes to whatever ``sys.stderr`` is *at emit time* (so pytest's
    capture and redirects both see it)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stderr.write(self.format(record) + "\n")
        except Exception:  # pragma: no cover - logging must never raise
            pass


_LOGGING_CONFIGURED = False


def _configure_logging() -> None:
    """Routes ``aegis_core`` warnings (e.g. quarantines at load) to stderr
    as ``aegis: WARNING ...`` lines, once per process."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return
    handler = _StderrHandler()
    handler.setFormatter(logging.Formatter("aegis: %(levelname)s %(message)s"))
    package_logger = logging.getLogger("aegis_core")
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.WARNING)
    _LOGGING_CONFIGURED = True


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
    subparser.add_argument(
        "--exit-style",
        choices=sorted(_EXIT_CODES),
        default="aegis",
        help="aegis: 0/2/3 for ALLOW/ESCALATE/BLOCK (default); claude-hook: 0 for ALLOW, "
        "2 for ESCALATE and BLOCK with a {decision, reason} JSON object; ci: 0 for ALLOW, "
        "1 otherwise",
    )
    subparser.add_argument(
        "--fail-closed",
        action="store_true",
        default=False,
        help="ESCALATE (instead of ALLOW) any intent that no constraint covers",
    )
    subparser.add_argument(
        "--max-quarantine-ratio",
        type=float,
        default=DEFAULT_MAX_QUARANTINE_RATIO,
        help="refuse to decide (exit 65) when quarantined/(loaded+quarantined) exceeds this "
        f"(default {DEFAULT_MAX_QUARANTINE_RATIO})",
    )
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
    parser = _ArgumentParser(prog="aegis")
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
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise DataError(f"--now {value!r} is not an ISO8601 timestamp: {exc}") from None


# Binaries whose argv legitimately carries a script string ("psql -c
# 'DELETE ...; SELECT 1'", "mongosh --eval 'db.x.drop()'"): their parsers
# classify that string themselves, so the compound-shell check is skipped.
_SCRIPT_ARGUMENT_BINARIES = {"psql", "mysql", "sqlite3", "mongosh", "alembic", "flyway",
                             "rails", "prisma"}


def _reject_compound_argv(argv: list[str]) -> None:
    """Shell control tokens can't be evaluated by the argv parsers; refuse
    them as a usage error instead of treating ``;`` as a resource name."""
    if os.path.basename(argv[0]) in _SCRIPT_ARGUMENT_BINARIES:
        return
    for tok in argv:
        if tok in _SHELL_CONTROL_TOKENS or any(m in tok for m in _SHELL_CONTROL_MARKERS):
            raise UsageError(
                f"compound shell command not supported (token {tok!r}); "
                "check each simple command separately"
            )


# --- output ----------------------------------------------------------------


class _Output:
    """Collects what the run prints. ``claude-hook`` style suppresses the
    per-intent/plan lines entirely and prints one decision object at the
    end; every other style prints as it goes."""

    def __init__(self, *, pretty: bool, style: str, store_health: StoreHealth):
        self.pretty = pretty
        self.style = style
        self.store_health = store_health
        self.quiet = style == "claude-hook"

    def decision(self, intent: InfrastructureIntent, decision: Decision) -> None:
        if self.quiet:
            return
        if self.pretty:
            dry_run_suffix = f" (dry-run; would be {decision.would_be})" if decision.dry_run else ""
            print(
                f"{decision.verdict}: {intent.provider} {intent.action} {intent.resource}"
                f"{dry_run_suffix}"
            )
            if decision.citations:
                print(f"  citations: {', '.join(decision.citations)}")
            if decision.discarded:
                print(f"  discarded: {decision.discarded}")
            for note in decision.notes:
                print(f"  note: {note}")
            print(f"  covered: {decision.covered}  latency_ms: {decision.latency_ms:.4f}")
        else:
            payload = {
                "intent": intent.to_dict(),
                "decision": asdict(decision),
                "store_health": self.store_health.to_dict(),
            }
            print(json.dumps(payload))

    def plan(self, plan_decision, *, plan_health: StoreHealth) -> None:
        """Prints the batch-level verdict once, after the per-intent lines."""
        if self.quiet:
            return
        plan_citations = [
            c for c in plan_decision.citations
            if not any(c in d.citations for d in plan_decision.per_intent)
        ]
        if self.pretty:
            print(f"PLAN {plan_decision.verdict}: {plan_decision.n_intents} intent(s)")
            if plan_citations:
                print(f"  plan citations: {', '.join(plan_citations)}")
            for note in plan_decision.notes:
                print(f"  note: {note}")
            if plan_decision.discarded:
                print(f"  discarded: {plan_decision.discarded}")
            if plan_health.quarantined:
                print(f"  plan constraints quarantined at load: {plan_health.quarantined}")
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
                    "quarantined_at_load": self.store_health.quarantined,
                    "store_health": self.store_health.to_dict(),
                    "plan_store_health": plan_health.to_dict(),
                }
            }
            print(json.dumps(payload))

    def finish(self, verdict: str, reason_parts: list[str]) -> None:
        """The trailing STORE line (--pretty) or the claude-hook object."""
        if self.style == "claude-hook":
            if verdict != "ALLOW":
                reason = f"{verdict}: {', '.join(reason_parts) or 'no citations'}"
                print(json.dumps({"decision": "block", "reason": reason}))
                print(f"aegis: {reason}", file=sys.stderr)
            return
        if self.pretty:
            h = self.store_health
            print(
                f"STORE: loaded={h.loaded} quarantined={len(h.quarantined)} "
                f"principals={h.principals}"
            )
            for entry in h.quarantined:
                print(f"  quarantined: {entry['id']} ({entry['reason']})")


# --- evaluation --------------------------------------------------------------


def _load_or_data_error(loader, path: str, what: str):
    """Runs a loader, converting malformed-but-parseable files (wrong shape,
    missing keys) into a one-line DataError. Missing files propagate as
    FileNotFoundError (exit 66) and YAML syntax errors as yaml.YAMLError
    (exit 65) untouched."""
    try:
        return loader()
    except (KeyError, TypeError, AttributeError) as exc:
        raise DataError(f"malformed {what} file {path}: {exc.__class__.__name__}: {exc}") from None


def _check_store_health(
    health: StoreHealth, *, constraints_path: str, authority_path: str, max_ratio: float
) -> None:
    """The hard-fail gate: a store this degraded is refused, no verdict."""
    total = health.loaded + len(health.quarantined)
    if health.loaded == 0:
        raise DataError(
            f"constraint store {constraints_path} has 0 loaded constraints "
            f"({len(health.quarantined)} quarantined); refusing to decide"
        )
    if health.principals == 0:
        raise DataError(
            f"authority map {authority_path} grants nothing to anyone (0 principals); "
            "refusing to decide"
        )
    if health.quarantine_ratio > max_ratio:
        raise DataError(
            f"{len(health.quarantined)}/{total} constraints in {constraints_path} quarantined "
            f"(ratio {health.quarantine_ratio:.2f} > --max-quarantine-ratio {max_ratio}); "
            "refusing to decide"
        )


def _evaluate(intents: list[InfrastructureIntent], args: argparse.Namespace) -> int:
    now = _parse_now(args.now)
    pretty = bool(args.pretty)

    authority_map = _load_or_data_error(
        lambda: load_authority_map(args.authority), args.authority, "authority"
    )
    fetcher = FileSourceFetcher(args.sources) if args.sources else None
    store = _load_or_data_error(
        lambda: ConstraintStore.load(
            args.constraints, authority_map=authority_map, source_fetcher=fetcher
        ),
        args.constraints,
        "constraints",
    )
    plan_store = None
    if args.plan_constraints:
        plan_store = _load_or_data_error(
            lambda: PlanConstraintStore.load(args.plan_constraints, authority_map=authority_map),
            args.plan_constraints,
            "plan constraints",
        )

    health = store.health
    _check_store_health(
        health,
        constraints_path=args.constraints,
        authority_path=args.authority,
        max_ratio=args.max_quarantine_ratio,
    )
    if plan_store is not None and plan_store.health.quarantine_ratio > args.max_quarantine_ratio:
        ph = plan_store.health
        raise DataError(
            f"{len(ph.quarantined)}/{ph.loaded + len(ph.quarantined)} plan constraints in "
            f"{args.plan_constraints} quarantined (ratio {ph.quarantine_ratio:.2f} > "
            f"--max-quarantine-ratio {args.max_quarantine_ratio}); refusing to decide"
        )

    ledger = None
    if args.ledger:
        ledger = JsonlLedger(args.ledger)
        ledger.load()
    interceptor = AegisInterceptor(store, ledger=ledger, fail_closed=args.fail_closed)
    env_map = (
        _load_or_data_error(
            lambda: load_environment_map(args.environments), args.environments, "environments"
        )
        if args.environments
        else EnvironmentMap()
    )
    for intent in intents:
        env_map.annotate(intent)

    output = _Output(pretty=pretty, style=args.exit_style, store_health=health)

    if plan_store is not None:
        plan_decision = evaluate_plan(interceptor, plan_store, intents, now=now)
        for intent, decision in zip(intents, plan_decision.per_intent):
            output.decision(intent, decision)
        output.plan(plan_decision, plan_health=plan_store.health)
        reason_parts = list(plan_decision.citations)
        if not reason_parts:
            reason_parts = [n for n in plan_decision.notes if n.startswith("fail-closed")]
        output.finish(plan_decision.verdict, reason_parts)
        return _EXIT_CODES[args.exit_style][plan_decision.verdict]

    worst = "ALLOW"
    citations: list[str] = []
    fail_closed_notes: list[str] = []
    for intent in intents:
        decision = interceptor.intercept(intent, now=now)
        output.decision(intent, decision)
        if _VERDICT_RANK[decision.verdict] > _VERDICT_RANK[worst]:
            worst = decision.verdict
        citations.extend(c for c in decision.citations if c not in citations)
        fail_closed_notes.extend(n for n in decision.notes if n.startswith("fail-closed"))
    output.finish(worst, citations or fail_closed_notes)
    return _EXIT_CODES[args.exit_style][worst]


def _strip_leading_separator(argv: list[str]) -> list[str]:
    """argparse.REMAINDER captures a leading "--" as part of the remainder
    when it's used to separate our own flags from the wrapped command; drop
    it if present."""
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def _read_plan_json(path: str) -> dict:
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as exc:
            raise DataError(f"{path}: invalid JSON: {exc}") from None


def _run(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "check":
        raise UsageError("unknown command")

    if args.target in _ARGV_TARGET_PARSERS:
        target_argv = _strip_leading_separator(args.target_argv)
        if not target_argv:
            raise UsageError(f"check {args.target}: no {args.target} argv given after --")
        _reject_compound_argv(target_argv)
        intents = _ARGV_TARGET_PARSERS[args.target](target_argv)
        return _evaluate(intents, args)

    if args.target == "sql":
        sql_text = sys.stdin.read() if args.sql == "-" else args.sql
        intents = from_sql(sql_text, dialect=args.dialect, database=args.database)
        return _evaluate(intents, args)

    if args.target in ("terraform", "tofu", "pulumi-preview"):
        plan_json = _read_plan_json(args.plan_path)
        if args.target == "pulumi-preview":
            intents = from_pulumi_preview(plan_json)
        else:
            intents = from_terraform_plan(plan_json, tool=args.target)
        return _evaluate(intents, args)

    raise UsageError("unknown check target")


def main(argv: list[str] | None = None) -> int:
    """Entry point. Every failure is a one-line ``aegis: error: ...`` on
    stderr with a sysexits code; a traceback never reaches the caller."""
    argv = sys.argv[1:] if argv is None else argv
    _configure_logging()
    try:
        return _run(argv)
    except UsageError as exc:
        print(f"aegis: error: {exc}", file=sys.stderr)
        return EX_USAGE
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        target = exc.filename or exc
        print(f"aegis: error: cannot read {target}: {exc.strerror or exc}", file=sys.stderr)
        return EX_NOINPUT
    except (DataError, ValueError, yaml.YAMLError) as exc:
        message = str(exc).replace("\n", " ")
        print(f"aegis: error: {message}", file=sys.stderr)
        return EX_DATAERR
    except Exception as exc:  # noqa: BLE001 - the contract is "never a traceback"
        print(f"aegis: error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return EX_SOFTWARE


if __name__ == "__main__":
    sys.exit(main())
