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
    aegis check argv    [--split-compound] [...] -- <any supported CLI argv...>
    aegis check command [...] -- "<shell command string>"
    aegis check terraform [--constraints PATH] [--authority PATH] [--now ISO8601] \
        [--json | --pretty] <plan.json>
    aegis check tofu      (same as terraform; OpenTofu plans use the same schema)
    aegis sign   [--key SOURCE] PATH...     (a directory gets one AEGIS-MANIFEST.sig)
    aegis verify [--key SOURCE] PATH...
    aegis init   DIR                        (seed DIR with the packaged example policy files)
    aegis keygen [--out FILE]                (write a real signing key)

Every subcommand also takes ``--config-dir PATH`` and, when ``--constraints``/
``--authority``/``--environments``/``--plan-constraints`` are left unset,
resolves them from it -- search order: ``--config-dir``,
``$AEGIS_CONFIG_DIR``, ``$PWD/.aegis``, ``$PWD/data`` (only if it already has
a ``constraints*.yaml``), ``~/.config/aegis``, ``/etc/aegis``; see
aegis_core.config. Nothing found and no explicit path given is exit 66
(``no config found ...; run 'aegis init <dir>'``).

``--log-json PATH`` appends one JSON object per decision (every verdict,
intent, decision, store_health, constraints_sha256, timestamp) -- separate
from the ledger, which only ever records executed ALLOWs. ``--metrics-textfile
PATH`` (over)writes Prometheus textfile-collector metrics for the invocation:
``aegis_decisions_total{verdict=...}``, ``aegis_store_loaded``,
``aegis_store_quarantined``, ``aegis_decision_latency_ms{quantile=...}``.

**Signing.** Every policy file (constraints, authority, environments, plan
constraints, sources and their PRINCIPALS.yaml) must verify under a keyed
MAC (aegis_core.signing). The key comes from ``--key SOURCE``
(``env:VAR`` | ``file:PATH`` | hex), then ``$AEGIS_SIGNING_KEY``, then
``<dir of --constraints>/example-signing.key`` if it exists (with the
warning ``using example signing key`` -- that key is public). With none
of those, ``--insecure`` loads everything unverified (warning
``insecure: signatures not verified``); otherwise the CLI refuses (exit
65). ``--insecure`` always disables verification, even when a key could
have been found.

Every output carries a ``store_health`` object (``loaded``, ``quarantined``,
``principals``, ``constraints_sha256``, ``warnings``): a degraded store must
never look like a clean ALLOW. The CLI refuses to decide at all (exit 65)
when the store loaded zero constraints, the authority map grants nothing to
anyone, or more than ``--max-quarantine-ratio`` (default 0.10) of the
constraints were quarantined.

Exit codes (``--exit-style aegis``, the default):
    0   ALLOW               2   ESCALATE            3   BLOCK
    64  usage error         65  bad data (YAML/JSON/argv/--now, degraded store,
    66  missing input file      missing or bad signature)
    70  internal error (exception class on stderr)
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
from datetime import UTC, datetime, timedelta

import yaml

from aegis_core import config as config_module
from aegis_core import signing
from aegis_core.authority import load_authority_map
from aegis_core.environments import (
    EnvironmentMap,
    load_environment_map,
    resolve_current_context,
)
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor, Decision
from aegis_core.ledger import DecisionLedger, JsonlLedger, SqliteLedger, parse_window
from aegis_core.parser import (
    from_argocd_multi,
    from_argv,
    from_aws_multi,
    from_az_multi,
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
from aegis_core.shell import ShellRejected, intents_from_command
from aegis_core.signing import SignatureError
from aegis_core.store import ConstraintStore, StoreHealth

DEFAULT_CONSTRAINTS = "data/constraints.example.yaml"
DEFAULT_AUTHORITY = "data/authority.example.yaml"
DEFAULT_ENVIRONMENTS = "data/environments.example.yaml"
DEFAULT_PLAN_CONSTRAINTS = "data/plan_constraints.example.yaml"
DEFAULT_MAX_QUARANTINE_RATIO = 0.10
EXAMPLE_KEY_NAME = "example-signing.key"
SIGNING_KEY_ENV = "AEGIS_SIGNING_KEY"
SOURCES_DIR_NAME = "sources"
WARN_EXAMPLE_KEY = "using example signing key"
WARN_INSECURE = "insecure: signatures not verified"
NO_KEY_MESSAGE = f"no signing key: pass --key, set {SIGNING_KEY_ENV}, or --insecure"

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
# which the argv parsers cannot evaluate safely; without --split-compound
# such input is a usage error (use ``aegis check command`` for strings).
# Checked as substrings, because a plain shlex.split leaves "pods;" as one
# token, while a punctuation-aware split turns "$(cat x)" into "$", "(", ...
# -- so the parentheses and redirections are rejected on their own as well.
_SHELL_CONTROL_TOKENS = {"&"}
_SHELL_CONTROL_MARKERS = (";", "|", "&&", "$(", "`", "\n", "(", ")", "<", ">")

# Targets whose argv is parsed straight from the wrapped command line (as
# opposed to "terraform", which reads a plan JSON file instead). Each maps
# to the parser that turns its argv into a list of InfrastructureIntents.
_ARGV_TARGET_PARSERS = {
    "kubectl": from_kubectl_multi,
    "aws": from_aws_multi,
    "az": from_az_multi,
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

_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


class UsageError(Exception):
    """A command-line usage error (exit 64)."""


class DataError(Exception):
    """Bad input data or a store too degraded to decide with (exit 65)."""


class ConfigNotFoundError(Exception):
    """No config directory found and no explicit policy file paths given
    (exit 66) -- see ``aegis_core.config`` and REVIEW-4 T2.6."""


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


def _add_key_options(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--key",
        default=None,
        metavar="SOURCE",
        help="signing key: env:VAR | file:PATH | hex (default: $AEGIS_SIGNING_KEY, then "
        "<dir of --constraints>/example-signing.key if present)",
    )


def _add_common_options(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--config-dir",
        default=None,
        help="directory of policy files (search order: --config-dir, "
        f"${config_module.CONFIG_ENV_VAR}, $PWD/.aegis, $PWD/data (if it has constraints*.yaml), "
        "~/.config/aegis, /etc/aegis); fills in any of --constraints/--authority/"
        "--environments/--plan-constraints left unset (see 'aegis init')",
    )
    subparser.add_argument(
        "--constraints",
        default=None,
        help="path to the constraint store (default: resolved from --config-dir)",
    )
    subparser.add_argument(
        "--authority",
        default=None,
        help="path to the authority map (default: resolved from --config-dir)",
    )
    subparser.add_argument(
        "--environments",
        default=None,
        help="path to an environment identity map (data/environments.example.yaml shape); "
        "default resolved from --config-dir; omit entirely (no config dir either) to skip "
        "env annotation",
    )
    subparser.add_argument(
        "--plan-constraints",
        default=None,
        help="path to set-level plan constraints evaluated over the whole intent batch; "
        "default resolved from --config-dir; omit entirely to skip",
    )
    subparser.add_argument(
        "--sources",
        default=None,
        help="directory of <source_ref>.json files (default: <dir of --constraints>/sources "
        "when it exists; pass '' to disable); constraints whose cited source does not back "
        "them are quarantined as forged at load time",
    )
    _add_key_options(subparser)
    subparser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="load policy files without verifying signatures (never for real use)",
    )
    subparser.add_argument(
        "--ledger",
        default=None,
        help="decision ledger path (.jsonl, or .db/.sqlite for SQLite); enables rate-limited "
        "constraints and records every executed (ALLOW, non-dry-run) action",
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
        "--resolve-current-context",
        action="store_true",
        default=False,
        help="fill a missing context/profile/project/... from the invoking environment "
        "($KUBECONFIG current-context, $AWS_PROFILE, $CLOUDSDK_CORE_PROJECT, ...); "
        "TRUSTS THE INVOKING ENVIRONMENT",
    )
    subparser.add_argument(
        "--max-quarantine-ratio",
        type=float,
        default=DEFAULT_MAX_QUARANTINE_RATIO,
        help="refuse to decide (exit 65) when quarantined/(loaded+quarantined) exceeds this "
        f"(default {DEFAULT_MAX_QUARANTINE_RATIO})",
    )
    subparser.add_argument(
        "--log-json",
        default=None,
        metavar="PATH",
        help="append one JSON object per decision (every verdict, intent, decision, "
        "store_health, constraints_sha256, timestamp) to this file, separate from the "
        "ledger",
    )
    subparser.add_argument(
        "--metrics-textfile",
        default=None,
        metavar="PATH",
        help="write Prometheus textfile-collector metrics for this invocation "
        "(aegis_decisions_total, aegis_store_loaded, aegis_store_quarantined, "
        "aegis_decision_latency_ms); overwrites the file",
    )
    output_group = subparser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json", action="store_true", default=False, help="JSON output (default)"
    )
    output_group.add_argument(
        "--pretty", action="store_true", default=False, help="human-readable output"
    )


def _add_argv_target(check_sub: argparse._SubParsersAction, name: str, help_text: str) -> None:
    """Adds a "check <name> -- <argv...>" subparser sharing the common
    options and REMAINDER argv-capture pattern used by kubectl/aws/az/gcloud/argv."""
    subparser = check_sub.add_parser(name, help=help_text)
    _add_common_options(subparser)
    if name == "argv":
        subparser.add_argument(
            "--split-compound",
            action="store_true",
            default=False,
            help="treat the argv as a shell command line: split on ; && || | and unwrap "
            "sudo/env/timeout (same as 'aegis check command')",
        )
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
    command_parser = check_sub.add_parser(
        "command",
        help="Evaluate a shell command string: splits compound commands, unwraps launchers",
    )
    _add_common_options(command_parser)
    command_parser.add_argument("command_string", nargs=argparse.REMAINDER)

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

    for name, help_text in (
        ("sign", "Sign policy files (a directory gets one AEGIS-MANIFEST.sig)"),
        ("verify", "Verify policy file signatures"),
    ):
        sign_parser = subparsers.add_parser(name, help=help_text)
        _add_key_options(sign_parser)
        sign_parser.add_argument("paths", nargs="+")

    init_parser = subparsers.add_parser(
        "init", help="Seed a config directory with the packaged example policy files"
    )
    init_parser.add_argument("dir", help="directory to create/populate (e.g. ~/.config/aegis)")

    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate a real signing key (32 random bytes, hex-encoded, mode 0600)"
    )
    keygen_parser.add_argument(
        "--out", default="aegis-signing.key", help="path to write the key to"
    )

    return parser


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        now = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DataError(f"--now {value!r} is not an ISO8601 timestamp: {exc}") from None
    if now.tzinfo is None:
        raise DataError("--now must include a timezone offset")
    return now


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
                "use 'aegis check command' or --split-compound, or check each simple "
                "command separately"
            )


def _intents_from_shell_string(command: str) -> list[InfrastructureIntent]:
    try:
        return intents_from_command(command)
    except ShellRejected as exc:
        raise UsageError(f"command rejected: {exc.reason}") from None


# --- signing key resolution ------------------------------------------------------


def _resolve_key(args: argparse.Namespace, warnings: list[str]) -> tuple[bytes | None, bool]:
    """``(key, insecure)`` per the module docstring's resolution order.
    Records the ``using example signing key`` / ``insecure`` warnings;
    raises :class:`DataError` when there is no key and no ``--insecure``."""
    if args.insecure:
        warnings.append(WARN_INSECURE)
        return None, True
    if args.key:
        return signing.load_key(args.key), False
    if os.environ.get(SIGNING_KEY_ENV):
        return signing.load_key(f"env:{SIGNING_KEY_ENV}"), False
    example = os.path.join(os.path.dirname(os.path.abspath(args.constraints)), EXAMPLE_KEY_NAME)
    if os.path.exists(example):
        warnings.append(WARN_EXAMPLE_KEY)
        return signing.load_key(f"file:{example}"), False
    raise DataError(NO_KEY_MESSAGE)


def _resolve_config_paths(args: argparse.Namespace) -> None:
    """Fills in any of ``--constraints``/``--authority``/``--environments``/
    ``--plan-constraints`` the caller left unset (``None``) from
    ``--config-dir`` (see ``aegis_core.config``). ``--environments`` and
    ``--plan-constraints`` are allowed to stay ``None`` (those features are
    just skipped); ``--constraints``/``--authority`` are not, and a search
    that finds nothing for them is a hard ``ConfigNotFoundError`` (exit 66)
    -- falling back to the historical ``data/*.example.yaml`` paths only
    when neither a config dir nor an explicit path is available, so a repo
    checkout with no ``.aegis``/env var still works."""
    needs_any = any(
        getattr(args, name) is None
        for name in ("constraints", "authority", "environments", "plan_constraints")
    )
    if not needs_any:
        return
    search = config_module.search_config_dir(args.config_dir)
    resolved = (
        config_module.resolve_defaults(search.found)
        if search.found is not None
        else config_module.ResolvedConfig()
    )
    if args.constraints is None:
        args.constraints = resolved.constraints
    if args.authority is None:
        args.authority = resolved.authority
    if args.environments is None:
        args.environments = resolved.environments
    if args.plan_constraints is None:
        args.plan_constraints = resolved.plan_constraints

    if args.constraints is None and os.path.exists(DEFAULT_CONSTRAINTS):
        args.constraints = DEFAULT_CONSTRAINTS
    if args.authority is None and os.path.exists(DEFAULT_AUTHORITY):
        args.authority = DEFAULT_AUTHORITY

    if args.constraints is None or args.authority is None:
        searched = ", ".join(str(p) for p in search.searched)
        raise ConfigNotFoundError(
            f"no config found (searched: {searched}); run 'aegis init <dir>'"
        )


def _default_sources(args: argparse.Namespace) -> str | None:
    """``--sources`` as given; ``''`` disables; ``None`` means the
    ``sources`` directory next to the constraints file, when it exists."""
    if args.sources is not None:
        return args.sources or None
    candidate = os.path.join(os.path.dirname(os.path.abspath(args.constraints)), SOURCES_DIR_NAME)
    return candidate if os.path.isdir(candidate) else None


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
            if decision.dry_run:
                dry_run_suffix = (
                    f" (dry-run; would be {decision.would_be})"
                    if decision.would_be is not None
                    else " (dry-run; uncovered)"
                )
            else:
                dry_run_suffix = ""
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
            plan_sha = intent.metadata.get("plan_sha256")
            if plan_sha:
                print(f"  plan_sha256: {str(plan_sha)[:12]}")
            resolved = intent.metadata.get("resolved_from_environment")
            if resolved:
                print(f"  resolved_from_environment: {', '.join(resolved)}")
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
            for warning in h.warnings:
                print(f"WARNING: {warning}")
            print(
                f"STORE: loaded={h.loaded} quarantined={len(h.quarantined)} "
                f"principals={h.principals}"
            )
            for entry in h.quarantined:
                print(f"  quarantined: {entry['id']} ({entry['reason']})")


class _StructuredLog:
    """Collects one JSON record per decision for ``--log-json`` (every
    verdict -- unlike the ledger, which only ever records executed ALLOWs)
    and per-verdict counts / latencies for ``--metrics-textfile``."""

    def __init__(self, store_health: StoreHealth, constraints_sha256: str):
        self.store_health = store_health
        self.constraints_sha256 = constraints_sha256
        self.records: list[dict] = []
        self.verdict_counts: dict[str, int] = {}
        self.latencies_ms: list[float] = []

    def record(self, *, intent: InfrastructureIntent | None, decision) -> None:
        self.verdict_counts[decision.verdict] = self.verdict_counts.get(decision.verdict, 0) + 1
        self.latencies_ms.append(decision.latency_ms)
        self.records.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "intent": intent.to_dict() if intent is not None else None,
                "decision": asdict(decision),
                "store_health": {
                    "loaded": self.store_health.loaded,
                    "quarantined": len(self.store_health.quarantined),
                    "principals": self.store_health.principals,
                },
                "constraints_sha256": self.constraints_sha256,
            }
        )

    def write_log(self, path: str) -> None:
        with open(path, "a") as f:
            for rec in self.records:
                f.write(json.dumps(rec) + "\n")

    def write_metrics(self, path: str) -> None:
        lines = []
        for verdict in ("ALLOW", "ESCALATE", "BLOCK"):
            count = self.verdict_counts.get(verdict, 0)
            lines.append(f'aegis_decisions_total{{verdict="{verdict}"}} {count}')
        lines.append(f"aegis_store_loaded {self.store_health.loaded}")
        lines.append(f"aegis_store_quarantined {len(self.store_health.quarantined)}")
        if self.latencies_ms:
            ordered = sorted(self.latencies_ms)
            for quantile, label in ((0.5, "0.5"), (0.9, "0.9"), (0.99, "0.99")):
                idx = min(len(ordered) - 1, int(quantile * len(ordered)))
                lines.append(
                    f'aegis_decision_latency_ms{{quantile="{label}"}} {ordered[idx]:.4f}'
                )
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")


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


def _open_ledger(
    path: str, store: ConstraintStore, now: datetime | None
) -> DecisionLedger:
    """Picks ``SqliteLedger`` for ``.db``/``.sqlite``/``.sqlite3``, else
    ``JsonlLedger``; sizes its retention window to the largest
    ``rate_limit.per`` in the store; validates every ``rate_limit.key``
    and folds the resulting warnings (and a broken hash chain) into the
    store's warnings so ``store_health`` shows them."""
    rate_limited = [c for c in store.constraints.values() if c.rate_limit]
    max_window = timedelta(hours=24)
    for c in rate_limited:
        max_window = max(max_window, parse_window(c.rate_limit["per"]))
    cls = SqliteLedger if path.lower().endswith(_SQLITE_SUFFIXES) else JsonlLedger
    ledger = cls(path, max_window=max_window)
    for c in rate_limited:
        for warning in ledger.validate_rate_key(c.rate_limit.get("key") or []):
            store.warnings.append(f"{c.id}: {warning}")
    ledger.load(now)
    if not ledger.chain_ok:
        store.warnings.append("ledger: chain-broken")
    if ledger.skipped_lines:
        store.warnings.append(f"ledger: {ledger.skipped_lines} malformed line(s) skipped")
    return ledger


def _evaluate(intents: list[InfrastructureIntent], args: argparse.Namespace) -> int:
    _resolve_config_paths(args)
    now = _parse_now(args.now)
    pretty = bool(args.pretty)

    if not os.path.exists(args.constraints):
        raise FileNotFoundError(2, "No such file or directory", args.constraints)
    key_warnings: list[str] = []
    key, insecure = _resolve_key(args, key_warnings)
    load = {"key": key, "insecure": insecure}

    authority_map = _load_or_data_error(
        lambda: load_authority_map(args.authority, **load), args.authority, "authority"
    )
    sources = _default_sources(args)
    fetcher = FileSourceFetcher(sources, **load) if sources else None
    store = _load_or_data_error(
        lambda: ConstraintStore.load(
            args.constraints, authority_map=authority_map, source_fetcher=fetcher, **load
        ),
        args.constraints,
        "constraints",
    )
    store.warnings[:0] = key_warnings
    plan_store = None
    if args.plan_constraints:
        plan_store = _load_or_data_error(
            lambda: PlanConstraintStore.load(
                args.plan_constraints, authority_map=authority_map, **load
            ),
            args.plan_constraints,
            "plan constraints",
        )

    if plan_store is not None and plan_store.health.quarantine_ratio > args.max_quarantine_ratio:
        ph = plan_store.health
        raise DataError(
            f"{len(ph.quarantined)}/{ph.loaded + len(ph.quarantined)} plan constraints in "
            f"{args.plan_constraints} quarantined (ratio {ph.quarantine_ratio:.2f} > "
            f"--max-quarantine-ratio {args.max_quarantine_ratio}); refusing to decide"
        )

    ledger = _open_ledger(args.ledger, store, now) if args.ledger else None
    interceptor = AegisInterceptor(store, ledger=ledger, fail_closed=args.fail_closed)
    env_map = (
        _load_or_data_error(
            lambda: load_environment_map(args.environments, **load),
            args.environments,
            "environments",
        )
        if args.environments
        else EnvironmentMap()
    )
    for w in env_map.warnings:
        if w not in store.warnings:
            store.warnings.append(w)
    for intent in intents:
        if args.resolve_current_context:
            resolve_current_context(intent)
        env_map.annotate(intent)

    health = store.health
    _check_store_health(
        health,
        constraints_path=args.constraints,
        authority_path=args.authority,
        max_ratio=args.max_quarantine_ratio,
    )

    output = _Output(pretty=pretty, style=args.exit_style, store_health=health)
    structured_log = (
        _StructuredLog(health, store.constraints_sha256)
        if (args.log_json or args.metrics_textfile)
        else None
    )

    if plan_store is not None:
        plan_decision = evaluate_plan(interceptor, plan_store, intents, now=now)
        for intent, decision in zip(intents, plan_decision.per_intent):
            output.decision(intent, decision)
            if structured_log is not None:
                structured_log.record(intent=intent, decision=decision)
        output.plan(plan_decision, plan_health=plan_store.health)
        if structured_log is not None:
            structured_log.record(intent=None, decision=plan_decision)
            if args.log_json:
                structured_log.write_log(args.log_json)
            if args.metrics_textfile:
                structured_log.write_metrics(args.metrics_textfile)
        reason_parts = list(plan_decision.citations)
        if not reason_parts:
            reason_parts = [n for n in plan_decision.notes if _is_fail_closed_note(n)]
        output.finish(plan_decision.verdict, reason_parts)
        return _EXIT_CODES[args.exit_style][plan_decision.verdict]

    worst = "ALLOW"
    citations: list[str] = []
    fail_closed_notes: list[str] = []
    for intent in intents:
        decision = interceptor.intercept(intent, now=now)
        output.decision(intent, decision)
        if structured_log is not None:
            structured_log.record(intent=intent, decision=decision)
        if _VERDICT_RANK[decision.verdict] > _VERDICT_RANK[worst]:
            worst = decision.verdict
        citations.extend(c for c in decision.citations if c not in citations)
        fail_closed_notes.extend(n for n in decision.notes if _is_fail_closed_note(n))
    if structured_log is not None:
        if args.log_json:
            structured_log.write_log(args.log_json)
        if args.metrics_textfile:
            structured_log.write_metrics(args.metrics_textfile)
    output.finish(worst, citations or fail_closed_notes)
    return _EXIT_CODES[args.exit_style][worst]


def _is_fail_closed_note(note: str) -> bool:
    return note.startswith(("fail-closed", "env-unresolved", "unknown-target", "ledger:"))


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


def _run_signing(args: argparse.Namespace) -> int:
    source = args.key or (f"env:{SIGNING_KEY_ENV}" if os.environ.get(SIGNING_KEY_ENV) else None)
    if source is None:
        raise UsageError(f"{args.command}: pass --key SOURCE or set {SIGNING_KEY_ENV}")
    key = signing.load_key(source)
    for raw in args.paths:
        if not os.path.exists(raw):
            raise FileNotFoundError(2, "No such file or directory", raw)
    return signing.run(args.command, key, args.paths)


def _run_init(args: argparse.Namespace) -> int:
    written = config_module.init_config_dir(args.dir)
    if written:
        print(f"aegis: wrote {len(written)} file(s) to {args.dir}")
    else:
        print(f"aegis: {args.dir} already has every example file; nothing written")
    print("Next steps:")
    print(f"  1. Generate a real signing key:  aegis keygen --out {args.dir}/aegis-signing.key")
    print(
        f"  2. Sign your policy files:       aegis sign --key file:{args.dir}/aegis-signing.key "
        f"{args.dir}/*.yaml {args.dir}/sources"
    )
    print(
        f"  3. Replace the *.example.yaml files in {args.dir} with your own constraints.yaml / "
        "authority.yaml / ... (aegis prefers a real file over the .example one when both exist)"
    )
    return 0


def _run_keygen(args: argparse.Namespace) -> int:
    path = config_module.generate_signing_key(args.out)
    print(f"aegis: wrote signing key to {path}")
    return 0


def _run(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in ("sign", "verify"):
        return _run_signing(args)
    if args.command == "init":
        return _run_init(args)
    if args.command == "keygen":
        return _run_keygen(args)
    if args.command != "check":
        raise UsageError("unknown command")

    if args.target == "command":
        parts = _strip_leading_separator(args.command_string)
        command = " ".join(parts).strip()
        if not command:
            raise UsageError("check command: no command string given after --")
        return _evaluate(_intents_from_shell_string(command), args)

    if args.target in _ARGV_TARGET_PARSERS:
        target_argv = _strip_leading_separator(args.target_argv)
        if not target_argv:
            raise UsageError(f"check {args.target}: no {args.target} argv given after --")
        if getattr(args, "split_compound", False):
            # The argv *is* the shell text here ("kubectl get pods; kubectl
            # delete node/w1" as one or several tokens), so it is re-joined
            # verbatim, not re-quoted.
            return _evaluate(_intents_from_shell_string(" ".join(target_argv)), args)
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
    except ConfigNotFoundError as exc:
        print(f"aegis: error: {exc}", file=sys.stderr)
        return EX_NOINPUT
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        target = exc.filename or exc
        print(f"aegis: error: cannot read {target}: {exc.strerror or exc}", file=sys.stderr)
        return EX_NOINPUT
    except (DataError, ValueError, yaml.YAMLError, SignatureError) as exc:
        message = str(exc).replace("\n", " ")
        print(f"aegis: error: {message}", file=sys.stderr)
        return EX_DATAERR
    except Exception as exc:  # noqa: BLE001 - the contract is "never a traceback"
        print(f"aegis: error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return EX_SOFTWARE


if __name__ == "__main__":
    sys.exit(main())
