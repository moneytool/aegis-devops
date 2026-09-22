"""Shell-string front end (REVIEW-4 T1.2).

Every agent framework hands over a *string* (``"kubectl get pods; kubectl
delete node/w1"``), not an argv. This module turns that string into the
simple commands it would run, unwraps the launchers that hide the real
binary (``sudo``, ``env VAR=…``, ``timeout N``, ``nice``, ``nohup``,
``command``, ``time``, ``sh -c "…"``, ``k``/``tf``/``g`` aliases) and
hands each recognised binary to :func:`aegis_core.parser.from_argv`.

**Fail closed.** Anything whose argv cannot be known without running it is
a :class:`ShellRejected`: command substitution (``$(…)``, backticks),
parameter expansion (``$VAR`` — outside single quotes), process
substitution (``<(…)``/``>(…)``), subshells (``(…)``), here-docs
(``<<``/``<<<``), ``eval``/``exec``/``source``/``.``/``xargs``, a shell
``-c`` nested inside another shell ``-c``, and any other shell operator the
tokenizer does not model. Tilde and glob characters are passed through
literally (they only ever change *paths*, and the parsers treat those as
opaque). Redirections are stripped from the argv and recorded on the
:class:`SimpleCommand` (``2>&1``, ``>/tmp/x``); they never turn a
``kubectl get`` into something else.

**Pipelines.** ``kubectl get pods | grep x`` is one read intent: an
unknown binary inside a pipeline (``grep``) produces nothing. An unknown
binary standing on its own (``rm -rf /``, ``terraform apply``, ``bash
deploy.sh``) produces a synthetic intent ``provider="shell"``,
``resource="binary/<name>"``, ``action="exec"``, ``params={"argv": …}`` so
a ``--fail-closed`` policy can escalate on tools Aegis has no parser for.

**Environment.** ``KUBECONFIG=/prod kubectl …`` and ``env AWS_PROFILE=prod
aws …`` land in ``metadata["env_assignments"]``; the variables the parsers
already have metadata keys for (``KUBECONFIG`` -> ``kubeconfig``,
``AWS_PROFILE`` -> ``profile``, ``AWS_DEFAULT_REGION``/``AWS_REGION`` ->
``region``, ``CLOUDSDK_CORE_PROJECT`` -> ``project``, ``HELM_NAMESPACE``
-> ``namespace``) are copied into those keys when the argv itself did not
set them (an explicit ``--namespace`` beats the environment). The
launchers that were stripped are listed in ``metadata["wrappers"]``.
"""

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent
from aegis_core.parser import from_argv


class ShellRejected(ValueError):
    """The command string contains a construct whose argv cannot be
    determined without executing it (or one this tokenizer does not
    model). ``reason`` is a short, stable phrase for the CLI's message."""

    def __init__(self, reason: str, command: str | None = None):
        self.reason = reason
        self.command = command
        super().__init__(reason if command is None else f"{reason}: {command!r}")


@dataclass
class SimpleCommand:
    """One command of a compound line, after splitting on ``;`` / ``&&`` /
    ``||`` / ``|`` / ``&`` / newline. ``redirects`` holds the redirections
    stripped from ``argv`` (``"2>&1"``, ``">/tmp/x"``); ``in_pipeline`` is
    True when the command reads from or writes to another command through
    ``|``."""

    argv: list[str]
    redirects: list[str] = field(default_factory=list)
    in_pipeline: bool = False


# --- tokenising --------------------------------------------------------------

_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
_PIPE_SEPARATORS = frozenset({"|", "|&"})
_REDIRECT_OPS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<>"})
_PUNCTUATION = frozenset("();<>|&")
_FD_MARK = "\x01"
# Reserved words that only group or negate ("{ a; b; }", "! cmd") -- they
# never change what runs, so they are dropped from the simple command.
_GROUPING_WORDS = frozenset({"{", "}", "!"})


def _prescan(command: str) -> str:
    """Quote-aware pass over the raw string, before shlex sees it: rejects
    unquoted ``$`` and backticks (shlex would strip the quotes and lose the
    distinction), turns unquoted newlines into ``;``, and marks a file
    descriptor glued to a redirection (``2>&1`` -> ``\\x012>&1``) so it is
    not mistaken for an argument."""
    out: list[str] = []
    i, n = 0, len(command)
    in_single = in_double = False
    while i < n:
        c = command[i]
        if in_single:
            if c == "'":
                in_single = False
            out.append(c)
            i += 1
            continue
        if c == "\\":
            out.append(command[i : i + 2])
            i += 2
            continue
        if in_double:
            if c == '"':
                in_double = False
            elif c == "`":
                raise ShellRejected("command substitution (backtick) inside double quotes")
            elif c == "$":
                raise ShellRejected("shell expansion ($...) inside double quotes")
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_single = True
        elif c == '"':
            in_double = True
        elif c == "`":
            raise ShellRejected("command substitution (backtick)")
        elif c == "$":
            raise ShellRejected("shell expansion ($...)")
        elif c == "\n":
            out.append(" ; ")
            i += 1
            continue
        elif c.isdigit() and (i == 0 or command[i - 1].isspace()):
            j = i
            while j < n and command[j].isdigit():
                j += 1
            if j < n and command[j] in "<>":
                out.append(_FD_MARK + command[i:j])
                i = j
                continue
        out.append(c)
        i += 1
    if in_single or in_double:
        raise ShellRejected("unbalanced quotes")
    return "".join(out)


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(_prescan(command), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError as exc:  # pragma: no cover - _prescan catches unbalanced quotes first
        raise ShellRejected(f"could not tokenise: {exc}") from exc


# Shell builtins / launchers whose effect cannot be determined statically.
_REJECTED_BUILTINS = frozenset({"eval", "exec", "source", ".", "xargs"})


def _check_builtin(argv: list[str]) -> None:
    if argv and _basename(argv[0]) in _REJECTED_BUILTINS:
        raise ShellRejected(f"{_basename(argv[0])!r} cannot be checked statically")


def split_compound(command: str) -> list[SimpleCommand]:
    """Splits a shell command string into its simple commands.

    Tokenises with ``shlex`` (POSIX quoting, ``punctuation_chars``) after
    the quote-aware :func:`_prescan`; splits on ``;``, ``&&``, ``||``,
    ``|``, ``|&``, ``&`` and unquoted newlines; strips redirections into
    :attr:`SimpleCommand.redirects` and the grouping words ``{`` / ``}`` /
    ``!`` (a brace group's body is checked command by command). Quoted
    metacharacters (``--set 'a=b;c'``) never split. Raises :class:`ShellRejected` for the
    constructs listed in the module docstring, including a simple command
    whose binary is ``eval`` / ``exec`` / ``source`` / ``.`` / ``xargs``.
    """
    commands: list[SimpleCommand] = []
    argv: list[str] = []
    redirects: list[str] = []
    pending_fd: str | None = None
    pending_op: str | None = None
    in_pipeline = False

    def flush(pipeline: bool) -> None:
        nonlocal argv, redirects
        if pending_op is not None:
            raise ShellRejected(f"redirection {pending_op!r} without a target", command)
        while argv and argv[0] in _GROUPING_WORDS:
            argv = argv[1:]
        if argv:
            _check_builtin(argv)
            commands.append(SimpleCommand(argv, redirects, pipeline))
        argv, redirects = [], []

    for tok in _tokens(command):
        if pending_op is not None:
            redirects.append(f"{pending_fd or ''}{pending_op}{tok}")
            pending_op = pending_fd = None
            continue
        if tok.startswith(_FD_MARK):
            pending_fd = tok[1:]
            continue
        if tok in _REDIRECT_OPS:
            pending_op = tok
            continue
        if pending_fd is not None:  # a digit run glued to something odd, e.g. "2>(x)"
            raise ShellRejected("unsupported redirection", command)
        if tok in _SEPARATORS:
            is_pipe = tok in _PIPE_SEPARATORS
            flush(in_pipeline or is_pipe)
            in_pipeline = is_pipe
            continue
        if set(tok) <= _PUNCTUATION:
            raise ShellRejected(f"unsupported shell operator {tok!r}", command)
        argv.append(tok)
    flush(in_pipeline)
    return commands


# --- unwrapping launchers ----------------------------------------------------------

_ALIASES = {"k": "kubectl", "tf": "terraform", "tofu": "tofu", "g": "git"}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_SUDO_BOOL_SHORT = frozenset("EHnkKbAlvS")
_SUDO_VALUE_SHORT = frozenset("ugpCDrtTUh")
_SUDO_BOOL_LONG = frozenset(
    {
        "preserve-env", "set-home", "non-interactive", "reset-timestamp", "remove-timestamp",
        "background", "askpass", "list", "validate", "stdin",
    }
)
_SUDO_VALUE_LONG = frozenset(
    {"user", "group", "prompt", "chdir", "host", "role", "type", "command-timeout", "other-user"}
)
_SUDO_SHELL_OPTIONS = frozenset({"-i", "-s", "--login", "--shell", "-e", "--edit"})


def _basename(token: str) -> str:
    # Path(".").name is "" — keep the dot so the `.` builtin is recognised.
    return Path(token).name or token


def _strip_sudo(rest: list[str]) -> list[str]:
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            return rest[i + 1 :]
        if tok in _SUDO_SHELL_OPTIONS:
            raise ShellRejected(f"sudo {tok} opens a shell/editor")
        if tok.startswith("--"):
            key, _, value = tok[2:].partition("=")
            if key in _SUDO_BOOL_LONG or (key in _SUDO_VALUE_LONG and value):
                i += 1
                continue
            if key in _SUDO_VALUE_LONG:
                i += 2
                continue
            raise ShellRejected(f"unrecognised sudo option {tok!r}")
        if tok.startswith("-") and len(tok) > 1:
            body = tok[1:]
            if body[0] in _SUDO_VALUE_SHORT:
                i += 1 if len(body) > 1 else 2  # -uadmin or -u admin
                continue
            if set(body) <= _SUDO_BOOL_SHORT:
                i += 1
                continue
            raise ShellRejected(f"unrecognised sudo option {tok!r}")
        break
    return rest[i:]


def _strip_env(rest: list[str]) -> tuple[list[str], dict[str, str]]:
    assignments: dict[str, str] = {}
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if tok in ("-S", "--split-string") or tok.startswith("--split-string="):
            raise ShellRejected("env -S re-splits its argument")
        if tok in ("-i", "--ignore-environment", "-0", "--null", "-v", "--debug"):
            i += 1
            continue
        if tok in ("-u", "--unset", "-C", "--chdir"):
            i += 2
            continue
        if tok.startswith(("--unset=", "--chdir=")):
            i += 1
            continue
        if tok.startswith("-u") and len(tok) > 2:
            i += 1
            continue
        if _ASSIGNMENT_RE.match(tok):
            key, _, value = tok.partition("=")
            assignments[key] = value
            i += 1
            continue
        if tok.startswith("-"):
            raise ShellRejected(f"unrecognised env option {tok!r}")
        break
    return rest[i:], assignments


def _strip_timeout(rest: list[str]) -> list[str]:
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("-s", "--signal", "-k", "--kill-after"):
            i += 2
            continue
        if tok.startswith(("--signal=", "--kill-after=")) or (
            tok.startswith(("-s", "-k")) and len(tok) > 2
        ):
            i += 1
            continue
        if tok in ("--preserve-status", "--foreground", "-v", "--verbose"):
            i += 1
            continue
        if tok.startswith("-"):
            raise ShellRejected(f"unrecognised timeout option {tok!r}")
        break
    # the duration itself
    return rest[i + 1 :]


def _strip_nice(rest: list[str]) -> list[str]:
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("-n", "--adjustment"):
            i += 2
            continue
        if tok.startswith(("--adjustment=", "-n")) and len(tok) > 2:
            i += 1
            continue
        if re.fullmatch(r"-\d+", tok):
            i += 1
            continue
        if tok.startswith("-"):
            raise ShellRejected(f"unrecognised nice option {tok!r}")
        break
    return rest[i:]


def _shell_c_string(rest: list[str]) -> str | None:
    """For ``sh [opts] -c STRING [args…]`` returns STRING; ``None`` when the
    shell is not invoked with ``-c`` (``bash script.sh`` — an ordinary,
    unknown binary as far as the gate is concerned)."""
    i = 0
    saw_c = False
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if tok in ("-o", "+o"):
            i += 2
            continue
        if tok in ("--login", "--norc", "--noprofile", "--posix", "--restricted"):
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1 and not tok.startswith("--"):
            if "c" in tok[1:]:
                saw_c = True
            i += 1
            continue
        break
    if not saw_c or i >= len(rest):
        return None
    return rest[i]


def _unwrap_inner(
    argv: list[str], depth: int
) -> tuple[list[str], dict[str, str], list[str], str | None]:
    """Strips launchers from ``argv``. Returns ``(argv, env_assignments,
    wrappers, shell_string)``; when a ``sh -c STRING`` is reached at depth
    0 the string is returned un-split for the caller to recurse into (a
    ``sh -c`` at depth >= 1 is rejected)."""
    env: dict[str, str] = {}
    wrappers: list[str] = []
    while True:
        if not argv:
            raise ShellRejected("nothing left to run after unwrapping launchers")
        head = _basename(argv[0])
        if _ASSIGNMENT_RE.match(argv[0]):
            key, _, value = argv[0].partition("=")
            env[key] = value
            argv = argv[1:]
            continue
        if head in _REJECTED_BUILTINS:
            raise ShellRejected(f"{head!r} cannot be checked statically")
        if head == "--":
            argv = argv[1:]
            continue
        if head == "sudo":
            rest = _strip_sudo(argv[1:])
            if not rest:
                break
            wrappers.append("sudo")
            argv = rest
            continue
        if head == "env":
            rest, more = _strip_env(argv[1:])
            if not rest:
                break
            env.update(more)
            wrappers.append("env")
            argv = rest
            continue
        if head == "timeout":
            wrappers.append("timeout")
            argv = _strip_timeout(argv[1:])
            continue
        if head == "nice":
            rest = _strip_nice(argv[1:])
            if not rest:
                break
            wrappers.append("nice")
            argv = rest
            continue
        if head in ("nohup", "time"):
            rest = argv[1:]
            if head == "time" and rest and rest[0] == "-p":
                rest = rest[1:]
            if not rest:
                break
            wrappers.append(head)
            argv = rest
            continue
        if head == "command":
            rest = argv[1:]
            if rest and rest[0] == "-p":
                rest = rest[1:]
            if not rest or rest[0].startswith("-"):
                break  # `command -v x` only prints a path
            wrappers.append("command")
            argv = rest
            continue
        if head in _SHELLS:
            string = _shell_c_string(argv[1:])
            if string is None:
                break
            if depth >= 1:
                raise ShellRejected(f"nested {head} -c")
            wrappers.append(f"{head} -c")
            return argv, env, wrappers, string
        break
    head = _basename(argv[0])
    if head in _ALIASES:
        argv = [_ALIASES[head], *argv[1:]]
    return argv, env, wrappers, None


def unwrap(argv: list[str]) -> tuple[list[str], dict[str, str]]:
    """Strips leading ``VAR=value`` assignments and the launchers ``sudo``
    (``-u user``, ``-E``, …), ``env`` (recording its assignments),
    ``timeout [opts] N``, ``nice [-n N]``, ``nohup``, ``command``, ``time``
    and ``sh``/``bash`` ``-c "…"`` (recursing into the string once), then
    applies the alias table (``k`` -> ``kubectl``, ``tf`` -> ``terraform``,
    ``g`` -> ``git``). Returns ``(argv, env_assignments)``.

    Raises :class:`ShellRejected` for ``eval``/``exec``/``source``/``.``/
    ``xargs``, ``sudo -i``/``-s``, a nested ``sh -c``, an unrecognised
    launcher option, or a ``sh -c`` string that is itself compound (use
    :func:`intents_from_command` for those)."""
    argv, env, _wrappers, string = _unwrap_inner(list(argv), 0)
    if string is None:
        return argv, env
    inner = split_compound(string)
    if len(inner) != 1:
        raise ShellRejected("compound command inside sh -c", string)
    argv, more, _wrappers, _ = _unwrap_inner(inner[0].argv, 1)
    return argv, {**env, **more}


# --- intents -----------------------------------------------------------------------

# Binaries from_argv can turn into intents. terraform/tofu are deliberately
# absent: their argv carries no plan, so they surface as an unknown binary
# (a synthetic shell/exec intent) instead of a ValueError.
_KNOWN_BINARIES = frozenset(
    {
        "kubectl", "aws", "az", "gcloud", "gsutil", "helm", "argocd", "flux", "git", "gh",
        "psql", "mysql", "sqlite3", "mongosh", "pulumi", "alembic", "flyway", "rails", "prisma",
    }
)

_ENV_METADATA_KEYS = {
    "KUBECONFIG": "kubeconfig",
    "AWS_PROFILE": "profile",
    "AWS_DEFAULT_REGION": "region",
    "AWS_REGION": "region",
    "CLOUDSDK_CORE_PROJECT": "project",
    "HELM_NAMESPACE": "namespace",
}


def _expand(
    command: str, depth: int
) -> Iterator[tuple[SimpleCommand, dict[str, str], list[str]]]:
    for simple in split_compound(command):
        argv, env, wrappers, string = _unwrap_inner(simple.argv, depth)
        if string is None:
            yield SimpleCommand(argv, simple.redirects, simple.in_pipeline), env, wrappers
            continue
        for inner, inner_env, inner_wrappers in _expand(string, depth + 1):
            yield (
                SimpleCommand(
                    inner.argv,
                    [*simple.redirects, *inner.redirects],
                    simple.in_pipeline or inner.in_pipeline,
                ),
                {**env, **inner_env},
                [*wrappers, *inner_wrappers],
            )


def _annotate(
    intent: InfrastructureIntent,
    env: dict[str, str],
    wrappers: list[str],
    simple: SimpleCommand,
) -> None:
    metadata: dict[str, Any] = intent.metadata
    if env:
        metadata["env_assignments"] = dict(env)
        for var, value in env.items():
            key = _ENV_METADATA_KEYS.get(var)
            if key is not None and key not in metadata:
                metadata[key] = value
    if wrappers:
        metadata["wrappers"] = list(wrappers)
    if simple.redirects:
        metadata["redirects"] = list(simple.redirects)


def intents_from_command(command: str) -> list[InfrastructureIntent]:
    """Every InfrastructureIntent a shell command string would give rise
    to: :func:`split_compound` -> :func:`unwrap` -> ``from_argv`` for each
    simple command whose binary Aegis knows. Inside a pipeline, unknown
    binaries (``| grep x``) produce nothing; on their own they produce the
    synthetic ``shell`` / ``binary/<name>`` / ``exec`` intent described in
    the module docstring. Environment assignments and stripped launchers
    are recorded in each intent's metadata.

    Raises :class:`ShellRejected` (a ``ValueError``) for the shell
    constructs that cannot be checked statically, and ``ValueError`` from
    the underlying parser for a known binary with an argv it cannot make
    sense of — both are the caller's cue to fail closed.
    """
    intents: list[InfrastructureIntent] = []
    for simple, env, wrappers in _expand(command, 0):
        if not simple.argv:
            continue
        name = _basename(simple.argv[0])
        if name in _KNOWN_BINARIES:
            produced = from_argv(simple.argv)
        elif simple.in_pipeline:
            continue
        else:
            produced = [
                InfrastructureIntent(
                    resource=f"binary/{name}",
                    action="exec",
                    provider="shell",
                    params={"argv": list(simple.argv)},
                )
            ]
        for intent in produced:
            _annotate(intent, env, wrappers, simple)
        intents.extend(produced)
    return intents
