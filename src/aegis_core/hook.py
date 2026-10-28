"""Agent hook adapter: ``aegis hook <agent>`` and ``aegis install <agent>``.

Coding agents (Claude Code, Codex CLI, GitHub Copilot CLI, Cursor, VS Code
agent mode) can run a command before each shell command the model asks
for, and block it. Each sends a slightly different JSON payload on stdin
and expects a slightly different reply. This module reads any of them,
decides with the same engine as ``aegis check command``, and answers in
the agent's own format.

**Opt-in, per project.** An agent hook runs in every project the agent is
opened in, including ones that have never heard of Aegis. So the hook
only does anything where a policy exists: ``$AEGIS_CONFIG_DIR``, a
``.aegis/`` directory in the project (or any parent of it), or
``~/.config/aegis``. Anywhere else every command is allowed and nothing
is printed. (The ``$PWD/data`` and ``/etc/aegis`` fallbacks that ``aegis
check`` uses are deliberately not opt-in signals here: a repository that
happens to ship a ``data/constraints.yaml`` has not asked to be gated.)

**Only what the policy says.** Inside an opted-in project a command is
blocked only when the policy blocks it (or escalates it). Everything the
policy does not cover runs, exactly as with ``aegis check command``.

**Failures.** When the policy itself cannot be used (missing file, bad
signature, degraded store) or the command cannot be analysed statically
(``$(...)``, ``$VAR``, ``eval`` ...), the hook blocks only commands that
involve infrastructure tooling -- one of the binaries Aegis has a parser
for, or terraform/tofu -- and allows the rest: ``ls`` has nothing to do
with a broken policy. The block message says what is wrong. A compound
command is judged part by part: ``terraform plan 2>&1; echo "exit=$?"``
checks ``terraform plan`` and lets ``echo`` through. A part with an unknown
argument passes only when its program treats arguments as data
(``ARGS_ONLY_PROGRAMS`` in shell.py) or it only assigns a harmless
variable; any other unknown part (an expansion that runs a command, an
unknown program, ``find -exec``, ``export KUBECONFIG=$X``, …) is refused, by
name, when the command names an infrastructure tool anywhere.

**Code the command does not show.** A shell or interpreter reading code from
a pipe, a here-string or a here-doc asks, unless a literal ``echo``/``printf``
writes it (that text is then checked). A local shell script (``bash x.sh``,
``sh < x.sh``, ``./x``, ``source x.sh``) is read, up to 64 KiB and without
following what it sources, and its lines that name an infrastructure tool
are checked as commands: a blocked line (or a block the lines reach
together) blocks; a line that cannot be checked, or a script that is
missing or unreadable, asks.

**Replies.** A block is exit code 2 with the reason on stderr, which
Claude Code, Codex, Copilot and VS Code all treat as "deny". Cursor is the
exception on both sides: it shows an exit-2 hook's stdout verbatim, so a
block there is its JSON ``{"permission": "deny"}`` on exit 0, and with
``failClosed`` it blocks a hook that printed nothing, so "allow" is said
explicitly. An ESCALATE verdict asks
the user where the agent supports that ("ask"); Codex does not (an
unknown decision makes it log an error and run the command), so there it
is a deny.
"""

from __future__ import annotations

import contextlib
import fnmatch
import importlib.resources
import io
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from aegis_core import config as config_module
from aegis_core.shell import (
    _KNOWN_BINARIES,
    _SHELLS,
    ARGS_ONLY_PROGRAMS,
    GLOB_REASON,
    ShellRejected,
    _basename,
    _interpreter,
    find_heredoc,
    intents_from_command,
    loose_argv,
    loose_code_reader,
    plain_binary,
    runs_expansion,
    script_runs_loosely,
    split_segments,
    stdin_feeders,
    strip_comment,
)

AGENTS = ("claude", "codex", "copilot", "cursor", "gemini", "opencode", "vscode")

# Agents whose usage the budget cap can measure (design v1.0 §4). Cursor and
# VS Code expose no token data.
BUDGET_AGENTS = frozenset({"claude", "codex", "copilot", "gemini", "opencode"})
BUDGET_FILE = "budget.yaml"
# Hook events that come before a new prompt rather than a tool call.
PROMPT_EVENTS = frozenset({"UserPromptSubmit", "BeforeAgent"})
# Agents that show a hook's JSON "systemMessage" to the user (a warning that
# does not block). OpenCode's plugin shows "warning" as a toast; Copilot CLI
# has no such channel, so its warning goes to stderr.
_SYSTEM_MESSAGE_AGENTS = frozenset({"claude", "codex", "gemini"})

# Binaries whose commands are gated even when the policy is unusable or the
# command cannot be parsed. terraform/tofu have no argv parser (their plans
# are checked as JSON) but are infrastructure tools all the same; k/tf are
# the aliases shell.py already unwraps.
INFRA_BINARIES = frozenset(_KNOWN_BINARIES | {"terraform", "tofu", "k", "tf"})
_INFRA_WORD_RE = re.compile(
    r"(?<![\w.-])(?:" + "|".join(sorted(map(re.escape, INFRA_BINARIES), key=len, reverse=True))
    + r")(?![\w.-])"
)

# A shell, eval or source fed code made at run time: `bash -c "$(cat x)"`,
# `eval "$(…)"`, `source <(…)`, `sh <(curl …)`. Asked about, not denied:
# `eval "$(pyenv init -)"` is an everyday line.
_GENERATED_CODE_RE = re.compile(
    r"(?:^|[;&|(]\s*|\s)((?:sudo\s+)?(?:(?:ba|z|da|k|a)?sh|eval|source|\.))"
    r"(?:\s+-[A-Za-z]+)*\s+[\"']?(?:\$\(|`|<\()"
)


# Tool names agents use for "run a shell command". Anything else (file
# edits, MCP tools ...) is not ours to judge and is allowed.
_SHELL_TOOL_NAMES = frozenset(
    {"bash", "shell", "run_in_terminal", "runinterminal", "run_shell_command", "terminal"}
)

EXIT_ALLOW = 0
EXIT_BLOCK = 2


def _allow(agent: str) -> tuple[int, str, str]:
    """Silence means "allow" everywhere except Cursor, which with
    ``failClosed`` treats a hook that printed nothing as a failure and
    blocks -- so there "allow" has to be said."""
    if agent == "cursor":
        return EXIT_ALLOW, json.dumps({"permission": "allow"}), ""
    return EXIT_ALLOW, "", ""


class HookInputError(ValueError):
    """The payload is not something this adapter understands."""


@dataclass
class HookRequest:
    command: str | None  # None: not a shell tool call
    cwd: str | None


@dataclass
class HookVerdict:
    decision: str  # "allow" | "deny" | "ask"
    reason: str = ""
    # a deny because (part of) the command could not be checked, not a policy BLOCK
    unchecked: bool = False


# --- reading the payload ---------------------------------------------------------


def _as_dict(value) -> dict:
    """``toolArgs`` is parsed JSON when Copilot could parse it, else a string."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def parse_request(agent: str, payload: dict) -> HookRequest:
    """Pulls the shell command (if this is a shell tool call) and the
    working directory out of an agent's hook payload.

    - Claude Code, Codex, VS Code (Claude-compatible form):
      ``{"tool_name": "Bash", "tool_input": {"command": ...}, "cwd": ...}``
    - Copilot CLI: ``{"toolName": "bash", "toolArgs": {"command": ...}, "cwd": ...}``
      (VS Code reading the same ``.github/hooks`` file sends the
      ``tool_name``/``tool_input`` form instead; both are accepted.)
    - Cursor ``beforeShellExecution``: ``{"command": ..., "cwd": ...}``
    """
    if not isinstance(payload, dict):
        raise HookInputError("hook payload is not a JSON object")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    if agent == "cursor" and "tool_name" not in payload and "toolName" not in payload:
        command = payload.get("command")
        if not isinstance(command, str):
            raise HookInputError("cursor payload has no 'command' string")
        return HookRequest(command, cwd)
    tool = payload.get("tool_name", payload.get("toolName"))
    args = _as_dict(payload.get("tool_input", payload.get("toolArgs")))
    if not isinstance(tool, str):
        raise HookInputError("hook payload has no tool name")
    if tool.lower() not in _SHELL_TOOL_NAMES:
        return HookRequest(None, cwd)
    command = args.get("command")
    if not isinstance(command, str):
        raise HookInputError(f"{tool} tool call has no 'command' string")
    return HookRequest(command, cwd)


# --- opt-in ----------------------------------------------------------------------


def _project_dir(request: HookRequest) -> Path:
    for candidate in (
        request.cwd,
        os.environ.get("CLAUDE_PROJECT_DIR"),
        os.environ.get("COPILOT_PROJECT_DIR"),
        os.environ.get("CURSOR_PROJECT_DIR"),
        os.environ.get("GEMINI_PROJECT_DIR"),
    ):
        if candidate:
            return Path(candidate)
    return Path.cwd()


def find_opt_in_config(start: Path) -> Path | None:
    """The policy directory that opts this project in, or None.
    ``$AEGIS_CONFIG_DIR`` > nearest ``.aegis/`` at or above ``start`` >
    ``~/.config/aegis``."""
    env = os.environ.get(config_module.CONFIG_ENV_VAR)
    if env:
        return Path(env)
    try:
        start = start.resolve()
    except OSError:
        pass
    for directory in (start, *start.parents):
        candidate = directory / ".aegis"
        if candidate.is_dir():
            return candidate
    user = Path.home() / ".config" / "aegis"
    return user if user.is_dir() else None


# --- deciding --------------------------------------------------------------------


def _infra_text(text: str) -> str:
    """``text`` with what the shell removes before it runs a word: line
    continuations, quotes and backslashes (``kube''ctl``, ``"kube"ctl``,
    ``kube\\ctl`` all run ``kubectl``)."""
    return text.replace("\\\n", "").replace("'", "").replace('"', "").replace("\\", "")


def mentions_infra(command: str) -> bool:
    """True when an infrastructure binary appears as a word anywhere in the
    command text, also once quotes, backslashes and line continuations are
    removed (used for code the parser cannot read)."""
    return bool(_INFRA_WORD_RE.search(command) or _INFRA_WORD_RE.search(_infra_text(command)))


def _is_gated(command: str) -> bool:
    """Would a working policy have anything to say about this command?
    True for any intent from a known parser, or terraform/tofu."""
    try:
        intents = intents_from_command(command)
    except ValueError:
        return mentions_infra(command)
    for intent in intents:
        if intent.provider != "shell":
            return True
        binary = intent.resource.removeprefix("binary/")
        if binary in INFRA_BINARIES:
            return True
    return False


# A local shell script is read up to this size; a bigger one asks.
SCRIPT_SCAN_LIMIT = 64 * 1024
# At most this many of its lines may name an infrastructure tool; more asks.
SCRIPT_SCAN_MAX_LINES = 64
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
_CD_RE = re.compile(r"(?:^|[;&|(\n]\s*|\s)(?:cd|pushd|popd)(?:\s|$|;)")


def decide(command: str, config_dir: Path, extra_args: list[str] | None = None, *,
           cwd: str | Path | None = None) -> HookVerdict:
    """Runs ``aegis check command`` against ``config_dir`` and maps the
    result to allow / deny / ask. Tool errors deny only gated commands.
    ``cwd`` is where the command will run (relative script paths are read
    from there; default: the current directory)."""
    where = Path(cwd) if cwd else Path.cwd()
    return _decide(command, config_dir, extra_args, where, scan=True)


def _with_asks(verdict: HookVerdict, asks: list[str]) -> HookVerdict:
    """An allow becomes the first pending ask; a deny or ask stands."""
    if verdict.decision == "allow" and asks:
        return HookVerdict("ask", asks[0])
    return verdict


# Past this size a command is not parsed (the checks are not all linear in it).
_MAX_COMMAND_CHARS = 64 * 1024
# At most this many pieces of piped shell code get a policy run of their own.
_MAX_PIPED_CHECKS = 32


def _decide(command: str, config_dir: Path, extra_args: list[str] | None, cwd: Path | None,
            *, scan: bool) -> HookVerdict:
    if len(command) > _MAX_COMMAND_CHARS:
        reason = (f"aegis: this command is over {_MAX_COMMAND_CHARS // 1024} KiB, too long to "
                  "check; split it up or put it in a script")
        if mentions_infra(command):
            return HookVerdict("deny", reason, unchecked=True)
        return HookVerdict("ask", reason)
    pre = _precheck(command, config_dir, extra_args, cwd, scan=scan)
    if isinstance(pre, HookVerdict):
        return pre
    checkable, asks = pre
    if not checkable.strip(" \t\n;&|"):
        return _with_asks(HookVerdict("allow"), asks)
    return _with_asks(_policy(checkable, config_dir, extra_args), asks)


def _precheck(command: str, config_dir: Path, extra_args: list[str] | None,
              cwd: Path | None, *, scan: bool,
              rebuilt: bool = False) -> HookVerdict | tuple[str, list[str]]:
    """Everything before the policy: a verdict when the command is decided
    without it (an allow here means the policy has nothing to say), else the
    command to check against the policy plus asks that stand if it allows."""
    escalate_scripts = "--escalate-scripts" in (extra_args or [])
    try:
        intents = intents_from_command(command)
    except ShellRejected as exc:
        if exc.reason == GLOB_REASON:
            return _glob_denied(command, exc.command or "")
        if rebuilt:  # cannot happen: every part of a rebuilt command parsed on its own
            return _rejected(command, exc.reason, config_dir, extra_args, cwd,
                             scan=scan, escalate_scripts=escalate_scripts)
        part = _checkable_part(command, exc, config_dir, extra_args, cwd,
                               scan=scan, escalate_scripts=escalate_scripts)
        if isinstance(part, HookVerdict):
            return part
        checkable, asks = part
        # the rebuilt command keeps every literal `cd DIR`, so it starts from cwd too
        inner = _precheck(checkable, config_dir, extra_args, cwd, scan=scan, rebuilt=True)
        if isinstance(inner, HookVerdict):
            return _with_asks(inner, asks)
        return inner[0], [*asks, *inner[1]]
    except ValueError as exc:  # a known binary with an argv its parser rejects
        return HookVerdict("deny", f"aegis: cannot parse this command: {exc}", unchecked=True)
    asks: list[str] = []
    for intent in intents:
        runs = intent.params.get("runs_code") if intent.provider == "shell" else None
        if runs is not None and runs["kind"] == "inline" and mentions_infra(runs.get("code", "")):
            return HookVerdict(
                "deny",
                f"aegis: cannot check code passed to {runs['interpreter']} on the command "
                "line, and it names an infrastructure tool; run the infrastructure command on "
                "its own",
                unchecked=True,
            )
    for n_piped, (reader, feeder) in enumerate(stdin_feeders(command)):
        if n_piped == _MAX_PIPED_CHECKS:
            asks.append(f"aegis: more than {_MAX_PIPED_CHECKS} pieces of code are piped into a "
                        "shell or interpreter, too many to check; run them as a script")
            break
        verdict = _piped_code(command, reader, feeder, config_dir, extra_args, cwd,
                              rebuilt=rebuilt)
        if verdict is not None:
            if verdict.decision == "deny":
                return verdict
            asks.append(verdict.reason)
    for intent in intents:
        verdict = _hidden_infra_program(intent, cwd)
        if verdict is not None:
            asks.append(verdict.reason)
    for intent in intents:
        verdict = _hidden_command(intent)
        if verdict is not None:
            asks.append(verdict.reason)
    if scan:
        for runs, here in _scripts_with_directory(command, cwd):
            verdict = _scan_script(runs, config_dir, extra_args, here, command=command)
            if verdict is not None:
                if verdict.decision == "deny":
                    return verdict
                asks.append(verdict.reason)
    return command, asks


# Programs that take an infrastructure tool's *name* as an argument without
# running it: documentation and name lookups, package managers and downloaders,
# search, editors, process tools, linters, build tools, and file tools.
#
# This list answers a different question from shell.ARGS_ONLY_PROGRAMS, so do
# not merge the two. ARGS_ONLY_PROGRAMS is "an unknown ($X) argument cannot
# make this program run code or change what a later infra tool sees", which is
# why sort (--compress-program), tee/cp/mv/ln (can overwrite ~/.kube/config)
# and read (assigns KUBECONFIG) are left off it. Here the arguments are
# literal and the only question is "does `prog kubectl` run kubectl?" -- for
# sort, tee, cp, mv, ln and read it does not, so they belong here.
_NAMES_WITHOUT_RUNNING = frozenset({
    "man", "info", "which", "whereis", "whatis", "type", "hash", "command", "tldr", "help",
    "apropos", "brew", "apt", "apt-get", "yum", "dnf", "apk", "pacman", "port", "snap",
    "choco", "winget", "scoop", "asdf", "mise", "nix-shell", "nix-env", "rg", "ag", "ack",
    "fd", "find", "locate", "tree", "less", "more", "vim", "vi", "nano", "code", "open",
    "bat", "touch", "mkdir", "cd", "pushd", "popd", "ls", "rm", "cp", "mv", "ln", "tee",
    "sort", "read", "install", "uninstall", "make", "pgrep", "pkill", "killall", "kill",
    "lsof", "strings", "tflint", "checkov", "tfsec", "trivy", "curl", "wget", "aria2c",
    "scp", "rsync", "git", "apt-cache", "dpkg", "rpm", "pip", "pip3", "pipx", "uv", "cargo",
    "go", "gem",
})


def _glob_denied(command: str, word: str) -> HookVerdict:
    """A program word the shell may expand (``kube{,}ctl``, ``k*``,
    ``./scripts/*.sh``). Denied when it could expand to an infrastructure
    tool's name, when it is a bare word (expanded against whatever files the
    directory holds), or when the command names a tool; otherwise (a path
    pattern such as ``./scripts/*.sh``) asked."""
    reason = (f"aegis: cannot check this command statically ({GLOB_REASON}): the shell may "
              "expand the program word into another program's name; spell the program out")
    pattern = word.rsplit("/", 1)[-1]
    alternatives = _brace_alternatives(pattern)
    # too many alternatives to try (`{a,b}{a,b}…`): it may become any name
    could_be_infra = alternatives is None or any(
        fnmatch.fnmatchcase(name, alternative)
        for alternative in alternatives for name in INFRA_BINARIES)
    if could_be_infra or "/" not in word or mentions_infra(command):
        return HookVerdict("deny", reason, unchecked=True)
    return HookVerdict("ask", reason)


_MAX_BRACE_ALTERNATIVES = 256


def _brace_alternatives(pattern: str) -> list[str] | None:
    """``a{b,c}d`` -> ``["abd", "acd"]`` (one level per brace pair, enough to
    tell whether a program word could become a tool's name); ``None`` when
    there would be more than :data:`_MAX_BRACE_ALTERNATIVES` (the expansion
    grows exponentially with the number of brace pairs)."""
    done: list[str] = []
    todo = [pattern]
    while todo:
        current = todo.pop()
        match = re.search(r"\{([^{}]*)\}", current)
        if match is None:
            done.append(current)
        else:
            head, tail = current[: match.start()], current[match.end():]
            todo.extend(head + part + tail for part in match.group(1).split(","))
        if len(done) + len(todo) > _MAX_BRACE_ALTERNATIVES:
            return None
    return done


def _hidden_infra_program(intent, cwd: Path | None) -> HookVerdict | None:
    """An unknown program with an infrastructure tool's name among its
    arguments (``setpriv kubectl …``, ``chrt 0 kubectl …``, ``tmux new -d
    'kubectl …'``: a launcher the parser does not unwrap) may run that tool
    where its argv cannot be checked: asked. Not for programs that only take
    a tool's name (:data:`_NAMES_WITHOUT_RUNNING`, ``command -v``) -- except
    for the options with which they run a command (``rsync -e``, ``scp -o
    ProxyCommand=``, ``nix-shell --run``) -- nor for URLs or a ``-d dir``
    option value naming an existing directory. A path to a tool
    (``/usr/local/bin/kubectl``, ``./kubectl``) counts as the tool."""
    if intent.provider != "shell":
        return None
    argv = intent.params.get("argv") or []
    if not argv:
        return None
    name = _basename(argv[0])
    if name == "alias":  # alias kk=kubectl: a later `kk delete …` runs kubectl unchecked
        for tok in argv[1:]:
            alias, eq, value = tok.partition("=")
            if eq and mentions_infra(value):
                return HookVerdict(
                    "ask", f"aegis: the alias {alias} runs an infrastructure tool under another "
                    "name, which cannot be checked; run the tool by its own name")
        return None
    if name in ARGS_ONLY_PROGRAMS or name in INFRA_BINARIES:
        return None
    if name in _NAMES_WITHOUT_RUNNING and not _runs_a_program(name, argv[1:]):
        # only the options that hand it a command to run are read
        for option, value in _exec_option_values(name, argv[1:]):
            if mentions_infra(value):
                return HookVerdict(
                    "ask", f"aegis: {name} {option} runs a command that names an "
                    "infrastructure tool, which cannot be checked through it; run it on its own")
        return None
    after_option = False
    for tok in argv[1:]:
        if tok.startswith("-"):
            # a short option or a long one without "=" may take the next word
            after_option = "=" not in tok
            continue
        value, after_option = after_option, False
        words = tok.split()
        if not words or "://" in tok:
            continue
        # /usr/local/bin/kubectl, ./kubectl, nix run nixpkgs#kubectl: still kubectl
        tool = _basename(words[0]).rsplit("#", 1)[-1]
        if tool not in INFRA_BINARIES:
            if name in _CODE_ARG_PROGRAMS and len(words) > 1 and mentions_infra(tok):
                # code or a command line in one argument (awk 'BEGIN{system("kubectl …")}',
                # sed '1e kubectl …', tmux new 'cd x && kubectl …')
                return HookVerdict(
                    "ask", f"aegis: {name} is given text that names an infrastructure tool, "
                    f"which it may run where its arguments cannot be checked; run the tool "
                    "on its own")
            continue
        if len(words) == 1 and value and "/" not in tok and cwd is not None and (
                cwd / tok).is_dir():
            continue  # `-d terraform` with a terraform/ directory: an option value
        return HookVerdict(
            "ask", f"aegis: {name} may run {tool}, whose arguments cannot be checked "
            f"through {name}; run {tool} on its own")
    return None


# Programs that run an argument as code or as a command line, so a tool named
# inside that argument may run (`awk 'BEGIN{system("kubectl …")}'`, `sed '1e …'`).
_CODE_ARG_PROGRAMS = frozenset({
    "awk", "gawk", "mawk", "nawk", "busybox", "sed", "gsed", "tmux", "screen", "expect",
    "parallel", "watchexec", "entr", "nodemon", "dtach", "abduco", "xterm", "flock",
    "unshare", "chroot", "su", "runuser", "nsenter", "firejail", "bwrap", "systemd-run",
})

# Options of exempt programs whose value is a command they run.
_EXEC_OPTIONS = {
    "rsync": ("-e", "--rsh"),
    "scp": ("-o", "-S"),
    "nix-shell": ("--run", "--command"),
    "fd": ("-x", "-X", "--exec", "--exec-batch"),
    "hash": ("-p",),  # hash -p /usr/bin/kubectl kk: kk now runs kubectl
    "rg": ("--pre",),
    "vim": ("-c", "--cmd"),
    "vi": ("-c", "--cmd"),
}

# Subcommands of exempt programs that build and run a program with the
# remaining words as its arguments (``cargo run -- kubectl delete …``): there
# the words are read like any unknown program's. The subcommands that run a
# command directly (``uv run``, ``pipx run``, ``mise exec`` …) are unwrapped
# by the shell parser instead, so the command itself is checked.
_PROGRAM_RUNNING_SUBCOMMANDS = {
    "cargo": frozenset({"run", "r"}),
    "go": frozenset({"run"}),
    "uv": frozenset({"run", "tool"}),
    "pipx": frozenset({"run"}),
    "mise": frozenset({"exec", "x"}),
    "asdf": frozenset({"exec"}),
    "gem": frozenset({"exec"}),
    "brew": frozenset({"bundle"}),
}


# Options of those programs that take a value before the subcommand.
_GLOBAL_VALUED_OPTIONS = {
    "cargo": frozenset({"--color", "--config", "-Z", "-C", "--manifest-path"}),
    "go": frozenset({"-C"}),
    "uv": frozenset({"--directory", "--project", "--config-file", "--cache-dir", "--color"}),
    "mise": frozenset({"-C", "--cd", "-E", "--env", "-j", "--jobs"}),
}


def _runs_a_program(name: str, args: list[str]) -> bool:
    """Whether ``name args…`` is a subcommand of an exempt program that runs a
    program (:data:`_PROGRAM_RUNNING_SUBCOMMANDS`); its first non-option word
    decides."""
    subcommands = _PROGRAM_RUNNING_SUBCOMMANDS.get(name)
    if not subcommands:
        return False
    valued = _GLOBAL_VALUED_OPTIONS.get(name, frozenset())
    i = 0
    while i < len(args) and (args[i].startswith(("-", "+"))):  # cargo +nightly, go -C dir
        i += 2 if args[i] in valued else 1
    return i < len(args) and args[i] in subcommands


# Environment variables whose value is a command (or a script) that the program
# run, or a shell it starts, runs: git's ssh, pager and editors, and the file
# bash/sh source before a non-interactive command.
_COMMAND_ENV_VARS = frozenset({
    "GIT_SSH_COMMAND", "GIT_SSH", "GIT_PAGER", "PAGER", "GIT_EDITOR", "EDITOR", "VISUAL",
    "GIT_SEQUENCE_EDITOR", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS", "MANPAGER",
    "LESSOPEN", "LESSCLOSE",
})
_SOURCED_ENV_VARS = frozenset({"BASH_ENV", "ENV"})


def _hidden_command(intent) -> HookVerdict | None:
    """A command a program runs from its configuration rather than its argv:
    git's command-valued settings and subcommands (``git -c alias.x='!cmd'``,
    ``git bisect run cmd``, see :func:`aegis_core.shell.git_runs`) and an
    environment variable that names a command (``GIT_SSH_COMMAND=cmd``,
    ``EDITOR=cmd``). Asked when that command names an infrastructure tool or
    cannot be read. ``BASH_ENV``/``ENV`` (a file bash or sh sources first)
    always asks: the hook does not read that file."""
    env = intent.metadata.get("env_assignments") or {}
    for var in sorted(_SOURCED_ENV_VARS & env.keys()):
        if env[var]:
            return HookVerdict(
                "ask", f"aegis: {var}={env[var]} makes the shell source a file first, which "
                "the hook does not read; run the command without it")
    commands = list(intent.metadata.get("runs_commands") or [])
    commands += [env[var] for var in sorted(_COMMAND_ENV_VARS & env.keys())]
    for text in commands:
        if text is None or mentions_infra(text):
            return HookVerdict(
                "ask", "aegis: a command this one runs from its configuration (a git "
                "alias, hook-like setting or subcommand such as bisect run, or an "
                "editor/pager/ssh variable) names an infrastructure tool or cannot be read, "
                "so it cannot be checked; run the infrastructure command on its own")
    return None


def _exec_option_values(name: str, args: list[str]) -> list[tuple[str, str]]:
    """``(option, value)`` for the options of ``name`` that take a command:
    ``rsync -e CMD`` / ``--rsh=CMD``, ``scp -o ProxyCommand=CMD`` / ``-S CMD``,
    ``nix-shell --run CMD`` / ``--command CMD``."""
    options = _EXEC_OPTIONS.get(name, ())
    found: list[tuple[str, str]] = []
    if name in ("vim", "vi"):
        found += [("+", tok[1:]) for tok in args if tok.startswith("+")]  # vim +'!cmd'
    for i, tok in enumerate(args):
        key, eq, glued = tok.partition("=")
        if key in options and key.startswith("--") and eq:
            found.append((key, glued))
        elif tok in options and i + 1 < len(args):
            found.append((tok, args[i + 1]))
        elif len(tok) > 2 and tok[:2] in options and not tok.startswith("--"):
            found.append((tok[:2], tok[2:]))  # -oProxyCommand=…
    return found


def _scripts_with_directory(command: str, cwd: Path | None) -> list[tuple[dict, Path | None]]:
    """Every script a parsable command runs, with the directory it is run from:
    ``cwd``, moved by each literal ``cd DIR`` in front of it. A ``cd`` that runs
    in the background or in a pipeline (a subshell), one to a computed place,
    ``env -C``/``sudo -D`` and a ``cd`` inside ``sh -c`` make it unknown."""
    found: list[tuple[dict, Path | None]] = []
    here = cwd
    segments = split_segments(command) or [(command, "")]
    previous_sep = ""
    for text, sep in segments:
        subshell = sep in ("&", "|", "|&") or previous_sep in ("|", "|&")
        previous_sep = sep
        loose = loose_argv(text) or []
        if loose and _basename(loose[0]) in ("cd", "pushd", "popd"):
            here = None if subshell else _cd(here, loose)
            continue
        try:
            intents = intents_from_command(text)
        except ValueError:
            continue
        words = set(text.split())
        chdir = bool(words & {"-C", "--chdir", "-D"}) or "--chdir=" in text
        for intent in intents:
            if intent.provider != "shell":
                continue
            argv = intent.params.get("argv") or []
            if argv and _basename(argv[0]) in ("cd", "pushd", "popd"):
                here = None  # a cd inside sh -c "…"
            runs = intent.params.get("runs_code")
            if runs is not None and runs["kind"] == "script":
                found.append((runs, None if chdir else here))
    return found


def _cd(here: Path | None, argv: list[str]) -> Path | None:
    """The directory after ``cd DIR``; ``None`` when it cannot be known."""
    args = [a for a in argv[1:] if a not in ("-P", "-L", "-e", "--")]
    if here is None or _basename(argv[0]) == "popd" or len(args) > 1:
        return None
    if not args:
        return Path.home() if _basename(argv[0]) == "cd" else None
    target = args[0]
    if target.startswith("-") or any(ch in target for ch in "$`"):
        return None
    try:
        path = Path(target).expanduser()
    except RuntimeError:  # ~user / ~+ the hook cannot resolve
        return None
    return path if path.is_absolute() else here / path


def _literal_code(argv: list[str]) -> str | None:
    """The text a literal ``echo``/``printf`` writes, when that is certain:
    no ``echo -e``, no backslash escapes other than ``printf``'s ``\\n``/``\\t``,
    no ``printf`` format directives or extra arguments. ``None`` otherwise."""
    name, args = _basename(argv[0]), list(argv[1:])
    if name == "echo":
        while args and re.fullmatch(r"-[neE]+", args[0]):
            if "e" in args[0]:
                return None
            args = args[1:]
        text = " ".join(args)
        return None if "\\" in text else text
    if name == "printf":
        if len(args) != 1 or args[0].startswith("-") or "%" in args[0]:
            return None
        text = args[0].replace("\\n", "\n").replace("\\t", "\t")
        return None if "\\" in text else text
    return None


def _piped_code(command: str, reader: list[str], feeder: list[str] | None, config_dir: Path,
                extra_args: list[str] | None, cwd: Path | None, *,
                rebuilt: bool) -> HookVerdict | None:
    """A shell or interpreter reading its code from a pipe (issue #56). Deny
    when the command names an infrastructure tool; else read the code when a
    literal ``echo``/``printf`` writes it (code for a shell is checked like a
    command); ask when the code comes from anything else."""
    interpreter = _basename(reader[0])
    if mentions_infra(command):
        return HookVerdict(
            "deny",
            f"aegis: cannot check code passed to {interpreter} through a pipe, and it names an "
            "infrastructure tool; run the infrastructure command on its own",
            unchecked=True,
        )
    if feeder is None:
        return None  # the reader only writes into a pipe
    producer = _basename(feeder[0])
    # In a rebuilt command an echo may stand for `echo "$X"`, so it is not literal.
    code = None if rebuilt else _literal_code(feeder)
    if code is None:
        return HookVerdict(
            "ask", f"aegis: {interpreter} runs code piped from {producer}, which the hook "
            "cannot read; save it to a file and run that, so its commands are checked")
    if mentions_infra(code):
        return HookVerdict(
            "deny",
            f"aegis: cannot check code passed to {interpreter} through a pipe, and it names an "
            "infrastructure tool; run the infrastructure command on its own",
            unchecked=True,
        )
    if interpreter not in _SHELLS:
        return None
    verdict = _decide(code, config_dir, extra_args, cwd, scan=False)
    if verdict.decision == "allow":
        return None
    reason = verdict.reason.removeprefix("aegis: ")
    if verdict.decision == "deny" and not verdict.unchecked:
        return HookVerdict("deny", f"aegis: code piped into {interpreter}: {reason}")
    return HookVerdict("ask", f"aegis: code piped into {interpreter}: {reason}")


def _rejected(command: str, reason: str, config_dir: Path, extra_args: list[str] | None,
              cwd: Path | None, *, scan: bool, escalate_scripts: bool) -> HookVerdict:
    """A command (or a part of it) that cannot be parsed, judged as a whole:
    deny when it names an infrastructure tool, ask for code generated at run
    time or piped from a here-document or another program, check the local
    shell scripts it names, else allow."""
    if mentions_infra(command):
        return HookVerdict(
            "deny",
            f"aegis: cannot check this command statically ({reason}); "
            "run the infrastructure command on its own, without shell expansion",
            unchecked=True,
        )
    generated = _GENERATED_CODE_RE.search(command)
    if generated:
        return HookVerdict(
            "ask",
            f"aegis: {generated.group(1)} runs code that is only produced when the command "
            "runs, so it cannot be checked; run the commands directly instead",
        )
    producer = loose_code_reader(command)
    if producer is not None:
        return HookVerdict(
            "ask", f"aegis: a shell or interpreter runs code from {producer}, which the hook "
            "cannot read; save it to a file and run that, so its commands are checked")
    scripts = script_runs_loosely(command)
    if scan:
        here = None if _CD_RE.search(command) else cwd
        for runs in scripts:
            verdict = _scan_script(runs, config_dir, extra_args, here, command=command)
            if verdict is not None:
                return verdict
    if escalate_scripts and scripts:
        return HookVerdict(
            "ask", "aegis: this runs a local script, which the hook cannot read "
            "(--escalate-scripts)")
    return HookVerdict("allow")


def _checkable_part(command: str, exc: ShellRejected, config_dir: Path,
                    extra_args: list[str] | None, cwd: Path | None, *, scan: bool,
                    escalate_scripts: bool) -> HookVerdict | tuple[str, list[str]]:
    """For a command that cannot be parsed as a whole (issue #55): judges it
    part by part (``;``, ``&&``, ``||``, ``|``, newline). A part that cannot be
    checked and names an infrastructure tool is a deny that names it. A part
    whose program only reads its arguments as data (``echo "exit=$?"``,
    ``tail -n "$N"``; :func:`plain_binary`) stands in as that bare program; one
    that only assigns, or sources a local script (read like ``bash x.sh``),
    drops out. Returns the command rebuilt from the parts that can be checked,
    plus pending asks -- or a verdict, when a part is unknown (it runs an
    expansion, ``$K …``, ``eval …``, ``find -exec``, ``ssh``, …): deny when the
    command names an infrastructure tool anywhere, else the whole-command rules
    of :func:`_rejected`."""
    # a here-doc's body lines are data, not commands: judged as a whole, as before
    segments = None if "<<" in command else split_segments(command)
    if not segments:
        return _rejected(command, exc.reason, config_dir, extra_args, cwd,
                         scan=scan, escalate_scripts=escalate_scripts)
    kept: list[tuple[str, str]] = []
    asks: list[str] = []
    opaque: tuple[str, str] | None = None
    # a script run anywhere in the command, also inside a part that drops out
    # (`OUT=$(bash x.sh)`) or cannot be split out (`for …; do ./x.sh "$i"; done`)
    loose_scripts = script_runs_loosely(command)
    if scan:
        start = None if _CD_RE.search(command) else cwd
        for runs in loose_scripts:
            verdict = _scan_script(runs, config_dir, extra_args, start, command=command)
            if verdict is not None:
                if verdict.decision == "deny":
                    return verdict
                asks.append(verdict.reason)
    if escalate_scripts and loose_scripts:
        asks.append("aegis: this runs a local script, which the hook cannot read "
                    "(--escalate-scripts)")
    here = cwd
    previous_sep = ""
    for text, sep in segments:
        loose = loose_argv(text)
        if loose and _basename(loose[0]) in ("cd", "pushd", "popd"):
            subshell = sep in ("&", "|", "|&") or previous_sep in ("|", "|&")
            here = None if subshell else _cd(here, loose)
        previous_sep = sep
        try:
            intents_from_command(text)
        except ShellRejected as seg_exc:
            reason = seg_exc.reason
            if reason == GLOB_REASON:
                return _glob_denied(command, seg_exc.command or "")
        except ValueError:  # a parser error: kept, so the full check reports it
            kept.append((text, sep))
            continue
        else:
            kept.append((text, sep))
            continue
        shown = text.strip()
        if mentions_infra(text):
            return HookVerdict(
                "deny",
                f"aegis: cannot check this command statically ({reason}) in {shown!r}; "
                "run the infrastructure command on its own, without shell expansion",
                unchecked=True,
            )
        sourced = None if runs_expansion(text) else _sourced_script(text)
        if sourced is not None:
            verdict = _scan_script(sourced, config_dir, extra_args, here,
                                   command=command) if scan else None
            if verdict is not None and verdict.decision == "deny":
                return verdict
            if verdict is not None:
                asks.append(verdict.reason)
            elif escalate_scripts:
                asks.append("aegis: this runs a local script, which the hook cannot read "
                            "(--escalate-scripts)")
            continue
        binary = plain_binary(text)
        if binary is None:
            opaque = opaque or (shown, reason)
            continue
        if binary in ("cd", "pushd"):
            kept.append(("cd -", sep))  # a cd to a place only known at run time
        elif binary:
            kept.append((shlex.quote(binary), sep))
    if opaque is not None:
        if mentions_infra(command):
            return HookVerdict(
                "deny",
                f"aegis: cannot check this command statically ({opaque[1]}) in {opaque[0]!r}, "
                "and the command names an infrastructure tool; run the infrastructure command "
                "on its own, without shell expansion",
                unchecked=True,
            )
        return _with_asks(
            _rejected(command, exc.reason, config_dir, extra_args, cwd,
                      scan=scan, escalate_scripts=escalate_scripts),
            asks)
    # a dropped part takes its separator with it; the last kept part loses its own
    rebuilt = "".join(text + sep for text, sep in kept[:-1])
    if kept:
        last, last_sep = kept[-1]
        rebuilt += last + (last_sep if last_sep == "&" else "")
    return rebuilt, asks


def _sourced_script(segment: str) -> dict[str, str] | None:
    """``source x.sh`` / ``. x.sh`` as a ``runs_code`` record; else ``None``."""
    try:
        words = shlex.split(segment, comments=True)
    except ValueError:
        return None
    if len(words) >= 2 and words[0] in ("source", "."):
        return {"kind": "script", "interpreter": words[0], "path": words[1]}
    return None


def _script_lines(text: str) -> list[tuple[int, str, str | None]]:
    """``(line_number, command_text, ask_reason)`` for a script: continuations
    joined (backslash-newline removed, as the shell does, but not at the end of
    a comment, which ends at the newline), comments dropped, and here-document
    bodies treated as what reads them: as commands when a shell reads them,
    directly or through a pipe (``cat <<EOF | sh``); as unreadable code
    (``ask_reason``) when another interpreter reads one that names an
    infrastructure tool, or when an unquoted tag lets a ``$(…)`` in the body
    that names one run; otherwise as data, skipped."""
    joined: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        candidate = pending + line
        code = strip_comment(candidate)
        trailing = len(code) - len(code.rstrip("\\"))
        if code == candidate and trailing % 2 == 1:
            pending = candidate[:-1]
            continue
        joined.append((start, candidate))
        pending = ""
    if pending:
        joined.append((start, pending))
    out: list[tuple[int, str, str | None]] = []
    i = 0
    while i < len(joined):
        number, line = joined[i]
        i += 1
        if line.lstrip().startswith("#"):
            continue
        heredoc = find_heredoc(line)
        if heredoc is None:
            out.append((number, strip_comment(line), None))
            continue
        begin, end, dash, tag, quoted = heredoc
        if not tag:  # the delimiter word cannot be read: ask, and check what follows
            out.append((number, line, "cannot tell where the here-document ends, so the "
                                      "lines after it were not checked as data or commands"))
            continue
        body: list[tuple[int, str]] = []
        while i < len(joined):
            n, body_line = joined[i]
            i += 1
            if (body_line.lstrip("\t") if dash else body_line) == tag:
                break
            body.append((n, body_line))
        command = strip_comment(line[:begin] + line[end:])
        out.append((number, command, None))
        reader = loose_argv(line[:begin]) or []
        name = _basename(reader[0]) if reader else ""
        if name in _SHELLS or loose_code_reader(command) is not None:
            out.extend((n, strip_comment(b), None) for n, b in body)
        elif _interpreter(name) and any(mentions_infra(b) for _n, b in body):
            out.append((number, line, f"{name} reads a here-document that names an "
                                      "infrastructure tool, which the hook cannot check"))
        elif not quoted:
            for n, b in body:
                if runs_expansion(b) and mentions_infra(b):
                    out.append((n, b, "the here-document runs a command substitution that "
                                      "names an infrastructure tool, which the hook cannot "
                                      "check"))
    return out


def _written_by_command(file: Path, command: str, cwd: Path | None) -> bool:
    """True when ``file`` is named more than once in ``command``: besides the
    run itself, as a redirection target or an argument of another command
    (``printf … > x.sh; bash x.sh``, ``cp a x.sh; bash x.sh``, ``chmod +x
    nuke; ./nuke``), so what runs may not be what is on disk now. A spelling
    the hook cannot resolve (``"$PWD/x.sh"``, ``"$(pwd)/x.sh"``) counts when
    its last component is the file's name. Arguments of programs that only
    read files (``cat x.sh``, ``grep … x.sh``) do not count; redirection
    targets always do."""
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = command.split()
    target = os.path.normpath(file)
    try:
        resolved = file.resolve() if file.exists() else None
    except OSError:
        resolved = None
    computed = any(ch in command for ch in "$`")
    count = 0
    program: str | None = None  # the current simple command's program
    redirect = False
    for token in tokens:
        if not token:
            continue
        if set(token) <= set("();|&"):
            program, redirect = None, False
            continue
        if set(token) <= set("<>&|"):
            redirect = ">" in token
            continue
        was_redirect, redirect = redirect, False
        if program is None and not _ASSIGNMENT_WORD.match(token):
            program = _basename(token)
        elif not was_redirect and program in _FILE_READERS:
            continue
        if any(ch in token for ch in "$`"):
            count += token.rstrip("\"')").rsplit("/", 1)[-1] == file.name
            continue
        if token.rsplit("/", 1)[-1] != file.name and re.search(
                r"(?<![\w.-])" + re.escape(file.name) + r"(?![\w.-])", token):
            # inside code or a command line (python3 -c '…Path("x.sh").write_text(…)'):
            # it may write the file
            count += 1
            continue
        try:
            path = Path(token).expanduser()
        except RuntimeError:  # ~user or ~+ the hook cannot resolve: an unknown path
            continue
        if not path.is_absolute():
            if cwd is None:
                continue
            path = cwd / path
        same = os.path.normpath(path) == target
        if not same and resolved is not None:
            try:
                same = path.exists() and path.resolve() == resolved
            except OSError:
                same = False
        if not same and computed and token.startswith("/"):
            same = token.rsplit("/", 1)[-1] == file.name  # the tail of an unquoted $(pwd)/x
        count += same
    return count > 1


_ASSIGNMENT_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Programs whose file arguments are only read: naming the script there is not a write.
_FILE_READERS = frozenset({
    "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "less", "more", "wc", "diff",
    "cmp", "file", "stat", "ls", "bat", "md5sum", "sha1sum", "sha256sum", "shasum",
    "shellcheck",
})


def _scan_script(runs: dict, config_dir: Path, extra_args: list[str] | None,
                 cwd: Path | None, *, command: str = "") -> HookVerdict | None:
    """Reads a local shell script that a command runs (``bash x.sh``, ``sh <
    x.sh``, ``./x``, ``source x.sh``; issue #56) and checks every line that
    names an infrastructure tool as a command against the policy. ``None``
    when there is nothing to say: not a shell script, no such line, or every
    such line allowed. A blocked line (or a block only the lines together
    reach) denies; a line that cannot be checked asks; so does a script that is
    missing, written by the same ``command``, unreadable, not a regular file,
    holding a NUL byte, larger than :data:`SCRIPT_SCAN_LIMIT`, with more than
    :data:`SCRIPT_SCAN_MAX_LINES` such lines, or whose directory is unknown (a
    ``cd`` to a computed place came first). What the script sources or runs in
    turn is not read."""
    interpreter = _basename(runs.get("interpreter", "") or "")
    path = runs.get("path", "") or ""
    if path.startswith("< "):
        path = path[2:]
    shell_run = interpreter in _SHELLS or interpreter in ("source", ".")
    if interpreter and not shell_run:
        return None
    if not path or path.startswith("-"):
        return None
    if any(ch in path for ch in "$`"):
        return HookVerdict("ask", f"aegis: {path} is a script whose name is only known when "
                                  "the command runs, so its commands cannot be checked")
    try:
        file = Path(path).expanduser()
    except RuntimeError:  # ~user / ~+ the hook cannot resolve
        return HookVerdict("ask", f"aegis: cannot tell which file {path} is, so its commands "
                                  "were not checked")
    if not file.is_absolute():
        if cwd is None:
            return HookVerdict("ask", f"aegis: cannot tell which directory {path} is run "
                                      "from (a cd to a computed place comes first), so its "
                                      "commands were not checked")
        file = cwd / file
    if command and _written_by_command(file, command, cwd):
        return HookVerdict("ask", f"aegis: {path} is written by this command, so its commands "
                                  "cannot be checked; run it separately")
    try:
        if not file.exists():
            if shell_run or path.endswith(_SHELL_SUFFIXES):
                return HookVerdict("ask", f"aegis: {path} does not exist yet, so the commands "
                                          "in it cannot be checked; write it first, then run it")
            return None
        if not file.is_file():
            return HookVerdict("ask", f"aegis: {path} is not a regular file, so the commands "
                                      "in it cannot be checked")
        with file.open("rb") as handle:
            data = handle.read(SCRIPT_SCAN_LIMIT + 1)
    except OSError as exc:
        return HookVerdict("ask", f"aegis: cannot read {path} to check the commands in it "
                                  f"({exc.strerror or exc})")
    if len(data) > SCRIPT_SCAN_LIMIT:
        return HookVerdict("ask", f"aegis: {path} is larger than {SCRIPT_SCAN_LIMIT // 1024} "
                                  "KiB, so the commands in it were not checked")
    text = data.decode("utf-8", errors="replace")
    first = text.split("\n", 1)[0]
    shebang_shell: bool | None = None  # None: no #! line
    if first.startswith("#!"):
        words = first[2:].replace("\0", " ").split()
        program = _basename(words[0]) if words else ""
        if program == "env":
            rest = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
            program = _basename(rest[0]) if rest else ""
        shebang_shell = program in _SHELLS
    if not interpreter and shebang_shell is False:
        return None  # ./x with another interpreter's #! line
    if "\0" in text:
        if shell_run or shebang_shell:
            return HookVerdict("ask", f"aegis: {path} contains a NUL byte, so its commands "
                                      "were not checked")
        return None  # ./x without #!: a binary, not a shell script
    lines = [(n, line, ask) for n, line, ask in _script_lines(text)
             if ask is not None or mentions_infra(line)]
    if not lines:
        return None
    if len(lines) > SCRIPT_SCAN_MAX_LINES:
        return HookVerdict("ask", f"aegis: {path} names an infrastructure tool on more than "
                                  f"{SCRIPT_SCAN_MAX_LINES} lines, so they were not checked")
    first_ask: str | None = None
    checkable: list[tuple[int, str, str]] = []
    for number, line, ask in lines:
        located = f"{path} line {number}: {line.strip()!r}"
        if ask is not None:
            first_ask = first_ask or f"aegis: {located}: {ask}"
            continue
        pre = _precheck(line, config_dir, extra_args, cwd, scan=False)
        if isinstance(pre, HookVerdict):
            if pre.decision == "allow":
                continue
            reason = pre.reason.removeprefix("aegis: ")
            if pre.decision == "deny" and not pre.unchecked:
                return HookVerdict("deny", f"aegis: {reason} ({located})")
            first_ask = first_ask or f"aegis: {located}: {reason}"
            continue
        checked, asks = pre
        if asks:
            first_ask = first_ask or f"aegis: {located}: {asks[0].removeprefix('aegis: ')}"
        if checked.strip(" \t\n;&|"):
            checkable.append((number, line, checked))
    verdict = _policy("\n".join(c for _n, _l, c in checkable), config_dir, extra_args) \
        if checkable else HookVerdict("allow")
    if verdict.decision == "allow":
        return HookVerdict("ask", first_ask) if first_ask else None
    # the first line at which the lines so far reach the verdict -- a deny for a
    # deny, so an earlier ESCALATE line is not blamed for a BLOCK (bisection: a
    # handful of policy runs, not one per line)
    def reached(prefix: str) -> bool:
        decision = _policy(prefix, config_dir, extra_args).decision
        return decision == "deny" if verdict.decision == "deny" else decision != "allow"

    low, high = 1, len(checkable)
    while low < high:
        middle = (low + high) // 2
        if reached("\n".join(c for _n, _l, c in checkable[:middle])):
            high = middle
        else:
            low = middle + 1
    number, line, _checked = checkable[low - 1]
    located = f"{path} line {number}: {line.strip()!r}"
    if verdict.decision == "deny":
        return HookVerdict("deny", f"{verdict.reason} ({located})")
    return HookVerdict("ask", first_ask or f"{verdict.reason} ({located})")


def _policy(command: str, config_dir: Path, extra_args: list[str] | None) -> HookVerdict:
    """``aegis check command`` on a command that parses."""
    from aegis_core import cli  # local: cli imports this module

    argv = [
        "check", "command", "--config-dir", str(config_dir), "--exit-style", "claude-hook",
        *(extra_args or []), "--", command,
    ]
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    if rc == 0:
        return HookVerdict("allow")
    if rc == 2:
        reason = "aegis: blocked by policy"
        for line in out.getvalue().splitlines():
            try:
                reason = json.loads(line).get("reason", reason)
            except (json.JSONDecodeError, AttributeError):
                continue
        return HookVerdict("ask" if reason.startswith("ESCALATE") else "deny", f"aegis: {reason}")
    message = err.getvalue().strip().splitlines()
    detail = message[-1] if message else f"exit {rc}"
    if not _is_gated(command):
        return HookVerdict("allow")
    return HookVerdict(
        "deny",
        f"{detail} -- policy in {config_dir} is unusable, so infrastructure commands are "
        "blocked until it is fixed (see 'aegis verify')",
    )


# --- replying --------------------------------------------------------------------


# Agents whose hooks cannot ask the user: an ESCALATE is a deny there.
# (Codex treats an unknown decision as an error and runs the command.)
_NO_ASK = frozenset({"codex", "gemini", "opencode"})


def _both_shapes(decision: str, reason: str) -> dict:
    """Copilot CLI reads a top-level ``permissionDecision``; VS Code reads
    ``hookSpecificOutput``. Both read the same ``.github/hooks`` files and
    the same Copilot plugins, so their reply carries both."""
    return {
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }


def render(agent: str, verdict: HookVerdict, *, escalate_as: str = "ask") -> tuple[int, str, str]:
    """``(exit_code, stdout, stderr)`` for this agent. Deny is exit 2 +
    stderr (Cursor: its JSON on exit 0); ask is each agent's own JSON with
    exit 0."""
    decision = verdict.decision
    if decision == "ask" and (agent in _NO_ASK or escalate_as == "deny"):
        decision = "deny"
    if decision == "allow":
        return _allow(agent)
    reason = verdict.reason or "aegis: blocked by policy"
    if decision == "deny":
        body = {
            "claude": {"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": reason}},
            "codex": {"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": reason}},
            "copilot": _both_shapes("deny", reason),
            "vscode": _both_shapes("deny", reason),
            "cursor": {"permission": "deny", "user_message": reason, "agent_message": reason},
            "gemini": {"decision": "deny", "reason": reason},
            # the OpenCode plugin throws with stderr; stdout is not read
            "opencode": {"decision": "deny", "reason": reason},
        }[agent]
        if agent == "cursor":
            # Cursor shows the stdout of an exit-2 hook verbatim as the
            # reason; a JSON deny with exit 0 is parsed and shown properly.
            # (failClosed still turns anything unparseable into a block.)
            return EXIT_ALLOW, json.dumps(body), ""
        return EXIT_BLOCK, json.dumps(body), reason
    # ask
    body = {
        "claude": {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": reason}},
        "copilot": _both_shapes("ask", reason),
        "vscode": _both_shapes("ask", reason),
        "cursor": {"permission": "ask", "user_message": reason, "agent_message": reason},
    }[agent]
    return EXIT_ALLOW, json.dumps(body), ""


def _with_warning(agent: str, reply: tuple[int, str, str], warning: str) -> tuple[int, str, str]:
    """Adds a budget warning to a reply that lets the call through, in the
    agent's own channel."""
    code, out, err = reply
    if not warning or code != EXIT_ALLOW:
        return reply
    if agent in _SYSTEM_MESSAGE_AGENTS or agent == "opencode":
        try:
            body = json.loads(out) if out else {}
        except json.JSONDecodeError:
            body = {}
        body["systemMessage" if agent != "opencode" else "warning"] = warning
        return code, json.dumps(body), err
    return code, out, f"{err}\n{warning}".strip()


def render_prompt(agent: str, verdict: HookVerdict, warning: str = "") -> tuple[int, str, str]:
    """The reply to a prompt hook (Claude Code / Codex ``UserPromptSubmit``,
    Gemini CLI ``BeforeAgent``): block the prompt, or let it through,
    optionally with a warning."""
    if verdict.decision == "deny":
        reason = verdict.reason or "aegis: blocked"
        body = ({"decision": "deny", "reason": reason} if agent == "gemini"
                else {"decision": "block", "reason": reason})
        return EXIT_BLOCK, json.dumps(body), reason
    if warning:
        return EXIT_ALLOW, json.dumps({"systemMessage": warning}), ""
    return EXIT_ALLOW, "", ""


def _budget_outcome(agent: str, payload: dict, request: HookRequest, config_dir: Path,
                    extra_args: list[str] | None):
    """The budget gate's outcome for this call. A budget.yaml that cannot be
    used denies (the project opted in to a budget; fail closed)."""
    from aegis_core import cli  # local: cli imports this module
    from aegis_core.budget.gate import Outcome, check

    try:
        policy, key, insecure = cli.load_budget_with_key(config_dir, extra_args)
    except Exception as exc:  # noqa: BLE001 - any failure to load is reported, not raised
        return Outcome("deny", f"aegis budget: {config_dir / BUDGET_FILE} cannot be used "
                               f"({exc.__class__.__name__}: {exc}); fix and re-sign it, or "
                               "remove it")
    if policy is None:
        return Outcome("allow")
    return check(agent, payload, request.cwd, policy, key=key, insecure=insecure)


def run_hook(agent: str, stdin_text: str, *, escalate_as: str = "ask",
             extra_args: list[str] | None = None) -> tuple[int, str, str]:
    """The whole hook: payload text in, ``(exit, stdout, stderr)`` out.
    Never raises. Outside an opted-in project every failure allows; inside
    one, a failure blocks (fail closed where the user asked to be gated).

    Where the project's policy directory also holds a ``budget.yaml``, the
    budget cap is checked after the policy decision (a BLOCK stands whatever
    the budget says): for every tool call the hook sees, and for prompt
    events."""
    config_dir: Path | None = None
    try:
        try:
            payload = json.loads(stdin_text or "")
        except json.JSONDecodeError as exc:
            raise HookInputError(f"hook payload is not JSON: {exc}") from None
        if not isinstance(payload, dict):
            raise HookInputError("hook payload is not a JSON object")
        prompt = payload.get("hook_event_name") in PROMPT_EVENTS
        if prompt:
            cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
            request = HookRequest(None, cwd)
        else:
            request = parse_request(agent, payload)
        has_command = bool(request.command and request.command.strip())
        if not has_command and agent not in BUDGET_AGENTS:
            return _allow(agent)
        config_dir = find_opt_in_config(_project_dir(request))
        if config_dir is None:
            return _allow(agent)
        has_budget = agent in BUDGET_AGENTS and (config_dir / BUDGET_FILE).is_file()
        if not has_command and not has_budget:
            return _allow(agent)

        verdict = decide(request.command, config_dir, extra_args, cwd=request.cwd) \
            if has_command \
            else HookVerdict("allow")
        if verdict.decision == "deny":
            return render(agent, verdict, escalate_as=escalate_as)
        warning = ""
        if has_budget:
            outcome = _budget_outcome(agent, payload, request, config_dir, extra_args)
            if outcome.decision == "deny":
                verdict = HookVerdict("deny", outcome.message)
            elif outcome.message:
                warning = outcome.message
        if prompt:
            return render_prompt(agent, verdict, warning)
        return _with_warning(agent, render(agent, verdict, escalate_as=escalate_as), warning)
    except Exception as exc:  # noqa: BLE001 - a hook must answer, never crash
        if config_dir is None and not isinstance(exc, HookInputError):
            return _allow(agent)
        if config_dir is None:
            # Unreadable payload: only block if Aegis is configured anywhere.
            try:
                config_dir = find_opt_in_config(Path.cwd())
            except Exception:  # noqa: BLE001
                config_dir = None
            if config_dir is None:
                return _allow(agent)
        reason = f"aegis: hook error ({exc.__class__.__name__}: {exc}); blocking to fail closed"
        return render(agent, HookVerdict("deny", reason))


def main_hook(agent: str, *, escalate_as: str, extra_args: list[str]) -> int:
    code, out, err = run_hook(
        agent, sys.stdin.read(), escalate_as=escalate_as, extra_args=extra_args
    )
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return code


# --- installing ------------------------------------------------------------------


def _aegis_command() -> list[str]:
    """How the agent should start this aegis: the absolute path of the
    running entry point when there is one (GUI apps do not inherit a
    shell's PATH), else ``python -m aegis_core.cli``."""
    argv0 = Path(sys.argv[0])
    if argv0.name == "aegis" and argv0.exists():
        return [str(argv0.resolve())]
    return [sys.executable, "-m", "aegis_core.cli"]


def hook_command(agent: str, check_args: tuple[str, ...] = ()) -> str:
    """The command the agent runs; ``check_args`` (``--escalate-scripts``) are passed on
    to ``aegis check command`` after ``--``."""
    return shlex.join([*_aegis_command(), "hook", agent, *(("--", *check_args) if check_args
                                                         else ())])


def _is_ours(command: object) -> bool:
    return isinstance(command, str) and " hook " in command and "aegis" in command


def config_path(agent: str, *, user: bool, project: Path) -> Path:
    home = Path.home()
    return {
        ("claude", True): home / ".claude" / "settings.json",
        ("claude", False): project / ".claude" / "settings.json",
        ("codex", True): home / ".codex" / "hooks.json",
        ("codex", False): project / ".codex" / "hooks.json",
        ("copilot", True): home / ".copilot" / "hooks" / "aegis.json",
        ("copilot", False): project / ".github" / "hooks" / "aegis.json",
        ("vscode", True): home / ".copilot" / "hooks" / "aegis-vscode.json",
        ("vscode", False): project / ".github" / "hooks" / "aegis-vscode.json",
        ("cursor", True): home / ".cursor" / "hooks.json",
        ("cursor", False): project / ".cursor" / "hooks.json",
        ("gemini", True): home / ".gemini" / "settings.json",
        ("gemini", False): project / ".gemini" / "settings.json",
        ("opencode", True): home / ".config" / "opencode" / "plugins" / "aegis-devops.js",
        ("opencode", False): project / ".opencode" / "plugins" / "aegis-devops.js",
    }[(agent, user)]


def _strip_ours(entries: list) -> list:
    """Drops earlier aegis entries so installing twice leaves one."""
    kept = []
    for entry in entries:
        if not isinstance(entry, dict):
            kept.append(entry)
            continue
        if _is_ours(entry.get("command")) or _is_ours(entry.get("bash")):
            continue
        inner = entry.get("hooks")
        if isinstance(inner, list):
            remaining = [
                h for h in inner if not (isinstance(h, dict) and _is_ours(h.get("command")))
            ]
            if not remaining:
                continue
            entry = {**entry, "hooks": remaining}
        kept.append(entry)
    return kept


# Events aegis may own per agent; reinstalling or removing cleans all of them.
_EVENTS = {
    "claude": ("PreToolUse", "UserPromptSubmit"),
    "codex": ("PreToolUse", "UserPromptSubmit"),
    "gemini": ("BeforeTool", "BeforeAgent"),
    "copilot": ("preToolUse",),
    "vscode": ("PreToolUse",),
    "cursor": ("beforeShellExecution",),
}


def _entries(agent: str, command: str, budget: bool) -> list[tuple[str, dict]]:
    """``(event, entry)`` pairs for this agent. With a budget, the tool hook
    sees every tool call (the budget counts all of them, not only shell
    commands) and a prompt hook is added where the agent has one that can
    block (design v1.0 §6)."""
    if agent in ("claude", "codex"):
        matcher = ("*" if agent == "claude" else ".*") if budget else (
            "Bash" if agent == "claude" else "^Bash$")
        hook = {"type": "command", "command": command, "timeout": 30}
        pairs = [("PreToolUse", {"matcher": matcher, "hooks": [hook]})]
        if budget:
            pairs.append(("UserPromptSubmit", {"hooks": [dict(hook)]}))
        return pairs
    if agent == "gemini":
        hook = {"name": "aegis-devops", "type": "command", "command": command, "timeout": 30000}
        pairs = [("BeforeTool", {"matcher": ".*" if budget else "run_shell_command",
                                 "hooks": [hook]})]
        if budget:
            pairs.append(("BeforeAgent", {"hooks": [dict(hook)]}))
        return pairs
    if agent == "copilot":
        # no matcher: Copilot CLI already sends every tool call; its prompt hook
        # cannot block, so a budget adds nothing here
        return [("preToolUse", {"type": "command", "bash": command, "timeoutSec": 30})]
    if agent == "vscode":
        # VS Code's native format: PascalCase events and no "version" (a
        # numeric version marks the Copilot CLI format instead). VS Code
        # ignores matchers here, so the hook sees every tool call and
        # parse_request lets the non-terminal ones through.
        return [("PreToolUse", {"type": "command", "command": command, "timeout": 30})]
    return [("beforeShellExecution", {"command": command, "failClosed": True})]  # cursor


def merge_config(agent: str, existing: dict, command: str | None, *,
                 budget: bool = False) -> dict:
    """``existing`` with the aegis hooks added (``command``) or removed
    (``None``), every other setting and hook left as it was."""
    doc = dict(existing)
    hooks = dict(doc.get("hooks") or {})
    if agent in ("copilot", "cursor") and command is not None:
        doc.setdefault("version", 1)
    wanted = _entries(agent, command, budget) if command is not None else []
    for event in _EVENTS[agent]:
        entries = _strip_ours(list(hooks.get(event) or []))
        entries.extend(entry for ev, entry in wanted if ev == event)
        if entries:
            hooks[event] = entries
        else:
            hooks.pop(event, None)
    doc["hooks"] = hooks
    return doc


def budget_configured(*, user: bool, project: Path) -> bool:
    """Whether the policy directory that would apply holds a ``budget.yaml``,
    resolved with the hook's own precedence and never by looking past a
    directory that shadows another: for a project install,
    ``$AEGIS_CONFIG_DIR``, else the nearest ``.aegis/`` at or above the
    project, else ``~/.config/aegis`` (:func:`find_opt_in_config`); for a
    user install, ``$AEGIS_CONFIG_DIR``, else ``~/.config/aegis``."""
    if user:
        env = os.environ.get(config_module.CONFIG_ENV_VAR)
        directory: Path | None = Path(env) if env else Path.home() / ".config" / "aegis"
    else:
        directory = find_opt_in_config(project)
    return directory is not None and (directory / BUDGET_FILE).is_file()


_AFTER_INSTALL = {
    "claude": "Restart Claude Code (or run /hooks) to load it.",
    "codex": "Codex runs a new hook only after you trust it: open codex and run /hooks.",
    "copilot": "Copilot CLI loads repository hooks only in trusted folders; a user-level "
    "install (--user) always loads.",
    "vscode": "Hooks are a Preview feature in VS Code; enable chat hooks in its settings if "
    "they do not run.",
    "cursor": "Restart Cursor to load it.",
    "gemini": "Restart Gemini CLI; '/hooks' lists it (project hooks may ask to be trusted).",
    "opencode": "Restart OpenCode to load the plugin.",
}


def _install_opencode_plugin(path: Path, *, remove: bool, budget: bool | None = None,
                             check_args: tuple[str, ...] = ()) -> Path:
    """OpenCode hooks are JS plugins: write (or delete) our plugin file, with
    the argv of this aegis and the budget coverage filled in. The plugin
    detects a ``budget.yaml`` at run time, so the default is ``"auto"``;
    ``--no-budget`` (``budget=False``) writes ``"off"``: shell commands only."""
    if remove:
        if path.exists():
            path.unlink()
        return path
    template = (
        importlib.resources.files("aegis_core") / "integrations" / "opencode-plugin.js"
    ).read_text()
    marker = "const INSTALLED = null"
    if marker not in template:
        raise ValueError("opencode plugin template has no INSTALLED marker")
    mode_marker = 'const BUDGET_MODE = "auto"'
    if mode_marker not in template:
        raise ValueError("opencode plugin template has no BUDGET_MODE marker")
    args_marker = "const CHECK_ARGS = []"
    if args_marker not in template:
        raise ValueError("opencode plugin template has no CHECK_ARGS marker")
    mode = "off" if budget is False else "auto"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(template.replace(marker, f"const INSTALLED = {json.dumps(_aegis_command())}")
                    .replace(mode_marker, f"const BUDGET_MODE = {json.dumps(mode)}")
                    .replace(args_marker, f"const CHECK_ARGS = {json.dumps(list(check_args))}"))
    return path


def install(agent: str, *, user: bool, project: Path, remove: bool = False,
            budget: bool | None = None, escalate_scripts: bool = False) -> Path:
    """Writes (or removes) the agent's hook. ``budget``: ``True``/``False``
    install or leave out the budget hooks; ``None`` detects whether the
    policy directory that applies holds a ``budget.yaml``. ``escalate_scripts``
    adds ``-- --escalate-scripts`` to the hook command (reinstalling without it
    takes it out again)."""
    check_args = ("--escalate-scripts",) if escalate_scripts else ()
    path = config_path(agent, user=user, project=project)
    if agent == "opencode":
        return _install_opencode_plugin(path, remove=remove, budget=budget,
                                        check_args=check_args)
    if budget is None:
        budget = budget_configured(user=user, project=project)
    existing: dict = {}
    if path.exists():
        text = path.read_text()
        if text.strip():
            existing = json.loads(text)
            if not isinstance(existing, dict):
                raise ValueError(f"{path} is not a JSON object; not touching it")
    updated = merge_config(agent, existing, None if remove else hook_command(agent, check_args),
                           budget=budget and agent in BUDGET_AGENTS)
    if remove and not updated["hooks"] and set(updated) <= {"version", "hooks"}:
        # nothing but our (now removed) hook was ever in it
        if path.exists():
            path.unlink()
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(updated, indent=2) + "\n")
    return path


_BUDGET_INSTALL_NOTE = {
    "claude": "budget: the hook sees every tool call, and UserPromptSubmit stops new prompts "
              "over the limit",
    "codex": "budget: the hook sees every tool call, and UserPromptSubmit stops new prompts "
             "over the limit",
    "gemini": "budget: the hook sees every tool call, and BeforeAgent stops new prompts over "
              "the limit",
    "copilot": "budget: the hook already sees every tool call (premium requests are "
               "counted); Copilot CLI's prompt hook cannot block, so prompts are not stopped",
    "opencode": "budget: the plugin checks every tool call wherever a budget.yaml applies "
                "(--no-budget: shell commands only); OpenCode has no prompt hook, so prompts "
                "are not stopped",
}


def main_install(agent: str, *, user: bool, project: str, remove: bool,
                 budget: bool | None = None, escalate_scripts: bool = False) -> int:
    path = install(agent, user=user, project=Path(project), remove=remove, budget=budget,
                   escalate_scripts=escalate_scripts)
    if agent == "opencode":
        budget = budget is not False   # the plugin detects a budget.yaml at run time
    elif budget is None:
        budget = budget_configured(user=user, project=Path(project))
    if remove:
        print(f"aegis: removed the {agent} hook from {path}")
        return 0
    print(f"aegis: {agent} hook written to {path}")
    if budget and agent in _BUDGET_INSTALL_NOTE:
        print(f"  {_BUDGET_INSTALL_NOTE[agent]}")
    elif budget:
        print(f"  budget: not measured for {agent} (no token data); only the policy applies")
    if escalate_scripts:
        print("  --escalate-scripts: commands that run a script, a task runner, inline or "
              "piped code ask first (block where the agent has no ask)")
    print(f"  {_AFTER_INSTALL[agent]}")
    if not user and not (Path(project) / ".aegis").is_dir():
        print(f"  No policy in {Path(project) / '.aegis'} yet, so every command is allowed "
              "until you run: aegis init .aegis")
    return 0
