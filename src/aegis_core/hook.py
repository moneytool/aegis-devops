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
checks ``terraform plan`` and lets ``echo`` through; only a part that cannot
be checked and names an infrastructure tool (or whose binary is itself
unknown, in a command that names one) is refused, by name.

**Code the command does not show.** A shell or interpreter reading code from
a pipe whose producer is not a literal ``echo``/``printf`` (``curl … | sh``,
``base64 -d | sh``) asks. A local shell script (``bash x.sh``, ``sh < x.sh``,
``./x.sh``, ``source x.sh``) is read, up to 64 KiB and without following
what it sources, and its lines that name an infrastructure tool are checked
as commands: a blocked line blocks, a line that cannot be checked asks.

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
    ShellRejected,
    intents_from_command,
    plain_binary,
    script_runs_loosely,
    split_segments,
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


def mentions_infra(command: str) -> bool:
    """True when an infrastructure binary appears as a word anywhere in the
    command text (used only when the command could not be parsed)."""
    return bool(_INFRA_WORD_RE.search(command))


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
# Producers whose output is the literal text on the command line.
_LITERAL_PRODUCERS = frozenset({"echo", "printf"})
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")


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


def _decide(command: str, config_dir: Path, extra_args: list[str] | None, cwd: Path, *,
            scan: bool, rebuilt: bool = False) -> HookVerdict:
    escalate_scripts = "--escalate-scripts" in (extra_args or [])
    try:
        intents = intents_from_command(command)
    except ShellRejected as exc:
        if rebuilt:  # cannot happen: every part of a rebuilt command parsed on its own
            return _rejected(command, exc.reason, config_dir, extra_args, cwd,
                             scan=scan, escalate_scripts=escalate_scripts)
        part = _checkable_part(command, exc, config_dir, extra_args, cwd,
                               scan=scan, escalate_scripts=escalate_scripts)
        if isinstance(part, HookVerdict):
            return part
        checkable, asks = part
        if not checkable.strip(" \t\n;&|"):
            return _with_asks(HookVerdict("allow"), asks)
        verdict = _decide(checkable, config_dir, extra_args, cwd, scan=scan, rebuilt=True)
        return _with_asks(verdict, asks)
    except ValueError as exc:  # a known binary with an argv its parser rejects
        return HookVerdict("deny", f"aegis: cannot parse this command: {exc}")
    asks: list[str] = []
    for intent in intents:
        runs = intent.params.get("runs_code") if intent.provider == "shell" else None
        if runs is None:
            continue
        hidden = runs.get("code", "") if runs["kind"] == "inline" else command
        if runs["kind"] in ("inline", "stdin") and mentions_infra(hidden):
            how = "on the command line" if runs["kind"] == "inline" else "through a pipe"
            return HookVerdict(
                "deny",
                f"aegis: cannot check code passed to {runs['interpreter']} {how}, and it "
                "names an infrastructure tool; run the infrastructure command on its own",
            )
        producer = runs.get("producer")
        if runs["kind"] == "stdin" and producer and (
                rebuilt or producer not in _LITERAL_PRODUCERS):
            # In a rebuilt command an echo may stand for `echo "$X"`, so it is opaque too.
            asks.append(
                f"aegis: {runs['interpreter']} runs code piped from {producer}, which the "
                "hook cannot read; save it to a file and run that, so its commands are checked")
        if runs["kind"] == "script" and scan:
            verdict = _scan_script(runs, config_dir, extra_args, cwd)
            if verdict is not None:
                if verdict.decision == "deny":
                    return verdict
                asks.append(verdict.reason)
    return _with_asks(_policy(command, config_dir, extra_args), asks)


def _rejected(command: str, reason: str, config_dir: Path, extra_args: list[str] | None,
              cwd: Path, *, scan: bool, escalate_scripts: bool) -> HookVerdict:
    """A command (or a part of it) that cannot be parsed, judged as a whole:
    deny when it names an infrastructure tool, ask for code generated at run
    time, check the local shell scripts it names, else allow."""
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
    scripts = script_runs_loosely(command)
    if scan:
        for runs in scripts:
            verdict = _scan_script(runs, config_dir, extra_args, cwd)
            if verdict is not None:
                return verdict
    if escalate_scripts and scripts:
        return HookVerdict(
            "ask", "aegis: this runs a local script, which the hook cannot read "
            "(--escalate-scripts)")
    return HookVerdict("allow")


def _checkable_part(command: str, exc: ShellRejected, config_dir: Path,
                    extra_args: list[str] | None, cwd: Path, *, scan: bool,
                    escalate_scripts: bool) -> HookVerdict | tuple[str, list[str]]:
    """For a command that cannot be parsed as a whole (issue #55): judges it
    part by part (``;``, ``&&``, ``||``, ``|``, newline). A part that cannot be
    checked and names an infrastructure tool is a deny that names it. A part
    whose binary is a plain, known name (``echo "exit=$?"``, ``tail -n "$N"``)
    stands in as that bare binary; one that only assigns variables, or sources a
    local script (read like ``bash x.sh``), drops out. Returns the command
    rebuilt from the parts that can be checked, plus pending asks -- or a
    verdict, when a part's binary is itself unknown (``$K …``, ``eval …``,
    ``bash -c "$X"``): deny when the command names an infrastructure tool
    anywhere, else the whole-command rules of :func:`_rejected`."""
    # a here-doc's body lines are data, not commands: judged as a whole, as before
    segments = None if "<<" in command else split_segments(command)
    if not segments:
        return _rejected(command, exc.reason, config_dir, extra_args, cwd,
                         scan=scan, escalate_scripts=escalate_scripts)
    pieces: list[str] = []
    asks: list[str] = []
    opaque: tuple[str, str] | None = None
    for text, sep in segments:
        try:
            intents_from_command(text)
        except ShellRejected as seg_exc:
            reason = seg_exc.reason
        except ValueError:  # a parser error: kept, so the full check reports it
            pieces.append(text + sep)
            continue
        else:
            pieces.append(text + sep)
            continue
        shown = text.strip()
        if mentions_infra(text):
            return HookVerdict(
                "deny",
                f"aegis: cannot check this command statically ({reason}) in {shown!r}; "
                "run the infrastructure command on its own, without shell expansion",
                unchecked=True,
            )
        sourced = _sourced_script(text)
        if sourced is not None:
            verdict = _scan_script(sourced, config_dir, extra_args, cwd) if scan else None
            if verdict is not None and verdict.decision == "deny":
                return verdict
            if verdict is not None:
                asks.append(verdict.reason)
            elif escalate_scripts:
                asks.append("aegis: this runs a local script, which the hook cannot read "
                            "(--escalate-scripts)")
            pieces.append(sep)
            continue
        binary = plain_binary(text)
        if binary is None:
            opaque = opaque or (shown, reason)
            continue
        pieces.append((shlex.quote(binary) if binary else "") + sep)
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
    return "".join(pieces), asks


def _sourced_script(segment: str) -> dict[str, str] | None:
    """``source x.sh`` / ``. x.sh`` with a literal path, as a ``runs_code``
    record; else ``None``."""
    try:
        words = shlex.split(segment, comments=True)
    except ValueError:
        return None
    if len(words) >= 2 and words[0] in ("source", ".") and not any(
            ch in words[1] for ch in "$`<>()"):
        return {"kind": "script", "interpreter": words[0], "path": words[1]}
    return None


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """``(line_number, line)`` with backslash-newline continuations joined."""
    out: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending += line[:-1] + " "
            continue
        out.append((start, pending + line))
        pending = ""
    if pending:
        out.append((start, pending))
    return out


def _scan_script(runs: dict, config_dir: Path, extra_args: list[str] | None,
                 cwd: Path) -> HookVerdict | None:
    """Reads a local shell script that a command runs (``bash x.sh``, ``sh <
    x.sh``, ``./x.sh``, ``source x.sh``; issue #56) and checks every line that
    names an infrastructure tool as a command of its own. ``None`` when there
    is nothing to say: not a shell script, no such file, or no such line, or
    every such line allowed. A blocked line denies; a line that cannot be
    checked, a file that cannot be read or is larger than
    :data:`SCRIPT_SCAN_LIMIT`, or more than :data:`SCRIPT_SCAN_MAX_LINES` such
    lines, asks. What the script sources or runs in turn is not read."""
    from aegis_core.shell import _SHELLS, _basename

    interpreter = _basename(runs.get("interpreter", "") or "")
    path = runs.get("path", "") or ""
    if path.startswith("< "):
        path = path[2:]
    if interpreter and interpreter not in _SHELLS and interpreter not in ("source", "."):
        return None
    if not path or path.startswith("-") or any(ch in path for ch in "$`"):
        return None
    file = Path(path).expanduser()
    if not file.is_absolute():
        file = cwd / file
    try:
        if not file.is_file():
            return None
        with file.open("rb") as handle:
            data = handle.read(SCRIPT_SCAN_LIMIT + 1)
    except OSError as exc:
        return HookVerdict("ask", f"aegis: cannot read {path} to check the commands in it "
                                  f"({exc.strerror or exc})")
    if len(data) > SCRIPT_SCAN_LIMIT:
        return HookVerdict("ask", f"aegis: {path} is larger than {SCRIPT_SCAN_LIMIT // 1024} "
                                  "KiB, so the commands in it were not checked")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None  # a binary, not a shell script
    if not interpreter:  # ./x: a shell script only by its #! line or name
        first = text.split("\n", 1)[0]
        if first.startswith("#!"):
            words = first[2:].split()
            program = _basename(words[0]) if words else ""
            if program == "env" and len(words) > 1:
                program = _basename(words[1])
            if program not in _SHELLS:
                return None
        elif not path.endswith(_SHELL_SUFFIXES):
            return None
    lines = [(n, line) for n, line in _logical_lines(text)
             if not line.lstrip().startswith("#") and mentions_infra(line)]
    if not lines:
        return None
    if len(lines) > SCRIPT_SCAN_MAX_LINES:
        return HookVerdict("ask", f"aegis: {path} names an infrastructure tool on more than "
                                  f"{SCRIPT_SCAN_MAX_LINES} lines, so they were not checked")
    combined = _decide("\n".join(line for _n, line in lines), config_dir, extra_args, cwd,
                       scan=False)
    if combined.decision == "allow":
        return None
    first_ask: HookVerdict | None = None
    for number, line in lines:
        verdict = _decide(line, config_dir, extra_args, cwd, scan=False)
        if verdict.decision == "allow":
            continue
        located = f"{path} line {number}: {line.strip()!r}"
        if verdict.decision == "deny" and not verdict.unchecked:
            return HookVerdict("deny", f"{verdict.reason} ({located})")
        if first_ask is None:
            reason = verdict.reason.removeprefix("aegis: ")
            first_ask = HookVerdict("ask", f"aegis: {located}: {reason}")
    if first_ask is not None:
        return first_ask
    return HookVerdict(combined.decision if not combined.unchecked else "ask",
                       f"{combined.reason} ({path})")


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
