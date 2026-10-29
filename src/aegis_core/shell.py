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
When that binary runs code the hook cannot read (:func:`code_run`: inline
``python3 -c``/``node -e`` code, a shell or interpreter fed through a pipe,
a script file, a task runner), the intent also carries
``params["runs_code"]`` -- kept even inside a pipeline -- so the hook can
deny inline code that names an infrastructure tool and ``--escalate-scripts``
can escalate the rest.

**Environment.** ``KUBECONFIG=/prod kubectl …`` and ``env AWS_PROFILE=prod
aws …`` land in ``metadata["env_assignments"]``; the variables the parsers
already have metadata keys for (``KUBECONFIG`` -> ``kubeconfig``,
``AWS_PROFILE`` -> ``profile``, ``AWS_DEFAULT_REGION``/``AWS_REGION`` ->
``region``, ``CLOUDSDK_CORE_PROJECT`` -> ``project``, ``HELM_NAMESPACE``
-> ``namespace``) are copied into those keys when the argv itself did not
set them (an explicit ``--namespace`` beats the environment). The
launchers that were stripped are listed in ``metadata["wrappers"]``.
"""

import functools
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent
from aegis_core.parser import from_argv, from_terraform_argv


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
    ``|``; ``stdin_pipe`` only when it reads from one (``a | b``: ``b``)."""

    argv: list[str]
    redirects: list[str] = field(default_factory=list)
    in_pipeline: bool = False
    stdin_pipe: bool = False


# --- tokenising --------------------------------------------------------------

_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
_PIPE_SEPARATORS = frozenset({"|", "|&"})
_REDIRECT_OPS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<>"})
_PUNCTUATION = frozenset("();<>|&")
_FD_MARK = "\x01"
_ESCAPE_MARK = "\x02"
# Reserved words that only group or negate ("{ a; b; }", "! cmd") -- they
# never change what runs, so they are dropped from the simple command.
_GROUPING_WORDS = frozenset({"{", "}", "!"})
# Reserved words in front of a command ("if kubectl get ns x; then kubectl delete
# ns x; fi" runs both kubectl commands) are dropped the same way. A word that only
# closes a construct, or a "for x in a b" header (its words are literal here, any
# expansion has been rejected), leaves nothing to run.
_LEADING_RESERVED = frozenset({"if", "then", "else", "elif", "do", "while", "until"})
_CLOSING_RESERVED = frozenset({"fi", "done", "esac"})
_HEADER_RESERVED = frozenset({"for", "select"})


def _strip_reserved(argv: list[str]) -> list[str]:
    """``argv`` without the grouping and reserved words in front of it, and
    without ``coproc`` (and the NAME of ``coproc NAME { …; }``); ``[]`` for a
    closing word (``fi``, ``done``) or a ``for``/``select`` header. A
    ``function NAME`` definition is rejected, like ``f() { …; }``."""
    while argv:
        if argv[0] in _GROUPING_WORDS or argv[0] in _LEADING_RESERVED:
            argv = argv[1:]
        elif argv[0] == "coproc":
            argv = argv[2:] if len(argv) > 2 and argv[2] == "{" else argv[1:]
        else:
            break
    if argv and argv[0] == "function":
        raise ShellRejected("function definition")
    if argv and (argv[0] in _HEADER_RESERVED
                 or (argv[0] in _CLOSING_RESERVED and len(argv) == 1)):
        return []
    return argv


def _prescan(command: str) -> str:
    """Quote-aware pass over the raw string, before shlex sees it: rejects
    unquoted ``$`` and backticks (shlex would strip the quotes and lose the
    distinction), turns unquoted newlines into ``;``, removes backslash-newline
    line continuations (outside single quotes and comments, as the shell does),
    drops ``#`` comments up to the newline, and marks a file
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
            if command.startswith("\n", i + 1):
                i += 2  # a line continuation: the shell removes both characters
                continue
            if not in_double and i + 1 < n and command[i + 1] in _PUNCTUATION:
                # `\;` is a literal ';' word (find -exec … \;), not a separator:
                # quoted and marked so shlex keeps it a word that never equals ';'
                out.append(f"'{_ESCAPE_MARK}{command[i + 1]}'")
                i += 2
                continue
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
        elif c == "#" and (i == 0 or command[i - 1].isspace() or command[i - 1] in ";&|()"):
            # a comment ends at the newline, whatever comes before it (a trailing
            # backslash does not continue it); dropped here so that shlex never
            # sees it run on past the "; " the newline becomes
            while i < n and command[i] != "\n":
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
    # _prescan has dropped the real comments; shlex's own would also cut a word
    # at a '#' inside it (`pods#x --as=admin` lost everything after the '#')
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:  # pragma: no cover - _prescan catches unbalanced quotes first
        raise ShellRejected(f"could not tokenise: {exc}") from exc


# Shell builtins / launchers whose effect cannot be determined statically.
_REJECTED_BUILTINS = frozenset({"eval", "exec", "source", ".", "xargs", "builtin"})


def strip_exec_builtin(argv: list[str]) -> list[str]:
    """``argv`` without a leading ``exec`` / ``builtin`` (and ``exec``'s ``-a
    NAME`` / ``-c`` / ``-l`` options), and without the ``--`` after ``source`` /
    ``.`` (also after ``command``): ``exec -a x ./x.sh`` -> ``./x.sh``, ``builtin . --
    x.sh`` -> ``. x.sh``, ``command source x.sh`` -> ``source x.sh``."""
    while argv and argv[0] in ("exec", "builtin"):
        head, argv = argv[0], argv[1:]
        while head == "exec" and argv and argv[0].startswith("-"):
            opt, argv = argv[0], argv[1:]
            if opt == "--":
                break
            if "a" in opt[1:]:
                argv = argv[1:]  # -a NAME
    if argv and argv[0] == "command":  # command [-p] source x.sh runs the builtin
        rest = argv[2:] if argv[1:2] == ["-p"] else argv[1:]
        if rest and _basename(rest[0]) in ("source", "."):
            argv = rest
    if len(argv) >= 2 and _basename(argv[0]) in ("source", ".") and argv[1] == "--":
        argv = [argv[0], *argv[2:]]
    return argv


def _check_builtin(argv: list[str]) -> None:
    if argv and _basename(argv[0]) in _REJECTED_BUILTINS:
        raise ShellRejected(f"{_basename(argv[0])!r} cannot be checked statically")


def split_compound(command: str) -> list[SimpleCommand]:
    """Splits a shell command string into its simple commands.

    Tokenises with ``shlex`` (POSIX quoting, ``punctuation_chars``) after
    the quote-aware :func:`_prescan`; splits on ``;``, ``&&``, ``||``,
    ``|``, ``|&``, ``&`` and unquoted newlines; strips redirections into
    :attr:`SimpleCommand.redirects`, the grouping words ``{`` / ``}`` /
    ``!`` (a brace group's body is checked command by command) and the reserved
    words in front of a command (``if`` / ``then`` / ``do`` / ...); a closing
    ``fi`` / ``done`` / ``esac`` and a ``for`` / ``select`` header give no
    command. Quoted
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
        argv = _strip_reserved(argv)
        if argv:
            _check_builtin(argv)
            commands.append(SimpleCommand(argv, redirects, pipeline, in_pipeline))
        argv, redirects = [], []

    for tok in _tokens(command):
        if pending_op is not None:
            redirects.append(f"{pending_fd or ''}{pending_op}{tok.replace(_ESCAPE_MARK, '')}")
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
        argv.append(tok.replace(_ESCAPE_MARK, ""))
    flush(in_pipeline)
    return commands


def split_segments(command: str) -> list[tuple[str, str]] | None:
    """Splits a command string on its top-level ``;``, ``&&``, ``||``, ``|``,
    ``|&``, ``&`` and newlines *without* rejecting anything, for a caller that
    wants to know which part of a rejected command is the problem. Returns
    ``[(segment_text, separator_after_it), …]`` -- joining ``text + separator``
    gives back the command -- or ``None`` when the quoting does not balance.
    Nothing inside quotes, ``$(…)``, ``${…}``, backticks, ``(…)`` or a
    ``#`` comment splits; ``2>&1``, ``&>`` and ``>|`` are redirections, not
    separators."""
    top = _top_level(command)
    if top is None:
        return None
    segments: list[tuple[str, str]] = []
    start = 0
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if top[i] and c in ";\n|&":
            prev = command[i - 1] if i else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if c == "&" and ((prev and prev in "<>") or nxt == ">"):
                i += 1  # 2>&1, <&3, &>file, &>>file
                continue
            if c == "|" and prev == ">":
                i += 1  # >| noclobber
                continue
            width = 2 if command[i : i + 2] in ("&&", "||", "|&", ";;") else 1
            segments.append((command[start:i], command[i : i + width]))
            i += width
            start = i
            continue
        i += 1
    segments.append((command[start:], ""))
    return segments


def _top_level(command: str) -> list[bool] | None:
    """For each character of ``command``: True when it stands at the top level
    -- outside quotes, ``$(…)``, ``${…}``, backticks, ``(…)``, a backslash
    escape and a ``#`` comment -- where the shell would split on it. ``None``
    when the quoting or parentheses do not balance."""
    flags = [False] * len(command)
    stack: list[str] = []  # open contexts: ' " $( ( ${ `
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        ctx = stack[-1] if stack else ""
        if ctx == "'":
            if c == "'":
                stack.pop()
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if ctx == "`":
            if c == "`":
                stack.pop()
            i += 1
            continue
        if ctx == '"':
            if c == '"':
                stack.pop()
            elif command.startswith(("$(", "${"), i):
                stack.append(command[i : i + 2])
                i += 1
            elif c == "`":
                stack.append("`")
            i += 1
            continue
        if ctx == "${":
            if c == "}":
                stack.pop()
            i += 1
            continue
        # top level, or inside $( … ) / ( … )
        if c in "'\"`":
            stack.append(c)
        elif command.startswith(("$(", "${"), i):
            stack.append(command[i : i + 2])
            i += 1
        elif c in "<>" and command.startswith("(", i + 1):
            stack.append("(")  # process substitution
            i += 1
        elif c == "(":
            stack.append("(")
        elif c == ")":
            if not stack:
                return None
            stack.pop()
        elif c == "#" and (i == 0 or command[i - 1].isspace() or command[i - 1] in ";&|("):
            while i < n and command[i] != "\n":
                i += 1
            continue
        elif not stack:
            flags[i] = True
        i += 1
    return None if stack else flags


def _top_level_words(segment: str) -> list[str] | None:
    """The words of ``segment`` split on top-level whitespace only, quotes and
    expansions kept as written (``TS=$(date +%s)`` is one word)."""
    top = _top_level(segment)
    if top is None:
        return None
    words, current = [], ""
    for ch, at_top in zip(segment, top, strict=True):
        if at_top and ch.isspace():
            if current:
                words.append(current)
            current = ""
        else:
            current += ch
    if current:
        words.append(current)
    return words


def loose_argv(segment: str) -> list[str] | None:
    """The words of one segment, unexpanded (``"$X"`` stays ``$X``), after the
    grouping/reserved words and the launchers in front; ``None`` when the
    words cannot be split or the launchers are themselves opaque."""
    try:
        argv = shlex.split(segment, comments=True)
    except ValueError:
        return None
    words, argv = iter(argv), []
    for t in words:
        if re.fullmatch(r"\d*(?:>>?|<|&>)", t):
            next(words, None)  # `2> /dev/null`: the target goes with the operator
        elif not t.startswith(("<", ">", "0<", "1>", "2>", "&>")):
            argv.append(t)
    try:
        argv = _strip_reserved(argv)
        if not argv:
            return []
        argv, _env, _wrappers, _string = _unwrap_inner(argv, 1)
    except ShellRejected:
        return None
    return argv


# Programs that only ever treat their arguments as data: an unknown argument
# (``echo "exit=$?"``, ``tail -n "$N"``) cannot make them run another program.
# Anything else -- find -exec, watch, ssh, trap, awk system(), docker run,
# npx, builtin, su -c, tmux, vim, flock, strace, sed's e command, … -- may, so
# a part with an unknown argument and any other program stays unknown.
# Left out on purpose: sort (--compress-program runs one), read and printf -v
# (assign a variable such as KUBECONFIG), cp/mv/ln/tee/install (can overwrite
# ~/.kube/config before kubectl runs). An output redirection to a computed or
# configuration path makes any of these unknown too (:func:`plain_binary`).
ARGS_ONLY_PROGRAMS = frozenset({
    "echo", "printf", "cat", "tac", "tail", "head", "grep", "egrep", "fgrep", "wc",
    "date", "sleep", "test", "[", "true", "false", ":", "ls", "mkdir", "rmdir",
    "uniq", "cut", "tr", "basename", "dirname", "pwd", "cd", "touch", "rm",
    "chmod", "stat", "file", "du", "df", "diff", "cmp", "comm",
    "which", "whoami", "id", "uname", "hostname", "realpath", "readlink", "seq", "nl",
    "rev", "fold", "paste", "base64", "md5sum", "sha1sum", "sha256sum", "shasum",
    "mktemp", "jq", "exit", "return", "shift", "unset",
})
# Output redirection targets that make a part unknown: computed, or a place an
# infrastructure tool reads its configuration from.
_CONFIG_TARGET_RE = re.compile(r"[$`]|\.kube|\.aws|\.config|\.azure|\.docker|\.ssh|"
                               r"\.gitconfig|\.terraformrc|\.netrc|\.pgpass|\.my\.cnf")
# Builtins that assign or declare: their NAME=value words count as assignments.
_DECLARATION_BUILTINS = frozenset({"export", "declare", "typeset", "local", "readonly"})
# Variables that change which program runs or which account/cluster it talks to.
_INFRA_ENV_PREFIXES = (
    "KUBE", "AWS_", "CLOUDSDK_", "GOOGLE_", "GCLOUD_", "AZURE_", "ARM_", "HELM_", "TF_",
    "PULUMI_", "ARGOCD_", "FLUX", "GIT_", "GH_", "PG", "MYSQL", "MONGO", "DATABASE_",
)
_INFRA_ENV_NAMES = frozenset({"PATH", "ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH",
                              "DYLD_INSERT_LIBRARIES", "HOME", "XDG_CONFIG_HOME"})


GLOB_REASON = "brace/glob in program name"


def _globbed(program: str) -> bool:
    """True when the shell may expand a program word into another name
    (``kube{,}ctl``, ``kubec?``, ``kube[c]tl``); ``[`` and ``[[`` are tests."""
    return program not in ("[", "[[") and any(ch in program for ch in "{}*?[")


def _infra_env(name: str) -> bool:
    return (name in _ENV_METADATA_KEYS or name in _INFRA_ENV_NAMES
            or name.startswith(_INFRA_ENV_PREFIXES))


def runs_expansion(segment: str) -> bool:
    """True when ``segment`` runs a command of its own through an expansion:
    ``$(…)`` (and ``$((…))``), backticks, ``<(…)`` or ``>(…)``, outside single
    quotes (inside double quotes an apostrophe is literal and ``$(…)`` and
    backticks still run)."""
    in_single = in_double = False
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if in_single:
            in_single = c != "'"
        elif c == "\\":
            i += 1
        elif c == "`" or segment.startswith("$(", i):
            return True
        elif in_double:
            in_double = c != '"'
        elif c == '"':
            in_double = True
        elif c == "'":
            in_single = True
        elif segment.startswith(("<(", ">("), i):
            return True
        i += 1
    return False


def find_heredoc(line: str) -> tuple[int, int, bool, str, bool] | None:
    """The first real here-document operator in ``line`` -- outside quotes and
    comments, ``<<`` but not ``<<<`` -- as ``(start, end, dash, tag,
    quoted)``: ``dash`` for ``<<-``, ``quoted`` when the tag is quoted (the
    body is then not expanded), ``tag`` the delimiter word with its quoting
    removed, ``""`` when the word cannot be read (an unclosed quote, ``$'…'``
    or ``$"…"`` quoting, nothing after ``<<``). ``None`` when there is none."""
    in_single = in_double = False
    closers: list[str] = []  # open $((…)), ((…)), $[…], ${…}: a `<<` there is a shift
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_single:
            in_single = c != "'"
        elif c == "\\":
            i += 1
        elif closers and line.startswith(closers[-1], i):
            i += len(closers.pop())
            continue
        elif line.startswith(("$((", "(("), i):
            closers.append("))")
            i += 3 if c == "$" else 2
            continue
        elif line.startswith(("$[", "${"), i):
            closers.append("]" if line[i + 1] == "[" else "}")
            i += 2
            continue
        elif in_double:
            in_double = c != '"'
        elif c == "'":
            in_single = True
        elif c == '"':
            in_double = True
        elif c == "#" and not closers and (
                i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|("):
            return None
        elif not closers and line.startswith("<<", i) and not line.startswith("<<<", i) and (
                i == 0 or line[i - 1] != "<"):
            j = i + 2
            dash = line.startswith("-", j)
            j += 1 if dash else 0
            while j < n and line[j] in " \t":
                j += 1
            # the delimiter is one shell word: quotes and backslashes join and
            # escape (`'END DATA'`, `E"N"D`, `END\ X`), and are removed
            k, tag, quoted, quote = j, [], False, ""
            while k < n:
                ch = line[k]
                if quote == "'":
                    if ch == "'":
                        quote = ""
                    else:
                        tag.append(ch)
                elif quote == '"':
                    if ch == '"':
                        quote = ""
                    elif ch == "\\" and k + 1 < n and line[k + 1] in '"\\$`':
                        k += 1
                        tag.append(line[k])
                    else:
                        tag.append(ch)
                elif ch == "$" and k + 1 < n and line[k + 1] in "'\"":
                    return (i, n, dash, "", True)  # $'…' / $"…": not decoded, so unknown
                elif ch in "'\"":
                    quote, quoted = ch, True
                elif ch == "\\":
                    quoted = True
                    if k + 1 < n:
                        k += 1
                        tag.append(line[k])
                elif ch.isspace() or ch in ";&|<>()":
                    break
                else:
                    tag.append(ch)
                k += 1
            if quote or (k == j):
                return (i, n, dash, "", quoted)  # cannot tell where it ends
            return (i, k, dash, "".join(tag), quoted)
        i += 1
    return None


def strip_comment(line: str) -> str:
    """``line`` without a trailing ``# comment`` (a ``#`` that starts a word,
    outside quotes)."""
    in_single = in_double = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_single:
            in_single = c != "'"
        elif c == "\\":
            i += 1
        elif in_double:
            in_double = c != '"'
        elif c == "'":
            in_single = True
        elif c == '"':
            in_double = True
        elif c == "#" and (i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|("):
            return line[:i].rstrip()
        i += 1
    return line


def plain_binary(segment: str) -> str | None:
    """For one segment of a command that was rejected: the program it runs when
    that is a literal name from :data:`ARGS_ONLY_PROGRAMS` -- ``echo`` for
    ``echo "exit=$?"``, ``tail`` for ``tail -n "$N"`` -- so only its arguments
    are unknown and none of them can run anything. ``""`` for a segment that
    only assigns (``X=$HOME``, ``export X=$Y``): no program of its own runs.
    ``None`` (unknown) for anything else: a segment that runs an expansion
    (:func:`runs_expansion`), a program outside the list, a program that is
    itself an expansion, and an assignment to a variable that changes what a
    later infrastructure tool runs or talks to (``KUBECONFIG``, ``AWS_*``,
    ``PATH``, … -- also after ``export``/``declare``/``local``/…)."""
    if runs_expansion(segment):
        return None
    words = _top_level_words(segment)
    if words is None:
        return None
    try:
        words = _strip_reserved(words)
    except ShellRejected:
        return None
    assigning = words[1:] if words and words[0] in _DECLARATION_BUILTINS else words
    assignments = [w for w in assigning if _ASSIGNMENT_RE.match(w)]
    if any(_infra_env(w.partition("=")[0]) for w in assignments):
        return None
    if words and words[0] in _DECLARATION_BUILTINS:
        if all(_ASSIGNMENT_RE.match(w) or re.fullmatch(r"[A-Za-z_]\w*|-[a-zA-Z]+", w)
               for w in words[1:]):
            return ""
        return None
    if words and len(assignments) == len(words):
        return ""
    for k, w in enumerate(words):
        target = None
        match = re.match(r"^\d*(?:>>|>\||&>>|&>|>)(.*)$", w)
        if match:
            target = match.group(1) or (words[k + 1] if k + 1 < len(words) else "")
        if target is not None and not target.startswith("&") and _CONFIG_TARGET_RE.search(target):
            return None
    argv = loose_argv(segment)
    if not argv:
        return None
    head = argv[0]
    if any(ch in head for ch in "$`()<>{}=\\'\"") or _globbed(head):
        return None
    name = _basename(head)
    if head != name and not head.startswith(_SYSTEM_PREFIXES):
        return None  # ./echo is not echo
    if name == "printf" and "-v" in argv[1:]:
        return None
    return name if name in ARGS_ONLY_PROGRAMS else None


# --- unwrapping launchers ----------------------------------------------------------

_ALIASES = {"k": "kubectl", "tf": "terraform", "tofu": "tofu", "g": "git"}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "rbash", "mksh", "yash",
                     "fish", "csh", "tcsh", "posh"})
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


@functools.lru_cache(maxsize=4096)  # called for every word, often the same few
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
            # a cluster of short options (-En, -Eu admin, -Euadmin): flags, then at
            # most one option that takes the rest of the word or the next word
            i += 1
            for k, letter in enumerate(tok[1:], start=1):
                if f"-{letter}" in _SUDO_SHELL_OPTIONS:
                    raise ShellRejected(f"sudo -{letter} opens a shell/editor")
                if letter in _SUDO_VALUE_SHORT:
                    i += 0 if tok[k + 1:] else 1  # -uadmin or -u admin
                    break
                if letter not in _SUDO_BOOL_SHORT:
                    raise ShellRejected(f"unrecognised sudo option {tok!r}")
            continue
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
        if tok in ("--split-string", "-S") or tok.startswith("--split-string="):
            string = tok.partition("=")[2] if tok.startswith("--split-string=") else (
                rest[i + 1] if i + 1 < len(rest) else "")
            rest, i = _split_env_string(string) + rest[i + (1 if "=" in tok else 2):], 0
            continue
        if tok in ("--ignore-environment", "--null", "--debug"):
            i += 1
            continue
        if tok in ("--unset", "--chdir"):
            i += 2
            continue
        if tok.startswith(("--unset=", "--chdir=")):
            i += 1
            continue
        if _ASSIGNMENT_RE.match(tok):
            key, _, value = tok.partition("=")
            assignments[key] = value
            i += 1
            continue
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            # a cluster of short options (-iv, -iC dir, -iCdir, -u NAME, -S STRING):
            # flags, then at most one option that takes the rest of the word or the next
            i += 1
            for k, letter in enumerate(tok[1:], start=1):
                if letter in "i0v":
                    continue
                if letter not in "uCS":
                    raise ShellRejected(f"unrecognised env option {tok!r}")
                value = tok[k + 1:]
                if not value:
                    value = rest[i] if i < len(rest) else ""
                    i += 1
                if letter == "S":
                    rest, i = _split_env_string(value) + rest[i:], 0
                break
            continue
        if tok.startswith("-"):
            raise ShellRejected(f"unrecognised env option {tok!r}")
        break
    return rest[i:], assignments


def _split_env_string(string: str) -> list[str]:
    """The words of ``env -S STRING``, when env splits it as the shell would:
    no escapes or ``${VAR}`` of its own, and no options of env inside it
    (``-C dir`` there would move the command where the hook does not look)."""
    try:
        words = shlex.split(string, comments=True)
    except ValueError:
        words = []
    if not words or "\\" in string or "$" in string or words[0].startswith("-"):
        raise ShellRejected("env -S re-splits its argument")
    return words


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


# More launchers: for each, (options that take a value, options without one).
# An unrecognised option is rejected, so it cannot hide the program.
_LAUNCHER_OPTIONS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "setsid": (frozenset(), frozenset({"-c", "-f", "-w", "--ctty", "--fork", "--wait"})),
    "stdbuf": (frozenset({"-i", "-o", "-e"}), frozenset()),
    "doas": (frozenset({"-u", "-C"}), frozenset({"-n"})),
    "ionice": (frozenset({"-c", "-n", "-p", "-P", "-u"}), frozenset({"-t"})),
    "caffeinate": (frozenset({"-t", "-w"}), frozenset({"-d", "-i", "-m", "-s", "-u"})),
    "unbuffer": (frozenset(), frozenset({"-p"})),
    "chronic": (frozenset(), frozenset({"-e", "-v"})),
    "busybox": (frozenset(), frozenset()),
    "watch": (frozenset({"-n", "--interval", "-q", "--equexit"}),
              frozenset({"-d", "--differences", "-t", "--no-title", "-g", "--chgexit",
                         "-e", "--errexit", "-b", "--beep", "-c", "--color", "-p",
                         "--precise", "-x", "--exec", "-w", "--no-wrap"})),
    "script": (frozenset({"-c", "--command", "-t", "--timing", "-T", "-I", "-O", "-B",
                          "-E", "--echo", "-m"}),
               frozenset({"-q", "--quiet", "-a", "--append", "-e", "--return", "-f",
                          "--flush"})),
}


# Package and environment managers whose subcommand runs a command in the
# project's environment: ``uv run kubectl …`` runs kubectl. Keyed by the
# program and the words of the subcommand; the value is (options that take a
# value, options that don't). ``--`` ends the options; any other option is
# rejected, so an unknown one cannot hide the command.
_UV_COMMON_VALUED = frozenset({
    "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index",
    "--default-index", "--index-url", "-i", "--extra-index-url", "--find-links", "-f",
    "--index-strategy", "--keyring-provider", "--resolution", "--prerelease", "--link-mode",
    "--exclude-newer", "--config-setting", "-C", "--config-file", "--cache-dir", "--color",
    "--directory", "--project", "--python-platform", "--refresh-package",
    "--reinstall-package", "--upgrade-package", "-P", "--no-binary-package",
    "--no-build-package", "--env-file", "--allow-insecure-host",
})
_UV_COMMON_FLAGS = frozenset({
    "-q", "--quiet", "-v", "--verbose", "--offline", "--no-cache", "-n", "--refresh",
    "--reinstall", "--upgrade", "-U", "--native-tls", "--no-progress", "--preview",
    "--no-config", "--isolated", "--no-python-downloads", "--no-env-file", "--no-build",
    "--no-binary", "--compile-bytecode", "--no-sources",
})
_SUBCOMMAND_LAUNCHERS: dict[tuple[str, ...], tuple[frozenset[str], frozenset[str]]] = {
    ("uv", "run"): (
        _UV_COMMON_VALUED | {"--extra", "--group", "--only-group", "--no-group", "--package",
                             "--no-extra", "--torch-backend", "--python-preference"},
        _UV_COMMON_FLAGS | {"--all-extras", "--no-dev", "--dev", "--only-dev", "--frozen",
                            "--locked", "--no-sync", "--no-project", "--active",
                            "--no-editable", "--exact", "--inexact", "--all-packages",
                            "--all-groups", "--no-default-groups", "--script", "-s",
                            "--gui-script", "--managed-python", "--no-managed-python",
                            "--no-build-isolation"}),
    ("uv", "tool", "run"): (_UV_COMMON_VALUED | {"--from"}, _UV_COMMON_FLAGS),
    ("uvx",): (_UV_COMMON_VALUED | {"--from"}, _UV_COMMON_FLAGS),
    ("pipx", "run"): (
        frozenset({"--spec", "--python", "--pip-args", "--index-url", "-i"}),
        frozenset({"--no-cache", "--path", "--pypackages", "--system-site-packages", "-q",
                   "--quiet", "-v", "--verbose", "--fetch-missing-python"})),
    ("poetry", "run"): (
        frozenset({"-C", "--directory", "-P", "--project"}),
        frozenset({"-q", "--quiet", "-v", "-vv", "-vvv", "--verbose", "-n",
                   "--no-interaction", "--ansi", "--no-ansi", "--no-plugins", "--no-cache"})),
    ("bundle", "exec"): (frozenset({"--gemfile"}), frozenset({"--keep-file-descriptors"})),
    ("asdf", "exec"): (frozenset(), frozenset()),
    ("gem", "exec"): (frozenset({"-v", "--version", "-g", "--gem"}),
                      frozenset({"--conservative", "--prerelease"})),
}
# ``mise exec [TOOL@VERSION…] -- CMD``, ``mise exec -c STRING``, ``brew bundle
# exec -- CMD``: the command follows ``--`` (or is a shell string).
_DOUBLE_DASH_LAUNCHERS: dict[tuple[str, ...], tuple[frozenset[str], frozenset[str]]] = {
    ("mise", "exec"): (frozenset({"-C", "--cd", "-E", "--env", "-j", "--jobs", "-c",
                                  "--command"}),
                       frozenset({"--raw", "-q", "--quiet", "-v", "--verbose", "-y", "--yes",
                                  "--no-prepare"})),
    ("mise", "x"): (frozenset({"-C", "--cd", "-E", "--env", "-j", "--jobs", "-c",
                               "--command"}),
                    frozenset({"--raw", "-q", "--quiet", "-v", "--verbose", "-y", "--yes",
                               "--no-prepare"})),
    ("brew", "bundle", "exec"): (frozenset({"--file"}), frozenset({"--services", "-v",
                                                                   "--verbose"})),
}


# Options of these programs that may come before the subcommand (``uv
# --directory backend run …``, ``poetry -C backend run …``): (take a value, don't).
_GLOBAL_OPTIONS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "uv": (frozenset({"--directory", "--project", "--config-file", "--cache-dir", "--color",
                      "--python-preference", "--allow-insecure-host"}),
           frozenset({"-q", "--quiet", "-v", "--verbose", "--offline", "--no-cache", "-n",
                      "--native-tls", "--preview", "--no-config", "--no-progress",
                      "--managed-python", "--no-managed-python", "--no-python-downloads"})),
    "poetry": (frozenset({"-C", "--directory", "-P", "--project"}),
               frozenset({"-q", "--quiet", "-v", "-vv", "-vvv", "--verbose", "-n",
                          "--no-interaction", "--ansi", "--no-ansi", "--no-plugins",
                          "--no-cache"})),
    "bundle": (frozenset({"--gemfile"}), frozenset({"--verbose", "--no-color", "-V"})),
    "mise": (frozenset({"-C", "--cd", "-E", "--env", "-j", "--jobs"}),
             frozenset({"-q", "--quiet", "-v", "--verbose", "-y", "--yes"})),
}


def _skip_global_options(head: str, argv: list[str]) -> int:
    """How many words of :data:`_GLOBAL_OPTIONS` follow the program name."""
    valued, flags = _GLOBAL_OPTIONS.get(head, (frozenset(), frozenset()))
    i = 1
    while i < len(argv):
        opt, eq, _glued = argv[i].partition("=")
        if opt in valued:
            i += 1 if eq else 2
        elif argv[i] in flags:
            i += 1
        else:
            break
    return min(i, len(argv)) - 1


# Launchers whose program word is a package spec with a version or extras.
_PACKAGE_SPEC_LAUNCHERS = frozenset({("uvx",), ("uv", "tool", "run"), ("pipx", "run"),
                                     ("gem", "exec")})
_PACKAGE_SPEC_RE = re.compile(r"(\[[^\]]*\])?(?:[@=<>!~:].*)?$")


def _subcommand_launcher(argv: list[str]) -> tuple[tuple[str, ...], int] | None:
    """The key of :data:`_SUBCOMMAND_LAUNCHERS` or :data:`_DOUBLE_DASH_LAUNCHERS`
    that ``argv`` starts with, and how many words it spans; ``None`` when it is
    not one (``uv pip install x``, ``pipx install x``). Options before the
    subcommand are rejected when a running subcommand follows them (``uv
    --directory d run …``): they are rare, and an option value could hide
    which subcommand runs."""
    head = _basename(argv[0])
    skip = _skip_global_options(head, argv)
    for table in (_SUBCOMMAND_LAUNCHERS, _DOUBLE_DASH_LAUNCHERS):
        for key in table:
            if key[0] != head:
                continue
            words = argv[1 + skip:len(key) + skip]
            if list(words) == list(key[1:]):
                return key, len(key) + skip
    if len(argv) > 1 + skip and argv[1 + skip].startswith("-"):
        for key in (*_SUBCOMMAND_LAUNCHERS, *_DOUBLE_DASH_LAUNCHERS):
            if len(key) > 1 and key[0] == head and key[1] in argv[2:]:
                raise ShellRejected(f"{head} option {argv[1]!r} before the {key[1]} subcommand")
    return None


def _strip_subcommand_launcher(
    key: tuple[str, ...], rest: list[str]
) -> tuple[list[str], str | None]:
    """``(argv, shell_string)`` after a subcommand launcher's options. For the
    ``--`` launchers, ``argv`` is what follows ``--`` (empty without one)."""
    double_dash = key in _DOUBLE_DASH_LAUNCHERS
    valued, flags = (_DOUBLE_DASH_LAUNCHERS if double_dash else _SUBCOMMAND_LAUNCHERS)[key]
    name = " ".join(key)
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            return rest[i + 1:], None
        if not tok.startswith("-") or tok == "-":
            if double_dash:  # mise exec node@20 -- …: tool versions until --
                i += 1
                continue
            break
        opt, eq, glued = tok.partition("=")
        if double_dash and opt in ("-c", "--command"):
            return [], glued if eq else (rest[i + 1] if i + 1 < len(rest) else "")
        if opt in valued:
            i += 1 if eq else 2
            continue
        if tok in flags:
            i += 1
            continue
        if key == ("uv", "run") and tok in ("-m", "--module"):
            return ["python", "-m", *rest[i + 1:]], None
        raise ShellRejected(f"unrecognised {name} option {tok!r}")
    if double_dash:
        return [], None
    rest = rest[i:]
    if rest and key in _PACKAGE_SPEC_LAUNCHERS:
        # uvx kubectl@latest, pipx run 'kubectl==1.0', gem exec kubectl:1.0: the program
        rest = [_PACKAGE_SPEC_RE.sub("", rest[0]) or rest[0], *rest[1:]]
    if key == ("uv", "run") and rest and rest[0].endswith(".py"):
        return ["python", *rest], None  # uv run script.py runs it with Python
    return rest, None


def _strip_launcher(head: str, rest: list[str]) -> tuple[list[str], str | None]:
    """``(argv, shell_string)`` after a launcher's options: ``shell_string``
    is set for ``script -c CMD`` and for ``watch`` without ``-x``, whose
    arguments are joined and run by ``sh -c``."""
    valued, flags = _LAUNCHER_OPTIONS[head]
    i, command, exec_mode = 0, None, False
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if not tok.startswith("-") or tok == "-":
            break
        key = tok.partition("=")[0]
        if key in ("-c", "--command") and head == "script":
            command = tok.partition("=")[2] or (rest[i + 1] if i + 1 < len(rest) else "")
            i += 1 if "=" in tok else 2
            continue
        if key in ("-x", "--exec"):
            exec_mode = True
        if key in valued:
            i += 1 if "=" in tok else 2
            continue
        if tok in flags:
            i += 1
            continue
        if len(tok) > 2 and not tok.startswith("--"):  # -oL, -n5, -qc CMD, -dn 5
            letters, step = tok[1:], 1
            for k, letter in enumerate(letters):
                if f"-{letter}" in flags:
                    continue
                if f"-{letter}" not in valued:
                    raise ShellRejected(f"unrecognised {head} option {tok!r}")
                value = letters[k + 1:] or (rest[i + 1] if i + 1 < len(rest) else "")
                step = 1 if letters[k + 1:] else 2
                if head == "script" and letter == "c":
                    command = value
                break
            i += step
            continue
        raise ShellRejected(f"unrecognised {head} option {tok!r}")
    rest = rest[i:]
    if head == "script":
        if command is None:
            raise ShellRejected("script without -c opens a shell")
        return [], command
    if head == "watch" and not exec_mode and rest:
        return [], " ".join(rest)
    return rest, None


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


# At most this many launchers (sudo, env, nice, …) are unwrapped in front of one
# command; more is not a real command line, and is rejected.
_MAX_LAUNCHERS = 32


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
        if len(wrappers) >= _MAX_LAUNCHERS:  # each one copies the words: keep it linear
            raise ShellRejected(f"more than {_MAX_LAUNCHERS} launchers in a row")
        head = _basename(argv[0])
        if _ASSIGNMENT_RE.match(argv[0]) or head == "--":
            k = 0  # a run of assignments and `--`, dropped in one copy
            while k < len(argv) and (argv[k] == "--" or _ASSIGNMENT_RE.match(argv[k])):
                key, _, value = argv[k].partition("=")
                if argv[k] != "--":
                    env[key] = value
                k += 1
            argv = argv[k:]
            continue
        if head in _REJECTED_BUILTINS:
            raise ShellRejected(f"{head!r} cannot be checked statically")
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
        launcher = _subcommand_launcher(argv)
        if launcher is not None:
            key, width = launcher
            rest, string = _strip_subcommand_launcher(key, argv[width:])
            if string is not None:  # mise exec -c "cmd": a shell string
                if depth >= 1:
                    raise ShellRejected(f"nested {' '.join(key)} command string")
                wrappers.append(" ".join(key))
                return argv, env, wrappers, string
            if not rest:
                break
            wrappers.append(" ".join(key))
            argv = rest
            continue
        if head in _LAUNCHER_OPTIONS:
            rest, string = _strip_launcher(head, argv[1:])
            if string is not None:  # watch "cmd args", script -c "cmd": a shell string
                if depth >= 1:
                    raise ShellRejected(f"nested {head} command string")
                wrappers.append(head)
                return argv, env, wrappers, string
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
# (a synthetic shell/exec intent) instead of a ValueError -- except
# ``destroy`` / ``apply -destroy``, which from_terraform_argv recognises.
_KNOWN_BINARIES = frozenset(
    {
        "kubectl", "aws", "az", "gcloud", "gsutil", "helm", "argocd", "flux", "git", "gh",
        "psql", "mysql", "sqlite3", "mongosh", "pulumi", "alembic", "flyway", "rails", "prisma",
    }
)

# Subcommands of migration tools that neither touch the database nor run
# arbitrary code (tests, generators, status): they are ordinary programs, not
# migrations. Any other subcommand the migration parser does not know is
# refused, as before (`rails db:schema:load`, `rails runner …`, `rails console`).
_DEV_TASKS = {
    "rails": frozenset({"test", "t", "server", "s", "generate", "g", "routes", "about", "stats",
                        "notes", "assets:precompile", "assets:clean", "db:migrate:status",
                        "db:version", "zeitwerk:check", "tmp:clear", "log:clear", "-v",
                        "--version", "--help", "-h"}),
    "alembic": frozenset({"current", "history", "heads", "branches", "show", "check",
                          "revision", "merge", "--version", "--help", "-h"}),
    "prisma": frozenset({"generate", "format", "validate", "version", "-v", "--version",
                         "--help", "-h", "migrate status"}),
}


# Git configuration keys whose value is a command git runs (an `alias.*` or
# `*.helper` value only when it starts with "!").
_GIT_COMMAND_KEYS = re.compile(
    r"(core\.(sshcommand|pager|editor|fsmonitor|askpass)|sequence\.editor|gpg\.program"
    r"|gpg\.\w+\.program|pager\..+|diff\..+\.(textconv|command)|filter\..+\.(clean|smudge|process)"
    r"|merge\..+\.driver|uploadpack\.packobjectshook|difftool\..+\.cmd|mergetool\..+\.cmd"
    r"|interactive\.difffilter|diff\.external|core\.gitproxy|core\.alternaterefscommand"
    r"|remote\..+\.(uploadpack|receivepack)|sendemail\.(.+\.)?(tocmd|cccmd))$")
_GIT_BANG_KEYS = re.compile(r"(alias\..+|credential(\..+)?\.helper)$")
_GIT_GLOBAL_VALUED = frozenset({"-C", "--git-dir", "--work-tree", "--namespace",
                                "--super-prefix", "--exec-path", "--list-cmds"})
# `git config` options whose value is not a key or a setting.
_GIT_CONFIG_VALUED = frozenset({"-f", "--file", "--blob", "--type", "--default", "--comment",
                                "--value", "--url"})
# Subcommands of `git submodule foreach` that only read or sync the
# submodules, so `git submodule foreach git pull` is not asked about.
_GIT_FOREACH_SAFE = frozenset({"pull", "fetch", "status", "log", "diff", "show", "checkout",
                               "switch", "rev-parse", "describe", "branch", "remote"})
# Options of git subcommands whose value is a command run on this or the
# remote side (`git clone -u CMD`, `git push --receive-pack=CMD`).
_GIT_SUBCOMMAND_OPTIONS = {
    "rebase": ("-x", "--exec"), "difftool": ("-x", "--extcmd"),
    "mergetool": ("-x", "--extcmd"), "clone": ("-u", "--upload-pack"),
    "fetch": ("--upload-pack",), "pull": ("--upload-pack",), "ls-remote": ("--upload-pack",),
    "push": ("--receive-pack", "--exec"), "send-pack": ("--receive-pack", "--exec"),
    "archive": ("--exec",),
}
_GIT_FILTER_OPTIONS = frozenset({"--tree-filter", "--index-filter", "--msg-filter",
                                 "--env-filter", "--commit-filter", "--parent-filter",
                                 "--tag-name-filter"})


def _git_config_value(key: str, value: str | None) -> list[str | None]:
    """The command a ``key=value`` git configuration makes git run: ``[]``
    when it is not a command, ``[None]`` when it is one but the value is not
    known (``--config-env``)."""
    key = key.lower()
    if _GIT_COMMAND_KEYS.match(key):
        return [value]
    if _GIT_BANG_KEYS.match(key) and (value is None or value.startswith("!")):
        return [None if value is None else value[1:]]
    if key.endswith(".helper") and _GIT_BANG_KEYS.match(key) and value.startswith("/"):
        return [value]  # an absolute helper path runs as is
    return []


def git_runs(argv: list[str]) -> list[str | None]:
    """The commands ``git …`` would run from its own arguments: command-valued
    configuration (``-c alias.x='!cmd'``, ``-c core.sshCommand=cmd``, ``git
    config core.pager cmd``) and the subcommands that run their argument
    (``bisect run``, ``submodule foreach``, ``rebase -x``, ``difftool`` /
    ``mergetool -x``, ``filter-branch --*-filter``). ``None`` stands for a
    command whose text is not on the command line."""
    runs: list[str | None] = []
    args = argv[1:]
    i = 0
    while i < len(args) and args[i].startswith("-"):  # global options
        opt, eq, glued = args[i].partition("=")
        value = glued if eq else (args[i + 1] if i + 1 < len(args) else "")
        if opt == "-c":
            key, has_value, setting = value.partition("=")
            runs += _git_config_value(key, setting if has_value else "")
        elif opt == "--config-env":
            runs += _git_config_value(value.partition("=")[0], None)
        if opt in ("-c", "--config-env") or opt in _GIT_GLOBAL_VALUED:
            i += 1 if eq else 2
            continue
        i += 1
    rest = args[i:]
    if not rest:
        return runs
    sub, sub_args = rest[0], rest[1:]
    if sub == "config":
        words, k = [], 0
        while k < len(sub_args):
            word = sub_args[k]
            k += 2 if word in _GIT_CONFIG_VALUED else 1
            if not word.startswith("-"):
                words.append(word)
        if words[:1] == ["set"]:  # git 2.46+: git config set KEY VALUE
            words = words[1:]
        if len(words) >= 2:
            runs += _git_config_value(words[0], " ".join(words[1:]))
    elif sub == "bisect" and sub_args[:1] == ["run"]:
        runs.append(" ".join(sub_args[1:]))
    elif sub == "submodule" and "foreach" in sub_args:
        tail = [w for w in sub_args[sub_args.index("foreach") + 1:]
                if w not in ("--recursive", "-q", "--quiet")]
        if len(tail) > 1 and tail[0] == "git" and tail[1] in _GIT_FOREACH_SAFE:
            runs += git_runs(tail)  # git submodule foreach git pull
        else:
            runs.append(" ".join(tail))
    else:
        options = _GIT_SUBCOMMAND_OPTIONS.get(sub, ())
        if sub == "filter-branch":
            options = tuple(_GIT_FILTER_OPTIONS)
        for k, tok in enumerate(sub_args):
            opt, eq, glued = tok.partition("=")
            if opt in options:
                runs.append(glued if eq else (sub_args[k + 1] if k + 1 < len(sub_args) else ""))
            elif len(tok) > 2 and tok[:2] in options and not tok.startswith("--"):
                runs.append(tok[2:])  # -x'cmd'
    return runs


def _is_dev_task(name: str, argv: list[str]) -> bool:
    """Whether ``argv`` runs one of :data:`_DEV_TASKS` (``rails test …``,
    ``alembic current``, ``prisma generate``, ``prisma migrate status``)."""
    tasks = _DEV_TASKS.get("rails" if name == "bin/rails" else name)
    if not tasks or len(argv) < 2:
        return False
    task = argv[1]
    if name == "prisma" and task == "migrate" and len(argv) > 2:
        task = f"migrate {argv[2]}"
    if name in ("rails", "bin/rails") and task.startswith("test:"):
        return True
    return task in tasks


# Interpreters and the flags that hand them code on the command line.
_INLINE_FLAGS = {
    "python": ("-c",), "node": ("-e", "--eval", "-p", "--print"), "perl": ("-e", "-E"),
    "ruby": ("-e",), "php": ("-r",), "bun": ("-e", "--eval", "-p", "--print"),
    "deno": ("eval",), "osascript": ("-e",), "pwsh": ("-c", "-Command"),
    "powershell": ("-c", "-Command"),
}
# Options that take a value, so the value is not mistaken for a script path.
_VALUE_FLAGS = frozenset({"-o", "+o", "-O", "+O", "-W", "-X", "-r", "--require"})
_PYTHON_RE = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")
# Task runners: what they run is in a Makefile / package.json the hook does not read.
_TASK_RUNNERS = frozenset({"make", "gmake", "just", "task", "rake", "invoke"})
_RUN_SUBCOMMANDS = {"npm": ("run", "run-script"), "pnpm": ("run",), "yarn": ("run",),
                    "bun": ("run",), "deno": ("run", "task")}
_SYSTEM_PREFIXES = ("/bin/", "/sbin/", "/usr/", "/opt/homebrew/", "/nix/")


def _interpreter(name: str) -> str | None:
    if _PYTHON_RE.match(name):
        return "python"
    return name if name in _INLINE_FLAGS or name in _SHELLS else None


# Interpreters whose short options cluster (``python3 -Ic CODE``, ``perl -lne CODE``):
# the letters that take inline code or a module, and the letters whose value is the
# rest of the cluster (``-Wignore``), after which no code letter can follow, and the
# letters followed by optional digits only (perl ``-l`` / ``-0``: ``-l012ne``).
_CLUSTERS = {
    "python": ("c", "m", "WXQ", ""),
    "perl": ("eE", "", "IMmdDxiC", "l0"),
    "ruby": ("e", "", "IrxCEFiTWK", "0"),
}


def _cluster(interp: str, tok: str) -> tuple[str, str] | None:
    """For a clustered short option ``-Ic`` / ``-Icprint(1)`` / ``-lne``: ``(letter,
    attached)`` for the code (or module) letter it contains -- ``attached`` is the rest
    of the token, empty when the value is the next argument -- else ``None``."""
    spec = _CLUSTERS.get(interp)
    if spec is None or not tok.startswith("-") or tok.startswith("--") or len(tok) < 2:
        return None
    code_letters, module_letters, valued, digits = spec
    i = 1
    while i < len(tok):
        ch = tok[i]
        if ch in code_letters or (module_letters and ch in module_letters):
            return ch, tok[i + 1:]
        if ch in valued:
            return None
        i += 1
        if ch in digits:
            while i < len(tok) and tok[i].isdigit():
                i += 1
    return None


def _stdin_file(simple: SimpleCommand) -> str | None:
    """The file a command reads its standard input from (``< x.sh``, ``0< x.sh``)."""
    for r in simple.redirects:
        body = r[1:] if r.startswith("0<") else r
        if body.startswith("<") and not body.startswith(("<<", "<>", "<&")):
            return body[1:]
    return None


def code_run(simple: SimpleCommand) -> dict[str, str] | None:
    """What a command runs that the hook cannot read: ``{"kind": "inline",
    "code": …}`` for code passed on the command line (``python3 -c``, ``python3
    -Ic``, ``node -e`` / ``--eval=…``, ``perl -lne``, …), ``{"kind": "stdin"}`` for an
    interpreter or shell reading its code from a pipe (``curl … | bash``),
    ``{"kind": "script", "path": …}`` for a script file -- named, or fed through
    ``< file`` -- or a task runner (``bash nuke.sh``, ``bash < nuke.sh``, ``./nuke.sh``,
    ``python3 x.py``, ``make destroy``, ``npm run teardown``). ``None`` for anything
    else. A shell ``-c`` never gets here: its string is unwrapped and checked like
    any other command."""
    argv = simple.argv
    if not argv:
        return None
    head = argv[0]
    name = _basename(head)
    interp = _interpreter(name)
    if interp is not None:
        flags = _INLINE_FLAGS.get(interp, ())
        rest = argv[1:]
        skip = False
        for i, tok in enumerate(rest):
            if skip:
                skip = False
                continue
            following = rest[i + 1] if i + 1 < len(rest) else ""
            if tok in flags:
                return {"kind": "inline", "interpreter": name, "code": following}
            long_flag = next((f for f in flags if f.startswith("--")
                              and tok.startswith(f + "=")), None)
            if long_flag:
                return {"kind": "inline", "interpreter": name,
                        "code": tok[len(long_flag) + 1:]}
            if interp == "python" and tok.startswith("-c") and len(tok) > 2:
                return {"kind": "inline", "interpreter": name, "code": tok[2:]}
            clustered = _cluster(interp, tok)
            if clustered is not None:
                letter, attached = clustered
                value = attached or following
                if letter == "m":
                    return {"kind": "script", "interpreter": name,
                            "path": f"-m {value}".strip()}
                return {"kind": "inline", "interpreter": name, "code": value}
            if tok == "-m" and interp == "python":
                return {"kind": "script", "interpreter": name,
                        "path": f"-m {following}".strip()}
            if tok == "-" or (interp in _SHELLS and tok == "-s"):
                break  # code from stdin
            if (tok in _VALUE_FLAGS and not (interp in _SHELLS and tok == "-r")) or (
                    interp in ("perl", "ruby") and tok in ("-I", "-C", "-x")):
                skip = True  # perl -I lib -e …: lib is a value, not the script
                continue
            if tok.startswith(("-", "+")):
                continue
            if interp in ("deno", "bun") and tok in _RUN_SUBCOMMANDS.get(interp, ()):
                return {"kind": "script", "interpreter": name, "path": following}
            return {"kind": "script", "interpreter": name, "path": tok}
        source = _stdin_file(simple)
        if source is not None:
            return {"kind": "script", "interpreter": name, "path": f"< {source}"}
        if simple.in_pipeline:
            return {"kind": "stdin", "interpreter": name}
        return None
    if name in _TASK_RUNNERS:
        targets = [t for t in argv[1:] if not t.startswith("-")]
        return {"kind": "script", "interpreter": name, "path": " ".join(targets) or "(default)"}
    if name in _RUN_SUBCOMMANDS and len(argv) > 1 and argv[1] in _RUN_SUBCOMMANDS[name]:
        return {"kind": "script", "interpreter": f"{name} {argv[1]}",
                "path": argv[2] if len(argv) > 2 else ""}
    if "/" in head and not head.startswith(_SYSTEM_PREFIXES):
        return {"kind": "script", "interpreter": "", "path": head}
    return None


# --- shell words, dequoted ------------------------------------------------------------
#
# The hook's checks for shells reading standard input match on the words the
# shell will see (`'sh'`, `"sh"` and `\sh` are all `sh`), not on the raw text,
# and model redirections in order (the last `<` is standard input). The lexer
# below follows bash's quoting: '…', "…", $'…' with its backslash escapes,
# backslashes, $(…)/<(…)/>(…) read recursively, `…`, comments, and here-document
# bodies (<<, <<-, quoted delimiters, several on one line), which are set aside
# rather than read as commands. One linear pass.

# A token: (kind, value, start, end). kind is "word" (value dequoted; a
# `$(…)`, `` `…` `` or `<(…)` stays raw inside it), "op" (a redirection
# operator, its descriptor number in front: `<`, `2>`, `<<<`, `&>`, `<&`) or
# "sep" (`;`, `&`, `&&`, `|`, `||`, `|&`, newline, `(`, `)`).
_Token = tuple[str, str, int, int]
_LEX_REDIRECT_OPS = ("&>>", "<<<", "<<-", "&>", "<<", "<>", "<&", ">>", ">&", ">|", "<", ">")
_ANSI_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b",
                   "f": "\f", "v": "\v"}
# $(…) nested deeper than this is skipped by counting brackets, not read.
_MAX_SUBSTITUTION_DEPTH = 32


@dataclass(frozen=True)
class Lexed:
    """The tokens of a command line, the here-document bodies it holds, and
    whether a quote, ``$(…)`` or backtick is left open at its end."""

    tokens: tuple[_Token, ...]
    bodies: tuple[str, ...]
    unclosed: bool
    # the command lines of the outermost $(…), <(…), >(…) and `…`
    substitutions: tuple[str, ...] = ()


def _skip_balanced(text: str, i: int, n: int) -> tuple[int, bool]:
    """The index after the `)` that closes the `(` at ``text[i]``, quotes and
    backslashes heeded, and whether it was closed (else ``n``)."""
    depth = 0
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1, n)
            if j < 0:
                return n, False
            i = j + 1
            continue
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1, True
        i += 1
    return n, False


def _skip_bodies(text: str, i: int, pending: list[tuple[str, bool]], bodies: list[str]) -> int:
    """Past the here-document bodies that start at ``i`` (one per ``<<`` on the
    line before, in order), each up to its delimiter line; collects them."""
    n = len(text)
    for delimiter, strip_tabs in pending:
        start = i
        while i < n:
            j = text.find("\n", i)
            line = text[i:n if j < 0 else j]
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
            i = n if j < 0 else j + 1
        bodies.append(text[start:i])  # never ended: the body runs to the end
        if i < n:  # past the delimiter line
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
    return i


def _scan(text: str, i: int, tokens: list[_Token], bodies: list[str], state: dict,
          depth: int, nested: bool) -> int:
    """Tokens of ``text`` from ``i`` into ``tokens``; inside a ``$(…)``
    (``nested``) up to its closing ``)``, whose index + 1 is returned."""
    n = len(text)
    pending: list[tuple[str, bool]] = []  # here-documents whose bodies start at the next line
    want: str | None = None  # a << just read: the next word is its delimiter
    parens = 0
    while i < n:
        c = text[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "#":  # a comment, where a word would start
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == ")" and nested and parens == 0:
            return i + 1
        if c in "\n;()" or (c in "|&" and not text.startswith("&>", i)):
            two = text[i:i + 2]
            sep = two if two in ("&&", "||", "|&", ";;") else c
            parens += 1 if c == "(" else -1 if c == ")" and parens else 0
            tokens.append(("sep", sep, i, i + len(sep)))
            i += len(sep)
            if c == "\n" and pending:
                i = _skip_bodies(text, i, pending, bodies)
                pending = []
            continue
        start = j = i
        while j < n and text[j].isdigit():
            j += 1
        if j < n and text[j] in "<>&" and not text.startswith(("<(", ">("), j):
            op = next((o for o in _LEX_REDIRECT_OPS if text.startswith(o, j)), None)
            if op is not None and not (op.startswith("&") and j > i):
                tokens.append(("op", text[i:j] + op, start, j + len(op)))
                want = op if op in ("<<", "<<-") else None
                i = j + len(op)
                continue
        value: list[str] = []
        while i < n:
            c = text[i]
            if c in " \t\r\n;|&()<>" and not (c in "<>" and text.startswith("(", i + 1)):
                break
            if c == "\\":
                if not text.startswith("\n", i + 1):  # else a line continuation
                    value.append(text[i + 1:i + 2])
                i += 2
            elif c == "$" and text.startswith("'", i + 1):  # $'…': backslash escapes
                i += 2
                while i < n and text[i] != "'":
                    if text[i] == "\\" and i + 1 < n:
                        value.append(_ANSI_C_ESCAPES.get(text[i + 1], text[i + 1]))
                        i += 2
                    else:
                        value.append(text[i])
                        i += 1
                state["unclosed"] |= i >= n
                i += 1
            elif c == "'":
                j = text.find("'", i + 1)
                state["unclosed"] |= j < 0
                j = n if j < 0 else j
                value.append(text[i + 1:j])
                i = j + 1
            elif c == '"':
                i += 1
                while i < n and text[i] != '"':
                    if text.startswith("$(", i):
                        j = _substitution(text, i, bodies, state, depth)
                        value.append(text[i:j])
                        i = j
                        continue
                    if text[i] == "\\" and text[i + 1:i + 2] in ('"', "\\", "$", "`", "\n"):
                        i += 1
                        if text[i] == "\n":
                            i += 1
                            continue
                    value.append(text[i:i + 1])
                    i += 1
                state["unclosed"] |= i >= n
                i += 1
            elif c in "$<>" and text.startswith("(", i + 1):  # $(…), <(…), >(…): raw
                j = _substitution(text, i, bodies, state, depth)
                value.append(text[i:j])
                i = j
            elif c == "`":
                j = text.find("`", i + 1)
                state["unclosed"] |= j < 0
                if depth == 0 and j > 0:
                    state["substitutions"].append(text[i + 1:j])
                j = n if j < 0 else j + 1
                value.append(text[i:j])
                i = j
            else:
                value.append(c)
                i += 1
        i = min(i, n)
        if not value and not text[start:i].replace("\\\n", ""):
            continue  # only line continuations
        word = "".join(value)
        tokens.append(("word", word, start, i))
        if want is not None:
            pending.append((word, want == "<<-"))
            want = None
    if nested:
        state["unclosed"] = True  # a $( never closed
    return n


def _substitution(text: str, i: int, bodies: list[str], state: dict, depth: int) -> int:
    """The index after the ``$(…)``/``<(…)``/``>(…)`` at ``i``, read as a
    command line of its own (its here-documents included)."""
    if depth >= _MAX_SUBSTITUTION_DEPTH:
        j, closed = _skip_balanced(text, i + 1, len(text))
        state["unclosed"] |= not closed
        return j
    j = _scan(text, i + 2, [], bodies, state, depth + 1, True)
    if depth == 0:
        state["substitutions"].append(text[i + 2:j - 1])
    return j


@functools.lru_cache(maxsize=32)
def lex(text: str) -> Lexed:
    """The tokens of ``text`` (see :data:`_Token`). Never raises; an unclosed
    quote runs to the end and is reported in :attr:`Lexed.unclosed`."""
    tokens: list[_Token] = []
    bodies: list[str] = []
    state: dict = {"unclosed": False, "substitutions": []}
    _scan(text, 0, tokens, bodies, state, 0, False)
    return Lexed(tuple(tokens), tuple(bodies), state["unclosed"], tuple(state["substitutions"]))


def _shell_tokens(text: str) -> tuple[_Token, ...]:
    return lex(text).tokens


def dequoted(text: str) -> str:
    """``text`` as the words the shell sees, joined by spaces (separators and
    operators kept), for the checks that look for a program by name."""
    return " ".join(value for _kind, value, _s, _e in _shell_tokens(text))


_READER_NAME_RE = re.compile(
    rf"(?:{'|'.join(sorted(_SHELLS))}|python[\d.]*|perl|ruby|node|php|lua)")


def _readers(tokens: tuple[_Token, ...]) -> list[int]:
    """The indexes of the words that name a shell or interpreter (``sh``,
    ``'sh'``, ``\\sh``, ``/bin/sh``, ``/usr/bin/python3``)."""
    return [k for k, (kind, value, _s, _e) in enumerate(tokens)
            if kind == "word" and _READER_NAME_RE.fullmatch(_basename(value))]


def _c_string_at(tokens: tuple[_Token, ...], k: int) -> int | None:
    """For a shell word at ``k``: the index of its ``-c`` string word, after
    its options (``-o NAME``, clusters, ``--long``; at most a few dozen words,
    so callers stay linear); ``None`` when it has none."""
    if _basename(tokens[k][1]) not in _SHELLS:
        return None
    j = k + 1
    while j < min(len(tokens), k + 64) and tokens[j][0] == "word":
        word = tokens[j][1]
        if word in ("-o", "+o", "-O", "+O"):
            j += 2
        elif re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", word):
            return j + 1 if j + 1 < len(tokens) and tokens[j + 1][0] == "word" else None
        elif re.fullmatch(r"[-+][a-zA-Z]+|--[\w-]+", word):
            j += 1
        else:
            return None
    return None


def _eval_words_end(tokens: tuple[_Token, ...], k: int) -> int:
    """For an ``eval`` word at ``k``: the index after its words."""
    j = k + 1
    while j < len(tokens) and tokens[j][0] == "word":
        j += 1
    return j


def _inner_commands(text: str) -> list[tuple[str, int, int]]:
    """The command lines one level inside ``text``: each ``sh -c`` string and
    the words of each ``eval`` (joined), with the range of ``text`` they take
    up (from the shell or ``eval`` word to the string or last word). An
    ``eval``'s words are not searched again for a ``-c`` string at this level;
    that is the next level's job."""
    tokens = _shell_tokens(text)
    found = []
    k = 0
    while k < len(tokens):
        kind, value, start, _end = tokens[k]
        if kind == "word" and value == "eval":
            j = _eval_words_end(tokens, k)
            if j > k + 1:
                found.append((" ".join(t[1] for t in tokens[k + 1:j]), start, tokens[j - 1][3]))
            k = j
            continue
        if kind == "word":
            j = _c_string_at(tokens, k)
            if j is not None:
                found.append((tokens[j][1], start, tokens[j][3]))
                k = j + 1
                continue
        k += 1
    return found


def nested_commands(command: str, depth: int = 0) -> list[str]:
    """``command`` and the command lines inside it: ``sh -c`` strings, the
    words of ``eval``, here-document bodies and command substitutions, to four
    levels (each level is part of the one above, so this stays linear)."""
    found = [command]
    if depth >= 4:
        return found
    inner = [string for string, _s, _e in _inner_commands(command)]
    lexed = lex(command)
    for text in dict.fromkeys([*inner, *lexed.bodies, *lexed.substitutions]):
        if text:
            found += nested_commands(text, depth + 1)
    return found


# Where a loose part ends: the shell's separators, and the edges of $(…), `…`,
# <(…), >(…), (…), { …; } and case patterns.
_LOOSE_SPLIT_RE = re.compile(r"(\|\||&&|;;|\$\(|[<>]\(|[;|&\n()`])")


def script_runs_loosely(command: str, _depth: int = 0) -> list[dict[str, str]]:
    """Best effort for a command the parser rejected (``bash x.sh "$TARGET"``,
    ``OUT=$(bash x.sh)``, ``for i in 1 2; do ./x.sh "$i"; done``): splits it on
    the shell's separators and on the edges of command substitutions, process
    substitutions, subshells and groups, without expanding anything; strips
    reserved words and launchers, reads one level of ``sh -c STRING``, and
    returns what :func:`code_run` finds in each part. Never raises; only for
    asking, never for allowing."""
    found = []
    if _depth < 4:
        # a sh -c string or eval's words hold separators of their own: read them
        # on their own (bash -c 'set -e; bash x.sh "$@"', eval 'bash x.sh; true'),
        # dequoted as the shell does ('\'' included), before the split cuts them up
        kept, at = [], 0
        for inner, start, end in _inner_commands(command):
            found.extend(script_runs_loosely(inner, _depth + 1))
            kept.append(command[at:start] + " ")
            at = end
        command = "".join(kept) + command[at:]
    pieces = _LOOSE_SPLIT_RE.split(command)
    opened: list[str] = []  # brackets and backticks still open
    continuation = False  # this part follows a closing `)`/`` ` ``: the rest of a word
    for k, part in enumerate(pieces):
        if k % 2:  # a delimiter
            if part in ("$(", "<(", ">(", "("):
                opened.append("(")
                continuation = False
            elif part == ")":
                # closes a bracket (`$(pwd)/x.sh` goes on as one word), or ends a
                # case pattern (`a) bash x.sh`), after which a command starts
                continuation = bool(opened)
                if opened:
                    opened.pop()
            elif part == "`":
                if opened and opened[-1] == "`":
                    opened.pop()
                    continuation = True
                else:
                    opened.append("`")
                    continuation = False
            else:
                continuation = False
            continue
        if continuation:
            continue
        try:
            argv = shlex.split(part, comments=False)
        except ValueError:
            continue
        try:
            argv = _strip_reserved(argv)
        except ShellRejected:
            continue
        argv = strip_exec_builtin(argv)  # exec bash x.sh, builtin source x.sh
        if not argv:
            continue
        if argv[0] == "eval":  # eval 'bash x.sh': its words are a command line
            evals = 0
            while evals < len(argv) and argv[evals] == "eval":
                evals += 1  # eval eval eval …: one join for the whole chain
            if _depth < 4:
                found.extend(script_runs_loosely(" ".join(argv[evals:]), _depth + 1))
            continue
        redirects = [t for t in argv if t.startswith(("<", "0<"))]
        argv = [t for t in argv if not t.startswith(("<", "0<"))]  # linear: no `in` list
        if argv and _basename(argv[0]) in ("source", "."):
            found.append({"kind": "script", "interpreter": argv[0],
                          "path": argv[1] if len(argv) > 1 else ""})
            continue
        try:
            argv, _env, _wrappers, string = _unwrap_inner(argv, 0 if _depth == 0 else 1)
        except ShellRejected:
            continue
        if string is not None:
            found.extend(script_runs_loosely(string, _depth + 1))
            continue
        runs = code_run(SimpleCommand(argv, redirects))
        if runs is not None:
            found.append(runs)
    return found


# Words that name a script to run, rather than a file to read.
_SCRIPT_WORD_RE = re.compile(r"^(?:\.{1,2}/|~/)|\.(?:sh|bash|zsh|ksh|py|rb|pl|js|mjs|php|lua)$")


def opaque_launcher_code(command: str) -> str | None:
    """Best effort for a command the parser rejected: a shell, interpreter or
    script named after a launcher the parser could not unwrap (an option of
    ``env``/``sudo``/… it does not know, ``sudo -i``, an ``env -S`` string it
    does not split), so what the launcher runs is unknown: ``env -P x bash
    x.sh``, ``sudo -iu bob bash x.sh``, ``cat x.sh | env -Q sh``. Returns that
    word, else ``None``. Never raises; only for asking."""
    for part in _LOOSE_SPLIT_RE.split(command)[::2]:
        try:
            argv = strip_exec_builtin(_strip_reserved(shlex.split(part, comments=False)))
        except (ShellRejected, ValueError):
            continue
        if not argv or _basename(argv[0]) in _REJECTED_BUILTINS:
            continue  # eval/source/xargs …: their own checks
        try:
            _unwrap_inner(list(argv), 0)
        except ShellRejected:
            for word in " ".join(argv[1:]).split():  # env -S 'bash x.sh': two words
                if _interpreter(_basename(word)) or _SCRIPT_WORD_RE.search(word):
                    return word
    return None


def stdin_feeders(command: str) -> list[tuple[list[str], list[str] | None]]:
    """For a command that parses: ``(reader_argv, feeder_argv)`` for each shell
    or interpreter reading its code from a pipe; ``feeder_argv`` is the command
    writing into that pipe (``None`` when the reader only writes into one)."""
    found: list[tuple[list[str], list[str] | None]] = []
    previous: SimpleCommand | None = None
    for simple, _env, _wrappers in _expand(command, 0):
        if not simple.argv:
            continue
        feeder, previous = (previous if simple.stdin_pipe else None), simple
        runs = code_run(simple)
        if runs is not None and runs["kind"] == "stdin":
            found.append((simple.argv, feeder.argv if feeder is not None else None))
    return found


_HEREDOC_OPS = ("<<<", "<<-", "<<")


def _stdin_reader(argv: list[str], depth: int = 0) -> str | None:
    """The shell or interpreter that ``argv`` runs reading its code from
    standard input, through ``exec``/``builtin``/``eval``, launchers and a
    ``-c`` string, any part of which may be it (``eval sh``, ``bash -c 'eval
    sh'``, ``sh -c '(sh)'``, ``eval 'true; sh'``); at most four levels. Never
    raises."""
    if depth > 4:
        return None
    try:
        argv = strip_exec_builtin(_strip_reserved(argv))
        evals = 0
        while evals < len(argv) and argv[evals] == "eval":
            evals += 1
        if evals:  # eval WORDS: the words, joined, are read again as a command line
            return _string_reader(" ".join(argv[evals:]), depth + 1)
        if not argv:
            return None
        argv, _env, _wrappers, string = _unwrap_inner(argv, 0)
        if string is not None:
            return _string_reader(string, depth + 1)
        name = _basename(argv[0])
        if _interpreter(name) and code_run(SimpleCommand(argv)) is None:
            return name
    except (ShellRejected, ValueError):
        pass
    return None


def string_reader(text: str) -> str | None:
    """The shell or interpreter a command-list string (``eval sh``, ``true;
    sh``) runs reading standard input; ``None`` when there is none."""
    return _string_reader(text, 0)


def _string_reader(text: str, depth: int) -> str | None:
    """:func:`_stdin_reader` for each part of a command list given as a string."""
    for part in re.split(r"[;&|(){}\n]", text):
        try:
            words = shlex.split(part, comments=True)
        except ValueError:
            continue
        reader = _stdin_reader(words, depth) if words else None
        if reader:
            return reader
    return None


def loose_code_reader(command: str, _depth: int = 0) -> str | None:
    """Best effort for a command the parser rejected: when a shell or
    interpreter with no script or inline-code argument reads its code from a
    pipe or a here-document/here-string (``base64 -d <<< … | sh``, ``sh <<<
    "$(…)"``, ``cat <<EOF | bash``), what feeds it (the program before the
    pipe, or ``"a here-document"``); else ``None``. Never raises."""
    segments = split_segments(command)
    if segments is None:
        match = re.search(r"(?:^|[|;&(\s])((?:ba|z|da|k|a)?sh|python[\d.]*|node|perl|ruby)"
                          r"(?:\s+-\S+)*\s*<<", command)
        return "a here-document" if match else None
    after_pipe = False
    previous = ""
    for text, sep in segments:
        inner = text.strip()
        opened = len(inner) - len(inner.lstrip("("))
        closed = len(inner) - len(inner.rstrip(")"))
        if min(opened, closed) and _depth < 4:  # a subshell: (cd x; … | sh)
            found = loose_code_reader(inner[min(opened, closed):-min(opened, closed)],
                                      _depth + 1)
            if found is not None:
                return found
        try:  # the brackets of a subshell are not part of its words
            words = shlex.split(inner.lstrip("(").rstrip(")"), comments=False)
        except ValueError:
            words = []
        heredoc = any(w.startswith(_HEREDOC_OPS) for w in words)
        argv: list[str] = []
        skip = False
        depth = 0  # inside a redirection target's $(…) / `…`: <<< $(cat x.sh)
        for w in words:
            if depth:
                depth = max(0, depth + w.count("(") - w.count(")")
                            + (1 if w.count("`") % 2 else 0) * (-1 if depth else 1))
                continue
            if skip:
                skip = False
                depth = max(0, w.count("(") - w.count(")")) + (w.count("`") % 2)
                continue
            if w in _HEREDOC_OPS or w in _REDIRECT_OPS:
                skip = True
                continue
            if w.startswith(("<", ">", "0<", "1>", "2>", "&>")):
                target = w.lstrip("0123456789<>&")
                depth = max(0, target.count("(") - target.count(")")) + (target.count("`") % 2)
                continue
            argv.append(w)
        reader = _stdin_reader(argv)
        if reader and (heredoc or after_pipe):
            return "a here-document" if heredoc else (previous or "a pipe")
        after_pipe = sep in _PIPE_SEPARATORS
        previous = _basename(argv[0]) if argv else ""
    return None


_ENV_METADATA_KEYS = {
    "KUBECONFIG": "kubeconfig",
    "AWS_PROFILE": "profile",
    "AWS_DEFAULT_REGION": "region",
    "AWS_REGION": "region",
    "CLOUDSDK_CORE_PROJECT": "project",
    "HELM_NAMESPACE": "namespace",
}


_FIND_EXEC_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})


def find_exec_commands(argv: list[str]) -> list[list[str]]:
    """The commands ``find`` runs for each file: the words after ``-exec``,
    ``-execdir``, ``-ok`` or ``-okdir`` up to ``;`` or ``+`` (``{}``, the file,
    stays a literal argument). ``[]`` for anything but ``find``."""
    if not argv or _basename(argv[0]) != "find":
        return []
    found: list[list[str]] = []
    i = 1
    while i < len(argv):
        if argv[i] in _FIND_EXEC_FLAGS:
            j = i + 1
            while j < len(argv) and argv[j] not in (";", "+"):
                j += 1
            if j == len(argv):
                raise ShellRejected(f"find {argv[i]} without ';' or '+'")
            if j == i + 1:
                raise ShellRejected(f"find {argv[i]} without a command")
            found.append(argv[i + 1 : j])
            i = j
        i += 1
    return found


def _expand(
    command: str, depth: int
) -> Iterator[tuple[SimpleCommand, dict[str, str], list[str]]]:
    for simple in split_compound(command):
        argv, env, wrappers, string = _unwrap_inner(simple.argv, depth)
        if string is None:
            yield (SimpleCommand(argv, simple.redirects, simple.in_pipeline, simple.stdin_pipe),
                   env, wrappers)
            for inner_argv in find_exec_commands(argv):
                for inner, inner_env, inner_wrappers in _expand(shlex.join(inner_argv),
                                                                depth + 1):
                    yield (SimpleCommand(inner.argv, inner.redirects),
                           {**env, **inner_env}, [*wrappers, "find -exec", *inner_wrappers])
            continue
        for inner, inner_env, inner_wrappers in _expand(string, depth + 1):
            yield (
                SimpleCommand(
                    inner.argv,
                    [*simple.redirects, *inner.redirects],
                    simple.in_pipeline or inner.in_pipeline,
                    simple.stdin_pipe or inner.stdin_pipe,
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


def intents_from_command(command: str, *,
                         keep_pipeline_stages: bool = False) -> list[InfrastructureIntent]:
    """Every InfrastructureIntent a shell command string would give rise
    to: :func:`split_compound` -> :func:`unwrap` -> ``from_argv`` for each
    simple command whose binary Aegis knows. Inside a pipeline, unknown
    binaries (``| grep x``) produce nothing unless ``keep_pipeline_stages``
    (the hook's own checks of their arguments); on their own they produce the
    synthetic ``shell`` / ``binary/<name>`` / ``exec`` intent described in
    the module docstring. Environment assignments and stripped launchers
    are recorded in each intent's metadata.

    Raises :class:`ShellRejected` (a ``ValueError``) for the shell
    constructs that cannot be checked statically, and ``ValueError`` from
    the underlying parser for a known binary with an argv it cannot make
    sense of — both are the caller's cue to fail closed.
    """
    intents: list[InfrastructureIntent] = []
    previous: SimpleCommand | None = None
    for simple, env, wrappers in _expand(command, 0):
        if not simple.argv:
            continue
        feeder, previous = (previous if simple.stdin_pipe else None), simple
        if _globbed(simple.argv[0]):
            raise ShellRejected(GLOB_REASON, simple.argv[0])  # .command: the program word
        name = _basename(simple.argv[0])
        destroy = (
            from_terraform_argv(simple.argv) if name in ("terraform", "tofu") else None
        )
        if destroy is not None:
            produced = destroy
        elif name in _KNOWN_BINARIES and not _is_dev_task(name, simple.argv):
            produced = from_argv(simple.argv)
        else:
            runs = code_run(simple)
            if simple.in_pipeline and runs is None and not keep_pipeline_stages:
                continue
            params: dict[str, Any] = {"argv": list(simple.argv)}
            if runs is not None:
                if runs["kind"] == "stdin" and feeder is not None:
                    runs = {**runs, "producer": _basename(feeder.argv[0])}
                params["runs_code"] = runs
            produced = [
                InfrastructureIntent(
                    resource=f"binary/{name}",
                    action="exec",
                    provider="shell",
                    params=params,
                )
            ]
        if name == "git":
            commands = git_runs(simple.argv)
            if commands:
                for intent in produced:
                    intent.metadata["runs_commands"] = commands
        for intent in produced:
            _annotate(intent, env, wrappers, simple)
        intents.extend(produced)
    return intents
