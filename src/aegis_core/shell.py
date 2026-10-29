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
    # the program word holds a glob character the shell expands (unquoted where
    # it is written, in the text this command was read from)
    globbed: bool = False


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
# Words that end a shell's options: the next word is the -c string or script
# (bash -c - 'cmd', bash - x.sh, bash -- x.sh).
SHELL_OPTIONS_END = frozenset({"--", "-"})
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
    i = 0  # one slice at the end: a long run of `!`/`{` stays linear
    while i < len(argv):
        if argv[i] in _GROUPING_WORDS or argv[i] in _LEADING_RESERVED:
            i += 1
        elif argv[i] == "coproc":
            i += 2 if len(argv) > i + 2 and argv[i + 2] == "{" else 1
        else:
            break
    argv = argv[i:]
    if argv and argv[0] == "function":
        raise ShellRejected("function definition")
    if argv and (argv[0] in _HEADER_RESERVED
                 or (argv[0] in _CLOSING_RESERVED and len(argv) == 1)):
        return []
    return argv


def _prescan(command: str) -> str:
    """Quote-aware pass over the raw string, before shlex sees it: rejects
    unquoted ``$`` and backticks (shlex would strip the quotes and lose the
    distinction), turns unquoted newlines into ``;`` (not after a trailing
    ``|``, ``|&``, ``&&`` or ``||``, which go on past them), removes
    backslash-newline line continuations (outside single quotes and comments, as the shell does),
    drops ``#`` comments up to the newline, and marks a file
    descriptor glued to a redirection (``2>&1`` -> ``\\x012>&1``) so it is
    not mistaken for an argument."""
    out: list[str] = []
    i, n = 0, len(command)
    in_single = in_double = False
    tail = ""  # the last two characters outside quotes and comments: `|`, `&&`, …
    while i < n:
        c = command[i]
        if not (in_single or in_double or c in " \t\r\n" or (c == "#" and (
                i == 0 or command[i - 1].isspace() or command[i - 1] in ";&|()"))
                or (c == "\\" and command.startswith("\n", i + 1))):  # a continuation
            tail = (tail + c)[-2:]
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
            # after a trailing |, |&, && or || the command goes on past the newline
            joined = tail.endswith("|") or tail.endswith(("&&", "|&"))
            out.append(" " if joined else " ; ")
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
    i = 0  # one slice at the end: exec exec … stays linear
    while i < len(argv) and argv[i] in ("exec", "builtin"):
        head = argv[i]
        i += 1
        while head == "exec" and i < len(argv) and argv[i].startswith("-"):
            opt = argv[i]
            i += 1
            if opt == "--":
                break
            if "a" in opt[1:]:
                i += 1  # -a NAME
    argv = argv[i:] if i else argv
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


def _program_globbed(text: str, word: str, wrappers: list[str],
                     spellings: tuple[frozenset[str], frozenset[str]] | None = None) -> bool:
    """Whether the program word ``word`` of a command read from ``text`` is a
    glob the shell expands: a glob character in it is unquoted where ``text``
    spells it (``"[[["`` and ``'k*'`` are names). A word that reached the
    program position through a launcher (``uvx 'kube[a]x'``), or that ``text``
    does not spell as a word of its own, counts as a glob when it holds one."""
    if not _globbed(word):
        return False
    if wrappers:
        return True
    unquoted, spelt = spellings if spellings is not None else _glob_spellings(text)
    return word in unquoted or word not in spelt


def globbed_program_word(command: str) -> str | None:
    """The first program word, in ``command`` or any command line nested in it
    (``eval`` words, ``sh -c`` strings, substitutions, and the here-document
    bodies a shell reads: ``bash <<EOF``, ``cat <<EOF | sh``; not data bodies,
    ``cat > notes.md <<EOF`` / ``* item``), that is a glob the shell expands
    (:func:`_program_globbed`, read in the text it is spelt in), also as the
    program ``find -exec`` runs; ``None`` when there is none. For commands the
    parser rejects, whose nested lines it never reads."""
    for text in _glob_texts(command):
        spellings = None
        for words, _redirects in _simple_commands(_shell_tokens(text), case_patterns=True):
            try:
                argv = _peel_precommands(strip_exec_builtin(_strip_reserved(words)))
                if not argv or argv[0] == "eval":
                    continue
                argv, _env, wrappers, _string = _unwrap_inner(argv, 0)
                found = [(argv[0], bool(wrappers))]
                for inner in find_exec_commands(argv):  # spelt here, not re-quoted
                    inner, _env, inner_wrappers, _string = _unwrap_inner(inner, 1)
                    found.append((inner[0], bool(inner_wrappers)))
            except ShellRejected:  # launchers not read: the first word that is not
                # an assignment (x=$(( a[1] )) alone runs nothing)
                found = [(w, False) for w in words if not _ASSIGNMENT_RE.match(w)][:1]
            for word, launched in found:
                if _globbed(word):
                    spellings = spellings or _glob_spellings(text)
                    if launched or _program_globbed(text, word, [], spellings):
                        return word
    return None


def _glob_texts(command: str, depth: int = 0) -> list[str]:
    """:func:`nested_commands` with only the here-document bodies a shell reads."""
    return [text for text, _substituted in _glob_texts_marked(command, depth)]


def _glob_texts_marked(command: str, depth: int = 0,
                       substituted: bool = False) -> list[tuple[str, bool]]:
    """:func:`_glob_texts`, each text marked when it is (inside) a command
    substitution, backticks or a process substitution, whose output goes on."""
    found = [(command, substituted)]
    if depth >= 4:
        return found
    lexed = lex(command)
    subs = set(lexed.substitutions)
    for text in dict.fromkeys([*_inner_commands(command), *lexed.glob_bodies,
                               *lexed.substitutions]):
        if text:
            found += _glob_texts_marked(text, depth + 1, substituted or text in subs)
    return found


def globbed_word_in_unknown_bodies(command: str) -> str | None:
    """:func:`globbed_program_word` for the here-document bodies whose reader
    is not known (not a shell, not only data sinks: ``tee >(sh)``, a function):
    such a word asks rather than denies."""
    marked = _glob_texts_marked(command)
    # an eval anywhere may run a body that looked like data (x=$(cat <<E …); eval "$x")
    evals = any(kind == "word" and value == "eval"
                for text, _sub in marked for kind, value, _s, _e in _shell_tokens(text))
    for text, substituted in marked:
        lexed = lex(text)
        shell_run = set(lexed.glob_bodies)
        # in a substitution a data body's output goes on (echo "$(cat <<E …)" | x):
        # every body but the shell-run ones, added to the unknown ones
        bodies = lexed.ask_bodies if not (evals or substituted) else list(dict.fromkeys(
            [*lexed.ask_bodies, *(b for b in lexed.bodies if b not in shell_run),
             *lexed.data_strings]))
        for body in bodies:
            word = globbed_program_word(body)
            if word is not None:
                return word
    return None


def _glob_spellings(text: str) -> tuple[frozenset[str], frozenset[str]]:
    """The words of ``text`` (dequoted) that some spelling writes with an
    unquoted glob character, and all its words: one pass over the tokens.
    Callers compute it once per text (not cached: many nested texts must not
    push the outer one out of a cache and have it read again)."""
    unquoted, spelt = set(), set()
    for kind, value, start, end in _shell_tokens(text):
        if kind == "word":
            spelt.add(value)
            if _unquoted_glob(text[start:end]):
                unquoted.add(value)
    return frozenset(unquoted), frozenset(spelt)


def _unquoted_glob(raw: str) -> bool:
    """Whether a word as written holds a glob character outside quotes."""
    quote, i = "", 0
    while i < len(raw):
        c = raw[i]
        if quote:
            if c == quote:
                quote = ""
            elif c == "\\" and quote == '"':
                i += 1
        elif c == "\\":
            i += 1
        elif c in "'\"":
            quote = c
        elif c in "{}*?[":
            return True
        i += 1
    return False


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
# Shells that ship versioned binaries (bash5.2, zsh5, ksh93, mksh-R59); not sh2.
_VERSIONED_SHELL_RE = re.compile(r"(bash|zsh|ksh|mksh|dash|yash)(?:\d[\d.]*|-R\d+[a-z]?)")
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")  # x=, x+=, a[1]=

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
    name = Path(token).name or token
    versioned = _VERSIONED_SHELL_RE.fullmatch(name)  # zsh5, ksh93, bash5.2: the shell
    return versioned.group(1) if versioned else name


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
        if tok == "--":  # timeout -- 5 cmd
            i += 1
            break
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


# Options of GNU time (/usr/bin/time, gtime); the time keyword only takes -p.
_TIME_VALUE_OPTIONS = frozenset({"-f", "-o", "--format", "--output"})
_TIME_FLAGS = frozenset({"-p", "-v", "-l", "-a", "-q", "--verbose", "--quiet", "--append",
                         "--portability"})


def _strip_time(rest: list[str]) -> list[str]:
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if tok in _TIME_VALUE_OPTIONS:
            i += 2
            continue
        if tok in _TIME_FLAGS or tok.startswith(("--format=", "--output=")):
            i += 1
            continue
        if tok.startswith("-"):
            raise ShellRejected(f"unrecognised time option {tok!r}")
        break
    return rest[i:]


def _strip_nice(rest: list[str]) -> list[str]:
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":  # nice -- cmd
            i += 1
            break
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
def _package_name(spec: str) -> str:
    """``pkg[extra]==1.0`` -> ``pkg``: the name before its extras and version
    spec, in one pass (a regex was quadratic on runs of ``[``)."""
    close = -1  # the first ] at or after the current [, carried along
    for i, ch in enumerate(spec):
        if ch == "[":
            if close < i:
                close = spec.find("]", i)
                if close == -1:
                    close = len(spec)  # none: no later [ closes either
            if close < len(spec) and (close + 1 == len(spec) or spec[close + 1] in "@=<>!~:"):
                return spec[:i]
        elif ch in "@=<>!~:":
            return spec[:i]
    return spec


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
        rest = [_package_name(rest[0]) or rest[0], *rest[1:]]
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


def _shell_c_string(rest: list[str], shell: str = "sh") -> str | None:
    """For ``sh [opts] -c STRING [args…]`` returns STRING; ``None`` when the
    shell is not invoked with ``-c`` (``bash script.sh`` — an ordinary,
    unknown binary as far as the gate is concerned)."""
    i = 0
    saw_c = False
    while i < len(rest):
        tok = rest[i]
        if tok in SHELL_OPTIONS_END:
            i += 1
            break
        if tok.startswith(("-", "+")) and len(tok) > 1:
            # -o pipefail, -co pipefail 'cmd', --rcfile FILE, --norc, +x
            values, letters = shell_option(tok, shell)
            if tok.startswith("-") and not tok.startswith("--") and "c" in letters:
                saw_c = True
            i += 1 + values
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
    turns = 0
    last: list[str] | None = None
    while True:
        if argv == last:
            break  # a turn that changed nothing: stop rather than loop forever
        last = argv
        # assignments, `--`, `!`, `{`, reserved words (`do`, `then`) and `coproc`, in
        # any mix (-- ! A=1 do …), are passed over in one pass and one copy
        k = 0
        while k < len(argv):
            word = argv[k]
            if word == "--" or word in _GROUPING_WORDS or word in _LEADING_RESERVED:
                k += 1
            elif word == "coproc":
                k += 3 if len(argv) > k + 2 and argv[k + 2] == "{" else 1
            elif _ASSIGNMENT_RE.match(word):
                key, _, value = word.partition("=")
                env[key] = value
                k += 1
            else:
                break
        if k:
            argv = argv[k:]
        if argv and (argv[0] in _HEADER_RESERVED or argv[0] in _CLOSING_RESERVED
                     or argv[0] == "function"):
            argv = _strip_reserved(argv)  # for … in, a lone done: nothing runs
        if not argv:
            raise ShellRejected("nothing left to run after unwrapping launchers")
        turns += 1
        if len(wrappers) >= _MAX_LAUNCHERS or turns > 2 * _MAX_LAUNCHERS:
            # each turn copies the words: keep it linear
            raise ShellRejected(f"more than {_MAX_LAUNCHERS} launchers in a row")
        head = _basename(argv[0])
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
        if head in ("nohup", "time", "gtime"):
            rest = argv[1:] if head == "nohup" else _strip_time(argv[1:])
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
        if head in ("noglob", "nocorrect") or (head == "repeat" and len(argv) > 2):
            # zsh precommand modifiers: noglob CMD, repeat N CMD
            wrappers.append(head)
            argv = argv[2:] if head == "repeat" else argv[1:]
            continue
        if head == "command":
            k = 1
            while k < len(argv) and re.fullmatch(r"-p+", argv[k]):  # -p -p, -pp
                k += 1
            if k < len(argv) and argv[k] == "--":  # command -- cmd, command -p -- cmd
                k += 1
            rest = argv[k:]
            if not rest or rest[0].startswith("-"):
                break  # `command -v x` only prints a path
            wrappers.append("command")
            argv = rest
            continue
        if head in _SHELLS:
            string = _shell_c_string(argv[1:], head)
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
# Shells whose -o/-O take an attached value (zsh -opipefail); bash, dash and sh
# take the next word whatever follows the letter.
_ATTACHED_VALUE_SHELLS = frozenset({"zsh", "ksh", "mksh", "yash"})


def shell_option(word: str, shell: str, *, as_value: bool = False) -> tuple[int, str]:
    """For an option of ``shell``: how many of the words after it are its
    values, and the option letters it sets. ``--rcfile``/``--init-file`` take
    one; in a short cluster each ``o``/``O`` takes the next word, in order
    (``-o NAME``, ``-co NAME 'cmd'``, ``-oO A B``), except in zsh, ksh, mksh
    and yash, where an ``o``/``O`` with letters after it takes them as its
    value and ends the cluster (``zsh -eopipefail``: e, then pipefail). By
    default the letters are all of the cluster's other letters, to be safe
    (ksh93 reads ``-oc`` as ``-c``); ``as_value`` gives the other reading of an
    :func:`ambiguous_option`, where the letters after the ``o`` are only its
    value (``zsh -onoclobber x.sh`` runs x.sh)."""
    if word in ("--rcfile", "--init-file"):
        return 1, ""
    if word.startswith("--") or len(word) < 2 or word[0] not in "-+":
        return 0, ""
    attached = _basename(shell) in _ATTACHED_VALUE_SHELLS
    values = 0
    for k, letter in enumerate(word[1:], start=2):
        if letter in "oO":
            if attached and k < len(word):
                if as_value:
                    return values, "".join(ch for ch in word[1:k - 1] if ch not in "oO")
                break  # the rest of the word is the option's name
            values += 1
    # every letter counts as set, also those after an attached value: ksh93
    # reads -oc as -c and -oi as -i, so -c, -i and -s are not missed
    return values, "".join(ch for ch in word[1:] if ch not in "oO")


def ambiguous_option(word: str, shell: str) -> bool:
    """Whether a zsh/ksh/mksh/yash option cluster reads two ways that differ:
    an ``o``/``O`` with letters after it that hold ``c``, ``i`` or ``s``
    (``-onoclobber``: the value noclobber, or -c set, as ksh93 reads ``-oc``)."""
    return shell_option(word, shell) != shell_option(word, shell, as_value=True)
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
        skip = 0  # values still to pass over
        for i, tok in enumerate(rest):
            if skip:
                skip -= 1
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
            if interp in _SHELLS and tok in SHELL_OPTIONS_END and following:
                # bash - x.sh: a lone - ends the options like --; x.sh is the script
                return {"kind": "script", "interpreter": name, "path": following}
            if tok == "-" or (interp in _SHELLS and tok == "-s"):
                break  # code from stdin
            if interp in _SHELLS and shell_option(tok, name)[0]:
                skip = shell_option(tok, name)[0]  # bash -eo pipefail x.sh: pipefail is a value
                continue
            if (tok in _VALUE_FLAGS and not (interp in _SHELLS and tok == "-r")) or (
                    interp in ("perl", "ruby") and tok in ("-I", "-C", "-x")):
                skip = 1  # perl -I lib -e …: lib is a value, not the script
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
                   "E": "\x1b", "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
# $(…) nested deeper than this is skipped by counting brackets, not read.
_MAX_SUBSTITUTION_DEPTH = 32
# The separators after which the shell reads on past a newline.
_CONTINUING_SEPS = frozenset({"|", "|&", "&&", "||"})


@dataclass(frozen=True)
class Lexed:
    """The tokens of a command line, the here-document bodies it holds, and
    whether a quote, ``$(…)``, backtick or here-document is left open at its
    end."""

    tokens: tuple[_Token, ...]
    bodies: tuple[str, ...]  # here-document bodies, all checked as commands
    unclosed: bool
    # the command lines of the outermost $(…), <(…), >(…) and `…`
    substitutions: tuple[str, ...] = ()
    # for the glob check: the bodies a shell runs, and those an unknown reader gets
    glob_bodies: tuple[str, ...] = ()
    ask_bodies: tuple[str, ...] = ()
    data_strings: tuple[str, ...] = ()  # here-strings only data sinks read
    deep: bool = False  # $(…) nested past what the lexer reads


def _skip_brackets(text: str, i: int, n: int, opening: str = "(",
                   closing: str = ")") -> tuple[int, bool]:
    """The index after the ``closing`` that matches the ``opening`` at
    ``text[i]``, quotes and backslashes heeded, and whether it was closed (else
    ``n``)."""
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
        if c == opening:
            depth += 1
        elif c == closing:
            depth -= 1
            if depth == 0:
                return i + 1, True
        i += 1
    return n, False


def _ansi_c(text: str, i: int, n: int) -> tuple[str, int, bool]:
    """The value of the ``$'…'`` whose text starts at ``i`` (after ``$'``), as
    bash decodes it (``\\n``, ``\\xHH``, ``\\NNN`` octal, ``\\uHHHH``,
    ``\\UHHHHHHHH``, ``\\cX``, …), the index after its closing quote, and
    whether there was one."""
    value: list[str] = []
    while i < n and text[i] != "'":
        if text[i] != "\\" or i + 1 >= n:
            value.append(text[i])
            i += 1
            continue
        e = text[i + 1]
        i += 2
        digits = {"x": (16, 2), "u": (16, 4), "U": (16, 8)}.get(e)
        if digits is not None or e in "01234567":
            base, width = digits or (8, 3)
            start = i if digits else i - 1
            j = start
            while j < n and j - start < width and text[j] in "0123456789abcdefABCDEF"[:base + (
                    6 if base == 16 else 0)]:
                j += 1
            if j == start:  # \x with no digits: kept as written
                value.append("\\" + e)
                continue
            code = int(text[start:j], base)
            value.append(chr(code & 0xFF) if base == 8 or e == "x" else
                         chr(code) if code < 0x110000 else "")
            i = j
        elif e == "c" and i < n:
            value.append(chr(ord(text[i]) & 0x1F))
            i += 1
        elif e in _ANSI_C_ESCAPES:
            value.append(_ANSI_C_ESCAPES[e])
        else:
            value.append("\\" + e)  # an unknown escape stays as written
    return "".join(value), i + 1, i < n


_BACKTICK_ESCAPE_RE = re.compile(r"\\([`\\$])")
_DQ_BACKTICK_ESCAPE_RE = re.compile(r"\\([`\\$\"])")  # "`…`" also unescapes \"


def _backtick(text: str, i: int, state: dict, depth: int, in_double: bool = False) -> int:
    """The index after the ``` `…` ``` that opens at ``text[i]``: it ends at
    the first backtick no backslash escapes. Its command line, with bash's
    unescaping (``\\` `` -> `` ` ``, ``\\\\`` -> ``\\``, ``\\$`` -> ``$``, so an
    escaped backtick inside is a nested substitution; directly inside double
    quotes also ``\\"`` -> ``"``, as bash does there and only there), is
    recorded at the top level and read as a command line in turn
    (:func:`nested_commands`)."""
    n = len(text)
    j = i + 1
    while j < n and text[j] != "`":
        j += 2 if text[j] == "\\" else 1
    if j >= n:
        state["unclosed"] = True
    if depth == 0:
        escapes = _DQ_BACKTICK_ESCAPE_RE if in_double else _BACKTICK_ESCAPE_RE
        state["substitutions"].append(escapes.sub(r"\1", text[i + 1:min(j, n)]))
    return min(j + 1, n)


def _body_substitutions(body: str, state: dict) -> None:
    """Records the command substitutions an unquoted here-document body runs
    (``$(…)``, backticks, also inside ``${…}``, ``$((…))`` and ``$[…]``); its
    quotes are literal characters there, so they hide nothing."""
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
        elif c == "$" and body[i + 1:i + 2] in ("(", "{", "["):
            i = _expansion(body, i, [], state, 0, in_double=True)
        elif c == "`":
            i = _backtick(body, i, state, 0)
        else:
            i += 1


# Programs that only read a here-document as data (to a file, the terminal, a
# filter or a commit message). Not sed (its e command), awk (system()), xargs,
# ssh, sudo, …: for the glob check, a body only these read is not run.
_DATA_SINKS = frozenset({"cat", "tee", "head", "tail", "wc", "grep", "sort", "uniq", "cut",
                         "tr", "jq", "yq", "base64", "diff", "git", "gh", "true", ":"})
_COMPOUND_WORDS = frozenset({"{", "}", "if", "then", "else", "elif", "fi", "do", "done",
                             "while", "until", "!", "time"})
_DESCRIPTOR_PATHS = ("/dev/fd/", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/proc/")


_NON_SHELL_READERS = re.compile(r"python[\d.]*|pypy[\d.]*|node|perl|ruby|php|lua")


def _pipelines(tokens: list[_Token], start: int) -> list[tuple[int, int]]:
    """For each token from ``start`` on: the ``(low, high)`` bounds of what
    reads a here-document attached there: from the start of its own command
    (the stages before it in the pipeline never see the body: ``echo x | cat
    <<E``) to the end of its pipeline (separators other than ``|``/``|&`` end
    one). Two passes."""
    ends = [0] * (len(tokens) - start)
    end = len(tokens)
    for k in range(len(tokens) - 1, start - 1, -1):  # where each token's pipeline ends
        if tokens[k][0] == "sep" and tokens[k][1] not in ("|", "|&"):
            end = k
        ends[k - start] = end
    bounds, command = [], start
    for k in range(start, len(tokens)):  # where each token's command starts
        bounds.append((command, ends[k - start]))
        if tokens[k][0] == "sep":
            command = k + 1
    return bounds


def _tail_reader(tokens: list[_Token], low: int, high: int, memo: dict[int, str]) -> str:
    """:func:`_body_reader` of ``tokens[low:high]``, a command and the pipeline
    stages after it, read stage by stage from the right so each stage is read
    once (``memo``, keyed by where a stage starts)."""
    stages, k = [], low
    while k < high and k not in memo:  # the stages not read yet
        end = k
        while end < high and not (tokens[end][0] == "sep" and tokens[end][1] in ("|", "|&")):
            end += 1
        stages.append((k, end))
        k = end + 1
    reader = memo.get(k, "data") if k < high else "data"
    for start, end in reversed(stages):
        own = _body_reader(tokens[start:end])
        reader = "shell" if "shell" in (own, reader) else (
            "data" if own == reader == "data" else "unknown")
        memo[start] = reader
    return memo.get(low, reader)


def _body_reader(line: list[_Token]) -> str:
    """Who reads a here-document whose opening line is ``line``, for the glob
    check: ``"shell"`` when a shell, ``eval``, ``source``, ``.`` or ``exec`` is
    a program there (``bash <<EOF``, ``cat <<EOF | sh``); ``"data"`` when every
    program is a data sink (:data:`_DATA_SINKS`) or an interpreter of another
    language reading the body as its program (``python3``, ``python3 -``,
    ``node``; also ``python3 -m json.tool``), with no ``<(…)``/``>(…)`` and no
    descriptor path (``/dev/fd/3``); ``"unknown"`` otherwise (an interpreter
    with inline code or a script, ``python3 -c '…os.system(input())'``, may
    hand the body to a shell). Only words in command position count (``jq .``:
    the ``.`` is jq's)."""
    data = True
    program: str | None = None  # the interpreter whose arguments are being read
    arguments: list[str] = []
    command_start, after_op = True, False
    for kind, value, _s, _e in [*line, ("sep", "", 0, 0)]:
        if kind == "sep":
            if program is not None and not _reads_its_program(program, arguments):
                data = False
            program, arguments, command_start, after_op = None, [], True, False
            continue
        if kind == "op":
            after_op = True
            continue
        if "<(" in value or ">(" in value or value.startswith(_DESCRIPTOR_PATHS):
            data = False
        if after_op:  # a redirection's target
            after_op = False
            continue
        if not command_start:
            if program is not None:
                arguments.append(value)
            continue
        if value in _COMPOUND_WORDS or _ASSIGNMENT_RE.match(value):
            continue
        name = _basename(value)
        if name in _SHELLS or value in ("eval", "source", ".", "exec"):
            return "shell"
        if _NON_SHELL_READERS.fullmatch(name):
            program = name
        elif name not in _DATA_SINKS:
            data = False  # sudo, xargs, ssh, $SHELL, a function, …
        command_start = False
    return "data" if data else "unknown"


def _reads_its_program(name: str, arguments: list[str]) -> bool:
    """Whether an interpreter run with ``arguments`` reads its program from
    standard input (the here-document): none, or a lone ``-``; ``python3 -m
    json.tool`` (with options) only formats it."""
    if arguments in ([], ["-"]):
        return True
    return name.startswith(("python", "pypy")) and arguments[:2] == ["-m", "json.tool"] and all(
        a.startswith("-") for a in arguments[2:])


def _skip_bodies(text: str, i: int, pending: list[tuple[str, bool, bool]],
                 bodies: list[str], state: dict, depth: int) -> int:
    """Past the here-document bodies that start at ``i`` (one per ``<<`` on the
    line before, in order), each up to its delimiter line; collects them. Each
    is checked as commands, quoted or not, whatever reads it: which program
    reads a body as code cannot be told reliably (functions, aliases, PATH,
    ``>(…)``). An unquoted body's ``$(…)`` and backticks also run, quotes or
    not (in a body they are literal), so they are read as command lines too. A
    body whose delimiter never comes leaves the command unclosed."""
    n = len(text)
    for delimiter, strip_tabs, quoted in pending:
        start = i
        while i < n:
            j = text.find("\n", i)
            line = text[i:n if j < 0 else j]
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
            i = n if j < 0 else j + 1
        else:
            state["unclosed"] = True  # never ended: the body runs to the end
        bodies.append(text[start:i])
        if not quoted and depth == 0:
            _body_substitutions(text[start:i], state)
        if i < n:  # past the delimiter line
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
    return i


def _scan(text: str, i: int, tokens: list[_Token], bodies: list[str], state: dict,
          depth: int, nested: bool) -> int:
    """Tokens of ``text`` from ``i`` into ``tokens``; inside a ``$(…)``
    (``nested``) up to its closing ``)``, whose index + 1 is returned."""
    n = len(text)
    # here-documents whose bodies start at the next line: (delimiter, <<-, quoted)
    pending: list[tuple[str, bool, bool]] = []
    pending_ops: list[int] = []  # the token index of each pending body's <<
    want: str | None = None  # a << just read: the next word is its delimiter
    parens = 0
    joined = False  # after |, |&, && or ||: a newline does not end the command
    line_start = len(tokens)  # where this line's tokens begin (for its here-documents)
    command_position = True  # the next word starts a command (or follows if, do, …)
    strings: list[tuple[str, int]] = []  # this line's here-strings (<<< word): word, <<< index
    string_next = False  # a <<< just read: the next word is a here-string

    def flush_strings() -> None:
        """Classifies this line's here-strings like one-line here-document bodies."""
        if not strings:
            return
        pipelines = _pipelines(tokens, line_start)
        readers: dict[int, str] = {}  # each stage read once, however many strings
        for value, at in strings:
            low, high = pipelines[at - line_start]
            state["strings"].append((value, _tail_reader(tokens, low, high, readers), depth))
        strings.clear()
    while i < n:
        c = text[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and text.startswith("\n", i + 1):  # a line continuation: a space
            i += 2
            continue
        if c == "#":  # a comment, where a word would start
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\n" and (joined or pending):
            flush_strings()
            if pending:
                code = len(bodies)
                i = _skip_bodies(text, i + 1, pending, bodies, state, depth)
                pipelines = _pipelines(tokens, line_start)
                readers: dict[int, str] = {}
                for body, at in zip(bodies[code:], pending_ops, strict=False):
                    # the reader is the pipeline the << is in, not the whole line
                    low, high = pipelines[at - line_start]
                    reader = _tail_reader(tokens, low, high, readers)
                    if reader == "shell":
                        state["glob_bodies"].append(body)  # bash <<EOF, cat <<EOF | sh
                    elif reader == "unknown" or depth > 0:
                        # inside $(…), <(…), >(…) the output goes on to who knows
                        state["ask_bodies"].append(body)
                pending, pending_ops = [], []
                line_start = len(tokens)
                if not joined:
                    tokens.append(("sep", "\n", i - 1, i))
                continue
            i += 1
            continue
        if c == ")" and nested and parens == 0:
            flush_strings()  # its here-strings, before the substitution ends
            return i + 1
        if c == "(" and _ARITHMETIC_RE.match(text, i):  # (( … )), for (( … )): arithmetic
            j = _skip_expansion(text, i, "(", ")", bodies, state, depth)
            tokens.append(("word", text[i:j], i, j))
            joined = False
            i = j
            continue
        if c in "\n;()" or (c in "|&" and not text.startswith("&>", i)):
            if c == ")" and tokens and tokens[-1][:2] == ("sep", "("):
                state["defines"] = True  # name() …: a function, maybe a reader
            two = text[i:i + 2]
            sep = two if two in ("&&", "||", "|&", ";;") else c
            if c in "()":
                state["grouped"] = True
            elif sep in ("|", "|&"):
                state["piped"] = True
            parens += 1 if c == "(" else -1 if c == ")" and parens else 0
            tokens.append(("sep", sep, i, i + len(sep)))
            command_position = True
            joined = sep in _CONTINUING_SEPS
            i += len(sep)
            if sep == "\n":
                flush_strings()
                line_start = len(tokens)
            continue
        joined = False
        start = j = i
        while j < n and text[j].isdigit():
            j += 1
        if j < n and text[j] in "<>&" and not text.startswith(("<(", ">("), j):
            op = next((o for o in _LEX_REDIRECT_OPS if text.startswith(o, j)), None)
            if op is not None and not (op.startswith("&") and j > i):
                tokens.append(("op", text[i:j] + op, start, j + len(op)))
                want = op if op in ("<<", "<<-") else None
                string_next = op == "<<<"
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
                decoded, i, closed = _ansi_c(text, i + 2, n)
                value.append(decoded)
                state["unclosed"] |= not closed
            elif c == "'":
                j = text.find("'", i + 1)
                state["unclosed"] |= j < 0
                j = n if j < 0 else j
                value.append(text[i + 1:j])
                i = j + 1
            elif c == '"':
                i += 1
                while i < n and text[i] != '"':
                    if text[i] == "$" and text[i + 1:i + 2] in ("(", "{", "["):
                        j = _expansion(text, i, bodies, state, depth, in_double=True)
                        value.append(text[i:j])
                        i = j
                        continue
                    if text[i] == "`":  # "`…`" runs too
                        j = _backtick(text, i, state, depth, in_double=True)
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
            elif (c in "<>" and text.startswith("(", i + 1)) or (
                    c == "$" and text[i + 1:i + 2] in ("(", "{", "[")):
                j = _expansion(text, i, bodies, state, depth)  # raw in the word
                value.append(text[i:j])
                i = j
            elif c == "`":
                j = _backtick(text, i, state, depth)
                value.append(text[i:j])
                i = j
            else:
                value.append(c)
                i += 1
        if i == start:  # no rule took the character: pass it, never loop on it
            i += 1
            continue
        i = min(i, n)
        if not value and not text[start:i].replace("\\\n", ""):
            continue  # only line continuations
        word = "".join(value)
        tokens.append(("word", word, start, i))
        if word in ("function", "alias"):
            state["defines"] = True
        if word in _COMPOUND_RESERVED and i - start == len(word) and command_position:
            state["grouped"] = True  # { }, if, while, do, …: a reader may be inside
        else:
            command_position = False
        if string_next:
            strings.append((word, len(tokens) - 2))  # the <<< just before
            string_next = False
        if want is not None:
            quoted = any(q in text[start:i] for q in "'\"\\")
            pending.append((word, want == "<<-", quoted))
            pending_ops.append(len(tokens) - 2)  # the << just before the delimiter
            want = None
    flush_strings()
    if nested:
        state["unclosed"] = True  # a $( never closed
    if pending:
        state["unclosed"] = True  # a here-document whose body never starts
    return n


# `((…))` is arithmetic only when it closes with an adjacent `))`; `((cmd) )`
# is a subshell in a subshell and `$((cmd) )` a command substitution. Quotes
# are ordinary characters in arithmetic; up to four levels of inner brackets;
# possessive, so linear.
_BRACKETED = r"[^()]++"
for _ in range(4):
    _BRACKETED = rf"[^()]++|\((?:{_BRACKETED})*+\)"
_ARITHMETIC_RE = re.compile(rf"\(\((?:{_BRACKETED})*+\)\)")


# ${…}, $[…], $((…)) and $(…) nested deeper than this, all kinds together, are
# matched by counting, not read with their own quoting (single quotes then count
# as literal: more is read), and the command asks (Lexed.deep).
_MAX_NESTING = 128


def _nest(state: dict) -> bool:
    """Enters one more level of nesting when :data:`_MAX_NESTING` allows it
    (the caller leaves it again); else marks the command too deep."""
    if state.get("nesting", 0) >= _MAX_NESTING:
        state["deep"] = True
        return False
    state["nesting"] = state.get("nesting", 0) + 1
    return True


def _skip_expansion(text: str, i: int, opening: str, closing: str, bodies: list[str],
                    state: dict, depth: int, quotes: bool = False) -> int:
    """The index after the ``closing`` that matches the ``opening`` at
    ``text[i]`` (an arithmetic ``((…))``, ``${…}`` or ``$[…]``). A ``<<`` in
    it is a shift or a pattern, not a here-document; the ``$(…)``, ``<(…)``,
    ``>(…)`` and backticks in it are read as commands. Single quotes hide
    them only where they quote: in an unquoted ``${…}`` (``quotes``) outside
    double quotes; in arithmetic, ``$[…]`` and anything double-quoted they are
    literal. A ``${…}``, ``$[…]`` or ``$((…))`` inside is read the same way
    with its own rule. Each character is read once, so this is linear."""
    n = len(text)
    level = 0
    in_double = False
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'" and quotes and not in_double:
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            in_double = not in_double
            i += 1
        elif c == "`":
            i = _backtick(text, i, state, depth)
        elif c == "$" and text[i + 1:i + 2] in ("{", "[") and _nest(state):
            pair = ("{", "}") if text[i + 1] == "{" else ("[", "]")
            i = _skip_expansion(text, i + 1, *pair, bodies, state, depth,
                                quotes=pair[0] == "{" and quotes and not in_double)
            state["nesting"] -= 1
        elif c == "$" and text.startswith("(", i + 1) and _ARITHMETIC_RE.match(text, i + 1) \
                and _nest(state):
            i = _skip_expansion(text, i + 1, "(", ")", bodies, state, depth)
            state["nesting"] -= 1
        elif (c == "$" and text.startswith("(", i + 1) and not _ARITHMETIC_RE.match(text, i + 1)) \
                or (c in "<>" and text.startswith("(", i + 1)):
            i = _substitution(text, i, bodies, state, depth)
        else:
            if in_double and opening != "(":
                pass  # a `}` or `]` inside double quotes does not close
            elif c == opening:
                level += 1
            elif c == closing:
                level -= 1
                if level == 0:
                    return i + 1
            i += 1
    state["unclosed"] = True
    return n


def _expansion(text: str, i: int, bodies: list[str], state: dict, depth: int,
               in_double: bool = False) -> int:
    """The index after the ``$(…)``/``<(…)``/``>(…)`` at ``i``, read as a
    command line of its own (its here-documents included), or after the
    ``$((…))``, ``${…}`` or ``$[…]`` there (:func:`_skip_expansion`;
    ``in_double``: inside double quotes)."""
    if text.startswith("${", i):
        return _skip_expansion(text, i + 1, "{", "}", bodies, state, depth,
                               quotes=not in_double)
    if text.startswith("$[", i):
        return _skip_expansion(text, i + 1, "[", "]", bodies, state, depth)
    if text[i] == "$" and _ARITHMETIC_RE.match(text, i + 1):
        return _skip_expansion(text, i + 1, "(", ")", bodies, state, depth)
    return _substitution(text, i, bodies, state, depth)


def _substitution(text: str, i: int, bodies: list[str], state: dict, depth: int) -> int:
    """The index after the ``$(…)``/``<(…)``/``>(…)`` at ``i``, read as a
    command line of its own (its here-documents included)."""
    if depth >= _MAX_SUBSTITUTION_DEPTH or not _nest(state):
        j, closed = _skip_brackets(text, i + 1, len(text))
        state["unclosed"] |= not closed
        state["deep"] = True
        return j
    j = _scan(text, i + 2, [], bodies, state, depth + 1, True)
    state["nesting"] -= 1
    if depth == 0:
        state["substitutions"].append(text[i + 2:j - 1])
    return j


@functools.lru_cache(maxsize=32)
def lex(text: str) -> Lexed:
    """The tokens of ``text`` (see :data:`_Token`). Never raises; an unclosed
    quote runs to the end and is reported in :attr:`Lexed.unclosed`."""
    tokens: list[_Token] = []
    bodies: list[str] = []
    state: dict = {"unclosed": False, "substitutions": [], "deep": False, "glob_bodies": [],
                   "ask_bodies": [], "defines": False, "grouped": False, "piped": False,
                   "strings": []}
    _scan(text, 0, tokens, bodies, state, 0, False)
    # here-strings (<<< word) are one-line bodies for the glob check
    anywhere = state["defines"] or (state["grouped"] and state["piped"])
    data_strings = []
    for value, reader, depth in state["strings"]:
        if reader == "shell":
            state["glob_bodies"].append(value)
        elif reader == "unknown" or depth > 0 or anywhere:
            state["ask_bodies"].append(value)
        else:
            data_strings.append(value)
    shell_run = set(state["glob_bodies"])
    return Lexed(tuple(tokens), tuple(bodies), state["unclosed"],
                 substitutions=tuple(state["substitutions"]), deep=state["deep"],
                 glob_bodies=tuple(state["glob_bodies"]),
                 # a function or alias anywhere may be a reader, and so may a
                 # program a group or subshell is piped into ((cat <<E …) | x):
                 # no body is data then
                 ask_bodies=tuple(dict.fromkeys(
                     [*(b for b in bodies if b not in shell_run), *state["ask_bodies"]]))
                 if anywhere else tuple(state["ask_bodies"]),
                 data_strings=tuple(data_strings))


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
    """For a shell word at ``k``: the index of its ``-c`` string word
    (:func:`_shell_scan`); ``None`` when it has none."""
    return _shell_scan(tokens, k)[0]


# At most this many option words after a shell are read; past it the command is
# too deep to check, and asks (see nested_too_deep).
_MAX_SHELL_OPTIONS = 64


def _shell_scan(tokens: tuple[_Token, ...], k: int) -> tuple[int | None, bool]:
    """For a shell word at ``k``: the index of its ``-c`` string word, after
    its options (``-o NAME``, clusters, ``--long``), or ``None``; and whether
    it has more than :data:`_MAX_SHELL_OPTIONS` option words, which are not
    all read (so callers stay linear)."""
    if _basename(tokens[k][1]) not in _SHELLS:
        return None, False
    j, saw_c = k + 1, False
    while tokens[j:j + 1] and tokens[j][0] == "word":
        if j >= k + _MAX_SHELL_OPTIONS:
            return None, True  # more options than are read
        word = tokens[j][1]
        if word in SHELL_OPTIONS_END:
            j += 1
            break
        if re.fullmatch(r"[-+][a-zA-Z]+|--[\w-]+", word):
            values, letters = shell_option(word, tokens[k][1])
            saw_c = saw_c or (word.startswith("-") and not word.startswith("--")
                              and "c" in letters)
            j += 1 + values  # -co pipefail 'cmd': the value, then the string
            continue
        break
    return (j if saw_c and j < len(tokens) and tokens[j][0] == "word" else None), False


def options_capped(text: str) -> bool:
    """Whether a shell in ``text`` has more options than :func:`_shell_scan`
    reads before its ``-c`` string or script."""
    tokens = _shell_tokens(text)
    return any(_shell_scan(tokens, k)[1] for k in _readers(tokens))


def _eval_words_end(tokens: tuple[_Token, ...], k: int) -> int:
    """For an ``eval`` word at ``k``: the index after its words."""
    j = k + 1
    while j < len(tokens) and tokens[j][0] == "word":
        j += 1
    return j


def _inner_commands(text: str) -> list[str]:
    """The command lines one level inside ``text``: each ``sh -c`` string, the
    words of each ``eval`` (joined), and the command string of a launcher
    (``watch 'cmd'``, ``script -c 'cmd'``, ``mise exec -c 'cmd'``, also behind
    ``sudo``/``nohup``/…). An ``eval``'s words are not searched again for a
    ``-c`` string at this level; that is the next level's job."""
    tokens = _shell_tokens(text)
    found = []
    k = 0
    while k < len(tokens):
        kind, value, _start, _end = tokens[k]
        if kind == "word" and value == "eval":
            j = _eval_words_end(tokens, k)
            if j > k + 1:
                found.append(" ".join(t[1] for t in tokens[k + 1:j]))
            k = j
            continue
        if kind == "word":
            j = _c_string_at(tokens, k)
            if j is not None:
                found.append(tokens[j][1])
                k = j + 1
                continue
        k += 1
    for words, _redirects in _simple_commands(tokens):
        found += _launched_commands(words)
    return found


def _launched_commands(words: list[str]) -> list[str]:
    """The command lines a launcher in front of ``words`` runs: its command
    string (``watch 'cmd'``, ``sudo script -qc 'cmd' /dev/null``) or the
    commands of ``find … -exec|-execdir|-ok|-okdir CMD … \\;|+``; ``[]`` when
    there are none or the launchers cannot be unwrapped."""
    try:
        argv = strip_exec_builtin(_strip_reserved(words))
        if not argv or argv[0] == "eval":
            return []
        argv, _env, _wrappers, string = _unwrap_inner(argv, 0)
        if string:
            return [string]
        return [shlex.join(inner) for inner in find_exec_commands(argv)]
    except ShellRejected:
        return []


def nested_commands(command: str) -> list[str]:
    """``command`` and the command lines inside it: ``sh -c`` strings, the
    words of ``eval``, here-document bodies and command substitutions, to four
    levels (each level is part of the one above, so this stays linear)."""
    return list(_nesting(command)[0])


def nested_too_deep(command: str) -> bool:
    """Whether ``command`` holds command lines nested deeper than
    :func:`nested_commands` reads (``$($($($($(…)))))``), or deeper than the
    lexer reads ``$(…)``: what runs there is not checked."""
    return _nesting(command)[1] or lex(command).deep


@functools.lru_cache(maxsize=32)
def _nesting(command: str) -> tuple[tuple[str, ...], bool]:
    found: list[str] = []
    deep = [False]

    def walk(text: str, depth: int) -> None:
        found.append(text)
        lexed = lex(text)
        inner = _inner_commands(text)
        texts = [t for t in dict.fromkeys([*inner, *lexed.bodies, *lexed.substitutions]) if t]
        deep[0] |= options_capped(text)
        if depth >= 4:
            deep[0] |= bool(texts)
            return
        for t in texts:
            walk(t, depth + 1)

    walk(command, 0)
    return tuple(found), deep[0]


def script_runs_loosely(command: str) -> list[dict[str, str]]:
    """Best effort for a command the parser rejected (``bash x.sh "$TARGET"``,
    ``OUT=$(bash x.sh)``, ``for i in 1 2; do ./x.sh "$i"; done``): for the
    command and every command line nested in it (:func:`nested_commands`:
    ``sh -c`` strings, ``eval`` words, ``$(…)``, backticks, here-document
    bodies), splits the lexer's tokens into simple commands at the shell's
    separators (quotes heeded: ``bash x.sh 'a;b'`` is one command), strips
    reserved words and launchers, and returns what :func:`code_run` finds in
    each, each script once. Never raises; only for asking, never for allowing."""
    found: dict[tuple, dict[str, str]] = {}
    for text in nested_commands(command):
        for words, redirects in _simple_commands(_shell_tokens(text)):
            runs = _loose_run(words, redirects)
            if runs is not None:
                found.setdefault(tuple(sorted(runs.items())), runs)
                source = _stdin_file(SimpleCommand([], redirects))
                if runs["kind"] == "script" and "$" in runs.get("path", "") and source and (
                        _basename(runs.get("interpreter", "")) in _SHELLS):
                    # sh < x.sh $X: with $X empty, sh reads its commands from x.sh
                    extra = {"kind": "script", "interpreter": runs["interpreter"],
                             "path": f"< {source}"}
                    found.setdefault(tuple(sorted(extra.items())), extra)
            for runs in [*_rcfile_runs(words), *_value_reading_runs(words, redirects)]:
                found.setdefault(tuple(sorted(runs.items())), runs)
    return list(found.values())


def value_reading_scripts(command: str) -> list[dict[str, str]]:
    """The scripts shells in ``command`` (or in a command line nested in it)
    run when their :func:`ambiguous_option` clusters are read as values
    (``zsh -onoclobber x.sh`` -> x.sh; the other reading, ``-c`` set, makes
    x.sh the command string and is checked as such), as ``runs_code`` script
    records."""
    return [runs for text in nested_commands(command)
            for words, redirects in _simple_commands(_shell_tokens(text))
            for runs in _value_reading_runs(words, redirects)]


def _value_reading_runs(words: list[str], redirects: list[str] | None = None
                        ) -> list[dict[str, str]]:
    """:func:`value_reading_scripts` for one simple command's words (and its
    standard-input redirections, for ``-s``)."""
    argv = _shell_in_command_position(words)
    if not argv:
        return []
    shell, ambiguous, j = _basename(argv[0]), False, 1
    while j < len(argv):
        word = argv[j]
        if word in SHELL_OPTIONS_END:  # bash - x.sh: a lone - ends the options too
            j += 1
            break
        if not word.startswith(("-", "+")) or word == "+":
            break
        ambiguous = ambiguous or ambiguous_option(word, shell)
        values, letters = shell_option(word, shell, as_value=True)
        short = word.startswith("-") and not word.startswith("--")
        if short and "c" in letters:
            return []  # a real -c: its string is read as a command line
        if short and "s" in letters:  # -s ARGS: the code is standard input
            source = _stdin_file(SimpleCommand([], redirects or []))
            return [{"kind": "script", "interpreter": shell, "path": f"< {source}"}] \
                if ambiguous and source else []
        j += 1 + values
    if not ambiguous or j >= len(argv):
        return []
    return [{"kind": "script", "interpreter": shell, "path": argv[j]}]


def _shell_in_command_position(words: list[str]) -> list[str]:
    """The argv of the shell a simple command runs, after reserved words and
    launchers (``sudo zsh …``); ``[]`` when it runs no shell there."""
    try:
        argv = strip_exec_builtin(_strip_reserved(words))
        argv = _unwrap_inner(argv, 0)[0] if argv else argv
    except ShellRejected:
        argv = words
    return argv if argv and _basename(argv[0]) in _SHELLS else []


def interactive_rcfiles(command: str) -> list[dict[str, str]]:
    """The startup files an interactive shell in ``command`` (or in a command
    line nested in it) sources: ``bash --rcfile x.sh -i``, ``bash --init-file
    x.sh -ic 'echo'``, as ``runs_code`` script records. A shell that is not
    interactive (``-c`` alone) does not read them."""
    return [runs for text in nested_commands(command)
            for words, _redirects in _simple_commands(_shell_tokens(text))
            for runs in _rcfile_runs(words)]


def _rcfile_runs(words: list[str]) -> list[dict[str, str]]:
    """:func:`interactive_rcfiles` for one simple command's words: the shell in
    command position (after reserved words and launchers; ``echo bash -i
    --rcfile x`` runs no shell)."""
    argv = _shell_in_command_position(words)
    if not argv:
        return []
    shell = _basename(argv[0])
    files, interactive, short, j = [], False, False, 1
    while j < len(argv):
        word = argv[j]
        if word == "--" or not word.startswith(("-", "+")) or word in ("-", "+"):
            break
        # only bash has --rcfile, and only before its short options (bash -i
        # --rcfile x is an error)
        if word in ("--rcfile", "--init-file") and j + 1 < len(argv) and (
                shell in ("bash", "rbash") and not short):
            files.append(argv[j + 1])
        short = short or not word.startswith("--")
        values, letters = shell_option(word, shell)
        if word.startswith("-") and not word.startswith("--") and "i" in letters:
            interactive = True  # -i, -ic, -il, -io pipefail
        j += 1 + values
    if not interactive:
        return []
    return [{"kind": "script", "interpreter": shell, "path": path} for path in files]


# Words around which a pipe may lead into a compound command, whose reader the
# pipeline does not show (cat <<E | if …; then python3 -c …; fi).
_COMPOUND_RESERVED = frozenset({"{", "}", "if", "then", "else", "elif", "fi", "while", "until",
                                "do", "done", "for", "select", "case", "esac", "function",
                                "coproc"})
_CASE_LEADERS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "{", "!",
                           "time"})


def _simple_commands(tokens: tuple[_Token, ...], *, case_patterns: bool = False
                     ) -> Iterator[tuple[list[str], list[str]]]:
    """The words and the standard-input redirections (``<x.sh``) of each simple
    command in ``tokens``, split at every separator (``;``, ``&``, ``|``,
    ``&&``, ``||``, newline, ``(``, ``)``, ``;;``)."""
    words: list[str] = []
    redirects: list[str] = []
    cases = 0  # open case … esac (only read with case_patterns, for the glob check)
    pattern = False  # in a case arm's pattern, up to its )
    plain_case = False
    lead = 0  # reserved words in front of this command (do, then, {, !, time)
    k = 0
    while k < len(tokens):
        kind, value, _s, _e = tokens[k]
        if pattern:  # `a|b*)`, `*)`: patterns, not commands
            if kind == "word" and value == "esac" and not words:
                cases -= 1
                pattern = False
            elif kind == "sep" and value == ")":
                pattern = False
            k += 1
            continue
        if (case_patterns and kind == "word" and value == "in" and len(words) - lead == 2
                and plain_case and not redirects):
            pattern, words, lead = True, [], 0  # case WORD in: an arm's pattern next
            cases += 1
            k += 1
            continue
        if kind == "sep":
            if words or redirects:
                yield _without_function_header(words), redirects
            words, redirects, lead = [], [], 0
            if cases and (value == ";;" or (value == ";" and tokens[k + 1:k + 2]
                                            and tokens[k + 1][:2] == ("sep", "&"))):
                pattern = True  # ;; ;& ;;&: the next arm's pattern
        elif kind == "op":  # the operator and its target word
            has_target = k + 1 < len(tokens) and tokens[k + 1][0] == "word"
            redirects.append(value + (tokens[k + 1][1] if has_target else ""))
            k += 2 if has_target else 1
            continue
        elif kind == "word" and value == "esac" and cases and not words:
            cases -= 1
        else:
            if len(words) == lead and value in _CASE_LEADERS and _e - _s == len(value):
                lead += 1  # do case …, then case …, { case … (spelt bare: "do" is a word)
            elif len(words) == lead:  # an unquoted `case` first (after those), with no
                # redirect or other word before it, starts a case statement
                plain_case = value == "case" and _e - _s == 4 and not redirects
            words.append(value)
        k += 1
    if words or redirects:
        yield _without_function_header(words), redirects


def _without_function_header(words: list[str]) -> list[str]:
    """``words`` without a leading ``function NAME`` (the body that follows is
    read like that of ``NAME() { …; }``)."""
    return words[2:] if words[:1] == ["function"] else words


def _peel_precommands(argv: list[str]) -> list[str]:
    """``argv`` without zsh's precommand words in front (``noglob``,
    ``nocorrect``, ``repeat N``) and the ``exec``/``builtin`` after them, so
    ``noglob source x.sh`` is read like ``source x.sh``."""
    i = 0
    while i < len(argv):
        if argv[i] in ("noglob", "nocorrect"):
            i += 1
        elif argv[i] == "repeat" and i + 2 < len(argv):
            i += 2
        else:
            break
    return strip_exec_builtin(argv[i:]) if i else argv


def _loose_run(words: list[str], redirects: list[str]) -> dict[str, str] | None:
    """What one simple command of :func:`script_runs_loosely` runs."""
    try:
        argv = _peel_precommands(strip_exec_builtin(_strip_reserved(words)))  # exec bash x.sh
    except ShellRejected:
        return None
    if not argv or argv[0] == "eval":  # eval's words: a nested command line
        return None
    if _basename(argv[0]) in ("source", "."):
        return {"kind": "script", "interpreter": argv[0], "path": argv[1] if len(argv) > 1 else ""}
    try:
        argv, _env, _wrappers, string = _unwrap_inner(argv, 0)
    except ShellRejected:
        return None
    if string is not None:  # sh -c STRING: a nested command line
        return None
    stdin = [r for r in redirects if r.startswith(("<", "0<"))]
    return code_run(SimpleCommand(argv, stdin))


# Words that name a script to run, rather than a file to read.
_SCRIPT_WORD_RE = re.compile(r"^(?:\.{1,2}/|~/)|\.(?:sh|bash|zsh|ksh|py|rb|pl|js|mjs|php|lua)$")


def opaque_launcher_code(command: str) -> str | None:
    """Best effort for a command the parser rejected: a shell, interpreter or
    script named after a launcher the parser could not unwrap (an option of
    ``env``/``sudo``/… it does not know, ``sudo -i``, an ``env -S`` string it
    does not split), so what the launcher runs is unknown: ``env -P x bash
    x.sh``, ``sudo -iu bob bash x.sh``, ``cat x.sh | env -Q sh``. Returns that
    word, else ``None``. Never raises; only for asking."""
    parts = (words for text in nested_commands(command)
             for words, _redirects in _simple_commands(_shell_tokens(text)))
    for words in parts:
        try:
            argv = _peel_precommands(strip_exec_builtin(_strip_reserved(words)))
        except ShellRejected:
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
    ``-execdir``, ``-ok`` or ``-okdir`` up to ``;``, or up to a ``+`` right
    after ``{}`` (any other ``+`` is an argument: ``env -u + cmd``; ``{}``, the
    file, stays a literal argument). ``[]`` for anything but ``find``."""
    if not argv or _basename(argv[0]) != "find":
        return []
    found: list[list[str]] = []
    i = 1
    while i < len(argv):
        if argv[i] in _FIND_EXEC_FLAGS:
            j = i + 1
            while j < len(argv) and argv[j] != ";" and not (
                    argv[j] == "+" and argv[j - 1] == "{}"):
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
    spellings: list = []  # this text's quoting, read once when first needed

    def globbed(word: str, wrappers: list[str]) -> bool:
        if not _globbed(word):
            return False
        if not spellings:
            spellings.append(_glob_spellings(command))
        return _program_globbed(command, word, wrappers, spellings[0])

    for simple in split_compound(command):
        argv, env, wrappers, string = _unwrap_inner(simple.argv, depth)
        if string is None:
            yield (SimpleCommand(argv, simple.redirects, simple.in_pipeline, simple.stdin_pipe,
                                 bool(argv) and globbed(argv[0], wrappers)),
                   env, wrappers)
            for inner_argv in find_exec_commands(argv):
                # find runs CMD without a shell, but the outer shell has already
                # expanded find's words: CMD's program is a glob as spelt here
                for inner, inner_env, inner_wrappers in _expand(shlex.join(inner_argv),
                                                                depth + 1):
                    inner_globbed = inner.globbed or bool(inner.argv) and globbed(
                        inner.argv[0], [])
                    yield (SimpleCommand(inner.argv, inner.redirects, globbed=inner_globbed),
                           {**env, **inner_env}, [*wrappers, "find -exec", *inner_wrappers])
            continue
        for inner, inner_env, inner_wrappers in _expand(string, depth + 1):
            yield (
                SimpleCommand(
                    inner.argv,
                    [*simple.redirects, *inner.redirects],
                    simple.in_pipeline or inner.in_pipeline,
                    simple.stdin_pipe or inner.stdin_pipe,
                    inner.globbed,
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
        if simple.globbed:
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
