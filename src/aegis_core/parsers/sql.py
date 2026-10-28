"""SQL statement-class gating (PLAN §7.8).

``from_sql`` splits a batch of SQL text into individual statements with a
small hand-written, dialect-aware lexer (no SQL-parsing library: just enough
quote/escape/comment/dollar-quote awareness to split correctly on ``;``) and
classifies each one by its leading keyword(s) into the shared
InfrastructureIntent shape (see ``aegis_core.parser`` / PLAN §3.1):
``resource`` is ``kind/name``, ``action`` is one of the shared verbs, and
``params["raw_action"]`` carries the literal SQL keyword(s) matched.

Classification is fail-safe: a statement this module doesn't recognise is
never treated as a harmless ``read`` -- it becomes ``update`` with
``params["unclassified"] = True`` so it still has to clear a real
constraint check rather than sailing through uncovered.

The DB-CLI wrappers (``from_psql``/``from_mysql``/``from_sqlite3``) and
``from_mongosh`` extract the SQL/JS payload from an argv and dispatch into
the same classifier (or, for mongosh, a small parallel one for the Mongo
shell's dot-method calls). ``from_migration_argv`` covers the coarser
migration-tool commands (alembic/flyway/rails/prisma) that don't carry SQL
text at all.

REVIEW-4 T1.4 hardening -- evasion shapes now handled:

* Comments (``--``, ``/* */``, MySQL ``#``) are stripped, quote-aware, *before*
  classification, so ``DELETE/**/FROM users`` is no longer unclassified.
* ``TRUNCATE``/``DROP TABLE|SCHEMA|DATABASE|INDEX|VIEW``/unwhered ``DELETE``
  all carry ``params["unbounded"] = True`` (DROP/TRUNCATE also
  ``params["ddl"] = True``).
* ``WITH cte AS (DELETE|UPDATE|INSERT ...) SELECT ...`` reports the DML
  inside the CTE, strongest first (delete > update > put), with
  ``params["cte"] = True`` (since #58: every DML operation, see below).
* ``EXPLAIN <stmt>`` reads (``params["explain"] = True``); ``EXPLAIN ANALYZE
  <stmt>`` is classified as ``<stmt>`` itself (Postgres executes it), plus
  ``params["explain_analyze"] = True``.
* ``DO $$ ... $$``, ``CALL proc(...)``, ``EXECUTE ...``, ``PERFORM ...`` are
  opaque write operations (``update``, ``params["opaque"] = True``,
  resource ``procedure/<name>`` when parseable else ``block/*``) --
  fail-safe, never treated as reads.
* MySQL multi-table ``DELETE t1, t2 FROM t1 JOIN t2 ...`` deletes from each
  listed table; ``DELETE FROM t1 USING t2`` deletes from ``t1`` and reads
  ``t2``.
* ``DROP SCHEMA ... [CASCADE]`` / ``DROP DATABASE ...`` set
  ``params["cascade"]`` when ``CASCADE`` is present, and additionally emit a
  *second*, synthetic ``table/*`` unbounded-delete intent (``metadata["schema"]``
  set to the dropped schema/database name) so table-scoped deletion rules
  also fire against everything the drop cascades into.
* ``from_psql``/``from_mysql``/``from_sqlite3`` collect *every*
  ``-c``/``-e``/``--command``/``--execute`` occurrence (argv order), not
  just the last one. A ``-f``/``--file`` script that doesn't exist on disk
  yields ``update`` with ``params["unreadable"] = params["opaque"] = True``
  (fail-safe -- never a silent ALLOW). Shell input redirection (``< file``)
  carries no trace in argv and cannot be recovered here.
* ``from_mongosh`` understands ``db.getCollection("x").method(...)`` and
  ``db["x"].method(...)`` collection selectors (not just ``db.x.method``),
  and a chained ``db.x.find(...).forEach(...)`` classifies by the leading
  ``find`` call (read) instead of being silently dropped. ``.drop()`` /
  ``.dropDatabase()`` now also carry ``params["unbounded"] = True``.
* GRANT/REVOKE fall back to resource ``privilege/*`` (not ``role/*``) when
  the grantee can't be parsed out of the statement.

Issue #58 -- what a statement reads, and statements that were weaker than they look:

* One dialect-aware lexer does the splitting, the comment removal and the
  scan below, so they agree on where every string and comment ends.
  ``''`` escapes a quote everywhere; ``\\'`` does too inside ``E'...'`` (any
  dialect) and inside every MySQL string, single- or double-quoted, as the
  server reads them, while a plain ``'...'`` keeps the standard reading in
  ``postgres``/``sqlite``/``generic``. ``$$``/``$tag$`` bodies are strings
  (not in MySQL or SQLite). ``E'...'`` and ``U&'...'``/``U&"..."`` (with
  ``UESCAPE``, comments allowed around it; not in MySQL) are decoded; an
  escaped literal is never compared to a keyword as plain text
  (``set_config(U&'\\0072ole', ...)`` fails safe).
  SQLite ``[name]`` is an identifier. MySQL ``#`` and ``-- `` comments are
  comments; ``--`` not followed by whitespace is not, in MySQL. Postgres
  block comments nest; MySQL's and SQLite's do not. The body of a MySQL
  executable comment (``/*! ... */``, ``/*!50000 ...``, ``/*M! ...``) is read
  as SQL under ``mysql`` and ``generic`` -- MySQL runs it -- and as a plain
  comment under ``postgres`` and ``sqlite``; a quote, ``--``, ``#`` or ``/*``
  in it (under ``generic``, or a versioned one under ``mysql``, which an older
  server skips) adds an unclassified ``ambiguous_comment``. ``E'...'``
  escapes are Postgres only. ``generic`` can't know which reading applies, so a backslash before
  a quote in a plain string, or a ``/*`` inside a block comment, adds an
  ``unknown/*`` ``update`` (``ambiguous_escape`` / ``ambiguous_comment``).
  The keyword regexes run on the statement with comments removed and every
  string literal blanked, so nothing inside a string can match.
* Every table the scan can see becomes its own ``read`` intent
  (deduplicated, in order): ``FROM`` and every ``JOIN`` target, comma joins
  (a clause word used as an alias -- ``products set, users`` -- and a MySQL
  index hint -- ``FORCE INDEX FOR ORDER BY (i)`` -- do not end the list),
  subqueries, ``UNION``/``INTERSECT``/``EXCEPT`` branches, ``TABLE
  t`` and ``WITH`` bodies. A CTE's name is not a table (except inside its own
  non-recursive body); a function in ``FROM`` (``generate_series(...)``,
  ``ROWS FROM (...)``) is not a table, and neither is ``dual`` in MySQL.
  Tables read inside functions, views or procedures a query calls are not
  seen: the database role's grants are the backstop.
* Every DML operation in a statement is reported -- the top-level one and
  each one inside a ``WITH`` body -- strongest first (delete > update > put),
  each with its own target (``params["cte"]`` when the statement starts with
  ``WITH``). ``ONLY`` and MySQL's ``LOW_PRIORITY``/``QUICK``/``IGNORE``/
  ``DELAYED`` are not table names; MySQL multi-table ``DELETE t1, t2 FROM``
  and ``UPDATE t1 JOIN t2 ... SET`` write every listed table (the UPDATE
  walk to ``SET`` has no cutoff). A MySQL DELETE target that is an alias
  resolves to its table, using only the aliases of the DELETE's own query
  block (one naming no table or alias there, or an alias of two tables,
  deletes from every table read); a plain ``DELETE FROM t`` is never
  re-resolved. An upsert (``ON CONFLICT ... DO UPDATE``, ``ON DUPLICATE KEY
  UPDATE``) is a ``put`` and an ``update``; ``REPLACE`` / SQLite ``INSERT OR
  REPLACE`` a ``put`` and a ``delete`` (``params["upsert"]``). ``DROP <kind>
  a, b`` and ``TRUNCATE a, b`` delete every name (a schema or database each
  with its ``table/*``). ``MERGE INTO
  t`` is the strongest of its ``WHEN ... THEN`` actions (``update`` if none
  is found). A DML keyword whose target can't be read is ``unknown/*``
  ``update``, unclassified. ``unbounded`` means no ``WHERE`` in the
  operation's own bracket group. A write also reads every *other* table it
  names (``INSERT ... SELECT``/``TABLE t``, ``UPDATE ... FROM``, ``DELETE
  ... USING``, ``CREATE TABLE|VIEW ... AS SELECT``).
* ``EXPLAIN <stmt>`` (and MySQL ``DESCRIBE|DESC <stmt>``) reads every table
  ``<stmt>`` names; with ``ANALYZE`` -- ``EXPLAIN ANALYZE``, ``EXPLAIN
  (ANALYZE[, ...])`` -- it is classified as ``<stmt>``. Repeated prefixes
  are stripped in a loop.
* ``SELECT ... INTO t`` is a ``create`` of ``table/t`` (``params["ddl"]``,
  ``params["select_into"]``), like ``CREATE TABLE t AS SELECT``, plus its
  reads. MySQL ``SELECT ... INTO OUTFILE|DUMPFILE`` writes a file: ``update``
  of ``file/<path>`` with ``params["opaque"] = params["unclassified"] = True``.
  ``SELECT ... INTO @var`` only sets a variable and stays a read. ``INTO
  OUTFILE`` is a file write wherever it appears (after ``TABLE``, ``VALUES``
  or a parenthesised query too); ``(SELECT ... INTO t ...)`` is a create,
  also right after a ``WITH`` list. ``DROP`` lists are deduplicated.
* A ``BEGIN ATOMIC`` function body is still split on ``;`` (merging it would
  let a later statement hide inside), but its first DML is reported.
* ``SET [SESSION|LOCAL] ROLE``, ``SET SESSION AUTHORIZATION``, ``SET
  role|"role"|session_authorization = ...``, ``RESET ROLE|SESSION
  AUTHORIZATION``, MySQL ``SET DEFAULT ROLE`` and ``SET PASSWORD``, and
  ``[pg_catalog.]set_config(...)`` on ``role``/``session_authorization``
  change identity: ``update`` of ``role/<name>`` with ``params["privilege"]
  = True``, as GRANT/REVOKE. ``role/*`` when the name is NONE/DEFAULT or
  can't be read, and for a ``set_config`` whose setting is not a plain string
  literal (it might be ``role``). Other ``SET``s stay ``session/*`` reads.
* A locking read (``FOR UPDATE``, ``FOR NO KEY UPDATE``, ``FOR SHARE``, ``FOR
  KEY SHARE``, MySQL ``LOCK IN SHARE MODE``) stays a ``read`` -- it changes no
  data -- but each of its reads carries ``params["locking"] = True``,
  ``params["lock_strength"]`` (the strongest lock taken) and ``nowait`` /
  ``skip_locked`` when given, so a rule can match it with ``scope: {locking:
  true}``.
* The scan is linear and never recurses (deep nesting, thousands of CTEs or
  repeated ``EXPLAIN`` prefixes stay fast). A statement over
  ``_MAX_STATEMENT_TOKENS`` tokens is classified from its first part plus an
  ``unknown/*`` ``update`` with ``params["too_large"]`` for the rest.

See the ``evasion`` list at the bottom of this module for the full
enumeration (imported by the adversarial test suite).
"""

import bisect
import contextlib
import contextvars
import copy
import re
from collections.abc import Iterator
from typing import Any, NamedTuple

from aegis_core.intent import InfrastructureIntent
from aegis_core.parser import _basename, _coerce  # noqa: F401  (re-exported convention)

# --- lexing ---------------------------------------------------------------------
#
# One dialect-aware lexer serves statement splitting, comment removal and the
# table/DML scan (#58), so the three can never disagree about where a string
# or a comment ends:
#
# * ``'...'`` strings take ``''`` as an escaped quote everywhere, and also
#   ``\x`` in ``E'...'`` strings (any dialect) and in every MySQL string
#   (single- or double-quoted), as the server reads them. ``E'...'`` and
#   ``U&'...'`` (with ``UESCAPE``) bodies are decoded; such a literal is
#   marked ``escaped`` so a check that compares it to a keyword (``role``)
#   treats it as not-a-plain-literal and fails safe.
# * ``"..."`` is a quoted identifier (in MySQL its body follows the string
#   escape rules above), ``U&"..."`` a decoded one; `` `...` `` is a MySQL
#   identifier and ``[...]`` a SQLite one.
# * ``$$...$$`` / ``$tag$...$tag$`` are strings (not in MySQL or SQLite, which
#   have no dollar quoting); ``$1`` is a parameter.
# * ``--`` comments (MySQL: only ``--`` followed by whitespace), MySQL ``#``
#   comments and ``/* */`` comments are dropped; Postgres block comments
#   nest. An executable comment ``/*! ... */`` (``/*!50000``, MariaDB
#   ``/*M!``) is not a comment to MySQL: under ``mysql`` and ``generic`` only
#   its markers are dropped and its body is read as SQL; Postgres and SQLite
#   skip it like any comment.
# * ``generic`` cannot know which reading the server uses, so a backslash
#   before a quote in a plain string, or a ``/*`` inside a block comment,
#   marks the statement ambiguous: it then also yields an unclassified write.


class _T(NamedTuple):
    kind: str  # word, qident, str, var, param, num, punct
    value: str  # unquoted identifier / decoded string contents / the text itself
    raw: str
    gap: bool  # whitespace or a comment came before it
    escaped: bool = False  # an E'', U&'' or backslash-escaped literal


# Only ASCII whitespace separates tokens: PostgreSQL, MySQL and SQLite read any
# other character (a no-break space, U+3000, …) as part of an identifier.
_WS_CHARS = " \t\n\r\f\v"
_WS_RE = re.compile(r"[ \t\n\r\f\v]+")
_EXEC_OPEN_RE = re.compile(r"/\*M?!\d*")
# An executable comment some servers skip: versioned, or MariaDB-only.
_VERSIONED_OPEN_RE = re.compile(r"/\*(?:M!\d*|!\d+)")
_VERSION_NUMBER_RE = re.compile(r"/\*M?!(\d+)")
# Distinct comment versions read one by one; past this many the text is flagged.
_MAX_VERSION_READINGS = 4
# Text in a /*! … */ body that would move where another reader ends it.
_BODY_MARKER_RE = re.compile(r"['\"`#$]|--|/\*")
_COMMENT_MARK_RE = re.compile(r"/\*|\*/")
_DOLLAR_OPEN_RE = re.compile(r"\$(?:[^\W\d][\w]*)?\$")
_CHARSET_PREFIX_RE = re.compile(r"_[A-Za-z0-9]+(?=')")
_UESCAPE_RE = re.compile(r"UESCAPE(?![\w$])", re.IGNORECASE)
_WORD_RE = re.compile(r"(?:[^\W\d]|[^\x00-\x7f])(?:[\w$]|[^\x00-\x7f])*")
_NUM_RE = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+")
# MySQL identifiers may start with a digit or `$` (`2fa_codes`, `$secret`); a
# word that is all digits, or a number with an exponent, is still a number.
_MYSQL_IDENT_RE = re.compile(r"[\d$](?:[\w$]|[^\x00-\x7f])*")
_MYSQL_NUMBER_RE = re.compile(r"\d+(?:[eE][+-]?\d+)?|0[xX][0-9a-fA-F]+|0[bB][01]+")
_PARAM_RE = re.compile(r"\$\d+")
_VAR_RE = re.compile(r"@@?(?:[\w$.]+|'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.|\"\")*\"|`[^`]*`)")
# Outside MySQL ``@`` is an operator (``@ 'x'``, ``@'x'``) or a named parameter
# (``@name``): a quote after it starts an ordinary string of the dialect.
_NAMED_VAR_RE = re.compile(r"@@?[\w$.]+")
_BODY_RE = {
    ("'", False): re.compile(r"(?:[^']|'')*", re.DOTALL),
    ("'", True): re.compile(r"(?:[^'\\]|\\.|'')*", re.DOTALL),
    ('"', False): re.compile(r'(?:[^"]|"")*', re.DOTALL),
    ('"', True): re.compile(r'(?:[^"\\]|\\.|"")*', re.DOTALL),
    ("`", False): re.compile(r"(?:[^`]|``)*", re.DOTALL),
}
_BACKSLASH_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_E_ESCAPE_RE = re.compile(
    r"\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|(.))|''",
    re.DOTALL,
)
_E_SIMPLE = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _chr(code: int) -> str:
    try:
        return chr(code)
    except (ValueError, OverflowError):
        return "�"


def _decode_e_string(body: str) -> str:
    """Postgres ``E'...'`` escapes: ``\\n``, ``\\145`` (octal), ``\\x65``,
    ``\\u0065``, ``\\U00000065``, ``\\<c>`` and ``''``."""
    def repl(m: re.Match[str]) -> str:
        octal, hx, u4, u8, other = m.groups()
        if m.group(0) == "''":
            return "'"
        if octal:
            return _chr(int(octal, 8))
        if hx:
            return _chr(int(hx, 16))
        if u4 or u8:
            return _chr(int(u4 or u8, 16))
        return _E_SIMPLE.get(other, other)
    return _E_ESCAPE_RE.sub(repl, body)


def _decode_unicode(body: str, esc: str) -> str:
    """``U&'...'`` / ``U&"..."``: ``<esc>XXXX``, ``<esc>+XXXXXX``, ``<esc><esc>``."""
    e = re.escape(esc)
    pattern = re.compile(rf"{e}(?:{e}|\+([0-9A-Fa-f]{{6}})|([0-9A-Fa-f]{{4}}))")

    def repl(m: re.Match[str]) -> str:
        code = m.group(1) or m.group(2)
        return esc if code is None else _chr(int(code, 16))
    return pattern.sub(repl, body)


_LINE_END_RE = re.compile(r"[\n\r]")
_START_TRANSACTION_RE = re.compile(r"\s*START\s+TRANSACTION\b", re.IGNORECASE)
_CLIENT_COMMAND_RE = re.compile(r"\\([A-Za-z]+|[!.?#])")
_DOT_COMMAND_RE = re.compile(r"\.([A-Za-z]+)")
_PIPE_AFTER_RE = re.compile(r"[ \t]*\|")
# sqlite3 dot-commands that only set how results are shown, or show the schema.
_FORMAT_DOT_COMMANDS = frozenset({
    "mode", "headers", "header", "separator", "nullvalue", "width", "timeout", "bail",
    "echo", "changes", "timer", "eqp", "explain", "stats", "prompt", "tables", "schema",
    "indexes", "indices", "databases", "help", "dump",
})


def _at_line_start(sql: str, i: int) -> bool:
    """Whether only spaces or tabs come between the start of ``sql`` or of a
    line and position ``i`` (each run of them is walked once per dot)."""
    k = i - 1
    while k >= 0 and sql[k] in " \t":
        k -= 1
    return k < 0 or sql[k] in "\n\r"


def _line_comment_end(sql: str, i: int, cr: bool) -> int:
    """Where a ``--`` (or MySQL ``#``) comment starting at ``i`` ends: the next
    newline, or, when ``cr`` (Postgres, and ``generic``, which reads more
    statements that way), the next newline or carriage return."""
    if cr:
        m = _LINE_END_RE.search(sql, i)
        return len(sql) if m is None else m.start()
    j = sql.find("\n", i)
    return len(sql) if j == -1 else j


def _skip_noise(sql: str, i: int, nested: bool, cr: bool = False) -> int:
    """Index of the first character at or after ``i`` that is not whitespace
    or a ``--`` / ``/* */`` comment."""
    n = len(sql)
    while i < n:
        if sql[i] in _WS_CHARS:
            i += 1
        elif sql.startswith("--", i):
            i = _line_comment_end(sql, i, cr)
        elif sql.startswith("/*", i) and not nested:
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif sql.startswith("/*", i):
            level, j = 1, i + 2
            while level and j < n:
                cm = _COMMENT_MARK_RE.search(sql, j)
                if cm is None:
                    j = n
                    break
                level += 1 if cm.group(0) == "/*" else -1
                j = cm.end()
            i = j
        else:
            break
    return i


def _uescape(sql: str, i: int, nested: bool) -> tuple[str, int] | None:
    """``UESCAPE 'c'`` after a ``U&`` literal ending at ``i``, comments
    allowed around it: (escape char, index after it), or None."""
    j = _skip_noise(sql, i, nested, cr=True)  # U& literals: Postgres and generic only
    if not _UESCAPE_RE.match(sql, j):
        return None
    k = _skip_noise(sql, j + 7, nested, cr=True)
    if sql[k : k + 1] == "'" and sql[k + 2 : k + 3] == "'":
        return sql[k + 1], k + 3
    return None


# Statements longer than this are scanned only up to it, plus an unclassified
# write for the rest: the scan is linear, the cap only bounds its cost.
_MAX_STATEMENT_TOKENS = 100_000

_Statement = tuple[list[_T], bool, frozenset[str]]


def _lex(sql: str, dialect: str, version: float = float("inf"),
         mariadb: bool = True) -> list[_Statement]:
    """Lexes ``sql`` and splits it on ``;``: a list of (tokens, had_comment,
    flags) per non-empty statement. A statement with no tokens but a comment
    is kept (it is classified as unknown, never dropped). ``flags`` holds
    ``ambiguous_escape`` / ``ambiguous_comment`` (``generic``, and a MySQL
    ``--`` followed by a control character)."""
    mysql = dialect == "mysql"
    generic = dialect == "generic"
    nested_comments = dialect == "postgres"
    dollar_quotes = dialect not in ("mysql", "sqlite")
    statements: list[_Statement] = []
    toks: list[_T] = []
    flags: set[str] = set()
    had_comment = False
    gap = False
    exec_open = 0
    i, n = 0, len(sql)
    close_from, close, last_marker = n + 1, -1, -1  # the last /*! … */ body searched

    def emit(kind: str, value: str, raw: str, escaped: bool = False) -> None:
        nonlocal gap
        toks.append(_T(kind, value, raw, gap, escaped))
        gap = False

    while i < n:
        ch = sql[i]
        if ch in _WS_CHARS:
            i = _WS_RE.match(sql, i).end()  # type: ignore[union-attr]
            gap = True
            continue
        if exec_open and sql.startswith("*/", i):
            exec_open -= 1
            i += 2
            gap = True
            continue
        control_dash = mysql and sql.startswith("--", i) and i + 2 < n and (
            ord(sql[i + 2]) < 32 or sql[i + 2] == "\x7f") and sql[i + 2] not in _WS_CHARS
        if control_dash:
            # --<control>: a comment to the server, not to the mysql client, which
            # then splits the text elsewhere
            flags.add("ambiguous_comment")
        if (ch == "-" and sql.startswith("--", i)
                and (not mysql or i + 2 >= n or sql[i + 2] in _WS_CHARS or control_dash)) or (
                ch == "#" and mysql):
            # Postgres ends a -- comment at a carriage return too
            i = _line_comment_end(sql, i, cr=dialect in ("postgres", "generic"))
            gap = had_comment = True
            continue
        if ch == "/" and sql.startswith("/*", i):
            em = _EXEC_OPEN_RE.match(sql, i) if dialect in ("mysql", "generic") else None
            if em and (("M" in em.group(0) and not mariadb)
                       or int(em.group(0).lstrip("/*M!") or 0) > version):
                em = None  # a server of that version (or Oracle MySQL) skips it
            if em:
                # MySQL runs the body of /*! … */ (unless its version is newer than the
                # server's); other servers skip to the first */. When text in the body
                # would move where it ends, the readings differ.
                opener = em.group(0)
                # versioned (skipped by an older server) or MariaDB-only /*M! (a
                # plain comment to Oracle MySQL)
                if generic or "M" in opener or any(c.isdigit() for c in opener):
                    if not (close_from <= em.end() and (close == -1 or close >= em.end())):
                        # MySQL comments do not nest: one search serves every opener
                        # before the same */, so this stays linear
                        close_from, close = em.end(), sql.find("*/", em.end())
                        end_at = n if close == -1 else close
                        last_marker = -1
                        for mk in _BODY_MARKER_RE.finditer(sql, em.end(), end_at):
                            last_marker = mk.start()
                    if last_marker >= em.end():
                        flags.add("ambiguous_comment")
                exec_open += 1
                i = em.end()
            elif nested_comments:
                level, j = 1, i + 2
                while level and j < n:
                    cm = _COMMENT_MARK_RE.search(sql, j)
                    if cm is None:
                        j = n
                        break
                    level += 1 if cm.group(0) == "/*" else -1
                    j = cm.end()
                i = j
                had_comment = True
            else:
                j = sql.find("*/", i + 2)
                end = n if j == -1 else j + 2
                if generic and sql.find("/*", i + 2, end) != -1:
                    flags.add("ambiguous_comment")  # Postgres would nest it
                i = end
                had_comment = True
            gap = True
            continue

        start = i
        quote = ""
        backslash = mysql
        e_string = unicode = False
        if ch in "'\"`":
            quote = ch
        elif ch in "EeNnBbXx" and sql[i + 1 : i + 2] == "'":
            # E'…' escapes are Postgres only (generic flags them below)
            quote, e_string = "'", ch in "Ee" and dialect in ("postgres", "generic")
            i += 1
        elif (ch in "Uu" and not mysql and dialect != "sqlite" and sql[i + 1 : i + 2] == "&"
              and sql[i + 2 : i + 3] in ("'", '"')):  # MySQL and SQLite have no U& literals
            quote, unicode, backslash = sql[i + 2], True, False
            i += 2
        elif ch == "_" and mysql:
            cm = _CHARSET_PREFIX_RE.match(sql, i)
            if cm:
                quote = "'"
                i = cm.end()
        elif ch == "[" and dialect == "sqlite":
            j = sql.find("]", i + 1)
            end = n if j == -1 else j
            i = n if j == -1 else j + 1
            emit("qident", sql[start + 1 : end], sql[start:i])
            continue
        if quote:
            slash = (backslash or e_string) and quote != "`"
            bm = _BODY_RE[(quote, slash)].match(sql, i + 1)
            end = bm.end()  # type: ignore[union-attr]
            body = sql[i + 1 : end]
            i = end + 1 if end < n else n
            escaped = e_string or unicode or (slash and "\\" in body)
            trailing = len(body) - len(body.rstrip("\\"))
            if generic and not unicode and (
                    (e_string and "\\" in body)
                    or (not e_string and ("\\" + quote in body or trailing % 2 == 1))):
                # MySQL would end the string later (`'x\''…`, a body ending in `\`);
                # SQLite and MySQL read E'x\' as a name and a string ending at the `\'`
                flags.add("ambiguous_escape")
            if unicode:
                esc = "\\"
                ue = _uescape(sql, i, nested_comments)
                if ue:
                    esc, i = ue
                body = _decode_unicode(body.replace(quote + quote, quote), esc)
            elif e_string:
                body = _decode_e_string(body)
            else:
                if slash:
                    body = _BACKSLASH_ESCAPE_RE.sub(r"\1", body)
                body = body.replace(quote + quote, quote)
            emit("str" if quote == "'" else "qident", body, sql[start:i], escaped)
            continue

        if ch == "$":
            dm = _DOLLAR_OPEN_RE.match(sql, i) if dollar_quotes else None
            if dm:
                tag = dm.group(0)
                end = sql.find(tag, dm.end())
                body_end = n if end == -1 else end
                i = n if end == -1 else end + len(tag)
                emit("str", sql[dm.end() : body_end], sql[start:i])
                continue
            pm = _PARAM_RE.match(sql, i)
            if pm:
                i = pm.end()
                emit("param", pm.group(0), pm.group(0))
                continue
        if ch == "@":
            vm = (_VAR_RE if mysql else _NAMED_VAR_RE).match(sql, i)
            if vm:
                i = vm.end()
                emit("var", vm.group(0), vm.group(0))
                continue
        wm = _WORD_RE.match(sql, i)
        if wm:
            i = wm.end()
            emit("word", wm.group(0), wm.group(0))
            continue
        if (mysql and ch == "." and toks and toks[-1].kind in ("word", "qident") and not gap
                and sql[i + 1 : i + 2].isdigit()):
            i += 1  # app.2fa_codes: a qualifier dot, not the number .2
            emit("punct", ".", ".")
            continue
        if mysql and (ch.isdigit() or ch == "$"):
            im = _MYSQL_IDENT_RE.match(sql, i)
            word = im.group(0) if im else ""
            after_dot = bool(toks) and toks[-1].kind == "punct" and toks[-1].value == "." \
                and not gap
            if word and word != "$" and (after_dot or not _MYSQL_NUMBER_RE.fullmatch(word)):
                i = im.end()  # type: ignore[union-attr]
                emit("word", word, word)
                continue
        nm = _NUM_RE.match(sql, i)
        if nm:
            i = nm.end()
            emit("num", nm.group(0), nm.group(0))
            continue
        if ch == "\\" and dialect != "sqlite":
            # a client command (mysql \g \G \! \. …, psql \g \gexec \! \i \copy …): the
            # client runs it, not the server. \g / \G end the statement like `;`;
            # anything else may run a shell, read a file or change the delimiter.
            mm = _CLIENT_COMMAND_RE.match(sql, i)
            name = mm.group(1) if mm else ""
            i = mm.end() if mm else i + 1
            if mysql and name in ("g", "G", "gx") and not _PIPE_AFTER_RE.match(sql, i):
                # mysql: a statement end, and the next one may follow on the same line
                # (the line is not scanned: many \g on one line stay linear)
                if toks or had_comment:
                    statements.append((toks, had_comment, frozenset(flags)))
                toks, had_comment, gap, flags = [], False, False, set()
                continue
            line_end = _line_comment_end(sql, i, cr=True)
            rest = sql[i:line_end].strip()
            if name in ("g", "G", "gx") and not rest.startswith("|"):
                # mysql: the next statement may follow on the same line; psql: the
                # rest of the line is a file the output is written to
                if not mysql:
                    i = line_end
                    if rest:
                        flags.add("client_command")  # \g FILE writes FILE
                        had_comment = True  # also after an empty buffer (re-runs the last)
                if toks or had_comment:
                    statements.append((toks, had_comment, frozenset(flags)))
                toks, had_comment, gap, flags = [], False, False, set()
                continue
            flags.add("client_command")
            had_comment = True  # keep the statement even when nothing else is in it
            i = line_end  # its arguments run to the end of the line
            gap = True
            continue
        if ch == "." and dialect == "sqlite" and not toks and _at_line_start(sql, i):
            # a sqlite3 dot-command (.shell, .system, .import, .read …) at a line
            # start; the ones that only set the output format are left alone
            dot = _DOT_COMMAND_RE.match(sql, i)
            if dot is None or dot.group(1).lower() not in _FORMAT_DOT_COMMANDS:
                flags.add("client_command")
                had_comment = True
            i = _line_comment_end(sql, i, cr=False)
            gap = True
            continue
        i += 1
        if ch == ";":
            if toks or had_comment:
                statements.append((toks, had_comment, frozenset(flags)))
            toks, had_comment, gap, flags = [], False, False, set()
            continue
        emit("punct", ch, ch)
    if toks or had_comment:
        statements.append((toks, had_comment, frozenset(flags)))
    return statements


def _render(toks: list[_T]) -> str:
    """Statement text for the keyword regexes below: comments removed (a
    comment becomes one space, so ``DELETE/**/FROM`` still reads as two
    words), every string literal blanked to ``''`` so nothing inside one can
    match, and backtick identifiers written as ``"..."``."""
    out: list[str] = []
    for t in toks:
        if t.gap and out:
            out.append(" ")
        if t.kind == "str":
            out.append("''")
        elif t.kind == "qident":
            out.append('"' + t.value.replace('"', '""') + '"')
        else:
            out.append(t.raw)
    return "".join(out)


# --- identifier handling ------------------------------------------------------

_NAME_RE = r'(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)'
_QUALIFIED_NAME_RE = rf"(?P<name>{_NAME_RE}(?:\.{_NAME_RE})?)"


def _unquote(part: str) -> str:
    part = part.strip()
    if part.startswith('"') and part.endswith('"'):
        return part[1:-1].replace('""', '"')
    return part


def _split_schema(raw: str) -> tuple[str, str | None]:
    """``public.users`` -> (``public.users``, ``public``); ``users`` ->
    (``users``, None). Returns the qualified name with quoting stripped."""
    parts: list[str] = []
    part = ""
    in_quote = False
    for ch in raw:
        if ch == '"':
            in_quote = not in_quote
            part += ch
        elif ch == "." and not in_quote:
            parts.append(part)
            part = ""
        else:
            part += ch
    parts.append(part)
    unquoted = [_unquote(p) for p in parts]
    if len(unquoted) == 2:
        return f"{unquoted[0]}.{unquoted[1]}", unquoted[0]
    return unquoted[0], None


# --- statement classification -------------------------------------------------

_ALTER_RE = re.compile(
    rf"\A\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_QUALIFIED_NAME_RE}", re.IGNORECASE
)
_CREATE_RE = re.compile(
    r"\A\s*CREATE\s+(?:OR\s+REPLACE\s+)?"
    # MySQL view/routine options: ALGORITHM=x DEFINER=u SQL SECURITY x
    r"(?:ALGORITHM\s*=\s*\w+\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:SQL\s+SECURITY\s+\w+\s+)?"
    r"(?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+)?"
    r"(?:UNLOGGED\s+)?(?:UNIQUE\s+)?(?P<mat>MATERIALIZED\s+)?"
    r"(?P<kind>TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER)"
    rf"\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_CREATE_FALLBACK_RE = re.compile(
    rf"\A\s*CREATE\s+(?P<kind>[A-Za-z_]+)\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_SHOW_FROM_RE = re.compile(
    r"\A\s*SHOW\s+(?:(?:FULL|EXTENDED)\s+)*(?:COLUMNS|FIELDS|INDEX|INDEXES|KEYS)\s+(?:FROM|IN)\s+"
    rf"{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_DESCRIBE_TARGET_RE = re.compile(rf"\A\s*(?:DESCRIBE|DESC)\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_GRANT_TO_RE = re.compile(rf"\bTO\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_REVOKE_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_DROP_COLUMN_RE = re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE)
_CASCADE_RE = re.compile(r"\bCASCADE\b", re.IGNORECASE)
_CALL_RE = re.compile(rf"\A\s*CALL\s+{_QUALIFIED_NAME_RE}\s*\(", re.IGNORECASE)
_EXECUTE_PROC_RE = re.compile(
    rf"\A\s*(?:EXECUTE|PERFORM)\s+{_QUALIFIED_NAME_RE}\s*\(", re.IGNORECASE
)


def _resource_and_metadata(qualified: str, kind: str) -> tuple[str, dict[str, Any]]:
    qualified_name, schema = _split_schema(qualified)
    metadata: dict[str, Any] = {}
    if schema:
        metadata["schema"] = schema
    return f"{kind}/{qualified_name}", metadata


_Classification = tuple[str, str, dict[str, Any], str, str, dict[str, Any]]


# --- the statement scan (#58) -----------------------------------------------------
#
# One linear pass over a statement's tokens finds every table it reads (FROM
# and JOIN targets, comma joins, subqueries, set-operation branches, ``TABLE
# t``, CTE bodies), every DML operation in it (top level and inside CTEs), a
# top-level ``SELECT ... INTO`` target, a row-locking clause and
# ``set_config('role', ...)`` calls. Nothing in it recurses.

# Words that end a FROM list at their depth (outside an alias position).
_FROM_LIST_END = frozenset({
    "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "WINDOW",
    "UNION", "INTERSECT", "EXCEPT", "MINUS", "FOR", "INTO", "RETURNING", "SET",
    "VALUES", "SELECT", "QUALIFY", "LOCK", "PROCEDURE",
})
# Words that cannot be a bare table alias (so one right after a table name is
# a clause, not an alias).
_NOT_ALIAS = frozenset({
    "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "WINDOW",
    "UNION", "INTERSECT", "EXCEPT", "FOR", "INTO", "RETURNING", "ON", "USING",
    "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL", "STRAIGHT_JOIN",
    "SELECT", "VALUES", "AS", "TABLESAMPLE", "WITH", "LATERAL", "OUTER", "FROM",
})
_SUBQUERY_START = frozenset({"SELECT", "WITH", "VALUES", "TABLE"})
# Clause words some dialects take as a bare alias.
_CLAUSE_ALIASES = frozenset({"OFFSET", "RETURNING", "WINDOW", "FETCH", "LIMIT"})
_SET_OP_BEFORE_TABLE = frozenset({"UNION", "INTERSECT", "EXCEPT", "MINUS", "ALL", "DISTINCT", "AS"})
_DML = frozenset({"INSERT", "UPDATE", "DELETE", "MERGE"})
_LOCK_RANK = {"key share": 0, "share": 1, "no key update": 2, "update": 3}
_ACTION_RANK = {"delete": 3, "update": 2, "put": 1}


class _Op:
    __slots__ = ("action", "targets", "raw", "index", "unbounded", "upsert", "using",
                 "merge_actions")

    def __init__(self, action: str | None, raw: str, index: int) -> None:
        self.action = action  # None: an unparseable DML statement
        self.targets: list[list[str]] = []
        self.raw = raw
        self.index = index
        self.unbounded: bool | None = None
        # (action, raw): ON CONFLICT DO UPDATE / ON DUPLICATE KEY UPDATE are
        # updates, INSERT OR REPLACE / REPLACE delete the conflicting rows.
        self.upsert: tuple[str, str] | None = None
        self.using = False  # DELETE FROM t ... USING ... (MySQL: t may be an alias)
        # MERGE: every WHEN ... THEN action, besides the strongest (``action``)
        self.merge_actions: set[str] = set()


class _Scan:
    __slots__ = ("tables", "ops", "into", "lock", "nowait", "skip_locked", "roles",
                 "changes_lexing", "delete_all")

    def __init__(self) -> None:
        self.tables: list[list[str]] = []
        self.ops: list[_Op] = []
        # None, or (kind, value): ("table", parts) / ("file", path|None) /
        # ("var", None) / ("unknown", None).
        self.into: tuple[str, Any] | None = None
        self.lock: str | None = None
        self.nowait = False
        self.skip_locked = False
        # set_config('role'|'session_authorization', x): the role, or None
        # when it can't be read from literals (fail-safe: role/*).
        self.roles: list[str | None] = []
        # set_config('standard_conforming_strings', …) and the like
        self.changes_lexing = False
        # a MySQL DELETE whose target names no table or alias here: it may delete
        # from every table the statement reads (the op, for its params)
        self.delete_all: _Op | None = None


def _is_word(tok: _T | None, *words: str) -> bool:
    return tok is not None and tok.kind == "word" and tok.value.upper() in words


def _is_punct(tok: _T | None, ch: str) -> bool:
    return tok is not None and tok.kind == "punct" and tok.value == ch


def _is_name(tok: _T | None) -> bool:
    return tok is not None and tok.kind in ("word", "qident")


def _norm_ident(tok: _T) -> str:
    # Unquoted identifiers are case-insensitive; quoted ones are exact.
    return tok.value.lower() if tok.kind == "word" else tok.value


# Words after which MySQL's STRAIGHT_JOIN is a select modifier, not a join.
_SELECT_MODIFIERS = ("SELECT", "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY")
# Statements that may open a bracket group in an UPDATE's table list; each is
# its own op, so the group walk does not read into it.
_GROUP_STATEMENTS = ("UPDATE", "DELETE", "INSERT", "REPLACE", "MERGE")


def _scan(toks: list[_T], first_word: str, dialect: str) -> _Scan:
    n = len(toks)
    scan = _Scan()

    def tok(j: int) -> _T | None:
        return toks[j] if 0 <= j < n else None

    # Depth of every token (a bracket gets its outer depth), the open bracket
    # enclosing it, and each open bracket's matching close.
    depth = [0] * n
    encl = [-1] * n
    close_of: dict[int, int] = {}
    stack: list[int] = []
    for j, t in enumerate(toks):
        if t.kind == "punct" and t.value in ")]" and stack:
            close_of[stack.pop()] = j
        depth[j] = len(stack)
        encl[j] = stack[-1] if stack else -1
        if t.kind == "punct" and t.value in "([":
            stack.append(j)

    def group_end(j: int) -> int:
        return close_of.get(encl[j], n) if encl[j] >= 0 else n

    # Last WHERE in each bracket group: a DELETE/UPDATE is bounded when its
    # group has a WHERE after it.
    last_where: dict[int, int] = {}
    for j, t in enumerate(toks):
        if t.kind == "word" and t.value.upper() == "WHERE":
            last_where[encl[j]] = j

    # CTE names -> [(visible from, visible until)]. A non-recursive CTE's
    # name is visible after its body, a recursive one's inside it too; both
    # until the group holding the WITH closes.
    ctes: dict[str, list[tuple[int, int]]] = {}
    # Where a WITH list ends when a SEARCH/CYCLE clause closes it (the main
    # statement's keyword follows a word there, not a ``)``).
    cte_list_ends: set[int] = set()
    for i in range(n):
        if not _is_word(toks[i], "WITH"):
            continue
        scope_end = group_end(i)
        j = i + 1
        recursive = _is_word(tok(j), "RECURSIVE")
        if recursive:
            j += 1
        while _is_name(tok(j)):
            name = _norm_ident(toks[j])
            j += 1
            if _is_punct(tok(j), "(") and j in close_of:  # column list
                j = close_of[j] + 1
            if not _is_word(tok(j), "AS"):
                break
            j += 1
            if _is_word(tok(j), "NOT"):
                j += 1
            if _is_word(tok(j), "MATERIALIZED"):
                j += 1
            if not _is_punct(tok(j), "(") or j not in close_of:
                break
            start, end = j, close_of[j]
            ctes.setdefault(name, []).append((start if recursive else end, scope_end))
            j = end + 1
            # SEARCH {DEPTH|BREADTH} FIRST BY c, … SET col; CYCLE c, … SET col
            # [TO v DEFAULT v] USING col (Postgres 14+)
            if _is_word(tok(j), "SEARCH"):
                end_at = _search_clause_end(toks, j)
                if end_at is not None:
                    j = end_at
                    cte_list_ends.add(j)
            if _is_word(tok(j), "CYCLE"):
                end_at = _cycle_clause_end(toks, j)
                if end_at is not None:
                    j = end_at
                    cte_list_ends.add(j)
            if not _is_punct(tok(j), ","):
                break
            cte_list_ends.discard(j)
            j += 1

    cte_index: dict[str, tuple[int, list[int], list[int]]] = {}

    def is_cte(name: str, pos: int) -> bool:
        """Whether a CTE named ``name`` is in scope at ``pos``: some (lo, hi)
        with lo < pos < hi. Bisects the starts with a running maximum of the
        ends, so many same-name scopes and references stay fast."""
        scopes = ctes.get(name)
        if not scopes:
            return False
        cached = cte_index.get(name)
        if cached is None or cached[0] != len(scopes):
            ordered = sorted(scopes)
            starts = [lo for lo, _hi in ordered]
            reach, best = [], -1
            for _lo, hi in ordered:
                best = max(best, hi)
                reach.append(best)
            cached = cte_index[name] = (len(scopes), starts, reach)
        _n, starts, reach = cached
        k = bisect.bisect_left(starts, pos) - 1  # the last scope starting before pos
        return k >= 0 and reach[k] > pos

    def name_parts(j: int) -> tuple[list[_T], int]:
        parts = [toks[j]]
        m = j + 1
        while _is_punct(tok(m), ".") and _is_name(tok(m + 1)):
            parts.append(toks[m + 1])
            m += 2
        return parts, m

    # Parentheses that hold the statement's own query (``(SELECT ...)``,
    # ``WITH x AS (...) (SELECT ...)``), as opposed to a subquery: a SELECT
    # ... INTO directly inside one is the statement's.
    main_parens: set[int] = set()
    for j, t in enumerate(toks):
        if not _is_punct(t, "("):
            continue
        before = tok(j - 1)
        if j == 0 or (_is_punct(before, "(") and j - 1 in main_parens) or (
            first_word == "WITH" and depth[j] == 0 and _is_punct(before, ")")
        ):
            main_parens.add(j)

    seen: set[tuple[str, ...]] = set()
    alias_pos: set[int] = set()
    # Per query block (the enclosing bracket, -1 for the top level): alias ->
    # the tables it names there, and the names of the tables it reads.
    alias_of: dict[int, dict[str, set[tuple[str, ...]]]] = {}
    block_tables: dict[int, set[str]] = {}
    skip_dual = dialect == "mysql"
    from_list: dict[int, bool] = {}
    # ``(`` positions parse_ref descended into (``FROM (a, b)``, ``JOIN (b JOIN
    # c)``): a table list continues inside them.
    ref_parens: set[int] = set()
    block_of: dict[int, int] = {}  # query_block of a ref_parens bracket

    def query_block(j: int) -> int:
        """The query block of position ``j``: its enclosing bracket, skipping
        the brackets of a table list (``FROM (a, b)`` is the outer block's).
        A table-list bracket is marked before anything inside it is read, so
        its answer is kept (nested ``JOIN (`` groups stay linear)."""
        block = encl[j]
        path = []
        while block in ref_parens:
            if block in block_of:
                block = block_of[block]
                break
            path.append(block)
            block = encl[block]
        for p in path:
            block_of[p] = block
        return block

    def mark_alias(m: int, table: list[str] | None = None) -> None:
        t = tok(m)
        if _is_word(t, "AS"):
            m += 1
            t = tok(m)
            if not _is_name(t):
                return
        elif t is None or not (
            t.kind == "qident" or (t.kind == "word" and t.value.upper() not in _NOT_ALIAS)
            # a clause word right before `,` is an alias (SQLite and MySQL take
            # `FROM products offset, users`): `OFFSET ,` is not a clause
            or (t.kind == "word" and t.value.upper() in _CLAUSE_ALIASES
                and _is_punct(tok(m + 1), ","))
        ):
            return
        assert t is not None
        alias_pos.add(m)
        if table is not None:
            alias_of.setdefault(query_block(m), {}).setdefault(t.value.lower(), set()).add(
                tuple(table))

    def parse_ref(j: int) -> None:
        while True:
            if _is_punct(tok(j), "{") and _is_word(tok(j + 1), "OJ"):
                j += 2  # ODBC escape: FROM { OJ a LEFT OUTER JOIN b ON … }
            while _is_word(tok(j), "ONLY", "LATERAL"):
                j += 1
            t = tok(j)
            if not _is_punct(t, "("):
                break
            # ``(a JOIN b ...)``: descend; a subquery's own FROM is found by
            # the main loop.
            nxt = tok(j + 1)
            if nxt is None or _is_word(nxt, *_SUBQUERY_START, *_GROUP_STATEMENTS):
                return  # FROM (DELETE … RETURNING *): that statement is its own op
            from_list[depth[j] + 1] = True
            ref_parens.add(j)
            j += 1
        if _is_punct(t, "[") and _is_name(tok(j + 1)) and _is_punct(tok(j + 2), "]"):
            # [name]: a SQLite/SQL Server identifier read in another dialect
            parts, m = [toks[j + 1]], j + 3
        else:
            if not _is_name(t):
                return
            assert t is not None
            upper = t.value.upper() if t.kind == "word" else ""
            if upper in ("SELECT", "WITH", "VALUES") or (upper == "DUAL" and skip_dual):
                return
            if upper == "ROWS" and _is_word(tok(j + 1), "FROM"):
                return  # ROWS FROM (f(...), g(...))
            parts, m = name_parts(j)
            if _is_punct(tok(m), "("):
                return  # a function in FROM (generate_series(...), unnest(...))
            if _is_punct(tok(m), "*"):
                m += 1  # ONLY t *
            if len(parts) == 1 and is_cte(_norm_ident(t), j):
                mark_alias(m)
                return
        table = [p.value for p in parts]
        mark_alias(m, table)
        block_tables.setdefault(query_block(j), set()).add(table[-1].lower())
        key = tuple(_norm_ident(p) for p in parts)
        if key not in seen:
            seen.add(key)
            scan.tables.append(table)

    def target_at(j: int) -> tuple[list[str] | None, int]:
        while _is_word(tok(j), "ONLY"):
            j += 1
        t = tok(j)
        if not _is_name(t) or (
            t is not None and t.kind == "word" and t.value.upper() in _NOT_ALIAS | {"SET"}
        ):
            return None, j
        parts, m = name_parts(j)
        return [p.value for p in parts], m

    def group_targets(open_at: int, targets: list[list[str]]) -> None:
        """The tables of a bracketed join group (``(secret s JOIN other o ON
        1)``, ``(a, b)``): its first table and each one after ``,`` or JOIN, at
        any depth; a subquery inside it is skipped, and so is a statement
        inside it (``JOIN (UPDATE …``), which reports its own targets, so each
        token is read by one walk at most."""
        if _is_word(tok(open_at + 1), *_GROUP_STATEMENTS):
            return
        close = close_of[open_at]
        p = open_at + 1
        expect = True  # a table name may start here
        while p < close:
            tp = toks[p]
            if _is_punct(tp, "("):
                if p not in close_of:
                    return
                if _is_word(tok(p + 1), *_SUBQUERY_START, *_GROUP_STATEMENTS):
                    p = close_of[p] + 1
                    expect = False
                    continue
                p += 1
                expect = True
                continue
            if expect:
                table, _m = target_at(p)
                if table:
                    targets.append(table)
            expect = _is_punct(tp, ",") or _is_word(tp, "JOIN", "STRAIGHT_JOIN")
            p += 1

    def parse_op(i: int, u: str) -> _Op:
        d = depth[i]
        j = i + 1
        if u == "DELETE":
            while _is_word(tok(j), "LOW_PRIORITY", "QUICK", "IGNORE"):
                j += 1
            if _is_word(tok(j), "FROM"):
                op = _Op("delete", "DELETE FROM", i)
                target, m = target_at(j + 1)
                while target:  # DELETE FROM t1, t2 USING ... (MySQL)
                    op.targets.append(target)
                    if _is_punct(tok(m), ".") and _is_punct(tok(m + 1), "*"):
                        m += 2
                    if not _is_punct(tok(m), ","):
                        break
                    target, m = target_at(m + 1)
            else:  # DELETE t1, t2 FROM ... (MySQL)
                op = _Op("delete", "DELETE", i)
                target, m = target_at(j)
                while target:
                    op.targets.append(target)
                    if _is_punct(tok(m), ".") and _is_punct(tok(m + 1), "*"):
                        m += 2
                    if not _is_punct(tok(m), ","):
                        break
                    target, m = target_at(m + 1)
                if not _is_word(tok(m), "FROM"):
                    op.targets = []
            op.unbounded = last_where.get(encl[i], -1) < i
        elif u == "UPDATE":
            while _is_word(tok(j), "LOW_PRIORITY", "IGNORE"):
                j += 1
            replace = False
            if _is_word(tok(j), "OR") and tok(j + 1) is not None:  # SQLite UPDATE OR ...
                replace = _is_word(tok(j + 1), "REPLACE")
                j += 2
            op = _Op("update", "UPDATE", i)
            if replace:  # deletes the rows the new values conflict with
                op.upsert = ("delete", "UPDATE OR REPLACE")
            target, m = target_at(j)
            if target:
                op.targets.append(target)
                # MySQL multi-table UPDATE: every table before SET may be
                # written (t1, t2 SET / t1 JOIN t2 ON ... SET). The walk stays
                # at this depth (it jumps over closed groups) and stops at the
                # next statement keyword, so the scan stays linear.
                k = m
                while k < n and not _is_word(toks[k], "SET"):
                    tk = toks[k]
                    if depth[k] != d or _is_punct(tk, ")") or (
                        tk.kind == "word" and tk.value.upper() in _DML
                    ):
                        break
                    if _is_punct(tk, "(") or _is_punct(tk, "["):
                        if k not in close_of:
                            break
                        if _is_punct(tk, "(") and not _is_word(tok(k - 1), "USING"):
                            group_targets(k, op.targets)  # JOIN (secret s JOIN o ON 1)
                        k = close_of[k] + 1
                        continue
                    if _is_punct(tk, ",") or _is_word(tk, "JOIN", "STRAIGHT_JOIN"):
                        more, _m = target_at(k + 1)
                        if more:
                            op.targets.append(more)
                    k += 1
            op.unbounded = last_where.get(encl[i], -1) < i
        elif u in ("INSERT", "REPLACE"):
            while _is_word(tok(j), "LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"):
                j += 1
            replace = u == "REPLACE"
            if _is_word(tok(j), "OR") and tok(j + 1) is not None:  # SQLite INSERT OR ...
                replace = _is_word(tok(j + 1), "REPLACE")
                j += 2
            if _is_word(tok(j), "INTO"):
                j += 1
            op = _Op("put", "INSERT INTO", i)
            if replace:  # deletes the rows it conflicts with, then inserts
                op.upsert = ("delete", "REPLACE" if u == "REPLACE" else "INSERT OR REPLACE")
            target, _m = target_at(j)
            if target:
                op.targets.append(target)
        else:  # MERGE
            if _is_word(tok(j), "INTO"):
                j += 1
            op = _Op(None, "MERGE", i)  # action set by its WHEN ... THEN clauses
            target, _m = target_at(j)
            if target:
                op.targets.append(target)
        if not op.targets:
            op.action = None
            op.targets = []
        return op

    query_at: dict[int, bool] = {}
    last_kw: dict[int, str] = {}
    using_done: dict[int, bool] = {}
    merge_at: dict[int, _Op] = {}
    insert_at: dict[int, _Op] = {}
    delete_at: dict[int, _Op] = {}
    idents: set[int] = set()  # keyword-looking words used as identifiers
    skip_until = -1  # end of a MySQL index hint being skipped
    lock_walked = 0  # how far the lock-option walk has read
    joined: dict[int, bool] = {}  # a JOIN seen at this depth (its USING lists columns)
    op_indexes: set[int] = set()  # where each DML operation starts

    for i, t in enumerate(toks):
        if i <= skip_until:
            continue
        d = depth[i]
        prev = tok(i - 1)
        if t.kind == "punct":
            if t.value in "([":
                query_at[d + 1] = False
                from_list[d + 1] = i in ref_parens
                using_done[d + 1] = False
                last_kw.pop(d + 1, None)
                joined.pop(d + 1, None)
                merge_at.pop(d + 1, None)
                insert_at.pop(d + 1, None)
                delete_at.pop(d + 1, None)
            elif t.value == ")" and from_list.get(d) and not (
                    _is_word(tok(i + 1), "SET") and last_kw.get(d) == "UPDATE"):
                mark_alias(i + 1)  # (SELECT ...) alias / f(...) alias; not UPDATE … (id) SET
            elif t.value == "," and from_list.get(d):
                parse_ref(i + 1)
            continue
        if t.kind == "qident":
            if t.value.lower() == "set_config" and _is_punct(tok(i + 1), "("):
                _set_config(toks, i, close_of, depth, scan)
            continue
        if t.kind != "word":
            continue
        u = t.value.upper()

        if u in ("USE", "FORCE", "IGNORE") and from_list.get(d) and _is_word(
            tok(i + 1), "INDEX", "KEY"
        ):
            # MySQL index hint: USE|FORCE|IGNORE INDEX|KEY [FOR JOIN|ORDER BY|
            # GROUP BY] (names) -- none of it is a table or a clause.
            j = i + 2
            if _is_word(tok(j), "FOR"):
                j += 2 if _is_word(tok(j + 1), "JOIN") else 3
            if _is_punct(tok(j), "(") and j in close_of:
                skip_until = close_of[j]
            continue

        if i in alias_pos or _is_punct(prev, ".") or (
            _is_word(prev, "AS") and u not in _SUBQUERY_START  # CREATE ... AS SELECT
        ):
            # An identifier that happens to be a keyword. Only MySQL's
            # ``LOCK IN SHARE MODE`` can follow a table name.
            if not (u == "LOCK" and _is_word(tok(i + 1), "IN")):
                idents.add(i)
                if u == "SET_CONFIG" and _is_punct(tok(i + 1), "("):
                    _set_config(toks, i, close_of, depth, scan)
                continue

        if u == "SELECT":
            query_at[d] = True
            last_kw[d] = u
            from_list[d] = False
            continue
        if u == "REPLACE" and (
            prev is None or i in cte_list_ends
            or (first_word == "WITH" and _is_punct(prev, ")"))
        ) and not _is_punct(tok(i + 1), "("):
            # MySQL/SQLite REPLACE [INTO] t (also after a WITH list): an insert
            # that first deletes the rows it conflicts with.
            op = parse_op(i, u)
            scan.ops.append(op)
            query_at[d] = True
            last_kw[d] = "INSERT"
            insert_at[d] = op
            continue
        if u in _DML:
            if u == "UPDATE" and d in insert_at and (
                _is_word(prev, "DO")
                or (_is_word(prev, "KEY") and _is_word(tok(i - 2), "DUPLICATE"))
            ):
                insert_at[d].upsert = (
                    "update",
                    "ON CONFLICT DO UPDATE" if _is_word(prev, "DO") else "ON DUPLICATE KEY UPDATE",
                )
            elif prev is None or _is_punct(prev, "(") or _is_punct(prev, ")") or _is_word(
                prev, "ATOMIC"
            ) or i in cte_list_ends or (
                # CREATE RULE r AS ON … DO [INSTEAD|ALSO] DELETE …: the rule's action
                first_word == "CREATE" and _is_word(prev, "DO", "INSTEAD", "ALSO")
            ):
                # A statement keyword (top level, a CTE body, after a CTE
                # list, the first one in a BEGIN ATOMIC function body).
                op = parse_op(i, u)
                scan.ops.append(op)
                op_indexes.add(i)
                if u == "MERGE":
                    merge_at[d] = op
                elif u == "INSERT":
                    insert_at[d] = op
                elif u == "DELETE":
                    delete_at[d] = op
                query_at[d] = True
                last_kw[d] = u
                joined[d] = False
                from_list[d] = False
            elif _is_word(prev, "THEN") and d in merge_at:
                action = {"DELETE": "delete", "UPDATE": "update", "INSERT": "put"}[u] \
                    if u != "MERGE" else None
                op = merge_at[d]
                if action:
                    op.merge_actions.add(action)
                if action and (op.action is None
                               or _ACTION_RANK[action] > _ACTION_RANK[op.action]):
                    op.action = action
            continue

        if u == "IN" and dialect == "sqlite" and _is_name(tok(i + 1)):
            parse_ref(i + 1)  # sqlite: `x IN t` reads table t
            continue
        if u == "FROM":
            # not a table list: DELETE FROM t (the op's target), IS [NOT]
            # DISTINCT FROM x, ROWS FROM (f(), g()); `1 rows FROM t` and `0 delete
            # FROM t` alias a column and are one
            delete_from = _is_word(prev, "DELETE") and i - 1 in op_indexes
            distinct_from = _is_word(prev, "DISTINCT") and (
                _is_word(tok(i - 2), "IS")
                or (_is_word(tok(i - 2), "NOT") and _is_word(tok(i - 3), "IS")))
            rows_from = _is_word(prev, "ROWS") and _is_punct(tok(i + 1), "(") and (
                _is_word(tok(i - 2), "FROM", "JOIN") or _is_punct(tok(i - 2), ","))
            if query_at.get(d) and (
                i - 1 in idents or not (delete_from or distinct_from or rows_from)
            ):
                from_list[d] = True
                parse_ref(i + 1)
            continue
        # SELECT STRAIGHT_JOIN a FROM t: a select modifier, not a join
        if u in ("JOIN", "STRAIGHT_JOIN") and not (
                u == "STRAIGHT_JOIN" and _is_word(prev, *_SELECT_MODIFIERS)):
            joined[d] = True
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "USING" and last_kw.get(d) in ("DELETE", "MERGE") and not using_done.get(d) \
                and not (joined.get(d) and _is_punct(tok(i + 1), "(")):  # JOIN b USING (id)
            using_done[d] = True
            if last_kw.get(d) == "DELETE" and d in delete_at:
                delete_at[d].using = True
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "TABLE" and (
            prev is None
            or _is_word(prev, *_SET_OP_BEFORE_TABLE)
            or _is_punct(prev, "(")
            or i in cte_list_ends
            or (first_word == "WITH" and d == 0 and _is_punct(prev, ")"))  # WITH … TABLE t
            or (last_kw.get(d) == "INSERT" and (_is_name(prev) or _is_punct(prev, ")"))
                and not _is_word(prev, "INTO"))
        ):
            parse_ref(i + 1)
            continue

        if u in _FROM_LIST_END and i not in alias_pos and (
            # MySQL index hints (FORCE INDEX FOR JOIN (i)) keep the list going
            u != "FOR" or _is_word(tok(i + 1), "UPDATE", "SHARE", "NO", "KEY")
        ):
            from_list[d] = False

        if u == "INTO" and _is_word(tok(i + 1), "OUTFILE", "DUMPFILE"):
            # A file write wherever it appears (after TABLE, VALUES, a
            # parenthesised query, ...).
            path = tok(i + 2)
            if scan.into is None or scan.into[0] != "file":
                scan.into = (
                    "file", path.value if path and path.kind in ("str", "qident") else None
                )
            continue
        if (
            u == "INTO"
            and scan.into is None
            and (encl[i] == -1 or encl[i] in main_parens)  # the statement's own query
            and last_kw.get(d) == "SELECT"
            and first_word in ("SELECT", "WITH")
        ):
            j = i + 1
            while _is_word(tok(j), "LOCAL", "GLOBAL", "TEMP", "TEMPORARY", "UNLOGGED", "TABLE"):
                j += 1
            target = tok(j)
            if _is_word(target, "STRICT"):  # PL/pgSQL SELECT … INTO STRICT vars
                scan.into = ("var", None)
            elif target is not None and target.kind == "var":
                scan.into = ("var", None)
            elif _is_name(target):
                parts, _m = name_parts(j)
                scan.into = ("table", [p.value for p in parts])
            else:
                scan.into = ("unknown", None)
            continue

        strength: str | None = None
        after = i + 1
        if u == "FOR":
            if _is_word(tok(i + 1), "UPDATE"):
                strength, after = "update", i + 2
            elif _is_word(tok(i + 1), "SHARE"):
                strength, after = "share", i + 2
            elif _is_word(tok(i + 1), "NO") and _is_word(tok(i + 2), "KEY") and _is_word(
                tok(i + 3), "UPDATE"
            ):
                strength, after = "no key update", i + 4
            elif _is_word(tok(i + 1), "KEY") and _is_word(tok(i + 2), "SHARE"):
                strength, after = "key share", i + 3
        elif (
            u == "LOCK"
            and _is_word(tok(i + 1), "IN")
            and _is_word(tok(i + 2), "SHARE")
            and _is_word(tok(i + 3), "MODE")
        ):
            strength, after = "share", i + 4  # MySQL
        if strength is not None:
            if scan.lock is None or _LOCK_RANK[strength] > _LOCK_RANK[scan.lock]:
                scan.lock = strength
            # NOWAIT / SKIP LOCKED are global flags, so a stretch already
            # walked for an earlier lock clause is not walked again (linear)
            j = max(after, lock_walked)
            while j < n and depth[j] >= d and not _is_word(toks[j], "FOR"):
                if _is_word(toks[j], "NOWAIT"):
                    scan.nowait = True
                elif _is_word(toks[j], "SKIP") and _is_word(tok(j + 1), "LOCKED"):
                    scan.skip_locked = True
                j += 1
            lock_walked = j
            continue

        if u == "SET_CONFIG" and _is_punct(tok(i + 1), "("):
            _set_config(toks, i, close_of, depth, scan)

    # MySQL ``DELETE s FROM secret AS s ...`` / ``DELETE FROM s USING secret
    # AS s``: a single-part target may be an alias -- of the operation's own
    # query block only. A target naming no table or alias there, or an alias
    # of two tables, deletes from every table the statement reads. A plain
    # ``DELETE FROM t`` (no USING) names its table directly.
    for op in scan.ops:
        if op.action != "delete" or not (op.raw == "DELETE" or op.using):
            continue
        block = encl[op.index]
        aliases = alias_of.get(block, {})
        names = block_tables.get(block, set())
        resolved: dict[tuple[str, ...], list[str]] = {}
        any_table = False  # every table the statement reads, added once
        for target in op.targets:
            key = target[0].lower()
            if len(target) == 1 and key in aliases:
                if len(aliases[key]) == 1:
                    table = list(next(iter(aliases[key])))
                    resolved.setdefault(tuple(table), table)
                else:  # one alias, two tables in this block: any of them
                    any_table = True
            elif len(target) == 1 and op.raw == "DELETE" and key not in names:
                any_table = True
            else:
                resolved.setdefault(tuple(target), target)
        if any_table:
            if scan.tables:
                scan.delete_all = scan.delete_all or op  # every table, emitted once
            else:
                for table in op.targets:
                    resolved.setdefault(tuple(table), table)
        op.targets = list(resolved.values())
    return scan


def _name_list_end(toks: list[_T], j: int) -> int:
    """After ``a, b.c, d`` starting at ``j``: the index past the list."""
    n = len(toks)
    while j < n and _is_name(toks[j]):
        j += 1
        while j + 1 < n and _is_punct(toks[j], ".") and _is_name(toks[j + 1]):
            j += 2
        if j < n and _is_punct(toks[j], ","):
            j += 1
        else:
            break
    return j


def _search_clause_end(toks: list[_T], j: int) -> int | None:
    """``SEARCH {DEPTH|BREADTH} FIRST BY cols SET col`` at ``j``: the index past
    it, or ``None`` when the words do not have that shape (the walk reads each
    token at most once)."""
    t = toks
    if not (j + 3 < len(t) and _is_word(t[j + 1], "DEPTH", "BREADTH")
            and _is_word(t[j + 2], "FIRST") and _is_word(t[j + 3], "BY")):
        return None
    m = _name_list_end(t, j + 4)
    if m + 1 < len(t) and _is_word(t[m], "SET") and _is_name(t[m + 1]):
        return m + 2
    return None


def _cycle_clause_end(toks: list[_T], j: int) -> int | None:
    """``CYCLE cols SET col [TO v DEFAULT v] USING col`` at ``j``: the index past
    it, or ``None``."""
    t, n = toks, len(toks)
    m = _name_list_end(t, j + 1)
    if not (m + 1 < n and _is_word(t[m], "SET") and _is_name(t[m + 1])):
        return None
    m += 2
    if m + 3 < n and _is_word(t[m], "TO") and _is_word(t[m + 2], "DEFAULT"):
        m += 4
    if m + 1 < n and _is_word(t[m], "USING") and _is_name(t[m + 1]):
        return m + 2
    return None


def _plain_string_arg(
    toks: list[_T], close_of: dict[int, int], lo: int, hi: int, *, decoded: bool = False
) -> str | None:
    """The value of tokens ``lo..hi`` (exclusive) when they are one string
    literal, possibly in parentheses (``('role')``); else None."""
    while hi - lo >= 3 and _is_punct(toks[lo], "(") and close_of.get(lo) == hi - 1:
        lo, hi = lo + 1, hi - 1
    if hi - lo == 1 and toks[lo].kind == "str" and (decoded or not toks[lo].escaped):
        return toks[lo].value
    return None  # an expression, or an E''/U&'' literal: not compared as text


def _set_config(
    toks: list[_T], i: int, close_of: dict[int, int], depth: list[int], scan: _Scan
) -> None:
    """``set_config(setting, value, is_local)`` at token ``i`` (the name; any
    ``pg_catalog.`` qualifier before it does not matter). A role change when
    the setting is ``role``/``session_authorization`` -- or when it isn't a
    plain string literal, since it then might be (fail-safe: ``role/*``)."""
    if i + 1 not in close_of:
        scan.roles.append(None)  # unclosed call: fail safe, and stay linear
        return
    close = close_of[i + 1]
    args: list[tuple[int, int]] = []
    start = j = i + 2
    while j < close and len(args) < 2:
        t = toks[j]
        if t.kind == "punct" and t.value in "([" and j in close_of:
            j = close_of[j] + 1  # skip nested calls in one step
            continue
        if t.kind == "punct" and t.value == ",":
            args.append((start, j))
            start = j + 1
        j += 1
    if len(args) < 2:
        args.append((start, min(j, close)))
    setting = _plain_string_arg(toks, close_of, *args[0])
    if setting is None or setting.strip().lower() in _LEXING_SETTINGS | _CHARSET_SETTINGS:
        scan.changes_lexing = True
    if setting is not None and setting.strip().lower() not in ("role", "session_authorization"):
        return
    value = None
    if setting is not None and len(args) > 1:
        value = _plain_string_arg(toks, close_of, *args[1], decoded=True)
    scan.roles.append(value)


def _table_resource(parts: list[str]) -> tuple[str, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    if len(parts) >= 2:
        metadata["schema"] = parts[-2]
    return "table/" + ".".join(parts), metadata


def _lock_params(scan: _Scan) -> dict[str, Any]:
    if scan.lock is None:
        return {}
    params: dict[str, Any] = {"locking": True, "lock_strength": scan.lock}
    if scan.nowait:
        params["nowait"] = True
    if scan.skip_locked:
        params["skip_locked"] = True
    return params


def _scan_results(
    scan: _Scan, *, first_word: str, primary: list[_Classification]
) -> list[_Classification]:
    """``primary`` (a statement's own intent, if the caller classified it),
    then every DML operation the scan found (strongest first), a
    ``SELECT ... INTO`` target, role changes, and a read of every other table
    the statement reads."""
    results = list(primary)
    cte = first_word == "WITH"
    ops = sorted(scan.ops, key=lambda o: -_ACTION_RANK.get(o.action or "update", 2))
    for op in ops:
        if op.action is None and not op.targets:
            results.append(("unknown/*", "update", {"unclassified": True}, "dml", op.raw, {}))
            continue
        action = op.action or "update"  # MERGE with no WHEN ... THEN found
        for parts in op.targets:
            resource, meta = _table_resource(parts)
            params: dict[str, Any] = {}
            if op.unbounded is not None:
                params["unbounded"] = op.unbounded
            if cte:
                params["cte"] = True
            results.append((resource, action, params, "dml", op.raw, meta))
            for other in sorted(op.merge_actions - {action},
                                key=lambda a: -_ACTION_RANK.get(a, 2)):
                results.append((resource, other, dict(params), "dml", op.raw, meta))
            if op.upsert:
                upsert: dict[str, Any] = {"upsert": True, **({"cte": True} if cte else {})}
                results.append((resource, op.upsert[0], upsert, "dml", op.upsert[1], meta))
    if scan.delete_all is not None:
        params = {"unbounded": scan.delete_all.unbounded} \
            if scan.delete_all.unbounded is not None else {}
        if cte:
            params["cte"] = True
        for parts in scan.tables:
            resource, meta = _table_resource(parts)
            results.append((resource, "delete", dict(params), "dml", scan.delete_all.raw, meta))

    if scan.into is not None:
        into_kind, value = scan.into
        if into_kind == "table":
            resource, meta = _table_resource(value)
            results.append(
                (resource, "create", {"ddl": True, "select_into": True}, "ddl", "SELECT INTO", meta)
            )
        elif into_kind == "file":
            results.append(
                (f"file/{value}" if value else "file/*", "update",
                 {"opaque": True, "unclassified": True, "into_file": True}, "opaque",
                 "SELECT INTO OUTFILE", {})
            )
        elif into_kind == "unknown":
            results.append(
                ("unknown/*", "update", {"unclassified": True}, "dml", "SELECT INTO", {})
            )
        # ("var", None): MySQL ``INTO @x`` only sets a variable.

    results.extend(
        (f"role/{r}" if r else "role/*", "update", {"privilege": True}, "dcl",
         "set_config(role)", {})
        for r in scan.roles
    )
    if scan.changes_lexing:
        results.append(("unknown/*", "update", {"unclassified": True, "changes_lexing": True},
                        "dml", "set_config", {}))

    # Dedupe writes, then add reads of the tables not already written.
    deduped: list[_Classification] = []
    written: set[tuple[str, str]] = set()
    for r in results:
        if (r[0], r[1]) not in written:
            written.add((r[0], r[1]))
            deduped.append(r)
    exclude = {r[0] for r in deduped}
    raw_read = first_word if not scan.ops and not primary and first_word else "SELECT"
    lock = _lock_params(scan)
    reads: list[_Classification] = []
    for parts in scan.tables:
        resource, meta = _table_resource(parts)
        if resource in exclude:
            continue
        exclude.add(resource)
        reads.append((resource, "read", dict(lock), "dql", raw_read, meta))
    if not reads and not primary and not scan.ops and (
        scan.into is None or scan.into[0] == "var"
    ):
        reads.append(("table/*", "read", lock, "dql", raw_read, {}))
    return deduped + reads


def _role_names(toks: list[_T]) -> list[str | None]:
    """Role names in ``SET ROLE a, 'b'@'%'``; NONE/DEFAULT/ALL become None."""
    names: list[str | None] = []
    expect = True
    for t in toks:
        if _is_punct(t, ","):
            expect = True
            continue
        if not expect:
            continue
        expect = False
        if t.kind == "word" and t.value.upper() in ("NONE", "DEFAULT", "ALL"):
            names.append(None)
        elif t.kind in ("word", "qident", "str"):
            names.append(t.value)
        else:
            names.append(None)
    return names or [None]


def _identity_change(toks: list[_T]) -> list[_Classification] | None:
    """``SET [SESSION|LOCAL] ROLE``, ``SET SESSION AUTHORIZATION``, ``SET
    role|"role"|session_authorization = ...``, ``RESET ROLE|SESSION
    AUTHORIZATION``, MySQL ``SET DEFAULT ROLE`` and ``SET PASSWORD``:
    privilege changes, not session reads. None for any other SET/RESET."""
    first = toks[0].value.upper()
    n = len(toks)

    def setting_at(j: int) -> tuple[str | None, int]:
        t = toks[j] if j < n else None
        if _is_word(t, "SESSION") and _is_word(toks[j + 1] if j + 1 < n else None,
                                                "AUTHORIZATION"):
            return "session_authorization", j + 2
        if _is_name(t):
            assert t is not None
            return t.value.lower(), j + 1
        return None, j

    j = 1
    if first == "SET" and _is_word(toks[1] if n > 1 else None, "SESSION", "LOCAL"):
        if not (_is_word(toks[1], "SESSION") and n > 2 and _is_word(toks[2], "AUTHORIZATION")):
            j = 2
    setting, j = setting_at(j)
    label = {"role": "ROLE", "session_authorization": "SESSION AUTHORIZATION"}
    if setting in label:
        assert setting is not None
        if first == "RESET":
            return [("role/*", "update", {"privilege": True}, "dcl", f"RESET {label[setting]}", {})]
        if j < n and (_is_punct(toks[j], "=") or _is_word(toks[j], "TO")):
            j += 1
        return [
            (f"role/{name}" if name else "role/*", "update", {"privilege": True}, "dcl",
             f"SET {label[setting]}", {})
            for name in dict.fromkeys(_role_names(toks[j:]))
        ]
    if first != "SET":
        return None
    if setting == "default" and _is_word(toks[j] if j < n else None, "ROLE"):
        user: str | None = None
        for k in range(j, n - 1):
            if _is_word(toks[k], "TO") and toks[k + 1].kind in ("word", "qident", "str"):
                user = toks[k + 1].value
        return [(f"role/{user}" if user else "role/*", "update", {"privilege": True}, "dcl",
                 "SET DEFAULT ROLE", {})]
    if setting == "password":
        name = None
        if _is_word(toks[j] if j < n else None, "FOR"):
            name = _role_names(toks[j + 1 :])[0]
        return [(f"role/{name}" if name else "role/*", "update", {"privilege": True}, "dcl",
                 "SET PASSWORD", {})]
    return None


# Words after EXPLAIN (or MySQL's DESCRIBE/DESC) that are options, not the
# statement explained.
_EXPLAIN_WORD_OPTIONS = frozenset({"ANALYZE", "ANALYSE", "VERBOSE", "EXTENDED", "PARTITIONS"})
_DESCRIBE_EXPLAINS = frozenset({
    "SELECT", "WITH", "INSERT", "UPDATE", "DELETE", "REPLACE", "TABLE", "VALUES", "MERGE",
    "ANALYZE", "ANALYSE", "FORMAT", "EXTENDED", "PARTITIONS",
})


def _is_explain(toks: list[_T], j: int) -> bool:
    if j >= len(toks):
        return False
    if _is_word(toks[j], "EXPLAIN"):
        return True
    nxt = toks[j + 1] if j + 1 < len(toks) else None
    return _is_word(toks[j], "DESCRIBE", "DESC") and (
        _is_word(nxt, *_DESCRIBE_EXPLAINS) or _is_punct(nxt, "(")
    )


def _strip_explain(toks: list[_T]) -> tuple[list[_T], bool]:
    """Strips any number of leading ``EXPLAIN [(options)] [ANALYZE] [VERBOSE]
    [FORMAT=x]`` prefixes (a loop, not recursion). Returns the explained
    statement's tokens and whether it runs (ANALYZE, not switched off)."""
    j, n, analyze = 0, len(toks), False
    while _is_explain(toks, j):
        j += 1
        if j < n and _is_punct(toks[j], "("):
            k = j + 1
            while k < n and not _is_punct(toks[k], ")"):
                if _is_word(toks[k], "ANALYZE", "ANALYSE") and not _is_word(
                    toks[k + 1] if k + 1 < n else None, "FALSE", "OFF"
                ) and not (k + 1 < n and toks[k + 1].value == "0"):
                    analyze = True
                k += 1
            j = k + 1
        if j + 1 < n and _is_word(toks[j], "QUERY") and _is_word(toks[j + 1], "PLAN"):
            j += 2  # SQLite EXPLAIN QUERY PLAN
        while j < n and (_is_word(toks[j], *_EXPLAIN_WORD_OPTIONS) or _is_word(toks[j], "FORMAT")):
            if _is_word(toks[j], "ANALYZE", "ANALYSE"):
                analyze = True
            if _is_word(toks[j], "FORMAT") and j + 2 < n and _is_punct(toks[j + 1], "="):
                j += 2
            j += 1
    return toks[j:], analyze


_DROP_KINDS = frozenset({
    "TABLE", "DATABASE", "SCHEMA", "INDEX", "VIEW", "SEQUENCE", "FUNCTION", "PROCEDURE", "TRIGGER",
})


def _classify_drop(toks: list[_T]) -> list[_Classification]:
    """``DROP [TEMPORARY|MATERIALIZED] <kind> [CONCURRENTLY] [IF EXISTS] a, b,
    ...``: one unbounded delete per name, and for a schema or database also a
    synthetic ``table/*`` delete (see module docstring). Empty when the kind
    isn't one of ``_DROP_KINDS``."""
    n = len(toks)
    j = 1
    mat = ""
    while j < n and _is_word(toks[j], "TEMPORARY", "MATERIALIZED"):
        if _is_word(toks[j], "MATERIALIZED"):
            mat = "MATERIALIZED "
        j += 1
    if j >= n or not _is_word(toks[j], *_DROP_KINDS):
        return []
    kind = toks[j].value.lower()
    j += 1
    if j < n and _is_word(toks[j], "CONCURRENTLY"):
        j += 1
    if j + 1 < n and _is_word(toks[j], "IF") and _is_word(toks[j + 1], "EXISTS"):
        j += 2
    params: dict[str, Any] = {"unbounded": True, "ddl": True}
    if any(_is_word(t, "CASCADE") for t in toks):
        params["cascade"] = True
    raw = f"DROP {mat}{kind.upper()}"
    results: list[_Classification] = []
    seen: set[str] = set()
    while j < n and _is_name(toks[j]) and not _is_word(toks[j], "CASCADE", "RESTRICT"):
        parts = [toks[j].value]
        j += 1
        while j + 1 < n and _is_punct(toks[j], ".") and _is_name(toks[j + 1]):
            parts.append(toks[j + 1].value)
            j += 2
        if j < n and _is_punct(toks[j], "("):  # DROP FUNCTION f(int)
            level = 0
            while j < n:
                if _is_punct(toks[j], "("):
                    level += 1
                elif _is_punct(toks[j], ")"):
                    level -= 1
                    if level == 0:
                        j += 1
                        break
                j += 1
        meta: dict[str, Any] = {"schema": parts[-2]} if len(parts) >= 2 else {}
        resource = f"{kind}/" + ".".join(parts)
        if resource in seen:  # DROP TABLE users, users
            if j < n and _is_punct(toks[j], ","):
                j += 1
                continue
            break
        seen.add(resource)
        results.append((resource, "delete", dict(params), "ddl", raw, meta))
        if kind in ("schema", "database"):
            results.append(
                ("table/*", "delete", {"unbounded": True}, "ddl", f"DROP {kind.upper()} (cascade)",
                 {"schema": parts[-1]})
            )
        if j < n and _is_punct(toks[j], ","):
            j += 1
            continue
        break
    return results


def _classify_tokens(toks: list[_T], dialect: str) -> list[_Classification]:
    """Returns a list of (resource, action, params, statement_class,
    raw_action, extra_metadata) for one statement."""
    if not toks:
        return [("unknown/*", "update", {"unclassified": True}, "dml", "UNKNOWN", {})]
    truncated = len(toks) > _MAX_STATEMENT_TOKENS
    if truncated:
        toks = toks[:_MAX_STATEMENT_TOKENS]
        results = list(_classify_tokens(toks, dialect))
        return [*results, ("unknown/*", "update", {"unclassified": True, "too_large": True},
                           "dml", "UNKNOWN", {})]

    lead = 0
    while lead < len(toks) and _is_punct(toks[lead], "("):
        lead += 1
    first_tok = toks[lead] if lead < len(toks) else None
    first_word = first_tok.value.upper() if first_tok is not None and first_tok.kind == "word" \
        else ""
    if lead and first_word not in ("SELECT", "WITH", "VALUES", "TABLE"):
        first_word = ""

    if _is_explain(toks, 0):
        rest, analyze = _strip_explain(toks)
        sub = _classify_tokens(rest, dialect) if rest else []
        if analyze:
            annotated: list[_Classification] = []
            for r, a, p, sc, ra, extra in sub:
                p = dict(p)
                p["explain_analyze"] = True
                annotated.append((r, a, p, sc, ra, extra))
            return annotated or [("table/*", "read", {"explain": True}, "dql", "EXPLAIN", {})]
        # Plain EXPLAIN plans the statement without running it: a read of
        # every table it names (its targets included).
        explained: list[_Classification] = []
        named: set[str] = set()
        for r, _a, _p, _sc, _ra, extra in sub:
            if r.startswith("table/") and r != "table/*" and r not in named:
                named.add(r)
                explained.append((r, "read", {"explain": True}, "dql", "EXPLAIN", extra))
        return explained or [("table/*", "read", {"explain": True}, "dql", "EXPLAIN", {})]

    body = _render(toks)

    if first_word == "DROP":
        dropped = _classify_drop(toks)
        if dropped:
            return dropped

    if first_word == "TRUNCATE":
        truncated_tables: list[_Classification] = []
        j = 1
        if _is_word(toks[j] if j < len(toks) else None, "TABLE"):
            j += 1
        while j < len(toks):
            while _is_word(toks[j] if j < len(toks) else None, "ONLY"):
                j += 1
            if j >= len(toks) or not _is_name(toks[j]):
                break
            parts = [toks[j]]
            j += 1
            while j + 1 < len(toks) and _is_punct(toks[j], ".") and _is_name(toks[j + 1]):
                parts.append(toks[j + 1])
                j += 2
            resource, extra_meta = _table_resource([p.value for p in parts])
            truncated_tables.append(
                (resource, "delete", {"truncate": True, "unbounded": True, "ddl": True}, "ddl",
                 "TRUNCATE", extra_meta)
            )
            if j < len(toks) and _is_punct(toks[j], "*"):
                j += 1
            if j < len(toks) and _is_punct(toks[j], ","):
                j += 1
                continue
            break
        if truncated_tables:
            return truncated_tables

    if first_word in (
        "SELECT", "WITH", "VALUES", "TABLE", "DELETE", "UPDATE", "INSERT", "MERGE"
    ) or (first_word == "REPLACE" and len(toks) > 1 and not _is_punct(toks[1], "(")):
        return _scan_results(_scan(toks, first_word, dialect), first_word=first_word, primary=[])

    m = _ALTER_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"ddl": True}
        if _DROP_COLUMN_RE.search(rest):
            params["drop_column"] = True
        return [(resource, "update", params, "ddl", "ALTER TABLE", extra_meta)]

    m = _CREATE_RE.match(body) or _CREATE_FALLBACK_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        mat = "MATERIALIZED " if m.re is _CREATE_RE and m.group("mat") else ""
        create = (resource, "create", {"ddl": True}, "ddl", f"CREATE {mat}{kind.upper()}",
                  extra_meta)
        # CREATE TABLE|VIEW ... AS SELECT reads its source tables.
        return _scan_results(_scan(toks, first_word, dialect), first_word=first_word,
                             primary=[create])

    if first_word in ("SHOW", "DESCRIBE", "DESC"):
        resource, extra_meta = "table/*", {}
        dm = (_DESCRIBE_TARGET_RE.match(body) if first_word in ("DESCRIBE", "DESC")
              else _SHOW_FROM_RE.match(body))  # SHOW COLUMNS|INDEX FROM t
        if dm:
            resource, extra_meta = _resource_and_metadata(dm.group("name"), "table")
        return [(resource, "read", {}, "dql", first_word, extra_meta)]

    if first_word in ("GRANT", "REVOKE"):
        pattern = _GRANT_TO_RE if first_word == "GRANT" else _REVOKE_FROM_RE
        gm = None
        for gm in pattern.finditer(body):
            pass  # take the *last* match (closest to the grantee clause)
        if gm:
            resource, extra_meta = _resource_and_metadata(gm.group("name"), "role")
        else:
            resource, extra_meta = "privilege/*", {}
        return [(resource, "update", {"privilege": True}, "dcl", first_word, extra_meta)]

    if first_word in ("SET", "RESET"):
        identity = _identity_change(toks)
        if identity is not None:
            return identity
        if _changes_lexing(toks):
            # the server reads later statements' strings differently
            # (NO_BACKSLASH_ESCAPES, ANSI_QUOTES, standard_conforming_strings, a
            # multi-byte client charset): what this reads as one string may be
            # two statements there
            return [("unknown/*", "update", {"unclassified": True, "changes_lexing": True},
                     "dml", first_word, {})]

    if first_word == "START" and not _START_TRANSACTION_RE.match(body):
        # START REPLICA / SLAVE / GROUP_REPLICATION change the server
        return [("unknown/*", "update", {"unclassified": True}, "dml", first_word, {})]
    if first_word == "SET" and any(_is_word(t, "SELECT", "TABLE") for t in toks):
        # SET @a = (SELECT secret FROM users): the tables its subqueries read
        return _scan_results(_scan(toks, first_word, dialect), first_word=first_word,
                             primary=[("session/*", "read", {}, "tcl", first_word, {})])
    if first_word in ("BEGIN", "COMMIT", "ROLLBACK", "SET", "START"):
        return [("session/*", "read", {}, "tcl", first_word, {})]

    if first_word == "DO":
        return [("block/*", "update", {"opaque": True}, "opaque", "DO", {})]

    if first_word == "CALL":
        cm = _CALL_RE.match(body)
        if cm:
            resource, extra_meta = _resource_and_metadata(cm.group("name"), "procedure")
        else:
            resource, extra_meta = "block/*", {}
        return [(resource, "update", {"opaque": True}, "opaque", "CALL", extra_meta)]

    if first_word in ("EXECUTE", "PERFORM"):
        xm = _EXECUTE_PROC_RE.match(body)
        if xm:
            resource, extra_meta = _resource_and_metadata(xm.group("name"), "procedure")
        else:
            resource, extra_meta = "block/*", {}
        return [(resource, "update", {"opaque": True}, "opaque", first_word, extra_meta)]

    # Unknown statement: fail-safe -- never treated as a harmless read.
    return [("unknown/*", "update", {"unclassified": True}, "dml", first_word or "UNKNOWN", {})]


# Settings that change how the server splits and quotes later statements.
_LEXING_SETTINGS = frozenset({"sql_mode", "standard_conforming_strings", "backslash_quote"})
# Client character-set settings: a multi-byte charset whose trailing byte can be
# a backslash (gbk, sjis, big5, …) changes where a string ends; these do not.
_CHARSET_SETTINGS = frozenset({"names", "character_set_client", "client_encoding", "charset"})
_SAFE_CHARSETS = frozenset({
    "utf8", "utf8mb3", "utf8mb4", "utf-8", "unicode", "latin1", "latin2", "ascii", "binary",
    "default", "sql_ascii", "win1252", "iso_8859_1", "iso-8859-1",
})


def _setting_name(t: _T) -> str:
    return t.value.lower().lstrip("@").removeprefix("session.").removeprefix("global.")


def _changes_lexing(toks: list[_T]) -> bool:
    """Whether a ``SET`` changes how the server reads later statements' strings:
    ``sql_mode`` (NO_BACKSLASH_ESCAPES, ANSI_QUOTES), ``standard_conforming_strings``,
    ``backslash_quote``, or a client charset that is not known to be safe
    (``SET NAMES gbk``, ``SET CHARACTER SET sjis``, ``SET client_encoding = 'SJIS'``)."""
    for k, t in enumerate(toks):
        if t.kind not in ("word", "qident", "var"):
            continue
        name = _setting_name(t)
        if name in _LEXING_SETTINGS:
            return True
        if name == "character" and k + 1 < len(toks) and _is_word(toks[k + 1], "SET"):
            name, k = "charset", k + 1
        if name in _CHARSET_SETTINGS:
            m = k + 1
            while m < len(toks) and toks[m].kind == "punct" and toks[m].value in ("=",):
                m += 1
            if m < len(toks) and _is_word(toks[m], "TO"):
                m += 1
            value = toks[m] if m < len(toks) else None
            if value is None or value.kind not in ("word", "str", "qident") or (
                    value.value.lower() not in _SAFE_CHARSETS):
                return True
    return False

DIALECTS = ("postgres", "mysql", "sqlite", "generic")
_DIALECT_ALIASES = {"postgresql": "postgres", "pg": "postgres", "mariadb": "mysql",
                    "sqlite3": "sqlite"}


def normalize_dialect(dialect: str | None) -> str:
    """The dialect ``from_sql`` reads ``dialect`` as: one of :data:`DIALECTS`.
    An unknown name is read as ``generic`` rather than as one dialect's rules,
    since a lexer for the wrong dialect can hide a statement."""
    name = (dialect or "").strip().lower()
    name = _DIALECT_ALIASES.get(name, name)
    return name if name in DIALECTS else "generic"


def from_sql(
    sql: str, *, dialect: str = "generic", database: str | None = None
) -> list[InfrastructureIntent]:
    """Parses a batch of ``;``-separated SQL statements into
    InfrastructureIntents (one or more per statement -- see module
    docstring), provider ``"sql"``. ``dialect`` (``postgres``, ``mysql``,
    ``sqlite``, ``generic``) decides how strings, comments and dollar quotes
    are read; the name is matched without case (``PostgreSQL``, ``mariadb``
    and ``sqlite3`` name their dialect), and any other value is read as
    ``generic``, which flags what a server could read differently."""
    dialect = normalize_dialect(dialect)
    intents = _intents_of(sql, dialect, database)
    if (dialect == "mysql" and _VERSIONED_OPEN_RE.search(sql)) or (
            dialect == "generic" and _EXEC_OPEN_RE.search(sql)):
        # a server runs the /*!N comments up to its own version and skips the rest
        # (Oracle MySQL skips /*M! too): /*!99999 select 1 */ drop table users. One
        # reading per version threshold, with and without the MariaDB-only ones.
        versions = sorted({int(v) for v in _VERSION_NUMBER_RE.findall(sql)})
        if len(versions) > _MAX_VERSION_READINGS:
            versions = [versions[0], versions[-1]]  # too many to read each: flagged
            intents.append(InfrastructureIntent(
                resource="unknown/*", action="update", provider="sql",
                params={"unclassified": True, "ambiguous_comment": True,
                        "statement_class": "dml", "raw_action": "AMBIGUOUS"},
                metadata={"dialect": dialect, **({"database": database} if database else {})}))
        seen = {_intent_key(i) for i in intents}
        # generic: Postgres and SQLite skip even an unversioned /*! … */ (-1 skips all)
        for version in [*([-1] if dialect == "generic" else []), 0, *versions]:
            for mariadb in (True, False):
                for intent in _intents_of(sql, dialect, database, version=version,
                                          mariadb=mariadb):
                    if _intent_key(intent) not in seen:
                        seen.add(_intent_key(intent))
                        intents.append(intent)
    return intents


def _intents_of(sql: str, dialect: str, database: str | None, *,
                version: float = float("inf"), mariadb: bool = True) -> list[InfrastructureIntent]:
    intents = []
    reading_all = version == float("inf") and mariadb
    statements = _lex(sql, dialect, version, mariadb)
    reads = _FILE_READS.get()
    if reads is not None:  # many tiny statements (x;x;x;…) cost as much as a big one
        reads["statements"] = reads.get("statements", 0) + len(statements)
        if reads["statements"] > _MAX_DECISION_STATEMENTS:
            raise SqlBudgetExceeded("more SQL statements than can be checked in one command")
    for toks, _comment, flags in statements:
        if not reading_all and not toks and not flags:
            continue  # only a skipped comment: /*!40101 SET NAMES utf8 */;
        results = list(_classify_tokens(toks, dialect))
        for flag in sorted(flags):  # generic: the server may read it differently
            results.append(
                ("unknown/*", "update", {"unclassified": True, flag: True}, "dml", "AMBIGUOUS", {})
            )
        for resource, action, params, statement_class, raw_action, extra_meta in results:
            params = dict(params)
            params["statement_class"] = statement_class
            params["raw_action"] = raw_action

            metadata: dict[str, Any] = {"dialect": dialect}
            if database is not None:
                metadata["database"] = database
            metadata.update(extra_meta)

            intents.append(
                InfrastructureIntent(
                    resource=resource,
                    action=action,
                    provider="sql",
                    params=params,
                    metadata=metadata,
                )
            )
    return intents


# --- psql / mysql / sqlite3 argv wrappers -------------------------------------


# Short options of psql / mysql that take a value, so letters after them in a
# bundle (`-dcars`, `-psecret`) are that value, not more options. mysql's -f,
# -v, -U, -o, -T and psql's -S take none (`mysql -fe 'SQL'`, `psql -Sc 'SQL'`).
_PSQL_SHORT_VALUED = frozenset("dhpUfvPFRToL")
_MYSQL_SHORT_VALUED = frozenset("DhPupS")


def _bundled_command(tok: str, letters: set[str],
                     valued: frozenset[str]) -> tuple[str, str | None, bool] | None:
    """For a bundle of short options (``-Atc``, ``-cSELECT 1``, ``-BNe``,
    ``-qf x.sql``): the first of ``letters`` in it, the value attached to it,
    and whether its value is the next word instead; ``None`` when the bundle
    holds none of them."""
    for k, letter in enumerate(tok[1:], start=1):
        if letter in letters:
            rest = tok[k + 1:]
            return (letter, rest, False) if rest else (letter, None, True)
        # psql -1c / -0c: those letters take no value
        if letter in valued or not letter.isalnum():
            return None
    return None


def _parse_db_cli_tokens(
    tokens: list[str], *, command_flags: set[str], database_flags: set[str],
    file_flags: frozenset[str] = frozenset({"-f", "--file"}),
    value_flags: frozenset[str] = frozenset(),
    short_valued: frozenset[str] = frozenset(),
    mysql_spelling: bool = False,
) -> tuple[str | None, str | None, list[str | None], list[str], list[str]]:
    """Shared argv walk for psql/mysql/sqlite3: returns (database, host,
    sql_texts, file_paths, positional). ``sql_texts`` and ``file_paths`` collect *every*
    ``-c``/``-e``/``--command``/``--execute`` occurrence in argv order --
    a real invocation runs each one in turn, so the last one no longer
    silently wins (REVIEW-4 T1.4). Input redirected via the shell
    (``< file.sql``) leaves no trace in argv and can't be recovered here."""
    database: str | None = None
    host: str | None = None
    sql_texts: list[str | None] = []
    file_paths: list[str] = []  # psql runs every -c and -f, in order
    positional: list[str] = []

    # short-option bundles: psql and mysql only (sqlite3's options are words)
    short_commands = {f[1] for f in command_flags if len(f) == 2} if short_valued else set()
    short_files = {f[1] for f in file_flags if len(f) == 2} if short_valued else set()
    # the clients accept any unique prefix of a long option (psql --comm, mysql --exec)
    # psql and mysql (not sqlite3) accept any unique prefix of a long option
    # (psql --comm, mysql --exec); mysql also ignores case, reads `_` as `-` and
    # drops stacked loose-/maximum-/skip-/enable-/disable- prefixes
    long_options = sorted({f for f in (*command_flags, *file_flags, *database_flags,
                                       *value_flags, "--host") if f.startswith("--")})
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if short_valued and tok.startswith("--") and len(tok) > 2:
            name, eq, value = tok.partition("=")
            if mysql_spelling:
                name = _mysql_option_name(name)
            matches = [f for f in long_options if f.startswith(name)]
            if name in long_options:
                tok = name + eq + value
            elif len(matches) == 1 or (matches and all(m in command_flags for m in matches)):
                tok = matches[0] + eq + value  # --init-comm: either way it is SQL
        if tok in command_flags:
            i += 1
            sql_texts.append(tokens[i] if i < n else None)  # a trailing -c: unknown SQL
        elif (len(tok) > 2 and tok[0] == "-" and tok[1] != "-"
              and (bundled := _bundled_command(tok, short_commands | short_files,
                                               short_valued)) is not None):
            letter, text, takes_next = bundled  # psql -Atc 'SQL', -c'SQL', -qf x.sql
            if takes_next:
                i += 1
                text = tokens[i] if i < n else None
            if letter in short_commands:
                sql_texts.append(text)
            elif text is not None:
                file_paths.append(text)
        elif any(tok.startswith(f"{f}=") for f in command_flags if f.startswith("--")):
            sql_texts.append(tok.split("=", 1)[1])
        elif tok in file_flags:
            i += 1
            if i < n:
                file_paths.append(tokens[i])
        elif tok in value_flags:
            i += 1  # the value is not the database or SQL
        elif "--file" in file_flags and tok.startswith("--file="):
            file_paths.append(tok.split("=", 1)[1])
        elif tok in database_flags:
            i += 1
            if i < n:  # a trailing -d names no database
                database = tokens[i]
        elif any(tok.startswith(f"{f}=") for f in database_flags if f.startswith("--")):
            database = tok.split("=", 1)[1]
        elif tok in ("-h", "--host"):
            i += 1
            if i < n:
                host = tokens[i]
        elif tok.startswith("--host="):
            host = tok.split("=", 1)[1]
        elif tok.startswith("-") and tok != "-":
            pass  # unrecognised flag -- ignored, value (if any) left as positional
        else:
            positional.append(tok)
        i += 1

    if database is None:
        for tok in positional:
            if "://" in tok:
                database = tok.rsplit("/", 1)[-1] or None
                break

    return database, host, sql_texts, file_paths, positional


def _psql_variable_values(tokens: list[str]) -> list[str]:
    """The values of psql ``-v NAME=VALUE`` / ``--set`` / ``--variable``."""
    values: list[str] = []
    for k, tok in enumerate(tokens):
        if tok in ("-v", "--set", "--variable") and k + 1 < len(tokens):
            setting = tokens[k + 1]
        elif tok.startswith(("--set=", "--variable=")):
            setting = tok.split("=", 1)[1]
        elif tok.startswith("-v") and len(tok) > 2:
            setting = tok[2:]
        else:
            continue
        _name, eq, value = setting.partition("=")
        if eq and value:
            values.append(value)
    return values


def _intent_key(intent: InfrastructureIntent) -> tuple[str, str, str]:
    return intent.resource, intent.action, repr(sorted(intent.params.items()))


# The most of the script files (-f, -init) that is read, in all, for one call
# or, inside shared_file_budget(), for one hook decision; a file past it is
# opaque (a 1 MiB script classifies in a few seconds).
_SQL_FILE_LIMIT = 1024 * 1024
# The most SQL classified in all: -c/-e texts and script files, a file once per
# run of it (psql -f x.sql && psql -f x.sql && …); past it the SQL is unknown.
_SQL_FILE_USE_LIMIT = 2 * _SQL_FILE_LIMIT
# The most statements classified in one hook decision, all readings counted.
_MAX_DECISION_STATEMENTS = 50_000
_FILE_READS: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "aegis_sql_file_reads", default=None)


class SqlBudgetExceeded(ValueError):
    """More SQL in one call (or, inside shared_file_budget(), one hook decision)
    than the classifier reads: the caller fails closed, as for SQL it cannot
    parse -- unclassified SQL may be allowed by a policy."""


@contextlib.contextmanager
def shared_file_budget() -> Iterator[None]:
    """One script-file budget for everything parsed inside it (every client
    call of a command line, and the hook's second parse, which reuses what
    the first one read)."""
    token = _FILE_READS.set(_new_reads())
    try:
        yield
    finally:
        _FILE_READS.reset(token)


@contextlib.contextmanager
def without_script_files() -> Iterator[None]:
    """Inside shared_file_budget(): parse without reading script files (each
    is an opaque script), for a pass that does not need their SQL."""
    reads = _FILE_READS.get()
    if reads is None:
        yield
        return
    reads["skip"] = True
    try:
        yield
    finally:
        reads["skip"] = False


def _new_reads() -> dict[str, Any]:
    return {"left": _SQL_FILE_LIMIT, "uses": _SQL_FILE_USE_LIMIT, "files": {}, "intents": {},
            "skip": False}


def _build_cli_intents(
    *,
    sql_texts: list[str | None],
    file_paths: list[str],
    database: str | None,
    host: str | None,
    dialect: str,
    argv: list[str],
) -> list[InfrastructureIntent]:
    if not sql_texts and not file_paths:
        raise ValueError(f"could not find SQL text or a script file in: {argv!r}")
    # psql/mysql run each -c/-e (and psql each -f) on its own: a comment or quote
    # left open in one must not swallow the next. A -c with no text is unknown SQL.
    intents: list[InfrastructureIntent] = []
    reads = _FILE_READS.get() or _new_reads()
    if sql_texts and reads["skip"]:  # this pass does not need the SQL
        sql_texts = [None]
    elif sql_texts:
        for k, text in enumerate(sql_texts):
            if text is not None and len(text) > reads["uses"]:
                raise SqlBudgetExceeded("more SQL than can be checked in one command")
            elif text is not None:
                reads["uses"] -= len(text)
        for text in sql_texts:
            if text is None:
                meta: dict[str, Any] = {"dialect": dialect}
                if database is not None:
                    meta["database"] = database
                intents.append(InfrastructureIntent(
                    resource="unknown/*", action="update", provider="sql",
                    params={"unclassified": True, "statement_class": "dml",
                            "raw_action": "MISSING_SQL"},
                    metadata=meta))
            else:
                intents.extend(from_sql(text, dialect=dialect, database=database))
        texts = [t for t in sql_texts if t is not None]
        if dialect == "mysql" and len(texts) > 1 and len(" ".join(texts)) <= reads["uses"]:
            reads["uses"] -= len(" ".join(texts))
            # the mysql client joins every -e into one buffer (with a space), so a
            # quote or comment open in one -e runs on into the next; both readings
            # are kept
            seen = {_intent_key(i) for i in intents}
            for intent in from_sql(" ".join(texts), dialect=dialect, database=database):
                if _intent_key(intent) not in seen:
                    seen.add(_intent_key(intent))
                    intents.append(intent)
        elif dialect == "mysql" and len(texts) > 1:  # the joined reading cannot be made
            raise SqlBudgetExceeded("more SQL than can be checked in one command")
    for file_path in file_paths:
        from pathlib import Path

        text = None
        key = ""
        too_large = False
        try:
            path = Path(file_path)
            if reads["skip"]:
                pass  # this pass does not need the file's SQL
            elif (key := str(path.resolve())) in reads["files"]:
                text = reads["files"][key]  # read already in this decision
            elif path.is_file():
                with path.open("rb") as handle:
                    data = handle.read(reads["left"] + 1)
                too_large = len(data) > reads["left"]
                if not too_large:
                    reads["left"] -= len(data)
                    text = data.decode("utf-8", errors="replace")
                reads["files"][key] = text
        except (OSError, ValueError):  # unreadable, or a NUL in the name
            text = None
        if too_large:  # past what one command may have read: fail closed, not opaque
            raise SqlBudgetExceeded(f"{file_path} is more SQL than can be checked in one command")
        if text is not None and len(text) > reads["uses"]:
            raise SqlBudgetExceeded("more SQL than can be checked in one command")
        if text is not None:
            reads["uses"] -= len(text)
            # a file run again in the same decision is classified once
            done = reads.setdefault("intents", {})
            cache_key = (key, dialect, database)
            if cache_key not in done:
                done[cache_key] = from_sql(text, dialect=dialect, database=database)
            intents.extend(copy.deepcopy(done[cache_key]))
        else:
            metadata: dict[str, Any] = {"dialect": dialect}
            if database is not None:
                metadata["database"] = database
            intents += [
                InfrastructureIntent(
                    resource=f"script/{_basename(file_path)}",
                    action="update",
                    provider="sql",
                    params={
                        "raw_action": "file",
                        "unclassified": True,
                        # Fail-safe: an unreadable script is never a silent
                        # ALLOW -- the agent may write the file *after* this
                        # check runs, so treat it as an opaque write.
                        "unreadable": True,
                        "opaque": True,
                        "file": file_path,
                    },
                    metadata=metadata,
                )
            ]

    if host is not None:
        for intent in intents:
            intent.metadata["host"] = host
    return intents


def from_psql(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``psql`` invocation, extracting ``-c``/``--command`` SQL,
    ``-f``/``--file`` scripts, and the target database from ``-d``/
    ``--dbname`` or a trailing connection URI/dbname positional."""
    if not argv or _basename(argv[0]) != "psql":
        raise ValueError(f"not a recognizable psql invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_texts, file_paths, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-c", "--command"}, database_flags={"-d", "--dbname"},
        short_valued=_PSQL_SHORT_VALUED,
    )
    if file_paths:
        # psql interpolates -v/--set/--variable values into a script (`:x`), where
        # they are read as SQL: check each value as SQL too
        sql_texts = [*sql_texts, *_psql_variable_values(tokens)]
    if database is None:
        non_uri_positional = [t for t in positional if "://" not in t]
        if non_uri_positional:
            database = non_uri_positional[0]
    return _build_cli_intents(
        sql_texts=sql_texts, file_paths=file_paths, database=database, host=host,
        dialect="postgres", argv=argv,
    )


_MYSQL_OPTION_PREFIXES = ("loose-", "maximum-", "skip-", "enable-", "disable-")


def _mysql_option_name(name: str) -> str:
    """A mysql long option's name as my_getopt reads it: case folded, `_` as
    `-`, the loose-/maximum-/skip-/enable-/disable- prefixes dropped however
    often they are stacked (`--Maximum-Loose_Execute` -> `--execute`)."""
    base = name[2:].lower().replace("_", "-")
    while base.startswith(_MYSQL_OPTION_PREFIXES):
        base = base.split("-", 1)[1]
    return "--" + base


def _mysql_side_options(tokens: list[str]) -> tuple[str | None, list[str]]:
    """The statement delimiter a mysql call sets (``--delimiter=//``) and the
    option files it names (``--defaults-file``, ``--defaults-extra-file``)."""
    delimiter, files = None, []
    for k, tok in enumerate(tokens):
        if not tok.startswith("--"):
            continue
        name, eq, value = tok.partition("=")
        name = _mysql_option_name(name)
        if not eq:
            value = tokens[k + 1] if k + 1 < len(tokens) else ""
        if len(name) >= 5 and "--delimiter".startswith(name):
            delimiter = value
        elif name in ("--defaults-file", "--defaults-extra-file"):
            files.append(value)
    return delimiter, files


def _option_file_sql(path: str) -> list[str] | None:
    """The SQL a mysql option file runs (its ``execute`` and ``init-command``
    settings, however spelt); ``None`` when it cannot be read."""
    from pathlib import Path

    try:
        with Path(path).expanduser().open("rb") as handle:
            data = handle.read(_OPTION_FILE_LIMIT + 1)
    except (OSError, ValueError, RuntimeError):
        return None
    if len(data) > _OPTION_FILE_LIMIT:
        return None
    found = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        key, eq, value = line.strip().partition("=")
        if eq and _mysql_option_name("--" + key.strip()) in (
                "--execute", "--init-command", "--init-command-add"):
            found.append(value.strip().strip("'\""))
    return found


_OPTION_FILE_LIMIT = 64 * 1024


def from_mysql(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``mysql`` invocation, extracting ``-e``/``--execute`` SQL and the
    database from ``-D``/``--database`` or a trailing positional. The mysql
    client has no script option (``-f`` is ``--force``); a script comes in
    on stdin."""
    if not argv or _basename(argv[0]) != "mysql":
        raise ValueError(f"not a recognizable mysql invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_texts, file_paths, positional = _parse_db_cli_tokens(
        tokens,
        # --init-command runs on connect, before the -e text
        command_flags={"-e", "--execute", "--init-command", "--init-command-add"},
        database_flags={"-D", "--database"},
        file_flags=frozenset(),
        short_valued=_MYSQL_SHORT_VALUED, mysql_spelling=True,
        value_flags=frozenset({"--delimiter", "--defaults-file", "--defaults-extra-file"}),
    )
    if database is None and positional:
        database = positional[0]
    delimiter, option_files = _mysql_side_options(tokens)
    unreadable = []
    for option_file in option_files:  # [client] init-command=… runs on connect
        file_sql = _option_file_sql(option_file)
        if file_sql is None:
            unreadable.append(option_file)
        else:
            sql_texts = [*file_sql, *sql_texts]
    if delimiter and delimiter != ";":
        # --delimiter=// ends statements at // instead of ;: read it that way too
        sql_texts = [*sql_texts, *(t.replace(delimiter, ";") for t in sql_texts
                                   if t is not None and delimiter in t)]
    if not sql_texts and unreadable:
        sql_texts = [None]
    intents = _build_cli_intents(
        sql_texts=sql_texts, file_paths=file_paths, database=database, host=host,
        dialect="mysql", argv=argv,
    )
    for option_file in unreadable:  # an option file the hook cannot read may hold SQL
        intents.append(InfrastructureIntent(
            resource=f"script/{_basename(option_file)}", action="update", provider="sql",
            params={"raw_action": "file", "unclassified": True, "unreadable": True,
                    "opaque": True, "file": option_file},
            metadata={"dialect": "mysql", **({"database": database} if database else {})}))
    return intents


# sqlite3 options that take a value (sqlite3 options are single-dash words:
# -csv, -batch, -cmd …; it has no short-option bundles).
_SQLITE3_VALUED = frozenset({
    f"{dash}{name}" for dash in ("-", "--") for name in (
        "nullvalue", "separator", "newline", "vfs", "lookaside", "pagecache", "heap", "nonce",
        "mmap", "maxsize", "escape", "zip-file")
})


def from_sqlite3(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``sqlite3`` invocation. sqlite3 has no ``-c`` flag; SQL is
    given as a trailing positional (``sqlite3 mydb.db "DROP TABLE users;"``)
    after the database file, via ``-cmd SQL`` (run first), or via
    ``-f``/``-init``."""
    if not argv or _basename(argv[0]) != "sqlite3":
        raise ValueError(f"not a recognizable sqlite3 invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_texts, file_paths, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-cmd", "--cmd"}, database_flags=set(),
        file_flags=frozenset({"-f", "--init", "-init"}), value_flags=_SQLITE3_VALUED,
    )
    # the SQL arguments run after any -init script and -cmd command
    if positional:
        database = database or positional[0]
        sql_texts = [*sql_texts, *positional[1:]]  # sqlite3 runs each SQL argument in turn
    intents = _build_cli_intents(
        sql_texts=sql_texts, file_paths=file_paths, database=database, host=host,
        dialect="sqlite", argv=argv,
    )
    meta: dict[str, Any] = {"dialect": "sqlite", **({"database": database} if database else {})}
    if len(positional) < 2:
        # no SQL argument: after its -cmd / -init input sqlite3 reads SQL from stdin
        intents.append(InfrastructureIntent(
            resource="unknown/*", action="update", provider="sql",
            params={"unclassified": True, "statement_class": "dml", "raw_action": "STDIN"},
            metadata=meta))
    elif not intents:  # only dot-commands that show the schema (.tables, .schema)
        intents.append(InfrastructureIntent(
            resource="table/*", action="read", provider="sql",
            params={"raw_action": "DOT_COMMAND"}, metadata=meta))
    return intents


# --- mongosh -------------------------------------------------------------------

# Matches the *head* of a mongo shell call: ``db``, an optional collection
# selector (``.getCollection("x")``, ``["x"]``, or plain ``.x``), then
# ``.method(`` -- stopping right at the opening paren so the caller can
# bracket-match the args and simply ignore anything chained after the
# closing paren (``.find().forEach(...)`` classifies by ``find``, not by
# being dropped -- REVIEW-4 T1.4).
_MONGO_HEAD_RE = re.compile(
    r"\Adb\s*"
    r"(?:"
    r"\.\s*getCollection\s*\(\s*(?P<gc_quote>['\"])(?P<gc_name>.*?)(?P=gc_quote)\s*\)"
    r"|"
    r"\[\s*(?P<br_quote>['\"])(?P<br_name>.*?)(?P=br_quote)\s*\]"
    r"|"
    r"\.\s*(?P<dot_name>[A-Za-z_]\w*)"
    r")?"
    r"\s*\.\s*(?P<method>[A-Za-z_]+)\s*\(",
    re.DOTALL,
)


def _match_paren(text: str, start: int) -> int:
    """``start`` is the index right after an opening ``(`` (depth 1).
    Returns the index of the matching ``)``, quote-aware, or -1."""
    depth = 1
    i, n = start, len(text)
    in_single = in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_mongo_call(call: str) -> tuple[str | None, str, str] | None:
    """Returns (collection, method, args) for the *first*
    ``db.<...>.<method>(...)`` call in ``call``, tolerating
    ``getCollection("x")``/``db["x"]`` collection selectors and ignoring
    any further chained calls (e.g. ``.find(...).forEach(...)``)."""
    m = _MONGO_HEAD_RE.match(call)
    if not m:
        return None
    collection = m.group("gc_name") or m.group("br_name") or m.group("dot_name")
    args_start = m.end()
    close = _match_paren(call, args_start)
    if close == -1:
        return None
    return collection, m.group("method"), call[args_start:close]


def _first_brace_arg(args: str) -> str | None:
    args = args.strip()
    if not args.startswith("{"):
        return None
    depth = 0
    for idx, ch in enumerate(args):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return args[: idx + 1]
    return None


def _is_empty_filter(args: str) -> bool:
    arg = _first_brace_arg(args)
    if arg is None:
        return not args.strip()  # no args at all -> unfiltered
    return arg.strip()[1:-1].strip() == ""


def _classify_mongo_call(collection: str | None, method: str, args: str) -> InfrastructureIntent:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {"raw_action": method}

    if method == "dropDatabase":
        resource = "database/*"
        action = "delete"
        params["unbounded"] = True
    elif method == "drop":
        resource = f"collection/{collection}"
        action = "delete"
        params["unbounded"] = True
    elif method in ("deleteMany", "deleteOne", "remove"):
        resource = f"collection/{collection}"
        action = "delete"
        # deleteOne always targets a single document, regardless of filter.
        params["unbounded"] = _is_empty_filter(args) if method != "deleteOne" else False
    elif method.startswith("insert"):
        resource = f"collection/{collection}"
        action = "put"
    elif method.startswith("update"):
        resource = f"collection/{collection}"
        action = "update"
        params["unbounded"] = _is_empty_filter(args)
    elif method.startswith("find") or method.startswith("count") or method == "aggregate":
        resource = f"collection/{collection}"
        action = "read"
    else:
        resource = f"collection/{collection}" if collection else "unknown/*"
        action = "update"
        params["unclassified"] = True

    return InfrastructureIntent(
        resource=resource, action=action, provider="mongodb", params=params, metadata=metadata
    )


def from_mongosh(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``mongosh --eval "<js>"`` invocation into one
    InfrastructureIntent per top-level ``db.<collection>.<method>(...)`` (or
    ``db.dropDatabase()``) call in the eval string, provider ``"mongodb"``."""
    if not argv or _basename(argv[0]) != "mongosh":
        raise ValueError(f"not a recognizable mongosh invocation: {argv!r}")

    tokens = argv[1:]
    eval_text: str | None = None
    host: str | None = None
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--eval":
            i += 1
            eval_text = tokens[i]
        elif tok.startswith("--eval="):
            eval_text = tok.split("=", 1)[1]
        elif tok.startswith("-") and tok != "-":
            pass
        elif host is None and "://" not in tok:
            host = tok
        i += 1

    if eval_text is None:
        raise ValueError(f"could not find a --eval script in: {argv!r}")

    intents = []
    for call in eval_text.split(";"):
        call = call.strip()
        if not call:
            continue
        parsed = _parse_mongo_call(call)
        if parsed is None:
            continue
        collection, method, args = parsed
        intents.append(_classify_mongo_call(collection, method, args))

    if not intents:
        raise ValueError(f"could not parse any db.<collection>.<method>() call in: {argv!r}")
    return intents


# --- migration tools -----------------------------------------------------------


def from_migration_argv(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a coarse migration-tool invocation (alembic/flyway/rails/prisma)
    into a single InfrastructureIntent, provider ``"migration"``."""
    if not argv:
        raise ValueError("empty argv")
    tool = _basename(argv[0])
    tokens = argv[1:]

    if tool == "alembic":
        if not tokens:
            raise ValueError(f"alembic requires a subcommand: {argv!r}")
        subcmd, *rest = tokens
        if subcmd == "downgrade":
            rev = rest[0] if rest else "*"
            return [
                InfrastructureIntent(
                    resource=f"migration/{rev}",
                    action="rollback",
                    provider="migration",
                    params={"raw_action": "downgrade"},
                    metadata={"tool": "alembic"},
                )
            ]
        if subcmd == "upgrade":
            rev = rest[0] if rest else "head"
            return [
                InfrastructureIntent(
                    resource=f"migration/{rev}",
                    action="update",
                    provider="migration",
                    params={"raw_action": "upgrade"},
                    metadata={"tool": "alembic"},
                )
            ]
        raise ValueError(f"unsupported alembic subcommand: {argv!r}")

    if tool == "flyway":
        if not tokens:
            raise ValueError(f"flyway requires a subcommand: {argv!r}")
        subcmd = tokens[0]
        if subcmd == "clean":
            action = "delete"
        elif subcmd == "migrate":
            action = "update"
        else:
            raise ValueError(f"unsupported flyway subcommand: {argv!r}")
        return [
            InfrastructureIntent(
                resource="database/*",
                action=action,
                provider="migration",
                params={"raw_action": subcmd},
                metadata={"tool": "flyway"},
            )
        ]

    if tool in ("rails", "bin/rails"):
        if not tokens:
            raise ValueError(f"rails requires a task: {argv!r}")
        task = tokens[0]
        task_action = {
            "db:drop": "delete",
            "db:reset": "delete",
            "db:migrate": "update",
            "db:rollback": "rollback",
        }.get(task)
        if task_action is None:
            raise ValueError(f"unsupported rails task: {argv!r}")
        return [
            InfrastructureIntent(
                resource="database/*",
                action=task_action,
                provider="migration",
                params={"raw_action": task},
                metadata={"tool": "rails"},
            )
        ]

    if tool == "prisma":
        if len(tokens) < 2 or tokens[0] != "migrate":
            raise ValueError(f"unsupported prisma invocation: {argv!r}")
        subcmd = tokens[1]
        if subcmd == "reset":
            action = "delete"
        elif subcmd == "deploy":
            action = "update"
        else:
            raise ValueError(f"unsupported prisma migrate subcommand: {argv!r}")
        return [
            InfrastructureIntent(
                resource="database/*",
                action=action,
                provider="migration",
                params={"raw_action": f"migrate {subcmd}"},
                metadata={"tool": "prisma"},
            )
        ]

    raise ValueError(f"unsupported migration tool invocation: {argv!r}")


# --- evasion catalogue (REVIEW-4 T1.4) ------------------------------------------
#
# Statement/argv shapes this module now classifies correctly (never as a
# harmless "read", and never silently dropped). The adversarial test suite
# imports this list to drive its attack corpus -- see module docstring for
# the "Do" behind each entry.
evasion: list[str] = [
    "TRUNCATE [TABLE] t",
    "DROP TABLE t",
    "DROP SCHEMA s [CASCADE]",
    "DROP DATABASE d",
    "DROP INDEX i",
    "DROP VIEW v",
    "DELETE FROM t (no WHERE)",
    "DELETE/**/FROM t (block-comment-obfuscated keyword)",
    "DELETE -- line comment\\nFROM t",
    "WITH cte AS (DELETE FROM t ...) SELECT ...",
    "WITH cte AS (UPDATE t SET ...) SELECT ...",
    "WITH cte AS (INSERT INTO t ...) SELECT ...",
    "EXPLAIN <stmt>",
    "EXPLAIN ANALYZE <stmt>",
    "DO $$ ... $$",
    "CALL proc(...)",
    "EXECUTE proc(...)",
    "EXECUTE 'dynamic sql'",
    "PERFORM proc(...)",
    "DELETE t1, t2 FROM t1 JOIN t2 ... (MySQL multi-table delete)",
    "DELETE FROM t1 USING t2",
    "GRANT ... TO <unparseable grantee>",
    "REVOKE ... FROM <unparseable grantee>",
    'psql -c "..." -c "..." (multiple -c)',
    "psql -f <missing file>",
    'mysql -e "..." -e "..." (multiple -e)',
    "mysql -f <missing file>",
    'db.getCollection("x").deleteMany({})',
    'db["x"].drop()',
    "db.x.drop()",
    "db.dropDatabase()",
    "db.x.remove({})",
    "db.x.deleteMany() (no argument)",
    "db.x.updateMany({}, ...)",
    "db.x.find().forEach(...)",
    "SELECT ... FROM allowed JOIN|, other (#58)",
    "SELECT ... WHERE x IN (SELECT ... FROM other) (#58)",
    "SELECT ... UNION SELECT ... FROM other (#58)",
    "SELECT ... INTO new_table FROM t (#58)",
    "SELECT ... INTO OUTFILE '/path' (#58)",
    "SET ROLE r / SET SESSION AUTHORIZATION u / RESET ROLE (#58)",
    "SELECT set_config('role', 'r', false) (#58)",
    "EXPLAIN (ANALYZE) <stmt> (#58)",
    "E'x\\''; DROP ... / MySQL 'x\\''; DROP ... (backslash-escaped quote, #58)",
    "$$--$$ UNION SELECT ... (comment marker inside a dollar quote, #58)",
    "/*!50000 UNION SELECT ... */ (MySQL executable comment, #58)",
    "SET \"role\" = 'x' / set_config(lower('ROLE'), ...) (#58)",
    "WITH x AS (DELETE ...) DELETE|INSERT|UPDATE|MERGE ... (several DML, #58)",
    "FROM t <clause word as alias>, other (#58)",
    "DELETE FROM ONLY t / DELETE IGNORE FROM t / TRUNCATE ONLY t (#58)",
    "DESCRIBE SELECT ... (#58)",
    "/* a /* b */ ' */; DROP ... (Postgres nested comment, #58)",
    "set_config(U&'\\0072ole', ...) / E'rol\\145' (escaped setting name, #58)",
    "FROM U&\"\\0073ecret\" (Unicode-escaped identifier, #58)",
    "DELETE s FROM secret AS s JOIN ... (MySQL delete via alias, #58)",
    "INSERT ... ON CONFLICT DO UPDATE / ON DUPLICATE KEY UPDATE (#58)",
    "TABLE t INTO OUTFILE / (SELECT ...) INTO OUTFILE (#58)",
    "DROP TABLE harmless, users (#58)",
    "FROM a FORCE INDEX FOR ORDER BY (i), users (#58)",
    "FROM a, [users] (SQLite brackets, #58)",
]
