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
  (not in MySQL or SQLite). MySQL ``#`` and ``-- `` comments are comments;
  ``--`` not followed by whitespace is not, in MySQL. The body of a MySQL
  executable comment (``/*! ... */``, ``/*!50000 ...``, ``/*M! ...``) is read
  as SQL in every dialect -- MySQL runs it, and over-reporting is the safe
  side. The keyword regexes run on the statement with comments removed and
  every string literal blanked, so nothing inside a string can match.
* Every table the scan can see becomes its own ``read`` intent
  (deduplicated, in order): ``FROM`` and every ``JOIN`` target, comma joins
  (a clause word used as an alias -- ``products set, users`` -- does not end
  the list), subqueries, ``UNION``/``INTERSECT``/``EXCEPT`` branches, ``TABLE
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
  and ``UPDATE t1 JOIN t2 ... SET`` write every listed table. ``MERGE INTO
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
  ``SELECT ... INTO @var`` only sets a variable and stays a read.
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

import re
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
#   (single- or double-quoted), as the server reads them.
# * ``"..."`` is a quoted identifier (in MySQL its body follows the string
#   escape rules above); `` `...` `` is a MySQL identifier.
# * ``$$...$$`` / ``$tag$...$tag$`` are strings (not in MySQL or SQLite, which
#   have no dollar quoting); ``$1`` is a parameter.
# * ``--`` comments (MySQL: only ``--`` followed by whitespace), MySQL ``#``
#   comments and ``/* */`` comments are dropped. An executable comment
#   ``/*! ... */`` (``/*!50000``, MariaDB ``/*M!``) is not a comment to MySQL:
#   only its markers are dropped and its body is read as SQL, in every dialect
#   (reporting more than a server runs is the safe side).


class _T(NamedTuple):
    kind: str  # word, qident, str, var, param, num, punct
    value: str  # unquoted identifier / string contents / the text itself
    raw: str
    gap: bool  # whitespace or a comment came before it


_WS_RE = re.compile(r"\s+")
_EXEC_OPEN_RE = re.compile(r"/\*M?!\d*")
_DOLLAR_OPEN_RE = re.compile(r"\$(?:[^\W\d][\w]*)?\$")
_CHARSET_PREFIX_RE = re.compile(r"_[A-Za-z0-9]+(?=')")
_WORD_RE = re.compile(r"[^\W\d][\w$]*")
_NUM_RE = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+")
_PARAM_RE = re.compile(r"\$\d+")
_VAR_RE = re.compile(r"@@?(?:[\w$.]+|'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.|\"\")*\"|`[^`]*`)")
_BODY_RE = {
    ("'", False): re.compile(r"(?:[^']|'')*", re.DOTALL),
    ("'", True): re.compile(r"(?:[^'\\]|\\.|'')*", re.DOTALL),
    ('"', False): re.compile(r'(?:[^"]|"")*', re.DOTALL),
    ('"', True): re.compile(r'(?:[^"\\]|\\.|"")*', re.DOTALL),
    ("`", False): re.compile(r"(?:[^`]|``)*", re.DOTALL),
}
_BACKSLASH_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)

# Statements longer than this are scanned only up to it, plus an unclassified
# write for the rest: the scan is linear, the cap only bounds its cost.
_MAX_STATEMENT_TOKENS = 100_000


def _lex(sql: str, dialect: str) -> list[tuple[list[_T], bool]]:
    """Lexes ``sql`` and splits it on ``;``: a list of (tokens, had_comment)
    per non-empty statement. A statement with no tokens but a comment is kept
    (it is classified as unknown, never dropped)."""
    mysql = dialect == "mysql"
    dollar_quotes = dialect not in ("mysql", "sqlite")
    statements: list[tuple[list[_T], bool]] = []
    toks: list[_T] = []
    had_comment = False
    gap = False
    exec_open = 0
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch.isspace():
            i = _WS_RE.match(sql, i).end()  # type: ignore[union-attr]
            gap = True
            continue
        if exec_open and sql.startswith("*/", i):
            exec_open -= 1
            i += 2
            gap = True
            continue
        if (ch == "-" and sql.startswith("--", i)
                and (not mysql or i + 2 >= n or sql[i + 2].isspace())) or (ch == "#" and mysql):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            gap = had_comment = True
            continue
        if ch == "/" and sql.startswith("/*", i):
            em = _EXEC_OPEN_RE.match(sql, i)
            if em:
                exec_open += 1
                i = em.end()
            else:
                j = sql.find("*/", i + 2)
                i = n if j == -1 else j + 2
                had_comment = True
            gap = True
            continue

        start = i
        quote = ""
        backslash = mysql
        if ch in "'\"`":
            quote = ch
        elif ch in "EeNnBbXx" and sql[i + 1 : i + 2] == "'":
            quote, backslash = "'", backslash or ch in "Ee"
            i += 1
        elif ch in "Uu" and sql.startswith("&'", i + 1):
            quote = "'"
            i += 2
        elif ch == "_" and mysql:
            cm = _CHARSET_PREFIX_RE.match(sql, i)
            if cm:
                quote = "'"
                i = cm.end()
        if quote:
            body_re = _BODY_RE[(quote, backslash and quote != "`")]
            bm = body_re.match(sql, i + 1)
            end = bm.end()  # type: ignore[union-attr]
            body = sql[i + 1 : end]
            i = end + 1 if end < n else n
            if backslash and quote != "`":
                body = _BACKSLASH_ESCAPE_RE.sub(r"\1", body)
            body = body.replace(quote + quote, quote)
            kind = "str" if quote == "'" else "qident"
            toks.append(_T(kind, body, sql[start:i], gap))
            gap = False
            continue

        if ch == "$":
            dm = _DOLLAR_OPEN_RE.match(sql, i) if dollar_quotes else None
            if dm:
                tag = dm.group(0)
                end = sql.find(tag, dm.end())
                body_end = n if end == -1 else end
                i = n if end == -1 else end + len(tag)
                toks.append(_T("str", sql[dm.end() : body_end], sql[start:i], gap))
                gap = False
                continue
            pm = _PARAM_RE.match(sql, i)
            if pm:
                i = pm.end()
                toks.append(_T("param", pm.group(0), pm.group(0), gap))
                gap = False
                continue
        if ch == "@":
            vm = _VAR_RE.match(sql, i)
            if vm:
                i = vm.end()
                toks.append(_T("var", vm.group(0), vm.group(0), gap))
                gap = False
                continue
        wm = _WORD_RE.match(sql, i)
        if wm:
            i = wm.end()
            toks.append(_T("word", wm.group(0), wm.group(0), gap))
            gap = False
            continue
        nm = _NUM_RE.match(sql, i)
        if nm:
            i = nm.end()
            toks.append(_T("num", nm.group(0), nm.group(0), gap))
            gap = False
            continue
        i += 1
        if ch == ";":
            if toks or had_comment:
                statements.append((toks, had_comment))
            toks, had_comment, gap = [], False, False
            continue
        toks.append(_T("punct", ch, ch, gap))
        gap = False
    if toks or had_comment:
        statements.append((toks, had_comment))
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

_DROP_RE = re.compile(
    r"\A\s*DROP\s+(?P<kind>TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER)"
    rf"\s+(?:IF\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_ALTER_RE = re.compile(
    rf"\A\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_QUALIFIED_NAME_RE}", re.IGNORECASE
)
_CREATE_RE = re.compile(
    r"\A\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+)?"
    r"(?:UNLOGGED\s+)?(?:UNIQUE\s+)?(?P<mat>MATERIALIZED\s+)?"
    r"(?P<kind>TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER)"
    rf"\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_CREATE_FALLBACK_RE = re.compile(
    rf"\A\s*CREATE\s+(?P<kind>[A-Za-z_]+)\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_SHOW_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
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
_SET_OP_BEFORE_TABLE = frozenset({"UNION", "INTERSECT", "EXCEPT", "MINUS", "ALL", "DISTINCT", "AS"})
_DML = frozenset({"INSERT", "UPDATE", "DELETE", "MERGE"})
_LOCK_RANK = {"key share": 0, "share": 1, "no key update": 2, "update": 3}
_ACTION_RANK = {"delete": 3, "update": 2, "put": 1}
_SEARCH_LIMIT = 256  # how far an UPDATE looks ahead for its SET


class _Op:
    __slots__ = ("action", "targets", "raw", "index", "unbounded")

    def __init__(self, action: str | None, raw: str, index: int) -> None:
        self.action = action  # None: an unparseable DML statement
        self.targets: list[list[str]] = []
        self.raw = raw
        self.index = index
        self.unbounded: bool | None = None


class _Scan:
    __slots__ = ("tables", "ops", "into", "lock", "nowait", "skip_locked", "roles")

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


def _is_word(tok: _T | None, *words: str) -> bool:
    return tok is not None and tok.kind == "word" and tok.value.upper() in words


def _is_punct(tok: _T | None, ch: str) -> bool:
    return tok is not None and tok.kind == "punct" and tok.value == ch


def _is_name(tok: _T | None) -> bool:
    return tok is not None and tok.kind in ("word", "qident")


def _norm_ident(tok: _T) -> str:
    # Unquoted identifiers are case-insensitive; quoted ones are exact.
    return tok.value.lower() if tok.kind == "word" else tok.value


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
            if not _is_punct(tok(j), ","):
                break
            j += 1

    def is_cte(name: str, pos: int) -> bool:
        return any(lo < pos < hi for lo, hi in ctes.get(name, ()))

    def name_parts(j: int) -> tuple[list[_T], int]:
        parts = [toks[j]]
        m = j + 1
        while _is_punct(tok(m), ".") and _is_name(tok(m + 1)):
            parts.append(toks[m + 1])
            m += 2
        return parts, m

    seen: set[tuple[str, ...]] = set()
    alias_pos: set[int] = set()
    skip_dual = dialect in ("mysql", "oracle")
    from_list: dict[int, bool] = {}

    def mark_alias(m: int) -> None:
        t = tok(m)
        if _is_word(t, "AS"):
            alias_pos.add(m + 1)
        elif t is not None and (
            t.kind == "qident" or (t.kind == "word" and t.value.upper() not in _NOT_ALIAS)
        ):
            alias_pos.add(m)

    def parse_ref(j: int) -> None:
        while True:
            while _is_word(tok(j), "ONLY", "LATERAL"):
                j += 1
            t = tok(j)
            if not _is_punct(t, "("):
                break
            # ``(a JOIN b ...)``: descend; a subquery's own FROM is found by
            # the main loop.
            nxt = tok(j + 1)
            if nxt is None or _is_word(nxt, *_SUBQUERY_START):
                return
            from_list[depth[j] + 1] = True
            j += 1
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
        mark_alias(m)
        if len(parts) == 1 and is_cte(_norm_ident(t), j):
            return
        key = tuple(_norm_ident(p) for p in parts)
        if key not in seen:
            seen.add(key)
            scan.tables.append([p.value for p in parts])

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
            op = _Op("update", "UPDATE", i)
            target, m = target_at(j)
            if target:
                op.targets.append(target)
                # MySQL multi-table UPDATE: every table before SET may be
                # written (t1, t2 SET / t1 JOIN t2 ON ... SET).
                k, limit = m, min(n, m + _SEARCH_LIMIT)
                while k < limit and not _is_word(toks[k], "SET"):
                    tk = toks[k]
                    if depth[k] < d:
                        break
                    if _is_punct(tk, "(") and k in close_of:
                        k = close_of[k] + 1
                        continue
                    if _is_punct(tk, ",") or _is_word(tk, "JOIN", "STRAIGHT_JOIN"):
                        more, _m = target_at(k + 1)
                        if more:
                            op.targets.append(more)
                    k += 1
            op.unbounded = last_where.get(encl[i], -1) < i
        elif u == "INSERT":
            while _is_word(tok(j), "LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"):
                j += 1
            if _is_word(tok(j), "OR") and tok(j + 1) is not None:  # SQLite INSERT OR ...
                j += 2
            if _is_word(tok(j), "INTO"):
                j += 1
            op = _Op("put", "INSERT INTO", i)
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
    idents: set[int] = set()  # keyword-looking words used as identifiers

    for i, t in enumerate(toks):
        d = depth[i]
        prev = tok(i - 1)
        if t.kind == "punct":
            if t.value in "([":
                query_at[d + 1] = False
                from_list[d + 1] = False
                using_done[d + 1] = False
                last_kw.pop(d + 1, None)
                merge_at.pop(d + 1, None)
            elif t.value == ")" and from_list.get(d):
                mark_alias(i + 1)  # (SELECT ...) alias / f(...) alias
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
        if u in _DML:
            if prev is None or _is_punct(prev, "(") or _is_punct(prev, ")"):
                # A statement keyword (top level, a CTE body, after a CTE list).
                op = parse_op(i, u)
                scan.ops.append(op)
                if u == "MERGE":
                    merge_at[d] = op
                query_at[d] = True
                last_kw[d] = u
                from_list[d] = False
            elif _is_word(prev, "THEN") and d in merge_at:
                action = {"DELETE": "delete", "UPDATE": "update", "INSERT": "put"}[u] \
                    if u != "MERGE" else None
                op = merge_at[d]
                if action and (op.action is None
                               or _ACTION_RANK[action] > _ACTION_RANK[op.action]):
                    op.action = action
            continue

        if u == "FROM":
            if query_at.get(d) and (
                i - 1 in idents or not _is_word(prev, "DELETE", "DISTINCT", "ROWS")
            ):
                from_list[d] = True
                parse_ref(i + 1)
            continue
        if u in ("JOIN", "STRAIGHT_JOIN"):
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "USING" and last_kw.get(d) in ("DELETE", "MERGE") and not using_done.get(d):
            using_done[d] = True
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "TABLE" and (
            prev is None
            or _is_word(prev, *_SET_OP_BEFORE_TABLE)
            or _is_punct(prev, "(")
            or (last_kw.get(d) == "INSERT" and (_is_name(prev) or _is_punct(prev, ")"))
                and not _is_word(prev, "INTO"))
        ):
            parse_ref(i + 1)
            continue

        if u in _FROM_LIST_END:
            from_list[d] = False

        if (
            u == "INTO"
            and d == 0
            and scan.into is None
            and last_kw.get(0) == "SELECT"
        ):
            j = i + 1
            while _is_word(tok(j), "TEMP", "TEMPORARY", "UNLOGGED", "TABLE"):
                j += 1
            target = tok(j)
            if _is_word(target, "OUTFILE", "DUMPFILE"):
                path = tok(j + 1)
                scan.into = (
                    "file", path.value if path and path.kind in ("str", "qident") else None
                )
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
            j = after
            while j < n and depth[j] >= d and not _is_word(toks[j], "FOR"):
                if _is_word(toks[j], "NOWAIT"):
                    scan.nowait = True
                elif _is_word(toks[j], "SKIP") and _is_word(tok(j + 1), "LOCKED"):
                    scan.skip_locked = True
                j += 1
            continue

        if u == "SET_CONFIG" and _is_punct(tok(i + 1), "("):
            _set_config(toks, i, close_of, depth, scan)

    return scan


def _plain_string_arg(toks: list[_T], close_of: dict[int, int], lo: int, hi: int) -> str | None:
    """The value of tokens ``lo..hi`` (exclusive) when they are one string
    literal, possibly in parentheses (``('role')``); else None."""
    while hi - lo >= 3 and _is_punct(toks[lo], "(") and close_of.get(lo) == hi - 1:
        lo, hi = lo + 1, hi - 1
    if hi - lo == 1 and toks[lo].kind == "str":
        return toks[lo].value
    return None


def _set_config(
    toks: list[_T], i: int, close_of: dict[int, int], depth: list[int], scan: _Scan
) -> None:
    """``set_config(setting, value, is_local)`` at token ``i`` (the name; any
    ``pg_catalog.`` qualifier before it does not matter). A role change when
    the setting is ``role``/``session_authorization`` -- or when it isn't a
    plain string literal, since it then might be (fail-safe: ``role/*``)."""
    close = close_of.get(i + 1, len(toks))
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
    if setting is not None and setting.strip().lower() not in ("role", "session_authorization"):
        return
    value = None
    if setting is not None and len(args) > 1:
        value = _plain_string_arg(toks, close_of, *args[1])
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
        while j < n and (_is_word(toks[j], *_EXPLAIN_WORD_OPTIONS) or _is_word(toks[j], "FORMAT")):
            if _is_word(toks[j], "ANALYZE", "ANALYSE"):
                analyze = True
            if _is_word(toks[j], "FORMAT") and j + 2 < n and _is_punct(toks[j + 1], "="):
                j += 2
            j += 1
    return toks[j:], analyze


def _classify_tokens(toks: list[_T], dialect: str) -> list[_Classification]:
    """Returns a list of (resource, action, params, statement_class,
    raw_action, extra_metadata) for one statement."""
    if not toks:
        return [("unknown/*", "update", {"unclassified": True}, "dml", "UNKNOWN", {})]
    truncated = len(toks) > _MAX_STATEMENT_TOKENS
    if truncated:
        toks = toks[:_MAX_STATEMENT_TOKENS]
        results = _classify_tokens(toks, dialect)
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

    m = _DROP_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        rest = body[m.end() :]
        params: dict[str, Any] = {"unbounded": True, "ddl": True}
        if _CASCADE_RE.search(rest):
            params["cascade"] = True
        results: list[_Classification] = [
            (resource, "delete", params, "ddl", f"DROP {kind.upper()}", extra_meta)
        ]
        if kind in ("schema", "database"):
            qualified_name, _schema = _split_schema(m.group("name"))
            target_name = qualified_name.rsplit(".", 1)[-1]
            results.append(
                (
                    "table/*",
                    "delete",
                    {"unbounded": True},
                    "ddl",
                    f"DROP {kind.upper()} (cascade)",
                    {"schema": target_name},
                )
            )
        return results

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

    if first_word in ("SELECT", "WITH", "VALUES", "TABLE", "DELETE", "UPDATE", "INSERT", "MERGE"):
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
              else _SHOW_FROM_RE.search(body))  # SHOW COLUMNS|INDEX FROM t
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


def from_sql(
    sql: str, *, dialect: str = "generic", database: str | None = None
) -> list[InfrastructureIntent]:
    """Parses a batch of ``;``-separated SQL statements into
    InfrastructureIntents (one or more per statement -- see module
    docstring), provider ``"sql"``. ``dialect`` (``postgres``, ``mysql``,
    ``sqlite``, ``generic``) decides how strings, comments and dollar quotes
    are read."""
    intents = []
    for toks, _comment in _lex(sql, dialect):
        for resource, action, params, statement_class, raw_action, extra_meta in (
            _classify_tokens(toks, dialect)
        ):
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


def _parse_db_cli_tokens(
    tokens: list[str], *, command_flags: set[str], database_flags: set[str]
) -> tuple[str | None, str | None, list[str], str | None, list[str]]:
    """Shared argv walk for psql/mysql/sqlite3: returns (database, host,
    sql_texts, file_path, positional). ``sql_texts`` collects *every*
    ``-c``/``-e``/``--command``/``--execute`` occurrence in argv order --
    a real invocation runs each one in turn, so the last one no longer
    silently wins (REVIEW-4 T1.4). Input redirected via the shell
    (``< file.sql``) leaves no trace in argv and can't be recovered here."""
    database: str | None = None
    host: str | None = None
    sql_texts: list[str] = []
    file_path: str | None = None
    positional: list[str] = []

    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in command_flags:
            i += 1
            sql_texts.append(tokens[i])
        elif any(tok.startswith(f"{f}=") for f in command_flags if f.startswith("--")):
            sql_texts.append(tok.split("=", 1)[1])
        elif tok in ("-f", "--file"):
            i += 1
            file_path = tokens[i]
        elif tok.startswith("--file="):
            file_path = tok.split("=", 1)[1]
        elif tok in database_flags:
            i += 1
            database = tokens[i]
        elif any(tok.startswith(f"{f}=") for f in database_flags if f.startswith("--")):
            database = tok.split("=", 1)[1]
        elif tok in ("-h", "--host"):
            i += 1
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

    return database, host, sql_texts, file_path, positional


def _build_cli_intents(
    *,
    sql_texts: list[str],
    file_path: str | None,
    database: str | None,
    host: str | None,
    dialect: str,
    argv: list[str],
) -> list[InfrastructureIntent]:
    if sql_texts:
        intents = from_sql("; ".join(sql_texts), dialect=dialect, database=database)
    elif file_path is not None:
        from pathlib import Path

        path = Path(file_path)
        if path.exists():
            intents = from_sql(path.read_text(), dialect=dialect, database=database)
        else:
            metadata: dict[str, Any] = {"dialect": dialect}
            if database is not None:
                metadata["database"] = database
            intents = [
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
    else:
        raise ValueError(f"could not find SQL text or a script file in: {argv!r}")

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
    database, host, sql_texts, file_path, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-c", "--command"}, database_flags={"-d", "--dbname"}
    )
    if database is None:
        non_uri_positional = [t for t in positional if "://" not in t]
        if non_uri_positional:
            database = non_uri_positional[0]
    return _build_cli_intents(
        sql_texts=sql_texts, file_path=file_path, database=database, host=host,
        dialect="postgres", argv=argv,
    )


def from_mysql(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``mysql`` invocation, extracting ``-e``/``--execute`` SQL,
    ``-f``... (source file via ``--file``), and the database from
    ``-D``/``--database`` or a trailing positional."""
    if not argv or _basename(argv[0]) != "mysql":
        raise ValueError(f"not a recognizable mysql invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_texts, file_path, positional = _parse_db_cli_tokens(
        tokens,
        command_flags={"-e", "--execute"},
        database_flags={"-D", "--database"},
    )
    if database is None and positional:
        database = positional[0]
    return _build_cli_intents(
        sql_texts=sql_texts, file_path=file_path, database=database, host=host,
        dialect="mysql", argv=argv,
    )


def from_sqlite3(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``sqlite3`` invocation. sqlite3 has no ``-c`` flag; SQL is
    given as a trailing positional (``sqlite3 mydb.db "DROP TABLE users;"``)
    after the database file, or via ``-f``/``--init``."""
    if not argv or _basename(argv[0]) != "sqlite3":
        raise ValueError(f"not a recognizable sqlite3 invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_texts, file_path, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-c", "--command"}, database_flags={"-d", "--dbname"}
    )
    if file_path is None:
        for i, tok in enumerate(tokens):
            if tok in ("-f", "--init"):
                file_path = tokens[i + 1] if i + 1 < len(tokens) else None
                break
    if not sql_texts and file_path is None:
        if len(positional) >= 2:
            database = database or positional[0]
            sql_texts = ["; ".join(positional[1:])]
        elif len(positional) == 1:
            database = database or positional[0]
    return _build_cli_intents(
        sql_texts=sql_texts, file_path=file_path, database=database, host=host,
        dialect="sqlite", argv=argv,
    )


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
]
