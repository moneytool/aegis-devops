"""SQL statement-class gating (PLAN §7.8).

``from_sql`` splits a batch of SQL text into individual statements with a
small hand-written tokenizer (no SQL-parsing library: just enough
quote/comment/dollar-quote awareness to split correctly on ``;``) and
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

* Comments (``--`` and ``/* */``) are stripped, quote-aware, *before*
  classification, so ``DELETE/**/FROM users`` is no longer unclassified.
* ``TRUNCATE``/``DROP TABLE|SCHEMA|DATABASE|INDEX|VIEW``/unwhered ``DELETE``
  all carry ``params["unbounded"] = True`` (DROP/TRUNCATE also
  ``params["ddl"] = True``).
* ``WITH cte AS (DELETE|UPDATE|INSERT ...) SELECT ...`` is classified by the
  *strongest* DML found inside the CTE (delete > update > put > read), with
  ``params["cte"] = True`` and the resource taken from that inner DML.
* ``EXPLAIN <stmt>`` reads (``params["explain"] = True``); ``EXPLAIN ANALYZE
  <stmt>`` is classified as ``<stmt>`` itself (Postgres executes it), plus
  ``params["explain_analyze"] = True``.
* ``DO $$ ... $$``, ``CALL proc(...)``, ``EXECUTE ...``, ``PERFORM ...`` are
  opaque write operations (``update``, ``params["opaque"] = True``,
  resource ``procedure/<name>`` when parseable else ``block/*``) --
  fail-safe, never treated as reads.
* MySQL multi-table ``DELETE t1, t2 FROM t1 JOIN t2 ...`` and ``DELETE FROM
  t1 USING t2`` both resolve to a delete on the first target table.
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

* Every table a statement reads becomes its own ``read`` intent (deduplicated,
  in order): ``FROM`` and every ``JOIN`` target, comma joins, subqueries in
  ``WHERE``/``FROM``/the select list, ``UNION``/``INTERSECT``/``EXCEPT``
  branches, ``TABLE t``, and ``WITH`` bodies. A CTE's name is not a table
  (except inside its own non-recursive body), a function in ``FROM``
  (``generate_series(...)``) is not a table, and keywords inside string
  literals or quoted identifiers are never read as SQL. A write
  (``INSERT ... SELECT``, ``UPDATE ... FROM``, ``DELETE ... USING``, ``CREATE
  TABLE|VIEW ... AS SELECT``, a ``WITH`` holding DML) keeps its own intent
  first and adds a read of every *other* table it reads. ``EXPLAIN <stmt>``
  reads every table ``<stmt>`` names; ``EXPLAIN (ANALYZE ...) <stmt>`` is
  classified as ``<stmt>``, like ``EXPLAIN ANALYZE``.
* ``SELECT ... INTO t`` is a ``create`` of ``table/t`` (``params["ddl"]``,
  ``params["select_into"]``), like ``CREATE TABLE t AS SELECT``, plus its
  reads. MySQL ``SELECT ... INTO OUTFILE|DUMPFILE`` writes a file: ``update``
  of ``file/<path>`` with ``params["opaque"] = params["unclassified"] = True``.
  ``SELECT ... INTO @var`` only sets a variable and stays a read.
* ``SET [SESSION|LOCAL] ROLE``, ``SET SESSION AUTHORIZATION``, ``SET role =
  ...``, ``RESET ROLE|SESSION AUTHORIZATION``, MySQL ``SET DEFAULT ROLE`` and
  ``SET PASSWORD``, and ``set_config('role', ...)`` change identity: ``update``
  of ``role/<name>`` (``role/*`` for NONE/DEFAULT/unnamed) with
  ``params["privilege"] = True``, as GRANT/REVOKE. Other ``SET``s stay
  ``session/*`` reads.
* A locking read (``FOR UPDATE``, ``FOR NO KEY UPDATE``, ``FOR SHARE``, ``FOR
  KEY SHARE``, MySQL ``LOCK IN SHARE MODE``) stays a ``read`` -- it changes no
  data -- but each of its reads carries ``params["locking"] = True``,
  ``params["lock_strength"]`` (the strongest lock taken) and ``nowait`` /
  ``skip_locked`` when given, so a rule can match it with ``scope: {locking:
  true}``.

See the ``evasion`` list at the bottom of this module for the full
enumeration (imported by the adversarial test suite).
"""

import re
from typing import Any

from aegis_core.intent import InfrastructureIntent
from aegis_core.parser import _basename, _coerce  # noqa: F401  (re-exported convention)

# --- statement splitting -----------------------------------------------------

_DOLLAR_TAG_RE = re.compile(r"\$[A-Za-z_]*\$")


def _split_sql_statements(sql: str) -> list[str]:
    """Splits ``sql`` on ``;`` outside single/double-quoted strings, ``--``
    line comments, ``/* */`` block comments, and postgres ``$$``/``$tag$``
    dollar-quoted bodies."""
    statements: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    in_single = in_double = in_line_comment = in_block_comment = False
    dollar_tag: str | None = None

    while i < n:
        ch = sql[i]

        if in_line_comment:
            buf.append(ch)
            i += 1
            if ch == "\n":
                in_line_comment = False
            continue

        if in_block_comment:
            if ch == "*" and sql[i + 1 : i + 2] == "/":
                buf.append("*/")
                i += 2
                in_block_comment = False
            else:
                buf.append(ch)
                i += 1
            continue

        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
            else:
                buf.append(ch)
                i += 1
            continue

        if in_single:
            if ch == "'" and sql[i + 1 : i + 2] == "'":
                buf.append("''")
                i += 2
            elif ch == "'":
                buf.append(ch)
                i += 1
                in_single = False
            else:
                buf.append(ch)
                i += 1
            continue

        if in_double:
            if ch == '"' and sql[i + 1 : i + 2] == '"':
                buf.append('""')
                i += 2
            elif ch == '"':
                buf.append(ch)
                i += 1
                in_double = False
            else:
                buf.append(ch)
                i += 1
            continue

        # Not inside any special region.
        if ch == "-" and sql[i + 1 : i + 2] == "-":
            in_line_comment = True
            buf.append("--")
            i += 2
            continue
        if ch == "/" and sql[i + 1 : i + 2] == "*":
            in_block_comment = True
            buf.append("/*")
            i += 2
            continue
        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            buf.append(ch)
            i += 1
            continue
        if ch == "$":
            m = _DOLLAR_TAG_RE.match(sql, i)
            if m:
                dollar_tag = m.group(0)
                buf.append(dollar_tag)
                i += len(dollar_tag)
                continue
        if ch == ";":
            statements.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf)
    if tail.strip():
        statements.append(tail)

    return [s.strip() for s in statements if s.strip()]


_LEADING_NOISE_RE = re.compile(r"\A(?:\s+|--[^\n]*(?:\n|\Z)|/\*.*?\*/)+", re.DOTALL)


def _strip_leading_noise(stmt: str) -> str:
    return _LEADING_NOISE_RE.sub("", stmt)


def _strip_comments(stmt: str) -> str:
    """Removes ``--`` line comments and ``/* */`` block comments from
    ``stmt`` (quote-aware: never touches ``--``/``/*`` inside a quoted
    string), replacing each one with a single space so keywords a comment
    was wedged between (``DELETE/**/FROM``) still classify correctly.
    Applied before classification so comment-obfuscated keywords can't
    dodge it (REVIEW-4 T1.4)."""
    out: list[str] = []
    i, n = 0, len(stmt)
    in_single = in_double = False
    while i < n:
        ch = stmt[i]
        if in_single:
            out.append(ch)
            if ch == "'" and stmt[i + 1 : i + 2] == "'":
                out.append(stmt[i + 1])
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            out.append(ch)
            if ch == '"' and stmt[i + 1 : i + 2] == '"':
                out.append(stmt[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "-" and stmt[i + 1 : i + 2] == "-":
            j = stmt.find("\n", i)
            out.append(" ")
            i = n if j == -1 else j
            continue
        if ch == "/" and stmt[i + 1 : i + 2] == "*":
            j = stmt.find("*/", i + 2)
            out.append(" ")
            i = n if j == -1 else j + 2
            continue
        out.append(ch)
        i += 1
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
_TRUNCATE_RE = re.compile(
    rf"\A\s*TRUNCATE\s+(?:TABLE\s+)?{_QUALIFIED_NAME_RE}", re.IGNORECASE
)
_DELETE_RE = re.compile(rf"\A\s*DELETE\s+FROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_UPDATE_RE = re.compile(rf"\A\s*UPDATE\s+{_QUALIFIED_NAME_RE}\s+SET\b", re.IGNORECASE)
_ALTER_RE = re.compile(rf"\A\s*ALTER\s+TABLE\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_CREATE_RE = re.compile(
    r"\A\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?(?:UNIQUE\s+)?"
    r"(?P<kind>TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER)"
    rf"\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_CREATE_FALLBACK_RE = re.compile(
    rf"\A\s*CREATE\s+(?P<kind>[A-Za-z_]+)\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED_NAME_RE}",
    re.IGNORECASE,
)
_INSERT_RE = re.compile(rf"\A\s*INSERT\s+INTO\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_SHOW_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_DESCRIBE_TARGET_RE = re.compile(rf"\A\s*(?:DESCRIBE|DESC)\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_GRANT_TO_RE = re.compile(rf"\bTO\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_REVOKE_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_WHERE_RE = re.compile(r"\bWHERE\b", re.IGNORECASE)
_DROP_COLUMN_RE = re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE)
_CASCADE_RE = re.compile(r"\bCASCADE\b", re.IGNORECASE)
_FIRST_WORD_RE = re.compile(r"\A\s*(?P<word>[A-Za-z]+)")
_SECOND_WORD_RE = re.compile(r"\A\s*[A-Za-z]+\s+(?P<word>[A-Za-z]+)")

# MySQL multi-table DELETE where the target(s) come *before* FROM:
# ``DELETE t1, t2 FROM t1 JOIN t2 ...``. ``DELETE FROM t1 USING t2`` already
# matches ``_DELETE_RE`` above (its first token after DELETE is FROM), so
# this only needs to cover the "table list before FROM" form.
_DELETE_MULTI_TARGET_RE = re.compile(
    rf"\A\s*DELETE\s+{_QUALIFIED_NAME_RE}(?:\s*,\s*{_NAME_RE})*\s+FROM\b", re.IGNORECASE
)

# Non-anchored scan versions of the DML matchers, used to find the
# strongest statement inside a CTE body (``WITH x AS (DELETE ...) SELECT``)
# and inside ``EXPLAIN ANALYZE <stmt>``.
_DELETE_SCAN_RE = re.compile(rf"\bDELETE\s+FROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_UPDATE_SCAN_RE = re.compile(rf"\bUPDATE\s+{_QUALIFIED_NAME_RE}\s+SET\b", re.IGNORECASE)
_INSERT_SCAN_RE = re.compile(rf"\bINSERT\s+INTO\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)

_EXPLAIN_RE = re.compile(
    r"\A\s*EXPLAIN\s*(?:\((?P<opts>[^()]*)\)\s*)?(?:(?P<analyze>ANALY[SZ]E)\s+)?"
    r"(?:VERBOSE\s+)?(?:FORMAT\s*=\s*\w+\s+)?(?P<rest>.*)\Z",
    re.IGNORECASE | re.DOTALL,
)
# ``EXPLAIN (ANALYZE[, ...])`` runs the statement too, unless ANALYZE is off.
_EXPLAIN_OPTS_ANALYZE_RE = re.compile(
    r"\bANALY[SZ]E\b(?!\s+(?:FALSE|OFF|0)\b)", re.IGNORECASE
)

_CALL_RE = re.compile(rf"\A\s*CALL\s+{_QUALIFIED_NAME_RE}\s*\(", re.IGNORECASE)
_EXECUTE_PROC_RE = re.compile(
    rf"\A\s*(?:EXECUTE|PERFORM)\s+{_QUALIFIED_NAME_RE}\s*\(", re.IGNORECASE
)


_SET_ROLE_RE = re.compile(
    r"\A\s*SET\s+(?:(?:SESSION|LOCAL)\s+)?"
    r"(?P<kw>ROLE|SESSION\s+AUTHORIZATION|SESSION_AUTHORIZATION)\b"
    r"\s*(?:=\s*|TO\b\s*)?(?P<rest>.*)\Z",
    re.IGNORECASE | re.DOTALL,
)
_RESET_ROLE_RE = re.compile(
    r"\A\s*RESET\s+(?P<kw>ROLE|SESSION\s+AUTHORIZATION|SESSION_AUTHORIZATION)\b", re.IGNORECASE
)
_SET_DEFAULT_ROLE_RE = re.compile(r"\A\s*SET\s+DEFAULT\s+ROLE\b", re.IGNORECASE)
_SET_PASSWORD_RE = re.compile(
    r"\A\s*SET\s+PASSWORD\b(?:\s+FOR\s+(?P<rest>.*))?", re.IGNORECASE | re.DOTALL
)


def _resource_and_metadata(qualified: str, kind: str) -> tuple[str, dict[str, Any]]:
    qualified_name, schema = _split_schema(qualified)
    metadata: dict[str, Any] = {}
    if schema:
        metadata["schema"] = schema
    return f"{kind}/{qualified_name}", metadata


_Classification = tuple[str, str, dict[str, Any], str, str, dict[str, Any]]


# --- table references inside a statement (#58) -----------------------------------
#
# A small token-level scan of one (comment-stripped) statement that finds every
# table it reads: FROM and JOIN targets, comma joins, subqueries anywhere,
# UNION/INTERSECT/EXCEPT branches, CTE bodies and ``TABLE t``. It also finds a
# top-level ``SELECT ... INTO`` target, a row-locking clause (``FOR UPDATE`` ...)
# and ``set_config('role', ...)`` calls. String literals and quoted identifiers
# are single tokens, so a keyword inside a string is never misread.

_TOKEN_RE = re.compile(
    r"(?P<str>(?:[EeNnBbXx]|[Uu]&)?'(?:[^']|'')*(?:'|\Z))"
    r"|(?P<qident>\"(?:[^\"]|\"\")*(?:\"|\Z)|`(?:[^`]|``)*(?:`|\Z))"
    r"|(?P<var>@@?(?:[\w$.]+|'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`))"
    r"|(?P<param>\$\d+)"
    r"|(?P<num>\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+)"
    r"|(?P<word>[^\W\d][\w$]*)"
    r"|(?P<punct>\S)"
)

_Tok = tuple[str, str]


def _sql_tokens(text: str) -> list[_Tok]:
    """(kind, value) tokens; kinds: ``word``, ``qident`` (quotes removed),
    ``str`` (contents only), ``var`` (``@x``), ``param``, ``num``, ``punct``.
    Dollar-quoted bodies (``$$...$$``, ``$tag$...$tag$``) are ``str``."""
    toks: list[_Tok] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        if text[i] == "$":
            dm = _DOLLAR_TAG_RE.match(text, i)
            if dm:
                tag = dm.group(0)
                end = text.find(tag, dm.end())
                body_end = n if end == -1 else end
                toks.append(("str", text[dm.end() : body_end]))
                i = n if end == -1 else end + len(tag)
                continue
        m = _TOKEN_RE.match(text, i)
        if m is None:  # pragma: no cover - the punct alternative matches any non-space
            i += 1
            continue
        kind = m.lastgroup or "punct"
        raw = m.group(0)
        if kind == "str":
            body = raw[raw.index("'") + 1 :]
            if body.endswith("'"):
                body = body[:-1]
            toks.append(("str", body.replace("''", "'")))
        elif kind == "qident":
            q = raw[0]
            body = raw[1:-1] if len(raw) > 1 and raw.endswith(q) else raw[1:]
            toks.append(("qident", body.replace(q + q, q)))
        else:
            toks.append((kind, raw))
        i = m.end()
    return toks


# Words that end a FROM list at their nesting depth (a later ``,`` is then no
# longer a comma join).
_FROM_LIST_END = frozenset({
    "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "WINDOW",
    "UNION", "INTERSECT", "EXCEPT", "MINUS", "FOR", "INTO", "RETURNING", "SET",
    "VALUES", "SELECT", "QUALIFY", "LOCK", "PROCEDURE",
})
_SUBQUERY_START = frozenset({"SELECT", "WITH", "VALUES", "TABLE"})
_SET_OP_BEFORE_TABLE = frozenset({"UNION", "INTERSECT", "EXCEPT", "MINUS", "ALL", "DISTINCT", "AS"})
_NOT_A_TABLE = frozenset({"DUAL", "SELECT", "WITH", "VALUES"})
_LOCK_RANK = {"key share": 0, "share": 1, "no key update": 2, "update": 3}


class _Scan:
    __slots__ = ("tables", "into", "lock", "nowait", "skip_locked", "roles")

    def __init__(self) -> None:
        self.tables: list[list[str]] = []
        # None, or (kind, value): ("table", parts) / ("file", path|None) /
        # ("var", None) / ("unknown", None).
        self.into: tuple[str, Any] | None = None
        self.lock: str | None = None
        self.nowait = False
        self.skip_locked = False
        self.roles: list[str | None] = []  # set_config('role'|'session_authorization', x)


def _is_word(tok: _Tok | None, *words: str) -> bool:
    return tok is not None and tok[0] == "word" and tok[1].upper() in words


def _norm_ident(tok: _Tok) -> str:
    # Unquoted identifiers are case-insensitive; quoted ones are exact.
    return tok[1].lower() if tok[0] == "word" else tok[1]


def _scan_statement(body: str, first_word: str) -> _Scan:
    toks = _sql_tokens(body)
    n = len(toks)
    scan = _Scan()

    def tok(j: int) -> _Tok | None:
        return toks[j] if 0 <= j < n else None

    # Paren/bracket depth of every token (a bracket token gets its outer depth)
    # and the matching close of every open.
    depth = [0] * n
    close_of: dict[int, int] = {}
    stack: list[int] = []
    d = 0
    for j, (kind, val) in enumerate(toks):
        if kind == "punct" and val in "([":
            depth[j] = d
            stack.append(j)
            d += 1
        elif kind == "punct" and val in ")]":
            if stack:
                close_of[stack.pop()] = j
            d = max(d - 1, 0)
            depth[j] = d
        else:
            depth[j] = d

    # CTE names: (normalised name, visible from token index, visible until).
    # A non-recursive CTE's name is visible after its own body, a recursive
    # one's inside it too; both until the group holding the WITH closes.
    ctes: list[tuple[str, int, int]] = []
    for i in range(n):
        if not _is_word(toks[i], "WITH"):
            continue
        d0 = depth[i]
        scope_end = next(
            (j for j in range(i + 1, n) if toks[j] == ("punct", ")") and depth[j] < d0), n
        )
        j = i + 1
        recursive = _is_word(tok(j), "RECURSIVE")
        if recursive:
            j += 1
        while j < n and toks[j][0] in ("word", "qident"):
            name = _norm_ident(toks[j])
            j += 1
            if tok(j) == ("punct", "(") and j in close_of:  # column list
                j = close_of[j] + 1
            if not _is_word(tok(j), "AS"):
                break
            j += 1
            if _is_word(tok(j), "NOT"):
                j += 1
            if _is_word(tok(j), "MATERIALIZED"):
                j += 1
            if tok(j) != ("punct", "(") or j not in close_of:
                break
            start, end = j, close_of[j]
            ctes.append((name, start if recursive else end, scope_end))
            j = end + 1
            if tok(j) != ("punct", ","):
                break
            j += 1

    def is_cte(name: str, pos: int) -> bool:
        return any(c == name and lo < pos < hi for c, lo, hi in ctes)

    seen: set[tuple[str, ...]] = set()

    def name_parts(j: int) -> tuple[list[_Tok], int]:
        parts = [toks[j]]
        m = j + 1
        while tok(m) == ("punct", ".") and (tok(m + 1) or ("", ""))[0] in ("word", "qident"):
            parts.append(toks[m + 1])
            m += 2
        return parts, m

    from_list: dict[int, bool] = {}

    def parse_ref(j: int) -> None:
        while _is_word(tok(j), "ONLY", "LATERAL"):
            j += 1
        t = tok(j)
        if t is None:
            return
        if t == ("punct", "("):
            # A parenthesised join ``(a JOIN b ON ...)``; a subquery's own
            # FROM is picked up by the main loop.
            nxt = tok(j + 1)
            if nxt is not None and not _is_word(nxt, *_SUBQUERY_START):
                from_list[depth[j] + 1] = True
                parse_ref(j + 1)
            return
        if t[0] not in ("word", "qident"):
            return
        if t[0] == "word" and t[1].upper() in _NOT_A_TABLE:
            return
        parts, m = name_parts(j)
        if tok(m) == ("punct", "("):
            return  # a function in FROM (generate_series(...), unnest(...))
        if len(parts) == 1 and is_cte(_norm_ident(t), j):
            return
        key = tuple(_norm_ident(p) for p in parts)
        if key not in seen:
            seen.add(key)
            scan.tables.append([p[1] for p in parts])

    query_at: dict[int, bool] = {}
    last_kw: dict[int, str] = {}
    delete_using_done = False

    for i, t in enumerate(toks):
        d = depth[i]
        kind, val = t
        if kind == "punct":
            if val in "([":
                query_at[d + 1] = False
                from_list[d + 1] = False
                last_kw.pop(d + 1, None)
            elif val == "," and from_list.get(d):
                parse_ref(i + 1)
            continue
        if kind != "word":
            continue
        u = val.upper()
        prev = tok(i - 1)

        if u in ("SELECT", "INSERT", "UPDATE", "DELETE", "MERGE"):
            if u in ("UPDATE", "DELETE") and _is_word(prev, "FOR", "KEY", "DO", "ON"):
                pass  # FOR [NO KEY] UPDATE, ON CONFLICT DO UPDATE, ON DELETE CASCADE
            else:
                query_at[d] = True
                last_kw[d] = u
            if u == "SELECT":
                from_list[d] = False
            continue  # a FOR [NO KEY] UPDATE clause is read at its FOR

        if u == "FROM":
            if query_at.get(d) and not _is_word(prev, "DELETE", "DISTINCT"):
                from_list[d] = True
                parse_ref(i + 1)
            continue
        if u in ("JOIN", "STRAIGHT_JOIN"):
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "USING" and first_word == "DELETE" and d == 0 and not delete_using_done:
            delete_using_done = True
            from_list[d] = True
            parse_ref(i + 1)
            continue
        if u == "TABLE" and (
            _is_word(prev, *_SET_OP_BEFORE_TABLE) or prev == ("punct", "(")
        ):
            parse_ref(i + 1)
            continue

        if u in _FROM_LIST_END:
            from_list[d] = False

        if (
            u == "INTO"
            and d == 0
            and scan.into is None
            and first_word in ("SELECT", "WITH")
            and last_kw.get(0) == "SELECT"
        ):
            j = i + 1
            while _is_word(tok(j), "TEMP", "TEMPORARY", "UNLOGGED", "TABLE"):
                j += 1
            target = tok(j)
            if _is_word(target, "OUTFILE", "DUMPFILE"):
                path = tok(j + 1)
                scan.into = ("file", path[1] if path and path[0] == "str" else None)
            elif target is not None and target[0] == "var":
                scan.into = ("var", None)
            elif target is not None and target[0] in ("word", "qident"):
                parts, _m = name_parts(j)
                scan.into = ("table", [p[1] for p in parts])
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

        if val.lower() == "set_config" and tok(i + 1) == ("punct", "("):
            setting = tok(i + 2)
            if setting is not None and setting[0] == "str" and setting[1].strip().lower() in (
                "role", "session_authorization"
            ):
                value = tok(i + 4) if tok(i + 3) == ("punct", ",") else None
                scan.roles.append(value[1] if value and value[0] == "str" else None)

    return scan


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


def _role_results(scan: _Scan) -> list[_Classification]:
    return [
        (f"role/{r}" if r else "role/*", "update", {"privilege": True}, "dcl",
         "set_config(role)", {})
        for r in scan.roles
    ]


def _read_results(
    scan: _Scan, *, raw_action: str, exclude: set[str]
) -> list[_Classification]:
    out: list[_Classification] = []
    lock = _lock_params(scan)
    for parts in scan.tables:
        resource, meta = _table_resource(parts)
        if resource in exclude:
            continue
        exclude.add(resource)
        out.append((resource, "read", dict(lock), "dql", raw_action, meta))
    return out


def _with_reads(
    primary: list[_Classification], body: str, first_word: str
) -> list[_Classification]:
    """``primary`` (a write's own intent) plus a read of every other table the
    statement reads (``INSERT ... SELECT``, ``UPDATE ... FROM``, ``DELETE ...
    USING``, subqueries, a ``WITH`` clause's bodies)."""
    scan = _scan_statement(body, first_word)
    exclude = {r for r, *_ in primary}
    return [
        *primary,
        *_role_results(scan),
        *_read_results(scan, raw_action="SELECT", exclude=exclude),
    ]


def _classify_query(body: str, first_word: str) -> list[_Classification]:
    """A ``SELECT`` (or a ``WITH`` with no DML in it): a read of every table it
    reads, plus a ``create`` for ``SELECT ... INTO t`` or an opaque write for
    MySQL's ``SELECT ... INTO OUTFILE|DUMPFILE``."""
    scan = _scan_statement(body, first_word)
    results: list[_Classification] = []
    exclude: set[str] = set()
    if scan.into is not None:
        into_kind, value = scan.into
        if into_kind == "table":
            resource, meta = _table_resource(value)
            exclude.add(resource)
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
        # ("var", None): MySQL ``INTO @x`` only sets a session variable.
    results.extend(_role_results(scan))
    reads = _read_results(scan, raw_action=first_word, exclude=exclude)
    if not reads and (scan.into is None or scan.into[0] == "var"):
        reads = [("table/*", "read", _lock_params(scan), "dql", first_word, {})]
    return [*results, *reads]


def _role_names(rest: str) -> list[str | None]:
    """Role names in ``SET ROLE a, 'b'@'%'``; NONE/DEFAULT/ALL become None."""
    names: list[str | None] = []
    expect = True
    for kind, val in _sql_tokens(rest):
        if (kind, val) == ("punct", ","):
            expect = True
            continue
        if not expect:
            continue
        expect = False
        if kind == "word" and val.upper() in ("NONE", "DEFAULT", "ALL"):
            names.append(None)
        elif kind in ("word", "qident", "str"):
            names.append(val)
        else:
            names.append(None)
    return names or [None]


def _classify_identity_change(body: str) -> list[_Classification] | None:
    """``SET ROLE``, ``SET SESSION AUTHORIZATION``, ``RESET ROLE``, MySQL ``SET
    DEFAULT ROLE`` and ``SET PASSWORD``: privilege changes, not session reads."""
    m = _SET_ROLE_RE.match(body)
    if m:
        kw = "ROLE" if m.group("kw").upper() == "ROLE" else "SESSION AUTHORIZATION"
        results: list[_Classification] = []
        for name in dict.fromkeys(_role_names(m.group("rest"))):
            results.append(
                (f"role/{name}" if name else "role/*", "update", {"privilege": True}, "dcl",
                 f"SET {kw}", {})
            )
        return results
    m = _RESET_ROLE_RE.match(body)
    if m:
        kw = "ROLE" if m.group("kw").upper() == "ROLE" else "SESSION AUTHORIZATION"
        return [("role/*", "update", {"privilege": True}, "dcl", f"RESET {kw}", {})]
    if _SET_DEFAULT_ROLE_RE.match(body):
        gm = None
        for gm in _GRANT_TO_RE.finditer(body):
            pass
        resource = f"role/{_split_schema(gm.group('name'))[0]}" if gm else "role/*"
        return [(resource, "update", {"privilege": True}, "dcl", "SET DEFAULT ROLE", {})]
    m = _SET_PASSWORD_RE.match(body)
    if m:
        names = _role_names(m.group("rest")) if m.group("rest") else [None]
        name = names[0]
        return [(f"role/{name}" if name else "role/*", "update", {"privilege": True}, "dcl",
                 "SET PASSWORD", {})]
    return None


def _classify_statement(stmt: str) -> list[_Classification]:
    """Returns a list of (resource, action, params, statement_class,
    raw_action, extra_metadata) -- normally one entry, but two for
    ``DROP SCHEMA``/``DROP DATABASE`` (see module docstring)."""
    body = _strip_leading_noise(_strip_comments(stmt))

    first = _FIRST_WORD_RE.match(body)
    first_word = first.group("word").upper() if first else ""

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

    m = _TRUNCATE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        params = {"truncate": True, "unbounded": True, "ddl": True}
        return [(resource, "delete", params, "ddl", "TRUNCATE", extra_meta)]

    m = _DELETE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"unbounded": not bool(_WHERE_RE.search(rest))}
        return _with_reads(
            [(resource, "delete", params, "dml", "DELETE FROM", extra_meta)], body, first_word
        )

    if first_word == "DELETE":
        m = _DELETE_MULTI_TARGET_RE.match(body)
        if m:
            resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
            rest = body[m.end() :]
            params = {"unbounded": not bool(_WHERE_RE.search(rest))}
            return _with_reads(
                [(resource, "delete", params, "dml", "DELETE", extra_meta)], body, first_word
            )

    m = _UPDATE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"unbounded": not bool(_WHERE_RE.search(rest))}
        return _with_reads(
            [(resource, "update", params, "dml", "UPDATE", extra_meta)], body, first_word
        )

    m = _ALTER_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"ddl": True}
        if _DROP_COLUMN_RE.search(rest):
            params["drop_column"] = True
        return [(resource, "update", params, "ddl", "ALTER TABLE", extra_meta)]

    m = _CREATE_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        create = (resource, "create", {"ddl": True}, "ddl", f"CREATE {kind.upper()}", extra_meta)
        return _with_reads([create], body, first_word)  # CREATE TABLE|VIEW ... AS SELECT

    m = _CREATE_FALLBACK_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        create = (resource, "create", {"ddl": True}, "ddl", f"CREATE {kind.upper()}", extra_meta)
        return _with_reads([create], body, first_word)

    m = _INSERT_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        insert = (resource, "put", {}, "dml", "INSERT INTO", extra_meta)
        return _with_reads([insert], body, first_word)

    if first_word == "WITH":
        dm = _DELETE_SCAN_RE.search(body)
        if dm:
            resource, extra_meta = _resource_and_metadata(dm.group("name"), "table")
            rest = body[dm.end() :]
            params = {"unbounded": not bool(_WHERE_RE.search(rest)), "cte": True}
            return _with_reads(
                [(resource, "delete", params, "dml", "DELETE FROM", extra_meta)], body, first_word
            )
        um = _UPDATE_SCAN_RE.search(body)
        if um:
            resource, extra_meta = _resource_and_metadata(um.group("name"), "table")
            rest = body[um.end() :]
            params = {"unbounded": not bool(_WHERE_RE.search(rest)), "cte": True}
            return _with_reads(
                [(resource, "update", params, "dml", "UPDATE", extra_meta)], body, first_word
            )
        im = _INSERT_SCAN_RE.search(body)
        if im:
            resource, extra_meta = _resource_and_metadata(im.group("name"), "table")
            insert = (resource, "put", {"cte": True}, "dml", "INSERT INTO", extra_meta)
            return _with_reads([insert], body, first_word)
        return _classify_query(body, first_word)

    if first_word == "EXPLAIN":
        em = _EXPLAIN_RE.match(body)
        rest = em.group("rest") if em else ""
        if em and (
            em.group("analyze") or _EXPLAIN_OPTS_ANALYZE_RE.search(em.group("opts") or "")
        ):
            sub_results = _classify_statement(rest)
            annotated: list[_Classification] = []
            for r, a, p, sc, ra, extra in sub_results:
                p = dict(p)
                p["explain_analyze"] = True
                annotated.append((r, a, p, sc, ra, extra))
            return annotated
        # Plain EXPLAIN plans the statement without running it: a read of
        # every table the statement names (its target included).
        explained: list[_Classification] = []
        named: set[str] = set()
        for r, _a, _p, _sc, _ra, extra in _classify_statement(rest):
            if r.startswith("table/") and r != "table/*" and r not in named:
                named.add(r)
                explained.append((r, "read", {"explain": True}, "dql", "EXPLAIN", extra))
        return explained or [("table/*", "read", {"explain": True}, "dql", "EXPLAIN", {})]

    if first_word == "SELECT":
        return _classify_query(body, first_word)

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
        identity = _classify_identity_change(body)
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
    InfrastructureIntents (one per statement, or two for a ``DROP
    SCHEMA``/``DROP DATABASE`` -- see module docstring), provider
    ``"sql"``."""
    intents = []
    for stmt in _split_sql_statements(sql):
        for resource, action, params, statement_class, raw_action, extra_meta in (
            _classify_statement(stmt)
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
]
