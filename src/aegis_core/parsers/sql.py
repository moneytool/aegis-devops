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
_SELECT_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_DESCRIBE_TARGET_RE = re.compile(rf"\A\s*(?:DESCRIBE|DESC)\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_GRANT_TO_RE = re.compile(rf"\bTO\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_REVOKE_FROM_RE = re.compile(rf"\bFROM\s+{_QUALIFIED_NAME_RE}", re.IGNORECASE)
_WHERE_RE = re.compile(r"\bWHERE\b", re.IGNORECASE)
_DROP_COLUMN_RE = re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE)
_FIRST_WORD_RE = re.compile(r"\A\s*(?P<word>[A-Za-z]+)")
_SECOND_WORD_RE = re.compile(r"\A\s*[A-Za-z]+\s+(?P<word>[A-Za-z]+)")


def _resource_and_metadata(qualified: str, kind: str) -> tuple[str, dict[str, Any]]:
    qualified_name, schema = _split_schema(qualified)
    metadata: dict[str, Any] = {}
    if schema:
        metadata["schema"] = schema
    return f"{kind}/{qualified_name}", metadata


def _classify_statement(stmt: str) -> tuple[str, str, dict[str, Any], str, str]:
    """Returns (resource, action, params, statement_class, raw_action)."""
    body = _strip_leading_noise(stmt)

    m = _DROP_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        return resource, "delete", {}, "ddl", f"DROP {kind.upper()}", extra_meta

    m = _TRUNCATE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        return resource, "delete", {"truncate": True}, "ddl", "TRUNCATE", extra_meta

    m = _DELETE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"unbounded": not bool(_WHERE_RE.search(rest))}
        return resource, "delete", params, "dml", "DELETE FROM", extra_meta

    m = _UPDATE_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params = {"unbounded": not bool(_WHERE_RE.search(rest))}
        return resource, "update", params, "dml", "UPDATE", extra_meta

    m = _ALTER_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        rest = body[m.end() :]
        params: dict[str, Any] = {"ddl": True}
        if _DROP_COLUMN_RE.search(rest):
            params["drop_column"] = True
        return resource, "update", params, "ddl", "ALTER TABLE", extra_meta

    m = _CREATE_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        return resource, "create", {"ddl": True}, "ddl", f"CREATE {kind.upper()}", extra_meta

    m = _CREATE_FALLBACK_RE.match(body)
    if m:
        kind = m.group("kind").lower()
        resource, extra_meta = _resource_and_metadata(m.group("name"), kind)
        return resource, "create", {"ddl": True}, "ddl", f"CREATE {kind.upper()}", extra_meta

    m = _INSERT_RE.match(body)
    if m:
        resource, extra_meta = _resource_and_metadata(m.group("name"), "table")
        return resource, "put", {}, "dml", "INSERT INTO", extra_meta

    first = _FIRST_WORD_RE.match(body)
    first_word = first.group("word").upper() if first else ""

    if first_word in ("SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC"):
        if first_word in ("DESCRIBE", "DESC"):
            dm = _DESCRIBE_TARGET_RE.match(body)
            if dm:
                resource, extra_meta = _resource_and_metadata(dm.group("name"), "table")
            else:
                resource, extra_meta = "table/*", {}
        else:
            fm = _SELECT_FROM_RE.search(body)
            if fm:
                resource, extra_meta = _resource_and_metadata(fm.group("name"), "table")
            else:
                resource, extra_meta = "table/*", {}
        return resource, "read", {}, "dql", first_word, extra_meta

    if first_word in ("GRANT", "REVOKE"):
        pattern = _GRANT_TO_RE if first_word == "GRANT" else _REVOKE_FROM_RE
        gm = None
        for gm in pattern.finditer(body):
            pass  # take the *last* match (closest to the grantee clause)
        if gm:
            resource, extra_meta = _resource_and_metadata(gm.group("name"), "role")
        else:
            resource, extra_meta = "role/*", {}
        return resource, "update", {"privilege": True}, "dcl", first_word, extra_meta

    if first_word in ("BEGIN", "COMMIT", "ROLLBACK", "SET", "START"):
        return "session/*", "read", {}, "tcl", first_word, {}

    # Unknown statement: fail-safe -- never treated as a harmless read.
    return "unknown/*", "update", {"unclassified": True}, "dml", first_word or "UNKNOWN", {}


def from_sql(
    sql: str, *, dialect: str = "generic", database: str | None = None
) -> list[InfrastructureIntent]:
    """Parses a batch of ``;``-separated SQL statements into one
    InfrastructureIntent per statement, provider ``"sql"``."""
    intents = []
    for stmt in _split_sql_statements(sql):
        resource, action, params, statement_class, raw_action, extra_meta = _classify_statement(
            stmt
        )
        params = dict(params)
        params["statement_class"] = statement_class
        params["raw_action"] = raw_action

        metadata: dict[str, Any] = {"dialect": dialect}
        if database is not None:
            metadata["database"] = database
        metadata.update(extra_meta)

        intents.append(
            InfrastructureIntent(
                resource=resource, action=action, provider="sql", params=params, metadata=metadata
            )
        )
    return intents


# --- psql / mysql / sqlite3 argv wrappers -------------------------------------


def _parse_db_cli_tokens(
    tokens: list[str], *, command_flags: set[str], database_flags: set[str]
) -> tuple[str | None, str | None, str | None, str | None, list[str]]:
    """Shared argv walk for psql/mysql/sqlite3: returns (database, host,
    sql_text, file_path, positional)."""
    database: str | None = None
    host: str | None = None
    sql_text: str | None = None
    file_path: str | None = None
    positional: list[str] = []

    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in command_flags:
            i += 1
            sql_text = tokens[i]
        elif any(tok.startswith(f"{f}=") for f in command_flags if f.startswith("--")):
            sql_text = tok.split("=", 1)[1]
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

    return database, host, sql_text, file_path, positional


def _build_cli_intents(
    *,
    sql_text: str | None,
    file_path: str | None,
    database: str | None,
    host: str | None,
    dialect: str,
    argv: list[str],
) -> list[InfrastructureIntent]:
    if sql_text is not None:
        intents = from_sql(sql_text, dialect=dialect, database=database)
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
                    params={"raw_action": "file", "unclassified": True, "file": file_path},
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
    database, host, sql_text, file_path, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-c", "--command"}, database_flags={"-d", "--dbname"}
    )
    if database is None:
        non_uri_positional = [t for t in positional if "://" not in t]
        if non_uri_positional:
            database = non_uri_positional[0]
    return _build_cli_intents(
        sql_text=sql_text, file_path=file_path, database=database, host=host,
        dialect="postgres", argv=argv,
    )


def from_mysql(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``mysql`` invocation, extracting ``-e``/``--execute`` SQL,
    ``-f``... (source file via ``--file``), and the database from
    ``-D``/``--database`` or a trailing positional."""
    if not argv or _basename(argv[0]) != "mysql":
        raise ValueError(f"not a recognizable mysql invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_text, file_path, positional = _parse_db_cli_tokens(
        tokens,
        command_flags={"-e", "--execute"},
        database_flags={"-D", "--database"},
    )
    if database is None and positional:
        database = positional[0]
    return _build_cli_intents(
        sql_text=sql_text, file_path=file_path, database=database, host=host,
        dialect="mysql", argv=argv,
    )


def from_sqlite3(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``sqlite3`` invocation. sqlite3 has no ``-c`` flag; SQL is
    given as a trailing positional (``sqlite3 mydb.db "DROP TABLE users;"``)
    after the database file, or via ``-f``/``--init``."""
    if not argv or _basename(argv[0]) != "sqlite3":
        raise ValueError(f"not a recognizable sqlite3 invocation: {argv!r}")
    tokens = argv[1:]
    database, host, sql_text, file_path, positional = _parse_db_cli_tokens(
        tokens, command_flags={"-c", "--command"}, database_flags={"-d", "--dbname"}
    )
    if file_path is None:
        for i, tok in enumerate(tokens):
            if tok in ("-f", "--init"):
                file_path = tokens[i + 1] if i + 1 < len(tokens) else None
                break
    if sql_text is None and file_path is None:
        if len(positional) >= 2:
            database = database or positional[0]
            sql_text = "; ".join(positional[1:])
        elif len(positional) == 1:
            database = database or positional[0]
    return _build_cli_intents(
        sql_text=sql_text, file_path=file_path, database=database, host=host,
        dialect="sqlite", argv=argv,
    )


# --- mongosh -------------------------------------------------------------------

_MONGO_EVAL_RE = re.compile(
    r"db\.(?:(?P<collection>[A-Za-z_]\w*)\.)?(?P<method>[A-Za-z_]+)\s*\((?P<args>.*)\)\s*\Z",
    re.DOTALL,
)


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
    elif method == "drop":
        resource = f"collection/{collection}"
        action = "delete"
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
        m = _MONGO_EVAL_RE.match(call)
        if not m:
            continue
        intents.append(
            _classify_mongo_call(m.group("collection"), m.group("method"), m.group("args"))
        )

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
