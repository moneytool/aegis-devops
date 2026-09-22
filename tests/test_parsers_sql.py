from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis_core.interceptor import AegisInterceptor
from aegis_core.parsers.sql import (
    from_migration_argv,
    from_mongosh,
    from_mysql,
    from_psql,
    from_sql,
    from_sqlite3,
)
from aegis_core.store import ConstraintStore

EXAMPLE_STORE = "data/constraints.example.yaml"
NOW = datetime(2026, 4, 2, 12, 0, 0, tzinfo=UTC)


def _authority_map():
    return {
        "admin": {"scaling", "deletion", "configuration"},
        "sre_lead": {"scaling", "configuration"},
        "developer": {"configuration"},
    }


# --- statement splitting -----------------------------------------------------


def test_split_handles_line_comment_containing_semicolon():
    intents = from_sql("SELECT 1; -- comment; with a fake terminator\nSELECT 2;")
    assert len(intents) == 2
    assert all(i.action == "read" for i in intents)


def test_split_handles_block_comment_containing_semicolon():
    intents = from_sql("SELECT 1; /* comment ; still comment */ SELECT 2;")
    assert len(intents) == 2


def test_split_ignores_semicolon_inside_single_quoted_string():
    intents = from_sql("INSERT INTO t VALUES ('a;b');")
    assert len(intents) == 1
    assert intents[0].action == "put"


def test_split_handles_escaped_single_quote():
    intents = from_sql("INSERT INTO t VALUES ('it''s; fine');")
    assert len(intents) == 1


def test_split_ignores_semicolon_inside_double_quoted_identifier():
    intents = from_sql('SELECT * FROM "weird;table";')
    assert len(intents) == 1


def test_split_handles_dollar_quoted_body():
    sql = "CREATE FUNCTION f() RETURNS void AS $$ BEGIN DELETE FROM x; END; $$ LANGUAGE plpgsql;"
    intents = from_sql(sql)
    assert len(intents) == 1
    assert intents[0].action == "create"


def test_split_handles_tagged_dollar_quote():
    sql = "CREATE FUNCTION f() AS $body$ SELECT 1; $body$ LANGUAGE sql;"
    intents = from_sql(sql)
    assert len(intents) == 1


def test_split_trailing_statement_without_semicolon():
    intents = from_sql("SELECT 1; SELECT 2")
    assert len(intents) == 2


def test_split_skips_blank_statements():
    intents = from_sql("SELECT 1;;;SELECT 2;")
    assert len(intents) == 2


# --- classification: DDL ------------------------------------------------------


@pytest.mark.parametrize(
    "kind,sql,resource",
    [
        ("table", "DROP TABLE users;", "table/users"),
        ("database", "DROP DATABASE prod;", "database/prod"),
        ("schema", "DROP SCHEMA analytics;", "schema/analytics"),
        ("index", "DROP INDEX idx_users_email;", "index/idx_users_email"),
        ("view", "DROP VIEW active_users;", "view/active_users"),
    ],
)
def test_drop_statements_classify_as_delete(kind, sql, resource):
    (intent,) = from_sql(sql)
    assert intent.action == "delete"
    assert intent.resource == resource
    assert intent.params["statement_class"] == "ddl"
    assert intent.provider == "sql"


def test_drop_table_if_exists():
    (intent,) = from_sql("DROP TABLE IF EXISTS users;")
    assert intent.resource == "table/users"
    assert intent.action == "delete"


def test_truncate_sets_truncate_param():
    (intent,) = from_sql("TRUNCATE TABLE orders;")
    assert intent.action == "delete"
    assert intent.resource == "table/orders"
    assert intent.params["truncate"] is True
    assert intent.params["statement_class"] == "ddl"


def test_truncate_without_table_keyword():
    (intent,) = from_sql("TRUNCATE orders;")
    assert intent.resource == "table/orders"


def test_alter_table_marks_ddl():
    (intent,) = from_sql("ALTER TABLE users ADD COLUMN age int;")
    assert intent.action == "update"
    assert intent.params["ddl"] is True
    assert "drop_column" not in intent.params


def test_alter_table_drop_column_flagged():
    (intent,) = from_sql("ALTER TABLE users DROP COLUMN ssn;")
    assert intent.params["ddl"] is True
    assert intent.params["drop_column"] is True


def test_create_table():
    (intent,) = from_sql("CREATE TABLE t (id INT);")
    assert intent.action == "create"
    assert intent.resource == "table/t"
    assert intent.params["ddl"] is True
    assert intent.params["statement_class"] == "ddl"


def test_create_index_on_table():
    (intent,) = from_sql("CREATE INDEX idx_email ON users(email);")
    assert intent.action == "create"
    assert intent.resource == "index/idx_email"


def test_create_table_if_not_exists():
    (intent,) = from_sql("CREATE TABLE IF NOT EXISTS t (id INT);")
    assert intent.resource == "table/t"


def test_create_unrecognized_kind_falls_back():
    (intent,) = from_sql("CREATE ROLE readonly;")
    assert intent.action == "create"
    assert intent.resource == "role/readonly"
    assert intent.params["ddl"] is True


# --- classification: DML ------------------------------------------------------


def test_delete_from_without_where_is_unbounded():
    (intent,) = from_sql("DELETE FROM users;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert intent.params["unbounded"] is True
    assert intent.params["statement_class"] == "dml"


def test_delete_from_with_where_is_not_unbounded():
    (intent,) = from_sql("DELETE FROM users WHERE id = 1;")
    assert intent.params["unbounded"] is False


def test_update_without_where_is_unbounded():
    (intent,) = from_sql("UPDATE users SET active = false;")
    assert intent.action == "update"
    assert intent.params["unbounded"] is True


def test_update_with_where_is_not_unbounded():
    (intent,) = from_sql("UPDATE users SET active = false WHERE id = 1;")
    assert intent.params["unbounded"] is False


def test_insert_into_classifies_as_put():
    (intent,) = from_sql("INSERT INTO users (id) VALUES (1);")
    assert intent.action == "put"
    assert intent.resource == "table/users"
    assert intent.params["statement_class"] == "dml"


# --- classification: DQL ------------------------------------------------------


def test_select_classifies_as_read_with_from_resource():
    (intent,) = from_sql("SELECT * FROM users WHERE id = 1;")
    assert intent.action == "read"
    assert intent.resource == "table/users"
    assert intent.params["statement_class"] == "dql"


def test_with_cte_select_classifies_as_read():
    (intent,) = from_sql("WITH recent AS (SELECT * FROM users) SELECT * FROM recent;")
    assert intent.action == "read"


def test_show_classifies_as_read():
    (intent,) = from_sql("SHOW TABLES;")
    assert intent.action == "read"
    assert intent.resource == "table/*"


def test_explain_classifies_as_read():
    (intent,) = from_sql("EXPLAIN SELECT * FROM users;")
    assert intent.action == "read"


def test_describe_classifies_as_read_with_target():
    (intent,) = from_sql("DESCRIBE users;")
    assert intent.action == "read"
    assert intent.resource == "table/users"


# --- classification: DCL / TCL ------------------------------------------------


def test_grant_classifies_as_update_privilege():
    (intent,) = from_sql("GRANT SELECT, INSERT ON users TO alice;")
    assert intent.action == "update"
    assert intent.resource == "role/alice"
    assert intent.params["privilege"] is True
    assert intent.params["statement_class"] == "dcl"


def test_revoke_classifies_as_update_privilege():
    (intent,) = from_sql("REVOKE SELECT ON users FROM alice;")
    assert intent.action == "update"
    assert intent.resource == "role/alice"
    assert intent.params["privilege"] is True


def test_begin_commit_rollback_set_classify_as_read_session():
    for stmt in ("BEGIN;", "COMMIT;", "ROLLBACK;", "SET search_path = public;"):
        (intent,) = from_sql(stmt)
        assert intent.action == "read"
        assert intent.resource == "session/*"
        assert intent.params["statement_class"] == "tcl"


# --- fail-safe unknown ---------------------------------------------------------


def test_unknown_statement_is_never_read():
    (intent,) = from_sql("VACUUM ANALYZE users;")
    assert intent.action != "read"
    assert intent.action == "update"
    assert intent.params["unclassified"] is True


# --- schema-qualified names ----------------------------------------------------


def test_schema_qualified_delete_resource_and_metadata():
    (intent,) = from_sql("DELETE FROM public.users;")
    assert intent.resource == "table/public.users"
    assert intent.metadata["schema"] == "public"


def test_schema_qualified_quoted_identifier():
    (intent,) = from_sql('DROP TABLE "Public"."Users";')
    assert intent.resource == "table/Public.Users"
    assert intent.metadata["schema"] == "Public"


# --- metadata: database / dialect ----------------------------------------------


def test_from_sql_metadata_carries_database_and_dialect():
    (intent,) = from_sql("SELECT 1;", dialect="postgres", database="proddb")
    assert intent.metadata["dialect"] == "postgres"
    assert intent.metadata["database"] == "proddb"


def test_from_sql_metadata_omits_database_when_not_given():
    (intent,) = from_sql("SELECT 1;")
    assert "database" not in intent.metadata


# --- psql / mysql / sqlite3 argv wrappers --------------------------------------


def test_from_psql_command_flag():
    (intent,) = from_psql(["psql", "-h", "dbhost", "-d", "proddb", "-c", "DROP TABLE users;"])
    assert intent.resource == "table/users"
    assert intent.action == "delete"
    assert intent.metadata["database"] == "proddb"
    assert intent.metadata["host"] == "dbhost"
    assert intent.metadata["dialect"] == "postgres"


def test_from_psql_missing_file_falls_back_to_script_resource():
    (intent,) = from_psql(["psql", "-d", "proddb", "-f", "definitely_missing_9182.sql"])
    assert intent.resource == "script/definitely_missing_9182.sql"
    assert intent.action == "update"
    assert intent.params["unclassified"] is True


def test_from_psql_existing_file_is_parsed(tmp_path):
    script = tmp_path / "migrate.sql"
    script.write_text("DELETE FROM users;")
    intents = from_psql(["psql", "-d", "proddb", "-f", str(script)])
    assert len(intents) == 1
    assert intents[0].resource == "table/users"
    assert intents[0].params["unbounded"] is True


def test_from_psql_positional_dbname():
    (intent,) = from_psql(["psql", "proddb", "-c", "SELECT 1;"])
    assert intent.metadata["database"] == "proddb"


def test_from_psql_rejects_non_psql_argv():
    with pytest.raises(ValueError):
        from_psql(["mysql", "-e", "SELECT 1"])


def test_from_mysql_execute_flag():
    (intent,) = from_mysql(["mysql", "-h", "dbhost", "-D", "shop", "-e", "DROP TABLE t;"])
    assert intent.resource == "table/t"
    assert intent.metadata["database"] == "shop"
    assert intent.metadata["dialect"] == "mysql"
    assert intent.metadata["host"] == "dbhost"


def test_from_mysql_long_execute_flag():
    (intent,) = from_mysql(["mysql", "--execute=SELECT 1;", "--database=shop"])
    assert intent.action == "read"
    assert intent.metadata["database"] == "shop"


def test_from_sqlite3_positional_sql():
    (intent,) = from_sqlite3(["sqlite3", "mydb.db", "DROP TABLE users;"])
    assert intent.resource == "table/users"
    assert intent.metadata["database"] == "mydb.db"
    assert intent.metadata["dialect"] == "sqlite"


def test_from_sqlite3_command_flag():
    (intent,) = from_sqlite3(["sqlite3", "-d", "mydb.db", "-c", "SELECT 1;"])
    assert intent.metadata["database"] == "mydb.db"
    assert intent.action == "read"


# --- mongosh --------------------------------------------------------------------


@pytest.mark.parametrize(
    "eval_js,expected_action,expected_resource",
    [
        ("db.users.drop()", "delete", "collection/users"),
        ("db.dropDatabase()", "delete", "database/*"),
        ("db.users.deleteOne({_id: 1})", "delete", "collection/users"),
        ("db.users.insertOne({name: 'x'})", "put", "collection/users"),
        ("db.users.find({name: 'x'})", "read", "collection/users"),
        ("db.users.countDocuments({})", "read", "collection/users"),
        ("db.users.aggregate([])", "read", "collection/users"),
    ],
)
def test_mongosh_method_classification(eval_js, expected_action, expected_resource):
    (intent,) = from_mongosh(["mongosh", "--eval", eval_js])
    assert intent.provider == "mongodb"
    assert intent.action == expected_action
    assert intent.resource == expected_resource


def test_mongosh_delete_many_empty_filter_is_unbounded():
    (intent,) = from_mongosh(["mongosh", "--eval", "db.users.deleteMany({})"])
    assert intent.params["unbounded"] is True


def test_mongosh_delete_many_with_filter_is_not_unbounded():
    (intent,) = from_mongosh(["mongosh", "--eval", "db.users.deleteMany({status: 'x'})"])
    assert intent.params["unbounded"] is False


def test_mongosh_update_many_empty_filter_is_unbounded():
    (intent,) = from_mongosh(
        ["mongosh", "--eval", "db.users.updateMany({}, {$set: {active: false}})"]
    )
    assert intent.action == "update"
    assert intent.params["unbounded"] is True


def test_mongosh_update_many_with_filter_is_not_unbounded():
    (intent,) = from_mongosh(
        ["mongosh", "--eval", "db.users.updateMany({status: 'x'}, {$set: {active: false}})"]
    )
    assert intent.params["unbounded"] is False


def test_mongosh_remove_empty_filter_is_unbounded():
    (intent,) = from_mongosh(["mongosh", "--eval", "db.users.remove({})"])
    assert intent.params["unbounded"] is True


def test_mongosh_rejects_non_mongosh_argv():
    with pytest.raises(ValueError):
        from_mongosh(["mongo", "--eval", "db.users.find()"])


# --- migration tools --------------------------------------------------------------


def test_alembic_downgrade_is_rollback():
    (intent,) = from_migration_argv(["alembic", "downgrade", "-1"])
    assert intent.action == "rollback"
    assert intent.resource == "migration/-1"
    assert intent.provider == "migration"


def test_alembic_upgrade_head_is_update():
    (intent,) = from_migration_argv(["alembic", "upgrade", "head"])
    assert intent.action == "update"
    assert intent.resource == "migration/head"


def test_flyway_clean_is_delete():
    (intent,) = from_migration_argv(["flyway", "clean"])
    assert intent.action == "delete"
    assert intent.resource == "database/*"


def test_flyway_migrate_is_update():
    (intent,) = from_migration_argv(["flyway", "migrate"])
    assert intent.action == "update"


def test_rails_db_drop_is_delete():
    (intent,) = from_migration_argv(["rails", "db:drop"])
    assert intent.action == "delete"


def test_rails_db_reset_is_delete():
    (intent,) = from_migration_argv(["rails", "db:reset"])
    assert intent.action == "delete"


def test_rails_db_migrate_is_update():
    (intent,) = from_migration_argv(["rails", "db:migrate"])
    assert intent.action == "update"


def test_rails_db_rollback_is_rollback():
    (intent,) = from_migration_argv(["rails", "db:rollback"])
    assert intent.action == "rollback"


def test_prisma_migrate_reset_is_delete():
    (intent,) = from_migration_argv(["prisma", "migrate", "reset"])
    assert intent.action == "delete"


def test_prisma_migrate_deploy_is_update():
    (intent,) = from_migration_argv(["prisma", "migrate", "deploy"])
    assert intent.action == "update"


def test_migration_rejects_unsupported_tool():
    with pytest.raises(ValueError):
        from_migration_argv(["liquibase", "update"])


# --- end-to-end: interceptor against the example store -------------------------


def _load_example_store():
    return ConstraintStore.load(EXAMPLE_STORE, authority_map=_authority_map())


def test_example_store_loads_with_zero_quarantined():
    store = _load_example_store()
    assert store.quarantined == []
    assert len(store.constraints) == 20


def test_unbounded_delete_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("DELETE FROM users;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-unbounded-table-delete" in decision.citations


def test_bounded_delete_is_allowed_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("DELETE FROM users WHERE id = 1;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ALLOW"
    assert decision.covered is False


def test_drop_database_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("DROP DATABASE prod;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-database-delete" in decision.citations


def test_alter_table_drop_column_is_escalated_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("ALTER TABLE users DROP COLUMN ssn;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ESCALATE"
    assert "sql-escalate-table-ddl-drop-column" in decision.citations


def test_mongo_unbounded_delete_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_mongosh(["mongosh", "--eval", "db.users.deleteMany({})"])
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "mongodb-block-unbounded-collection-delete" in decision.citations


def test_flyway_clean_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_migration_argv(["flyway", "clean"])
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "migration-block-database-delete" in decision.citations


def test_example_yaml_exists_alongside_matching_sources():
    for ref in ("jira-5001", "jira-5002", "jira-5003", "jira-5004", "plan-5005", "jira-5006"):
        assert Path(f"data/sources/{ref}.json").exists()
