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
    intents = from_sql(sql)
    intent = intents[0]
    assert intent.action == "delete"
    assert intent.resource == resource
    assert intent.params["statement_class"] == "ddl"
    assert intent.provider == "sql"
    assert intent.params["unbounded"] is True
    assert intent.params["ddl"] is True
    if kind in ("schema", "database"):
        # DROP SCHEMA/DROP DATABASE also emit a synthetic table/* unbounded
        # delete so table-scoped rules fire against everything it cascades
        # into (REVIEW-4 T1.4).
        assert len(intents) == 2
        synthetic = intents[1]
        assert synthetic.resource == "table/*"
        assert synthetic.action == "delete"
        assert synthetic.params["unbounded"] is True
        assert synthetic.metadata["schema"] == resource.split("/", 1)[1]
    else:
        assert len(intents) == 1


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
    assert intent.params["unreadable"] is True
    assert intent.params["opaque"] is True


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
    assert len(store.constraints) == 30


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
    (intent, synthetic) = from_sql("DROP DATABASE prod;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-database-delete" in decision.citations
    # The synthetic table/* cascade intent also blocks, via the unbounded
    # table-delete rule.
    synthetic_decision = interceptor.intercept(synthetic, now=NOW)
    assert synthetic_decision.verdict == "BLOCK"
    assert "sql-block-unbounded-table-delete" in synthetic_decision.citations


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


# =================================================================================
# REVIEW-4 T1.4 -- SQL/Mongo classifier evasion shapes
# =================================================================================

from aegis_core.parsers.sql import evasion  # noqa: E402


def test_evasion_catalogue_is_nonempty_and_importable():
    assert isinstance(evasion, list)
    assert len(evasion) >= 30
    assert all(isinstance(s, str) for s in evasion)


# --- 1. TRUNCATE/DROP/DELETE unbounded flags -------------------------------------


def test_truncate_is_unbounded_and_ddl():
    (intent,) = from_sql("TRUNCATE TABLE orders;")
    assert intent.params["unbounded"] is True
    assert intent.params["ddl"] is True
    assert intent.params["truncate"] is True


def test_drop_index_is_unbounded_and_ddl():
    (intent,) = from_sql("DROP INDEX idx_users_email;")
    assert intent.params["unbounded"] is True
    assert intent.params["ddl"] is True


def test_drop_view_is_unbounded_and_ddl():
    (intent,) = from_sql("DROP VIEW active_users;")
    assert intent.params["unbounded"] is True
    assert intent.params["ddl"] is True


def test_delete_from_without_where_unbounded_flag_still_set():
    (intent,) = from_sql("DELETE FROM users;")
    assert intent.params["unbounded"] is True


# --- 2. Comment stripping before classification -----------------------------------


def test_delete_with_block_comment_between_keywords_is_delete_unbounded():
    (intent,) = from_sql("DELETE/**/FROM users;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert intent.params["unbounded"] is True


def test_delete_with_line_comment_between_keywords_is_delete():
    (intent,) = from_sql("DELETE --comment\nFROM users;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"


def test_truncate_with_block_comment_still_classifies():
    (intent,) = from_sql("TRUNCATE/**/TABLE/**/orders;")
    assert intent.action == "delete"
    assert intent.resource == "table/orders"
    assert intent.params["unbounded"] is True


def test_drop_table_with_line_comment_still_classifies():
    (intent,) = from_sql("DROP TABLE --danger\nusers;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"


def test_comment_does_not_leak_fake_semicolon_terminator_into_classification():
    # A ';' inside a comment must not split the statement -- covered by the
    # splitter already, but confirm classification survives the combination
    # with comment stripping.
    intents = from_sql("DELETE FROM users -- ; not a real terminator\n;")
    assert len(intents) == 1
    assert intents[0].params["unbounded"] is True


# --- 3. CTEs: classify by strongest inner statement -------------------------------


def test_cte_with_delete_classifies_as_delete_with_cte_flag():
    (intent,) = from_sql("WITH d AS (DELETE FROM users RETURNING *) SELECT 1;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert intent.params["cte"] is True
    assert intent.params["unbounded"] is True


def test_cte_with_delete_and_where_is_not_unbounded():
    (intent,) = from_sql(
        "WITH d AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT 1;"
    )
    assert intent.action == "delete"
    assert intent.params["unbounded"] is False


def test_cte_with_update_classifies_as_update():
    (intent,) = from_sql("WITH u AS (UPDATE users SET active = false) SELECT 1;")
    assert intent.action == "update"
    assert intent.resource == "table/users"
    assert intent.params["cte"] is True


def test_cte_with_insert_classifies_as_put():
    (intent,) = from_sql("WITH i AS (INSERT INTO users (id) VALUES (1)) SELECT 1;")
    assert intent.action == "put"
    assert intent.resource == "table/users"
    assert intent.params["cte"] is True


def test_cte_prefers_delete_over_update_when_both_present():
    (intent,) = from_sql(
        "WITH u AS (UPDATE accounts SET x = 1), d AS (DELETE FROM users) SELECT 1;"
    )
    assert intent.action == "delete"
    assert intent.resource == "table/users"


def test_cte_plain_select_still_reads():
    (intent,) = from_sql("WITH recent AS (SELECT * FROM users) SELECT * FROM recent;")
    assert intent.action == "read"
    assert "cte" not in intent.params


# --- 4. EXPLAIN / EXPLAIN ANALYZE -------------------------------------------------


def test_explain_without_analyze_is_read_with_flag():
    (intent,) = from_sql("EXPLAIN DELETE FROM users;")
    assert intent.action == "read"
    assert intent.params["explain"] is True


def test_explain_analyze_delete_classifies_as_delete_unbounded():
    (intent,) = from_sql("EXPLAIN ANALYZE DELETE FROM users;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert intent.params["unbounded"] is True
    assert intent.params["explain_analyze"] is True


def test_explain_analyze_select_still_reads_with_flag():
    (intent,) = from_sql("EXPLAIN ANALYZE SELECT * FROM users;")
    assert intent.action == "read"
    assert intent.params["explain_analyze"] is True


def test_explain_select_is_read():
    (intent,) = from_sql("EXPLAIN SELECT * FROM users;")
    assert intent.action == "read"
    assert intent.params["explain"] is True


# --- 5. DO / CALL / EXECUTE / PERFORM ---------------------------------------------


def test_do_block_is_opaque_update():
    (intent,) = from_sql("DO $$ BEGIN DELETE FROM users; END $$;")
    assert intent.action == "update"
    assert intent.resource == "block/*"
    assert intent.params["opaque"] is True


def test_call_proc_is_opaque_update_with_procedure_resource():
    (intent,) = from_sql("CALL cleanup_users();")
    assert intent.action == "update"
    assert intent.resource == "procedure/cleanup_users"
    assert intent.params["opaque"] is True


def test_execute_proc_is_opaque_update_with_procedure_resource():
    (intent,) = from_sql("EXECUTE cleanup_users();")
    assert intent.action == "update"
    assert intent.resource == "procedure/cleanup_users"
    assert intent.params["opaque"] is True


def test_execute_dynamic_sql_string_falls_back_to_block_resource():
    (intent,) = from_sql("EXECUTE 'DELETE FROM users';")
    assert intent.action == "update"
    assert intent.resource == "block/*"
    assert intent.params["opaque"] is True


def test_perform_proc_is_opaque_update():
    (intent,) = from_sql("PERFORM cleanup_users();")
    assert intent.action == "update"
    assert intent.resource == "procedure/cleanup_users"
    assert intent.params["opaque"] is True


# --- 6. MySQL multi-table DELETE --------------------------------------------------


def test_mysql_multi_table_delete_targets_first_table():
    (intent, joined) = from_sql("DELETE users FROM users JOIN orders ON users.id = orders.uid;")
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert (joined.resource, joined.action) == ("table/orders", "read")


def test_delete_from_using_targets_first_table():
    (intent, using) = from_sql("DELETE FROM t1 USING t2 WHERE t1.id = t2.id;")
    assert intent.action == "delete"
    assert intent.resource == "table/t1"
    assert intent.params["unbounded"] is False
    assert (using.resource, using.action) == ("table/t2", "read")


def test_delete_from_using_without_where_is_unbounded():
    (intent, _using) = from_sql("DELETE FROM t1 USING t2;")
    assert intent.params["unbounded"] is True


# --- 7. DROP SCHEMA/DATABASE cascade + synthetic table/* intent ------------------


def test_drop_schema_cascade_sets_cascade_param():
    (intent, synthetic) = from_sql("DROP SCHEMA public CASCADE;")
    assert intent.resource == "schema/public"
    assert intent.params["cascade"] is True
    assert synthetic.resource == "table/*"
    assert synthetic.action == "delete"
    assert synthetic.params["unbounded"] is True
    assert synthetic.metadata["schema"] == "public"


def test_drop_schema_without_cascade_has_no_cascade_param():
    (intent, _synthetic) = from_sql("DROP SCHEMA analytics;")
    assert "cascade" not in intent.params


def test_drop_database_emits_synthetic_table_wildcard_delete():
    (intent, synthetic) = from_sql("DROP DATABASE prod;")
    assert intent.resource == "database/prod"
    assert synthetic.resource == "table/*"
    assert synthetic.metadata["schema"] == "prod"


# --- 8. psql/mysql: multiple -c/-e, unreadable -f --------------------------------


def test_from_psql_collects_all_command_flags_in_order():
    intents = from_psql(
        ["psql", "-d", "proddb", "-c", "DELETE FROM users;", "-c", "SELECT 1;"]
    )
    assert len(intents) == 2
    assert intents[0].action == "delete"
    assert intents[0].resource == "table/users"
    assert intents[1].action == "read"


def test_from_mysql_collects_all_execute_flags_in_order():
    intents = from_mysql(
        ["mysql", "-D", "shop", "-e", "DROP TABLE t;", "-e", "SELECT 1;"]
    )
    assert len(intents) == 2
    assert intents[0].action == "delete"
    assert intents[0].resource == "table/t"
    assert intents[1].action == "read"


def test_from_mysql_missing_file_is_opaque_unreadable():
    (intent,) = from_mysql(["mysql", "-D", "shop", "-f", "definitely_missing_7213.sql"])
    assert intent.resource == "script/definitely_missing_7213.sql"
    assert intent.action == "update"
    assert intent.params["unreadable"] is True
    assert intent.params["opaque"] is True


# --- 9. mongosh: getCollection / bracket access / chained find().forEach() ------


def test_mongosh_get_collection_delete_many_is_unbounded_delete():
    (intent,) = from_mongosh(
        ["mongosh", "--eval", 'db.getCollection("users").deleteMany({})']
    )
    assert intent.action == "delete"
    assert intent.resource == "collection/users"
    assert intent.params["unbounded"] is True


def test_mongosh_bracket_access_drop_is_unbounded_delete():
    (intent,) = from_mongosh(["mongosh", "--eval", 'db["users"].drop()'])
    assert intent.action == "delete"
    assert intent.resource == "collection/users"
    assert intent.params["unbounded"] is True


def test_mongosh_plain_drop_is_unbounded_delete():
    (intent,) = from_mongosh(["mongosh", "--eval", "db.users.drop()"])
    assert intent.params["unbounded"] is True


def test_mongosh_drop_database_is_unbounded_delete():
    (intent,) = from_mongosh(["mongosh", "--eval", "db.dropDatabase()"])
    assert intent.resource == "database/*"
    assert intent.params["unbounded"] is True


def test_mongosh_chained_find_forEach_classifies_as_read():
    (intent,) = from_mongosh(
        ["mongosh", "--eval", "db.users.find({}).forEach(function(doc) { print(doc); })"]
    )
    assert intent.action == "read"
    assert intent.resource == "collection/users"


# --- 10. GRANT/REVOKE unparseable grantee -> privilege/* -------------------------


def test_grant_with_no_to_clause_falls_back_to_privilege_wildcard():
    (intent,) = from_sql("GRANT SELECT ON users;")
    assert intent.resource == "privilege/*"
    assert intent.params["privilege"] is True
    assert intent.action == "update"


def test_revoke_with_no_from_clause_falls_back_to_privilege_wildcard():
    (intent,) = from_sql("REVOKE SELECT ON users;")
    assert intent.resource == "privilege/*"
    assert intent.params["privilege"] is True


# --- 11. fail-safe: opaque ops are never read -------------------------------------


def test_do_call_execute_perform_are_never_read():
    for sql in (
        "DO $$ BEGIN NULL; END $$;",
        "CALL some_proc();",
        "EXECUTE some_proc();",
        "PERFORM some_proc();",
    ):
        (intent,) = from_sql(sql)
        assert intent.action != "read"
        assert intent.params["opaque"] is True


# --- end-to-end: interceptor against the example store (T1.4 accept criteria) ---


def test_truncate_users_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("TRUNCATE users;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-unbounded-table-delete" in decision.citations


def test_cte_delete_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("WITH d AS (DELETE FROM users RETURNING *) SELECT 1;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-unbounded-table-delete" in decision.citations


def test_explain_delete_is_allowed_as_read_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("EXPLAIN DELETE FROM users;")
    assert intent.action == "read"
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "ALLOW"


def test_explain_analyze_delete_is_blocked_end_to_end():
    store = _load_example_store()
    interceptor = AegisInterceptor(store)
    (intent,) = from_sql("EXPLAIN ANALYZE DELETE FROM users;")
    decision = interceptor.intercept(intent, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "sql-block-unbounded-table-delete" in decision.citations


# --- 12. #58: every table a statement reads ---------------------------------------


def _reads(sql: str) -> list[str]:
    intents = from_sql(sql, dialect="postgres")
    return [i.resource for i in intents if i.action == "read"]


def _summary(sql: str) -> list[tuple[str, str]]:
    return [(i.action, i.resource) for i in from_sql(sql, dialect="postgres")]


@pytest.mark.parametrize("sql,tables", [
    # joins, with and without aliases
    ("SELECT p.name FROM products p JOIN users u ON u.id = p.owner_id",
     ["products", "users"]),
    ("SELECT * FROM products AS p INNER JOIN users AS u ON u.id = p.owner_id",
     ["products", "users"]),
    ("SELECT * FROM a LEFT OUTER JOIN b ON a.id = b.id RIGHT JOIN c ON c.id = a.id",
     ["a", "b", "c"]),
    ("SELECT * FROM a CROSS JOIN b NATURAL JOIN c FULL JOIN d USING (id)",
     ["a", "b", "c", "d"]),
    ("SELECT * FROM a STRAIGHT_JOIN b ON a.id = b.id", ["a", "b"]),
    ("SELECT * FROM (a JOIN b ON a.x = b.x) JOIN c ON true", ["a", "b", "c"]),
    # comma joins
    ("SELECT * FROM a, b", ["a", "b"]),
    ("SELECT * FROM a x, b AS y, c WHERE x.id = y.id", ["a", "b", "c"]),
    ("SELECT * FROM a JOIN b ON a.x = b.x, c WHERE a.y IN (1, 2)", ["a", "b", "c"]),
    # subqueries: WHERE, FROM, nested, EXISTS, scalar, LATERAL
    ("SELECT * FROM products WHERE id IN (SELECT id FROM users)", ["products", "users"]),
    ("SELECT * FROM (SELECT * FROM users) sub", ["users"]),
    ("SELECT * FROM (SELECT * FROM (SELECT * FROM deep) x WHERE x.id IN "
     "(SELECT id FROM deeper)) y", ["deep", "deeper"]),
    ("SELECT * FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.x = ANY(ARRAY[1, 2]))",
     ["a", "b"]),
    ("SELECT (SELECT max(price) FROM products) AS top", ["products"]),
    ("SELECT * FROM ONLY parent, LATERAL (SELECT * FROM kid WHERE kid.p = parent.id) k",
     ["parent", "kid"]),
    # set operations
    ("SELECT name FROM products UNION SELECT password_hash FROM users",
     ["products", "users"]),
    ("SELECT a FROM t1 UNION ALL SELECT a FROM t2 INTERSECT SELECT a FROM t3 "
     "EXCEPT SELECT a FROM t4", ["t1", "t2", "t3", "t4"]),
    ("SELECT * FROM t UNION ALL TABLE users", ["t", "users"]),
    # dedupe
    ("SELECT * FROM users u1 JOIN users u2 ON u1.boss = u2.id", ["users"]),
    # names
    ('SELECT * FROM "Weird Name" w JOIN "S"."T" ON true', ["Weird Name", "S.T"]),
    ("SELECT * FROM public.users JOIN audit.log l ON true", ["public.users", "audit.log"]),
    ("SELECT * FROM `shop`.`users` JOIN `orders` ON 1", ["shop.users", "orders"]),
    ("SELECT * FROM cat.sch.tbl", ["cat.sch.tbl"]),
    # functions in FROM are not tables
    ("SELECT * FROM generate_series(1, 10) g, users", ["users"]),
    ("SELECT * FROM unnest(ARRAY[1, 2]) WITH ORDINALITY AS t(v, n)", ["*"]),
    # FROM inside a function call is not a table
    ("SELECT EXTRACT(YEAR FROM ts), SUBSTRING(name FROM 2 FOR 3), TRIM(BOTH 'x' FROM s) "
     "FROM events WHERE a IS DISTINCT FROM b", ["events"]),
    # keywords inside string literals and dollar quotes are not parsed
    ("SELECT 'x FROM secrets JOIN y' AS s FROM products "
     "WHERE name = 'a UNION SELECT * FROM users'", ["products"]),
    ("SELECT $$ FROM users $$ FROM products", ["products"]),
    ("SELECT * FROM products WHERE note = 'it''s FROM users'", ["products"]),
    # clauses after FROM end the comma list
    ("SELECT * FROM a ORDER BY x, y", ["a"]),
    ("SELECT a, b FROM t GROUP BY a, b", ["t"]),
    ("SELECT 1", ["*"]),
])
def test_select_reads_every_table(sql, tables):
    assert _reads(sql) == [f"table/{t}" for t in tables]
    assert all(i.action == "read" for i in from_sql(sql))


def test_select_read_of_schema_qualified_table_carries_schema():
    intents = from_sql('SELECT * FROM products JOIN "Audit"."Log" ON true;')
    assert [i.resource for i in intents] == ["table/products", "table/Audit.Log"]
    assert "schema" not in intents[0].metadata
    assert intents[1].metadata["schema"] == "Audit"
    assert all(i.params["statement_class"] == "dql" for i in intents)
    assert all(i.params["raw_action"] == "SELECT" for i in intents)


@pytest.mark.parametrize("sql,tables", [
    # a CTE's name is not a table; its body is read
    ("WITH cheap AS (SELECT * FROM products) SELECT * FROM cheap JOIN users ON true",
     ["products", "users"]),
    ("WITH a AS (SELECT * FROM t1), b AS (SELECT * FROM a JOIN t2 ON true) SELECT * FROM b",
     ["t1", "t2"]),
    ("WITH x (id) AS MATERIALIZED (SELECT id FROM t1) SELECT * FROM x", ["t1"]),
    # inside its own body a (non-recursive) CTE's name is the real table
    ("WITH users AS (SELECT * FROM users WHERE active) SELECT * FROM users", ["users"]),
    ("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT * FROM t",
     ["*"]),
    # a CTE in a subquery does not hide the real table outside it
    ("SELECT * FROM (WITH users AS (SELECT 1) SELECT * FROM users) s JOIN users u ON true",
     ["users"]),
    ("SELECT * FROM (WITH u AS (SELECT * FROM t1) SELECT * FROM u) s, u", ["t1", "u"]),
])
def test_cte_bodies_are_read_and_cte_names_are_not_tables(sql, tables):
    assert _reads(sql) == [f"table/{t}" for t in tables]


def test_cte_dml_keeps_strongest_dml_and_adds_other_reads():
    assert _summary(
        "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d JOIN secrets ON true;"
    ) == [("delete", "table/users"), ("read", "table/secrets")]
    assert _summary(
        "WITH src AS (SELECT * FROM users) INSERT INTO pub SELECT * FROM src;"
    ) == [("put", "table/pub"), ("read", "table/users")]


@pytest.mark.parametrize("sql,expected", [
    ("INSERT INTO pub SELECT * FROM users",
     [("put", "table/pub"), ("read", "table/users")]),
    ("INSERT INTO t VALUES (1, 'FROM users')", [("put", "table/t")]),
    ("INSERT INTO t SELECT * FROM t", [("put", "table/t")]),
    ("UPDATE t SET a = (SELECT max(x) FROM s) WHERE id = 1",
     [("update", "table/t"), ("read", "table/s")]),
    ("UPDATE t SET a = s.a FROM s, u WHERE t.id = s.id",
     [("update", "table/t"), ("read", "table/s"), ("read", "table/u")]),
    ("DELETE FROM t WHERE id IN (SELECT id FROM s)",
     [("delete", "table/t"), ("read", "table/s")]),
    ("CREATE TABLE c AS SELECT * FROM users",
     [("create", "table/c"), ("read", "table/users")]),
    ("CREATE VIEW v AS SELECT * FROM a JOIN b ON true",
     [("create", "view/v"), ("read", "table/a"), ("read", "table/b")]),
    ("CREATE TABLE t (id int REFERENCES u ON DELETE CASCADE)", [("create", "table/t")]),
])
def test_writes_also_read_their_source_tables(sql, expected):
    assert _summary(sql) == expected


def test_show_columns_from_still_names_its_table():
    (intent,) = from_sql("SHOW COLUMNS FROM users;", dialect="mysql")
    assert (intent.action, intent.resource) == ("read", "table/users")


def test_write_flags_unchanged_by_extra_reads():
    (update, read) = from_sql("UPDATE t SET a = (SELECT 1 FROM s);")
    assert update.params["unbounded"] is True
    assert read.params == {"statement_class": "dql", "raw_action": "SELECT"}


# --- SELECT ... INTO ---


def test_select_into_is_a_create_plus_reads():
    (create, read) = from_sql("SELECT * INTO users_copy FROM users;", dialect="postgres")
    assert (create.action, create.resource) == ("create", "table/users_copy")
    assert create.params["ddl"] is True
    assert create.params["select_into"] is True
    assert create.params["statement_class"] == "ddl"
    assert create.params["raw_action"] == "SELECT INTO"
    assert (read.action, read.resource) == ("read", "table/users")


@pytest.mark.parametrize("sql,expected", [
    ("SELECT * INTO TEMP TABLE t2 FROM users", [("create", "table/t2"), ("read", "table/users")]),
    ("SELECT * INTO UNLOGGED archive.t2 FROM a JOIN b ON true",
     [("create", "table/archive.t2"), ("read", "table/a"), ("read", "table/b")]),
    ("SELECT 1 INTO t", [("create", "table/t")]),
    ("WITH x AS (SELECT * FROM users) SELECT * INTO copy FROM x",
     [("create", "table/copy"), ("read", "table/users")]),
    # MySQL: into a session variable only reads
    ("SELECT name INTO @n FROM users WHERE id = 1", [("read", "table/users")]),
    ("SELECT 1 INTO @a", [("read", "table/*")]),
    # INSERT INTO is not SELECT INTO
    ("INSERT INTO t SELECT * FROM s", [("put", "table/t"), ("read", "table/s")]),
    # INTO in a string is not a clause
    ("SELECT 'INTO x' FROM t", [("read", "table/t")]),
])
def test_select_into_variants(sql, expected):
    assert _summary(sql) == expected


@pytest.mark.parametrize("sql,path", [
    ("SELECT * FROM users INTO OUTFILE '/tmp/users.csv'", "/tmp/users.csv"),
    ("SELECT * INTO DUMPFILE '/tmp/blob' FROM users", "/tmp/blob"),
])
def test_select_into_outfile_is_an_opaque_write(sql, path):
    (write, read) = from_sql(sql, dialect="mysql")
    assert write.action == "update"
    assert write.resource == f"file/{path}"
    assert write.params["opaque"] is True
    assert write.params["unclassified"] is True
    assert write.params["into_file"] is True
    assert (read.action, read.resource) == ("read", "table/users")


def test_select_into_unparseable_target_is_unclassified_write():
    (intent,) = from_sql("SELECT 1 INTO 42;")
    assert intent.action == "update"
    assert intent.params["unclassified"] is True


# --- SET ROLE and other identity changes ---


@pytest.mark.parametrize("sql,resource,raw", [
    ("SET ROLE admin", "role/admin", "SET ROLE"),
    ("SET LOCAL ROLE admin", "role/admin", "SET ROLE"),
    ("SET SESSION ROLE 'admin'", "role/admin", "SET ROLE"),
    ('SET ROLE "Admin"', "role/Admin", "SET ROLE"),
    ("SET role TO admin", "role/admin", "SET ROLE"),
    ("SET role = admin", "role/admin", "SET ROLE"),
    ("SET ROLE NONE", "role/*", "SET ROLE"),
    ("SET SESSION AUTHORIZATION admin", "role/admin", "SET SESSION AUTHORIZATION"),
    ("SET SESSION SESSION AUTHORIZATION admin", "role/admin", "SET SESSION AUTHORIZATION"),
    ("SET SESSION AUTHORIZATION DEFAULT", "role/*", "SET SESSION AUTHORIZATION"),
    ("SET session_authorization = 'admin'", "role/admin", "SET SESSION AUTHORIZATION"),
    ("RESET ROLE", "role/*", "RESET ROLE"),
    ("RESET SESSION AUTHORIZATION", "role/*", "RESET SESSION AUTHORIZATION"),
    ("SET DEFAULT ROLE ALL TO alice", "role/alice", "SET DEFAULT ROLE"),
    ("SET PASSWORD FOR 'bob'@'%' = 'x'", "role/bob", "SET PASSWORD"),
    ("SET PASSWORD = 'x'", "role/*", "SET PASSWORD"),
])
def test_identity_changes_are_privilege_updates(sql, resource, raw):
    (intent,) = from_sql(sql)
    assert intent.action == "update"
    assert intent.resource == resource
    assert intent.params["privilege"] is True
    assert intent.params["statement_class"] == "dcl"
    assert intent.params["raw_action"] == raw


def test_set_role_to_several_roles_emits_one_intent_each():
    intents = from_sql("SET ROLE 'r1'@'%', r2;", dialect="mysql")
    assert [i.resource for i in intents] == ["role/r1", "role/r2"]
    assert all(i.params["privilege"] is True for i in intents)


def test_set_config_role_in_a_select_is_a_privilege_update():
    (role, read) = from_sql("SELECT set_config('role', 'admin', false);")
    assert (role.action, role.resource) == ("update", "role/admin")
    assert role.params["privilege"] is True
    assert (read.action, read.resource) == ("read", "table/*")


@pytest.mark.parametrize("sql", [
    "SET search_path = public",
    "SET statement_timeout = '2s'",
    "SET rolename_hint = 'x'",
    "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    "SET NAMES utf8mb4",
    "SET @role = 'admin'",
])
def test_other_sets_stay_session_reads(sql):
    (intent,) = from_sql(sql)
    assert intent.action == "read"
    assert intent.resource == "session/*"


def test_reset_other_setting_stays_unclassified():
    (intent,) = from_sql("RESET search_path;")
    assert intent.action == "update"
    assert intent.params["unclassified"] is True


# --- locking reads ---


@pytest.mark.parametrize("sql,strength", [
    ("SELECT * FROM orders FOR UPDATE", "update"),
    ("SELECT * FROM orders FOR NO KEY UPDATE", "no key update"),
    ("SELECT * FROM orders FOR SHARE", "share"),
    ("SELECT * FROM orders FOR KEY SHARE", "key share"),
    ("SELECT * FROM orders LOCK IN SHARE MODE", "share"),
    ("SELECT * FROM orders FOR SHARE FOR UPDATE", "update"),
])
def test_locking_select_stays_read_with_locking_param(sql, strength):
    (intent,) = from_sql(sql)
    assert intent.action == "read"
    assert intent.resource == "table/orders"
    assert intent.params["locking"] is True
    assert intent.params["lock_strength"] == strength
    assert "nowait" not in intent.params
    assert "skip_locked" not in intent.params


def test_locking_select_records_nowait_and_skip_locked():
    (intent,) = from_sql("SELECT * FROM orders FOR UPDATE NOWAIT;")
    assert intent.params["nowait"] is True
    intents = from_sql("SELECT * FROM orders o JOIN items i USING (id) "
                       "FOR NO KEY UPDATE OF o SKIP LOCKED;")
    assert [i.resource for i in intents] == ["table/orders", "table/items"]
    assert all(i.params["skip_locked"] is True for i in intents)
    assert all(i.params["lock_strength"] == "no key update" for i in intents)


def test_locking_in_a_subquery_is_seen():
    (intent,) = from_sql("SELECT * FROM (SELECT * FROM orders FOR UPDATE) s;")
    assert intent.params["locking"] is True


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders",
    "SELECT SUBSTRING(name FROM 1 FOR 3) FROM orders",
    "SELECT 'FOR UPDATE' FROM orders",
])
def test_non_locking_select_has_no_locking_param(sql):
    (intent,) = from_sql(sql)
    assert "locking" not in intent.params


# --- EXPLAIN ---


def test_explain_reads_every_table_and_its_target():
    assert _summary("EXPLAIN SELECT * FROM a JOIN b ON true;") == [
        ("read", "table/a"), ("read", "table/b")
    ]
    assert _summary("EXPLAIN DELETE FROM users WHERE id IN (SELECT id FROM banned);") == [
        ("read", "table/users"), ("read", "table/banned")
    ]
    assert _summary("EXPLAIN SELECT * INTO t FROM users;") == [
        ("read", "table/t"), ("read", "table/users")
    ]


def test_explain_with_options_analyze_runs_the_statement():
    (intent,) = from_sql("EXPLAIN (ANALYZE, BUFFERS) DELETE FROM users;")
    assert intent.action == "delete"
    assert intent.params["explain_analyze"] is True
    (intent,) = from_sql("EXPLAIN ANALYZE VERBOSE DELETE FROM users;")
    assert intent.action == "delete"
    (intent,) = from_sql("EXPLAIN (ANALYZE false) DELETE FROM users;")
    assert intent.action == "read"
    (intent,) = from_sql("EXPLAIN (FORMAT JSON) SELECT * FROM users;")
    assert (intent.action, intent.resource) == ("read", "table/users")


# --- DB-CLI wrappers ---


def test_psql_select_into_is_a_create():
    intents = from_psql(["psql", "-d", "shop", "-c", "SELECT * INTO users_copy FROM users"])
    assert [(i.action, i.resource) for i in intents] == [
        ("create", "table/users_copy"), ("read", "table/users")
    ]
    assert all(i.metadata["database"] == "shop" for i in intents)


def test_psql_join_reads_both_tables_and_set_role_is_update():
    intents = from_psql(["psql", "-c", "SELECT * FROM a JOIN users ON true", "-c", "SET ROLE x"])
    assert [(i.action, i.resource) for i in intents] == [
        ("read", "table/a"), ("read", "table/users"), ("update", "role/x")
    ]


def test_mysql_into_outfile_is_opaque_write():
    intents = from_mysql(["mysql", "-e", "SELECT * FROM users INTO OUTFILE '/tmp/u'"])
    assert intents[0].action == "update"
    assert intents[0].params["opaque"] is True
    assert intents[0].metadata["dialect"] == "mysql"


def test_sqlite3_union_reads_both_tables():
    intents = from_sqlite3(["sqlite3", "app.db", "SELECT a FROM t UNION SELECT b FROM u"])
    assert [i.resource for i in intents] == ["table/t", "table/u"]


# --- end-to-end against the example store (signatures unchanged) ---


def test_join_read_still_allowed_by_example_store():
    interceptor = AegisInterceptor(_load_example_store())
    for intent in from_sql("SELECT * FROM a JOIN users ON true FOR UPDATE;"):
        assert interceptor.intercept(intent, now=NOW).verdict == "ALLOW"


def test_cte_delete_with_extra_reads_still_blocked_end_to_end():
    interceptor = AegisInterceptor(_load_example_store())
    (delete, read) = from_sql("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d, logs;")
    assert interceptor.intercept(delete, now=NOW).verdict == "BLOCK"
    assert interceptor.intercept(read, now=NOW).verdict == "ALLOW"
