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
    # Every DML operation is reported (#58); the strongest comes first.
    (intent, other) = from_sql(
        "WITH u AS (UPDATE accounts SET x = 1), d AS (DELETE FROM users) SELECT 1;"
    )
    assert intent.action == "delete"
    assert intent.resource == "table/users"
    assert (other.action, other.resource) == ("update", "table/accounts")


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


def test_from_mysql_has_no_script_option():
    # round 5: mysql's -f is --force; a script comes in on stdin, which argv does not show
    with pytest.raises(ValueError, match="could not find SQL text"):
        from_mysql(["mysql", "-D", "shop", "-f", "definitely_missing_7213.sql"])


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


# --- 13. #58 review: one dialect-aware lexer ------------------------------------


def _summary_in(sql: str, dialect: str) -> list[tuple[str, str]]:
    return [(i.action, i.resource) for i in from_sql(sql, dialect=dialect)]


@pytest.mark.parametrize("sql,dialect,expected", [
    # E'' strings take \' as an escaped quote in Postgres; generic also flags them
    # (SQLite and MySQL read E as a name and end the string at the \')
    ("SELECT * FROM products WHERE a = E'x\\''; DROP TABLE users", "postgres",
     [("read", "table/products"), ("delete", "table/users")]),
    ("SELECT * FROM a WHERE x = E'x\\'' UNION SELECT * FROM users", "postgres",
     [("read", "table/a"), ("read", "table/users")]),
    ("SELECT E'foo\\'bar', x FROM secret", "postgres", [("read", "table/secret")]),
    ("SELECT E'\\'' , (SELECT pw FROM users) , '' FROM products", "postgres",
     [("read", "table/users"), ("read", "table/products")]),
    ("SELECT e'it\\'s; FROM x' FROM t", "postgres", [("read", "table/t")]),
    ("SELECT e'it\\'s; FROM x' FROM t", "generic", [("read", "table/t"), ("update", "unknown/*")]),
    # every MySQL string, single- or double-quoted
    ("SELECT * FROM products WHERE a = 'x\\''; DROP TABLE users", "mysql",
     [("read", "table/products"), ("delete", "table/users")]),
    ('SELECT * FROM products WHERE a = "x\\""; DROP TABLE users', "mysql",
     [("read", "table/products"), ("delete", "table/users")]),
    ("SELECT * FROM t WHERE a = 'x\\' UNION SELECT * FROM users'", "mysql",
     [("read", "table/t")]),
    # ... but a plain '...' is standard SQL elsewhere: \ is an ordinary character
    ("SELECT * FROM products WHERE a = 'x\\' UNION SELECT * FROM users", "postgres",
     [("read", "table/products"), ("read", "table/users")]),
    ("SELECT * FROM products WHERE a = 'x\\' UNION SELECT * FROM users", "sqlite",
     [("read", "table/products"), ("read", "table/users")]),
    # round 5: a body ending in a backslash is also ambiguous under generic
    ("SELECT * FROM products WHERE a = 'C:\\'; DROP TABLE users", "generic",
     [("read", "table/products"), ("update", "unknown/*"), ("delete", "table/users")]),
])
def test_backslash_escapes_follow_the_dialect(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


def test_backslash_escape_through_the_cli_wrappers():
    sql = "SELECT * FROM products WHERE a = E'x\\''; DROP TABLE users"
    intents = from_psql(["psql", "-c", sql])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]
    intents = from_mysql(["mysql", "-e", sql.replace("E'", "'")])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("sql,dialect,expected", [
    ("SELECT * FROM allowed WHERE x = $$--$$ UNION SELECT * FROM secret", "postgres",
     [("read", "table/allowed"), ("read", "table/secret")]),
    ("SELECT * FROM allowed WHERE x = $$/*$$ UNION SELECT * FROM secret", "postgres",
     [("read", "table/allowed"), ("read", "table/secret")]),
    ("SELECT * FROM allowed WHERE x = $t1$ ; ' -- $t1$ UNION SELECT * FROM secret", "postgres",
     [("read", "table/allowed"), ("read", "table/secret")]),
    # no dollar quoting in MySQL or SQLite: what follows $$ is SQL
    ("SELECT $$ FROM secret", "mysql", [("read", "table/secret")]),
    ("SELECT $$; DROP TABLE users; $$", "sqlite",
     [("read", "table/*"), ("delete", "table/users"), ("update", "unknown/*")]),
])
def test_dollar_quotes_are_strings_and_comments_inside_them_are_not(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


@pytest.mark.parametrize("sql,dialect,expected", [
    # MySQL runs the body of an executable comment: read it as SQL under mysql and
    # generic; Postgres and SQLite skip it like any comment
    ("SELECT * FROM products /*!50000 UNION SELECT * FROM users */", "mysql",
     [("read", "table/products"), ("read", "table/users")]),
    ("SELECT * FROM products /*! UNION SELECT * FROM users */", "postgres",
     [("read", "table/products")]),
    ("SELECT * FROM products /*! UNION SELECT * FROM users */", "generic",
     [("read", "table/products"), ("read", "table/users")]),
    ("SELECT * FROM products /*M!100100 UNION SELECT * FROM users */", "mysql",
     [("read", "table/products"), ("read", "table/users")]),
    ("SELECT 1 /*!; DROP TABLE users */", "mysql",
     [("read", "table/*"), ("delete", "table/users")]),
    # an ordinary comment still hides its body
    ("SELECT * FROM products /* UNION SELECT * FROM users */", "mysql",
     [("read", "table/products")]),
    # MySQL: '--' starts a comment only before whitespace; '#' starts one
    ("SELECT * FROM a WHERE 1--1 UNION SELECT * FROM users", "mysql",
     [("read", "table/a"), ("read", "table/users")]),
    ("SELECT 1 # it's a comment\nFROM users", "mysql", [("read", "table/users")]),
    ("SELECT * FROM a -- UNION SELECT * FROM users", "mysql", [("read", "table/a")]),
])
def test_comment_forms(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


@pytest.mark.parametrize("sql,resource,raw", [
    ("SET \"role\" = 'admin'", "role/admin", "SET ROLE"),
    ('SET "role" TO admin', "role/admin", "SET ROLE"),
    ('SET SESSION "role" = admin', "role/admin", "SET ROLE"),
    ('SET LOCAL "ROLE" = admin', "role/admin", "SET ROLE"),
    ("SET SESSION \"session_authorization\" = 'admin'", "role/admin",
     "SET SESSION AUTHORIZATION"),
    ('RESET "role"', "role/*", "RESET ROLE"),
])
def test_quoted_setting_names_are_identity_changes(sql, resource, raw):
    (intent,) = from_sql(sql, dialect="postgres")
    assert (intent.action, intent.resource) == ("update", resource)
    assert intent.params["privilege"] is True
    assert intent.params["raw_action"] == raw


@pytest.mark.parametrize("sql,resource", [
    ("SELECT pg_catalog.set_config('role', 'admin', false)", "role/admin"),
    ("SELECT pg_catalog.\"set_config\"('role', 'admin', false)", "role/admin"),
    ("SELECT \"set_config\"('role', 'admin', false)", "role/admin"),
    ("SELECT set_config(('role'), ('admin'), false)", "role/admin"),
    ("SELECT set_config('session_authorization', 'admin', false)", "role/admin"),
    # not a plain literal: it may name the role setting, so fail safe
    ("SELECT set_config(lower('ROLE'), 'admin', false)", "role/*"),
    ("SELECT set_config(concat('ro', 'le'), 'admin', false)", "role/*"),
    ("SELECT set_config(name, 'admin', false) FROM t", "role/*"),
    ("SELECT set_config('role', (SELECT 'admin'), false)", "role/*"),
])
def test_set_config_variants_are_role_changes(sql, resource):
    roles = [i for i in from_sql(sql, dialect="postgres") if i.resource.startswith("role/")]
    assert [(i.action, i.resource) for i in roles] == [("update", resource)]
    assert roles[0].params["privilege"] is True


def test_set_config_of_another_setting_is_not_a_role_change():
    assert _summary("SELECT set_config('search_path', 'public', false)") == [("read", "table/*")]


def test_dml_in_ctes_and_main_statement_are_all_reported():
    assert _summary("WITH x AS (DELETE FROM allowed RETURNING *) DELETE FROM secret") == [
        ("delete", "table/allowed"), ("delete", "table/secret")
    ]
    assert _summary(
        "WITH d AS (DELETE FROM t RETURNING *) INSERT INTO archive SELECT * FROM d"
    ) == [("delete", "table/t"), ("put", "table/archive")]
    intents = from_sql("WITH a AS (INSERT INTO log VALUES (1)), b AS (UPDATE s SET x = 1 WHERE y) "
                       "DELETE FROM t WHERE id = 2")
    assert [(i.action, i.resource, i.params.get("unbounded")) for i in intents] == [
        ("delete", "table/t", False), ("update", "table/s", False), ("put", "table/log", None)
    ]
    assert all(i.params["cte"] is True for i in intents)


@pytest.mark.parametrize("sql,expected", [
    ("WITH x AS (SELECT 1) UPDATE users AS u SET pw = 'x'", [("update", "table/users")]),
    ("WITH x AS (SELECT 1) UPDATE ONLY users SET pw = 'x'", [("update", "table/users")]),
    ("WITH x AS (SELECT 1) UPDATE users u SET pw = 'x' FROM secrets",
     [("update", "table/users"), ("read", "table/secrets")]),
    ("WITH s AS (SELECT * FROM src) MERGE INTO users u USING s ON u.id = s.id "
     "WHEN MATCHED THEN DELETE", [("delete", "table/users"), ("read", "table/src")]),
    ("MERGE INTO users u USING src s ON u.id = s.id WHEN MATCHED THEN UPDATE SET a = 1 "
     "WHEN NOT MATCHED THEN INSERT VALUES (1)",
     [("update", "table/users"), ("put", "table/users"), ("read", "table/src")]),
    ("MERGE INTO users USING src ON true WHEN NOT MATCHED THEN INSERT VALUES (1)",
     [("put", "table/users"), ("read", "table/src")]),
    # a DML keyword whose target can't be read is still a write
    ("WITH x AS (SELECT 1) UPDATE SET a = 1", [("update", "unknown/*")]),
])
def test_with_main_statement_dml_is_a_write(sql, expected):
    assert _summary(sql) == expected


@pytest.mark.parametrize("alias", ["qualify", "set", "lock", "procedure", "minus", '"where"'])
def test_clause_words_used_as_aliases_do_not_end_a_comma_join(alias):
    assert _reads(f"SELECT * FROM products {alias}, users") == ["table/products", "table/users"]
    assert _reads(f"SELECT * FROM products AS {alias}, users") == [
        "table/products", "table/users"
    ]
    assert _reads(f"SELECT * FROM (SELECT * FROM a) {alias}, users") == [
        "table/a", "table/users"
    ]
    assert _reads(f"SELECT * FROM generate_series(1, 2) {alias}, users") == ["table/users"]


def test_mysql_lock_in_share_mode_after_a_table_still_locks():
    (intent,) = from_sql("SELECT * FROM t LOCK IN SHARE MODE", dialect="mysql")
    assert intent.params["lock_strength"] == "share"


@pytest.mark.parametrize("sql,expected", [
    ("SELECT 1 AS update INTO t FROM users", [("create", "table/t"), ("read", "table/users")]),
    ("SELECT 1 AS delete, 2 AS insert INTO t FROM users",
     [("create", "table/t"), ("read", "table/users")]),
    ("SELECT a AS into FROM users", [("read", "table/users")]),
    ("SELECT a, update FROM users", [("read", "table/users")]),
    ("SELECT t.update, t.delete FROM t", [("read", "table/t")]),
])
def test_keywords_as_column_labels_are_identifiers(sql, expected):
    assert _summary(sql) == expected


def test_dual_is_a_table_outside_mysql():
    assert _summary_in("SELECT * FROM allowed, dual", "postgres") == [
        ("read", "table/allowed"), ("read", "table/dual")
    ]
    assert _summary_in("SELECT 1 FROM dual", "mysql") == [("read", "table/*")]


@pytest.mark.parametrize("sql,dialect,expected", [
    ("DELETE FROM ONLY users", "postgres", [("delete", "table/users")]),
    ("WITH x AS (SELECT 1) DELETE FROM ONLY users WHERE id = 1", "postgres",
     [("delete", "table/users")]),
    ("DELETE IGNORE FROM users", "mysql", [("delete", "table/users")]),
    ("DELETE LOW_PRIORITY QUICK IGNORE FROM users WHERE id = 1", "mysql",
     [("delete", "table/users")]),
    ("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.id", "mysql",
     [("delete", "table/t1"), ("delete", "table/t2")]),
    ("TRUNCATE ONLY users", "postgres", [("delete", "table/users")]),
    ("TRUNCATE TABLE a, ONLY b *, s.c", "postgres",
     [("delete", "table/a"), ("delete", "table/b"), ("delete", "table/s.c")]),
    ("UPDATE LOW_PRIORITY IGNORE users SET a = 1", "mysql", [("update", "table/users")]),
    ("UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.a = t2.b", "mysql",
     [("update", "table/t1"), ("update", "table/t2")]),
    ("INSERT IGNORE INTO users VALUES (1)", "mysql", [("put", "table/users")]),
    ("INSERT OR REPLACE INTO users VALUES (1)", "sqlite",
     [("put", "table/users"), ("delete", "table/users")]),
    ("ALTER TABLE ONLY users ADD COLUMN x int", "postgres", [("update", "table/users")]),
])
def test_dml_modifiers_are_not_table_names(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


def test_delete_modifier_keeps_unbounded_flag():
    (intent,) = from_sql("DELETE IGNORE FROM users", dialect="mysql")
    assert intent.params["unbounded"] is True
    (intent,) = from_sql("DELETE FROM ONLY users WHERE id = 1")
    assert intent.params["unbounded"] is False


def test_unbounded_ignores_where_in_strings_and_subqueries():
    (intent,) = from_sql("DELETE FROM users RETURNING 'WHERE'")
    assert intent.params["unbounded"] is True
    (intent, _read) = from_sql("UPDATE t SET a = (SELECT 1 FROM s WHERE x)")
    assert intent.params["unbounded"] is True


@pytest.mark.parametrize("sql,expected", [
    ("DESCRIBE SELECT * FROM users", [("read", "table/users")]),
    ("DESC SELECT * FROM users JOIN orders ON true",
     [("read", "table/users"), ("read", "table/orders")]),
    ("DESCRIBE FORMAT=JSON SELECT * FROM users", [("read", "table/users")]),
    ("DESCRIBE users", [("read", "table/users")]),
])
def test_describe_of_a_statement_is_explain(sql, expected):
    assert _summary_in(sql, "mysql") == expected


def test_describe_analyze_runs_the_statement():
    (intent,) = from_sql("DESC ANALYZE DELETE FROM users", dialect="mysql")
    assert (intent.action, intent.resource) == ("delete", "table/users")
    assert intent.params["explain_analyze"] is True


@pytest.mark.parametrize("sql,expected", [
    ("WITH d AS (UPDATE logs SET a = 1 RETURNING *) SELECT * INTO newt FROM d",
     [("update", "table/logs"), ("create", "table/newt")]),
    ("WITH x AS (SELECT 'DELETE FROM users') SELECT * FROM x", [("read", "table/*")]),
    ("SELECT 'UPDATE users SET a = 1' FROM t", [("read", "table/t")]),
    ("SELECT * FROM t WHERE note = 'x' || 'INSERT INTO users'", [("read", "table/t")]),
])
def test_dml_found_by_tokens_not_inside_strings(sql, expected):
    assert _summary(sql) == expected


def test_rows_from_is_not_a_table():
    assert _reads("SELECT * FROM products, ROWS FROM (generate_series(1, 3)) g") == [
        "table/products"
    ]


def test_create_materialized_view():
    intents = from_sql("CREATE MATERIALIZED VIEW mv AS SELECT * FROM users")
    assert [(i.action, i.resource) for i in intents] == [
        ("create", "view/mv"), ("read", "table/users")
    ]
    assert intents[0].params["raw_action"] == "CREATE MATERIALIZED VIEW"


def test_insert_from_table_statement_reads_the_table():
    assert _summary("INSERT INTO t TABLE users") == [("put", "table/t"), ("read", "table/users")]


def test_into_outfile_double_quoted_path():
    (write, _read) = from_sql('SELECT * FROM users INTO OUTFILE "/tmp/x"', dialect="mysql")
    assert write.resource == "file//tmp/x"


@pytest.mark.parametrize("sql,expected", [
    ("TABLE users", [("read", "table/users")]),
    ("VALUES (1), (2)", [("read", "table/*")]),
    ("((SELECT * FROM a) UNION (SELECT * FROM b))", [("read", "table/a"), ("read", "table/b")]),
    ("(SELECT * FROM a) UNION ALL TABLE b", [("read", "table/a"), ("read", "table/b")]),
])
def test_top_level_query_forms_are_reads(sql, expected):
    assert _summary(sql) == expected


def test_comment_only_statement_stays_unclassified():
    assert _summary("SELECT 1; -- trailing") == [("read", "table/*"), ("update", "unknown/*")]


# --- size and nesting: linear, no recursion ---


def _timed(sql: str) -> tuple[float, list]:
    import time

    start = time.perf_counter()
    intents = from_sql(sql, dialect="postgres")
    return time.perf_counter() - start, intents


def test_one_megabyte_of_with_is_fast_and_fails_safe():
    elapsed, intents = _timed("WITH " * 200_000)
    assert elapsed < 5.0
    assert any(i.params.get("unclassified") for i in intents)


def test_twenty_thousand_ctes_are_fast():
    sql = "WITH " + ", ".join(
        f"c{i} AS (SELECT * FROM {'base' if i == 0 else f'c{i - 1}'})" for i in range(20_000)
    ) + " SELECT * FROM c19999"
    elapsed, intents = _timed(sql)
    assert elapsed < 5.0
    assert ("read", "table/base") in [(i.action, i.resource) for i in intents]


def test_statement_over_the_token_cap_adds_an_unclassified_write():
    sql = "INSERT INTO t VALUES " + ", ".join(["(1)"] * 40_000)
    intents = from_sql(sql)
    assert intents[0].resource == "table/t"
    assert intents[-1].params["unclassified"] is True
    assert intents[-1].params["too_large"] is True


def test_deep_nesting_does_not_recurse():
    elapsed, intents = _timed("SELECT * FROM " + "(" * 10_000)
    assert elapsed < 5.0
    assert [i.action for i in intents] == ["read"]
    sql = "SELECT * FROM " + "(SELECT * FROM " * 10_000 + "t" + ")" * 10_000
    elapsed, intents = _timed(sql)
    assert elapsed < 5.0
    assert [i.resource for i in intents] == ["table/t"]
    elapsed, intents = _timed("SELECT " + "set_config(" * 5_000 + "'role'" + ")" * 5_000)
    assert elapsed < 5.0


def test_repeated_explain_analyze_does_not_recurse():
    (intent,) = from_sql("EXPLAIN ANALYZE " * 1000 + "DELETE FROM users")
    assert (intent.action, intent.resource) == ("delete", "table/users")
    (intent,) = from_sql("EXPLAIN " * 1000 + "DELETE FROM users")
    assert (intent.action, intent.resource) == ("read", "table/users")


# --- 14. #58 review, round 2 --------------------------------------------------


@pytest.mark.parametrize("sql,expected", [
    # Postgres block comments nest: the comment ends at the second */
    ("SELECT 1 /* outer /* inner */ ' */; DROP TABLE secret; -- '",
     [("read", "table/*"), ("delete", "table/secret"), ("update", "unknown/*")]),
    ("SELECT 1 /* a /* b /* c */ */ */ ; SELECT * FROM users",
     [("read", "table/*"), ("read", "table/users")]),
    ("SELECT 1 /* a /* b */ still comment */ FROM users", [("read", "table/users")]),
])
def test_postgres_block_comments_nest(sql, expected):
    assert _summary_in(sql, "postgres") == expected


def test_mysql_and_sqlite_block_comments_do_not_nest():
    sql = "SELECT 1 /* a /* b */ FROM users"
    assert _summary_in(sql, "mysql") == [("read", "table/users")]
    assert _summary_in(sql, "sqlite") == [("read", "table/users")]


def test_generic_nested_comment_is_ambiguous():
    intents = from_sql("SELECT 1 /* outer /* inner */ ' */; DROP TABLE secret; -- '")
    flagged = [i for i in intents if i.params.get("ambiguous_comment")]
    assert [(i.action, i.resource) for i in flagged] == [("update", "unknown/*")]
    assert flagged[0].params["unclassified"] is True


@pytest.mark.parametrize("setting", [
    "U&'\\0072ole'", "E'rol\\145'", "E'\\x72ole'", "U&'rol\\0065'", "U&'rol!0065' UESCAPE '!'",
    "U&'\\+000072ole'", "E'search_path'",
])
def test_escaped_set_config_setting_fails_safe(setting):
    intents = from_sql(f"SELECT set_config({setting}, 'admin', false)", dialect="postgres")
    roles = [(i.action, i.resource) for i in intents if i.resource.startswith("role/")]
    assert roles == [("update", "role/*")]


@pytest.mark.parametrize("sql,resource", [
    ("SELECT set_config('role', U&'\\0061dmin', false)", "role/admin"),
    ("SELECT set_config('role', E'adm\\151n', false)", "role/admin"),
    ("SET ROLE U&'\\0061dmin'", "role/admin"),
    ("SET ROLE E'adm\\x69n'", "role/admin"),
    ("SET ROLE U&'!0061dmin' UESCAPE '!'", "role/admin"),
])
def test_escaped_role_names_are_decoded(sql, resource):
    intents = from_sql(sql, dialect="postgres")
    assert [i.resource for i in intents if i.resource.startswith("role/")] == [resource]


@pytest.mark.parametrize("sql", [
    'SELECT * FROM U&"\\0073ecret"',
    "SELECT * FROM U&\"!0073ecret\" UESCAPE '!'",
    'SELECT * FROM allowed JOIN U&"secr\\0065t" ON true',
])
def test_unicode_escaped_identifiers_are_decoded(sql):
    assert "table/secret" in _reads(sql)


@pytest.mark.parametrize("sql,expected", [
    ("DELETE s FROM secret AS s JOIN allowed AS a ON s.id = a.id",
     [("delete", "table/secret"), ("read", "table/allowed")]),
    ("DELETE s FROM secret s JOIN allowed a ON s.id = a.id",
     [("delete", "table/secret"), ("read", "table/allowed")]),
    ("DELETE s, a FROM secret s JOIN allowed a ON s.id = a.id",
     [("delete", "table/secret"), ("delete", "table/allowed")]),
    ("DELETE FROM a1 USING t1 AS a1 JOIN t2", [("delete", "table/t1"), ("read", "table/t2")]),
    ("DELETE t1 FROM t1 JOIN t2 ON true", [("delete", "table/t1"), ("read", "table/t2")]),
    # names no table or alias: every FROM table may be the target
    ("DELETE x FROM secret JOIN allowed ON true",
     [("delete", "table/secret"), ("delete", "table/allowed")]),
])
def test_mysql_delete_aliases_resolve_to_tables(sql, expected):
    assert _summary_in(sql, "mysql") == expected


@pytest.mark.parametrize("sql,dialect,raw", [
    ("INSERT INTO secret(id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = 2", "postgres",
     "ON CONFLICT DO UPDATE"),
    ("INSERT INTO secret VALUES (1) ON DUPLICATE KEY UPDATE id = 2", "mysql",
     "ON DUPLICATE KEY UPDATE"),
    ("INSERT INTO secret VALUES (1) ON CONFLICT(id) DO UPDATE SET a = 1", "sqlite",
     "ON CONFLICT DO UPDATE"),
])
def test_upserts_are_also_updates(sql, dialect, raw):
    put, update = from_sql(sql, dialect=dialect)
    assert (put.action, put.resource) == ("put", "table/secret")
    assert (update.action, update.resource) == ("update", "table/secret")
    assert update.params["upsert"] is True
    assert update.params["raw_action"] == raw


def test_on_conflict_do_nothing_is_only_a_put():
    assert _summary("INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING") == [("put", "table/t")]


@pytest.mark.parametrize("sql,dialect,expected", [
    ("TABLE users INTO OUTFILE '/tmp/x'", "mysql",
     [("update", "file//tmp/x"), ("read", "table/users")]),
    ("VALUES ROW(1) INTO OUTFILE '/tmp/x'", "mysql", [("update", "file//tmp/x")]),
    ("(SELECT * FROM users) INTO OUTFILE '/tmp/x'", "mysql",
     [("update", "file//tmp/x"), ("read", "table/users")]),
    ("SELECT * FROM (SELECT * FROM users INTO OUTFILE '/tmp/x') s", "mysql",
     [("update", "file//tmp/x"), ("read", "table/users")]),
    ("(SELECT * INTO t FROM users)", "postgres", [("create", "table/t"), ("read", "table/users")]),
    ("((SELECT * INTO t FROM users))", "postgres",
     [("create", "table/t"), ("read", "table/users")]),
    # a subquery can't SELECT INTO: no create
    ("SELECT * FROM (SELECT * INTO t FROM x) s", "postgres", [("read", "table/x")]),
])
def test_into_after_table_values_and_parens(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


@pytest.mark.parametrize("sql,expected", [
    ("DROP TABLE tmp_x, users", [("delete", "table/tmp_x"), ("delete", "table/users")]),
    ("DROP TABLE IF EXISTS a, s.users CASCADE",
     [("delete", "table/a"), ("delete", "table/s.users")]),
    ("DROP VIEW v1, v2", [("delete", "view/v1"), ("delete", "view/v2")]),
    ("DROP INDEX CONCURRENTLY IF EXISTS i1, i2",
     [("delete", "index/i1"), ("delete", "index/i2")]),
    ("DROP MATERIALIZED VIEW mv", [("delete", "view/mv")]),
    ("DROP TEMPORARY TABLE t", [("delete", "table/t")]),
    ("DROP FUNCTION f(int, text), g()", [("delete", "function/f"), ("delete", "function/g")]),
])
def test_drop_lists_delete_every_name(sql, expected):
    assert _summary(sql) == expected


def test_drop_list_with_cascade_marks_every_name():
    intents = from_sql("DROP TABLE a, users CASCADE")
    assert all(i.params["cascade"] is True and i.params["unbounded"] is True for i in intents)
    assert intents[1].metadata.get("schema") is None


def test_drop_schema_list_cascades_each_schema():
    intents = from_sql("DROP SCHEMA a, prod CASCADE")
    assert [(i.action, i.resource, i.metadata.get("schema")) for i in intents] == [
        ("delete", "schema/a", None), ("delete", "table/*", "a"),
        ("delete", "schema/prod", None), ("delete", "table/*", "prod"),
    ]


def test_drop_list_is_blocked_end_to_end():
    interceptor = AegisInterceptor(_load_example_store())
    intents = from_sql("DROP DATABASE a, prod")
    verdicts = [interceptor.intercept(i, now=NOW).verdict for i in intents]
    assert verdicts.count("BLOCK") >= 2


def test_unclosed_set_config_is_fast_and_fails_safe():
    elapsed, intents = _timed("SELECT " + "set_config(" * 50_000)
    assert elapsed < 5.0
    assert ("update", "role/*") in [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("piece", [
    "set_config(", "WITH x AS (", "FOR UPDATE (", "UPDATE t ", "DELETE x, ", "EXPLAIN (",
    "INTO OUTFILE ", "USE INDEX (", "THEN DELETE ", "DROP TABLE a, ", "/* /* ", "[a] ",
])
def test_repeated_fragments_stay_linear(piece):
    for dialect in ("postgres", "mysql", "sqlite", "generic"):
        import time

        start = time.perf_counter()
        from_sql("SELECT " + piece * 50_000, dialect=dialect)
        assert time.perf_counter() - start < 5.0, (piece, dialect)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM products, [users]",
    "SELECT * FROM products JOIN [users] ON 1",
])
def test_bracket_identifiers(sql):
    assert _summary_in(sql, "sqlite") == [("read", "table/products"), ("read", "table/users")]
    assert _summary_in(sql, "generic") == [("read", "table/products"), ("read", "table/users")]


def test_postgres_array_subscript_is_not_a_table():
    assert _summary_in("SELECT a[1] FROM t", "postgres") == [("read", "table/t")]


@pytest.mark.parametrize("sql", [
    "SELECT * FROM products x FORCE INDEX FOR ORDER BY (i), users",
    "SELECT * FROM products USE INDEX FOR JOIN (i) JOIN users ON true",
    "SELECT * FROM products IGNORE KEY FOR GROUP BY (i), users",
    "SELECT * FROM products FORCE INDEX (i), users",
])
def test_mysql_index_hints_do_not_end_the_from_list(sql):
    assert _summary_in(sql, "mysql") == [("read", "table/products"), ("read", "table/users")]


@pytest.mark.parametrize("sql,expected", [
    ("UPDATE OR IGNORE products SET a = 1", [("update", "table/products")]),
    # round 4: OR REPLACE deletes the rows the new values conflict with
    ("UPDATE OR REPLACE products SET a = 1 WHERE id = 1",
     [("update", "table/products"), ("delete", "table/products")]),
])
def test_sqlite_update_or_conflict_clause(sql, expected):
    assert _summary_in(sql, "sqlite") == expected


@pytest.mark.parametrize("sql", [
    "SELECT * FROM products WHERE a = 'x\\''; DROP TABLE users",
    'SELECT * FROM products WHERE a = "x\\""; DROP TABLE users',
])
def test_generic_backslash_before_quote_is_ambiguous(sql):
    intents = from_sql(sql)  # dialect generic
    flagged = [i for i in intents if i.params.get("ambiguous_escape")]
    assert [(i.action, i.resource) for i in flagged] == [("update", "unknown/*")]
    assert flagged[0].params["unclassified"] is True


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT 'C:\\path' FROM t", "generic"),
    ("SELECT 'x\\'' FROM t", "mysql"),
    ("SELECT 'x\\' FROM t", "postgres"),
])
def test_unambiguous_backslashes_are_not_flagged(sql, dialect):
    assert not any(i.params.get("ambiguous_escape") for i in from_sql(sql, dialect=dialect))


@pytest.mark.parametrize("sql,dialect,expected", [
    ("CREATE INDEX CONCURRENTLY idx ON t (a)", "postgres", [("create", "index/idx")]),
    ("CREATE OR REPLACE ALGORITHM=MERGE VIEW v AS SELECT * FROM users", "mysql",
     [("create", "view/v"), ("read", "table/users")]),
    ("CREATE DEFINER='root'@'%' PROCEDURE p() BEGIN END", "mysql", [("create", "procedure/p")]),
    ("CREATE DEFINER = CURRENT_USER SQL SECURITY INVOKER VIEW v AS SELECT 1", "mysql",
     [("create", "view/v")]),
    ("SHOW TABLES FROM db", "mysql", [("read", "table/*")]),
    ("SHOW FULL COLUMNS FROM users", "mysql", [("read", "table/users")]),
    ("SHOW INDEX IN users", "mysql", [("read", "table/users")]),
])
def test_create_and_show_forms(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


def test_begin_atomic_body_dml_is_reported():
    sql = ("CREATE FUNCTION f() RETURNS int LANGUAGE sql "
           "BEGIN ATOMIC DELETE FROM t; SELECT 1; END")
    summary = _summary_in(sql, "postgres")
    assert summary[:2] == [("create", "function/f"), ("delete", "table/t")]
    # the body is split on ';' (safe side): the trailing END is unclassified
    assert summary[-1] == ("update", "unknown/*")


def test_begin_atomic_does_not_swallow_a_following_statement():
    intents = from_sql("SELECT begin atomic; DROP TABLE users", dialect="postgres")
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


# --- 15. #58 review, round 3 --------------------------------------------------


@pytest.mark.parametrize("sql,dialect,expected", [
    # a subquery's alias never redirects the outer DELETE's target
    ("DELETE FROM secret WHERE EXISTS (SELECT 1 FROM allowed AS secret)", "postgres",
     [("delete", "table/secret"), ("read", "table/allowed")]),
    ("DELETE FROM secret WHERE EXISTS (SELECT 1 FROM allowed AS secret)", "mysql",
     [("delete", "table/secret"), ("read", "table/allowed")]),
    ("DELETE p FROM products p WHERE p.id IN (SELECT id FROM users p)", "mysql",
     [("delete", "table/products"), ("read", "table/users")]),
    ("DELETE FROM p USING products AS p WHERE p.id IN (SELECT id FROM users p)", "mysql",
     [("delete", "table/products"), ("read", "table/users")]),
    ("DELETE x FROM products x WHERE EXISTS (SELECT 1 FROM (SELECT 1 FROM users x) y)", "mysql",
     [("delete", "table/products"), ("read", "table/users")]),
    # a plain DELETE FROM t ... USING keeps t when t is no alias
    ("DELETE FROM t1 USING t2 WHERE t1.id = t2.id", "mysql",
     [("delete", "table/t1"), ("read", "table/t2")]),
    # one alias for two tables in the same block: any of them
    ("DELETE s FROM secret s JOIN allowed s ON true", "mysql",
     [("delete", "table/secret"), ("delete", "table/allowed")]),
])
def test_delete_aliases_are_scoped_to_the_operation(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


@pytest.mark.parametrize("sql,dialect,expected", [
    ("SELECT * FROM products WHERE a = U&'x\\''; DROP TABLE users", "mysql",
     [("read", "table/products"), ("delete", "table/users")]),
    ("SELECT * FROM products WHERE a = U&'x\\''; DROP TABLE users", "postgres",
     [("read", "table/products")]),
])
def test_u_amp_strings_only_outside_mysql(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


def test_u_amp_through_mysql_wrapper():
    intents = from_mysql(["mysql", "-e", "SELECT * FROM products WHERE a = U&'x\\''; "
                                         "DROP TABLE users"])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("sql", [
    "SELECT * FROM U&\"!0073ecret\" /*comment*/ UESCAPE '!'",
    "SELECT * FROM U&\"!0073ecret\" UESCAPE /* c /* nested */ */ '!'",
    "SELECT * FROM U&\"!0073ecret\" -- c\n UESCAPE -- d\n '!'",
])
def test_uescape_found_across_comments(sql):
    assert _summary_in(sql, "postgres") == [("read", "table/secret")]


def test_long_multi_table_update_reports_every_target():
    predicates = " AND ".join(["a.id = b.id"] * 40)
    sql = (f"UPDATE allowed a JOIN allowed b ON {predicates} "
           "JOIN secret s ON s.id = a.id SET s.id = 0")
    summary = _summary_in(sql, "mysql")
    assert ("update", "table/secret") in summary
    assert ("read", "table/secret") not in summary


def test_multi_table_update_walk_stays_linear():
    import time

    start = time.perf_counter()
    from_sql("UPDATE t " + "JOIN a ON (x) " * 30_000 + "SET a = 1", dialect="mysql")
    from_sql("UPDATE t ) " * 30_000, dialect="mysql")
    assert time.perf_counter() - start < 5.0


@pytest.mark.parametrize("sql,dialect,raw", [
    ("INSERT OR REPLACE INTO products VALUES (1)", "sqlite", "INSERT OR REPLACE"),
    ("REPLACE INTO products VALUES (1)", "mysql", "REPLACE"),
    ("REPLACE products SET a = 1", "mysql", "REPLACE"),
])
def test_replace_deletes_conflicting_rows(sql, dialect, raw):
    put, delete = from_sql(sql, dialect=dialect)
    assert (put.action, put.resource) == ("put", "table/products")
    assert (delete.action, delete.resource) == ("delete", "table/products")
    assert delete.params["upsert"] is True
    assert delete.params["raw_action"] == raw


def test_replace_function_is_not_a_statement():
    assert _summary_in("SELECT REPLACE(a, 'x', 'y') FROM t", "mysql") == [("read", "table/t")]


def test_insert_or_ignore_is_only_a_put():
    assert _summary_in("INSERT OR IGNORE INTO t VALUES (1)", "sqlite") == [("put", "table/t")]


@pytest.mark.parametrize("sql,expected", [
    ("WITH x AS (SELECT 1) (SELECT * INTO t FROM x)", [("create", "table/t")]),
    ("WITH x AS (SELECT * FROM users) ((SELECT * INTO t FROM x))",
     [("create", "table/t"), ("read", "table/users")]),
    # a subquery after the WITH list is not the statement's own query
    ("WITH x AS (SELECT 1) SELECT * FROM (SELECT * INTO t FROM x) s", [("read", "table/*")]),
])
def test_select_into_in_parens_after_with(sql, expected):
    assert _summary(sql) == expected


def test_drop_list_deduplicates_names():
    assert _summary("DROP TABLE users, users, a") == [
        ("delete", "table/users"), ("delete", "table/a")
    ]
    assert len(from_sql("DROP SCHEMA prod, prod")) == 2


# --- council round 4 ---------------------------------------------------------------


@pytest.mark.parametrize("argv", [
    ["psql", "-c", "SELECT 1 --", "-c", "DROP TABLE users"],
    ["psql", "-c", "SELECT '", "-c", "DROP TABLE users"],
    ["mysql", "-e", "SELECT 1 #", "-e", "DROP TABLE users"],
    ["sqlite3", "db", "SELECT 1 --", "DROP TABLE users"],
])
def test_each_command_text_is_classified_on_its_own(argv):
    parse = {"psql": from_psql, "mysql": from_mysql, "sqlite3": from_sqlite3}[argv[0]]
    assert ("delete", "table/users") in [(i.action, i.resource) for i in parse(argv)]


@pytest.mark.parametrize("dialect,expected", [
    ("mariadb", "mysql"), ("MySQL", "mysql"), ("PostgreSQL", "postgres"),
    ("Postgres", "postgres"), ("sqlite3", "sqlite"), ("", "generic"), ("oracle", "generic"),
])
def test_dialect_names_are_normalised_and_unknown_ones_read_as_generic(dialect, expected):
    (intent, *_rest) = from_sql("SELECT 1", dialect=dialect)
    assert intent.metadata["dialect"] == expected


def test_an_unknown_dialect_does_not_hide_a_statement():
    summary = _summary_in("SELECT 'a\\''; DROP TABLE users", "mariadb")
    assert ("delete", "table/users") in summary


@pytest.mark.parametrize("sql,dialect,tables", [
    ("SELECT * FROM (a, users)", "mysql", ["a", "users"]),
    ("SELECT * FROM a JOIN (b, users) ON 1", "mysql", ["a", "b", "users"]),
    ("SELECT * FROM a CROSS JOIN (b, c, users)", "mysql", ["a", "b", "c", "users"]),
    ("SELECT * FROM a JOIN (b, (c, users)) ON 1", "mysql", ["a", "b", "c", "users"]),
    ("SELECT * FROM (a, users)", "sqlite", ["a", "users"]),
    ("SELECT * FROM products offset, users", "sqlite", ["products", "users"]),
    ("SELECT * FROM products returning, users", "mysql", ["products", "users"]),
    ("SELECT password_hash, 1 rows FROM users", "postgres", ["users"]),
    ("SELECT password_hash, 0 delete FROM users", "postgres", ["users"]),
    ("SELECT query, calls, rows FROM pg_stat_statements", "postgres", ["pg_stat_statements"]),
    ("WITH x AS (SELECT 1) TABLE users", "postgres", ["users"]),
])
def test_round4_reads_every_table(sql, dialect, tables):
    assert _summary_in(sql, dialect) == [("read", f"table/{t}") for t in tables]


@pytest.mark.parametrize("sql,dialect,expected", [
    ("DELETE a FROM (a, users)", "mysql", [("delete", "table/a"), ("read", "table/users")]),
    ("DELETE FROM a USING a JOIN (b, users) ON 1", "mysql",
     [("delete", "table/a"), ("read", "table/b"), ("read", "table/users")]),
    ("UPDATE products p INNER JOIN (secret s) ON 1 SET s.x=1", "mysql",
     [("update", "table/products"), ("update", "table/secret")]),
    ("UPDATE products p JOIN (secret s JOIN other o ON 1) ON 1 SET o.x=1", "mysql",
     [("update", "table/products"), ("update", "table/secret"), ("update", "table/other")]),
    ("DELETE a FROM a JOIN b USING (id)", "mysql", [("delete", "table/a"), ("read", "table/b")]),
    ("SELECT * FROM a WHERE x IS DISTINCT FROM y", "postgres", [("read", "table/a")]),
    ("SELECT a, b INTO STRICT x, y FROM t", "postgres", [("read", "table/t")]),
])
def test_round4_writes_and_reads(sql, dialect, expected):
    assert _summary_in(sql, dialect) == expected


@pytest.mark.parametrize("tail,expected", [
    ("SEARCH DEPTH FIRST BY id SET ord DELETE FROM users", ("delete", "table/users")),
    ("CYCLE id SET is_cycle USING path DELETE FROM users", ("delete", "table/users")),
    ("CYCLE id SET c TO true DEFAULT false USING p UPDATE users SET x=1",
     ("update", "table/users")),
    ("SEARCH BREADTH FIRST BY id SET ord INSERT INTO users SELECT * FROM t",
     ("put", "table/users")),
])
def test_a_dml_after_a_cte_search_or_cycle_clause(tail, expected):
    sql = ("WITH RECURSIVE t(id) AS (SELECT 1 UNION ALL SELECT id+1 FROM t WHERE id<3) "
           + tail)
    assert expected in _summary_in(sql, "postgres")


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "generic"])
def test_a_quote_after_at_is_an_ordinary_string_outside_mysql(dialect):
    summary = _summary_in("SELECT @'a\\'; DELETE FROM users; SELECT 'b'", dialect)
    assert ("delete", "table/users") in summary


@pytest.mark.parametrize("argv", [
    ["mysql", "-e", "SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE users; -- '"],
    ["mysql", "-e", "SET SESSION sql_mode='ANSI_QUOTES'; SELECT \"a\\\"; DROP TABLE users; -- \""],
    ["mysql", "-e", "SET @@sql_mode = ''"],
    ["mysql", "-e", "SET NAMES gbk"],
    ["mysql", "-e", "SET CHARACTER SET sjis"],
    ["psql", "-c", "SET standard_conforming_strings = off", "-c", "SELECT 1"],
    ["psql", "-c", "SELECT set_config('standard_conforming_strings', 'off', false)"],
])
def test_a_setting_that_changes_how_strings_are_read_is_unclassified(argv):
    parse = {"psql": from_psql, "mysql": from_mysql}[argv[0]]
    flagged = [i for i in parse(argv) if i.params.get("changes_lexing")]
    assert flagged and flagged[0].params["unclassified"] is True


@pytest.mark.parametrize("sql", ["SET NAMES utf8mb4", "SET CHARACTER SET utf8",
                                 "SET client_encoding TO 'UTF8'", "SET search_path = x"])
def test_safe_settings_stay_session_reads(sql):
    assert _summary_in(sql, "mysql") == [("read", "session/*")]


@pytest.mark.parametrize("sql", [
    "DELETE " + ", ".join(f"a{i}" for i in range(4000)) + " FROM "
    + ", ".join(f"t{i}" for i in range(4000)) + " WHERE 1=0",
    "DELETE " + ", ".join(f"t{i}" for i in range(4000)) + " FROM t0 "
    + " ".join(f"JOIN t{i} ON 1" for i in range(1, 4000)),
    "SELECT 1 " + "LOCK IN SHARE MODE " * 6000,
])
def test_round4_inputs_stay_linear(sql):
    import time
    start = time.perf_counter()
    from_sql(sql, dialect="mysql")
    assert time.perf_counter() - start < 3


# --- council round 5 ---------------------------------------------------------------


@pytest.mark.parametrize("sql,expected", [
    ("MERGE INTO a USING b ON a.id=b.id WHEN MATCHED THEN UPDATE SET x=1 "
     "WHEN NOT MATCHED THEN INSERT VALUES (1)",
     [("update", "table/a"), ("put", "table/a"), ("read", "table/b")]),
    ("MERGE INTO a USING b ON true WHEN MATCHED THEN DELETE "
     "WHEN NOT MATCHED THEN INSERT VALUES (1)",
     [("delete", "table/a"), ("put", "table/a"), ("read", "table/b")]),
    ("MERGE INTO a USING b ON true WHEN MATCHED THEN UPDATE SET x=1 WHEN NOT MATCHED THEN "
     "INSERT VALUES (1) WHEN NOT MATCHED BY SOURCE THEN DELETE",
     [("delete", "table/a"), ("update", "table/a"), ("put", "table/a"), ("read", "table/b")]),
])
def test_merge_reports_each_when_action(sql, expected):
    assert _summary_in(sql, "postgres") == expected


@pytest.mark.parametrize("dialect,deleted", [
    ("postgres", True), ("generic", True), ("mysql", False), ("sqlite", False),
])
def test_a_carriage_return_ends_a_line_comment_in_postgres(dialect, deleted):
    summary = _summary_in("SELECT 1 -- c\r; DROP TABLE x", dialect)
    assert (("delete", "table/x") in summary) is deleted


@pytest.mark.parametrize("sql,expected", [
    ("CREATE RULE r AS ON SELECT TO a DO INSTEAD DELETE FROM secret",
     [("create", "rule/r"), ("delete", "table/secret")]),
    ("CREATE RULE r AS ON INSERT TO a DO ALSO INSERT INTO log VALUES (1)",
     [("create", "rule/r"), ("put", "table/log")]),
    ("SELECT a INTO LOCAL TEMP t FROM b", [("create", "table/t"), ("read", "table/b")]),
])
def test_round5_rule_actions_and_into_targets(sql, expected):
    assert _summary_in(sql, "postgres") == expected


@pytest.mark.parametrize("argv", [
    ["psql", "-Atc", "DROP TABLE x"], ["psql", "-cDROP TABLE x"],
    ["psql", "-At", "-c", "DROP TABLE x"], ["mysql", "-BNe", "DROP TABLE x"],
    ["mysql", "-eDROP TABLE x"], ["mysql", "-uroot", "-e", "DROP TABLE x"],
])
def test_bundled_and_attached_command_options(argv):
    parse = from_psql if argv[0] == "psql" else from_mysql
    assert ("delete", "table/x") in [(i.action, i.resource) for i in parse(argv)]


def test_an_option_value_bundle_is_not_a_command_option():
    # -dcars is the database "cars", -psecret a password: no SQL in them
    assert [(i.action, i.resource) for i in from_psql(["psql", "-dcars", "-c", "SELECT 1"])] \
        == [("read", "table/*")]
    assert [(i.action, i.resource) for i in from_mysql(["mysql", "-psecret", "-e", "SELECT 1"])] \
        == [("read", "table/*")]


def test_a_trailing_command_option_is_unknown_sql():
    intents = from_psql(["psql", "-c", "SELECT 1", "-c"])
    assert intents[-1].resource == "unknown/*"
    assert intents[-1].params["unclassified"] is True


@pytest.mark.parametrize("sql", [
    "SELECT 'a\\'; SELECT 1 FROM t'; DROP TABLE users",
    'SELECT "a\\"; SELECT 1',
    "SELECT * FROM t WHERE p = 'C:\\' -- '; DROP TABLE users",
])
def test_generic_string_ending_in_a_backslash_is_ambiguous(sql):
    assert any(i.params.get("ambiguous_escape") for i in from_sql(sql))


def test_generic_even_backslashes_are_not_ambiguous():
    assert _summary_in("SELECT 'a\\\\' FROM t", "generic") == [("read", "table/t")]


@pytest.mark.parametrize("argv", [
    ["psql", "-c", "SELECT 1", "-f", "drop.sql"], ["psql", "-f", "drop.sql", "-c", "SELECT 1"],
    ["psql", "-c", "SELECT 1", "--file=drop.sql"], ["psql", "-f", "drop.sql", "-f", "none.sql"],
    ["sqlite3", "-init", "drop.sql", "db", "SELECT 1"],
])
def test_every_script_file_is_read(tmp_path, monkeypatch, argv):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "drop.sql").write_text("DROP TABLE users;\n")
    parse = from_psql if argv[0] == "psql" else from_sqlite3
    assert ("delete", "table/users") in [(i.action, i.resource) for i in parse(argv)]


def test_mysql_dash_f_is_force_not_a_file():
    intents = from_mysql(["mysql", "-f", "-e", "DROP TABLE users"])
    assert [(i.action, i.resource) for i in intents] == [("delete", "table/users")]


@pytest.mark.parametrize("sql,expected", [
    ("EXPLAIN QUERY PLAN SELECT * FROM users", [("read", "table/users")]),
])
def test_sqlite_explain_query_plan(sql, expected):
    assert _summary_in(sql, "sqlite") == expected


def test_update_join_using_columns_are_not_tables():
    assert _summary_in("UPDATE t1 LEFT JOIN t2 USING (id) SET t1.a = 1, t2.b = 2", "mysql") \
        == [("update", "table/t1"), ("update", "table/t2")]


def test_many_dml_ops_stay_linear():
    import time
    sql = "WITH " + ", ".join(f"c{i} AS (DELETE FROM t{i} RETURNING 1)" for i in range(12000))
    start = time.perf_counter()
    from_sql(sql + " SELECT 1", dialect="postgres")
    assert time.perf_counter() - start < 3


def test_mysql_joins_its_execute_texts():
    # the client joins every -e with a space: a quote open in one runs into the next
    intents = from_mysql(["mysql", "t", "-e", "SELECT 'a", "-e",
                          "SELECT '; DELETE FROM users; -- '"])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("sql,dialect,deleted", [
    ("SELECT 1\\G DELETE FROM users", "mysql", True),
    ("SELECT 1 \\g\nDELETE FROM users;", "postgres", True),
])
def test_client_statement_ends(sql, dialect, deleted):
    assert (("delete", "table/users") in _summary_in(sql, dialect)) is deleted


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT 1 \\! echo x", "mysql"), ("SELECT 1 \\! echo x", "postgres"),
    ("\\copy t to x", "postgres"), ("SELECT 1 \\g |rm x", "postgres"),
    ("\\. evil.sql", "mysql"), (".shell rm -rf x", "sqlite"),
])
def test_client_commands_are_unclassified(sql, dialect):
    assert any(i.params.get("client_command") for i in from_sql(sql, dialect=dialect))


@pytest.mark.parametrize("sql,expected", [
    ("SELECT * FROM users u JOIN 2fa_codes c ON c.uid=u.id",
     [("read", "table/users"), ("read", "table/2fa_codes")]),
    ("SELECT * FROM app.2fa_codes", [("read", "table/app.2fa_codes")]),
    ("SELECT 1, 2.5, 1e5, 0x1F, .5 FROM t", [("read", "table/t")]),
    ("SELECT * FROM { OJ users LEFT OUTER JOIN secret ON 1=1 }",
     [("read", "table/users"), ("read", "table/secret")]),
    ("START REPLICA", [("update", "unknown/*")]),
    ("START TRANSACTION", [("read", "session/*")]),
])
def test_round5_mysql_names_and_statements(sql, expected):
    assert _summary_in(sql, "mysql") == expected


def test_mysql_init_command_is_sql():
    intents = from_mysql(["mysql", "t", "--init-command=DELETE FROM users", "-e", "SELECT 1"])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


def test_psql_variables_next_to_a_script_are_sql():
    intents = from_psql(["psql", "-v", "x=1; DELETE FROM users", "-f", "q.sql"])
    assert ("delete", "table/users") in [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("sql,dialect", [
    ("WITH " + ", ".join(f"c{i} AS (DELETE zz FROM t{i})" for i in range(3000)) + " SELECT 1",
     "mysql"),
    ("SELECT " + "(WITH a AS (SELECT 1) SEARCH " * 4000 + "1" + ")" * 4000, "postgres"),
])
def test_round5_inputs_stay_linear(sql, dialect):
    import time
    start = time.perf_counter()
    from_sql(sql, dialect=dialect)
    assert time.perf_counter() - start < 3



def _actions(intents):
    return [(i.action, i.resource) for i in intents]


@pytest.mark.parametrize("flags", [["-csv"], ["-batch"], ["-echo"], ["-column"],
                                   ["-header", "-csv"], ["-separator", "|"], ["-cmd", ".mode csv"]])
def test_sqlite3_single_dash_options_keep_the_sql_arguments(flags):
    intents = from_sqlite3(["sqlite3", *flags, "app.db", "DELETE FROM users"])
    assert _actions(intents) == [("delete", "table/users")]
    assert intents[0].metadata.get("database") == "app.db"


def test_sqlite3_cmd_is_sql_that_runs_first():
    intents = from_sqlite3(["sqlite3", "-cmd", "DROP TABLE users", "app.db", "SELECT 1 FROM t"])
    assert ("delete", "table/users") in _actions(intents)
    intents = from_sqlite3(["sqlite3", "-cmd", ".shell rm -rf x", "app.db", "SELECT 1 FROM t"])
    assert any(i.params.get("unclassified") for i in intents)


def test_sqlite3_init_directory_is_an_opaque_script(tmp_path):
    intents = from_sqlite3(["sqlite3", "-init", str(tmp_path), "app.db", "SELECT 1"])
    script = [i for i in intents if i.resource == f"script/{tmp_path.name}"]
    assert script and script[0].params["unclassified"]


@pytest.mark.parametrize("argv", [["mysql", "-fe", "DELETE FROM users"],
                                  ["mysql", "-vvve", "DELETE FROM users"],
                                  ["psql", "-Sc", "DELETE FROM users"]])
def test_bundles_with_letters_that_take_no_value(argv):
    parse = from_mysql if argv[0] == "mysql" else from_psql
    assert _actions(parse(argv)) == [("delete", "table/users")]


@pytest.mark.parametrize("sql", ["SELECT * FROM users WHERE x IN secrets",
                                 "UPDATE users SET a = 1 WHERE a IN secrets",
                                 "DELETE FROM users WHERE a NOT IN main.secrets"])
def test_sqlite_in_table_reads_the_table(sql):
    resources = [i.resource for i in from_sql(sql, dialect="sqlite")]
    assert any(r in ("table/secrets", "table/main.secrets") for r in resources)


@pytest.mark.parametrize("sql", ["SELECT * FROM users \\g /home/u/.bashrc",
                                 "SELECT 1 \\gx /tmp/out",
                                 "SELECT 'touch x' \\g (tuples_only=on format=unaligned) |sh"])
def test_psql_g_with_an_argument_is_a_client_command(sql):
    assert any(i.params.get("unclassified") for i in from_sql(sql, dialect="postgres"))


def test_psql_bare_g_ends_the_statement():
    intents = from_sql("SELECT * FROM users \\g\nDELETE FROM t", dialect="postgres")
    assert _actions(intents) == [("read", "table/users"), ("delete", "table/t")]


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT 1 AS x\u00a0$a$; DROP TABLE users; SELECT 1 AS y\u00a0$a$", "postgres"),
    ("SELECT 1 AS x\u3000$a$; DROP TABLE users; SELECT 1 AS y\u3000$a$", "postgres"),
    ("SELECT 1 FROM t WHERE 1 --\u00a0; DROP TABLE users", "mysql"),
])
def test_unicode_spaces_are_not_whitespace(sql, dialect):
    assert ("delete", "table/users") in _actions(from_sql(sql, dialect=dialect))


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
def test_replace_after_a_with_list_is_a_write(dialect):
    sql = "WITH x AS (SELECT 1) REPLACE INTO secret SELECT * FROM x"
    assert ("put", "table/secret") in _actions(from_sql(sql, dialect=dialect))


def test_sqlite_format_dot_commands_are_not_client_commands():
    intents = from_sql(".mode csv\n.headers on\nSELECT * FROM t", dialect="sqlite")
    assert _actions(intents) == [("read", "table/t")]


@pytest.mark.parametrize("sql", [
    "UPDATE a JOIN (" * 20000 + "b" + ")" * 20000 + " SET x = 1",
    "UPDATE a JOIN (" * 20000 + "b SET x = 1" + ")" * 20000,
])
def test_nested_update_join_groups_stay_linear(sql):
    import time
    start = time.perf_counter()
    from_sql(sql, dialect="mysql")
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize("dialect", ["mysql", "generic"])
def test_set_with_a_subquery_reports_its_tables(dialect):
    sql = "SET @a = (SELECT password_hash FROM users WHERE id = 1)"
    assert ("read", "table/users") in _actions(from_sql(sql, dialect=dialect))


def test_a_trailing_database_flag_is_ignored():
    assert _actions(from_psql(["psql", "-c", "DELETE FROM users", "-d"])) == [
        ("delete", "table/users")]


@pytest.mark.parametrize("dot", [".tables", ".schema", ".indexes users"])
def test_sqlite3_schema_dot_commands_are_reads(dot):
    assert _actions(from_sqlite3(["sqlite3", "app.db", dot])) == [("read", "table/*")]


def test_sqlite3_reading_stdin_after_cmd_is_unclassified():
    intents = from_sqlite3(["sqlite3", "-cmd", ".mode csv", "app.db"])
    assert intents and all(i.params.get("unclassified") for i in intents)


def test_psql_digit_flag_in_a_bundle():
    assert _actions(from_psql(["psql", "-1c", "DELETE FROM users"])) == [("delete", "table/users")]


@pytest.mark.parametrize("control", ["\x01", "\x7f"])
def test_mysql_dash_dash_before_a_control_character_is_ambiguous(control):
    hidden = from_sql(f"SELECT 1 --{control} '\n; DELETE FROM users; -- '", dialect="mysql")
    assert ("delete", "table/users") in _actions(hidden)
    split = from_sql(f"SELECT 1 --{control} ; DELETE FROM users", dialect="mysql")
    assert any(i.params.get("unclassified") for i in split)


@pytest.mark.parametrize("flags", [["-fdrop.sql"], ["-qf", "drop.sql"], ["-Xfdrop.sql"]])
def test_psql_bundled_or_attached_script_is_read(tmp_path, monkeypatch, flags):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "drop.sql").write_text("DROP TABLE users;\n")
    assert ("delete", "table/users") in _actions(from_psql(["psql", *flags, "-c", "SELECT 1"]))
    assert ("delete", "table/users") in _actions(from_psql(["psql", *flags]))


def test_psql_g_file_after_an_empty_buffer_is_a_client_command():
    intents = from_sql("SELECT 'echo pwned' ;\n\\g /home/user/.bashrc\n", dialect="postgres")
    assert any(i.params.get("unclassified") for i in intents)
    assert any(i.params.get("unclassified") for i in from_sql("\\g /tmp/out\n", dialect="postgres"))


@pytest.mark.parametrize("argv", [["psql", "-X1c", "DROP TABLE users"],
                                  ["psql", "-0c", "DROP TABLE users"]])
def test_bundles_with_digit_letters(argv):
    assert ("delete", "table/users") in _actions(from_psql(argv))


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT 1 /*! ' */ ; DROP TABLE users; -- '", "postgres"),
    ("SELECT 1 /*! -- */ ; DROP TABLE users", "sqlite"),
    ("SELECT 1 /*!50000 ' */ ; DROP TABLE users; -- '", "postgres"),
    ("SELECT e'x\\' FROM (SELECT 1 AS e); DROP TABLE users; --'", "sqlite"),
])
def test_mysql_and_e_string_syntax_is_not_read_in_other_dialects(sql, dialect):
    assert ("delete", "table/users") in _actions(from_sql(sql, dialect=dialect))


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT 1 /*! ' */ ; DROP TABLE users; -- '", "generic"),
    ("SELECT 1 /*!99999 ' */ ; DROP TABLE users; -- '", "mysql"),
    ("SELECT E'x\\'' FROM t", "generic"),
])
def test_text_read_differently_by_the_servers_is_flagged(sql, dialect):
    assert any(i.params.get("unclassified") for i in from_sql(sql, dialect=dialect))


def test_mysqldump_version_comments_are_not_flagged():
    sql = "/*!40101 SET NAMES utf8 */; SELECT 1 FROM t"
    assert not any(i.params.get("unclassified") for i in from_sql(sql, dialect="mysql"))


def test_a_dml_subquery_in_from_is_not_a_table():
    intents = from_sql("SELECT f() FROM (DELETE FROM users RETURNING *) d", dialect="postgres")
    assert _actions(intents) == [("delete", "table/users")]


@pytest.mark.parametrize("sql,dialect", [("/*!50000 x" * 50000, "generic"),
                                         ("/*!50000 x" * 50000, "mysql"),
                                         ("/*!50000 x */" * 30000, "mysql")])
def test_many_executable_comments_stay_linear(sql, dialect):
    import time
    start = time.perf_counter()
    from_sql(sql, dialect=dialect)
    assert time.perf_counter() - start < 5


def test_mariadb_only_comment_is_ambiguous_under_mysql():
    intents = from_sql("/*M! SELECT 'a */ DROP TABLE x; -- ' */", dialect="mysql")
    assert any(i.params.get("unclassified") for i in intents)
