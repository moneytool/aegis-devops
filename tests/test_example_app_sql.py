"""examples/app_sql_gate.py and examples/app-sql/: the guide docs/guides/app-sql.md.

Every row of the guide's table is checked here, including the gaps it documents (a read
whose JOIN reaches another table, SELECT ... INTO, SET ROLE pass as reads). If the SQL
classifier learns to see those, the gap tests fail: update the guide with them."""

import importlib.util
import os
import re
import shutil
from pathlib import Path

import pytest

from aegis_core.signing import SignatureError, sign_file

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "examples" / "app-sql"


def _module():
    spec = importlib.util.spec_from_file_location("app_sql_gate",
                                                  ROOT / "examples" / "app_sql_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def policy(tmp_path):
    key = os.urandom(32)
    for name in ("constraints.yaml", "authority.yaml"):
        shutil.copy(POLICY / name, tmp_path / name)
        sign_file(tmp_path / name, key)
    return tmp_path, key


@pytest.fixture
def gate(policy):
    directory, key = policy
    return _module().SqlGate(directory, key=key)


@pytest.mark.parametrize("sql", [
    "SELECT id, name, price FROM products WHERE price < 50 AND color = 'red' LIMIT 20",
    "WITH cheap AS (SELECT * FROM products WHERE price < 10) SELECT * FROM cheap",
    "EXPLAIN SELECT * FROM products",
    "SELECT 1; SELECT 2",
])
def test_reads_run(gate, sql):
    gate.check(sql)


@pytest.mark.parametrize("sql,what", [
    ("UPDATE products SET price = 0", "update table/products"),
    ("DELETE FROM orders WHERE id = 1", "delete table/orders"),
    ("INSERT INTO products VALUES (1)", "put table/products"),
    ("SELECT 1; DROP TABLE products", "delete table/products"),
    ("TRUNCATE products", "delete table/products"),
    ("CREATE TABLE x (a int)", "create table/x"),
    ("ALTER TABLE products ADD COLUMN x int", "update table/products"),
    ("GRANT ALL ON products TO public", "update role/public"),
    ("COPY products TO '/tmp/x'", "update unknown/*"),
    ("CALL refresh_prices()", "update procedure/refresh_prices"),
    ("EXPLAIN ANALYZE DELETE FROM orders", "delete table/orders"),
    ("DELETE/**/FROM orders", "delete table/orders"),
])
def test_writes_and_unclassified_are_rejected(gate, sql, what):
    module = _module()
    with pytest.raises(PermissionError, match=re.escape(f"{what}: search-sql-read-only")) as exc:
        gate.check(sql)
    assert type(exc.value).__name__ == module.SqlRejected.__name__


def test_empty_or_comment_only_sql_is_rejected(gate):
    with pytest.raises(PermissionError, match="no SQL statement"):
        gate.check("   ")
    with pytest.raises(PermissionError, match="search-sql-read-only"):
        gate.check("-- nothing here")      # unclassified, so it counts as a write


@pytest.mark.parametrize("sql", [
    "SELECT p.name FROM products p JOIN customers c ON c.id = p.id",    # 2nd table unseen
    "SELECT * FROM products UNION SELECT email, password_hash FROM users",
    "SELECT * INTO copy_of_products FROM products",                     # creates a table
    "SET ROLE admin",
    "SELECT pg_sleep(60)",                                              # cost
])
def test_documented_gaps_pass_as_reads(gate, sql):
    """The guide says these get through; the database role and a read-only transaction
    are what stop them."""
    gate.check(sql)


def test_unsigned_policy_is_refused(tmp_path):
    for name in ("constraints.yaml", "authority.yaml"):
        shutil.copy(POLICY / name, tmp_path / name)
    with pytest.raises(SignatureError):
        _module().SqlGate(tmp_path, key=os.urandom(32))


def test_edited_rule_is_refused(policy):
    """Editing the rule without recomputing its provenance hash quarantines it, and the
    gate refuses to start rather than allowing everything."""
    directory, key = policy
    path = directory / "constraints.yaml"
    path.write_text(path.read_text().replace("effect: BLOCK", "effect: ESCALATE"))
    sign_file(path, key)     # validly signed, but the hash no longer matches the fields
    with pytest.raises(RuntimeError, match="no usable rules"):
        _module().SqlGate(directory, key=key)
