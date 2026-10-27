# Check the SQL an LLM writes before your app runs it (experimental)

Your application lets a model write SQL: a storefront search box that turns "red shoes under $50"
into a query, an analytics chat, a support bot that looks up orders. The model can be talked
into writing something else, and a database will run whatever it is given.

This guide puts two layers in front of that query. The database layer does the real work. Aegis
adds a check on the statement itself, using rules that are signed and authority-checked, in a few
lines of Python.

**Experimental.** It uses Aegis's Python API (`aegis_core`), which the 1.0 compatibility promise
does not cover (that covers the policy file formats, the CLI and the hook protocol). The code is
[`examples/app_sql_gate.py`](https://github.com/moneytool/aegis-devops/blob/main/examples/app_sql_gate.py),
and every result in the Aegis column of the table below is a test in
[`tests/test_example_app_sql.py`](https://github.com/moneytool/aegis-devops/blob/main/tests/test_example_app_sql.py).

## 1. The database: what the query may touch

This is the layer that decides which tables and columns a query can reach. Do it first; Aegis does
not replace it. In PostgreSQL:

```sql
CREATE ROLE search_ai LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE shop TO search_ai;
GRANT USAGE ON SCHEMA public TO search_ai;
REVOKE CREATE ON SCHEMA public FROM search_ai;            -- no SELECT … INTO new tables
GRANT SELECT ON products, categories, inventory TO search_ai;   -- or a view without cost/supplier columns
ALTER ROLE search_ai SET default_transaction_read_only = on;
ALTER ROLE search_ai SET statement_timeout = '2s';         -- pg_sleep, cross joins
```

A session can switch `default_transaction_read_only` off again; what stops writes is that the
role has no write grants. Run the model's query as `search_ai`, add a `LIMIT` in your code if the query has none, and use
row-level security if one table holds several customers' data.

## 2. Aegis: what kind of statement it is

Aegis splits the SQL into statements and classifies each one: a read, an insert, an update, a
delete, a schema change, a permission change, or something it cannot classify (a procedure call,
`COPY`, a `DO` block). Comments and `WITH` clauses do not hide a write: `DELETE/**/FROM orders` and
`EXPLAIN ANALYZE DELETE …` are deletes. `SELECT … INTO new_table` creates a table, and `SET ROLE`
is a permission change. A statement it cannot classify counts as a write.

A read is reported once for every table it reads: the `FROM` table, each `JOIN`, subqueries,
`UNION` branches and `WITH` bodies. A rule can therefore name a table (`resource_pattern:
table/customers`) and catch a query that reaches it through a JOIN. `SELECT … FOR UPDATE` stays a
read, marked `locking: true` for a rule that wants to match it.

One rule allows reads only:

```yaml
# constraints.yaml (examples/app-sql/constraints.yaml)
constraints:
- id: search-sql-read-only
  provider: sql
  resource_pattern: "*"
  actions: [create, delete, put, update]
  effect: BLOCK
  constraint_class: configuration
  principal: app_owner
  …                                  # source, rule text and provenance_hash: see the file
```

```yaml
# authority.yaml: who may assert that class of rule
principals:
  app_owner: [configuration]
```

The `provenance_hash` covers every field of the rule, so an edited rule is quarantined, and the gate
then refuses to start rather than allowing everything. If you change a field, recompute the hash
(`aegis_core.provenance.compute_provenance_hash`, see
[CONTRIBUTING](https://github.com/moneytool/aegis-devops/blob/main/docs/CONTRIBUTING.md#4-adding-an-example-constraint-with-a-real-hash)).
Sign both files with a key your app reads from its secret store:

```bash
aegis keygen --out aegis-signing.key
aegis sign --key file:aegis-signing.key policy/constraints.yaml policy/authority.yaml
aegis check sql --config-dir policy --key file:aegis-signing.key --pretty "DELETE FROM orders"
```

```
BLOCK: sql delete table/orders
  citations: search-sql-read-only
  covered: True  latency_ms: 0.1751
STORE: loaded=1 quarantined=0 principals=1
```

Exit 3 means BLOCK; a read prints `ALLOW` and exits 0.

In the app, load the policy once and check every generated query before it runs:

```python
from app_sql_gate import SqlGate, SqlRejected   # examples/app_sql_gate.py

gate = SqlGate("policy/", key=bytes.fromhex(os.environ["AEGIS_SIGNING_KEY"]))

def search(generated_sql: str):
    try:
        gate.check(generated_sql)
    except SqlRejected as why:
        log.warning("refused model SQL: %s", why)
        return []
    with search_ai_connection() as conn:              # the read-only role from step 1
        return conn.execute(generated_sql).fetchall()
```

Loading took 0.6 ms and a check 25 µs on an Apple M4 Pro (one rule, a typical search query).

## What it catches, and what it does not

| Generated SQL | Aegis | Stopped by |
|---|---|---|
| `SELECT … FROM products WHERE price < 50 LIMIT 20` | runs | |
| `UPDATE products SET price = 0`, `DELETE FROM orders …`, `INSERT …` | **rejected** | Aegis (and the role) |
| `SELECT 1; DROP TABLE products` | **rejected** (each statement is checked) | Aegis (and the role) |
| `CREATE`, `ALTER`, `TRUNCATE`, `GRANT`, `COPY`, `CALL`, `DO $$…$$` | **rejected** | Aegis (and the role) |
| `DELETE/**/FROM orders`, `EXPLAIN ANALYZE DELETE …` | **rejected** | Aegis |
| `SELECT * INTO copy_of_products FROM products` | **rejected** (creates a table) | Aegis (and the role: no `CREATE`) |
| `SET ROLE admin`, `SET SESSION AUTHORIZATION admin` | **rejected** (a permission change) | Aegis (and the role: not a member) |
| `SELECT … FROM products p JOIN customers c …` | runs: a read of `products` and of `customers` | the role (no grant on `customers`) |
| `SELECT … UNION SELECT email, password_hash FROM users` | runs: a read of each table | the role |
| `SELECT … FOR UPDATE` | runs: a read, marked `locking` | the role, a read-only transaction |
| `SELECT pg_sleep(60)`, an unbounded cross join | runs | `statement_timeout` |
| A read of the right table for the wrong customer | runs | row-level security |

So the Aegis check guarantees the statement type ("this app's model only ever reads"), under a
rule nobody can loosen without the signing key and the `configuration` authority. Aegis names every
table a read touches, so you can add a rule that blocks reads of `table/users`; that is a list you
keep up to date, while the role's grants fail closed on any table you forgot. Which tables and
columns a read may reach is still up to the database, and Aegis does not look inside functions a
query calls. Search engines (Elasticsearch, OpenSearch, Algolia, Solr) and other query languages
are not covered.

## When this is worth it

- Several teams share the policy, or the rule must be auditable: who asserted it, from which
  source, and whether it has been edited since.
- You already use Aegis for coding agents and want the same rules and review flow for the app.

For a single service whose team owns both the queries and the database, step 1 alone, with
fixed query templates the model only fills in, is usually enough.

Reference: [writing constraints](../constraints.md) · [CLI](../cli.md) · [guides](README.md)
