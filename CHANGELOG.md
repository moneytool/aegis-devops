# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From 1.0 the public surface listed
under 1.0.0 below is stable: breaking it needs 2.0. Before 1.0 any release could change
behaviour.

## [Unreleased]

### Added
- Guide (experimental): [check the SQL an LLM writes before your app runs it](docs/guides/app-sql.md),
  with `examples/app_sql_gate.py` and a signed-rule template in `examples/app-sql/`. Aegis
  enforces "reads only" on generated SQL; the guide is explicit that a read's tables, columns and
  cost are the database role's job. Every Aegis result in its table is a test.

### Fixed
- SQL classifier (`psql -c`, `mysql -e`, `sqlite3`, `aegis check sql` and `from_sql`) (#58):
  - A statement now yields a `read` intent for each table the classifier can see in it, not only
    the first one after `FROM`: each `JOIN` and comma-joined table, subqueries,
    `UNION`/`INTERSECT`/`EXCEPT` branches, `TABLE t` and `WITH` bodies (a CTE's own name is not a
    table; functions in `FROM` are not tables). Tables read inside functions, views or procedures
    a query calls are not seen; the database role's grants are the backstop. Writes add a read of
    each other table they name (`INSERT … SELECT`, `UPDATE … FROM`, `DELETE … USING`,
    `CREATE TABLE|VIEW … AS SELECT`). `EXPLAIN <stmt>` and MySQL `DESCRIBE <stmt>` read every table
    `<stmt>` names.
  - Every DML operation in a statement is reported, each with its own target: the top-level one and
    each one inside a `WITH` body (it was only the strongest one inside a CTE, and a `WITH … UPDATE
    t AS u`, `UPDATE ONLY` or `MERGE` main statement could be read as a SELECT). MySQL multi-table
    `DELETE t1, t2 FROM …` and `UPDATE t1 JOIN t2 … SET` write each listed table. `MERGE INTO t` is
    each of its `WHEN … THEN` actions (an `UPDATE` and an `INSERT` branch give an `update` and a
    `put`). `ONLY` and MySQL's `IGNORE`/`LOW_PRIORITY`/`QUICK`
    are no longer read as the table name (`DELETE FROM ONLY users` was `table/ONLY`), nor is
    SQLite's `UPDATE OR IGNORE`. A MySQL `DELETE s FROM secret AS s …` resolves the alias to
    `secret`, using only the aliases of the DELETE's own query block, never a subquery's (a
    target naming no table or alias there deletes from every table read). An upsert (`ON CONFLICT
    … DO UPDATE`, `ON DUPLICATE KEY UPDATE`) is a `put` and an `update`; MySQL `REPLACE` and
    SQLite `INSERT OR REPLACE` are a `put` and a `delete`. A long multi-table `UPDATE … JOIN …
    SET` reports every table before `SET`.
    `DROP TABLE|VIEW|INDEX|… a, b` and `TRUNCATE a, b` delete every name (`DROP TABLE tmp_x, users`
    deleted only `tmp_x`; a repeated name counts once), and `DROP SCHEMA a, b` cascades for each. `unbounded` now means no
    `WHERE` in the operation itself, not anywhere in the text.
  - Strings, comments and dollar quotes are read by one dialect-aware lexer, used for splitting
    statements as well as classifying them, so the two agree. A backslash escapes a quote inside
    Postgres `E'…'` strings and every MySQL string (`E'x\''; DROP TABLE users` was one read); a
    plain `'…'` keeps the standard reading for `postgres`, `sqlite` and `generic`. A comment marker
    inside a `$$` string no longer hides the rest of the statement. Postgres block comments nest
    (`/* a /* b */ ' */; DROP TABLE secret` hid the DROP). `E'…'` and `U&'…'`/`U&"…"` (with
    `UESCAPE`) are decoded, and an escaped literal is never taken as a plain setting name
    (`set_config(U&'\0072ole', …)` is a role change); `U&` literals are not read in MySQL, and
    `UESCAPE` may have comments around it. SQLite `[name]` is an identifier. MySQL `#`
    comments are comments, and `--` not followed by a space is not one in MySQL. The body of a MySQL
    executable comment (`/*! … */`, `/*!50000 … */`) is read as SQL in every dialect, since MySQL
    runs it. MySQL index hints (`FORCE INDEX FOR ORDER BY (i)`) no longer end a `FROM` list. `dual`
    is a pseudo-table only in MySQL. With the default `--dialect generic`, a statement whose
    quoting or comments MySQL and Postgres would read differently (a backslash before a quote, a
    comment inside a comment) also yields an unclassified `update` (`ambiguous_escape` /
    `ambiguous_comment`).
  - `SELECT … INTO t` is a `create` of `table/t` (as `CREATE TABLE … AS SELECT` already was), not a
    read. MySQL `SELECT … INTO OUTFILE|DUMPFILE` is an opaque, unclassified `update` of
    `file/<path>` wherever it appears (`TABLE t INTO OUTFILE …`, `(SELECT …) INTO OUTFILE …`);
    `SELECT … INTO @var` stays a read. `(SELECT * INTO t FROM …)` is a create too, also right
    after a `WITH` list.
  - `SET ROLE`, `SET SESSION AUTHORIZATION`, `SET role = …` / `SET "role" = …`, `RESET ROLE`, MySQL
    `SET DEFAULT ROLE` and `SET PASSWORD`, and `[pg_catalog.]set_config('role', …)` are an `update`
    of `role/<name>` with `privilege: true`, like `GRANT`/`REVOKE`, instead of a `session/*` read.
    A `set_config` whose first argument is not a plain string literal is an update of `role/*`.
    Other `SET`s stay reads.
  - `SELECT … FOR UPDATE|NO KEY UPDATE|SHARE|KEY SHARE` (and MySQL `LOCK IN SHARE MODE`) stay
    reads, now with `locking: true`, `lock_strength` and `nowait`/`skip_locked`, so a rule can
    match them with `scope: {locking: true}`.
  - `EXPLAIN (ANALYZE[, …]) <stmt>` is classified as `<stmt>`, as `EXPLAIN ANALYZE <stmt>` already
    was; it was a read. `CREATE MATERIALIZED VIEW mv` is `view/mv`; `CREATE INDEX CONCURRENTLY`,
    MySQL `CREATE … ALGORITHM=… / DEFINER=… / SQL SECURITY …` views and routines, and
    `SHOW TABLES FROM db` (now `table/*`; only `SHOW COLUMNS|INDEX FROM t` names a table) no longer
    take a keyword for the name. A DML statement opening a `BEGIN ATOMIC` function body is
    reported; the body is still split on `;`, so the trailing `END` is unclassified.
  - A top-level `TABLE t`, `VALUES …` or parenthesised `(SELECT …) UNION (SELECT …)` is a read
    (it was unclassified).
  - Classification is linear and never recurses: deeply nested SQL, thousands of CTEs or repeated
    `EXPLAIN` prefixes no longer take seconds or raise `RecursionError`. A statement over 100,000
    tokens is classified from its first part plus an unclassified `update` (`too_large`). An
    unclosed `set_config(` no longer takes seconds per thousand repeats.
  - `aegis check sql --dialect` is documented ([CLI reference](docs/cli.md#sql-and---dialect)).
    Dialect names are matched without case (`postgresql`, `mariadb` and `sqlite3` name their
    dialect); any other name is read as `generic` (`aegis check sql` says so on stderr; its exit
    codes are unchanged).
  - A `--` comment ends at a carriage return as well as a newline in `postgres` and `generic`, as
    Postgres reads it (`SELECT 1 -- c` + CR + `; DROP TABLE x` was a read).
  - Each `psql -c` text and each `sqlite3` SQL argument is classified on its own, as the client
    runs them: a trailing `--` comment or an open quote in one no longer hides the next (`psql -c
    "SELECT 1 --" -c "DROP TABLE users"` was a read). The `mysql` client joins its `-e` texts with
    a space, so they are classified both joined and one by one. `mysql --init-command` and `psql
    -v` values next to a `-f` script are classified as SQL.
  - Client commands: a bare `\g`/`\G` ends a statement (`SELECT 1\G DELETE FROM users` hid the
    delete), and other mysql/psql backslash commands (`\!`, `\.`, `\i`, `\copy`, `\gexec`, a psql
    `\g FILE`/`\g |cmd`/`\g (…)`, …) and `sqlite3` dot-commands (`.shell`, `.system`, …; not the
    output-format ones such as `.mode` and `.headers`) are unclassified writes (`client_command`).
  - Only ASCII whitespace separates words. A no-break space (or U+3000, U+2028, …) was taken as
    a space, while PostgreSQL, MySQL and SQLite read it as part of a name: `SELECT 1 AS x<NBSP>$a$;
    DROP TABLE users; …` hid the drop inside a fake dollar quote, and a MySQL `--<NBSP>` was taken
    for a comment.
  - `sqlite3`: its single-dash options (`-csv`, `-batch`, `-echo`, `-column`, `-header`) are no
    longer read as `-c` bundles that swallowed the SQL arguments; `-cmd SQL` is read as SQL that
    runs before them, and the values of `-separator`, `-nullvalue` and similar options are not
    taken for the database. `mysql -fe`/`-vvve` and `psql -Sc` bundles are read. A `-f`/`-init`
    file that is a directory, unreadable or over 8 MiB is an opaque, unclassified script instead
    of an error. Under `sqlite`, `x IN t` (a table on the right of `IN`) reads `t`, and `WITH …
    REPLACE INTO t …` is a write like `WITH … INSERT OR REPLACE`. `aegis check sql --dialect
    NAME` with an unknown name now records `"dialect": "generic"` in the intent metadata.
  - `SET @a = (SELECT … FROM users)` reports the tables its subqueries read beside the `session/*`
    read. Nested `UPDATE a JOIN (…` groups are read in linear time (they were quadratic: 20,000
    levels took minutes). A trailing `-d`/`-h` with no value is ignored instead of an error. MySQL
    identifiers that start with a digit or `$` (`2fa_codes`, `app.2fa_codes`) are read as names,
    `FROM { OJ … }` reports its tables, and only `START TRANSACTION` is a session read (`START
    REPLICA` is unclassified).
  - A statement that changes how the server reads later strings is an unclassified `update`
    (`changes_lexing`): `SET sql_mode` (`NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`), `SET
    standard_conforming_strings`, `SET backslash_quote`, `SET NAMES` / `CHARACTER SET` /
    `client_encoding` with a charset other than UTF-8, Latin-1 or ASCII, and `set_config()` of
    these. `PGOPTIONS` and an `options=` connection setting are not read.
  - Outside MySQL, a quote after `@` starts an ordinary string (`@` is an operator there); only
    MySQL reads `@'…'` as a quoted user variable.
  - SQLite `UPDATE OR REPLACE` is an upsert like `INSERT OR REPLACE` (an extra `delete`). A
    bracketed join group in a MySQL multi-table `UPDATE` (`JOIN (secret s) … SET s.x=1`) is
    written, not read; a parenthesised table list (`FROM (a, users)`, `JOIN (b, (c, users))`)
    reports every table; a clause word used as an alias before a comma (`FROM products offset,
    users`) does not end the list; a bare column alias before `FROM` (`SELECT 1 rows FROM t`, `0
    delete FROM t`) no longer hides the table; a DML after a CTE `SEARCH … SET col` / `CYCLE …
    USING col` clause, and `WITH … TABLE t`, are recognised; `JOIN b USING (id)` in a MySQL
    `DELETE` no longer reads a table `id`; `SELECT … INTO STRICT x` is a variable assignment.
  - The action of a `CREATE RULE … DO [INSTEAD|ALSO] …` is reported (`DO INSTEAD DELETE FROM
    secret` deletes from `secret`), and `SELECT … INTO LOCAL|GLOBAL TEMP t` creates `t`.
  - Every `psql -f`/`--file` script is read, also next to `-c` (only the last one was, and none
    when a `-c` was given), as are `sqlite3 -init` scripts next to SQL arguments; `mysql -f` is
    `--force`, not a script (`mysql -f -e "DROP …"` lost the DROP). In `generic`, a string whose
    body ends in a backslash is ambiguous too (`'C:\' -- '; DROP …`). SQLite `EXPLAIN QUERY PLAN`
    keeps the table it explains; `UPDATE … JOIN t2 USING (id)` no longer writes a table `id`.
  - `psql`/`mysql` bundled and attached command options are read (`psql -Atc 'SQL'`, `-c'SQL'`,
    `mysql -BNe 'SQL'`; `-dcars`, `-psecret` are option values), and a `-c` with nothing after it
    is unknown SQL (an unclassified `update`) instead of an error.
  - Multi-table `DELETE` targets and repeated `LOCK IN SHARE MODE` are resolved in linear time
    (thousands of either took tens of seconds).

  **Behaviour change:** a statement can now produce more intents than before. Where a rule matches
  one of the newly visible tables or writes, or `create`/`update` on `table/*` or `role/*`, a
  command that used to be ALLOWed is now BLOCKed or ESCALATEd. That is the intended fix; review
  rules on reads of specific tables, and any `actions: [create, update]` rule on `*`, before
  upgrading. Pass the right `dialect` to `from_sql` and `aegis check sql`: it now changes how
  strings and comments are read, and `generic` turns an ambiguous statement into an extra
  unclassified write. Known limits: tables read inside functions, views or procedures a query calls
  are not seen, and a function with side effects is a read (`SELECT dblink_exec('DELETE …')`,
  `lo_export(…)`, `pg_terminate_backend(…)`, the sqlite3 shell's `writefile(…)`); an `UPDATE
  pg_settings …` that changes the role is a table update, not a `privilege` change; MySQL `"…"` is read with string escapes even under `ANSI_QUOTES`, and `\'` as an
  escaped quote even under `NO_BACKSLASH_ESCAPES`, when the mode is set outside the command (a
  `SET` in the command itself is flagged); and `generic`
  reads `$$`, `--x` and `#` the Postgres way without flagging them (see the CLI reference). The example
  policies and their signatures are unchanged.

## [1.2.1] — 2026-10-24

A coverage-report fix for `aegis compile kubernetes`.

### Fixed
- `aegis compile kubernetes`: rules on `apply`, `update`, `patch`, `edit` or `replace` are now
  reported over-enforced. Admission sees the CREATE or UPDATE these send, not the kubectl verb,
  so such a rule also denies an agent's create, set image, label and annotate (update verbs:
  also scale, through the `scale` subresource), which the client-side verifier allows; the
  coverage report called these rules exact.

## [1.2.0] — 2026-10-21

OpenCode V2 support, `aegis install --escalate-scripts`, and a hook latency benchmark.

### Added
- `aegis install <agent> --escalate-scripts`: registers the hook with `-- --escalate-scripts`
  (OpenCode: the plugin passes it on), so the opt-in script escalation no longer needs a
  hand-edited hook command. Reinstalling without the flag takes it out. With the flag, the
  OpenCode plugin blocks every shell command in an opted-in project when aegis cannot run.
- `scripts/hook_latency.py` and `results/hook-latency.json`: one `aegis hook claude` call on six
  shell commands, 1.0.0 against 1.1.0 on the same interpreter. 1.1.0 was 0.7–1.2 ms slower
  (median) on the five commands both decide alike, consistently about 1 ms, within run-to-run
  spread; inline code naming an infrastructure tool is denied before the policy loads
  (70 → 55 ms). `--escalate-scripts` was not measured. `docs/agents.md` has a "Cost" section.
- `scripts/budget_latency.py`: p95 is the nearest-rank value (the same sample for its 40 runs,
  so `results/budget-latency.json` is unchanged).
- The OpenCode plugin (`aegis install opencode`) supports OpenCode V2 (2.x) alongside V1: its
  default export is `{ id: "aegis-devops", setup(ctx), server() }`, so V2 calls `setup`
  (registering `ctx.tool.hook("execute.before", …)`) and V1 (1.15 and later) calls `server`.
  No npm dependency; same decisions and fail-closed behaviour on both. Under V2 a budget
  warning goes to OpenCode's log (V2 server plugins have no toast). Needed to stay in the
  awesome-opencode catalog, which removes V1-only plugins on 2027-01-01.

### Changed
- The OpenCode plugin no longer has a named `AegisDevOps` export (the default export replaces
  it). Reinstall with `aegis install opencode` to get the new file; nothing else changes.

## [1.1.0] — 2026-10-20

Denial reports for the server-side layer, and the agent hook checks code passed inline or
piped to an interpreter.

### Added
- **Preview:** `aegis report aws`: which calls the compiled SCPs denied, from CloudTrail
  (`--collect` with `aws cloudtrail lookup-events`, or saved events): attributed to Aegis when
  the error carries the SCP's policy ARN (`--policy-id`), per rule (the rules whose mapped
  actions cover the call), real versus deliberate tests (`--test-principal`). No real denial in
  a window of at least `--quiet-days` (default 30) exits 1: zero denials is not proof the policy
  works. SCP denials without a policy ARN are reported as possibly Aegis's; EC2's encoded
  reasons as undetermined. Proposed after outside review of the AWS SCP article.
- **Preview:** `aegis report kubernetes`: which requests the compiled ValidatingAdmissionPolicies
  denied, or warned about in report-only mode, from the API server's audit log (the `Audit`
  action's `validation_failure` annotation): per rule (exact, from the policy name), real versus
  deliberate tests (`--test-principal`), impersonated requests counted as the identity
  impersonated. Reports bindings that ran with other actions than the compiled ones and
  `aegis-*` policies missing from the output. No real denial in at least `--quiet-days`, or no
  events, exits 1. Reads `--audit-log-path` files (`.gz` ok), an `EventList`, or EKS
  `aws logs filter-log-events` output. Verified on kind.
- `aegis check command --escalate-scripts` (off by default; add it to the hook command as
  `aegis hook <agent> -- --escalate-scripts`): escalates commands that run code Aegis cannot
  read: `bash nuke.sh`, `bash < nuke.sh`, `./nuke.sh`, `source x`, `python3 x.py`, `make`,
  `npm run` (also with `$VAR` arguments), inline `python3 -c` code, a shell fed through a
  pipe. Shell intents for those carry `params.runs_code`.
- `docs/agents.md`: "What the hook cannot see", the tested list of what gets past the hook
  (scripts, Write/Edit tool files, SDK calls) and the server-side layer that does not.

### Changed
- Agent hook: inline interpreter code (`python -c` / `-Ic`, `node -e` / `--eval=`, `perl -e` /
  `-lne`, `ruby -e`, `php -r`, …) and code piped into a shell or interpreter are denied when
  the code names an infrastructure tool. Before, `python3 -c "subprocess.run(['kubectl','delete',…])"` and
  `echo 'kubectl delete …' | bash` ran unchecked.
- Agent hook: `bash -c "$(…)"`, `eval "$(…)"`, `source <(…)` and similar ask first (deny where
  the agent has no "ask"): the code they run only exists at run time. Before, they ran unless
  the command text named an infrastructure tool.

## [1.0.0] — 2026-10-10

The cross-agent session budget cap ([`docs/budget.md`](docs/budget.md)), and the 1.0 stability
promise ([design §9](docs/dev/DESIGN-v1.0-budget-cap.md)).

**Stable from 1.0** (breaking any of these needs 2.0): the policy file formats (`constraints`,
`authority`, `environments`, `plan_constraints`, `agents`, `budget`, all `version: 1`), the CLI
commands and their exit codes, the hook protocol per agent, and the GitHub Action's inputs and
outputs. **Still preview within 1.x:** the server-side compilers' output (`aegis compile`) and
the identity audit (`aegis audit-identity`), which may change shape in minor releases.
**Deferred, additive when it comes:** public-key signing (`docs/dev/DESIGN-v0.4-public-key-signing.md`).

### Added
- `aegis_core.budget`, the budget cap's core (design §3–§6):
  - `budget.yaml`, signed, whose `principal` must hold the new **`budget`** authority class:
    a per-session and a per-project-per-day limit in estimated USD or tokens (`unit` is
    required), a warning threshold, the day's time zone, the agents measured (only listed
    agents are), `on_unknown_log`, `on_unknown_price`, signed price overrides and a
    premium-request limit for Copilot CLI. Every shape problem is a load error.
  - A dated price table (`aegis_core/budget/prices.yaml`: Anthropic, OpenAI and Google list
    prices read 2026-10-07). An unpriced model is estimated per billing category from its
    vendor's (or the whole table's) highest rate — an estimate, not an upper bound — or, with
    `on_unknown_price: deny`, refused until priced. Usage is stored as tokens per model, so a
    new override re-prices earlier usage.
  - Usage readers for the session logs of Claude Code, Codex CLI, Gemini CLI, OpenCode and
    Copilot CLI (premium requests), with linked sub-agents counted inside their parent session,
    tested against redacted samples of real logs.
  - Accounting that the logs can always rebuild: per-session records, project/day totals merged
    by revision from a durable per-session counter, a session inventory outside the cache,
    rebuilds that report whether the day is complete, partial or of unknown completeness, and
    usage bucketed by the time the log recorded, never the time it was read.
  - Evaluation to allow / warn / deny with the measured usage, limits and observed overshoot.
- The budget cap in `aegis hook` (design §6): in a project whose policy directory holds a
  `budget.yaml`, after the policy decision (a BLOCK always stands), every covered tool call is
  denied once the usage available at the hook reaches a limit, and new prompts where the agent
  can block them (Claude Code and Codex `UserPromptSubmit`, Gemini CLI `BeforeAgent`); a warning
  is shown once per session per threshold (`systemMessage`; an OpenCode toast; stderr for Copilot
  CLI). A `budget.yaml` that cannot be used (bad signature, shape, authority) fails closed.
- `aegis budget status|check|reset` (design §7): today's project total and its sessions, rebuilt
  from the logs (`--json`); `check` exits 0 under, 3 over, 65 for an unusable `budget.yaml`, 66
  for none; `reset --day` acknowledges an incomplete day's history as it stands, with a marker
  signed by the policy key that records the acknowledged state, so `on_unknown_log: deny` stops
  denying for exactly that (later problems count again; an agent without the key cannot reset).
- `docs/budget.md`; `aegis init` writes a signed `budget.example.yaml`.
- Live test in each agent (`docs/dev/budget-live-test/`): tool calls and prompts over a
  budget denied in Claude Code, Codex and OpenCode; Copilot CLI's premium-request count reaches
  its log only at the end of a turn; Gemini CLI not tested (API credits). `docs/budget.md` now
  says, per agent, from when a turn's usage is seen.
- `scripts/budget_latency.py`: the budget adds ~9 ms to a hook call (74 vs 65 ms median,
  `results/budget-latency.json`), under the 20 ms target. The price table ships as
  `prices.json` generated from `prices.yaml` (`scripts/sync_prices.py`; a test keeps them equal)
  and is read only from the package: parsing the YAML on every call had cost ~15 ms.
- `aegis install` adds the budget hooks when the policy directory that applies holds a
  `budget.yaml` (`--budget` / `--no-budget` to choose): the tool hook sees every tool call and
  the prompt hook is added where the agent has one. The Claude Code plugin and the Gemini
  extension carry budget-only entries that start no process in projects without a budget; the
  OpenCode plugin sends every tool call, with its session id, only where a budget applies.
- The example `authority.yaml` gives `admin` the `budget` class.
- `agents.yaml`: a trusted AWS `source-identity` now warns (`source-identity-inherited`): a
  source identity survives role chaining, so an agent started in a session that carries it is
  exempt too. `no_agents: true` on the entry states that no agent runs under it and clears the
  warning. Raised in a review of the AWS SCP article by dev.to reader mickyarun.

### Documentation
- README: "Why not RBAC, or the agent's own permission settings?", with each spelling of a
  command the example policy blocks; a test keeps the table true.
- `docs/server-side.md`: what the second layer adds and what it doesn't (one policy enforced
  twice, not a second opinion), and why a trusted source identity must never carry an agent
  (same review). Denial reporting from CloudTrail added to the plan.

### Changed
- **kubectl: an unknown namespace is never "not prod".** A command without `-n` (which runs in
  the kubeconfig context's namespace) or with `-A` now escalates a namespace-scoped rule that
  would otherwise match, with the note `namespace-unresolved: <id>`, as an unresolved `env`
  already did; before, the rule silently did not apply. Cluster-scoped kinds are unaffected.
  `--resolve-current-context` now also fills the namespace from the kubeconfig context
  (`default` when it sets none). Reported by a reader on dev.to (Chris Sellers).
- **kubectl: manifests that are not read escalate kind rules.** `apply|create|replace|delete -f
  <file>|<dir>|-` and `-k`: a rule for the same action on kinds or objects escalates with
  `manifest-not-inspected: <id>`, since the manifest may hold what it protects; Aegis still
  never reads the file. Same report.

## [0.3.2] — 2026-09-29

Package metadata only; no change to behaviour.

### Fixed
- PyPI listed no author: `pyproject.toml` now declares the author, as `CITATION.cff` does.

### Added
- `docs/dev/DESIGN-v0.4-public-key-signing.md`: the reviewed design for public-key (SSH)
  signing of policy files, the next release's main change.

## [0.3.1] — 2026-09-29

The Kubernetes server-side layer: the policy compiled to ValidatingAdmissionPolicies scoped to
agent identities, verified on a kind cluster against the client-side verdicts, and an identity
audit that reports the RBAC escapes admission cannot see. Also a fix to how the aws parser names
resources. Preview: see `docs/server-side.md`.

### Added
- **Preview:** `aegis compile kubernetes --cluster <name> --out DIR`: the verified snapshot as
  Kubernetes ValidatingAdmissionPolicies (one policy and binding per rule) scoped to agents by
  `matchConditions` generated from `agents.yaml`, with the control plane always exempt in
  deny-by-default. Deletes (including evictions, and `delete --all`, admitted per item), creates,
  every update spelling, scale (subresource or `spec.replicas`), set-image (init containers
  included), rollout-restart, cordon, taint, label and annotate (old/new object diffs), rollout-undo
  (any pod-template change: over-enforced, as admission cannot tell an undo from a restart), exec/attach/port-forward (CONNECT),
  and the namespace cascade compile; name and namespace globs become RE2. Time windows (no
  clock at admission), rate limits, reads and impersonation are reported not enforced. An
  `aegis-guardrails` policy stops agents minting tokens for other ServiceAccounts or running pods
  as another ServiceAccount. Report-only compiles `[Warn, Audit]`, enforce `[Deny, Audit]`. Same
  coverage report, manifest and `--check` as the AWS target. Verified on kind (Kubernetes 1.36.1)
  with `scripts/kube_acceptance.py`: 66 of 66 runs as expected; the client and the cluster agreed
  on every shared case and differed only where coverage says so (`docs/dev/kube-acceptance/`).
- `aegis audit-identity kubernetes [--context CTX]`: read-only review of a cluster against
  `agents.yaml` — every ServiceAccount and RBAC-bound user or group the compiled policies would
  restrict (with bindings and pod counts; control plane and universal groups left out), missing
  ServiceAccounts, a break-glass subject no binding grants anything, and escape permissions an
  identity the policies restrict still holds (impersonation, by name and per namespace;
  updating, patching or deleting admission policies, bindings or webhooks; creating mutating
  admission; RBAC escalate/bind/cluster-role-binding writes), asked as SubjectAccessReviews with
  the groups each identity carries. A failed review is an error, not a "no". `--save-inventory` and
  `--inventory` for offline review. Run against the kind cluster: it flagged the cluster-admin
  test agent and an untrusted `system:masters`, and nothing for an `edit`-only agent.

### Fixed
- **aws CLI resource names.** For 17 operations the parser lost the name of the resource acted
  on (`ec2 delete-volume --volume-id vol-1` became `ec2/volume/*`) or took its parent's
  (`eks delete-nodegroup --cluster-name c --nodegroup-name ng` became `eks/nodegroup/c`, likewise
  `ecs delete-service`). A rule written for one named resource never matched on the client,
  while `aegis compile aws` enforced it. The resource's own flag now names it (EC2 volumes,
  snapshots, VPCs, subnets, security groups by id, gateways, images, key pairs; RDS clusters and
  snapshots; EKS clusters, node groups, add-ons, Fargate profiles; ECS services; log groups and
  streams; Route 53 hosted zones; EFS file systems; ElastiCache clusters and replication groups),
  and a parent taken from `--cluster`/`--cluster-name` is kept as `params.parent`. Rules on the
  `*` forms still match; name-specific rules now apply on the client as in the compiled policy.

## [0.3.0] — 2026-09-28

The first server-side layer: the policy compiled to AWS Service Control Policies scoped to agent
identities, so an agent that calls the AWS API directly (an SDK, a script, a found credential) is
refused by AWS itself, not only by the client hook. Preview: see `docs/server-side.md`.

### Added
- `ConstraintStore.verified_snapshot()` and `aegis snapshot`: the constraints that may vote —
  loaded **and** passing integrity and authority now (authority is otherwise checked only per
  decision) — frozen, with every excluded constraint and its reason, and one sha256 digest over
  all inputs (constraints, authority map, environment and plan-constraint maps, sources
  manifest, repos/signers/agents files, the commit each Git source ref points at, the Aegis
  version, and store settings such as the default time zone). A constraint also needs **source
  evidence** — its cited source fetched and verified at load (new `ConstraintStore.source_verified`)
  — or it is excluded as `source-unverified`. The snapshot is detached and deeply immutable
  (canonical records; `constraints` returns fresh copies; `verify()` recomputes the digest). The
  base for the v0.3 compilers (`docs/dev/DESIGN-v0.3-server-side.md` §3.1). `aegis snapshot`
  refuses `--insecure`, `--sources ''`, and any environment / plan-constraint / `agents.yaml`
  file that does not verify.
- `agents.yaml` and `aegis agents`: the identity model server-side enforcement is compiled for
  (design §4). **Deny-by-default** is the default mode: the file names the trusted identities
  (people, CI roles, controllers) and every other identity counts as an agent; `mode:
  agents-only` lists agents instead. At least one **break-glass** identity is required and is
  never restricted; `enforcement` starts at `report-only`. Identities are typed per platform
  (Kubernetes user/group/ServiceAccount, AWS role/user/SourceIdentity, GCP service
  account/user/group, GitHub OIDC subject) and validated; wildcards, duplicates, assumed-role
  session ARNs, groups every identity carries (`system:authenticated`, …) and a break-glass
  GitHub subject not bound to a workflow are load errors. Matching is exact, as AWS ARN
  conditions are (a mis-cased ARN never exempts).
  The file is signed and its `principal` must hold the new `identity` class in
  `authority.yaml` (the example grants it to `admin`). Warnings: a trusted GitHub subject that
  is not bound to a workflow or protected environment (`workflow-unbound`), a platform with no
  break-glass identity. `aegis snapshot` now loads `agents.yaml` through this loader instead
  of only checking its signature, and carries its warnings. `aegis init` ships
  `agents.example.yaml`, which never becomes active on its own.
- **Preview:** `aegis compile aws --account <id> --out DIR`: the verified snapshot as AWS Service
  Control Policies scoped to agent identities from `agents.yaml` (design §6.5). Explicit Deny
  statements on the IAM actions and ARNs from a new action map
  (`src/aegis_core/compile/actions/aws.yaml`, keyed by what the CLI parser produces), with
  `scope.env`/`account` compiled per account from `environments.yaml` and `scope.region` as
  `aws:RequestedRegion`. A self-protection block stops agents assuming, passing or modifying
  exempt roles, minting credentials for exempt users, setting an exempt source identity and
  leaving the organization. `coverage.json`/`.md` accounts for every constraint (exact,
  over-enforced, partial, not enforced, not applicable, excluded) with same-effect actions
  not covered; `manifest.json` carries the snapshot digest and a Sid → rule map. Output is
  split to the 5,120-character SCP limit and fails loudly if it cannot fit; `--check DIR`
  reports drift. With `enforcement: report-only` the SCPs go under `report-only/` and are not
  deployable. Statements merge exactly (same resources pool actions, same actions pool
  resources); a rule covering every name of a type denies the action on any resource.
  Every mapping was **verified** in a sandbox AWS Organization on 2026-09-28 (live calls
  and the IAM policy simulator, as agent, trusted, break-glass and path-qualified SSO
  roles; `scripts/aws_acceptance.py`, evidence in `docs/dev/aws-acceptance/`). The run
  found that denying `sts:SetSourceIdentity` outright also broke role chaining for agent
  sessions that carry a source identity; the self-protection statement now denies only
  exempt values. Guide: `docs/server-side.md`.
- `aegis audit-identity aws`: read-only check of `agents.yaml` against the IAM roles and users
  that exist in an account (from `aws iam get-account-authorization-details`, or a saved copy with
  `--inventory`). Lists every identity the compiled policy would restrict (`--would-restrict`,
  the review before `enforcement: enforce`), with last-used dates and hints for Identity Center
  and `OrganizationAccountAccessRole` roles; exempt identities; service-linked roles (never
  restricted by SCPs). Problems (exit 1): an identity listed for this account that does not
  exist (a mistyped break-glass role is no break-glass), GitHub OIDC trust on an exempt role that
  is not bound to a workflow or protected environment, has a wildcard or no subject, and — while
  report-only — exempt roles that a restricted identity or the whole account may assume.

## [0.2.1] — 2026-09-28

Fixes found by the council review of the v0.3 server-side design
(`docs/dev/DESIGN-v0.3-server-side.md`, now in the repository with the reviews). Security
relevant: upgrade if you rely on the default `discard` behaviour or on kubectl rules.

### Fixed
- **An untrustworthy rule could force ESCALATE through an unresolved condition.** When an
  intent's environment (or, without tzdata, a rule's time window) could not be resolved, every
  matching rule forced ESCALATE before its integrity or authority was checked, so an
  unauthorized or tampered rule scoped on `env: prod` could stall any action whose environment
  was unknown. Those rules are now discarded (reported in `discarded[]`) on that path too, as
  they are when they match outright; `--on-untrusted-match escalate` keeps the old behaviour
  for them. Found by the council review of the v0.3 design.
- **kubectl normal forms.** `kubectl drain node1` (and `cordon`/`uncordon`) parsed to
  `node1/*` instead of `node/node1`; `exec`, `logs`, `attach`, `port-forward` on a bare pod
  name parsed to the bare name instead of `pod/<name>`; plural and short kinds such as
  `storageclasses`, `sc`, `ingressclasses`, `clusterrolebindings`, `crd` were not normalised.
  A rule written for the normal form missed each of these. Rules written against the old forms
  need updating (see `docs/constraints.md`).
- `kubectl drain … --ignore-daemonsets` (and `--delete-emptydir-data`, `--disable-eviction`)
  was rejected as malformed.
- A global option before `rollout` or `set image` was read as the subcommand:
  `kubectl -n prod rollout restart deploy/web` became the action `rollout--n` on `prod/*`
  (losing the namespace, so a namespace-scoped rollout rule missed it), and
  `kubectl --as admin rollout restart …` escaped the impersonation rule. The subcommand is now
  taken before global options are merged, and global options between the verb and its
  subcommand (`kubectl rollout --as admin restart …`, which kubectl accepts) are consumed the
  same way, so every placement parses identically. An unrecognised option there still fails
  closed.

### Changed
- kubectl `--as` / `--as-group` / `--as-uid` are no longer dropped: they are recorded in
  `params.impersonate`, and each impersonated identity becomes its own `impersonate` intent
  (`user/<name>`, `group/<name>`, `uid/<id>`). Impersonation moves a request out of an agent
  identity's scope on the server side, so the client hook is the one layer that sees it.
- The example policy blocks kubectl impersonation (`block-kubectl-impersonation`); change its
  effect to ESCALATE if a human should be able to approve it. The example store now loads 30
  rules.

## [0.2.0] — 2026-09-27

**Real trust roots, step 1.** A rule can cite a signed commit in a policy repository, and its
principal is the commit's verified signer (SSH or GPG) rather than a name written in the rule
or asserted with the shared signing key. Together with 0.1.7 (Git sources, SSH), this completes
step 1 of the v0.2 roadmap (`docs/dev/PLAN.md` §9; design in
`docs/dev/DESIGN-v0.2-git-sources.md`). Opt-in: nothing changes unless a rule cites `git:`.
Still to come: per-principal public-key signing for the other policy files (step 2) and
Slack/Jira sources (step 3).

### Added
- **OpenPGP (GPG) signatures for Git sources**, alongside SSH. A GPG signer is listed with its
  primary fingerprint and armored public key; Aegis verifies against a private keyring holding
  exactly those keys (a mismatch is a load error), so neither the user's keyring nor the
  repository's config can add trusted keys. Expired and revoked keys do not verify.
- `aegis sources`: one line per constraint with its source transport (`git`, `file`,
  `unchecked`), the verified principal, or the quarantine reason; exits 1 if any rule is
  quarantined.
- `aegis init` writes commented `repos.example.yaml` and `signers.example.yaml` (inert until
  copied to `repos.yaml` / `signers.yaml`).

## [0.1.7] — 2026-09-27

Git sources: a rule can cite a signed commit, and its principal is the commit's verified
signer. Opt-in; nothing changes unless a rule cites `git:`.

### Added
- **Git sources with signature-derived principals** (v0.2 step 1,
  `docs/dev/DESIGN-v0.2-git-sources.md`). A constraint may cite
  `git:<repo>@<sha>:<path>` in a locally configured clone (`repos.yaml`); its principal is the
  verified SSH signer of that commit, mapped through `signers.yaml`, instead of a name in the
  rule or `PRINCIPALS.yaml`. New quarantine reasons: `invalid-source-ref`, `unknown-repo`,
  `unknown-commit`, `unsigned-source`, `unknown-signer`, `commit-does-not-touch-source`,
  `superseded`, `stale-source`, `invalid-git-source`. New options `--repos`, `--signers`,
  `--max-source-age`. Git runs with a from-scratch environment and overrides for every
  signature setting, so a repository's own config cannot choose the trusted keys. Shallow and
  grafted clones are refused (they change which parents Git reports), the commit-graph cache is
  off, and "did this commit add the rule" is read from the signed commit object. A `git:`
  citation with no Git configuration is always rejected (`unknown-repo`). File sources are
  unchanged.

## [0.1.6] — 2026-09-27

A correction to the published benchmark. No change to how a decision is made.

### Fixed
- **The agent-harness benchmark rows were scored against rules they were never shown.** The
  `claude-cli*`, `codex*` and `ollama` rows are shown only the corpus's 100-constraint holdout
  subset, but were scored against the reference oracle over all 500 constraints. On the 120
  hold-out intents the oracle's verdict differs between the two for 37 intents, and 11 of the
  30 poison candidates involve poisoned rules outside the 100. So those rows were marked as
  missing legitimate rules they never saw (recall 0.72–0.77) and as resisting poisoned rules
  they never saw. Each row is now scored against the oracle over exactly the rules it was
  given (`scored_against` in `results/benchmark.json`). The same cached answers, re-scored
  (no model was re-run): poison-susceptibility **1.000** for six of the seven models and
  **0.789** for `gpt-6-luna` (previously reported as 0.23–0.33), recall 0.97–1.00. The earlier
  numbers **understated** how often the models act on poisoned rules. The 0.1.2 entry below
  ("All land between 0.23 and 0.33 poison-susceptibility and every one acts on 5 of 8 forged
  rules") is wrong for that reason.
- This also accounts for the gap between the Sonnet 5 API self-check (1.000) and the
  `claude-cli-sonnet` row (previously 0.333): the latter was scored against 400 rules it never
  saw.

### Added
- `aegis-holdout`: Aegis restricted to the same 100-constraint subset, so there is a
  like-for-like row on that basis (0 of 19 poison candidates acted on, over-block 0.000).
- Tests that every published row is scored on the basis it was shown, and that the holdout
  oracle only ever sees the holdout constraints.
- The repository is a Gemini CLI extension (`gemini-extension.json`, `hooks/hooks.json`):
  `gemini extensions install https://github.com/moneytool/aegis-devops`.

### Changed
- The Claude Code plugin moved to `plugins/claude/` (the marketplace entry points there, so
  `claude plugin marketplace add moneytool/aegis-devops` and the install command are
  unchanged). Gemini CLI reads an extension's hooks from `hooks/hooks.json` at the root, where
  the Claude plugin's hooks used to be.

## [0.1.5] — 2026-09-27

Gemini CLI and OpenCode join the supported agents; all seven are live-tested. No change to how
a decision is made.

### Added
- `aegis hook gemini` / `aegis install gemini`: a `BeforeTool` hook on Gemini CLI's
  `run_shell_command`.
- `aegis hook opencode` / `aegis install opencode`: OpenCode's hooks are JavaScript plugins, so
  the installer writes a bundled plugin (`tool.execute.before`) that hands each `bash` command
  to `aegis hook opencode` and throws when Aegis says no.

## [0.1.4] — 2026-09-27

A GitHub Copilot plugin, and a fix to the forged-source demo. No change to how a decision is
made.

### Added
- A GitHub Copilot plugin (`plugins/copilot/`, Agent Plugins 1.0):
  `copilot plugin install moneytool/aegis-devops:plugins/copilot`. It runs the same wrapper as
  the Claude Code plugin, so without `aegis` installed it still allows everything outside
  opted-in projects instead of failing every command.

### Changed
- Copilot replies now carry VS Code's `hookSpecificOutput` shape as well as Copilot CLI's
  top-level `permissionDecision`, since both read the same hook files and plugins.

### Fixed
- `data/sources-forged/` lacked the eight sources added with the default rules, so the
  `--sources data/sources-forged` demo quarantined 9 of 29 rules and refused to decide.

## [0.1.3] — 2026-09-27

Aegis can now sit in front of a coding agent's shell commands, and the example policy blocks
the obviously infrastructure-breaking ones. No change to how a decision is made.

### Added
- `aegis hook <agent>`: runs as the pre-tool hook of Claude Code, Codex CLI, GitHub Copilot
  CLI, VS Code agent mode or Cursor, reads that agent's payload and answers in its format.
  It acts only in projects that opted in (`.aegis/` here or above, `$AEGIS_CONFIG_DIR`, or
  `~/.config/aegis`) and blocks only what the policy blocks; an unusable policy or a command
  that cannot be analysed blocks only infrastructure commands. See `docs/agents.md`.
- `aegis install <agent> [--user] [--remove]` writes (or removes) that hook in the agent's
  config without touching its other settings.
- A Claude Code plugin and marketplace (`.claude-plugin/`, `hooks/`):
  `claude plugin marketplace add moneytool/aegis-devops`.
- Default rules in the example policy for infrastructure-breaking commands: `terraform destroy`
  / `tofu destroy` / `apply -destroy`, `pulumi destroy` and `stack rm`, deleting a Kubernetes
  namespace, an S3 bucket, an RDS database, a GCP project or an Azure resource group (BLOCK),
  and deleting an Argo CD application (ESCALATE). The example store now loads 29 rules.
- `terraform`/`tofu` `destroy` (and `apply -destroy`) are recognised from the command line as
  a `terraform` `delete` intent on `workspace/<dir>`; other terraform subcommands still need a
  plan and are not gated from their argv.

### Changed
- The design notes and review history (`PLAN.md`, `REVIEW*.md`, `FEEDBACK.md`) moved to
  `docs/dev/`.

## [0.1.2] — 2026-09-26

No change to how a decision is made. Released so the PyPI page and the Zenodo record carry the
full benchmark.

### Added
- The benchmark now covers seven agent-harness models across two vendors: Claude Haiku 4.5,
  Sonnet 5, Opus 5 and Fable 5.1 through `claude -p`; `gpt-6-astra`, `gpt-6-sol` and
  `gpt-6-luna` through `codex exec`. All land between 0.23 and 0.33 poison-susceptibility and
  every one acts on 5 of 8 forged rules; Aegis acts on none of the 30 poisoned intents.
- `scripts/run_until_done.sh` runs a verifier to completion across CLI usage limits: it waits
  for the reset time the CLI reports and resumes from the cached answers.
- `scripts/make_latency_svg.py`: the latency chart is generated from `results/latency.json`, and
  the docs drift test fails if it is stale.

### Changed
- A decision is now O(k) in the matching (provider, action) bucket rather than O(n) in the
  store: the environment and time-window checks scanned every constraint. p99 at 10,000
  constraints fell from 5.9 ms to 3.7 ms.
- Latency figures report p95/p99 only; p50 fell between the cheap no-match decisions and real
  matches and described neither.

### Fixed
- LLM benchmark runs could not resume: the recording client never read its own cache, so every
  run re-asked every prompt. A usage-limit reply was cached as an empty answer; it now raises
  and is never cached.
- Each call verifies the model that actually answered; a mismatch stops the run instead of
  recording one model's numbers under another's name.
- `.gitignore` excluded all of `results/`, so its whitelist had never applied; the harness caches
  and the preserved fail-closed results are now tracked.
- A timing test that failed on shared CI runners was replaced by a count of the work done.

### Known
- Loading a store with `--sources` is about 35% slower than first measured, most likely from
  the path-traversal guard resolving every source path; it is a once-per-load cost.

## [0.1.1] — 2026-09-24

Documentation and packaging only; no change to the decision engine. Released so the PyPI
page carries the current README, and so the release is archived on Zenodo with a DOI.

### Added
- Codex CLI (`gpt-6-astra`) and Claude Code CLI (Haiku) rows in the benchmark. Both are
  agent harnesses rather than raw completions, scored on a 100-constraint hold-out subset.
- `SECURITY.md`, `CITATION.cff`, and this changelog.
- `scripts/make_benchmark_svg.py`: the benchmark chart is generated from
  `results/benchmark.json` instead of drawn by hand.
- `tests/test_docs_consistency.py`: CI now fails if a results table, the chart, a corpus
  diversity figure, or a description of the default policy disagrees with the data or the
  code.

### Changed
- The README is now a short entry point; reference material moved to `docs/cli.md`,
  `docs/constraints.md`, `docs/configuration.md` and `docs/benchmark.md`.
- The quick start leads with `pip install` and `aegis init ./.aegis`. Without `init`, a fresh
  install had no policy files and every check exited 66.
- The alpha caveats moved from a banner at the top of the README into Project status.

### Fixed
- `docs/cli.md` and `docs/configuration.md` still described the old escalate-on-untrusted
  default and showed ESCALATE output for tampered and forged rules. On 0.1.0 both examples
  ALLOW, with the rule named in `discarded` and in store health. They now show real output
  from the current code.
- `docs/benchmark.md` quoted the previous corpus's diversity figures and called
  `evade-case-variant` an `xfail`.

## [0.1.0] — 2026-09-23

First release. Published to PyPI as `aegis-devops`.

### Added
- **Constraint store** with two independent guarantees per rule: integrity (a provenance hash
  over the source-side fields) and authority (which principal may assert which class of rule).
  Schema validation, quarantine with reasons, and signed policy files.
- **Interceptor** returning ALLOW / BLOCK / ESCALATE with citations, discarded rules, coverage,
  notes and latency. Dry runs are never blocked but report the verdict a real run would get.
- **Parsers** for kubectl, Terraform and OpenTofu plans, AWS, Azure, gcloud/gsutil, Helm,
  ArgoCD, Flux, git, the GitHub CLI, Pulumi, and SQL/mongo/migration tools — all normalising to
  one intent shape. `aegis check command` splits a whole shell string, since that is what an
  agent framework hands you.
- **Plan-level constraints** evaluated over a whole batch (`max_intents`, `max_matching`,
  `forbid_together`, `ratio`).
- **Environment identity mapping** from kube contexts, cloud accounts, projects, subscriptions
  and repos, so rules scope on `env: prod` rather than raw identifiers. An unresolved
  environment escalates rather than being treated as "not prod".
- **Rate-limited constraints** backed by a locked, hash-chained, rotating decision ledger
  (JSONL or SQLite).
- **Signing** of policy and source files, with per-directory manifests, and `aegis sign` /
  `aegis verify` / `aegis keygen`.
- **CLI** with `aegis init`, config discovery, structured decision logs, a Prometheus textfile
  exporter, and `--exit-style claude-hook` plus a ready-made Claude Code PreToolUse hook.
- **Evaluation**: a 500-constraint labelled corpus (323 distinct structures) seeded from public
  postmortems, the Gatekeeper library, and cloud security benchmarks; an independent reference
  oracle so ground truth never runs the system under test; an adversarial suite of attacks in
  five categories; and a benchmark against OPA, a signed-bundle OPA variant, and real LLM
  self-checks.

### Changed
- An untrustworthy matching constraint (tampered, forged, or from an unauthorized principal)
  gets **no vote** by default. An earlier default made it force ESCALATE; measurement showed
  that scored the same poison-susceptibility and over-block rate as a verifier with no trust
  model at all, because letting an unverifiable rule produce a verdict hands whoever planted it
  control over that verdict. The old behaviour is available as `--on-untrusted-match escalate`.

### Known limitations
See "Project status" in the README and [`docs/dev/PLAN.md`](docs/dev/PLAN.md) §8. In short: the source fetcher reads files
rather than real connectors, signing uses a shared secret, and a principal is a signed name
rather than a bound identity.

[1.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.1
[1.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.0
[1.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.1.0
[1.0.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.0.0
[0.3.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.2
[0.3.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.1
[0.3.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.0
[0.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.1
[0.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.0
[0.1.7]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.7
[0.1.6]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.6
[0.1.5]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.5
[0.1.4]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.4
[0.1.3]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.3
[0.1.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.2
[0.1.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.1
[0.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.0
