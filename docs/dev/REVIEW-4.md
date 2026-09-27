# Aegis-DevOps — Review, Round 4 (AI Council, post-engine)
**Date:** 2026-09-21
**Reviewing:** commit `97d3a4b` — full engine (20 CLI targets, plan constraints, ledger, env map, forged quarantine), corpus, benchmark, docs.
**Council:** Security Architect (Fable 5.1) · DevOps Principal / SRE (Opus 5) · ML Researcher / PC reviewer (Sonnet 5). Each seat worked read-only and reproduced its findings by running the CLI. The consolidator (Opus 5) re-ran the Critical items before ranking.
**Previous rounds:** `FEEDBACK.md` (scope), `REVIEW.md`, `REVIEW-2.md` (plan), `REVIEW-3.md` (first code).

---

## Verdict

**Three seats, one conclusion: the decision core is correct; the enforcement boundary around it is not.** The interceptor's match → integrity → authority → effect pipeline does what the paper claims and is well tested. But (1) three ordinary `kubectl`/`git` invocation shapes bypass every rule with exit 0, (2) every degraded-store condition — typo in the authority file, a hand-edited rule, an unrecognised verb — produces the same `ALLOW` / exit 0 as a legitimately allowed action, and (3) the headline benchmark number is a unit-test result dressed as a measurement, because ground truth comes from Aegis itself.

PC score from the research seat: **3/5 — weak accept if the three must-have experiments land; reject as currently evidenced.** SRE seat: **not deployable in front of a real agent yet.** Security seat: **the trust root doesn't exist yet** (unkeyed hash, unsigned authority/env files).

None of this is architectural. Every Critical item below is a contained fix.

---

## Priority 0 — Critical (fix before anything else)

### T0.1 Global flags before the verb produce garbage intents that ALLOW
**Seats:** Security C1, SRE #2. **Reproduced by consolidator.**
`parser.py:282` takes `argv[1]` as the verb unconditionally (git at `:1488` likewise).
```
$ aegis check kubectl -- kubectl -n prod delete deployment/x      → 3× ALLOW, exit 0 (action is literally "-n")
$ aegis check git     -- git -C /repo push -f origin main         → ALLOW git read history/*, exit 0
$ aegis check kubectl -- kubectl --context=prod delete node/w1     → ALLOW (verb = "--context=prod")
```
**Do:** For every argv parser, consume leading global options (kubectl: `-n/--namespace/--context/--cluster/--kubeconfig/-s/--server/-o/-v`; git: `-C/-c/--git-dir/--work-tree/--no-pager`; helm: `-n/--kube-context/--kubeconfig`; az/gcloud/aws already handle this — verify) *before* selecting the verb. Raise `ValueError` if the selected verb starts with `-`.
**Accept:** The three commands above → BLOCK / BLOCK / BLOCK. A parametrised test runs every parser with its global flags in front of the verb and asserts the same intent as the flags-after form.

### T0.2 Glued short flags, label selectors, comma kinds, and namespace cascade
**Seats:** Security H2, SRE #2. **Reproduced by consolidator** (`-nprod` case).
```
kubectl scale deployment/api --replicas=5 -nprod        → ALLOW (should BLOCK in window)
kubectl delete -l role=worker node                       → resource "role=worker/node"
kubectl delete nodes,pods --all --context prod-us-east   → resource "nodes,pods/*"
kubectl delete namespace prod --context prod-us-east     → ALLOW (cascades every object in the ns)
helm uninstall web -nprod                                → ALLOW
```
**Do:** Expand `-nVALUE`, `-lVALUE`, `-fVALUE`, `-oVALUE` short-flag forms. Treat `-l/--selector/--field-selector` as value flags → `params["selector"]`, resource `kind/*`. Split kinds on `,` into multiple intents. Add a `namespace/<name>` delete → also emit a synthetic `*/*` delete intent scoped to that namespace so `scope: {namespace: prod}` rules fire (or ESCALATE unconditionally on namespace deletion — pick one, document it).
**Accept:** Each line above hits the rule a constraint author would expect. Test per case.

### T0.3 Degraded store is indistinguishable from "allowed"
**Seats:** Security C3, SRE #1, #12. **Reproduced by consolidator** (bit-flip → ALLOW exit 0).
A one-character hash edit, a `principal:` vs `principals:` typo, a YAML typing change (`end: 17:00` unquoted → int), an empty constraints file, or a verb nobody wrote a rule for all yield `ALLOW`, exit 0, `discarded: []` in the per-intent JSON. Quarantine is only printed inside the plan summary. `logger.warning` goes to an unconfigured stderr handler.
**Do:**
1. Emit a `store_health` object on every output (`loaded`, `quarantined: [{id, reason}]`, `principals`, `constraints_path_sha256`) — in the per-intent JSON, the plan line, and `--pretty`.
2. Hard-fail (exit 64+, no verdict) when the loaded store has zero constraints, the authority map has zero principals, or `quarantined / (loaded + quarantined) > --max-quarantine-ratio` (default 0.1).
3. A quarantined or discarded constraint whose `effect` was BLOCK/ESCALATE must contribute **ESCALATE** to the verdict (fail-closed on integrity failure), reported with reason. Flip `tests/test_adversarial.py:172` accordingly — a tampered BLOCK rule yields ESCALATE, not ALLOW.
4. `--fail-closed`: `covered: False` → ESCALATE.
**Accept:** Bit-flipped hash → ESCALATE exit 2 with `store_health.quarantined` populated. Empty authority file → exit 65 with a one-line message, no traceback. `covered: False` under `--fail-closed` → exit 2.

### T0.4 Exit-code contract collides with argparse and inverts under Claude Code hooks
**Seat:** SRE #4.
`ESCALATE = 2` collides with argparse usage errors (also 2). Claude Code `PreToolUse` hooks treat exit 2 as *block* and any other non-zero as *non-blocking error* — so Aegis BLOCK (3) would **not** block a Claude Code agent, and a usage error would. Bad `--now`, missing files, and a trailing `-n` with no value all traceback (exit 1, undocumented).
**Do:** Catch every exception in `main()`; tool errors exit 64 (`EX_USAGE`) / 65 (`EX_DATAERR`) / 66 (`EX_NOINPUT`) with a one-line stderr message. Add `--exit-style {aegis,claude-hook,ci}`: `claude-hook` maps BLOCK and ESCALATE → 2 and prints `{"decision":"block","reason":…}`; `ci` maps any non-ALLOW → 1. Document the full table in the README. Ship `examples/claude-code-hook.sh` (see T1.2).
**Accept:** README exit-code table has no overlaps; `aegis check kubectl --typo` → 64; `--exit-style claude-hook` on a BLOCK → 2.

### T0.5 The benchmark's ground truth is the system under test
**Seat:** Research #1, #2. **Consolidator agrees; this was disclosed in the README but is still the paper's central weakness.**
`build_corpus.py` computes `expected_verdict` by running `AegisInterceptor`. `split.json` exists but `benchmark.py` defaults to `--split all`, and the split filters *constraints* not *intents*, so `--split holdout` is not a held-out test set. `coverage` means different things per verifier (`interceptor.py:88` vs `llm.py:130`).
**Do:**
1. Write `scripts/reference_oracle.py` — an independent, deliberately naïve oracle that derives `expected_verdict` from `labels.jsonl` + a minimal matcher (provider ==, fnmatch, action ∈, scope ==, window) **without importing `aegis_core.interceptor`**. Regenerate `intents.jsonl` from it. Aegis's F1 against this oracle is then a real number (and if it isn't 1.0, that's a finding).
2. Split *intents* (and the seeds they derive from), not constraints. Make `--split holdout` the default for reported numbers; `all` only with `--i-know-this-is-dev`.
3. Define `covered` once — "≥1 constraint matched before any filter" — computed by the harness from the same match step for every verifier.
4. Report `n_distinct = 196` structural cases alongside `n = 500` (see T2.2).
**Accept:** `results/benchmark.md` header shows `split: holdout`, `oracle: reference`, both `n` and `n_distinct`; Aegis's row is a measurement, not a sanity check; the README caveat is removed.

---

## Priority 1 — High

### T1.1 No root of trust: hash is unkeyed; authority, environments, plan files unsigned; source files self-assert `principal`
**Seat:** Security C2. Consolidator note: PLAN §8 already lists "`principal` is a string"; the seat's point is stronger — with `--sources`, a forged Trusted constraint needs *no secret*, because the source file supplies its own `principal`.
**Do (v1, cheap):** `aegis sign --key K data/*.yaml data/sources/` writes `<file>.sig` (HMAC-SHA256 or Ed25519 via stdlib-free `hashlib.blake2b(key=)`); loaders refuse unsigned/mis-signed files unless `--insecure`. The fetcher returns `principal` from the *transport* (file owner / directory ACL for v1; commit signer / Slack user ID later), never from the payload.
**Do (paper):** State the threat model precisely: Aegis defends against poisoned *content* from a source the operator has already decided to trust; it does not defend against an attacker with write access to the policy directory. That is a legitimate boundary — say it.
**Accept:** Unsigned `constraints.yaml` → exit 65. Test: source file with `principal: admin` but transport says `developer` → `unauthorized`.

### T1.2 Shell-string integration doesn't exist
**Seat:** SRE #3. Every agent framework hands over a *string*; `aegis check argv` treats `;`, `&&`, `|`, `$(…)` as resource names and rejects `sudo`/`env`/`timeout`/`k` wrappers with exit 1.
**Do:** Reject any token containing shell metacharacters with exit 64 unless `--split-compound`, which uses a small stdlib tokenizer (no `bashlex` dependency: split on `;`, `&&`, `||`, `|` outside quotes) and checks every simple command, unwrapping `sudo`, `env VAR=…`, `timeout N`, `nice`, `command`, and an alias table (`k`→`kubectl`, `tf`→`terraform`). Ship `examples/claude-code-hook.sh` and `examples/langgraph_node.py` that use it.
**Accept:** `"kubectl get pods; kubectl delete node/w1"` → BLOCK. `"sudo kubectl delete node/w1"` → BLOCK. `"kubectl get pods | grep x"` → ALLOW (pipe into non-command).

### T1.3 `env` resolves for four providers only, and for kubectl only with `--context` on the argv
**Seats:** Security H1, SRE #5. `scope: {env: prod}` is unexpressible for helm, argocd, flux, gh, pulumi, terraform, and silently absent for kubectl when the agent relies on the kubeconfig current-context (the default).
**Do:** `EnvironmentMap.resolve` must consult `context`/`cluster`/`project`/`account`/`subscription`/`resource_group` regardless of provider. Add `--resolve-current-context` (reads `$KUBECONFIG`/`~/.kube/config` current-context, `AWS_PROFILE`/`AWS_DEFAULT_REGION`, `CLOUDSDK_CORE_PROJECT`, `HELM_NAMESPACE`) — opt-in, documented as "trusts the invoking environment". Add `argocd_apps` and `terraform_workspaces` maps to `environments.yaml`. When any matched constraint scopes on `env` and the intent has no `env` → ESCALATE with note `env-unresolved`.
**Accept:** `helm uninstall web --kube-context prod-us-east` → env=prod → BLOCK. `kubectl delete pod/x -n prod` (no context, no flag) against an env-scoped rule → ESCALATE `env-unresolved`, not ALLOW.

### T1.4 SQL / Mongo classifier misses the obvious destructive shapes
**Seat:** Security H3.
```
TRUNCATE users / DROP TABLE users        → not unbounded → the unbounded-delete rule misses
WITH d AS (DELETE FROM users …) SELECT … → read
EXPLAIN ANALYZE DELETE FROM users        → read (Postgres executes it)
DELETE/**/FROM users                      → unclassified
psql -c "DELETE …" -c "SELECT 1"          → only the last -c is checked
psql -f not-yet-written.sql               → uncovered ALLOW (agent writes the file after the check)
db.getCollection("users").deleteMany({})  → unclassified; db.users.drop() → not unbounded
```
**Do:** `unbounded: true` for TRUNCATE, DROP TABLE/SCHEMA/DATABASE, `.drop()`, `.dropDatabase()`. Strip comments before classification. Scan CTE bodies and `EXPLAIN ANALYZE` for DML (classify by the *strongest* statement found). Collect all `-c`. Missing `-f` file → ESCALATE `script-unreadable`. Handle `getCollection(...)` and bracket access. `sql-block-database-delete` pattern should be `{database,schema}/*` or two rules.
**Accept:** Each line above → BLOCK or ESCALATE. Add these as `evasion` attacks in the adversarial suite.

### T1.5 Agent-controlled `params` shadow operator-derived `metadata` in scope matching; string/bool mismatches; `--dry-run=false` is a dry run
**Seat:** Security H4. `store.py:202` merges `{**metadata, **params}` so `--env=dev` beats a resolved `env: prod`; `argocd --prune=true` yields the string `"true"` ≠ `True`; argocd/flux set `dry_run` for `--dry-run=false`.
**Do:** Match scope keys against `metadata` first; `params` may only supply keys `metadata` lacks. Coerce `"true"/"false"` for known boolean flags everywhere (one helper). `dry_run` only when the value is absent or truthy — every parser (kubectl and helm already do this; fix argocd, flux, and audit aws/az/gcloud).
**Accept:** `kubectl delete pod/x --context prod-us-east --env=dev` → BLOCK. `argocd app sync prod-web --prune=true` → ESCALATE. `argocd app sync x --prune --dry-run=false` → ESCALATE, `dry_run: false`.

### T1.6 Terraform/Pulumi plan matching is address-fragile and unbound to what gets applied
**Seat:** Security H5. `module.app.aws_instance.web` misses `aws_instance.*`; region absent when `var.region` has no constant; the checked JSON can differ from the applied plan.
**Do:** Match `resource_pattern` against both the full address and `type.name` (strip `module.*.` prefixes). Resolve region from `variables` / `planned_values` / `provider_config` expressions. Record `plan_sha256` of the JSON in the decision; ship a wrapper (`examples/terraform-gate.sh`) that runs `terraform show -json <exact .tfplan>` itself and passes the hash through to `apply`.
**Accept:** `module.app.aws_db_instance.main` delete → BLOCK via `plan-no-db-deletes`. Decision JSON carries `plan_sha256`.

### T1.7 Provider-namespace aliases bypass rules written for the normal form
**Seat:** Security H6. `git push -f` with no refspec → `ref/*` (misses `ref/main`); `aws s3api delete-bucket` → `s3api/…`; `az resource delete --ids …/managedClusters/c` → `resource/*`; `gh api -X POST …/workflows/deploy-prod.yml/dispatches` → `api/…`.
**Do:** `git push -f`/`--mirror` with no refspec → ESCALATE (`unknown-target`). `s3api` → `s3`. Parse ARM `--ids` paths into `<provider>/<kind>/<name>`. Map `gh api` workflow-dispatch paths to `workflow/<file>` action `run`.
**Accept:** All four → the rule the author expected.

### T1.8 No validation at load ("schema-strict" is not true)
**Seats:** Security M1, SRE #8. `effect: Block` / `DENY` → **cited as the reason to ALLOW**. Duplicate ids → last wins silently. `days: [Friday]` never matches. Missing `actions:` → traceback.
**Do:** Validate at load: `effect ∈ {BLOCK, ESCALATE}`, `provider` non-empty, `actions` non-empty set of strings, `days ⊆ {Mon…Sun}` (accept full names, normalise), `HH:MM`, `tz` resolvable via `zoneinfo`, unique `id`. Quarantine with reason `invalid` (counts toward the T0.3 ratio). Effect matching in the interceptor must fail closed: unknown effect → ESCALATE.
**Accept:** Each malformed input above → quarantined `invalid`; never a traceback; never cited as an ALLOW reason.

### T1.9 Ledger has no locking and no rotation; rate limits can't bucket per resource
**Seats:** SRE #6, #7; Security M4. 16 concurrent processes against `max: 3` → 7–9 ALLOWs. `key: [cluster]` silently ignored because the cluster name is in `resource`. Truncating the file resets every limit. A corrupt line crashes every later check.
**Do:** `fcntl.flock` around load → count → record (or SQLite `BEGIN IMMEDIATE`). Prune records older than the largest window on load. Support `key: [resource]`. Warn at load when a `key` names a field no parser emits. Skip and count malformed lines instead of raising. Hash-chain records (`prev_sha256`) so truncation is detectable.
**Accept:** 16-process barrier test → exactly 3 ALLOW. `key: [resource]` buckets `prod-1` and `prod-2` separately. Truncated ledger → `store_health.ledger: "chain-broken"` and ESCALATE for rate-limited rules.

---

## Priority 2 — Before the paper

### T2.1 Run the real baselines
**Seat:** Research #3. `llm-heuristic` is the straw man REVIEW-2 §2 warned about. OPA has never been run.
**Do:** Install `opa`, add the row. Run the real LLM baseline twice: naïve prompt (as PLAN §4) and a **provenance-aware** prompt that also gives the model `authority.yaml` and the hashes and asks it to verify. Report both. Add a **signed-bundle OPA** variant that quarantines `tampered`/`forged` but not `unauthorized` — that is the honest competitor, and the delta on the `unauthorized` class is the paper's contribution.
**Accept:** Four baseline rows in `results/benchmark.md`: `opa`, `opa-signed`, `llm-naive`, `llm-aware`.

### T2.2 Corpus diversity and attack realism
**Seat:** Research #4. 500 constraints = **196** distinct `(provider, pattern, actions, scope)` tuples, 71 distinct patterns, 66 distinct `rule_text`s. `tampered`/`forged` model *post-ingest* attacks; `unauthorized` is the realistic pre-ingest attacker, and `poison_susceptibility` lumps them.
**Do:** Report `n_distinct` everywhere `n` appears. Split `poison_susceptibility` into `ps_unauthorized`, `ps_tampered`, `ps_forged`. Add ≥ 30 seeds from a third source family (e.g. cloud-provider well-architected/security-hub findings) to raise pattern diversity. Name the attack model explicitly in PLAN §4.
**Accept:** `n_distinct ≥ 300`; three PS columns.

### T2.3 Latency scaling and sample size
**Seat:** Research #5; SRE #13 measured it: matching is O(n) — p50 0.04 ms @100, 0.25 ms @1k, 2.3 ms @10k; load is 3.7 s @10k with the pure-Python YAML loader (0.6 s with `CSafeLoader`).
**Do:** Add `scripts/latency_sweep.py` (100 / 500 / 2.5k / 10k constraints, ≥ 2 000 decisions each, bootstrap CI on p99). Use `yaml.CSafeLoader` when available. Index the store by `(provider, action)`.
**Accept:** A latency-vs-N figure in `docs/`; p99 reported with a CI.

### T2.4 Time-window semantics
**Seats:** Security M2, SRE #9. Overnight windows (`22:00–06:00`) never match; `end` is inclusive to the minute so 23:59:30 is outside `…–23:59`; a window without `tz` inherits whatever `now` carries; `--now` is caller-supplied and also shifts rate-limit windows.
**Do:** Support `start > end` wrap-around; treat `end` as exclusive at minute granularity (document); require `tz` per window or a store-level `default_tz`; reject naïve `--now`; `--now` only honoured with `--allow-now-override` (tests) — production uses the clock.
**Accept:** Tests for each; `days` exclusion and naïve-`now` branches (currently uncovered) covered.

### T2.5 Scope vocabulary and matching semantics
**Seat:** SRE #10. gcloud `--zone` overwrites `region`; terraform `create` never carries region; `helm --set a=1,b=2` → `{"a": "1,b=2"}`; YAML int vs str (`account: 123456789012`); no glob / OR / nesting in scope values.
**Do:** One documented `metadata` vocabulary table per provider in the README (`region`, `zone` (and `region` derived from zone), `namespace`, `context`, `cluster`, `project`, `account`, `subscription`, `resource_group`, `env`). Coerce scope values to `str` before comparing. Allow lists (OR) and globs in scope values, and dotted paths (`set.replicaCount`). Parse comma-separated `--set` and `--set-string`.
**Accept:** Rule #5 from the SRE expressibility table ("block `helm --set replicaCount=0` in prod") is expressible and fires with a second `--set` present.

### T2.6 Config discovery, packaging, structured logging
**Seats:** SRE #11, #12, #14. Defaults are CWD-relative `data/*.example.yaml`; from any other directory the CLI tracebacks and 66 tests fail. No `AEGIS_*` env vars. `pyproject` mixes PEP 639 `license` with `setuptools>=68`; no `readme`/`urls`/`classifiers`; data files aren't package data. No structured decision log except the ALLOW-only ledger.
**Do:** `AEGIS_CONFIG_DIR` / `--config-dir` with search order `$PWD/.aegis`, `~/.config/aegis`, `/etc/aegis`; ship the example files as package data for `aegis init`. `--log-json PATH` appending every decision (all verdicts) with `store_health`. Fix `pyproject` (`setuptools>=77`, `readme`, `urls`, `classifiers`, `package-data`). Use tests' `conftest.py` to `chdir` to the repo root so the suite passes from anywhere.
**Accept:** `cd /tmp && aegis check kubectl -- kubectl get pods` gives a clear "no config found" message, exit 66. `pytest` passes from `/tmp`. `pip wheel .` succeeds.

### T2.7 README accuracy
**Seat:** SRE #15. Demo prints 13 not 14; first-call latency is ~2.5 ms (lazy `zoneinfo` import), not 0.14; the `--sources` example demonstrates nothing because every example source is consistent; exit-code table omits 1 and 2-collision.
**Do:** Fix the numbers; import `zoneinfo` at module top; add a deliberately forged example (`data/sources-forged/`) so the `--sources` demo shows a quarantine; document exit codes per T0.4.
**Accept:** Every README command re-run and its output pasted verbatim (as Section E did).

---

## Priority 3 — Low / hygiene

- **L1** Error paths that traceback: bad JSON in a source file, `principals: {admin: null}`, top-level list YAML, unknown `tz` (and slim containers without `tzdata`). Catch, exit 65, one line. *(Security L1)*
- **L2** `FileSourceFetcher` joins `source_ref` unsanitised (`../../x`). Reject path separators. *(Security L2)*
- **L3** `--json` is a no-op flag; `(dry-run; would be None)` for uncovered dry runs. *(SRE nice-to-have)*
- **L4** `verify_integrity()` re-hashes every match at decision time — fine, add a comment. *(SRE)*
- **L5** Empty `--authority` / key-less `--constraints` files are allow-all; subsumed by T0.3 item 2. *(Security M3)*

---

## What all three seats agreed holds up

- The decision pipeline (`interceptor.py:85-116`) is small, correct, and exercised end-to-end: tampered/unauthorized discard, BLOCK > ESCALATE precedence, dry-run downgrade with `would_be`, authority re-checked per decision.
- `yaml.safe_load` / `json.load` everywhere; no `eval`, no shell-outs. `sh -c`, `sudo`, `xargs`, unknown binaries → exit 1, never 0.
- kubectl alias / case / API-group normalisation, AWS global-flag placement, git refspec forms (`+ref`, `HEAD:refs/heads/main`, `:branch`), `--dry-run=none` semantics — all correct.
- Matching cost is a non-issue (2.3 ms at 10k constraints); load-time quarantine on the 500-constraint corpus with `--sources` is ~60 ms warm.
- The 470 tests are not padded: line coverage ~90 %+ on core modules, assertions are specific, corpus tests check byte-for-byte determinism, and `test_benchmark.py` is honest about the circular F1.
- The environment-mapping design (never infer `env` from namespace, never default to `dev`) is the right call — the problem is only reach (T1.3).
- The benchmark write-up discloses its own circularity; the corpus seeds cite real public sources and the label proportions match the plan rather than being fitted after the fact.

---

## Research seat: contribution statement and must-have experiments

**One-sentence contribution:** *Aegis extends policy-as-code enforcement with a per-constraint authority model — not just tamper-evidence — so that a constraint mined from unstructured operational text can be mechanically checked for both integrity and provenance-of-permission before an autonomous agent acts on it, closing a gap that neither signed OPA/Kyverno bundles (integrity only) nor LLM self-checks (neither) close.*

**Related-work positioning to add to PLAN §2:** OPA/Gatekeeper + signed bundles (Sigstore/cosign, in-toto, SLSA) solve integrity in transit, not authority-by-class; Kyverno is architecturally identical for this comparison; Cedar/Verified Permissions is a stronger authz language with the same gap; NeMo Guardrails / Guardrails AI / Llama Guard are content-safety, a different problem; Claude Code hooks / MCP permissions are the closest *mechanism* (intercept, allow/block/ask) but binary and store-less — Aegis is what such a hook should call. HolmesGPT/RunLore remain correctly positioned as retrieval, not gates.

**Must-have experiments before Nov 19 (priority order):**
1. Break the circularity (T0.5) — Aegis's own precision/recall against an independent oracle is the single number the paper is missing.
2. Run the real baselines (T2.1) — without the OPA row, "why not OPA" is an assertion; the `opa-signed` variant is what a systems PC will ask for.
3. Latency-vs-scale sweep and a held-out poison-susceptibility number at n in the thousands (T2.3, T0.5).

---

## Acceptance protocol for the reviewer

```
venv/bin/python -m pytest -q                                          # from repo root AND from /tmp
venv/bin/python -m ruff check src tests scripts examples
venv/bin/aegis check kubectl -- kubectl -n prod delete deployment/x ; echo $?          # expect 3
venv/bin/aegis check git -- git -C /tmp push -f origin main ; echo $?                  # expect 3
venv/bin/aegis check kubectl --now 2026-09-22T14:00:00Z -- kubectl scale deployment/api-server --replicas=5 -nprod ; echo $?   # expect 3
sed 's/\(provenance_hash: .*\)./\1x/' data/constraints.example.yaml > /tmp/bitflip.yaml
venv/bin/aegis check kubectl --constraints /tmp/bitflip.yaml -- kubectl delete node/x ; echo $?   # expect 2, store_health.quarantined non-empty
venv/bin/aegis check kubectl --typo -- kubectl get pods ; echo $?                       # expect 64
venv/bin/aegis check argv --split-compound -- "kubectl get pods; kubectl delete node/w1" ; echo $?   # expect 3
grep -n "split: holdout\|n_distinct" results/benchmark.md                             # both present
```
