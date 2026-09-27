# Aegis-DevOps — Review, Round 3 (first code review)
**Date:** 2026-09-20
**Reviewing:** `src/aegis_core/*.py`, `tests/*.py`, revised `PLAN.md`
**Previous rounds:** `REVIEW.md` (scope), `REVIEW-2.md` (plan)

This document is written for the implementing model. Each task has a **Do** section (what to change), an **Accept** section (how the reviewer will verify it), and a priority. Do the tasks in order. Do not start Priority 2 until every Priority 1 task is accepted.

---

## Verdict

The plan is now good. The code does not yet implement the plan. Specifically, **the two properties the whole project is about — integrity and authority — are not enforced at decision time.** A tampered constraint and a constraint asserted by an unauthorized principal both still produce `BLOCK`. Until that is fixed, the interceptor is a substring matcher with a hash field bolted on, and the adversarial test suite (Weeks 5-6) would have nothing to attack.

There are also foundational problems: the test that exercises the interceptor contains the model's own abandoned draft and would fail under `pytest`; the package has no `pyproject.toml`; `python src/aegis_core/interceptor.py` crashes on import; there is no git repository.

Scorecard against `PLAN.md` §3 deliverables:

| Deliverable | Status |
| :--- | :--- |
| Constraint Store — schema-strict JSON/YAML, `provenance_hash`, `authorized_principal` | In-memory dict only. Hash is self-generated and proves nothing about the source. Authority check is "is the name in a dict", not "may this principal assert this class". |
| Interceptor — structured intents, returns ALLOW/BLOCK/ESCALATE | Returns ALLOW/BLOCK only. Ignores `provider`, `params`, integrity and authority. Does not return citing sources. |
| Adversarial Test Suite | Not started (expected; Weeks 5-6). But nothing above is attackable yet. |

---

## Priority 0 — Repository hygiene (do first, ~30 minutes)

### T0.1 Initialise git and ignore the right things
**Do:** `git init` in the project root. Create `.gitignore` containing at minimum: `venv/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `*.egg-info/`, `.ruff_cache/`, `data/*.jsonl` (raw generated corpora), `data/*.json` unless it is the seed dataset. Make one commit: `chore: initial commit — plan, reviews, prototype`.
**Accept:** `git log --oneline` shows one commit; `git status` is clean; `venv/` is not tracked.

### T0.2 Make it an installable package
**Do:** Add `pyproject.toml` with `[project] name = "aegis-devops"`, `requires-python = ">=3.11"`, `[build-system]` using setuptools, `[tool.setuptools.packages.find] where = ["src"]`, and `[project.optional-dependencies] dev = ["pytest", "pytest-benchmark", "ruff"]`. Then `venv/Scripts/python.exe -m pip install -e ".[dev]"`.
**Do:** Delete every `sys.path.insert(...)` line from `src/aegis_core/interceptor.py:5` and from all four test files. They are wrong anyway — `interceptor.py:5` resolves to `src/src`, which is why `python src/aegis_core/interceptor.py` crashes with `ModuleNotFoundError`.
**Do:** Remove the `if __name__ == "__main__":` blocks from `store.py` and `interceptor.py`. Library modules do not carry demo code; that belongs in tests or an `examples/` script.
**Accept:** `venv/Scripts/python.exe -c "import aegis_core.interceptor"` works from any directory. `grep -r "sys.path" src tests` returns nothing.

### T0.3 Make the tests real pytest tests
**Do:** Rewrite `tests/test_interceptor.py` from scratch. The current file has `test_interceptor_workflow()` (line 11) which contains a stream-of-consciousness draft ("Wait, the current logic is…", line 45), a `NameError` (`interceptator_fixed`, line 54), and never asserts anything useful. The only assertions that actually run are in the `__main__` block, which `pytest` does not execute.
**Do:** In all test files: remove `print(...PASSED)` lines and `__main__` blocks; one behaviour per `def test_*`; no try/except around the thing under test — use `pytest.raises`.
**Do:** `tests/test_store.py::test_unauthorized_principal` currently *prints* FAILED instead of failing. Replace with `with pytest.raises(PermissionError): ...`.
**Accept:** `venv/Scripts/python.exe -m pytest -q` runs, discovers every test, and exits 0. No test file contains the word "PASSED" or the string `__main__`.

### T0.4 Typos
**Do:** `PLAN.md:12` "Anchered" → "Anchored". `PLAN.md:16` "tamered" → "tampered". `store.py:36` docstring says `rule_annotated` but the parameter is `rule_text`. `interceptor.py:36` "e.s. regex" → "e.g. regex" (or delete the comment; see T1.3).
**Accept:** `grep -rn "Anchered\|tamered\|rule_annotated\|e\.s\." PLAN.md src` returns nothing.

---

## Priority 1 — Make the core claim true

### T1.1 Constraints must be structured, not free text
**Why:** `store.get_matching_constraints` (`store.py:77`) does `resource in rule_text and action in rule_text`. That means an intent with `action="get"` matches a rule containing the word "budget", and `action="scale"` matches "no-scaling" only by the accident of substring. `PLAN.md` §3 says "schema-strict". `REVIEW-2` §4 says structured intents only. A free-text rule cannot be matched deterministically against a structured intent, and it cannot be given an authority *class* (T1.2) because there is no field saying what class it is.

**Do:** Replace the `Dict[str, Any]` constraint with a dataclass (or pydantic model — pick one, add it to `pyproject.toml` if pydantic) with these fields:

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `id` | str | unique |
| `provider` | `"kubernetes" \| "terraform"` | which intent family this applies to |
| `resource_pattern` | str | glob, e.g. `deployment/*`, `node/*`, `aws_instance.*` |
| `actions` | set[str] | e.g. `{"scale", "delete"}` |
| `scope` | dict | optional narrowing: `namespace`, `region`, `cluster` |
| `time_window` | optional | e.g. `{"days": ["Mon".."Fri"], "start": "09:00", "end": "17:00", "tz": "America/New_York"}` — the plan's own example ("during peak hours") needs this |
| `effect` | `"BLOCK" \| "ESCALATE"` | what to do on match |
| `constraint_class` | `"scaling" \| "deletion" \| "configuration" \| ...` | **the authority axis** — what kind of thing this rule asserts |
| `principal` | str | who asserted it |
| `source_ref` | str | Git SHA / Slack permalink / ticket ID |
| `source_timestamp` | str (ISO 8601) | when the *source* said it, not when we ingested it |
| `rule_text` | str | the human sentence, kept for citation only — **never matched against** |
| `provenance_hash` | str | see T1.4 |

**Do:** Matching = `provider` equal AND `fnmatch(intent.resource, resource_pattern)` AND `intent.action in actions` AND scope fields (if present on the constraint) equal the intent's `params`/`metadata` AND (if `time_window` present) the evaluation time falls inside it. Pass `now` into the interceptor as a parameter so tests are deterministic.
**Do:** The store must load from and save to a YAML or JSON file (`ConstraintStore.load(path)` / `.save(path)`). Put a 5-rule example at `data/constraints.example.yaml`.
**Accept:** Tests prove: (a) `action="get"` does not match a rule whose only relation to "get" is a substring; (b) a `deployment/*` rule matches `deployment/api-server` and not `service/api-server`; (c) a time-windowed rule matches at 10:00 local and not at 03:00; (d) a rule with `provider="terraform"` never matches a kubernetes intent; (e) round-trip `save` → `load` yields equal constraints and identical hashes.

### T1.2 Enforce authority by constraint class
**Why:** `store.py:47` only checks `principal in self.authority_map`. `is_authorized(principal, rule_type)` (`store.py:81`) exists but nothing calls it. So a `developer` (authorised for `configuration` only) can currently assert a `scaling` constraint and it will be enforced. This is the exact attack REVIEW-2 §1 describes, and it succeeds against the current code.

**Do:** `add_constraint` must call `is_authorized(principal, constraint.constraint_class)` and raise `PermissionError` when false.
**Do:** Move `authority_map` out of the constructor into a loadable policy file (`data/authority.example.yaml`) so the adversarial suite can vary it. Constructor takes it as an argument; default is empty (deny all), not the hard-coded three principals.
**Do:** Authority must ALSO be re-checked at decision time (see T1.3) — a constraint that was valid when ingested may be from a principal whose authority was later revoked.
**Accept:** Test: principal `developer` asserting `constraint_class="scaling"` raises `PermissionError`. Test: a constraint inserted directly into the store's dict (bypassing `add_constraint`) from an unauthorised principal is ignored by the interceptor.

### T1.3 The interceptor must only honour verified constraints
**Why:** `interceptor.py:35-39` is `for match in matches: return "BLOCK"` — a loop that returns on the first iteration, and it never calls `verify_integrity` or `is_authorized`. A constraint whose `rule_text` was edited after ingest (hash now mismatches) still blocks. The whole project claim is that poisoned constraints are *rejected*; today they are *obeyed*.

**Do:** Decision logic, in this order, for each matching constraint:
1. `verify_integrity(c)` false → constraint is **discarded** and recorded as `tampered` in the decision's diagnostics.
2. `is_authorized(c.principal, c.constraint_class)` false → **discarded**, recorded as `unauthorized`.
3. Remaining constraints: if any has `effect="BLOCK"` → `BLOCK`; else if any has `effect="ESCALATE"` → `ESCALATE`; else `ALLOW`.
4. If the intent matched **zero** constraints at all → `ALLOW` with `coverage=False` (this is the "Coverage" metric from PLAN §4 — the interceptor has to emit it).

**Do:** Return a `Decision` dataclass, not a string: `{verdict: "ALLOW"|"BLOCK"|"ESCALATE", citations: [constraint ids that drove the verdict], discarded: [{id, reason}], covered: bool, latency_ms: float}`. `REVIEW.md` §6 item 2 requires citations; the plan's latency metric requires timing here. The verdict string must be `ESCALATE` (matches PLAN.md), not `ESCAL_TO_HUMAN` (`interceptor.py:21`).
**Do:** Use `intent.provider` and `intent.params` in matching (currently both ignored).
**Accept:** Tests: (a) tampered constraint (mutate `rule_text` after add) → intent is `ALLOW`ed and `discarded` lists it with reason `tampered`; (b) revoke a principal from the authority map after ingest → its constraints are discarded with reason `unauthorized`; (c) BLOCK outranks ESCALATE when both match; (d) `covered` is `False` when nothing matched; (e) `latency_ms` is populated and < 5 ms for a 500-constraint store (use `pytest-benchmark` or a plain timing assertion).

### T1.4 Make the provenance hash mean something
**Why:** `_calculate_provenance_hash(rule_text, timestamp)` where `timestamp` is `datetime.now()` at ingest. This hashes the store's own memory of the rule. It detects a later edit to `rule_text` **only if the attacker forgets to recompute the hash** — and since the store recomputes the hash on `add_constraint`, an attacker who re-adds the poisoned rule through the normal path gets a valid hash. It also has no link to `source_ref`, so it does not prove the constraint came from that commit/message.

**Do:** Hash the canonical serialisation of the **source-side** fields only: `provider, resource_pattern, sorted(actions), scope, time_window, effect, constraint_class, principal, source_ref, source_timestamp, rule_text`. Use `json.dumps(..., sort_keys=True, separators=(",", ":"))` then SHA-256. Do **not** include the ingest time.
**Do:** Add a `verify_source(constraint, fetcher)` hook — an interface that, given `source_ref`, re-fetches the original (a Git commit's file at that SHA; a Slack message by permalink) and recomputes the hash from it. For v1 ship a `FileSourceFetcher` that reads `data/sources/<source_ref>.json`; the adversarial suite will forge these files. Do not build real Git/Slack connectors in v1.
**Do:** Fix `store.py:66` — `data['proven_hash'] if 'prov_hash' in data else ...` references two keys that never exist. Delete the conditional.
**Do:** Store constraints in the file as-is, with the hash; on `load`, verify every hash and reject (or quarantine, with a log line) any that fail.
**Accept:** Tests: (a) same source fields → same hash regardless of ingest time; (b) changing any one source field changes the hash; (c) `load` of a file where one rule's `rule_text` was hand-edited quarantines exactly that rule; (d) `verify_source` returns false when the fetcher's copy differs from the stored one.

---

## Priority 2 — Plan gaps carried over from REVIEW-2

These are document fixes to `PLAN.md`. They were on the REVIEW-2 §8 checklist and were not incorporated.

### T2.1 Dataset circularity mitigations (REVIEW-2 §5)
**Do:** In `PLAN.md` §4 "The Dataset", add: (1) constraints are seeded from public postmortems and public policy repos (name two, e.g. the Kubernetes failure-stories list and a public OPA policy library) — not invented; (2) a held-out 20% split is frozen before Week 3 and never inspected during development; (3) at least part of the adversarial set is authored by a second person; (4) the corpus is released as a standalone artifact.
**Accept:** All four points present in §4.

### T2.2 Define the labels
**Do:** The plan says "Trusted, Untrusted, and Malicious" but never defines them operationally. Add one line each: Trusted = valid provenance AND authorised principal; Untrusted = valid provenance, unauthorised principal (the REVIEW-2 §1 case); Malicious = provenance fails (tampered or forged source). Note these map 1:1 to the T1.3 discard reasons — that is what makes the confusion matrix computable.
**Accept:** §4 has the three definitions.

### T2.3 Baseline B is underspecified
**Do:** State which model, which prompt format, and that the *same* 500 constraints are stuffed into the prompt for Baseline B that Aegis loads into the store. Otherwise the comparison is not apples-to-apples. State the LLM is called through a provider-agnostic interface so the baseline can be re-run on a local model.
**Accept:** §4 names the model and states constraint parity.

### T2.4 Dates
**Do:** `PLAN.md` §5 has week numbers but no calendar dates. Anchor Week 1 to a Monday and put the date next to every week and every gate. SREcon CFP is Nov 19, 2026 — with today being Sept 20, ten weeks ends Nov 29, which is **after** the deadline. Either compress to 8.5 weeks or state explicitly that the SREcon submission is written in Week 8 on Week-7 results and the paper polish continues after.
**Do:** KubeCon EU decision date in §6 says Oct 1; REVIEW-2 says the CFP closes Oct 11. Make the decision now and write the outcome into the plan — "submit" or "skip" — rather than a future decision date.
**Accept:** Every week in §5 has a date; the SREcon conflict is resolved in the text; §6 says submit or skip for KubeCon EU.

---

## Priority 3 — Before Week 3 starts

Not blocking; do after Priority 1 and 2 are accepted.

- **T3.1** Add `ruff` config to `pyproject.toml` and make `ruff check src tests` clean.
- **T3.2** Add a `README.md`: what it is (two sentences from PLAN §2), install, run tests, the five-rule example, and the "why not OPA/Gatekeeper" paragraph copied from PLAN §3.
- **T3.3** Add `examples/demo.py` that loads `data/constraints.example.yaml`, runs three intents (allow / block / escalate) and prints the `Decision` including citations. This replaces the deleted `__main__` blocks and will become the SREcon demo.
- **T3.4** Add an `IntentParser` stub with two functions and tests: `from_kubectl(argv: list[str]) -> InfrastructureIntent` (handles `kubectl scale deployment/x --replicas=5 -n prod` and `kubectl delete pod/x`) and `from_terraform_plan(plan_json: dict) -> list[InfrastructureIntent]` (one intent per `resource_changes[]` entry, action from `change.actions`). This is the Week 3-4 work; stubbing the signatures now stops the schema in T1.1 from drifting.

---

## Acceptance protocol for the reviewer

When the implementing model reports done, the reviewer will run, from the project root:

```
git log --oneline
venv/Scripts/python.exe -m pip install -e ".[dev]"
venv/Scripts/python.exe -m pytest -q
venv/Scripts/python.exe -m ruff check src tests
grep -rn "sys.path\|PASSED\|__main__" src tests
grep -rn "Anchered\|tamered\|rule_annotated\|ESCAL_TO_HUMAN" PLAN.md src
```

and then read `src/aegis_core/interceptor.py` to confirm the T1.3 decision order and `src/aegis_core/store.py` to confirm the T1.4 hash input. Any `grep` line above returning output, or any test failing, sends the round back.
