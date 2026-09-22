# Project: Aegis-DevOps
## Goal: Mitigating "Agentic Drift" via a Proven: Provenance-Backed and Authority-Aware Policy Verifier

### 1. The Problem: Context Poisoning & Agentic Drift
In autonomous DevOps (AgentOps), AI agents execute infrastructure commands (e.g., `kubectl`, `terraform`) based on retrieved context. This creates two critical vulnerabilities:
1.  **Agentic Drift:** Agents follow "hallucinated" or outdated instructions because they lack an immutable, authoritative source of truth.
2.  **Context Poisoning:** An attacker (or a misconfigured automated system) can inject malicious "instructions" into the unstructured operational data (Slack, Jira, Git) that the agent uses for retrieval.

**The Critical Distinction:** Provenance (integrity) only proves the data hasn't been tampered with since ingestion; it does *not* prove the source was authorized to set that policy.

### 2. The Solution: The Aegis Verifier
A lightweight, high-performance middleware layer that intercepts proposed agent actions and validates them against an **Authority-Anchored Constraint Store**.

**Key Technical Innovation:**
Unlike existing tools (HolmesGPT, RunLore) that focus on *retrieval*, Aegis focuses on *verification*. Every constraint in the store must pass two tests:
1.  **Integrity Check:** A `provenance_hash` verifies the data hasn't been tampered with since ingestion.
2.  **Authority Check:** An `authority_model` verifies that the source (e.g., a specific SRE Lead's Git commit) has the permission to assert this specific class of constraint.

### 3. Core Components (The Deliverables)
1.  **The Constraint Store (The "Source"):** A schema-strict, JSON/YAML-based repository of operational boundaries (e.g., "Do not scale Nodes in US-East-1 during peak hours"). Each entry must contain `provenance_hash` (integrity) and `authorized_principal` (authority).
2.  **The Aegis Interceptor (The "Middleware"):** A Python-based engine that intercepts **Structured Intents** (a normalised `provider / resource / action / scope` record parsed from a CLI invocation or a plan file — see §3.1) and cross-references the `Constraint Store`. It returns: `ALLOW`, `BLOCK`, or `ESCALATE`, with citations and a list of discarded (tampered / unauthorized) constraints.
3.  **The Adversarial Test Suite (The "Evaluation"):** A framework that generates "poisoned" constraints (unverified or unauthorized) to measure the system's robustness.

#### 3.1 Action surface (what the interceptor can parse)
Every parser emits the same intent shape so one constraint schema covers every tool. `resource` is `service/kind[/name]` (lower-case, singular kinds; `kind/*` when no name is given); `action` is drawn from a shared verb vocabulary (`create, delete, update, scale, start, stop, restart, read, put, attach, detach, apply, exec, …`) with the raw verb preserved in `params.raw_action`; environment identifiers (`namespace, region, zone, project, subscription, resource_group, account, context`) land in `metadata` so constraints can scope on them.

| Status | Tool | Parser | Notes |
| :--- | :--- | :--- | :--- |
| Done | `kubectl` | `from_kubectl` / `from_kubectl_multi` | aliases, API groups, multi-resource, `apply -f`, `rollout`, `exec --`, `set image` |
| Done | Terraform | `from_terraform_plan` | one intent per `resource_changes[]`; type/provider/region/tags metadata |
| Done | AWS CLI, Azure CLI, gcloud/gsutil | `from_aws`, `from_az`, `from_gcloud` | `provider = aws \| azure \| gcp`; id-flag targeting; `s3://` / `gs://` paths |
| Done | OpenTofu | `from_terraform_plan` + `aegis check tofu` | identical plan JSON; `provider` stays `terraform` so one rule governs both; `metadata.tool` records which |
| Done | Helm, ArgoCD, Flux | `from_helm`, `from_argocd`/`from_argocd_multi`, `from_flux` | release delete/upgrade, app sync/prune, kustomization/helmrelease reconcile |
| Done | Git, `gh` | `from_git`, `from_gh` | force-push / branch / tag ops; `gh` workflow runs, PR/release actions |
| Done | Pulumi | `from_pulumi_preview`, `from_pulumi_argv` (`src/aegis_core/parsers/pulumi.py`) | one intent per preview step (same class as Terraform); coarse stack-scoped intent when no preview JSON is available |
| Done | SQL CLIs, migrations | `from_sql`, `from_psql`/`from_mysql`/`from_sqlite3`, `from_mongosh`, `from_migration_argv` (`src/aegis_core/parsers/sql.py`) | hand-written statement splitter; DDL vs DML, `DROP`/`TRUNCATE`/unbounded `DELETE`; unrecognised statements fail safe to `update` + `unclassified` rather than `read` |
| Backlog | CDK | plan/diff parser | same class as Terraform/Pulumi; not started |
| Out of scope (v1) | raw `ssh` / Ansible / arbitrary shell | — | named as a limitation in the paper |

Cross-cutting items tracked in §7 — set-level (per-plan) constraints, rate/budget constraints,
dry-run awareness, and environment identity mapping — are all done; open gaps are tracked in §8.

**Why not OPA/Gatekeeper?** 
OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis derives **unstructured human constraints** (from Slack, Jira, Git) and applies **authority-driven validation** to the agent's intent *before* it reaches the infrastructure.

### 4. Evaluation Methodology (The "Science")
To make this project publishable at **SREcon** or **KubeCon**, we will use a rigorous empirical approach:
*   **The Dataset:** A synthetic, labeled corpus of 500 constraints (Trusted, Untrusted, and Malicious).
    *   Constraints are seeded from public postmortems and public policy repos — the Kubernetes failure-stories list (k8s.af / hjacobs/kubernetes-failure-stories) and the OPA Gatekeeper policy library (open-policy-agent/gatekeeper-library) — not invented from scratch.
    *   A held-out 20% split is frozen before Week 3 and never inspected during development to avoid dataset leakage.
    *   At least part of the adversarial set is authored by a second person to mitigate circularity bias.
    *   The corpus is released as a standalone artifact for independent reuse and citation.
    *   Labels are defined operationally: **Trusted** = valid provenance AND authorized principal; **Untrusted** = valid provenance but unauthorized principal (the REVIEW-2 §1 attack case); **Malicious** = provenance fails (tampered or forged source). These map 1:1 to the interceptor's discard reasons (`unauthorized`, `tampered`), which is what makes the confusion matrix computable.
    *   **Diversity, honestly:** the 500 constraints contain `n_distinct_structural = 196` distinct `(provider, resource_pattern, actions, scope)` tuples (71 distinct patterns, 66 distinct rule texts) — `data/corpus/stats.json`; every place a result reports `n` it reports `n_distinct` beside it.
    *   **Attack model.** `tampered` (field mutated after hashing) and `forged` (self-consistent hash, fabricated or missing source) are *post-ingest* attacks on the store — the class that signed bundles (cosign / in-toto) already defend against. `unauthorized` (valid provenance, principal not allowed to assert that class) is the *pre-ingest* attacker — a real person or bot with a real citation who simply isn't entitled to set that policy — and is the realistic one. Poison-susceptibility is reported per kind (`ps_unauthorized`, `ps_tampered`, `ps_forged`, plus `pe_*` for fail-closed ESCALATEs); the `unauthorized` column is where Aegis's authority model separates from a signed-bundle OPA (`opa-signed`).
*   **Ground truth:** `expected_verdict` for every intent comes from `scripts/reference_oracle.py`, an independent, deliberately naive matcher driven off `labels.jsonl` (only Trusted rules drive the verdict; BLOCK > ESCALATE > ALLOW) that never imports `aegis_core.interceptor`, `aegis_core.store` or `aegis_core.plan`. Aegis is scored against it like any other verifier; disagreement is a finding, not a harness bug. The reported test set is the **intent holdout** — 20% of the 600 intents, stratified by expected verdict × poison candidate and frozen with the corpus seed — with the full constraint store loaded (the store is the deployed artefact; the intents are the test set). `covered` is defined once, by the harness, as "any constraint of any label structurally matched".
*   **The Baselines:** 
    *   **Baseline B (LLM-Self-Check):** Model = Claude Sonnet 5 (`claude-sonnet-5`) called via a provider-agnostic interface so it can be re-run on a local model (e.g., via Ollama). Prompt format: system prompt containing the full constraint list as YAML; user turn containing the structured intent as JSON. Model must answer with one of `ALLOW`, `BLOCK`, or `ESCALATE`. The *same* 500 constraints are stuffed into the prompt that Aegis loads into the store (constraint parity ensures apples-to-apples comparison).
    *   **Baseline C (Deterministic):** Standard OPA/Rego-based policy enforcement (`opa`), plus `opa-signed`: the same Rego fed a signed bundle that excludes `tampered`/`forged` constraints but keeps `unauthorized` ones — the honest competitor.
*   **The Metrics (The Confusion Matrix):**
    *   **True Positive (TP):** Correctly blocking malicious actions.
    *   **Over-block Rate (False Positive):** Percentage of legitimate actions incorrectly blocked.
    *   **Coverage:** Percentage of proposed actions that the store has any authority over.
    *   **Latency:** p50 and p99 latency of the interception loop.

### 5. 10-Week Implementation Roadmap
*   **Week 1-2 (Sep 21–Oct 4): The Foundation.** Define the Constraint Schema (Integrity + Authority). Build the `ConstraintStore` with hashing and principal-mapping. **[Go/No-Go Gate: Schema stability, end of Week 2 (Oct 4)]**
*   **Week 3-4 (Oct 5–Oct 18): The Engine.** Implement the `AegisInterceptor` for structured `kubectl` and `terraform` triples. **Done ahead of schedule (2026-09-21):** the engine now covers all 20 CLI/plan targets in §3.1 (kubectl, terraform/tofu, aws/az/gcloud, helm/argocd/flux, git/gh, SQL CLIs/migrations, pulumi), plus environment mapping, dry-run handling, rate limits, and plan-level constraints — see §7.
*   **Week 5-6 (Oct 19–Nov 1): The Adversary.** Build the `AdversarialTestSuite` (generating poisoned/forged inputs).
*   **Week 7-8 (Nov 2–Nov 15): The Benchmark.** Execute the "Baseline vs. Aegis" experiment. Generate performance/confusion matrix graphs. Submit to **SREcon27 Americas** (deadline Nov 19, 2026) during Week 8 (Nov 9–15) with Week-7 results.
*   **Week 9-10 (Nov 16–Nov 29): The Artifact.** Polish the paper post-submission and finalize the open-source library and documentation release.

### 6. Target Venues
*   **Primary:** **SREcon27 Americas** (Technical Paper/Case Study) — Deadline Nov 19, 2026.
*   **Secondary:** **KubeCon + CloudNativeCon EU 2027** — **Skip** (CFP closes Oct 11, 2026 — before any benchmark results exist). Consider as a possible target only if a later CFP becomes available; otherwise target **KubeCon + CloudNativeCon NA 2027**.

### 7. Backlog (post-Week-4 hardening, ordered)
Items surfaced by the Week 1–3 build and the REVIEW-4 council. None block the SREcon submission.

1.  **Dry-run awareness — done.** `--dry-run`, `terraform plan`, `helm --dry-run` are already captured in `params`; the interceptor downgrades BLOCK → ALLOW (with `covered=True` and a `dry_run` flag in the decision) so read-only rehearsals are never over-blocked.
2.  **Environment identity mapping — done (T1.3).** `data/environments.example.yaml` maps kube contexts/clusters/kubeconfig paths, AWS account IDs/profiles, GCP projects, Azure subscriptions/resource groups, GitHub repos, ArgoCD app globs and terraform workspaces → `env: prod|staging|dev`; resolution is provider-agnostic; an env-scoped rule against an intent with no resolved `env` ESCALATEs (`env-unresolved`); `--resolve-current-context` (opt-in, trusts the invoking environment) fills a missing context/profile/project from `$KUBECONFIG`/`$AWS_PROFILE`/`$CLOUDSDK_CORE_PROJECT`/….
3.  **Forged sources at decision time — done.** `verify_source` runs inside `ConstraintStore.load` against `<dir of constraints>/sources` by default (`--sources` overrides, `''` disables); the transport's signed `PRINCIPALS.yaml` — not the payload — says who a source belongs to (`principal-mismatch`). Still not re-checked at decision time — see §8.
4.  **Helm / ArgoCD / Flux / Git / CI parsers — done.** `from_helm`, `from_argocd`/`_multi`, `from_flux`, `from_git`, `from_gh` ship as both library functions and `aegis check` subcommands, exercised in `examples/demo.py` and `tests/test_cli.py`.
5.  **Set-level constraints — done.** `src/aegis_core/plan.py`'s `PlanConstraint` evaluates `max_intents`, `max_matching`, `requires_all`, `forbid_together`, and `ratio` predicates over a whole intent batch via `--plan-constraints`; selectors match every resource alias (`aws_db_instance.*` catches `module.app.aws_db_instance.main`, T1.6/T1.7) and escalate on an unresolved `env`.
6.  **Rate / budget constraints — done (T1.9).** `Constraint.rate_limit` (`max`/`per`/`key`) plus `DecisionLedger`/`JsonlLedger`/`SqliteLedger` (`--ledger`, picked by extension) enforce "≤ N ops per window per bucket"; cross-process locking, hash-chained records (`chain-broken` fails closed), rotation to the largest window, `key: [resource]` buckets per concrete target, and `rate_limit.key` vocabulary validation at load.
7.  **Root of trust — done (T1.1).** Every policy file is MAC-signed (`aegis sign`/`verify`; detached `.sig` per file, one `AEGIS-MANIFEST.sig` per sources directory); the CLI refuses to decide without a key (`--key`, `$AEGIS_SIGNING_KEY`, or the public example key with a warning) unless `--insecure`. The key is a shared secret — see §8.
8.  **Shell-string front end — done (T1.2).** `aegis check command -- "<string>"` / `--split-compound` split compound commands, unwrap `sudo`/`env`/`timeout`/`sh -c`/aliases, and refuse (exit 64) anything whose argv needs execution to know; `examples/claude-code-hook.sh` uses it.
9.  **Real source connectors + identity.** Git (file at SHA), Slack (permalink), Jira fetchers replacing `FileSourceFetcher`; `principal` bound to commit signature / Slack user ID / SSO group rather than a bare string. This is the line between "reference design" and "deployable". Not started — see §8.
10. **SQL statement-class gating, then Pulumi — done.** `src/aegis_core/parsers/sql.py` (`from_sql` + psql/mysql/sqlite3/mongosh/migration wrappers, hardened against the T1.4 evasions) and `src/aegis_core/parsers/pulumi.py` (`from_pulumi_preview`/`from_pulumi_argv`) ship with tests. CDK remains backlog (§3.1).

### 8. Open gaps (honest, as of 2026-09-21)
None of these block the current feature set; they're the known distance between "reference
design" and "deployable" (see item 9 above), plus a few sharp edges worth naming rather than
discovering later.

*   **`evade-case-variant` is `xfail`.** The constraint matcher is case-sensitive (`fnmatch` on
    POSIX); the parser normalises resource kinds to lower-case, which covers the common case,
    but a constraint author or an attacker who varies case elsewhere can still slip past a
    pattern. Documented in `tests/test_adversarial.py`, not fixed.
*   **Forged sources are checked at load, not at decision time.** With the default `sources/`
    directory (or `--sources`) forgery is caught when the store loads; a source that changes
    while a long-lived process keeps its store in memory isn't noticed until the next load.
*   **The signing key is a shared secret.** Signatures are keyed BLAKE2b MACs: whoever can verify
    can also sign, so the key must be kept away from the agent and from anyone who can write
    policy files. Public-key signatures (and a key-rotation story) are not implemented. The
    committed `data/example-signing.key` is public and demo-only.
*   **`--resolve-current-context` trusts the process environment.** It is opt-in for exactly that
    reason: an agent that can set `$KUBECONFIG` can steer what Aegis believes the target is.
*   **OPA rows depend on a local binary.** `opa` and `opa-signed` are run and reported in
    `results/benchmark.md` (opa 1.20); on a machine without the `opa` binary the harness skips
    both rows with a note rather than failing.
*   **Real LLM baseline not yet run.** `src/aegis_core/baselines/llm.py`'s `AnthropicClient`
    path is implemented, but no run has been recorded — no `ANTHROPIC_API_KEY` in this
    environment. `results/benchmark.md` only has the offline `llm-heuristic` stand-in.
*   **No real Git/Slack/Jira connectors.** `FileSourceFetcher` (a flat JSON file per
    `source_ref`) is the only `SourceFetcher` implementation; there is no commit-SHA, Slack
    permalink, or Jira-ticket fetcher yet.
*   **`principal` is still a bare string.** The signed `PRINCIPALS.yaml` binds a source to a
    principal name, but that name isn't bound to a commit signature, a Slack user ID, or an
    SSO group — whoever holds the signing key can attribute a source to anyone.
*   **Raw shell/`ssh`/Ansible is explicitly out of scope (v1)**, per §3.1 — `aegis check
    command` splits and unwraps shell strings, but an unknown binary is only a synthetic
    `shell`/`exec` intent (escalated under `--fail-closed`), never parsed.
*   **Plan constraints are evaluated per invocation, not across invocations.** `evaluate_plan`
    sees one batch of intents from one `aegis check` call; there is no persistence of partial
    plan state across multiple separate invocations that together make up one logical change.
