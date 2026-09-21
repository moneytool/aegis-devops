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
2.  **The Aegis Interceptor (The "Middleware"):** A Python-based engine that intercepts **Structured Intents** (e.g., `kubectl` verb/resource/namespace triples or `terraform plan -json` outputs) and cross-references the `Constraint Store`. It returns: `ALLOW`, `BLOCK`, or `ESCALATE`.
3.  **The Adversarial Test Suite (The "Evaluation"):** A framework that generates "poisoned" constraints (unverified or unauthorized) to measure the system's robustness.

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
*   **The Baselines:** 
    *   **Baseline B (LLM-Self-Check):** Model = Claude Sonnet 5 (`claude-sonnet-5`) called via a provider-agnostic interface so it can be re-run on a local model (e.g., via Ollama). Prompt format: system prompt containing the full constraint list as YAML; user turn containing the structured intent as JSON. Model must answer with one of `ALLOW`, `BLOCK`, or `ESCALATE`. The *same* 500 constraints are stuffed into the prompt that Aegis loads into the store (constraint parity ensures apples-to-apples comparison).
    *   **Baseline C (Deterministic):** Standard OPA/Rego-based policy enforcement.
*   **The Metrics (The Confusion Matrix):**
    *   **True Positive (TP):** Correctly blocking malicious actions.
    *   **Over-block Rate (False Positive):** Percentage of legitimate actions incorrectly blocked.
    *   **Coverage:** Percentage of proposed actions that the store has any authority over.
    *   **Latency:** p50 and p99 latency of the interception loop.

### 5. 10-Week Implementation Roadmap
*   **Week 1-2 (Sep 21–Oct 4): The Foundation.** Define the Constraint Schema (Integrity + Authority). Build the `ConstraintStore` with hashing and principal-mapping. **[Go/No-Go Gate: Schema stability, end of Week 2 (Oct 4)]**
*   **Week 3-4 (Oct 5–Oct 18): The Engine.** Implement the `AegisInterceptor` for structured `kubectl` and `terraform` triples.
*   **Week 5-6 (Oct 19–Nov 1): The Adversary.** Build the `AdversarialTestSuite` (generating poisoned/forged inputs).
*   **Week 7-8 (Nov 2–Nov 15): The Benchmark.** Execute the "Baseline vs. Aegis" experiment. Generate performance/confusion matrix graphs. Submit to **SREcon27 Americas** (deadline Nov 19, 2026) during Week 8 (Nov 9–15) with Week-7 results.
*   **Week 9-10 (Nov 16–Nov 29): The Artifact.** Polish the paper post-submission and finalize the open-source library and documentation release.

### 6. Target Venues
*   **Primary:** **SREcon27 Americas** (Technical Paper/Case Study) — Deadline Nov 19, 2026.
*   **Secondary:** **KubeCon + CloudNativeCon EU 2027** — **Skip** (CFP closes Oct 11, 2026 — before any benchmark results exist). Consider as a possible target only if a later CFP becomes available; otherwise target **KubeCon + CloudNativeCon NA 2027**.
