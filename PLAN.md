# Project: Aegis-DevOps
## Goal: Mitigating "Agentic Drift" via a Proven: Provenance-Backed and Authority-Aware Policy Verifier

### 1. The Problem: Context Poisoning & Agentic Drift
In autonomous DevOps (AgentOps), AI agents execute infrastructure commands (e.g., `kubectl`, `terraform`) based on retrieved context. This creates two critical vulnerabilities:
1.  **Agentic Drift:** Agents follow "hallucinated" or outdated instructions because they lack an immutable, authoritative source of truth.
2.  **Context Poisoning:** An attacker (or a misconfigured automated system) can inject malicious "instructions" into the unstructured operational data (Slack, Jira, Git) that the agent uses for retrieval.

**The Critical Distinction:** Provenance (integrity) only proves the data hasn't been tampered with since ingestion; it does *not* prove the source was authorized to set that policy.

### 2. The Solution: The Aegis Verifier
A lightweight, high-performance middleware layer that intercepts proposed agent actions and validates them against an **Authority-Anchered Constraint Store**.

**Key Technical Innovation:**
Unlike existing tools (HolmesGPT, RunLore) that focus on *retrieval*, Aegis focuses on *verification*. Every constraint in the store must pass two tests:
1.  **Integrity Check:** A `provenance_hash` verifies the data hasn't been tamered with since ingestion.
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
*   **The Baselines:** 
    *   **Baseline B (LLM-Self-Check):** Constraints injected directly into the LLM prompt.
    *   **Baseline C (Deterministic):** Standard OPA/Rego-based policy enforcement.
*   **The Metrics (The Confusion Matrix):**
    *   **True Positive (TP):** Correctly blocking malicious actions.
    *   **Over-block Rate (False Positive):** Percentage of legitimate actions incorrectly blocked.
    *   **Coverage:** Percentage of proposed actions that the store has any authority over.
    *   **Latency:** p50 and p99 latency of the interception loop.

### 5. 10-Week Implementation Roadmap
*   **Week 1-2: The Foundation.** Define the Constraint Schema (Integrity + Authority). Build the `ConstraintStore` with hashing and principal-mapping. **[Go/No-Go Gate: Schema stability]**
*   **Week 3-4: The Engine.** Implement the `AegisInterceptor` for structured `kubectl` and `terraform` triples.
*   **Week 5-6: The Adversary.** Build the `AdversarialTestSuite` (generating poisoned/forged inputs).
*   **Week 7-8: The Benchmark.** Execute the "Baseline vs. Aegis" experiment. Generate performance/confusion matrix graphs.
*   **Week 9-10: The Artifact.** Finalize the open-source library, documentation, and the technical paper for **SREcon27 Americas (Deadline: Nov 19, 2026)**.

### 6. Target Venues
*   **Primary:** **SREcon27 Americas** (Technical Paper/Case Study).
*   **Secondary:** **KubeCon + CloudNativeCon EU 2027** (Demo/Workshop - *Decision by Oct 1: KubeCon EU 2027*).
