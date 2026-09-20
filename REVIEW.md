# RA-DevOps — Project Review
**Date:** 2026-09-20
**Reviewing:** `PLAN.md`, `FEEDBACK.md`

## Verdict

Real problem, weak plan. As written this is a positioning document rather than a project: four hard products stacked together, aimed at venues that don't match the work, in a category that got crowded while the plan was being drafted. The realistic one-person version is roughly 15% of what's here.

---

## 1. What holds up

The core observation is correct. Agents can run `kubectl` but don't know that the team never scales that StatefulSet during business hours, and that constraint lives in a Slack thread from 2024. That gap is real and unsolved.

**Feature C (Agentic Policy Verifier) is the strongest idea in the document.** It is the part an enterprise would pay for, and the only part with a clean pass/fail evaluation. Everything else in the plan is infrastructure in service of it.

---

## 2. Scope

Four features, each of which is a company:

| Feature | Honest effort estimate (solo, part-time) |
| :--- | :--- |
| A — Semantic ingestion across Jira/GitHub/Slack/Confluence | 6–12 months, then permanent connector maintenance |
| B — Hybrid graph+vector store synced to live infrastructure | 6–12 months, unsolved at the edges |
| C — Policy verifier middleware | 2–4 months for a credible version |
| D — Reasoning-trace dashboard | 2–3 months |

Attempting all four means four demos and zero shipped things.

---

## 3. The biggest hole: no evaluation plan

`FEEDBACK.md` missed this entirely, and it matters more than any of the three critiques it raised.

- **Metric 1** — "hallucination rate measured by a controlled set of trick questions." Which set? Written by whom? Against what baseline?
- **Metric 2** — "context recall." There is no labelled corpus to recall from.
- **Metric 3** — a self-healing loop in a simulated cluster is a demo, not a metric.

The only genuinely interesting claim in the design is that the **graph layer earns its cost over plain vector RAG**. That claim requires:

1. A fixed corpus (synthetic is fine, and is faster to build than it sounds).
2. A labelled question set with known-correct retrievals.
3. A baseline: vector-only RAG, no graph.
4. A measured delta.

**Build the eval harness before the ingestion pipeline.** If it can't be measured, nothing downstream is publishable or even knowable.

---

## 4. The venue table is wrong

The publication strategy in `FEEDBACK.md` should be replaced.

- **NeurIPS** does not take systems papers about DevOps context layers from a solo practitioner with no dataset. "Quantify information entropy reduction" is a phrase, not a research contribution.
- **USENIX (ATC/Security)** would require a stated threat model, an implemented attack, and a defense with measured bounds. That is a legitimate target *if* section 6 below gets built — but not as an aspiration attached to an unbuilt plan.

**Better targets for work of this shape:** SREcon, KubeCon / CloudNativeCon, USENIX LISA-adjacent and industry workshops, plus written practitioner artifacts and a usable open-source release.

These also produce a stronger evidentiary record than a rejected top-tier submission: judged conference talks, invited peer review, and demonstrably adopted open-source carry weight that an unpublished preprint does not.

---

## 5. Prior art — the plan does not account for it

The space filled in quickly during 2026:

- **HolmesGPT** — CNCF sandbox project, ~2.5k stars as of May 2026, created by Robusta with major Microsoft contributions. Agentic incident investigation across Kubernetes, VMs, cloud providers and SaaS. Has an operator mode that runs continuously and can open fix PRs.
- **K8sGPT** — narrower, deterministic analyzers plus LLM explanation, CNCF sandbox, strong CLI workflow.
- **Keep** — alert consolidation and correlation.
- **RunLore** — explicitly markets "learns your platform": every investigation opens a PR into a Git knowledge base a human merges. This is close to the institutional-memory pitch in `PLAN.md`.
- **Aurora (Arvo)** — advertises a Memgraph-backed graph model for blast-radius dependency analysis, i.e. Feature B.

One 2026 roundup counts 46+ vendors selling "AI SRE."

None of this kills the idea. But the plan must state what it does that **HolmesGPT plus a curated runbook repo** does not, and at present it cannot.

---

## 6. Recommended scope cut

Build one thing: **the provenance-backed policy verifier.**

1. **Constraint store with provenance.** Every rule traces to a raw source — commit hash, Slack permalink, ticket ID, author, timestamp. No constraint enters the store unattributed.
2. **Verifier middleware.** Intercepts a proposed action, evaluates it against applicable constraints, returns allow / block / escalate with the citing sources attached.
3. **Adversarial test suite.** Plant poisoned constraints in the source corpus (forged Slack messages, malicious commits) and measure whether the verifier still holds. This is the USENIX-shaped contribution, and it is the one thing none of the incumbents currently claim.

**Integrate rather than compete.** Ship it as a policy layer in front of an existing agent — an MCP server or a HolmesGPT-compatible toolset — so the ingestion problem (Feature A) is inherited instead of rebuilt.

Result: one novel claim, one measurable result, an artifact people can install, and a talk. Features B and D can follow if the first piece earns them.

---

## 7. Notes on the documents themselves

- The three expert critiques in `FEEDBACK.md` are generic enough to have been produced from the project title alone. They surface poisoning, staleness and observability, but not scope, evaluation, prior art, or the absence of any milestone sequence or dates.
- `PLAN.md` contains "Retrieable" and "Graph-RRAG." Neither document has had a careful human pass.
- There is no timeline anywhere in either file. Add dated milestones tied to the eval harness.

---

## 8. Immediate next steps

1. Rewrite `PLAN.md` around the section 6 scope, with milestones and dates.
2. Build the corpus + labelled question set + vector-only baseline **first**.
3. Write a one-paragraph differentiation statement vs. HolmesGPT, RunLore and Aurora. If it can't be written convincingly, the scope is still wrong.
4. Drop NeurIPS from the plan. Target SREcon / KubeCon with a submission deadline on the calendar.
