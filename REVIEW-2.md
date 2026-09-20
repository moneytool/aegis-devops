# Aegis-DevOps — Review, Round 2
**Date:** 2026-09-20
**Reviewing:** revised `PLAN.md` (Aegis-DevOps)
**Previous round:** `REVIEW.md` (RA-DevOps)

## Verdict

Big improvement. Scope is now buildable by one person, the claim is falsifiable, and there is a timeline. Four issues remain, and one is a factual error in the venue list. All should be resolved before week 1 starts.

---

## 1. Provenance proves integrity, not authority

**This is the load-bearing weakness of the revised plan.**

A `provenance_hash` linking a constraint to a Git commit or a Slack message proves the constraint was not fabricated or altered after ingest. It does **not** prove the source should be trusted. The attacker in your own threat model posts in Slack or commits to the repo — and gets perfectly valid provenance.

What each source actually gives you:

| Source | Real property | Not a property |
| :--- | :--- | :--- |
| Git commit hash | Tamper-evident; author-attributable **only** if commits are signed and signatures verified | Authority — most orgs don't enforce signing |
| Jira ticket ID | An identifier | No integrity at all; ticket contents are mutable and the ID doesn't pin them |
| "Signed Slack event" | Authenticates **Slack as transport** via the workspace signing secret | Does not authenticate the human author; anyone in the channel produces a validly signed event |

**Required fix:** add a second axis to the Constraint Store beyond provenance — an **authority model** specifying which principals may assert which classes of constraint (an SRE lead may assert a production scaling boundary; an arbitrary channel member may not).

- **Provenance** answers: has this been tampered with since ingest, and is it stale?
- **Authority** answers: was this source permitted to say it?

Both are needed. Only the first is currently in the plan, and the second is the more interesting contribution — tamper-evidence alone is a solved problem.

---

## 2. The baseline is a straw man, and OPA is missing

"A standard RAG agent with only vector similarity" loses by construction. No reviewer doubts that result, so measuring it proves nothing.

Add stronger baselines:

- **Baseline B — Prompt-stuffed constraints.** Constraints injected into the agent's context; the LLM self-checks. This is what most teams actually do today.
- **Baseline C — Deterministic policy engine.** Hand-authored rules in OPA/Rego, Kyverno, or Conftest; HashiCorp Sentinel for the Terraform path.

**Baseline C is the one that decides whether this project is interesting.** The current `PLAN.md` never mentions OPA, and *"why isn't this just Gatekeeper?"* is the first question at any KubeCon session.

The answer must be: admission control evaluates **structured API objects** against **hand-authored rules**, whereas Aegis derives constraints from **unstructured human text**, which is exactly why provenance and authority are required for it to be safe.

**Action:** write that differentiation paragraph before week 1. If it isn't convincing on paper, the scope is still wrong.

---

## 3. VCR is gameable as a single metric

A verifier that returns `BLOCK` for everything scores 100% Verified Compliance Rate. Report a confusion matrix, not one number:

- **Over-block rate** on legitimate actions — the metric that decides whether anyone would run this in production
- **Coverage** — fraction of proposed actions the store has anything at all to say about
- **Latency, p50 / p99** — Aegis sits in the critical path of every agent action; a verifier that adds seconds is unusable regardless of accuracy

---

## 4. Intent parsing is the unbudgeted cost

Mapping "the agent wants to run `terraform apply` with this plan" onto "does this touch nodes in us-east-1 during peak hours" requires resource resolution, time/calendar awareness, and fuzzy matching against constraint text. That is the real research problem, and weeks 3–4 do not budget for it.

**Scope it down explicitly in the plan:** structured intents only in v1 —

- `kubectl` verb / resource / namespace triples
- `terraform plan -json` output

No free-text intents in v1. Say so in the document so the boundary is deliberate rather than discovered in week 4.

---

## 5. Dataset circularity

If one person authors both the 500 constraints and the forged attacks, the evaluation measures that person's imagination.

Mitigations:

1. Seed constraints from **public postmortems** and **public policy repos**, not pure invention.
2. Keep a **held-out set** untouched while building.
3. Have a **second person** write part of the adversarial set.
4. Release the corpus as a **standalone artifact** — a labelled provenance/poisoning dataset is independently reusable and is itself citable work.

---

## 6. Venue corrections and real deadlines

**`USENIX LISA` no longer exists.** It was wound down after LISA '21 after 35 years, and USENIX folded its systems-engineering content into SREcon. Remove it from section 6.

Verified deadlines as of 2026-09-20:

| Venue | Event | CFP deadline | Status |
| :--- | :--- | :--- | :--- |
| **SREcon27 Americas** | Seattle, WA — April 12–14, 2027 | **Thursday, November 19, 2026** | **Primary target.** ~8.5 weeks out; lands almost exactly on the end of the 8-week plan |
| **KubeCon + CloudNativeCon EU 2027** | Barcelona — March 15–18, 2027 | **Sunday, October 11, 2026** (notifications Dec 7) | 3 weeks out, before results exist. Submit on plan + early prototype, or skip to KubeCon NA 2027 |

**Resulting schedule:** weeks 1–8 as planned → SREcon submission on Nov 19. Decide **this week** whether to throw an abstract at KubeCon EU before Oct 11.

---

## 7. Timeline realism

Eight weeks with zero buffer, executed around a full-time job.

- Week 8 currently holds "open-source library + documentation + technical paper." That is roughly three weeks of work.
- **Either** extend to ten weeks **or** cut the whitepaper and ship the talk proposal plus a strong README.
- Add explicit **go/no-go gates**: if the constraint schema is not stable by end of week 2, everything downstream slips — decide then, not in week 6.

---

## 8. Checklist before week 1

- [ ] Add the authority model to the Constraint Store design (section 1)
- [ ] Add Baselines B and C to the evaluation methodology (section 2)
- [ ] Replace VCR-alone with the full metric set including latency (section 3)
- [ ] Write the structured-intents-only scope boundary into the plan (section 4)
- [ ] Write the one-paragraph "why not OPA/Gatekeeper" differentiation statement
- [ ] Remove USENIX LISA; set SREcon Nov 19 as the anchor deadline
- [ ] Decide on KubeCon EU (Oct 11) — submit or skip
- [ ] Re-cut the timeline to 10 weeks, or drop the whitepaper from week 8
