You are one member of an independent review council for a design spec. Other reviewers (different models) review the same spec separately; do not assume anyone else will catch what you skip.

Repository: aegis-devops (Python). Aegis is a policy verifier for AI agents' infrastructure actions: before an action runs it decides ALLOW / BLOCK / ESCALATE against a store of constraints, where every constraint must pass integrity (provenance hash), source verification (file sources or, since v0.2.0, Git commits signed by keys in signers.yaml) and authority (authority.yaml: which principal may assert which constraint class) checks. Today enforcement is client-side only: agent pre-tool hooks (Claude Code, Codex, Copilot, VS Code, Cursor, Gemini CLI, OpenCode), `aegis check` in CI.

THE SPEC UNDER REVIEW: docs/dev/DESIGN-v0.3-server-side.md — server-side enforcement: a Kubernetes validating admission webhook, a compiler from verified Aegis policy to AWS/GCP/Azure native deny policies, a Terraform CI gate, GitHub rulesets. Read it in full. Read supporting code as needed: src/aegis_core/interceptor.py, store.py, intent.py, parser.py (kubectl/aws/gcloud/az parsers), gitsource.py, cli.py, docs/dev/DESIGN-v0.2-git-sources.md, docs/dev/PLAN.md §8-9.

Review for, in this order:
1. FACTUAL CORRECTNESS of every platform claim (Kubernetes admission: AdmissionReview fields, matchConditions and its GA version, failurePolicy/timeouts, which operations go through admission, deletecollection, namespace deletion, CONNECT subresources, dryRun; AWS IAM/SCP evaluation, condition keys, time conditions, SCP limits; GCP IAM deny policies; Azure Policy deny/denyAction scope and identity scoping, deny assignments, custom roles/NotActions, locks). Say exactly what is wrong and what is right, with your confidence.
2. SECURITY GAPS: ways an agent can still get a blocked action through with this design in place; ways the new components add attack surface or availability risk; trust-boundary mistakes; anything that contradicts Aegis's core rule that an unverified constraint gets no vote.
3. DESIGN FLAWS / MISSING PIECES that would block implementation or make it wrong (intent mapping, identity scoping, reload, drift, parity testing, coverage reporting, action mapping).
4. PRIORITIES AND PHASING: is the order right? What should be cut or moved?
5. Answers to the six OPEN QUESTIONS in §10, each with a recommendation and reason.

Output format (markdown), be concrete and terse:
## Verdict
(one paragraph: ship as-is / revise / rethink, and the single most important change)
## Findings
A numbered list. Each: **[P0|P1|P2|P3] Title** — section reference — what is wrong — why it matters — the concrete fix. P0 = the design is wrong or unsafe as written; P1 = must fix before implementing; P2 = should fix; P3 = nice to have. Mark any platform fact you are not sure of as (UNSURE).
## Open questions (§10)
1-6, each: recommendation + one-line reason.
## Missing from the spec
Bullets.

Do not modify any files. Do not run network commands. Read-only review.
