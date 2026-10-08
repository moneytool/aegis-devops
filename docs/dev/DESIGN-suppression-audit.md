# Design: suppression audit (`aegis audit suppressions`)

Status: **draft for review**, 2026-10-07. Target release: **v1.1** (after the v1.0 budget cap,
[DESIGN-v1.0-budget-cap.md](DESIGN-v1.0-budget-cap.md)); the hook part (§7) is additive and can
follow in v1.2.

## 1. Problem

Every infrastructure repository accumulates suppressions: `#checkov:skip=…`, `#tfsec:ignore:…`,
`.trivyignore` entries, `# nosec`, `# nosemgrep`, `# tflint-ignore`, `gitleaks:allow`,
`continue-on-error: true` in CI. Each one was a reasonable exception the day it was added. A year
later nobody knows who added it, why, or whether it still applies — and nobody sees it any more.
The scanner reports green because it was told to.

Three things make this worse now:

- **No cross-tool view.** Each scanner knows only its own ignores. A repo running Checkov, Trivy,
  tflint, gitleaks and Semgrep has five syntaxes and no single list. Only a few tools support
  expiry at all (tfsec `:exp:`, Trivy `.trivyignore.yaml` `expired_at`), each in its own way.
- **Coding agents add suppressions to get CI green.** Asked to "make the checks pass", an agent's
  cheapest move is often `# checkov:skip` or `# noqa`. That is a policy change made by the agent,
  invisible in review unless someone reads every line.
- **Suppressions are unsigned policy.** Aegis already says that an agent must not be able to
  loosen its own policy by editing a file (signed `constraints.yaml`, `agents.yaml`). An inline
  ignore is exactly that loosening, one level down.

## 2. Goals and non-goals

Goals:

- One inventory of every suppression in a repository, across the common IaC, security and CI
  tools (§3), with **age, author and reason** from `git blame`.
- **Expiry**: an optional, tool-neutral annotation (§4) that fails CI once the date has passed.
- **New-only in PRs**: in a pull request, report only the suppressions that PR adds or widens,
  so existing debt does not block work but new debt is seen.
- **Agent gate** (v1.2): the hook asks before an agent writes a new suppression (§7).
- Offline, no services, read-only on the repository. JSON and SARIF output.

Non-goals: deciding whether a suppression is *justified* (that is the reviewer's job; we make
it visible); rewriting or removing suppressions automatically; language linters beyond the
security- and infra-relevant ones in v1.1 (`eslint-disable`, `# type: ignore` are §10 backlog);
suppressions configured only in a remote service (SaaS scanner dashboards).

## 3. What is detected (v1.1)

One small parser per tool, each with fixtures from real repositories.

| Tool | Inline form | File form |
|---|---|---|
| Checkov | `#checkov:skip=CKV_AWS_20:reason` ; K8s annotation `checkov.io/skip1` | `.checkov.yaml` `skip-check` |
| tfsec | `#tfsec:ignore:<id>[:exp:YYYY-MM-DD]` | — |
| Trivy | `#trivy:ignore:<id>` | `.trivyignore`, `.trivyignore.yaml` |
| tflint | `# tflint-ignore: <rule>` | `.tflint.hcl` `rule … { enabled = false }` |
| KICS | `# kics-scan ignore-line` / `ignore-block` | `kics.config` `exclude-queries` |
| Semgrep | `# nosemgrep[: rule-id]` | `.semgrepignore` |
| Bandit | `# nosec[ B101]` | `.bandit` `skips` |
| gitleaks | `gitleaks:allow` | `.gitleaksignore` |
| hadolint | `# hadolint ignore=DL3008` | `.hadolint.yaml` `ignored` |
| ShellCheck | `# shellcheck disable=SC2086` | `.shellcheckrc` `disable=` |
| kube-linter | `ignore-check.kube-linter.io/<check>` annotation | `.kube-linter.yaml` `exclude` |
| GitHub Actions | `continue-on-error: true` on a step or job | — |

Each finding records: tool, rule id(s) (or `*` for a blanket ignore), file and line, the
suppressed scope (line, block, file, repo-wide), the native reason if the tool has one, the
commit and author that introduced it, its age, and its Aegis annotation (§4) if any.

**Blanket ignores are flagged separately**: `# nosec` without an id, `# nosemgrep` without a
rule, a `.trivyignore` line that matches a whole class. They hide every future finding on that
line, not just the one someone looked at.

## 4. The annotation

Tool-native syntax stays as it is; Aegis reads an optional trailer on the same or the preceding
line:

```hcl
# aegis: reason="legacy bucket, migrated in INFRA-412" owner=@platform expires=2026-12-31
resource "aws_s3_bucket" "logs" { #checkov:skip=CKV_AWS_18
```

- Keys: `reason` (required in `strict`), `owner`, `expires` (ISO date), `ticket`.
- For file-form ignores (`.trivyignore`, `.gitleaksignore`), the trailer is a comment on the
  line above the entry.
- Where the tool already has an expiry (tfsec `:exp:`, Trivy `expired_at`), Aegis reads it too;
  if both are present the earlier date wins.

## 5. Policy: `suppressions.yaml`

Optional, in the policy directory, signed like the other files; its `principal` must hold a new
**`suppression`** class in `authority.yaml`. Without it the audit runs in report-only mode with
defaults.

```yaml
version: 1
principal: admin            # must hold the 'suppression' class
mode: report-only           # report-only | enforce
require: [reason]           # annotation keys required on every suppression (enforce mode)
max_age_days: 365           # a suppression older than this without `expires` is a finding
max_expires_days: 180       # `expires` may be at most this far from the day it was added
blanket: deny               # allow | warn | deny  (§3, blanket ignores)
tools: [checkov, tfsec, trivy, tflint, kics, semgrep, bandit, gitleaks, hadolint, shellcheck,
        kube-linter, github-actions]
exempt_paths: ["test/fixtures/**"]
```

Load errors, never guesses: unknown keys, unknown tools, non-positive limits, a principal without
`suppression`.

## 6. CLI and the Action

- `aegis audit suppressions [PATH] [--json | --sarif] [--since REF]`: the inventory. `--since`
  limits it to suppressions added or widened after a git ref (the PR base).
- Exit codes, as elsewhere: 0 clean, 3 policy violations (expired, missing reason in enforce
  mode, a denied blanket ignore, older than `max_age_days`), 65 broken `suppressions.yaml`.
- The GitHub Action (`moneytool/aegis-devops-action`) gets a `suppressions` input:
  `off | report | enforce`. In a PR it runs with `--since <base>`, posts one summary comment
  listing the new suppressions with author and reason, and uploads SARIF so they appear in code
  scanning. A minor bump of the Action (v1.2).

## 7. Agent gate (v1.2)

The hook today evaluates shell commands only. With a `suppressions.yaml` present,
`aegis install <agent>` also adds a matcher for the agent's file-edit tools (Claude Code
`Edit|Write|MultiEdit`, Codex `apply_patch`, Gemini `replace|write_file`, OpenCode `edit|write`).
The hook runs the §3 parsers on the **added lines only** and:

- a new suppression **with** a complete annotation → allow, with a message naming it;
- a new suppression **without** one → ESCALATE ("the agent wants to suppress CKV_AWS_18 in
  main.tf:12 — allow?"); deny on Codex, which has no ask (as for every ESCALATE);
- an edit that removes or narrows a suppression → allow silently.

The agent cannot satisfy the gate by editing `suppressions.yaml` — it is signed.

## 8. Threats and limits

| Threat | Result |
|---|---|
| Agent adds `# checkov:skip` to pass CI | §7 asks the user; without the hook, the PR comment (§6) lists it with the agent's commit |
| Agent writes a fake annotation (`reason="ok"`) | allowed — the gate checks presence, not truth; the reason is shown to the reviewer, who judges it |
| Agent edits `suppressions.yaml` to relax limits | refused: signed, principal must hold `suppression` |
| Suppression moved via a file-form ignore instead of inline | detected: file forms are parsed too (§3) |
| Scanner config disables a rule globally (`skip-check` in `.checkov.yaml`) | detected as repo-wide scope, flagged prominently |
| A tool's syntax we do not parse (custom wrapper, new scanner) | not detected; the docs list supported tools; new parsers are small |
| `git blame` misattributes after a reformat or move | `--ignore-revs-file` honoured (`.git-blame-ignore-revs`) |
| Shell or CI-level bypass (`|| true`, removing the scan step) | out of scope for v1.1; `continue-on-error` is the only CI form detected (§10) |

## 9. Why this belongs in Aegis

It is the same claim Aegis already makes, applied one level down: **an agent should not be able
to loosen policy by editing a file**. Aegis has the pieces — the hook in every major agent,
signed policy with authority classes, report-only/enforce, the Action with SARIF — so this is
mostly parsers plus wiring. It also gives Aegis a reason to be installed in repositories that do
not run Terraform plans through it, which broadens adoption.

A standalone tool was considered (no Aegis dependency, wider audience). Rejected for v1.1: the
inventory alone is a lint, and the part no one else can do is the signed policy and the agent
gate. The parsers live in `aegis_core/suppressions/` with no imports from the rest, so they can be
split into a library later if there is demand.

## 10. Implementation plan

1. `aegis_core/suppressions/`: finding model, one parser per tool (§3) with fixtures, annotation
   parser (§4), blame lookup, `--since` diffing.
2. `suppressions.yaml` loader with the `suppression` authority class; evaluation (§5).
3. `aegis audit suppressions` with text/JSON/SARIF output; docs (`docs/suppressions.md`),
   README, CHANGELOG. Release v1.1.0.
4. Action input `suppressions` + PR comment + SARIF upload; Action v1.2.0.
5. Hook edit-tool matchers and the added-lines gate (§7), live-tested per agent; v1.2.0.
6. Backlog: `eslint-disable`, `# type: ignore`, `# noqa`, `@pytest.mark.skip`, `|| true` in CI
   scripts, Terraform `lifecycle { ignore_changes }`.

Measured before release: precision and recall of the parsers on a sample of public Terraform /
Kubernetes repositories (hand-labelled), and hook latency for the §7 gate.

## 11. Open questions

1. **Release slot:** v1.1 after the budget cap, or ahead of it? Proposed: after — 1.0 is
   already scoped.
2. **Default when `suppressions.yaml` is absent:** report-only with `blanket: warn` and no
   age limit? Proposed: yes — nothing fails until a policy says so.
3. **`continue-on-error` in CI:** include in v1.1 (noisy: many uses are legitimate)? Proposed:
   include, but report only, never enforce.
4. **Annotation syntax:** `aegis:` trailer as in §4, or reuse each tool's native reason field
   where one exists? Proposed: read both, document the trailer as the portable form.
5. **Agent gate default:** ESCALATE on any unannotated new suppression, or only in `enforce`
   mode? Proposed: only in `enforce`; report-only mode just prints a message.
