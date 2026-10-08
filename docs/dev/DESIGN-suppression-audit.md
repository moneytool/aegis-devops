# Design: suppression audit (`aegis audit suppressions`)

Status: **draft for review**, 2026-10-07. Target release: **v1.1** (after the v1.0 budget cap,
[DESIGN-v1.0-budget-cap.md](DESIGN-v1.0-budget-cap.md)); the hook part (§6, §7.1) is additive and can
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
- **Agent gate** (v1.2): the hook asks before an agent writes a new or widened suppression (§6, §7).
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

- Keys: `reason`, `owner`, `expires` (ISO date), `ticket`. All are optional in the syntax;
  which ones a suppression must carry is set by `require` in `suppressions.yaml` (§5), and a
  missing key is a violation only in enforce mode (§6).
- For file-form ignores (`.trivyignore`, `.gitleaksignore`), the trailer is a comment on the
  line above the entry.
- Where the tool already has an expiry (tfsec `:exp:`, Trivy `expired_at`), Aegis reads it too;
  if both are present the earlier date wins.

## 5. Policy: `suppressions.yaml`

Optional, in the policy directory, signed like the other files; its `principal` must hold a new
**`suppression`** class in `authority.yaml`.

```yaml
version: 1
principal: admin            # must hold the 'suppression' class
mode: enforce               # report-only | enforce  (§6: what each one does)
require: [reason]           # annotation keys every suppression must carry
max_age_days: 365           # a suppression older than this without `expires` is a violation
max_expires_days: 180       # `expires` may be at most this far from the day it was added
blanket: deny               # allow | warn | deny  (§3, blanket ignores)
tools: [checkov, tfsec, trivy, tflint, kics, semgrep, bandit, gitleaks, hadolint, shellcheck,
        kube-linter, github-actions]
exempt_paths: ["test/fixtures/**"]
```

Every rule above (`require`, `max_age_days`, `max_expires_days`, `blanket: deny`, expiry) yields
a **violation**. Whether a violation fails anything is decided by the mode alone (§6): in
report-only it is printed as "would fail", never returned as an error. `blanket: warn` is a
finding that never fails, in either mode. `continue-on-error` findings are always report-only
(§11 Q3), whatever the mode.

Load errors, never guesses: unknown keys, unknown tools, non-positive limits, a principal without
`suppression`.

### 5.1 Where enforcement reads the policy from

Signing stops an edit to `suppressions.yaml`; it does not stop a PR from **deleting** it, or from
replacing `authority.yaml` or the key configuration. So the tree under review is never the source
of its own enforcement policy.

- **CI (`--since <base>`, the Action).** The policy, `authority.yaml` and the key configuration
  are read from the **base revision** (`git show <base>:<policy-dir>/…`), or from a
  deployment-owned directory passed as `--policy-dir` (outside the checkout, e.g. an org config
  repo checked out at a pinned ref). The candidate tree is audited as untrusted data only. Its
  own copy of the policy has no effect on the effective mode; a change to it is reported as a
  finding (`policy-changed`) so the reviewer sees it, and takes effect only once it is on the
  base branch.
- **Local hook.** Aegis keeps a small record outside the repository
  (`~/.cache/aegis/suppressions/<project-id>.json`) of the strongest mode last seen for the
  project, with the signer. A project **never** configured is unconfigured: report-only with
  defaults, no record. A project whose record says `enforce` but whose policy is now missing, has
  a bad signature, or has a principal or key that no longer verifies is **broken**, not
  unconfigured: the gate treats it as enforce with a broken policy (§6). Going from enforce to
  report-only needs a validly signed policy that says so; `aegis suppressions forget` clears the
  record by hand.
- **Plain `aegis audit suppressions` without `--since`** (a developer's local inventory) reads
  the policy from the working tree, like `aegis check`. It is a report, not a gate.

## 6. Modes, exit codes and the Action

- `aegis audit suppressions [PATH] [--json | --sarif] [--since REF] [--policy-dir DIR]
  [--mode report-only|enforce]`: the inventory. With `--since`, only suppressions that are new or
  **widened** relative to the ref (§7) are evaluated; the full inventory is still in the JSON.

**Effective mode.** It comes from the trusted policy (§5.1). A `--mode` flag or the Action input
can **raise** it, never lower it: effective = the stricter of the two. With no trusted policy,
the effective mode is the flag/input, else report-only, with default rules (no `require`, no age
limits, `blanket: warn`; only expired annotations are violations).

| Situation | report-only | enforce |
|---|---|---|
| No findings | exit 0 | exit 0 |
| Findings, no violations | exit 0, findings listed | exit 0, findings listed |
| Violations (expired, missing required key, `blanket: deny`, too old, expiry too far) | exit 0, listed as "would fail" | **exit 3** |
| A suppression file the parser cannot read (e.g. broken `.checkov.yaml`) | exit 0, `unparsed` finding | **exit 3** (cannot prove it is clean) |
| Trusted policy malformed, bad signature, principal lacks `suppression` | **exit 65** | **exit 65** |
| Local hook: record says enforce, policy now missing or unverifiable (§5.1) | — | treated as enforce with a broken policy: **exit 65**, gate as below |

A broken trusted policy is 65 in both modes because the mode itself cannot be known; this
matches how the rest of Aegis treats an unusable policy.

**Action.** `moneytool/aegis-devops-action` gets a `suppressions` input:
- `off`: the step is skipped.
- `report`: run with the trusted policy's mode (so it **still fails** if the base branch policy
  says enforce); post the PR comment and SARIF.
- `enforce`: as `report`, but raise the mode to enforce if the policy is report-only or absent.

The input lives in the workflow file, which a PR can edit; the Action cannot defend against its
own removal. Protecting it is the repository's job (required status checks, or a ruleset
"required workflow" owned outside the repo); the docs say so. In a PR it runs with
`--since <base>`, posts one summary comment listing new and widened suppressions with author and
reason, and uploads SARIF. A minor bump of the Action (v1.2).

**Hook**, by effective mode:

| Edit adds or widens a suppression | report-only | enforce | enforce, broken policy |
|---|---|---|---|
| with all required annotation keys, no other violation | allow, message | allow, message | ESCALATE |
| with a violation | allow, message ("would fail in enforce") | ESCALATE | ESCALATE |
| the proposed file cannot be reconstructed or parsed (§7) | allow, message | ESCALATE | ESCALATE |
| removes or narrows a suppression | allow | allow | allow |
| edits the policy files themselves | allow (the signature decides) | allow, message | allow, message |

ESCALATE asks in Claude Code, Copilot, VS Code and Cursor, and is a block in Codex, Gemini CLI and
OpenCode, which have no "ask" (as for every Aegis ESCALATE, see `docs/agents.md`).

## 7. Detecting new and widened suppressions (CI and hook)

Added-line parsing is not enough. Turning on `enabled = false` inside an existing `.tflint.hcl`
rule block leaves the rule name on an unchanged line; a new YAML list entry needs its enclosing
key; an annotation may sit on an unchanged line above. So both `--since` and the hook compare
**complete files**:

1. **Reconstruct** the before and after contents of every touched file. CI: `git show
   <base>:<path>` and the candidate tree. Hook: the file on disk is *before*; *after* is computed
   by applying the tool call in memory (Claude Code `Edit`/`MultiEdit` old→new replacements,
   `Write` content, Codex `apply_patch` hunks, Gemini `replace`/`write_file`, OpenCode
   `edit`/`write`). If the application fails (stale `old_string`, a hunk that does not apply),
   the edit is "cannot reconstruct" (§6 hook table). Renames are followed (`git diff -M`; in the
   hook, a delete plus a write of the same content).
2. **Parse both** with the tool's structured parser (HCL for `.tflint.hcl`, YAML for
   `.checkov.yaml`/`.hadolint.yaml`/`.kube-linter.yaml`/workflows, line formats for the ignore
   files, comment scanning for inline forms), not with regexes over a diff.
3. **Normalize** each finding to a key: tool, file, the suppressed anchor (resource address,
   YAML path, or the code line's content hash when there is no structure), plus its value: the
   rule set (or `*`), scope (line < block < file < repo), and annotation.
4. **Compare** before and after by key. A finding is **new** if its key is absent before.
   For a key present in both, Aegis computes the **newly suppressed rules**:
   - explicit rule sets on both sides: `after_rules − before_rules`. Any nonempty result is
     evaluated, even if other rules were removed in the same change, so replacing `CKV_1` with
     `CKV_2` (same size, not a superset) suppresses `CKV_2` anew;
   - specific → blanket (`# nosec B101` → `# nosec`): widened, always, as a blanket ignore;
   - blanket → specific, or blanket → blanket: no newly suppressed rules.

   The finding is **widened** if the newly suppressed rules are nonempty, it becomes blanket, its
   scope grows, its annotation loses a required key, or its `expires` moves later. Only the newly
   suppressed rules are evaluated against policy; the rules it already covered are not
   re-reported. A change is **pure narrowing** only when it is none of these (rules removed, scope
   reduced, expiry brought forward); narrowing and removal are recorded, never violations. An
   annotation change on an unchanged suppression (reason edited, owner removed) is evaluated like
   a new one.

### 7.1 Hook installation

The hook today evaluates shell commands only. When a project has a suppression policy (or a §5.1
enforce record), `aegis install <agent>` also adds a matcher for the agent's file-edit tools, and
the hook applies the §6 table to the result of steps 1–4 for the touched file. Agents whose edit
payload cannot be reconstructed (VS Code, which sends no edit content to hooks; Cursor's shell-only
hook) get no gate; the docs list them.

## 8. Threats and limits

| Threat | Result |
|---|---|
| Agent adds `# checkov:skip` to pass CI | hook gate (§6) by mode; in CI the PR comment lists it with the commit and author |
| Agent writes a fake annotation (`reason="ok"`) | allowed — the gate checks presence, not truth; the reason is shown to the reviewer, who judges it |
| Agent edits `suppressions.yaml` to relax limits | refused: signed, principal must hold `suppression`; in CI the base-branch copy is used anyway (§5.1) |
| PR deletes `suppressions.yaml` while adding suppressions | no effect in CI: policy comes from the base revision; reported as `policy-changed` |
| PR replaces `authority.yaml` or the key configuration | no effect in CI, same reason; locally, the §5.1 record notices the signer no longer verifies → broken policy |
| Local deletion of the policy | §5.1 record → broken policy, not unconfigured. The agent runs as the user and *can* delete the record too; as with the budget cap's session logs, this is a guard against convenient shortcuts, not against a deliberately hostile agent |
| PR edits the workflow to `suppressions: off` or removes the step | not stopped by Aegis; the repository's required checks / required workflows must protect it (§6) |
| Widening without a new marker (`enabled = false` in an existing tflint block, a new list entry, `CKV_1` → `CKV_1,CKV_2`) | detected: full-file semantic comparison (§7) |
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

1. `aegis_core/suppressions/`: finding model, one structured parser per tool (§3) with fixtures,
   annotation parser (§4), blame lookup, normalization and before/after comparison (§7).
2. `suppressions.yaml` loader with the `suppression` authority class; trusted-source resolution
   (§5.1: base revision, `--policy-dir`, local enforce record); mode resolution and exit codes (§6).
3. `aegis audit suppressions` with text/JSON/SARIF output; docs (`docs/suppressions.md`),
   README, CHANGELOG. Release v1.1.0.
4. Action input `suppressions` + PR comment + SARIF upload; Action v1.2.0.
5. Hook edit-tool matchers, in-memory reconstruction of the proposed file, and the §6 gate,
   live-tested per agent; v1.2.0.
6. Backlog: `eslint-disable`, `# type: ignore`, `# noqa`, `@pytest.mark.skip`, `|| true` in CI
   scripts, Terraform `lifecycle { ignore_changes }`.

**Fixtures and validation cases** (each must pass before the step that needs it ships):

- *Detection (§7):* `enabled = false` added inside an existing `.tflint.hcl` rule block; a new
  entry appended to `skip-check:` in `.checkov.yaml` and to `ignored:` in `.hadolint.yaml`; an
  inline rule list widened (`CKV_AWS_18` → `CKV_AWS_18,CKV_AWS_19`), replaced at equal size
  (`CKV_AWS_18` → `CKV_AWS_19`), and changed by mixed removal and addition (`CKV_AWS_18,CKV_AWS_19` →
  `CKV_AWS_19,CKV_AWS_20`: only `CKV_AWS_20` is new); blanket → specific (narrowing); a specific id made blanket
  (`# nosec B101` → `# nosec`); scope widened (`ignore-line` → `ignore-block`); an annotation on an
  unchanged preceding line removed or its `expires` pushed later; a suppression moved to another
  file and a renamed file (not new); a multi-hunk `apply_patch` and a `MultiEdit` touching the same
  block; an edit whose `old_string` no longer matches (cannot reconstruct).
- *Trusted policy (§5.1):* PR deletes `suppressions.yaml`; PR edits it with an invalid signature;
  PR replaces `authority.yaml` or the key configuration; PR changes `mode: enforce` to
  `report-only` (all four: effective mode unchanged in CI, `policy-changed` reported); Action input
  `report` against an enforce base policy (still fails); local policy deleted after an enforce run
  (broken, not unconfigured); `aegis suppressions forget`.
- *Modes (§6):* every row of both tables, for each exit code.

Measured before release: precision and recall of the parsers on a sample of public Terraform /
Kubernetes repositories (hand-labelled), and hook latency for the §7 gate.

## 11. Open questions

1. **Release slot:** v1.1 after the budget cap, or ahead of it? Proposed: after — 1.0 is
   already scoped.
2. **Defaults with no trusted policy** (§6): report-only, `blanket: warn`, no age limit, only
   expired annotations are violations. Proposed: yes — nothing fails until a policy or the Action
   input says so.
3. **`continue-on-error` in CI:** include in v1.1 (noisy: many uses are legitimate)? Proposed:
   include as report-only findings in every mode (§5), never violations.
4. **Annotation syntax:** `aegis:` trailer as in §4, or reuse each tool's native reason field
   where one exists? Proposed: read both, document the trailer as the portable form.
5. **Local enforce record (§5.1):** worth the extra state, given an agent running as the user can
   delete it? Proposed: yes — it turns an accidental or casual policy deletion into a visible
   broken-policy state, and costs one small file.
