# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — while the major version is 0,
any release may change behaviour.

## [Unreleased]

### Added
- The repository is a Gemini CLI extension (`gemini-extension.json`, `hooks/hooks.json`):
  `gemini extensions install https://github.com/moneytool/aegis-devops`.

### Changed
- The Claude Code plugin moved to `plugins/claude/` (the marketplace entry points there, so
  `claude plugin marketplace add moneytool/aegis-devops` and the install command are
  unchanged). Gemini CLI reads an extension's hooks from `hooks/hooks.json` at the root, where
  the Claude plugin's hooks used to be.

## [Unreleased]

### Fixed
- **An untrustworthy rule could force ESCALATE through an unresolved condition.** When an
  intent's environment (or, without tzdata, a rule's time window) could not be resolved, every
  matching rule forced ESCALATE before its integrity or authority was checked, so an
  unauthorized or tampered rule scoped on `env: prod` could stall any action whose environment
  was unknown. Those rules are now discarded (reported in `discarded[]`) on that path too, as
  they are when they match outright; `--on-untrusted-match escalate` keeps the old behaviour
  for them. Found by the council review of the v0.3 design.
- **kubectl normal forms.** `kubectl drain node1` (and `cordon`/`uncordon`) parsed to
  `node1/*` instead of `node/node1`; `exec`, `logs`, `attach`, `port-forward` on a bare pod
  name parsed to the bare name instead of `pod/<name>`; plural and short kinds such as
  `storageclasses`, `sc`, `ingressclasses`, `clusterrolebindings`, `crd` were not normalised.
  A rule written for the normal form missed each of these. Rules written against the old forms
  need updating (see `docs/constraints.md`).
- `kubectl drain … --ignore-daemonsets` (and `--delete-emptydir-data`, `--disable-eviction`)
  was rejected as malformed.
- A global option before `rollout` or `set image` was read as the subcommand:
  `kubectl -n prod rollout restart deploy/web` became the action `rollout--n` on `prod/*`
  (losing the namespace, so a namespace-scoped rollout rule missed it), and
  `kubectl --as admin rollout restart …` escaped the impersonation rule. The subcommand is now
  taken before global options are merged, and global options between the verb and its
  subcommand (`kubectl rollout --as admin restart …`, which kubectl accepts) are consumed the
  same way, so every placement parses identically. An unrecognised option there still fails
  closed.

### Changed
- kubectl `--as` / `--as-group` / `--as-uid` are no longer dropped: they are recorded in
  `params.impersonate`, and each impersonated identity becomes its own `impersonate` intent
  (`user/<name>`, `group/<name>`, `uid/<id>`). Impersonation moves a request out of an agent
  identity's scope on the server side, so the client hook is the one layer that sees it.
- The example policy blocks kubectl impersonation (`block-kubectl-impersonation`); change its
  effect to ESCALATE if a human should be able to approve it. The example store now loads 30
  rules.

## [0.2.0] — 2026-09-27

**Real trust roots, step 1.** A rule can cite a signed commit in a policy repository, and its
principal is the commit's verified signer (SSH or GPG) rather than a name written in the rule
or asserted with the shared signing key. Together with 0.1.7 (Git sources, SSH), this completes
step 1 of the v0.2 roadmap (`docs/dev/PLAN.md` §9; design in
`docs/dev/DESIGN-v0.2-git-sources.md`). Opt-in: nothing changes unless a rule cites `git:`.
Still to come: per-principal public-key signing for the other policy files (step 2) and
Slack/Jira sources (step 3).

### Added
- **OpenPGP (GPG) signatures for Git sources**, alongside SSH. A GPG signer is listed with its
  primary fingerprint and armored public key; Aegis verifies against a private keyring holding
  exactly those keys (a mismatch is a load error), so neither the user's keyring nor the
  repository's config can add trusted keys. Expired and revoked keys do not verify.
- `aegis sources`: one line per constraint with its source transport (`git`, `file`,
  `unchecked`), the verified principal, or the quarantine reason; exits 1 if any rule is
  quarantined.
- `aegis init` writes commented `repos.example.yaml` and `signers.example.yaml` (inert until
  copied to `repos.yaml` / `signers.yaml`).

## [0.1.7] — 2026-09-27

Git sources: a rule can cite a signed commit, and its principal is the commit's verified
signer. Opt-in; nothing changes unless a rule cites `git:`.

### Added
- **Git sources with signature-derived principals** (v0.2 step 1,
  `docs/dev/DESIGN-v0.2-git-sources.md`). A constraint may cite
  `git:<repo>@<sha>:<path>` in a locally configured clone (`repos.yaml`); its principal is the
  verified SSH signer of that commit, mapped through `signers.yaml`, instead of a name in the
  rule or `PRINCIPALS.yaml`. New quarantine reasons: `invalid-source-ref`, `unknown-repo`,
  `unknown-commit`, `unsigned-source`, `unknown-signer`, `commit-does-not-touch-source`,
  `superseded`, `stale-source`, `invalid-git-source`. New options `--repos`, `--signers`,
  `--max-source-age`. Git runs with a from-scratch environment and overrides for every
  signature setting, so a repository's own config cannot choose the trusted keys. Shallow and
  grafted clones are refused (they change which parents Git reports), the commit-graph cache is
  off, and "did this commit add the rule" is read from the signed commit object. A `git:`
  citation with no Git configuration is always rejected (`unknown-repo`). File sources are
  unchanged.

## [0.1.6] — 2026-09-27

A correction to the published benchmark. No change to how a decision is made.

### Fixed
- **The agent-harness benchmark rows were scored against rules they were never shown.** The
  `claude-cli*`, `codex*` and `ollama` rows are shown only the corpus's 100-constraint holdout
  subset, but were scored against the reference oracle over all 500 constraints. On the 120
  hold-out intents the oracle's verdict differs between the two for 37 intents, and 11 of the
  30 poison candidates involve poisoned rules outside the 100. So those rows were marked as
  missing legitimate rules they never saw (recall 0.72–0.77) and as resisting poisoned rules
  they never saw. Each row is now scored against the oracle over exactly the rules it was
  given (`scored_against` in `results/benchmark.json`). The same cached answers, re-scored
  (no model was re-run): poison-susceptibility **1.000** for six of the seven models and
  **0.789** for `gpt-6-luna` (previously reported as 0.23–0.33), recall 0.97–1.00. The earlier
  numbers **understated** how often the models act on poisoned rules. The 0.1.2 entry below
  ("All land between 0.23 and 0.33 poison-susceptibility and every one acts on 5 of 8 forged
  rules") is wrong for that reason.
- This also accounts for the gap between the Sonnet 5 API self-check (1.000) and the
  `claude-cli-sonnet` row (previously 0.333): the latter was scored against 400 rules it never
  saw.

### Added
- `aegis-holdout`: Aegis restricted to the same 100-constraint subset, so there is a
  like-for-like row on that basis (0 of 19 poison candidates acted on, over-block 0.000).
- Tests that every published row is scored on the basis it was shown, and that the holdout
  oracle only ever sees the holdout constraints.

## [0.1.5] — 2026-09-27

Gemini CLI and OpenCode join the supported agents; all seven are live-tested. No change to how
a decision is made.

### Added
- `aegis hook gemini` / `aegis install gemini`: a `BeforeTool` hook on Gemini CLI's
  `run_shell_command`.
- `aegis hook opencode` / `aegis install opencode`: OpenCode's hooks are JavaScript plugins, so
  the installer writes a bundled plugin (`tool.execute.before`) that hands each `bash` command
  to `aegis hook opencode` and throws when Aegis says no.

## [0.1.4] — 2026-09-27

A GitHub Copilot plugin, and a fix to the forged-source demo. No change to how a decision is
made.

### Added
- A GitHub Copilot plugin (`plugins/copilot/`, Agent Plugins 1.0):
  `copilot plugin install moneytool/aegis-devops:plugins/copilot`. It runs the same wrapper as
  the Claude Code plugin, so without `aegis` installed it still allows everything outside
  opted-in projects instead of failing every command.

### Changed
- Copilot replies now carry VS Code's `hookSpecificOutput` shape as well as Copilot CLI's
  top-level `permissionDecision`, since both read the same hook files and plugins.

### Fixed
- `data/sources-forged/` lacked the eight sources added with the default rules, so the
  `--sources data/sources-forged` demo quarantined 9 of 29 rules and refused to decide.

## [0.1.3] — 2026-09-27

Aegis can now sit in front of a coding agent's shell commands, and the example policy blocks
the obviously infrastructure-breaking ones. No change to how a decision is made.

### Added
- `aegis hook <agent>`: runs as the pre-tool hook of Claude Code, Codex CLI, GitHub Copilot
  CLI, VS Code agent mode or Cursor, reads that agent's payload and answers in its format.
  It acts only in projects that opted in (`.aegis/` here or above, `$AEGIS_CONFIG_DIR`, or
  `~/.config/aegis`) and blocks only what the policy blocks; an unusable policy or a command
  that cannot be analysed blocks only infrastructure commands. See `docs/agents.md`.
- `aegis install <agent> [--user] [--remove]` writes (or removes) that hook in the agent's
  config without touching its other settings.
- A Claude Code plugin and marketplace (`.claude-plugin/`, `hooks/`):
  `claude plugin marketplace add moneytool/aegis-devops`.
- Default rules in the example policy for infrastructure-breaking commands: `terraform destroy`
  / `tofu destroy` / `apply -destroy`, `pulumi destroy` and `stack rm`, deleting a Kubernetes
  namespace, an S3 bucket, an RDS database, a GCP project or an Azure resource group (BLOCK),
  and deleting an Argo CD application (ESCALATE). The example store now loads 29 rules.
- `terraform`/`tofu` `destroy` (and `apply -destroy`) are recognised from the command line as
  a `terraform` `delete` intent on `workspace/<dir>`; other terraform subcommands still need a
  plan and are not gated from their argv.

### Changed
- The design notes and review history (`PLAN.md`, `REVIEW*.md`, `FEEDBACK.md`) moved to
  `docs/dev/`.

## [0.1.2] — 2026-09-26

No change to how a decision is made. Released so the PyPI page and the Zenodo record carry the
full benchmark.

### Added
- The benchmark now covers seven agent-harness models across two vendors: Claude Haiku 4.5,
  Sonnet 5, Opus 5 and Fable 5.1 through `claude -p`; `gpt-6-astra`, `gpt-6-sol` and
  `gpt-6-luna` through `codex exec`. All land between 0.23 and 0.33 poison-susceptibility and
  every one acts on 5 of 8 forged rules; Aegis acts on none of the 30 poisoned intents.
- `scripts/run_until_done.sh` runs a verifier to completion across CLI usage limits: it waits
  for the reset time the CLI reports and resumes from the cached answers.
- `scripts/make_latency_svg.py`: the latency chart is generated from `results/latency.json`, and
  the docs drift test fails if it is stale.

### Changed
- A decision is now O(k) in the matching (provider, action) bucket rather than O(n) in the
  store: the environment and time-window checks scanned every constraint. p99 at 10,000
  constraints fell from 5.9 ms to 3.7 ms.
- Latency figures report p95/p99 only; p50 fell between the cheap no-match decisions and real
  matches and described neither.

### Fixed
- LLM benchmark runs could not resume: the recording client never read its own cache, so every
  run re-asked every prompt. A usage-limit reply was cached as an empty answer; it now raises
  and is never cached.
- Each call verifies the model that actually answered; a mismatch stops the run instead of
  recording one model's numbers under another's name.
- `.gitignore` excluded all of `results/`, so its whitelist had never applied; the harness caches
  and the preserved fail-closed results are now tracked.
- A timing test that failed on shared CI runners was replaced by a count of the work done.

### Known
- Loading a store with `--sources` is about 35% slower than first measured, most likely from
  the path-traversal guard resolving every source path; it is a once-per-load cost.

## [0.1.1] — 2026-09-24

Documentation and packaging only; no change to the decision engine. Released so the PyPI
page carries the current README, and so the release is archived on Zenodo with a DOI.

### Added
- Codex CLI (`gpt-6-astra`) and Claude Code CLI (Haiku) rows in the benchmark. Both are
  agent harnesses rather than raw completions, scored on a 100-constraint hold-out subset.
- `SECURITY.md`, `CITATION.cff`, and this changelog.
- `scripts/make_benchmark_svg.py`: the benchmark chart is generated from
  `results/benchmark.json` instead of drawn by hand.
- `tests/test_docs_consistency.py`: CI now fails if a results table, the chart, a corpus
  diversity figure, or a description of the default policy disagrees with the data or the
  code.

### Changed
- The README is now a short entry point; reference material moved to `docs/cli.md`,
  `docs/constraints.md`, `docs/configuration.md` and `docs/benchmark.md`.
- The quick start leads with `pip install` and `aegis init ./.aegis`. Without `init`, a fresh
  install had no policy files and every check exited 66.
- The alpha caveats moved from a banner at the top of the README into Project status.

### Fixed
- `docs/cli.md` and `docs/configuration.md` still described the old escalate-on-untrusted
  default and showed ESCALATE output for tampered and forged rules. On 0.1.0 both examples
  ALLOW, with the rule named in `discarded` and in store health. They now show real output
  from the current code.
- `docs/benchmark.md` quoted the previous corpus's diversity figures and called
  `evade-case-variant` an `xfail`.

## [0.1.0] — 2026-09-23

First release. Published to PyPI as `aegis-devops`.

### Added
- **Constraint store** with two independent guarantees per rule: integrity (a provenance hash
  over the source-side fields) and authority (which principal may assert which class of rule).
  Schema validation, quarantine with reasons, and signed policy files.
- **Interceptor** returning ALLOW / BLOCK / ESCALATE with citations, discarded rules, coverage,
  notes and latency. Dry runs are never blocked but report the verdict a real run would get.
- **Parsers** for kubectl, Terraform and OpenTofu plans, AWS, Azure, gcloud/gsutil, Helm,
  ArgoCD, Flux, git, the GitHub CLI, Pulumi, and SQL/mongo/migration tools — all normalising to
  one intent shape. `aegis check command` splits a whole shell string, since that is what an
  agent framework hands you.
- **Plan-level constraints** evaluated over a whole batch (`max_intents`, `max_matching`,
  `forbid_together`, `ratio`).
- **Environment identity mapping** from kube contexts, cloud accounts, projects, subscriptions
  and repos, so rules scope on `env: prod` rather than raw identifiers. An unresolved
  environment escalates rather than being treated as "not prod".
- **Rate-limited constraints** backed by a locked, hash-chained, rotating decision ledger
  (JSONL or SQLite).
- **Signing** of policy and source files, with per-directory manifests, and `aegis sign` /
  `aegis verify` / `aegis keygen`.
- **CLI** with `aegis init`, config discovery, structured decision logs, a Prometheus textfile
  exporter, and `--exit-style claude-hook` plus a ready-made Claude Code PreToolUse hook.
- **Evaluation**: a 500-constraint labelled corpus (323 distinct structures) seeded from public
  postmortems, the Gatekeeper library, and cloud security benchmarks; an independent reference
  oracle so ground truth never runs the system under test; an adversarial suite of attacks in
  five categories; and a benchmark against OPA, a signed-bundle OPA variant, and real LLM
  self-checks.

### Changed
- An untrustworthy matching constraint (tampered, forged, or from an unauthorized principal)
  gets **no vote** by default. An earlier default made it force ESCALATE; measurement showed
  that scored the same poison-susceptibility and over-block rate as a verifier with no trust
  model at all, because letting an unverifiable rule produce a verdict hands whoever planted it
  control over that verdict. The old behaviour is available as `--on-untrusted-match escalate`.

### Known limitations
See "Project status" in the README and [`docs/dev/PLAN.md`](docs/dev/PLAN.md) §8. In short: the source fetcher reads files
rather than real connectors, signing uses a shared secret, and a principal is a signed name
rather than a bound identity.

[0.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.0
[0.1.7]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.7
[0.1.6]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.6
[0.1.5]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.5
[0.1.4]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.4
[0.1.3]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.3
[0.1.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.2
[0.1.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.1
[0.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.0
