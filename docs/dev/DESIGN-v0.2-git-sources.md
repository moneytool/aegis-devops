# Design: Git source connector and signature-derived principals (v0.2, step 1)

Status: **agreed** 2026-09-27 (decisions in §8); implementation in progress. Implements step 1 of [PLAN.md §9](PLAN.md). No code
yet: this changes where the threat model's trust boundary sits, so the design is agreed first.

## 1. Problem

Aegis checks two things about every rule before it gets a vote: that nobody changed it since
ingest (integrity), and that its author was allowed to write that kind of rule (authority).
Today both checks bottom out in things an operator asserts rather than proves:

- **The source** a rule cites is `sources/<source_ref>.json`, a file on disk. Whoever can write
  that directory (and holds the signing key) can make any rule "backed by its source".
- **The author** is a name. `sources/PRINCIPALS.yaml` maps each `source_ref` to a principal, and
  the file is signed, but with a shared BLAKE2b key: whoever can verify can also sign, so
  whoever holds the key can attribute any source to anyone, including `admin`.

So v0.1 proves the *decision procedure* is sound; it does not prove the *identities* feeding it
(README "Project status", PLAN §8). Most operational policy lives in Git repositories, and Git
already has the missing pieces: content-addressed history and signed commits. This design uses
them.

## 2. Goal and non-goals

**Goal.** A rule may cite a file at a specific commit in a policy repository. Aegis then:

1. reads the rule's source from that commit, not from a JSON file on disk;
2. takes the rule's principal from **that commit's verified signature**, mapped through a
   signer map, instead of from `PRINCIPALS.yaml` or from the rule itself;
3. quarantines the rule if the signature is missing or invalid, the signer is unknown, the
   commit did not actually change the rule, or the rule has since been changed or removed.

The authority check stays exactly as it is (`authority.yaml`: principal → constraint classes).
What changes is that the principal it is given is now proven, not asserted.

**Non-goals for this step.**
- Replacing the shared BLAKE2b key for the *other* policy files (`constraints.yaml`,
  `authority.yaml`, ...). That is v0.2 step 2 (per-principal public keys), which this design
  prepares for but does not do.
- Slack and Jira sources (step 3).
- Network access at decision time. Aegis never fetches; it reads local clones (§4.1).
- Deciding *which* humans are trustworthy. The signer map records that decision; Aegis enforces it.

## 3. What changes in the trust boundary

| | v0.1 (file sources) | v0.2 (Git sources) |
|---|---|---|
| Source content trusted because | the file is in `sources/` and signed with the shared key | it is the blob at a named commit (content-addressed) |
| Principal trusted because | `PRINCIPALS.yaml` says so, signed with the shared key | the commit carries a valid signature from a key the signer map assigns to that principal |
| To forge an `admin` rule you need | the shared key and write access to the config dir | an admin's **private signing key**, or write access to the signer map |
| Revoking a rule | edit files, re-sign | commit a change that removes or edits it (the old citation becomes stale, §4.5) |

The new trust roots are therefore:

1. **the private signing keys of the people in the signer map**, and
2. **the signer map itself** (`signers.yaml`, §4.3), plus the operator-held config that pins it.

Everything else — who can push to the repo, commit author/committer names, branch names, the
agent's own access — is untrusted by construction. In particular an agent (or a compromised CI
job) that can push commits gains nothing unless it can also produce a signature from a mapped
key.

**One operational requirement follows, and the docs must say it loudly:** the agent's
environment must not have access to a human's signing key. That includes forwarded SSH agents
(`SSH_AUTH_SOCK`) and unlocked `gpg-agent` sessions on a developer laptop where the agent runs.
If the agent can make a signing key sign, it *is* that principal. Aegis cannot detect this; it
can warn when `SSH_AUTH_SOCK` or `GPG_AGENT_INFO` is set in the process that runs a check.

## 4. Design

### 4.1 Repositories are configured, not named in rules

A new config file, `repos.yaml` in the Aegis config directory, lists the policy repositories:

```yaml
repos:
  platform-policy:                 # repo id used in source_refs
    path: /srv/aegis/platform-policy   # a local clone; Aegis never fetches
    ref: refs/remotes/origin/main      # the ref that defines "current" (§4.5)
```

A rule cannot point Aegis at an arbitrary path or URL: it can only name a repo id from this
file. Keeping the clone up to date (`git fetch`) is the operator's job (cron, CI), and it is
also the only thing that makes a revocation visible (§4.5). `repos.yaml` is a policy file and
is signed like the others.

### 4.2 `source_ref` grammar

```
git:<repo-id>@<commit-sha>:<path>
```

- `repo-id`: `[a-z0-9][a-z0-9._-]{0,63}`, must exist in `repos.yaml`.
- `commit-sha`: the full 40-hex SHA-1 (or 64-hex SHA-256 object format). No abbreviations, no
  branch names, no `HEAD~1`: the citation must name exactly one immutable object.
- `path`: a repository-relative path. Rejected if it is absolute, contains `..`, a backslash, a
  NUL, or a component starting with `-`, or does not match the rule-file pattern (below).

**One rule per file.** A Git source is a file `rules/<rule-id>.yaml` (pattern configurable per
repo) whose content is exactly the rule's source fields — the same fields a
`sources/<ref>.json` payload has today, minus `principal` (which now comes from the
signature). One file per rule is what makes "which commit changed this rule" a question Git can
answer exactly, without parsing diffs of a shared file.

Existing `sources/<ref>.json` references keep working unchanged: any `source_ref` without the
`git:` prefix goes to `FileSourceFetcher`. A store can mix both.

### 4.3 Signer map: `signers.yaml`

```yaml
signers:
  - principal: admin
    keys:
      - type: ssh
        key: "ssh-ed25519 AAAAC3Nza... alice@example.com"
      - type: gpg
        fingerprint: "4F2A 9C31 ... 77D0"
  - principal: sre_lead
    keys:
      - type: ssh
        key: "ssh-ed25519 AAAAC3Nzb... bob@example.com"
```

- Each key maps to exactly one principal; a key listed twice is a load error, not a guess.
- Principals are the same names `authority.yaml` uses, so the authority check is unchanged.
- **Where it lives in v0.2 step 1:** in the Aegis config directory, signed with the existing
  mechanism, and held by the operator — *not* in the policy repo. Putting it in the repo would
  let whoever can merge to the repo add their own key. Moving it into the repo safely needs a
  pinned root key and a rule that changes to `signers.yaml` must be signed by a key the
  *previous* version lists as an admin. That chain is the natural first piece of step 2, and is
  left as an open question (§8).

### 4.4 Verification of one Git-sourced rule

`GitSourceFetcher.fetch(source_ref)` and `.principal_for(source_ref)` implement the existing
`SourceFetcher` interface, so `verify_source_reason` and the store are unchanged. For a rule
citing `git:R@C:P`:

1. **Resolve** repo `R` from `repos.yaml`; `C` must exist as a commit object in that clone.
2. **Signature.** Verify `C`'s signature with Git itself (`git verify-commit`), configured for
   the check: SSH signatures use an `allowed_signers` file *generated from `signers.yaml`*, GPG
   signatures a keyring generated the same way. The result must be a good signature
   (`%G?` = `G`) from a key present in `signers.yaml`; the principal is that key's principal.
   Anything else — unsigned, bad, expired or revoked key, unknown key, a key only present in the
   user's own keyring — quarantines the rule with reason `unsigned-source` / `unknown-signer`.
3. **The commit changed this rule.** `P` must differ between `C` and `C`'s first parent (or be
   added by `C`). A signed commit that merely *contains* the file — say an admin's unrelated
   commit made after a developer added the rule — does not make the admin its author. Reason:
   `commit-does-not-touch-source`.
4. **Content.** The blob at `C:P` is parsed and used as the source payload; the provenance hash
   is recomputed with the principal from step 2, exactly as `verify_source_reason` does now. A
   mismatch is `forged`; a principal different from the rule's `principal` field is
   `principal-mismatch` (unchanged semantics).
5. **Still current** (§4.5): `C` must be in the history of the repo's configured `ref`, and the
   file at `ref` must be byte-identical to the file at `C` (same blob). If a later commit
   changed or deleted `P`, the rule is `superseded`. Comparing blobs rather than asking for "the
   last commit that touched `P`" keeps a rule cited by its author's own commit current after
   that branch is merged (`git log -- P` would name the feature commit or the merge depending
   on history simplification).

Merges: step 3 uses the first-parent diff, so a signed **merge** commit that brings `P` in counts
as touching it, and its signer becomes the principal. That matches the common "review, then an
authorised person merges" workflow: the merger vouches for what they merge. Teams that want the
original author instead can cite the non-merge commit; both are verified the same way.

### 4.5 Revocation and freshness

A rule is revoked by committing a change to (or deletion of) its file on the tracked ref: the
file there no longer matches the cited blob, so the citation fails step 5 on the next load. This only works if the local
clone is fetched: the store's health output gains the clone's age (`git log -1 --format=%ct` of
the tracked ref) and a warning when it is older than a configurable limit, because a stale clone
silently keeps revoked rules alive. Freshness is checked at store load, like source verification
today (PLAN §8: "forged sources are checked at load, not at decision time"); long-running
processes should reload on fetch.

### 4.6 Running Git safely

Every Git invocation runs with a fixed, minimal environment, because the repository and its
config are attacker-influenced input:

- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, and `-c` overrides (which take
  precedence over every config file) for **every** setting that decides how a signature is
  checked: `gpg.format`, `gpg.program`, `gpg.openpgp.program`, `gpg.ssh.program`,
  `gpg.x509.program`, `gpg.ssh.allowedSignersFile`, `gpg.ssh.revocationFile`. Missing one
  would let the repository's own `.git/config` name the program that "verifies" its
  signatures. Neither the repo's config nor the user's can change which keys count or which
  program verifies them. `core.hooksPath=/dev/null`, `core.fsmonitor=false`; no command used runs hooks,
  but belt and braces.
- `GIT_TERMINAL_PROMPT=0`, no network commands, `--no-replace-objects` (replace refs could swap
  the object a SHA resolves to), `GIT_NO_LAZY_FETCH=1` for partial clones.
- **History must be the objects' history.** Shallow clones and grafts change which parents Git
  reports for a commit — in a depth-1 clone the tip commit has "no parent", so every inherited
  file looks added by it — and the commit-graph is an unverified cache of parents. So: a
  shallow or grafted clone is refused at load (a configuration error), `core.commitGraph=false`,
  and the "did this commit touch the rule" check reads the tree and parent from the raw signed
  commit object and diffs trees, never relying on Git's view of ancestry. (Found in review of
  the first implementation: a real `git clone --depth 1` attributed a developer's unsigned rule
  to the admin who signed the next, unrelated commit.)
- Arguments are passed as an argv list, never through a shell; paths are passed after `--`.

Feasibility check (2026-09-27, Git 2.52, throwaway repo, SSH ed25519 keys): with the overrides
above, a commit signed by a key listed only in an allowed-signers file that the *repository's
own* `.git/config` points to verifies as `U` (unknown signer) — rejected — while the same
commit verifies as `G` (good) when Git is run without the overrides. An admin-signed commit
verifies as `G` with the allowed-signers principal as signer, an unsigned commit as `N`, and
`git diff-tree` / `git log -1 -- <path>` answer the "did this commit touch the rule" and "is it
still current" questions directly.
- `safe.directory` is set for the configured path only.

### 4.7 Performance

Verification happens at store load, as it does for file sources. Distinct commits are verified
once each (a store with 500 rules from one repo typically cites far fewer commits), and the
results are cached per commit SHA for the life of the process, as `CachingSourceFetcher` does
today. Expected cost: one `git verify-commit` per distinct commit plus one `git log` per rule
file for the freshness check, which can be batched into a single `git log --name-only` walk of
the tracked ref. Decision latency is unaffected.

## 5. Failure behaviour

All of the above are **per-rule quarantines**, reported in `store_health` with a reason, so one
bad citation never takes the store down; the existing `--max-quarantine-ratio` hard-fail still
applies. Configuration errors — `repos.yaml` names a path that is not a Git repository,
`signers.yaml` is unsigned or malformed, `git` is missing — are load errors (exit 65), because
they are the operator's, not an attacker's.

New quarantine reasons: `unsigned-source`, `unknown-signer`, `commit-does-not-touch-source`,
`superseded`, `unknown-repo`, `invalid-source-ref`. Existing ones (`forged`,
`principal-mismatch`, `tampered`, `unauthorized`) keep their meaning.

## 6. Threats this closes, and what remains

| Attack | v0.1 | v0.2 step 1 |
|---|---|---|
| Plant a rule in a ticket or chat and have an agent ingest it | stopped (no source backs it) | stopped |
| Holder of the shared key attributes a rule to `admin` | **succeeds** | stopped for Git sources: needs an admin's private key |
| Push an unsigned or self-signed commit adding a rule | n/a | stopped (`unsigned-source` / `unknown-signer`) |
| Cite an admin's commit that merely contains a developer's rule | n/a | stopped (`commit-does-not-touch-source`) |
| Keep using a rule after it was removed upstream | n/a | stopped once the clone is fetched (`superseded`); a stale clone is warned about |
| Forge the committer name/email | n/a | irrelevant: only the signature counts |
| Rewrite history / force-push | n/a | irrelevant for the cited commit (SHA-pinned); a force-push that drops it makes the rule `superseded` or `unknown` |
| Shallow clone, grafts or a doctored commit-graph making an unrelated signed commit look like the rule's author | n/a | stopped: shallow/grafted clones are refused, commit-graph is off, parents are read from the commit object |
| Cite `git:` in a deployment with no Git configuration, hoping it is not checked | n/a | stopped: a `git:` citation with no Git configuration is always `unknown-repo` |
| Steal an admin's signing key | — | **not stopped**: that is the new root of trust. Mitigate with hardware keys and key expiry |
| Agent runs with access to a human's SSH/GPG agent | — | **not stopped**: the agent can sign as that human. Warn when agent sockets are present (§3) |
| Edit `signers.yaml` | — | needs the operator's config-dir write access and the shared key (until step 2) |

## 7. Testing plan

Tests create real repositories in temp directories and sign with real keys generated in the
test (`ssh-keygen -t ed25519`; GPG cases skipped if `gpg` is absent), so nothing depends on the
developer's keys:

- happy path: signed commit adds `rules/x.yaml`; rule verifies; principal comes from the key.
- unsigned commit; commit signed by a key not in `signers.yaml`; key in the map under a
  different principal (→ `principal-mismatch`); expired key.
- admin's signed commit that does not touch the file while a developer's unsigned commit added
  it (→ `commit-does-not-touch-source`); signed merge commit that brings the file in (→ merger).
- later commit edits / deletes the file (→ `superseded`); clone older than the limit (→ warning).
- rule fields edited in `constraints.yaml` after ingest (→ `forged`).
- `source_ref` grammar: abbreviated SHA, branch name, `..`, absolute path, leading `-`, unknown
  repo id — all rejected before Git runs.
- hostile repo config: `.git/config` sets `gpg.ssh.allowedSignersFile` to an attacker file, a
  `core.fsmonitor` command, replace refs — none change the outcome.
- mixed store: file sources and Git sources side by side; benchmark corpus unaffected.
- performance: 500 rules across 50 commits load within a stated budget.

## 8. Decisions (agreed 2026-09-27)

1. **Merge commits: the signer of the cited commit is the principal**, including the signer of
   a merge commit (the merger vouches for what they merge). The docs must say that the key
   GitHub uses to sign merges made in its web UI (`web-flow`) must **never** be put in
   `signers.yaml`: it would make anyone who can press "Merge" on GitHub any principal.
   Rule changes are merged locally with the merger's own key, or cite the author's own signed
   commit.
2. **`signers.yaml` lives in the operator's config directory**, signed with the existing
   mechanism, until step 2. The shared key's job shrinks from "can attribute any rule to
   anyone" to "guards one list of public keys". Moving it into the policy repo with a pinned
   root key and a signed chain of changes is step 2.
3. **One rule per file.** It keeps "which commit wrote this rule" an exact Git question.
   Revisit only on demand.
4. **SSH signatures first.** GPG follows once SSH is solid; the design does not change.
   (Both shipped for v0.2.0: GPG signers are listed by primary fingerprint plus armored key,
   imported into a private keyring that must hold exactly those keys; the signature type is
   read from the commit object's `gpgsig` header.)
5. **Stale clones warn by default; an opt-in limit enforces.** Every Aegis rule restricts
   (BLOCK or ESCALATE), so a stale clone either keeps enforcing a revoked rule (the safe
   direction) or misses a newly added one (a gap the warning makes visible). Quarantining on
   staleness by default would turn a broken `git fetch` job into blocked infrastructure
   commands. Default: a store-health warning when the tracked ref's newest commit is older
   than 24 h; `--max-source-age` makes it a per-repo quarantine for teams that want it.

## 9. Rollout

- Opt-in: nothing changes unless a rule cites `git:`. File sources, the example policy and the
  benchmark corpus are untouched; the benchmark gains a separate adversarial suite for Git
  sources rather than changing its numbers.
- `aegis init` gains an example `repos.yaml` / `signers.yaml` (commented out).
- `aegis verify` learns to report Git-sourced rules' signature status, so an operator can check
  a policy repo before pointing Aegis at it.
- Docs: `docs/configuration.md` (the two new files), the threat model section above in
  `SECURITY.md`, and the README "Project status" paragraph, which today says principals are
  "a signed name rather than an identity bound to a commit signature".
