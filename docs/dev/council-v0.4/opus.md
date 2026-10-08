# Council review: Claude Opus 5.5

Reviewed the v0.4 draft (revision 3) of `docs/dev/DESIGN-v0.4-public-key-signing.md` on
2026-09-29, read-only, with web access to official docs. Brief: [`brief.md`](brief.md). Verbatim
final answer:

## Verdict
**Revise before implementing.** The crypto core is sound: SSHSIG, a per-purpose namespace, `find-principals` followed by `verify -I -n`, and the signer left out of the file. The design still leaves three unsigned ways to weaken policy, and each one gets past the §8 threat table:
- **Rollback** of an older signed file. This includes `signers.yaml` and `authority.yaml`, so "remove the key" does not actually revoke anyone.
- **Deletion or omission** of signed files and rules.
- **Downgrade** to the MAC via the public `example-signing.key`, which `_resolve_key` still picks up from inside the policy tree.

The most important change: add a **signed, versioned policy index** (the set of files, their hashes, their expected signers, a monotonic `serial` and an `expires`) that the verifier checks against a deployment-owned minimum. Separately, make **"a trust root is configured" imply "public keys required" and "no key discovery from the policy tree"**.

## Findings

1. **[P0] Downgrade needs no secret: the example MAC key is auto-discovered from the policy tree** — §7, §5.1; `cli.py:_resolve_key`
   - **What is wrong:** with no `--key` and no `$AEGIS_SIGNING_KEY`, `_resolve_key` loads `<dir of --constraints>/example-signing.key` and only warns. That key is public. Someone who can merge adds that file, deletes the v2 `.sig` files and writes v1 MACs with the example key. `check` and the hooks accept v1 "with a warning". §7 says a downgrade "requires the shared key" and that "dropping the shared key from its environment removes the path"; both are false.
   - **Why it matters:** this is the same bug class the pin section fixes (a trust input read from the policy tree), and it leaves a path around every other v2 control.
   - **Fix:** never resolve any key, pin or strictness setting from the policy directory. When a trust root is configured, refuse v1 outright in every command (see Q3), and make the example MAC key an explicit `--key` opt-in only.

2. **[P0] Rollback defeats key revocation and authority changes, not just constraints** — §5.1, §8 rows "principal's key is stolen" and "rollback"
   - **What is wrong:** a root-signed `signers.yaml` has no serial and no expiry, so every version the root ever signed verifies forever.
   - **Attack:** someone who can merge reverts `signers.yaml`, `signers.yaml.sig` and `authority.yaml` to a version that still lists the stolen or departed key, then adds files signed by that key.
   - **Why it matters:** the §8 mitigation "until the key is removed from `signers.yaml`" does not hold against the exact attacker §5.1 targets ("whoever can merge"). It also contradicts DESIGN-v0.3 §8/§9, which lists rollback protection for the webhook, and v0.4 is that webhook's prerequisite.
   - **Fix:** root-signed files must carry a signed `serial` and `expires` (Aegis refuses them after `expires`). Deployment configuration may pin `min-serial` next to the pin, and the snapshot records the serial. `expires` alone needs no state and bounds the replay window.

3. **[P0/P1] Deleting or omitting signed content needs no signature, and `policy` can remove higher-class rules** — §5.2, §5.3
   - **What is wrong:** with `constraints.d/*.yaml`, removing `alice.yaml` (her prod `deletion` guard) is an unsigned merge. Likewise, whoever signs `constraints.yaml` chooses which `git:` citations exist, so a `policy`-only signer silently drops an admin's Git-sourced `deletion` rule. Optional files (`plan_constraints.yaml`, `environments.yaml`) are just skipped when absent (`_resolve_config_paths`).
   - **Why it matters:** "a rule cannot borrow another principal's authority" covers adding a vote, not removing one. In a guardrail system, removal is the attack.
   - **Fix:** the signed index lists every required file with its expected signer and hash. A missing listed file is a load error. Removing a rule of class X from the index needs a signer holding X, or the index lives in root-signed `authority.yaml`. Git-sourced rules could instead be enumerated from `rule_glob` on the tracked ref rather than by citation.

4. **[P1] `environments.yaml` and `agents.yaml` edits disarm other principals' rules** — §5.2
   - **What is wrong:** `environments.yaml` needs only `policy`, yet it decides which cluster, context or account is `prod`. Re-labelling prod as dev neuters every admin rule scoped to `env: prod`. `agents.yaml` (`identity`) can move an agent identity to trusted or break-glass and so bypass every compiled rule.
   - **Why it matters:** this is authority by indirection, a confused-deputy path.
   - **Fix:** give `environments.yaml` its own class (or root), and document that `identity` is effectively admin. Optionally require the signer to hold every rule class whose scope the change alters.

5. **[P1] Pin configured but v1 files still accepted** — §5.4 step 1, §6, §7
   - **What is wrong:** the spec dispatches on the header per file. It never says a v1 `signers.yaml` or `authority.yaml` is refused once a pin exists, nor what a v1 constraints file means under §5.3: its principals are claims, so it reopens the "`policy` signer writes `principal: admin`" hole. During migration every verifier (CI, the Action's `signing-key`) still holds the forging MAC key, which is the problem §1 exists to fix.
   - **Fix:**
     - A pin makes the verifier strict for all files.
     - A mixed directory is allowed only when no pin is set.
     - With a pin, `signers.yaml` and `authority.yaml` must be v2 root-signed, with no exceptions.
     - v1 rules never get "authenticated principal" status.

6. **[P1] How the root key is obtained from a fingerprint pin is unspecified** — §5.1, §5.4
   - **What is wrong:** a pin is `SHA256:…`, but `verify` needs the public key in an `allowed_signers` file. `find-principals` cannot help here, because no allowed_signers file holds the root yet.
   - **Fix:**
     1. Parse the armored SSHSIG blob. Its fields are MAGIC, version, publickey, namespace, reserved, hashalg, signature.
     2. Compute `SHA256(publickey blob)`, base64 without padding (the same fingerprint `ssh-keygen -lf` prints), and compare it with the pins.
     3. Write a one-line allowed_signers file: `aegis-root namespaces="aegis-policy" <key>`.
     4. Run `verify -I aegis-root`.
   - Also: refuse a `signers.yaml` that lists a pinned root key under any principal (this enforces Q5). Record the root fingerprint as the "principal" for the root-signed files.

7. **[P1] OpenSSH version floor is too low** — §3 ("≥ 8.2"). Facts, high confidence:
   - `-Y sign/verify` appeared in 8.1 and `find-principals` in 8.2.
   - `valid-after` / `valid-before` in allowed_signers appeared in **8.7**.
   - 8.9 fixed several `find-principals` bugs:
     - it checked lifetimes only for CA certs, not plain keys;
     - a NULL dereference on lines with a `namespaces=` restriction, which is exactly the line format Aegis generates;
     - wildcard principal matching.
   - How pre-8.7 versions treat an unknown `valid-before` option (whole line rejected vs. option ignored) is (UNSURE); either is wrong for a design that counts on key expiry.
   - **Fix:** require **≥ 8.9**, checked with `ssh -V` / a probe. Ubuntu 20.04 ships 8.2; GitHub's ubuntu-22.04 image has 8.9 and 24.04 has 9.6.

8. **[P1] Say plainly what `find-principals` proves: nothing** — §5.4
   - **What is right:** the order (find-principals, then `verify -I <p> -n aegis-policy`). The man page confirms `find-principals` only looks up the signature's embedded public key; it checks neither signature validity nor namespace.
   - **Must be explicit:**
     - Only `verify`'s exit status counts.
     - The same allowed_signers file is used for both calls.
     - The message is passed on stdin from the **same byte buffer the loader then parses**. Today loaders call `check_signature(path)` and re-read the path, a TOCTOU that v2 should close; same for manifest `sha256` then re-read.
     - More than one returned principal is an error.
     - Deduplicate keys by decoded blob or fingerprint, not by base64 string. `_SSH_KEY_RE` accepts any base64, and a non-canonical encoding could list one key twice (UNSURE whether ssh-keygen normalises it).
     - Generated lines must carry `namespaces="aegis-policy"`, separate from the `"git"` lines in `gitsource.py`. Namespace separation is already cryptographic (the namespace is inside the signed data), which is right.
     - Keep the principal regex free of `*?,!`, because allowed_signers principals are pattern-lists; add a test.
     - Reject `cert-authority` in v0.4.

9. **[P1] The gated AI agent can sign policy with the developer's key** — §3 ("one key per person signs both … commits and … files"), §8
   - **What is wrong:** agents run on the developer's machine with `SSH_AUTH_SOCK` (1Password, a software key in ssh-agent). The agent can run `ssh-keygen -Y sign -n aegis-policy` (or do it from Python, so the hook cannot see it) and sign `constraints.d/<dev>.yaml` or `agents.yaml` as the developer. `gitsource.py` already warns about this for commits; v0.4 makes it a policy-signing path.
   - **Fix:**
     - Recommend a **separate policy-signing key** that requires touch (`sk-*`, never `no-touch-required`; optionally `verify-required`).
     - Let `signers.yaml` restrict the `identity`, `sources` and root roles to `sk-*` keys under `--require-public-key`.
     - Warn in hooks when `SSH_AUTH_SOCK` is set and a signer key for this user is a software key.
     - Add a §8 row for this.

10. **[P1] The Action's apply-time gate depends on credential scoping the spec does not state** — §6.1(1)
    - **What is wrong:** "apply credentials exist only in that pipeline" is false by default with GitHub OIDC. A same-repo branch PR can edit its workflow to add `id-token: write` and assume the cloud role if the trust policy accepts `repo:org/repo:*`. Fork PRs cannot get an OIDC token (high confidence), but insiders with push access can.
    - **Also:** the apply-time check verifies the *merged* policy directory, so a PR that changes Terraform plus a rollback or deletion of policy (findings 2 and 3) passes the enforcing check.
    - **Fix:**
      - Require an environment-bound OIDC subject (`repo:o/r:environment:prod`), and restrict that environment's deployment branches to `main` (optionally with required reviewers).
      - State that policy for the enforcing gate should come from a separately protected ref or repo, or be checked against the index's `min-serial`.
      - `--require-public-key` is implied (finding 5).

11. **[P1] The `workflow_run` template is missing a permission and has poisoning traps** — §6.1(2)
    - **Missing permission (high confidence):** downloading an artifact from another run needs **`actions: read`**; `contents: read` is not enough.
    - **Empty PR list (high confidence):** `github.event.workflow_run.pull_requests` is empty for fork PRs. Use `workflow_run.head_sha` and `head_repository`, check out exactly that SHA (not the branch name, which can move), and post the status on that SHA.
    - **Artifact poisoning:**
      - Extract the artifact into a temp directory outside `$GITHUB_WORKSPACE`.
      - Check out the PR tree to a separate path with `persist-credentials: false`.
      - Never `uses: ./…` or `pip install` from the PR checkout; pin the Action by SHA and Aegis by version and hash.
      - The trigger is matched by workflow *name*, so any PR workflow with that name can feed it an artifact. That is acceptable only because the artifact is treated as untrusted anyway.
    - **PR-controlled `repos.yaml`:** it names local `path:`s. Refuse Git sources in the PR-check mode, or allow only paths the trusted job cloned itself.

12. **[P1] Behaviour with no pin, and in `aegis init`, is undefined** — §5.1, §6
    - **What is wrong:** v2 files with no pin configured: fail closed? Treat as unsigned? Where does `aegis init` write the example pin? Not the policy directory, which is refused. Writing to `~/.config/aegis-trust` affects every project.
    - **Fix:**
      - No pin plus any v2 file → "unsigned" (exit 65 unless `--insecure`).
      - `init` prints the example pin and suggests `--trust-root` / `$AEGIS_TRUST_ROOT` for the demo, writing nothing global without a flag.

13. **[P2] A user-writable pin location offers no protection against a same-user agent** — §5.1
    - **What is wrong:** `~/.config/aegis-trust/trust-root` (and the `require-public-key` file beside it) can be rewritten by the gated agent: it repins its own root and signs everything.
    - **Fix:** prefer `/etc/aegis-trust` (root-owned), and under strict mode check owner and mode (not writable by the current uid). The §8 table should state that a same-user agent can edit hook config and a user-level pin.

14. **[P2] `valid-before` expires files, not just keys** — §3 ("key expiry for free")
    - **What is wrong:** SSHSIG carries no trusted signing time, so `verify` evaluates validity at *now* (or at `-O verify-time`, which here would be signer-chosen). When a key expires, every file it ever signed stops verifying.
    - **Why it matters:** that is useful as a freshness bound, but every verifier fails closed together.
    - **Fix:** document it; `aegis verify` should warn N days before expiry. Never pass a verify time taken from file content.

15. **[P2] Detached signatures do not bind a file's role or path** — §4
    - **What is wrong:** a `policy` signer's `environments.yaml` signature is valid for the bytes under any name, and in any deployment that trusts that signer (staging → prod reuse, cross-repo copy).
    - **Fix:** use per-role namespaces (`aegis-policy:constraints`, `…:environments`, `…:agents`, `…:signers`), or sign `role\0relpath\0bytes`. The v2 manifest signature must cover the header too, not only the `files` mapping. Limit the nearest-manifest search to the policy root; today it walks up to `/`.

16. **[P2] Duplicate rule ids across `constraints.d/`** — §5.3
    - **What is wrong:** bob's file can reuse alice's rule id and shadow or collide with her rule.
    - **Fix:** make a duplicate id across files a load error, or exclude both, and report it.

17. **[P2] `PRINCIPALS.yaml` wording is ambiguous** — §5.3
    - "Can no longer attribute rules to someone other than the signer": the signer of the constraints file, or of the sources manifest (`sources` class)? Specify it. `principal-mismatch` should compare against the constraints-file signer.

18. **[P2] Migration breaks every existing multi-principal `constraints.yaml`** — §5.3, §7
    - **What is wrong:** under v2, every rule whose principal is not the signer becomes `principal-unauthenticated`. That trips `--max-quarantine-ratio`, so the CLI refuses to decide.
    - **Fix:** add a `aegis migrate` / `sign --split` that writes `constraints.d/<principal>.yaml`, plus a dry-run report of which rules would lose their vote.

19. **[P2] File classes share a namespace with rule classes** — §5.2
    - **What is wrong:** `policy`, `identity` and `sources` are ordinary strings in the same map as `deletion` etc. An existing rule class named `policy` would silently grant file-signing rights.
    - **Fix:** use a separate `files:` section in `authority.yaml` or a `file:` prefix.

20. **[P2] Hook latency** — §9
    - **What is wrong:** each hook invocation runs two `ssh-keygen` forks per file, and `constraints.d` multiplies the file count.
    - **Fix:** cache verification results keyed by (sha256 of the bytes, sig bytes, allowed_signers digest, validity window), and invalidate on any change.

21. **[P3] UX details**
    - `--ssh-agent` needs a public key to choose which agent key signs (`ssh-keygen -Y sign -f key.pub` uses the agent).
    - `aegis sign` should pre-check that the key's principal holds the file's class and that every rule's principal equals the signer.
    - RSA must be `rsa-sha2-512` (ssh-keygen's default for SSHSIG); consider a minimum of 3072 bits.
    - The snapshot should record pin fingerprints, the `signers.yaml` serial, and the strict / `allow-example-keys` flags inside the digest.

**What the spec gets right (high confidence):**
- The SSHSIG and `aegis-policy` namespace choice.
- Not storing the signer in the file.
- The find-principals → `verify -I -n` sequence.
- The pin read only from deployment-owned config, and refused inside the policy tree.
- `pull_request` running the workflow from the PR merge commit.
- `workflow_run` using the default-branch definition.
- Avoiding `pull_request_target`.
- Required checks being matchable by name from a PR-edited same-repo workflow (both appear as the GitHub Actions app).
- The fork-approval setting ("require approval for all outside collaborators") is real, but it does **not** cover same-repo branches from people with write access; the spec should say so.
- Org ruleset "require workflows to pass" availability by plan is (UNSURE).

## Open questions (§10)
1. **SSH vs Python Ed25519:** SSH, with a minimum of OpenSSH 8.9. Reason: it reuses `gitsource`'s already-hardened runner and hardware/agent keys; an optional pure-Python verifier later suits the webhook image.
2. **Pinned root vs chain of custody:** pinned root, **plus** a signed `serial` and `expires` on root-signed files. Reason: without them the pinned root cannot revoke anything (finding 2), and a chain-of-custody design needs the same serial anyway.
3. **Default strictness:** agree that `compile` refuses shared keys. But **a configured trust root must make `check` and the hooks strict too**, and example-key discovery from the policy directory must go. Reason: "warn" in a pinned deployment keeps the MAC forging path, and the public example key makes it secret-free (finding 1).
4. **Rollback:** disagree with "document only". Add `expires` (stateless) now for `signers.yaml`, `authority.yaml` and the policy index, and a signed `serial` with an optional deployment `min-serial`. Reason: rollback currently undoes revocation, and DESIGN-v0.3 promises rollback protection for the webhook this release unblocks.
5. **Root signs ordinary files:** no. Also enforce it: refuse a `signers.yaml` that lists a pinned key under any principal. Reason: this keeps the root offline, and it cannot vote as a principal.

## Missing from the spec
- A signed policy index / manifest of the policy **set**: required files, expected signers, hashes, serial, expiry. This covers deletion, omission, mix-and-match and rollback.
- How the root public key is obtained from the SSHSIG blob and matched against the pin.
- A statement that a pin implies strict (no v1, no example MAC key, no key discovery from the policy tree).
- The no-pin behaviour, and the `aegis init` demo pin flow.
- The exact `allowed_signers` line format:
  - which `signers.yaml` options pass through (`valid-after`, `valid-before`, `verify-required`);
  - `cert-authority` refused;
  - `namespaces` set per purpose.
- The minimum OpenSSH version (8.9) and how it is probed.
- Verifying and parsing the same byte buffer (TOCTOU).
- Threat rows for:
  - an agent on the workstation signing through `SSH_AUTH_SOCK`;
  - a same-user agent rewriting a user-level pin;
  - OIDC role assumption by a PR-edited workflow;
  - policy weakening via `environments.yaml`.
- The `workflow_run` template details: `actions: read`, `head_sha` pinning, the empty `pull_requests` array for forks, artifact extraction outside the workspace, no `repos.yaml` Git paths from PR data.
- Duplicate rule ids across `constraints.d`, and a separate namespace for file classes vs rule classes.
- Migration tooling (split `constraints.yaml` by principal) and a dry-run impact report.
- Tests to add:
  - rollback of `signers.yaml` after key removal;
  - deleting a `constraints.d` file;
  - dropping a git citation;
  - a v1 file with `example-signing.key` placed in the policy directory while a pin is set;
  - a root key listed as a principal;
  - a non-canonical duplicate key;
  - ssh-keygen older than 8.9;
  - a namespace-mismatch signature (for example, a Git commit signature presented as a policy signature);
  - a file expiring via `valid-before`.

Sources: [OpenSSH 8.2 release notes](https://www.openssh.org/txt/release-8.2), [OpenSSH 8.7 release notes](https://www.openssh.org/txt/release-8.7), [OpenSSH 8.9 release notes](https://www.openssh.org/txt/release-8.9), [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen).
