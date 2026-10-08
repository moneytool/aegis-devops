# Council review of the v0.4 design (deferred)

Three independent reviews of [`DESIGN-v0.4-public-key-signing.md`](../DESIGN-v0.4-public-key-signing.md)
(revision 3), 2026-09-29: [gpt-6-astra](astra.md) (Codex CLI, read-only, no network),
[Claude Fable 5.1](fable.md) and [Claude Opus 5.5](opus.md) (read-only, official docs). Brief:
[`brief.md`](brief.md). All three: **revise before implementing**; the cryptographic core
(SSHSIG, `find-principals` then `verify -I -n`, a pinned root, the pin outside the policy tree,
the `workflow_run` split) is sound.

**Status: deferred.** Public-key signing solves problems of multi-maintainer policy, verifiers
that must not be able to sign (CI, the Action on fork PRs, an in-cluster webhook) and
attribution. With a single maintainer and no webhook, the shared-key MAC remains the accepted
v1 boundary. Resume this before building the webhook, before the Action checks fork PRs without
a secret, or when a second maintainer or an adopting team needs attribution.

## What to change in the design before implementing (consensus)

1. **Sign the policy set, not bare files.** A signed envelope (`kind`, `path`, policy id,
   `serial`, `sha256`) and a signed policy index listing every file, its hash and expected
   signer, with a serial and an expiry. This closes deletion or omission of signed files
   (the fail-open direction for a restrict-only engine), renaming, cross-deployment replay and
   rollback (including of `signers.yaml`, which otherwise revives revoked keys). All three.
2. **No key, pin or strictness from the policy tree.** `_resolve_key` must stop discovering
   `example-signing.key` beside the constraints (a secret-free downgrade to the MAC). All three.
3. **A configured trust root implies strict everywhere** (`check` and hooks too), unless an
   explicit override; v2 files under a v1 `signers.yaml`/`authority.yaml` are refused. Opus and
   Fable (gpt-6-astra: strict for new public-key deployments).
4. **Root bootstrap defined:** parse the SSHSIG blob, hash the embedded public key, compare with
   the pin, verify against a one-line allowed_signers; a pinned root listed in `signers.yaml` is
   a load error; no `cert-authority`. All three (Fable: pin the full public key).
5. **File classes in their own `authority.yaml` section**, not mixed with rule classes; separate
   classes for `environments.yaml` and `repos.yaml` (editing them disarms others' rules).
   Opus and Fable.
6. **OpenSSH floor above 8.2:** key validity needs 8.7, find-principals fixes land in 8.9 (Opus,
   gpt-6-astra: 8.9; Fable: tiered 8.2/8.7/9.1).
7. **Verify and parse the same bytes;** do not reuse the path-keyed load cache for strict loads.
   gpt-6-astra and Opus.
8. **Local-agent limits stated:** an agent running as the developer can sign through
   `SSH_AUTH_SOCK` or rewrite a user-level pin; recommend a touch-required `sk-*` policy key and a
   root-owned pin location. Opus and Fable.
9. **`workflow_run` template:** `actions: read`, bind to `workflow_run.head_sha` (the
   `pull_requests` array is empty for forks), extract artifacts outside the workspace, never run
   PR code; apply-time enforcement needs environment-bound OIDC. All three.
10. **Attribution and migration:** define `PRINCIPALS.yaml` vs file signer, duplicate rule ids
    across `constraints.d/`, and a `migrate`/split tool with a dry-run of rules that would lose
    their vote. Opus and Fable.

Open decisions for when this resumes: strictness default (item 3), rollback scope (serial +
expiry vs expiry only), OpenSSH floor (item 6).
