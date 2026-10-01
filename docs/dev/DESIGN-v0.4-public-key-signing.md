# Design: public-key signing for policy files (v0.4)

> **Deferred (2026-09-29).** A council review ([`council-v0.4/`](council-v0.4/README.md)) asked for
> revisions before implementation, and with a single maintainer and no in-cluster verifier the
> shared-key MAC remains the accepted boundary. Resume before the Kubernetes webhook, before the
> Action checks fork PRs without a secret, or when a second maintainer needs attribution; apply
> the council's consensus changes first.

Status: **draft for review**, 2026-09-29 (revision 3: review of #24 — pin location, rule
principal binding, example keys; the Action's trust boundary on pull requests). PLAN §9 step 2; a prerequisite of the Kubernetes
webhook (DESIGN-v0.3 §3.4).

## 1. Problem

Every policy file Aegis trusts — `constraints.yaml`, `authority.yaml`, `environments.yaml`,
`plan_constraints.yaml`, `agents.yaml`, `repos.yaml`, `signers.yaml`, and the sources manifest —
is authenticated with a **shared-secret keyed BLAKE2b MAC** (`aegis_core/signing.py`). Four
consequences:

1. **Whoever can verify can forge.** A CI job, the GitHub Action, or a future webhook pod that
   checks policy holds a key that can sign any policy. DESIGN-v0.3 §3.4 makes this the blocker
   for any in-cluster verifier.
2. **No attribution.** A valid MAC says "someone with the key", not who. The authority map says
   who may assert which *rule* class, but nothing says who may change `authority.yaml`,
   `agents.yaml` or `environments.yaml`; `agents.yaml`'s `principal:` is a claim, not a proof.
3. **One key, one blast radius.** Losing it loses everything; rotating it means re-signing
   everything and redistributing a secret.
4. **The Action needs a secret** (`signing-key`) to check a plan, so a fork PR cannot run a real
   policy check, and every repo using the Action stores a forging key.

Git-sourced *rules* already avoid this: their principal is the verified signer of the commit
(v0.2.0, SSH and GPG). This design extends public-key verification to the policy files
themselves.

## 2. Goals and non-goals

Goals:

- Verifiers hold **only public keys**; nothing that verifies can sign.
- Every policy file's signature identifies a **principal**, and the authority map decides which
  principals may sign which kind of file.
- One **pinned root** anchors the key list, so the key list can live with the policy (in the
  repo) without letting whoever can merge add their own key.
- **No new mandatory dependency**; keys people already have (SSH keys, hardware-backed keys, SSH
  agents such as 1Password or a YubiKey) work.
- The shared-key MAC keeps working during migration, clearly reported as the weaker mode, and
  server-side artifacts can require public-key signatures.

Non-goals (v0.4): threshold / multi-party signing; Sigstore keyless signing (a later option for
CI-produced snapshots); per-rule signatures (rules are attributed by their sources, as today);
protecting against a compromised root key.

## 3. Decision: SSH signatures (`sshsig`)

A policy signature is an **SSH signature** (`ssh-keygen -Y sign`, the `SSHSIG` format OpenSSH
has had since 8.1) over the file bytes, in namespace `aegis-policy`. Verification uses
`ssh-keygen -Y find-principals` (who signed) and `ssh-keygen -Y verify` with an
`allowed_signers` file generated from `signers.yaml`.

Why:

- **Already a runtime requirement and already trusted code:** Git sources verify SSH commit
  signatures through the same `ssh-keygen`, the same `signers.yaml` and the same
  principal names (`aegis_core/gitsource.py`). One key per person signs both their policy
  commits and their policy files.
- **Keys people have and protect well:** `ssh-ed25519`, `sk-ssh-ed25519@openssh.com` (FIDO2
  hardware keys), keys held by an SSH agent. Aegis never needs to handle a private key file.
- **No new Python dependency** (the package depends only on PyYAML); the stdlib has no Ed25519.
- `allowed_signers` supports `valid-after` / `valid-before` per key — key expiry for free.

Alternatives considered:

| Option | Why not (for v0.4) |
|---|---|
| Raw Ed25519 via `cryptography` | A new compiled dependency for every install; a new key format and keygen for users; no hardware-key or agent story. Kept as an *optional* pure-Python verifier later, for a slim webhook image (§9). |
| minisign / signify | Another tool and key format; no link to the Git signing keys already in `signers.yaml`. |
| GPG | Supported for Git sources already, but awkward for files (keyrings, `GNUPGHOME`, agent state). May be added later behind the same interface. |
| Sigstore (keyless) | Needs network and an OIDC identity at sign and verify time; a good fit for CI-signed snapshots later, not for an offline CLI policy check. |

`ssh-keygen -Y find-principals` needs OpenSSH ≥ 8.2 (2020); Aegis checks the version and says so.

## 4. File formats

**Detached signature, v2.** `<file>.sig` keeps its name; the content is

```
aegis-sig-v2
-----BEGIN SSH SIGNATURE-----
...
-----END SSH SIGNATURE-----
```

The signed message is the file's bytes, exactly as v1. The signer is *not* written in the file;
it is found with `find-principals` and so cannot be forged by editing a field.

**Manifest, v2.** `AEGIS-MANIFEST.sig` becomes
`{"header": "aegis-manifest-v2", "files": {relpath: sha256}, "sig": "<armored SSHSIG over the
canonical files mapping>"}` — the same canonical mapping v1 MACs.

A loader recognises the header and dispatches; v1 and v2 files can coexist during migration.

## 5. Trust model

### 5.1 The pinned root

`signers.yaml` (already the key → principal list for Git sources) becomes the trust anchor for
policy signatures too. It must be signed by a **root key**, and the root key is **pinned
out-of-band** by its fingerprint:

- The pin comes **only from deployment-owned configuration, never from the policy tree**
  (review of #24): `--trust-root SHA256:…` (repeatable), `$AEGIS_TRUST_ROOT` (comma-separated),
  or a `trust-root` file in a location Aegis never reads policy from —
  `$XDG_CONFIG_HOME/aegis-trust/trust-root` (default `~/.config/aegis-trust/trust-root`) or
  `/etc/aegis-trust/trust-root`. The Action takes a `trust-root` input, set in the workflow
  file, which the main-branch ruleset and CODEOWNERS protect.
- A pin found **inside the resolved policy directory** (an `aegis.toml`, a `trust-root` file,
  anything under `.aegis/`) is a load error, not a fallback: whoever can merge a policy change
  could otherwise replace the pin with their own key, sign a new `signers.yaml` and pass. A
  deployment-owned location that happens to resolve inside the policy checkout is refused too.
- Several fingerprints may be pinned (rotation: pin new + old, re-sign `signers.yaml` with the
  new key, drop the old pin).
- The root key signs only `signers.yaml` (and `authority.yaml`, §5.2). It can live offline or on
  a hardware key; day-to-day policy changes are signed by principals' own keys.

A pin is configuration, not policy: whoever controls the operator's environment already
controls what Aegis runs. The pin is what lets `signers.yaml` move into the policy repo: a
merged change to it that the root did not sign does not verify, and the pin itself is out of
the merge's reach.

**Chain of custody (open question 2).** The v0.2 design sketched an alternative: each version
of `signers.yaml` signed by a key the *previous* version lists as an admin, anchored at a
pinned first version. That removes the need to keep a root key available, but needs the
previous version at verify time (Git history, or a stored copy) and a rollback story. This
design proposes the simpler pinned root for v0.4.0 and the chain as a later option.

### 5.2 Who may sign which file

New constraint classes in `authority.yaml` say which principals may sign which files:

| File | Class the signer needs |
|---|---|
| `signers.yaml`, `authority.yaml` | signed by a **pinned root key** (the authority map cannot authorise its own author) |
| `constraints.yaml`, `plan_constraints.yaml`, `environments.yaml` | `policy` |
| `agents.yaml` | `identity` (as today) — and the signer **must be** the file's `principal:`, which stops being a claim |
| `repos.yaml`, the sources manifest | `sources` |

A file signed by a principal without that class is refused with the reason (`signed by
sre_lead, who does not hold 'policy'`), the same way an unauthorised rule is.

### 5.3 Binding each rule's principal to a signature

A rule's `principal:` is a claim unless something authenticated says that principal asserted
it (review of #24). Signing the *file* is not enough: a signer who holds only `policy` could
write `principal: admin` on a `deletion` rule, and the authority check would read the claimed
admin. So under public-key signing a rule may vote only if its principal is **authenticated**:

- **Git-sourced rules** (`git:<repo>@<sha>:<path>`): the verified commit signer, as today
  (v0.2.0). The `principal:` in the rule must equal it.
- **Every other rule**: its `principal:` must equal the **signer of the file that carries it**
  (`constraints.yaml`, `plan_constraints.yaml`). A file signed by alice can carry only alice's
  file-sourced rules. Rules from several principals therefore come either from Git sources or
  from several files, one per principal (`constraints.d/*.yaml`, each signed by its author;
  the loader gains a directory form).
- A rule whose principal is not authenticated this way is excluded as
  `principal-unauthenticated` (reported in `aegis sources`, the snapshot's `excluded`, and the
  coverage reports), exactly like a forged or unauthorised rule. `PRINCIPALS.yaml` in a file
  sources directory can no longer attribute rules to someone other than the signer.
- Then the existing check applies unchanged: the authenticated principal must hold the rule's
  class (`deletion`, …) in `authority.yaml`.

So the file signature says who published the file (and needs the file's class, §5.2); the
authenticated principal says who asserted each rule (and needs the rule's class); a rule
cannot borrow another principal's authority.

### 5.4 What verification does, per file

1. Read `<file>.sig` (or the nearest manifest). v1 header → MAC path (§7). v2 → continue.
2. `find-principals` against `allowed_signers` built from the verified `signers.yaml` → the
   signing principal (exactly one; a key listed twice is already a load error).
3. `verify -I <principal> -n aegis-policy` → the signature is valid for these bytes.
4. The principal holds the class the file needs (§5.2) → accept, and record
   `(file, scheme=ssh, principal, key fingerprint)`.
5. For a constraints file, each rule's principal must be authenticated (§5.3) and hold the
   rule's class; otherwise that rule is excluded, and the rest of the file still loads.

`signers.yaml` itself is verified first, against the pinned root fingerprints only.

## 6. User-facing changes

- `aegis sign --ssh-key ~/.ssh/id_ed25519 FILE…` (or `--ssh-agent`), writing v2 signatures;
  `aegis sign --key …` keeps writing v1.
- `aegis verify` prints, per file, the scheme and the signer: `ok  constraints.yaml  ssh
  alice (SHA256:…)` / `ok  environments.yaml  shared-key`.
- `aegis trust init --root-key …`: writes a `signers.yaml` skeleton, signs it with the root key,
  prints the fingerprint to pin.
- `aegis snapshot` records scheme, principal and fingerprint per input, all inside the digest; a
  snapshot built from any shared-key file says so.
- `aegis compile` requires public-key signatures by default (server-side artifacts are exactly
  where a forging key must not be needed); `--allow-shared-key` overrides it, loudly.
- `aegis check` and the agent hooks accept both, warning `shared-key signature` once per
  process, unless `--require-public-key` (or `$AEGIS_REQUIRE_PUBLIC_KEY`, or a
  `require-public-key` file beside the pin in the deployment-owned location). Strictness, like
  the pin, is never read from the policy tree: a PR must not be able to switch it off.
- The Action gains `trust-root` (and reads `signers.yaml` from the policy directory); with it,
  no secret is needed, so fork PRs get a real policy check. `signing-key` stays for v1 policies.
- `aegis init` writes public-key examples: an **example** SSH key pair (clearly named, public,
  never a real key — like today's `example-signing.key`) and a `signers.yaml` signed by it, so
  the out-of-the-box demo exercises the v2 path.
- **The example keys never count as a real trust root** (review of #24). Their fingerprints are
  built into Aegis as known-public. `aegis compile`, `aegis snapshot` and `--require-public-key`
  refuse a signature by, or a pin to, an example key unless `--allow-example-keys` is given (an
  insecure-demo override that is printed on every run and recorded in the snapshot and
  manifests); `aegis verify` and `aegis check` accept it with a warning that this signer is
  public demo material, as they do for today's example MAC key.

### 6.1 The Action and untrusted pull requests

A `pull_request` workflow runs the workflow file **from the PR's merge commit** (review of #24).
A PR, including one from a fork, can therefore edit that workflow for its own run: change the
Action's `trust-root` input, drop the check, or print a green verdict under the same job name.
CODEOWNERS and the main-branch ruleset stop such an edit from being *merged*, not from being
*run*. And the PR controls more than the pin: it controls the Terraform code the plan is made
from, so it can also hand the check a harmless-looking plan. The design therefore separates an
advisory check on the PR from the enforcing one:

1. **The enforcing check runs where the PR cannot edit it: at apply time.** The pipeline that
   holds apply credentials runs on the protected branch after merge, from trusted workflow
   configuration, makes the plan itself, checks *that exact plan* with the pin from its own
   (protected) configuration and applies only if it passes (DESIGN-v0.3 §7: the apply
   credentials must exist only in that pipeline). This is the control; nothing a PR edits reaches
   it.
2. **The PR check is advisory, and runs from trusted configuration when it must be trusted.**
   For a result a maintainer relies on before merging, the Action documents the two-workflow
   pattern: the `pull_request` workflow (no secrets, read-only token) only produces the plan JSON
   as an artifact; a `workflow_run` workflow, defined on the default branch and so not editable
   by the PR, downloads it, checks out the PR's policy directory at the PR head **as data**
   (Aegis only parses YAML/JSON and verifies signatures; no PR code, script or `terraform` is
   executed in this job), verifies with the pin from its own definition or a repository
   variable, and reports the verdict. It holds only `contents: read`, `pull-requests: write` and
   `statuses: write`. `pull_request_target` is not used, because it invites checking out and
   running PR code with an elevated token.
3. **What stays out of reach.** A PR's plan artifact is produced by PR-controlled code, so even
   the trusted PR check can only say "this plan would pass", not "this is the plan that will be
   applied"; hence (1). And GitHub matches required checks by name, which a PR-edited workflow in
   the same repository can imitate. For user-owned repositories, the mitigation is to require
   approval before *any* outside contributor's workflow runs, so a modified workflow never runs
   unreviewed. For organisations, it is ruleset-required workflows, which run the default-branch
   definition. The Action's README states both, and that the PR check is advisory.

## 7. Migration and downgrade

- v1 (MAC) and v2 (SSH) signatures coexist. A directory may mix them while being migrated;
  `aegis verify` lists which files are still v1.
- **Downgrade attack:** replacing a v2 signature with a v1 MAC. It requires the shared key; with
  `--require-public-key` (and in `aegis compile` by default) it is refused outright. Once a
  deployment has migrated, dropping the shared key from its environment removes the path.
- The shared-key example key keeps working for the demo until v0.5, then the examples are v2
  only.

## 8. Threats

| Threat | v1 (MAC) | v2 (this design) |
|---|---|---|
| A verifier (CI, Action, webhook pod) is compromised | attacker can sign any policy | attacker learns public keys only |
| A principal's key is stolen | — (one shared key) | attacker can sign files of that principal's classes only, until the key is removed from `signers.yaml` (or expires via `valid-before`) |
| A merge adds a key to `signers.yaml` | needs the shared key | refused: `signers.yaml` must be root-signed |
| `agents.yaml` edited to trust an agent | needs the shared key; `principal:` is a claim | needs a key whose principal holds `identity` |
| The root key is stolen | n/a | full compromise of the key list — the root of trust; mitigate with an offline or hardware key and pinning two roots for rotation |
| Rollback to an older, validly signed file | possible | **still possible** (open question 4) |
| Downgrade to a MAC | n/a | needs the shared key; refused when public keys are required |
| A merge replaces the trust-root pin | n/a | refused: the pin is read only from deployment-owned configuration, and a pin inside the policy tree is a load error (§5.1) |
| A `policy`-only signer claims an admin as a rule's principal | possible (the principal is a claim) | the rule is excluded as `principal-unauthenticated` unless its principal is the file's signer or its Git commit's signer (§5.3) |
| A fork PR edits the workflow's `trust-root` input or the check for its own run | n/a | advisory PR check only; enforcement runs at apply time from protected configuration on the exact plan applied; a trusted PR check uses `workflow_run` and treats PR content as data (§6.1) |
| Someone signs with the public example key | accepted with a warning | `compile`, `snapshot` and `--require-public-key` refuse it without `--allow-example-keys` |

## 9. Implementation plan

1. `signing.py`: a `Verifier` interface with `MacVerifier` (today's code) and `SshVerifier`
   (`find-principals` + `verify`, reusing `gitsource`'s scrubbed-environment `ssh-keygen`
   runner); v2 detached and manifest formats; `SignatureResult(scheme, principal,
   fingerprint)` returned instead of a bool.
2. `signers.yaml` root verification and the pin, read only from `--trust-root`,
   `$AEGIS_TRUST_ROOT` or the deployment-owned `aegis-trust/trust-root` file (§5.1), with a
   load error for any pin inside the policy tree.
3. Loaders take a verifier and an authority check per file class (§5.2); `agents.yaml`
   principal must equal its signer; rule principals bound to the file or commit signer (§5.3),
   with a `constraints.d/` directory form; the pin read only from deployment-owned locations
   and refused inside the policy tree (§5.1); known example-key fingerprints (§6).
4. CLI: `sign --ssh-key/--ssh-agent`, `verify` output, `trust init`, `--require-public-key`,
   compile default; snapshot fields.
5. Examples and `aegis init` switched to v2; docs (`configuration.md` Signing section rewritten).
6. The Action: `trust-root` input, `signing-key` optional; a documented apply-time gate and
   a `workflow_run` template for a trusted PR check that treats PR content as data (§6.1).
7. Later, if the webhook image wants no OpenSSH: an optional pure-Python SSHSIG/Ed25519
   verifier (`aegis-devops[crypto]`), tested against `ssh-keygen` output.

Tests: real `ssh-keygen` keys in temp dirs (as `test_gitsource.py` does), including a FIDO-style
key type string, expired keys (`valid-before`), a key in the wrong class, a root-unsigned
`signers.yaml`, a tampered file, a v1/v2 mixed directory, a downgrade attempt under
`--require-public-key`, and the snapshot recording scheme and signer. From the review of #24: a
trust-root pin committed in the policy directory (refused), a `policy`-only signer writing
`principal: admin` on a `deletion` rule (excluded as `principal-unauthenticated`), and
`compile` refusing an example-key signature without `--allow-example-keys`.

## 10. Open questions

1. **SSH signatures vs a Python Ed25519 dependency** (§3). Proposed: SSH, with an optional
   pure-Python verifier later.
2. **Pinned root vs chain of custody** for `signers.yaml` (§5.1). Proposed: pinned root now.
3. **Default strictness in v0.4.0.** Proposed: `compile` requires public keys; `check` and the
   hooks warn. Alternative: warn everywhere until v0.5.
4. **Rollback protection.** A validly signed *older* `constraints.yaml` still verifies. Options:
   a signed `serial` field that must not decrease against a stored high-water mark; pinning the
   snapshot digest in deployments (the compilers' manifests already carry it); relying on Git
   history for policy that lives in a repo. Proposed: document the gap in v0.4.0, add the serial
   check if the council agrees it is worth the state it needs.
5. **Should the root also be able to sign ordinary policy files?** Proposed: no — keeping the
   root offline is the point.
