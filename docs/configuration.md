# Configuration

Config directory discovery, signing, source verification, and rate limits/ledger.

← back to the [README](../README.md)

## Configuration

Running `aegis` from the repo checkout with no flags "just works" because `$PWD/data` already
has `constraints.example.yaml` — but installed as a wheel there is no `data/` next to the
interpreter. `--constraints`/`--authority`/`--environments`/`--plan-constraints` each default to
`None` and are resolved from a **config directory**, searched in this order, first match wins:

1. `--config-dir DIR` (explicit)
2. `$AEGIS_CONFIG_DIR`
3. `$PWD/.aegis`
4. `$PWD/data` — **only** if it already contains a `constraints*.yaml` (this is what keeps a
   repo checkout working with no setup)
5. `~/.config/aegis`
6. `/etc/aegis`

Inside that directory, a real file wins over its `.example` counterpart when both exist
(`constraints.yaml` over `constraints.example.yaml`, and likewise for `authority`/
`environments`/`plan_constraints`); `sources/` and `example-signing.key` next to the constraints
file are picked up the same way they always were. Any of `--constraints`/`--authority`/etc.
passed explicitly is used as-is and skips discovery for that one file. When none of the above
finds a directory *and* `--constraints`/`--authority` were never given either, the CLI refuses
cleanly instead of tracebacking on a relative path that doesn't exist from the current
directory:

```
$ cd /tmp && aegis check kubectl -- kubectl get pods
aegis: error: no config found (searched: /tmp/.aegis, /Users/you/.config/aegis, /etc/aegis); run 'aegis init <dir>'
```

`aegis init <dir>` seeds a fresh directory with the packaged example policy files (the same
`*.example.yaml` + `.sig` + `sources/` the repo ships in `data/`, embedded in the wheel under
`aegis_core._examples/` — see `../scripts/sync_package_examples.py`, which keeps that copy in sync
with `data/` and is checked by `tests/test_config.py`) and prints next steps:

```
$ aegis init ~/.config/aegis
aegis: wrote 38 file(s) to /Users/you/.config/aegis
Next steps:
  1. Generate a real signing key:  aegis keygen --out ~/.config/aegis/aegis-signing.key
  2. Sign your policy files:       aegis sign --key file:~/.config/aegis/aegis-signing.key ~/.config/aegis/*.yaml ~/.config/aegis/sources
  3. Replace the *.example.yaml files in ~/.config/aegis with your own constraints.yaml / authority.yaml / ... (aegis prefers a real file over the .example one when both exist)
```

`aegis keygen [--out FILE]` (default `aegis-signing.key`) writes 32 random bytes, hex-encoded,
mode `0600` — a real key, distinct from the public `example-signing.key` that `init` copies in
verbatim. Once you've edited the example files into real ones and signed them with your own key,
either export `AEGIS_SIGNING_KEY` or keep using `--key file:...`; the example-key fallback only
ever fires when `example-signing.key` is the *only* key next to `--constraints`.

Other env vars: `$AEGIS_SIGNING_KEY` (see "Signing" below). There is currently no env var for
`--now`, `--ledger`, or the output flags — those stay CLI-only so a shell alias can't silently
change what gets decided.

## Signing

Every policy file — constraints, plan constraints, authority map, environment map, source
snapshots and `PRINCIPALS.yaml` — must verify under a keyed BLAKE2b MAC before the CLI will
decide with it. Single files carry a detached `<file>.sig`; a directory of sources carries one
`AEGIS-MANIFEST.sig` (a JSON manifest of `{relpath: sha256}` plus the MAC of that mapping), so
hundreds of snapshots are one signature. A file with a detached `.sig` is checked against it;
otherwise the nearest manifest above it must list it with a matching hash.

```bash
aegis sign   --key file:aegis-signing.key data/constraints.yaml data/sources   # .sig + manifest
aegis verify --key env:AEGIS_SIGNING_KEY  data/constraints.yaml data/sources
```

**`aegis verify` scope on a directory.** `sign` on a directory covers everything under it (every
`.yaml`/`.json`, recursively) — that's a deliberate "sign the whole tree" operation for a
directory you've pointed it at on purpose, e.g. `data/sources`. `verify` on a directory is
narrower on purpose: it only checks files that were *actually signed* — one with its own
`<file>.sig`, or one listed in an `AEGIS-MANIFEST.sig` found at or below that directory — never
every `.yaml`/`.json` it happens to find. A policy directory can legitimately hold unrelated,
unsigned content next to real policy files — `data/corpus/seeds.yaml`, `split.json` and
`stats.json` are corpus-generation artifacts no Aegis loader ever reads — and `aegis verify
data/corpus` must not report those as `FAILED` just because of their extension. Passing a file
directly (not discovered via a directory walk) is unaffected: it is always checked, signed or
not, so a real gap still surfaces as `FAILED` on the file itself or by naming the directory that
has — or should have — a manifest covering it.

The key is resolved from `--key SOURCE` (`env:VAR`, `file:PATH`, or raw hex), then
`$AEGIS_SIGNING_KEY`, then `<dir of --constraints>/example-signing.key` if it exists — with the
store warning `using example signing key`, because **`data/example-signing.key` is public and
demo-only**: it is committed so the shipped examples and corpus verify out of the box, and
anyone holding it can forge those files. Generate your own (`python -c 'import secrets;
print(secrets.token_hex(32))'`), re-sign, and keep it out of the agent's reach. With no key at
all the CLI exits 65 (`no signing key: pass --key, set AEGIS_SIGNING_KEY, or --insecure`);
`--insecure` loads everything unverified and says so in every `store_health.warnings`. This is a
MAC, not a public-key signature: whoever can sign can verify, which is the v1 boundary — Aegis
defends against poisoned *content* from sources you chose to trust, not against an attacker
who holds the signing key.

## Source verification

`--sources DIR` points at a directory of `<source_ref>.json` files plus a `PRINCIPALS.yaml`
that says which principal the *transport* attributes each source to. It defaults to the
`sources/` directory next to the constraints file when one exists (`--sources ''` opts out), so
with the shipped layout forgery is detected without any flag. A constraint whose cited source
doesn't back it (missing file, or different content) is quarantined as `forged` at load time; one
whose transport principal differs from the principal it claims is quarantined as
`principal-mismatch`. Either way it gets no vote, like any other quarantine (see
[Store health](cli.md#store-health)).

`FileSourceFetcher` is a v1 stand-in for real Git/Slack/Jira connectors — it re-reads a flat
JSON file rather than calling out to a commit, a permalink, or a ticket API (see "Open gaps" in
`dev/PLAN.md`).

`data/sources-forged/` is `data/sources/` with `jira-1001.json`'s `rule_text` edited after the
fact (still validly signed — signing proves the *file* wasn't touched in transit, not that its
*content* still matches what a constraint cites) so `--sources` has something real to catch:

```bash
aegis check kubectl --now 2026-03-16T10:00:00-05:00 --pretty --sources data/sources-forged -- \
    kubectl scale deployment/api-server --replicas=5 -n prod
```

```
aegis: WARNING Quarantined constraint no-scale-prod-peak: source does not back its claimed fields
ALLOW: kubernetes scale deployment/api-server
  discarded: [{'id': 'no-scale-prod-peak', 'reason': 'forged'}]
  covered: True  latency_ms: 0.14
PLAN ALLOW: 1 intent(s)
STORE: loaded=20 quarantined=1 principals=3
  quarantined: no-scale-prod-peak (forged)
  warning: using example signing key
  warning: Quarantined constraint no-scale-prod-peak: source does not back its claimed fields
```

The same `kubectl scale ...` command against the real `data/sources` (the CLI's default) is a
plain `BLOCK` — see the [README](../README.md)'s Quick start. Forging the source turns a
legitimate rule into one with no vote, which is loud rather than quiet: the action is
allowed on the strength of the rules that remain, and the forged one is named in
`discarded` and in the store's health. Add `--on-untrusted-match escalate` to make it
`ESCALATE` instead.

## Git sources (signed commits)

A constraint can cite a rule file at a specific commit in a policy repository instead of a
`sources/<ref>.json` file:

```yaml
source_ref: "git:platform-policy@3f1c9e0d2b7a4c6e8f0a1b2c3d4e5f60718293a4:rules/no-delete-nodes.yaml"
```

The rule's **principal is then the verified signer of that commit**, not a name written in the
rule or in `PRINCIPALS.yaml`. Two files in the config directory (next to the constraints file,
or `--repos` / `--signers`) turn this on:

```yaml
# repos.yaml — local clones; Aegis never fetches (keep them fresh with your own `git fetch`)
repos:
  platform-policy:
    path: /srv/aegis/platform-policy
    ref: refs/remotes/origin/main      # the ref that defines "current"
    rule_glob: rules/*.yaml            # optional; one rule per file
```

```yaml
# signers.yaml — which SSH signing key speaks for which principal (authority.yaml names)
signers:
  - principal: admin
    keys:
      - type: ssh
        key: "ssh-ed25519 AAAAC3Nza... alice@example.com"
```

Both are policy files and are signed like the others. A rule file holds the same fields as a
`sources/<ref>.json` payload, minus `principal` and `source_ref`.

A git-sourced constraint is quarantined, with the reason in `store_health`, when the reference
is malformed (`invalid-source-ref`), names an unconfigured repo (`unknown-repo`) or a commit the
clone lacks (`unknown-commit`), the commit is unsigned (`unsigned-source`) or signed by a key
`signers.yaml` does not list (`unknown-signer`), the commit did not add or change the rule's
file (`commit-does-not-touch-source`), or the file on the tracked ref no longer matches the
cited version (`superseded`, which is how a rule is revoked). The usual `forged` and
`principal-mismatch` checks apply on top. A merge commit's signer counts as the principal for
the files it brings in.

Git runs with an environment built from scratch and with overrides for every signature
setting, so a repository's own `.git/config` cannot choose which keys are trusted. The store
warns when a clone's tracked ref has no commit newer than 24 hours (revocations upstream are
not visible until you fetch); `--max-source-age HOURS` quarantines that repository's rules
instead.

Two operational rules matter more than any of the above:

- **Never list GitHub's `web-flow` key** (the key GitHub uses to sign merges made in its web UI)
  in `signers.yaml`. It would make anyone who can press "Merge" on GitHub any principal. Merge
  rule changes locally with your own key, or cite the author's signed commit.
- **The agent must not be able to use a human's signing key.** If the agent this gates can
  reach an SSH or GPG agent holding a listed key (a forwarded `SSH_AUTH_SOCK`, an unlocked
  `gpg-agent`), it can sign as that principal. The store warns when either is set.

Only SSH signatures are supported so far; GPG is planned. Design and threat model:
[`dev/DESIGN-v0.2-git-sources.md`](dev/DESIGN-v0.2-git-sources.md).

## Rate limits & ledger

`--ledger PATH` enables `rate_limit` constraints and records every executed (`ALLOW`,
non-dry-run) decision, bucketed by the constraint's `key` metadata fields within its `per`
window. A `.jsonl` path gives an append-only JSON-lines ledger; `.db`/`.sqlite`/`.sqlite3` gives
a SQLite one. Both serialise load → count → record across processes (an `flock` on a sidecar
`.lock` file, or `BEGIN IMMEDIATE`), so sixteen racing agents against `max: 3` get exactly three
ALLOWs; both hash-chain their records, and a truncated or hand-edited ledger surfaces as the
store warning `ledger: chain-broken` and makes every rate-limited rule ESCALATE rather than
count from zero. Records older than the largest `per` window in the store (at least 24h) are
pruned on load, so a ledger never grows without bound; malformed lines are skipped and counted.
A `rate_limit.key` naming a field no parser emits is reported in `store_health.warnings` at load
instead of silently bucketing nothing (`resource` is allowed, to bucket per concrete target).

```bash
aegis check kubectl --ledger results/ledger.db --pretty -- \
    kubectl get service/frontend -n prod
```
