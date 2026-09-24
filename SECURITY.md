# Security policy

## Status

Aegis is **alpha** (v0.1.x) and is not production-ready. Read the gaps in
[`PLAN.md` §8](PLAN.md) before deploying it in front of anything you care about.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/moneytool/aegis-devops/security/advisories/new).
Please do not open a public issue for a bypass.

Include the constraint file, the exact invocation, the verdict you got and the verdict you
expected. A failing test against `data/constraints.example.yaml` is the most useful form.

## What counts as a vulnerability

Aegis's job is to decide correctly about an action given a set of constraints. Anything that
makes it decide **wrongly** is in scope, in rough order of severity:

- **Parser evasion** — an invocation that a reasonable rule author would expect to be caught,
  which parses to an intent that does not match their rule. This is the largest attack surface
  and historically where the real bugs have been: `kubectl -n prod delete …` and `git -C dir
  push -f` once parsed to garbage and returned ALLOW. New forms are welcome as bug reports.
- **Integrity or authority bypass** — a constraint that is tampered, forged, or asserted by an
  unauthorized principal, yet still drives a verdict.
- **Signature bypass** — a modified policy file, source file, or manifest that still verifies.
- **Path traversal or injection** through a constraint-author-controlled field (`source_ref`,
  `resource_pattern`, shell strings passed to `aegis check command`).
- **Fail-open error paths** — any input that makes the CLI exit 0 on an action that should have
  been BLOCKed, rather than exiting non-zero.

## What does not count

These are documented limitations, not vulnerabilities. They are listed in `PLAN.md` §8 and
named in the README's "Project status" section:

- The source fetcher reads files on disk rather than connecting to Git, Slack or Jira. Anyone
  who can write to the sources directory can author policy.
- Signing uses a shared secret (keyed BLAKE2b), not per-principal public keys. Anyone with the
  key can sign anything.
- A `principal` is a signed name, not an identity bound to a commit signature or SSO group.
- `data/example-signing.key` is public by design, for the demo policy files. Using it for real
  policy is a misconfiguration, which the CLI warns about on every run.
- Resource matching is case-sensitive on names.
- Aegis does not sandbox anything. It returns a verdict; enforcing it is the caller's job, and
  an agent that ignores a non-zero exit code is not something Aegis can prevent.
