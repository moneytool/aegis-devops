---
title: Aegis-DevOps — guardrails for AI agents running kubectl, terraform and SQL
description: >-
  Aegis-DevOps blocks AI coding agents (Claude Code, Codex, Copilot, Cursor, Gemini CLI,
  OpenCode) from running destructive infrastructure commands such as kubectl delete,
  terraform destroy or DROP TABLE, using signed, authority-checked policy. Open source,
  Apache-2.0.
---

# Aegis-DevOps

**Stop AI agents from running `kubectl delete`, `terraform destroy` or `DROP TABLE` because a
ticket told them to.**

Aegis-DevOps is an open-source policy guardrail for AI coding agents and DevOps automation. It
checks every infrastructure command an agent wants to run — `kubectl`, `terraform`/`tofu`,
`helm`, `aws`, `gcloud`, `az`, `argocd`, `gh`, SQL — **before it runs**, and blocks or escalates
it when your policy says no. A policy rule only counts if nobody has edited it since it was
signed and its author was allowed to write that kind of rule, so a line planted in a Jira
ticket or chat message (prompt injection, context poisoning) cannot become policy.

![Aegis-DevOps blocking an injected kubectl delete](where-it-sits.gif)

## Where it runs

- **Coding agents:** a pre-tool hook for Claude Code (plugin), OpenAI Codex, GitHub Copilot
  (CLI and VS Code), Cursor, Gemini CLI (extension) and OpenCode — see [Coding agents](agents.md).
- **CI:** the [Aegis-DevOps Plan Check](https://github.com/marketplace/actions/aegis-devops-plan-check)
  GitHub Action checks a Terraform or OpenTofu plan on every pull request. See it block a pull
  request that deletes a production database in the
  [demo repository](https://github.com/moneytool/aegis-devops-demo) — fork it and try your own
  change in two minutes, no cloud account needed.
- **Server-side (preview):** the same policy compiled to AWS Service Control Policies and
  Kubernetes ValidatingAdmissionPolicies scoped to agent identities, so the cloud or cluster
  refuses the call whatever the client — see [Server-side enforcement](server-side.md).

## Try it in 60 seconds

1. **Watch it block a pull request, with nothing to install:** the demo's
   [example PR](https://github.com/moneytool/aegis-devops-demo/pull/1) deletes a production
   database and Aegis's failing check blocks it. Fork the
   [demo repository](https://github.com/moneytool/aegis-devops-demo) to try your own change.
2. **Check a command yourself:**

   ```bash
   pip install aegis-devops && aegis init .aegis
   aegis check command --pretty -- "kubectl delete namespace prod"   # BLOCK
   aegis check command --pretty -- "kubectl get pods -n prod"        # ALLOW
   ```

3. **Put it in front of your coding agent** (Claude Code shown; others in
   [Coding agents](agents.md)):

   ```bash
   claude plugin marketplace add moneytool/aegis-devops
   claude plugin install aegis-devops@aegis-devops
   ```

## Documentation

- [Coding agents](agents.md) — install and what gets blocked, per agent
- [CLI reference](cli.md) — `aegis check`, exit codes, snapshots, compile, identity audit
- [Writing constraints](constraints.md) — rules, scopes, authority, environments
- [Configuration](configuration.md) — config directory, signing, Git sources, `agents.yaml`
- [Server-side enforcement](server-side.md) — AWS SCPs and Kubernetes admission policies
- [Benchmark](benchmark.md) — Aegis against OPA and LLM self-checks on poisoned rules

## Project

- Source: [github.com/moneytool/aegis-devops](https://github.com/moneytool/aegis-devops)
- Package: [pypi.org/project/aegis-devops](https://pypi.org/project/aegis-devops/)
- Cite: [doi.org/10.5281/zenodo.22950337](https://doi.org/10.5281/zenodo.22950337)
- License: Apache-2.0
