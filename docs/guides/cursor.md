# Stop Cursor's agent from running terraform destroy, kubectl delete or DROP TABLE

Cursor's agent runs terminal commands on its own in agent mode. Its command allow list works by command name, so allowing `kubectl` so the agent can read cluster state also allows `kubectl delete`. Cursor's `beforeShellExecution` hook sees every command before it runs and can deny it with a message to both you and the agent.

[Aegis-DevOps](https://github.com/moneytool/aegis-devops#readme) is that hook. It checks each command against your policy before it runs and blocks what the policy forbids, with the reason shown to the model. It's open source (Apache-2.0) and decides in under a millisecond.

## Install

```bash
pip install aegis-devops
aegis init .aegis                 # opt this project in, with the example policy
aegis install cursor              # this project: .cursor/hooks.json
# or: aegis install cursor --user # every project: ~/.cursor/hooks.json
```

Restart Cursor after installing. The hook entry sets `failClosed: true`, so a crashed or timed-out hook blocks the command instead of letting it run.

## What happens

Ask the agent to run `terraform destroy`, `kubectl delete namespace prod` or `psql -c 'DROP TABLE users'` in the project. Cursor refuses the command and shows both you and the agent:

```
aegis: BLOCK: block-namespace-delete, no-delete-in-prod-namespace, plan-k8s-delete-ratio
```

`kubectl get pods` and other commands the policy has no rule against run as normal. An ESCALATE verdict becomes Cursor's "ask", so you approve or refuse it yourself.

## What the example policy blocks

`aegis init` writes an example policy. Besides its demo rules it blocks `terraform destroy` / `tofu destroy`, `pulumi destroy`, deleting a Kubernetes namespace or node, an S3 bucket, an RDS database, a GCP project or an Azure resource group, dropping a database or deleting every row of a table, force-pushing `main`, deleting Helm releases in production, and `kubectl --as` impersonation. Deleting an Argo CD application asks first.

Everything else runs as usual: `kubectl get pods`, `terraform plan`, `ls`, `npm test`. Aegis only acts in projects that opted in (a `.aegis/` directory in the project or a parent, `$AEGIS_CONFIG_DIR`, or `~/.config/aegis`), so installing the hook changes nothing in your other projects.

## Check a command without the agent

```
$ aegis check command --pretty -- "terraform destroy -auto-approve"
BLOCK: terraform delete workspace/current
  citations: block-terraform-destroy
  covered: True  latency_ms: 0.1449
PLAN BLOCK: 1 intent(s)
STORE: loaded=30 quarantined=0 principals=3
  warning: using example signing key

$ aegis check command --pretty -- "kubectl get pods -n prod"
ALLOW: kubernetes get pod/*
  covered: False  latency_ms: 0.0086
PLAN ALLOW: 1 intent(s)
STORE: loaded=30 quarantined=0 principals=3
  warning: using example signing key
```

Aegis reads the command the way the tool would: `kubectl -n prod delete ns app`, `sudo kubectl ...` and `cd infra && terraform destroy` all resolve to the same action as the plain form.

## Write your own rule

Rules live in `.aegis/constraints*.yaml`. This is the rule behind the `terraform destroy` block:

```yaml
- id: block-terraform-destroy
  provider: terraform
  resource_pattern: workspace/*
  actions: [delete]
  effect: BLOCK
  constraint_class: deletion
  principal: admin
  rule_text: Block 'terraform destroy' and 'tofu destroy' (and apply -destroy)
```

`effect` is `BLOCK` or `ESCALATE`; a command no rule matches is allowed. See [writing constraints](../constraints.md) for the resource names each tool produces, scopes such as namespace, region and environment, and time windows.

## Why the rules are signed

The agent reads tickets, pull request comments and docs, and any of them can contain text that looks like an instruction or a rule. Aegis only counts a rule if nobody has edited it since it was signed, and if its author is allowed to write that kind of rule (the authority map in `authority.yaml`). A rule that fails either check is discarded and reported, so a line planted in a ticket can't become policy, and can't be used to stall the agent either.

Before you rely on the policy, replace the example signing key with your own: `aegis keygen`, then `aegis sign`. See [configuration](../configuration.md).

## Details

Hook used: `beforeShellExecution`. Full notes on every agent, including what happens when the policy itself is broken: [coding agents](../agents.md).

Also for: [Claude Code](claude-code.md), [Codex CLI](codex.md), [Gemini CLI](gemini-cli.md), [GitHub Copilot CLI and VS Code](copilot.md), and [Terraform plans in CI](terraform-plan-ci.md).
