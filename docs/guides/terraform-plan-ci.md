# Block risky Terraform and OpenTofu plans in CI, before anyone applies them

A pull request that changes Terraform can look harmless in the diff and still produce a plan that deletes a production database, or replaces forty resources at once. That's more likely when an AI agent wrote the change. Checking the plan (what Terraform will actually do) instead of the code catches it before `apply`.

[Aegis-DevOps](https://github.com/moneytool/aegis-devops#readme) checks each resource change in the plan JSON, plus plan-level rules such as "no database deletes" or "no more than 25 resources in one plan", against your policy. The [GitHub Action](https://github.com/marketplace/actions/aegis-devops-plan-check) fails the job when the policy blocks the plan and comments the result on the pull request.

## GitHub Actions

```yaml
name: terraform
on: pull_request

permissions:
  contents: read
  pull-requests: write   # for the PR comment

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false
      - run: terraform init -input=false && terraform plan -input=false -out=tfplan
      - uses: moneytool/aegis-devops-action@v1
        with:
          plan: tfplan
          signing-key: ${{ secrets.AEGIS_SIGNING_KEY }}
```

Add a policy to the repository first: `pip install aegis-devops && aegis init .aegis`. For OpenTofu, use `opentofu/setup-opentofu` and set `tool: tofu`. The Action's [README](https://github.com/moneytool/aegis-devops-action#readme) covers every input.

## Any other CI

```bash
pip install aegis-devops
terraform show -json tfplan > plan.json
aegis check terraform plan.json --exit-style ci    # exit 0 = allowed, 1 = blocked or escalated
```

## What it looks like

A plan that deletes `aws_db_instance.main` and creates an S3 bucket, checked against the example policy:

```
$ aegis check terraform --pretty --exit-style ci plan.json
ALLOW: terraform delete aws_db_instance.main
  plan_sha256: 786a24311cff
  covered: False  latency_ms: 0.1340
ALLOW: terraform create aws_s3_bucket.logs
  plan_sha256: 786a24311cff
  covered: False  latency_ms: 0.0030
PLAN BLOCK: 2 intent(s)
  plan citations: plan-no-db-deletes
  note: max_matching: 1 delete/replace > 0
STORE: loaded=30 quarantined=0 principals=3
  warning: using example signing key
$ echo $?
1
```

Each change is allowed on its own, but the plan-level rule `plan-no-db-deletes` blocks the plan as a whole.

## Plan-level rules

Rules in `.aegis/plan_constraints*.yaml` look at the whole plan:

- `max_intents`: escalate a plan that touches more than N resources.
- `max_matching`: block a plan with more than N changes of a kind, e.g. zero deletes or replaces of `aws_db_instance.*`.
- `forbid_together`: block a plan that mixes two kinds of change, e.g. deletes in `us-east-1` and creates anywhere, so they're reviewed separately.
- `requires_all`: fire when a plan is missing something that should always travel together.

See [writing constraints](../constraints.md).

## How this differs from OPA or Sentinel

Both check a plan against rules, and both are good at it. Aegis adds a check on the rules themselves: a rule only counts if nobody has edited it since it was signed, and if its author is allowed to write that kind of rule. That matters when the change, or the rules, may have come from an AI agent that read a ticket or a pull request comment. The same policy also runs as a pre-execution hook for [Claude Code](claude-code.md), [Cursor](cursor.md), [Codex](codex.md), [Copilot](copilot.md) and [Gemini CLI](gemini-cli.md), so an agent can't skip CI by running `terraform apply` itself.
