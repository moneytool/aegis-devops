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
          fail-on: escalate      # fail on ESCALATE too, not only BLOCK
          signing-key: ${{ secrets.AEGIS_SIGNING_KEY }}
```

`fail-on: escalate` matters: the Action's default (`block`) lets an ESCALATE verdict pass, and the
example policy escalates rather than blocks some plans (`plan-max-25-resources`: more than 25
resources in one plan). With it, the check fails on either verdict, like `--exit-style ci`
below. An escalated plan then needs its own review and approval before anyone applies it, for
example a protected environment with required reviewers on the apply job.

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

Both check a plan against rules, and both are good at it. Aegis adds a check on the rules themselves: a rule only counts if nobody has edited it since it was signed, and if its author is allowed to write that kind of rule. That matters when the change, or the rules, may have come from an AI agent that read a ticket or a pull request comment. The same policy also runs as a pre-execution hook for [Claude Code](claude-code.md), [Cursor](cursor.md), [Codex](codex.md), [Copilot](copilot.md) and [Gemini CLI](gemini-cli.md).

## What the hooks do and don't cover

The two checks are different. The **agent hook** sees the command, so it enforces command-level
rules: `terraform destroy` and `terraform apply -destroy` are blocked by the example policy. It
does **not** see what a saved plan will change, so a plain `terraform apply` (or `terraform apply
tfplan`) is allowed, even for a plan that the **plan check** above would block. Plan-level rules
such as `plan-no-db-deletes` hold only where the exact plan is checked and the apply path is
protected:

- apply in CI, from the plan the check approved, behind a protected environment;
- keep apply credentials (cloud keys, state backend access) out of the agents' environment;
- if agents must never run Terraform at all, add a rule for the shell intent
  `binary/terraform` (provider `shell`, action `exec`) — it blocks every `terraform` command,
  `plan` included, since the hook cannot tell them apart; or rely on the
  [server-side layer](../server-side.md), which denies the cloud calls whatever runs them.
