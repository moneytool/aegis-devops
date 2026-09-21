# Aegis-DevOps

A lightweight, high-performance middleware layer that intercepts proposed agent actions and
validates them against an **Authority-Anchored Constraint Store**. Unlike existing tools
(HolmesGPT, RunLore) that focus on *retrieval*, Aegis focuses on *verification*: every
constraint in the store must pass an integrity check (has it been tampered with since
ingestion?) and an authority check (was its source ever allowed to assert this kind of
policy?) before it can drive a decision.

## Install

```bash
python -m venv venv
venv/bin/python -m pip install -e ".[dev]"
```

## Run tests

```bash
venv/bin/python -m pytest -q
```

## The five-rule example

`data/constraints.example.yaml` ships five constraints spanning both providers, all three
constraint classes, a scoped rule, and a time-windowed rule:

| id | provider | resource_pattern | actions | effect | constraint_class |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `no-scale-prod-peak` | kubernetes | `deployment/*` | scale | BLOCK | scaling |
| `no-delete-nodes` | kubernetes | `node/*` | delete | BLOCK | deletion |
| `escalate-terraform-prod-destroy` | terraform | `aws_instance.*` | delete, replace | ESCALATE | deletion |
| `escalate-configmap-changes` | kubernetes | `configmap/*` | update, delete | ESCALATE | configuration |
| `no-direct-asg-changes` | terraform | `aws_autoscaling_group.*` | update | BLOCK | scaling |

`data/authority.example.yaml` maps principals to the constraint classes they may assert
(`admin`: all three; `sre_lead`: scaling, configuration; `developer`: configuration).

Run `examples/demo.py` to see the store, the authority map, and the interceptor working
together against three intents — one allowed, one blocked, one escalated:

```bash
venv/bin/python examples/demo.py
```

## Why not OPA/Gatekeeper?

OPA/Gatekeeper evaluates **structured API objects** against **hand-authored rules**. Aegis
derives **unstructured human constraints** (from Slack, Jira, Git) and applies
**authority-driven validation** to the agent's intent *before* it reaches the infrastructure.
