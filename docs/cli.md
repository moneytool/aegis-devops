# CLI reference

Exit codes, store health, the Claude Code hook, argv parsing, compound commands, dry runs, and
library usage for the `aegis` CLI.

← back to the [README](../README.md)

### Argv forms

Global options in front of the verb (`kubectl -n prod delete …`, `git -C /repo push …`,
`helm --kube-context prod uninstall …`), glued short flags (`-nprod`), label selectors
(`-l role=worker`) and comma-separated kinds (`nodes,pods`) all parse to the same intents as
their canonical forms; a leading option Aegis does not recognise is an error (exit 65), never a
guess at where the verb starts. `kubectl delete namespace prod` additionally emits a synthetic
`*/*` delete intent scoped to that namespace, so namespace-scoped deletion rules fire on it.

### Exit codes

The exit code is the worst verdict across all evaluated intents, or a tool error. Verdict codes
depend on `--exit-style`; tool errors are identical in every style and never print a verdict.

| exit code | `--exit-style aegis` (default) | `--exit-style claude-hook` | `--exit-style ci` |
| :--- | :--- | :--- | :--- |
| `0` | ALLOW | ALLOW (prints nothing) | ALLOW |
| `1` | — | — | ESCALATE or BLOCK |
| `2` | ESCALATE | ESCALATE or BLOCK, printing `{"decision": "block", "reason": "<verdict>: <citations>"}` | — |
| `3` | BLOCK | — | — |
| `64` | usage error (unknown flag, no argv after `--`, compound argv without `--split-compound`, a command string Aegis refuses to evaluate statically) | same | same |
| `65` | bad data: unparseable argv, `--now`, YAML or JSON; degraded store (see below); no signing key, or a missing/bad signature | same | same |
| `66` | a constraints/authority/environments/plan/key file does not exist or is unreadable | same | same |
| `70` | internal error; the exception class name is on stderr | same | same |

Every error is one `aegis: error: …` line on stderr, never a traceback. `claude-hook` exists
because Claude Code `PreToolUse` hooks treat exit 2 as *block* and any other non-zero code as a
non-blocking error, which would invert the default `3 = BLOCK` contract.

### Store health

Every output carries the state of the constraint store, so a degraded store can never be
mistaken for a clean allow. Each per-intent JSON line and the plan summary include a
`store_health` object — `loaded`, `quarantined: [{id, reason}]`, `principals`,
`constraints_sha256` (of the raw file bytes), `warnings` — and `--pretty` ends with a
`STORE: loaded=N quarantined=M principals=P` line plus one line per quarantined rule, preceded
by one `WARNING: …` line per store warning (`using example signing key`, `insecure: signatures
not verified`, `ledger: chain-broken`, rate-limit key typos). Quarantines also go to stderr as
`aegis: WARNING …` lines.

Integrity failures **fail closed**. A constraint that was quarantined at load (`tampered`,
`forged`) or discarded at decision time (`tampered`, `unauthorized`) is still matched, and if it
was a BLOCK or ESCALATE rule its match contributes **ESCALATE** — never BLOCK (nobody can vouch
for the rule) and never ALLOW (the action it covers is contested). The decision reports it in
`discarded` and with a `fail-closed: <id> (<reason>)` note:

```bash
aegis check kubectl --constraints /tmp/oneflip.yaml --key file:data/example-signing.key \
    --pretty -- kubectl delete node/x
```

```
aegis: WARNING Quarantined constraint no-delete-nodes: provenance hash mismatch
ESCALATE: kubernetes delete node/x
  discarded: [{'id': 'no-delete-nodes', 'reason': 'tampered'}]
  note: env-unresolved: no-delete-in-prod-env
  note: fail-closed: no-delete-nodes (tampered)
  covered: True  latency_ms: 0.13
PLAN ESCALATE: 1 intent(s)
  plan citations: plan-k8s-delete-ratio
  note: ratio: 1/1 = 1.00 > 0.5
WARNING: Quarantined constraint no-delete-nodes: provenance hash mismatch
STORE: loaded=20 quarantined=1 principals=3
  quarantined: no-delete-nodes (tampered)
```

(`/tmp/oneflip.yaml` here is `data/constraints.example.yaml` with the last hex digit of
`no-delete-nodes`'s `provenance_hash` flipped and re-signed with the example key — a valid
signature, invalid content, exactly what a hand-edited rule or a one-bit storage error looks
like. `--key` is explicit because the example key normally auto-resolves next to
`--constraints`, and `/tmp` has no `example-signing.key` of its own.)

Aegis refuses to decide at all (exit 65, one-line message, no verdict) when the store loaded
zero constraints, the authority map grants nothing to anyone, or more than
`--max-quarantine-ratio` (default `0.10`) of the constraints were quarantined. `--fail-closed`
additionally turns an *uncovered* intent (no rule matched) into ESCALATE with the note
`fail-closed: uncovered`.

Two more fail-closed clauses live in the interceptor: a rule that scopes on `env` when the
intent's environment could not be resolved contributes ESCALATE with the note
`env-unresolved: <id>` (see [Environment mapping](constraints.md#environment-mapping)), and an
intent whose target the parser could not pin down (`git push -f` with no refspec) contributes
ESCALATE with the note `unknown-target`, so it cannot slip past a `ref/main` rule as `ref/*`.

### Claude Code hook

`examples/claude-code-hook.sh` is a `PreToolUse` hook: it reads the hook JSON from stdin and
hands `tool_input.command` — the raw string — to `aegis check command --exit-style claude-hook`.
ALLOW lets the tool call proceed; ESCALATE and BLOCK exit 2 with the reason on stderr (which
Claude Code shows to the model). Compound commands are split and launchers unwrapped (see
"Compound commands" below); binaries Aegis has no parser for are not gated unless you add
`--fail-closed` via `AEGIS_ARGS`; any tool error — including a command string Aegis refuses to
evaluate statically, such as `kubectl delete $(cat x)` — is converted into a block, so the hook
never fails open. It runs the `aegis` in the venv next to it (`AEGIS_BIN` overrides).

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
  {"type": "command", "command": "/path/to/aegis-devops/examples/claude-code-hook.sh"}]}]}}
```

## Compound commands

Agent frameworks hand over a shell *string*, not an argv. `aegis check command -- "<string>"`
(and `aegis check argv --split-compound`) turns that string into the simple commands it would
run — splitting on `;`, `&&`, `||`, `|`, `&` and newlines, unwrapping `sudo`, `env VAR=…`,
`timeout`, `nice`, `nohup`, `command`, `time`, `sh -c "…"` and the `k`/`tf`/`g` aliases — and
checks every one whose binary Aegis knows. The exit code is the worst verdict across them:

```
aegis check command -- "kubectl get pods; kubectl delete node/w1"   # BLOCK, exit 3
aegis check command -- "sudo kubectl delete node/w1"                # BLOCK, exit 3
aegis check command -- "kubectl get pods | grep x"                  # ALLOW, exit 0
aegis check command -- 'kubectl delete $(cat x)'                    # exit 64: command rejected
```

Inside a pipeline an unknown binary (`| grep x`) produces nothing; on its own it produces a
synthetic `shell` / `binary/<name>` / `exec` intent that `--fail-closed` escalates. `KUBECONFIG=…`
and `env AWS_PROFILE=…` prefixes land in the intent's metadata (`kubeconfig`, `profile`, …) so
the environment map sees them. **Fail closed:** anything whose argv cannot be known without
running it is refused as a usage error (exit 64, `command rejected: <reason>`) — command
substitution (`$(…)`, backticks), `$VAR` outside single quotes, process substitution,
subshells, here-docs, `eval`/`exec`/`source`/`.`/`xargs`, and unbalanced quotes. Without the
flag, `aegis check <target>` still treats any shell metacharacter in an argv as a usage error.

## Dry runs

A rehearsal (`kubectl --dry-run=client|server`, `aws --dry-run`, `az --what-if|--dry-run`,
`gcloud --dry-run`) can't change infrastructure, so Aegis never blocks or escalates it — the
verdict is always `ALLOW`, with `dry_run: true` and `would_be` reporting what a real run would
have gotten:

```
ALLOW: kubernetes scale deployment/api-server (dry-run; would be BLOCK)
  citations: no-scale-prod-peak
  covered: True  latency_ms: 0.12
PLAN ALLOW: 1 intent(s)
  note: would_be: BLOCK
```

`terraform`/`tofu` plans are evaluated normally — the plan JSON *is* the proposed change, not a
rehearsal of one.

## Library usage

```python
from aegis_core.authority import load_authority_map
from aegis_core.store import ConstraintStore
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_kubectl

authority_map = load_authority_map("data/authority.example.yaml")
store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
interceptor = AegisInterceptor(store)

intent = from_kubectl(["kubectl", "delete", "node/worker-1"])
decision = interceptor.intercept(intent)
print(decision.verdict, decision.citations, decision.covered)
# BLOCK ['no-delete-nodes'] True
```

`Decision` also carries `discarded` (constraints that matched but were thrown out, with why),
`notes` (`fail-closed: …`, `rate-limit: …`), `latency_ms`, `dry_run`, and `would_be`.
`store.health` is the `StoreHealth` the CLI prints; `AegisInterceptor(store, fail_closed=True)`
is the library form of `--fail-closed`.
