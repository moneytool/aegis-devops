# Contributing a new parser

Every Aegis parser — `kubectl`, `terraform`, `aws`, `pulumi`, `sql`, ... — turns
tool-specific input (an argv list or a plan/preview JSON document) into one or
more `InfrastructureIntent` records. The interceptor, the constraint matcher,
the adversarial suite, and the benchmark harness never see raw argv or JSON;
they only ever see this one normalised shape. Adding a new tool means adding a
new parser that emits it — nothing downstream changes.

## 1. The normalised shape (PLAN.md §3.1)

Every parser must produce:

- `resource` — `service/kind[/name]`, lower-case, singular kind
  (`deployment/api-server`, `aws_instance.web`, `table/users`). Use `kind/*`
  when no specific name is available.
- `action` — one verb from the shared vocabulary (`create, delete, update,
  scale, start, stop, restart, read, put, attach, detach, apply, exec,
  rollback, ...`). Map the tool's own verb onto this vocabulary; keep the
  original string in `params["raw_action"]` so nothing is lost.
- `provider` — the tool family (`kubernetes`, `terraform`, `aws`, `azure`,
  `gcp`, `helm`, `argocd`, `flux`, `git`, `github`, `sql`, `pulumi`, ...).
  Constraints match on this, so reuse an existing provider name if the new
  tool governs the same class of resource (e.g. OpenTofu reuses
  `provider="terraform"` so one rule set governs both).
- `metadata` — environment identifiers the tool exposes
  (`namespace, region, zone, project, subscription, resource_group, account,
  context`). These feed `EnvironmentMap.annotate` (see the README's
  "Environment mapping" section) — never invent an identifier the agent
  itself controls (e.g. don't treat a namespace literally named `prod` as
  proof of production).
- `params` — everything else: flags, dry-run markers, the raw command.

Look at `src/aegis_core/parser.py`'s `_VERB_NORMALIZE` table before adding a
new verb mapping — most CLI verbs already have a home there.

## 2. Where to register the parser

- Add `from_<tool>(argv) -> InfrastructureIntent` (or `from_<tool>_multi(argv)
  -> list[InfrastructureIntent]` if one invocation can touch several
  resources) to `src/aegis_core/parser.py`, or to its own module under
  `src/aegis_core/parsers/` for a large or self-contained parser (see
  `parsers/sql.py`, `parsers/pulumi.py`).
- Register the tool in `from_argv`'s dispatch table in `parser.py` so `aegis
  check argv -- <tool> ...` can find it by binary name.
- Add an entry to `_ARGV_TARGET_PARSERS` in `src/aegis_core/cli.py` so `aegis
  check <tool> -- ...` works as its own subcommand, and add the subcommand's
  `argparse` registration next to the others in `cli.py` (copy an existing
  `add_parser(...)` block for an argv-based tool, or the plan/JSON-based
  block if the new tool emits a document instead of an argv, like Terraform
  or Pulumi preview).
- Update the `usage:` docstring at the top of `cli.py` and the "Supported
  tools" table in `README.md`.

## 3. Tests to add

- Unit tests for the parser itself (`tests/test_parser.py`, or a new
  `tests/test_parsers_<tool>.py` alongside `test_parsers_sql.py` /
  `test_parsers_pulumi.py`): verb mapping, resource/name extraction,
  metadata extraction, at least one multi-resource case if applicable.
- A CLI test in `tests/test_cli.py` exercising `aegis check <tool> -- ...`
  end-to-end against `data/constraints.example.yaml`, covering exit codes.
- If the tool introduces a genuinely new attack surface (a new way to word a
  destructive action, a new place identity/authority can be spoofed), add a
  case to `tests/test_adversarial.py` and, if it's a new category of attack
  rather than a new instance of an existing one, register it in
  `src/aegis_core/adversarial.py`'s `_REGISTRY`.

## 4. Adding an example constraint with a real hash

Constraints ship with a real `provenance_hash` — never hand-write one.
Compute it with `aegis_core.provenance.compute_provenance_hash` and paste the
result into the YAML:

```bash
venv/bin/python - <<'EOF'
from aegis_core.provenance import compute_provenance_hash

h = compute_provenance_hash(
    provider="helm",
    resource_pattern="release/*",
    actions=["delete"],
    scope={"namespace": "prod"},
    time_window=None,
    effect="BLOCK",
    constraint_class="deletion",
    principal="admin",
    source_ref="jira-9001",
    source_timestamp="2026-04-01T09:00:00+00:00",
    rule_text="Never uninstall a Helm release in prod without a change ticket.",
)
print(h)
EOF
```

Add the resulting constraint to `data/constraints.example.yaml` (and, if you
want load-time forgery detection to actually verify it, a matching
`data/sources/<source_ref>.json` with the same source-side fields — see the
README's "Source verification" section). Run `venv/bin/python examples/demo.py`
and the store's tests afterward to confirm the hash round-trips.
