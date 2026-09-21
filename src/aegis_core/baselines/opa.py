"""Baseline C — OPA/Rego (PLAN.md §4).

Like the LLM baseline, this one loads *every* constraint — tampered,
unauthorized, and forged included — because OPA/Gatekeeper has no concept
of provenance or authority. It evaluates structured input against
hand-authored (here, generated) rules, which is exactly the "why not
OPA/Gatekeeper" distinction PLAN.md §3 draws.

Known limitation: constraint ``time_window`` is NOT evaluated by the
generated Rego (OPA has ``time.now_ns`` but wiring day-of-week + local-tz
window logic into Rego is out of scope for this baseline) — a
time-windowed constraint is emitted as an always-active rule with a
comment noting the window it's ignoring. This means the OPA baseline will
over-match relative to Aegis on time-windowed constraints; that's a
documented baseline limitation, not a bug in the comparison.
"""

import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import Decision
from aegis_core.store import Constraint

_RULE_TEMPLATE = """\
rule_{n}_block if {{
{block_body}
}}

rule_{n}_escalate if {{
{escalate_body}
}}
"""


def _glob_literal(pattern: str) -> str:
    return json.dumps(pattern)


def _resource_line(pattern: str) -> str:
    # OPA's glob.match(pattern, delimiters, match) — "/" is the only
    # delimiter our resource patterns use (e.g. "deployment/*").
    return f"    glob.match({_glob_literal(pattern)}, [\"/\"], input.resource)"


def _scope_lines(scope: dict) -> list[str]:
    lines = []
    for key, value in scope.items():
        lines.append(f"    input.metadata.{key} == {json.dumps(value)}")
    return lines


def _actions_line(actions: set[str]) -> str:
    actions_json = json.dumps(sorted(actions))
    return f"    input.action in {actions_json}"


def _rule_body(c: Constraint) -> list[str]:
    lines = [
        f"    input.provider == {json.dumps(c.provider)}",
        _resource_line(c.resource_pattern),
        _actions_line(c.actions),
    ]
    lines.extend(_scope_lines(c.scope))
    if c.time_window:
        lines.append(f"    # time_window ignored by this baseline: {json.dumps(c.time_window)}")
    return lines


def _emit_matches(rule_name: str, entries: list[Constraint]) -> str:
    """Emits a `<rule_name> contains <id> if { ... }` clause per matching
    constraint. Rego allows multiple definitions of the same `contains`
    rule head — they combine with OR / set-union semantics, which is
    exactly the "any matching constraint votes" behaviour we want."""
    if not entries:
        # A plain empty-set rule (not a `contains` partial rule) — avoids an
        # "unsafe variable" compile error from a `contains id if { false }`
        # stub, since `id` would never be bound in that body.
        return f"{rule_name} := set()"
    clauses = []
    for c in entries:
        body = "\n".join(_rule_body(c))
        clauses.append(f"{rule_name} contains {json.dumps(c.id)} if {{\n{body}\n}}")
    return "\n\n".join(clauses)


def render_rego(constraints: list[Constraint]) -> str:
    """Generates a Rego v1 policy: one BLOCK/ESCALATE rule per constraint,
    folded into ``block_ids`` / ``escalate_ids`` sets. BLOCK beats
    ESCALATE beats the default ALLOW."""
    block_entries = [c for c in constraints if c.effect == "BLOCK"]
    escalate_entries = [c for c in constraints if c.effect == "ESCALATE"]

    parts = [
        "package aegis",
        "",
        "import rego.v1",
        "",
        'default verdict := "ALLOW"',
        "",
        _emit_matches("block_ids", block_entries),
        "",
        _emit_matches("escalate_ids", escalate_entries),
        "",
        'verdict := "BLOCK" if count(block_ids) > 0',
        "",
        'verdict := "ESCALATE" if {',
        "    count(block_ids) == 0",
        "    count(escalate_ids) > 0",
        "}",
        "",
        "citations := block_ids if count(block_ids) > 0",
        "",
        "citations := escalate_ids if {",
        "    count(block_ids) == 0",
        "    count(escalate_ids) > 0",
        "}",
        "",
        "citations := set() if {",
        "    count(block_ids) == 0",
        "    count(escalate_ids) == 0",
        "}",
    ]
    return "\n".join(parts) + "\n"


class OpaVerifier:
    """Baseline C: shells out to a real ``opa eval`` per decision.

    ``available`` is False (and ``decide`` raises) when the ``opa`` binary
    isn't on PATH — the benchmark script skips this row with a clear note
    rather than failing the whole run.
    """

    name = "opa"

    def __init__(self, constraints: list[Constraint], opa_bin: str = "opa"):
        self.constraints = constraints
        self.opa_bin = opa_bin
        self.available = shutil.which(opa_bin) is not None
        self._policy_path: Path | None = None
        if self.available:
            self._tmpdir = tempfile.TemporaryDirectory(prefix="aegis-opa-")
            self._policy_path = Path(self._tmpdir.name) / "policy.rego"
            self._policy_path.write_text(render_rego(constraints))

    def decide(self, intent: InfrastructureIntent, now: datetime) -> Decision:
        if not self.available:
            raise RuntimeError(
                f"OPA binary '{self.opa_bin}' not found on PATH; OpaVerifier is unavailable."
            )

        start = time.perf_counter()
        input_payload = {"input": intent.to_dict()}
        result = subprocess.run(
            [
                self.opa_bin,
                "eval",
                "-f",
                "json",
                "-d",
                str(self._policy_path),
                "-I",
                "data.aegis",
            ],
            input=json.dumps(input_payload),
            capture_output=True,
            text=True,
            timeout=10,
        )
        latency_ms = (time.perf_counter() - start) * 1000

        if result.returncode != 0:
            raise RuntimeError(f"opa eval failed: {result.stderr}")

        payload = json.loads(result.stdout)
        expressions = payload["result"][0]["expressions"]
        value = expressions[0]["value"]
        verdict = value.get("verdict", "ALLOW")
        citations = sorted(value.get("citations", []) or [])

        return Decision(
            verdict=verdict,
            citations=citations,
            discarded=[],
            covered=verdict != "ALLOW",
            latency_ms=latency_ms,
        )
