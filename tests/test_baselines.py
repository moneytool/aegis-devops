"""Tests for the baseline verifiers (PLAN.md §4 Week 7-8)."""

import json
from datetime import UTC, datetime

import pytest

from aegis_core.baselines.llm import (
    HeuristicLLMClient,
    LLMVerifier,
    RecordingClient,
    ReplayClient,
    parse_llm_response,
)
from aegis_core.baselines.opa import OpaVerifier, render_rego, signed_bundle_constraints
from aegis_core.intent import InfrastructureIntent
from aegis_core.store import Constraint

NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="c-untrusted-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="contractor",  # not authorized for "scaling" in the real corpus
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    defaults.update(overrides)
    return Constraint.create(**defaults)


SCALE_INTENT = InfrastructureIntent(
    resource="deployment/api-server", action="scale", provider="kubernetes"
)


# ---------------------------------------------------------------------------
# The thesis, in one test: an Untrusted constraint (invalid authority) that
# Aegis's own interceptor would discard still drives a naive LLM
# self-check's verdict, because the heuristic client — like a real LLM
# stuffed with the same constraint list — has no authority concept.
# ---------------------------------------------------------------------------


def test_heuristic_llm_blocks_on_constraint_aegis_would_discard():
    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.store import ConstraintStore

    untrusted = make_constraint()

    # Aegis: authority_map doesn't grant "contractor" anything, so this
    # constraint is discarded at decision time. Aegis never *obeys* it
    # (no BLOCK): pre-fail-closed it ALLOWed; with REVIEW-4 T0.3 fail-closed
    # a discarded BLOCK rule contributes ESCALATE instead. Either way the
    # rule is reported as discarded, not cited as the reason for a BLOCK.
    store = ConstraintStore(authority_map={"admin": {"scaling"}})
    store.constraints[untrusted.id] = untrusted
    aegis_decision = AegisInterceptor(store).intercept(SCALE_INTENT, now=NOW)
    assert aegis_decision.verdict in ("ALLOW", "ESCALATE")
    assert aegis_decision.verdict != "BLOCK"
    assert {"id": untrusted.id, "reason": "unauthorized"} in aegis_decision.discarded

    # The heuristic LLM baseline sees the same constraint with no authority
    # filter at all, and blocks.
    client = HeuristicLLMClient([untrusted])
    verifier = LLMVerifier(client, [untrusted], name="llm-heuristic")
    llm_decision = verifier.decide(SCALE_INTENT, now=NOW)
    assert llm_decision.verdict == "BLOCK"
    assert untrusted.id in llm_decision.citations


def test_heuristic_llm_allows_when_no_constraint_matches():
    unrelated = InfrastructureIntent(
        resource="service/frontend", action="get", provider="kubernetes"
    )
    client = HeuristicLLMClient([make_constraint()])
    verifier = LLMVerifier(client, [make_constraint()])
    decision = verifier.decide(unrelated, now=NOW)
    assert decision.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_parse_llm_response_block_with_citations():
    verdict, citations, discarded = parse_llm_response("BLOCK\ncitations: a, b")
    assert verdict == "BLOCK"
    assert citations == ["a", "b"]
    assert discarded == []


def test_parse_llm_response_unparseable():
    verdict, citations, discarded = parse_llm_response("I cannot determine this.")
    assert verdict == "ESCALATE"
    assert citations == []
    assert discarded == [{"id": "-", "reason": "unparseable"}]


def test_parse_llm_response_bare_allow():
    verdict, citations, discarded = parse_llm_response("ALLOW")
    assert verdict == "ALLOW"
    assert citations == []
    assert discarded == []


# ---------------------------------------------------------------------------
# Recording / replay round-trip
# ---------------------------------------------------------------------------


class _StubClient:
    def __init__(self, response: str):
        self.response = response
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        return self.response


def test_recording_replay_round_trip(tmp_path):
    cache_path = tmp_path / "cache.jsonl"
    stub = _StubClient("BLOCK\ncitations: c-1")
    recorder = RecordingClient(stub, cache_path)

    response = recorder.complete("system prompt", "user turn")
    assert response == "BLOCK\ncitations: c-1"
    assert stub.calls == 1
    assert cache_path.exists()

    # Cache file is valid JSONL with the expected shape.
    lines = cache_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert set(entry.keys()) == {"key", "response"}

    replay = ReplayClient(cache_path)
    replayed = replay.complete("system prompt", "user turn")
    assert replayed == "BLOCK\ncitations: c-1"


def test_replay_client_raises_on_cache_miss(tmp_path):
    cache_path = tmp_path / "empty-cache.jsonl"
    replay = ReplayClient(cache_path)
    with pytest.raises(KeyError):
        replay.complete("nope", "nope")


# ---------------------------------------------------------------------------
# render_rego structure
# ---------------------------------------------------------------------------


def test_render_rego_uses_v1_keywords_and_structure():
    block_c = make_constraint(id="c-block", effect="BLOCK", scope={"namespace": "prod"})
    escalate_c = make_constraint(
        id="c-escalate",
        effect="ESCALATE",
        resource_pattern="aws_instance.*",
        provider="terraform",
        actions={"delete"},
    )
    rego = render_rego([block_c, escalate_c])

    assert "package aegis" in rego
    assert "import rego.v1" in rego
    assert 'default verdict := "ALLOW"' in rego
    assert "if {" in rego
    assert "contains" in rego
    assert 'glob.match("deployment/*", ["/"], input.resource)' in rego
    assert 'input.metadata.namespace == "prod"' in rego
    assert '"c-block"' in rego
    assert '"c-escalate"' in rego
    assert 'verdict := "BLOCK" if count(block_ids) > 0' in rego


def test_render_rego_handles_no_block_or_escalate_constraints():
    rego = render_rego([])
    assert "block_ids := set()" in rego
    assert "escalate_ids := set()" in rego


# ---------------------------------------------------------------------------
# opa-signed: a signed-bundle deployment drops tampered/forged, keeps
# unauthorized (bundle signing proves integrity, not authority).
# ---------------------------------------------------------------------------


_SIGNED_LABELS = {
    "c-ok": {"label": "Trusted", "reason": "authorized"},
    "c-unauth": {"label": "Untrusted", "reason": "unauthorized"},
    "c-tampered": {"label": "Malicious", "reason": "tampered"},
    "c-forged": {"label": "Malicious", "reason": "forged"},
}


def _signed_fixture_constraints():
    return [
        make_constraint(id="c-ok", principal="platform_admin"),
        make_constraint(id="c-unauth", principal="contractor"),
        make_constraint(id="c-tampered", resource_pattern="node/*"),
        make_constraint(id="c-forged", resource_pattern="pod/*"),
        make_constraint(id="c-unlabelled", resource_pattern="job/*"),
    ]


def test_signed_bundle_filters_exactly_tampered_and_forged():
    kept = signed_bundle_constraints(_signed_fixture_constraints(), _SIGNED_LABELS)
    assert [c.id for c in kept] == ["c-ok", "c-unauth", "c-unlabelled"]


def test_opa_signed_rego_excludes_tampered_and_forged_ids():
    kept = signed_bundle_constraints(_signed_fixture_constraints(), _SIGNED_LABELS)
    rego = render_rego(kept)
    assert '"c-ok"' in rego
    assert '"c-unauth"' in rego  # the realistic pre-ingest attacker survives signing
    assert '"c-tampered"' not in rego
    assert '"c-forged"' not in rego

    verifier = OpaVerifier(kept, opa_bin="definitely-not-a-real-binary-xyz", name="opa-signed")
    assert verifier.name == "opa-signed"
    assert [c.id for c in verifier.constraints] == ["c-ok", "c-unauth", "c-unlabelled"]


# ---------------------------------------------------------------------------
# OpaVerifier availability
# ---------------------------------------------------------------------------


def test_opa_verifier_unavailable_when_binary_missing():
    verifier = OpaVerifier([make_constraint()], opa_bin="definitely-not-a-real-binary-xyz")
    assert verifier.available is False
    with pytest.raises(RuntimeError):
        verifier.decide(SCALE_INTENT, now=NOW)


def test_opa_verifier_real_eval_if_available():
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary not on PATH")

    block_c = make_constraint(id="c-block", effect="BLOCK")
    verifier = OpaVerifier([block_c])
    assert verifier.available is True
    decision = verifier.decide(SCALE_INTENT, now=NOW)
    assert decision.verdict == "BLOCK"
    assert "c-block" in decision.citations

    # Non-matching intent must fall through to the default ALLOW.
    unrelated = InfrastructureIntent(
        resource="service/frontend", action="get", provider="kubernetes"
    )
    assert verifier.decide(unrelated, now=NOW).verdict == "ALLOW"
