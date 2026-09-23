"""Tests for the baseline verifiers (PLAN.md §4 Week 7-8)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from aegis_core.baselines.llm import (
    AwarePromptBuilder,
    HeuristicLLMClient,
    LLMVerifier,
    RecordingClient,
    ReplayClient,
    parse_llm_response,
    render_system_prompt,
    render_user_turn,
)
from aegis_core.baselines.opa import OpaVerifier, render_rego, signed_bundle_constraints
from aegis_core.intent import InfrastructureIntent
from aegis_core.store import Constraint, _constraint_from_dict

NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "pre_t05_corpus"


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


# ---------------------------------------------------------------------------
# AwarePromptBuilder (REVIEW-4 T2.1) and the external llm-naive/llm-aware
# replay caches recorded by a sibling harness (agent-guardrail-bench@a98a8fa)
# against this repo's pre-T0.5 corpus. See results/llm-external.md for the
# full measured tables and cost estimate. These tests confirm this repo's
# CURRENT prompt rendering still reproduces the prompts that cache was
# recorded against -- i.e. results/llm-cache-{naive,aware}.jsonl replay
# cleanly, and would immediately go stale if render_system_prompt or
# AwarePromptBuilder's text ever drifts.
# ---------------------------------------------------------------------------


def test_aware_prompt_builder_appends_authority_after_naive_prompt():
    constraints = [make_constraint()]
    authority_map = {"platform_admin": {"scaling"}}
    naive = render_system_prompt(constraints)
    aware = AwarePromptBuilder(constraints, authority_map).render_system_prompt()
    assert aware.startswith(naive)
    assert "Authority rules" in aware
    assert "platform_admin" in aware
    assert "scaling" in aware


def test_aware_prompt_builder_renders_sorted_principal_classes():
    constraints = [make_constraint()]
    authority_map = {"sre_lead": {"deletion", "scaling"}, "admin": {"access"}}
    builder = AwarePromptBuilder(constraints, authority_map)
    authority_yaml = yaml.safe_load(builder.render_authority_yaml())
    assert authority_yaml == {
        "principals": {"sre_lead": ["deletion", "scaling"], "admin": ["access"]}
    }


def _load_pre_t05_fixture():
    with open(FIXTURES_DIR / "constraints.yaml") as f:
        raw_constraints = yaml.safe_load(f)["constraints"]
    with open(FIXTURES_DIR / "authority.yaml") as f:
        authority_raw = yaml.safe_load(f)["principals"]
    authority_map = {p: set(classes) for p, classes in authority_raw.items()}
    intents = []
    with open(FIXTURES_DIR / "intents_holdout.jsonl") as f:
        for line in f:
            line = line.strip()
            if line:
                intents.append(json.loads(line))
    return raw_constraints, authority_map, intents


def _load_external_cache(path: Path) -> dict[str, str]:
    cache: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            cache[entry["key"]] = entry["response"]
    return cache


def _replay_hit_rate(system_prompt: str, intents: list[dict], cache: dict[str, str]) -> float:
    client = ReplayClient.__new__(ReplayClient)  # avoid re-reading the file per call
    client._cache = cache
    client.cache_path = None
    hits = 0
    for rec in intents:
        intent = InfrastructureIntent(
            resource=rec["resource"],
            action=rec["action"],
            provider=rec["provider"],
            params=rec.get("params") or {},
            metadata=rec.get("metadata") or {},
        )
        now = datetime.fromisoformat(rec["now"])
        user_turn = render_user_turn(intent, now)
        try:
            client.complete(system_prompt, user_turn)
            hits += 1
        except KeyError:
            pass
    return hits / len(intents)


_EXTERNAL_CACHES_PRESENT = (RESULTS_DIR / "llm-cache-naive.jsonl").exists() and (
    RESULTS_DIR / "llm-cache-aware.jsonl"
).exists()


@pytest.mark.skipif(
    not _EXTERNAL_CACHES_PRESENT,
    reason="results/llm-cache-{naive,aware}.jsonl not present (see results/llm-external.md)",
)
def test_llm_replay_naive_matches_external_cache():
    raw_constraints, _authority_map, intents = _load_pre_t05_fixture()
    holdout_ids = set(json.load(open(FIXTURES_DIR / "split.json"))["holdout"])
    holdout_constraints = [
        _constraint_from_dict(c) for c in raw_constraints if c["id"] in holdout_ids
    ]
    system_prompt = render_system_prompt(holdout_constraints)
    cache = _load_external_cache(RESULTS_DIR / "llm-cache-naive.jsonl")
    hit_rate = _replay_hit_rate(system_prompt, intents, cache)
    assert hit_rate >= 0.95, (
        f"only {hit_rate:.0%} of external llm-naive cache keys hit -- "
        "render_system_prompt has drifted from what produced "
        "results/llm-cache-naive.jsonl; see results/llm-external.md"
    )


@pytest.mark.skipif(
    not _EXTERNAL_CACHES_PRESENT,
    reason="results/llm-cache-{naive,aware}.jsonl not present (see results/llm-external.md)",
)
def test_llm_replay_aware_matches_external_cache():
    raw_constraints, authority_map, intents = _load_pre_t05_fixture()
    holdout_ids = set(json.load(open(FIXTURES_DIR / "split.json"))["holdout"])
    holdout_constraints = [
        _constraint_from_dict(c) for c in raw_constraints if c["id"] in holdout_ids
    ]
    system_prompt = AwarePromptBuilder(holdout_constraints, authority_map).render_system_prompt()
    cache = _load_external_cache(RESULTS_DIR / "llm-cache-aware.jsonl")
    hit_rate = _replay_hit_rate(system_prompt, intents, cache)
    assert hit_rate >= 0.95, (
        f"only {hit_rate:.0%} of external llm-aware cache keys hit -- "
        "AwarePromptBuilder has drifted from what produced "
        "results/llm-cache-aware.jsonl; see results/llm-external.md"
    )
