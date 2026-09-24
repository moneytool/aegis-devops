"""Tests for the baseline verifiers (PLAN.md §4 Week 7-8)."""

import json
import subprocess
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from aegis_core.baselines.external import (
    ClaudeCliAuthError,
    ClaudeCliClient,
    CodexCliClient,
    OllamaClient,
    RetryingClient,
    _last_verdict_line,
    _sum_token_usage,
    probe_codex_models,
)
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


# ---------------------------------------------------------------------------
# CodexCliClient (aegis_core.baselines.external) -- mocked subprocess only,
# no test here ever invokes a real `codex` binary.
# ---------------------------------------------------------------------------


def test_last_verdict_line_ignores_echoed_prompt_and_takes_the_last_match():
    # The system prompt itself contains the words ALLOW/BLOCK/ESCALATE
    # (it's instructing the model to use them), so a first-match search
    # over the full echoed stdout would find the wrong occurrence. The
    # real answer, per PLAN, is duplicated: once right after `codex`, once
    # again after `tokens used` / a token count.
    stdout = (
        "user\n"
        "Respond with exactly one line containing only one of: ALLOW, BLOCK, "
        "ESCALATE.\n\n"
        "warning: Code Mode is unavailable because failed to spawn code-mode "
        "host.\n"
        "codex\n"
        "BLOCK\n"
        "tokens used\n"
        "1,234\n"
        "BLOCK\n"
    )
    assert _last_verdict_line(stdout) == "BLOCK"


def test_last_verdict_line_returns_full_text_when_unparseable():
    assert _last_verdict_line("I cannot determine this.") == "I cannot determine this."


def _fake_run_writing_last_message(last_message: str, stdout: str, returncode: int = 0):
    def fake_run(args, input, capture_output, timeout):
        idx = args.index("--output-last-message")
        Path(args[idx + 1]).write_text(last_message)
        return subprocess.CompletedProcess(args, returncode, stdout=stdout.encode(), stderr=b"")

    return fake_run


def test_codex_client_prefers_output_last_message_file(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/codex")
    stdout = (
        "OpenAI Codex v0.155.0-alpha.9.2\n--------\nmodel: gpt-6-astra\n--------\n"
        "user\n...\n"
        "codex\nALLOW\ntokens used\n2,033\nALLOW\n"
    )
    monkeypatch.setattr(
        "aegis_core.baselines.external.subprocess.run",
        _fake_run_writing_last_message("ALLOW\n", stdout),
    )
    client = CodexCliClient()
    result = client.complete("system prompt", "user turn")
    assert result == "ALLOW"
    assert client.resolved_model == "gpt-6-astra"
    assert client.last_tokens_used == 2033


def test_codex_client_falls_back_to_stdout_when_last_message_file_missing(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/codex")
    stdout = (
        "OpenAI Codex v0.155.0-alpha.9.2\n--------\nmodel: gpt-6-astra\n--------\n"
        "user\nRespond with exactly one of: ALLOW, BLOCK, ESCALATE.\n\n"
        "warning: Code Mode is unavailable.\n"
        "codex\nESCALATE\ntokens used\n1,500\nESCALATE\n"
    )

    def fake_run(args, input, capture_output, timeout):
        # Deliberately never write to the --output-last-message path.
        return subprocess.CompletedProcess(args, 0, stdout=stdout.encode(), stderr=b"")

    monkeypatch.setattr("aegis_core.baselines.external.subprocess.run", fake_run)
    client = CodexCliClient()
    result = client.complete("system prompt", "user turn")
    assert result == "ESCALATE"
    assert client.resolved_model == "gpt-6-astra"
    assert client.last_tokens_used == 1500


def test_codex_client_raises_on_timeout(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/codex")

    def fake_run(args, input, capture_output, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr("aegis_core.baselines.external.subprocess.run", fake_run)
    client = CodexCliClient(timeout_s=1)
    with pytest.raises(RuntimeError, match="timed out"):
        client.complete("system prompt", "user turn")


def test_codex_client_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: None)
    client = CodexCliClient()
    assert client.available is False
    with pytest.raises(RuntimeError, match="PATH"):
        client.complete("system prompt", "user turn")


def test_probe_codex_models_returns_first_working_candidate(monkeypatch):
    tried: list[str | None] = []

    def fake_run_once(self, prompt):
        tried.append(self.model)
        if self.model == "o4-mini":
            return "ALLOW"
        raise RuntimeError(f"'{self.model}' model is not supported")

    monkeypatch.setattr(CodexCliClient, "_run_once", fake_run_once)
    resolved = probe_codex_models(
        candidates=("gpt-5.1-codex-mini", "gpt-5-mini", "o4-mini", "gpt-5.1-codex", None),
        timeout_s=1,
    )
    assert resolved == "o4-mini"
    assert tried == ["gpt-5.1-codex-mini", "gpt-5-mini", "o4-mini"]


def test_probe_codex_models_returns_none_when_every_candidate_fails(monkeypatch):
    def fake_run_once(self, prompt):
        raise RuntimeError("not supported")

    monkeypatch.setattr(CodexCliClient, "_run_once", fake_run_once)
    resolved = probe_codex_models(candidates=("candidate-a", "candidate-b"), timeout_s=1)
    assert resolved is None


# ---------------------------------------------------------------------------
# OllamaClient -- mocked urllib only, no test here talks to a real server.
# ---------------------------------------------------------------------------


class _FakeHttpResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self):
        return self._body


def test_ollama_client_parses_json_response_and_records_token_counts(monkeypatch):
    body = json.dumps(
        {
            "model": "mistral:latest",
            "response": "ALLOW",
            "done": True,
            "prompt_eval_count": 13842,
            "eval_count": 3,
        }
    ).encode("utf-8")

    def fake_urlopen(req, timeout=None):
        return _FakeHttpResponse(body)

    monkeypatch.setattr("aegis_core.baselines.external.urllib.request.urlopen", fake_urlopen)
    client = OllamaClient()
    result = client.complete("system prompt", "user turn")
    assert result == "ALLOW"
    assert client.last_prompt_tokens == 13842
    assert client.last_eval_tokens == 3


def test_ollama_client_raises_when_server_unreachable(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("aegis_core.baselines.external.urllib.request.urlopen", fake_urlopen)
    client = OllamaClient()
    with pytest.raises(RuntimeError, match="could not reach"):
        client.complete("system prompt", "user turn")
    assert client.available is False


# ---------------------------------------------------------------------------
# ClaudeCliClient (aegis_core.baselines.external) -- mocked subprocess only,
# no test here ever invokes a real `claude` binary.
# ---------------------------------------------------------------------------


def _fake_claude_run(envelope: dict, returncode: int = 0):
    def fake_run(args, input, capture_output, timeout):
        return subprocess.CompletedProcess(
            args, returncode, stdout=json.dumps(envelope).encode("utf-8"), stderr=b""
        )

    return fake_run


def test_claude_cli_client_parses_json_envelope_and_records_usage(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/claude")
    envelope = {
        "result": "BLOCK\ncitations: c-1",
        "is_error": False,
        "duration_ms": 4321,
        "duration_api_ms": 4000,
        "num_turns": 1,
        "modelUsage": {
            "claude-haiku-4-5-20251001": {
                "inputTokens": 23700,
                "outputTokens": 12,
                "cacheReadInputTokens": 0,
            }
        },
        "session_id": "abc-123",
        "stop_reason": "end_turn",
        "subtype": "success",
        "permission_denials": [],
    }
    monkeypatch.setattr(
        "aegis_core.baselines.external.subprocess.run", _fake_claude_run(envelope)
    )
    client = ClaudeCliClient(model="haiku")
    result = client.complete("system prompt", "user turn")
    assert result == "BLOCK\ncitations: c-1"
    assert client.last_tokens_used == 23712
    assert client.last_session_id == "abc-123"
    assert client.last_num_turns == 1


def test_claude_cli_client_raises_clear_auth_error_on_expired_oauth(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/claude")
    envelope = {
        "result": (
            "API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\","
            "\"message\":\"OAuth access token has expired. Re-authenticate to continue.\"}}"
        ),
        "is_error": True,
        "duration_ms": 182000,
        "num_turns": 0,
        "modelUsage": {},
        "session_id": "abc-123",
        "stop_reason": None,
        "subtype": "error_during_execution",
        "permission_denials": [],
    }
    monkeypatch.setattr(
        "aegis_core.baselines.external.subprocess.run", _fake_claude_run(envelope)
    )
    client = ClaudeCliClient(model="haiku")
    with pytest.raises(ClaudeCliAuthError, match="claude login"):
        client.complete("system prompt", "user turn")


def test_claude_cli_client_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: None)
    client = ClaudeCliClient()
    assert client.available is False
    with pytest.raises(RuntimeError, match="PATH"):
        client.complete("system prompt", "user turn")


def test_claude_cli_client_raises_on_timeout(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/claude")

    def fake_run(args, input, capture_output, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr("aegis_core.baselines.external.subprocess.run", fake_run)
    client = ClaudeCliClient(timeout_s=1)
    with pytest.raises(RuntimeError, match="timed out"):
        client.complete("system prompt", "user turn")


def test_claude_cli_client_non_json_stdout_raises_runtime_error(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/claude")

    def fake_run(args, input, capture_output, timeout):
        return subprocess.CompletedProcess(args, 1, stdout=b"not json", stderr=b"some stderr")

    monkeypatch.setattr("aegis_core.baselines.external.subprocess.run", fake_run)
    client = ClaudeCliClient()
    with pytest.raises(RuntimeError, match="non-JSON"):
        client.complete("system prompt", "user turn")


def test_sum_token_usage_handles_normal_shape():
    usage = {
        "claude-haiku-4-5-20251001": {"inputTokens": 100, "outputTokens": 20},
        "claude-sonnet-5": {"inputTokens": 5, "outputTokens": 1},
    }
    assert _sum_token_usage(usage) == 126


def test_sum_token_usage_handles_absent_and_unexpected_shapes():
    assert _sum_token_usage(None) is None
    assert _sum_token_usage({}) is None
    assert _sum_token_usage("not a dict") is None
    assert _sum_token_usage({"model": "not a dict either"}) is None
    assert _sum_token_usage({"model": {"tokensUsed": "a lot"}}) is None  # non-numeric ignored
    assert _sum_token_usage({"model": {"inputTokens": 5, "extra": "ignored"}}) == 5


def test_retrying_client_does_not_retry_claude_cli_auth_error(monkeypatch):
    monkeypatch.setattr("aegis_core.baselines.external.shutil.which", lambda _: "/usr/bin/claude")
    calls = {"n": 0}

    def fake_run(args, input, capture_output, timeout):
        calls["n"] += 1
        envelope = {
            "result": "401 OAuth access token has expired. Re-authenticate to continue.",
            "is_error": True,
        }
        return subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(envelope).encode("utf-8"), stderr=b""
        )

    monkeypatch.setattr("aegis_core.baselines.external.subprocess.run", fake_run)
    inner = ClaudeCliClient(model="haiku")
    wrapped = RetryingClient(inner, retries=2)
    with pytest.raises(ClaudeCliAuthError, match="claude login"):
        wrapped.complete("system prompt", "user turn")
    # No retry: exactly one subprocess invocation, not up to three.
    assert calls["n"] == 1


def test_claude_cli_cache_key_includes_model(tmp_path):
    cache_path = tmp_path / "claude-cli-cache.jsonl"
    RecordingClient(_SucceedsClient("ALLOW"), cache_path, model="haiku").complete(
        "same system prompt", "same user turn"
    )
    RecordingClient(_SucceedsClient("BLOCK"), cache_path, model="sonnet").complete(
        "same system prompt", "same user turn"
    )
    lines = cache_path.read_text().strip().splitlines()
    keys = {json.loads(line)["key"] for line in lines}
    assert len(keys) == 2

    assert (
        ReplayClient(cache_path, model="haiku").complete("same system prompt", "same user turn")
        == "ALLOW"
    )
    assert (
        ReplayClient(cache_path, model="sonnet").complete("same system prompt", "same user turn")
        == "BLOCK"
    )


# ---------------------------------------------------------------------------
# RetryingClient -- retry-once-then-unparseable wrapping used by
# scripts/benchmark.py around CodexCliClient/OllamaClient.
# ---------------------------------------------------------------------------


class _AlwaysFailsClient:
    def __init__(self):
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        raise RuntimeError("boom")


class _SucceedsClient:
    def __init__(self, response: str):
        self.response = response
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        return self.response


def test_retrying_client_degrades_to_empty_string_after_one_retry():
    inner = _AlwaysFailsClient()
    wrapped = RetryingClient(inner, retries=1)
    result = wrapped.complete("system", "user")
    assert result == ""
    assert inner.calls == 2  # original attempt + one retry
    # An empty response is exactly what parse_llm_response treats as
    # ESCALATE + "unparseable" -- the semantics PLAN wants for a
    # persistently failing call rather than crashing the benchmark loop.
    verdict, citations, discarded = parse_llm_response(result)
    assert verdict == "ESCALATE"
    assert discarded == [{"id": "-", "reason": "unparseable"}]


def test_retrying_client_returns_first_success_without_retrying():
    inner = _SucceedsClient("ALLOW")
    wrapped = RetryingClient(inner)
    assert wrapped.complete("system", "user") == "ALLOW"
    assert inner.calls == 1


# ---------------------------------------------------------------------------
# Cache key includes the model name (RecordingClient/ReplayClient), so
# codex/ollama runs recorded against different models into the same cache
# file never collide.
# ---------------------------------------------------------------------------


def test_cache_key_includes_model_name_and_avoids_collisions(tmp_path):
    cache_path = tmp_path / "shared-cache.jsonl"

    RecordingClient(_SucceedsClient("ALLOW"), cache_path, model="model-a").complete(
        "same system prompt", "same user turn"
    )
    RecordingClient(_SucceedsClient("BLOCK"), cache_path, model="model-b").complete(
        "same system prompt", "same user turn"
    )

    lines = cache_path.read_text().strip().splitlines()
    assert len(lines) == 2
    keys = {json.loads(line)["key"] for line in lines}
    assert len(keys) == 2  # distinct keys despite identical (system, user)

    replay_a = ReplayClient(cache_path, model="model-a")
    replay_b = ReplayClient(cache_path, model="model-b")
    assert replay_a.complete("same system prompt", "same user turn") == "ALLOW"
    assert replay_b.complete("same system prompt", "same user turn") == "BLOCK"

    # A replay client with no model set (the pre-existing llm-naive/aware
    # behaviour) must not accidentally match a model-tagged entry.
    replay_untagged = ReplayClient(cache_path)
    with pytest.raises(KeyError):
        replay_untagged.complete("same system prompt", "same user turn")
