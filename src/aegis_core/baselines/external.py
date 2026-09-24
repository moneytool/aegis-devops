"""Three more LLM baseline clients (REVIEW-4 follow-up, then extended):
``codex exec`` as an agent-harness self-check, a local ``ollama`` model,
and ``claude -p`` (the Claude Code CLI) as a second agent-harness
self-check, all implementing the same ``aegis_core.baselines.llm.LLMClient``
protocol as ``AnthropicClient`` so they plug into the existing
``LLMVerifier`` / ``RecordingClient`` / ``ReplayClient`` machinery
unchanged.

Both baselines are fed the SAME naive prompt ``llm-naive`` uses
(``aegis_core.baselines.llm.render_system_prompt``) — but over the
**holdout constraint split** (``data/corpus/split.json["holdout"]``, 100
constraints), not the full 500-constraint corpus. The full corpus renders
to ~69,000 prompt tokens, which is infeasible for a local 7B model's
context window and prohibitively slow/expensive to probe repeatedly
against an agent harness; the 100-constraint holdout subset (~14k tokens)
is also what the pinned ``results/llm-external.md`` Claude rows were
measured against, so these two new rows stay comparable to that table.
Callers MUST pass that subset explicitly (see ``scripts/benchmark.py``'s
verifier construction) — there is no silent default to "all constraints"
here.

None of these clients is a raw completion endpoint in the way
``AnthropicClient`` is:

* Codex is an **agent harness** wrapped around a model (it can plan, use
  tools, spawn a sandboxed shell) even when invoked read-only for a single
  turn — the ``notes`` column in the benchmark report must say
  "agent harness (codex exec)", not "model", for this row.
* Ollama is a genuinely local, low-context, unaligned-for-this-task 7B
  model — it may not reliably follow the ALLOW/BLOCK/ESCALATE format at
  all (see ``tests/test_baselines.py`` and the README for the measured
  answer).
* ``claude -p`` (the Claude Code CLI) is likewise an **agent harness**, not
  a raw completion endpoint, even with ``--allowedTools ""`` denying it any
  tool use for the single turn — the ``notes`` column says "agent harness
  (claude -p)", not "model", for this row too.
"""

import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .llm import _VALID_VERDICTS, LLMClient  # noqa: F401  (re-exported for callers)

# ---------------------------------------------------------------------------
# Codex CLI
# ---------------------------------------------------------------------------

# Tried in order by ``probe_codex_models``; the last entry (``None``) means
# "don't pass -m at all, use whatever `codex exec`'s own config resolves
# to" -- the configured default at the time this was written is
# ``gpt-6-astra``. Passing an invalid ``-m`` name does not fail fast: the
# CLI accepts it, prints an immediate `ERROR: ... not supported` line to
# stdout, and then hangs rather than exiting -- so every candidate here
# MUST be probed under a hard timeout, never called without one.
CODEX_MODEL_CANDIDATES: tuple[str | None, ...] = (
    "gpt-5.1-codex-mini",
    "gpt-5-mini",
    "o4-mini",
    "gpt-5.1-codex",
    None,
)

_CODEX_BASE_ARGS = [
    "codex",
    "exec",
    "--ignore-user-config",
    "--skip-git-repo-check",
    "--ephemeral",
    "-s",
    "read-only",
]

_VERDICT_LINE_RE = re.compile(r"^\s*(ALLOW|BLOCK|ESCALATE)\b.*$", re.IGNORECASE | re.MULTILINE)
_MODEL_BANNER_RE = re.compile(r"^model:\s*(\S+)\s*$", re.MULTILINE)
_TOKENS_USED_RE = re.compile(r"tokens used\s*\n\s*([\d,]+)", re.IGNORECASE)


def _last_verdict_line(text: str) -> str:
    """Codex's stdout (when not using ``--output-last-message``) echoes the
    prompt, then a `codex` turn, then `tokens used` / a number, then the
    answer AGAIN. A naive substring search over that text would match
    ALLOW/BLOCK/ESCALATE inside the echoed system prompt (which literally
    instructs the model with those words) before it ever reaches the real
    answer. Take the LAST line that starts with a verdict token instead."""
    matches = [m.group(0).strip() for m in _VERDICT_LINE_RE.finditer(text or "")]
    return matches[-1] if matches else (text or "")


class CodexCliClient:
    """Shells out to ``codex exec`` for a single, non-interactive,
    read-only turn. Codex has no system-turn concept, so ``system`` and
    ``user`` are concatenated into one stdin prompt.

    Prefers ``--output-last-message <file>`` (a clean, single-message
    dump of the agent's final answer) over parsing the human-formatted
    stdout; falls back to robust stdout parsing (see ``_last_verdict_line``)
    if that file is missing or empty for any reason.
    """

    stub = False

    def __init__(self, model: str | None = None, timeout_s: int = 120):
        self.model = model
        self.timeout_s = timeout_s
        # Populated after each call from the `model: <name>` banner Codex
        # prints, so callers can record what actually answered even when
        # ``model`` was left ``None`` (server/account default).
        self.resolved_model: str | None = model
        self.last_tokens_used: int | None = None

    @property
    def available(self) -> bool:
        return shutil.which("codex") is not None

    def _run_once(self, prompt: str) -> str:
        if not self.available:
            raise RuntimeError(
                "CodexCliClient requires the `codex` CLI on PATH (not found)."
            )
        args = list(_CODEX_BASE_ARGS)
        if self.model:
            args += ["-m", self.model]
        with tempfile.TemporaryDirectory() as tmpdir:
            last_message_path = Path(tmpdir) / "last-message.txt"
            args += ["--output-last-message", str(last_message_path), "-"]
            try:
                proc = subprocess.run(
                    args,
                    input=prompt.encode("utf-8"),
                    capture_output=True,
                    timeout=self.timeout_s,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    "CodexCliClient requires the `codex` CLI on PATH (not found)."
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"codex exec timed out after {self.timeout_s}s "
                    f"(model={self.model!r}) -- an invalid -m value hangs "
                    "instead of erroring; probe candidates first."
                ) from exc

            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            # CLI-level failures (e.g. a ChatGPT-account usage-limit
            # rejection: "You've hit your usage limit... try again at
            # <time>") land on stderr, not stdout -- combine both so a
            # quota error doesn't silently look like an empty response.
            combined = stdout + "\n" + stderr if stderr else stdout

            model_match = _MODEL_BANNER_RE.search(combined)
            if model_match:
                self.resolved_model = model_match.group(1)
            tokens_match = _TOKENS_USED_RE.search(combined)
            if tokens_match:
                self.last_tokens_used = int(tokens_match.group(1).replace(",", ""))

            if last_message_path.exists():
                last_message = last_message_path.read_text(encoding="utf-8").strip()
                if last_message:
                    return _last_verdict_line(last_message) or last_message

            # Fall back to parsing the raw, human-formatted stdout+stderr.
            return _last_verdict_line(combined)

    def complete(self, system: str, user: str) -> str:
        """Raises ``RuntimeError`` when ``codex`` is missing from PATH or
        the call times out (a single attempt -- see ``RetryingClient`` for
        the retry-then-degrade-to-unparseable wrapping the benchmark run
        uses over this)."""
        prompt = system + "\n\n" + user
        return self._run_once(prompt)


def probe_codex_models(
    candidates: tuple[str | None, ...] = CODEX_MODEL_CANDIDATES,
    timeout_s: int = 60,
) -> str | None:
    """Tries each candidate model against a trivial smoke prompt under a
    hard timeout, returning the first one that answers cleanly. Returns
    ``None`` if every named candidate fails (meaning: fall back to no
    ``-m`` flag at all, i.e. whatever `codex exec` defaults to for this
    account). Never leaves a hung subprocess behind: every attempt runs
    under ``CodexCliClient(timeout_s=timeout_s)``, which kills the
    subprocess via ``subprocess.run(timeout=...)``.

    Call this from ``scripts/probe_codex_models.py``, not from tests or
    the benchmark hot path -- probing every candidate that fails costs up
    to ``len(candidates) * timeout_s`` seconds.
    """
    for model in candidates:
        client = CodexCliClient(model=model, timeout_s=timeout_s)
        try:
            response = client._run_once(
                "You are a smoke test. Reply with exactly one word: ALLOW"
            )
        except RuntimeError:
            continue
        if _VERDICT_LINE_RE.match(response or ""):
            return model
    return None


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


class OllamaClient:
    """Talks to a local Ollama server's HTTP API
    (``POST /api/generate``) -- structured JSON in and out, reproducible
    with ``temperature=0, seed=0``, no CLI parsing involved.
    """

    stub = False

    def __init__(
        self,
        model: str = "mistral:latest",
        host: str = "http://localhost:11434",
        timeout_s: int = 180,
        num_ctx: int = 32768,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.timeout_s = timeout_s
        self.num_ctx = num_ctx
        # Populated after each call for the benchmark report's token/latency
        # accounting (see `results/benchmark.md`'s `codex`/`ollama` notes).
        self.last_prompt_tokens: int | None = None
        self.last_eval_tokens: int | None = None

    @property
    def available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except (urllib.error.URLError, OSError):
            return False

    def _generate(self, system: str, prompt: str) -> dict:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": 0,
                "seed": 0,
                "num_ctx": self.num_ctx,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            self.last_prompt_tokens = result.get("prompt_eval_count")
            self.last_eval_tokens = result.get("eval_count")
            return result
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"OllamaClient could not reach {self.host} ({exc}). "
                "Is `ollama serve` running?"
            ) from exc

    def complete(self, system: str, user: str) -> str:
        """Raises ``RuntimeError`` when the Ollama server isn't reachable
        (a single attempt -- see ``RetryingClient`` for the retry-then-
        degrade-to-unparseable wrapping the benchmark run uses over
        this)."""
        result = self._generate(system, user)
        return result.get("response", "")


# ---------------------------------------------------------------------------
# Claude Code CLI (`claude -p`)
# ---------------------------------------------------------------------------

# Matches the specific "OAuth token expired" failure mode: `claude -p`
# returns exit code 0 with `is_error: true` and a `result` string like
# "... 401 ... OAuth access token has expired. Re-authenticate to continue."
# This is NOT a model verdict and NOT a transient failure -- retrying it
# just re-runs the CLI's own ~180s internal retry loop for the same
# guaranteed failure. Detected on `is_error` being true AND the result text
# matching one of these tokens.
_AUTH_FAILURE_RE = re.compile(r"\b(401|authenticate|oauth)\b", re.IGNORECASE)


class ClaudeCliAuthError(RuntimeError):
    """Raised when ``claude -p`` reports ``is_error: true`` with a result
    that looks like an expired/missing OAuth session (see
    ``_AUTH_FAILURE_RE``). A ``RuntimeError`` subclass so existing
    ``except RuntimeError`` call sites still catch it, but
    ``RetryingClient`` special-cases it to never retry (see below) and
    ``scripts/benchmark.py`` special-cases it to skip the row cleanly with
    an instruction to run ``claude login``, rather than crash the whole
    benchmark run or waste minutes retrying a guaranteed failure."""


def _sum_token_usage(model_usage: object) -> int | None:
    """Defensively sums every numeric ``*token*`` field across every model
    entry in the CLI's ``modelUsage`` object. ``modelUsage`` is a dict keyed
    by model name (e.g. ``{"claude-haiku-4-5-20251001": {"inputTokens":
    ..., "outputTokens": ...}}``) but its exact shape is not pinned by any
    spec we control, so this never assumes specific key names beyond
    "contains the substring 'token'" and tolerates ``None``, a non-dict, or
    per-model entries that aren't dicts -- returning ``None`` (rather than
    0) when nothing token-shaped was found at all, so callers can tell "no
    usage info" apart from "usage info said zero"."""
    if not isinstance(model_usage, dict):
        return None
    total = 0
    found = False
    for usage in model_usage.values():
        if not isinstance(usage, dict):
            continue
        for key, value in usage.items():
            if "token" in key.lower() and isinstance(value, (int, float)) and not isinstance(
                value, bool
            ):
                total += value
                found = True
    return total if found else None


class ClaudeCliClient:
    """Shells out to ``claude -p`` (the Claude Code CLI) for a single,
    non-interactive turn, with all tool use denied (``--allowedTools ""``)
    and no session persisted. Like ``CodexCliClient``, ``claude`` has no
    system-turn concept for this invocation style, so ``system`` and
    ``user`` are concatenated into one stdin prompt.

    Invocation (see README "Benchmark" for the measured shape of the
    response)::

        claude -p --model <model> --output-format json \\
            --no-session-persistence --allowedTools "" < prompt.txt

    ``--output-format json`` returns a single JSON object on stdout whose
    ``result`` field is the assistant's text -- that's what
    ``aegis_core.baselines.llm.parse_llm_response`` extracts the
    ALLOW/BLOCK/ESCALATE verdict from, exactly as it does for every other
    ``LLMClient``. Token counts (when available) are read defensively from
    the ``modelUsage`` dict (see ``_sum_token_usage``) and stashed on
    ``last_tokens_used``/``last_model_usage`` for the benchmark's cost
    accounting, mirroring ``CodexCliClient.last_tokens_used``.
    """

    stub = False

    def __init__(self, model: str = "haiku", timeout_s: int = 300, binary: str = "claude"):
        self.model = model
        self.timeout_s = timeout_s
        self.binary = binary
        self.last_model_usage: dict | None = None
        self.last_tokens_used: int | None = None
        self.last_session_id: str | None = None
        self.last_num_turns: int | None = None

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _run_once(self, prompt: str) -> str:
        if not self.available:
            raise RuntimeError(
                f"ClaudeCliClient requires the `{self.binary}` CLI on PATH (not found)."
            )
        args = [
            self.binary,
            "-p",
            "--model",
            self.model,
            "--output-format",
            "json",
            "--no-session-persistence",
            "--allowedTools",
            "",
        ]
        try:
            proc = subprocess.run(
                args,
                input=prompt.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_s,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"ClaudeCliClient requires the `{self.binary}` CLI on PATH (not found)."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"claude -p timed out after {self.timeout_s}s (model={self.model!r})."
            ) from exc

        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"claude -p returned non-JSON stdout (exit={proc.returncode}): "
                f"stdout={stdout[:300]!r} stderr={stderr[:300]!r}"
            ) from exc

        result_text = envelope.get("result") or ""
        is_error = bool(envelope.get("is_error"))
        if is_error and _AUTH_FAILURE_RE.search(result_text):
            raise ClaudeCliAuthError("claude CLI is not authenticated: run 'claude login'")

        self.last_model_usage = envelope.get("modelUsage")
        self.last_tokens_used = _sum_token_usage(self.last_model_usage)
        self.last_session_id = envelope.get("session_id")
        self.last_num_turns = envelope.get("num_turns")
        return result_text

    def complete(self, system: str, user: str) -> str:
        """Raises ``RuntimeError`` when ``claude`` is missing from PATH or
        the call times out, and the narrower ``ClaudeCliAuthError`` when the
        CLI's own OAuth session has expired (a single attempt -- see
        ``RetryingClient`` for the retry-then-degrade-to-unparseable
        wrapping the benchmark run uses over this, which never retries a
        ``ClaudeCliAuthError``)."""
        prompt = system + "\n\n" + user
        return self._run_once(prompt)


class RetryingClient:
    """Wraps any ``LLMClient`` so one transient failure (a timeout, a
    dropped connection) doesn't crash a long benchmark run over a single
    flaky call: retries once, and if the retry also raises, degrades to an
    empty string rather than propagating -- ``parse_llm_response`` (see
    ``aegis_core.baselines.llm``) treats an empty/unparseable response as
    ESCALATE with a recorded ``"unparseable"`` discard, which is exactly
    the semantics ``scripts/benchmark.py`` wants for a persistently failing
    call.

    Kept separate from ``CodexCliClient``/``OllamaClient``/``ClaudeCliClient``
    themselves so each client's own ``complete()`` keeps a simple, directly
    testable contract (raise ``RuntimeError`` on failure); only the
    production benchmark run needs the retry-and-degrade behaviour.

    ``ClaudeCliAuthError`` (see above) is a deliberate exception to the
    retry-and-degrade contract: it means "this call is guaranteed to fail
    again, immediately, for a reason retrying cannot fix" (an expired OAuth
    session), not a transient error, so it is re-raised on the first
    attempt rather than retried -- retrying it would just re-run the CLI's
    own ~180s internal retry loop for the same guaranteed outcome.
    """

    stub = False

    def __init__(self, inner: LLMClient, retries: int = 1):
        self.inner = inner
        self.retries = retries

    def complete(self, system: str, user: str) -> str:
        attempts = self.retries + 1
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                return self.inner.complete(system, user)
            except ClaudeCliAuthError:
                raise
            except RuntimeError as exc:
                last_exc = exc
                continue
        assert last_exc is not None  # pragma: no cover - attempts >= 1 always runs the loop
        return ""
