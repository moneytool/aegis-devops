"""The budget cap inside ``aegis hook`` and ``aegis install`` (design v1.0 §6).

Each test runs the real hook against an ``aegis init`` policy directory with
a ``budget.yaml`` signed by the example key, and a synthetic Claude Code
transcript as the usage source (claude-opus-5-5: $4 per million input
tokens, so 250,000 input tokens is $1)."""

import json
from pathlib import Path

import pytest

from aegis_core.config import init_config_dir
from aegis_core.hook import install, main_install, run_hook
from aegis_core.signing import load_key, sign_file

SID = "sess-1"
MODEL = "claude-opus-5-5"
DAY = "2026-10-08"


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "CLAUDE_CONFIG_DIR",
                "CODEX_HOME", "AEGIS_CONFIG_DIR", "AEGIS_SIGNING_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    init_config_dir(project / ".aegis")
    return {"home": home, "project": project, "tmp": tmp_path}


def write_budget(env, text: str) -> Path:
    path = env["project"] / ".aegis" / "budget.yaml"
    path.write_text(text)
    sign_file(path, load_key(f"file:{env['project'] / '.aegis' / 'example-signing.key'}"))
    return path


BUDGET = "principal: admin\nunit: usd\nsession: {limit: 1.0, warn_at: 0.5}\n"


def transcript(env, input_tokens: int, sid: str = SID) -> Path:
    path = env["home"] / ".claude" / "projects" / "-project" / f"{sid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    recs = [{"type": "user", "sessionId": sid, "cwd": str(env["project"]),
             "timestamp": f"{DAY}T09:00:00Z"}]
    if input_tokens:
        recs.append({"type": "assistant", "sessionId": sid, "requestId": "r1",
                     "timestamp": f"{DAY}T09:01:00Z",
                     "message": {"id": "m1", "model": MODEL,
                                 "usage": {"input_tokens": input_tokens, "output_tokens": 0}}})
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return path


def call(env, tool="Edit", command=None, agent="claude", event=None, sid=SID, **extra):
    payload = {"session_id": sid, "cwd": str(env["project"]),
               "transcript_path": str(env["home"] / ".claude" / "projects" / "-project"
                                      / f"{sid}.jsonl"), **extra}
    if event:
        payload["hook_event_name"] = event
        payload["prompt"] = "hello"
    else:
        payload["tool_name"] = tool
        payload["tool_input"] = {"command": command} if command else {"file_path": "x"}
    return run_hook(agent, json.dumps(payload))


# --- no budget: unchanged behaviour -------------------------------------------------------


def test_without_a_budget_non_shell_tools_are_not_looked_at(env):
    transcript(env, 10_000_000)
    assert call(env) == (0, "", "")
    assert not (env["home"] / ".cache" / "aegis").exists()


# --- under, near and over the limit ---------------------------------------------------------


def test_under_the_warning_threshold_is_silent(env):
    write_budget(env, BUDGET)
    transcript(env, 25_000)                                   # $0.10
    assert call(env) == (0, "", "")


def test_crossing_the_warning_threshold_warns_once(env):
    write_budget(env, BUDGET)
    transcript(env, 150_000)                                  # $0.60 of $1.00
    code, out, _ = call(env)
    assert code == 0
    message = json.loads(out)["systemMessage"]
    assert "60%" in message and "$0.40 left" in message
    assert call(env) == (0, "", "")                           # once per session


def test_at_the_limit_every_tool_call_is_denied(env):
    write_budget(env, BUDGET)
    transcript(env, 300_000)                                  # $1.20
    for tool, command in (("Edit", None), ("Read", None), ("Bash", "ls -la")):
        code, out, err = call(env, tool=tool, command=command)
        assert code == 2
        decision = json.loads(out)["hookSpecificOutput"]
        assert decision["permissionDecision"] == "deny"
        assert "session limit reached" in err and "start a new session" in err
        assert "overshoot $0.20" in err


def test_a_policy_block_stands_whatever_the_budget(env):
    write_budget(env, BUDGET)
    transcript(env, 1_000)
    code, _, err = call(env, tool="Bash", command="kubectl delete namespace prod")
    assert code == 2 and "budget" not in err and "BLOCK" in err


# --- prompts --------------------------------------------------------------------------------


def test_a_new_prompt_over_the_limit_is_stopped(env):
    write_budget(env, BUDGET)
    transcript(env, 300_000)
    code, out, err = call(env, event="UserPromptSubmit")
    assert code == 2 and json.loads(out) == {"decision": "block", "reason": err}
    assert "session limit reached" in err


@pytest.mark.parametrize("agent,decision", [("claude", "block"), ("codex", "block"),
                                            ("gemini", "deny")])
def test_prompt_replies_in_each_agents_format(agent, decision):
    from aegis_core.hook import HookVerdict, render_prompt

    code, out, err = render_prompt(agent, HookVerdict("deny", "over"))
    assert (code, json.loads(out), err) == (2, {"decision": decision, "reason": "over"}, "over")
    assert render_prompt(agent, HookVerdict("allow"), "near") == (
        0, json.dumps({"systemMessage": "near"}), "")
    assert render_prompt(agent, HookVerdict("allow")) == (0, "", "")


def test_a_prompt_under_the_limit_passes_silently(env):
    write_budget(env, BUDGET)
    transcript(env, 1_000)
    assert call(env, event="UserPromptSubmit") == (0, "", "")


# --- failures -------------------------------------------------------------------------------


def test_an_unusable_budget_file_fails_closed(env):
    path = write_budget(env, BUDGET)
    path.write_text(BUDGET.replace("1.0", "1000"))           # edited after signing
    transcript(env, 1_000)
    code, _, err = call(env)
    assert code == 2 and "budget.yaml cannot be used" in err and "re-sign" in err


def test_an_unlocatable_session_warns_once_or_denies(env):
    write_budget(env, BUDGET)
    code, out, _ = call(env, sid="nobody")
    assert code == 0 and "not being measured" in json.loads(out)["systemMessage"]
    assert call(env, sid="nobody") == (0, "", "")
    write_budget(env, BUDGET + "on_unknown_log: deny\n")
    code, _, err = call(env, sid="nobody")
    assert code == 2 and "on_unknown_log: deny" in err


def test_unlisted_agents_are_not_measured(env):
    write_budget(env, BUDGET + "agents: [codex]\n")
    transcript(env, 300_000)
    assert call(env) == (0, "", "")


# --- warning channels -----------------------------------------------------------------------


def test_copilot_has_no_message_channel_so_its_warning_goes_to_stderr(env):
    from aegis_core.hook import _with_warning

    assert _with_warning("copilot", (0, "", ""), "aegis budget: 80%") == (
        0, "", "aegis budget: 80%")
    code, out, _ = _with_warning("opencode", (0, "", ""), "aegis budget: 80%")
    assert json.loads(out) == {"warning": "aegis budget: 80%"}
    code, out, _ = _with_warning("claude", (0, '{"hookSpecificOutput": {}}', ""), "w")
    assert json.loads(out) == {"hookSpecificOutput": {}, "systemMessage": "w"}
    assert _with_warning("claude", (2, "x", "y"), "w") == (2, "x", "y")


# --- install ----------------------------------------------------------------------------------


def _settings(env) -> dict:
    return json.loads((env["project"] / ".claude" / "settings.json").read_text())


def test_install_with_a_budget_widens_the_hook_and_adds_the_prompt_hook(env, capsys):
    write_budget(env, BUDGET)
    main_install("claude", user=False, project=str(env["project"]), remove=False)
    hooks = _settings(env)["hooks"]
    assert [e["matcher"] for e in hooks["PreToolUse"]] == ["*"]
    assert len(hooks["UserPromptSubmit"]) == 1
    assert "UserPromptSubmit stops new prompts" in capsys.readouterr().out
    # reinstalling without the budget narrows it again and drops the prompt hook
    main_install("claude", user=False, project=str(env["project"]), remove=False,
                 budget=False)
    hooks = _settings(env)["hooks"]
    assert [e["matcher"] for e in hooks["PreToolUse"]] == ["Bash"]
    assert "UserPromptSubmit" not in hooks
    install("claude", user=False, project=env["project"], remove=True)
    assert not (env["project"] / ".claude" / "settings.json").exists()


@pytest.mark.parametrize("agent,tool_event,matcher,prompt_event", [
    ("codex", "PreToolUse", ".*", "UserPromptSubmit"),
    ("gemini", "BeforeTool", ".*", "BeforeAgent"),
])
def test_install_budget_shapes_for_codex_and_gemini(env, agent, tool_event, matcher,
                                                    prompt_event):
    path = install(agent, user=False, project=env["project"], budget=True)
    hooks = json.loads(path.read_text())["hooks"]
    assert [e["matcher"] for e in hooks[tool_event]] == [matcher]
    assert len(hooks[prompt_event]) == 1


def test_install_keeps_other_hooks_when_switching_budget_on_and_off(env):
    settings = env["project"] / ".claude" / "settings.json"
    settings.parent.mkdir()
    mine = {"type": "command", "command": "echo mine"}
    settings.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [mine]}]}}))
    install("claude", user=False, project=env["project"], budget=True)
    install("claude", user=False, project=env["project"], budget=False)
    assert _settings(env)["hooks"]["UserPromptSubmit"] == [{"hooks": [mine]}]
