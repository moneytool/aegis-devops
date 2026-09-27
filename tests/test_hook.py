"""Tests for the agent hook adapter (``aegis hook <agent>`` / ``aegis install``).

Isolation matters here: an agent hook runs in *every* project the agent is
opened in, so a test that leaks the real ``$HOME`` (or a real ``.aegis`` /
``AEGIS_CONFIG_DIR``) could see this repo's own policy, or the developer's
real ``~/.config/aegis``. Every test below points ``HOME`` at a tmp_path,
clears the project-dir env vars the agents set, and chdirs into a throwaway
project directory before touching ``aegis_core.hook``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core import cli as cli_module
from aegis_core import config as config_module
from aegis_core import hook

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_SIGNING_KEY_PATH = REPO_ROOT / "data" / "example-signing.key"


@pytest.fixture(autouse=True)
def _signing_key_in_env(monkeypatch):
    """Every policy file 'aegis init' writes here is pre-signed with the
    packaged example key; the CLI (and this hook, which shells out to it)
    needs AEGIS_SIGNING_KEY set to verify it, same convention as
    tests/test_cli.py."""
    from aegis_core.signing import load_key

    key = load_key(f"file:{EXAMPLE_SIGNING_KEY_PATH}")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())

# A command the packaged example policy (data/constraints.example.yaml, the
# same files ``aegis init`` copies) marks ESCALATE, with no --now dependence:
# "escalate-configmap-changes" fires on any configmap delete/update.
ESCALATE_COMMAND = "kubectl delete configmap/foo -n default"

BLOCK_COMMAND = "kubectl delete nodes --all"
BLOCK_REASON_SNIPPET = "no-delete-nodes"


# --- isolation & setup helpers -----------------------------------------------------


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """HOME -> tmp, every project-dir env var cleared, cwd -> a fresh project
    dir. Returns (home, project)."""
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(config_module.CONFIG_ENV_VAR, raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("COPILOT_PROJECT_DIR", raising=False)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    monkeypatch.chdir(project)
    return home, project


def opt_in(directory: Path) -> Path:
    """``aegis init <directory>/.aegis``; returns the .aegis dir."""
    config_dir = directory / ".aegis"
    rc = cli_module.main(["init", str(config_dir)])
    assert rc == 0
    return config_dir


# --- payload builders ---------------------------------------------------------------


def claude_payload(command: str | None, cwd: str | None = None, tool_name: str = "Bash") -> dict:
    payload = {
        "session_id": "sess-1",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command} if command is not None else {},
    }
    if cwd is not None:
        payload["cwd"] = cwd
    return payload


def copilot_payload(command: str | None, cwd: str | None = None, *, args_as_string: bool = False,
                     tool_name: str = "bash") -> dict:
    args = {"command": command, "description": "run it"} if command is not None else {}
    payload = {
        "sessionId": "9b7c1234",
        "timestamp": 1790520881397,
        "toolName": tool_name,
        "toolArgs": json.dumps(args) if args_as_string else args,
    }
    if cwd is not None:
        payload["cwd"] = cwd
    return payload


def cursor_payload(command: str | None, cwd: str | None = None) -> dict:
    payload = {"conversation_id": "c-1", "generation_id": "g-1"}
    if command is not None:
        payload["command"] = command
    if cwd is not None:
        payload["cwd"] = cwd
    return payload


AGENT_PAYLOAD_BUILDERS = {
    "claude": claude_payload,
    "codex": claude_payload,
    "vscode": claude_payload,
    "copilot": copilot_payload,
    "cursor": cursor_payload,
}


def payload_for(agent: str, command: str | None, cwd: str | None = None) -> dict:
    return AGENT_PAYLOAD_BUILDERS[agent](command, cwd)


def run(agent: str, payload: dict, **kwargs) -> tuple[int, str, str]:
    return hook.run_hook(agent, json.dumps(payload), **kwargs)


# --- 1. not opted in ------------------------------------------------------------


@pytest.mark.parametrize("agent", hook.AGENTS)
@pytest.mark.parametrize("command", ["ls", BLOCK_COMMAND])
def test_not_opted_in_always_allows(isolated, agent, command):
    code, out, err = run(agent, payload_for(agent, command))
    assert code == 0
    assert out == ""
    assert err == ""


# --- 2. opt-in sources ------------------------------------------------------------


def test_opt_in_project_dot_aegis(isolated):
    _home, project = isolated
    opt_in(project)
    code, _out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


def test_opt_in_parent_dot_aegis(isolated):
    _home, project = isolated
    opt_in(project)
    sub = project / "sub" / "dir"
    sub.mkdir(parents=True)
    code, _out, err = run("claude", payload_for("claude", BLOCK_COMMAND, cwd=str(sub)))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


def test_opt_in_via_config_env_var(monkeypatch, isolated):
    _home, project = isolated
    elsewhere = project.parent / "elsewhere"
    config_dir = opt_in(elsewhere)
    monkeypatch.setenv(config_module.CONFIG_ENV_VAR, str(config_dir))
    code, _out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


def test_opt_in_via_user_config_dir(isolated):
    home, _project = isolated
    user_config = home / ".config" / "aegis"
    rc = cli_module.main(["init", str(user_config)])
    assert rc == 0
    code, _out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


def test_data_constraints_yaml_in_project_is_not_an_opt_in_signal(isolated):
    """A repo that ships a data/constraints.yaml (like this one) has not
    asked to be gated -- unlike 'aegis check', the hook does not treat
    $PWD/data as an opt-in source."""
    _home, project = isolated
    data_dir = project / "data"
    data_dir.mkdir()
    (data_dir / "constraints.yaml").write_text("constraints: []\n")
    code, out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 0
    assert out == ""
    assert err == ""


# --- 3. decisions once opted in --------------------------------------------------


@pytest.fixture
def opted_in_project(isolated):
    _home, project = isolated
    opt_in(project)
    return project


@pytest.mark.parametrize("command", ["ls -la", "npm test", "echo $HOME", "git status"])
def test_allowed_commands(opted_in_project, command):
    code, out, err = run("claude", payload_for("claude", command))
    assert code == 0
    assert out == ""
    assert err == ""


def test_delete_nodes_denied(opted_in_project):
    code, out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


@pytest.mark.parametrize("command", ["kubectl delete ns $NS", "kubectl get pods $(whoami)"])
def test_not_statically_checkable_infra_commands_denied(opted_in_project, command):
    code, out, err = run("claude", payload_for("claude", command))
    assert code == 2
    assert "cannot check this command statically" in err


def test_compound_command_with_blocked_tail_denied(opted_in_project):
    code, out, err = run("claude", payload_for("claude", f"ls && {BLOCK_COMMAND}"))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


def test_sudo_prefixed_blocked_command_denied(opted_in_project):
    code, out, err = run("claude", payload_for("claude", f"sudo {BLOCK_COMMAND}"))
    assert code == 2
    assert BLOCK_REASON_SNIPPET in err


# --- 4. per-agent reply format on deny --------------------------------------------


def test_claude_deny_format(opted_in_project):
    code, out, err = run("claude", payload_for("claude", BLOCK_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert body["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert err


def test_codex_deny_format(opted_in_project):
    code, out, err = run("codex", payload_for("codex", BLOCK_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert err


def test_copilot_deny_format(opted_in_project):
    code, out, err = run("copilot", payload_for("copilot", BLOCK_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["permissionDecision"] == "deny"
    assert "permissionDecisionReason" in body
    assert err


def test_cursor_deny_format(opted_in_project):
    code, out, err = run("cursor", payload_for("cursor", BLOCK_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["permission"] == "deny"
    assert body["user_message"]
    assert body["agent_message"]
    assert err


def test_vscode_deny_format_has_both_shapes(opted_in_project):
    code, out, err = run("vscode", payload_for("vscode", BLOCK_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["permissionDecision"] == "deny"
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert err


# --- 5. ESCALATE -> ask -----------------------------------------------------------


@pytest.mark.parametrize("agent", ["claude", "copilot", "vscode", "cursor"])
def test_escalate_asks_where_supported(opted_in_project, agent):
    code, out, err = run(agent, payload_for(agent, ESCALATE_COMMAND))
    assert code == 0
    assert err == ""
    body = json.loads(out)
    if agent == "cursor":
        assert body["permission"] == "ask"
    elif agent == "claude":
        assert body["hookSpecificOutput"]["permissionDecision"] == "ask"
    else:  # copilot, vscode: top-level permissionDecision
        assert body["permissionDecision"] == "ask"


def test_escalate_codex_denies(opted_in_project):
    code, out, err = run("codex", payload_for("codex", ESCALATE_COMMAND))
    assert code == 2
    body = json.loads(out)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert err


@pytest.mark.parametrize("agent", hook.AGENTS)
def test_escalate_as_deny_denies_for_every_agent(opted_in_project, agent):
    code, out, err = run(agent, payload_for(agent, ESCALATE_COMMAND), escalate_as="deny")
    assert code == 2
    assert err


# --- 6. broken policy --------------------------------------------------------------


@pytest.fixture
def broken_policy_project(opted_in_project):
    config_dir = opted_in_project / ".aegis"
    sig = config_dir / "constraints.example.yaml.sig"
    assert sig.exists()
    sig.unlink()
    return opted_in_project, config_dir


@pytest.mark.parametrize("command,expect_allow", [
    ("ls -la", True),
    ("echo hi", True),
    ("kubectl get pods", False),
    ("terraform apply", False),
])
def test_broken_policy_gates_only_infra_commands(broken_policy_project, command, expect_allow):
    _project, config_dir = broken_policy_project
    code, out, err = run("claude", payload_for("claude", command))
    if expect_allow:
        assert code == 0
        assert out == ""
        assert err == ""
    else:
        assert code == 2
        assert str(config_dir) in err


# --- 7. non-shell tool calls -------------------------------------------------------


@pytest.mark.parametrize("tool_name", ["Edit", "Write"])
def test_non_shell_claude_style_tool_allowed(opted_in_project, tool_name):
    payload = {
        "session_id": "s", "hook_event_name": "PreToolUse",
        "tool_name": tool_name, "tool_input": {"file_path": "x.py", "content": "1"},
    }
    code, out, err = run("claude", payload)
    assert code == 0
    assert out == ""
    assert err == ""


def test_non_shell_copilot_tool_allowed(opted_in_project):
    payload = {
        "sessionId": "s", "timestamp": 1, "toolName": "edit",
        "toolArgs": {"path": "x.py", "content": "1"},
    }
    code, out, err = run("copilot", payload)
    assert code == 0
    assert out == ""
    assert err == ""


# --- 8. bad payloads -----------------------------------------------------------


def test_bad_json_not_opted_in_allows(isolated):
    code, out, err = run("claude", "not json{{{")  # type: ignore[arg-type]
    assert code == 0
    assert out == err == ""


def test_bad_json_opted_in_denies(opted_in_project):
    code, out, err = run("claude", "not json{{{")  # type: ignore[arg-type]
    assert code == 2
    assert err


def test_json_array_payload_not_opted_in_allows(isolated):
    code, out, err = run("claude", [1, 2, 3])  # type: ignore[arg-type]
    assert code == 0
    assert out == err == ""


def test_json_array_payload_opted_in_denies(opted_in_project):
    code, out, err = run("claude", [1, 2, 3])  # type: ignore[arg-type]
    assert code == 2
    assert err


def test_missing_tool_name_not_opted_in_allows(isolated):
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_input": {"command": "ls"}}
    code, out, err = run("claude", payload)
    assert code == 0
    assert out == err == ""


def test_missing_tool_name_opted_in_denies(opted_in_project):
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_input": {"command": "ls"}}
    code, out, err = run("claude", payload)
    assert code == 2
    assert err


def test_run_hook_never_raises_on_garbage(isolated):
    # A completely malformed nested structure -- run_hook must still answer.
    code, out, err = hook.run_hook("claude", json.dumps({"tool_name": 123, "tool_input": None}))
    assert code == 0


def test_run_hook_never_raises_opted_in(opted_in_project):
    code, out, err = hook.run_hook("claude", json.dumps({"tool_name": 123, "tool_input": None}))
    assert code == 2


# --- 9. mentions_infra word-boundary behaviour -----------------------------------


@pytest.mark.parametrize("command,expected", [
    ("kubectl get pods", True),
    ("mykubectl get pods", False),
    ("/usr/local/bin/kubectl x", True),
    ("echo git", True),
    ("digit foo", False),
])
def test_mentions_infra_word_boundaries(command, expected):
    assert hook.mentions_infra(command) is expected


# --- 10. install -----------------------------------------------------------------


@pytest.mark.parametrize("agent", hook.AGENTS)
def test_install_project_path_matches_config_path(isolated, agent, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    path = hook.install(agent, user=False, project=project)
    assert path == hook.config_path(agent, user=False, project=project)
    assert path.exists()


@pytest.mark.parametrize("agent", hook.AGENTS)
def test_install_user_path_matches_config_path(isolated, agent):
    home, project = isolated
    path = hook.install(agent, user=True, project=project)
    assert path == hook.config_path(agent, user=True, project=project)
    assert str(path).startswith(str(home))


def test_install_claude_json_shape(isolated, tmp_path):
    path = hook.install("claude", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    entries = doc["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["matcher"] == "Bash"
    assert entries[0]["hooks"][0]["type"] == "command"
    assert "hook claude" in entries[0]["hooks"][0]["command"]


def test_install_codex_json_shape(isolated, tmp_path):
    path = hook.install("codex", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    entries = doc["hooks"]["PreToolUse"]
    assert entries[0]["matcher"] == "^Bash$"


def test_install_copilot_json_shape(isolated, tmp_path):
    path = hook.install("copilot", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    assert doc["version"] == 1
    entries = doc["hooks"]["preToolUse"]
    assert "bash" in entries[0]
    assert "hook copilot" in entries[0]["bash"]


def test_install_vscode_json_shape(isolated, tmp_path):
    path = hook.install("vscode", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    entries = doc["hooks"]["PreToolUse"]
    assert "command" in entries[0]
    assert "hook vscode" in entries[0]["command"]


def test_install_cursor_json_shape(isolated, tmp_path):
    path = hook.install("cursor", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    entries = doc["hooks"]["beforeShellExecution"]
    assert entries[0]["failClosed"] is True
    assert "hook cursor" in entries[0]["command"]


@pytest.mark.parametrize("agent", hook.AGENTS)
def test_install_is_idempotent(isolated, agent, tmp_path):
    hook.install(agent, user=False, project=tmp_path)
    path = hook.install(agent, user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    event = list(doc["hooks"].keys())[0]
    assert len(doc["hooks"][event]) == 1


def test_install_preserves_unrelated_settings_and_hooks(isolated, tmp_path):
    path = hook.config_path("claude", user=False, project=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = {
        "some_setting": "keep-me",
        "hooks": {
            "PreToolUse": [
                {"matcher": "Write", "hooks": [{"type": "command", "command": "echo other"}]},
            ],
            "PostToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo post"}]},
            ],
        },
    }
    path.write_text(json.dumps(existing))
    hook.install("claude", user=False, project=tmp_path)
    doc = json.loads(path.read_text())
    assert doc["some_setting"] == "keep-me"
    assert doc["hooks"]["PostToolUse"] == existing["hooks"]["PostToolUse"]
    pre = doc["hooks"]["PreToolUse"]
    matchers = {e["matcher"] for e in pre}
    assert matchers == {"Write", "Bash"}


@pytest.mark.parametrize("agent", hook.AGENTS)
def test_install_remove_removes_only_ours(isolated, agent, tmp_path):
    path = hook.config_path(agent, user=False, project=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    hook.install(agent, user=False, project=tmp_path)
    doc_before = json.loads(path.read_text())
    # Inject an unrelated entry into the same event so removal must be selective.
    event = list(doc_before["hooks"].keys())[0]
    other_entry = {"matcher": "Other", "hooks": [{"type": "command", "command": "echo keep"}]} \
        if agent in ("claude", "codex") else \
        ({"type": "command", "bash": "echo keep"} if agent == "copilot" else
         {"type": "command", "command": "echo keep"} if agent == "vscode" else
         {"command": "echo keep", "failClosed": False})
    doc_before["hooks"][event].append(other_entry)
    path.write_text(json.dumps(doc_before))

    hook.install(agent, user=False, project=tmp_path, remove=True)
    doc_after = json.loads(path.read_text())
    remaining = doc_after["hooks"].get(event, [])
    assert len(remaining) == 1
    assert remaining[0] == other_entry
    # Confirm ours is really gone.
    dumped = json.dumps(remaining)
    assert "hook " + agent not in dumped


def test_install_refuses_non_object_json(isolated, tmp_path):
    path = hook.config_path("claude", user=False, project=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ValueError):
        hook.install("claude", user=False, project=tmp_path)


# --- 11. end-to-end through the CLI entry point -----------------------------------


def _run_cli_hook(agent: str, payload: dict, cwd: Path, home: Path, signing_key: str):
    import os
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["AEGIS_SIGNING_KEY"] = signing_key
    for var in ("AEGIS_CONFIG_DIR", "CLAUDE_PROJECT_DIR", "COPILOT_PROJECT_DIR",
                "CURSOR_PROJECT_DIR"):
        env.pop(var, None)
    aegis_bin = Path(sys.executable).parent / "aegis"
    return subprocess.run(
        [str(aegis_bin), "hook", agent],
        input=json.dumps(payload), capture_output=True, text=True, cwd=str(cwd), env=env,
    )


def test_cli_entry_point_allow(isolated):
    home, project = isolated
    opt_in(project)
    from aegis_core.signing import load_key
    key = load_key(f"file:{EXAMPLE_SIGNING_KEY_PATH}")
    result = _run_cli_hook("claude", claude_payload("ls -la"), project, home, key.hex())
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_cli_entry_point_deny(isolated):
    home, project = isolated
    opt_in(project)
    from aegis_core.signing import load_key
    key = load_key(f"file:{EXAMPLE_SIGNING_KEY_PATH}")
    result = _run_cli_hook("claude", claude_payload(BLOCK_COMMAND), project, home, key.hex())
    assert result.returncode == 2
    assert BLOCK_REASON_SNIPPET in result.stderr
    body = json.loads(result.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_remove_deletes_a_file_that_only_held_our_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = hook.install("copilot", user=True, project=tmp_path)
    assert path.exists()
    hook.install("copilot", user=True, project=tmp_path, remove=True)
    assert not path.exists()
