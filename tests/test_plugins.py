"""Packaging of the Claude Code plugin, the Copilot plugin and the Gemini CLI
extension, and the wrapper script all three run when ``aegis`` itself may be
missing."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from aegis_core import __version__

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "hooks" / "aegis-hook.sh"
COPILOT = ROOT / "plugins" / "copilot"
CLAUDE = ROOT / "plugins" / "claude"


def test_copilot_plugin_manifest():
    manifest = json.loads((COPILOT / "plugin.json").read_text())
    assert manifest["$schema"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
    assert manifest["name"] == "aegis-devops"
    # awesome-copilot pins a semver version to a release tag
    assert manifest["version"] == __version__


def test_copilot_plugin_hook_runs_the_wrapper():
    hooks = json.loads((COPILOT / "com.github.copilot" / "hooks" / "hooks.json").read_text())
    [entry] = hooks["hooks"]["preToolUse"]
    assert entry["bash"] == '"${PLUGIN_ROOT}"/aegis-hook.sh copilot'
    assert (COPILOT / "aegis-hook.sh").stat().st_mode & 0o111


@pytest.mark.parametrize(
    "copy", ["plugins/copilot/aegis-hook.sh", "plugins/claude/hooks/aegis-hook.sh"]
)
def test_plugin_wrappers_are_copies_of_the_root_one(copy):
    # a plugin can only ship files inside its own folder
    path = ROOT / copy
    assert path.read_bytes() == WRAPPER.read_bytes()
    assert path.stat().st_mode & 0o111


def test_claude_marketplace_points_at_the_plugin_folder():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    [entry] = market["plugins"]
    assert entry["name"] == "aegis-devops"
    assert entry["source"] == "./plugins/claude"
    manifest = json.loads((CLAUDE / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == entry["name"]
    # the repo root is the Gemini extension now; no Claude plugin manifest there
    assert not (ROOT / ".claude-plugin" / "plugin.json").exists()


def test_claude_plugin_hook_runs_the_wrapper():
    hooks = json.loads((CLAUDE / "hooks" / "hooks.json").read_text())
    shell, others = hooks["hooks"]["PreToolUse"]
    assert shell["matcher"] == "Bash"
    assert shell["hooks"][0]["command"] == '"${CLAUDE_PLUGIN_ROOT}"/hooks/aegis-hook.sh claude'
    # budget cap: every other tool, and new prompts, through the budget-only fast path
    budget_only = '"${CLAUDE_PLUGIN_ROOT}"/hooks/aegis-hook.sh claude --budget-only'
    assert others["matcher"] == "^(?!Bash$).*"
    assert others["hooks"][0]["command"] == budget_only
    assert not re.search(others["matcher"], "Bash") and re.search(others["matcher"], "Edit")
    [prompt] = hooks["hooks"]["UserPromptSubmit"]
    assert prompt["hooks"][0]["command"] == budget_only


def test_gemini_extension_manifest():
    manifest = json.loads((ROOT / "gemini-extension.json").read_text())
    assert manifest["name"] == "aegis-devops"
    assert manifest["version"] == __version__


def test_gemini_extension_hook_runs_the_wrapper():
    # Gemini CLI reads an extension's hooks from hooks/hooks.json at its root;
    # nothing else may live there (Gemini warns about unknown events)
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    assert set(hooks["hooks"]) == {"BeforeTool", "BeforeAgent"}
    entry, others = hooks["hooks"]["BeforeTool"]
    assert entry["matcher"] == "run_shell_command"
    [h] = entry["hooks"]
    assert h["command"] == '"${extensionPath}${/}hooks${/}aegis-hook.sh" gemini'
    assert h["timeout"] == 30000
    budget_only = '"${extensionPath}${/}hooks${/}aegis-hook.sh" gemini --budget-only'
    assert others["matcher"] == "^(?!run_shell_command$).*"
    assert others["hooks"][0]["command"] == budget_only
    assert not re.search(others["matcher"], "run_shell_command")
    [prompt] = hooks["hooks"]["BeforeAgent"]
    assert prompt["hooks"][0]["command"] == budget_only


# --- the wrapper with no aegis installed --------------------------------------------


def _run_wrapper(tmp_path, command, *, opted_in):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    if opted_in:
        (project / ".aegis").mkdir()
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}  # no aegis, no uvx
    payload = json.dumps({"toolName": "bash", "toolArgs": {"command": command}})
    proc = subprocess.run(
        ["bash", str(WRAPPER), "copilot"], input=payload, capture_output=True, text=True,
        cwd=project, env=env, check=False,
    )
    return proc.returncode, proc.stderr


@pytest.mark.skipif(os.name == "nt", reason="bash wrapper")
@pytest.mark.parametrize("command", ["ls -la", "kubectl delete nodes --all"])
def test_wrapper_without_aegis_allows_everything_outside_opted_in_projects(tmp_path, command):
    assert _run_wrapper(tmp_path, command, opted_in=False) == (0, "")


@pytest.mark.skipif(os.name == "nt", reason="bash wrapper")
def test_wrapper_without_aegis_blocks_only_infra_in_opted_in_projects(tmp_path):
    code, err = _run_wrapper(tmp_path, "kubectl get pods", opted_in=True)
    assert code == 2
    assert "pip install aegis-devops" in err
    (tmp_path / "home").rename(tmp_path / "old-home")
    (tmp_path / "project").rename(tmp_path / "old-project")
    assert _run_wrapper(tmp_path, "ls -la", opted_in=True) == (0, "")


# --- the wrapper's budget-only fast path --------------------------------------------------


def _run_budget_only(tmp_path, *, budget: bool, aegis_ok: bool = True):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    (project / ".aegis").mkdir(parents=True)
    if budget:
        (project / ".aegis" / "budget.yaml").write_text("unit: usd\n")
    marker = tmp_path / "aegis-ran"
    fake = tmp_path / "aegis"
    fake.write_text(f"#!/bin/sh\ncat >/dev/null\ntouch {marker}\nexit 0\n")
    fake.chmod(0o755)
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin",
           **({"AEGIS_BIN": str(fake)} if aegis_ok else {})}
    payload = json.dumps({"tool_name": "Edit", "tool_input": {}, "session_id": "s"})
    proc = subprocess.run(["bash", str(WRAPPER), "claude", "--budget-only"], input=payload,
                          capture_output=True, text=True, cwd=project, env=env, check=False)
    return proc.returncode, marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="bash wrapper")
def test_budget_only_entries_cost_nothing_without_a_budget(tmp_path):
    """No budget.yaml: the wrapper exits before starting aegis at all."""
    assert _run_budget_only(tmp_path, budget=False) == (0, False)


@pytest.mark.skipif(os.name == "nt", reason="bash wrapper")
def test_budget_only_entries_run_aegis_where_a_budget_applies(tmp_path):
    assert _run_budget_only(tmp_path, budget=True) == (0, True)


@pytest.mark.skipif(os.name == "nt", reason="bash wrapper")
def test_budget_only_entries_allow_when_aegis_is_missing(tmp_path):
    """Without aegis nothing can be measured; only shell commands are gated
    by the wrapper's own fallback."""
    assert _run_budget_only(tmp_path, budget=True, aegis_ok=False) == (0, False)
