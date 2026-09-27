"""Packaging of the Claude Code and Copilot plugins, and the wrapper script
they both run when ``aegis`` itself may be missing."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from aegis_core import __version__

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "hooks" / "aegis-hook.sh"
COPILOT = ROOT / "plugins" / "copilot"


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


def test_copilot_wrapper_is_a_copy_of_the_claude_one():
    # a plugin can only ship files inside its own folder
    assert (COPILOT / "aegis-hook.sh").read_bytes() == WRAPPER.read_bytes()


def test_claude_plugin_hook_runs_the_wrapper():
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    [entry] = hooks["hooks"]["PreToolUse"]
    assert entry["matcher"] == "Bash"
    assert entry["hooks"][0]["command"] == '"${CLAUDE_PLUGIN_ROOT}"/hooks/aegis-hook.sh claude'


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
