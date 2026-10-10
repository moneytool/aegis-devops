"""The bundled OpenCode plugin, run under Node (OpenCode runs plugins in Bun,
which provides the same node:child_process/fs/os/path APIs it uses)."""

import json
import shutil
import subprocess

import pytest

from aegis_core import hook
from aegis_core.cli import main
from aegis_core.signing import load_key

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")
EXAMPLE_KEY = load_key("file:data/example-signing.key")

HARNESS = """
import { pathToFileURL } from "node:url"
const [pluginPath, directory, command] = process.argv.slice(2)
const { AegisDevOps } = await import(pathToFileURL(pluginPath).href)
const hooks = await AegisDevOps({ directory })
try {
  await hooks["tool.execute.before"]({ tool: "bash" }, { args: { command } })
  console.log(JSON.stringify({ allowed: true }))
} catch (e) {
  console.log(JSON.stringify({ allowed: false, message: e.message }))
}
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for var in ("AEGIS_CONFIG_DIR", "CLAUDE_PROJECT_DIR", "COPILOT_PROJECT_DIR",
                "CURSOR_PROJECT_DIR", "GEMINI_PROJECT_DIR", "AEGIS_BIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AEGIS_SIGNING_KEY", EXAMPLE_KEY.hex())
    plugin = hook.install("opencode", user=False, project=project)
    mjs = tmp_path / "aegis-devops.mjs"  # ESM regardless of any package.json
    mjs.write_text(plugin.read_text())
    harness = tmp_path / "harness.mjs"
    harness.write_text(HARNESS)
    return {"home": home, "project": project, "plugin": mjs, "harness": harness}


def _call(env, command, extra_env=None):
    import os

    proc_env = {**os.environ, **(extra_env or {})}
    out = subprocess.run(
        [NODE, str(env["harness"]), str(env["plugin"]), str(env["project"]), command],
        capture_output=True, text=True, env=proc_env, check=True, timeout=60,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_not_opted_in_allows_everything(env):
    assert _call(env, "kubectl delete nodes --all") == {"allowed": True}


def test_opted_in_blocks_only_what_the_policy_blocks(env):
    main(["init", str(env["project"] / ".aegis")])
    assert _call(env, "ls -la") == {"allowed": True}
    blocked = _call(env, "kubectl delete nodes --all")
    assert blocked["allowed"] is False
    assert "no-delete-nodes" in blocked["message"]


def test_escalate_blocks_because_opencode_cannot_ask(env):
    main(["init", str(env["project"] / ".aegis")])
    result = _call(env, "argocd app delete app1")
    assert result["allowed"] is False
    assert "ESCALATE" in result["message"]


def test_missing_aegis_blocks_only_infra_in_opted_in_projects(env):
    missing = {"AEGIS_BIN": str(env["home"] / "no-such-aegis")}
    assert _call(env, "kubectl delete nodes --all", missing) == {"allowed": True}
    (env["project"] / ".aegis").mkdir()
    blocked = _call(env, "kubectl get pods", missing)
    assert blocked["allowed"] is False
    assert "pip install aegis-devops" in blocked["message"]
    assert _call(env, "ls -la", missing) == {"allowed": True}


TOOL_HARNESS = """
import { pathToFileURL } from "node:url"
const [pluginPath, directory, tool] = process.argv.slice(2)
const { AegisDevOps } = await import(pathToFileURL(pluginPath).href)
const hooks = await AegisDevOps({ directory, client: {} })
try {
  await hooks["tool.execute.before"]({ tool, sessionID: "ses_1" }, { args: { filePath: "x" } })
  console.log(JSON.stringify({ allowed: true }))
} catch (e) {
  console.log(JSON.stringify({ allowed: false, message: e.message }))
}
"""


@pytest.mark.parametrize("budget,expect_aegis", [(None, True), (True, True), (False, False)])
def test_no_budget_keeps_non_bash_tools_away_from_aegis(env, tmp_path, budget, expect_aegis):
    """Review of #39: --no-budget must hold for OpenCode too. A fake aegis
    that denies everything shows whether a read call reached it."""
    import os

    main(["init", str(env["project"] / ".aegis")])
    (env["project"] / ".aegis" / "budget.yaml").write_text("unit: usd\n")
    plugin = hook.install("opencode", user=False, project=env["project"], budget=budget)
    mjs = tmp_path / f"plugin-{budget}.mjs"
    mjs.write_text(plugin.read_text())
    harness = tmp_path / "tool-harness.mjs"
    harness.write_text(TOOL_HARNESS)
    fake = tmp_path / "deny-all"
    fake.write_text("#!/bin/sh\ncat >/dev/null\necho denied >&2\nexit 2\n")
    fake.chmod(0o755)
    out = subprocess.run([NODE, str(harness), str(mjs), str(env["project"]), "read"],
                         capture_output=True, text=True, check=True, timeout=60,
                         env={**os.environ, "AEGIS_BIN": str(fake)})
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["allowed"] is (not expect_aegis)
