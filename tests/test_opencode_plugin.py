"""The bundled OpenCode plugin, run under Node (OpenCode runs plugins in Bun,
which provides the same node:child_process/fs/os/path APIs it uses).

The plugin's default export serves both OpenCode plugin APIs: V1 (1.15 and
later) calls ``server(input)`` and gets the hook object back; V2 (2.x) calls
``setup(ctx)``, which registers the hook with ``ctx.tool.hook``. The harnesses
below drive each the way OpenCode does."""

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
const { default: plugin } = await import(pathToFileURL(pluginPath).href)
const hooks = await plugin.server({ directory })
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
const { default: plugin } = await import(pathToFileURL(pluginPath).href)
const hooks = await plugin.server({ directory, client: {} })
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


# OpenCode V2: setup(ctx) registers the hook; the callback gets one event with
# tool, sessionID and the tool's input, and a throw fails that call.
V2_HARNESS = """
import { pathToFileURL } from "node:url"
const [pluginPath, directory, tool, command] = process.argv.slice(2)
const { default: plugin } = await import(pathToFileURL(pluginPath).href)
const registered = []
const ctx = {
  location: { directory },
  tool: {
    hook: async (name, callback) => {
      registered.push({ name, callback })
      return { dispose: async () => {} }
    },
  },
}
const result = await plugin.setup(ctx)
const shape = {
  id: plugin.id,
  setupIsFunction: typeof plugin.setup === "function",
  serverIsFunction: typeof plugin.server === "function",
  exports: Object.keys(await import(pathToFileURL(pluginPath).href)),
  hooks: registered.map((r) => r.name),
  setupReturn: result === undefined ? "undefined" : typeof result,
}
const input = tool === "bash" ? { command } : { filePath: "x" }
try {
  await registered[0].callback({ tool, sessionID: "ses_1", input })
  console.log(JSON.stringify({ ...shape, allowed: true }))
} catch (e) {
  console.log(JSON.stringify({ ...shape, allowed: false, message: e.message }))
}
"""


def _call_v2(env, tool, command="", extra_env=None):
    import os

    harness = env["plugin"].parent / "v2-harness.mjs"
    harness.write_text(V2_HARNESS)
    out = subprocess.run(
        [NODE, str(harness), str(env["plugin"]), str(env["project"]), tool, command],
        capture_output=True, text=True, env={**os.environ, **(extra_env or {})},
        check=True, timeout=60,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_v2_export_shape(env):
    """A V2 plugin is `{ id, setup }` (Plugin.define is the identity function);
    the same object keeps `server` for V1. Nothing else is exported: a V1
    loader registers every export, so a second one would double each check."""
    result = _call_v2(env, "bash", "ls")
    assert result["id"] == "aegis-devops"
    assert result["setupIsFunction"] and result["serverIsFunction"]
    assert result["exports"] == ["default"]
    assert result["hooks"] == ["execute.before"]
    assert result["setupReturn"] == "undefined"


def test_v2_hook_blocks_what_the_policy_blocks(env):
    main(["init", str(env["project"] / ".aegis")])
    assert _call_v2(env, "bash", "ls -la")["allowed"] is True
    blocked = _call_v2(env, "bash", "kubectl delete nodes --all")
    assert blocked["allowed"] is False
    assert "no-delete-nodes" in blocked["message"]


def test_v2_non_bash_tools_reach_aegis_only_with_a_budget(env, tmp_path):
    main(["init", str(env["project"] / ".aegis")])
    fake = tmp_path / "deny-all"
    fake.write_text("#!/bin/sh\ncat >/dev/null\necho denied >&2\nexit 2\n")
    fake.chmod(0o755)
    missing = {"AEGIS_BIN": str(fake)}
    assert _call_v2(env, "read", extra_env=missing)["allowed"] is True
    (env["project"] / ".aegis" / "budget.yaml").write_text("unit: usd\n")
    assert _call_v2(env, "read", extra_env=missing)["allowed"] is False


def test_source_is_detected_as_v2_by_the_catalog_probe():
    """awesome-opencode's compat probe (scripts/utils/compat.js) marks a
    dependency-free plugin V2 from its source: an object literal with an id
    and a setup entry point. These are its regexes as of 2026-10-20."""
    import re
    from importlib.resources import files

    source = (files("aegis_core") / "integrations" / "opencode-plugin.js").read_text()
    v2_object = re.compile(r"\{[^{}]*\bid\s*:\s*[\w\"'`][^{}]*\b(async\s+)?setup\s*[:,(}]")
    assert v2_object.search(source), "catalog probe would not see a V2 { id, setup } export"
    assert "@opencode-ai/plugin" not in source  # no V1 import to misread as V1-only
