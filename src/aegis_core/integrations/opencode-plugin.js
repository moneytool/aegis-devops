// Aegis-DevOps plugin for OpenCode: checks each bash command against the
// project's Aegis policy before it runs. Written by `aegis install opencode`
// into .opencode/plugins/ (or ~/.config/opencode/plugins/ with --user).
//
// OpenCode hooks are plugins, not shell commands, so this hands the command to
// `aegis hook opencode` and throws (which blocks the call and shows the model
// the reason) when Aegis says no. Everything is decided by aegis itself: it
// allows every command outside projects with a policy (.aegis/ here or above,
// $AEGIS_CONFIG_DIR, ~/.config/aegis), and inside one blocks only what the
// policy blocks. If aegis cannot be started, the same rule applies in its
// crudest form: in an opted-in project block commands naming an
// infrastructure binary, allow the rest.
//
// Budget cap (aegis 1.0): where the policy directory holds a budget.yaml,
// every tool call goes to aegis, not only bash, with OpenCode's session id so
// aegis can read this session's usage; a warning comes back as a toast.
import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"

// `aegis install opencode` replaces null with the argv that starts the aegis
// it was run from (GUI apps do not see your shell's PATH).
const INSTALLED = null
// `aegis install opencode --no-budget` replaces "auto" with "off": then only bash
// commands go to aegis, whatever budget.yaml says.
const BUDGET_MODE = "auto"
const AEGIS = process.env.AEGIS_BIN ? [process.env.AEGIS_BIN] : INSTALLED || ["aegis"]
const INFRA =
  /(^|[^\w.-])(kubectl|k|terraform|tf|tofu|aws|az|gcloud|gsutil|helm|argocd|flux|git|gh|psql|mysql|sqlite3|mongosh|pulumi|alembic|flyway|rails|prisma)([^\w.-]|$)/

// The policy directory aegis would use: $AEGIS_CONFIG_DIR, the nearest .aegis/
// at or above the project, or ~/.config/aegis.
function policyDir(start) {
  if (process.env.AEGIS_CONFIG_DIR) return process.env.AEGIS_CONFIG_DIR
  let dir = resolve(start || process.cwd())
  for (;;) {
    if (existsSync(join(dir, ".aegis"))) return join(dir, ".aegis")
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  const user = join(homedir(), ".config", "aegis")
  return existsSync(user) ? user : null
}

function optedIn(start) {
  return policyDir(start) !== null
}

function hasBudget(start) {
  const dir = policyDir(start)
  return dir !== null && existsSync(join(dir, "budget.yaml"))
}

async function toast(client, message) {
  try {
    await client.tui.showToast({ body: { message, variant: "warning" } })
  } catch {
    console.warn(message)
  }
}

export const AegisDevOps = async ({ directory, client }) => ({
  "tool.execute.before": async (input, output) => {
    const cwd = directory || process.cwd()
    const isBash = input?.tool === "bash"
    const command = output?.args?.command
    if (isBash && (typeof command !== "string" || !command.trim())) return
    if (!isBash && (BUDGET_MODE === "off" || !hasBudget(cwd))) return
    const payload = JSON.stringify({
      tool_name: input?.tool,
      tool_input: isBash ? { command } : output?.args || {},
      cwd,
      session_id: input?.sessionID,
    })
    const run = spawnSync(AEGIS[0], [...AEGIS.slice(1), "hook", "opencode"], {
      input: payload,
      encoding: "utf8",
      timeout: 30000,
      cwd,
    })
    if (run.error || run.status === null) {
      if (isBash && optedIn(cwd) && INFRA.test(command)) {
        throw new Error(
          "aegis-devops could not run, so this infrastructure command cannot be checked: " +
            "run 'pip install aegis-devops' (blocking to fail closed)",
        )
      }
      return
    }
    if (run.status === 0) {
      try {
        const reply = JSON.parse(run.stdout || "{}")
        if (reply.warning) await toast(client, reply.warning)
      } catch {}
      return
    }
    throw new Error((run.stderr || "").trim() || `aegis: blocked (exit ${run.status})`)
  },
})
