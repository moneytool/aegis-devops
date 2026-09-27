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
import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"

// `aegis install opencode` replaces null with the argv that starts the aegis
// it was run from (GUI apps do not see your shell's PATH).
const INSTALLED = null
const AEGIS = process.env.AEGIS_BIN ? [process.env.AEGIS_BIN] : INSTALLED || ["aegis"]
const INFRA =
  /(^|[^\w.-])(kubectl|k|terraform|tf|tofu|aws|az|gcloud|gsutil|helm|argocd|flux|git|gh|psql|mysql|sqlite3|mongosh|pulumi|alembic|flyway|rails|prisma)([^\w.-]|$)/

function optedIn(start) {
  if (process.env.AEGIS_CONFIG_DIR) return true
  if (existsSync(join(homedir(), ".config", "aegis"))) return true
  let dir = resolve(start || process.cwd())
  for (;;) {
    if (existsSync(join(dir, ".aegis"))) return true
    const parent = dirname(dir)
    if (parent === dir) return false
    dir = parent
  }
}

export const AegisDevOps = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input?.tool !== "bash") return
    const command = output?.args?.command
    if (typeof command !== "string" || !command.trim()) return
    const cwd = directory || process.cwd()
    const payload = JSON.stringify({ tool_name: "bash", tool_input: { command }, cwd })
    const run = spawnSync(AEGIS[0], [...AEGIS.slice(1), "hook", "opencode"], {
      input: payload,
      encoding: "utf8",
      timeout: 30000,
      cwd,
    })
    if (run.error || run.status === null) {
      if (optedIn(cwd) && INFRA.test(command)) {
        throw new Error(
          "aegis-devops could not run, so this infrastructure command cannot be checked: " +
            "run 'pip install aegis-devops' (blocking to fail closed)",
        )
      }
      return
    }
    if (run.status === 0) return
    throw new Error((run.stderr || "").trim() || `aegis: blocked (exit ${run.status})`)
  },
})
