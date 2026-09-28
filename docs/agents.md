# Coding agents

Aegis can sit in front of the shell commands a coding agent runs. The agent asks to run a
command, the agent's pre-tool hook hands it to `aegis hook <agent>`, and Aegis answers in
that agent's own format: allow, block (with the reason shown to the model), or ask the user.

| Agent | Install | Hook it uses | Live-tested |
|---|---|---|---|
| Claude Code | plugin, or `aegis install claude` | `PreToolUse` (Bash) | yes |
| Codex CLI | `aegis install codex` | `PreToolUse` (Bash) | yes |
| GitHub Copilot CLI | plugin, or `aegis install copilot` | `preToolUse` (bash) | yes |
| VS Code (Copilot agent mode) | `aegis install vscode` | `PreToolUse` (run_in_terminal) | yes |
| Cursor | `aegis install cursor` | `beforeShellExecution` | yes (`cursor-agent`) |
| Gemini CLI | extension, or `aegis install gemini` | `BeforeTool` (run_shell_command) | yes |
| OpenCode | `aegis install opencode` | plugin, `tool.execute.before` (bash) | yes |

"Live-tested" means a real session of that agent (Claude Code, Codex, Copilot, Cursor,
Gemini CLI and OpenCode from their CLIs, VS Code from its chat panel), asked to run `ls -la`,
`kubectl get pods` and `kubectl delete nodes --all` in a project with the example policy,
ran the first two and was stopped on the third with the policy's reason. The unit tests
(`tests/test_hook.py`) cover every agent's payload and reply format.

## What gets blocked

**Only projects that opted in.** An agent hook runs in every project the agent opens, so
Aegis does nothing unless a policy exists for the project:

1. `$AEGIS_CONFIG_DIR`, or
2. a `.aegis/` directory in the project or any parent of it, or
3. `~/.config/aegis` (applies to every project).

Anywhere else every command runs and Aegis prints nothing. Run `aegis init .aegis` in a
project to opt it in.

**What the example policy blocks.** `aegis init` writes an example policy that, besides its
demo rules, blocks the obviously infrastructure-breaking commands: `terraform destroy` /
`tofu destroy`, `pulumi destroy`, deleting a Kubernetes namespace or node, an S3 bucket, an
RDS database, a GCP project or an Azure resource group, dropping a database or an unbounded
table, force-pushing `main`, deleting Helm releases in production, and running kubectl as
another identity (`--as`); deleting an Argo CD application asks first. Replace it with your own `constraints.yaml` once you have one.

**Only what the policy says.** Inside an opted-in project, a command is stopped only when the
policy blocks it or escalates it. `ls`, `npm test`, `git status` and anything else the policy
has no rule for run as usual.

**When something is wrong.** If the policy files cannot be used (a bad signature, a missing
file, too many rules quarantined) or a command cannot be analysed without running it
(`$(...)`, `$VAR`, `eval`, ...), Aegis blocks only commands that involve infrastructure tools
— the binaries it has parsers for (`kubectl`, `aws`, `az`, `gcloud`, `helm`, `argocd`, `flux`,
`git`, `gh`, `psql`, `mysql`, `sqlite3`, `mongosh`, `pulumi` and the migration tools) plus
`terraform` and `tofu` — and says why. Everything else still runs: `ls` has nothing to do with
a broken policy.

**Escalations.** An ESCALATE verdict asks the user in Claude Code, Copilot, VS Code and Cursor.
Codex has no "ask" for hooks (it treats an unknown decision as an error and runs the command),
and Gemini CLI and OpenCode have none either, so there an escalation is a block. `aegis hook <agent> --escalate-as deny` makes every agent
block instead of asking.

## Claude Code

As a plugin (updates with the repository):

```bash
pip install aegis-devops
claude plugin marketplace add moneytool/aegis-devops
claude plugin install aegis-devops@aegis-devops
```

The plugin runs `hooks/aegis-hook.sh`, which looks for `aegis` in `$AEGIS_BIN`, then on your
`PATH`, then through `uvx`. If none is found it still refuses infrastructure commands in
opted-in projects, with a message saying to install aegis-devops.

Or without the plugin, as a hook in your settings:

```bash
aegis install claude            # this project: .claude/settings.json
aegis install claude --user     # every project: ~/.claude/settings.json
```

## Codex CLI

```bash
aegis install codex             # this project: .codex/hooks.json
aegis install codex --user      # every project: ~/.codex/hooks.json
```

Codex runs a new hook only after you trust it: start `codex`, trust the folder if asked, and
approve the hook in `/hooks`. Codex records trust against the hook's hash, so re-running
`aegis install` after moving the `aegis` binary asks again.

## GitHub Copilot CLI

As a plugin (from the repository; the same plugin works in VS Code):

```bash
pip install aegis-devops
copilot plugin install moneytool/aegis-devops:plugins/copilot
```

Or as a hook in your config:

```bash
aegis install copilot --user    # every project: ~/.copilot/hooks/aegis.json
aegis install copilot           # this repository: .github/hooks/aegis.json
```

Copilot CLI reads a repository's `.github/hooks` only in folders you have trusted, so the
user-level install is the one that always loads. Note that Copilot treats a hook that times
out (30 s) as "allow"; Aegis decides in milliseconds, so this only matters if the machine is
badly overloaded.

## VS Code

```bash
aegis install vscode            # this workspace: .github/hooks/aegis-vscode.json
aegis install vscode --user     # every workspace: ~/.copilot/hooks/aegis-vscode.json
```

Hooks are a Preview feature in VS Code and run only in trusted workspaces. VS Code ignores
matchers in this file, so the hook sees every tool call and lets everything that is not a
terminal command through.

## Cursor

```bash
aegis install cursor            # this project: .cursor/hooks.json
aegis install cursor --user     # every project: ~/.cursor/hooks.json
```

The entry sets `failClosed: true`, so a crashed or timed-out hook blocks the command instead
of letting it run. Restart Cursor after installing.

## Gemini CLI

As an extension (the repository is one):

```bash
pip install aegis-devops
gemini extensions install https://github.com/moneytool/aegis-devops
```

It runs the same wrapper as the Claude Code and Copilot plugins, so without `aegis` installed it
still allows everything outside opted-in projects. Or as a hook in your settings:

```bash
aegis install gemini            # this project: .gemini/settings.json
aegis install gemini --user     # every project: ~/.gemini/settings.json
```

The hook runs before `run_shell_command`. Gemini CLI fingerprints project hooks and may ask
you to trust a new one; `/hooks` lists and enables them. A block is exit code 2, which Gemini CLI enforces
but also reports as a failed hook (`Hook(s) [aegis-devops] failed for event BeforeTool`); the
tool call is still refused with Aegis's reason. Exit 2 is kept deliberately: it cannot be
misread as "allow".

## OpenCode

```bash
aegis install opencode          # this project: .opencode/plugins/aegis-devops.js
aegis install opencode --user   # every project: ~/.config/opencode/plugins/aegis-devops.js
```

OpenCode's hooks are JavaScript plugins, so this writes a small plugin that hands each `bash`
command to `aegis hook opencode` and throws (which blocks the call and shows the model the
reason) when Aegis says no. If `aegis` cannot be started, the plugin still refuses
infrastructure commands in opted-in projects. Restart OpenCode after installing.

## Removing it

`aegis install <agent> --remove` (with the same `--user` or project) removes the Aegis entry
and leaves every other setting and hook in the file alone.

## How the installed command finds aegis

`aegis install` writes the absolute path of the `aegis` it was run with, because editors
started from the Dock do not see your shell's `PATH`. If you later move or reinstall Aegis
into a different virtualenv, run `aegis install` again.
