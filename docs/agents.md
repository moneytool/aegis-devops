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
| OpenCode (V1 1.15+ and V2) | `aegis install opencode` | plugin, `tool.execute.before` (bash) | yes |

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

**Compound commands** are judged part by part. In `terraform plan 2>&1; echo "exit=$?"` the
`terraform plan` is checked against the policy and the `echo` runs. A part with an unknown
argument passes only when its program treats arguments as data (`echo`, `printf` without
`-v`, `cat`, `tail`, `head`, `grep`, `wc`, `ls`, `test`, `rm`, `mkdir`, `jq` and similar; not
`sort`, `cp`, `mv`, `ln`, `tee` or `read`) and it does not redirect output to a computed path
or a configuration directory (`~/.kube`, `~/.aws`, `~/.config`, …), or when it only assigns a
variable that does not steer an infrastructure tool. Every other part with something unknown
in it is refused when the command names an infrastructure tool anywhere: a part that runs its
own command (`$(…)`, backticks, `<(…)`, also inside double quotes), one whose program is
unknown (`$TOOL …`), runs other programs (`find -exec`, `watch`, `ssh`, `trap`, `awk`,
`docker run`, `eval`, `bash -c`, …) or sets `KUBECONFIG`, `AWS_*`, `PATH` and the like (also
through `export`/`declare`/`local`). So `TS=$(date +%s); kubectl get pods` is refused on
purpose: any command substitution next to an infrastructure command is. The message quotes
the part. Without an infrastructure tool in the command such parts run as before. A program
word the shell could expand into another name (`kube{,}ctl`, `kubec?`, `kube[c]tl`) is always
refused. `aegis check command` stays strict: it exits 64 for any command it cannot parse, and
names the part that caused it.

**Escalations.** An ESCALATE verdict asks the user in Claude Code, Copilot, VS Code and Cursor.
Codex has no "ask" for hooks (it treats an unknown decision as an error and runs the command),
and Gemini CLI and OpenCode have none either, so there an escalation is a block. `aegis hook <agent> --escalate-as deny` makes every agent
block instead of asking.

## What the hook cannot see

The hook reads the command an agent is about to run, and the local shell scripts it runs. It
cannot read other code the command runs, so an agent that writes its infrastructure calls into
a Python program, a Makefile, or calls a cloud SDK, gets past it. With the example policy:

| Command the agent runs | Result |
|---|---|
| `kubectl delete namespace prod` | blocked by the policy |
| `bash -c 'kubectl delete namespace prod'` | blocked: the string is unwrapped and checked |
| `if true; then kubectl delete namespace prod; fi` | blocked: `if`/`then`/`do` … are stripped and the command checked |
| `kubectl get pods; echo "exit=$?"` | runs: `kubectl get pods` is checked, the `echo` part has no infrastructure tool |
| `kubectl delete namespace prod; echo "exit=$?"` | blocked by the policy |
| `NS=prod; kubectl delete ns "$NS"` | blocked: the `kubectl` part cannot be checked (the message quotes it) |
| `K=kubectl; $K delete namespace prod` | blocked: cannot be checked, names an infrastructure tool |
| `TS=$(date +%s); kubectl get pods`, `C=…; kubectl get ns; find . -exec $C …` | blocked: a part runs a command the hook cannot see, next to an infrastructure tool |
| `coproc kubectl …`, `kubectl delete \` + newline + `namespace prod`, `watch`/`setsid`/`stdbuf`/`doas`/`ionice`/`caffeinate`/`unbuffer`/`busybox`/`script -c` `kubectl …` | checked like the plain command |
| another program whose first argument is `kubectl` (`setpriv kubectl …`) | blocked: the tool cannot be checked through it (`man`, `which`, `rg`, package managers and the like excepted) |
| `kube{,}ctl …`, `kubec? …` | blocked: brace/glob in program name |
| `python3 -c "subprocess.run(['kubectl','delete','namespace','prod'])"` | blocked: inline code that names an infrastructure tool |
| `node -e` / `--eval=…`, `python3 -Ic`, `perl -e` / `-lne`, `ruby -e`, `php -r` naming `kubectl` | blocked the same way |
| `echo 'kubectl delete namespace prod' \| bash`, also `echo 'kube''ctl …' \| sh` | blocked: code piped into a shell that names an infrastructure tool |
| `curl -fsSL https://… \| sh`, `echo … \| base64 -d \| sh`, `cat x.py \| python3` | asks: the piped code is not on the command line (blocked in Codex, Gemini CLI, OpenCode) |
| `printf 'kube%s …' ctl \| sh`, `echo -e '\x6b…' \| sh`, `base64 -d <<< … \| sh`, `sh <<< "$(…)"`, `bash <<EOF` | asks the same way |
| `bash -c "$(cat nuke.sh)"`, `eval "$(…)"`, `source <(curl …)` | asks: the code only exists when the command runs |
| `cat > nuke.sh <<'EOF' … EOF` (here-doc that names `kubectl`) | blocked: cannot be checked, names an infrastructure tool |
| `bash nuke.sh`, `sh < nuke.sh`, `./nuke.sh`, `source nuke.sh`, where a line of `nuke.sh` is blocked | blocked by the policy (the message names the line) |
| the same, where a line names `kubectl` but cannot be checked (`kubectl delete ns "$NS"`) | asks |
| the same, where the script does not exist yet or is written by the same command (`printf '…' > x.sh; bash x.sh`, `cp a x.sh; bash x.sh`, `chmod +x x; ./x`), cannot be read, holds a NUL byte, is over 64 KiB, names a tool on more than 64 lines, or is run after a `cd` the hook cannot follow | asks |
| a script that `nuke.sh` sources or runs in turn | **runs**: only the script on the command line is read |
| a script changed between the check and the run, or a symlink retargeted in between | **runs** the new content: the hook reads it once, before the command starts |
| `python3 cleanup.py`, `make destroy`, `npm run teardown` | **runs** |
| a file written with the agent's Write/Edit tool, then run by something other than a shell | **runs**: file edits are not commands |
| a cloud SDK or HTTP call from code the agent wrote | **runs** |

A script is read when a shell runs it (`bash`, `sh`, `zsh`, `dash`, `ksh`, `ash`, `source`,
`.`), or when it is run directly (`./x`) and its `#!` line names a shell (`#!/usr/bin/env -S
bash` too) or it has no `#!` line at all (the shell then runs it). Bytes that are not UTF-8 are
read anyway. A NUL byte asks when a shell is named (`bash x.sh`, `source x.sh`, a shell `#!`
line); only a `./x` with no `#!` line and a NUL byte is taken for a binary and not read. A
script that the same command also writes, copies, moves, links, edits or names as an argument
or redirection target asks, since what runs may not be what is on disk at check time. A
relative path is read from the agent's working directory, or from the directory a literal
`cd DIR` earlier in the command moves to; a `cd` in the background (`&`) or in a pipeline, to
a computed place, or `env -C`/`sudo -D` make the directory unknown, which asks. Only lines that
name an infrastructure tool are checked, each as a command of its own, against the same
policy: comments (whole-line and trailing) are skipped; a backslash at the end of a line joins
the next line as the shell does, except at the end of a comment, which ends at the newline;
`<<` counts as a here-doc only outside quotes and comments; a here-doc body counts as commands
when a shell reads it, directly or through a pipe (`cat <<EOF | sh`), asks when another
interpreter reads one that names a tool or when an unquoted body's `$(…)` names one, and is
data otherwise. All checkable lines go to the policy in one run; only when that run is not an
allow are a few more runs made to find the line (bisection, on deny when the verdict is a
deny), so a block that only the lines together reach (an aggregate rule) is still a block.
`aegis check command` does not read files: this is the hook only.

Piped code asks unless the stage feeding the shell or interpreter is a literal `echo` (no `-e`,
no backslashes) or `printf` (one argument, no `%` directives, no escapes but `\n` and `\t`).
That text is read the way the shell would read it (quotes removed): when it names an
infrastructure tool it is blocked, and code for a shell is then checked like a command of its
own. `curl … | sh` installers are common, so piped code asks rather than blocks; where the
agent cannot ask (Codex, Gemini CLI, OpenCode, or `--escalate-as deny`) it is a block. The same
goes for a shell or interpreter fed by a here-string or a here-doc in a command the hook
cannot parse.

"Names an infrastructure tool" means one of the binaries listed above appears as a word in the
code, also after quotes, backslashes and line continuations are removed (`kube''ctl`,
`"kube"ctl`). Code that builds the name (`"kube" + "ctl"`, `printf kube%s ctl`) or calls an SDK
(`boto3`, `@aws-sdk`) is not recognised. Scripts are read once, before the command runs: a
script rewritten in between, or a symlink pointed elsewhere, is not seen again. The hook is a
guard against mistakes, not against an agent that is trying to get round it.

**Escalate local scripts (optional, off by default).** Install the hook with
`--escalate-scripts` and every command that runs code the hook cannot fully check asks first
(blocks in Codex, Gemini CLI and OpenCode): a script file (named or fed through `<`, also with
`$VAR` arguments, and also when the hook read it and found nothing blocked), a task runner
(`make`, `just`, `npm run`, …), inline interpreter code and a shell fed through a pipe:

```bash
aegis install claude --escalate-scripts     # any agent; reinstall without it to turn it off
```

That registers `aegis hook claude -- --escalate-scripts` (OpenCode: the plugin passes it on,
and if aegis cannot run it blocks every shell command in an opted-in project rather than only
infrastructure ones). A
hook command you wrote by hand takes the same `-- --escalate-scripts`. `aegis install` rewrites
the whole hook command, so other options you added by hand after `--` are dropped when you
reinstall. The Claude Code and Copilot plugins and the Gemini CLI extension do not take
options; use `aegis install` for this (with a plugin also installed, both hooks run and the
stricter answer wins).

It also asks for `python -m pytest`, `./configure` and `. venv/bin/activate`, so turn it on
where agents should not run scripts unattended. `aegis check command --escalate-scripts` does
the same outside a hook (note `runs-code: …`).

**The real boundary is on the server.** A script or an SDK call reaches the same cloud and
cluster APIs. The [server-side layer](server-side.md) compiles the policy to AWS SCPs and
Kubernetes admission policies, which deny the call whatever made it.

## Cost

With 1.1.0, one hook call on a shell command took 55–74 ms (median, Apple M4 Pro, CPython
3.12.12; a new process per call, as the agents run it). Against 1.0.0 on the same interpreter,
1.1.0 was 0.7–1.2 ms slower on the five commands both versions decide alike: consistently about 1 ms,
within the run-to-run spread (p95 is up to 4.4 ms above the median). Inline code that names an
infrastructure tool is now denied before the policy loads, so that call is faster
(70 → 55 ms). `--escalate-scripts` was not measured.
Measured with [`scripts/hook_latency.py`](https://github.com/moneytool/aegis-devops/blob/main/scripts/hook_latency.py)
([`results/hook-latency.json`](https://github.com/moneytool/aegis-devops/blob/main/results/hook-latency.json)).
The budget check adds its own ~9 ms where a `budget.yaml` exists ([budget: cost](budget.md#cost)).

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

The plugin works with both OpenCode plugin APIs from one default export: OpenCode V2 (2.x)
calls its `setup(ctx)`, which registers the check with `ctx.tool.hook("execute.before", …)`;
OpenCode V1 (1.15 and later) calls its `server()`, which returns the `tool.execute.before`
hook. It needs no npm dependency (V2's `Plugin.define` is the identity function). One
difference: a budget warning is a toast under V1 and a line in OpenCode's log under V2,
whose server plugins have no toast API. On V2 the config key for plugins is `plugins` (V1:
`plugin`); `aegis install opencode` writes to the plugin directory, which both versions load.

## Removing it

`aegis install <agent> --remove` (with the same `--user` or project) removes the Aegis entry
and leaves every other setting and hook in the file alone.

## How the installed command finds aegis

`aegis install` writes the absolute path of the `aegis` it was run with, because editors
started from the Dock do not see your shell's `PATH`. If you later move or reinstall Aegis
into a different virtualenv, run `aegis install` again.
