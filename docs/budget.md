# Session budget cap

A coding agent stuck in a loop, or fanning out sub-agents, spends money (API keys) or quota
(subscriptions) with nothing to stop it. Aegis can cap that spend per agent session and per
project per day, in estimated dollars or in tokens, across Claude Code, Codex, Gemini CLI,
OpenCode and Copilot CLI (premium requests). The cap is written into a **signed** policy
file, so an agent cannot raise its own limit by editing a file.

← back to the [README](https://github.com/moneytool/aegis-devops#readme) · design: [`dev/DESIGN-v1.0-budget-cap.md`](https://github.com/moneytool/aegis-devops/blob/main/docs/dev/DESIGN-v1.0-budget-cap.md)

## What it guarantees, and what it does not

> Aegis denies covered tool calls and prompts when the usage available at that hook reaches
> the limit. It does not impose a finite bound on additional model spending: in-flight
> requests, delayed usage records, retries after a denial, and tool-free activity can add
> cost.

Hooks run before tool calls and prompts, never before a model request, and an agent writes a
request's usage to its log only after the request has been paid for. So a session can end
**above** its limit — by the request that crossed it, by the model's replies to the denials,
by sub-agents that were already running, and, in OpenCode and Copilot CLI (which have no prompt
hook that can block), by chat that uses no tools. `aegis budget status` shows any usage over
a limit as **overshoot**. If you must never exceed an amount, set the limit below it, and put a
spend limit in front of the model requests themselves as well (a gateway, your vendor's
spending limits); those are separate layers whose guarantees you need to check.

The budget is a guard against loops and mistakes. An agent runs as you and can rewrite its own
session log; Aegis does not defend against an agent that does that on purpose.

## Set it up

```bash
aegis init .aegis                          # once; writes budget.example.yaml among the examples
cp .aegis/budget.example.yaml .aegis/budget.yaml
$EDITOR .aegis/budget.yaml                 # your limits
aegis sign --key file:KEY .aegis/budget.yaml
aegis install claude                       # and codex, gemini, opencode, copilot: reinstall
aegis budget status
```

Reinstalling matters: with a `budget.yaml` in the policy directory, `aegis install` widens each
agent's hook from shell commands to **every tool call** and adds the prompt hook where the
agent has one (`--budget` / `--no-budget` choose explicitly). The Claude Code plugin and the
Gemini extension already carry those entries; they start no extra process in projects without
a budget.

## `budget.yaml`

```yaml
version: 1
principal: admin            # must hold the 'budget' class in authority.yaml
unit: usd                   # usd | tokens — required
session:     {limit: 20,  warn_at: 0.8}          # per agent session
project_day: {limit: 100, warn_at: 0.8, tz: America/Chicago}   # all sessions in the project, per day
agents: [claude, codex, gemini, opencode, copilot]   # only listed agents are measured
on_unknown_log: allow       # allow (warn) | deny
on_unknown_price: estimate  # estimate (warn) | deny — usd only
pricing:                    # signed overrides, USD per million tokens
  claude-opus-5-5: {input: 4, output: 20, cache_read: 0.2, cache_write: 8}
copilot: {premium_requests: 50, warn_at: 0.8}       # per Copilot CLI session
```

- **Who may change it.** The file is signed like every policy file, and its `principal` must
  hold the `budget` class (the example `authority.yaml` gives it to `admin`). A file that was
  edited after signing, or whose principal lacks the class, is refused — and inside a project
  with a budget the hook then **denies** every covered call with a message saying so, rather
  than run without the budget you asked for.
- **Errors, never guesses.** Unknown fields, a missing `unit`, a limit that is not a finite
  positive number, `warn_at` outside (0, 1), an unknown time zone or agent, a price override
  missing a category: all load errors.
- **`tokens`** counts input, output, cache-read and cache-write tokens together, and ignores
  prices.
- **Copilot CLI** writes token counts only at shutdown, so it is measured in premium requests
  and only when `copilot.premium_requests` is set.
- **Cursor and VS Code** expose no token data and are not measured.

## What happens near and at the limit

| | Tool calls | New prompts | You see |
|---|---|---|---|
| Below `warn_at` | allowed | allowed | nothing |
| Past `warn_at` | allowed | allowed | one warning per session per threshold |
| At the limit | **denied**, every tool | **denied** where the agent can block them | what was spent, which limit, how to continue |

The infrastructure policy still decides first: a command the policy blocks stays blocked
whatever the budget says. To continue past a limit: start a new session (session limit), wait
for the next day in `tz` (project limit), or raise the limit in `budget.yaml` and re-sign it.

| Agent | Tool hook | Prompt hook | Warning shows as |
|---|---|---|---|
| Claude Code | `PreToolUse`, every tool | `UserPromptSubmit` | a message in the transcript |
| Codex CLI | `PreToolUse`, every tool | `UserPromptSubmit` | a UI warning |
| Gemini CLI | `BeforeTool`, every tool | `BeforeAgent` | a message in the terminal |
| OpenCode | plugin, every tool | — | a toast |
| Copilot CLI | `preToolUse`, every tool (premium requests) | — (it cannot block) | stderr only |

## Where the numbers come from

No hook payload carries token usage, so Aegis reads each agent's own session log, incrementally:
Claude Code's transcript (and its sub-agents'), Codex rollouts, Gemini CLI chats, OpenCode's
database (read-only; only its session and message tables), and Copilot CLI's events. A
sub-agent is counted inside its parent session. Nothing is sent anywhere.

**Dollars are estimates** from a dated table of list prices (`aegis_core/budget/prices.yaml`;
Anthropic, OpenAI and Google). On a subscription they are an API-equivalent figure, not your
bill; `unit: tokens` may suit you better there. A model the table does not know is priced, per
category, at the highest rate of its vendor (or of the whole table) — a guess that can still be
low — and flagged; with `on_unknown_price: deny` its sessions are denied until you add a signed
`pricing:` entry for it.

**The day** is the calendar day in `project_day.tz`, from the time each log record carries.

**What Aegis keeps** is derived from the logs and can be rebuilt: a cache under
`~/.cache/aegis/budget/`, and a small durable state under `~/.local/state/aegis/budget/` (a
per-session revision counter, locks, and a list of the sessions seen each day, so a rebuild can
tell when history is missing). Deleting the cache resets nothing while the logs exist.

### When usage cannot be verified

Some usage can only be counted as a lower bound: a log Aegis cannot find or read, records it
does not recognise, usage with no recorded time, a project day rebuilt after sessions' logs
were deleted, or the first day of a budget when other sessions had already run that day.
`on_unknown_log` decides what that means:

- `allow` (default): a warning, once; the lower bound is used.
- `deny`: covered calls are denied. A session's own unreadable log stays denied (start a new
  session). For an incomplete **project day**, `aegis budget reset --day` acknowledges that
  day's history **as it stands**: it records the day's verification state at that moment (how
  complete the history is, and for each session that is a lower bound: whether its log is
  missing, how many records could not be read, how much usage has no recorded time) and is
  signed with the
  policy key, so an agent cannot write one. Exactly that is excused; anything that becomes
  unverifiable afterwards — a new session with an unreadable log, another unreadable record in a
  session already acknowledged, more sessions without a log — counts again. Otherwise it clears at the next day.

## Commands

```bash
aegis budget status [--project DIR] [--agent A] [--json]
aegis budget check  [--project DIR] [--agent A --session ID]
aegis budget reset  --day [YYYY-MM-DD] [--project DIR] [--key KEY]
```

- `status` rebuilds today's project total from the logs, then shows it against the limit, each
  session that contributed (today's usage, its session total against the session limit, and
  whether it is a lower bound), estimated prices and the policy's warnings.
- `check` exits **0** under budget (a warning included), **3** over, **65** if `budget.yaml`
  cannot be used, **66** if there is none: for CI and scripts, including headless agent runs.
  It rebuilds the project day from the logs too; with `--agent` and `--session` it also checks
  that session's own limit.
- `reset --day` rebuilds the day, then writes the signed acknowledgement of its current state
  described above (default: today in the policy's `tz`); it needs the signing key and refuses
  `--insecure`.

## Cost

Measured with [`scripts/budget_latency.py`](https://github.com/moneytool/aegis-devops/blob/main/scripts/budget_latency.py)
([`results/budget-latency.json`](https://github.com/moneytool/aegis-devops/blob/main/results/budget-latency.json)):
the budget adds about **9 ms** to one hook call (Apple M4 Pro, Python 3.12: 74 ms median with a
budget, 65 ms without), against a design target of 20 ms. Projects without a `budget.yaml` pay
nothing.
