# Design: cross-agent session budget cap (v1.0)

Status: **draft for review**, 2026-10-07. Builds on the research in
[`TODO-budget-cap.md`](TODO-budget-cap.md) (PLAN backlog item 11). Target release: **v1.0.0** —
the budget cap is the headline feature, and 1.0 also declares the public surface stable (§9).

## 1. Problem

Coding agents spend money (API keys) or quota (subscriptions) with no hard stop that works
across agents. Reporting exists (ccusage, tokscale); enforcement does not: Claude Code's
`--max-budget-usd` works only in print mode, gateways (LiteLLM, Bifrost) only see traffic routed
through them, and single-agent enforcers have no adoption. A runaway loop — an agent retrying a
failing build all night, or a sub-agent fan-out — has no ceiling.

Aegis already sits in every major agent's hook path and already has signed policy. A budget
written into signed policy is one **the agent cannot raise by editing a file**.

## 2. Goals and non-goals

Goals:

- One cap — tokens or estimated USD — **per agent session** and **per project per day**, enforced
  by the existing hook in Claude Code, Codex, Gemini CLI and OpenCode; a premium-request cap for
  Copilot CLI.
- Warn at a threshold (default 80%), stop at 100%: tool calls are denied and, where the agent
  allows it, new prompts too.
- Budgets live in a signed, authority-checked policy file, like every other Aegis policy.
- No network, no vendor admin keys: usage is read from each agent's local session log.
- Fails safe for the user's work by default (unknown log format → allow with a warning), with a
  strict option.

Non-goals (v1.0): team or org roll-ups; vendor admin/billing APIs; Cursor and VS Code agent
(no token data in their hooks or logs); real invoices (the $ figure is an estimate, see §5);
defending against an agent that rewrites its own session log (§8).

## 3. Policy: `budget.yaml`

Lives in the policy directory beside `constraints.yaml`, signed like the other files. Its
`principal` must hold the new **`budget`** class in `authority.yaml` (the same pattern as
`agents.yaml` and the `identity` class).

```yaml
version: 1
principal: admin            # must hold the 'budget' class in authority.yaml
unit: usd                   # usd | tokens
session:
  limit: 20                 # per agent session
  warn_at: 0.8
project_day:
  limit: 100                # all sessions in this project, per calendar day
  warn_at: 0.8
  tz: America/Chicago       # the day boundary; default UTC
agents: [claude, codex, gemini, opencode, copilot]   # default: every supported agent
on_unknown_log: allow       # allow (warn) | deny
pricing:                    # optional overrides of the built-in table, per model
  claude-opus-5-5: {input: 15.0, output: 75.0, cache_read: 1.5, cache_write: 18.75}
copilot:
  premium_requests: 50      # Copilot CLI counts premium requests, not tokens
```

Load errors, never guesses: unknown fields, a non-positive limit, `warn_at` outside (0, 1), an
unknown agent, a price override with missing fields, a principal without `budget`.

## 4. Measuring usage

No pre-tool hook payload carries token usage, so on every hook call Aegis reads the session's
log **incrementally**:

| Agent | Session id from the hook | Log | Tokens | Model |
|---|---|---|---|---|
| Claude Code | `session_id`, `transcript_path` | `~/.claude/projects/<slug>/<session>.jsonl` | `message.usage.*` (input, output, cache creation, cache read) | `message.model` |
| Codex CLI | `session_id`, `transcript_path` | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` | `token_count` events | hook payload `model` |
| Gemini CLI | `session_id`, `transcript_path` | `~/.gemini/tmp/<project>/chats/session-*.jsonl` | `tokens.*` | `model` |
| OpenCode | `sessionID` | `~/.local/share/opencode/opencode.db` (SQLite, read-only) | `message.data.tokens` (and `cost`) | `message.data` |
| Copilot CLI | `sessionId` | `~/.copilot/session-state/<id>/events.jsonl` | premium requests (tokens only at shutdown) | — |

- **One parser per agent**, versioned, each with recorded and redacted fixture logs from real
  agent versions. A parser recognises its format by structure; an unrecognised record or file is
  "unknown log", handled by `on_unknown_log`.
- **Incremental state** per session in `~/.cache/aegis/budget/<agent>/<session>.json`: byte
  offset (or the last row id for SQLite), running totals per model, last update time. A file
  that shrank, or an offset past its end, means the totals are recomputed from the start. The
  state is a cache: deleting it costs a re-read, never resets the budget (§8).
- **Project/day totals** are the sum, over sessions whose working directory is inside the
  project root (the directory holding `.aegis/`), of usage timestamped within today in `tz`.
  Kept in `~/.cache/aegis/budget/projects/<sha256(project root)>/<date>.json`, updated with a
  file lock, since agents run tool calls in parallel.
- **Cost:** budget per hook call is a log tail plus a small JSON write; target p99 under 20 ms
  added to the hook, measured in the existing latency benchmark.

## 5. Turning tokens into dollars

- A **built-in price table** (`aegis_core/budget/prices.yaml`), versioned and dated, per model:
  input, output, cache-read and cache-write prices per million tokens. It ships with each
  release; `budget.yaml` may override entries (signed, so an agent cannot cheapen its model).
- **Unknown model:** counted at the most expensive known model of the same vendor, with a
  warning naming the model, so an unpriced model never makes a budget go further. In
  `unit: tokens` mode prices are not used at all.
- **Subscriptions:** most Claude Code and Codex users pay a flat subscription, so "$" there is
  an API-equivalent estimate; the docs and messages say "estimated", and `unit: tokens` is the
  natural mode for them. For API-key users it is a real-money guard.

## 6. Enforcement

When a budget is configured, `aegis install` widens each agent's hook matchers from shell
commands to **all tool calls**, and adds a prompt hook where the agent has one.

| Agent | Before each tool call | Before a new prompt | How "warn" shows |
|---|---|---|---|
| Claude Code | `PreToolUse` (matcher `*`) | `UserPromptSubmit` | `systemMessage` to the user |
| Codex CLI | `PreToolUse` | — | stderr message |
| Gemini CLI | `BeforeTool` | `BeforeAgent` | `systemMessage` |
| OpenCode | plugin `tool.execute.before` | — | toast |
| Copilot CLI | `preToolUse` (premium-request cap) | — | stderr message |

Hook and event names in this table come from the 2026-10-06 research and must be re-checked
against each agent's current version before implementation (step 4 of §10).

- **Below `warn_at`:** nothing changes; budget adds no output.
- **Crossing `warn_at`:** one warning per session per threshold (not per call), with usage, the
  limit and how much is left.
- **At 100%:** every tool call is denied, and every new prompt where possible, with one message:
  what was spent, which limit (session or project/day), and how to continue: start a new
  session (session cap), wait for the next day (project cap), or raise the limit in
  `budget.yaml`, which must be re-signed.
- The infrastructure-policy decision still runs first: a command the policy blocks stays blocked
  whatever the budget says. Budget never turns a BLOCK into an ALLOW.

## 7. CLI

- `aegis budget status [--agent X] [--json]`: this project's day so far and the current (or
  most recent) session per agent, with limits and percentages.
- `aegis budget check`: exit 0 under budget, 3 over, 65 on a broken `budget.yaml`; for CI and
  scripts, including headless agent runs.
- `aegis install <agent>` reports whether the budget hooks were added.
- Later (1.x): a `budget` input on the GitHub Action for headless agent runs in CI.

## 8. Threats and limits

| Threat | Result |
|---|---|
| The agent edits `budget.yaml` to raise its limit | refused: the file is signed and its principal must hold `budget` |
| The agent deletes the cache state | totals are recomputed from the logs; nothing is reset |
| The agent truncates or rewrites its own session log | **not stopped**: the agent runs as the user and can write the log. The budget is a runaway guard against mistakes and loops, not a defence against a deliberately hostile agent; the docs say so |
| A log format changes after an agent update | parser does not recognise it → `on_unknown_log` (allow with a warning by default; `deny` for strict deployments) |
| Parallel tool calls race on the totals | file lock on the project/day state |
| An unknown or renamed model | priced at the vendor's most expensive known model, with a warning |
| Clock or time-zone confusion around midnight | the day comes from `tz` in signed policy; usage is bucketed by the log's own timestamps |

## 9. Why this is 1.0

1.0 is a promise about the public surface, and the budget cap is the right feature to make it
with:

- **Stable from 1.0:** the policy file formats (`constraints`, `authority`, `environments`,
  `plan_constraints`, `agents`, `budget`, all `version: 1`), the CLI commands and their exit
  codes, the hook protocol per agent, and the Action's inputs and outputs. Breaking any of these
  needs 2.0.
- **Explicitly preview within 1.x:** the server-side compilers' output (`aegis compile`) and the
  identity audit, which may still change shape in minor releases.
- **Deferred, and additive when it comes:** public-key signing (DESIGN-v0.4) adds a v2 signature
  format alongside today's; existing policies keep working.

## 10. Implementation plan

1. `aegis_core/budget/`: `budget.yaml` loader (signature, shape, `budget` class), price table,
   per-agent log parsers with fixtures, incremental state with locking, totals.
2. Hook integration: budget evaluation after the policy decision, per-agent warn/deny output,
   prompt hooks; `aegis install` widening the matchers when a budget is configured.
3. `aegis budget status|check`; docs (`docs/budget.md`), README, CHANGELOG; latency measured.
4. Live test per agent on this machine (Claude Code, Codex, Gemini CLI, OpenCode, Copilot CLI),
   as for the original hooks.
5. Release 1.0.0; then the Action's `budget` input in 1.1.

## 11. Open questions

1. **Behaviour at 100%: deny every tool call, or allow read-only tools?** Proposed: deny all —
   simplest to reason about, and a session over budget should stop.
2. **Default unit:** `usd` (meaningful to API-key users) or `tokens` (honest for
   subscriptions)? Proposed: no default — `unit` is required.
3. **Warn as ESCALATE (ask) or as a message?** Proposed: a message; asking on every call near
   the limit would be noise.
4. **Should the project/day cap also count sessions from agents not listed in `agents`?**
   Proposed: no — only listed agents are measured and enforced.
5. **Copilot CLI:** ship the premium-request cap in 1.0, or wait for token data? Proposed: ship
   it, clearly labelled.
