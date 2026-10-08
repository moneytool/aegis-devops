# Design: cross-agent session budget cap (v1.0)

Status: **draft for review**, 2026-10-07; revised the same day after review (guarantee §6.1, accounting §4.1, unknown prices §5). Builds on the research in
[`TODO-budget-cap.md`](TODO-budget-cap.md) (PLAN backlog item 11). Target release: **v1.0.0** —
the budget cap is the headline feature, and 1.0 also declares the public surface stable (§9).

## 1. Problem

Coding agents spend money (API keys) or quota (subscriptions) with no stop that works
across agents. Reporting exists (ccusage, tokscale); enforcement does not: Claude Code's
`--max-budget-usd` works only in print mode, gateways (LiteLLM, Bifrost) only see traffic routed
through them, and single-agent enforcers have no adoption. A runaway loop — an agent retrying a
failing build all night, or a sub-agent fan-out — has no ceiling.

Aegis already sits in every major agent's hook path and already has signed policy. A budget
written into signed policy is one **the agent cannot raise by editing a file**.

What it guarantees is narrower than a spending ceiling, and §6.1 states it exactly: once
**observed** usage reaches the limit, Aegis stops the agent's **subsequent tool activity** (and
new prompts, where the agent has a prompt hook). Usage is observed after a model request has
been paid for, so a session can end somewhat above its limit.

## 2. Goals and non-goals

Goals:

- One cap — tokens or estimated USD — **per agent session** and **per project per day**, enforced
  by the existing hook in Claude Code, Codex, Gemini CLI and OpenCode; a premium-request cap for
  Copilot CLI.
- Warn at a threshold (default 80%); once observed usage reaches 100%, deny every subsequent
  tool call and, where the agent allows it, new prompts too. Overshoot is bounded and documented
  (§6.1), not zero.
- Budgets live in a signed, authority-checked policy file, like every other Aegis policy.
- No network, no vendor admin keys: usage is read from each agent's local session log.
- Fails safe for the user's work by default (unknown log format → allow with a warning), with a
  strict option.

Non-goals (v1.0): a hard spending ceiling, which needs enforcement before each model request
(a gateway or proxy in the request path, §6.1); team or org roll-ups; vendor admin/billing APIs; Cursor and VS Code agent
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
on_unknown_price: estimate   # estimate (warn) | deny; usd only, see §5
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
- **Cost:** budget per hook call is a log tail plus two small JSON writes (§4.1); target p99
  under 20 ms added to the hook, measured in the existing latency benchmark.

Field names and paths in the table come from the 2026-10-06 research and are re-verified per
agent version in implementation step 4, with fixtures; in particular the `cwd` and parent-session
fields that §4.1 relies on.

### 4.1 Accounting

The **logs are the only source of truth**; everything under `~/.cache/aegis/budget/` is derived
from them and can be rebuilt. Two rules make updates idempotent: a session's usage is only ever
**replaced**, never added to a running total, and a total is always a **sum computed** from
per-session entries.

**Session record** — `~/.cache/aegis/budget/sessions/<agent>/<session id>.json`:

- the log locator (file path, or database path and session id for OpenCode) and the file's
  identity (device, inode, and a hash of its first 4 KiB);
- the read position (byte offset, or last row id), the end of the last complete record only, so
  a half-written line is read again next time;
- usage so far, bucketed by **(day in `tz`, model)**, from each record's own timestamp (a record
  without one goes into the day it was read);
- attribution: the project root and, for a sub-agent, the parent session (below).

**Project contributions** — `~/.cache/aegis/budget/projects/<sha256(project root)>/<date>.json`
maps `(agent, session id)` → that session's usage on that day. The project/day total is the sum
of the map's values, computed on read.

**Update protocol**, on each hook call for session S in project P:

1. Take S's lock (`flock` on `S.json.lock`). Re-read S's record under the lock.
2. Check the file identity. Different inode or head hash, or a file shorter than the offset,
   means the log was replaced or truncated: discard the record and re-read the log from the
   start.
3. Read from the offset to the last complete record; add to the day/model buckets; advance the
   offset. Write the record atomically (temp file, `fsync`, `rename`).
4. Take P's lock, re-read the map, **set** the entry for S to S's bucket for today (replace,
   not add), write atomically, release. Release S's lock.
5. Evaluate both limits from S's record and the map's sum.

A second hook for S that was waiting on the lock finds the offset advanced and reads nothing
new; a crash between steps 3 and 4 leaves the map one update behind, and the next call sets the
entry again. Locks are always taken in the order session → project, so two hooks cannot
deadlock. Reading usage under the lock is what prevents double counting; the lock on the project
file alone would not.

**Project attribution.** A session belongs to the project whose root (the nearest ancestor
holding `.aegis/`, the same lookup the policy uses) contains the **working directory the
session started in**, as recorded in the log; a later `cd` does not move it. Nested projects:
the innermost root wins.

**Sub-agents.** A sub-agent's usage counts toward its **parent session's** session cap and the
parent's project, wherever the log links them: Claude Code writes sub-agent transcripts under
`<session>/subagents/` next to the parent log, and the parser reads them as part of the parent
session. A sub-agent whose log carries no parent link is counted as its own session in the
project its working directory belongs to: still inside the project/day cap, outside the parent's
session cap. Each parser's fixtures cover its agent's sub-agent layout.

**Session discovery and reconstruction.** The project map only knows sessions that ran a hook.
To rebuild it, and on `aegis budget status --rebuild`, each parser implements
`discover(project root, day)`: list its agent's logs modified since the start of the day in
`tz` (an mtime filter keeps this cheap), read each one's starting `cwd`, and keep those
attributed to the project. Then:

- **session record deleted:** rebuilt on the next hook from the log path in the hook payload;
- **project map deleted, or a day file missing:** rebuilt on the next hook by `discover`, under
  P's lock, before step 4;
- **whole cache deleted:** both of the above.

**When logs are unavailable** — rotated, deleted, unreadable, or a payload with no log path —
the usage they held cannot be recovered. The rebuilt total is then a **lower bound**:
`aegis budget status` says "rebuilt from N sessions; M known sessions have no log", and the
case is treated as an unknown log (`on_unknown_log`: `allow` warns once; `deny` denies until the
day ends or the limit is raised). A session record whose log has disappeared keeps its last
totals, so deleting a log after the fact does not lower the count while the cache survives.

## 5. Turning tokens into dollars

- A **built-in price table** (`aegis_core/budget/prices.yaml`), versioned and dated, per model:
  input, output, cache-read and cache-write prices per million tokens. It ships with each
  release; `budget.yaml` may override entries (signed, so an agent cannot cheapen its model).
- **A model's price** comes from a `budget.yaml` override, else the built-in table, matched on
  the exact model id after the parser normalises it (dated aliases, provider prefixes such as
  `anthropic/`). Each table entry names its vendor.
- **Unknown model — a fallback, and only an estimate.** What happens to a model with no price is
  set by `on_unknown_price` in `budget.yaml`:
  - `estimate` (default): a model whose **vendor is identified** — from the provider field the
    log records (OpenCode, Copilot) or the model id's prefix in the table's vendor list — is
    priced at that vendor's most expensive table entry; a model whose vendor **cannot be
    identified, or has no entries**, at the most expensive entry in the whole table. Either is a
    guess, not an upper bound: a new model can cost more than any model Aegis knows. Status
    output and the warning (once per session per model) say "estimated, unpriced model X".
  - `deny`: in `unit: usd`, a session that has used a model with no explicit price (override or
    table) gets its next tool calls denied, with a message naming the model and the
    `pricing:` entry to add. This is the setting for deployments that need dollar figures to be
    exact as far as the published prices go.
- In `unit: tokens` mode prices are not used at all, and `on_unknown_price` is ignored.
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
- **Once observed usage reaches 100%:** every subsequent tool call is denied, and every new
  prompt where possible, with one message:
  what was spent, which limit (session or project/day), and how to continue: start a new
  session (session cap), wait for the next day (project cap), or raise the limit in
  `budget.yaml`, which must be re-signed.
- The infrastructure-policy decision still runs first: a command the policy blocks stays blocked
  whatever the budget says. Budget never turns a BLOCK into an ALLOW.

### 6.1 What is guaranteed, and the overshoot

Hooks run before tool calls and prompts, never before a model request. Usage appears in the log
only after a request has been answered and paid for. So the guarantee is:

> Once the usage Aegis has **observed** reaches a limit, the agent's **subsequent tool calls**
> are denied, and its new prompts where the agent has a prompt hook.

It is **not** a ceiling on spend. The total can exceed the limit by:

- **The request that crossed it.** The model turn that pushed usage over the limit was already
  paid for when the next hook sees it, including a long or expensive turn.
- **Turns after the denial.** A denied tool call returns to the model, which answers once more
  (usually to report the denial), and that turn is paid for too.
- **Tool-free activity.** A model turn with no tool call reaches no tool hook. Where the agent
  has no prompt hook (Codex, OpenCode, Copilot CLI), the user can keep chatting over budget;
  each tool call is still denied.
- **Parallelism.** Concurrent sub-agents and sessions each finish the model request they have in
  flight, and each can make one more call before observing the shared total.

Bound, stated in the docs: roughly one model turn per concurrent session or sub-agent, plus the
reply to the denial, plus unbounded tool-free chat where there is no prompt hook. Users who need
a margin set the limit below their true ceiling. `aegis budget status` reports usage above the
limit as "overshoot", so it is visible rather than hidden.

A hard ceiling needs enforcement **before each model request**: a gateway or proxy in the
request path (LiteLLM, Bifrost, a vendor's own spend limits), or Claude Code's
`--max-budget-usd` in print mode. Aegis does not claim it, and the docs point to those tools for
it. Gating model requests is a possible later layer (the agent would be pointed at a local
Aegis endpoint), not part of 1.0.

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
| The agent deletes the cache state | totals are rebuilt from the logs (§4.1); nothing is reset while the logs exist. Logs already gone make the rebuilt total a lower bound, reported as such |
| The agent truncates or rewrites its own session log | **not stopped**: the agent runs as the user and can write the log. The budget is a runaway guard against mistakes and loops, not a defence against a deliberately hostile agent; the docs say so |
| A log format changes after an agent update | parser does not recognise it → `on_unknown_log` (allow with a warning by default; `deny` for strict deployments) |
| Parallel tool calls race on the totals | per-session lock while reading, then a keyed replace in the project map under its lock (§4.1); no double counting |
| Spend between observations: the crossing request, the reply to a denial, parallel sub-agents, chat without tool calls | **not stopped**: bounded overshoot, documented and shown by `aegis budget status` (§6.1). A hard ceiling needs a gateway in the request path |
| An unknown or renamed model | `estimate`: priced at the vendor's (or the table's) most expensive entry, labelled as an estimate that may be low; `deny`: tool calls denied until priced (§5) |
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
6. **Default for `on_unknown_price`:** `estimate` (keeps working when an agent ships a new model,
   possibly under-counting) or `deny` (exact, but every new model stops sessions until the
   policy is re-signed)? Proposed: `estimate`, with `deny` recommended for API-key deployments.
7. **Gating model requests later?** A local endpoint the agents' API traffic goes through would
   give a hard ceiling (§6.1). Proposed: out of 1.0; revisit if users ask for a hard ceiling.
