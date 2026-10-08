# Design: cross-agent session budget cap (v1.0)

Status: **draft for review**, 2026-10-07; revised the same day after two review rounds (guarantee §6.1, accounting §4.1, pricing §5, validation §10 step 5); §11 questions 6–7 decided. Builds on the research in
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

What it guarantees is narrower than a spending ceiling, and §6.1 states it exactly: Aegis
denies covered tool calls and prompts when the usage available at that hook reaches the limit.
It does **not** bound further model spending; usage is recorded after a model request has been
paid for, and spend that never reaches a hook is not stopped.

## 2. Goals and non-goals

Goals:

- One cap — tokens or estimated USD — **per agent session** and **per project per day**, enforced
  by the existing hook in Claude Code, Codex, Gemini CLI and OpenCode; a premium-request cap for
  Copilot CLI.
- Warn at a threshold (default 80%); once the usage available at a hook reaches 100%, deny
  covered tool calls and, where the agent allows it, new prompts. Spend past the limit is
  possible, not bounded, and reported (§6.1).
- Budgets live in a signed, authority-checked policy file, like every other Aegis policy.
- No network, no vendor admin keys: usage is read from each agent's local session log.
- Fails safe for the user's work by default (unknown log format → allow with a warning), with a
  strict option.

Non-goals (v1.0): any finite bound on spending, which would need enforcement before each
model request (§6.1); team or org roll-ups; vendor admin/billing APIs; Cursor and VS Code agent
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
- **Cost:** budget per hook call is a log tail plus two small JSON writes and, at most once a minute, an inventory append (§4.1); target p99
  under 20 ms added to the hook, measured in the existing latency benchmark.

Field names and paths in the table come from the 2026-10-06 research and are re-verified per
agent version in implementation step 4, with fixtures; in particular the `cwd` and parent-session
fields that §4.1 relies on.

### 4.1 Accounting

The **logs are the source of truth for usage**; everything under `~/.cache/aegis/budget/` is
derived from them and can be rebuilt. A small **session inventory** outside the cache (below)
records which sessions existed, so a rebuild can tell when history is missing. Three rules make
updates idempotent: a session's usage is only ever **replaced**, never added to a running
total; a replacement only wins if it is **newer** (a per-session revision); and a total is
always a **sum computed** from per-session entries.

**Session record** — `~/.cache/aegis/budget/sessions/<agent>/<session id>.json`:

- the log locator (file path, or database path and session id for OpenCode) and the file's
  identity (device, inode, and a hash of its first 4 KiB);
- the read position (byte offset, or last row id), the end of the last complete record only, so
  a half-written line is read again next time;
- a **revision** number, incremented on every write of the record;
- usage so far as **token counts per billing category** (input, output, cache read, cache
  write; premium requests for Copilot), bucketed by **(day in `tz`, original model id)**. Dollars
  are never stored: they are computed from the current prices when read (§5);
- the day of each record comes from **stable recorded metadata**: its own timestamp, else the
  nearest earlier timestamped record in the same log, else the session start time recorded in
  the log. A record with none of these is bucketed as **day unknown**: it counts toward the
  session cap, is left out of every day's project total, is shown in `aegis budget status`,
  and is an unknown log for `on_unknown_log`. It is never put in the day it happens to be read,
  so rebuilding a cache cannot move old usage into today;
- attribution: the project root and, for a sub-agent, the parent session (below).

**Project contributions** — `~/.cache/aegis/budget/projects/<sha256(project root)>/<date>.json`
maps `(agent, session id)` → `(revision, that session's usage on that day)`. The project/day
total is the sum of the map's usage values, computed on read. Only a **contribution owner** has
an entry: a top-level session, or an unlinked sub-agent (see Sub-agents).

**Merge rule**, used by every writer of the map: under P's lock, re-read the map and, for each
incoming `(session, revision, usage)`, set the entry only if the incoming revision is greater
than the stored one. Writers merge entries one by one; nobody ever writes a whole map built
from an earlier snapshot.

**Update protocol**, on each hook call for session S in project P:

1. Take S's lock (`flock` on `S.json.lock`). Re-read S's record under the lock.
2. Check the file identity. Different inode or head hash, or a file shorter than the offset,
   means the log was replaced or truncated: discard the record and re-read the log from the
   start.
3. Read from the offset to the last complete record; add to the day/model buckets; advance the
   offset. Write the record atomically (temp file, `fsync`, `rename`).
4. Take P's lock and **merge** S's entry for today with S's new revision (merge rule), write
   atomically, release. Release S's lock.
5. Evaluate both limits from S's record and the map's sum.

A second hook for S that was waiting on the lock finds the offset advanced and reads nothing
new. A crash after step 3 and before step 4 leaves the map one revision behind; the next call
merges again (crash recovery). Locks are always taken in the order session → project, and
no code path takes a session lock while holding a project lock, so hooks and rebuilds cannot
deadlock. Reading usage under the session lock is what prevents double counting; the lock on
the project file alone would not.

**Project attribution.** A session belongs to the project whose root (the nearest ancestor
holding `.aegis/`, the same lookup the policy uses) contains the **working directory the
session started in**, as recorded in the log; a later `cd` does not move it. Nested projects:
the innermost root wins.

**Sub-agents.** One owner per unit of usage. A **linked** sub-agent (its log links it to a
parent session; Claude Code writes sub-agent transcripts under `<session>/subagents/` next to
the parent log) is part of the parent: the parser reads its logs into the parent's session
record, so its usage counts toward the parent's session cap and appears **only inside the
parent's** project entry, never as an entry of its own. Hooks fired from a linked sub-agent
update the parent's record, and `discover` (below) skips linked sub-agent logs as top-level
sessions. An **unlinked** sub-agent (no parent link in its log) is its own session and owner:
inside the project/day cap of the project its working directory belongs to, outside any
parent's session cap. Each parser's fixtures cover its agent's sub-agent layout.

**Session inventory** — `~/.local/state/aegis/budget/<sha256(project root)>/<date>.jsonl`
(`$XDG_STATE_HOME`), **outside the disposable cache**: an append-only line per session the first
time Aegis sees it (agent, session id, log locator, start time), and a checkpoint of its usage
and revision at most once a minute. Deleting `~/.cache/aegis/` does not touch it. It is not
tamper-proof — the agent runs as the same user (§8) — but it lets a rebuild know what it should
find.

**Discovery and rebuild.** The project map only knows sessions that ran a hook. Each parser
implements `discover(project root, day)`: list its agent's logs modified since the start of the
day in `tz` (an mtime filter keeps this cheap), read each one's starting `cwd`, keep the
top-level and unlinked sessions attributed to the project. A rebuild runs on the next hook when
the project's day file is missing, and on `aegis budget status --rebuild`:

1. **Without holding P's lock**, list the sessions: discovered ones plus those in the inventory.
2. For each session, take **that session's lock alone**, bring its record up to date from its
   log (the update protocol's steps 1–3, which bump its revision), note `(revision, usage)`,
   and release it. A session whose log is gone uses its inventory checkpoint.
3. Take P's lock and **merge** every noted entry by the merge rule. An entry a concurrent hook
   has since updated has a higher revision and is kept; a rebuild can never overwrite newer data.

A missing **session record** alone is rebuilt by step 2 for that session on its next hook.

**Completeness.** Each rebuild records how complete it is, and `aegis budget status` shows it:

- **complete:** every inventory session for the day was read from its log;
- **partial:** the inventory names sessions whose logs are gone; their checkpoints are used, and
  the status says "M of N sessions rebuilt from checkpoints";
- **unknown:** the inventory itself is missing or unreadable, so there is no record of which
  sessions existed. Aegis never reports "0 missing" in this case.

The totals of a partial or unknown rebuild are treated as an unknown log. With `on_unknown_log:
allow` Aegis warns once and continues with the lower total. With `on_unknown_log: deny` (strict
recovery) covered tool calls are denied until the day boundary in `tz`, or until an explicit
`aegis budget reset --day`, which writes a reset marker **signed with the policy key** (the same
authority as raising the limit), so an agent cannot clear it by itself.

## 5. Turning tokens into dollars

- A **built-in price table** (`aegis_core/budget/prices.yaml`), versioned and dated, per model:
  input, output, cache-read and cache-write prices per million tokens. It ships with each
  release; `budget.yaml` may override entries (signed, so an agent cannot cheapen its model).
- **A model's price** comes from a `budget.yaml` override, else the built-in table, matched on
  the exact model id after the parser normalises it (dated aliases, provider prefixes such as
  `anthropic/`). Each table entry names its vendor.
- **Unknown model — a fallback, and only an estimate.** What happens to a model with no price is
  set by `on_unknown_price` in `budget.yaml`:
  - `estimate` (**default**, decided in §11 question 6): a model whose **vendor is
    identified** — from the provider field the log records (OpenCode, Copilot) or the model id's
    prefix in the table's vendor list — is priced, **per billing category**, at the highest
    input, highest output, highest cache-read and highest cache-write rate among that vendor's
    entries (taken separately, since no single model need have the highest rate in every
    category). A model whose vendor **cannot be identified, or has no entries**, gets the
    highest rate per category across the whole table. A known model whose entry lacks a category
    gets the fallback rate for that category only. All of this is a guess, not an upper bound: a
    new model can cost more than any model Aegis knows. Status output and the warning (once per
    session per model) say "estimated, unpriced model X".
  - `deny`: documented for users who prefer to stop covered activity when a price is unknown,
    such as API-key deployments. In `unit: usd`, a session that has used a model with no
    explicit price for a category it used (override or table) gets its covered tool calls
    denied, with a message naming the model and the `pricing:` entry to add. This makes the
    dollar figure **require explicit prices**; it still is not an invoice.
- **Repricing.** Usage is stored as tokens per category under the **original model id** (§4.1),
  and dollars are computed when read. Adding a signed price override therefore re-prices all
  earlier usage of that model, estimated or not, without re-reading logs and without double
  counting.
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
- **Once the usage available at the hook reaches 100%:** every covered tool call is denied,
  and every new prompt where possible, with one message:
  what was spent, which limit (session or project/day), and how to continue: start a new
  session (session cap), wait for the next day (project cap), or raise the limit in
  `budget.yaml`, which must be re-signed.
- The infrastructure-policy decision still runs first: a command the policy blocks stays blocked
  whatever the budget says. Budget never turns a BLOCK into an ALLOW.

### 6.1 What is guaranteed, and what is not

Hooks run before tool calls and prompts, never before a model request, and usage appears in a
log only after a request has been answered and paid for. The guarantee is exactly:

> Aegis denies covered tool calls and prompts when the usage available at that hook reaches the
> limit. It does not impose a finite bound on additional model spending; in-flight requests,
> delayed usage records, retries after denial, and tool-free activity can add cost.

Illustrative sources of spend past the limit, none of them bounded by Aegis:

- **In-flight requests.** The model turn that crossed the limit, and any request already running
  in a parallel session or sub-agent, are paid for before a hook can see them.
- **Delayed usage records.** An agent may write usage some time after the request (Copilot CLI
  reports tokens only at shutdown), so a hook can evaluate against a total that is behind.
- **Retries after denial.** A denied tool call returns to the model, which may answer, retry the
  call, or try other tools; each of those model turns is paid for, however many there are.
- **Tool-free activity.** A model turn with no tool call reaches no tool hook. Where the agent
  has no prompt hook (Codex, OpenCode, Copilot CLI), the user can keep chatting over budget.

`aegis budget status` reports usage above a limit as **observed overshoot**, so it is visible.
Users who want a margin set the limit below the amount they must not exceed.

Bounding spend needs enforcement **before each model request**. Gateways or proxies in the
request path (LiteLLM, Bifrost), vendors' own spend limits, and Claude Code's `--max-budget-usd`
in print mode are **alternative enforcement layers**; the docs mention them as such, and their
guarantees must be verified for each deployment rather than assumed. Gating model requests
through a local Aegis endpoint is out of 1.0 (decided, §11 question 7).

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
| The agent deletes the cache state | totals are rebuilt from the logs and the session inventory (§4.1); nothing is reset while the logs exist. Missing logs or a missing inventory make the rebuild partial or of unknown completeness, reported as such and denied in strict mode |
| The agent truncates or rewrites its own session log | **not stopped**: the agent runs as the user and can write the log. The budget is a runaway guard against mistakes and loops, not a defence against a deliberately hostile agent; the docs say so |
| A log format changes after an agent update | parser does not recognise it → `on_unknown_log` (allow with a warning by default; `deny` for strict deployments) |
| Parallel tool calls, or a rebuild, race on the totals | per-session lock while reading; keyed, revision-checked merge into the project map under its lock; lock order session → project only (§4.1). No double counting, no stale overwrite |
| Spend a hook cannot see in time: in-flight requests, delayed usage records, retries after denial, tool-free activity | **not stopped, not bounded** (§6.1); observed overshoot is reported by `aegis budget status`. Bounding spend needs a layer before each model request, whose guarantees must be verified separately |
| An unknown or renamed model | `estimate`: priced at the vendor's (or the table's) most expensive entry, labelled as an estimate that may be low; `deny`: tool calls denied until priced (§5) |
| Clock or time-zone confusion around midnight | the day comes from `tz` in signed policy; usage is bucketed by stable recorded timestamps, never by the time it is read, so a rebuild after midnight puts old usage in its own day |

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
5. **Validation cases**, as automated tests with fixtures and as part of the live runs:
   - spend past the limit (§6.1): delayed usage records, parallel sessions sharing a project cap,
     repeated retries of a denied tool, turns without tools; each must deny covered calls once
     the available usage is over, and report the observed overshoot;
   - accounting (§4.1): a crash between the session write and the project merge; a rebuild
     concurrent with hook updates (no stale overwrite, no deadlock); linked sub-agent discovery
     (counted once, inside the parent); missing history (logs gone with the inventory present →
     partial; inventory gone → unknown, never "0 missing"; strict mode denies); a rebuild after
     midnight (old usage stays in its own day; timestamp-less records never move into today);
   - pricing (§5): unknown vendor, a missing price category, an explicit override re-pricing
     earlier estimated usage, and `unit: tokens` ignoring prices.
6. Release 1.0.0; then the Action's `budget` input in 1.1.

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
6. **Default for `on_unknown_price`** — **decided:** `estimate` is the default (keeps working
   when an agent ships a new model, possibly under-counting); `deny` (requires explicit prices,
   so every new model stops covered activity until a price is signed) is documented for users
   who prefer it, such as API-key deployments.
7. **Gating model requests** — **decided:** out of 1.0. A local endpoint that the agents' API
   traffic goes through is the only way Aegis itself could bound spend (§6.1); revisit if users
   ask for it.
