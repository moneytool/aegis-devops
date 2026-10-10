# Budget cap: live test in each agent (v1.0, step 4)

Run on 2026-10-09 (US Central; 2026-10-10 UTC) on macOS (Apple M4 Pro) against `main` at
`b838ec1` (#40 merged), installed into a throwaway venv. Each agent ran headless in a throwaway
project made with `aegis init`, whose `budget.yaml` (signed with the example key) set a
**1,000-token session limit**: any model turn exceeds it, so the first tool call or prompt
that comes after usage reaches the log should be denied.

```yaml
version: 1
principal: admin
unit: tokens
session: {limit: 1000, warn_at: 0.5}
project_day: {limit: 100000000}
agents: [claude, codex, gemini, opencode, copilot]
on_unknown_log: allow
copilot: {premium_requests: 1}
```

## Results

| Agent (version) | Hooks installed | Tool call after usage is logged | New prompt over budget | When usage reaches the log |
|---|---|---|---|---|
| Claude Code 2.1.273 | project `.claude/settings.json` (`PreToolUse *`, `UserPromptSubmit`) | **denied**: the `Read` call after the first turn, "session limit reached: 22,848 tokens of 1,000 tokens" | **blocked** (`claude -p --resume`): 0 model turns, $0 | before the tool runs: the first tool call already sees its turn |
| Codex CLI 0.162.0-alpha | user `~/.codex/hooks.json` (`PreToolUse .*`, `UserPromptSubmit`) | **denied** in a later turn: "Command blocked by PreToolUse hook: aegis budget: session limit reached: 21,241 tokens of 1,000 tokens" | **blocked** (`codex exec resume`): "UserPromptSubmit Blocked" | at the end of the model response: tool calls of the **same** turn (here two parallel `cat`s) see none of it |
| OpenCode 1.18.26 | project plugin (`BUDGET_MODE auto`) | **denied** in the second step: "Read .aegis/budget.yaml failed … session limit reached: 12,958 tokens" | — (no prompt hook) | when the step finishes, **after** its tool calls: the first step's tool call is allowed |
| Copilot CLI 1.0.89-5 | user `~/.copilot/hooks/aegis.json` (`preToolUse`, every tool) | not denied in a one-prompt run (`aegis budget status` then showed 1.00 of 1.00 premium requests, `deny`) | — (its prompt hook cannot block) | `session.usage_checkpoint` at the **end of the turn**: the premium-request count is visible only to later turns |
| Gemini CLI 0.61.0 | project `.gemini/settings.json` (`BeforeTool .*`, `BeforeAgent`) | **not tested**: the account's API returned *402 prepayment credits depleted* before any model turn | `BeforeAgent` fired and registered the session (0 tokens, allowed) | — |

Every denial message reached the model, which reported the limit and the ways to continue
instead of working around them. `aegis budget status` agreed with every hook decision and
listed each session with its usage.

## What it showed

1. **The protocol works in Claude Code, Codex and OpenCode, live:** non-shell tools (Claude's
   `Read`, OpenCode's `read`) reach the budget gate; shell commands go through the policy and
   then the budget; denied prompts cost nothing.
2. **When an agent writes usage decides how late the cap bites** — the "delayed usage records"
   of design §6.1, now measured per agent:
   - Claude Code writes a response's usage before its tool calls run: denial on the first tool
     call after the limit.
   - Codex writes `token_count` after the response, but the response's own (parallel) tool calls
     are already dispatched: denial from the next turn.
   - OpenCode writes a step's tokens when the step finishes, after its tool calls: denial from
     the next step.
   - Copilot CLI writes its premium-request checkpoint at the end of a turn: denial from the next
     turn's tool calls; a single `-p` prompt cannot be stopped.

   `docs/budget.md` now states this per agent.
3. **Install friction, documented:** Codex loads project hooks only in a trusted project and
   new hooks only after review (`/hooks`), so an unattended run needs a user-level install and
   `--dangerously-bypass-hook-trust`; Copilot CLI loads repository hooks only in trusted folders
   (user-level always loads); Gemini CLI headless needs `GEMINI_CLI_TRUST_WORKSPACE=true` (or
   `--skip-trust`) in an untrusted folder.

## Cost

Claude Code: $0.18 (one 2-turn run; the blocked resume cost $0). Codex: 4 runs on a ChatGPT
plan (~20k–64k tokens each). OpenCode: 2 runs on `github-copilot/gpt-5-mini`. Copilot CLI: 1
run (19.98 AI credits, 1 premium request). Gemini: none (402 before the first request).

## Clean-up

The temporary user-level hooks (`~/.copilot/hooks/aegis.json`, `~/.codex/hooks.json`, neither
of which existed before) were removed with `aegis install … --remove`; the throwaway project,
venv and run logs were in `/private/tmp/aegis-budget-live/`.
