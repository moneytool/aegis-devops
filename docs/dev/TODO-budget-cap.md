# TODO: cross-agent session budget cap

Status: **parked**, 2026-10-06. Researched and scoped; not started. Decide when to take it.

## The idea

One hard token / estimated-$ budget per agent session and per project per day, enforced by the
hook Aegis already installs, across Claude Code, Codex, Gemini CLI and OpenCode. Pitch: *"One
hard budget across Claude Code, Codex, Gemini CLI and OpenCode."*

## Why this, and not the alternatives (research, 2026-10-06)

- **Reporting is solved.** ccusage (~18.9k stars, ~557k npm/month) and tokscale (~5.6k stars,
  ~154k npm/month) report usage across many agents; neither enforces.
- **Enforcement is not.** Claude Code's `--max-budget-usd` is print-mode only; the issue asking
  for interactive/unattended caps was closed as not planned. The enforcers that exist cover one
  agent and have almost no adoption (budgetclaw: 8 stars). Gateways (LiteLLM, Bifrost) enforce
  only for traffic routed through them and cannot see tool calls.
- **Aegis differentiator:** the budget lives in a *signed* policy file, so the agent cannot
  raise its own cap by editing it. No competitor has this.
- **Rejected: cross-vendor spend report from admin APIs.** Needs Enterprise/Teams admin keys we
  do not have to test with; seat products (M365, Copilot metrics, Gemini Code Assist, Kiro)
  give activity counts, not $; GitHub's per-user cost is a UI download, not REST; joining
  identities across vendors is messy; FOCUS has no AI columns until 1.5 (~end of 2026);
  adoption would be invisible private deployments.
- **Rejected (by the user): per-session action budgets** (max N infra commands per session).
  Signed `rate_limit` constraints already cover time-window action budgets.

## What each agent exposes

No pre-tool hook payload carries token usage; the cap must read the session log on each call.

| Agent | Hook gives | Local log with tokens + model | v1 support |
|---|---|---|---|
| Claude Code | `session_id`, `transcript_path` | `~/.claude/projects/<slug>/<session>.jsonl`, `message.usage.*`, `message.model` | full |
| Codex CLI | `session_id`, `transcript_path`, `model` | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`, `token_count` events | full |
| Gemini CLI | `session_id`, `transcript_path` (AfterModel hook also has `usageMetadata`) | `~/.gemini/tmp/<project>/chats/session-*.jsonl`, `tokens.*`, `model` | full |
| OpenCode | `sessionID` | `~/.local/share/opencode/opencode.db`, `message.data` has `cost` and `tokens` | full |
| Copilot CLI | `sessionId` | `~/.copilot/session-state/<id>/events.jsonl`, premium requests mid-session, tokens only at shutdown | premium-request cap |
| VS Code agent | `session_id` | undocumented chatSessions JSON | not supported |
| Cursor | `conversation_id`, `model` | no token fields found | not supported |

Most Claude Code / Codex users are on flat subscriptions, so "$" there is an API-equivalent
estimate: frame it as a runaway guard, offer a tokens mode, and real money protection for
API-key users.

## Proposed v1 scope (~3-5 days with tests; next minor release)

1. `.aegis/budget.yaml`, signed like the other policy files: per-session and per-project-per-day
   caps in tokens or estimated $; ask at 80%, deny at 100%.
2. When a budget is set, the hook also gates non-shell tool calls (wider matchers), and in Claude
   Code blocks new prompts (`UserPromptSubmit`) once over budget. Today the matchers only see
   shell commands (`hook.py` `merge_config`).
3. Incremental log reads (remember the offset per session); unknown log format -> fail open
   with a warning.
4. A small built-in price table plus a tokens mode.
5. `aegis budget status` (current session and today).
6. A budget input on the GitHub Action for headless agent runs (can slip to a patch release).

Out of v1: team rollups, the admin-API report, Cursor, VS Code.

Risk: agent log formats are undocumented and change between versions; this needs upkeep.

## Sources

- Hooks: code.claude.com/docs/en/hooks, learn.chatgpt.com/docs/hooks,
  docs.github.com/en/copilot/reference/hooks-configuration,
  code.visualstudio.com/docs/agents/reference/hooks-reference, cursor.com/docs/agent/hooks,
  geminicli.com/docs/hooks/reference/, opencode.ai/docs/plugins/
- Landscape: github.com/ryoppippi/ccusage, github.com/junhoyeo/tokscale,
  github.com/RoninForge/budgetclaw, github.com/BerriAI/litellm, github.com/maximhq/bifrost,
  code.claude.com/docs/en/cli-reference (`--max-budget-usd`)
- Vendor APIs: platform.claude.com/docs/en/manage-claude/usage-cost-api,
  platform.claude.com/docs/en/manage-claude/claude-code-analytics-api,
  docs.github.com/en/rest/billing/usage, cursor.com/docs/account/teams/admin-api,
  focus.finops.org/focus-specification/
