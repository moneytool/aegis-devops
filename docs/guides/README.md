# Guides

Short, task-first pages. Each one starts from a problem and ends with a working install.

- [Stop Claude Code from running terraform destroy, kubectl delete or DROP TABLE](claude-code.md)
- [Stop Cursor's agent from running terraform destroy, kubectl delete or DROP TABLE](cursor.md)
- [Stop OpenAI Codex CLI from running terraform destroy, kubectl delete or DROP TABLE](codex.md)
- [Stop GitHub Copilot (CLI and VS Code agent mode) from running destructive commands](copilot.md)
- [Stop Gemini CLI from running terraform destroy, kubectl delete or DROP TABLE](gemini-cli.md)
- [Block risky Terraform and OpenTofu plans in CI, before anyone applies them](terraform-plan-ci.md)
- [Check the SQL an LLM writes before your app runs it](app-sql.md) (experimental: the database role does the scoping, Aegis enforces reads-only under signed rules)
- [Cap what a coding agent spends, per session and per day](../budget.md) (Claude Code, Codex, Gemini CLI, OpenCode, Copilot CLI; also in CI with the Action's `budget` input)

Examples were run against aegis-devops 1.0.0 with the policy from `aegis init`.

Reference: [coding agents](../agents.md) · [writing constraints](../constraints.md) · [configuration](../configuration.md) · [server-side enforcement](../server-side.md)
