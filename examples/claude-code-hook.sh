#!/usr/bin/env bash
# Claude Code PreToolUse hook: gate every Bash tool call through Aegis.
# Register in .claude/settings.json:
#   {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
#     {"type": "command", "command": "/path/to/aegis-devops/examples/claude-code-hook.sh"}]}]}}
# Claude Code semantics: exit 0 = allow; exit 2 = block, stderr is shown to the model.
# `aegis check command --exit-style claude-hook` takes the raw command string: it splits
# compound commands (";", "&&", "||", "|"), unwraps sudo/env/timeout/sh -c, and checks every
# simple command whose binary Aegis knows; binaries it has no parser for are not gated
# (add --fail-closed to escalate them instead). It returns 0 (ALLOW) or 2 (ESCALATE/BLOCK)
# and prints {"decision": "block", "reason": ...}; those two codes propagate as-is. Any
# tool error -- 64 usage (including a command Aegis refuses to evaluate statically:
# $(...), backticks, eval, xargs ...), 65 data / signature, 66 missing file, 70 internal --
# and any failure of this script's own parsing are converted to 2, so the hook never
# fails open. Run it from the aegis-devops checkout (or set AEGIS_ARGS to point
# --constraints/--key at your own policy files). The aegis binary is $AEGIS_BIN, else the
# venv next to this script, else whatever "aegis" is on PATH.
set -u
fail() { echo "aegis: $1; blocking to fail closed" >&2; exit 2; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
aegis=${AEGIS_BIN:-}
[ -z "$aegis" ] && [ -x "$here/../venv/bin/aegis" ] && aegis="$here/../venv/bin/aegis"
[ -z "$aegis" ] && aegis=aegis
cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null) \
  || fail "could not read hook input"
[ -z "$cmd" ] && exit 0
# shellcheck disable=SC2086  # AEGIS_ARGS is intentionally word-split
"$aegis" check command --exit-style claude-hook ${AEGIS_ARGS:-} -- "$cmd"; rc=$?
case "$rc" in 0|2) exit "$rc" ;; *) fail "tool error (exit $rc)" ;; esac
