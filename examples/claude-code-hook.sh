#!/usr/bin/env bash
# Claude Code PreToolUse hook: gate every Bash tool call through Aegis.
# Register in .claude/settings.json:
#   {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
#     {"type": "command", "command": "/path/to/aegis-devops/examples/claude-code-hook.sh"}]}]}}
# Claude Code semantics: exit 0 = allow; exit 2 = block, stderr is shown to the model.
# `aegis --exit-style claude-hook` returns 0 (ALLOW) or 2 (ESCALATE/BLOCK) and prints
# {"decision": "block", "reason": ...}; those two codes propagate as-is. Any tool error
# (64 usage / 65 data / 66 missing file / 70 internal) and any failure of this script's
# own parsing are converted to 2, so the hook never fails open. Compound commands
# (";", "&&", "||", "|", "$(...)") are rejected by aegis as a usage error (64) -- and hence
# blocked here -- until REVIEW-4 T1.2 adds --split-compound.
set -u
fail() { echo "aegis: $1; blocking to fail closed" >&2; exit 2; }
cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null) \
  || fail "could not read hook input"
[ -z "$cmd" ] && exit 0
# shell-split into one token per line; punctuation_chars makes ";" / "&&" / "|" their own tokens
split=$(python3 -c 'import shlex,sys
print("\n".join(shlex.shlex(sys.argv[1], posix=True, punctuation_chars=True)))' "$cmd" 2>/dev/null) \
  || fail "could not split command: $cmd"
argv=(); while IFS= read -r tok; do argv+=("$tok"); done <<< "$split"
case "$(basename "${argv[0]}")" in  # binaries Aegis knows how to parse; anything else is not gated
  kubectl|aws|az|gcloud|gsutil|helm|argocd|flux|git|gh|psql|mysql|sqlite3|mongosh|pulumi|alembic|flyway|rails|prisma) ;;
  *) exit 0 ;;
esac
aegis check argv --exit-style claude-hook -- "${argv[@]}"; rc=$?
case "$rc" in 0|2) exit "$rc" ;; *) fail "tool error (exit $rc)" ;; esac
