#!/usr/bin/env bash
# Plugin entry point: find the aegis binary and hand it the hook payload.
#
#   aegis-hook.sh <agent>                (the payload arrives on stdin)
#   aegis-hook.sh <agent> --budget-only  (non-shell tools and prompts: only the
#                                         budget cap applies, so this exits at
#                                         once unless the policy directory that
#                                         applies holds a budget.yaml)
#
# aegis itself decides everything (see aegis_core/hook.py): outside a
# project with a policy it allows every command, inside one it blocks only
# what the policy blocks. This wrapper only has to cope with aegis not
# being installed. Then it cannot parse anything, so it falls back to the
# same rule in its crudest form: in an opted-in project (a .aegis/ here or
# above, $AEGIS_CONFIG_DIR, or ~/.config/aegis) block any payload that
# names an infrastructure binary, and allow the rest.
set -u
agent=${1:-claude}
mode=${2:-}

# The policy directory aegis would use: $AEGIS_CONFIG_DIR, the nearest .aegis/
# at or above the project, or ~/.config/aegis (as aegis_core/hook.py does).
policy_dir() {
  if [ -n "${AEGIS_CONFIG_DIR:-}" ]; then printf '%s' "$AEGIS_CONFIG_DIR"; return 0; fi
  d=${CLAUDE_PROJECT_DIR:-${COPILOT_PROJECT_DIR:-${GEMINI_PROJECT_DIR:-$PWD}}}
  while [ -n "$d" ]; do
    if [ -d "$d/.aegis" ]; then printf '%s' "$d/.aegis"; return 0; fi
    [ "$d" = "/" ] && break
    d=$(dirname "$d")
  done
  if [ -d "$HOME/.config/aegis" ]; then printf '%s' "$HOME/.config/aegis"; return 0; fi
  return 1
}

if [ "$mode" = "--budget-only" ]; then
  dir=$(policy_dir) || exit 0
  [ -f "$dir/budget.yaml" ] || exit 0
fi
payload=$(cat)

aegis=${AEGIS_BIN:-}
if [ -z "$aegis" ] && command -v aegis >/dev/null 2>&1; then aegis=aegis; fi
if [ -n "$aegis" ]; then
  printf '%s' "$payload" | "$aegis" hook "$agent"
  exit $?
fi
if command -v uvx >/dev/null 2>&1; then
  printf '%s' "$payload" | uvx --quiet --from aegis-devops aegis hook "$agent"
  rc=$?
  # uvx itself failing (offline, no such package) is not a verdict
  case "$rc" in 0|2) exit "$rc" ;; esac
fi

# Without aegis nothing can be measured; the budget-only entries allow.
[ "$mode" = "--budget-only" ] && exit 0

opted_in() {
  [ -n "${AEGIS_CONFIG_DIR:-}" ] && return 0
  [ -d "$HOME/.config/aegis" ] && return 0
  d=${CLAUDE_PROJECT_DIR:-${COPILOT_PROJECT_DIR:-${GEMINI_PROJECT_DIR:-$PWD}}}
  while [ -n "$d" ]; do
    [ -d "$d/.aegis" ] && return 0
    [ "$d" = "/" ] && break
    d=$(dirname "$d")
  done
  return 1
}
opted_in || exit 0
infra='kubectl|k|terraform|tf|tofu|aws|az|gcloud|gsutil|helm|argocd|flux|git|gh|psql|mysql|sqlite3|mongosh|pulumi|alembic|flyway|rails|prisma'
if printf '%s' "$payload" | grep -Eq "(^|[^[:alnum:]_.-])($infra)([^[:alnum:]_.-]|$)"; then
  echo "aegis-devops is not installed, so this infrastructure command cannot be checked: run 'pip install aegis-devops' (blocking to fail closed)" >&2
  exit 2
fi
exit 0
