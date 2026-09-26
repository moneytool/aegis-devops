#!/bin/bash
# Run one benchmark verifier to completion across usage-limit resets.
#
#   scripts/run_until_done.sh <verifier> [<scratch-out-dir>]
#   e.g. scripts/run_until_done.sh claude-cli-fable
#
# benchmark.py exits 75 when a CLI reports a usage limit, printing
# "QUOTA_EXCEEDED resets_at=<time>". This loop sleeps until shortly after that
# time and runs again. Answers are cached as they arrive and a re-run reuses
# them, so each attempt only asks what the previous one did not reach. A
# usage-limit reply is never cached, so nothing wrong gets recorded.
#
# State for the progress display: results/<verifier>-runner.state
# Log:                            results/<verifier>-run.log
set -u
cd "$(dirname "$0")/.." || exit 1
V=${1:?usage: run_until_done.sh <verifier> [out-dir]}
OUT=${2:-${TMPDIR:-/tmp}/aegis-run-$V}
LOG=results/$V-run.log
STATE=results/$V-runner.state
MAX_ATTEMPTS=12      # ~12 reset cycles is days of waiting; give up after that
FALLBACK_WAIT=${AEGIS_FALLBACK_WAIT:-1800}   # no reset time from the CLI: wait 30 min
# test hook: replace the benchmark command (the loop itself is what is under test)
BENCH=${AEGIS_BENCH_CMD:-venv/bin/python scripts/benchmark.py}
mkdir -p "$OUT"
: > "$LOG"

seconds_until() {  # "10:44 PM" | "2:10am" | "3pm" -> seconds until then (+120s), today or tomorrow
  venv/bin/python - "$1" <<'PY'
import sys, re, datetime as dt
s = sys.argv[1].strip().lower().replace(" ", "")
m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?(am|pm)?", s)
if not m:
    print(-1); raise SystemExit
h, mi, ap = int(m.group(1)), int(m.group(2) or 0), m.group(3)
if ap == "pm" and h != 12: h += 12
if ap == "am" and h == 12: h = 0
now = dt.datetime.now()
t = now.replace(hour=h % 24, minute=mi, second=0, microsecond=0)
if t <= now:
    t += dt.timedelta(days=1)
print(int((t - now).total_seconds()) + 120)
PY
}

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  echo "running (attempt $attempt)" > "$STATE"
  echo "=== attempt $attempt $(date '+%a %H:%M %Z') ===" >> "$LOG"
  $BENCH --verifiers "$V" --out "$OUT" >> "$LOG" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "done $(date '+%H:%M')" > "$STATE"
    echo "=== finished $(date '+%a %H:%M %Z') ===" >> "$LOG"
    exit 0
  fi
  if [ "$rc" -ne 75 ]; then
    echo "FAILED rc=$rc $(date '+%H:%M') -- see $LOG" > "$STATE"
    exit "$rc"
  fi
  when=$(grep -o "QUOTA_EXCEEDED resets_at=[^:]*" "$LOG" | tail -1 | sed 's/QUOTA_EXCEEDED resets_at=//; s/ *$//')
  wait_s=$(seconds_until "$when")
  [ "${wait_s:-0}" -le 0 ] && wait_s=$FALLBACK_WAIT
  until_hm=$(date -v+"${wait_s}"S '+%H:%M')
  echo "waiting for limit reset until $until_hm (CLI said: ${when:-unknown})" > "$STATE"
  echo "--- usage limit; resets_at='$when'; sleeping ${wait_s}s until $until_hm ---" >> "$LOG"
  sleep "$wait_s"
done
echo "GAVE UP after $MAX_ATTEMPTS attempts $(date '+%H:%M')" > "$STATE"
exit 1
