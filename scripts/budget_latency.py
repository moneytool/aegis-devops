"""What the budget cap adds to one ``aegis hook`` call (design v1.0 §4: target
under 20 ms).

Times ``python -m aegis_core.cli hook claude`` as the agent runs it (a new
process per tool call) on a non-shell tool call, in two otherwise identical
projects made with ``aegis init``: one with a signed ``budget.yaml`` and a
Claude Code transcript to read, one without. Runs are interleaved so both see
the same machine load, after a warm-up run, and with bytecode caching on (a
pip install ships compiled bytecode; ``PYTHONDONTWRITEBYTECODE`` would make
every run recompile aegis and inflate both numbers).

    python scripts/budget_latency.py [--runs 40] [--out results/budget-latency.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _setup(base: Path) -> tuple[dict[str, str], dict[str, str]]:
    sys.path.insert(0, str(ROOT / "src"))
    from aegis_core.config import init_config_dir
    from aegis_core.signing import load_key, sign_file

    home = base / "home"
    projects = {"budget": base / "with-budget", "none": base / "without-budget"}
    payloads = {}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for name, project in projects.items():
        init_config_dir(project / ".aegis")
        if name == "budget":
            budget = project / ".aegis" / "budget.yaml"
            budget.write_text("principal: admin\nunit: usd\nsession: {limit: 20}\n"
                              "project_day: {limit: 100}\nagents: [claude]\n")
            sign_file(budget, load_key(f"file:{project / '.aegis' / 'example-signing.key'}"))
        log = home / ".claude" / "projects" / f"-{name}" / "s.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        recs = [{"type": "user", "sessionId": "s", "cwd": str(project), "timestamp": now}]
        recs += [{"type": "assistant", "sessionId": "s", "requestId": f"r{i}", "timestamp": now,
                  "message": {"id": f"m{i}", "model": "claude-opus-5-5",
                              "usage": {"input_tokens": 1000, "output_tokens": 100}}}
                 for i in range(200)]
        log.write_text("".join(json.dumps(r) + "\n" for r in recs))
        payloads[name] = json.dumps({"session_id": "s", "transcript_path": str(log),
                                     "cwd": str(project), "tool_name": "Edit",
                                     "tool_input": {"file_path": "x"}})
    env = {k: v for k, v in os.environ.items() if k not in (
        "PYTHONDONTWRITEBYTECODE", "AEGIS_CONFIG_DIR", "XDG_CACHE_HOME", "XDG_STATE_HOME")}
    env.update({"HOME": str(home), "PYTHONPATH": str(ROOT / "src")})
    return payloads, {**env, "_budget": str(projects["budget"]),
                      "_none": str(projects["none"])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs", type=int, default=40)
    ap.add_argument("--out", default=str(ROOT / "results" / "budget-latency.json"))
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        payloads, env = _setup(Path(tmp))
        cwd = {"budget": env.pop("_budget"), "none": env.pop("_none")}
        cmd = [sys.executable, "-m", "aegis_core.cli", "hook", "claude"]

        def run(name: str) -> float:
            start = time.perf_counter()
            proc = subprocess.run(cmd, input=payloads[name], text=True, capture_output=True,
                                  env=env, cwd=cwd[name], check=False)
            if proc.returncode != 0:
                raise SystemExit(f"hook failed ({name}): {proc.stderr}")
            return (time.perf_counter() - start) * 1000

        for name in payloads:  # warm-up: bytecode, price-table cache, session record
            run(name)
        samples: dict[str, list[float]] = {"budget": [], "none": []}
        for _ in range(args.runs):
            for name in samples:
                samples[name].append(run(name))

    def summary(xs: list[float]) -> dict[str, float]:
        ordered = sorted(xs)
        return {"median_ms": round(statistics.median(xs), 1),
                "p95_ms": round(ordered[max(0, int(len(xs) * 0.95) - 1)], 1)}

    with_b, without = summary(samples["budget"]), summary(samples["none"])
    result = {
        "measured": datetime.now(UTC).date().isoformat(),
        "runs": args.runs,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "hook_without_budget": without,
        "hook_with_budget": with_b,
        "added_median_ms": round(with_b["median_ms"] - without["median_ms"], 1),
        "target_ms": 20,
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
