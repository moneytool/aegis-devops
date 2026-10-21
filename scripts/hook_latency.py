"""What one ``aegis hook claude`` call costs on a shell command, and how two
aegis versions compare (1.1 added inline-code and script checks to that path).

Each interpreter given with ``--python NAME=PATH`` must have aegis-devops
installed (e.g. ``uv venv a && uv pip install --python a/bin/python
aegis-devops==1.0.0``). For every command below, the hook runs as the agent
runs it -- a new process per tool call -- in a project made with ``aegis init``
(the example policy). Runs are interleaved across interpreters and commands so
all see the same machine load, after a warm-up run, with bytecode caching on
(``PYTHONDONTWRITEBYTECODE`` would make every run recompile aegis).

    python scripts/hook_latency.py --python 1.0.0=/tmp/a/bin/python \\
        --python 1.1.0=/tmp/b/bin/python [--runs 30] [--out results/hook-latency.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COMMANDS = [
    ("plain", "ls -la"),
    ("blocked", "kubectl delete namespace prod"),
    ("pipeline", "kubectl get pods -o json | python3 -c 'import json,sys; json.load(sys.stdin)'"),
    ("inline-infra", "python3 -c \"import subprocess; subprocess.run(['kubectl','get','pods'])\""),
    ("script", "bash nuke.sh"),
    ("expansion", 'bash cleanup.sh "$TARGET"'),
]


def _payload(command: str, cwd: Path) -> str:
    return json.dumps({"session_id": "s", "cwd": str(cwd), "tool_name": "Bash",
                       "hook_event_name": "PreToolUse", "tool_input": {"command": command}})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--python", action="append", required=True, metavar="NAME=PATH")
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--out", default=str(ROOT / "results" / "hook-latency.json"))
    args = ap.parse_args()
    pythons = dict(p.split("=", 1) for p in args.python)
    env = {k: v for k, v in os.environ.items() if k not in (
        "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "AEGIS_CONFIG_DIR", "XDG_CACHE_HOME",
        "XDG_STATE_HOME")}
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        first = next(iter(pythons.values()))
        subprocess.run([first, "-m", "aegis_core.cli", "init", str(project / ".aegis")],
                       check=True, capture_output=True)
        env["HOME"] = str(Path(tmp) / "home")
        versions = {}
        for name, py in pythons.items():
            versions[name] = subprocess.run(
                [py, "-c", "import aegis_core; print(aegis_core.__version__)"],
                capture_output=True, text=True, check=True).stdout.strip()

        def run(py: str, command: str) -> tuple[float, str]:
            start = time.perf_counter()
            proc = subprocess.run([py, "-m", "aegis_core.cli", "hook", "claude"],
                                  input=_payload(command, project), text=True,
                                  capture_output=True, env=env, cwd=project, check=False)
            elapsed = (time.perf_counter() - start) * 1000
            if proc.returncode not in (0, 2):
                raise SystemExit(f"hook failed ({py}, {command!r}): {proc.stderr}")
            decision = "deny" if proc.returncode == 2 else (
                json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
                if proc.stdout.strip() else "allow")
            return elapsed, decision

        decisions: dict[str, dict[str, str]] = {n: {} for n in pythons}
        for name, py in pythons.items():  # warm-up: bytecode
            for label, command in COMMANDS:
                decisions[name][label] = run(py, command)[1]
        samples = {n: {label: [] for label, _ in COMMANDS} for n in pythons}
        for _ in range(args.runs):
            for label, command in COMMANDS:
                for name, py in pythons.items():
                    samples[name][label].append(run(py, command)[0])

    def summary(xs: list[float]) -> dict[str, float]:
        ordered = sorted(xs)
        return {"median_ms": round(statistics.median(xs), 1),
                "p95_ms": round(ordered[max(0, int(len(xs) * 0.95) - 1)], 1)}

    result = {
        "measured": datetime.now(UTC).date().isoformat(),
        "runs": args.runs,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "versions": versions,
        "commands": {label: command for label, command in COMMANDS},
        "results": {name: {label: {**summary(xs), "decision": decisions[name][label]}
                           for label, xs in by_cmd.items()}
                    for name, by_cmd in samples.items()},
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
