"""What one ``aegis hook claude`` call costs on a shell command, and how two
aegis versions compare (1.1 added inline-code and script checks to that path).

Each interpreter given with ``--python NAME=PATH`` must have aegis-devops
installed (e.g. ``uv venv a && uv pip install --python a/bin/python
aegis-devops==1.0.0``). For every command below, the hook runs as the agent
runs it -- a new process per tool call -- in a project made with ``aegis init``
(the example policy, written by the first interpreter's aegis: recorded as
``policy_from``). Runs are interleaved across interpreters and commands so all
see the same machine load, the interpreter order alternating each round, after
a warm-up run, with bytecode caching on (``PYTHONDONTWRITEBYTECODE`` would make
every run recompile aegis). The caller's ``AEGIS_*`` settings are removed, so
its signing key cannot replace the example key. The interpreters must be the
same Python; every timed run must reach the warm-up's decision, and a hook
that answers because it could not use the policy aborts the run. p95 is the
nearest-rank value.

    python scripts/hook_latency.py --python 1.0.0=/tmp/a/bin/python \\
        --python 1.1.0=/tmp/b/bin/python [--runs 30] [--out results/hook-latency.json]
"""

from __future__ import annotations

import argparse
import json
import math
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


# A hook that answers because it could not use the policy is not the path being timed.
_BROKEN = ("hook error", "is unusable", "cannot be used")


def _cpu() -> str:
    try:
        return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return platform.processor() or "unknown"


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
    # every AEGIS_* setting is the caller's (a signing key would override the example key
    # the generated policy is signed with, and turn each decision into "policy unusable")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_") and k not in (
        "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "XDG_CACHE_HOME", "XDG_STATE_HOME")}
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        env["HOME"] = str(Path(tmp) / "home")
        policy_from, first = next(iter(pythons.items()))
        subprocess.run([first, "-m", "aegis_core.cli", "init", str(project / ".aegis")],
                       check=True, capture_output=True, env=env)
        versions = {}
        probe = ("import aegis_core, json, platform, sys; print(json.dumps({'aegis': "
                 "aegis_core.__version__, 'python': platform.python_version(), "
                 "'implementation': platform.python_implementation(), "
                 "'base_prefix': sys.base_prefix}))")
        for name, py in pythons.items():
            versions[name] = json.loads(subprocess.run(
                [py, "-c", probe], capture_output=True, text=True, check=True,
                env=env).stdout)
        interpreters = {(v["implementation"], v["python"]) for v in versions.values()}
        if len(interpreters) != 1:
            raise SystemExit(f"the interpreters differ ({sorted(interpreters)}); compare "
                             "aegis versions on one Python")

        def run(py: str, command: str) -> tuple[float, str]:
            start = time.perf_counter()
            proc = subprocess.run([py, "-m", "aegis_core.cli", "hook", "claude"],
                                  input=_payload(command, project), text=True,
                                  capture_output=True, env=env, cwd=project, check=False)
            elapsed = (time.perf_counter() - start) * 1000
            if proc.returncode not in (0, 2) or any(
                    s in proc.stderr + proc.stdout for s in _BROKEN):
                raise SystemExit(f"hook failed ({py}, {command!r}): {proc.stderr}{proc.stdout}")
            decision = "deny" if proc.returncode == 2 else (
                json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
                if proc.stdout.strip() else "allow")
            return elapsed, decision

        decisions: dict[str, dict[str, str]] = {n: {} for n in pythons}
        for name, py in pythons.items():  # warm-up: bytecode
            for label, command in COMMANDS:
                decisions[name][label] = run(py, command)[1]
        samples = {n: {label: [] for label, _ in COMMANDS} for n in pythons}
        order = list(pythons.items())
        for i in range(args.runs):
            for label, command in COMMANDS:
                # alternate which version goes first, so neither always follows the other
                for name, py in (order if i % 2 == 0 else order[::-1]):
                    elapsed, decision = run(py, command)
                    if decision != decisions[name][label]:
                        raise SystemExit(f"{name}: {command!r} decided {decision}, "
                                         f"{decisions[name][label]} in the warm-up")
                    samples[name][label].append(elapsed)

    def summary(xs: list[float]) -> dict[str, float]:
        ordered = sorted(xs)
        return {"median_ms": round(statistics.median(xs), 1),  # p95: nearest rank
                "p95_ms": round(ordered[max(0, math.ceil(len(xs) * 0.95) - 1)], 1)}

    result = {
        "measured": datetime.now(UTC).date().isoformat(),
        "runs": args.runs,
        "driver_python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "cpu": _cpu(),
        "versions": versions,
        "policy_from": policy_from,
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
