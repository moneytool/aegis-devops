#!/usr/bin/env python3
"""Run once, by hand, to find the cheapest Codex model this account/CLI
combination can actually use for `codex exec`.

Passing an unsupported `-m` name to `codex exec` does not fail fast -- the
CLI prints an `ERROR: ... not supported` line and then hangs rather than
exiting, so probing candidates must always run under a hard timeout. This
script does exactly that via ``aegis_core.baselines.external.probe_codex_models``
and prints the result; it is NOT part of the test suite or the benchmark
hot path (it can take up to ``len(candidates) * timeout_s`` seconds when
every candidate fails).

    venv/bin/python scripts/probe_codex_models.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis_core.baselines.external import CODEX_MODEL_CANDIDATES, probe_codex_models


def main() -> int:
    print(f"Probing {len(CODEX_MODEL_CANDIDATES)} candidates (60s hard timeout each): "
          f"{CODEX_MODEL_CANDIDATES}")
    resolved = probe_codex_models()
    if resolved is None:
        print(
            "No named candidate answered cleanly within timeout; falling back to "
            "no `-m` flag (the account/CLI's own configured default)."
        )
    else:
        print(f"Resolved Codex model: {resolved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
