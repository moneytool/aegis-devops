"""Regenerates src/aegis_core/budget/prices.json from prices.yaml.

prices.yaml is the table people edit (it carries the sources and the
reasoning in comments); the package loads prices.json, which is faster to read
on every hook call. tests/test_budget_policy.py fails if the two differ.

    python scripts/sync_prices.py [--check]
"""

import json
import sys
from pathlib import Path

import yaml

BUDGET = Path(__file__).resolve().parent.parent / "src" / "aegis_core" / "budget"


def main() -> int:
    table = yaml.safe_load((BUDGET / "prices.yaml").read_text())
    text = json.dumps(table, indent=1, sort_keys=True) + "\n"
    target = BUDGET / "prices.json"
    if "--check" in sys.argv[1:]:
        if not target.exists() or target.read_text() != text:
            print(f"{target} is stale: run python scripts/sync_prices.py", file=sys.stderr)
            return 1
        return 0
    target.write_text(text)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
