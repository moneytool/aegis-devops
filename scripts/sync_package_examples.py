#!/usr/bin/env python3
"""Copies the example policy files under ``data/`` into
``src/aegis_core/_examples/`` so they can ship as package data (REVIEW-4
T2.6). ``data/`` stays the single source of truth; this script (and
``tests/test_config.py::test_examples_package_in_sync``) is what keeps the
packaged copy from drifting out of sync with it.

    venv/bin/python scripts/sync_package_examples.py [--check]

``--check`` exits non-zero (without writing anything) if the packaged copy
is out of date, for use in CI / pre-publish checks.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
SOURCES_DIR = DATA_DIR / "sources"
DEST_DIR = REPO_ROOT / "src" / "aegis_core" / "_examples"

_TOP_LEVEL_GLOBS = ("*.example.yaml", "*.example.yaml.sig")
_TOP_LEVEL_EXTRA = ("example-signing.key",)


def _planned_files() -> dict[Path, Path]:
    """Maps destination path -> source path for every file that belongs
    in the packaged examples tree."""
    plan: dict[Path, Path] = {}
    for pattern in _TOP_LEVEL_GLOBS:
        for src in sorted(DATA_DIR.glob(pattern)):
            plan[DEST_DIR / src.name] = src
    for name in _TOP_LEVEL_EXTRA:
        src = DATA_DIR / name
        if src.exists():
            plan[DEST_DIR / name] = src
    if SOURCES_DIR.is_dir():
        for src in sorted(SOURCES_DIR.rglob("*")):
            if src.is_file():
                rel = src.relative_to(SOURCES_DIR)
                plan[DEST_DIR / "sources" / rel] = src
    return plan


_NON_DATA_FILES = {"__init__.py"}  # makes _examples/ importable via importlib.resources


def sync(check: bool) -> bool:
    """Returns True if the packaged copy already matched (nothing to do,
    or --check confirms it's in sync); False if it was out of date."""
    plan = _planned_files()
    existing = set(DEST_DIR.rglob("*")) if DEST_DIR.is_dir() else set()
    existing_files = {
        p
        for p in existing
        if p.is_file() and "__pycache__" not in p.parts and p.name not in _NON_DATA_FILES
    }
    stale = existing_files - set(plan)

    changed: list[Path] = []
    for dest, src in plan.items():
        if not dest.exists() or not filecmp.cmp(src, dest, shallow=False):
            changed.append(dest)

    if check:
        if changed or stale:
            print("src/aegis_core/_examples/ is out of sync with data/:")
            for p in changed:
                print(f"  would update: {p.relative_to(REPO_ROOT)}")
            for p in stale:
                print(f"  would remove: {p.relative_to(REPO_ROOT)}")
            return False
        print("src/aegis_core/_examples/ is in sync with data/")
        return True

    for dest, src in plan.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
    for p in stale:
        p.unlink()
    # Prune now-empty directories left behind by removed stale files.
    if DEST_DIR.is_dir():
        for d in sorted(DEST_DIR.rglob("*"), reverse=True):
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
    (DEST_DIR / "__init__.py").touch(exist_ok=True)
    print(f"Synced {len(plan)} file(s) into {DEST_DIR.relative_to(REPO_ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ok = sync(args.check)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
