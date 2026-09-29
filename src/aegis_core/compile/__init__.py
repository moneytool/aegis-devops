"""Compilers from the verified snapshot to server-side policy artifacts
(``docs/dev/DESIGN-v0.3-server-side.md`` §6).

A compiler never holds cloud credentials: it writes files an operator
reviews, signs and applies with their own IaC. Every constraint in the
policy is accounted for in the coverage report, and anything that cannot be
expressed exactly is reported as over-enforced or not enforced, never
approximated silently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CompileError(ValueError):
    """The policy cannot be compiled for this target as asked (e.g. the
    output does not fit the platform's limits). Nothing is written."""


def canonical_json(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def pretty_json(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def write_outputs(out_dir: str | Path, files: dict[str, str]) -> list[Path]:
    """Writes ``files`` (relative path -> text) under ``out_dir``. Refuses
    to leave stale compiler output behind: any ``*.json``/``*.md`` already
    in ``out_dir`` that this compile does not produce is removed only if it
    was listed in the previous ``manifest.json``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    previous = out / "manifest.json"
    if previous.exists():
        try:
            old = json.loads(previous.read_text()).get("files", [])
        except (ValueError, AttributeError):
            old = []
        for rel in old:
            if isinstance(rel, str) and rel not in files and ".." not in rel:
                (out / rel).unlink(missing_ok=True)
    written = []
    for rel, text in sorted(files.items()):
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        written.append(path)
    return written


def check_outputs(out_dir: str | Path, files: dict[str, str]) -> list[str]:
    """The drift between ``out_dir`` and a fresh compile: one line per file
    that is missing, different, or left over from a previous compile."""
    out = Path(out_dir)
    problems = []
    for rel, text in sorted(files.items()):
        path = out / rel
        if not path.exists():
            problems.append(f"missing: {rel}")
        elif path.read_text() != text:
            problems.append(f"differs: {rel}")
    manifest = out / "manifest.json"
    if manifest.exists():
        try:
            listed = json.loads(manifest.read_text()).get("files", [])
        except (ValueError, AttributeError):
            listed = []
        for rel in listed:
            if isinstance(rel, str) and rel not in files and (out / rel).exists():
                problems.append(f"stale: {rel}")
    return problems
