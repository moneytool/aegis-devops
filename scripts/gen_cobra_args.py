"""Writes src/aegis_core/data/cobra_args.json: how many arguments each helm and flux
command takes, from the ``Args:`` validator of the cobra.Command that builds it
(``require.ExactArgs(2)``, ``cobra.MaximumNArgs(1)``, ``require.NoArgs``...), so the parser
refuses an argument count the tool refuses.

    python scripts/gen_cobra_args.py src/aegis_core/data/cobra_args.json \\
        helm=<helm checkout>/pkg/cmd flux=<flux2 checkout>/cmd/flux

A command is named by its ``Use:`` word and, where its file name says so (``repo_add.go``,
``get_values.go``, ``create_source_git.go``), the words before it. Each is ``[least,
most]``, ``most`` null for no limit."""

import json
import re
import subprocess
import sys
from pathlib import Path

_VALIDATOR = re.compile(
    r"Args:\s*(?:require|cobra)\.(?P<kind>ExactArgs|MinimumNArgs|MaximumNArgs|RangeArgs|NoArgs"
    r"|ArbitraryArgs)(?:\((?P<a>\d+)(?:,\s*(?P<b>\d+))?\))?")
_USE = re.compile(r'Use:\s*"(?P<word>[\w-]+)')


def _bounds(kind: str, a: str | None, b: str | None) -> list[int | None]:
    if kind == "ExactArgs":
        return [int(a), int(a)]
    if kind == "MinimumNArgs":
        return [int(a), None]
    if kind == "MaximumNArgs":
        return [0, int(a)]
    if kind == "RangeArgs":
        return [int(a), int(b)]
    if kind == "NoArgs":
        return [0, 0]
    return [0, None]


def scan(root: Path) -> dict[str, list[int | None]]:
    """Each command's bounds: a file's Use word, with the parent words its file name
    gives (``repo_add.go`` -> ``repo add``)."""
    out: dict[str, list[int | None]] = {}
    for path in sorted(root.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="ignore")
        for use in _USE.finditer(text):
            window = text[use.end():use.end() + 1500]
            nxt = _USE.search(window)
            window = window[:nxt.start()] if nxt else window
            found = _VALIDATOR.search(window)
            if not found:
                continue
            word = use.group("word")
            stem = path.stem.split("_")
            parents = stem[:stem.index(word)] if word in stem else []
            key = " ".join([*parents, word])
            out[key] = _bounds(found.group("kind"), found.group("a"), found.group("b"))
    return dict(sorted(out.items()))


def main(out: str, specs: list[str]) -> None:
    data: dict = {}
    sources = []
    for spec in specs:
        tool, _, directory = spec.partition("=")
        top = subprocess.run(["git", "-C", directory, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=False).stdout.strip()
        url = subprocess.run(["git", "-C", directory, "config", "remote.origin.url"],
                             capture_output=True, text=True, check=False).stdout.strip()
        rev = subprocess.run(["git", "-C", directory, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=False).stdout.strip()
        sub = Path(directory).resolve().relative_to(Path(top).resolve()).as_posix()
        sources.append(f"{tool}={url.removesuffix('.git')}@{rev}/{sub}")
        data[tool] = scan(Path(directory))
    data["_source"] = "cobra Args validators: " + "; ".join(sources)
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
