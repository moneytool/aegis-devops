"""Writes src/aegis_core/data/kubectl_flags.json: every flag of every kubectl command, with
its short letter and whether it takes a value, read from ``kubectl <command> --help`` and
``kubectl options`` of an installed kubectl.

    python scripts/gen_kubectl_flags.py src/aegis_core/data/kubectl_flags.json

The help is read with ``KUBECONFIG=/dev/null`` and an empty ``HOME``: ``--help`` needs no
cluster, and no kubeconfig or context is read. Each command is ``{flag: [kind, letter]}``,
``kind`` ``bool`` when the help shows a ``true``/``false`` default and ``value`` otherwise;
``options`` holds the flags every command takes (``kubectl options``)."""

import json
import re
import subprocess
import sys

_ENV = {"PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin", "KUBECONFIG": "/dev/null",
        "HOME": "/tmp/nonexistent-home"}
_FLAG = re.compile(r"^\s+(?:-(\w), )?--([\w-]+)=(.*?):\s*$")


def _help(path: list[str]) -> str:
    return subprocess.run(["kubectl", *path, "--help"], capture_output=True, text=True,
                          env=_ENV, check=False).stdout


def _subcommands(text: str) -> list[str]:
    out, on = [], False
    for line in text.splitlines():
        if re.match(r"^\S.*Commands.*:$", line):
            on = True
            continue
        if on:
            m = re.match(r"^  ([a-z][\w-]*)\s{2,}", line)
            if m:
                out.append(m.group(1))
            elif line.strip() and not line.startswith("  "):
                on = False
    return out


def _flags(text: str) -> dict[str, list[str]]:
    found = {}
    for line in text.splitlines():
        m = _FLAG.match(line)
        if m:
            letter, name, default = m.groups()
            found[name] = ["bool" if default in ("true", "false") else "value", letter or ""]
    return dict(sorted(found.items()))


def main(out: str) -> None:
    version = subprocess.run(["kubectl", "version", "--client", "-o", "json"],
                             capture_output=True, text=True, env=_ENV, check=False).stdout
    git_version = json.loads(version)["clientVersion"]["gitVersion"]
    data: dict = {"_source": f"kubectl {git_version} --help of every command, and "
                             "kubectl options"}
    options = subprocess.run(["kubectl", "options"], capture_output=True, text=True,
                             env=_ENV, check=False).stdout
    data["options"] = _flags(options)
    seen: set[tuple[str, ...]] = set()

    def walk(path: list[str]) -> None:
        if tuple(path) in seen or len(path) > 3:
            return
        seen.add(tuple(path))
        text = _help(path)
        if path:
            data[" ".join(path)] = _flags(text)
        for sub in _subcommands(text):
            if sub not in ("help", "completion"):
                walk([*path, sub])

    walk([])
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
