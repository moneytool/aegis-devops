"""Writes src/aegis_core/data/gcloud_flags.json: every flag of each gcloud command the parser
models, with whether it takes a value, read from the gcloud reference pages
(https://cloud.google.com/sdk/gcloud/reference/...), which list each flag as
``--flag=VALUE`` (a value), ``--flag[=VALUE]`` (an optional value, which argparse takes
from the next word unless it starts with "-"), ``--flag`` or ``--[no-]flag`` (a boolean),
with its short spellings (``alias``: each short spelling and the flag it is), and which
values are lists (``TAG,[TAG,…]``) or maps (``[KEY=VALUE,…]``). gcloud itself is not
needed.

    python scripts/gen_gcloud_flags.py src/aegis_core/data/gcloud_flags.json <sdk mirror>

Each value flag's type (``types``) is read from a checkout of the SDK source mirror
(github.com/google-cloud-sdk-unofficial/google-cloud-sdk: lib/surface and
lib/googlecloudsdk/command_lib, the ``type=`` of each ``add_argument``).

``root`` holds the gcloud-wide flags (the reference's top page)."""

import ast
import datetime
import html
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

BASE = "https://cloud.google.com/sdk/gcloud/reference"

COMMANDS = {
    "compute instances": "create delete update describe list start stop reset set-iam-policy "
                         "add-iam-policy-binding remove-iam-policy-binding import export",
    "compute": "ssh",
    "compute disks": "create delete update describe list resize set-iam-policy "
                     "add-iam-policy-binding remove-iam-policy-binding",
    "compute firewall-rules": "create delete update describe list",
    "container clusters": "create delete update describe list resize upgrade get-credentials",
    "container node-pools": "create delete update describe list rollback",
    "sql instances": "create delete describe list",
    "sql import": "sql csv bak tde",
    "sql export": "sql csv bak tde",
    "storage buckets": "create delete update describe list add-iam-policy-binding "
                       "remove-iam-policy-binding set-iam-policy",
    "storage": "cp mv rm",
    "functions": "deploy delete describe list add-iam-policy-binding remove-iam-policy-binding "
                 "set-iam-policy",
    "run": "deploy",
    "run services": "delete describe list update add-iam-policy-binding "
                    "remove-iam-policy-binding set-iam-policy",
    "iam service-accounts": "create delete update describe list add-iam-policy-binding "
                            "remove-iam-policy-binding set-iam-policy",
    "projects": "create delete update describe list add-iam-policy-binding "
                "remove-iam-policy-binding set-iam-policy",
    "pubsub topics": "create delete update describe list add-iam-policy-binding "
                     "remove-iam-policy-binding set-iam-policy",
}

_DT = re.compile(r'<dt id="(-[^"]*)"><span class="normalfont">(.*?)</span></dt>', re.S)
_CODE = re.compile(r"<code[^>]*>(.*?)</code>", re.S)
_NAME = re.compile(r"-{1,2}(\[no-\])?([A-Za-z0-9][\w-]*)")


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def flags(page: str) -> dict[str, list[str]]:
    bools: set[str] = set()
    values: set[str] = set()
    optional: set[str] = set()
    alias: dict[str, str] = {}
    lists: set[str] = set()
    dicts: set[str] = set()
    for match in _DT.finditer(page):
        inner = match.group(2)
        codes = [_text(c) for c in _CODE.findall(inner)]
        if not codes:
            continue
        rest = _text(inner)[len(codes[0]):]
        kind = values if rest.startswith("=") else optional if rest.startswith("[=") else bools
        spec = rest.partition(" ")[0]
        # an ArgList (TAG,[TAG,…]) or ArgDict ([KEY=VALUE,…]): its value is split on commas
        shape = (dicts if "=" in spec[1:] else lists) if "…" in spec or ",[" in spec else None
        long_name = None
        for spelling in [codes[0], *codes[1:]]:
            found = _NAME.fullmatch(spelling)
            if not found:
                continue
            kind.add(found.group(2))
            if found.group(1):
                bools.add("no-" + found.group(2))
            if shape is not None and kind is values:
                shape.add(found.group(2))
            if long_name is None:
                long_name = found.group(2)
            elif found.group(2) != long_name:
                alias[found.group(2)] = long_name  # -z is --zone
    return {"bool": sorted(bools), "value": sorted(values), "optional": sorted(optional),
            "alias": dict(sorted(alias.items())), "list": sorted(lists), "dict": sorted(dicts)}


# The SDK mirror's directories for each command group the parser models (lib/surface and
# lib/googlecloudsdk/command_lib), where its flags' types are declared.
_SDK_AREAS = {
    "compute": ["compute"], "container": ["container"], "sql": ["sql"],
    "storage": ["storage"], "functions": ["functions"], "run": ["run"], "iam": ["iam"],
    "projects": ["projects", "resource_manager"], "pubsub": ["pubsub"],
}


def _type_kind(node: ast.AST | None) -> str | None:
    """A flag's ``type=`` as the kinds the parser normalizes: ``int``, ``float``, ``bool``
    (ArgBoolean), ``size:<default unit>`` (BinarySize, in bytes), ``duration:<default
    unit>`` (Duration, in seconds), ``list:<element kind>`` (ArgList), ``dict`` (ArgDict);
    None for a string; ``unresolved`` for a type that cannot be read statically."""
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return {"int": "int", "float": "float", "str": None}.get(node.id, "unresolved")
    if isinstance(node, ast.Call):
        name = getattr(node.func, "attr", getattr(node.func, "id", ""))
        kwargs = {k.arg: k.value for k in node.keywords}

        def const(key: str, default: str) -> str | None:
            value = kwargs.get(key)
            if value is None:
                return default
            return value.value if isinstance(value, ast.Constant) else None

        if name == "BoundedInt":
            return "int" if "unlimited" not in kwargs else "unresolved"
        if name == "BoundedFloat":
            return "float"
        if name == "ArgBoolean":
            return "bool" if not node.args and not kwargs else "unresolved"
        if name == "BinarySize":
            unit = const("default_unit", "G")
            return f"size:{unit}" if unit and "target_unit" not in kwargs else "unresolved"
        if name == "Duration":
            unit = const("default_unit", "s")
            parsed = const("parsed_unit", "s")
            return f"duration:{unit}" if unit and parsed == "s" else "unresolved"
        if name == "ArgList":
            element = _type_kind(kwargs.get("element_type"))
            return f"list:{element or 'str'}" if element != "unresolved" else "unresolved"
        if name == "ArgDict":
            return "dict"
    return "unresolved"


def sdk_types(root: str) -> dict[str, dict[str, str]]:
    """Per command group, every flag's type from the SDK mirror's ``add_argument`` and
    ``base.Argument`` calls. A flag declared with different types in the group is
    ``unresolved``."""
    found: dict[str, dict[str, set]] = {}
    for area, dirs in _SDK_AREAS.items():
        kinds: dict[str, set] = {}
        for sub in dirs:
            for base_dir in (Path(root) / "lib/surface" / sub,
                             Path(root) / "lib/googlecloudsdk/command_lib" / sub):
                for path in base_dir.rglob("*.py"):
                    try:
                        tree = ast.parse(path.read_text(errors="ignore"))
                    except SyntaxError:
                        continue
                    for call in ast.walk(tree):
                        if not (isinstance(call, ast.Call) and getattr(
                                call.func, "attr", getattr(call.func, "id", "")) in (
                                "add_argument", "Argument")):
                            continue
                        names = [a.value[2:] for a in call.args if isinstance(a, ast.Constant)
                                 and isinstance(a.value, str) and a.value.startswith("--")]
                        if not names:
                            continue
                        kwargs = {k.arg: k.value for k in call.keywords}
                        kind = _type_kind(kwargs.get("type"))
                        for name in names:
                            kinds.setdefault(name, set()).add(kind)
        found[area] = kinds
    return {area: {name: (next(iter(k)) if len(k) == 1 else "unresolved")
                   for name, k in kinds.items() if k != {None}}
            for area, kinds in found.items()}


def fetch(path: str) -> str:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=60) as response:
        return response.read().decode("utf-8")


def main(out: str, sdk: str) -> None:
    commit = subprocess.run(["git", "-C", sdk, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=False).stdout.strip()
    table = {"_source": f"{BASE} (fetched {datetime.date.today().isoformat()}); value types "
                        f"from github.com/google-cloud-sdk-unofficial/google-cloud-sdk {commit}",
             "root": flags(fetch(""))}
    types = sdk_types(sdk)
    for group, verbs in COMMANDS.items():
        area = types.get(group.split()[0], {})
        for verb in verbs.split():
            command = f"{group} {verb}"
            entry = flags(fetch("/" + command.replace(" ", "/")))
            # each value flag's declared type (only the ones that are not strings); a value
            # flag the SDK does not declare stays text
            entry["types"] = {name: area[name] for name in entry["value"] if name in area}
            table[command] = entry
    with open(out, "w") as f:
        json.dump(table, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
