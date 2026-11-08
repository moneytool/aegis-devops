"""Writes src/aegis_core/data/gcloud_flags.json: every flag of each gcloud command the parser
models, with whether it takes a value, read from the gcloud reference pages
(https://cloud.google.com/sdk/gcloud/reference/...), which list each flag as
``--flag=VALUE`` (a value), ``--flag[=VALUE]`` (an optional value, which argparse takes
from the next word unless it starts with "-"), ``--flag`` or ``--[no-]flag`` (a boolean),
with its short spellings (``alias``: each short spelling and the flag it is), and which
values are lists (``TAG,[TAG,…]``) or maps (``[KEY=VALUE,…]``). gcloud itself is not
needed.

    python scripts/gen_gcloud_flags.py src/aegis_core/data/gcloud_flags.json

``root`` holds the gcloud-wide flags (the reference's top page)."""

import datetime
import html
import json
import re
import sys
import urllib.request

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


def fetch(path: str) -> str:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=60) as response:
        return response.read().decode("utf-8")


def main(out: str) -> None:
    table = {"_source": f"{BASE} (fetched {datetime.date.today().isoformat()})",
             "root": flags(fetch(""))}
    for group, verbs in COMMANDS.items():
        for verb in verbs.split():
            command = f"{group} {verb}"
            table[command] = flags(fetch("/" + command.replace(" ", "/")))
    with open(out, "w") as f:
        json.dump(table, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
