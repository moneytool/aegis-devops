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
from typing import Any

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
    unit>`` (Duration, in seconds), ``list:<element kind>`` (ArgList), ``dict`` (ArgDict),
    ``file`` (FileContents, YAMLFileContents, BufferedFileInput: read from a file) and
    ``dict:file`` (an ArgDict of them); None for a string; ``unresolved`` for a type that
    cannot be read statically."""
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
        if name in _FILE_TYPES:
            return "file"
        if name == "ArgList":
            element = _type_kind(kwargs.get("element_type"))
            return f"list:{element or 'str'}" if element != "unresolved" else "unresolved"
        if name == "ArgDict":
            # ArgDict(value_type=FileContents()): each key's value is a file's contents
            values = _type_kind(kwargs.get("value_type")) if "value_type" in kwargs else None
            return "dict:file" if values == "file" else "dict"
    if isinstance(node, ast.Attribute) and node.attr in _FILE_TYPES:
        return "file"
    return "unresolved"


# calliope's types whose value is read from a file (or stdin) when gcloud runs
_FILE_TYPES = frozenset({"FileContents", "YAMLFileContents", "BufferedFileInput"})


_ACTIONS = {
    "append": "append", "UpdateAction": "update", "UpdateActionWithAppend": "update-append",
    "StoreOnceAction": "once", "StoreOnceWarningAction": "once",
}


def _action_kind(node: ast.AST | None) -> str | None:
    """A flag's ``action=`` as the parser reads it: ``append`` (each value kept),
    ``update`` (arg_parsers.UpdateAction: lists extend, maps merge, a repeat refused),
    ``update-append`` (UpdateActionWithAppend: a repeated key keeps every value), ``once``
    (StoreOnceAction: given twice is refused); None for a plain store (the last value) or
    a boolean; ``unresolved`` for an action that cannot be read statically."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        if node.value in ("store", "store_true", "store_false", "store_const", "count"):
            return None
        return _ACTIONS.get(node.value, "unresolved")
    name = getattr(node, "attr", getattr(node, "id", None))
    if isinstance(node, ast.Call):
        name = getattr(node.func, "attr", getattr(node.func, "id", None))
        if name in ("DeprecationAction",):
            return None  # warns, then stores as argparse does
    if name in ("StoreTrueFalseAction", "StoreFalseAction", "StoreTrueAction"):
        return None
    return _ACTIONS.get(name or "", "unresolved")


def _spec_from_name(name: str, scopes: list[ast.AST]) -> ast.Dict | None:
    """A spec built in a variable (``spec = {...}``, then ``spec['k'] = T`` under release
    track conditions) as one literal map: every member any assignment in the enclosing
    function (or else the module) adds, so a member the SDK may accept is not refused."""
    for scope in scopes:
        keys: list[ast.expr] = []
        values: list[ast.expr] = []
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (isinstance(target, ast.Name) and target.id == name
                        and isinstance(node.value, ast.Dict)):
                    keys.extend(node.value.keys)
                    values.extend(node.value.values)
                elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                      and target.value.id == name and isinstance(target.slice, ast.Constant)):
                    keys.append(target.slice)
                    values.append(node.value)
        if keys:
            return ast.Dict(keys=keys, values=values)
    return None


def _dict_spec(node: ast.AST | None, scopes: list[ast.AST] | None = None) -> Any:
    """An ArgDict's ``spec`` (also inside ArgList(element_type=ArgDict(...))): ``{"members":
    {key: kind}, "required": [...], "key_only": bool}``, ``unresolved`` when the spec is not
    a literal map, None for an ArgDict without one (any key)."""
    if not isinstance(node, ast.Call):
        return None
    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
    kwargs = {k.arg: k.value for k in node.keywords}
    if name == "ArgList":
        return _dict_spec(kwargs.get("element_type"), scopes)
    if name != "ArgDict":
        return None
    spec = kwargs.get("spec")
    if spec is None:
        return None
    if isinstance(spec, ast.Name):
        spec = _spec_from_name(spec.id, scopes or []) or spec
    if not isinstance(spec, ast.Dict) or not all(
            isinstance(k, ast.Constant) and isinstance(k.value, str) for k in spec.keys):
        return "unresolved"
    required = kwargs.get("required_keys")
    key_only = kwargs.get("allow_key_only")
    return {
        "members": {k.value: _type_kind(v) for k, v in zip(spec.keys, spec.values)},
        "required": sorted(e.value for e in getattr(required, "elts", [])
                           if isinstance(e, ast.Constant)),
        "key_only": bool(getattr(key_only, "value", False)),
    }


def sdk_declarations(root: str) -> dict[str, dict[str, set[tuple[Any, Any, str]]]]:
    """Per command group, every declaration of each flag in the SDK mirror's
    ``add_argument`` and ``base.Argument`` calls, as ``(type, action, spec)``."""
    found: dict[str, dict[str, set[tuple[Any, Any, str]]]] = {}
    for area, dirs in _SDK_AREAS.items():
        decls: dict[str, set[tuple[Any, Any, str]]] = {}
        for sub in dirs:
            for base_dir in (Path(root) / "lib/surface" / sub,
                             Path(root) / "lib/googlecloudsdk/command_lib" / sub):
                for path in base_dir.rglob("*.py"):
                    try:
                        tree = ast.parse(path.read_text(errors="ignore"))
                    except SyntaxError:
                        continue
                    functions = [f for f in ast.walk(tree)
                                 if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
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
                        enclosing = [f for f in functions
                                     if f.lineno <= call.lineno <= (f.end_lineno or f.lineno)]
                        scopes = [*sorted(enclosing, key=lambda f: -f.lineno)[:1], tree]
                        decl = (_type_kind(kwargs.get("type")),
                                _action_kind(kwargs.get("action")),
                                json.dumps(_dict_spec(kwargs.get("type"), scopes),
                                           sort_keys=True))
                        for name in names:
                            decls.setdefault(name, set()).add(decl)
        found[area] = decls
    return found


def _one(kinds: set) -> Any:
    return next(iter(kinds)) if len(kinds) == 1 else "unresolved"


def sdk_details(root: str, shapes: dict[str, str] | None = None,
                ) -> dict[str, dict[str, dict[str, Any]]]:
    """Per command group, every flag's type, action and ArgDict spec. ``shapes`` (a
    command's reference page: ``dict``, ``list`` or ``scalar`` per flag) keeps only the
    declarations of that shape, since commands of one group can declare a flag of one name
    differently (``--network-interface`` is a map on instances create and a name on
    add-access-config). Declared differently still, the value is ``unresolved``."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for area, decls in sdk_declarations(root).items():
        out[area] = _details(decls, shapes or {})
    return out


def _details(decls: dict[str, set[tuple[Any, Any, str]]],
             shapes: dict[str, str]) -> dict[str, dict[str, Any]]:
    types: dict[str, Any] = {}
    actions: dict[str, Any] = {}
    specs: dict[str, Any] = {}
    for name, found in decls.items():
        shape = shapes.get(name)
        kept = {d for d in found if shape is None
                or (shape == "dict") == str(d[0]).startswith("dict")
                and (shape == "list") == str(d[0]).startswith("list")} or found
        kinds = {d[0] for d in kept}
        if kinds != {None}:
            types[name] = _one(kinds)
        acts = {d[1] for d in kept}
        if acts != {None}:
            actions[name] = _one(acts)
        spec_variants = {d[2] for d in kept}
        if spec_variants != {"null"}:
            specs[name] = _merge_specs(spec_variants)
    return {"types": types, "actions": actions, "specs": specs}


def _merge_specs(variants: set[str]) -> Any:
    """One flag's ArgDict specs across the group's declarations, merged: every member any
    declares, with its kind where they agree and ``unresolved`` where they differ; keys
    required only where every declaration requires them. A declaration with no spec (any
    key) or one that is not a literal map leaves the whole spec ``unresolved``."""
    specs = [json.loads(v) for v in variants]
    if any(not isinstance(spec, dict) for spec in specs):
        return "unresolved"
    members: dict[str, Any] = {}
    for spec in specs:
        for key, kind in spec["members"].items():
            members[key] = kind if members.get(key, kind) == kind else "unresolved"
    required = set.intersection(*(set(spec["required"]) for spec in specs))
    return {"members": dict(sorted(members.items())), "required": sorted(required),
            "key_only": any(spec["key_only"] for spec in specs)}


def sdk_types(root: str) -> dict[str, dict[str, str]]:
    """Per command group, every flag's type (:func:`sdk_details`)."""
    return {area: d["types"] for area, d in sdk_details(root).items()}


def fetch(path: str) -> str:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=60) as response:
        return response.read().decode("utf-8")


def refresh_types(out: str, sdk: str) -> None:
    """Re-reads only the value types of an existing table from the SDK mirror at ``sdk``,
    keeping its flag lists (which come from the reference pages)."""
    with open(out) as f:
        table = json.load(f)
    commit = subprocess.run(["git", "-C", sdk, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=False).stdout.strip()
    source, _, _ = table["_source"].partition("; value types from")
    table["_source"] = (f"{source}; value types from "
                        f"github.com/google-cloud-sdk-unofficial/google-cloud-sdk {commit}")
    declarations = sdk_declarations(sdk)
    resolved = 0
    for command, entry in table.items():
        if command.startswith("_") or command == "root":
            continue
        decls = declarations.get(command.split()[0], {})
        resolved += _resolve_shapes(entry, decls)
        shapes = {n: "dict" if n in entry.get("dict", []) else
                  "list" if n in entry.get("list", []) else "scalar"
                  for n in [*entry["value"], *entry.get("optional", [])]}
        area = _details(decls, shapes)
        flags = [*entry["value"], *entry.get("optional", [])]
        entry["types"] = {n: area["types"][n] for n in entry["value"] if n in area["types"]}
        entry["actions"] = {n: area["actions"][n] for n in flags if n in area["actions"]}
        entry["specs"] = {n: area["specs"][n] for n in flags if n in area["specs"]}
    _check_shapes(table, declarations)
    print(f"{resolved} flags whose page shape and SDK type disagreed", file=sys.stderr)
    with open(out, "w") as f:
        json.dump(table, f, indent=1, sort_keys=True)
        f.write("\n")


def _shape(kind: Any) -> str:
    text = str(kind)
    return "dict" if text.startswith("dict") else "list" if text.startswith("list") else (
        "unresolved" if text == "unresolved" else "scalar")


def _resolve_shapes(entry: dict[str, Any], decls: dict[str, set]) -> int:
    """One shape per flag. Where the reference page's shape (a ``[KEY=VALUE,…]`` map, a
    ``A,[B,…]`` list or one value) is not the shape of any SDK declaration of the flag,
    the SDK's structured type wins (the page moves the flag to ``dict`` or ``list``); where
    the SDK has no structured type for it (a plain value, or declarations that disagree),
    which one gcloud parses is not known: the flag goes to ``shape_unresolved``, whose
    value the parser leaves unresolved. Returns how many flags disagreed."""
    count = 0
    unresolved: list[str] = []
    for name in [*entry["value"], *entry.get("optional", [])]:
        page = ("dict" if name in entry.get("dict", []) else
                "list" if name in entry.get("list", []) else "scalar")
        # a type the SDK builds in a way not read statically says nothing of the shape
        shapes = {_shape(t) for t, _a, _s in decls.get(name, set())} - {"unresolved"}
        if not shapes or page in shapes:
            continue
        count += 1
        structured = shapes & {"dict", "list"}
        if len(structured) == 1 and shapes <= {"dict", "list"}:
            sdk = next(iter(structured))
            for kind in ("dict", "list"):
                members = [n for n in entry.get(kind, []) if n != name]
                entry[kind] = sorted(members + ([name] if kind == sdk else []))
        else:
            unresolved.append(name)
    if unresolved:
        entry["shape_unresolved"] = sorted(unresolved)
    else:
        entry.pop("shape_unresolved", None)
    return count


def _check_shapes(table: dict[str, Any], declarations: dict[str, Any]) -> None:
    """Fails on a flag whose shape still disagrees with every SDK declaration and is not
    listed in ``shape_unresolved``: one source of truth for whether it is a map, a list
    or one value."""
    bad = []
    for command, entry in table.items():
        if command.startswith("_") or command == "root":
            continue
        decls = declarations.get(command.split()[0], {})
        for name in [*entry["value"], *entry.get("optional", [])]:
            page = ("dict" if name in entry.get("dict", []) else
                    "list" if name in entry.get("list", []) else "scalar")
            shapes = {_shape(t) for t, _a, _s in decls.get(name, set())} - {"unresolved"}
            if shapes and page not in shapes and name not in entry.get("shape_unresolved", []):
                bad.append(f"{command} --{name}: page {page}, SDK {sorted(shapes)}")
    if bad:
        raise SystemExit("shape disagreements without a resolution:\n" + "\n".join(bad))


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
    if sys.argv[1] == "--types-only":
        refresh_types(sys.argv[2], sys.argv[3])
    else:
        main(sys.argv[1], sys.argv[2])
