"""Writes src/aegis_core/data/gh_flags.json: every flag of every gh command, with its
pflag type and its short letter, read from the flag registrations in a checkout of
cli/cli (pkg/cmd and the helpers it calls in pkg/cmdutil and internal), so the parser
reads each gh command's flags as gh's pflag does, short letters included.

    python scripts/gen_gh_flags.py src/aegis_core/data/gh_flags.json <cli/cli checkout>

A command is named by its directory under pkg/cmd and the ``Use:`` word of the file that
builds it (``pr create``, ``codespace create``). A registration in a helper that takes the
command (``cmdutil.AddJSONFlags(cmd, ...)``, ``cmdutil.EnableRepoOverride(cmd, f)``,
``attachments.AddFlag(cmd)``) counts for the command that calls it. ``PersistentFlags()``
registrations are inherited by every command below. Each flag is ``[type, short]``:
the pflag type (``bool``, ``string``, ``stringSlice``...; ``value:<Go type>`` for a custom
Value, which the parser treats as taking a value) and its letter or ``""``."""

import json
import re
import subprocess
import sys
from pathlib import Path

_TYPES = {
    "String": "string", "Bool": "bool", "Int": "int", "Int32": "int32", "Int64": "int64",
    "Uint": "uint", "Uint64": "uint64", "Float64": "float64", "Duration": "duration",
    "StringSlice": "stringSlice", "StringArray": "stringArray",
    "StringToString": "stringToString", "IntSlice": "intSlice", "Count": "count",
}
_CALL = re.compile(
    r"\b(?P<recv>\w+(?:\.\w+)*?)?\.?(?P<fs>Persistent)?Flags\(\)\.(?P<type>"
    + "|".join(_TYPES) + r")(?P<var>Var)?(?P<p>P)?\(")
_FS_CALL = re.compile(r"\b(?P<fs>\w+)\.(?P<type>" + "|".join(_TYPES)
                      + r")(?P<var>Var)?(?P<p>P)?\(")
_VAR_CALL = re.compile(r"(?P<fs>Persistent)?Flags\(\)\.VarP?F?\(")
_HELPERS = {  # cmdutil helpers: (type, name argument, short argument), after (cmd, &p,
    "StringEnumFlag": "string", "NilStringFlag": "string", "NilBoolFlag": "bool",
    "StringSliceEnumFlag": "stringSlice",
}
_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)", re.M)
_USE = re.compile(r"\bUse:\s*\"([\w-]+)")
_CONST = re.compile(r"\b([A-Za-z_]\w*)\s*(?:string\s*)?=\s*\"([a-z0-9][a-z0-9-]*)\"")


def _args(text: str, start: int) -> list[str]:
    """The top-level arguments of a call whose ``(`` ends at ``start``."""
    out, depth, cur, i = [], 0, [], start
    while i < len(text):
        ch = text[i]
        if ch == '"' or ch == "`":
            end = text.index(ch, i + 1) if ch == "`" else _string_end(text, i)
            cur.append(text[i:end + 1])
            i = end + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                out.append("".join(cur).strip())
                return out
            depth -= 1
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    return out


def _string_end(text: str, i: int) -> int:
    j = i + 1
    while text[j] != '"':
        j += 2 if text[j] == "\\" else 1
    return j


def _literal(arg: str, consts: dict[str, str]) -> str | None:
    if arg.startswith('"') and arg.endswith('"'):
        return arg[1:-1]
    return consts.get(arg.rsplit(".", 1)[-1])


def _registrations(text: str, start: int, end: int,
                   consts: dict[str, str]) -> list[tuple[str, str, str, bool]]:
    """``(name, type, short, persistent)`` of each registration in ``text[start:end]``."""
    found = []
    body = text[start:end]
    for m in list(_CALL.finditer(body)) + list(_FS_CALL.finditer(body)):
        if m.re is _FS_CALL and m.group("fs") in ("Flags", "PersistentFlags"):
            continue
        if m.re is _FS_CALL and m.group("fs") not in ("f", "fl", "fs", "flags", "flagSet",
                                                      "pf", "persistent"):
            continue
        args = _args(body, m.end())
        if m.group("var"):
            args = args[1:]
        if not args:
            continue
        name = _literal(args[0], consts)
        short = _literal(args[1], consts) if m.group("p") and len(args) > 1 else ""
        if name:
            persistent = bool(m.groupdict().get("fs")) and m.re is _CALL or (
                m.re is _FS_CALL and m.group("fs") in ("pf", "persistent"))
            found.append((name, _TYPES[m.group("type")], short or "", persistent))
    for m in _VAR_CALL.finditer(body):
        args = _args(body, m.end())
        if len(args) < 2:
            continue
        name = _literal(args[1], consts)
        short = _literal(args[2], consts) if "VarP" in body[m.start():m.end()] and len(
            args) > 3 else ""
        go = re.search(r"(?:new|&)(\w+)", args[0])
        if name:
            found.append((name, f"value:{go.group(1) if go else args[0][:30]}", short or "",
                          bool(m.group("fs"))))
    for helper, kind in _HELPERS.items():
        for m in re.finditer(r"\bcmdutil\." + helper + r"\(", body):
            args = _args(body, m.end())
            if len(args) >= 4:
                name, short = _literal(args[2], consts), _literal(args[3], consts)
                if name:
                    found.append((name, kind, short or "", False))
    return found


def scan(root: Path) -> dict[str, dict[str, list]]:
    files = [p for d in ("pkg", "internal") for p in (root / d).rglob("*.go")
             if not p.name.endswith("_test.go") and "testdata" not in p.parts]
    consts: dict[str, str] = {}
    for path in files:
        for name, value in _CONST.findall(path.read_text(errors="ignore")):
            consts.setdefault(name, value)
    # every function that takes the command or a flag set, and what it registers
    helpers: dict[str, list[tuple[str, str]]] = {}  # name -> [(package, body)]
    for path in files:
        if root / "pkg" / "cmd" in path.parents and path.parent.name not in ("shared",):
            pass
        text = path.read_text(errors="ignore")
        pkg = re.search(r"^package (\w+)", text, re.M)
        funcs = list(_FUNC.finditer(text))
        for i, m in enumerate(funcs):
            if "cobra.Command" not in m.group(2) and "pflag.FlagSet" not in m.group(2):
                continue
            end = funcs[i + 1].start() if i + 1 < len(funcs) else len(text)
            helpers.setdefault(m.group(1), []).append((pkg.group(1) if pkg else "", text[
                m.start():end]))

    def from_calls(body: str, depth: int) -> list[tuple[str, str, str, bool]]:
        if depth > 3:
            return []
        out = []
        for m in re.finditer(r"\b(?:(\w+)\.)?([A-Za-z]\w*)\((?:\w+\.)?(?:cmd|c|\w+Cmd|f|fs)\b",
                             body):
            qualifier, name = m.group(1), m.group(2)
            if name.startswith("New") or name in _HELPERS:
                continue
            for pkg, hbody in helpers.get(name, []):
                if qualifier and qualifier != pkg:
                    continue
                if not qualifier and pkg not in ("cmdutil",) and depth == 0:
                    pass
                out.extend(_registrations(hbody, 0, len(hbody), consts))
                out.extend(from_calls(hbody, depth + 1))
        return out

    commands: dict[str, list[tuple[str, str, str, bool]]] = {}
    cmd_root = root / "pkg" / "cmd"
    for path in files:
        if cmd_root not in path.parents:
            continue
        text = path.read_text(errors="ignore")
        uses = _USE.findall(text)
        if not uses:
            continue
        parts = list(path.relative_to(cmd_root).parent.parts)
        if parts == ["root"]:
            parts = []
        use = uses[0]
        if not parts or parts[-1] != use:
            if parts and parts[-1] == "root":
                parts = parts[:-1]
            parts = parts + [use] if parts or use != "gh" else []
        key = " ".join(parts) or "root"
        regs = _registrations(text, 0, len(text), consts) + from_calls(text, 0)
        if re.search(r"\bcmdutil\.AddJSONFlags\(", text):
            # addJqFlag(f, "q") and addTemplateFlag(f, "t"): the letter is an argument
            regs += [("jq", "string", "q", False), ("template", "string", "t", False)]
        commands.setdefault(key, []).extend(regs)
    # inherit persistent flags from every command above
    out: dict[str, dict[str, list]] = {}
    for key in sorted(commands):
        flags: dict[str, list] = {"help": ["bool", "h"]}
        words = [] if key == "root" else key.split()
        for depth in range(len(words) + 1):
            above = " ".join(words[:depth]) or "root"
            for name, kind, short, persistent in commands.get(above, []):
                if depth == len(words) or persistent:
                    flags[name] = [kind, short]
        out[key] = dict(sorted(flags.items()))
    return out


def main(out: str, checkout: str) -> None:
    rev = subprocess.run(["git", "-C", checkout, "rev-parse", "HEAD"], capture_output=True,
                         text=True, check=False).stdout.strip()
    data = {"_source": f"https://github.com/cli/cli@{rev} flag registrations (pkg/cmd, "
                       "pkg/cmdutil, internal)"}
    data.update(scan(Path(checkout)))
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
