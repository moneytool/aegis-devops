"""Writes src/aegis_core/data/pflag_types.json: the pflag type of every flag of the Go
tools the parser reads (kubectl, helm, flux, argocd, gh), from their flag registrations
(``Flags().StringArrayVarP(&o.x, "name", "n", ...)``, ``Int64("name", ...)``, ...), so
the parser reads each flag as pflag does: a StringArray or StringSlice accumulates (a
StringSlice splits each value as CSV), an Int is read with base 0, a Duration with
time.ParseDuration, a Count counts.

    python scripts/gen_pflag_types.py src/aegis_core/data/pflag_types.json \\
        kubectl=<kubectl and cli-runtime sources> helm=<dirs> flux=<dirs> ...

A flag registered with different types in different commands is listed under each type
(``"mixed"``), and under ``<tool>:commands`` with the type each command gives it (the
command named from its directory, its ``xxxCmd`` variable or its constructor); a flag
name given by a Go constant is resolved when the constant is a string literal in the same
package; ``Var`` flags (a custom pflag.Value) are ``"value"``."""

import json
import re
import sys
from pathlib import Path

TYPES = ("StringArray", "StringSlice", "StringToString", "IntSlice", "Int32Slice",
         "Int64Slice", "UintSlice", "BoolSlice", "DurationSlice", "Float64Slice",
         "Float32Slice", "String", "Int", "Int8", "Int16", "Int32", "Int64", "Uint", "Uint8",
         "Uint16", "Uint32", "Uint64", "Bool", "Duration", "Float32", "Float64", "Count",
         "IP", "IPSlice", "IPMask", "IPNet", "BytesHex", "BytesBase64")
_CALL = re.compile(
    r"\.(?P<type>" + "|".join(TYPES) + r"|)(?P<var>Var)?(?P<p>P)?\(\s*"
    r"(?:(?P<ptr>&?[\w.\[\]()]+)\s*,\s*)?(?P<name>\"[^\"]*\"|[A-Za-z_][\w.]*)\s*,", re.S)
_CONST = re.compile(r"\b([A-Za-z_]\w*)\s*(?:string\s*)?=\s*\"([a-z0-9][a-z0-9.-]*)\"")


_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)", re.M)
_RECEIVER = re.compile(r"(\w+?)Cmd\.(?:Persistent)?Flags\(\)\s*$")
_WORDS = re.compile(r"[A-Z][a-z0-9]*|^[a-z][a-z0-9]*")


def _command_key(tool: str, path: Path, text: str, pos: int) -> str | None:
    """The command a registration belongs to, as words (``create deployment``, ``app sync``,
    ``pr merge``): gh's from its directory, flux's from the ``xxxCmd`` variable, the others'
    from the function that builds the command (NewCmdCreateDeployment, newUpgradeCmd,
    NewApplicationSyncCommand)."""
    if tool == "gh":
        parts = path.parts
        if "cmd" in parts:
            rest = parts[parts.index("cmd") + 1:-1]
            return " ".join(rest[:2]) if rest else None
    receiver = _RECEIVER.search(text[max(0, pos - 120):pos])
    if receiver:
        name = receiver.group(1)
    else:
        funcs = [m for m in _FUNC.finditer(text) if m.start() < pos]
        if not funcs:
            return None
        name = funcs[-1].group(1)
    words = [w.lower() for w in _WORDS.findall(name)]
    while words and words[0] in ("new", "cmd"):
        words.pop(0)
    while words and words[-1] in ("cmd", "command", "flags", "options"):
        words.pop()
    if words[:1] == ["application"]:
        words[0] = "app"
    return " ".join(words) or None


_VAR_OPEN = re.compile(r"\.VarP?\(")


def _balanced_arg(text: str, start: int) -> tuple[str | None, int]:
    """The first argument of a call whose ``(`` ends at ``start``, up to its top-level
    comma, and the index after that comma."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return None, i
            depth -= 1
        elif ch == "," and depth == 0:
            return text[start:i], i + 1
        elif ch == '"':
            i = text.index('"', i + 1)
        i += 1
    return None, i


def scan(dirs: list[str], tool: str = "") -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    files = [p for d in dirs for p in Path(d).rglob("*.go") if not p.name.endswith("_test.go")]
    consts: dict[str, str] = {}
    for path in files:
        for name, value in _CONST.findall(path.read_text(errors="ignore")):
            consts.setdefault(name, value)
    types: dict[str, set[str]] = {}
    by_command: dict[str, dict[str, set[str]]] = {}
    for path in files:
        text = path.read_text(errors="ignore")
        # Var/VarP whose Value is built in place (``newWaitValue(a, b)``): the regex's
        # pointer cannot hold nested parentheses, so these are read by balanced scanning
        for m in _VAR_OPEN.finditer(text):
            value_expr, after = _balanced_arg(text, m.end())
            if value_expr is None:
                continue
            nm = re.match(r"\s*(\"[^\"]*\"|[A-Za-z_][\w.]*)\s*,", text[after:])
            if not nm:
                continue
            raw = nm.group(1)
            name = raw[1:-1] if raw.startswith('"') else consts.get(raw.rsplit(".", 1)[-1])
            if not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
                continue
            go_type = re.search(r"&?(?:new)?([A-Z]?\w+?)(?:\{|\()", value_expr.strip())
            kind = f"value:{go_type.group(1) if go_type else value_expr.strip()[:40]}"
            types.setdefault(name, set()).add(kind)
            command = _command_key(tool, path, text, m.start())
            if command:
                by_command.setdefault(command, {}).setdefault(name, set()).add(kind)
        for m in _CALL.finditer(text):
            kind, var, ptr = m.group("type"), m.group("var"), m.group("ptr")
            if not kind and not var:
                continue  # .Something( that is not a flag registration
            if not kind:
                continue  # a custom Value: read above, with its Go type
            if var and not ptr:
                continue  # XxxVar needs its pointer first
            if not var and ptr:
                continue  # Xxx("name", ...) takes the name first
            raw = m.group("name")
            name = raw[1:-1] if raw.startswith('"') else consts.get(raw.rsplit(".", 1)[-1])
            if not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
                continue
            types.setdefault(name, set()).add(kind or "value")
            command = _command_key(tool, path, text, m.start())
            if command:
                by_command.setdefault(command, {}).setdefault(name, set()).add(kind or "value")

    def one(kinds: set[str]) -> str:
        return next(iter(kinds)) if len(kinds) == 1 else "mixed:" + ",".join(sorted(kinds))

    flags = {name: one(kinds) for name, kinds in sorted(types.items())}
    mixed = {name for name, kind in flags.items() if kind.startswith("mixed:")}
    # per command, only the flags whose type differs between commands
    commands = {command: {n: one(k) for n, k in sorted(found.items()) if n in mixed}
                for command, found in sorted(by_command.items())}
    return flags, {c: f for c, f in commands.items() if f}


# Every flag whose value is a custom pflag.Value, with what its Set() method does, read
# from each tool's source: as a plain type (an enum or a path is a String, an append-only
# slice a StringArray, a map a StringToString, an int an Int), or a reading of its own
# (helm 4's --wait: flags.go waitValue.Set). The generator fails on a custom Value this
# table does not list, so a tool update cannot add one silently.
CUSTOM_VALUES = {
    ("helm", "wait"): "HelmWait",  # bare: watcher; true: watcher; false: hookOnly; ...
    ("helm", "output"): "String",  # outputValue: table, json or yaml
    ("helm", "post-renderer"): "String",
    ("helm", "post-renderer-args"): "StringArray",  # postRendererArgsSlice appends
    ("kubectl", "aggregation-rule"): "StringToString",  # NewMapStringString
    ("kubectl", "auth-provider"): "String",
    ("kubectl", "exec-api-version"): "String",
    ("kubectl", "exec-command"): "String",
    ("kubectl", "exec-interactive-mode"): "String",
    ("flux", "crds"): "String", ("flux", "decryption-provider"): "String",
    ("flux", "level"): "String", ("flux", "log-level"): "String", ("flux", "path"): "String",
    ("flux", "provider"): "String", ("flux", "source"): "String",
    ("flux", "ssh-ecdsa-curve"): "String", ("flux", "ssh-key-algorithm"): "String",
    ("flux", "ssh-rsa-bits"): "Int",  # flags.RSAKeyBits: strconv.Atoi
    ("flux", "type"): "String", ("flux", "verify-provider"): "String",
    ("flux", "visibility"): "String",
}


def _resolve_custom(tool: str, flags: dict[str, str]) -> dict[str, str]:
    """Each custom Value replaced by what its Set() does (:data:`CUSTOM_VALUES`)."""
    out: dict[str, str] = {}
    for name, kind in flags.items():
        parts = kind[len("mixed:"):].split(",") if kind.startswith("mixed:") else [kind]
        resolved = set()
        for part in parts:
            if part.startswith("value"):
                if (tool, name) not in CUSTOM_VALUES:
                    raise SystemExit(f"{tool} --{name} is a custom pflag.Value ({part}) the "
                                     "generator does not know: read its Set() method and "
                                     "add it to CUSTOM_VALUES")
                resolved.add(CUSTOM_VALUES[(tool, name)])
            else:
                resolved.add(part)
        out[name] = next(iter(resolved)) if len(resolved) == 1 else "mixed:" + ",".join(
            sorted(resolved))
    return out


def main(out: str, specs: list[str]) -> None:
    data = {"_source": "pflag registrations in each tool's source: " + "; ".join(specs)}
    for spec in specs:
        tool, _, dirs = spec.partition("=")
        flags, commands = scan(dirs.split(","), tool)
        data[tool] = _resolve_custom(tool, flags)
        data[f"{tool}:commands"] = {c: _resolve_custom(tool, f) for c, f in commands.items()}
        data[f"{tool}:custom"] = sorted(name for name, kind in flags.items() if "value" in kind)
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
