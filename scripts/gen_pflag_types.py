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
    r"(?:(?P<ptr>&?[\w.\[\]()]+)\s*,\s*)?(?P<name>\"[^\"]*\"|[A-Za-z_][\w.]*)\s*,"
    r"(?:\s*\"(?P<short>[A-Za-z0-9]?)\"\s*,)?", re.S)
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


def scan(dirs: list[str], tool: str = "",
         shorts: dict[str, dict[str, str]] | None = None,
         ) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
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
            nm = re.match(r"\s*(\"[^\"]*\"|[A-Za-z_][\w.]*)\s*,"
                          r"(?:\s*\"([A-Za-z0-9]?)\"\s*,)?", text[after:])
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
                if shorts is not None and "VarP" in text[m.start():m.end()] and nm.group(2):
                    shorts.setdefault(command, {})[nm.group(2)] = name
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
                if shorts is not None and m.group("p") and m.group("short"):
                    shorts.setdefault(command, {})[m.group("short")] = name

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
    ("gh", "retention-period"): "Duration",  # codespace NullableDuration: time.ParseDuration
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


def _git(path: Path, *args: str) -> str:
    import subprocess

    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True,
                            check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def upstream(directory: str) -> str:
    """``directory`` as its upstream identifier, ``<repo URL>@<tag or commit>/<subpath>``,
    from the git checkout it is in. The JSON ships in the package, so a local path is never
    written: a directory outside a git checkout with an https origin is refused."""
    path = Path(directory).resolve()
    top = _git(path, "rev-parse", "--show-toplevel")
    url = _git(path, "config", "remote.origin.url")
    if not top or not url.startswith("https://"):
        raise SystemExit(f"{directory}: not a git checkout with an https origin; the "
                         "generator records upstream identifiers only, never local paths")
    url = re.sub(r"^https://[^@/]+@", "https://", url).removesuffix(".git")
    rev = _git(path, "describe", "--tags", "--exact-match") or _git(path, "rev-parse", "HEAD")
    sub = path.relative_to(Path(top).resolve()).as_posix()
    return f"{url}@{rev}" + ("" if sub == "." else f"/{sub}")


_VAR_REG = re.compile(r'\.(?:\w+?)Var(?:P)?\(\s*(&[\w.\[\]]+)\s*,\s*"([a-z][\w-]*)"')
_DEPRECATED = re.compile(r'MarkDeprecated\(\s*"([\w-]+)"')


def aliases(dirs: list[str], tool: str) -> dict[str, dict[str, str]]:
    """Per command, the flags one Go variable is registered under (``&client.ForceReplace``
    as --force and --force-replace): each other name with the name kept, the one no
    ``MarkDeprecated`` call names (else the first registered)."""
    out: dict[str, dict[str, str]] = {}
    for path in [p for d in dirs for p in Path(d).rglob("*.go") if not p.name.endswith("_test.go")]:
        text = path.read_text(errors="ignore")
        deprecated = set(_DEPRECATED.findall(text))
        groups: dict[tuple[str | None, str], list[str]] = {}
        for m in _VAR_REG.finditer(text):
            command = _command_key(tool, path, text, m.start())
            names = groups.setdefault((command, m.group(1)), [])
            if m.group(2) not in names:
                names.append(m.group(2))
        for (command, _ptr), names in groups.items():
            if len(names) < 2 or not command:
                continue
            kept = next((n for n in names if n not in deprecated), names[0])
            out.setdefault(command, {}).update({n: kept for n in names if n != kept})
    return {c: dict(sorted(v.items())) for c, v in sorted(out.items())}


def main(out: str, specs: list[str]) -> None:
    named = [f"{tool}=" + ",".join(upstream(d) for d in dirs.split(","))
             for tool, _, dirs in (spec.partition("=") for spec in specs)]
    data = {"_source": "pflag registrations in each tool's source: " + "; ".join(named)}
    for spec in specs:
        tool, _, dirs = spec.partition("=")
        letters: dict[str, dict[str, str]] = {}
        flags, commands = scan(dirs.split(","), tool, letters)
        # flags registered on one variable under two names (helm's --force and
        # --force-replace, gh's --confirm and --yes): each name with the one the parser keeps,
        # the one not marked deprecated
        data[f"{tool}:aliases"] = aliases(dirs.split(","), tool)
        # each command's short letters, as the registrations give them (``-n`` is
        # --namespace), by the command the registration belongs to
        data[f"{tool}:shorts"] = {c: dict(sorted(v.items())) for c, v in sorted(letters.items())}
        data[tool] = _resolve_custom(tool, flags)
        data[f"{tool}:commands"] = {c: _resolve_custom(tool, f) for c, f in commands.items()}
        data[f"{tool}:custom"] = sorted(name for name, kind in flags.items() if "value" in kind)
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
