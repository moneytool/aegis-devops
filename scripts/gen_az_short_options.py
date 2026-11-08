"""Writes src/aegis_core/data/az_short_options.json: the short options of az's commands
and the long option each is (``s``), and the long options declared for each command scope
(``l``, for argparse's prefix matching), read from azure-cli's
``command_modules/*/_params.py``:

    python scripts/gen_az_short_options.py <azure-cli checkout> \\
        src/aegis_core/data/az_short_options.json

Each ``with self.argument_context(SCOPE) as c:`` block names a command or group, and each
``c.argument(dest, ..., options_list=[...])`` in it (or an argument type with an
``options_list``, defined in the module) gives the short spellings of the first long
option. A scope applies to every command under it, and the most specific scope wins. A scope
built from loop variables, ``+``, ``.format()`` or an f-string is read for every value the
names can take (literal lists, and names bound to them). A scope built any other way is not
read, and the parser refuses a letter it has no entry for."""

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _strings(node: ast.AST) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [e.value for e in node.elts if isinstance(e, ast.Constant)
                  and isinstance(e.value, str)]
        return values if len(values) == len(node.elts) else None
    return None


def _options_list(call: ast.Call, types: dict[str, list[str]]) -> list[str] | None:
    for keyword in call.keywords:
        if keyword.arg == "options_list":
            return _strings(keyword.value)
    for arg in call.args[1:]:
        if isinstance(arg, ast.Name) and arg.id in types:
            return types[arg.id]
    for keyword in call.keywords:
        if keyword.arg == "arg_type" and isinstance(keyword.value, ast.Name):
            return types.get(keyword.value.id)
    return None


# How many words the core argument types take (azure-cli-core commands/parameters.py).
_CORE_TYPE_NARGS = {"tags_type": "*", "zones_type": "+", "tag_type": "?"}


def _nargs(call: ast.Call, type_nargs: dict[str, str]) -> str | None:
    """How many words an argument takes, as argparse reads its ``nargs`` (``+``, ``*``,
    ``?``) or ``action='append'`` (``append``: one word each time, all kept), from the call
    or the argument type it is given."""
    for keyword in call.keywords:
        if keyword.arg == "nargs" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
        if (keyword.arg == "action" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == "append"):
            return "append"
    for arg in [*call.args[1:], *(k.value for k in call.keywords if k.arg == "arg_type")]:
        if isinstance(arg, ast.Name) and arg.id in type_nargs:
            return type_nargs[arg.id]
    return None


def _aliases(options: list[str]) -> dict[str, str]:
    long_names = [o[2:] for o in options if o.startswith("--")]
    if not long_names:
        return {}
    return {o[1:]: long_names[0] for o in options
            if o.startswith("-") and not o.startswith("--") and len(o) == 2}


def _eval(node: ast.AST, env: dict[str, list[str]]) -> list[str] | None:
    """Every string a scope expression can be, given the names bound to lists of strings:
    a literal, a name, ``a + b``, ``'...'.format(x, ...)`` and an f-string. None when it
    cannot be read."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        # source.value for an enum member bound by a loop: not read
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _eval(node.left, env), _eval(node.right, env)
        if left is None or right is None:
            return None
        return [a + b for a in left for b in right]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format" and not node.keywords):
        templates = _eval(node.func.value, env)
        args = [_eval(a, env) for a in node.args]
        if templates is None or any(a is None for a in args):
            return None
        out = [""]
        combos: list[list[str]] = [[]]
        for values in args:
            combos = [c + [v] for c in combos for v in values]
        out = []
        for template in templates:
            for combo in combos:
                try:
                    out.append(template.format(*combo))
                except (IndexError, KeyError):
                    return None
        return out
    if isinstance(node, ast.JoinedStr):
        parts: list[list[str]] = [[""]]
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append([str(value.value)])
            elif isinstance(value, ast.FormattedValue):
                got = _eval(value.value, env)
                if got is None:
                    return None
                parts.append(got)
        out = [""]
        for options in parts:
            out = [a + b for a in out for b in options]
        return out
    return None


def _contexts(tree: ast.AST, method: str):
    """Every ``with self.<method>(SCOPE, ...) as var:`` block, as ``(names, var, node,
    call)``: SCOPE read for every value its names can take (:func:`_eval`), with loop
    variables over literal lists and names bound to them."""
    found: list[tuple[list[str], str, ast.With, ast.Call]] = []

    def block(statements: list[ast.stmt], env: dict[str, list[str]]) -> None:
        env = dict(env)
        for node in statements:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                values = _strings(node.value) or _eval(node.value, env)
                if values is not None:
                    env[node.targets[0].id] = values
            visit(node, env)

    def visit(node: ast.AST, env: dict[str, list[str]]) -> None:
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            items = _strings(node.iter) or (env.get(node.iter.id)
                                            if isinstance(node.iter, ast.Name) else None)
            block(node.body, {**env, node.target.id: items} if items else env)
            return
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr == method and call.args
                        and isinstance(item.optional_vars, ast.Name)):
                    found.append((_eval(call.args[0], env) or [], item.optional_vars.id,
                                  node, call))
            block(node.body, env)
            return
        if isinstance(node, (ast.FunctionDef, ast.If, ast.Try)):
            for field in ("body", "orelse", "finalbody"):
                block(getattr(node, field, []) or [], env)
            for handler in getattr(node, "handlers", []):
                block(handler.body, env)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, env)

    block(tree.body, {})
    return found


def _calls_on(node: ast.AST, var: str, names: tuple[str, ...]):
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and isinstance(sub.func.value, ast.Name) and sub.func.value.id == var
                and sub.func.attr in names):
            yield sub


def module_arguments(source: str) -> dict[str, dict[str, Any]]:
    """Per argument scope: ``dest`` -> its options list (None for knack's default
    ``--dest-name``), and the dests added with ``c.extra`` (not in any signature)."""
    tree = ast.parse(source)
    types: dict[str, list[str]] = {}
    type_nargs: dict[str, str] = dict(_CORE_TYPE_NARGS)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call)):
            options = _options_list(node.value, {})
            if options:
                types[node.targets[0].id] = options
            nargs = _nargs(node.value, {})
            if nargs:
                type_nargs[node.targets[0].id] = nargs
    helpers = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    def argument_calls(node: ast.AST, var: str, depth: int = 0):
        """The c.argument / c.extra calls of a block, and of the module's helper functions
        it hands ``c`` to (``_configure_db_dw_params(c)``), two levels deep."""
        yield from _calls_on(node, var, ("argument", "extra"))
        if depth >= 2:
            return
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id in helpers and sub.args
                    and isinstance(sub.args[0], ast.Name) and sub.args[0].id == var):
                helper = helpers[sub.func.id]
                if helper.args.args:
                    yield from argument_calls(helper, helper.args.args[0].arg, depth + 1)

    scopes: dict[str, dict[str, Any]] = {}
    for names, var, node, _call in _contexts(tree, "argument_context"):
        dests: dict[str, list[str] | None] = {}
        extras: set[str] = set()
        nargs: dict[str, str] = {}
        for sub in argument_calls(node, var):
            if not (sub.args and isinstance(sub.args[0], ast.Constant)
                    and isinstance(sub.args[0].value, str)):
                continue
            dest = sub.args[0].value
            dests[dest] = _options_list(sub, types)
            found = _nargs(sub, type_nargs)
            if found:
                nargs[dest] = found
            for keyword in sub.keywords:
                # argparse type=int / type=float: the only az values that are not text
                if (keyword.arg == "type" and isinstance(keyword.value, ast.Name)
                        and keyword.value.id in ("int", "float")):
                    nargs.setdefault(f"type:{dest}", keyword.value.id)
            if sub.func.attr == "extra":
                extras.add(dest)
        for name in names:
            entry = scopes.setdefault(name, {"dest": {}, "extra": set(), "nargs": {}})
            entry["dest"].update(dests)
            entry["extra"].update(extras)
            entry["nargs"].update(nargs)
    return scopes


_NOT_OPTIONS = frozenset({"cmd", "client", "self", "cls", "instance"})


def module_functions(paths: list[Path]) -> dict[str, tuple[list[str], bool]]:
    """Every function in a command module's own files: its parameters (the ones knack
    turns into options: not cmd, client, self or instance, nor *args and **kwargs), and
    whether it takes **kwargs, whose options come from elsewhere (an SDK model)."""
    functions: dict[str, tuple[list[str], bool]] = {}
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                args = node.args
                params = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
                          if a.arg not in _NOT_OPTIONS and not a.arg.startswith("_")]
                functions.setdefault(node.name, (params, args.kwarg is not None))
    return functions


def module_commands(source: str, functions: dict[str, tuple[list[str], bool]]
                    ) -> dict[str, tuple[list[str], bool]]:
    """Per command: the parameters of the function it runs that the module defines, and
    whether those are all its options (a custom function without **kwargs). An SDK
    method's are not here; a generic update command's are its custom function's and
    --set/--add/--remove/--force-string, besides its SDK getter's and setter's."""
    tree = ast.parse(source)
    commands: dict[str, tuple[list[str], bool]] = {}
    for names, var, node, _call in _contexts(tree, "command_group"):
        for sub in _calls_on(node, var, ("custom_command", "custom_show_command",
                                         "custom_wait_command", "command", "show_command",
                                         "wait_command", "generic_update_command",
                                         "generic_wait_command")):
            if not (sub.args and isinstance(sub.args[0], ast.Constant)
                    and isinstance(sub.args[0].value, str)):
                continue
            leaf = sub.args[0].value
            func = (sub.args[1].value if len(sub.args) > 1
                    and isinstance(sub.args[1], ast.Constant) else None)
            params: list[str] = []
            complete = False
            if sub.func.attr.startswith("custom_") and isinstance(func, str) \
                    and func in functions:
                params, kwargs = functions[func]
                complete = not kwargs
            elif sub.func.attr == "generic_update_command":
                custom = next((k.value.value for k in sub.keywords
                               if k.arg == "custom_func_name"
                               and isinstance(k.value, ast.Constant)), None)
                params = [*functions.get(custom, ([], False))[0],
                          "set", "add", "remove", "force_string"]
            for name in names:
                commands[f"{name} {leaf}"] = (params, complete)
    return commands


_AAZ_MULTI = frozenset({"AAZListArg", "AAZDictArg", "AAZTagsArg", "AAZZonesArg"})
_AAZ_DEFAULTS = {"AAZResourceGroupNameArg": ["--resource-group", "-g"],
                 "AAZResourceLocationArg": ["--location", "-l"]}


def aaz_commands(path: Path) -> dict[str, list[list[str]]]:
    """The options of each AAZ command class in a file (``@register_command("...")``):
    every ``_args_schema.<name> = AAZ...Arg(options=[...])``, or its default spelling."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    except SyntaxError:
        return {}
    out: dict[str, list[list[str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        names = [d.args[0].value for d in node.decorator_list
                 if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "register_command"
                 and d.args and isinstance(d.args[0], ast.Constant)]
        if not names:
            continue
        options: list[list[str]] = []
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Assign) and len(sub.targets) == 1
                    and isinstance(sub.targets[0], ast.Attribute)
                    and isinstance(sub.targets[0].value, ast.Name)
                    and sub.targets[0].value.id == "_args_schema"
                    and isinstance(sub.value, ast.Call)):
                listed = next((_strings(k.value) for k in sub.value.keywords
                               if k.arg == "options"), None)
                kind = getattr(sub.value.func, "id", getattr(sub.value.func, "attr", ""))
                spelled = listed or _AAZ_DEFAULTS.get(kind) or [
                    "--" + sub.targets[0].attr.replace("_", "-")]
                # an AAZ list or dict argument takes every word up to the next option
                options.append([*spelled, "nargs:+"] if kind in _AAZ_MULTI else spelled)
        for name in names:
            out[name] = options
    return out


def _scope_chain(command: str) -> list[str]:
    words = command.split()
    return [" ".join(words[:size]) for size in range(1, len(words) + 1)]


def main(checkout: str, out: str) -> None:
    root = Path(checkout) / "src/azure-cli/azure/cli/command_modules"
    arguments: dict[str, dict[str, Any]] = {}
    commands: dict[str, tuple[list[str], bool]] = {}
    aaz: dict[str, list[list[str]]] = {}
    for module in sorted(p for p in root.iterdir() if p.is_dir()):
        files = [p for p in module.rglob("*.py") if "tests" not in p.parts]
        params = module / "_params.py"
        if params.exists():
            for scope, found in module_arguments(params.read_text(encoding="utf-8-sig")).items():
                entry = arguments.setdefault(scope, {"dest": {}, "extra": set(), "nargs": {}})
                entry["dest"].update(found["dest"])
                entry["extra"].update(found["extra"])
                entry["nargs"].update(found["nargs"])
        functions = module_functions([p for p in files if "aaz" not in p.parts])
        for path in files:
            if path.name == "commands.py":
                commands.update(module_commands(path.read_text(encoding="utf-8-sig"), functions))
            if "aaz" in path.parts:
                aaz.update(aaz_commands(path))

    def dest_options(command: str, dest: str) -> list[str] | None:
        found: list[str] | None = None
        for scope in _scope_chain(command):
            entry = arguments.get(scope)
            if entry and dest in entry["dest"] and entry["dest"][dest] is not None:
                found = entry["dest"][dest]
        return found

    def dest_nargs(command: str, dest: str) -> str | None:
        found: str | None = _CORE_DEST_NARGS.get(dest)
        for scope in _scope_chain(command):
            entry = arguments.get(scope)
            if entry and dest in entry["nargs"]:
                found = entry["nargs"][dest]
        return found

    table: dict[str, dict[str, Any]] = {}
    # scopes: every option any argument scope declares (a group's may not all apply)
    for scope, entry in arguments.items():
        groups: list[list[str]] = []
        for dest, options in entry["dest"].items():
            nargs = entry["nargs"].get(dest)
            vtype = entry["nargs"].get(f"type:{dest}")
            groups.append([*(options or ["--" + dest.replace("_", "-")]),
                           *([f"nargs:{nargs}"] if nargs else []),
                           *([f"type:{vtype}"] if vtype else [])])
        table[scope] = {"s": {}, "l": set(), "c": False, "n": {}}
        _set_leaf(table, scope, groups, False)
    # each registered command: its function's parameters as knack spells them (exactly its
    # options when complete), or an AAZ class's
    for command, (params, complete) in commands.items():
        groups: list[list[str]] = []
        dests = set(params)
        for scope in _scope_chain(command):
            dests |= arguments.get(scope, {}).get("extra", set())
        for dest in dests:
            nargs = dest_nargs(command, dest)
            vtype = dest_nargs(command, f"type:{dest}")
            groups.append([*(dest_options(command, dest) or _CORE_DESTS.get(dest)
                             or ["--" + dest.replace("_", "-")]),
                           *([f"nargs:{nargs}"] if nargs else []),
                           *([f"type:{vtype}"] if vtype else [])])
        if command in aaz and not complete:
            groups, complete = aaz[command], True
        # an argument declared on this very command in _params.py is its own, though the
        # function's signature may not show it under that name
        own = arguments.get(command, {})
        groups.extend([*options, *([f"nargs:{own['nargs'][dest]}"]
                                   if dest in own.get("nargs", {}) else [])]
                      for dest, options in own.get("dest", {}).items() if options)
        if command.startswith("storage "):
            # storage's data-plane commands get their account and auth options when az
            # loads them, not from a signature or _params.py: never all known here
            complete = False
        _set_leaf(table, command, groups, complete)
    for command, groups in aaz.items():
        if command not in commands:
            _set_leaf(table, command, groups, True)
    storage = table.setdefault("storage", {"s": {}, "l": set(), "c": False, "n": {}})
    storage["l"] |= _STORAGE_DATA_PLANE
    commit = subprocess.run(["git", "-C", checkout, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=False).stdout.strip()
    data = {k: {"s": v["s"], "l": sorted(v["l"]), **({"c": True} if v["c"] else {}),
                **({"n": v["n"]} if v.get("n") else {})}
            for k, v in sorted(table.items())}
    with open(out, "w") as f:
        json.dump({"_source": f"azure-cli {commit} command_modules (_params.py, "
                              "commands.py, custom functions, aaz)", **data},
                  f, indent=0, sort_keys=False)
        f.write("\n")


def _aliases_all(dests: dict[str, list[str] | None]) -> dict[str, str]:
    out: dict[str, str] = {}
    for options in dests.values():
        if options:
            out.update(_aliases(options))
    return out


# The account and authentication options azure-cli's storage module adds to its
# data-plane commands when it loads them (storage/__init__.py, _validators.py).
_STORAGE_DATA_PLANE = {
    "account-name", "account-key", "connection-string", "sas-token", "auth-mode",
    "blob-endpoint", "file-endpoint", "queue-endpoint", "table-endpoint", "backup-intent",
    "enable-file-backup-request-intent", "timeout",
}


# Arguments azure-cli's core registers for every command by their name (core
# commands/parameters.py and the global registrations): their spelling is not --dest-name.
# How many words the arguments core registers by name take.
_CORE_DEST_NARGS = {"tags": "*", "zones": "+"}

_CORE_DESTS = {
    "resource_group_name": ["--resource-group", "-g"],
    "location": ["--location", "-l"],
    "tags": ["--tags"],
    "no_wait": ["--no-wait"],
}


def _set_leaf(table: dict[str, dict[str, Any]], command: str, groups: list[list[str]],
              complete: bool) -> None:
    """A command's own options: ``l`` its long ones and ``s`` its short ones (each the long
    option listed with it). ``c`` when they are all of them: then they replace what the
    scopes above declare, which may not apply to it; otherwise they add to them."""
    entry = table.setdefault(command, {"s": {}, "l": set(), "c": False, "n": {}})
    longs = {o[2:] for group in groups for o in group if o.startswith("--")}
    shorts: dict[str, str] = {}
    nargs: dict[str, str] = {}
    for group in groups:
        options = [o for o in group if not o.startswith(("nargs:", "type:"))]
        shorts.update(_aliases(options))
        for marker in (o for o in group if o.startswith(("nargs:", "type:"))):
            prefix = "" if marker.startswith("nargs:") else "type:"
            value = marker.partition(":")[2]
            nargs.update({prefix + o[2:]: value for o in options if o.startswith("--")})
    if complete:
        entry["l"], entry["s"], entry["n"] = longs, {**entry["s"], **shorts}, nargs
    else:
        entry["l"] |= longs
        entry["s"] = {**entry["s"], **shorts}
        entry["n"] = {**entry.get("n", {}), **nargs}
    entry["c"] = complete


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
