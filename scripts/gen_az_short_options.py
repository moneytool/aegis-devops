"""Writes src/aegis_core/data/az_short_options.json: every short option of az's commands
and the long option it is, read from azure-cli's ``command_modules/*/_params.py``:

    python scripts/gen_az_short_options.py <azure-cli checkout> \\
        src/aegis_core/data/az_short_options.json

Each ``with self.argument_context(SCOPE) as c:`` block names a command or group, and each
``c.argument(dest, ..., options_list=[...])`` in it (or an argument type with an
``options_list``, defined in the module) gives the short spellings of the first long
option. A scope applies to every command under it, and the most specific scope wins. A
scope written as a loop variable over a literal list counts once per item. Spellings built
at run time are not read: such a letter is recorded as written."""

import ast
import json
import subprocess
import sys
from pathlib import Path


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


def _aliases(options: list[str]) -> dict[str, str]:
    long_names = [o[2:] for o in options if o.startswith("--")]
    if not long_names:
        return {}
    return {o[1:]: long_names[0] for o in options
            if o.startswith("-") and not o.startswith("--") and len(o) == 2}


def module_scopes(source: str) -> dict[str, dict[str, str]]:
    tree = ast.parse(source)
    types: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call)):
            options = _options_list(node.value, {})
            if options:
                types[node.targets[0].id] = options
    scopes: dict[str, dict[str, str]] = {}

    def visit(node: ast.AST, loop: dict[str, list[str]]) -> None:
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            items = _strings(node.iter)
            inner = {**loop, node.target.id: items} if items else loop
            for child in node.body:
                visit(child, inner)
            return
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "argument_context" and call.args
                        and isinstance(item.optional_vars, ast.Name)):
                    scope = call.args[0]
                    names = ([scope.value] if isinstance(scope, ast.Constant)
                             and isinstance(scope.value, str) else
                             loop.get(scope.id, []) if isinstance(scope, ast.Name) else [])
                    var = item.optional_vars.id
                    found: dict[str, str] = {}
                    for sub in ast.walk(node):
                        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                                and isinstance(sub.func.value, ast.Name)
                                and sub.func.value.id == var
                                and sub.func.attr in ("argument", "extra")):
                            options = _options_list(sub, types)
                            if options:
                                found.update(_aliases(options))
                    for name in names:
                        scopes.setdefault(name, {}).update(found)
        for child in ast.iter_child_nodes(node):
            visit(child, loop)

    visit(tree, {})
    return {k: v for k, v in scopes.items() if v}


def main(checkout: str, out: str) -> None:
    root = Path(checkout)
    table: dict[str, dict[str, str]] = {}
    for path in sorted(root.glob("src/azure-cli/azure/cli/command_modules/*/_params.py")):
        for scope, aliases in module_scopes(path.read_text()).items():
            table.setdefault(scope, {}).update(aliases)
    commit = subprocess.run(["git", "-C", checkout, "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=False).stdout.strip()
    with open(out, "w") as f:
        json.dump({"_source": f"azure-cli {commit} command_modules/*/_params.py",
                   **dict(sorted(table.items()))}, f, indent=0, sort_keys=False)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
