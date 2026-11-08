"""Writes src/aegis_core/data/az_short_options.json: every short option of az's commands
and the long option it is, read from azure-cli's ``command_modules/*/_params.py``:

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
            inner = {**env, node.target.id: items} if items else env
            block(node.body, inner)
            return
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "argument_context" and call.args
                        and isinstance(item.optional_vars, ast.Name)):
                    names = _eval(call.args[0], env) or []
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
