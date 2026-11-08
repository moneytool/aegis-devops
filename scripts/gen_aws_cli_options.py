"""Writes src/aegis_core/data/aws_cli_options.zip: every option of every aws CLI command,
read from aws-cli's own argparse parsers, so the parser resolves an abbreviated option
(``--desired-cap``) as aws does and refuses one aws would refuse.

Run it with the Python interpreter of an installed aws-cli v2 (it imports ``awscli``):

    /opt/homebrew/Cellar/awscli/<version>/libexec/bin/python3 -I \\
        scripts/gen_aws_cli_options.py src/aegis_core/data/aws_cli_options.zip

One JSON member per top-level command (``autoscaling.json``), and ``VERSION``. Each
command is ``{"o": {option: arity}, "m": {Member: option}, "p": [[name, arity]],
"s": {subcommand: ...}}``: ``o`` every ``--option`` with how many words argparse gives it
(``""`` none, ``"1"`` one, ``"?"`` an optional one, ``"*"``/``"+"`` a list, ``"2"`` two),
``m`` the input shape's member names (what ``--cli-input-json`` keys are) with the option
each one is, ``t`` the type of each value that is not a string (``integer``, ``long``,
``float``, ``double``, ``timestamp``, ``blob``, ``structure``, ``map``, ``list:<member>``),
``x`` the botocore shape of each structure, map or list option (in the command's
``shapes``, by name), ``a`` options that accumulate (``append``, or ``filter`` for s3's
ordered --include/--exclude), ``c`` the choices argparse allows, ``k`` the value of a bare
optional-value option, ``al`` hidden aliases (another name of one argument), ``p``
positional arguments, ``s`` subcommands (``ec2 wait``)."""

import argparse
import json
import sys
import zipfile

import awscli
from awscli.argparser import ArgTableArgParser
from awscli.clidriver import create_clidriver


def _arity(action: argparse.Action) -> str:
    if action.nargs == 0:
        return ""
    if action.nargs is None:
        return "1"
    return str(action.nargs)


def _shape_name(model, shapes: dict) -> str:
    """Records ``model`` (and every shape it holds) in ``shapes`` by name, as botocore
    names them: ``{"t": type, "m": {member: shape}, "e": list member, "v": map value,
    "doc": document}``; returns its name."""
    name = getattr(model, "name", None) or model.type_name
    if name in shapes:
        return name
    node: dict = {"t": model.type_name}
    shapes[name] = node
    if getattr(model, "metadata", {}).get("document") or getattr(model, "is_document_type",
                                                                   False):
        node["doc"] = True
    if model.type_name == "structure":
        node["m"] = {k: _shape_name(v, shapes) for k, v in model.members.items()}
    elif model.type_name == "list":
        node["e"] = _shape_name(model.member, shapes)
    elif model.type_name == "map":
        node["v"] = _shape_name(model.value, shapes)
    return name


def _command(cmd, depth: int, shapes: dict | None = None) -> dict:
    entry: dict = {}
    shapes = {} if shapes is None else shapes
    # a command's own table first: building it registers the options plugins add to the
    # command's arguments (s3 sync's --delete, --size-only, --exact-timestamps)
    sub = None
    if depth < 3:
        if hasattr(cmd, "_get_command_table"):
            sub = cmd._get_command_table()
        else:
            sub = getattr(cmd, "subcommand_table", None)
    try:
        arg_table = cmd.arg_table
    except Exception:  # a group with no options of its own
        arg_table = None
    if arg_table:
        parser = ArgTableArgParser(arg_table)
        options, positional = {}, []
        for action in parser._actions:
            if not action.option_strings:
                positional.append([action.dest, _arity(action)])
            for spelling in action.option_strings:
                if spelling.startswith("--"):
                    options[spelling[2:]] = _arity(action)
        entry["o"] = options
        # each value's type, as aws-cli unpacks it (cli_type_name; a list's member type):
        # only the ones that are not strings
        types: dict[str, str] = {}
        for name, arg in arg_table.items():
            kind = getattr(arg, "cli_type_name", "string") or "string"
            if kind == "list":
                model = getattr(arg, "argument_model", None)
                member = getattr(getattr(model, "member", None), "type_name", "string")
                kind = f"list:{member}"
            if kind not in ("string", "boolean", "list:string"):
                types[name] = kind
        if types:
            entry["t"] = types
        # the botocore shape of every structure, map and list option (named in ``shapes``)
        complex_shapes = {}
        for name, arg in arg_table.items():
            model = getattr(arg, "argument_model", None)
            if model is not None and model.type_name in ("structure", "map", "list"):
                complex_shapes[name] = _shape_name(model, shapes)
        if complex_shapes:
            entry["x"] = complex_shapes
        members: dict[str, str] = {}
        for name, arg in arg_table.items():
            member = getattr(arg, "_serialized_name", None)
            if member and not (name.startswith("no-") and member in members):
                members[member] = name  # a boolean's member is its positive option
        if members:
            entry["m"] = members
        # hidden aliases (argrename.HIDDEN_ALIASES: a copy of an argument under another
        # name, for backward compatibility): each with the argument it stands for
        aliases = {}
        for name, arg in arg_table.items():
            member = getattr(arg, "_serialized_name", None)
            if getattr(arg, "_UNDOCUMENTED", False) and member:
                for other, other_arg in arg_table.items():
                    if (other != name and getattr(other_arg, "_serialized_name", None) == member
                            and not getattr(other_arg, "_UNDOCUMENTED", False)):
                        aliases[name] = other
        if aliases:
            entry["al"] = aliases
        if positional:
            entry["p"] = positional
        # what argparse does with a value beyond its count: "a" the options that accumulate
        # (action append, s3's AppendFilter), "c" the choices argparse allows, "k" the value
        # of a bare optional-value option (const)
        accumulate, choices, consts = {}, {}, {}
        for action in parser._actions:
            long_names = [s[2:] for s in action.option_strings if s.startswith("--")]
            if not long_names:
                continue
            name = long_names[0]
            if type(action).__name__ == "AppendFilter":
                accumulate[name] = "filter"
            elif isinstance(action, argparse._AppendAction):
                accumulate[name] = "append"
            if action.choices:
                choices[name] = list(action.choices)
            if action.nargs == "?" and action.const is not None:
                consts[name] = action.const
        if accumulate:
            entry["a"] = accumulate
        if choices:
            entry["c"] = choices
        if consts:
            entry["k"] = consts
    if sub:
        entry["s"] = {name: _command(child, depth + 1, shapes)
                      for name, child in sorted(sub.items())}
    return entry


def main(out: str) -> None:
    driver = create_clidriver()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("VERSION", awscli.__version__ + "\n")
        for name, cmd in sorted(driver._get_command_table().items()):
            shapes: dict = {}
            entry = _command(cmd, 1, shapes)
            if shapes:
                entry["shapes"] = shapes
            archive.writestr(f"{name}.json", json.dumps(entry, sort_keys=True,
                                                        separators=(",", ":")))


if __name__ == "__main__":
    main(sys.argv[1])
