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
``p`` positional arguments, ``s`` subcommands (``ec2 wait``)."""

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


def _command(cmd, depth: int) -> dict:
    entry: dict = {}
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
        members: dict[str, str] = {}
        for name, arg in arg_table.items():
            member = getattr(arg, "_serialized_name", None)
            if member and not (name.startswith("no-") and member in members):
                members[member] = name  # a boolean's member is its positive option
        if members:
            entry["m"] = members
        if positional:
            entry["p"] = positional
    sub = None
    if depth < 3:
        if hasattr(cmd, "_get_command_table"):
            sub = cmd._get_command_table()
        else:
            sub = getattr(cmd, "subcommand_table", None)
    if sub:
        entry["s"] = {name: _command(child, depth + 1) for name, child in sorted(sub.items())}
    return entry


def main(out: str) -> None:
    driver = create_clidriver()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("VERSION", awscli.__version__ + "\n")
        for name, cmd in sorted(driver._get_command_table().items()):
            archive.writestr(f"{name}.json", json.dumps(_command(cmd, 1), sort_keys=True,
                                                        separators=(",", ":")))


if __name__ == "__main__":
    main(sys.argv[1])
