"""Pulumi parsers (PLAN §3.1 backlog item "Pulumi, CDK").

``from_pulumi_preview`` turns a ``pulumi preview --json`` document into one
InfrastructureIntent per step, the same class of parser as
:func:`aegis_core.parser.from_terraform_plan`. ``from_pulumi_argv`` covers
the coarser case where no preview JSON is available at all -- it produces a
single, stack-scoped intent that's enough to gate the invocation itself.
"""

from typing import Any

from aegis_core.intent import InfrastructureIntent
from aegis_core.parser import _basename  # noqa: F401  (re-exported convention)

_OP_ACTION = {
    "same": "no-op",
    "create": "create",
    "update": "update",
    "replace": "replace",
    "create-replacement": "replace",
    "delete-replaced": "replace",
    "delete": "delete",
    "read": "read",
    "refresh": "read",
    "import": "create",
    "discard": "delete",
}

_READ_OPS = {"read", "refresh"}


def _parse_urn(urn: str) -> tuple[str, str, str, str]:
    """``urn:pulumi:<stack>::<project>::<type>::<name>`` -> (stack, project,
    type, name). A parented resource's type is ``<parentType>$<type>``; the
    last ``$``-separated segment is the resource's own type."""
    parts = urn.split("::")
    if len(parts) < 4 or not parts[0].startswith("urn:pulumi:"):
        raise ValueError(f"not a recognizable pulumi urn: {urn!r}")
    stack = parts[0][len("urn:pulumi:") :]
    project = parts[1]
    raw_type = parts[2]
    if "$" in raw_type:
        raw_type = raw_type.rsplit("$", 1)[-1]
    name = "::".join(parts[3:])
    return stack, project, raw_type, name


def _type_to_resource(raw_type: str, name: str) -> str:
    """``aws:ec2/instance:Instance`` + ``web`` -> ``aws/ec2/instance/web``.

    Pulumi types end with a CamelCase token that usually repeats the module's
    last segment (``ec2/instance:Instance``); collapsing it keeps resource
    globs short (``aws/ec2/instance/*``) and consistent with the terraform
    and cloud-CLI parsers.
    """
    segments = [seg for seg in raw_type.lower().replace(":", "/").split("/") if seg]
    if len(segments) >= 2 and segments[-1] == segments[-2]:
        segments.pop()
    return "/".join(segments) + f"/{name}"


def _state_field(state: dict[str, Any] | None, key: str) -> Any:
    if not state:
        return None
    if key in state:
        return state[key]
    return (state.get("inputs") or {}).get(key)


def from_pulumi_preview(
    preview_json: dict[str, Any],
    *,
    include_noop: bool = False,
    include_reads: bool = False,
) -> list[InfrastructureIntent]:
    """Parses ``pulumi preview --json`` (``{"steps": [...]}``) into one
    InfrastructureIntent per step, provider ``"pulumi"``.

    ``op: "same"`` steps are skipped unless ``include_noop=True`` (they
    aren't a proposed change). ``op: "read"``/``"refresh"`` steps are
    skipped unless ``include_reads=True`` for the same reason data-source
    reads are skipped in the terraform parser.
    """
    intents = []
    for step in preview_json.get("steps", []):
        op = step.get("op")
        action = _OP_ACTION.get(op)
        if action is None:
            raise ValueError(f"unsupported pulumi step op: {op!r}")

        if action == "no-op" and not include_noop:
            continue
        if op in _READ_OPS and not include_reads:
            continue

        stack, project, raw_type, name = _parse_urn(step["urn"])
        resource = _type_to_resource(raw_type, name)

        old_state = step.get("oldState")
        new_state = step.get("newState")

        metadata: dict[str, Any] = {
            "stack": stack,
            "project": project,
            "type": raw_type,
            "provider_name": raw_type.split(":", 1)[0],
        }
        region = _state_field(new_state, "region") or _state_field(old_state, "region")
        if region is not None:
            metadata["region"] = region

        params: dict[str, Any] = {"raw_action": op}
        if op == "import":
            params["import"] = True
        tags = _state_field(new_state, "tags") or _state_field(old_state, "tags")
        if tags is not None:
            params["tags"] = tags
        if step.get("replaceReasons") or step.get("diffReasons"):
            params["forced_replacement"] = True

        intents.append(
            InfrastructureIntent(
                resource=resource,
                action=action,
                provider="pulumi",
                params=params,
                metadata=metadata,
            )
        )
    return intents


def from_pulumi_argv(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``pulumi`` CLI invocation into a single, stack-scoped
    InfrastructureIntent -- used when no ``pulumi preview --json`` output is
    available to gate the invocation itself.

    ``pulumi up`` -> resource ``stack/<stack>``, action ``update``
    ``pulumi destroy`` -> action ``delete``
    ``pulumi stack rm`` -> action ``delete``
    ``pulumi preview`` -> action ``read``, ``params["dry_run"] = True``
    ``pulumi refresh`` -> action ``read``
    ``pulumi import`` -> action ``create``, ``params["import"] = True``
    """
    if not argv or _basename(argv[0]) != "pulumi":
        raise ValueError(f"not a recognizable pulumi invocation: {argv!r}")

    tokens = argv[1:]
    stack: str | None = None
    params: dict[str, Any] = {}
    positional: list[str] = []

    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in ("-s", "--stack"):
            i += 1
            stack = tokens[i]
        elif tok.startswith("--stack="):
            stack = tok.split("=", 1)[1]
        elif tok in ("-y", "--yes"):
            params["yes"] = True
        elif tok == "--skip-preview":
            params["skip_preview"] = True
        elif tok in ("-f", "--force"):
            params["force"] = True
        elif tok.startswith("-") and tok != "-":
            pass
        else:
            positional.append(tok)
        i += 1

    if not positional:
        raise ValueError(f"could not find a pulumi command in: {argv!r}")

    cmd, rest = positional[0], positional[1:]
    params["raw_action"] = cmd

    if cmd == "up":
        action = "update"
    elif cmd == "destroy":
        action = "delete"
    elif cmd == "refresh":
        action = "read"
    elif cmd == "preview":
        action = "read"
        params["dry_run"] = True
    elif cmd == "import":
        action = "create"
        params["import"] = True
    elif cmd == "stack" and rest and rest[0] == "rm":
        action = "delete"
        params["raw_action"] = "stack rm"
    else:
        raise ValueError(f"unsupported pulumi invocation: {argv!r}")

    resource = f"stack/{stack or '*'}"
    metadata = {"stack": stack} if stack else {}
    return InfrastructureIntent(
        resource=resource, action=action, provider="pulumi", params=params, metadata=metadata
    )
