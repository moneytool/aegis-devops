"""Turns raw kubectl argv and terraform plan JSON into structured
InfrastructureIntents."""

from typing import Any

from aegis_core.intent import InfrastructureIntent

_TERRAFORM_ACTION_MAP = {
    ("no-op",): "no-op",
    ("create",): "create",
    ("delete",): "delete",
    ("update",): "update",
    ("create", "delete"): "replace",
    ("delete", "create"): "replace",
}


def _coerce(value: str) -> Any:
    """Best-effort numeric coercion for CLI flag values."""
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def from_kubectl(argv: list[str]) -> InfrastructureIntent:
    """Parses a kubectl invocation, e.g.:

    ``kubectl scale deployment/x --replicas=5 -n prod``
      -> resource "deployment/x", action "scale",
         params {"replicas": 5}, metadata {"namespace": "prod"}

    ``kubectl delete pod/x``
      -> resource "pod/x", action "delete", params {}, metadata {}
    """
    if len(argv) < 3 or argv[0] != "kubectl":
        raise ValueError(f"not a recognizable kubectl invocation: {argv!r}")

    action = argv[1]
    resource = None
    params: dict[str, Any] = {}
    metadata: dict[str, Any] = {}

    i = 2
    while i < len(argv):
        token = argv[i]
        if token in ("-n", "--namespace"):
            i += 1
            metadata["namespace"] = argv[i]
        elif token.startswith("--"):
            key, sep, value = token[2:].partition("=")
            if not sep:
                i += 1
                value = argv[i]
            params[key] = _coerce(value)
        elif token.startswith("-"):
            # Unrecognized short flag; ignore for this stub parser.
            pass
        elif resource is None:
            resource = token
        i += 1

    if resource is None:
        raise ValueError(f"could not find a target resource in: {argv!r}")

    return InfrastructureIntent(
        resource=resource,
        action=action,
        provider="kubernetes",
        params=params,
        metadata=metadata,
    )


def from_terraform_plan(plan_json: dict[str, Any]) -> list[InfrastructureIntent]:
    """Parses a ``terraform show -json <plan>`` document into one
    InfrastructureIntent per ``resource_changes[]`` entry."""
    intents = []
    for change in plan_json.get("resource_changes", []):
        actions = tuple(change.get("change", {}).get("actions", []))
        action = _TERRAFORM_ACTION_MAP.get(actions)
        if action is None:
            raise ValueError(f"unsupported terraform change actions: {actions!r}")
        intents.append(
            InfrastructureIntent(
                resource=change["address"],
                action=action,
                provider="terraform",
                params={},
                metadata={},
            )
        )
    return intents
