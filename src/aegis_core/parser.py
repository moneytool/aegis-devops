"""Turns raw kubectl argv and terraform plan JSON into structured
InfrastructureIntents."""

from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent

_TERRAFORM_ACTION_MAP = {
    ("no-op",): "no-op",
    ("create",): "create",
    ("delete",): "delete",
    ("update",): "update",
    ("read",): "read",
    ("forget",): "forget",
    ("create", "delete"): "replace",
    ("delete", "create"): "replace",
}

# Common plural/short kubectl resource names, normalised to their canonical
# singular form.
_RESOURCE_ALIASES = {
    "deploy": "deployment",
    "deployments": "deployment",
    "po": "pod",
    "pods": "pod",
    "svc": "service",
    "services": "service",
    "no": "node",
    "nodes": "node",
    "ns": "namespace",
    "namespaces": "namespace",
    "cm": "configmap",
    "configmaps": "configmap",
    "sts": "statefulset",
    "statefulsets": "statefulset",
    "ds": "daemonset",
    "daemonsets": "daemonset",
    "secrets": "secret",
    "pvc": "persistentvolumeclaim",
    "persistentvolumeclaims": "persistentvolumeclaim",
    "ing": "ingress",
    "ingresses": "ingress",
    "sa": "serviceaccount",
    "serviceaccounts": "serviceaccount",
    "rs": "replicaset",
    "replicasets": "replicaset",
    "jobs": "job",
    "cronjobs": "cronjob",
    "hpa": "horizontalpodautoscaler",
}

# kubectl flags that are booleans (no value token follows) when given
# without "=value".
_KNOWN_BOOL_FLAGS = {"force", "cascade", "all", "dry-run", "wait", "now", "ignore-not-found"}

# Global flags whose value is consumed but not recorded anywhere.
_DISCARD_VALUE_FLAGS = {"kubeconfig", "o", "output", "server"}

# Flags that point at a manifest (file or kustomize directory).
_MANIFEST_FLAGS = {"f", "filename", "k", "kustomize"}

# Verbs whose "resource" is just the literal first positional token (a pod
# name, a path, ...), not a kind/name pair to be normalised.
_LITERAL_RESOURCE_VERBS = {"exec", "logs", "port-forward", "cp"}


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


def _split_flag(token: str) -> tuple[str, str | None]:
    body = token[2:] if token.startswith("--") else token[1:]
    key, sep, value = body.partition("=")
    return key, (value if sep else None)


def _split_resource_token(token: str) -> tuple[str, str | None]:
    if "/" in token:
        kind, name = token.split("/", 1)
    else:
        kind, name = token, None
    kind = kind.split(".", 1)[0]  # strip an API group suffix, e.g. "deployment.apps"
    kind = kind.lower()  # kinds are case-insensitive in kubectl; patterns are lower-case
    kind = _RESOURCE_ALIASES.get(kind, kind)
    return kind, name


def _parse_resources(positional: list[str]) -> list[str]:
    """Turns a list of positional kubectl tokens into one or more
    ``kind/name`` resource identifiers. A kind with no name (``kubectl get
    pods``) targets every object of that kind, so it becomes ``kind/*`` and
    matches ``kind/*`` constraint patterns."""
    if not positional:
        return []
    if any("/" in t for t in positional):
        resources = []
        for t in positional:
            kind, name = _split_resource_token(t)
            resources.append(f"{kind}/{name}" if name is not None else f"{kind}/*")
        return resources
    kind, _ = _split_resource_token(positional[0])
    if len(positional) == 1:
        return [f"{kind}/*"]
    return [f"{kind}/{name}" for name in positional[1:]]


def _parse_flags(
    tokens: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str] | None]:
    """Walks kubectl tokens (after the verb/subverb), splitting them into
    metadata, params, positional args, an optional manifest file/dir value,
    and an optional trailing ``--`` command."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    manifest_value: str | None = None
    command: list[str] | None = None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            command = tokens[i + 1 :]
            break
        if tok.startswith("-") and tok != "-":
            is_long = tok.startswith("--")
            key, val = _split_flag(tok)
            if key in ("n", "namespace"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["namespace"] = val
            elif key in ("A", "all-namespaces"):
                metadata["all_namespaces"] = True
            elif key == "context":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["context"] = val
            elif key == "cluster":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["cluster"] = val
            elif key in _MANIFEST_FLAGS:
                if val is None:
                    i += 1
                    val = tokens[i]
                manifest_value = val
            elif key in _DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = tokens[i]
            elif val is None and key in _KNOWN_BOOL_FLAGS:
                params[key] = True
            elif val is not None:
                params[key] = _coerce(val)
            elif is_long:
                # Unknown long flag with no "=value": treat the next token
                # as its value.
                i += 1
                params[key] = _coerce(tokens[i])
            # else: unrecognised bare short flag -- ignored.
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional, manifest_value, command


def _make_intents(
    resources: list[str],
    action: str,
    params: dict[str, Any],
    metadata: dict[str, Any],
) -> list[InfrastructureIntent]:
    return [
        InfrastructureIntent(
            resource=r,
            action=action,
            provider="kubernetes",
            params=dict(params),
            metadata=dict(metadata),
        )
        for r in resources
    ]


def from_kubectl_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a kubectl invocation into one InfrastructureIntent per target
    resource (kubectl commands may name more than one, e.g.
    ``kubectl delete pod/a pod/b``)."""
    if len(argv) < 2 or not (argv[0] == "kubectl" or argv[0].endswith("/kubectl")):
        raise ValueError(f"not a recognizable kubectl invocation: {argv!r}")

    verb = argv[1]
    tokens = argv[2:]

    subverb = None
    if verb == "rollout":
        if not tokens:
            raise ValueError(f"kubectl rollout requires a subcommand: {argv!r}")
        subverb, *tokens = tokens
    elif verb == "set":
        if not tokens or tokens[0] != "image":
            raise ValueError(f"unsupported 'kubectl set' invocation: {argv!r}")
        tokens = tokens[1:]

    metadata, params, positional, manifest_value, command = _parse_flags(tokens)
    if command is not None:
        params["command"] = command

    if manifest_value is not None and verb in ("apply", "create", "replace", "delete"):
        basename = manifest_value if manifest_value == "-" else Path(manifest_value).name
        params = {**params, "file": manifest_value}
        return _make_intents([f"manifest/{basename}"], verb, params, metadata)

    if verb == "rollout":
        resources = _parse_resources(positional)
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _make_intents(resources, f"rollout-{subverb}", params, metadata)

    if verb in _LITERAL_RESOURCE_VERBS:
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _make_intents([positional[0]], verb, params, metadata)

    if verb in ("label", "annotate"):
        resource_tokens = [t for t in positional if "=" not in t]
        kv_tokens = [t for t in positional if "=" in t]
        resources = _parse_resources(resource_tokens)
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        key = "labels" if verb == "label" else "annotations"
        params[key] = {k: v for k, _, v in (t.partition("=") for t in kv_tokens)}
        return _make_intents(resources, verb, params, metadata)

    if verb == "set":  # "set image"
        resource_tokens = [t for t in positional if "=" not in t]
        kv_tokens = [t for t in positional if "=" in t]
        resources = _parse_resources(resource_tokens)
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        params["images"] = {k: v for k, _, v in (t.partition("=") for t in kv_tokens)}
        return _make_intents(resources, "set-image", params, metadata)

    # get, describe, delete, scale, patch, cordon, drain, taint, expose, ...
    resources = _parse_resources(positional)
    if not resources:
        raise ValueError(f"could not find a target resource in: {argv!r}")
    return _make_intents(resources, verb, params, metadata)


def from_kubectl(argv: list[str]) -> InfrastructureIntent:
    """Parses a kubectl invocation that targets exactly one resource, e.g.:

    ``kubectl scale deployment/x --replicas=5 -n prod``
      -> resource "deployment/x", action "scale",
         params {"replicas": 5}, metadata {"namespace": "prod"}

    ``kubectl delete pod/x``
      -> resource "pod/x", action "delete", params {}, metadata {}

    Raises ValueError if the argv names more than one resource; use
    :func:`from_kubectl_multi` for that case.
    """
    intents = from_kubectl_multi(argv)
    if len(intents) != 1:
        raise ValueError(
            f"expected exactly one target resource, found {len(intents)}: {argv!r}"
        )
    return intents[0]


def _provider_short_name(provider_name: str) -> str:
    """``registry.terraform.io/hashicorp/aws`` -> ``aws``."""
    return provider_name.rsplit("/", 1)[-1]


def _region_from_provider_config(plan_json: dict[str, Any], provider_short: str) -> Any:
    provider_configs = plan_json.get("configuration", {}).get("provider_config", {})
    for key, cfg in provider_configs.items():
        if key == provider_short or key.startswith(f"{provider_short}."):
            region = cfg.get("expressions", {}).get("region", {}).get("constant_value")
            if region is not None:
                return region
    return None


def from_terraform_plan(
    plan_json: dict[str, Any], *, include_data: bool = False
) -> list[InfrastructureIntent]:
    """Parses a ``terraform show -json <plan>`` document into one
    InfrastructureIntent per ``resource_changes[]`` entry.

    Data-source entries whose action is "read" are skipped by default (they
    aren't a proposed change to infrastructure) unless ``include_data`` is
    True.
    """
    intents = []
    for change in plan_json.get("resource_changes", []):
        actions = tuple(change.get("change", {}).get("actions", []))
        action = _TERRAFORM_ACTION_MAP.get(actions)
        if action is None:
            raise ValueError(f"unsupported terraform change actions: {actions!r}")

        mode = change.get("mode")
        if mode == "data" and action == "read" and not include_data:
            continue

        metadata: dict[str, Any] = {}
        if "type" in change:
            metadata["type"] = change["type"]
        if "name" in change:
            metadata["name"] = change["name"]
        if mode is not None:
            metadata["mode"] = mode
        provider_name = change.get("provider_name")
        if provider_name:
            metadata["provider_name"] = _provider_short_name(provider_name)
        module_address = change.get("module_address")
        if module_address:
            metadata["module_address"] = module_address

        params: dict[str, Any] = {}
        if action in ("delete", "replace", "update"):
            before = change.get("change", {}).get("before") or {}
            after = change.get("change", {}).get("after") or {}
            region = before.get("region") or after.get("region")
            if region is None and provider_name:
                region = _region_from_provider_config(
                    plan_json, _provider_short_name(provider_name)
                )
            if region is not None:
                params["region"] = region
            tags = before.get("tags") or after.get("tags")
            if tags is not None:
                params["tags"] = tags
            if change.get("change", {}).get("replace_paths"):
                params["forced_replacement"] = True

        intents.append(
            InfrastructureIntent(
                resource=change["address"],
                action=action,
                provider="terraform",
                params=params,
                metadata=metadata,
            )
        )
    return intents
