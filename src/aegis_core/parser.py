"""Turns raw kubectl/aws/az/gcloud/helm/argocd/flux/git/gh argv and
terraform plan JSON into structured InfrastructureIntents."""

from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent

# Shared one-word verb normalisation used by the AWS/Azure/GCP parsers. Each
# cloud parser is also responsible for a handful of compound verbs (e.g.
# gcloud's "set-iam-policy") that aren't covered here.
_VERB_NORMALIZE = {
    "create": "create",
    "delete": "delete",
    "terminate": "delete",
    "remove": "delete",
    "rm": "delete",
    "rb": "delete",
    "purge": "delete",
    "update": "update",
    "modify": "update",
    "set": "update",
    "put": "put",
    "start": "start",
    "stop": "stop",
    "deallocate": "stop",
    "restart": "restart",
    "reboot": "restart",
    "reset": "restart",
    "scale": "scale",
    "resize": "scale",
    "describe": "read",
    "list": "read",
    "get": "read",
    "show": "read",
    "ls": "read",
    "ssh": "read",
    "get-credentials": "read",
    "export": "read",
    "attach": "attach",
    "detach": "detach",
    "cp": "put",
    "sync": "put",
    "mv": "put",
    "mb": "create",
    "import": "put",
    "deploy": "update",
    "upgrade": "update",
    "redeploy": "update",
    "wait": "read",
    # GitOps verb vocabulary (Helm/ArgoCD/Flux/Git/gh). "rollback" used to
    # collapse into "update"; now that Helm/ArgoCD/gcloud all have an
    # explicit rollback action, it's promoted to its own verb.
    "rollback": "rollback",
    # "sync", "push", "rewrite", "run" and "merge" are also part of the
    # shared vocabulary, but each is contextually overloaded (e.g. "sync"
    # already means "put" for `aws s3 sync` / `gsutil sync`, a file copy,
    # not a GitOps reconciliation). The ArgoCD/Flux/Git/gh parsers below
    # assign these verbs directly instead of routing through this table.
}


def _normalize_verb(verb: str) -> str:
    return _VERB_NORMALIZE.get(verb, verb)


def _singularize(word: str) -> str:
    """Best-effort English singularisation for a kubectl/cloud resource
    noun: "instances" -> "instance", "policies" -> "policy"."""
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _basename(path_str: str) -> str:
    return Path(path_str).name

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
_KNOWN_BOOL_FLAGS = {"force", "cascade", "all", "wait", "now", "ignore-not-found"}

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
            elif key == "dry-run":
                # bare --dry-run, --dry-run=client, --dry-run=server are all
                # rehearsals; --dry-run=none is a real run.
                if val is None or val in ("client", "server"):
                    params["dry_run"] = True
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


def _plan_tool(plan_json: dict[str, Any], default: str) -> str:
    """Identifies which tool wrote a plan JSON document.

    OpenTofu emits the same schema as Terraform. Newer OpenTofu versions
    add a top-level ``opentofu`` marker; older ones only differ in the
    version string, so callers pass a ``default`` from the CLI target.
    """
    if plan_json.get("opentofu") or "tofu" in str(plan_json.get("terraform_version", "")):
        return "opentofu"
    return default


def from_terraform_plan(
    plan_json: dict[str, Any], *, include_data: bool = False, tool: str = "terraform"
) -> list[InfrastructureIntent]:
    """Parses a ``terraform show -json <plan>`` (or ``tofu show -json``)
    document into one InfrastructureIntent per ``resource_changes[]`` entry.

    OpenTofu plans use the identical schema, so intents keep
    ``provider="terraform"`` — one constraint governs both tools, since the
    HCL and resource addresses are the same. Which tool produced the plan
    is recorded in ``metadata["tool"]`` (``terraform`` | ``opentofu``);
    ``tool`` is the fallback when the plan itself carries no marker.

    Data-source entries whose action is "read" are skipped by default (they
    aren't a proposed change to infrastructure) unless ``include_data`` is
    True.
    """
    tool = _plan_tool(plan_json, tool)
    intents = []
    for change in plan_json.get("resource_changes", []):
        actions = tuple(change.get("change", {}).get("actions", []))
        action = _TERRAFORM_ACTION_MAP.get(actions)
        if action is None:
            raise ValueError(f"unsupported terraform change actions: {actions!r}")

        mode = change.get("mode")
        if mode == "data" and action == "read" and not include_data:
            continue

        metadata: dict[str, Any] = {"tool": tool}
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


# --- AWS CLI -----------------------------------------------------------------

_AWS_BOOL_FLAGS = {"force", "no-paginate", "no-cli-pager"}
_AWS_DISCARD_VALUE_FLAGS = {"output", "query"}

_AWS_SINGLE_ID_FLAGS = {
    "instance-id",
    "bucket",
    "db-instance-identifier",
    "function-name",
    "cluster",
    "cluster-name",
    "table-name",
    "stack-name",
    "user-name",
    "role-name",
    "group-name",
    "queue-url",
    "topic-arn",
    "key-id",
    "auto-scaling-group-name",
    "load-balancer-arn",
    "repository-name",
    "secret-id",
}

_AWS_S3_VERB_MAP = {
    "rm": "delete",
    "rb": "delete",
    "cp": "put",
    "mv": "put",
    "sync": "put",
    "ls": "read",
    "mb": "create",
}


def _parse_aws_tokens(
    tokens: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str] | None]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    id_value: str | None = None
    multi_ids: list[str] | None = None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key == "region":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["region"] = val
            elif key == "profile":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["profile"] = val
            elif key == "dry-run":
                params["dry_run"] = True
            elif key == "no-dry-run":
                pass  # explicitly a real run; nothing to record
            elif key in _AWS_BOOL_FLAGS:
                params[key] = True if val is None else _coerce(val)
            elif key in _AWS_DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = tokens[i]
                # consumed, intentionally not recorded
            elif key == "cli-input-json":
                if val is None:
                    i += 1
                    val = tokens[i]
                params["cli_input_json"] = val
            elif key == "instance-ids":
                if val is not None:
                    multi_ids = [val]
                else:
                    ids: list[str] = []
                    while i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        ids.append(tokens[i])
                    multi_ids = ids
            elif key in _AWS_SINGLE_ID_FLAGS:
                if val is None:
                    i += 1
                    val = tokens[i]
                id_value = val
            elif val is not None:
                params[key] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key] = _coerce(tokens[i])
            else:
                params[key] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional, id_value, multi_ids


def _aws_resource(service: str, kind: str, name: str | None) -> str:
    return f"{service}/{kind}/{name}" if name else f"{service}/{kind}/*"


def _from_aws_s3(
    operation: str,
    rest: list[str],
    metadata: dict[str, Any],
    params: dict[str, Any],
    argv: list[str],
) -> list[InfrastructureIntent]:
    if operation not in _AWS_S3_VERB_MAP:
        raise ValueError(f"unsupported 'aws s3' subcommand: {argv!r}")
    action = _AWS_S3_VERB_MAP[operation]
    uri = next((t for t in rest if t.startswith("s3://")), None)
    if uri is None:
        raise ValueError(f"could not find an s3:// target in: {argv!r}")
    bucket, _, key = uri[len("s3://") :].partition("/")
    params = dict(params)
    params["raw_action"] = f"s3-{operation}"
    if key:
        params["key"] = key
    resource = f"s3/bucket/{bucket}"
    return [
        InfrastructureIntent(
            resource=resource, action=action, provider="aws", params=params, metadata=metadata
        )
    ]


def from_aws_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``aws`` CLI invocation into one InfrastructureIntent per
    target resource (``--instance-ids`` may name more than one)."""
    if not argv or _basename(argv[0]) != "aws":
        raise ValueError(f"not a recognizable aws invocation: {argv!r}")

    tokens = argv[1:]
    metadata, params, positional, id_value, multi_ids = _parse_aws_tokens(tokens)

    if len(positional) < 2:
        raise ValueError(f"could not determine an aws service/operation in: {argv!r}")

    service, operation, *rest = positional

    if service == "s3":
        return _from_aws_s3(operation, rest, metadata, params, argv)

    if service == "autoscaling" and operation == "set-desired-capacity":
        params = dict(params)
        params["raw_action"] = operation
        if "desired-capacity" in params:
            params["desired_capacity"] = params.pop("desired-capacity")
        resource = _aws_resource("autoscaling", "auto-scaling-group", id_value)
        return [
            InfrastructureIntent(
                resource=resource,
                action="scale",
                provider="aws",
                params=params,
                metadata=metadata,
            )
        ]

    if "-" in operation:
        verb, noun = operation.split("-", 1)
    else:
        verb, noun = operation, None

    action = _normalize_verb(verb)
    params = dict(params)
    params["raw_action"] = operation
    kind = _singularize(noun) if noun else service

    names = multi_ids if multi_ids else [id_value]
    resources = [_aws_resource(service, kind, n) for n in names]
    return [
        InfrastructureIntent(
            resource=r, action=action, provider="aws", params=dict(params), metadata=dict(metadata)
        )
        for r in resources
    ]


def from_aws(argv: list[str]) -> InfrastructureIntent:
    """Parses an ``aws`` CLI invocation that targets exactly one resource.

    Raises ValueError if the argv names more than one resource (e.g. via
    multiple ``--instance-ids``); use :func:`from_aws_multi` for that case.
    """
    intents = from_aws_multi(argv)
    if len(intents) != 1:
        raise ValueError(
            f"expected exactly one target resource, found {len(intents)}: {argv!r}"
        )
    return intents[0]


# --- Azure CLI -----------------------------------------------------------------

_AZ_VERBS = {
    "create",
    "delete",
    "update",
    "show",
    "list",
    "start",
    "stop",
    "restart",
    "deallocate",
    "scale",
    "set",
    "add",
    "remove",
    "deploy",
    "wait",
    "redeploy",
    "resize",
    "purge",
}

_AZ_BOOL_FLAGS = {"yes", "y", "no-wait"}

_AZ_GROUP_MAP = {
    ("vm",): "compute/vm",
    ("vmss",): "compute/vmss",
    ("aks",): "aks/cluster",
    ("storage", "account"): "storage/account",
    ("storage", "container"): "storage/container",
    ("sql", "server"): "sql/server",
    ("sql", "db"): "sql/db",
    ("network", "vnet"): "network/vnet",
    ("network", "nsg"): "network/nsg",
    ("group",): "resource/group",
    ("keyvault",): "keyvault/vault",
    ("webapp",): "web/app",
    ("functionapp",): "web/functionapp",
    ("acr",): "acr/registry",
    ("role", "assignment"): "iam/role-assignment",
    ("ad", "user"): "iam/user",
}


def _parse_az_tokens(
    tokens: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    name_value: str | None = None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("l", "location"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["region"] = val
            elif key == "subscription":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["subscription"] = val
            elif key in ("g", "resource-group"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["resource_group"] = val
            elif key in ("n", "name"):
                if val is None:
                    i += 1
                    val = tokens[i]
                name_value = val
            elif key in ("what-if", "dry-run"):
                params["dry_run"] = True
            elif key in _AZ_BOOL_FLAGS:
                params["yes" if key == "y" else key] = True if val is None else _coerce(val)
            elif val is not None:
                params[key] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key] = _coerce(tokens[i])
            else:
                params[key] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional, name_value


def from_az(argv: list[str]) -> InfrastructureIntent:
    """Parses an ``az`` CLI invocation, e.g.:

    ``az vm start --resource-group rg1 --name vm1``
      -> resource "compute/vm/vm1", action "start"
    """
    if not argv or _basename(argv[0]) != "az":
        raise ValueError(f"not a recognizable az invocation: {argv!r}")

    tokens = argv[1:]
    metadata, params, positional, name_value = _parse_az_tokens(tokens)

    if not positional:
        raise ValueError(f"could not find an az verb in: {argv!r}")

    verb = positional[-1]
    if verb not in _AZ_VERBS:
        raise ValueError(f"unrecognized az verb in: {argv!r}")

    group_words = positional[:-1]
    if not group_words:
        raise ValueError(f"could not determine an az resource group path in: {argv!r}")

    resource_prefix = _AZ_GROUP_MAP.get(tuple(group_words), "/".join(group_words))
    action = _normalize_verb(verb)
    params["raw_action"] = verb
    resource = f"{resource_prefix}/{name_value}" if name_value else f"{resource_prefix}/*"

    return InfrastructureIntent(
        resource=resource, action=action, provider="azure", params=params, metadata=metadata
    )


# --- gcloud / gsutil -----------------------------------------------------------

_GCLOUD_VERBS = {
    "create",
    "delete",
    "update",
    "describe",
    "list",
    "start",
    "stop",
    "reset",
    "resize",
    "set-iam-policy",
    "add-iam-policy-binding",
    "remove-iam-policy-binding",
    "deploy",
    "scale",
    "upgrade",
    "rollback",
    "ssh",
    "get-credentials",
    "import",
    "export",
}

_GCLOUD_IAM_BINDING_VERBS = {
    "set-iam-policy",
    "add-iam-policy-binding",
    "remove-iam-policy-binding",
}

_GCLOUD_GROUP_MAP = {
    ("compute", "instances"): "compute/instance",
    ("compute", "disks"): "compute/disk",
    ("compute", "firewall-rules"): "compute/firewall-rule",
    ("container", "clusters"): "container/cluster",
    ("container", "node-pools"): "container/node-pool",
    ("sql", "instances"): "sql/instance",
    ("storage", "buckets"): "storage/bucket",
    ("functions",): "functions/function",
    ("run", "services"): "run/service",
    ("iam", "service-accounts"): "iam/service-account",
    ("projects",): "project/project",
    ("pubsub", "topics"): "pubsub/topic",
}

_GCS_LEGACY_VERB_MAP = {"rm": "delete", "rb": "delete", "cp": "put"}


def _parse_gcloud_tokens(tokens: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key == "region":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["region"] = val
            elif key == "zone":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["zone"] = val
                metadata["region"] = val
            elif key == "project":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["project"] = val
            elif key in ("quiet", "q"):
                params["quiet"] = True if val is None else _coerce(val)
            elif key == "dry-run":
                if val is None or _coerce(val) not in (False, "false"):
                    params["dry_run"] = True
            elif key == "async":
                params["async"] = True if val is None else _coerce(val)
            elif val is not None:
                params[key] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key] = _coerce(tokens[i])
            else:
                params[key] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def _gcs_uri_intent(
    verb: str,
    uri_candidates: list[str],
    metadata: dict[str, Any],
    params: dict[str, Any],
    argv: list[str],
    raw_prefix: str,
) -> InfrastructureIntent:
    action = _GCS_LEGACY_VERB_MAP[verb]
    uri = next((t for t in uri_candidates if t.startswith("gs://")), None)
    if uri is None:
        raise ValueError(f"could not find a gs:// target in: {argv!r}")
    bucket, _, key = uri[len("gs://") :].partition("/")
    params = dict(params)
    params["raw_action"] = f"{raw_prefix}-{verb}"
    if key:
        params["key"] = key
    resource = f"storage/bucket/{bucket}"
    return InfrastructureIntent(
        resource=resource, action=action, provider="gcp", params=params, metadata=metadata
    )


def _from_gsutil(argv: list[str]) -> InfrastructureIntent:
    tokens = argv[1:]
    metadata, params, positional = _parse_gcloud_tokens(tokens)
    if not positional or positional[0] not in _GCS_LEGACY_VERB_MAP:
        raise ValueError(f"unsupported gsutil invocation: {argv!r}")
    verb = positional[0]
    return _gcs_uri_intent(verb, positional[1:], metadata, params, argv, "gsutil")


def from_gcloud(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``gcloud`` (or legacy ``gsutil``) CLI invocation, e.g.:

    ``gcloud compute instances start web-1 --zone us-central1-a``
      -> resource "compute/instance/web-1", action "start"
    """
    if not argv:
        raise ValueError("empty argv")

    basename = _basename(argv[0])
    if basename == "gsutil":
        return _from_gsutil(argv)
    if basename != "gcloud":
        raise ValueError(f"not a recognizable gcloud invocation: {argv!r}")

    tokens = argv[1:]
    metadata, params, positional = _parse_gcloud_tokens(tokens)

    if positional and positional[0] in ("alpha", "beta"):
        params["release_track"] = positional.pop(0)

    if (
        len(positional) >= 2
        and positional[0] == "storage"
        and positional[1] in _GCS_LEGACY_VERB_MAP
    ):
        return _gcs_uri_intent(positional[1], positional[2:], metadata, params, argv, "storage")

    verb_idx = next((i for i, t in enumerate(positional) if t in _GCLOUD_VERBS), None)
    if verb_idx is None:
        raise ValueError(f"could not find a recognized gcloud verb in: {argv!r}")

    group_words = positional[:verb_idx]
    if not group_words:
        raise ValueError(f"could not determine a gcloud resource group in: {argv!r}")
    verb = positional[verb_idx]
    name_value = positional[verb_idx + 1] if verb_idx + 1 < len(positional) else None

    resource_prefix = _GCLOUD_GROUP_MAP.get(tuple(group_words))
    if resource_prefix is None:
        *head, last = group_words
        resource_prefix = "/".join([*head, _singularize(last)])

    action = "update" if verb in _GCLOUD_IAM_BINDING_VERBS else _normalize_verb(verb)
    params["raw_action"] = verb
    resource = f"{resource_prefix}/{name_value}" if name_value else f"{resource_prefix}/*"

    return InfrastructureIntent(
        resource=resource, action=action, provider="gcp", params=params, metadata=metadata
    )


# --- Helm -----------------------------------------------------------------

_HELM_BOOL_FLAGS = {
    "atomic",
    "wait",
    "create-namespace",
    "force",
    "reuse-values",
    "reset-values",
    "cleanup-on-fail",
    "install",
}

_HELM_READ_VERBS = {"history", "status", "list", "get"}


def _parse_helm_tokens(tokens: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("n", "namespace"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["namespace"] = val
            elif key == "kube-context":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["context"] = val
            elif key == "dry-run":
                if val is None or val != "false":
                    params["dry_run"] = True
            elif key == "version":
                if val is None:
                    i += 1
                    val = tokens[i]
                params["version"] = _coerce(val)
            elif key in ("f", "values"):
                if val is None:
                    i += 1
                    val = tokens[i]
                params.setdefault("values_files", []).append(val)
            elif key == "set":
                if val is None:
                    i += 1
                    val = tokens[i]
                k, _sep, v = val.partition("=")
                params.setdefault("set", {})[k] = _coerce(v)
            elif key in _HELM_BOOL_FLAGS:
                params[key.replace("-", "_")] = True if val is None else _coerce(val)
            elif val is not None:
                params[key.replace("-", "_")] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key.replace("-", "_")] = _coerce(tokens[i])
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def from_helm(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``helm`` invocation, e.g.:

    ``helm upgrade --install api ./chart -n prod --dry-run``
      -> resource "release/api", action "update",
         params {"raw_action": "upgrade", "install": True, "chart": "./chart",
                  "dry_run": True}, metadata {"namespace": "prod"}
    """
    if len(argv) < 2 or _basename(argv[0]) != "helm":
        raise ValueError(f"not a recognizable helm invocation: {argv!r}")

    verb = argv[1]
    tokens = argv[2:]
    metadata, params, positional = _parse_helm_tokens(tokens)
    params["raw_action"] = verb

    if verb == "install":
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        release = positional[0]
        if len(positional) > 1:
            params["chart"] = positional[1]
        return InfrastructureIntent(
            resource=f"release/{release}", action="create", provider="helm",
            params=params, metadata=metadata,
        )

    if verb == "upgrade":
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        release = positional[0]
        if len(positional) > 1:
            params["chart"] = positional[1]
        return InfrastructureIntent(
            resource=f"release/{release}", action="update", provider="helm",
            params=params, metadata=metadata,
        )

    if verb in ("uninstall", "delete"):
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        release = positional[0]
        return InfrastructureIntent(
            resource=f"release/{release}", action="delete", provider="helm",
            params=params, metadata=metadata,
        )

    if verb == "rollback":
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        release = positional[0]
        if len(positional) > 1:
            params["revision"] = _coerce(positional[1])
        return InfrastructureIntent(
            resource=f"release/{release}", action="rollback", provider="helm",
            params=params, metadata=metadata,
        )

    if verb == "template":
        params["dry_run"] = True
        release = positional[0] if positional else "*"
        return InfrastructureIntent(
            resource=f"release/{release}", action="read", provider="helm",
            params=params, metadata=metadata,
        )

    if verb in _HELM_READ_VERBS:
        sub_positional = positional
        if verb == "get" and sub_positional:
            params["get_target"] = sub_positional[0]
            sub_positional = sub_positional[1:]
        release = sub_positional[0] if sub_positional else "*"
        return InfrastructureIntent(
            resource=f"release/{release}", action="read", provider="helm",
            params=params, metadata=metadata,
        )

    raise ValueError(f"unsupported helm subcommand: {argv!r}")


# --- ArgoCD -----------------------------------------------------------------

_ARGOCD_ACTION_MAP = {
    "sync": "sync",
    "delete": "delete",
    "create": "create",
    "set": "update",
    "rollback": "rollback",
    "terminate-op": "stop",
    "get": "read",
    "list": "read",
    "diff": "read",
    "history": "read",
}

_ARGOCD_MULTI_APP_VERBS = {"sync", "delete"}


def _parse_argocd_tokens(tokens: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key == "project":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["project"] = val
            elif key in ("server", "auth-token"):
                if val is None:
                    i += 1
                    val = tokens[i]
                # consumed, intentionally not recorded
            elif key == "grpc-web":
                pass  # consumed, intentionally not recorded
            elif key == "dry-run":
                params["dry_run"] = True
            elif key in ("prune", "force"):
                params[key] = True if val is None else _coerce(val)
            elif val is not None:
                params[key.replace("-", "_")] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key.replace("-", "_")] = _coerce(tokens[i])
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def from_argocd_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``argocd`` invocation into one InfrastructureIntent per
    target app (``argocd app sync`` / ``delete`` may name more than one)."""
    if len(argv) < 2 or _basename(argv[0]) != "argocd":
        raise ValueError(f"not a recognizable argocd invocation: {argv!r}")
    if argv[1] != "app":
        raise ValueError(f"unsupported argocd invocation: {argv!r}")
    if len(argv) < 3:
        raise ValueError(f"argocd app requires a subcommand: {argv!r}")

    subverb = argv[2]
    tokens = argv[3:]

    if subverb == "actions":
        if len(tokens) < 1 or tokens[0] != "run":
            raise ValueError(f"unsupported 'argocd app actions' invocation: {argv!r}")
        metadata, params, positional = _parse_argocd_tokens(tokens[1:])
        if len(positional) < 2:
            raise ValueError(f"could not find an app and action name in: {argv!r}")
        app, action_name = positional[0], positional[1]
        params["raw_action"] = "actions-run"
        params["action_name"] = action_name
        return [
            InfrastructureIntent(
                resource=f"app/{app}", action="update", provider="argocd",
                params=params, metadata=metadata,
            )
        ]

    if subverb not in _ARGOCD_ACTION_MAP:
        raise ValueError(f"unsupported argocd app subcommand: {argv!r}")

    metadata, params, positional = _parse_argocd_tokens(tokens)
    params["raw_action"] = subverb
    action = _ARGOCD_ACTION_MAP[subverb]

    if subverb == "list":
        apps = positional if positional else ["*"]
    elif subverb == "rollback":
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]
        if len(positional) > 1:
            params["revision"] = _coerce(positional[1])
    elif subverb in _ARGOCD_MULTI_APP_VERBS:
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = positional
    else:
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]

    return [
        InfrastructureIntent(
            resource=f"app/{app}", action=action, provider="argocd",
            params=dict(params), metadata=dict(metadata),
        )
        for app in apps
    ]


def from_argocd(argv: list[str]) -> InfrastructureIntent:
    """Parses an ``argocd`` invocation that targets exactly one app.

    Raises ValueError if the argv names more than one app; use
    :func:`from_argocd_multi` for that case.
    """
    intents = from_argocd_multi(argv)
    if len(intents) != 1:
        raise ValueError(
            f"expected exactly one target app, found {len(intents)}: {argv!r}"
        )
    return intents[0]


# --- Flux -----------------------------------------------------------------

_FLUX_VERB_ACTION = {
    "reconcile": "sync",
    "suspend": "stop",
    "resume": "start",
    "delete": "delete",
    "create": "create",
}

_FLUX_READ_VERBS = {"get", "logs", "export"}

_FLUX_KIND_ALIASES = {
    "kustomization": "kustomization",
    "kustomizations": "kustomization",
    "ks": "kustomization",
    "helmrelease": "helmrelease",
    "helmreleases": "helmrelease",
    "hr": "helmrelease",
}


def _parse_flux_tokens(tokens: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("n", "namespace"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["namespace"] = val
            elif key == "context":
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["context"] = val
            elif key == "dry-run":
                params["dry_run"] = True
            elif key == "export":
                params["dry_run"] = True
                params["export"] = True
            elif val is not None:
                params[key.replace("-", "_")] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key.replace("-", "_")] = _coerce(tokens[i])
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def _flux_kind_and_name(positional: list[str]) -> tuple[str, str]:
    """Turns the positional tokens following a flux verb into
    ``(kind, name)``, e.g. ``["source", "git", "podinfo"]`` ->
    ``("source-git", "podinfo")``, ``["kustomization", "podinfo"]`` ->
    ``("kustomization", "podinfo")``."""
    if not positional:
        raise ValueError("missing flux resource kind/name")
    head = positional[0]
    if head == "source":
        if len(positional) < 3:
            raise ValueError("missing flux source subkind/name")
        return f"source-{positional[1]}", positional[2]
    kind = _FLUX_KIND_ALIASES.get(head, head)
    if len(positional) < 2:
        raise ValueError("missing flux resource name")
    return kind, positional[1]


def from_flux(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``flux`` invocation, e.g.:

    ``flux reconcile source git podinfo -n flux-system``
      -> resource "source-git/podinfo", action "sync", metadata {"namespace": "flux-system"}
    ``flux suspend kustomization podinfo``
      -> resource "kustomization/podinfo", action "stop"
    """
    if len(argv) < 2 or _basename(argv[0]) != "flux":
        raise ValueError(f"not a recognizable flux invocation: {argv!r}")

    verb = argv[1]
    tokens = argv[2:]
    metadata, params, positional = _parse_flux_tokens(tokens)
    params["raw_action"] = verb

    if verb == "bootstrap":
        provider_name = positional[0] if positional else "*"
        return InfrastructureIntent(
            resource=f"bootstrap/{provider_name}", action="create", provider="flux",
            params=params, metadata=metadata,
        )

    if verb in _FLUX_VERB_ACTION:
        kind, name = _flux_kind_and_name(positional)
        return InfrastructureIntent(
            resource=f"{kind}/{name}", action=_FLUX_VERB_ACTION[verb], provider="flux",
            params=params, metadata=metadata,
        )

    if verb in _FLUX_READ_VERBS:
        if verb == "export":
            # "flux export ..." dumps resource YAML; it's read-only and
            # never touches the cluster, same as a dry-run.
            params["dry_run"] = True
        if positional:
            try:
                kind, name = _flux_kind_and_name(positional)
                resource = f"{kind}/{name}"
            except ValueError:
                kind = _FLUX_KIND_ALIASES.get(positional[0], positional[0])
                resource = f"{kind}/*"
        else:
            resource = "*/*"
        return InfrastructureIntent(
            resource=resource, action="read", provider="flux",
            params=params, metadata=metadata,
        )

    raise ValueError(f"unsupported flux subcommand: {argv!r}")


# --- Git -----------------------------------------------------------------


def _parse_git_tokens(tokens: list[str]) -> tuple[dict[str, Any], list[str]]:
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("force", "f"):
                params["force"] = True
            elif key == "force-with-lease":
                params["force"] = True
                params["force_with_lease"] = True
            elif key in ("delete", "d", "D"):
                params["delete"] = True
            elif key == "tags":
                params["tags"] = True
            elif key == "hard":
                params["hard"] = True
            elif key == "amend":
                params["amend"] = True
            elif val is not None:
                params[key.replace("-", "_")] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key.replace("-", "_")] = _coerce(tokens[i])
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    return params, positional


def _from_git_push(
    positional: list[str], params: dict[str, Any], metadata: dict[str, Any]
) -> InfrastructureIntent:
    remote = positional[0] if positional else None
    refspec = positional[1] if len(positional) > 1 else None
    if remote is not None:
        metadata = {**metadata, "remote": remote}

    delete = bool(params.get("delete"))
    force = bool(params.get("force"))
    ref = None

    if refspec:
        spec = refspec
        if spec.startswith("+"):
            force = True
            spec = spec[1:]
        if spec.startswith(":"):
            delete = True
            ref = spec[1:]
        elif ":" in spec:
            _src, _sep, dst = spec.partition(":")
            ref = dst
        else:
            ref = spec
        if ref.startswith("refs/heads/"):
            ref = ref[len("refs/heads/") :]
        elif ref.startswith("refs/tags/"):
            ref = ref[len("refs/tags/") :]

    params = dict(params)
    if force:
        params["force"] = True
    if delete:
        params["delete"] = True

    resource = f"ref/{ref}" if ref else "ref/*"
    action = "delete" if delete else "push"
    return InfrastructureIntent(
        resource=resource, action=action, provider="git", params=params, metadata=metadata
    )


def from_git(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``git`` invocation. Only remote-affecting or history-rewriting
    commands produce non-read intents; local reads are ``read``, e.g.:

    ``git push -f origin HEAD:main``
      -> resource "ref/main", action "push", params {"force": True}, metadata {"remote": "origin"}
    ``git rebase main``
      -> resource "history/main", action "rewrite"
    """
    if len(argv) < 2 or _basename(argv[0]) != "git":
        raise ValueError(f"not a recognizable git invocation: {argv!r}")

    verb = argv[1]
    tokens = argv[2:]
    params, positional = _parse_git_tokens(tokens)
    metadata: dict[str, Any] = {}
    params["raw_action"] = verb

    if verb == "push":
        return _from_git_push(positional, params, metadata)

    if verb == "branch":
        if params.get("delete"):
            if not positional:
                raise ValueError(f"could not find a branch name in: {argv!r}")
            return InfrastructureIntent(
                resource=f"branch/{positional[0]}", action="delete", provider="git",
                params=params, metadata=metadata,
            )
        return InfrastructureIntent(
            resource=f"branch/{positional[0] if positional else '*'}", action="read",
            provider="git", params=params, metadata=metadata,
        )

    if verb == "tag":
        if params.get("delete"):
            if not positional:
                raise ValueError(f"could not find a tag name in: {argv!r}")
            return InfrastructureIntent(
                resource=f"tag/{positional[0]}", action="delete", provider="git",
                params=params, metadata=metadata,
            )
        return InfrastructureIntent(
            resource=f"tag/{positional[0] if positional else '*'}", action="read",
            provider="git", params=params, metadata=metadata,
        )

    if verb == "rebase":
        target = positional[0] if positional else "HEAD"
        return InfrastructureIntent(
            resource=f"history/{target}", action="rewrite", provider="git",
            params=params, metadata=metadata,
        )

    if verb == "reset" and params.get("hard"):
        target = positional[0] if positional else "HEAD"
        return InfrastructureIntent(
            resource=f"history/{target}", action="rewrite", provider="git",
            params=params, metadata=metadata,
        )

    if verb == "commit" and params.get("amend"):
        return InfrastructureIntent(
            resource="history/HEAD", action="rewrite", provider="git",
            params=params, metadata=metadata,
        )

    if verb in ("filter-branch", "filter-repo"):
        target = positional[0] if positional else "HEAD"
        return InfrastructureIntent(
            resource=f"history/{target}", action="rewrite", provider="git",
            params=params, metadata=metadata,
        )

    # checkout, switch, log, status, diff, fetch, pull, commit (no --amend),
    # add, show, reset (no --hard), ... -- local/read-ish, nothing to gate.
    return InfrastructureIntent(
        resource="history/*", action="read", provider="git", params=params, metadata=metadata
    )


# --- GitHub CLI (gh) -------------------------------------------------------

_GH_METHOD_ACTION = {
    "GET": "read",
    "DELETE": "delete",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
}


def _parse_gh_tokens(tokens: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("R", "repo"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["repo"] = val
            elif key in ("r", "ref"):
                if val is None:
                    i += 1
                    val = tokens[i]
                metadata["ref"] = val
            elif key in ("f", "field", "raw-field"):
                if val is None:
                    i += 1
                    val = tokens[i]
                k, _sep, v = val.partition("=")
                params.setdefault("inputs", {})[k] = _coerce(v)
            elif key == "admin":
                params["admin"] = True if val is None else _coerce(val)
            elif key in ("squash", "merge", "rebase") and val is None:
                params["method"] = key
            elif key == "delete-branch":
                params["delete_branch"] = True
            elif key in ("X", "method"):
                if val is None:
                    i += 1
                    val = tokens[i]
                params["_method"] = val.upper()
            elif val is not None:
                params[key.replace("-", "_")] = _coerce(val)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                params[key.replace("-", "_")] = _coerce(tokens[i])
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def from_gh(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``gh`` (GitHub CLI) invocation, e.g.:

    ``gh pr merge 42 --admin --squash``
      -> resource "pr/42", action "merge", params {"admin": True, "method": "squash"}
    """
    if len(argv) < 2 or _basename(argv[0]) != "gh":
        raise ValueError(f"not a recognizable gh invocation: {argv!r}")

    group = argv[1]
    tokens = argv[2:]

    if group == "workflow":
        if not tokens:
            raise ValueError(f"gh workflow requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        if subverb == "run":
            if not positional:
                raise ValueError(f"could not find a workflow name in: {argv!r}")
            params["raw_action"] = "workflow-run"
            return InfrastructureIntent(
                resource=f"workflow/{positional[0]}", action="run", provider="github",
                params=params, metadata=metadata,
            )
        params["raw_action"] = f"workflow-{subverb}"
        name = positional[0] if positional else "*"
        return InfrastructureIntent(
            resource=f"workflow/{name}", action="read", provider="github",
            params=params, metadata=metadata,
        )

    if group == "release":
        if not tokens:
            raise ValueError(f"gh release requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        params["raw_action"] = f"release-{subverb}"
        tag = positional[0] if positional else "*"
        action = {"create": "create", "delete": "delete"}.get(subverb, "read")
        return InfrastructureIntent(
            resource=f"release/{tag}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "pr":
        if not tokens:
            raise ValueError(f"gh pr requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        params["raw_action"] = f"pr-{subverb}"
        number = positional[0] if positional else "*"
        action = {"merge": "merge", "close": "stop"}.get(subverb, "read")
        return InfrastructureIntent(
            resource=f"pr/{number}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "repo":
        if not tokens:
            raise ValueError(f"gh repo requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        params["raw_action"] = f"repo-{subverb}"
        name = positional[0] if positional else "*"
        action = "delete" if subverb == "delete" else "read"
        return InfrastructureIntent(
            resource=f"repo/{name}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "secret":
        if not tokens:
            raise ValueError(f"gh secret requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        params["raw_action"] = f"secret-{subverb}"
        name = positional[0] if positional else "*"
        action = {"set": "put", "delete": "delete"}.get(subverb, "read")
        return InfrastructureIntent(
            resource=f"secret/{name}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "variable":
        if not tokens:
            raise ValueError(f"gh variable requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest)
        params["raw_action"] = f"variable-{subverb}"
        name = positional[0] if positional else "*"
        action = "put" if subverb == "set" else "read"
        return InfrastructureIntent(
            resource=f"variable/{name}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "api":
        metadata, params, positional = _parse_gh_tokens(tokens)
        method = params.pop("_method", "GET")
        action = _GH_METHOD_ACTION.get(method, "read")
        params["raw_action"] = f"api-{method.lower()}"
        path = positional[0] if positional else "*"
        return InfrastructureIntent(
            resource=f"api/{path}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    # pr/repo view|list, issue, gist, auth, ... -- everything else is a read.
    metadata, params, positional = _parse_gh_tokens(tokens)
    params["raw_action"] = group
    target = positional[0] if positional else "*"
    return InfrastructureIntent(
        resource=f"{group}/{target}", action="read", provider="github",
        params=params, metadata=metadata,
    )


# --- generic dispatcher --------------------------------------------------------


_MIGRATION_TOOLS = {"alembic", "flyway", "rails", "prisma"}


def from_argv(argv: list[str]) -> list[InfrastructureIntent]:
    """Dispatches a raw argv to the right parser based on ``basename(argv[0])``,
    always returning a list of InfrastructureIntents (even for the
    single-intent parsers)."""
    if not argv:
        raise ValueError("empty argv")

    name = _basename(argv[0])
    if name == "kubectl":
        return from_kubectl_multi(argv)
    if name in ("terraform", "tofu"):
        raise ValueError(
            f"{name} invocations need a '{name} show -json' plan; "
            "use from_terraform_plan(plan_json) directly instead of from_argv"
        )
    if name == "aws":
        return from_aws_multi(argv)
    if name == "az":
        return [from_az(argv)]
    if name in ("gcloud", "gsutil"):
        return [from_gcloud(argv)]
    if name == "helm":
        return [from_helm(argv)]
    if name == "argocd":
        return from_argocd_multi(argv)
    if name == "flux":
        return [from_flux(argv)]
    if name == "git":
        return [from_git(argv)]
    if name == "gh":
        return [from_gh(argv)]
    if name in ("psql", "mysql", "sqlite3", "mongosh", "pulumi") or name in _MIGRATION_TOOLS:
        # Imported lazily: parsers/ depends on this module for shared helpers.
        from aegis_core.parsers import pulumi as _pulumi
        from aegis_core.parsers import sql as _sql

        dispatch = {
            "psql": _sql.from_psql,
            "mysql": _sql.from_mysql,
            "sqlite3": _sql.from_sqlite3,
            "mongosh": _sql.from_mongosh,
            "pulumi": lambda a: [_pulumi.from_pulumi_argv(a)],
        }
        fn = dispatch.get(name, _sql.from_migration_argv)
        return fn(argv)

    raise ValueError(f"unsupported CLI invocation: {argv!r}")
