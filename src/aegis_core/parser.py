"""Turns raw kubectl/aws/az/gcloud/helm/argocd/flux/git/gh argv and
terraform plan JSON into structured InfrastructureIntents.

**Global options before the verb.** Every argv parser first consumes the
tool's *global* options (``kubectl -n prod delete ...``, ``git -C /repo
push ...``, ``helm --kube-context prod uninstall ...``) before it selects
the verb, so a flag placed in front of the verb yields exactly the same
intent as the same flag placed after it. Flags that carry environment
identity (namespace / context / cluster / repo) land in ``metadata`` in
both positions. A leading option the parser does not recognise is a
``ValueError`` (fail closed) rather than a guess at where the verb starts,
and the token finally chosen as the verb must not start with ``-``.

**Glued short flags.** kubectl's ``-nprod`` / ``-lapp=web`` / ``-fx.yaml``
/ ``-ojson`` / ``-k./dir`` and helm/flux's ``-nprod`` are expanded to their
two-token form before parsing; ``-n=prod`` keeps working too.

**Selectors, comma-separated kinds.** ``-l/--selector`` and
``--field-selector`` are value flags recorded in ``params["selector"]`` /
``params["field_selector"]``; the resource is then ``kind/*`` (every
object the selector may match). ``kubectl delete nodes,pods`` yields one
intent per kind; naming objects alongside a multi-kind list is rejected
(kubectl rejects it too).

**Namespace deletion cascade.** ``kubectl delete namespace/<ns>`` (in any
form: ``namespace <ns>``, ``ns/<ns>``, ``namespaces <ns>``) deletes every
object inside the namespace, so besides the ``namespace/<ns>`` intent the
parser also emits a synthetic intent ``resource="*/*"``,
``action="delete"``, ``metadata["namespace"]=<ns>``,
``params["cascade_from"]="namespace/<ns>"`` — this is what lets a
``scope: {namespace: prod}`` deletion rule fire on the namespace deletion
itself. Only named namespaces cascade; ``namespace/*`` (``--all``, a
selector) does not, because there is no single namespace to scope on.

**Boolean flags and dry runs (REVIEW-4 T1.5).** Every parser routes its
known boolean flags through :func:`_coerce_bool`, so ``--prune=true`` is
``True`` and ``--prune=false`` is ``False`` — never the strings ``"true"`` /
``"false"``. ``params["dry_run"]`` is set *only* when the flag is bare or
truthy (``--dry-run``, ``--dry-run=true``, kubectl/helm ``=client`` /
``=server``); ``--dry-run=false`` / ``=none`` / ``=0`` leave the key
absent, so a "real run" rule fires.

**Provider-namespace aliases (REVIEW-4 T1.7).** ``aws s3api`` / ``s3control``
collapse to service ``s3``; ``az ... --ids <ARM path>`` is parsed into the
same ``<service>/<kind>/<name>`` form as the named-flag invocation; ``gh
api`` REST paths for workflow dispatch, releases, repo deletion, secrets
and branch protection map to the same resources as the porcelain
commands; ``git push`` without a refspec is marked
``params["unknown_target"]=True`` so the caller can escalate.

**Terraform / Pulumi plans (REVIEW-4 T1.6).** Every plan intent carries
``metadata["plan_sha256"]`` (:func:`plan_digest` of the JSON that was
checked) and ``metadata["type_name"]`` — the module-stripped
``<type>.<name>`` for terraform, ``<provider>/<module>/<type>`` for pulumi
— so :func:`terraform_resource_aliases` gives a matcher both the full
address and the short form to try against ``resource_pattern``.
"""

import hashlib
import json
import re
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

# Global boolean flags that are consumed but not recorded anywhere.
_DISCARD_BOOL_FLAGS = {
    "insecure-skip-tls-verify",
    "warnings-as-errors",
    "match-server-version",
    "disable-compression",
}

# Global flags whose value is consumed but not recorded anywhere.
_DISCARD_VALUE_FLAGS = {
    "kubeconfig",
    "o",
    "output",
    "s",
    "server",
    "v",
    "as",
    "as-uid",
    "as-group",
    "request-timeout",
    "token",
    "user",
    "username",
    "password",
    "cache-dir",
    "certificate-authority",
    "client-certificate",
    "client-key",
    "tls-server-name",
    "profile",
    "profile-output",
    "log-flush-frequency",
}

# Flags that point at a manifest (file or kustomize directory).
_MANIFEST_FLAGS = {"f", "filename", "k", "kustomize"}

# Flags carrying environment identity, recorded in metadata.
_KUBECTL_IDENTITY_FLAGS = {"n", "namespace", "context", "cluster"}

# Selector flags: value flags recorded in params; the target becomes kind/*.
_SELECTOR_FLAGS = {"l": "selector", "selector": "selector", "field-selector": "field_selector"}

# Every global option kubectl accepts in front of the verb, split by arity.
_KUBECTL_GLOBAL_VALUE_FLAGS = _KUBECTL_IDENTITY_FLAGS | _DISCARD_VALUE_FLAGS
_KUBECTL_GLOBAL_BOOL_FLAGS = {"A", "all-namespaces"} | _DISCARD_BOOL_FLAGS

# Short flags that may be glued to their value: -nprod, -lapp=web, -fx.yaml.
_KUBECTL_GLUED_SHORT_FLAGS = {"n", "l", "f", "o", "k", "s", "v"}

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


_TRUE_WORDS = frozenset({"true", "t", "yes", "y", "1", "on"})
_FALSE_WORDS = frozenset({"false", "f", "no", "n", "0", "off"})


def _coerce_bool(value: Any) -> bool | None:
    """Boolean coercion shared by every parser: ``None`` (a bare flag) ->
    True; ``"true"/"t"/"yes"/"y"/"1"/"on"`` -> True and
    ``"false"/"f"/"no"/"n"/"0"/"off"`` -> False, case-insensitively; a
    real bool/int passes through; any other spelling -> ``None`` (not a
    boolean value)."""
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    word = str(value).strip().lower()
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    return None


def _bool_param(value: str | None) -> Any:
    """The value to record for a *known-boolean* flag: ``--flag`` -> True,
    ``--flag=false`` -> False. A non-boolean spelling (kubectl's
    ``--cascade=orphan``) is recorded as given, never mistaken for True."""
    coerced = _coerce_bool(value)
    return coerced if coerced is not None else _coerce(value)


def _is_dry_run(value: str | None, *, truthy: frozenset[str] = frozenset()) -> bool:
    """Whether a ``--dry-run[=value]`` spelling is a rehearsal. Bare and
    boolean-true values are; so are the tool's own words in ``truthy``
    (kubectl/helm ``client``/``server``). Anything else — ``false``,
    ``none``, ``0``, an unrecognised word — is treated as a real run, so
    the stricter rule applies (fail closed)."""
    if value is None:
        return True
    word = value.strip().lower()
    if word in truthy:
        return True
    return _coerce_bool(word) is True


_KUBECTL_DRY_RUN_WORDS = frozenset({"client", "server"})


def _value_at(tokens: list[str], i: int, flag: str) -> str:
    """``tokens[i]`` as the value of ``flag``, or a ValueError (not an
    IndexError) when the argv ends right after a flag that needs a value."""
    if i >= len(tokens):
        raise ValueError(f"flag {flag!r} is missing its value: {tokens!r}")
    return tokens[i]


def _split_flag(token: str) -> tuple[str, str | None]:
    body = token[2:] if token.startswith("--") else token[1:]
    key, sep, value = body.partition("=")
    return key, (value if sep else None)


def _expand_glued_short_flags(tokens: list[str], short_value_flags: set[str]) -> list[str]:
    """``-nprod`` -> ``-n prod`` for every single-letter value flag in
    ``short_value_flags``. ``-n=prod`` and ``-n prod`` are left alone, as is
    any token that isn't a short flag."""
    expanded: list[str] = []
    for idx, tok in enumerate(tokens):
        if tok == "--":
            # everything after "--" is a wrapped command (kubectl exec ... -- ls -la)
            expanded.extend(tokens[idx:])
            break
        if (
            len(tok) > 2
            and tok[0] == "-"
            and tok[1] != "-"
            and tok[1] in short_value_flags
            and tok[2] != "="
        ):
            expanded.append(tok[:2])
            expanded.append(tok[2:])
        else:
            expanded.append(tok)
    return expanded


def _split_leading_globals(
    tokens: list[str],
    *,
    value_flags: set[str],
    bool_flags: set[str],
    tool: str,
) -> tuple[list[str], list[str]]:
    """Splits ``tokens`` into ``(leading_global_option_tokens, rest)`` where
    ``rest[0]`` is the tool's verb.

    A leading option is consumed as ``--flag=value`` (one token), or as
    ``--flag value`` when its key is in ``value_flags``, or as a bare
    boolean when its key is in ``bool_flags``. Anything else that starts
    with ``-`` before the verb is a ``ValueError``: guessing whether an
    unknown option swallows the next token is exactly how a verb gets
    misidentified. Raises ``ValueError`` when no verb follows the options,
    or when the option's value is missing."""
    i = 0
    n = len(tokens)
    while i < n and tokens[i].startswith("-") and tokens[i] != "-":
        tok = tokens[i]
        key, val = _split_flag(tok)
        if val is not None and (key in value_flags or key in bool_flags):
            i += 1
        elif key in value_flags:
            if i + 1 >= n:
                raise ValueError(f"{tool}: global option {tok!r} is missing its value")
            i += 2
        elif key in bool_flags:
            i += 1
        else:
            raise ValueError(f"{tool}: unrecognised global option {tok!r} before the verb")
    if i >= n:
        raise ValueError(f"{tool}: no verb found after global options: {tokens!r}")
    if tokens[i].startswith("-"):
        raise ValueError(f"{tool}: verb {tokens[i]!r} must not start with '-'")
    return tokens[:i], tokens[i:]


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
    matches ``kind/*`` constraint patterns. A comma-separated kind list
    (``nodes,pods``) yields one ``kind/*`` per kind; combining it with
    object names is rejected, as kubectl itself does."""
    if not positional:
        return []
    if any("/" in t for t in positional):
        resources = []
        for t in positional:
            kind, name = _split_resource_token(t)
            resources.append(f"{kind}/{name}" if name is not None else f"{kind}/*")
        return resources
    if "," in positional[0]:
        if len(positional) > 1:
            raise ValueError(
                f"a comma-separated kind list cannot be combined with names: {positional!r}"
            )
        kinds = [_split_resource_token(k)[0] for k in positional[0].split(",") if k]
        return [f"{kind}/*" for kind in kinds]
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
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key in ("A", "all-namespaces"):
                metadata["all_namespaces"] = True
            elif key == "context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif key == "cluster":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["cluster"] = val
            elif key == "dry-run":
                # bare --dry-run, --dry-run=client, --dry-run=server (and the
                # deprecated --dry-run=true) are rehearsals; --dry-run=none /
                # =false is a real run.
                if _is_dry_run(val, truthy=_KUBECTL_DRY_RUN_WORDS):
                    params["dry_run"] = True
            elif key in _SELECTOR_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[_SELECTOR_FLAGS[key]] = val
            elif key in _MANIFEST_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                manifest_value = val
            elif key in _DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
            elif key in _DISCARD_BOOL_FLAGS:
                pass
            elif key in _KNOWN_BOOL_FLAGS:
                params[key] = _bool_param(val)
            elif val is not None:
                params[key] = _coerce(val)
            elif is_long:
                # Unknown long flag with no "=value": treat the next token
                # as its value.
                i += 1
                params[key] = _coerce(_value_at(tokens, i, tok))
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

    all_tokens = _expand_glued_short_flags(argv[1:], _KUBECTL_GLUED_SHORT_FLAGS)
    leading, rest = _split_leading_globals(
        all_tokens,
        value_flags=_KUBECTL_GLOBAL_VALUE_FLAGS,
        bool_flags=_KUBECTL_GLOBAL_BOOL_FLAGS,
        tool="kubectl",
    )
    verb = rest[0]
    # Global options are parsed by the same flag walker as post-verb flags,
    # so "-n prod delete x" and "delete x -n prod" produce identical intents.
    tokens = leading + rest[1:]

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
    intents = _make_intents(resources, verb, params, metadata)
    if verb == "delete":
        intents.extend(_namespace_cascade_intents(resources, params, metadata))
    return intents


def _namespace_cascade_intents(
    resources: list[str], params: dict[str, Any], metadata: dict[str, Any]
) -> list[InfrastructureIntent]:
    """For every named ``namespace/<ns>`` being deleted, the synthetic
    ``*/*`` delete intent scoped to that namespace (see module docstring)."""
    cascades = []
    for resource in resources:
        kind, _, name = resource.partition("/")
        if kind != "namespace" or name in ("", "*"):
            continue
        cascades.append(
            InfrastructureIntent(
                resource="*/*",
                action="delete",
                provider="kubernetes",
                params={**params, "cascade_from": resource},
                metadata={**metadata, "namespace": name},
            )
        )
    return cascades


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


_TF_MODULE_PREFIX_RE = re.compile(r"^(?:module\.[^.\[]+(?:\[[^\]]*\])?\.)+")


def _split_terraform_address(address: str) -> tuple[str, str | None]:
    """``module.app.module.db[0].aws_db_instance.main`` ->
    ``("aws_db_instance.main", "module.app.module.db[0]")``; an address with
    no module prefix keeps its ``module_path`` as ``None``."""
    match = _TF_MODULE_PREFIX_RE.match(address)
    if not match:
        return address, None
    return address[match.end():], match.group(0).rstrip(".")


def _walk_state_modules(module: dict[str, Any] | None):
    """Yields every resource dict in a ``planned_values`` /
    ``prior_state.values`` module tree (root and nested child modules)."""
    if not module:
        return
    yield from module.get("resources") or []
    for child in module.get("child_modules") or []:
        yield from _walk_state_modules(child)


def _region_from_values(values: dict[str, Any] | None, address: str) -> Any:
    for resource in _walk_state_modules((values or {}).get("root_module")):
        if resource.get("address") == address:
            region = (resource.get("values") or {}).get("region")
            if region is not None:
                return region
    return None


def _config_module_for(plan_json: dict[str, Any], module_path: str | None) -> dict[str, Any]:
    """The ``configuration`` module dict that declares the resources at
    ``module_path`` (``None`` -> root module)."""
    module = plan_json.get("configuration", {}).get("root_module", {}) or {}
    for name in re.findall(r"module\.([^.\[]+)", module_path or ""):
        module = ((module.get("module_calls") or {}).get(name) or {}).get("module") or {}
    return module


def _provider_config_key(
    plan_json: dict[str, Any], type_name: str, module_path: str | None
) -> str | None:
    """The resource's ``provider_config_key`` (``aws``, ``aws.west``,
    ``module.app:aws``) from the configuration block, if declared."""
    base = re.sub(r"\[[^\]]*\]$", "", type_name)
    for resource in _config_module_for(plan_json, module_path).get("resources") or []:
        if resource.get("address") in (type_name, base):
            return resource.get("provider_config_key")
    return None


def _resolve_expression(plan_json: dict[str, Any], expression: dict[str, Any] | None) -> Any:
    """A configuration expression's value: its ``constant_value``, or the
    plan-time value of the ``var.<name>`` it references."""
    if not expression:
        return None
    if expression.get("constant_value") is not None:
        return expression["constant_value"]
    for ref in expression.get("references") or []:
        if ref.startswith("var."):
            name = ref[len("var."):].split(".", 1)[0].split("[", 1)[0]
            value = (plan_json.get("variables", {}).get(name) or {}).get("value")
            if value is not None:
                return value
    return None


def _region_from_provider_config(
    plan_json: dict[str, Any], provider_short: str, provider_key: str | None = None
) -> Any:
    provider_configs = plan_json.get("configuration", {}).get("provider_config", {}) or {}
    ordered = []
    if provider_key and provider_key in provider_configs:
        ordered.append(provider_key)
    ordered.extend(
        key
        for key in provider_configs
        if key not in ordered
        and (
            key == provider_short
            or key.startswith(f"{provider_short}.")
            or key.endswith(f":{provider_short}")
        )
    )
    for key in ordered:
        expressions = provider_configs[key].get("expressions", {}) or {}
        region = _resolve_expression(plan_json, expressions.get("region"))
        if region is not None:
            return region
    return None


def _terraform_region(
    plan_json: dict[str, Any],
    change: dict[str, Any],
    address: str,
    type_name: str,
    module_path: str | None,
) -> Any:
    """Region for one ``resource_changes[]`` entry, resolved in order from
    the change's before/after values, ``planned_values``, the provider
    configuration (a constant or the ``var.<name>`` it references, via
    ``variables``), and finally ``prior_state``."""
    before = change.get("change", {}).get("before") or {}
    after = change.get("change", {}).get("after") or {}
    region = before.get("region") or after.get("region")
    if region is not None:
        return region
    region = _region_from_values(plan_json.get("planned_values"), address)
    if region is not None:
        return region
    provider_name = change.get("provider_name")
    if provider_name:
        region = _region_from_provider_config(
            plan_json,
            _provider_short_name(provider_name),
            _provider_config_key(plan_json, type_name, module_path),
        )
        if region is not None:
            return region
    return _region_from_values((plan_json.get("prior_state") or {}).get("values"), address)


def plan_digest(plan_json: dict[str, Any]) -> str:
    """sha256 of the canonical JSON form of a plan / preview document
    (sorted keys, no whitespace) — the ``plan_sha256`` every intent from
    that document carries, so a decision can be bound to the exact plan
    that was checked and re-verified before ``apply``."""
    canonical = json.dumps(
        plan_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def terraform_resource_aliases(intent: InfrastructureIntent) -> list[str]:
    """The resource identifiers a matcher should try, in order, against a
    constraint's ``resource_pattern`` for a plan-derived intent: the full
    address (``module.app.aws_db_instance.main``) and the module-stripped
    ``metadata["type_name"]`` (``aws_db_instance.main``), so a rule written
    as ``aws_db_instance.*`` catches the resource wherever it lives. Works
    for pulumi intents too (``aws/rds/instance/db1`` and
    ``aws/rds/instance``). Intents without ``type_name`` yield just their
    resource, so the helper is safe to call on any intent. Same as
    :meth:`InfrastructureIntent.resource_aliases` (which the store and the
    plan evaluator use directly, so neither has to import this module)."""
    return intent.resource_aliases()


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

    ``resource`` is the full address. ``metadata["type_name"]`` is the
    module-stripped ``<type>.<name>`` and ``metadata["module_path"]`` the
    stripped prefix (see :func:`terraform_resource_aliases`);
    ``metadata["plan_sha256"]`` is :func:`plan_digest` of ``plan_json``.
    ``region`` (in ``params`` and ``metadata``) is resolved for every
    action, creates included, from the change values, ``planned_values``,
    the provider configuration / ``variables``, and ``prior_state``.

    Data-source entries whose action is "read" are skipped by default (they
    aren't a proposed change to infrastructure) unless ``include_data`` is
    True.
    """
    tool = _plan_tool(plan_json, tool)
    digest = plan_digest(plan_json)
    intents = []
    for change in plan_json.get("resource_changes", []):
        actions = tuple(change.get("change", {}).get("actions", []))
        action = _TERRAFORM_ACTION_MAP.get(actions)
        if action is None:
            raise ValueError(f"unsupported terraform change actions: {actions!r}")

        mode = change.get("mode")
        if mode == "data" and action == "read" and not include_data:
            continue

        address = change["address"]
        type_name, module_path = _split_terraform_address(address)

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
        module_address = change.get("module_address") or module_path
        if module_address:
            metadata["module_address"] = module_address
            metadata["module_path"] = module_address
        metadata["type_name"] = type_name
        metadata["plan_sha256"] = digest

        params: dict[str, Any] = {}
        region = _terraform_region(plan_json, change, address, type_name, module_path)
        if region is not None:
            params["region"] = region
            metadata["region"] = region
        before = change.get("change", {}).get("before") or {}
        after = change.get("change", {}).get("after") or {}
        tags = before.get("tags") or after.get("tags")
        if tags is not None:
            params["tags"] = tags
        if change.get("change", {}).get("replace_paths"):
            params["forced_replacement"] = True

        intents.append(
            InfrastructureIntent(
                resource=address,
                action=action,
                provider="terraform",
                params=params,
                metadata=metadata,
            )
        )
    return intents


# --- AWS CLI -----------------------------------------------------------------

_AWS_BOOL_FLAGS = {
    "force",
    "no-paginate",
    "no-cli-pager",
    # global booleans: never swallow the service/operation token after them
    "debug",
    "no-verify-ssl",
    "no-sign-request",
    "no-cli-auto-prompt",
    "cli-auto-prompt",
}
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
                    val = _value_at(tokens, i, tok)
                metadata["region"] = val
            elif key == "profile":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["profile"] = val
            elif key == "dry-run":
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key == "no-dry-run":
                pass  # explicitly a real run; nothing to record
            elif key in _AWS_BOOL_FLAGS:
                params[key] = _bool_param(val)
            elif key in _AWS_DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # consumed, intentionally not recorded
            elif key == "cli-input-json":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
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
                    val = _value_at(tokens, i, tok)
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


_IAM_PRIVILEGE_OPERATIONS = {
    "add-user-to-group",
    "create-access-key",
    "create-login-profile",
    "add-role-to-instance-profile",
    "update-assume-role-policy",
}


def _is_iam_privilege_grant(operation: str) -> bool:
    return (
        operation.startswith("attach-")
        or (operation.startswith("put-") and operation.endswith("-policy"))
        or operation in _IAM_PRIVILEGE_OPERATIONS
    )


def _from_aws_s3_alias(
    service: str,
    operation: str,
    metadata: dict[str, Any],
    params: dict[str, Any],
    id_value: str | None,
) -> list[InfrastructureIntent]:
    """``aws s3api`` and ``aws s3control`` are the low-level spellings of
    the S3 service: both collapse to service ``s3`` so a rule written for
    ``s3/bucket/*`` covers ``s3api delete-bucket --bucket b`` too.

    s3api: ``--bucket`` names the bucket (``s3/bucket/<b>``); an
    ``*-object*`` operation, or any operation with ``--key``, targets
    ``s3/object/<bucket>/<key>``. s3control: ``<kind>`` from the operation
    noun, name from ``--name`` (``s3/access-point/<name>``)."""
    if "-" in operation:
        verb, noun = operation.split("-", 1)
    else:
        verb, noun = operation, None
    action = _normalize_verb(verb)
    params = dict(params)
    params["raw_action"] = operation
    params["raw_service"] = service
    key = params.pop("key", None)
    if service == "s3api":
        bucket = id_value or "*"
        if key is not None:
            params["key"] = key
            resource = f"s3/object/{bucket}/{key}"
        elif noun and noun.startswith("object"):
            resource = f"s3/object/{bucket}/*"
        else:
            resource = f"s3/bucket/{bucket}"
    else:
        kind = _singularize(noun) if noun else service
        name = params.pop("name", None) or id_value
        resource = _aws_resource("s3", kind, name)
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

    if service in ("s3api", "s3control"):
        return _from_aws_s3_alias(service, operation, metadata, params, id_value)

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

    if service == "iam" and _is_iam_privilege_grant(operation):
        # attach-role-policy, put-user-policy, add-user-to-group,
        # create-access-key, ...: a "create"/"put"/"attach" by verb, but what
        # they do is widen someone's privileges. Normalised to "update" with
        # params["privilege"]=True so one rule catches every spelling.
        action = "update"
        params["privilege"] = True

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

_AZ_BOOL_FLAGS = {"yes", "y", "no-wait", "debug", "verbose", "only-show-errors"}

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
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    name_value: str | None = None
    ids_values: list[str] = []

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key in ("l", "location"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["region"] = val
            elif key == "subscription":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["subscription"] = val
            elif key in ("g", "resource-group"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["resource_group"] = val
            elif key in ("n", "name"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                name_value = val
            elif key in ("what-if", "dry-run"):
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key == "ids":
                # `az <group> <verb> --ids ID [ID ...]`: one or more ARM
                # resource ids in place of -g/-n (REVIEW-4 T1.7).
                if val is not None:
                    ids_values.append(val)
                else:
                    while i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        ids_values.append(tokens[i])
            elif key in _AZ_BOOL_FLAGS:
                params["yes" if key == "y" else key] = _bool_param(val)
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

    return metadata, params, positional, name_value, ids_values


# ARM resource types (lower-cased ``<namespace>/<type>``) -> the same
# ``<service>/<kind>`` prefix the named-flag form of the command produces, so
# ``az resource delete --ids .../Microsoft.ContainerService/managedClusters/c``
# and ``az aks delete -n c -g rg`` hit the same ``aks/cluster/*`` rule.
_ARM_TYPE_MAP = {
    "microsoft.containerservice/managedclusters": "aks/cluster",
    "microsoft.compute/virtualmachines": "compute/vm",
    "microsoft.compute/virtualmachinescalesets": "compute/vmss",
    "microsoft.storage/storageaccounts": "storage/account",
    "microsoft.sql/servers": "sql/server",
    "microsoft.keyvault/vaults": "keyvault/vault",
    "microsoft.network/virtualnetworks": "network/vnet",
    "microsoft.network/networksecuritygroups": "network/nsg",
    "microsoft.web/sites": "web/app",
    "microsoft.containerregistry/registries": "acr/registry",
}

# Nested ARM types (``<namespace>/<type>/<subtype>``) with a short form.
_ARM_SUBTYPE_MAP = {
    "microsoft.sql/servers/databases": "sql/db",
}


def _parse_arm_id(arm_id: str) -> tuple[str, dict[str, Any]]:
    """``/subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>
    [/<subtype>/<subname>...]`` -> ``(resource, metadata)`` where
    ``resource`` is ``<mapped service>/<kind>/<name>`` (or
    ``<ns lower>/<type lower>/<name>`` for an unmapped type) and
    ``metadata`` carries ``subscription`` / ``resource_group`` /
    ``arm_id``. Raises ``ValueError`` for anything that isn't an ARM id."""
    parts = [p for p in arm_id.split("/") if p]
    if len(parts) < 2 or parts[0].lower() != "subscriptions":
        raise ValueError(f"not an ARM resource id: {arm_id!r}")
    metadata: dict[str, Any] = {"subscription": parts[1], "arm_id": arm_id}
    i = 2
    if i < len(parts) and parts[i].lower() == "resourcegroups":
        if i + 1 >= len(parts):
            raise ValueError(f"ARM id has no resource group name: {arm_id!r}")
        metadata["resource_group"] = parts[i + 1]
        i += 2
    if i >= len(parts):
        if "resource_group" in metadata:
            return f"resource/group/{metadata['resource_group']}", metadata
        return f"subscription/{parts[1]}", metadata
    if parts[i].lower() != "providers" or i + 3 >= len(parts):
        raise ValueError(f"ARM id has no providers/<ns>/<type>/<name> segment: {arm_id!r}")
    namespace, kind, name = parts[i + 1], parts[i + 2], parts[i + 3]
    i += 4
    type_key = f"{namespace.lower()}/{kind.lower()}"
    prefix = _ARM_TYPE_MAP.get(type_key, type_key)
    rest = parts[i:]
    if not rest:
        return f"{prefix}/{name}", metadata
    if len(rest) % 2:
        raise ValueError(f"ARM id has an unpaired sub-resource segment: {arm_id!r}")
    subtypes = [rest[j].lower() for j in range(0, len(rest), 2)]
    mapped = _ARM_SUBTYPE_MAP.get(type_key + "/" + "/".join(subtypes))
    if mapped:
        return f"{mapped}/{rest[-1]}", metadata
    chain = "/".join(f"{rest[j].lower()}/{rest[j + 1]}" for j in range(0, len(rest), 2))
    return f"{prefix}/{name}/{chain}", metadata


def from_az_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``az`` CLI invocation into one InfrastructureIntent per
    target: one for the ``-n/--name`` form, or one per ``--ids`` ARM path
    (``az vm deallocate --ids /subscriptions/.../virtualMachines/a
    /subscriptions/.../virtualMachines/b`` names two)."""
    if not argv or _basename(argv[0]) != "az":
        raise ValueError(f"not a recognizable az invocation: {argv!r}")

    tokens = argv[1:]
    metadata, params, positional, name_value, ids_values = _parse_az_tokens(tokens)

    if not positional:
        raise ValueError(f"could not find an az verb in: {argv!r}")

    verb = positional[-1]
    if verb not in _AZ_VERBS:
        raise ValueError(f"unrecognized az verb in: {argv!r}")

    group_words = positional[:-1]
    if not group_words:
        raise ValueError(f"could not determine an az resource group path in: {argv!r}")

    action = _normalize_verb(verb)
    params["raw_action"] = verb

    if ids_values:
        intents = []
        for arm_id in ids_values:
            resource, arm_metadata = _parse_arm_id(arm_id)
            intents.append(
                InfrastructureIntent(
                    resource=resource,
                    action=action,
                    provider="azure",
                    params=dict(params),
                    metadata={**arm_metadata, **metadata},
                )
            )
        return intents

    resource_prefix = _AZ_GROUP_MAP.get(tuple(group_words), "/".join(group_words))
    resource = f"{resource_prefix}/{name_value}" if name_value else f"{resource_prefix}/*"

    return [
        InfrastructureIntent(
            resource=resource, action=action, provider="azure", params=params, metadata=metadata
        )
    ]


def from_az(argv: list[str]) -> InfrastructureIntent:
    """Parses an ``az`` CLI invocation that targets exactly one resource, e.g.:

    ``az vm start --resource-group rg1 --name vm1``
      -> resource "compute/vm/vm1", action "start"

    Raises ValueError if ``--ids`` names more than one resource; use
    :func:`from_az_multi` for that case.
    """
    intents = from_az_multi(argv)
    if len(intents) != 1:
        raise ValueError(
            f"expected exactly one target resource, found {len(intents)}: {argv!r}"
        )
    return intents[0]


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

# gcloud global booleans: never swallow the group/verb token after them.
_GCLOUD_BOOL_FLAGS = {"log-http", "no-user-output-enabled", "user-output-enabled"}


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
                    val = _value_at(tokens, i, tok)
                metadata["region"] = val
            elif key == "zone":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["zone"] = val
                metadata["region"] = val
            elif key == "project":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["project"] = val
            elif key in ("quiet", "q"):
                params["quiet"] = _bool_param(val)
            elif key == "dry-run":
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key == "async":
                params["async"] = _bool_param(val)
            elif key in _GCLOUD_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
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

# Helm global options (accepted before or after the verb).
_HELM_GLOBAL_VALUE_FLAGS = {
    "n",
    "namespace",
    "kube-context",
    "kubeconfig",
    "kube-apiserver",
    "kube-as-user",
    "kube-as-group",
    "kube-token",
    "kube-ca-file",
    "kube-tls-server-name",
    "registry-config",
    "repository-cache",
    "repository-config",
    "burst-limit",
    "qps",
}
_HELM_GLOBAL_BOOL_FLAGS = {"debug", "kube-insecure-skip-tls-verify"}
# Global value flags whose value is consumed but not recorded.
_HELM_DISCARD_VALUE_FLAGS = _HELM_GLOBAL_VALUE_FLAGS - {"n", "namespace", "kube-context"}


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
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key == "kube-context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif key in _HELM_DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # consumed, intentionally not recorded
            elif key in _HELM_GLOBAL_BOOL_FLAGS:
                pass  # consumed, intentionally not recorded
            elif key == "dry-run":
                # helm: --dry-run, =client, =server, =true rehearse;
                # =none / =false run for real.
                if _is_dry_run(val, truthy=_KUBECTL_DRY_RUN_WORDS):
                    params["dry_run"] = True
            elif key == "version":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params["version"] = _coerce(val)
            elif key in ("f", "values"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params.setdefault("values_files", []).append(val)
            elif key == "set":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                k, _sep, v = val.partition("=")
                params.setdefault("set", {})[k] = _coerce(v)
            elif key in _HELM_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
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

    leading, rest = _split_leading_globals(
        _expand_glued_short_flags(argv[1:], {"n"}),
        value_flags=_HELM_GLOBAL_VALUE_FLAGS,
        bool_flags=_HELM_GLOBAL_BOOL_FLAGS,
        tool="helm",
    )
    verb = rest[0]
    tokens = leading + rest[1:]
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

# ArgoCD global options (persistent flags, accepted anywhere on the line).
_ARGOCD_GLOBAL_VALUE_FLAGS = {
    "server",
    "auth-token",
    "config",
    "header",
    "client-crt",
    "client-crt-key",
    "server-crt",
    "kube-context",
    "port-forward-namespace",
    "logformat",
    "loglevel",
    "http-retry-max",
    "server-name",
    "grpc-web-root-path",
    "redis-haproxy-name",
    "redis-name",
    "repo-server-name",
    "controller-name",
}
_ARGOCD_GLOBAL_BOOL_FLAGS = {
    "grpc-web",
    "insecure",
    "plaintext",
    "core",
    "port-forward",
    "skip-test-tls",
}
# Known boolean sync/delete options (``--prune=true`` must be True, not "true").
_ARGOCD_BOOL_FLAGS = {"prune", "force", "cascade", "async", "apply-out-of-sync-only",
                      "server-side", "replace", "yes", "y"}


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
                    val = _value_at(tokens, i, tok)
                metadata["project"] = val
            elif key == "kube-context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif key in _ARGOCD_GLOBAL_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # consumed, intentionally not recorded
            elif key in _ARGOCD_GLOBAL_BOOL_FLAGS:
                pass  # consumed, intentionally not recorded
            elif key == "dry-run":
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key in _ARGOCD_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
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

    # Persistent flags may precede "app" and/or its subcommand; both runs
    # of globals are handed to the same token parser as the trailing flags.
    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_ARGOCD_GLOBAL_VALUE_FLAGS,
        bool_flags=_ARGOCD_GLOBAL_BOOL_FLAGS,
        tool="argocd",
    )
    if rest[0] != "app":
        raise ValueError(f"unsupported argocd invocation: {argv!r}")
    if len(rest) < 2:
        raise ValueError(f"argocd app requires a subcommand: {argv!r}")
    leading_2, rest = _split_leading_globals(
        rest[1:],
        value_flags=_ARGOCD_GLOBAL_VALUE_FLAGS,
        bool_flags=_ARGOCD_GLOBAL_BOOL_FLAGS,
        tool="argocd",
    )
    leading = leading + leading_2

    subverb = rest[0]
    tokens = leading + rest[1:]

    if subverb == "actions":
        if len(rest) < 2 or rest[1] != "run":
            raise ValueError(f"unsupported 'argocd app actions' invocation: {argv!r}")
        metadata, params, positional = _parse_argocd_tokens(leading + rest[2:])
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

# Flux global options (accepted before or after the verb).
_FLUX_GLOBAL_VALUE_FLAGS = {
    "n",
    "namespace",
    "context",
    "kubeconfig",
    "timeout",
    "as",
    "as-group",
    "as-uid",
    "cache-dir",
    "certificate-authority",
    "client-certificate",
    "client-key",
    "server",
    "token",
    "tls-server-name",
    "kube-api-burst",
    "kube-api-qps",
}
_FLUX_GLOBAL_BOOL_FLAGS = {"verbose", "insecure-skip-tls-verify"}
# Global value flags whose value is consumed but not recorded. --timeout is
# kept in params: it's meaningful to a rule author ("reconcile with a long
# timeout") and lands there whichever side of the verb it's on.
_FLUX_DISCARD_VALUE_FLAGS = _FLUX_GLOBAL_VALUE_FLAGS - {"n", "namespace", "context", "timeout"}

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
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key == "context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif key in _FLUX_DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # consumed, intentionally not recorded
            elif key in _FLUX_GLOBAL_BOOL_FLAGS:
                pass  # consumed, intentionally not recorded
            elif key == "dry-run":
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key == "export":
                export = _bool_param(val)
                params["export"] = export
                if export is True:
                    params["dry_run"] = True
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

    leading, rest = _split_leading_globals(
        _expand_glued_short_flags(argv[1:], {"n"}),
        value_flags=_FLUX_GLOBAL_VALUE_FLAGS,
        bool_flags=_FLUX_GLOBAL_BOOL_FLAGS,
        tool="flux",
    )
    verb = rest[0]
    tokens = leading + rest[1:]
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

# Git launcher options: only valid *before* the verb ("git -C /repo push"),
# and never part of the intent — a force-push is a force-push whichever
# working tree it's launched from — so they're consumed and dropped.
_GIT_GLOBAL_VALUE_FLAGS = {
    "C",
    "c",
    "git-dir",
    "work-tree",
    "namespace",
    "super-prefix",
    "config-env",
    "list-cmds",
    "attr-source",
}
_GIT_GLOBAL_BOOL_FLAGS = {
    "no-pager",
    "p",
    "paginate",
    "P",
    "no-optional-locks",
    "exec-path",
    "bare",
    "no-replace-objects",
    "no-lazy-fetch",
    "no-advice",
    "literal-pathspecs",
    "glob-pathspecs",
    "noglob-pathspecs",
    "icase-pathspecs",
}


# Bare boolean options of the git verbs we model; without this list the
# generic walker would swallow the token after ``--mirror`` as its value.
_GIT_BOOL_FLAGS = {
    "mirror", "all", "prune", "atomic", "no-verify", "verbose", "v", "quiet", "q",
    "u", "set-upstream", "follow-tags", "porcelain", "progress", "no-progress",
    "soft", "mixed", "merge", "keep", "interactive", "i", "autosquash", "no-edit",
}


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
            elif key in ("dry-run", "n"):
                if _is_dry_run(val):
                    params["dry_run"] = True
            elif key in _GIT_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
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
    # --mirror force-updates every ref on the remote (and deletes the ones
    # that don't exist locally): a force push by any other name.
    force = bool(params.get("force")) or params.get("mirror") is True
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
    if not ref:
        # No refspec: the target is whatever the local branch / push.default
        # / --all / --mirror resolve to — unknowable from the argv. Marked
        # so the caller can escalate ("git push -f" must not sail past a
        # "ref/main" rule as "ref/*").
        params["unknown_target"] = True

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

    _leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_GIT_GLOBAL_VALUE_FLAGS,
        bool_flags=_GIT_GLOBAL_BOOL_FLAGS,
        tool="git",
    )
    verb = rest[0]
    tokens = rest[1:]
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

_GH_GLOBAL_VALUE_FLAGS = {"R", "repo"}

# Groups whose first token is a subcommand ("gh workflow run ..."); the
# rest ("gh api ...", "gh issue ...") take their flags directly.
_GH_SUBVERB_GROUPS = {"workflow", "release", "pr", "repo", "secret", "variable"}


def _gh_fold_globals(group: str, tokens: list[str], leading: list[str]) -> list[str]:
    """Re-inserts leading global option tokens after the group's subcommand
    (or at the front, for groups without one) so they reach
    ``_parse_gh_tokens`` alongside the trailing flags."""
    if group in _GH_SUBVERB_GROUPS and tokens:
        return [tokens[0], *leading, *tokens[1:]]
    return [*leading, *tokens]


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
                    val = _value_at(tokens, i, tok)
                metadata["repo"] = val
            elif key in ("r", "ref"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["ref"] = val
            elif key in ("f", "F", "field", "raw-field"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                k, _sep, v = val.partition("=")
                params.setdefault("inputs", {})[k] = _coerce(v)
            elif key == "admin":
                params["admin"] = _bool_param(val)
            elif key in ("squash", "merge", "rebase") and val is None:
                params["method"] = key
            elif key == "delete-branch":
                params["delete_branch"] = _bool_param(val)
            elif key in ("X", "method"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
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


# ``gh api`` REST paths that are the raw spelling of a porcelain command.
# Each maps (path regex, method) -> (resource template over the regex
# groups, action), so ``gh api -X POST
# repos/o/r/actions/workflows/deploy-prod.yml/dispatches`` is
# ``workflow/deploy-prod.yml`` / ``run`` exactly like ``gh workflow run``.
_GH_API_REPO_RE = re.compile(r"^repos/([^/]+)/([^/]+)(?:/|$)")
_GH_API_ROUTES: list[tuple[re.Pattern[str], dict[str, tuple[str, str]]]] = [
    (
        re.compile(r"^repos/([^/]+)/([^/]+)/actions/workflows/([^/]+)/dispatches$"),
        {"POST": ("workflow/{2}", "run")},
    ),
    (
        re.compile(r"^repos/([^/]+)/([^/]+)/releases$"),
        {"POST": ("release/*", "create")},
    ),
    (
        re.compile(r"^repos/([^/]+)/([^/]+)/releases/([^/]+)$"),
        {"DELETE": ("release/{2}", "delete")},
    ),
    (
        re.compile(r"^repos/([^/]+)/([^/]+)$"),
        {"DELETE": ("repo/{0}/{1}", "delete")},
    ),
    (
        re.compile(r"^repos/([^/]+)/([^/]+)/actions/secrets/([^/]+)$"),
        {"PUT": ("secret/{2}", "put"), "DELETE": ("secret/{2}", "delete")},
    ),
    (
        re.compile(r"^repos/([^/]+)/([^/]+)/branches/([^/]+)/protection$"),
        {"DELETE": ("branch-protection/{2}", "delete"), "PUT": ("branch-protection/{2}", "update")},
    ),
]


def _gh_api_normalise_path(path: str) -> str:
    """``https://api.github.com/repos/o/r?x=1`` / ``/repos/o/r/`` -> ``repos/o/r``."""
    if path.startswith(("http://", "https://")):
        path = path.split("://", 1)[1].split("/", 1)[1] if "/" in path.split("://", 1)[1] else ""
    path = path.split("?", 1)[0]
    return path.strip("/")


def from_gh(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``gh`` (GitHub CLI) invocation, e.g.:

    ``gh pr merge 42 --admin --squash``
      -> resource "pr/42", action "merge", params {"admin": True, "method": "squash"}
    """
    if len(argv) < 2 or _basename(argv[0]) != "gh":
        raise ValueError(f"not a recognizable gh invocation: {argv!r}")

    # -R/--repo is a persistent flag of each command group, so it may sit in
    # front of the group ("gh -R o/r workflow run x") or between the group
    # and its subcommand ("gh workflow -R o/r run x"); both are folded into
    # the tokens handed to _parse_gh_tokens.
    leading, rest = _split_leading_globals(
        argv[1:], value_flags=_GH_GLOBAL_VALUE_FLAGS, bool_flags=set(), tool="gh"
    )
    group = rest[0]
    tokens = rest[1:]
    if group in _GH_SUBVERB_GROUPS and tokens:
        leading_2, tokens = _split_leading_globals(
            tokens, value_flags=_GH_GLOBAL_VALUE_FLAGS, bool_flags=set(), tool="gh"
        )
        leading = leading + leading_2
    if leading:
        tokens = _gh_fold_globals(group, tokens, leading)

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
        path = _gh_api_normalise_path(positional[0]) if positional else "*"
        params["api_path"] = path
        repo_match = _GH_API_REPO_RE.match(path)
        if repo_match and "repo" not in metadata:
            metadata["repo"] = f"{repo_match.group(1)}/{repo_match.group(2)}"
        for pattern, by_method in _GH_API_ROUTES:
            match = pattern.match(path)
            if not match:
                continue
            route = by_method.get(method)
            if route is None:
                break
            resource_template, action = route
            resource = resource_template.format(*match.groups())
            if resource.startswith("workflow/"):
                ref = (params.get("inputs") or {}).get("ref")
                if ref is not None and "ref" not in metadata:
                    metadata["ref"] = ref
            return InfrastructureIntent(
                resource=resource, action=action, provider="github",
                params=params, metadata=metadata,
            )
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
        return from_az_multi(argv)
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
