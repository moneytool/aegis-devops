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

**Names kubectl resolves at run time.** ``params["resolved_at_runtime"]``
marks an intent whose real targets kubectl only finds when it runs, with the
``kinds`` they can be. ``kubectl exec deploy/web`` (also ``attach``,
``port-forward``, ``logs``, any kind but a pod) runs on a pod behind the name: besides
``deployment/web`` it yields ``pod/*``, marked, so ``pod/*`` rules match and a
rule on one pod, which cannot be decided here, escalates
(``target-unresolved: <id>``). The categories ``all`` and ``api-extensions``
yield one ``kind/*`` per kind in them, as a comma list does, plus a marked
``all/*``, so a rule on one object of those kinds, or on a custom kind that
may have joined the category, escalates too. Any other ``kind/*`` (``--all``,
a selector, or a kind with no name, as in ``get pods`` or ``rollout restart
deploy``) is marked with its own kind, since kubectl may pick any object of it:
a rule on ``kind/*`` decides as usual, and a rule on one object escalates.
``kubectl describe pod pay`` falls back to every pod whose name starts with
``pay`` when no pod is called that, so its mark carries ``name_prefix`` and a
rule that can name such a pod escalates. A kind outside the built-in table may
be the plural or short name of any custom kind, so on the verbs that take a
custom resource its mark carries ``custom_kinds``, and a rule on a custom kind
escalates unless its name rules out the one written. None of this adds anything
when no rule is about the action and kind.

**Pods in other words.** ``kubectl cp`` names its pod in ``[ns/]pod:path`` on
either side, as kubectl itself reads it (:func:`_cp_pod`), and the namespace
written there counts as ``-n``. ``kubectl debug web`` is ``pod/web``, and
``--copy-to`` also reaches the copy it names. Both also keep the target earlier
versions gave them (``web:/a``, ``web/*``) as an intent of its own, so a signed
rule on that resource keeps its verdict. A plan ratio over them can still change.

**Words after ``--``.** Only ``exec``, ``run``, ``create`` and ``debug`` ask
kubectl where the ``--`` was (``ArgsLenAtDash``). Every other kubectl verb gets
those words as plain operands, so on the verbs in
:data:`_KUBECTL_OPERAND_VERBS` they count as operands: ``kubectl describe pod a
-- b`` names two pods. With nothing before the ``--`` the command stays refused.

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
absent, so a "real run" rule fires. The last one decides (#75): pflag and
argparse read a repeated flag that way, so ``--dry-run=client --dry-run=none``
is a real run, and ``--dry-run --no-dry-run`` is too where the tool has it.

**Short kubectl, helm, flux and argocd flags (#75).** pflag reads a short word letter
by letter: ``-qnprod`` is ``-q -n prod``, and ``-fp`` on ``logs`` is ``-f -p``. A
letter that takes a value ends the word and the rest is its value. So each walker
splits a short word as it reaches it, from one table of letters per tool, and a
word with an unknown letter in front of a value letter or ``A`` is refused.

**Flags the parser has no entry for (#80).** How to add a flag a later release of a tool
brings is in docs/cli.md ("Updating the flag tables"). kubectl, helm, flux and argocd each have
tables of every long flag that takes a value and every one that does not, read from
the tool's source. A value flag takes the next word whatever it looks like
(``--description -ndev``). A flag in no table is refused unless ``=value`` or its
place at the end shows its reading (:func:`_other_flag`), since the next word is its
value or an operand depending on what the flag is. Words after ``--`` are operands.
git's options are read as its parse-options reads them (:func:`_parse_git_options`),
aws and az as Python's argparse reads them, prefixes included, and terraform's as Go's
flag package does.

**Several manifests (#75).** ``--filename`` is a StringSlice, so ``-f a -f b`` and
``-f a,b`` are one ``manifest/<name>`` intent per file. ``--kustomize`` is a plain
string, so its last value is the one.

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

import csv
import hashlib
import io
import json
import re
from collections.abc import Collection
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

# Every built-in kind with its plural and short names. A fixed copy of `kubectl
# api-resources` (kubectl 1.36, kind server 1.37), so it needs refreshing when
# Kubernetes adds a kind: one missing from here counts as a possible custom kind.
_KUBECTL_BUILTIN_KINDS: dict[str, tuple[str, ...]] = {
    "apiservice": ("apiservices",),
    "binding": ("bindings",),
    "certificatesigningrequest": ("certificatesigningrequests", "csr"),
    "clusterrole": ("clusterroles",),
    "clusterrolebinding": ("clusterrolebindings",),
    "clustertrustbundle": ("clustertrustbundles",),
    "componentstatus": ("componentstatuses", "cs"),
    "configmap": ("configmaps", "cm"),
    "controllerrevision": ("controllerrevisions",),
    "cronjob": ("cronjobs", "cj"),
    "csidriver": ("csidrivers",),
    "csinode": ("csinodes",),
    "csistoragecapacity": ("csistoragecapacities",),
    "customresourcedefinition": ("customresourcedefinitions", "crd", "crds"),
    "daemonset": ("daemonsets", "ds"),
    "deployment": ("deployments", "deploy"),
    "deviceclass": ("deviceclasses",),
    "devicetaintrule": ("devicetaintrules",),
    "endpoints": ("ep",),
    "endpointslice": ("endpointslices",),
    "event": ("events", "ev"),
    "flowschema": ("flowschemas",),
    "horizontalpodautoscaler": ("horizontalpodautoscalers", "hpa"),
    "ingress": ("ingresses", "ing"),
    "ingressclass": ("ingressclasses",),
    "ipaddress": ("ipaddresses", "ip"),
    "job": ("jobs",),
    "lease": ("leases",),
    "limitrange": ("limitranges", "limits"),
    "localsubjectaccessreview": ("localsubjectaccessreviews",),
    "mutatingadmissionpolicy": ("mutatingadmissionpolicies",),
    "mutatingadmissionpolicybinding": ("mutatingadmissionpolicybindings",),
    "mutatingwebhookconfiguration": ("mutatingwebhookconfigurations",),
    "namespace": ("namespaces", "ns"),
    "networkpolicy": ("networkpolicies", "netpol"),
    "node": ("nodes", "no"),
    "persistentvolume": ("persistentvolumes", "pv"),
    "persistentvolumeclaim": ("persistentvolumeclaims", "pvc"),
    "pod": ("pods", "po"),
    "podcertificaterequest": ("podcertificaterequests",),
    "poddisruptionbudget": ("poddisruptionbudgets", "pdb"),
    "podtemplate": ("podtemplates",),
    "priorityclass": ("priorityclasses", "pc"),
    "prioritylevelconfiguration": ("prioritylevelconfigurations",),
    "replicaset": ("replicasets", "rs"),
    "replicationcontroller": ("replicationcontrollers", "rc"),
    "resourceclaim": ("resourceclaims",),
    "resourceclaimtemplate": ("resourceclaimtemplates",),
    "resourcequota": ("resourcequotas", "quota"),
    "resourceslice": ("resourceslices",),
    "role": ("roles",),
    "rolebinding": ("rolebindings",),
    "runtimeclass": ("runtimeclasses",),
    "secret": ("secrets",),
    "selfsubjectaccessreview": ("selfsubjectaccessreviews",),
    "selfsubjectreview": ("selfsubjectreviews",),
    "selfsubjectrulesreview": ("selfsubjectrulesreviews",),
    "service": ("services", "svc"),
    "serviceaccount": ("serviceaccounts", "sa"),
    "servicecidr": ("servicecidrs",),
    "statefulset": ("statefulsets", "sts"),
    "storageclass": ("storageclasses", "sc"),
    "storageversionmigration": ("storageversionmigrations",),
    "subjectaccessreview": ("subjectaccessreviews",),
    "tokenreview": ("tokenreviews",),
    "validatingadmissionpolicy": ("validatingadmissionpolicies",),
    "validatingadmissionpolicybinding": ("validatingadmissionpolicybindings",),
    "validatingwebhookconfiguration": ("validatingwebhookconfigurations",),
    "volumeattachment": ("volumeattachments",),
    "volumeattributesclass": ("volumeattributesclasses", "vac"),
}

# Plural and short names normalised to the singular kind.
_RESOURCE_ALIASES = {
    spelling: kind for kind, spellings in _KUBECTL_BUILTIN_KINDS.items() for spelling in spellings
}

# Every spelling of a built-in kind.
_KUBECTL_BUILTIN_NAMES = frozenset(_KUBECTL_BUILTIN_KINDS) | frozenset(_RESOURCE_ALIASES)

# kubectl flags that take no value token when given without "=value": the
# boolean flags of every kubectl command (from kubectl 1.36's --help on each of
# them), plus the flags pflag gives a default for a bare use (--cascade,
# --validate, --embed-certs, ...). "containers" and "prefix" are strings only
# under "set env" / "set resources", which the parser does not accept, and
# "command" only under "kuberc set" (see _parse_flags).
_KNOWN_BOOL_FLAGS = {
    "all", "all-containers", "all-pods", "allow-missing-template-keys", "append-hash",
    "append-server-path", "arguments-only", "as-current-user", "attach", "cached", "cascade",
    "client", "command", "containers", "create-annotation", "current",
    "delete-emptydir-data", "delete-local-data",
    "disable-eviction", "disable-filter", "edit", "embed-certs", "enable-alpha-plugins",
    "enable-helm", "exec-provide-cluster-info",
    "expose", "flatten", "follow", "force", "force-conflicts", "global-default", "helm-debug",
    "ignore-daemonsets", "ignore-errors", "ignore-not-found",
    "insecure-skip-tls-verify-backend", "interactive", "keep-annotations",
    "keep-init-containers", "keep-labels", "keep-liveness", "keep-readiness", "keep-startup",
    "leave-stdin-open", "list", "local", "merge", "minify", "name-only", "namespaced",
    "network",
    "no-headers", "no-preserve", "now", "openapi-patch", "output-patch",
    "output-watch-events", "overwrite", "prefix", "previous", "privileged", "prune", "quiet",
    "record", "recursive", "remove-extra-permissions", "remove-extra-subjects", "replace",
    "resolve", "rm", "same-node", "save-config", "server-print", "server-side",
    "set-raw-bytes", "share-processes", "show-capacity", "show-events",
    "show-kind", "show-labels", "show-managed-fields", "show-secrets", "show-swap", "stdin",
    "sum", "timestamps", "tty", "use-protocol-buffers", "validate", "wait", "watch",
    "watch-only", "windows-line-endings",
}

# kubectl flags that always take the next token as their value, even one
# that starts with "-" (pflag does: "--field-manager -n x" sets the field
# manager to "-n"). Recorded in params like any other flag value. Scope,
# selector, manifest, impersonation and discarded global flags are handled
# by name before this table is consulted.
_KUBECTL_VALUE_FLAGS = {
    "accept-hosts", "accept-paths", "address", "aggregation-rule", "allowlist-entry",
    "annotation", "annotations", "api-group", "api-prefix", "api-version", "appendarg",
    "as-user-extra", "audience", "auth-provider", "auth-provider-arg", "bound-object-kind",
    "bound-object-name", "bound-object-uid", "categories", "cert", "chunk-size", "class",
    "cluster-ip", "clusterip", "clusterrole", "concurrency", "container", "copy-to", "cpu",
    "current-replicas", "custom", "default-backend", "description", "detach-keys",
    "docker-email", "docker-password", "docker-server", "docker-username", "duration", "env",
    "exec-api-version", "exec-arg", "exec-command", "exec-env", "exec-interactive-mode",
    "external-ip", "external-name", "field-manager", "for", "from", "from-env-file",
    "from-file", "from-literal", "grace-period", "group", "hard", "helm-api-versions",
    "helm-command", "helm-kube-version", "image", "image-pull-policy", "keepalive", "key",
    "keys", "kuberc", "label-columns", "labels", "limit-bytes", "limits", "load-balancer-ip",
    "load-restrictor", "max", "max-log-requests", "max-unavailable", "memory", "min",
    "min-available", "mount", "name", "namespaces", "network-name", "node-port",
    "non-resource-url", "option", "output-directory", "override-type", "overrides", "patch",
    "patch-file", "pod-running-timeout", "pod-selector", "policy", "port", "preemption-policy",
    "prependarg", "protocol", "proxy-url", "prune-allowlist", "raw", "reject-methods",
    "reject-paths", "replicas", "requests", "resource", "resource-name", "resource-version",
    "restart", "retries", "revision", "role", "rule", "schedule", "scopes", "section",
    "serviceaccount", "session-affinity", "set-image", "since", "since-time",
    "skip-wait-for-delete-timeout", "sort-by", "subresource", "tail", "target",
    "target-port", "tcp", "template", "timeout", "to-revision", "type", "types",
    "unix-socket", "value", "verb", "verbs", "vmodule", "www", "www-prefix",
    # short forms: -c container, -L label-columns
    "c", "L",
}

# kubectl's integer flags (kubectl 1.36). pflag reads them with base 0, so
# "--replicas=0x0" is 0: see _go_int. --port is a string on expose and run.
_KUBECTL_INT_FLAGS = {
    "chunk-size", "concurrency", "current-replicas", "grace-period", "limit-bytes", "max",
    "max-log-requests", "min", "replicas", "retries", "revision",
    "skip-wait-for-delete-timeout", "tail", "to-revision",
}
# Short value flags, recorded under their long name ("-p" only on patch).
_KUBECTL_SHORT_VALUE_NAMES = {
    "c": "container", "L": "label-columns", "p": "patch", "r": "replicas",
}

# kubectl verbs whose short "-f" is the boolean --follow, not --filename.
_KUBECTL_FOLLOW_VERBS = {"logs"}

# What Go's strconv.ParseBool reads as false, which is how kubectl reads a boolean
# flag's value. It refuses any other word that is not one of its true spellings.
_GO_FALSE_WORDS = frozenset({"0", "f", "F", "FALSE", "false", "False"})

# Global boolean flags that are consumed but not recorded anywhere.
_DISCARD_BOOL_FLAGS = {
    "insecure-skip-tls-verify",
    "warnings-as-errors",
    "match-server-version",
    "disable-compression",
}

# Global flags whose value is consumed but not recorded anywhere.
_DISCARD_VALUE_FLAGS = {
    "o",
    "output",
    "s",
    "server",
    "v",
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

# kubectl impersonation flags, recorded in params["impersonate"].
_IMPERSONATION_FLAGS = {"as", "as-uid", "as-group"}

# Flags that point at a manifest (file or kustomize directory).
_MANIFEST_FLAGS = {"f", "filename", "k", "kustomize"}

# Flags carrying environment identity, recorded in metadata.
_KUBECTL_IDENTITY_FLAGS = {"n", "namespace", "context", "cluster", "kubeconfig"}

# Selector flags: value flags recorded in params; the target becomes kind/*.
_SELECTOR_FLAGS = {"l": "selector", "selector": "selector", "field-selector": "field_selector"}

# Every global option kubectl accepts in front of the verb, split by arity.
_KUBECTL_GLOBAL_VALUE_FLAGS = _KUBECTL_IDENTITY_FLAGS | _DISCARD_VALUE_FLAGS | _IMPERSONATION_FLAGS
_KUBECTL_GLOBAL_BOOL_FLAGS = {"A", "all-namespaces"} | _DISCARD_BOOL_FLAGS

# Which short letters take a value and which stand alone, from kubectl 1.36's --help
# on every command. A letter that takes a value ends a short word, and the rest of
# the word is its value (-nprod, -lapp=web, -fx.yaml). A boolean letter lets the word
# go on: -qnprod is -q -n prod. "f", "p" and "r" depend on the command: see
# _unbundle_short_word. Left out on purpose: -p, -P, -u and -w's value form on proxy,
# which the parser refuses without a target anyway.
_KUBECTL_SHORT_VALUE_LETTERS = frozenset("Lcefklnosv")
_KUBECTL_SHORT_BOOL_LETTERS = frozenset("ARhiqtw")

# Verbs whose target is a pod by default: a bare name is a pod
# ("exec api-0" -> pod/api-0), and "deploy/web" / "svc/web" normalise like
# any other kind/name token.
_POD_TARGET_VERBS = {"exec", "logs", "port-forward", "attach"}

# Of those, the ones whose kind/name kubectl resolves to a pod behind it, for a
# rule on that verb to decide (see "Names kubectl resolves at run time" above).
_POD_RESOLVING_VERBS = {"exec", "port-forward", "attach", "logs"}

# Verbs whose words after "--" are operands like any other, read from kubectl's
# source and checked on kubectl 1.36: `kubectl get pod/a -- b` fails as `get pod/a b`
# does. exec, run, create and debug use ArgsLenAtDash, so "--" starts a command there.
# logs and port-forward read their target from the first word only, top refuses a
# second one, and attach (at most two words) is handled where it is parsed.
_KUBECTL_OPERAND_VERBS = {
    "annotate", "autoscale", "certificate", "cordon", "cp", "delete", "describe", "drain", "edit",
    "expose", "get", "label", "patch", "rollout", "scale", "set", "taint", "uncordon", "wait",
}

# Verbs that take TYPE [NAME] and work on a custom resource. The kind they are
# given may be a plural or short name no table here can resolve. `config view`
# also reaches the parser as kind/name, and is not about a kind.
_KUBECTL_CUSTOM_KIND_VERBS = {
    "annotate", "autoscale", "delete", "describe", "edit", "get", "label", "patch", "scale",
    "wait",
}

# The categories kubectl knows without any custom resource definition, from
# `kubectl api-resources --categories=...` (1.36, on kind 1.37). A custom resource
# can join either, or declare its own, which no list here can show.
_KUBECTL_CATEGORIES = {
    "all": (
        "pod", "replicationcontroller", "service", "daemonset", "deployment", "replicaset",
        "statefulset", "horizontalpodautoscaler", "cronjob", "job",
    ),
    "api-extensions": (
        "mutatingadmissionpolicy", "mutatingadmissionpolicybinding",
        "mutatingwebhookconfiguration", "validatingadmissionpolicy",
        "validatingadmissionpolicybinding", "validatingwebhookconfiguration",
        "customresourcedefinition", "apiservice",
    ),
}

# Verbs that act on nodes: a bare name is a node ("drain node1" ->
# node/node1), not a kind to list.
_NODE_TARGET_VERBS = {"cordon", "uncordon", "drain"}


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


def _record_dry_run(params: dict[str, Any], rehearsal: bool) -> None:
    """The last ``--dry-run`` decides, as it does in pflag and argparse, so a real
    run clears an earlier rehearsal: ``--dry-run=client --dry-run=none`` is real."""
    if rehearsal:
        params["dry_run"] = True
    else:
        params.pop("dry_run", None)


def _split_short_word(
    word: str, bools: frozenset[str], values: frozenset[str], tool: str
) -> list[str]:
    """One short-flag word as the separate flags pflag reads in it: ``-qnprod`` is
    ``-q -n=prod``, ``-qn`` is ``-q -n`` (with the value in the next token) and ``-n=``
    is namespace ``=``, since pflag only strips a ``=`` that has something after it.
    The result needs no more splitting, so ``-n=prod`` comes back as it is.

    A letter in neither set makes the tool stop with an error, so nothing after it
    counts: it is dropped, as an unknown short flag always was. A later version could
    give that letter a meaning, though, and then a value letter or ``A`` behind it
    could be real. That word is refused, since which it would be cannot be told."""
    flags: list[str] = []
    rest = word[1:]
    while rest:
        letter, rest = rest[0], rest[1:]
        if len(rest) > 1 and rest[0] == "=":
            flags.append(f"-{letter}{rest}")
            break
        if letter in values:
            flags.append(f"-{letter}={rest}" if rest else f"-{letter}")
            break
        if letter not in bools:
            if any(c == "A" or c in values for c in rest):
                raise ValueError(
                    f"{tool}: cannot tell what {word!r} means: {letter!r} is not a short "
                    f"flag known on this command, and {rest!r} follows it"
                )
            break
        flags.append(f"-{letter}")
    return flags


def _other_flag(
    tokens: list[str], i: int, *, values: Collection[str], bools: Collection[str], tool: str,
) -> tuple[int, Any]:
    """A flag no branch of a pflag tool's walker reads by name, at ``tokens[i]``: the
    index of its last token and the value to record, as pflag reads it.

    A flag in ``bools`` takes no value token (it may carry ``=value``), and one in
    ``values`` always takes the next token, whatever it looks like: ``--description
    -ndev`` is the description ``-ndev``. A flag in neither is unknown to the parser,
    and then only ``=value``, or being the last word, says how to read it. Otherwise
    the next word is its value if it takes one, and a flag, a name or an operand if it
    does not, so the namespace, target or rehearsal read could be the wrong one either
    way: the command is refused (#80). A short flag ``-x`` gets the same reading. Each
    table must hold every flag the tool has, so this only refuses a flag the tool does
    not have, which it refuses too, or one a later version added."""
    tok = tokens[i]
    key, val = _split_flag(tok)
    if key in bools:
        return i, _bool_param(val)
    if key in values:
        if val is None:
            i += 1
            val = _value_at(tokens, i, tok)
        return i, _coerce(val)
    if val is not None:
        return i, _coerce(val)
    if i + 1 >= len(tokens):
        return i, True
    raise ValueError(
        f"{tool}: cannot tell whether {tok!r} takes a value (next word {tokens[i + 1]!r}); "
        f"write {tok}=<value> or put {tok} last: {tokens!r}"
    )


# What Go's strconv.ParseInt accepts with base 0, which is how pflag reads every
# integer flag: a sign, then 0x/0o/0b or a leading 0 (octal) for the base, and "_"
# only between digits (or after the base prefix).
_GO_INT_RE = re.compile(
    r"[+-]?(?:0[xX](?:_?[0-9a-fA-F])+|0[bB](?:_?[01])+|0[oO](?:_?[0-7])+|0(?:_?[0-7])*"
    r"|[1-9](?:_?[0-9])*)"
)


def _go_int(text: str, flag: str, bits: int = 64) -> int:
    """``text`` as pflag's integer flags read it (``strconv.ParseInt(text, 0, bits)``):
    ``0xf`` is 15, ``017`` is 15 and ``1_0`` is 10. Anything Go refuses (``08``,
    ``" 5"``, ``1e3``, a number out of range) is a ValueError, since the tool refuses it
    and runs nothing."""
    if not _GO_INT_RE.fullmatch(text):
        raise ValueError(f"{flag}: {text!r} is not a number the tool accepts")
    sign = -1 if text[0] == "-" else 1
    digits = text.lstrip("+-").replace("_", "")
    if len(digits) > 1 and digits[0] == "0" and digits[1] in "0123456789_":
        digits = "0o" + digits[1:]
    value = sign * int(digits, 0)
    if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise ValueError(f"{flag}: {text!r} is out of range")
    return value


def _kubectl_short_letters(
    verb: str | None, *, replicas: bool = False
) -> tuple[frozenset[str], frozenset[str]]:
    """kubectl's boolean and value letters on ``verb``. ``replicas`` says ``-r`` is
    ``--replicas`` here (``create deployment``). ``proxy`` has letters of its own that
    are not listed, and is refused without a target anyway."""
    bools = _KUBECTL_SHORT_BOOL_LETTERS
    values = _KUBECTL_SHORT_VALUE_LETTERS
    if verb in _KUBECTL_FOLLOW_VERBS:  # logs -f is --follow and -p is --previous
        bools, values = bools | {"f", "p"}, values - {"f"}
    elif verb == "patch":
        values = values | {"p"}
    elif replicas:
        values = values | {"r"}
    return bools, values


def _unbundle_short_word(word: str, verb: str | None, *, replicas: bool = False) -> list[str]:
    """:func:`_split_short_word` with kubectl's letters (:func:`_kubectl_short_letters`)."""
    bools, values = _kubectl_short_letters(verb, replicas=replicas)
    return _split_short_word(word, bools, values, "kubectl")


def _helm_short_letters(verb: str | None) -> tuple[frozenset[str], frozenset[str]]:
    """Helm's short letters: ``-a`` is a value on ``template`` and a boolean on ``list``
    (helm 3) and ``get values``."""
    if verb == "template":
        return _HELM_SHORT_BOOL_LETTERS, _HELM_SHORT_VALUE_LETTERS | {"a"}
    return _HELM_SHORT_BOOL_LETTERS | {"a"}, _HELM_SHORT_VALUE_LETTERS


def _flux_short_letters(verb: str | None) -> tuple[frozenset[str], frozenset[str]]:
    """Flux's short letters: ``-f`` is only a flag on ``logs`` of the verbs parsed here."""
    if verb == "logs":
        return _FLUX_SHORT_BOOL_LETTERS | {"f"}, _FLUX_SHORT_VALUE_LETTERS
    return _FLUX_SHORT_BOOL_LETTERS, _FLUX_SHORT_VALUE_LETTERS


def _read_string_slice(value: str) -> list[str]:
    """A pflag StringSlice value: one CSV record, so ``a,b`` is two and ``"a,b"`` is one.
    An empty value is no entries, as pflag reads it, so ``--filename= -f x.yaml`` is only
    ``x.yaml``."""
    if not value:
        return []
    try:
        return next(csv.reader(io.StringIO(value, newline=""))) or [value]
    except (csv.Error, StopIteration) as err:
        raise ValueError(f"cannot read the list {value!r}: {err}") from err


def _split_leading_globals(
    tokens: list[str],
    *,
    value_flags: set[str],
    bool_flags: set[str],
    tool: str,
    glued_values: bool = False,
) -> tuple[list[str], list[str]]:
    """Splits ``tokens`` into ``(leading_global_option_tokens, rest)`` where
    ``rest[0]`` is the tool's verb.

    A leading option is consumed as ``--flag=value`` (one token), or as
    ``--flag value`` when its key is in ``value_flags``, or as a bare
    boolean when its key is in ``bool_flags``. Anything else that starts
    with ``-`` before the verb is a ``ValueError``: guessing whether an
    unknown option swallows the next token is exactly how a verb gets
    misidentified. Raises ``ValueError`` when no verb follows the options,
    or when the option's value is missing. With ``glued_values``, a single-letter
    key in ``value_flags`` may carry its value in the same token (``-nprod``)."""
    i = 0
    n = len(tokens)
    while i < n and tokens[i].startswith("-") and tokens[i] != "-":
        tok = tokens[i]
        key, val = _split_flag(tok)
        if glued_values and len(tok) > 2 and tok[1] in value_flags and tok[2] != "=":
            i += 1
        elif val is not None and (key in value_flags or key in bool_flags):
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


def _is_pair_operand(token: str) -> bool:
    """Whether a word given to ``label``, ``annotate`` or ``set image`` is
    ``key=value`` or ``key-`` and not a resource, as kubectl decides it."""
    return ("=" in token and token[0] != "=") or (token.endswith("-") and token != "-")


def _is_taint_operand(token: str) -> bool:
    """The same for ``taint``, which also takes ``key:effect``."""
    return "=" in token or ":" in token or token.endswith("-")


def _expand_categories(resources: list[str]) -> list[str]:
    """Adds the kinds behind a category to ``kind/*`` resources: ``all/*`` keeps
    its place, followed by one ``kind/*`` per kind in it. A category with a
    name is refused: kubectl refuses ``all/web`` and ``all web`` too."""
    out: dict[str, None] = {}
    for resource in resources:
        kind, _, name = resource.partition("/")
        out[resource] = None
        if kind in _KUBECTL_CATEGORIES:
            if name != "*":
                raise ValueError(f"the category {kind!r} cannot be combined with a name: "
                                 f"{resource!r}")
            out.update((f"{k}/*", None) for k in _KUBECTL_CATEGORIES[kind])
    return list(out)


def _bare_flag(tokens: list[str], i: int) -> bool:
    """Whether the flag at ``tokens[i]`` has no value token after it: it is
    the last token, or the next token is another option (or ``--``)."""
    return i + 1 >= len(tokens) or (tokens[i + 1].startswith("-") and tokens[i + 1] != "-")


def _parse_flags(
    tokens: list[str], *, verb: str | None = None, raw_copy_to: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str], list[str] | None]:
    """Walks kubectl tokens (after the verb/subverb), splitting them into
    metadata, params, positional args, the manifest files or directory they name,
    and an optional trailing ``--`` command. ``raw_copy_to`` receives ``--copy-to``
    as written, since a pod name "001" is not the number in params."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    manifest_files: list[str] = []
    kustomize: str | None = None
    command: list[str] | None = None

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    # Found once here: kubectl also takes -r3 in front of the subcommand.
    replicas_short = verb == "create" and ("deployment" in tokens or "deploy" in tokens)
    short_bools, short_values = _kubectl_short_letters(verb, replicas=replicas_short)
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            command = tokens[i + 1 :]
            break
        if tok.startswith("-") and tok != "-":
            is_long = tok.startswith("--")
            if not is_long and len(tok) > 2:
                # Here and not before the walk: "--context -nprod" is a context
                # called "-nprod", which only the flag before it can show.
                flags = _unbundle_short_word(tok, verb, replicas=replicas_short)
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
            key, val = _split_flag(tok)
            if key in ("n", "namespace"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key in ("A", "all-namespaces"):
                if val in _GO_FALSE_WORDS:
                    metadata.pop("all_namespaces", None)
                else:
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
            elif key == "kubeconfig":
                # Which kubeconfig kubectl reads: --resolve-current-context
                # must take the context and namespace from this file only.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["kubeconfig"] = val
            elif key == "dry-run":
                # bare --dry-run, --dry-run=client, --dry-run=server (and the
                # deprecated --dry-run=true) are rehearsals; --dry-run=none /
                # =false is a real run.
                _record_dry_run(params, _is_dry_run(val, truthy=_KUBECTL_DRY_RUN_WORDS))
            elif key == "f" and verb in _KUBECTL_FOLLOW_VERBS:
                # kubectl logs -f is --follow, a boolean.
                params["follow"] = _bool_param(val)
            elif key in _SELECTOR_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[_SELECTOR_FLAGS[key]] = val
            elif key in _MANIFEST_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # --filename is a StringSlice, so every one counts and each may be a list.
                # --kustomize is a plain string, so the last one counts.
                if key in ("f", "filename"):
                    manifest_files.extend(_read_string_slice(val))
                else:
                    kustomize = val
            elif key in _IMPERSONATION_FLAGS:
                # kubectl --as / --as-group / --as-uid: the request runs as
                # someone else. Recorded (never silently dropped), so a
                # policy or a server-side check can see it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                imp = params.setdefault("impersonate", {})
                if key == "as-group":
                    imp.setdefault("groups", []).append(val)
                else:
                    imp["user" if key == "as" else "uid"] = val
            elif key in _DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
            elif key in _DISCARD_BOOL_FLAGS:
                pass
            elif key == "expose" and verb == "run":
                # Only a spelling kubectl reads as false turns the Service off. It
                # refuses a word like "no", so reading that as on creates nothing.
                params[key] = val not in _GO_FALSE_WORDS
            elif ((key in _KNOWN_BOOL_FLAGS and not (key == "command" and verb == "kuberc"))
                  or (key == "raw" and verb == "config")):
                params[key] = _bool_param(val)
            elif (key in _KUBECTL_VALUE_FLAGS or (key == "p" and verb == "patch")
                  or (key == "r" and replicas_short) or key == "command"):
                # Always the next token, even "-1" or "--context": that is
                # what kubectl does with it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                name = _KUBECTL_SHORT_VALUE_NAMES.get(key, key)
                if name in _KUBECTL_INT_FLAGS or (name == "port" and replicas_short):
                    # create deployment's --replicas and --port are Int32, the others Int
                    # or Int64; --port is a string on expose and run
                    bits = 32 if replicas_short and name in ("replicas", "port") else 64
                    params[name] = _go_int(val, f"kubectl {tok}", bits)
                else:
                    params[name] = _coerce(val)
                if key == "copy-to" and raw_copy_to is not None:
                    raw_copy_to[:] = [val]
            elif not is_long and key in short_bools:
                pass  # -i, -t, -q, -R, -w ...: nothing a rule reads
            elif not is_long and key in short_values:
                # -e (env): always the next token, as pflag reads it
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = _coerce(val)
            elif is_long or i + 1 < len(tokens) or val is not None:
                # Unknown to the parser. Refused unless "=value" or its place at the
                # end shows how kubectl would read it (see _other_flag).
                i, params[key] = _other_flag(tokens, i, values=(), bools=(), tool="kubectl")
            # else: an unknown short flag at the end -- ignored (kubectl refuses it).
        else:
            positional.append(tok)
        i += 1

    manifests = manifest_files + ([kustomize] if kustomize is not None else [])
    return metadata, params, positional, manifests, command


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


def _mark_open_targets(
    intents: list[InfrastructureIntent], *, custom_kinds: bool = False
) -> list[InfrastructureIntent]:
    """Marks the ``kind/*`` intents: which objects they reach is only known when
    kubectl runs. A category's kinds need no mark of their own: its intent has
    them all. With ``custom_kinds``, a kind outside the built-in table is marked
    too, also with a name: which kind it spells is only known when kubectl runs."""
    covered = {k for intent in intents if intent.resource.endswith("/*")
               for k in _KUBECTL_CATEGORIES.get(intent.resource[:-2], ())}
    for intent in intents:
        kind, _, name = intent.resource.partition("/")
        unknown_kind = custom_kinds and kind not in _KUBECTL_BUILTIN_NAMES
        if kind in _KUBECTL_CATEGORIES and name == "*":
            intent.params["resolved_at_runtime"] = {
                "from": kind, "kinds": list(_KUBECTL_CATEGORIES[kind]), "custom_kinds": True,
            }
        elif name == "*" and kind not in covered:
            intent.params["resolved_at_runtime"] = {"from": intent.resource, "kinds": [kind]}
            if unknown_kind:
                intent.params["resolved_at_runtime"]["custom_kinds"] = True
        elif name != "*" and unknown_kind:
            intent.params["resolved_at_runtime"] = {
                "from": intent.resource, "kinds": [kind], "name": name, "custom_kinds": True,
            }
    return intents


def _mark_name_prefix(intent: InfrastructureIntent, prefix: str) -> None:
    """``kubectl describe TYPE NAME`` with no object called NAME describes every
    object whose name starts with it. Only that two-word form does."""
    kind = intent.resource.partition("/")[0]
    target = {"from": intent.resource, "kinds": [kind], "name_prefix": prefix}
    if intent.params.get("resolved_at_runtime", {}).get("custom_kinds"):
        target["custom_kinds"] = True
    intent.params["resolved_at_runtime"] = target


def _cp_pod(operand: str) -> tuple[str, str] | None:
    """The ``(namespace, pod)`` in one ``kubectl cp`` operand, or None when it is
    a local path. kubectl's extractFileSpec decides by the first colon alone:
    with no colon it is local, and otherwise what comes before the colon is
    ``pod`` or ``ns/pod``, so ``./a:b`` is pod ``a``, in a namespace called
    ``.``. An empty pod name counts as local, and more than one slash, or a
    colon first, is an error (``/tmp/a:b``, ``:b``), so no pod is reached. An
    empty namespace means the one kubectl would use anyway."""
    before, colon, _ = operand.partition(":")
    pieces = before.split("/")
    if not colon or len(pieces) > 2 or not pieces[-1]:
        return None
    return (pieces[0] if len(pieces) == 2 else "", pieces[-1])


def _cp_intents(
    positional: list[str], params: dict[str, Any], metadata: dict[str, Any]
) -> list[InfrastructureIntent]:
    """One ``pod/<name>`` intent per pod named, on either side, then the first word
    as it is written: the target earlier versions gave, which a signed rule may
    name. With no pod, kubectl refuses the command, and only that word is left."""
    intents: list[InfrastructureIntent] = []
    for namespace, pod in filter(None, map(_cp_pod, positional)):
        where = {**metadata, "namespace": namespace} if namespace else metadata
        intents.extend(_make_intents([f"pod/{pod}"], "cp", params, where))
    return intents + _make_intents([positional[0]], "cp", params, metadata)


def _debug_intents(
    positional: list[str], raw_copy_to: list[str], params: dict[str, Any],
    metadata: dict[str, Any],
) -> list[InfrastructureIntent]:
    """``kubectl debug`` takes pods by bare name, or TYPE/NAME for a node.
    ``--copy-to`` runs in a new pod of that name. A node has no copy. The targets
    earlier versions gave (``web/*``) stay beside them, unmarked as they were, since
    a signed rule may name them, and what they refused stays refused."""
    earlier = _parse_resources(positional)
    targets = _default_kind_targets(positional, "pod")
    if raw_copy_to and raw_copy_to[0] and any(t.startswith("pod/") for t in targets):
        targets.append(f"pod/{raw_copy_to[0]}")
    return _make_intents(list(dict.fromkeys(targets + earlier)), "debug", params, metadata)


def _run_intents(
    positional: list[str], params: dict[str, Any], metadata: dict[str, Any]
) -> list[InfrastructureIntent]:
    """``kubectl run NAME`` creates a pod called NAME, whatever the word says, so it
    is never a category, and any words after it are arguments for that pod. A word
    with a slash is refused as a pod name, so it stays the kind/name it was read as.
    The targets earlier versions gave (``web/*``) stay beside the pod, unmarked as
    they were, since a signed rule may name them.

    ``--expose`` also creates a Service called NAME. kubectl creates the pod first and
    stops if that fails, so a word with a slash reaches no Service and adds none."""
    earlier = _parse_resources(positional)
    targets = _default_kind_targets(positional[:1], "pod")
    if params.get("expose") and "/" not in positional[0]:
        targets.append(f"service/{positional[0]}")
    return _make_intents(list(dict.fromkeys(targets + earlier)), "run", params, metadata)


def _default_kind_targets(positional: list[str], kind: str) -> list[str]:
    """``kind/<word>`` for a bare word, ``<kind>/<name>`` normalised for TYPE/NAME."""
    targets = []
    for token in positional:
        token_kind, name = _split_resource_token(token)
        targets.append(f"{token_kind}/{name}" if name is not None else f"{kind}/{token}")
    return targets


def from_kubectl_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a kubectl invocation into one InfrastructureIntent per target
    resource (kubectl commands may name more than one, e.g.
    ``kubectl delete pod/a pod/b``).

    With ``--as`` / ``--as-group`` / ``--as-uid`` the request runs as
    someone else, which moves it out of an agent identity's scope on the
    server side. So besides the action itself, each impersonated identity
    becomes its own ``impersonate`` intent (``user/<name>``,
    ``group/<name>``, ``uid/<id>``) that a policy can block or escalate."""
    intents = _from_kubectl_multi(argv)
    seen: set[str] = set()
    extra: list[InfrastructureIntent] = []
    for intent in intents:
        imp = intent.params.get("impersonate") or {}
        targets = ([f"user/{imp['user']}"] if "user" in imp else []) + [
            f"group/{g}" for g in imp.get("groups", [])
        ] + ([f"uid/{imp['uid']}"] if "uid" in imp else [])
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            extra.append(InfrastructureIntent(
                resource=target, action="impersonate", provider="kubernetes",
                params={"impersonate": imp}, metadata=dict(intent.metadata),
            ))
    return intents + extra


def _from_kubectl_multi(argv: list[str]) -> list[InfrastructureIntent]:
    if len(argv) < 2 or not (argv[0] == "kubectl" or argv[0].endswith("/kubectl")):
        raise ValueError(f"not a recognizable kubectl invocation: {argv!r}")

    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_KUBECTL_GLOBAL_VALUE_FLAGS,
        bool_flags=_KUBECTL_GLOBAL_BOOL_FLAGS,
        tool="kubectl",
        glued_values=True,
    )
    verb = rest[0]
    after_verb = rest[1:]

    # A subcommand ("rollout restart", "set image") is the token right after
    # the verb, so it is taken from the post-verb tokens *before* the leading
    # global options are merged back in -- otherwise "kubectl -n prod rollout
    # restart x" would read "-n" as the subcommand.
    # kubectl also accepts global options *between* the verb and its
    # subcommand ("kubectl rollout --as admin restart x"), so those are
    # consumed the same way as leading ones and kept for the flag walker.
    subverb = None
    if verb in ("rollout", "set"):
        if not after_verb:
            raise ValueError(f"kubectl {verb} requires a subcommand: {argv!r}")
        between, sub_rest = _split_leading_globals(
            after_verb,
            value_flags=_KUBECTL_GLOBAL_VALUE_FLAGS,
            bool_flags=_KUBECTL_GLOBAL_BOOL_FLAGS,
            tool="kubectl",
            glued_values=True,
        )
        subverb, after_verb = sub_rest[0], between + sub_rest[1:]
        if verb == "set":
            if subverb != "image":
                raise ValueError(f"unsupported 'kubectl set' invocation: {argv!r}")
            subverb = None

    # Global options are parsed by the same flag walker as post-verb flags,
    # so "-n prod delete x" and "delete x -n prod" produce identical intents.
    tokens = leading + after_verb

    raw_copy_to: list[str] = []
    metadata, params, positional, manifests, command = _parse_flags(
        tokens, verb=verb, raw_copy_to=raw_copy_to)
    # attach takes at most two words, and a second one after "--" is its NAME.
    attach_name_after_dash = (verb == "attach" and len(positional) == 1
                              and command is not None and len(command) == 1)
    if positional and command and (verb in _KUBECTL_OPERAND_VERBS or attach_name_after_dash):
        positional = positional + command
    elif command is not None:
        params["command"] = command

    if manifests and verb in ("apply", "create", "replace", "delete"):
        # The objects are in the manifest, which is not read: kind- and
        # name-based rules escalate on it (manifest-not-inspected).
        intents: list[InfrastructureIntent] = []
        for manifest in manifests:
            basename = manifest if manifest == "-" else Path(manifest).name
            with_file = {**params, "file": manifest, "manifest_not_inspected": True}
            intents.extend(_make_intents([f"manifest/{basename}"], verb, with_file, metadata))
        return intents

    if verb == "rollout":
        resources = _expand_categories(_parse_resources(positional))
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _mark_open_targets(_make_intents(resources, f"rollout-{subverb}", params, metadata))

    if verb == "cp":
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _cp_intents(positional, params, metadata)

    if verb == "debug":
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _debug_intents(positional, raw_copy_to, params, metadata)

    if verb == "run":
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _run_intents(positional, params, metadata)

    if not positional and params.get("selector") is not None and (
            verb == "logs" or verb in _NODE_TARGET_VERBS):
        # kubectl logs -l app=x reads every pod the selector matches, in the namespace
        # it would use anyway (logs has no -A), and cordon, uncordon and drain -l act on
        # every node it matches. Checked on kubectl 1.36 against a local stub server.
        kind = "pod" if verb == "logs" else "node"
        return _mark_open_targets(_make_intents([f"{kind}/*"], verb, params, metadata))

    if verb in _POD_TARGET_VERBS:
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        kind, name = _split_resource_token(positional[0])
        if verb == "attach" and len(positional) == 2:
            # attach alone also reads two words as TYPE NAME; exec and
            # port-forward take the first as the pod.
            name = positional[1]
        target = f"{kind}/{name}" if name is not None else f"pod/{positional[0]}"
        intents = _make_intents([target], verb, params, metadata)
        if verb in _POD_RESOLVING_VERBS and name is not None and kind != "pod":
            behind = {**params, "resolved_at_runtime": {"from": target, "kinds": ["pod"]}}
            intents.extend(_make_intents(["pod/*"], verb, behind, metadata))
        if attach_name_after_dash:
            # What this was read as before: a rule on it keeps its verdict.
            first_kind, first_name = _split_resource_token(positional[0])
            earlier = (f"{first_kind}/{first_name}" if first_name is not None
                       else f"pod/{positional[0]}")
            intents.extend(_make_intents([earlier], verb, params, metadata))
        return intents

    if verb in _NODE_TARGET_VERBS:
        if not positional:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        return _make_intents(_default_kind_targets(positional, "node"), verb, params, metadata)

    if verb in ("label", "annotate"):
        resource_tokens = [t for t in positional if not _is_pair_operand(t)]
        operands = [t for t in positional if _is_pair_operand(t)]
        resources = _expand_categories(_parse_resources(resource_tokens))
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        key = "labels" if verb == "label" else "annotations"
        params[key] = {k: v for k, _, v in (t.partition("=") for t in operands if "=" in t)}
        removed = [t[:-1] for t in operands if "=" not in t]
        if removed:
            params[f"{key}_removed"] = removed
        return _mark_open_targets(_make_intents(resources, verb, params, metadata),
                                  custom_kinds=True)

    if verb == "set":  # "set image"
        resource_tokens = [t for t in positional if not _is_pair_operand(t)]
        kv_tokens = [t for t in positional if _is_pair_operand(t)]
        resources = _expand_categories(_parse_resources(resource_tokens))
        if not resources:
            raise ValueError(f"could not find a target resource in: {argv!r}")
        params["images"] = {k: v for k, _, v in (t.partition("=") for t in kv_tokens)}
        return _mark_open_targets(_make_intents(resources, "set-image", params, metadata))

    # get, describe, delete, scale, patch, cordon, drain, taint, expose, ...
    if verb == "taint":
        positional = [t for t in positional if not _is_taint_operand(t)]
    resources = _parse_resources(positional)
    if verb == "taint" and resources and (params.get("all") or params.get("selector")):
        # kubectl taint ignores a name given with --all or -l (checked on kind)
        resources.append(f"{_split_resource_token(positional[0])[0]}/*")
    if not resources:
        raise ValueError(f"could not find a target resource in: {argv!r}")
    resources = _expand_categories(resources)
    intents = _mark_open_targets(_make_intents(resources, verb, params, metadata),
                                 custom_kinds=verb in _KUBECTL_CUSTOM_KIND_VERBS)
    if verb == "describe" and len(positional) == 2 and not any("/" in t for t in positional):
        _mark_name_prefix(intents[0], positional[1])
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


def _without_index(address: str) -> str:
    """``aws_instance.web[0]`` -> ``aws_instance.web``: a trailing ``[…]`` with
    no ``]`` inside, dropped in one pass (a regex was quadratic on ``[`` runs)."""
    if not address.endswith("]"):
        return address
    start = address.rfind("]", 0, len(address) - 1) + 1
    bracket = address.find("[", start, len(address) - 1)
    return address[:bracket] if bracket != -1 else address


def _provider_config_key(
    plan_json: dict[str, Any], type_name: str, module_path: str | None
) -> str | None:
    """The resource's ``provider_config_key`` (``aws``, ``aws.west``,
    ``module.app:aws``) from the configuration block, if declared."""
    base = _without_index(type_name)
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

# The flag that names the target resource, per (service, kind), for
# operations whose identifier flag is not one of _AWS_SINGLE_ID_FLAGS or is
# preceded by a parent's (--cluster-name before --nodegroup-name). Without
# it the name was lost ("*") or the parent's name was used, so a
# name-specific rule never matched on the client while the compiled AWS
# policy enforced it.
_AWS_TARGET_FLAGS = {
    ("ec2", "volume"): "volume-id",
    ("ec2", "snapshot"): "snapshot-id",
    ("ec2", "vpc"): "vpc-id",
    ("ec2", "subnet"): "subnet-id",
    ("ec2", "security-group"): "group-id",
    ("ec2", "internet-gateway"): "internet-gateway-id",
    ("ec2", "nat-gateway"): "nat-gateway-id",
    ("ec2", "image"): "image-id",
    ("ec2", "key-pair"): "key-name",
    ("rds", "db-cluster"): "db-cluster-identifier",
    ("rds", "db-snapshot"): "db-snapshot-identifier",
    ("rds", "db-cluster-snapshot"): "db-cluster-snapshot-identifier",
    ("eks", "cluster"): "name",
    ("eks", "nodegroup"): "nodegroup-name",
    ("eks", "addon"): "addon-name",
    ("eks", "fargate-profile"): "fargate-profile-name",
    ("ecs", "service"): "service",
    ("logs", "log-group"): "log-group-name",
    ("logs", "log-stream"): "log-stream-name",
    ("route53", "hosted-zone"): "id",
    ("efs", "file-system"): "file-system-id",
    ("elasticache", "cache-cluster"): "cache-cluster-id",
    ("elasticache", "replication-group"): "replication-group-id",
}

_AWS_TARGET_FLAG_NAMES = frozenset(_AWS_TARGET_FLAGS.values()) - _AWS_SINGLE_ID_FLAGS

# Every flag that names a target, which an abbreviation can stand for.
_AWS_ID_FLAG_NAMES = _AWS_SINGLE_ID_FLAGS | _AWS_TARGET_FLAG_NAMES | {"instance-ids"}

_AWS_S3_VERB_MAP = {
    "rm": "delete",
    "rb": "delete",
    "cp": "put",
    "mv": "put",
    "sync": "put",
    "ls": "read",
    "mb": "create",
}

# The aws CLI's global options (aws-cli 2.37 awscli/data/cli.json), with whether each takes
# a value. argparse reads them first, over the whole line, and takes any unambiguous
# prefix of one, so "--reg us-west-2" is the region wherever it is (checked by running
# aws 2.37 against a closed local port).
_AWS_GLOBAL_OPTIONS = {
    "debug": False, "endpoint-url": True, "no-verify-ssl": False, "no-paginate": False,
    "output": True, "query": True, "profile": True, "region": True, "version": False,
    "color": True, "no-sign-request": False, "ca-bundle": True, "cli-read-timeout": True,
    "cli-connect-timeout": True, "cli-binary-format": True, "no-cli-pager": False,
    "cli-auto-prompt": False, "no-cli-auto-prompt": False, "cli-error-format": True,
}

# The options of "aws s3 cp/mv/rm/sync/..." that take no value (awscli/customizations/s3
# subcommands.py and syncstrategy). --grants takes one or more words, --tags two, and the
# rest one each. --dryrun is that command's rehearsal.
_AWS_S3_BOOL_FLAGS = frozenset({
    "recursive", "human-readable", "summarize", "dryrun", "quiet", "force", "follow-symlinks",
    "no-follow-symlinks", "no-guess-mime-type", "only-show-errors", "no-progress",
    "progress-multiline", "ignore-glacier-warnings", "force-glacier-transfer", "no-overwrite",
    "delete", "exact-timestamps", "size-only", "validate-same-s3-paths",
})


def _aws_global_name(key: str) -> str | None:
    """The global option ``--key`` names, as argparse finds it: the exact name or the one
    global option it is a prefix of. None when it names none; ambiguous is refused."""
    if key in _AWS_GLOBAL_OPTIONS:
        return key
    found = [name for name in _AWS_GLOBAL_OPTIONS if name.startswith(key)]
    if len(found) > 1:
        raise ValueError(f"aws: --{key} is ambiguous ({', '.join(found)}), and aws refuses it")
    return found[0] if found else None


def _parse_aws_tokens(
    tokens: list[str], *, s3: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str] | None,
           list[tuple[str, list[str]]], str | None]:
    """``(metadata, params, positional, id, ids, abbreviations, id_flag)``. ``s3`` reads the options
    of the high-level ``aws s3`` commands. ``abbreviations`` are the ``(key, value)`` of
    options the parser does not know whose name starts a target flag's: argparse takes an
    unambiguous prefix of an operation's option too (``--role`` is ``--role-name`` on
    ``iam delete-role``), so a missing target may be in one of them."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    id_value: str | None = None
    multi_ids: list[str] | None = None
    abbreviations: list[tuple[str, list[str]]] = []
    id_flag: str | None = None  # the full flag that gave id_value

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            raise ValueError(f"aws: aws refuses the words after '--': {tokens!r}")
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if tok.startswith("--"):
                key = _aws_global_name(key) or key
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
            elif key == "dry-run" or (s3 and key == "dryrun"):
                _record_dry_run(params, _is_dry_run(val))
            elif key == "no-dry-run" or (len(key) >= 4 and "no-dry-run".startswith(key)):
                # an unambiguous prefix of --no-dry-run is that option to argparse
                params.pop("dry_run", None)  # explicitly a real run
            elif key in _AWS_GLOBAL_OPTIONS:
                if _AWS_GLOBAL_OPTIONS[key] and val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if key in _AWS_BOOL_FLAGS:
                    params[key] = _bool_param(val)
                # the other globals are consumed, intentionally not recorded
            elif s3 and key in _AWS_S3_BOOL_FLAGS:
                params[key] = _bool_param(val)
            elif s3 and val is None and key in ("grants", "tags"):
                count = n if key == "grants" else 2
                values: list[str] = []
                while len(values) < count and i + 1 < n and not tokens[i + 1].startswith("-"):
                    i += 1
                    values.append(tokens[i])
                params[key] = values
            elif s3 and val is None:
                # every other s3 option takes one word (--sse and --request-payer take the
                # next one too, when it is not an option)
                if i + 1 < n and not tokens[i + 1].startswith("-"):
                    i += 1
                    params[key] = tokens[i]
                else:
                    params[key] = True
            elif key in _AWS_BOOL_FLAGS:
                params[key] = _bool_param(val)
            elif key in ("cli-input-json", "cli-input-yaml"):
                # read before argparse, so only the full name counts (checked on aws 2.37)
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key.replace("-", "_")] = val
            elif key in ("instance-ids", "instance-id"):
                # nargs "+": every word up to the next option; "--instance-id" is that
                # option abbreviated on terminate-instances and others (checked on aws 2.37)
                if val is not None:
                    ids = [val]
                else:
                    ids = []
                    while i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        ids.append(tokens[i])
                if key == "instance-id" and len(ids) == 1:
                    id_value, id_flag = ids[0], "instance-ids"
                else:
                    multi_ids = ids
            elif key in _AWS_TARGET_FLAG_NAMES:
                # a resource name is a string, never coerced: "001", "123",
                # "nan" and "inf" are valid names (review of #19)
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = val
            elif key in _AWS_SINGLE_ID_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                id_value, id_flag = val, key
            else:
                if val is not None:
                    params[key] = _coerce(val)
                elif i + 1 < n and not tokens[i + 1].startswith("-"):
                    # argparse never takes a word starting with "-" as a value
                    i += 1
                    val = tokens[i]
                    params[key] = _coerce(val)
                else:
                    params[key] = True
                if val is not None and "instance-ids".startswith(key):
                    # a prefix of --instance-ids takes every word up to the next option
                    values = [val]
                    while i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        values.append(tokens[i])
                    params[key] = values if len(values) > 1 else params[key]
                    abbreviations.append((key, values))
                elif val is not None and any(flag.startswith(key) for flag in _AWS_ID_FLAG_NAMES):
                    abbreviations.append((key, [val]))
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional, id_value, multi_ids, abbreviations, id_flag


def _aws_resource(service: str, kind: str, name: str | None) -> str:
    return f"{service}/{kind}/{name}" if name else f"{service}/{kind}/*"


def _from_aws_s3(
    operation: str,
    rest: list[str],
    metadata: dict[str, Any],
    params: dict[str, Any],
    argv: list[str],
) -> list[InfrastructureIntent]:
    """One intent per ``s3://`` path: ``cp`` and ``sync`` write the destination (and the
    source is kept as before), ``mv`` also deletes its source, and ``sync --delete``
    deletes in the destination."""
    if operation not in _AWS_S3_VERB_MAP:
        raise ValueError(f"unsupported 'aws s3' subcommand: {argv!r}")
    action = _AWS_S3_VERB_MAP[operation]
    uris = [t for t in rest if t.startswith("s3://")]
    if not uris:
        raise ValueError(f"could not find an s3:// target in: {argv!r}")
    params = {**params, "raw_action": f"s3-{operation}"}
    intents: list[InfrastructureIntent] = []

    def add(uri: str, action: str) -> None:
        bucket, _, key = uri[len("s3://") :].partition("/")
        intent_params = {**params, "key": key} if key else dict(params)
        intents.append(InfrastructureIntent(resource=f"s3/bucket/{bucket}", action=action,
                                            provider="aws", params=intent_params,
                                            metadata=dict(metadata)))

    for uri in uris:
        add(uri, action)
    if operation == "mv" and rest and rest[0].startswith("s3://"):
        add(rest[0], "delete")
    if operation == "sync" and params.get("delete") is True and rest[-1:] == uris[-1:]:
        add(uris[-1], "delete")
    return intents


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


def _aws_abbreviated_target(
    abbreviations: list[tuple[str, list[str]]], target_flag: str | None,
) -> tuple[str | None, list[str]] | None:
    """``(flag, names)`` for a target the command names only through an abbreviated flag:
    argparse reads ``--role x`` as ``--role-name x`` on ``iam delete-role`` and ``--instance
    i-1 i-2`` as ``--instance-ids`` (checked on aws 2.37). Which option such a prefix
    stands for depends on the operation's other options, which the parser does not have,
    so this is used only where no full flag names the target: a name in place of ``*``
    can only make a rule on one name match."""
    for key, values in abbreviations:
        if target_flag and target_flag.startswith(key):
            return target_flag, values[:1]
        if "instance-ids".startswith(key) or any(flag.startswith(key)
                                                 for flag in _AWS_SINGLE_ID_FLAGS):
            return None, values
    return None


def from_aws_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``aws`` CLI invocation into one InfrastructureIntent per
    target resource (``--instance-ids`` may name more than one).

    With ``--cli-input-json`` or ``--cli-input-yaml`` and no flag naming the target, the
    target is in that input, which is not read: the intent is marked
    ``resolved_at_runtime``, so a rule on one name escalates."""
    if not argv or _basename(argv[0]) != "aws":
        raise ValueError(f"not a recognizable aws invocation: {argv!r}")

    tokens = argv[1:]
    (metadata, params, positional, id_value, multi_ids, abbreviations,
     id_flag) = _parse_aws_tokens(tokens)

    if len(positional) < 2:
        raise ValueError(f"could not determine an aws service/operation in: {argv!r}")

    service, operation, *rest = positional

    if service == "s3":
        if operation in _AWS_S3_VERB_MAP:
            # read again with the s3 commands' own options (--recursive takes no value)
            metadata, params, positional, *_ = _parse_aws_tokens(tokens, s3=True)
            service, operation, *rest = positional
        return _from_aws_s3(operation, rest, metadata, params, argv)

    from_input = "cli_input_json" in params or "cli_input_yaml" in params
    if service in ("s3api", "s3control"):
        if id_value is None:
            found = _aws_abbreviated_target(abbreviations, None)
            if found:
                id_value = found[1][0]
        # an abbreviation of the flag that named the bucket (or of --key) is that option to
        # argparse as well, and the last one counts there: every spelling is a target
        buckets = [id_value, *(v for k, vals in abbreviations
                               if id_flag and id_flag.startswith(k) for v in vals)]
        keys = [params.get("key"), *(v for k, vals in abbreviations if "key".startswith(k)
                                      and k != "key" for v in vals)]
        intents = []
        for bucket in dict.fromkeys(buckets):
            for key in dict.fromkeys(keys):
                with_key = {**params, "key": key} if key is not None else params
                intents.extend(_from_aws_s3_alias(service, operation, metadata, dict(with_key),
                                                  bucket))
        return _mark_aws_input_targets(intents) if from_input else intents

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

    target_flag = _AWS_TARGET_FLAGS.get((service, kind))
    # The flag a full spelling named the target with: an abbreviation of that same flag is
    # that option to argparse too (the last one counts there), so both names are targets.
    full_flag = ("instance-ids" if multi_ids else
                 target_flag if target_flag and isinstance(params.get(target_flag), str) else
                 id_flag)
    also = [value for key, values in abbreviations
            if full_flag and full_flag.startswith(key) for value in values]
    if target_flag and not multi_ids and not isinstance(params.get(target_flag), str):
        # "--nodegroup ng-1" beside "--cluster-name c": the target's own flag, abbreviated
        found = _aws_abbreviated_target(abbreviations, target_flag)
        if found and found[0] is not None:
            params[target_flag] = found[1][0]
    named = (multi_ids or id_value is not None
             or (target_flag is not None and isinstance(params.get(target_flag), str)))
    if not named:
        found = _aws_abbreviated_target(abbreviations, None)
        if found:
            multi_ids = found[1] if len(found[1]) > 1 else None
            id_value = found[1][0]
    if not multi_ids and target_flag and isinstance(params.get(target_flag), str):
        # the target's own flag wins; a parent id taken from a generic flag
        # (--cluster, --cluster-name) is kept as a parameter
        if id_value is not None:
            params.setdefault("parent", id_value)
        id_value = params[target_flag]
    names = multi_ids if multi_ids else [id_value]
    names = list(dict.fromkeys([*names, *also]))
    resources = [_aws_resource(service, kind, n) for n in names]
    intents = [
        InfrastructureIntent(
            resource=r, action=action, provider="aws", params=dict(params), metadata=dict(metadata)
        )
        for r in resources
    ]
    return _mark_aws_input_targets(intents) if from_input else intents


def _mark_aws_input_targets(intents: list[InfrastructureIntent]) -> list[InfrastructureIntent]:
    """Marks the intents whose name is ``*`` because the target is in --cli-input-json."""
    for intent in intents:
        if intent.resource.endswith("/*"):
            intent.params["resolved_at_runtime"] = {"from": intent.resource,
                                                    "kinds": [intent.resource[:-2]]}
    return intents


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

# The az options the parser reads into the target or its scope. az parses with Python's
# argparse (knack), which takes an unambiguous prefix of a long option, so "--resource-gr
# rg" is the resource group. Whether a prefix is one depends on the command's other options,
# which the parser does not have, so a prefix of one of these is refused. --id and
# --resource are full options of their own on many commands.
_AZ_SCOPE_OPTIONS = ("name", "resource-group", "location", "subscription", "ids")
_AZ_OWN_OPTIONS = frozenset({"id", "resource"})


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


# The short letters of az commands, from every command module's _params.py in azure-cli
# (dev branch, November 2026), plus -h (help) and -o (output). A letter in
# _AZ_SHORT_BOOL_LETTERS is a plain boolean (store_true) on at least one command, so in a
# bundled word the next letter may be an option of its own; every other known letter takes
# the rest of its word as its value (three-state flags such as -z take an attached word as
# their value too). -n, -g, -l and -o are read as the name, resource group, location and
# output everywhere, as the parser always has. A letter no command has is refused, since
# argparse would then try it as a prefix of a long single-dash option.
_AZ_SHORT_VALUE_LETTERS = frozenset("nglo")
_AZ_SHORT_BOOL_LETTERS = frozenset("abcdefimprtuyh")
_AZ_SHORT_KNOWN_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzKLPU")


def _az_short_readings(rest: str) -> list[list[str]]:
    """Every way argparse can read the letters of a short word, as flags: a letter that
    takes a value takes the rest of the word, and a boolean lets the next letter be an
    option. A reading that reaches a letter no command has is left out: az refuses it."""
    readings: list[list[str]] = []
    if not rest:
        return [[]]
    letter, tail = rest[0], rest[1:]
    if letter not in _AZ_SHORT_KNOWN_LETTERS:
        return []
    if letter not in "yh":
        if tail.startswith("="):
            readings.append([f"-{letter}={tail[1:]}"])
        else:
            readings.append([f"-{letter}={tail}"] if tail else [f"-{letter}"])
    if letter in _AZ_SHORT_BOOL_LETTERS and letter not in _AZ_SHORT_VALUE_LETTERS:
        readings.extend([f"-{letter}", *more] for more in _az_short_readings(tail))
    return readings


def _split_az_short_word(word: str) -> list[str]:
    """One short-option word as argparse reads it: ``-nweb`` is ``-n web``, ``-n=web`` is
    ``-n web``, ``-ynweb`` is ``-y -n web`` and ``-cmycontainer`` is ``-c mycontainer``. When
    the letters can be read more than one way (a letter that is a boolean on some commands)
    and the readings give a different name, resource group or location, the word is
    refused (``-dnprod``: ``-d nprod``, or ``-d -n prod`` where -d is a boolean)."""
    if word.startswith("--") or len(word) <= 2:
        return [word]
    if word[1] not in _AZ_SHORT_KNOWN_LETTERS:
        raise ValueError(f"az: -{word[1]} is a short option no az command has: {word!r}")
    readings = _az_short_readings(word[1:])
    if not readings:
        raise ValueError(f"az: no az command reads {word!r}")

    def scope(reading: list[str]) -> dict[str, str]:
        return {f[1]: f[3:] for f in reading if f[1] in "ngl"}

    if len({tuple(sorted(scope(r).items())) for r in readings}) > 1:
        raise ValueError(f"az: cannot tell what {word!r} means: it can set the name, resource "
                         f"group or location in more than one way")
    return readings[0]


def _parse_az_tokens(
    tokens: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    name_value: str | None = None
    ids_values: list[str] = []

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            raise ValueError(f"az: words after '--' are not options az reads: {tokens!r}")
        if tok.startswith("-") and tok != "-":
            if not tok.startswith("--") and len(tok) > 2 and tok[2] != "=":
                flags = _split_az_short_word(tok)
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
            key, val = _split_flag(tok)
            if (tok.startswith("--") and key not in _AZ_OWN_OPTIONS
                    and any(o != key and o.startswith(key) for o in _AZ_SCOPE_OPTIONS)):
                raise ValueError(f"az: {tok} may be an abbreviation of an option that names "
                                 f"the target or its scope; write the option in full")
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
                _record_dry_run(params, _is_dry_run(val))
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
                # argparse never takes a word starting with "-" as a value
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

_GCS_LEGACY_VERB_MAP = {"rm": "delete", "rb": "delete", "cp": "put", "mv": "put"}

# gcloud global booleans: never swallow the group/verb token after them.
_GCLOUD_BOOL_FLAGS = {"log-http", "no-user-output-enabled", "user-output-enabled"}

# The boolean options of "gcloud storage cp/mv/rm/rb" (and their short letters), so that
# "--recursive gs://b" leaves gs://b a path. From the gcloud storage documentation, not
# its source; a word starting "gs://" is never taken as a flag's value anyway.
_GCLOUD_STORAGE_BOOL_FLAGS = frozenset({
    "recursive", "r", "R", "all-versions", "a", "continue-on-error", "c",
    "read-paths-from-stdin", "I", "no-clobber", "n", "daisy-chain", "D", "do-not-decompress",
    "ignore-symlinks", "preserve-posix", "P", "print-created-message", "v",
    "skip-unsupported", "U", "exclude-managed-folders", "preserve-acl", "p",
    "include-managed-folders", "skip-if-dest-has-newer-mtime", "u",
})

# gsutil's getopt letters: in front of the command, and on rm, rb, cp and mv, from gsutil's
# documentation (gsutil was not available to read or run). A letter in a "values" set
# takes the rest of its word or the next word; a letter in neither is refused.
_GSUTIL_TOP_BOOLS, _GSUTIL_TOP_VALUES = frozenset("mqdDv"), frozenset("hoiu")
_GSUTIL_VERB_LETTERS = {
    "rm": (frozenset("afIrR"), frozenset()),
    "rb": (frozenset("f"), frozenset()),
    "cp": (frozenset("AcDeIMNnpPrRtUvZJ"), frozenset("asjzL")),
    "mv": (frozenset("AcDeIMNnpPrRtUvZJ"), frozenset("asjzL")),
}

# gcloud flags that take a value, beyond --region, --zone and --project, which a following
# word must not be read past: the global ones (gcloud topic flags) and those of the
# commands that change something most often, from the gcloud reference. A flag in no table
# that is followed by a word is refused: gcloud never takes a word starting with "-" as a
# value, but a word that does not start with "-" is the flag's value if it takes one and a
# name if it is a boolean, and gcloud reads every name after the verb (see
# from_gcloud_multi). Write such a flag as --flag=value. Add a flag here only when its
# reference page shows it taking a value (``--flag=VALUE``): one listed wrongly would
# take a name as its value.
_GCLOUD_VALUE_FLAGS = frozenset({
    # global
    "account", "billing-project", "configuration", "filter", "flags-file", "flatten",
    "format", "impersonate-service-account", "access-token-file", "trace-token",
    "verbosity", "limit", "page-size", "sort-by",
    # compute instances, disks, firewall rules
    "machine-type", "image", "image-family", "image-project", "network", "subnet",
    "boot-disk-size", "boot-disk-type", "size", "type", "labels", "tags", "metadata",
    "scopes", "service-account", "keep-disks", "delete-disks", "description", "rules",
    "source-ranges", "target-tags", "allow", "direction", "priority",
    # container clusters and node pools
    "cluster", "location", "node-pool", "num-nodes", "min-nodes", "max-nodes",
    "cluster-version", "node-version",
    # iam bindings
    "member", "role", "condition",
    # run, functions, sql
    "platform", "memory", "cpu", "port", "set-env-vars", "update-env-vars", "runtime",
    "entry-point", "source", "tier", "database-version", "storage-size",
})

# gcloud zone -> region: a zone is "<region>-<letter>" (e.g. "us-east1-b" ->
# "us-east1"); strip the trailing "-<letter>" component (REVIEW-4 T2.5).
_ZONE_SUFFIX = re.compile(r"-[a-z]$")


def _region_from_zone(zone: str) -> str:
    return _ZONE_SUFFIX.sub("", zone)


def _parse_gcloud_tokens(
    tokens: list[str], *, storage: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """``(metadata, params, positional)``. gcloud takes no abbreviated flag (calliope
    disables argparse's prefixes) and never a word starting with "-" as a value. A flag in
    no table followed by a word is refused (see :data:`_GCLOUD_VALUE_FLAGS`). A ``--no-``
    flag is gcloud's off switch of a boolean and takes no value. Words after ``--`` go to
    the command gcloud runs (``compute ssh``), and are kept in ``params["passthrough"]``.
    ``storage`` reads ``gcloud storage``, whose targets are only ``gs://`` paths: there an
    unknown flag may take a word that is not a path."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    # --zone derives metadata["region"] unless --region is given explicitly
    # -- explicit wins regardless of which flag comes first on the argv
    # (REVIEW-4 T2.5), so both are tracked separately and reconciled once
    # the whole argv has been walked.
    explicit_region: str | None = None
    zone_derived_region: str | None = None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            params["passthrough"] = tokens[i + 1:]
            break
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if key == "region":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                explicit_region = val
            elif key == "zone":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["zone"] = val
                zone_derived_region = _region_from_zone(val)
            elif key == "project":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["project"] = val
            elif key in ("quiet", "q"):
                params["quiet"] = _bool_param(val)
            elif key == "dry-run":
                _record_dry_run(params, _is_dry_run(val))
            elif key == "no-dry-run":
                # No gcloud command was found with this flag. If one has it, it is a real
                # run, and reading it as one can only be stricter.
                params.pop("dry_run", None)
            elif key == "async":
                params["async"] = _bool_param(val)
            elif key in _GCLOUD_BOOL_FLAGS or (storage and key in _GCLOUD_STORAGE_BOOL_FLAGS):
                params[key.replace("-", "_")] = _bool_param(val)
            elif key in _GCLOUD_VALUE_FLAGS and tok.startswith("--"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = _coerce(val)
            elif val is not None:
                params[key] = _coerce(val)
            elif key.startswith("no-") and tok.startswith("--"):
                params[key] = True
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                if not storage:
                    raise ValueError(
                        f"gcloud: cannot tell whether {tok!r} takes a value (next word "
                        f"{tokens[i + 1]!r}), and if it does not, that word is a name; write "
                        f"{tok}=<value> or put {tok} last: {tokens!r}")
                if tokens[i + 1].startswith("gs://"):
                    params[key] = True  # a path stays a path
                else:
                    i += 1
                    params[key] = _coerce(tokens[i])
            else:
                params[key] = True
        else:
            positional.append(tok)
        i += 1

    if explicit_region is not None:
        metadata["region"] = explicit_region
    elif zone_derived_region is not None:
        metadata["region"] = zone_derived_region

    return metadata, params, positional


def _gcs_uri_intents(
    verb: str,
    operands: list[str],
    metadata: dict[str, Any],
    params: dict[str, Any],
    argv: list[str],
    raw_prefix: str,
) -> list[InfrastructureIntent]:
    """One intent per ``gs://`` path: ``rm a b`` deletes both, ``cp`` and ``mv`` write the
    destination (the source is kept as before), and ``mv`` also deletes its source."""
    action = _GCS_LEGACY_VERB_MAP[verb]
    uris = [t for t in operands if t.startswith("gs://")]
    if not uris:
        raise ValueError(f"could not find a gs:// target in: {argv!r}")
    params = {**params, "raw_action": f"{raw_prefix}-{verb}"}
    intents = []
    targets = [(uri, action) for uri in uris]
    if verb == "mv" and operands and operands[0].startswith("gs://"):
        targets.append((operands[0], "delete"))
    for uri, act in targets:
        bucket, _, key = uri[len("gs://") :].partition("/")
        intents.append(InfrastructureIntent(
            resource=f"storage/bucket/{bucket}", action=act, provider="gcp",
            params={**params, "key": key} if key else dict(params), metadata=dict(metadata)))
    return intents


def _from_gsutil(argv: list[str]) -> list[InfrastructureIntent]:
    """gsutil reads its options with getopt: letters bundle (``-rf``), and a letter that
    takes a value takes the rest of its word or the next word. Options in front of the
    command are gsutil's own (``-m``, ``-o key=value``)."""
    tokens = argv[1:]
    words: list[str] = []
    i = 0
    verb: str | None = None
    bools, values = _GSUTIL_TOP_BOOLS, _GSUTIL_TOP_VALUES
    params: dict[str, Any] = {}
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            words.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and tok != "-" and not tok.startswith("--"):
            rest = tok[1:]
            while rest:
                letter, rest = rest[0], rest[1:]
                if letter in values:
                    if not rest:
                        i += 1
                        rest = _value_at(tokens, i, tok)
                    params[letter] = rest
                    break
                if letter not in bools:
                    raise ValueError(f"gsutil: -{letter} is not an option the parser knows "
                                     f"here: {argv!r}")
                params[letter] = True
        elif tok.startswith("--"):
            raise ValueError(f"gsutil: unsupported option {tok!r}: {argv!r}")
        elif verb is None:
            verb = tok
            if verb not in _GSUTIL_VERB_LETTERS:
                raise ValueError(f"unsupported gsutil invocation: {argv!r}")
            bools, values = _GSUTIL_VERB_LETTERS[verb]
        else:
            words.append(tok)
        i += 1
    if verb is None:
        raise ValueError(f"unsupported gsutil invocation: {argv!r}")
    if params.get("o") is not None or params.get("h") is not None:
        params = {k: v for k, v in params.items() if k not in ("o", "h")}
    return _gcs_uri_intents(verb, words, {}, params, argv, "gsutil")


def from_gcloud_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``gcloud`` (or legacy ``gsutil``) CLI invocation, e.g.:

    ``gcloud compute instances start web-1 --zone us-central1-a``
      -> resource "compute/instance/web-1", action "start"

    One intent per name: ``gcloud compute instances delete a b`` deletes both. A flag the
    parser has no entry for, followed by a word, is refused: the word is its value or a
    name, and the parser cannot tell which (``--no-graceful-shutdown`` is a boolean by its
    name, and takes none).
    """
    if not argv:
        raise ValueError("empty argv")

    basename = _basename(argv[0])
    if basename == "gsutil":
        return _from_gsutil(argv)
    if basename != "gcloud":
        raise ValueError(f"not a recognizable gcloud invocation: {argv!r}")

    tokens = argv[1:]
    # gcloud storage's targets are gs:// paths, so an unknown flag there cannot hide one
    storage = argv[1:2] == ["storage"] or argv[1:3] in (["alpha", "storage"],
                                                         ["beta", "storage"])
    metadata, params, positional = _parse_gcloud_tokens(tokens, storage=storage)

    release_track = None
    if positional and positional[0] in ("alpha", "beta"):
        release_track = positional.pop(0)

    if (
        len(positional) >= 2
        and positional[0] == "storage"
        and positional[1] in _GCS_LEGACY_VERB_MAP
    ):
        metadata, params, positional = _parse_gcloud_tokens(tokens, storage=True)
        if release_track:
            positional.remove(release_track)
            params["release_track"] = release_track
        return _gcs_uri_intents(positional[1], positional[2:], metadata, params, argv, "storage")
    if release_track:
        params["release_track"] = release_track

    verb_idx = next((i for i, t in enumerate(positional) if t in _GCLOUD_VERBS), None)
    if verb_idx is None:
        raise ValueError(f"could not find a recognized gcloud verb in: {argv!r}")

    group_words = positional[:verb_idx]
    if not group_words:
        raise ValueError(f"could not determine a gcloud resource group in: {argv!r}")
    verb = positional[verb_idx]
    names = positional[verb_idx + 1:]
    resource_prefix = _GCLOUD_GROUP_MAP.get(tuple(group_words))
    if group_words == ["sql"] and verb in ("import", "export") and names[:1] in (
            ["sql"], ["csv"], ["bak"], ["tde"]):
        # gcloud sql import|export <format> INSTANCE URI
        resource_prefix, names = "sql/instance", names[1:2]
    elif verb in _GCLOUD_IAM_BINDING_VERBS or verb in ("get-credentials", "ssh"):
        names = names[:1]  # set-iam-policy NAME POLICY_FILE
    if resource_prefix is None:
        *head, last = group_words
        resource_prefix = "/".join([*head, _singularize(last)])

    action = "update" if verb in _GCLOUD_IAM_BINDING_VERBS else _normalize_verb(verb)
    params["raw_action"] = verb
    resources = [f"{resource_prefix}/{name}" for name in dict.fromkeys(names)] or [
        f"{resource_prefix}/*"]
    return [InfrastructureIntent(resource=r, action=action, provider="gcp",
                                 params=dict(params), metadata=dict(metadata))
            for r in resources]


def from_gcloud(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``gcloud`` or ``gsutil`` invocation with exactly one target (see
    :func:`from_gcloud_multi`). Raises ValueError for ``gcloud ... delete a b``."""
    intents = from_gcloud_multi(argv)
    if len(intents) != 1:
        raise ValueError(f"expected exactly one gcloud target, found {len(intents)}: {argv!r}")
    return intents[0]


# --- Helm -----------------------------------------------------------------

_HELM_READ_VERBS = {"history", "status", "list", "get"}

# Helm's short letters on the verbs parsed here, read from helm's source (v4.3.1 and
# v3.22.1; helm is not run in the tests): -i is --install on upgrade, -f --values or list's
# --filter, -g --generate-name on install and template. "a" depends on the verb: see
# _helm_short_letters.
_HELM_SHORT_VALUE_LETTERS = frozenset("flmnos")
_HELM_SHORT_BOOL_LETTERS = frozenset("Adghiqr")
_HELM_SHORT_BOOL_NAMES = {"i": "install", "g": "generate_name"}

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
    "content-cache",  # helm 4
    "color",
    "colour",
}
_HELM_GLOBAL_BOOL_FLAGS = {"debug", "kube-insecure-skip-tls-verify"}
# Global value flags whose value is consumed but not recorded.
_HELM_DISCARD_VALUE_FLAGS = _HELM_GLOBAL_VALUE_FLAGS - {"n", "namespace", "kube-context"}

# Every long flag of every helm command, read from helm's flag registrations (v4.3.1
# pkg/cmd and v3.21.1 cmd/helm, and pkg/cli for the globals). Those that take a value
# take the next word whatever it looks like (#80). The ones with a default for a bare use
# (helm 4's --wait, --dry-run) are with the booleans. "server-side" is a boolean on
# install and template and takes a value on upgrade and rollback (helm 4).
_HELM_VALUE_FLAGS = frozenset({
    "api-versions", "app-version", "burst-limit", "ca-file", "cascade", "cert-file",
    "chart-api-version", "color", "colour", "content-cache", "description", "destination",
    "dir", "endpoint", "filter", "history-max", "jsonpath", "key", "key-file", "keyring",
    "kube-apiserver", "kube-as-group", "kube-as-user", "kube-ca-file", "kube-context",
    "kube-tls-server-name", "kube-token", "kube-version", "kubeconfig", "labels", "max",
    "max-col-width", "merge", "name", "name-template", "namespace", "offset", "output",
    "output-dir", "passphrase-file", "password", "post-renderer", "post-renderer-args", "qps",
    "registry-config", "repo", "repository-cache", "repository-config", "revision",
    "selector", "set", "set-file", "set-json", "set-literal", "set-string", "show-only",
    "starter", "template", "time-format", "timeout", "type", "untardir", "url", "username",
    "values", "version",
})
_HELM_BOOL_ONLY_FLAGS = frozenset({
    "all", "all-namespaces", "allow-deprecated-repos", "atomic", "cleanup-on-fail", "client",
    "create-namespace", "date", "debug", "dependency-update", "deployed", "devel",
    "disable-openapi-validation", "dry-run", "enable-dns", "fail-on-no-result",
    "fail-on-repo-update-fail", "failed", "force", "force-conflicts", "force-replace",
    "force-update", "generate-headers", "generate-name", "help", "hide-notes", "hide-secret",
    "ignore-not-found", "include-crds", "insecure", "insecure-skip-tls-verify", "install",
    "is-upgrade", "json", "keep-history", "kube-insecure-skip-tls-verify", "list-repo-url",
    "logs", "no-descriptions", "no-headers", "no-hooks", "no-update", "pass-credentials",
    "password-stdin", "pending", "plain-http", "prov", "quiet", "recreate-pods", "regexp",
    "release-name", "render-subchart-notes", "replace", "reset-then-reuse-values",
    "reset-values", "reuse-values", "reverse", "rollback-on-failure", "short", "show-desc",
    "show-resources", "show-rollback-revision", "sign", "skip-crds", "skip-refresh",
    "skip-schema-validation", "skip-tests", "strict", "superseded", "take-ownership",
    "uninstalled", "uninstalling", "untar", "validate", "verify", "versions", "wait",
    "wait-for-jobs", "with-subcharts",
})


def _helm_long_flags(verb: str | None) -> tuple[frozenset[str], frozenset[str]]:
    """Helm's value and boolean long flags on ``verb``."""
    if verb in ("upgrade", "rollback"):
        return _HELM_VALUE_FLAGS | {"server-side"}, _HELM_BOOL_ONLY_FLAGS
    return _HELM_VALUE_FLAGS, _HELM_BOOL_ONLY_FLAGS | {"server-side"}


def _parse_helm_tokens(
    tokens: list[str], verb: str | None = None
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    short_bools, short_values = _helm_short_letters(verb)
    long_values, long_bools = _helm_long_flags(verb)
    # helm merges --set, then --set-string, then --set-literal, whatever their order on
    # the line, so a later kind wins over an earlier one (pkg/cli/values MergeValues).
    sets: dict[str, list[str]] = {"set-json": [], "set": [], "set-string": [], "set-file": [],
                                  "set-literal": []}

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            # pflag: every word after it is an operand, "-nprod" too
            positional.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and tok != "-":
            is_long = tok.startswith("--")
            if not is_long and len(tok) > 2:
                flags = _split_short_word(tok, short_bools, short_values, "helm")
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
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
                _record_dry_run(params, _is_dry_run(val, truthy=_KUBECTL_DRY_RUN_WORDS))
            elif key == "version":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params["version"] = _coerce(val)
            elif key == "values" or (key == "f" and not is_long and verb != "list"):
                # A StringSlice: "-f a.yaml,b.yaml" is two files.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params.setdefault("values_files", []).extend(_read_string_slice(val))
            elif key in ("set", "set-string", "set-literal"):
                # Read as helm's strvals reads them (see _merge_helm_values):
                # `image.tag=v2` is {"image": {"tag": "v2"}}, which a rule's
                # dotted scope key walks.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                sets[key].append(val)
            elif key in ("set-file", "set-json"):
                # Kept as written too; merged into params["set"] below.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                dest = "set_file" if key == "set-file" else "set_json"
                params.setdefault(dest, []).append(val)
                sets[key].append(val)
            elif is_long and key in long_bools:
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and key in short_bools:
                # Takes no value: in "-i api ./c" the release is "api".
                params[_HELM_SHORT_BOOL_NAMES.get(key, key)] = _bool_param(val)
            elif not is_long and key in short_values:
                # Always the next token, whatever it looks like, as pflag reads it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = _coerce(val)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, params[key.replace("-", "_")] = _other_flag(
                    tokens, i, values=long_values if is_long else (), bools=(), tool="helm")
        else:
            positional.append(tok)
        i += 1

    _merge_helm_values(params, sets)
    return metadata, params, positional


# --- helm values from the command line --------------------------------------------------
# A port of helm's pkg/strvals (helm 4.3.1 and 3.21.1), which reads --set, --set-string,
# --set-json, --set-file and --set-literal into one nested map, so params["set"] has the
# shape helm gives the chart and a rule's dotted scope key (set.securityContext.privileged)
# walks it. What helm refuses is a ValueError.

_HELM_MAX_INDEX = 65536
_HELM_MAX_NESTED = 30
# The value of a --set-file key: the content of a file nobody read.
_HELM_FILE_VALUE = object()


class _StrvalsParser:
    def __init__(self, text: str, mode: str) -> None:
        self.s = text
        self.i = 0
        self.mode = mode  # "typed", "string", "json", "file" or "literal"

    def error(self, message: str) -> ValueError:
        return ValueError(f"helm cannot parse {self.s!r}: {message}")

    def until(self, stop: str) -> tuple[str, str | None]:
        """Characters up to one in ``stop`` (consumed and returned), with ``\\`` escaping
        the next character except in literal mode; None at the end."""
        out = []
        while self.i < len(self.s):
            ch = self.s[self.i]
            self.i += 1
            if ch in stop:
                return "".join(out), ch
            if ch == "\\" and self.mode != "literal":
                if self.i >= len(self.s):
                    return "".join(out), None
                out.append(self.s[self.i])
                self.i += 1
                continue
            out.append(ch)
        return "".join(out), None

    def typed(self, raw: str) -> Any:
        if self.mode == "file":
            return _HELM_FILE_VALUE
        if self.mode in ("string", "literal"):
            return raw
        low = raw.lower()
        if low in ("true", "false"):
            return low == "true"
        if low == "null":
            return None
        if raw == "0":
            return 0
        if raw and raw[0] != "0" and re.fullmatch(r"[+-]?[0-9]+", raw):
            value = int(raw)
            if -(1 << 63) <= value < (1 << 63):
                return value
        return raw

    def parse(self, data: dict[str, Any]) -> None:
        while self.i < len(self.s):
            self.key(data, 0)

    def value(self) -> Any:
        """The value after "=": JSON, a {a,b} list, or one word up to the next comma."""
        if self.mode == "literal":
            rest, self.i = self.s[self.i:], len(self.s)
            return rest
        if self.mode == "json":
            while self.i < len(self.s) and self.s[self.i].isspace():
                self.i += 1
            if self.i >= len(self.s) or self.s[self.i] == ",":
                self.i += 1
                return None
            try:
                value, end = json.JSONDecoder().raw_decode(self.s, self.i)
            except json.JSONDecodeError as err:
                raise self.error(f"not JSON: {err}") from err
            self.i = end
            while self.i < len(self.s) and self.s[self.i].isspace():
                self.i += 1
            if self.i < len(self.s):
                if self.s[self.i] != ",":
                    raise self.error("unexpected text after a JSON value")
                self.i += 1
            return value
        if self.i < len(self.s) and self.s[self.i] == "{":
            self.i += 1
            items = []
            while True:
                word, last = self.until(",}")
                if last is None:
                    raise self.error("list must terminate with '}'")
                items.append(self.typed(word))
                if last == "}":
                    if self.i < len(self.s) and self.s[self.i] == ",":
                        self.i += 1
                    return items
        word, _last = self.until(",")
        return self.typed(word)

    def key(self, data: dict[str, Any], level: int) -> None:
        stop = "=[." if self.mode == "literal" else "=[,."
        name, last = self.until(stop)
        if last is None:
            if name:
                raise self.error(f"key {name!r} has no value")
            return
        if last == ",":
            raise self.error(f"key {name!r} has no value")
        if last == "=":
            if name:
                data[name] = self.value()
            else:
                self.value()
            return
        if last == "[":
            existing = data.get(name, [])
            if not isinstance(existing, list):
                raise self.error(f"{name!r} is not a list")
            items = self.list_item(list(existing), self.index(), level)
            if name:
                data[name] = items
            return
        # "."
        level += 1
        if level > _HELM_MAX_NESTED:
            raise self.error("names nested too deep")
        existing = data.get(name, {})
        if not isinstance(existing, dict):
            raise self.error(f"{name!r} is not a map")  # helm panics, and refuses
        inner = dict(existing)
        self.key(inner, level)
        if not inner:
            raise self.error(f"key map {name!r} has no value")
        if name:
            data[name] = inner

    def index(self) -> int:
        word, last = self.until("]")
        if last is None or not re.fullmatch(r"[+-]?[0-9]+", word):
            raise self.error(f"bad list index {word!r}")
        index = int(word)
        if index < 0 or index > _HELM_MAX_INDEX:
            raise self.error(f"list index {index} out of range")
        return index

    @staticmethod
    def set_index(items: list[Any], index: int, value: Any) -> list[Any]:
        if len(items) <= index:
            items.extend([None] * (index + 1 - len(items)))
        items[index] = value
        return items

    def list_item(self, items: list[Any], index: int, level: int) -> list[Any]:
        word, last = self.until("[.=")
        if word:
            raise self.error(f"unexpected {word!r} after a list index")
        if last is None:
            raise self.error("a list index has no value")
        if last == "=":
            return self.set_index(items, index, self.value())
        if last == "[":
            current = items[index] if index < len(items) else None
            if current is not None and not isinstance(current, list):
                raise self.error("not a list")
            return self.set_index(items, index,
                                  self.list_item(list(current or []), self.index(), level))
        current = items[index] if index < len(items) else None
        inner = dict(current) if isinstance(current, dict) else {}
        self.key(inner, level)
        return self.set_index(items, index, inner)


def _helm_merge_maps(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """helm's MergeMaps: a map in ``b`` merges into a map in ``a``; anything else replaces."""
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _helm_merge_maps(out[k], v)
        else:
            out[k] = v
    return out


def _contains_file_value(value: Any) -> bool:
    if value is _HELM_FILE_VALUE:
        return True
    if isinstance(value, dict):
        return any(_contains_file_value(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_file_value(v) for v in value)
    return False


def _strip_file_values(value: Any, path: str, out: list[str]) -> Any:
    """``value`` without the --set-file leaves, whose dotted paths go to ``out``. A list
    holding one is dropped whole: a dotted scope key cannot index into a list."""
    if value is _HELM_FILE_VALUE or (isinstance(value, list) and _contains_file_value(value)):
        out.append(path)
        return _HELM_FILE_VALUE
    if isinstance(value, dict):
        kept = {}
        for k, v in value.items():
            stripped = _strip_file_values(v, f"{path}.{k}", out)
            if stripped is not _HELM_FILE_VALUE:
                kept[k] = stripped
        return kept
    return value


def _merge_helm_values(params: dict[str, Any], sets: dict[str, list[str]]) -> None:
    """``params["set"]``: the values the command line sets, as one nested map, merged in
    helm's order (pkg/cli/values MergeValues): --set-json, --set, --set-string, --set-file
    and --set-literal, a later one replacing an earlier one at the same key, a map
    replacing a scalar only through --set-json. A --set-file value is the file's content,
    which is not read, and a values file (-f) or --reuse-values can set any key the command
    line does not: those keys are in ``params["unresolved_scope"]`` (``set.<key>``, or
    ``set.*`` for every key not set), so a rule scoped on them escalates."""
    base: dict[str, Any] = {}
    for value in sets["set-json"]:
        stripped = value.strip()
        if stripped.startswith("{"):
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError as err:
                raise ValueError(f"helm: --set-json {value!r} is not JSON: {err}") from err
            if not isinstance(loaded, dict):
                raise ValueError(f"helm: --set-json {value!r} is not a JSON object")
            base = _helm_merge_maps(base, loaded)
        else:
            _StrvalsParser(value, "json").parse(base)
    for kind, mode in (("set", "typed"), ("set-string", "string"), ("set-file", "file"),
                       ("set-literal", "literal")):
        for value in sets[kind]:
            _StrvalsParser(value, mode).parse(base)
    unresolved: list[str] = []
    cleaned = _strip_file_values(base, "set", unresolved)
    if cleaned:
        params["set"] = cleaned
    if params.get("values_files") or params.get("reuse_values") is True or \
            params.get("reset_then_reuse_values") is True:
        unresolved.append("set.*")
    if unresolved:
        params["unresolved_scope"] = unresolved


def from_helm_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``helm`` invocation into one InfrastructureIntent per release it acts
    on, e.g.:

    ``helm upgrade --install api ./chart -n prod --dry-run``
      -> resource "release/api", action "update",
         params {"raw_action": "upgrade", "install": True, "chart": "./chart",
                  "dry_run": True}, metadata {"namespace": "prod"}

    ``helm uninstall a b`` uninstalls both releases, so it is two intents. ``helm install
    ./chart --generate-name`` (or ``--name-template``) names its release when it runs:
    the target is ``release/*``, marked ``resolved_at_runtime``.
    """
    if len(argv) < 2 or _basename(argv[0]) != "helm":
        raise ValueError(f"not a recognizable helm invocation: {argv!r}")

    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_HELM_GLOBAL_VALUE_FLAGS,
        bool_flags=_HELM_GLOBAL_BOOL_FLAGS,
        tool="helm",
        glued_values=True,
    )
    verb = rest[0]
    tokens = leading + rest[1:]
    metadata, params, positional = _parse_helm_tokens(tokens, verb)
    params["raw_action"] = verb

    def one(release: str, action: str) -> InfrastructureIntent:
        return InfrastructureIntent(
            resource=f"release/{release}", action=action, provider="helm",
            params=dict(params), metadata=dict(metadata),
        )

    if verb in ("install", "template"):
        if verb == "template":
            params["dry_run"] = True
        named_at_run = params.get("generate_name") is True or "name_template" in params
        if len(positional) == 1 and named_at_run:
            # helm's NameAndChart: the one word is the chart, and the name comes later
            params["chart"] = positional[0]
            return _mark_open_targets([one("*", "create" if verb == "install" else "read")])
        if verb == "template":
            if len(positional) > 1:
                params["chart"] = positional[1]
            return [one(positional[0] if positional else "*", "read")]
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        if len(positional) > 1:
            params["chart"] = positional[1]
        return [one(positional[0], "create")]

    if verb == "upgrade":
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        if len(positional) > 1:
            params["chart"] = positional[1]
        return [one(positional[0], "update")]

    if verb in ("uninstall", "delete"):
        # helm uninstalls every release named, one after the other
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        return [one(release, "delete") for release in dict.fromkeys(positional)]

    if verb == "rollback":
        if not positional:
            raise ValueError(f"could not find a helm release name in: {argv!r}")
        if len(positional) > 1:
            params["revision"] = _coerce(positional[1])
        return [one(positional[0], "rollback")]

    if verb in _HELM_READ_VERBS:
        sub_positional = positional
        if verb == "get" and sub_positional:
            params["get_target"] = sub_positional[0]
            sub_positional = sub_positional[1:]
        return [one(sub_positional[0] if sub_positional else "*", "read")]

    raise ValueError(f"unsupported helm subcommand: {argv!r}")


def from_helm(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``helm`` invocation that acts on exactly one release (see
    :func:`from_helm_multi`). Raises ValueError for ``helm uninstall a b``."""
    intents = from_helm_multi(argv)
    if len(intents) != 1:
        raise ValueError(
            f"expected exactly one target release, found {len(intents)}: {argv!r}"
        )
    return intents[0]


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

# ArgoCD global options (persistent flags of the root command, accepted anywhere on the
# line; argo-cd v3.6.1 and main, cmd/argocd/commands/root.go).
_ARGOCD_GLOBAL_VALUE_FLAGS = {
    "server", "auth-token", "config", "header", "H", "client-crt", "client-crt-key",
    "server-crt", "kube-context", "port-forward-namespace", "logformat", "loglevel",
    "http-retry-max", "server-name", "grpc-web-root-path", "redis-haproxy-name", "redis-name",
    "repo-server-name", "controller-name", "argocd-context", "redis-compress",
}
_ARGOCD_GLOBAL_BOOL_FLAGS = {
    "grpc-web", "insecure", "plaintext", "core", "port-forward", "prompts-enabled",
    "skip-test-tls",
}

# Every long flag of the "argocd app" commands, from argo-cd v3.6.1 and main
# (cmd/argocd/commands app*.go and cmd/util/app.go), and the globals above. A flag that
# takes a value takes the next word whatever it looks like (#80). "app unset" has
# booleans of the same names as some value flags of create and set (--nameprefix, --ref,
# ...), and is not parsed.
_ARGOCD_VALUE_FLAGS = frozenset(_ARGOCD_GLOBAL_VALUE_FLAGS) | frozenset({
    "annotations", "app-namespace", "cluster", "config-management-plugin", "container",
    "dest-name", "dest-namespace", "dest-server", "diff-exit-code", "directory-exclude",
    "directory-include", "dry-source-path", "dry-source-repo", "dry-source-revision", "env",
    "file", "filter", "filter-fields", "group", "helm-api-versions", "helm-chart",
    "helm-kube-version", "helm-namespace", "helm-set", "helm-set-file", "helm-set-string",
    "helm-version", "hydrate-to-branch", "ignore-normalizer-jq-execution-timeout", "info",
    "jsonnet-ext-var-code", "jsonnet-ext-var-str", "jsonnet-libs", "jsonnet-tla-code",
    "jsonnet-tla-str", "kind", "kustomize-api-versions", "kustomize-common-annotation",
    "kustomize-common-label", "kustomize-image", "kustomize-kube-version",
    "kustomize-namespace", "kustomize-replica", "kustomize-version", "label", "local",
    "local-include", "local-repo-root", "name", "nameprefix", "namesuffix", "namespace",
    "out", "output", "parameter", "patch", "patch-type", "path", "plugin-env", "project",
    "propagation-policy", "ref", "release-name", "repo", "resource", "resource-name",
    "retry-backoff-duration", "retry-backoff-factor", "retry-backoff-max-duration",
    "retry-limit", "revision", "revision-history-limit", "revisions", "selector",
    "server-side-diff-concurrency", "server-side-diff-max-batch-kb", "since-seconds",
    "source", "source-name", "source-names", "source-position", "source-positions",
    "strategy", "sync-option", "sync-policy", "sync-retry-backoff-duration",
    "sync-retry-backoff-factor", "sync-retry-backoff-max-duration", "sync-retry-limit",
    "sync-source-branch", "sync-source-path", "tag-prefix", "tail", "timeout", "type",
    "until-time", "values", "values-literal-file",
})
_ARGOCD_BOOL_FLAGS = frozenset(_ARGOCD_GLOBAL_BOOL_FLAGS) | frozenset({
    "all", "allow-empty", "apply-out-of-sync-only", "assumeYes", "async", "auto-prune",
    "cascade", "degraded", "delete", "directory-disable-extension-filter",
    "directory-recurse", "dry-run", "exit-code", "follow", "force", "hard-refresh", "health",
    "help", "helm-pass-credentials", "helm-skip-crds", "helm-skip-schema-validation",
    "helm-skip-tests", "hydrated", "ignore-missing-components",
    "ignore-missing-value-files", "kustomize-force-common-annotation",
    "kustomize-force-common-label", "kustomize-label-include-templates",
    "kustomize-label-without-selector", "match-case", "operation", "orphan", "orphaned",
    "pass-credentials", "preview-changes", "previous", "prune", "refresh", "replace",
    "retry-refresh", "self-heal", "server-side", "server-side-diff", "server-side-generate",
    "set-finalizer", "show-managed-fields", "show-operation", "show-params", "suspended",
    "sync", "sync-apply-only", "sync-dry-run", "sync-force", "sync-prune",
    "sync-retry-refresh", "upsert", "validate", "values-literal", "wait", "yes",
})

# The short letters of the "argocd app" commands parsed here, with the long flag each one
# is on each verb: all take a value but -y (delete's --yes) and -h. -f and -p are booleans
# only on "app logs", which is not parsed.
_ARGOCD_SHORT_VALUE_LETTERS = frozenset("HNPcflopr")
_ARGOCD_SHORT_BOOL_LETTERS = frozenset("hy")
_ARGOCD_SHORT_NAMES = {
    "H": "header", "N": "app-namespace", "P": "path", "c": "cluster", "f": "file",
    "o": "output", "r": "repo", "y": "yes", "h": "help",
}


def _argocd_short_name(letter: str, verb: str | None) -> str:
    """The long flag a short letter is on ``verb``."""
    if letter == "l":
        return "label" if verb == "create" else "selector"
    if letter == "p":
        return {"delete": "propagation-policy", "list": "project"}.get(verb or "", "parameter")
    return _ARGOCD_SHORT_NAMES.get(letter, letter)


def _parse_argocd_tokens(
    tokens: list[str], verb: str | None = None
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            # pflag: every word after it is an operand
            positional.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and tok != "-":
            is_long = tok.startswith("--")
            if not is_long and len(tok) > 2:
                flags = _split_short_word(tok, _ARGOCD_SHORT_BOOL_LETTERS,
                                          _ARGOCD_SHORT_VALUE_LETTERS, "argocd")
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
            key, val = _split_flag(tok)
            name = key if is_long else _argocd_short_name(key, verb)
            known = is_long or key in _ARGOCD_SHORT_VALUE_LETTERS | _ARGOCD_SHORT_BOOL_LETTERS
            if name == "project" and known:
                # A StringArray on sync and list: every one counts.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["project"] = val
                params.setdefault("projects", []).append(val)
            elif name == "kube-context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif name in _ARGOCD_GLOBAL_VALUE_FLAGS and known:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                # consumed, intentionally not recorded
            elif name in _ARGOCD_GLOBAL_BOOL_FLAGS:
                pass  # consumed, intentionally not recorded
            elif name == "dry-run":
                # Only "app sync" has --dry-run. argocd refuses it on the other verbs and
                # runs nothing, so it is a rehearsal only there.
                if verb == "sync":
                    _record_dry_run(params, _is_dry_run(val))
            elif known and (name in _ARGOCD_BOOL_FLAGS or key in _ARGOCD_SHORT_BOOL_LETTERS):
                params[name.replace("-", "_")] = _bool_param(val)
            elif not is_long and key in _ARGOCD_SHORT_VALUE_LETTERS:
                # Always the next token, whatever it looks like, as pflag reads it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[name.replace("-", "_")] = _coerce(val)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, params[key.replace("-", "_")] = _other_flag(
                    tokens, i, values=_ARGOCD_VALUE_FLAGS if is_long else (), bools=(),
                    tool="argocd")
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def from_argocd_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``argocd`` invocation into one InfrastructureIntent per
    target app (``argocd app sync`` / ``delete`` may name more than one).

    ``app sync`` also syncs every app ``-l/--selector`` or ``--project`` picks, and
    ``app delete -l`` deletes every app the selector picks (argo-cd app.go): each is an
    ``app/*`` intent, marked, beside the apps named."""
    if len(argv) < 2 or _basename(argv[0]) != "argocd":
        raise ValueError(f"not a recognizable argocd invocation: {argv!r}")

    # Persistent flags may precede "app" and/or its subcommand; both runs
    # of globals are handed to the same token parser as the trailing flags.
    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_ARGOCD_GLOBAL_VALUE_FLAGS,
        bool_flags=_ARGOCD_GLOBAL_BOOL_FLAGS,
        tool="argocd",
        glued_values=True,
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
        glued_values=True,
    )
    leading = leading + leading_2

    subverb = rest[0]
    tokens = leading + rest[1:]

    if subverb == "actions":
        if len(rest) < 2 or rest[1] != "run":
            raise ValueError(f"unsupported 'argocd app actions' invocation: {argv!r}")
        metadata, params, positional = _parse_argocd_tokens(leading + rest[2:], "actions-run")
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

    metadata, params, positional = _parse_argocd_tokens(tokens, subverb)
    params["raw_action"] = subverb
    action = _ARGOCD_ACTION_MAP[subverb]

    # The apps a selector or a project picks, which argocd lists when it runs.
    picked: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if subverb in _ARGOCD_MULTI_APP_VERBS:
        selector = params.get("selector")
        projects = params.get("projects", []) if subverb == "sync" else []
        for project in projects or ([None] if selector is not None else []):
            where = {**metadata, "project": project} if project is not None else metadata
            picked.append(({**params, "resolved_at_runtime": {"from": "app/*",
                                                               "kinds": ["app"]}}, where))

    if subverb == "list":
        apps = positional if positional else ["*"]
    elif subverb == "rollback":
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]
        if len(positional) > 1:
            params["revision"] = _coerce(positional[1])
    elif subverb in _ARGOCD_MULTI_APP_VERBS:
        if not positional and not picked:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = positional
    else:
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]

    intents = [
        InfrastructureIntent(
            resource=f"app/{app}", action=action, provider="argocd",
            params=dict(params), metadata=dict(metadata),
        )
        for app in apps
    ]
    intents.extend(
        InfrastructureIntent(resource="app/*", action=action, provider="argocd",
                             params=p, metadata=dict(m))
        for p, m in picked
    )
    return intents


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

# Flux global options (accepted before or after the verb): the kubeconfig flags of
# cli-runtime's ConfigFlags (without --request-timeout), --kube-api-qps/-burst, and
# flux's own --timeout, --verbose and --ns-follows-kube-context (flux2 v2.10 main.go).
_FLUX_GLOBAL_VALUE_FLAGS = {
    "n", "namespace", "context", "kubeconfig", "timeout", "as", "as-group", "as-uid",
    "as-user-extra", "cache-dir", "certificate-authority", "client-certificate", "client-key",
    "cluster", "user", "username", "password", "server", "token", "tls-server-name",
    "kube-api-burst", "kube-api-qps",
}
_FLUX_GLOBAL_BOOL_FLAGS = {
    "verbose", "insecure-skip-tls-verify", "disable-compression", "ns-follows-kube-context",
}
# Global value flags whose value is consumed but not recorded. --timeout is
# kept in params: it's meaningful to a rule author ("reconcile with a long
# timeout") and lands there whichever side of the verb it's on. --username and
# --password are also flags of "create source git" and others, and stay recorded.
_FLUX_DISCARD_VALUE_FLAGS = _FLUX_GLOBAL_VALUE_FLAGS - {
    "n", "namespace", "context", "timeout", "username", "password"}

# Every long flag of every flux command, read from flux2 v2.10 cmd/flux (and the globals
# above). A flag that takes a value takes the next word whatever it looks like (#80).
# --dry-run is only on build, migrate and uninstall, which the parser does not read.
_FLUX_VALUE_FLAGS = frozenset(_FLUX_GLOBAL_VALUE_FLAGS) | frozenset({
    "access-key", "add-ignore-paths", "address", "annotations", "api-version",
    "app-base-url", "app-client-id", "app-id", "app-installation-id",
    "app-installation-owner", "app-private-key", "audience-claim", "author-email",
    "author-name", "bearer-token", "branch", "bucket-name", "ca-cert-file", "ca-crt-file",
    "ca-file", "cert-file", "cert-ref", "channel", "chart", "chart-interval", "chart-ref",
    "chart-version", "checkout-branch", "cluster-domain", "cluster-role", "commit",
    "commit-message-appendix", "commit-template", "components", "components-extra", "crds",
    "creds", "decryption-provider", "decryption-secret", "depends-on", "digest",
    "email-claim", "endpoint", "event", "event-severity", "event-source", "extensions",
    "fetch-timeout", "filter-extract", "filter-regex", "filter-semver", "flux-namespace",
    "for", "git-repo-namespace", "git-repo-path", "git-repo-ref", "gpg-key-id",
    "gpg-key-ring", "gpg-passphrase", "group", "health-check", "health-check-timeout",
    "hostname", "ignore-paths", "image", "image-pull-secret", "image-ref", "interval",
    "key-file", "kind", "kubeconfig-secret-ref", "kustomization-file", "label",
    "label-selector", "layer-selector", "level", "local-sources", "log-level", "manifests",
    "name", "oci-provider", "oidc-audience", "oidc-provider", "oidc-token", "output", "owner",
    "path", "payload", "policy-change-delay", "poll-interval", "private-key-file",
    "provider", "provider-ref", "proxy-secret-ref", "push-branch", "reconcile-strategy",
    "ref-name", "reflect-digest", "region", "registry", "registry-creds", "release-name",
    "repository", "resource", "retries", "retry-delay", "retry-interval", "revision",
    "scan-timeout", "secret-key", "secret-name", "secret-ref", "select-alpha",
    "select-numeric", "select-semver", "service-account", "signing-key-secret",
    "signing-key-type", "since", "since-time", "source", "sparse-checkout",
    "sparse-checkout-paths", "ssh-ecdsa-curve", "ssh-hostkey-algos", "ssh-hostname",
    "ssh-key-algorithm", "ssh-rsa-bits", "ssh-signing-key-file", "ssh-signing-passphrase",
    "ssh-signing-password", "status-selector", "storage-namespace", "tag", "tag-semver",
    "tail", "target-namespace", "team", "tls-crt-file", "tls-key-file", "toleration-keys",
    "trust-policy-file", "type", "types", "url", "validation", "values", "values-from",
    "verify-issuer", "verify-provider", "verify-secret-ref", "verify-subject", "version",
    "visibility", "with-namespace", "with-service-account",
})
_FLUX_BOOL_FLAGS = frozenset(_FLUX_GLOBAL_BOOL_FLAGS) | frozenset({
    "all", "all-namespaces", "allow-insecure-http", "client", "compact",
    "create-target-namespace", "debug", "deploy-token-auth", "digests", "dry-run", "export",
    "follow", "force", "help", "ignore-not-found", "in-memory-build", "insecure",
    "insecure-registry", "keep-namespace", "network-policy", "no-header", "pass-credentials",
    "personal", "pre", "private", "progress-bar", "prune", "read-write-key", "reconcile",
    "recurse-submodules", "recursive", "reproducible", "reset", "resolve-symlinks",
    "show-history", "show-source", "show-status", "show-values", "show-vars", "silent",
    "skip-namespace", "ssh-signing-reuse-private-key", "strict", "strict-substitute",
    "token-auth", "wait", "watch", "watch-all-namespaces", "with-bearer-token",
    "with-credentials", "with-source", "yes",
})

# Flux's short letters on the verbs parsed here, read from its source (flux2 v2.10; flux is
# not run in the tests). -o is on none of them, and is listed so -oyaml reads as a value.
_FLUX_SHORT_VALUE_LETTERS = frozenset("lnopuv")
_FLUX_SHORT_BOOL_LETTERS = frozenset("Ahsw")

# The flux kinds, as the parser names them, with the names flux 2.10 also takes for them in
# TYPE/NAME and as a word its sub-commands do not have (cmd/flux/resource_arg.go: the kind,
# plural and short names), and the verbs that take each.
_FLUX_ALL_TYPE_VERBS = frozenset({"get", "reconcile", "suspend", "resume", "export", "delete"})
_FLUX_TYPES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "helmrelease": (frozenset({"helmrelease", "helmreleases", "hr"}), _FLUX_ALL_TYPE_VERBS),
    "kustomization": (frozenset({"kustomization", "kustomizations", "ks"}),
                      _FLUX_ALL_TYPE_VERBS),
    "source-git": (frozenset({"gitrepository", "gitrepositories", "gitrepo"}),
                   _FLUX_ALL_TYPE_VERBS),
    "source-oci": (frozenset({"ocirepository", "ocirepositories", "ocirepo"}),
                   _FLUX_ALL_TYPE_VERBS),
    "source-helm": (frozenset({"helmrepository", "helmrepositories", "helmrepo"}),
                    _FLUX_ALL_TYPE_VERBS),
    "source-chart": (frozenset({"helmchart", "helmcharts", "hc"}), _FLUX_ALL_TYPE_VERBS),
    "source-bucket": (frozenset({"bucket", "buckets"}), _FLUX_ALL_TYPE_VERBS),
    "source-external": (frozenset({"externalartifact", "externalartifacts", "ea"}),
                        frozenset({"get", "export"})),
    "artifact-generator": (frozenset({"artifactgenerator", "artifactgenerators", "ag"}),
                           _FLUX_ALL_TYPE_VERBS - {"delete"}),
    "image-repository": (frozenset({"imagerepository", "imagerepositories", "imgrepo",
                                    "imagerepo"}), _FLUX_ALL_TYPE_VERBS),
    "image-policy": (frozenset({"imagepolicy", "imagepolicies", "imgpol", "imagepol"}),
                     _FLUX_ALL_TYPE_VERBS),
    "image-update": (frozenset({"imageupdateautomation", "imageupdateautomations", "iua",
                                "imgupd", "imgauto"}), _FLUX_ALL_TYPE_VERBS),
    "alert": (frozenset({"alert", "alerts"}), _FLUX_ALL_TYPE_VERBS - {"reconcile"}),
    "alert-provider": (frozenset({"provider", "providers", "alert-provider",
                                  "alert-providers"}), _FLUX_ALL_TYPE_VERBS - {"reconcile"}),
    "receiver": (frozenset({"receiver", "receivers"}), _FLUX_ALL_TYPE_VERBS),
}
_FLUX_TYPE_NAMES = {name: kind for kind, (names, _verbs) in _FLUX_TYPES.items()
                    for name in names}

# The sub-commands of each verb: a word for a kind, or a group word whose sub-command is the
# kind ("source git"). From flux2 v2.10 cmd/flux (the Use and Aliases of each command).
_FLUX_MUTATION_WORDS = {"kustomization": "kustomization", "ks": "kustomization",
                        "helmrelease": "helmrelease", "hr": "helmrelease",
                        "alert": "alert", "alert-provider": "alert-provider",
                        "receiver": "receiver"}
_FLUX_SOURCE_KINDS = ("git", "oci", "helm", "chart", "bucket")
_FLUX_IMAGE_KINDS = ("repository", "policy", "update")
_FLUX_GROUPS = {
    "reconcile": {"source": _FLUX_SOURCE_KINDS, "image": _FLUX_IMAGE_KINDS,
                  "artifact": ("generator",)},
    "suspend": {"source": _FLUX_SOURCE_KINDS, "image": _FLUX_IMAGE_KINDS,
                "artifact": ("generator",)},
    "resume": {"source": _FLUX_SOURCE_KINDS, "image": _FLUX_IMAGE_KINDS,
               "artifact": ("generator",)},
    "delete": {"source": _FLUX_SOURCE_KINDS, "image": _FLUX_IMAGE_KINDS},
    "export": {"source": (*_FLUX_SOURCE_KINDS, "external"), "image": _FLUX_IMAGE_KINDS,
               "artifact": ("generator",)},
    "create": {"source": _FLUX_SOURCE_KINDS, "image": _FLUX_IMAGE_KINDS,
               "secret": ("git", "githubapp", "helm", "notation", "oci", "proxy", "receiver",
                          "tls")},
}
# reconcile alert and alert-provider are gone from flux 2.10 and still in older releases.
_FLUX_WORDS = {
    verb: _FLUX_MUTATION_WORDS | ({"tenant": "tenant"} if verb == "create" else {})
    for verb in _FLUX_GROUPS
}

# What "reconcile --with-source" also reconciles: the object's source, of one of these
# kinds, whose name is only known when flux reads the object (reconcile_with_source.go).
# A HelmRelease's chart is reconciled with its own source as well.
_FLUX_WITH_SOURCE_KINDS = {
    "kustomization": ("source-git", "source-oci", "source-bucket"),
    "helmrelease": ("source-chart", "source-oci", "source-helm", "source-git",
                    "source-bucket"),
    "source-chart": ("source-helm", "source-git", "source-bucket"),
}


def _parse_flux_tokens(
    tokens: list[str], verb: str | None = None
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    short_bools, short_values = _flux_short_letters(verb)

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            # pflag: every word after it is an operand
            positional.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and tok != "-":
            is_long = tok.startswith("--")
            if not is_long and len(tok) > 2:
                flags = _split_short_word(tok, short_bools, short_values, "flux")
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
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
            elif key in ("verbose", "insecure-skip-tls-verify", "disable-compression"):
                pass  # consumed, intentionally not recorded
            elif key == "dry-run":
                # Not a flag of any verb parsed here: flux refuses it and runs nothing.
                # It is never read as a rehearsal.
                pass
            elif key == "export":
                params["export"] = _bool_param(val)
            elif is_long and key in _FLUX_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and key in short_bools:
                # Takes no value: in "get ks -A a" the name is "a".
                params[key] = _bool_param(val)
            elif not is_long and key in short_values:
                # Always the next token, whatever it looks like, as pflag reads it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = _coerce(val)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, params[key.replace("-", "_")] = _other_flag(
                    tokens, i, values=_FLUX_VALUE_FLAGS if is_long else (), bools=(),
                    tool="flux")
        else:
            positional.append(tok)
        i += 1

    # --export only prints YAML, so it rehearses; its last value counts.
    if params.get("export") is True:
        params["dry_run"] = True
    return metadata, params, positional


def _flux_type_name(word: str, verb: str) -> tuple[str, str]:
    """``TYPE[.VERSION.GROUP]/NAME`` (flux 2.10) as ``(kind, name)``: flux rewrites it to
    the sub-command for TYPE. Anything flux refuses is refused."""
    typ, slash, name = word.partition("/")
    if not slash or not typ or not name or "/" in name or name.startswith("-"):
        raise ValueError(f"flux: {word!r} is not a TYPE/NAME flux accepts")
    kind = _FLUX_TYPE_NAMES.get(typ.split(".", 1)[0].lower())
    if kind is None or verb not in _FLUX_TYPES[kind][1]:
        raise ValueError(f"flux {verb}: {typ!r} is not a type flux {verb} takes")
    return kind, name


def _flux_kind_and_names(verb: str, positional: list[str]) -> tuple[str, list[str]]:
    """The kind and the names a flux verb is given, as flux reads them: a sub-command
    (``kustomization``, ``hr``, ``source git``, ``image policy``), a type flux 2.10 rewrites
    to one (``kustomizations``, ``gitrepo``), or TYPE/NAME words (``ks/a ks/b``), all of
    one type. Whatever flux refuses is a ValueError."""
    if not positional:
        raise ValueError("missing flux resource kind/name")
    head = positional[0]
    if "/" in head and verb in _FLUX_ALL_TYPE_VERBS:
        kinds_and_names = [_flux_type_name(word, verb) for word in positional]
        kinds = {kind for kind, _name in kinds_and_names}
        if len(kinds) > 1:
            raise ValueError(f"flux {verb}: TYPE/NAME words of different types: {positional!r}")
        return kinds.pop(), [name for _kind, name in kinds_and_names]
    groups = _FLUX_GROUPS.get(verb, {})
    if head in groups:
        if len(positional) < 2 or positional[1] not in groups[head]:
            raise ValueError(f"flux {verb} {head}: missing or unknown kind: {positional!r}")
        return f"{head}-{positional[1]}", positional[2:]
    if head in _FLUX_WORDS.get(verb, {}):
        return _FLUX_WORDS[verb][head], positional[1:]
    kind = _FLUX_TYPE_NAMES.get(head.lower())
    if kind is not None and verb in _FLUX_TYPES[kind][1]:
        return kind, positional[1:]
    raise ValueError(f"flux {verb}: unknown kind {head!r}")


def _flux_read_kind_and_names(verb: str, positional: list[str]) -> tuple[str, list[str]]:
    """The same for ``get`` and ``export``, which only read: a word no table knows stays
    the kind it was, so ``get all`` is ``all/*``. ``get`` has plural sub-commands."""
    if verb == "get" and positional:
        head, rest = positional[0], positional[1:]
        group = {"sources": "source", "source": "source", "images": "image", "image": "image",
                 "artifacts": "artifact", "artifact": "artifact"}.get(head)
        if group and rest:
            sub = {"generators": "generator"}.get(rest[0], rest[0])
            return f"{group}-{sub}", rest[1:]
        if "/" not in head:
            kind = _FLUX_TYPE_NAMES.get(head.lower())
            return (kind or head), rest
    try:
        return _flux_kind_and_names(verb, positional)
    except ValueError:
        return positional[0], []


def from_flux_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``flux`` invocation into one InfrastructureIntent per object, e.g.:

    ``flux reconcile source git podinfo -n flux-system``
      -> resource "source-git/podinfo", action "sync", metadata {"namespace": "flux-system"}
    ``flux suspend kustomization podinfo``
      -> resource "kustomization/podinfo", action "stop"
    ``flux suspend ks/a ks/b`` and ``flux suspend kustomization a b``
      -> "kustomization/a" and "kustomization/b"
    ``flux suspend kustomization --all`` -> "kustomization/*", marked
    """
    if len(argv) < 2 or _basename(argv[0]) != "flux":
        raise ValueError(f"not a recognizable flux invocation: {argv!r}")

    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_FLUX_GLOBAL_VALUE_FLAGS,
        bool_flags=_FLUX_GLOBAL_BOOL_FLAGS,
        tool="flux",
        glued_values=True,
    )
    verb = rest[0]
    tokens = leading + rest[1:]
    metadata, params, positional = _parse_flux_tokens(tokens, verb)
    params["raw_action"] = verb

    def make(resources: list[str], action: str, extra: dict[str, Any] | None = None):
        return [InfrastructureIntent(resource=r, action=action, provider="flux",
                                     params={**params, **(extra or {})},
                                     metadata=dict(metadata)) for r in resources]

    if verb == "bootstrap":
        provider_name = positional[0] if positional else "*"
        return make([f"bootstrap/{provider_name}"], "create")

    if verb in _FLUX_VERB_ACTION:
        action = _FLUX_VERB_ACTION[verb]
        kind, names = _flux_kind_and_names(verb, positional)
        if verb == "create":
            if not names:
                raise ValueError(f"could not find a flux object name in: {argv!r}")
            names = names[:1]  # flux create takes the first word as the name
        if not names:
            if verb in ("suspend", "resume") and params.get("all") is True:
                # every object of the kind in the namespace
                return _mark_open_targets(make([f"{kind}/*"], action))
            raise ValueError(f"missing flux resource name in: {argv!r}")
        intents = make([f"{kind}/{name}" for name in dict.fromkeys(names)], action)
        if verb == "reconcile" and params.get("with_source") is True:
            for name in dict.fromkeys(names):
                for source in _FLUX_WITH_SOURCE_KINDS.get(kind, ()):
                    marker = {"from": f"{kind}/{name}", "kinds": [source]}
                    intents.extend(make([f"{source}/*"], action,
                                        {"resolved_at_runtime": marker}))
        return intents

    if verb in _FLUX_READ_VERBS:
        if verb == "export":
            # "flux export ..." dumps resource YAML; it's read-only and
            # never touches the cluster, same as a dry-run.
            params["dry_run"] = True
        if not positional:
            return make(["*/*"], "read")
        kind, names = _flux_read_kind_and_names(verb, positional)
        return make([f"{kind}/{name}" for name in dict.fromkeys(names)] or [f"{kind}/*"],
                    "read")

    raise ValueError(f"unsupported flux subcommand: {argv!r}")


def from_flux(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``flux`` invocation that acts on exactly one object (see
    :func:`from_flux_multi`). Raises ValueError for ``flux suspend ks a b``."""
    intents = from_flux_multi(argv)
    if len(intents) != 1:
        raise ValueError(f"expected exactly one flux object, found {len(intents)}: {argv!r}")
    return intents[0]


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
                _record_dry_run(params, _is_dry_run(val))
            elif key == "no-dry-run":
                params.pop("dry_run", None)
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


# Every option of the git verbs the parser reads closely, from `git <verb> -h` and the
# hidden ones in `--git-completion-helper-all` (git 2.52). One word per option:
# "<short>/<long>", then "=" when it takes a value (the rest of a short word, after a
# "=", or the next word whatever it looks like), "?" when it takes one only after "="
# (or in the rest of a short word), and "!" when "--no-<long>" turns it off.
_GIT_OPTION_SPECS = {
    "push": (
        "v/verbose! q/quiet! /repo=! /all! /branches! /mirror! d/delete! /tags! n/dry-run! "
        "/porcelain! f/force! /force-with-lease?! /force-if-includes! /recurse-submodules=! "
        "/thin! /receive-pack=! /exec=! u/set-upstream! /progress! /prune! /no-verify /verify "
        "/follow-tags! /signed?! /atomic! o/push-option=! 4/ipv4 6/ipv6"
    ),
    "branch": (
        "v/verbose! q/quiet! t/track?! u/set-upstream-to=! /unset-upstream! /color?! "
        "r/remotes /contains= /no-contains= /with= /without= /abbrev?! a/all d/delete! D/ "
        "m/move! M/ /omit-empty! c/copy! C/ l/list! /show-current! /create-reflog! "
        "/edit-description! f/force! /merged= /no-merged= /column?! /sort=! /points-at=! "
        "i/ignore-case! /recurse-submodules! /format=! /set-upstream!"
    ),
    "tag": (
        "l/list n/? d/delete v/verify a/annotate! m/message= F/file=! /trailer= e/edit! "
        "s/sign! /cleanup=! u/local-user=! f/force! /create-reflog! /column?! /contains= "
        "/no-contains= /with= /without= /merged= /no-merged= /omit-empty! /sort=! "
        "/points-at=! /format=! /color?! i/ignore-case!"
    ),
    "rebase": (
        "/onto=! /keep-base! /no-verify /verify q/quiet! v/verbose! n/no-stat /stat "
        "/signoff! /committer-date-is-author-date! /reset-author-date! /ignore-date! C/= "
        "/ignore-whitespace! /whitespace=! f/force-rebase! /no-ff /ff /continue /skip /abort "
        "/quit /edit-todo /show-current-patch /apply m/merge i/interactive /preserve-merges! "
        "/rerere-autoupdate! /empty= /keep-empty! /autosquash! /update-refs! S/gpg-sign?! "
        "/autostash! x/exec=! /allow-empty-message! r/rebase-merges?! /fork-point! "
        "s/strategy=! X/strategy-option=! /root! /reschedule-failed-exec! "
        "/reapply-cherry-picks!"
    ),
    "reset": (
        "q/quiet! /no-refresh /refresh /mixed /soft /hard /merge /keep "
        "/recurse-submodules?! p/patch! U/unified= /inter-hunk-context= N/intent-to-add! "
        "/pathspec-from-file=! /pathspec-file-nul!"
    ),
    "commit": (
        "q/quiet! v/verbose! F/file=! /author=! /date=! m/message=! c/reedit-message=! "
        "C/reuse-message=! /fixup=! /squash=! /reset-author! /trailer= s/signoff! "
        "t/template=! e/edit! /cleanup=! /status! S/gpg-sign?! a/all! i/include! "
        "/interactive! p/patch! U/unified= /inter-hunk-context= o/only! n/no-verify /verify "
        "/dry-run! /short! /branch! /ahead-behind! /porcelain! /long! z/null! /amend! "
        "/no-post-rewrite /post-rewrite u/untracked-files?! /pathspec-from-file=! "
        "/pathspec-file-nul! /allow-empty! /allow-empty-message!"
    ),
}


def _git_option_table(spec: str) -> tuple[dict[str, tuple[str, str]], dict[str, str], set[str]]:
    """``(shorts, longs, negatable)`` from one entry of :data:`_GIT_OPTION_SPECS`: a short
    letter maps to ``(name, arity)``, a long name to its arity ("", "=" or "?")."""
    shorts: dict[str, tuple[str, str]] = {}
    longs: dict[str, str] = {}
    negatable: set[str] = set()
    for word in spec.split():
        short, _slash, rest = word.partition("/")
        neg = rest.endswith("!")
        rest = rest.rstrip("!")
        arity = rest[-1] if rest and rest[-1] in "=?" else ""
        name = rest.rstrip("=?")
        if name:
            longs[name] = arity
            if neg:
                negatable.add(name)
        if short:
            shorts[short] = (name or short, arity)
    return shorts, longs, negatable


_GIT_OPTIONS = {verb: _git_option_table(spec) for verb, spec in _GIT_OPTION_SPECS.items()}


def _git_long_option(verb: str, key: str) -> tuple[str, bool]:
    """The long option ``--key`` names on ``verb`` and whether it is the ``--no-`` form, as
    git's parse-options finds it: the exact name, ``no-<name>`` of a negatable one, or a
    prefix of exactly one of those (``--forc`` is ambiguous, ``--amen`` is ``--amend``)."""
    _shorts, longs, negatable = _GIT_OPTIONS[verb]
    if key in longs:
        return key, False
    if key.startswith("no-") and key[3:] in negatable:
        return key[3:], True
    spellings = [(name, False) for name in longs] + [(f"no-{name}", True) for name in negatable]
    found = [(name, neg) for name, neg in spellings if name.startswith(key)]
    if len(found) == 1:
        name, neg = found[0]
        return (name[3:] if neg else name), neg
    reason = "is ambiguous" if found else "is not an option of"
    raise ValueError(f"git {verb}: --{key} {reason} git {verb}")


def _parse_git_options(verb: str, tokens: list[str]) -> tuple[list[tuple[str, Any]], list[str]]:
    """``tokens`` as git's parse-options reads them on ``verb``: the options in order, as
    ``(long name, value)`` with value None for the ``--no-`` form and True for a bare
    option, and the operands. Short words bundle (``-fu``), a value option takes the rest
    of its word or the next word, ``--`` and ``--end-of-options`` end the options, and
    anything git refuses is a ValueError."""
    shorts, longs, _negatable = _GIT_OPTIONS[verb]
    options: list[tuple[str, Any]] = []
    operands: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in ("--", "--end-of-options"):
            operands.extend(tokens[i + 1:])
            break
        if tok.startswith("--"):
            key, val = _split_flag(tok)
            name, negated = _git_long_option(verb, key)
            arity = longs[name]
            if negated or not arity:
                if val is not None:
                    raise ValueError(f"git {verb}: {tok} takes no value")
                options.append((name, None if negated else True))
            elif val is None and arity == "=":
                i += 1
                if i < n:
                    val = tokens[i]
                options.append((name, val if val is not None else True))
            else:
                options.append((name, val if val is not None else True))
        elif tok.startswith("-") and tok != "-":
            rest = tok[1:]
            while rest:
                letter, rest = rest[0], rest[1:]
                if letter not in shorts:
                    raise ValueError(f"git {verb}: -{letter} is not an option of git {verb}")
                name, arity = shorts[letter]
                if not arity:
                    options.append((name, True))
                    continue
                if not rest and arity == "=":
                    i += 1
                    rest = tokens[i] if i < n else ""
                options.append((name, rest if rest else True))
                break
        else:
            operands.append(tok)
        i += 1
    return options, operands


def _git_last(options: list[tuple[str, Any]], *names: str) -> Any:
    """The value the last of ``names`` was given (None for a ``--no-`` form), or None."""
    value = None
    for name, val in options:
        if name in names:
            value = val
    return value


def _git_option_params(verb: str, options: list[tuple[str, Any]]) -> dict[str, Any]:
    """The params a git verb's options set, each by its last spelling."""
    params: dict[str, Any] = {}
    for name, val in options:
        key = name.replace("-", "_")
        if val is None:
            params.pop(key, None)
        else:
            params[key] = _coerce(val) if isinstance(val, str) else val
    for name in ("force", "delete", "dry_run", "amend", "hard"):
        params.pop(name, None)
    if verb == "push":
        if _git_last(options, "force") or _git_last(options, "force-with-lease"):
            params["force"] = True
        if _git_last(options, "force-with-lease"):
            params["force_with_lease"] = True
        if _git_last(options, "delete"):
            params["delete"] = True
        if _git_last(options, "dry-run"):
            params["dry_run"] = True
    elif verb in ("branch", "tag"):
        if _git_last(options, "delete", "D"):
            params["delete"] = True
        if _git_last(options, "force", "D", "M", "C"):
            params["force"] = True
        if verb == "branch":
            # -m/-M rename a branch and -c/-C copy one; the capital letters overwrite an
            # existing branch of the new name, as --force does
            if _git_last(options, "move", "M"):
                params["rename"] = True
            elif _git_last(options, "copy", "C"):
                params["copy"] = True
    elif verb == "commit":
        if _git_last(options, "amend"):
            params["amend"] = True
        if _git_last(options, "dry-run"):
            params["dry_run"] = True
    elif verb == "reset":
        # git keeps the last mode; a --hard anywhere counts, which can only be stricter
        if any(name == "hard" for name, _val in options):
            params["hard"] = True
    elif verb == "rebase" and _git_last(options, "force-rebase"):
        params["force"] = True
    return params


def _git_push_intent(
    refspec: str | None, params: dict[str, Any], metadata: dict[str, Any]
) -> InfrastructureIntent:
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
    if not ref or "*" in ref:
        # No refspec: the target is whatever the local branch / push.default
        # / --all / --mirror resolve to — unknowable from the argv. Marked
        # so the caller can escalate ("git push -f" must not sail past a
        # "ref/main" rule as "ref/*"). A pattern refspec ("refs/heads/*")
        # reaches every ref it matches, which is just as unknown.
        params["unknown_target"] = True

    resource = f"ref/{ref}" if ref else "ref/*"
    action = "delete" if delete else "push"
    return InfrastructureIntent(
        resource=resource, action=action, provider="git", params=params, metadata=metadata
    )


def _from_git_push(
    positional: list[str], params: dict[str, Any], metadata: dict[str, Any]
) -> list[InfrastructureIntent]:
    """One intent per refspec: ``git push origin a +b :c`` pushes a, force-pushes b and
    deletes c. ``--tags`` also pushes every tag, and ``--prune`` deletes every remote ref
    with no local one, neither of which the argv names."""
    remote = positional[0] if positional else None
    refspecs = positional[1:]
    if remote is not None:
        metadata = {**metadata, "remote": remote}
    intents = [_git_push_intent(refspec, params, metadata) for refspec in refspecs or [None]]
    if refspecs and params.get("tags") is True:
        intents.append(_git_push_intent(None, params, metadata))
    if params.get("prune") is True:
        intents.append(_git_push_intent(None, {**params, "delete": True}, metadata))
    return intents


def from_git_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``git`` invocation. Only remote-affecting or history-rewriting
    commands produce non-read intents; local reads are ``read``, e.g.:

    ``git push -f origin HEAD:main``
      -> resource "ref/main", action "push", params {"force": True}, metadata {"remote": "origin"}
    ``git rebase main``
      -> resource "history/main", action "rewrite"

    ``push``, ``branch``, ``tag``, ``rebase``, ``reset`` and ``commit`` are read as git's
    parse-options reads them (:func:`_parse_git_options`), so ``-fu`` is ``-f -u``,
    ``--amen`` is ``--amend``, ``-n`` is ``--dry-run`` only on push, and an option git
    refuses is refused. ``git push origin a b`` and ``git branch -d a b`` are one intent
    per ref or branch.
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
    if verb in _GIT_OPTIONS:
        options, positional = _parse_git_options(verb, tokens)
        params = _git_option_params(verb, options)
    else:
        params, positional = _parse_git_tokens(tokens)
    metadata: dict[str, Any] = {}
    params["raw_action"] = verb

    def one(resource: str, action: str) -> InfrastructureIntent:
        return InfrastructureIntent(resource=resource, action=action, provider="git",
                                    params=dict(params), metadata=dict(metadata))

    if verb == "push":
        return _from_git_push(positional, params, metadata)

    if verb in ("branch", "tag"):
        if params.get("delete"):
            if not positional:
                raise ValueError(f"could not find a {verb} name in: {argv!r}")
            # git deletes every one it is given
            return [one(f"{verb}/{name}", "delete") for name in dict.fromkeys(positional)]
        if params.get("rename") or params.get("copy"):
            return _git_branch_move(positional, one, params, argv)
        if verb == "branch" and params.get("force") and positional:
            # git branch -f <name> [<start>] resets an existing branch to <start>
            return [one(f"branch/{positional[0]}", "create"),
                    one(f"branch/{positional[0]}", "delete")]
        return [one(f"{verb}/{positional[0] if positional else '*'}", "read")]

    if verb == "rebase":
        # "git rebase <upstream> <branch>" rewrites <branch>: both are targets
        targets = positional[:2] or ["HEAD"]
        return [one(f"history/{target}", "rewrite") for target in targets]

    if verb == "reset" and params.get("hard"):
        target = positional[0] if positional else "HEAD"
        return [one(f"history/{target}", "rewrite")]

    if verb == "commit" and params.get("amend"):
        return [one("history/HEAD", "rewrite")]

    if verb == "filter-branch":
        target = positional[0] if positional else "HEAD"
        return [one(f"history/{target}", "rewrite")]

    if verb == "filter-repo":
        # git filter-repo rewrites every ref of the repository, whatever it is given
        return _mark_open_targets([one("history/*", "rewrite")])

    # checkout, switch, log, status, diff, fetch, pull, commit (no --amend),
    # add, show, reset (no --hard), ... -- local/read-ish, nothing to gate.
    return [one("history/*", "read")]


def _git_branch_move(positional, one, params, argv) -> list[InfrastructureIntent]:
    """``git branch -m|-c [<old>] <new>``: the new branch is created (``create``), and with
    -M, -C or --force an existing branch of that name is overwritten, so it is also a
    ``delete``. A rename also removes the old name (``delete``). With one name the old
    branch is the current one, which the argv does not show: ``branch/*``, marked, so a
    rule on one branch escalates."""
    if not positional or len(positional) > 2:
        raise ValueError(f"could not find the branch names in: {argv!r}")
    new = positional[-1]
    intents = [one(f"branch/{new}", "create")]
    if params.get("force"):
        intents.append(one(f"branch/{new}", "delete"))
    if params.get("rename"):
        if len(positional) == 2:
            intents.append(one(f"branch/{positional[0]}", "delete"))
        else:
            intents.extend(_mark_open_targets([one("branch/*", "delete")]))
    return intents


def from_git(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``git`` invocation that has exactly one target (see
    :func:`from_git_multi`). Raises ValueError for ``git push origin a b``."""
    intents = from_git_multi(argv)
    if len(intents) != 1:
        raise ValueError(f"expected exactly one git target, found {len(intents)}: {argv!r}")
    return intents[0]


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


# The flags of the gh commands that change something, from cli/cli v2.103 (pkg/cmd, and
# cmdutil's enum and optional-value flags): booleans, flags that take a value, and short
# letters with the long flag each stands for on that command. -R/--repo and -h/--help are
# on every one. pflag reads them, so a value flag takes the next word whatever it is, and a
# boolean takes none: "gh pr merge -s 42" is a squash merge of 42 ("-r" is --rebase there
# and --ref on "workflow run").
_GH_COMMAND_FLAGS: dict[tuple[str, str], tuple[frozenset[str], frozenset[str], dict[str, str]]] = {
    ("pr", "merge"): (
        frozenset({"admin", "auto", "delete-branch", "disable-auto", "merge", "rebase", "squash"}),
        frozenset({"author-email", "body", "body-file", "match-head-commit", "subject"}),
        {"A": "author-email", "F": "body-file", "b": "body", "d": "delete-branch",
         "m": "merge", "r": "rebase", "s": "squash", "t": "subject"},
    ),
    ("pr", "close"): (
        frozenset({"delete-branch"}), frozenset({"comment"}),
        {"c": "comment", "d": "delete-branch"},
    ),
    ("repo", "delete"): (
        frozenset({"accept-cascading-deletion-of-private-forks", "confirm", "yes"}),
        frozenset(), {},
    ),
    ("release", "create"): (
        frozenset({"draft", "fail-on-no-commits", "generate-notes", "latest", "notes-from-tag",
                   "prerelease", "verify-tag"}),
        frozenset({"discussion-category", "notes", "notes-file", "notes-start-tag", "target",
                   "title"}),
        {"F": "notes-file", "d": "draft", "n": "notes", "p": "prerelease", "t": "title"},
    ),
    ("release", "delete"): (frozenset({"cleanup-tag", "yes"}), frozenset(), {"y": "yes"}),
    ("secret", "set"): (
        frozenset({"no-repos-selected", "no-store", "user"}),
        frozenset({"app", "body", "env", "env-file", "org", "repos", "visibility"}),
        {"a": "app", "b": "body", "e": "env", "f": "env-file", "o": "org", "r": "repos",
         "u": "user", "v": "visibility"},
    ),
    ("secret", "delete"): (
        frozenset({"user"}), frozenset({"app", "env", "org"}),
        {"a": "app", "e": "env", "o": "org", "u": "user"},
    ),
    ("variable", "set"): (
        frozenset(), frozenset({"body", "env", "env-file", "org", "repos", "visibility"}),
        {"b": "body", "e": "env", "f": "env-file", "o": "org", "r": "repos", "v": "visibility"},
    ),
    ("workflow", "run"): (
        frozenset({"json"}), frozenset({"field", "raw-field", "ref"}),
        {"F": "field", "f": "raw-field", "r": "ref"},
    ),
    ("api", ""): (
        frozenset({"allow-escape-sequences", "include", "paginate", "silent", "slurp",
                   "verbose"}),
        frozenset({"cache", "field", "header", "hostname", "input", "jq", "method", "preview",
                   "raw-field", "template"}),
        {"F": "field", "H": "header", "X": "method", "f": "raw-field", "i": "include",
         "p": "preview", "q": "jq", "t": "template"},
    ),
}
_GH_COMMON_BOOLS = frozenset({"help"})
_GH_COMMON_VALUES = frozenset({"repo"})
_GH_COMMON_SHORTS = {"R": "repo", "h": "help"}


def _parse_gh_tokens(
    tokens: list[str], command: tuple[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    spec = _GH_COMMAND_FLAGS.get(command) if command else None
    if spec is not None:
        return _parse_gh_command_tokens(tokens, spec)
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


def _parse_gh_command_tokens(
    tokens: list[str], spec: tuple[frozenset[str], frozenset[str], dict[str, str]],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """A gh command from :data:`_GH_COMMAND_FLAGS`, read as pflag reads it: short words
    letter by letter, a value flag takes the next word, ``--`` ends the flags, and a flag
    in no table is refused unless ``=value`` or its place shows its reading."""
    bools = spec[0] | _GH_COMMON_BOOLS
    values = spec[1] | _GH_COMMON_VALUES
    shorts = {**_GH_COMMON_SHORTS, **spec[2]}
    short_bools = frozenset(letter for letter, name in shorts.items() if name in bools)
    short_values = frozenset(letter for letter, name in shorts.items() if name in values)
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []

    tokens = list(tokens)  # short words are split in place as the walk reaches them
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "--":
            positional.extend(tokens[i + 1:])
            break
        if not tok.startswith("-") or tok == "-":
            positional.append(tok)
            i += 1
            continue
        is_long = tok.startswith("--")
        if not is_long and len(tok) > 2:
            flags = _split_short_word(tok, short_bools, short_values, "gh")
            if flags != [tok]:
                tokens[i:i + 1] = flags
                n = len(tokens)
                continue
        key, val = _split_flag(tok)
        name = key if is_long else shorts.get(key)
        if name is None or (name not in bools and name not in values):
            i, params[key.replace("-", "_")] = _other_flag(tokens, i, values=(), bools=(),
                                                           tool="gh")
        elif name in bools:
            on = _bool_param(val)
            if name in ("squash", "merge", "rebase"):
                if on is True:
                    params["method"] = name
            else:
                params[name.replace("-", "_")] = on
        else:
            if val is None:
                i += 1
                val = _value_at(tokens, i, tok)
            if name == "repo":
                metadata["repo"] = val
            elif name == "ref":
                metadata["ref"] = val
            elif name in ("field", "raw-field"):
                k, _sep, v = val.partition("=")
                params.setdefault("inputs", {})[k] = _coerce(v)
            elif name == "method":
                params["_method"] = val.upper()
            else:
                params[name.replace("-", "_")] = _coerce(val)
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
        metadata, params, positional = _parse_gh_tokens(rest, ("workflow", subverb))
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
        metadata, params, positional = _parse_gh_tokens(rest, ("release", subverb))
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
        metadata, params, positional = _parse_gh_tokens(rest, ("pr", subverb))
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
        metadata, params, positional = _parse_gh_tokens(rest, ("repo", subverb))
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
        metadata, params, positional = _parse_gh_tokens(rest, ("secret", subverb))
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
        metadata, params, positional = _parse_gh_tokens(rest, ("variable", subverb))
        params["raw_action"] = f"variable-{subverb}"
        name = positional[0] if positional else "*"
        action = "put" if subverb == "set" else "read"
        return InfrastructureIntent(
            resource=f"variable/{name}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "api":
        metadata, params, positional = _parse_gh_tokens(tokens, ("api", ""))
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


def from_terraform_argv(argv: list[str]) -> list[InfrastructureIntent] | None:
    """The one terraform/tofu invocation whose argv alone says it is
    destructive: ``destroy`` (and ``apply -destroy``) removes everything the
    configuration manages. That is one intent, provider ``terraform``,
    resource ``workspace/<name>`` (``$TF_WORKSPACE`` is not visible here, so
    the name is ``current`` unless ``-chdir=`` gives a directory), action
    ``delete``. Every other subcommand returns ``None``: what ``apply`` or
    ``import`` would change is only known from a plan, which
    :func:`from_terraform_plan` checks.
    """
    if not argv or _basename(argv[0]) not in ("terraform", "tofu"):
        raise ValueError(f"not a recognizable terraform/tofu invocation: {argv!r}")
    tool = "opentofu" if _basename(argv[0]) == "tofu" else "terraform"
    chdir: str | None = None
    rest = argv[1:]
    while rest and rest[0].startswith("-"):
        if rest[0].startswith("-chdir="):
            chdir = rest[0].split("=", 1)[1]
        rest = rest[1:]
    if not rest:
        return None
    sub, args = rest[0], rest[1:]
    destroy = sub == "destroy" or (sub == "apply" and _go_bool_flag(args, "destroy"))
    if not destroy:
        return None
    return [
        InfrastructureIntent(
            resource=f"workspace/{chdir or 'current'}",
            action="delete",
            provider="terraform",
            params={"argv": list(argv), "auto_approve": _go_bool_flag(args, "auto-approve")},
            metadata={"tool": tool},
        )
    ]


def _go_bool_flag(args: list[str], name: str) -> bool:
    """Whether Go's flag package, which terraform and tofu use, ends with the boolean
    ``-name`` on: ``-name``, ``--name`` and ``-name=true`` turn it on, ``-name=false``
    off, and the last one counts. A value strconv.ParseBool refuses (``-destroy=yes``)
    makes the tool refuse the command, so it counts as on, which can only be stricter."""
    on = False
    for arg in args:
        if arg == "--":
            break
        key, sep, value = arg.lstrip("-").partition("=")
        if arg.startswith("-") and key == name:
            on = not sep or value not in _GO_FALSE_WORDS
    return on


# --- help / version probes ------------------------------------------------------
#
# "What is this binary" probes (``helm --help``, ``argocd version --client``,
# ``kubectl delete --help``) change nothing, so they become one read-only
# ``cli/<tool>`` intent instead of a parse error. Only exact, per-tool forms
# count: a ``--help`` that some option could swallow as its value
# (``kubectl -n --help delete ns prod`` deletes), a plugin or alias that
# would receive the flag itself (``kubectl foo --help`` runs kubectl-foo),
# and tools that run several commands from one argv (``flyway version
# clean``) are left to the provider parser.

_INFO_PROVIDER = {
    "kubectl": "kubernetes", "aws": "aws", "az": "azure", "gcloud": "gcp", "gsutil": "gcp",
    "helm": "helm", "argocd": "argocd", "flux": "flux", "git": "git", "gh": "github",
    "psql": "sql", "mysql": "sql", "sqlite3": "sql", "mongosh": "mongodb", "pulumi": "pulumi",
    "alembic": "migration", "flyway": "migration", "rails": "migration", "prisma": "migration",
}

# The single token that alone prints help / the version, per tool. psql and
# mysql have no "-h" here (it is --host there). aws has no help form at all:
# a [toplevel] alias in ~/.aws/cli/alias can replace "help" and any service
# name ("s3 = !cmd" makes "aws s3 help" run cmd); only --version is built in.
_INFO_HELP_FLAGS = {
    "kubectl": {"--help", "-h"}, "aws": set(), "az": {"--help", "-h"},
    "gcloud": {"--help", "-h"}, "gsutil": {"--help"}, "helm": {"--help", "-h"},
    "argocd": {"--help", "-h"}, "flux": {"--help", "-h"}, "git": {"--help", "-h"},
    "gh": {"--help", "-h"}, "psql": {"--help", "-?"}, "mysql": {"--help", "-?"},
    "sqlite3": {"--help", "-help"}, "mongosh": {"--help", "-h"},
    "pulumi": {"--help", "-h"}, "alembic": {"--help", "-h"},
    "flyway": {"--help", "-h", "-?"}, "rails": {"--help", "-h"},
    "prisma": {"--help", "-h"},
}
_INFO_VERSION_FLAGS = {
    "kubectl": {"--version"}, "aws": {"--version"}, "az": {"--version"},
    "gcloud": {"--version"}, "gsutil": {"version"}, "helm": {"--version"},
    "argocd": {"--version"}, "flux": {"--version"}, "git": {"--version"},
    "gh": {"--version"}, "psql": {"--version", "-V"}, "mysql": {"--version", "-V"},
    "sqlite3": {"--version", "-version"}, "mongosh": {"--version"},
    "pulumi": {"--version"}, "alembic": {"--version"}, "flyway": {"-v", "--version"},
    "rails": {"--version", "-v"}, "prisma": {"--version", "-v"},
}

# Tools with a "help [topic...]" subcommand that only prints help ...
_INFO_HELP_VERB_TOOLS = {"kubectl", "helm", "argocd", "flux", "git", "gh", "gcloud", "pulumi"}
# ... and with a "help" that must stand alone.
_INFO_BARE_HELP_TOOLS = {"flyway", "rails"}
# Tools whose "version" subcommand is a built-in leaf: options after it
# (--client, --short, -o json) still only print versions ...
_INFO_VERSION_VERB_TOOLS = {"kubectl", "helm", "argocd", "flux", "gh", "pulumi"}
# ... and whose "version" must stand alone (flyway runs every command word
# it is given: "flyway version clean" cleans).
_INFO_BARE_VERSION_TOOLS = {"git", "az", "gcloud", "prisma", "flyway", "rails"}

# "<tool> <words...> --help" is help when the first word is a built-in
# command (plugins, extensions and aliases receive the flag themselves).
# None: any first word, the tool handles --help before running anything.
_INFO_VERB_HELP_BUILTINS: dict[str, frozenset[str] | None] = {
    "kubectl": frozenset({
        "create", "expose", "run", "set", "explain", "get", "edit", "delete", "rollout",
        "scale", "autoscale", "certificate", "cluster-info", "top", "cordon", "uncordon",
        "drain", "taint", "describe", "logs", "attach", "exec", "port-forward", "proxy",
        "cp", "auth", "debug", "events", "diff", "apply", "patch", "replace", "wait",
        "kustomize", "label", "annotate", "completion", "api-resources", "api-versions",
        "config", "kuberc", "plugin", "version", "options",
    }),
    "helm": frozenset({
        "completion", "create", "dependency", "env", "get", "history", "install", "lint",
        "list", "package", "plugin", "pull", "push", "registry", "repo", "rollback",
        "search", "show", "status", "template", "test", "uninstall", "upgrade", "verify",
        "version",
    }),
    "argocd": frozenset({
        "account", "admin", "app", "appset", "cert", "cluster", "completion", "context",
        "gpg", "login", "logout", "proj", "relogin", "repo", "repocreds", "version",
    }),
    "flux": frozenset({
        "bootstrap", "build", "check", "completion", "create", "delete", "diff", "events",
        "export", "get", "install", "logs", "reconcile", "resume", "stats", "suspend",
        "trace", "tree", "uninstall", "version", "push", "pull", "tag", "list", "artifact",
        "debug", "envsubst", "migrate",
    }),
    "gh": frozenset({
        "auth", "browse", "codespace", "gist", "issue", "org", "pr", "project", "release",
        "repo", "cache", "run", "search", "secret", "ssh-key", "status", "variable",
        "workflow", "api", "attestation", "completion", "config", "extension", "gpg-key",
        "label", "ruleset", "alias",
    }),
    "pulumi": frozenset({
        "about", "cancel", "config", "console", "convert", "destroy", "env", "gen-completion",
        "import", "install", "login", "logout", "new", "org", "package", "plugin", "policy",
        "preview", "refresh", "schema", "stack", "state", "up", "version", "watch", "whoami",
    }),
    "az": None,
    "gcloud": None,
    "prisma": None,
}
# kubectl command groups and their built-in subcommands (kubectl 1.36, with
# aliases): "kubectl create <x> --help" runs a kubectl-create-<x> plugin
# when <x> is not one of these, so only these are help.
_KUBECTL_SUBCOMMANDS: dict[tuple[str, ...], frozenset[str]] = {
    ("create",): frozenset({
        "clusterrole", "clusterrolebinding", "configmap", "cm", "cronjob", "cj", "deployment",
        "deploy", "ingress", "ing", "job", "namespace", "ns", "poddisruptionbudget", "pdb",
        "priorityclass", "pc", "quota", "resourcequota", "role", "rolebinding", "secret",
        "service", "svc", "serviceaccount", "sa", "token",
    }),
    ("create", "secret"): frozenset({"docker-registry", "generic", "tls"}),
    ("create", "service"): frozenset({"clusterip", "externalname", "loadbalancer", "nodeport"}),
    ("create", "svc"): frozenset({"clusterip", "externalname", "loadbalancer", "nodeport"}),
    ("set",): frozenset({"env", "image", "resources", "selector", "serviceaccount", "sa",
                         "subject"}),
    ("rollout",): frozenset({"history", "pause", "restart", "resume", "status", "undo"}),
    ("certificate",): frozenset({"approve", "deny"}),
    ("cluster-info",): frozenset({"dump"}),
    ("top",): frozenset({"node", "nodes", "no", "pod", "pods", "po"}),
    ("auth",): frozenset({"can-i", "reconcile", "whoami"}),
    ("apply",): frozenset({"edit-last-applied", "set-last-applied", "view-last-applied"}),
    ("config",): frozenset({
        "current-context", "delete-cluster", "delete-context", "delete-user", "get-clusters",
        "get-contexts", "get-users", "rename-context", "set", "set-cluster", "set-context",
        "set-credentials", "unset", "use-context", "use", "view",
    }),
    ("kuberc",): frozenset({"set", "view"}),
    ("plugin",): frozenset({"list"}),
}

# One word, then the flag: the vcs tool rewrites "<cmd> --help" to
# "help <cmd>" only with --help directly after the command; alembic
# (argparse) exits on -h before running its command.
_INFO_ONE_VERB_HELP_TOOLS = {"git", "alembic"}

# Built-in command paths that pass every later argument, --help and -h
# included, to code outside the tool: "gh extension exec NAME --help" runs
# the extension (the command sets DisableFlagParsing).
_INFO_FORWARDING_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "gh": (("extension", "exec"),),
}

# The flags that make "<tool> <words...> <flag>" help, where narrower than
# the tool's own help flags: "git <cmd> -h" is handed to an alias as is
# (and is a real option of grep and ls-remote).
_INFO_VERB_HELP_FLAGS = {"git": {"--help"}}


def _kubectl_builtin_path(words: list[str]) -> bool:
    """Whether every kubectl command-group word in ``words`` is followed by
    one of that group's built-in subcommands (or by nothing)."""
    path: tuple[str, ...] = ()
    for word in words:
        path = (*path, word)
        parent = path[:-1]
        if parent and parent in _KUBECTL_SUBCOMMANDS and word not in _KUBECTL_SUBCOMMANDS[parent]:
            return False
        if path not in _KUBECTL_SUBCOMMANDS:
            return True  # a leaf command: what follows are its arguments
    return True


def _is_word(token: str) -> bool:
    return bool(token) and not token.startswith("-")


def _informational_kind(name: str, args: list[str]) -> str | None:
    """``"help"`` / ``"version"`` when ``<name> <args>`` is one of the exact
    informational forms described above, else ``None``."""
    if not args or "--" in args:
        return None
    if len(args) == 1 and args[0] in _INFO_HELP_FLAGS.get(name, ()):
        return "help"
    if len(args) == 1 and args[0] in _INFO_VERSION_FLAGS.get(name, ()):
        return "version"
    first, rest = args[0], args[1:]
    if first == "help":
        if name in _INFO_HELP_VERB_TOOLS and all(_is_word(t) for t in rest):
            return "help"
        if name in _INFO_BARE_HELP_TOOLS and not rest:
            return "help"
    if first == "version":
        if name in _INFO_VERSION_VERB_TOOLS:
            return "version"
        if name in _INFO_BARE_VERSION_TOOLS and (
            not rest or (name == "git" and rest == ["--build-options"])
        ):
            return "version"
    verb_help_flags = _INFO_VERB_HELP_FLAGS.get(name, _INFO_HELP_FLAGS.get(name, set()))
    if args[-1] in ("--help", "-h") and args[-1] in verb_help_flags:
        words = args[:-1]
        if not words or not all(_is_word(t) for t in words):
            return None
        if any(tuple(words[:len(path)]) == path
               for path in _INFO_FORWARDING_PATHS.get(name, ())):
            return None
        if name in _INFO_ONE_VERB_HELP_TOOLS:
            return "help" if len(words) == 1 else None
        if name in _INFO_VERB_HELP_BUILTINS:
            builtins = _INFO_VERB_HELP_BUILTINS[name]
            if name == "kubectl" and not _kubectl_builtin_path(words):
                return None
            if builtins is None or words[0] in builtins:
                return "help"
    return None


def informational_intent(argv: list[str]) -> InfrastructureIntent | None:
    """The read-only intent for a help / version probe (``helm --help``,
    ``argocd version --client``, ``kubectl delete --help``,
    ``aws s3 help``), or ``None`` when ``argv`` is not one: resource
    ``cli/<tool>``, action ``read``, the tool's usual provider, and
    ``params["informational"]`` set to ``"help"`` or ``"version"``."""
    if not argv:
        return None
    name = _basename(argv[0])
    if name not in _INFO_PROVIDER:
        return None
    kind = _informational_kind(name, list(argv[1:]))
    if kind is None:
        return None
    return InfrastructureIntent(
        resource=f"cli/{name}",
        action="read",
        provider=_INFO_PROVIDER[name],
        params={"informational": kind, "argv": list(argv)},
    )


def from_argv(argv: list[str]) -> list[InfrastructureIntent]:
    """Dispatches a raw argv to the right parser based on ``basename(argv[0])``,
    always returning a list of InfrastructureIntents (even for the
    single-intent parsers). Help and version probes become one read-only
    intent first (see :func:`informational_intent`)."""
    if not argv:
        raise ValueError("empty argv")

    info = informational_intent(argv)
    if info is not None:
        return [info]

    name = _basename(argv[0])
    if name == "kubectl":
        return from_kubectl_multi(argv)
    if name in ("terraform", "tofu"):
        destroy = from_terraform_argv(argv)
        if destroy is not None:
            return destroy
        raise ValueError(
            f"{name} invocations need a '{name} show -json' plan; "
            "use from_terraform_plan(plan_json) directly instead of from_argv"
        )
    if name == "aws":
        return from_aws_multi(argv)
    if name == "az":
        return from_az_multi(argv)
    if name in ("gcloud", "gsutil"):
        return from_gcloud_multi(argv)
    if name == "helm":
        return from_helm_multi(argv)
    if name == "argocd":
        return from_argocd_multi(argv)
    if name == "flux":
        return from_flux_multi(argv)
    if name == "git":
        return from_git_multi(argv)
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
