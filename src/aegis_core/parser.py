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
import os
import re
import zipfile
from collections.abc import Collection
from functools import lru_cache
from pathlib import Path
from typing import Any

from aegis_core.intent import InfrastructureIntent, canonical_key

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
    "ssh": "exec",  # runs commands on the machine
    "get-credentials": "read",
    "export": "export",  # writes the data out (gcloud sql export, aws ec2 export-image)
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

_KUBECTL_FLAGS_FILE = Path(__file__).parent / "data" / "kubectl_flags.json"


def _kubectl_flag_table() -> dict[str, Any]:
    """Every kubectl command's flags (``{flag: [kind, letter]}``) and the global ones
    (``options``), from ``kubectl <command> --help`` of kubectl 1.36
    (scripts/gen_kubectl_flags.py)."""
    with open(_KUBECTL_FLAGS_FILE) as f:
        return json.load(f)


_KUBECTL_TABLE = _kubectl_flag_table()
_KUBECTL_TABLE_KINDS: dict[str, set[str]] = {}
for _command, _flags in _KUBECTL_TABLE.items():
    if not _command.startswith("_") and _command != "options":
        for _name, (_kind, _letter) in _flags.items():
            _KUBECTL_TABLE_KINDS.setdefault(_name, set()).add(_kind)
_KUBECTL_OPTION_NAMES = frozenset(_KUBECTL_TABLE["options"])

# Overrides of the generated table, each for a reason the help cannot show:
# --cascade and --validate take a value but have a default for a bare use (pflag's
# NoOptDefVal), so a bare one takes no word; --delete-local-data and --record are
# deprecated booleans the help no longer lists.
_KUBECTL_BARE_DEFAULT_FLAGS = frozenset({"cascade", "validate"})
_KUBECTL_HIDDEN_BOOL_FLAGS = frozenset({"delete-local-data", "record"})
# Flags read by name before these tables (scope, selector, manifests, dry-run,
# impersonation and the global ones), or by command ("raw" is a value except on
# "config view"; "command", "containers" and "prefix" are strings only under kuberc set,
# set env and set resources, which _parse_flags handles).
_KUBECTL_BY_NAME = frozenset({
    "all-namespaces", "dry-run", "field-selector", "filename", "kustomize", "namespace",
    "output", "selector", "raw"}) | _KUBECTL_OPTION_NAMES

# kubectl flags that take no value token when given without "=value": every flag a
# kubectl command lists as a boolean, and the overrides above.
_KNOWN_BOOL_FLAGS = (
    {name for name, kinds in _KUBECTL_TABLE_KINDS.items() if "bool" in kinds}
    - _KUBECTL_BY_NAME) | _KUBECTL_BARE_DEFAULT_FLAGS | _KUBECTL_HIDDEN_BOOL_FLAGS

# kubectl flags that always take the next token as their value, even one that starts
# with "-" (pflag does: "--field-manager -n x" sets the field manager to "-n"):
# every flag a kubectl command lists as taking a value, but the booleans above and those
# read by name. --raw takes one wherever it is not config view's boolean.
# Three global value options no other table reads are listed too (--vmodule, --kuberc,
# --as-user-extra), and so are the letters -c and -L, which some callers look up before a
# letter is its long flag.
_KUBECTL_VALUE_FLAGS = (
    {name for name, kinds in _KUBECTL_TABLE_KINDS.items() if "value" in kinds}
    - _KUBECTL_BY_NAME - _KNOWN_BOOL_FLAGS) | {"raw", "c", "L", "vmodule", "kuberc",
                                                 "as-user-extra"}

# kubectl's integer flags (kubectl 1.36). pflag reads them with base 0, so
# "--replicas=0x0" is 0: see _go_int. --port is a string on expose and run.
_KUBECTL_INT_FLAGS = {
    "chunk-size", "concurrency", "current-replicas", "grace-period", "limit-bytes", "max",
    "max-log-requests", "min", "replicas", "retries", "revision",
    "skip-wait-for-delete-timeout", "tail", "to-revision",
}
@lru_cache(maxsize=256)
def _kubectl_letters(command: str | None) -> dict[str, tuple[str, str]]:
    """``{letter: (flag, kind)}`` on ``command`` (``logs``, ``create deployment``,
    ``rollout restart``): the global letters (``-n``, ``-s``, ``-v``) and the command's
    own, from its --help. For a command kubectl does not list, only the letters every
    command that has them gives the same meaning."""
    table = _KUBECTL_TABLE
    out = {letter: (name, kind) for name, (kind, letter) in table["options"].items()
           if letter}
    entry = table.get(command or "")
    if not isinstance(entry, dict) or command in ("options",) or (command or "")[:1] == "_":
        meanings: dict[str, set[tuple[str, str]]] = {}
        for key, flags in table.items():
            if key.startswith("_") or key == "options":
                continue
            for name, (kind, letter) in flags.items():
                if letter:
                    meanings.setdefault(letter, set()).add((name, kind))
        entry = {next(iter(m))[0]: [next(iter(m))[1], letter]
                 for letter, m in meanings.items() if len(m) == 1}
    out.update({letter: (name, kind) for name, (kind, letter) in entry.items() if letter})
    return out


def _kubectl_short_name(letter: str, verb: str | None, replicas: bool) -> str | None:
    """The long flag kubectl's ``-<letter>`` is on the command ``verb`` (from its --help),
    or None when it has none. ``replicas`` names ``create deployment`` when only
    ``create`` is known."""
    command = "create deployment" if replicas and verb == "create" else verb
    found = _kubectl_letters(command).get(letter)
    return found[0] if found else None


# kubectl verbs whose short "-f" is the boolean --follow, not --filename.
_KUBECTL_FOLLOW_VERBS = {"logs"}

# What Go's strconv.ParseBool reads as false, which is how kubectl reads a boolean
# flag's value. It refuses any other word that is not one of its true spellings.
_GO_FALSE_WORDS = frozenset({"0", "f", "F", "FALSE", "false", "False"})

# Flags that cannot change what a tool does to which object, per tool, each with why. Every
# other flag a parser consumes is recorded (params under its long name, or metadata). Never
# here: impersonation, auth, headers, endpoints, kubeconfig, context, server, TLS checks,
# tokens, certificates (tests/test_parser_flag_reading.py checks every flag of every table).
_NO_EFFECT_FLAGS: dict[str, dict[str, str]] = {
    "kubectl": {
        "o": "how the result is printed", "output": "how the result is printed",
        "v": "log verbosity", "log-flush-frequency": "how often logs are flushed",
        "profile": "profiles kubectl itself", "profile-output": "where that profile goes",
        "request-timeout": "only shortens how long kubectl waits",
        "warnings-as-errors": "can only make kubectl fail",
        "match-server-version": "can only make kubectl refuse to run",
        "disable-compression": "transport encoding of responses",
    },
    "helm": {
        "help": "prints the usage; the command does not run", "debug": "log verbosity",
        "color": "colour of the output",
        "colour": "colour of the output", "burst-limit": "client-side rate limit",
        "qps": "client-side rate limit", "content-cache": "where downloaded charts are cached",
    },
    "flux": {
        "help": "prints the usage; the command does not run", "verbose": "log verbosity",
        "disable-compression": "transport encoding of responses",
        "kube-api-burst": "client-side rate limit", "kube-api-qps": "client-side rate limit",
    },
    "argocd": {
        "help": "prints the usage; the command does not run", "logformat": "log format",
        "loglevel": "log verbosity",
        "http-retry-max": "how often a failed call is retried",
        "redis-compress": "compression of the cache it reads",
        "prompts-enabled": "whether it asks before acting (the command line decides anyway)",
    },
    "gh": {
        "help": "prints the usage; the command does not run",
    },
    "aws": {
        "output": "how the result is printed", "query": "which part of the result is printed",
        "color": "colour of the output", "no-cli-pager": "paging of the output",
        "no-cli-auto-prompt": "interactive prompting", "cli-auto-prompt": "interactive prompting",
        "cli-error-format": "how errors are printed", "no-paginate": "how results are paged",
        "cli-connect-timeout": "only shortens how long aws waits",
        "cli-read-timeout": "only shortens how long aws waits",
        "version": "prints the version and does nothing else", "debug": "log verbosity",
    },
    "gsutil": {
        "m": "runs operations in parallel", "q": "quiet output", "d": "debug output",
        "D": "debug output", "v": "prints the version",
    },
}
# Flags whose value is a secret: recorded as given but not kept (only that it was given).
_SECRET_FLAGS = frozenset({"token", "password", "kube-token", "auth-token"})
# Flags that change who the request runs as: the identity scope is then unresolved.
_IDENTITY_FLAGS = frozenset({
    "token", "username", "password", "client-certificate", "client-key", "kube-token",
    "auth-token", "client-crt", "client-crt-key",
})


def _record_flag(params: dict[str, Any], tool: str, key: str, val: Any) -> None:
    """A consumed flag recorded under its long name, unless it is one of ``tool``'s
    no-effect flags (:data:`_NO_EFFECT_FLAGS`). A secret's value is not kept; a flag that
    changes the identity leaves ``user`` unresolved."""
    if key in _NO_EFFECT_FLAGS.get(tool, {}):
        return
    params[key] = "[secret]" if key in _SECRET_FLAGS and isinstance(val, str) else (
        True if val is None else val)
    if key in _IDENTITY_FLAGS:
        _mark_unresolved(params, "user")


# Global boolean flags that kubectl consumes before the verb's own (recorded unless no-effect).
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


def _go_atoi(text: str, what: str) -> int:
    """``text`` as Go's strconv.Atoi reads it (an optional sign and decimal digits, as helm
    and argocd read a revision); anything else the tool refuses, and so does the parser.
    No value is ever typed by how it looks: only by the type the tool declares for it."""
    if not re.fullmatch(r"[+-]?[0-9]+", text):
        raise ValueError(f"{what} {text!r} is not a number the tool reads")
    return int(text)


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
    return coerced if coerced is not None else value


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


def _set_bool_param(params: dict[str, Any], key: str, value: Any) -> None:
    """Records a boolean flag under one key: ``--no-x`` is ``x: False`` and ``--x=false``
    is ``x: False`` too, with ``-`` as ``_``; the last spelling wins."""
    name = key.replace("-", "_")
    if name.startswith("no_") and isinstance(value, bool):
        name, value = name[3:], not value
    for spelling in (name, name.replace("_", "-"), f"no_{name}", f"no-{name.replace('_', '-')}"):
        params.pop(spelling, None)
    params[name] = value


def _record_all_namespaces(metadata: dict[str, Any], val: str | None) -> None:
    """``-A`` / ``--all-namespaces[=bool]`` as ``metadata["all_namespaces"]``, the one key
    the store reads for every namespace; the last spelling decides."""
    if _bool_param(val) is True:
        metadata["all_namespaces"] = True
    else:
        metadata.pop("all_namespaces", None)


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

    A letter in neither set is refused: what it means on this command is not known, and
    nothing is recorded as written."""
    flags: list[str] = []
    rest = word[1:]
    while rest:
        if rest.startswith("test."):
            break  # pflag ignores the rest of the word (go test's flags: parseSingleShortArg)
        letter, rest = rest[0], rest[1:]
        if len(rest) > 1 and rest[0] == "=":
            flags.append(f"-{letter}{rest}")
            break
        if letter in values:
            flags.append(f"-{letter}={rest}" if rest else f"-{letter}")
            break
        if letter not in bools:
            raise ValueError(f"{tool}: -{letter} in {word!r} is not a short flag the parser "
                             f"knows on this command; write its long flag")
        flags.append(f"-{letter}")
    return flags


# The pflag type of every flag of kubectl, helm, flux, argocd and gh, from their flag
# registrations (scripts/gen_pflag_types.py): what _pflag_store reads each value as.
_PFLAG_TYPES_FILE = Path(__file__).parent / "data" / "pflag_types.json"
_PFLAG_LISTS = frozenset({"StringArray", "StringSlice", "IntSlice", "Int32Slice", "Int64Slice",
                          "UintSlice", "BoolSlice", "DurationSlice", "Float64Slice",
                          "Float32Slice", "IPSlice"})
_PFLAG_CSV = _PFLAG_LISTS - {"StringArray"}
_PFLAG_INTS = {"Int": 64, "Int8": 8, "Int16": 16, "Int32": 32, "Int64": 64, "Uint": 64,
               "Uint8": 8, "Uint16": 16, "Uint32": 32, "Uint64": 64}
_PFLAG_FLOATS = frozenset({"Float32", "Float64"})
# The element type of each slice type (normalize_typed's kinds); a string slice has none.
_PFLAG_ELEMENT = {"IntSlice": "int", "Int32Slice": "int", "Int64Slice": "int",
                  "UintSlice": "int", "Float64Slice": "float", "Float32Slice": "float",
                  "BoolSlice": "bool", "DurationSlice": "duration"}
# What each pflag type is normalized as, for the parser's side and a rule's (None: text).
# Every type in pflag_types.json must be here (a test checks it).
PFLAG_NORMAL_KIND: dict[str, str | None] = {
    "String": None, "StringArray": None, "StringSlice": None, "IP": None, "IPSlice": None,
    "IPMask": None, "IPNet": None, "BytesHex": None, "BytesBase64": None,
    "Bool": "bool", "Count": "int", "Duration": "duration", "Float32": "float",
    "Float64": "float", "StringToString": "map", "StringToInt": "map-int",
    "StringToInt64": "map-int", "HelmWait": None,
    **{k: "int" for k in ("Int", "Int8", "Int16", "Int32", "Int64", "Uint", "Uint8",
                          "Uint16", "Uint32", "Uint64")},
    **_PFLAG_ELEMENT,
}


@lru_cache(maxsize=1)
def _pflag_tables() -> dict[str, Any]:
    with open(_PFLAG_TYPES_FILE) as f:
        return json.load(f)


def _pflag_kinds(tool: str, flag: str, command: str | None = None) -> frozenset[str]:
    """The pflag types ``--flag`` is registered with in ``tool``: the one ``command``
    (``create deployment``, ``app sync``, ``pr merge``) gives it when its type differs
    between commands and the table names the command, else every one it has, or none when
    the tables do not list it."""
    tables = _pflag_tables()
    kind = tables.get(tool, {}).get(flag)
    if kind is None:
        return frozenset()
    if kind.startswith("mixed:") and command:
        want = command.replace(" ", "").replace("-", "")
        for key, flags in tables.get(f"{tool}:commands", {}).items():
            norm = key.replace(" ", "")
            if flag in flags and norm in (want, "add" + want):
                kind = flags[flag]
                break
    return frozenset(kind[len("mixed:"):].split(",")) if kind.startswith("mixed:") \
        else frozenset({kind})


_GO_DURATION_RE = re.compile(r"([0-9]*\.?[0-9]+)(ns|us|µs|μs|ms|s|m|h)")
_GO_DURATION_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "ms": 1e-3, "s": 1.0,
                      "m": 60.0, "h": 3600.0}


def _go_duration(text: str, flag: str) -> int | float:
    """``text`` as Go's time.ParseDuration reads it (``5m``, ``1h2m3.5s``, ``-1s``, ``0``),
    in seconds: one representation, so ``--timeout 5m`` and ``--timeout 300s`` record the
    same. What Go refuses, the parser refuses."""
    body = text[1:] if text[:1] in "+-" else text
    sign = -1 if text.startswith("-") else 1
    if body == "0":
        return 0
    if not body or _GO_DURATION_RE.sub("", body):
        raise ValueError(f"{flag}: {text!r} is not a duration Go reads")
    total = sum(float(n) * _GO_DURATION_UNITS[u] for n, u in _GO_DURATION_RE.findall(body))
    total *= sign
    return int(total) if float(total).is_integer() else total


def _go_float(text: str, flag: str) -> float | int:
    """``text`` as Go's strconv.ParseFloat reads it; an integral value as an int."""
    try:
        value = float(text.replace("_", "")) if "_" not in text or text[:2].lower() in (
            "0x",) else float(text)
    except ValueError as exc:
        raise ValueError(f"{flag}: {text!r} is not a number Go reads") from exc
    return int(value) if value.is_integer() else value


_GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_GO_FALSE = frozenset({"0", "f", "F", "FALSE", "false", "False"})


def normalize_typed(kind: str, value: Any) -> Any:
    """One value of a typed flag in its one representation, for the parser's side and a
    rule's side alike: ``duration`` in seconds (Go's time.ParseDuration: ``5m``, ``300s``
    and ``5m0s`` are 300; a number is already seconds), ``int`` as Go's
    strconv.ParseInt(s, 0, 64) reads it (``0x0`` is 0, ``010`` is 8), ``float`` as
    ParseFloat, ``bool`` as ParseBool (``1``, ``t``, ``TRUE``, ``0``, ``f``, ``False``
    ...), ``map`` as a dict (``k=v,k2=v2``). A value the type cannot hold is a
    ValueError."""
    if kind == "duration":
        if isinstance(value, bool):
            raise ValueError(f"{value!r} is not a duration")
        if isinstance(value, (int, float)):
            return int(value) if float(value).is_integer() else value
        return _go_duration(str(value), "duration")
    if kind == "int":
        if isinstance(value, bool):
            raise ValueError(f"{value!r} is not an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return _go_int(str(value), "int", 64)
    if kind == "float":
        if isinstance(value, bool):
            raise ValueError(f"{value!r} is not a number")
        if isinstance(value, (int, float)):
            return int(value) if float(value).is_integer() else value
        return _go_float(str(value), "float")
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        text = str(value)
        if text in _GO_TRUE:
            return True
        if text in _GO_FALSE:
            return False
        raise ValueError(f"{value!r} is not a boolean Go reads")
    if kind.startswith(("gint", "gfloat", "gbool", "gsize:", "gduration:")):
        return _gcloud_typed(kind, value)
    if kind == "map-int":
        pairs = normalize_typed("map", value)
        return {k: normalize_typed("int", v) for k, v in pairs.items()}
    if kind == "map":
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        pairs: dict[str, str] = {}
        for item in _read_string_slice(str(value)):
            k, sep, v = item.partition("=")
            if not sep:
                raise ValueError(f"{item!r} must be key=value")
            pairs[k] = v
        return pairs
    return value


_GCLOUD_SIZE_SCALES = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40,
                       "P": 1 << 50, "KI": 1 << 10, "MI": 1 << 20, "GI": 1 << 30,
                       "TI": 1 << 40, "PI": 1 << 50}
_GCLOUD_LOWER_UNIT = {"PIB": "TIB", "PB": "TIB", "TIB": "GIB", "TB": "GIB", "GIB": "MIB",
                      "GB": "MIB", "MIB": "KIB", "MB": "KIB", "KIB": "B", "KB": "B"}


# The settings a gcloud file flag fills besides the one its name gives (--env-vars-file
# replaces what --set-env-vars or --update-env-vars would set).
_GCLOUD_FILE_FLAG_TARGETS = {
    "env-vars-file": ("env-vars", "set-env-vars", "update-env-vars"),
    "build-env-vars-file": ("build-env-vars", "set-build-env-vars", "update-build-env-vars"),
}


def _gcloud_mark_file_flag(params: dict[str, Any], key: str, declared: str | None) -> None:
    """gcloud reads the value of a file flag from a file when it runs: a flag named
    ``*-from-file`` or ``*-file``, or one the SDK types as FileContents, YAMLFileContents or
    BufferedFileInput (``file``, ``dict:file``). What the file holds is not read, so the
    setting it fills is unresolved: ``--metadata-from-file enable-oslogin=f.txt`` leaves
    ``metadata.enable-oslogin`` unresolved (each key given), ``--labels-file f`` leaves
    ``labels`` and every ``labels.*`` key unresolved."""
    if key.endswith("-from-file"):
        base = key[: -len("-from-file")]
    elif key.endswith("-file"):
        base = key[: -len("-file")]
    elif declared in ("file", "dict:file", "list:file"):
        base = key
    else:
        return
    targets = _GCLOUD_FILE_FLAG_TARGETS.get(key, (base,))
    value = params.get(key)
    if isinstance(value, dict):
        for name in value:
            for target in (key, *targets):
                _mark_unresolved(params, f"{target}.{name}")
        return
    for target in dict.fromkeys((key, *targets)):
        _mark_unresolved(params, target)
        _mark_unresolved(params, f"{target}.*")


def _gcloud_typed(kind: str, value: Any) -> Any:
    """A gcloud value as the SDK's declared type parses it (calliope arg_parsers):
    ``gint`` BoundedInt (Python int()), ``gfloat`` BoundedFloat, ``gbool`` ArgBoolean
    (true/yes, false/no, any case), ``gsize:<unit>`` BinarySize in bytes (``10GB``,
    ``2.5KB``, a bare number in the default unit, units without case, KB = 1024),
    ``gduration:<unit>`` Duration in seconds (times.ParseDuration: ``1h30m``, ``PT1H``, a
    bare integer in the default unit). A value the type refuses is a ValueError."""
    import decimal

    if isinstance(value, bool) and kind != "gbool":
        raise ValueError(f"{value!r} is not a {kind}")
    text = str(value)
    if kind == "gint":
        return value if isinstance(value, int) else int(text)
    if kind == "gfloat":
        number = float(text)
        return int(number) if number.is_integer() else number
    if kind == "gbool":
        if isinstance(value, bool):
            return value
        if text.lower() in ("true", "yes"):
            return True
        if text.lower() in ("false", "no"):
            return False
        raise ValueError(f"{value!r} is not a boolean gcloud reads")
    if kind.startswith("gsize:"):
        if isinstance(value, int):
            return value
        match = re.fullmatch(r"(\d+\.?\d*)([-/a-zA-Z]+)?", text)
        if not match:
            raise ValueError(f"{value!r} is not a size gcloud reads")
        amount, suffix = decimal.Decimal(match.group(1)), (match.group(2) or "")
        unit_key = suffix.upper()
        while amount != amount.to_integral_value() and unit_key in _GCLOUD_LOWER_UNIT:
            amount, unit_key = amount * 1024, _GCLOUD_LOWER_UNIT[unit_key]
        if amount != amount.to_integral_value():
            raise ValueError(f"{value!r} is not a whole size")
        unit = unit_key[:-1] if unit_key.endswith("B") else unit_key
        if not suffix:
            unit = kind[len("gsize:"):].upper().removesuffix("B")
        if unit not in _GCLOUD_SIZE_SCALES:
            raise ValueError(f"{value!r} has a unit gcloud does not read")
        return int(amount) * _GCLOUD_SIZE_SCALES[unit]
    if kind.startswith("gduration:"):
        if isinstance(value, (int, float)):
            return value
        default = kind[len("gduration:"):]
        if re.fullmatch(r"[+-]?\d+", text):
            text = f"{int(text)}{default}"
        return _gcloud_iso_duration(text)
    raise ValueError(f"unknown kind {kind}")


def _gcloud_iso_duration(text: str) -> int | float:
    """googlecloudsdk.core.util.iso_duration's Parse, in seconds (no calendar units)."""
    s = text.upper()
    sign = -1 if s.startswith("-") else 1
    s = s.lstrip("+-")
    t_implied = not s.startswith("P")
    s = s.removeprefix("P")
    total, amount, seen_t = 0.0, "", False
    for i, c in enumerate(s):
        if c.isdigit():
            amount += c
        elif c in ".,":
            amount += "."
        elif c == "T":
            if seen_t:
                raise ValueError("a duration has at most one T")
            seen_t = t_implied = True
        elif not amount:
            raise ValueError(f"duration unit {text[i:]!r} must follow a number")
        else:
            number = float(amount)
            amount = ""
            if c == "W":
                total += number * 7 * 86400
            elif c == "D":
                total += number * 86400
            elif c in "MUN" and s[i + 1:] == "S":
                total += number / {"M": 1000, "U": 1000000, "N": 1000000000}[c]
                break
            elif c in "YM" and not t_implied:
                raise ValueError("calendar units are not read here")
            elif c == "H":
                total += number * 3600
            elif c == "M":
                total += number * 60
            elif c == "S":
                total += number
            else:
                raise ValueError(f"unknown character {c!r} in duration")
            t_implied = True if c != "D" else t_implied
    if amount:
        raise ValueError(f"{text!r} ends without a unit")
    total *= sign
    rounded = round(total, 4)
    return int(rounded) if float(rounded).is_integer() else rounded


def _mark_type(params: dict[str, Any], key: str, kind: str) -> None:
    """Records that ``params[key]`` is a ``kind`` value (:func:`normalize_typed`), so the
    store reads a rule's value for that key the same way."""
    params.setdefault("value_types", {})[canonical_key(key)] = kind


def _pflag_store(params: dict[str, Any], tool: str, flag: str, key: str, value: Any,
                 command: str | None = None) -> None:
    """Records ``--flag value`` under ``key`` as pflag reads it (:data:`_PFLAG_TYPES_FILE`):
    a StringArray accumulates every value, a StringSlice (and the other slices) every
    value split as CSV, an Int is read with base 0 (Go's strconv.ParseInt), a Duration with
    time.ParseDuration, in seconds, a Float with ParseFloat, a StringToString as a map, a
    Count counts; a String is kept as written. A flag registered with several types (in
    different commands) keeps every reading a rule could match: a list when any is one."""
    if not isinstance(value, str):
        params[key] = value
        return
    kinds = _pflag_kinds(tool, flag, command)
    if not kinds:
        params[key] = value  # no declared type: the text, as written
        return
    if kinds & _PFLAG_LISTS:
        values: list[Any] = []
        if kinds & _PFLAG_CSV:
            values.extend(_read_string_slice(value))
        if kinds - _PFLAG_CSV:
            values.append(value)
        element = {_PFLAG_ELEMENT.get(k) for k in kinds}
        if len(element) == 1 and None not in element:
            # an IntSlice, BoolSlice, DurationSlice ... : each element read by its type, and
            # the type registered so a rule's value is read the same way
            kind = element.pop()
            values = [normalize_typed(kind, v) for v in values]
            _mark_type(params, key, kind)
        existing = params.get(key)
        before = existing if isinstance(existing, list) else (
            [] if existing is None else [existing])
        params[key] = before + [v for v in dict.fromkeys(values) if v not in before]
        return
    if kinds <= {"StringToInt", "StringToInt64"}:
        pairs = params.get(key) if isinstance(params.get(key), dict) else {}
        pairs.update(normalize_typed("map-int", value))
        params[key] = pairs
        _mark_type(params, key, "map-int")
        return
    if kinds == {"StringToString"}:
        pairs = params.get(key) if isinstance(params.get(key), dict) else {}
        for item in _read_string_slice(value):
            k, sep, v = item.partition("=")
            if not sep:
                raise ValueError(f"{tool} --{flag}: {item!r} must be key=value")
            pairs[k] = v
        params[key] = pairs
        _mark_type(params, key, "map")
        return
    if kinds <= set(_PFLAG_INTS):
        bits = min(_PFLAG_INTS[k] for k in kinds)
        number = _go_int(value, f"{tool} --{flag}", bits)
        if all(k.startswith("Uint") for k in kinds) and number < 0:
            raise ValueError(f"{tool} --{flag}: {value!r} is not an unsigned number")
        params[key] = number
        _mark_type(params, key, "int")
        return
    if kinds == {"Count"}:
        params[key] = _go_int(value, f"{tool} --{flag}", 64)
        _mark_type(params, key, "int")
        return
    if kinds == {"Duration"}:
        params[key] = _go_duration(value, f"{tool} --{flag}")
        _mark_type(params, key, "duration")
        return
    if kinds <= _PFLAG_FLOATS:
        params[key] = _go_float(value, f"{tool} --{flag}")
        _mark_type(params, key, "float")
        return
    params[key] = value  # a String (or a custom Value): the text, as written


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
        return i, val  # the text: _pflag_store reads it by the flag's type
    if val is not None:
        return i, val
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
    """kubectl's boolean and value letters on the command ``verb`` (from its --help:
    ``logs -f`` is the boolean --follow, ``patch -p`` takes a value). ``replicas`` names
    ``create deployment`` when only ``create`` is known."""
    command = "create deployment" if replicas and verb == "create" else verb
    letters = _kubectl_letters(command)
    bools = frozenset(k for k, (_n, kind) in letters.items() if kind == "bool") | {"h"}
    values = frozenset(k for k, (_n, kind) in letters.items() if kind != "bool")
    return bools, values


def _unbundle_short_word(word: str, verb: str | None, *, replicas: bool = False) -> list[str]:
    """:func:`_split_short_word` with kubectl's letters (:func:`_kubectl_short_letters`)."""
    bools, values = _kubectl_short_letters(verb, replicas=replicas)
    return _split_short_word(word, bools, values, "kubectl")


@lru_cache(maxsize=8)
def _pflag_aliases(tool: str) -> dict[str, str]:
    """The flags ``tool`` registers on one variable under two names, each with the name kept
    (``<tool>:aliases`` in pflag_types.json, from the registrations: helm 4's --force and
    --atomic are --force-replace and --rollback-on-failure, gh's --confirm is --yes)."""
    found: dict[str, str] = {}
    for names in _pflag_tables().get(f"{tool}:aliases", {}).values():
        found.update(names)
    return found


def _mirror_aliases(params: dict[str, Any], aliases: dict[str, str]) -> None:
    """Every name of one flag holds its value (applied in order under the kept name), so a
    rule written with any of them meets it."""
    for alias, kept in aliases.items():
        for spelling in (kept, kept.replace("-", "_")):
            if spelling in params:
                params.setdefault(alias.replace("-", "_") if "_" in spelling else alias,
                                  params[spelling])
                break


def _generated_shorts(tool: str, verb: str | None) -> dict[str, str]:
    """The short letters ``tool``'s registrations give the command ``verb`` itself
    (``<tool>:shorts`` in pflag_types.json): ``helm pull -d`` is --destination, where
    ``helm list -d`` is --date."""
    if verb is None:
        return {}
    found = _pflag_tables().get(f"{tool}:shorts", {}).get(verb)
    return dict(found) if isinstance(found, dict) else {}


def _helm_short_letters(verb: str | None) -> tuple[frozenset[str], frozenset[str]]:
    """Helm's short letters: the global ones (``-n``) and those every release command
    shares, with the letters the command's own registrations give winning (``-a`` is a
    value on ``template`` and a boolean on ``list`` and ``get values``; ``-d`` is a value
    on ``pull`` and ``package``), each a boolean or a value by its registered type."""
    bools = set(_HELM_SHORT_BOOL_LETTERS | {"a"})
    values = set(_HELM_SHORT_VALUE_LETTERS)
    for letter, flag in _generated_shorts("helm", verb).items():
        bools.discard(letter)
        values.discard(letter)
        (bools if _pflag_kinds("helm", flag) == {"Bool"} else values).add(letter)
    return frozenset(bools), frozenset(values)


_HELM_WAIT_STRATEGIES = frozenset({"watcher", "hookOnly", "legacy"})


def _helm_wait(val: str | None) -> str:
    """helm 4's ``--wait`` as its waitValue.Set reads it (pkg/cmd/flags.go): bare or
    ``true`` is ``watcher``, ``false`` is ``hookOnly``, ``watcher``, ``hookOnly`` and
    ``legacy`` are themselves; anything else helm refuses. helm 3's ``--wait`` is a
    boolean, and which helm runs is not on the line: the caller also leaves ``wait``
    unresolved, so a rule on it escalates rather than trust either reading."""
    if val is None or val == "true":
        return "watcher"
    if val == "false":
        return "hookOnly"
    if val in _HELM_WAIT_STRATEGIES:
        return val
    raise ValueError(f"helm: --wait={val!r} is not a wait strategy helm reads")


def _helm_short_name(letter: str, verb: str | None) -> str | None:
    """The long flag helm's ``-<letter>`` is on ``verb`` (helm 4.3.1 and 3.21.1 flag
    registrations), or None when it has none here."""
    own = _generated_shorts("helm", verb)
    if letter in own:
        return own[letter]
    names = {"n": "namespace", "o": "output", "m": "max", "s": "show-only",
             "A": "all-namespaces", "d": "date", "g": "generate-name", "i": "install",
             "q": "short", "r": "reverse"}
    if letter == "f":
        return "filter" if verb == "list" else "values"
    if letter == "l":
        return "selector" if verb == "list" else "labels"
    if letter == "a":
        return "api-versions" if verb == "template" else "all"
    return names.get(letter)


_FLUX_SHORT_NAMES = {
    "A": "all-namespaces", "l": "label-selector", "n": "namespace", "o": "output",
    "p": "password", "u": "username", "v": "version", "s": "silent", "w": "watch",
}


def _flux_short_name(letter: str, verb: str | None) -> str | None:
    """The long flag flux's ``-<letter>`` is (flux2 v2.10 cmd/flux), or None."""
    if letter == "f":
        return "follow" if verb == "logs" else None
    return _FLUX_SHORT_NAMES.get(letter)


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


_KUBECTL_SUBCOMMAND_VERBS = frozenset({"create", "set", "rollout", "config", "auth",
                                       "certificate", "top", "apply", "plugin"})


def _parse_flags(
    tokens: list[str], *, verb: str | None = None, raw_copy_to: list[str] | None = None,
    command_name: str | None = None,
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
    # the command whose flag types to read (create deployment, set image, rollout restart)
    sub = next((t for t in tokens if not t.startswith("-")), None)
    pflag_command = f"{verb} {sub}" if verb in _KUBECTL_SUBCOMMAND_VERBS and sub else verb
    # the letters are the command's own when kubectl lists it (apply's -f, not "apply
    # prod"'s, when "prod" is a flag's value)
    letters_command = next((c for c in (command_name, pflag_command)
                            if c and c in _KUBECTL_TABLE), verb)
    short_bools, short_values = _kubectl_short_letters(letters_command, replicas=replicas_short)
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
                flags = _unbundle_short_word(tok, letters_command, replicas=replicas_short)
                if flags != [tok]:
                    tokens[i:i + 1] = flags
                    n = len(tokens)
                    continue
            key, val = _split_flag(tok)
            if not is_long:
                # a short letter is its long flag from here on: both record the same
                long_name = _kubectl_short_name(key, letters_command, replicas_short)
                if long_name is None:
                    raise ValueError(f"kubectl: -{key} is not a short flag the parser knows "
                                     f"on this command; write its long flag: {tokens!r}")
                key, is_long = long_name, True
            if key == "namespace":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key == "all-namespaces":
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
            elif key == "user":
                # the kubeconfig user the request runs as: a scope a rule may name
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["user"] = val
            elif key == "server":
                # the API server the request goes to, over the context's cluster
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["server"] = val
            elif key in _DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                _record_flag(params, "kubectl", {"o": "output", "s": "server"}.get(key, key),
                             val)
            elif key in _DISCARD_BOOL_FLAGS:
                if _bool_param(val) is not False:
                    _record_flag(params, "kubectl", key, True)
            elif key == "expose" and verb == "run":
                # Only a spelling kubectl reads as false turns the Service off. It
                # refuses a word like "no", so reading that as on creates nothing.
                params[key] = val not in _GO_FALSE_WORDS
            elif ((key in _KNOWN_BOOL_FLAGS and not (key == "command" and verb == "kuberc"))
                  or (key == "raw" and verb == "config")):
                params[key] = _bool_param(val)
            elif key in _KUBECTL_VALUE_FLAGS or key == "command":
                # Always the next token, even "-1" or "--context": that is
                # what kubectl does with it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                name = key
                if name in _KUBECTL_INT_FLAGS or (name == "port" and replicas_short):
                    # create deployment's --replicas and --port are Int32, the others Int
                    # or Int64; --port is a string on expose and run
                    bits = 32 if replicas_short and name in ("replicas", "port") else 64
                    params[name] = _go_int(val, f"kubectl {tok}", bits)
                    _mark_type(params, name, "int")
                else:
                    _pflag_store(params, "kubectl", name, name, val, pflag_command)
                if key == "copy-to" and raw_copy_to is not None:
                    raw_copy_to[:] = [val]
            elif not is_long and key in short_bools:
                pass  # -i, -t, -q, -R, -w ...: nothing a rule reads
            elif not is_long and key in short_values:
                # -e (env): always the next token, as pflag reads it
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = val
            elif is_long or i + 1 < len(tokens) or val is not None:
                # Unknown to the parser. Refused unless "=value" or its place at the
                # end shows how kubectl would read it (see _other_flag).
                i, value = _other_flag(tokens, i, values=(), bools=(), tool="kubectl")
                _pflag_store(params, "kubectl", key, key, value, pflag_command)
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
    """Parses a kubectl invocation (see :func:`_from_kubectl_impersonating`). A selector beside
    names kubectl refuses ("name cannot be provided when a selector is specified", checked
    on kubectl 1.36), and so does the parser: the selector's scope is never read as the
    named objects'."""
    intents = _from_kubectl_impersonating(argv)
    for intent in intents:
        if (intent.params.get("selector") is not None
                and intent.action not in ("run", "expose", "create", "taint")
                and not intent.resource.endswith("/*")
                and not intent.resource.startswith("manifest/")
                and "resolved_at_runtime" not in intent.params):
            raise ValueError(f"kubectl: a name and a selector together, which kubectl "
                             f"refuses: {argv!r}")
        if intent.params.get("overrides") is not None and intent.action == "run":
            # --overrides is a JSON patch kubectl applies over the object it built, after
            # every other flag: it can change the image, the name and anything else
            _mark_unresolved(intent.params, "*")
            kind = intent.resource.partition("/")[0]
            intent.params["resolved_at_runtime"] = {"from": intent.resource, "kinds": [kind]}
        if (intent.params.get("from-file") is not None
                or intent.params.get("from-env-file") is not None):
            # create configmap/secret reads its data keys and values from those files
            # when it runs: the data is unknown, and so is every key in it
            _mark_unresolved(intent.params, "data")
            _mark_unresolved(intent.params, "data.*")
    return intents


def _from_kubectl_impersonating(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a kubectl invocation into one InfrastructureIntent per target
    resource (kubectl commands may name more than one, e.g.
    ``kubectl delete pod/a pod/b``).

    With ``--as`` / ``--as-group`` / ``--as-uid`` the request runs as
    someone else, which moves it out of an agent identity's scope on the
    server side. So besides the action itself, each impersonated identity
    becomes its own ``impersonate`` intent (``user/<name>``,
    ``group/<name>``, ``uid/<id>``) that a policy can block or escalate."""
    intents = _from_kubectl_multi(argv)
    return intents + _kube_impersonation_intents(intents)


def _kube_impersonation_intents(
    intents: list[InfrastructureIntent],
) -> list[InfrastructureIntent]:
    """Each identity a Kubernetes request is impersonated as (kubectl ``--as``,
    ``--as-group``, ``--as-uid``; helm ``--kube-as-user``, ``--kube-as-group``; flux
    ``--as``, ...), as one ``impersonate`` intent on ``user/<name>``, ``group/<name>`` or
    ``uid/<id>`` with provider ``kubernetes``, so one rule covers every tool."""
    seen: set[str] = set()
    extra: list[InfrastructureIntent] = []
    for intent in intents:
        imp = intent.params.get("impersonate") or {}
        if not isinstance(imp, dict) or "service_account" in imp:
            continue
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
    return extra


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
        tokens, verb=verb, raw_copy_to=raw_copy_to,
        command_name=f"{verb} {subverb}" if subverb else ("set image" if verb == "set"
                                                          else None))
    # attach takes at most two words, and a second one after "--" is its NAME.
    attach_name_after_dash = (verb == "attach" and len(positional) == 1
                              and command is not None and len(command) == 1)
    if positional and command and (verb in _KUBECTL_OPERAND_VERBS or attach_name_after_dash):
        positional = positional + command
    elif command is not None:
        params["command"] = command

    if params.get("raw") == "" and verb != "config":
        del params["raw"]  # kubectl only takes the raw path when it is not empty
    if isinstance(params.get("raw"), str) and verb != "config":
        if verb not in _KUBECTL_RAW_VERBS:
            raise ValueError(f"kubectl {verb} has no --raw: {argv!r}")
        resources, params, metadata = _kubectl_raw_target(argv, verb, params, metadata,
                                                          positional, manifests)
        return _kubectl_target_intents(verb, [], resources, params, metadata)

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
        if verb == "logs":
            # logs.go Complete: a second word is the container, over -c; a third is refused
            if len(positional) > 2:
                raise ValueError(f"kubectl logs takes a pod and a container: {argv!r}")
            if len(positional) == 2:
                params["container"] = positional[1]
                positional = positional[:1]
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
    if (verb == "create" and len(positional) > 1
            and positional[1] in _KUBECTL_SUBCOMMANDS.get(("create", positional[0]), ())):
        # create secret generic NAME, create service clusterip NAME: the second word is
        # the subcommand, not a name
        positional = [positional[0], *positional[2:]]
    resources = _parse_resources(positional)
    if verb == "taint" and resources and (params.get("all") or params.get("selector")):
        # kubectl taint ignores a name given with --all or -l (checked on kind)
        resources.append(f"{_split_resource_token(positional[0])[0]}/*")
    if not resources:
        raise ValueError(f"could not find a target resource in: {argv!r}")
    return _kubectl_target_intents(verb, positional, _expand_categories(resources), params,
                                   metadata)


def _kubectl_target_intents(
    verb: str, positional: list[str], resources: list[str], params: dict[str, Any],
    metadata: dict[str, Any],
) -> list[InfrastructureIntent]:
    """The intents of a verb's targets, with every expansion the verb has: open targets
    marked, describe's name prefix, create's --append-hash name, and delete's namespace
    cascade. A ``--raw`` path's target comes here too (:func:`_kubectl_raw_target`), so
    the two spellings of one request give the same intents."""
    intents = _mark_open_targets(_make_intents(resources, verb, params, metadata),
                                 custom_kinds=verb in _KUBECTL_CUSTOM_KIND_VERBS)
    if verb == "describe" and len(positional) == 2 and not any("/" in t for t in positional):
        _mark_name_prefix(intents[0], positional[1])
    if verb == "create" and params.get("append-hash") is True:
        # --append-hash renames the object NAME-<hash of its data>: data from files kubectl
        # reads when it runs, so only the prefix is known
        for intent in intents:
            kind, _, name = intent.resource.partition("/")
            if name and name != "*":
                intent.resource = f"{kind}/{name}-*"
                intent.params["resolved_at_runtime"] = {
                    "from": intent.resource, "kinds": [kind], "name_prefix": f"{name}-"}
    if verb == "delete":
        intents.extend(_namespace_cascade_intents(resources, params, metadata))
    intents.extend(_kubectl_created_objects(verb, resources, params, metadata))
    return intents


def _kubectl_created_objects(
    verb: str, resources: list[str], params: dict[str, Any], metadata: dict[str, Any],
) -> list[InfrastructureIntent]:
    """The objects a command creates besides the one it names, in its namespace: expose
    creates a Service and autoscale a HorizontalPodAutoscaler, named by ``--name`` or else
    after the source (expose.go, autoscale.go); create token requests a token of the
    ServiceAccount it names. ``--overrides`` patches the new object after every other flag,
    its name included, so every key of it is unresolved and the object is ``kind/*``,
    marked. A source with no name names nothing: the new object is ``kind/*``, marked."""
    kinds = {"expose": "service", "autoscale": "horizontalpodautoscaler"}
    out: list[InfrastructureIntent] = []
    if verb in kinds and resources:
        made: set[str] = set()
        overridden = params.get("overrides") is not None
        for source in resources:
            # one new object per source (kubectl visits each); --name names each of them.
            # expose's default name is the source's cut to 63 characters (expose.go: name
            # = info.Name[:DNS1035LabelMaxLength]); autoscale's is the source's as it is.
            # --overrides (expose only) can rename the object (metadata.name): any name.
            # The namespace stays: kubectl creates it in its own (Create(o.Namespace, ...)).
            source_name = source.partition("/")[2]
            if verb == "expose" and source_name != "*":
                source_name = source_name[:63]
            name = params.get("name") or source_name
            resource = (f"{kinds[verb]}/{name}" if name and name != "*" and not overridden
                        else f"{kinds[verb]}/*")
            if resource in made:
                continue
            made.add(resource)
            created = {**params}
            if params.get("overrides") is not None:
                _mark_unresolved(created, "**")
            intent = InfrastructureIntent(resource=resource, action="create",
                                          provider="kubernetes", params=created,
                                          metadata=dict(metadata))
            out.append(intent)
            if resource.endswith("/*"):
                _mark_open_targets([intent])
    elif verb == "create":
        for resource in resources:
            kind, _, name = resource.partition("/")
            if kind == "token" and name and name != "*":
                out.append(InfrastructureIntent(
                    resource=f"serviceaccount/{name}", action="create", provider="kubernetes",
                    params={**params, "subresource": "token"}, metadata=dict(metadata)))
    return out


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


# The kubectl verbs with a --raw path (kubectl 1.36: get.go, create.go, replace.go, and
# delete_flags.go for delete only, not for apply or run).
_KUBECTL_RAW_VERBS = frozenset({"get", "create", "replace", "delete"})
# The params of flags kubectl does not apply to a --raw request (canonical keys).
_KUBECTL_RAW_IGNORED = frozenset(canonical_key(k) for k in (
    "dry_run", "selector", "field-selector", "all", "all_namespaces", "cascade",
    "grace-period", "force", "now", "wait", "timeout", "recursive", "append-hash",
    "ignore-not-found", "file", "manifest_not_inspected", "kustomize"))
# Subresources of a namespace, which /api/v1/namespaces/<ns>/<word> could also be read as
# a collection in <ns>.
_KUBE_NAMESPACE_SUBRESOURCES = frozenset({"status", "finalize"})


def _kubectl_raw_target(
    argv: list[str], verb: str, params: dict[str, Any], metadata: dict[str, Any],
    positional: list[str], manifests: list[str],
) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
    """``kubectl get|create|replace|delete --raw PATH``: one GET, POST, PUT or DELETE to
    PATH (rawhttp). kubectl reads nothing else as the target: the positional words, ``-n``,
    ``-l`` and ``--dry-run`` are ignored (delete.go Complete returns before it resolves
    targets, and RawDelete, RawPost and RawPut send no dry-run). So the target, namespace
    and action come from the path: ``/api/v1[/namespaces/NS]/PLURAL[/NAME]`` and
    ``/apis/GROUP/VERSION[/namespaces/NS]/PLURAL[/NAME]``; a collection is ``kind/*``,
    marked. Any other path -- a subresource, a non-resource path, a query, an escaped,
    empty or dot segment -- is refused, since what it reads or changes is not known.
    ``-f`` is the request body, which is not read. Returns the target, params and
    metadata, which then go through the same expansions as a target named by words."""
    raw = params["raw"]
    write = verb != "get"
    if write:
        limit = 1 if verb == "delete" else None
        if limit is None and len(manifests) != 1:
            raise ValueError(f"kubectl {verb} --raw takes exactly one -f: {argv!r}")
        if limit is not None and len(manifests) > limit:
            raise ValueError(f"kubectl {verb} --raw takes one -f at most: {argv!r}")
        if any(m.startswith(("http://", "https://")) for m in manifests):
            raise ValueError(f"kubectl --raw cannot read from a url: {argv!r}")
        if verb == "create" and positional:
            raise ValueError(f"kubectl create takes no arguments: {argv!r}")
    if not raw.startswith("/"):
        raise ValueError(f"kubectl --raw {raw!r} is not a path on the API server: {argv!r}")
    path, query_sep, _query = raw.partition("?")
    segments = path.split("/")[1:]
    odd = bool(query_sep) or "#" in raw or "%" in path or any(
        seg in ("", ".", "..") for seg in segments)

    group: str | None = None
    rest: list[str] = []
    if segments[:2] == ["api", "v1"]:
        group, rest = "", segments[2:]
    elif len(segments) >= 3 and segments[0] == "apis":
        group, rest = segments[1], segments[3:]
    namespace = None
    subresource: list[str] = []
    if group is not None and len(rest) >= 3 and rest[0] == "namespaces":
        if group == "" and len(rest) == 3 and rest[2] in _KUBE_NAMESPACE_SUBRESOURCES:
            rest, subresource = rest[:2], rest[2:]
        else:
            namespace, rest = rest[1], rest[2:]
    if len(rest) > 2:
        rest, subresource = rest[:2], rest[2:]

    # what kubectl does not send with --raw: no dry-run, selector, --all, cascade or grace
    # period (the DELETE carries only the body -f gives), no --append-hash renaming
    kept = {k: v for k, v in params.items()
            if canonical_key(k) not in _KUBECTL_RAW_IGNORED}
    meta = {k: v for k, v in metadata.items() if k not in ("namespace", "all_namespaces")}
    if group is None or not rest or odd or subresource:
        # a read too: a path that names no object can still return any (a list under
        # /apis, an aggregated API), so it stays refused (fail closed)
        raise ValueError(f"kubectl {verb} --raw {raw!r} is not one resource or "
                         f"collection the parser can name: {argv!r}")
    plural = rest[0]
    name = rest[1] if len(rest) == 2 else None
    qualified = f"{plural}.{group}" if group else plural
    kind, _ = _split_resource_token(f"{qualified}/x")
    if kind in _KUBECTL_CATEGORIES:
        # a category is kubectl's, not the API server's: no such resource to request
        raise ValueError(f"kubectl --raw {raw!r} names a category, not a resource: {argv!r}")
    if namespace is not None:
        meta["namespace"] = namespace
    if manifests:
        kept["file"] = manifests[0]
        if verb in ("create", "replace"):
            kept["manifest_not_inspected"] = True  # the object sent is in the body
    if name is not None:
        return [f"{kind}/{name}"], kept, meta
    from aegis_core.store import _kind_is_cluster_scoped  # local: avoids a cycle

    if namespace is None and not _kind_is_cluster_scoped(f"{kind}/x"):
        meta["all_namespaces"] = True  # a namespaced collection with no namespace: all
    return [f"{kind}/*"], kept, meta


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

# The options of each "aws s3" command are aws-cli's own (the ARG_TABLE of each class in
# awscli/customizations/s3/subcommands.py, with the options sync's strategies add), read
# into aws_cli_options.zip by scripts/gen_aws_cli_options.py: how many words each takes
# ("" none, "1" one, "?" the next one unless it is an option, "+" every word up to the next
# option, "2" two), its type ("t": integer, map, blob), its shape ("x"), its choices ("c"),
# a bare optional value's value ("k"), and whether it accumulates ("a"). argparse takes an
# unambiguous prefix of any of them (--del is --delete on sync, --dryr is --dryrun), after
# the global options have had theirs.


def _aws_s3_spec(command: str) -> dict[str, Any]:
    """The table entry of ``aws s3 <command>``."""
    table = _aws_command_table("s3") or {}
    return table.get("s", {}).get(command, {})


def _aws_s3_store(params: dict[str, Any], command: str, name: str, value: Any,
                  spec: dict[str, Any], tokens: list[str]) -> None:
    """One value of an ``aws s3`` option, as aws-cli reads it: argparse checks the choices
    (exactly as written), then paramfile reads a ``file://``/``fileb://`` value (a one-word
    list as that word) from the file, which is not read: the option and its nested keys
    are unresolved. Then an option with a type is unpacked as aws-cli unpacks it (an
    integer with Python's int, a map from shorthand or JSON); the others stay text.
    --include and --exclude accumulate in order (``filters``, the later rule winning, as
    aws applies them), and mb --tags accumulates key-value pairs."""
    choices = spec.get("c", {}).get(name)
    words = value if isinstance(value, list) else [value]
    if choices and any(w not in choices for w in words if isinstance(w, str)):
        raise ValueError(f"aws s3 {command}: --{name} {value!r} is not one of {choices}, "
                         f"and aws refuses it: {tokens!r}")
    accumulate = spec.get("a", {}).get(name)
    if accumulate == "filter":
        pattern = words[0]
        params.setdefault("filters", []).append([name, pattern])
        params.setdefault(name, []).append(pattern)
        if _aws_file_ref(pattern):
            _mark_unresolved(params, name)
            _mark_unresolved(params, "filters")
        return
    if accumulate == "append":
        if _aws_file_ref(value) or any(_aws_file_ref(w) for w in words):
            params.setdefault(name, value if isinstance(value, list) else [value])
            _mark_unresolved(params, name)
            _mark_unresolved(params, f"{name}.*")
            return
        if name == "tags" and len(words) == 2:
            tags = params.setdefault(name, {})
            if not isinstance(tags, dict) or words[0] in tags:
                raise ValueError(f"aws s3 {command}: tag {words[0]!r} given twice: {tokens!r}")
            tags[words[0]] = words[1]
        else:
            params.setdefault(name, []).append(value)
        return
    if _aws_file_ref(value):
        params[name] = value  # paramfile reads it; _mark_aws_file_values marks it
        return
    kind = spec.get("t", {}).get(name)
    if kind == "integer":
        try:
            params[name] = int(str(value))
        except ValueError:
            raise ValueError(f"aws s3 {command}: --{name} {value!r} is not an integer, "
                             f"and aws refuses it: {tokens!r}") from None
    elif kind in ("map", "structure") or (kind or "").startswith("list"):
        shape = spec.get("x", {}).get(name)
        table = _aws_command_table("s3") or {}
        try:
            params[name] = _aws_unpack(value, shape, table.get("shapes", {}), f"--{name}")
        except _AwsFromFile:
            params[name] = value
            _mark_unresolved(params, name)
            _mark_unresolved(params, f"{name}.*")
    else:
        params[name] = value


def _aws_s3_option(command: str, key: str) -> str:
    """The option of ``aws s3 <command>`` that ``--key`` names: the exact name or the one
    option it is a prefix of. Anything else aws refuses, and so does the parser."""
    options = _aws_s3_spec(command).get("o", {})
    if key in options:
        return key
    found = [name for name in options if name.startswith(key)]
    if len(found) != 1:
        reason = f"is ambiguous ({', '.join(found)})" if found else "is not an option"
        raise ValueError(f"aws s3 {command}: --{key} {reason}, and aws refuses it")
    return found[0]


def _aws_global_name(key: str) -> str | None:
    """The global option ``--key`` names, as argparse finds it: the exact name or the one
    global option it is a prefix of. None when it names none; ambiguous is refused."""
    if key in _AWS_GLOBAL_OPTIONS:
        return key
    found = [name for name in _AWS_GLOBAL_OPTIONS if name.startswith(key)]
    if len(found) > 1:
        raise ValueError(f"aws: --{key} is ambiguous ({', '.join(found)}), and aws refuses it")
    return found[0] if found else None


# Every option of every aws command, read from aws-cli's own argparse parsers
# (scripts/gen_aws_cli_options.py; the archive's VERSION names the aws-cli it came from).
# argparse takes an unambiguous prefix of an operation's option, so the parser resolves
# each one against the operation's full list and records it under its full name.
_AWS_OPTIONS_ARCHIVE = Path(__file__).parent / "data" / "aws_cli_options.zip"


@lru_cache(maxsize=32)
def _aws_command_table(service: str) -> dict[str, Any] | None:
    """The options of ``aws <service>`` and its subcommands, or None when aws-cli has no
    such command."""
    try:
        with zipfile.ZipFile(_AWS_OPTIONS_ARCHIVE) as archive:
            return json.loads(archive.read(f"{service}.json"))
    except KeyError:
        return None


def aws_cli_options_version() -> str:
    """The aws-cli version the option table was read from."""
    with zipfile.ZipFile(_AWS_OPTIONS_ARCHIVE) as archive:
        return archive.read("VERSION").decode().strip()


def _aws_operation_spec(positional: list[str]) -> dict[str, Any]:
    """The table entry of the command ``positional`` names (``autoscaling
    set-desired-capacity``, ``ec2 wait instance-running``). aws refuses a command it does
    not have, and so does the parser."""
    table = _aws_command_table(positional[0]) if "/" not in positional[0] else None
    node = (table or {}).get("s", {}).get(positional[1])
    if node is None:
        raise ValueError(f"aws {positional[0]} {positional[1]}: not a command of aws-cli "
                         f"{aws_cli_options_version()}")
    if "s" in node:
        if len(positional) < 3 or positional[2] not in node["s"]:
            raise ValueError(f"aws {positional[0]} {positional[1]}: missing or unknown "
                             f"subcommand in {positional!r}")
        node = node["s"][positional[2]]
    return node


def _aws_option_name(spec: dict[str, Any], key: str) -> str:
    """The option of the operation ``--key`` names: the exact name, or the one option it is
    a prefix of (argparse's allow_abbrev). Anything else aws refuses, and so does the
    parser."""
    options = spec.get("o", {})
    if key in options:
        return key
    found = [name for name in options if name.startswith(key)]
    if len(found) != 1:
        reason = f"is ambiguous ({', '.join(sorted(found))})" if found else "is not an option"
        raise ValueError(f"aws: --{key} {reason} of this command, and aws refuses it")
    return found[0]


_AWS_NEGATIVE_NUMBER_RE = re.compile(r"^-\d+$|^-\d*\.\d+$")


def _aws_option_like(word: str) -> bool:
    """Whether argparse reads ``word`` as an option rather than a value: it starts with
    ``-``, is not a negative number and has no space."""
    return (word.startswith("-") and word != "-" and " " not in word
            and not _AWS_NEGATIVE_NUMBER_RE.match(word))


def _aws_typed(text: str, vtype: str | None, flag: str) -> Any:
    """A value as aws-cli unpacks it by its botocore shape (``vtype``, the option table's
    ``t``): an integer or long with Python's int(), a float or double with float(), a
    list's members by their type; any other value (a string, timestamp, blob, structure,
    map) is kept exactly as written, ``001`` included. What aws refuses, so does the
    parser."""
    kind = (vtype or "string").removeprefix("list:")
    if text.startswith(("file://", "fileb://")):
        return text  # read from a file when aws runs: unresolved (_mark_aws_file_values)
    try:
        if kind in ("integer", "long"):
            return int(text)
        if kind in ("float", "double"):
            return float(text)
    except ValueError as exc:
        raise ValueError(f"aws: {flag} {text!r} is not a {kind}, and aws refuses it") from exc
    return text


# aws-cli's argprocess: the operations whose list of one-member structures still takes
# plain words (ParamShorthand._uses_old_list_case, aws-cli 2.37).
_AWS_OLD_LIST_CASE = {
    ("firehose", "put-record-batch"): {"records"},
    ("workspaces", "reboot-workspaces"): {"reboot-workspace-requests"},
    ("workspaces", "rebuild-workspaces"): {"rebuild-workspace-requests"},
    ("workspaces", "terminate-workspaces"): {"terminate-workspace-requests"},
    ("elb", "remove-tags"): {"tags"},
    ("elb", "describe-instance-health"): {"instances"},
    ("elb", "deregister-instances-from-load-balancer"): {"instances"},
    ("elb", "register-instances-with-load-balancer"): {"instances"},
}


class _AwsFromFile(Exception):
    """A shorthand value aws reads from a file when it runs."""


def _aws_unpack(value: Any, shape_name: str, shapes: dict[str, Any], flag: str,
                old_list_case: bool = False) -> Any:
    """A structure, map or list option's value(s) as aws-cli's argprocess unpacks them:
    JSON when the value (or a list's one value) starts with ``[`` or ``{``; otherwise
    aws-cli's shorthand syntax (awscli/shorthand.py, :mod:`aegis_core.aws_shorthand`) for a
    structure, a map or a list of them, typed by the botocore shapes; a list of scalars
    takes each word, typed by its member shape. What aws cannot decode, the parser refuses;
    a value aws reads from a file (``file://`` in shorthand) raises :class:`_AwsFromFile`."""
    from aegis_core import aws_shorthand

    def node(name: str) -> dict[str, Any]:
        found = shapes.get(name)
        return found if isinstance(found, dict) else {"t": name}

    shape = node(shape_name)
    words = value if isinstance(value, list) else [value]
    first = str(words[0]).strip() if words else ""
    try:
        if shape.get("doc"):
            return json.loads(str(words[0]))
        if shape["t"] in ("structure", "map"):
            text = str(words[0])
            if text.lstrip().startswith("{"):
                return json.loads(text)
            members = shape.get("m", {})
            if (shape["t"] == "structure" and list(members) == ["Value"]
                    and node(members["Value"])["t"] == "string" and "=" not in text):
                return {"Value": text}
            parsed = aws_shorthand.ShorthandParser().parse(text)
            aws_shorthand.BackCompatVisitor(shapes).visit(parsed, shape_name)
            _aws_check_files(parsed)
            return parsed
        # a list
        if len(words) == 1 and first.startswith("["):
            return json.loads(str(words[0]))
        member = node(shape.get("e", "string"))
        if member["t"] in ("structure", "list", "map"):
            if old_list_case and member["t"] == "structure" and len(member.get("m", {})) == 1:
                key = next(iter(member["m"]))
                return [{key: w} for w in words]
            if first.startswith(("[", "{")):
                return [json.loads(str(w)) for w in words]
            parsed = [aws_shorthand.ShorthandParser().parse(str(w)) for w in words]
            aws_shorthand.BackCompatVisitor(shapes).visit(parsed, shape_name)
            _aws_check_files(parsed)
            return parsed
        return [_aws_typed(str(w), member["t"], flag) for w in words]
    except _AwsFromFile:
        raise
    except (ValueError, aws_shorthand.ShorthandParseError) as exc:
        raise ValueError(f"aws: {flag} {value!r} is not a value aws decodes: {exc}") from exc


def _aws_check_members(value: Any, shape_name: str, shapes: dict[str, Any], flag: str) -> None:
    """botocore's parameter validation of a decoded value's structure keys: a key the
    shape does not have, aws refuses."""
    shape = shapes.get(shape_name)
    if not isinstance(shape, dict):
        return
    if shape["t"] == "structure" and isinstance(value, dict):
        members = shape.get("m", {})
        for key, item in value.items():
            if key not in members:
                raise ValueError(f"aws: {flag}: {key!r} is not a member aws accepts")
            _aws_check_members(item, members[key], shapes, flag)
    elif shape["t"] == "list" and isinstance(value, list):
        for item in value:
            _aws_check_members(item, shape.get("e", ""), shapes, flag)
    elif shape["t"] == "map" and isinstance(value, dict):
        for item in value.values():
            _aws_check_members(item, shape.get("v", ""), shapes, flag)


def _aws_check_files(value: Any) -> None:
    from aegis_core.aws_shorthand import FromFile

    if isinstance(value, FromFile):
        raise _AwsFromFile(str(value))
    if isinstance(value, dict):
        for v in value.values():
            _aws_check_files(v)
    elif isinstance(value, list):
        for v in value:
            _aws_check_files(v)


def _aws_take_values(tokens: list[str], i: int, tok: str, val: str | None,
                     arity: str, vtype: str | None = None) -> tuple[Any, int]:
    """The value(s) argparse gives an option of ``arity`` (see _AWS_OPTIONS_ARCHIVE) at
    ``tokens[i]``, and the index of the last word taken."""
    n = len(tokens)
    if arity == "":
        if val is not None:
            raise ValueError(f"aws: {tok} takes no value, and aws refuses it")
        return True, i
    if val is not None:
        return (_aws_typed(val, vtype, tok) if arity in ("1", "?")
                else [_aws_typed(val, vtype, tok)]), i
    taken: list[str] = []
    limit = {"1": 1, "?": 1, "*": n, "+": n}.get(arity) or int(arity)
    while len(taken) < limit and i + 1 < n and not _aws_option_like(tokens[i + 1]):
        i += 1
        taken.append(tokens[i])
    if arity == "?" and not taken:
        return True, i
    if (arity in ("1", "+") and not taken) or (arity.isdigit() and arity != "1"
                                              and len(taken) != int(arity)):
        raise ValueError(f"aws: {tok} is missing its value: {tokens!r}")
    if arity in ("1", "?"):
        return _aws_typed(taken[0], vtype, tok), i
    return [_aws_typed(t, vtype, tok) for t in taken], i


def _parse_aws_tokens(
    tokens: list[str], *, s3: str | None = None, dry_prefix: bool = True,
    spec: dict[str, Any] | None = None, aws_shapes: dict[str, Any] | None = None,
    aws_old_list: frozenset[str] | set[str] = frozenset(),
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str] | None,
           list[tuple[str, list[str]]], str | None]:
    """``(metadata, params, positional, id, ids, abbreviations, id_flag)``. ``s3`` names the
    high-level ``aws s3`` command whose options to read (:func:`_aws_s3_spec`). ``spec``
    is the operation's entry in the option table (:func:`_aws_operation_spec`): every
    option is then resolved to its full name and given the words aws gives it, and one the
    operation does not have is refused.
    ``dry_prefix`` reads a prefix of ``--dry-run`` (``--dry``) as that option.
    ``abbreviations`` are the ``(key, value)`` of options the parser does not know whose
    name starts a target flag's: argparse takes an
    unambiguous prefix of an operation's option too (``--role`` is ``--role-name`` on
    ``iam delete-role``), so a missing target may be in one of them."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    id_value: str | None = None
    multi_ids: list[str] | None = None
    abbreviations: list[tuple[str, list[str]]] = []
    id_flag: str | None = None  # the full flag that gave id_value
    aliases_used: dict[str, str] = {}  # hidden alias -> the argument it copies

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
            arity = None
            spelled = key
            if spec is not None and key not in _AWS_GLOBAL_OPTIONS:
                if not tok.startswith("--"):
                    raise ValueError(f"aws: {tok} is not an option, and aws refuses it")
                key = _aws_option_name(spec, key)
                arity = spec["o"][key]
                # a hidden alias (argrename.HIDDEN_ALIASES) is the argument it copies
                if key in spec.get("al", {}):
                    aliases_used[key] = spec["al"][key]
                    key = spec["al"][key]
            if key in ("cli-input-json", "cli-input-yaml") and spelled != key:
                # argparse takes the abbreviation, but aws reads the input by its full name
                # before argparse, so the input is never used (run on aws 2.37)
                if val is None:
                    i += 1
                    _value_at(tokens, i, tok)
            elif key == "region":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["region"] = val
            elif key == "profile":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["profile"] = val
            elif s3 and tok.startswith("--") and key not in _AWS_GLOBAL_OPTIONS:
                name = _aws_s3_option(s3, key)
                s3_spec = _aws_s3_spec(s3)
                arity = s3_spec["o"][name]
                value: Any
                if name == "dryrun":
                    _record_dry_run(params, _is_dry_run(val))
                    i += 1
                    continue
                if not arity:
                    if val is not None:
                        raise ValueError(f"aws s3 {s3}: {tok} takes no value: {tokens!r}")
                    params[name] = True
                    i += 1
                    continue
                if val is not None:
                    value = val
                elif arity in ("+", "2"):
                    count = n if arity == "+" else 2
                    words: list[str] = []
                    while len(words) < count and i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        words.append(tokens[i])
                    if not words or (arity == "2" and len(words) != 2):
                        raise ValueError(f"aws s3 {s3}: {tok} is missing its values: {tokens!r}")
                    value = words
                elif i + 1 < n and not tokens[i + 1].startswith("-"):
                    i += 1
                    value = tokens[i]
                elif arity == "?":
                    value = s3_spec.get("k", {}).get(name, True)
                else:
                    raise ValueError(f"aws s3 {s3}: {tok} is missing its value: {tokens!r}")
                _aws_s3_store(params, s3, name, value, s3_spec, tokens)
            elif key == "dry-run" or (dry_prefix and len(key) >= 3 and tok.startswith("--")
                                      and "dry-run".startswith(key)):
                # a prefix of --dry-run, before the operation is known (then its table decides)
                _record_dry_run(params, _is_dry_run(val))
            elif key == "no-dry-run" or (len(key) >= 4 and "no-dry-run".startswith(key)):
                # an unambiguous prefix of --no-dry-run is that option to argparse
                params.pop("dry_run", None)  # explicitly a real run
            elif key in _AWS_GLOBAL_OPTIONS:
                if _AWS_GLOBAL_OPTIONS[key] and val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if key in _AWS_BOOL_FLAGS:
                    _set_bool_param(params, key, _bool_param(val))
                elif key == "endpoint-url":
                    metadata["endpoint_url"] = val  # see mark_config_scope
                else:
                    # recorded unless it cannot change what aws does (--no-sign-request,
                    # --no-verify-ssl, --ca-bundle, --cli-binary-format are kept)
                    _record_flag(params, "aws", key, val)
            elif key in _AWS_BOOL_FLAGS and arity in (None, ""):
                _set_bool_param(params, key, _bool_param(val))
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
                if spec is not None and len(ids) == 1 and ids[0].strip().startswith("["):
                    # aws-cli json-decodes a list option's one value that starts with "["
                    try:
                        decoded = json.loads(ids[0])
                    except ValueError as exc:
                        raise ValueError(f"aws: {tok} {ids[0]!r} is not JSON aws decodes"
                                         ) from exc
                    if not isinstance(decoded, list) or not all(
                            isinstance(d, str) for d in decoded):
                        raise ValueError(f"aws: {tok} {ids[0]!r} is not a list of strings")
                    ids = decoded
                if key == "instance-id" and len(ids) == 1:
                    id_value, id_flag = ids[0], key  # its own name (modify-instance-attribute)
                else:
                    multi_ids = ids  # --instance-ids (or an abbreviation of it)
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
            elif spec is not None and key in spec.get("pb", {}).values():
                # toplevelbool's --no-x: {"Value": false} under x (aws-cli refuses both)
                positive = key[len("no-"):]
                if positive in params:
                    raise ValueError(f"aws: --{positive} and --{key} together, which aws "
                                     f"refuses: {tokens!r}")
                params[positive] = {"Value": False}
            elif (spec is not None and key in spec.get("pb", {}) and val is None
                  and (i + 1 >= n or _aws_option_like(tokens[i + 1]))):
                # toplevelbool's bare --x: {"Value": true}
                if key in params:
                    raise ValueError(f"aws: --{key} given twice: {tokens!r}")
                params[key] = {"Value": True}
            elif key.startswith("no-") and val is None and tok.startswith("--") \
                    and arity in (None, ""):
                # botocore's "--no-<flag>" is a boolean's off switch: x: False
                _set_bool_param(params, key, True)
            elif arity is not None:
                complex_shape = spec.get("x", {}).get(key) if spec else None
                value, i = _aws_take_values(tokens, i, tok, val, arity,
                                            None if complex_shape else
                                            spec.get("t", {}).get(key) if spec else None)
                if arity == "":
                    _set_bool_param(params, key, True)
                elif complex_shape and not _aws_file_ref(value):
                    try:
                        params[key] = _aws_unpack(value, complex_shape, aws_shapes or {}, tok,
                                                  key in aws_old_list)
                        _aws_check_members(params[key], complex_shape, aws_shapes or {}, tok)
                    except _AwsFromFile:
                        params[key] = value
                        _mark_unresolved(params, key)  # a shorthand value from a file
                else:
                    params[key] = value
            else:
                if val is not None:
                    params[key] = val
                elif i + 1 < n and not tokens[i + 1].startswith("-"):
                    # argparse never takes a word starting with "-" as a value
                    i += 1
                    val = tokens[i]
                    params[key] = val
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

    for alias, kept in aliases_used.items():  # every name of the argument holds its value
        if kept in params:
            params[alias] = params[kept]
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

    # --recursive (and sync, which always is) reaches every key under the path, picked by
    # --include/--exclude filters when aws runs: the key is then only a prefix
    many = operation == "sync" or params.get("recursive") is True

    def add(uri: str, action: str, destination: bool = False) -> None:
        bucket, _, key = uri[len("s3://") :].partition("/")
        intent_params = {**params, "key": key} if key else dict(params)
        if many:
            # every key under the path (a prefix, as aws lists it)
            _mark_key_prefix(intent_params, key)
        elif destination:
            # cp/mv to s3://b/dir/ writes dir/<source's base name> (aws s3 never treats a
            # key without the slash as a folder)
            _copy_destination_key(intent_params, rest[:-1], False, folders=False)
        intents.append(InfrastructureIntent(resource=f"s3/bucket/{bucket}", action=action,
                                            provider="aws", params=intent_params,
                                            metadata=dict(metadata)))

    for uri in uris:
        add(uri, action, destination=operation in ("cp", "mv") and rest[-1:] == [uri]
            and uri == uris[-1])
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
    if id_value is not None:
        params["bucket"] = id_value  # --bucket, a param too (a rule on bucket)
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
        name = params.get("name") or id_value
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
            metadata, params, positional, *_ = _parse_aws_tokens(tokens, s3=operation)
            service, operation, *rest = positional
        _mark_aws_file_values(params, None)
        return _from_aws_s3(operation, rest, metadata, params, argv)

    # read again with the operation's own options: each is resolved to its full name
    spec = _aws_operation_spec(positional)
    shapes = (_aws_command_table(service) or {}).get("shapes", {})
    old_list = _AWS_OLD_LIST_CASE.get((service, operation), frozenset())
    (metadata, params, positional, id_value, multi_ids, abbreviations,
     id_flag) = _parse_aws_tokens(tokens, spec=spec, dry_prefix=False, aws_shapes=shapes,
                                  aws_old_list=old_list)
    from_input = "cli_input_json" in params or "cli_input_yaml" in params
    if from_input:
        extra, structured, unread = _aws_input_tokens(spec, params)
        if not unread:
            (metadata, params, positional, id_value, multi_ids, abbreviations,
             id_flag) = _parse_aws_tokens(extra + tokens, spec=spec, dry_prefix=False,
                                          aws_shapes=shapes, aws_old_list=old_list)
            for key, value in structured.items():
                params.setdefault(key, value)  # the command line wins over the input
    _mark_aws_file_values(params, spec if from_input and unread else None)
    if "generate-cli-skeleton" in params:
        # aws prints a skeleton (of the input, or of the output) and calls nothing
        params["dry_run"] = True
    intents = _from_aws_operation(service, operation, metadata, params, id_value,
                                  multi_ids, abbreviations, id_flag)
    return _mark_aws_input_targets(intents) if from_input else intents


def _aws_input_tokens(
    spec: dict[str, Any], params: dict[str, Any],
) -> tuple[list[str], dict[str, Any], bool]:
    """``--cli-input-json`` / ``--cli-input-yaml`` as the options it stands for:
    ``(words, structured, unread)``. Each member of the input (``DesiredCapacity``) is the
    option the operation's table names for it (``--desired-capacity``); a scalar or a list
    of scalars becomes words read in front of the command line, which overrides them as
    it does in aws; a structure or map is returned as is. ``unread`` when the input is in
    a file (``file://``, ``fileb://``), which is not read. A member the operation does not
    have, two inputs, or text that is not a mapping, aws refuses, and so does the
    parser."""
    if "cli_input_json" in params and "cli_input_yaml" in params:
        raise ValueError("aws: only one --cli-input- parameter may be specified")
    yaml_input = "cli_input_yaml" in params
    text = params["cli_input_yaml" if yaml_input else "cli_input_json"]
    if not isinstance(text, str):
        raise ValueError("aws: --cli-input- needs a value")
    if text.startswith(("file://", "fileb://")):
        return [], {}, True
    import yaml  # local: only an aws input needs it

    try:
        data = yaml.load(text, Loader=_aws_yaml_loader()) if yaml_input else json.loads(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"aws: --cli-input- is not valid input: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("aws: --cli-input- must be a mapping of parameters")
    members = spec.get("m", {})
    options = spec.get("o", {})
    words: list[str] = []
    structured: dict[str, Any] = {}
    for member, value in data.items():
        option = members.get(member)
        if option is None:
            raise ValueError(f"aws: --cli-input- has {member!r}, not a parameter of this "
                             "operation, and aws refuses it")
        if options.get(option) == "":
            if not isinstance(value, bool):
                raise ValueError(f"aws: --cli-input- {member} must be true or false")
            off = option[3:] if option.startswith("no-") else f"no-{option}"
            words.append(f"--{option}" if value else f"--{off}")
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            words.append(f"--{option}={value}")
        elif isinstance(value, list) and value and all(
                isinstance(v, (str, int, float)) and not isinstance(v, bool)
                and not _aws_option_like(str(v)) for v in value):
            words.extend([f"--{option}", *map(str, value)])
        else:
            structured[option] = value
    return words, structured, False


@lru_cache(maxsize=1)
def _aws_yaml_loader() -> type:
    """A YAML loader that types scalars as aws-cli v2 does (ruamel.yaml, YAML 1.2): only
    true/false are booleans (``yes`` is a string), ``010`` is ten, ``0o10`` eight and
    ``0x10`` sixteen, ``_`` may separate digits, and ``1:30`` is a string. Checked with aws
    2.37 against a closed local port. JSON numbers (``--cli-input-json``) stay exact, as
    in aws."""
    import yaml

    class Loader(yaml.SafeLoader):
        pass

    Loader.yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers
                if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:int",
                               "tag:yaml.org,2002:float")]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    Loader.add_implicit_resolver("tag:yaml.org,2002:bool",
                                 re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
                                 list("tTfF"))
    Loader.add_implicit_resolver(
        "tag:yaml.org,2002:int",
        re.compile(r"^(?:[-+]?[0-9][0-9_]*|0o[0-7_]+|0x[0-9a-fA-F_]+)$"),
        list("-+0123456789"))
    Loader.add_implicit_resolver(
        "tag:yaml.org,2002:float",
        re.compile(r"^(?:[-+]?(?:\.[0-9]+|[0-9][0-9_]*(?:\.[0-9_]*)?)(?:[eE][-+]?[0-9]+)?"
                   r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"),
        list("-+0123456789."))

    def construct_int(loader, node):
        text = loader.construct_scalar(node).replace("_", "")
        if text.startswith("0o"):
            return int(text[2:], 8)
        if text.startswith("0x"):
            return int(text[2:], 16)
        return int(text, 10)

    Loader.add_constructor("tag:yaml.org,2002:int", construct_int)
    return Loader


def _aws_file_ref(value: Any) -> bool:
    """Whether aws reads this option value from a file. paramfile runs before argprocess
    (before JSON or shorthand is decoded) and takes a one-word list as that word, so
    ``--tags file://t.json`` is a file on a list option too."""
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    return isinstance(value, str) and value.startswith(("file://", "fileb://"))


def _mark_aws_file_values(params: dict[str, Any], spec: dict[str, Any] | None) -> None:
    """aws reads an option's value from a file when it is ``file://`` or ``fileb://``
    (paramfile), which is not read: those options are unresolved. With ``spec``, the whole
    input is in a file: every option of the operation the command line does not give is
    unresolved (one the command line gives is known, since it overrides the input)."""
    marks = [mark for key, value in params.items()
             if _aws_file_ref(value) and not key.startswith("cli_input")
             for mark in (key, f"{key}.*")]  # and every key nested in it
    if spec is not None:
        given = {canonical_key(k) for k in params}
        options = spec.get("o", {})
        marks.extend(option for option in spec.get("m", {}).values()
                     if canonical_key(option) not in given and option in options)
    for mark in marks:
        _mark_unresolved(params, mark)


def _from_aws_operation(
    service: str, operation: str, metadata: dict[str, Any], params: dict[str, Any],
    id_value: str | None, multi_ids: list[str] | None,
    abbreviations: list[tuple[str, list[str]]], id_flag: str | None,
) -> list[InfrastructureIntent]:
    """The intents of one aws operation, its options read."""
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
        return intents

    if service == "autoscaling" and operation == "set-desired-capacity":
        params = dict(params)
        params["raw_action"] = operation
        if "desired-capacity" in params:
            params["desired_capacity"] = params.pop("desired-capacity")
        if id_value is not None and id_flag:
            params[id_flag] = id_value  # the flag that named the group, under its name
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
    # the flag that named the target is a param too, with each target's own value, so a
    # rule on it ({"role-name": "protected"}) meets it as a rule on the resource does
    id_key = ("instance-ids" if multi_ids else
              target_flag if target_flag and isinstance(params.get(target_flag), str) else
              id_flag)
    intents = []
    for name in names:
        target_params, target_metadata = dict(params), dict(metadata)
        if id_key and name is not None:
            target_params[id_key] = name
        name = _aws_name(service, kind, name, target_params, target_metadata)
        intents.append(InfrastructureIntent(
            resource=_aws_resource(service, kind, name), action=action, provider="aws",
            params=target_params, metadata=target_metadata))
    return intents


def _aws_name(service: str, kind: str, name: str | None, params: dict[str, Any],
              metadata: dict[str, Any]) -> str | None:
    """One target aws takes in several spellings. An ARN stays the resource (the compiled
    policies need it), with the resource's plain name as ``metadata["resource_aliases"]``
    so a rule on the name matches too (IAM keeps the last part of a path, CloudFormation
    the stack name), and the ARN's account and region as the resource's. A value read
    from a file (``file://``, ``fileb://``) is only known when aws runs, and so are the
    key a KMS alias names and the full name of a Secrets Manager secret (which ends in a
    random suffix): those targets are marked."""
    if name is None:
        return None
    if name.startswith(("file://", "fileb://")):
        params["resolved_at_runtime"] = {"from": f"{service}/{kind}/*",
                                         "kinds": [f"{service}/{kind}"]}
        return None
    plain = name
    if name.startswith("arn:"):
        fields = name.split(":", 5)
        if len(fields) == 6:
            _arn, _partition, _svc, region, account, resource = fields
            if region and "region" not in metadata:
                metadata["region"] = region
            if account:
                metadata["account"] = account
            if service == "kms" and resource.startswith("alias/"):
                plain = resource
            else:
                pieces = re.split(r"[:/]", resource)
                plain = pieces[-1] if service == "iam" else (
                    pieces[1] if len(pieces) > 1 else pieces[0])
            if plain and plain != name:
                metadata["resource_aliases"] = [_aws_resource(service, kind, plain)]
    if service == "secretsmanager" and re.search(r"-[A-Za-z0-9]{6}$", plain) and \
            name.startswith("arn:"):
        params["resolved_at_runtime"] = {"from": f"{service}/{kind}/{plain}",
                                         "kinds": [f"{service}/{kind}"],
                                         "name_prefix": plain[:-7]}
    if service == "kms" and plain.startswith("alias/"):
        # an alias names a key, which one is only known when aws runs
        params["resolved_at_runtime"] = {"from": f"{service}/{kind}/{plain}",
                                         "kinds": [f"{service}/{kind}"]}
    return name


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
    "upgrade",
}

_AZ_BOOL_FLAGS = {"yes", "y", "no-wait", "debug", "verbose", "only-show-errors"}

# The az options the parser reads into the target or its scope. az parses with Python's
# argparse (knack), which takes an unambiguous prefix of a long option, so "--resource-gr
# rg" is the resource group. Whether a prefix is one depends on the command's other options,
# which the parser does not have, so a prefix of one of these is refused. --id and
# --resource are full options of their own on many commands.
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{12}")

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


# Every short option of az's commands and the long option it is, read from azure-cli's
# command_modules/*/_params.py (scripts/gen_az_short_options.py; "_source" names the
# commit). A scope applies to the commands under it; the most specific one wins.
_AZ_SHORT_FILE = Path(__file__).parent / "data" / "az_short_options.json"


@lru_cache(maxsize=1)
def _az_short_tables() -> dict[str, dict[str, str]]:
    with open(_AZ_SHORT_FILE) as f:
        return json.load(f)


def _az_entry(words: list[str]) -> tuple[dict[str, str], frozenset[str]]:
    """The short options (each the long option it is) and the long options of
    ``az <words>``. A command whose every option is known (a custom function's parameters,
    an AAZ class: ``c`` in the table) has exactly its own; any other has those of every
    scope above it, some of which may not apply to it."""
    tables = _az_short_tables()
    leaf = tables.get(" ".join(words), {})
    if leaf.get("c"):
        return dict(leaf.get("s", {})), frozenset(leaf.get("l", ())) | _AZ_GLOBAL_LONGS
    shorts: dict[str, str] = {}
    longs: set[str] = set(_AZ_GLOBAL_LONGS)
    for size in range(1, len(words) + 1):
        entry = tables.get(" ".join(words[:size]), {})
        shorts.update(entry.get("s", {}))
        longs.update(entry.get("l", ()))
    return shorts, frozenset(longs)


# How many words az's own multi-value options take: the generic update's --set, --add and
# --remove (every word up to the next option, each time), --ids.
_AZ_GLOBAL_NARGS = {"set": "append+", "add": "append+", "remove": "append+", "ids": "+"}


def _az_nargs(words: list[str]) -> dict[str, str]:
    """How many words each long option of ``az <words>`` takes, where it is not one: ``+``
    and ``*`` every word up to the next option, ``?`` one if there is one, ``append`` one
    each time, all kept (from ``_params.py`` nargs and argument types, and AAZ list and
    dict arguments)."""
    tables = _az_short_tables()
    leaf = tables.get(" ".join(words), {})
    nargs = dict(_AZ_GLOBAL_NARGS)
    if leaf.get("c"):
        nargs.update(leaf.get("n", {}))
        return nargs
    for size in range(1, len(words) + 1):
        nargs.update(tables.get(" ".join(words[:size]), {}).get("n", {}))
    return nargs


def _az_long_aliases(words: list[str]) -> dict[str, str]:
    """The long options of ``az <words>`` that are another name of one argument, each with
    the first long option of its options_list (the table's ``a``)."""
    tables = _az_short_tables()
    leaf = tables.get(" ".join(words), {})
    if leaf.get("c"):
        return dict(leaf.get("a", {}))
    found: dict[str, str] = {}
    for size in range(1, len(words) + 1):
        found.update(tables.get(" ".join(words[:size]), {}).get("a", {}))
    return found


def _az_aliases(words: list[str]) -> dict[str, str]:
    """The short options of ``az <words>`` and the long option each is."""
    return _az_entry(words)[0]


# The long options az's core and knack give every command.
_AZ_GLOBAL_LONGS = frozenset({
    "resource-group", "name", "location", "subscription", "ids", "output", "query", "help",
    "debug", "verbose", "only-show-errors", "yes", "no-wait",
})


def _az_longs(words: list[str]) -> frozenset[str]:
    """The long options of ``az <words>`` (:func:`_az_entry`) and az's own: what argparse
    resolves an abbreviated long option against."""
    return _az_entry(words)[1]


def _az_long_option(key: str, longs: frozenset[str]) -> str:
    """The long option ``--key`` names, as argparse's allow_abbrev finds it: the exact name,
    or the one option it is a prefix of. A prefix of several, or a name that is neither, is
    refused: what it means on this command is not known for certain."""
    if key in longs:
        return key
    found = sorted(o for o in longs if o.startswith(key))
    if len(found) != 1:
        reason = f"is ambiguous ({', '.join(found)})" if found else "is not an option the " \
            "parser knows on this command"
        raise ValueError(f"az: --{key} {reason}; write the option in full")
    return found[0]


# az's own short options (knack and azure-cli core): -o output, -h help, -y the --yes that
# knack adds to every command that asks for confirmation (knack commands.py), and the -g,
# -n and -l of the shared resource-group, name and location arguments.
_AZ_GLOBAL_SHORTS = {"o": "output", "h": "help", "y": "yes", "g": "resource-group",
                     "n": "name", "l": "location"}


def _az_roles(aliases: dict[str, str]) -> dict[str, str]:
    """The long options that name the target, its resource group or its location on this
    command: ``--name``, ``--resource-group`` and ``--location``, and the option the
    command's -n, -g or -l is when it is another spelling of one of them (``-n`` is
    ``--account-name`` on some commands)."""
    roles = {"name": "name", "resource-group": "resource-group", "location": "location"}
    n, g, loc = aliases.get("n"), aliases.get("g"), aliases.get("l")
    if n and n != "node-count":
        roles[n] = "name"
    if g in ("group", "resource-group-name"):
        roles[g] = "resource-group"
    if loc and "location" in loc:
        roles[loc] = "location"
    return roles


def _az_convert(params: dict[str, Any], nargs: dict[str, str], tokens: list[str],
                skip: set[str] = frozenset()) -> None:
    """What az does to a value after argparse, from the argument's type or validator
    (the table's ``conv:``): ``tags`` (validate_tags: ``key[=value]`` words a map, a bare
    key an empty value), ``bool`` (get_three_state_flag: true/false without case, bare
    true), ``enum`` (get_enum_type: a choice matched without case, spelled as declared;
    another value az refuses). Another validator is not ported: its value is unresolved."""
    for key in list(params):
        conv = nargs.get(f"conv:{key}")
        if conv is None or key in skip:  # a value read from a file is not converted
            continue
        value = params[key]
        if conv == "tags":
            words = value if isinstance(value, list) else [] if value is True else [value]
            tags: dict[str, str] = {}
            for word in words:
                if word:
                    k, sep, v = str(word).partition("=")
                    tags[k] = v if sep else ""
            params[key] = tags
        elif conv == "bool":
            if value is True or value is False:
                continue
            word = str(value).lower()
            if word not in ("true", "false"):
                raise ValueError(f"az: --{key} {value!r} is not true or false: {tokens!r}")
            params[key] = word == "true"
        elif conv.startswith("enum:"):
            choices = json.loads(conv[len("enum:"):])

            def choose(v: Any) -> str:
                found = next((c for c in choices if c.lower() == str(v).lower()), None)
                if found is None:
                    raise ValueError(f"az: --{key} {v!r} is not one of {choices}")
                return found

            params[key] = [choose(v) for v in value] if isinstance(value, list) \
                else choose(value)
        else:
            _mark_unresolved(params, key)


def _az_typed(text: str, nargs: dict[str, str] | None, key: str, tok: str) -> Any:
    """An az value: the text, unless the argument declares ``type=int`` or ``type=float``
    (argparse's int() and float()); what argparse refuses, so does the parser."""
    vtype = (nargs or {}).get(f"type:{key}")
    try:
        if vtype == "int":
            return int(text)
        if vtype == "float":
            return float(text)
    except ValueError as exc:
        raise ValueError(f"az: {tok} {text!r} is not a {vtype}, and az refuses it") from exc
    return text


def _parse_az_tokens(
    tokens: list[str], aliases: dict[str, str] | None = None,
    longs: frozenset[str] | None = None, nargs: dict[str, str] | None = None,
    long_aliases: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str], str | None, list[str]]:
    """``aliases`` (:func:`_az_aliases`) records each short option as the long option it is
    on the command, so ``-c 1`` and ``--node-count 1`` record the same; the long option
    that names the target, resource group or location then feeds them whichever way it is
    spelled."""
    roles = _az_roles(aliases) if aliases is not None else None
    long_aliases = long_aliases or {}
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
            if longs is not None and tok.startswith("--"):
                key = _az_long_option(key, longs)  # --node-c is --node-count
                # another long name of the same argument is that argument
                # (options_list=['--name', '-n', '--table-name']): one key, values in order
                key = long_aliases.get(key, key)
            if aliases is not None and roles is not None:
                if not tok.startswith("--"):
                    if key not in aliases and key not in _AZ_GLOBAL_SHORTS:
                        raise ValueError(f"az: -{key} is not a short option the parser "
                                         f"knows on this command; write its long option: "
                                         f"{tokens!r}")
                    key = aliases.get(key) or _AZ_GLOBAL_SHORTS[key]
                role_of = key if roles.get(key, key) != key else None
                key = roles.get(key, key)
            else:
                role_of = None
            if key in ("l", "location"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if role_of:
                    params[role_of] = val  # --x-location is also a param under its name
                if " " in val:
                    # a display name ("East US"): az looks up the location it names in the
                    # subscription's list when it runs (core commands/parameters.py)
                    metadata.pop("region", None)
                    metadata["location_display_name"] = val
                else:
                    metadata.pop("location_display_name", None)
                    metadata["region"] = val
            elif key == "subscription":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if _GUID_RE.fullmatch(val):
                    metadata.pop("subscription_name", None)
                    metadata["subscription"] = val
                else:
                    # a name: which subscription ID it is, only az knows when it runs
                    metadata.pop("subscription", None)
                    metadata["subscription_name"] = val
            elif key in ("g", "resource-group"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["resource_group"] = val
                if role_of:
                    params[role_of] = val  # --resource-group-name is also a param
            elif key in ("n", "name"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if role_of:
                    params[role_of] = val  # --service-name, the -n here, is also a param
                name_value = val
                params["name"] = val  # also a param: a rule on name meets it
            elif nargs is not None and key in nargs and key not in ("ids",):
                # several words, as argparse gives an option with nargs + / * / ? or
                # action append: every word up to the next option-looking one
                kind = nargs[key]
                values = [val] if val is not None else []
                if val is None and kind != "append":
                    while i + 1 < n and not _aws_option_like(tokens[i + 1]):
                        i += 1
                        values.append(tokens[i])
                        if kind == "?":
                            break
                elif val is None:
                    i += 1
                    values.append(_value_at(tokens, i, tok))
                if kind == "+" and not values:
                    raise ValueError(f"az: {tok} needs at least one value: {tokens!r}")
                if kind == "?" and not values:
                    params[key] = True
                elif kind in ("append", "append+"):
                    params[key] = [*params.get(key, []), *values] \
                        if isinstance(params.get(key), list) else values
                else:
                    params[key] = values
            elif key in ("what-if", "dry-run"):
                _record_dry_run(params, _is_dry_run(val))
            elif key in _AZ_BOOL_FLAGS:
                params["yes" if key == "y" else key] = _bool_param(val)
            elif key == "ids":
                # `az <group> <verb> --ids ID [ID ...]`: one or more ARM
                # resource ids in place of -g/-n (REVIEW-4 T1.7).
                if val is not None:
                    ids_values.append(val)
                else:
                    before = len(ids_values)
                    while i + 1 < n and not tokens[i + 1].startswith("-"):
                        i += 1
                        ids_values.append(tokens[i])
                    if len(ids_values) == before:
                        # nargs "+": argparse refuses --ids with no ID after it
                        raise ValueError(f"az: --ids needs at least one ID: {tokens!r}")
            elif val is not None:
                params[key] = _az_typed(val, nargs, key, tok)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                # argparse never takes a word starting with "-" as a value
                i += 1
                params[key] = _az_typed(tokens[i], nargs, key, tok)
            else:
                params[key] = True
        else:
            positional.append(tok)
        i += 1

    # az reads an argument value "@path" from that file (knack's argument preprocessing,
    # before argparse and any validator), "@-" from stdin: any other option read that way
    # is unresolved, and so is every key nested in it (``tags.env`` of ``--tags @t.txt``).
    # This comes first: only a literal value is converted (tags to a map, a bool, a choice).
    from_file: set[str] = set()
    for key, value in list(params.items()):
        words = value if isinstance(value, list) else [value]
        if any(isinstance(w, str) and w.startswith("@") for w in words):
            from_file.add(key)
            _mark_unresolved(params, key)
            _mark_unresolved(params, f"{key}.*")
    if nargs is not None:
        _az_convert(params, nargs, tokens, skip=from_file)
    # the target or its scope would then be a file nobody read
    for value in (name_value, *ids_values, metadata.get("region"),
                  metadata.get("location_display_name"), metadata.get("resource_group"),
                  metadata.get("subscription"), metadata.get("subscription_name")):
        if isinstance(value, str) and value.startswith("@"):
            raise ValueError(f"az: {value!r} is read from a file when az runs, and names the "
                             f"target or its scope: {tokens!r}")
    # every long name of one argument holds its value, so a rule written with any of them
    # meets it (the value was applied in order under the first one)
    for alias, canonical in long_aliases.items():
        if canonical in params and alias not in params:
            params[alias] = params[canonical]
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
    if any(c in arm_id for c in "#?%") or "//" in arm_id.strip("/") or any(
            seg in (".", "..") for seg in arm_id.split("/")):
        # az puts the ID into the request URL: a fragment, a query, an escape or a dot
        # segment there is read by the URL, not as the name
        raise ValueError(f"az: {arm_id!r} is not an ARM resource id az sends as written")
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
    """Parses an ``az`` CLI invocation (see :func:`_from_az_multi`). Every intent, from the
    named form or an ``--ids`` path, then has its scope normalized once: a subscription
    that is not a GUID is ``subscription_name`` and a location with a space is
    ``location_display_name``, since az looks up the ID or name they stand for when it
    runs; ``subscription`` and ``region`` are then unresolved."""
    intents = _from_az_multi(argv)
    for intent in intents:
        md = intent.metadata
        sub = md.get("subscription")
        if isinstance(sub, str) and not _GUID_RE.fullmatch(sub):
            md["subscription_name"] = md.pop("subscription")
        region = md.get("region")
        if isinstance(region, str) and " " in region:
            md["location_display_name"] = md.pop("region")
    return intents


def _from_az_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``az`` CLI invocation into one InfrastructureIntent per
    target: one for the ``-n/--name`` form, or one per ``--ids`` ARM path
    (``az vm deallocate --ids /subscriptions/.../virtualMachines/a
    /subscriptions/.../virtualMachines/b`` names two)."""
    if not argv or _basename(argv[0]) != "az":
        raise ValueError(f"not a recognizable az invocation: {argv!r}")

    tokens = argv[1:]
    metadata, params, positional, name_value, ids_values = _parse_az_tokens(tokens)
    # read again with the command's own short options, each recorded as its long option
    # the command's words: up to its verb (a multi-value option's words may follow)
    words = positional[:next((i + 1 for i, w in enumerate(positional) if w in _AZ_VERBS),
                             len(positional))]
    metadata, params, positional, name_value, ids_values = _parse_az_tokens(
        tokens, _az_aliases(words), _az_longs(words), _az_nargs(words),
        _az_long_aliases(words))

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
        # az fills every argument with an id part (the name, --resource-group and
        # --subscription) from each ID and ignores what the command line gave them
        # (azure-cli core commands/arm.py parse_ids_arguments)
        ignored = {"resource_group", "subscription", "subscription_name"}
        for arm_id in ids_values:
            resource, arm_metadata = _parse_arm_id(arm_id)
            own = {k: v for k, v in metadata.items() if k not in ignored}
            # the name the ID gives, as --name would record it
            id_params = {**params, "name": resource.rsplit("/", 1)[-1]}
            intents.append(
                InfrastructureIntent(
                    resource=resource,
                    action=action,
                    provider="azure",
                    params=id_params,
                    metadata={**own, **arm_metadata},
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
    ("compute",): "compute/instance",  # gcloud compute ssh INSTANCE
    ("compute", "instances"): "compute/instance",
    ("compute", "disks"): "compute/disk",
    ("compute", "firewall-rules"): "compute/firewall-rule",
    ("container", "clusters"): "container/cluster",
    ("container", "node-pools"): "container/node-pool",
    ("sql", "instances"): "sql/instance",
    ("storage", "buckets"): "storage/bucket",
    ("functions",): "functions/function",
    ("run",): "run/service",  # gcloud run deploy SERVICE
    ("run", "services"): "run/service",
    ("iam", "service-accounts"): "iam/service-account",
    ("projects",): "project/project",
    ("pubsub", "topics"): "pubsub/topic",
}

_GCS_LEGACY_VERB_MAP = {"rm": "delete", "rb": "delete", "cp": "put", "mv": "put"}

# gcloud global booleans: never swallow the group/verb token after them. This table and
# _GCLOUD_VALUE_FLAGS are for commands outside the reference table (_GCLOUD_FLAGS_FILE),
# and for alpha and beta, whose flags that table may not list.
_GCLOUD_BOOL_FLAGS = {
    "log-http", "no-user-output-enabled", "user-output-enabled", "help",
    # The boolean flags of the commands that change something most often, from the gcloud
    # reference: each is a plain switch (with its --no- form, which the parser reads as a
    # boolean by its name). Add one here only when its reference page shows no value; one
    # that takes a value would make that value a name, an extra target, never a lost one.
    # container clusters create/update and node-pools create
    "enable-autoscaling", "enable-autorepair", "enable-autoupgrade", "enable-ip-alias",
    "enable-private-nodes", "enable-private-endpoint", "enable-master-authorized-networks",
    "enable-network-policy", "enable-shielded-nodes", "enable-vertical-pod-autoscaling",
    "enable-image-streaming", "enable-dataplane-v2", "enable-legacy-authorization",
    "enable-intra-node-visibility", "enable-autoprovisioning", "enable-gvnic",
    "enable-stackdriver-kubernetes", "enable-binauthz", "enable-kubernetes-alpha",
    "enable-tpu", "enable-l4-ilb-subsetting", "enable-service-externalips",
    "enable-identity-service", "spot", "preemptible",
    # compute instances create
    "can-ip-forward", "deletion-protection", "shielded-secure-boot", "shielded-vtpm",
    "shielded-integrity-monitoring", "boot-disk-auto-delete", "restart-on-failure",
    "require-csek-key-create", "enable-display-device", "confidential-compute",
    "enable-nested-virtualization",
    # sql instances create/patch
    "assign-ip", "enable-bin-log", "enable-point-in-time-recovery", "require-ssl",
    "storage-auto-increase", "enable-google-private-path",
    # run deploy, functions deploy
    "allow-unauthenticated", "use-http2", "cpu-boost", "cpu-throttling", "session-affinity",
    "trigger-http", "gen2", "retry",
}

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
    "concurrency", "max-instances", "min-instances", "timeout", "vpc-connector",
    "env-vars-file", "ingress", "command", "args", "trigger-topic", "trigger-bucket",
    "root-password", "availability-type", "edition", "storage-type",
    # more of container and compute
    "disk-size", "disk-type", "release-channel", "subnetwork", "workload-pool",
    "node-locations", "metadata-from-file", "network-interface", "provisioning-model",
    "maintenance-policy", "accelerator", "create-disk", "disk", "address",
})

# gcloud zone -> region: a zone is "<region>-<letter>" (e.g. "us-east1-b" ->
# "us-east1"); strip the trailing "-<letter>" component (REVIEW-4 T2.5).
_ZONE_SUFFIX = re.compile(r"-[a-z]$")


def _region_from_zone(zone: str) -> str:
    return _ZONE_SUFFIX.sub("", zone)


# Every flag of each gcloud command the parser models, read from the gcloud reference
# pages (scripts/gen_gcloud_flags.py; "_source" says where and when). For such a command
# each flag's kind is known, and one the command does not have is refused, as gcloud
# refuses it. "root" is the gcloud-wide flags.
_GCLOUD_FLAGS_FILE = Path(__file__).parent / "data" / "gcloud_flags.json"


@lru_cache(maxsize=1)
def _gcloud_flag_tables() -> dict[str, Any]:
    with open(_GCLOUD_FLAGS_FILE) as f:
        return json.load(f)


def _gcloud_flag_table(command: str) -> dict[str, Any] | None:
    """The flags of ``command`` (``compute instances update``) and gcloud's own, by kind,
    or None when the command is not in the table."""
    tables = _gcloud_flag_tables()
    entry = tables.get(command)
    if entry is None:
        return None
    root = tables["root"]
    table: dict[str, Any] = {kind: frozenset(entry.get(kind, ())) | frozenset(root.get(kind, ()))
                             for kind in ("bool", "value", "optional", "list", "dict")}
    table["alias"] = {**root.get("alias", {}), **entry.get("alias", {})}
    table["types"] = dict(entry.get("types", {}))
    table["actions"] = dict(entry.get("actions", {}))
    table["specs"] = dict(entry.get("specs", {}))
    table["shape_unresolved"] = frozenset(entry.get("shape_unresolved", ()))
    return table


# The SDK's declared types (gcloud_flags.json "types") as normalize_typed's kinds.
_GCLOUD_KINDS = {"int": "gint", "float": "gfloat", "bool": "gbool", "size": "gsize",
                 "duration": "gduration"}


def _gcloud_dict_members(params: dict[str, Any], key: str, value: dict[str, Any],
                         spec: Any, tokens: list[str]) -> dict[str, Any]:
    """An ArgDict's members as its ``spec`` types them (calliope ArgDict: ``count=01`` with
    ``{'count': int}`` is 1), each with the same normalizer a rule's value goes through
    (``value_types`` under ``<flag>.<member>``). With a spec, a member it does not declare,
    a missing required key, or a key with no value where the spec does not allow one is
    refused, as gcloud refuses it. A member whose type is not read statically (or a list
    inside the map) is unresolved; with a spec that is not read statically, the members are
    recorded and the flag and every member are unresolved."""
    if spec == "unresolved":
        # a spec the SDK builds in a way not read statically: the members are recorded, but
        # what type each has is not known, so the map and every member are unresolved
        _mark_unresolved(params, key)
        _mark_unresolved(params, f"{key}.*")
        for member in value:  # a recorded member is unresolved too (".*" spares those)
            _mark_unresolved(params, f"{key}.{member}")
        return value
    if not isinstance(spec, dict):
        return value
    members = spec.get("members", {})
    out: dict[str, Any] = {}
    for member, raw in value.items():
        if member not in members:
            raise ValueError(f"gcloud: --{key} has no key {member!r} (it takes "
                             f"{', '.join(sorted(members))}), and gcloud refuses it: {tokens!r}")
        if raw is None and not spec.get("key_only"):
            raise ValueError(f"gcloud: --{key} key {member!r} needs a value: {tokens!r}")
        kind = members[member]
        base = (kind or "").split(":")[0]
        if raw is None or kind is None:
            out[member] = raw
        elif base in _GCLOUD_KINDS:
            typed = _GCLOUD_KINDS[base] + (":" + kind.split(":", 1)[1] if ":" in kind else "")
            try:
                out[member] = normalize_typed(typed, raw)
            except ValueError as exc:
                raise ValueError(f"gcloud: --{key} {member}={raw!r}: {exc}") from exc
            _mark_type(params, f"{key}.{member}", typed)
        else:
            out[member] = raw
            _mark_unresolved(params, f"{key}.{member}")
    missing = [k for k in spec.get("required", []) if k not in value]
    if missing:
        raise ValueError(f"gcloud: --{key} needs {', '.join(missing)}: {tokens!r}")
    return out


def _gcloud_store(params: dict[str, Any], key: str, value: Any, action: str | None,
                  seen: dict[str, int], tokens: list[str]) -> None:
    """A list or map flag's value, kept as its argparse action keeps a repeat (the SDK's
    ``action=``, gcloud_flags.json "actions"): a plain store keeps the last; ``append``
    keeps each; ``update`` (UpdateAction) extends a list and merges a map, refusing a
    repeated item or key; ``update-append`` keeps every value of a repeated key; ``once``
    (StoreOnceAction) refuses a repeat. An action that is not read statically keeps each
    value and leaves the key unresolved when the flag is repeated."""
    count = seen.get(key, 0)
    seen[key] = count + 1
    if count == 0:
        params[key] = value
        return
    existing = params.get(key)
    if action is None:
        params[key] = value
    elif action == "once":
        raise ValueError(f"gcloud: --{key} cannot be given more than once: {tokens!r}")
    elif action == "append" or action == "unresolved":
        params[key] = ([*existing] if count > 1 else [existing]) + [value]
        if action == "unresolved":
            _mark_unresolved(params, key)
    elif isinstance(value, dict) and isinstance(existing, dict):
        merged = dict(existing)
        for k, v in value.items():
            if k in merged and action == "update":
                raise ValueError(f"gcloud: --{key} sets {k!r} twice: {tokens!r}")
            if k in merged:
                old = merged[k]
                merged[k] = [*old, v] if isinstance(old, list) else [old, v]
            else:
                merged[k] = v
        params[key] = merged
    else:
        items = list(existing) if isinstance(existing, list) else [existing]
        for item in (value if isinstance(value, list) else [value]):
            if item in items:
                raise ValueError(f"gcloud: --{key} gives {item!r} twice: {tokens!r}")
            items.append(item)
        params[key] = items


def _gcloud_arg(text: str, is_dict: bool, existing: Any) -> Any:
    """A gcloud ArgList (``a,b``) as a list, or an ArgDict (``k=v,k2=v2``) as a map, split on
    commas or on the delimiter gcloud's ``^DELIM^`` prefix names, of any length
    (``^:^a:b``, ``^--^env=prod--team=x``; gcloud topic escaping). A map flag given again
    (``--create-disk`` twice) keeps each map."""
    delimiter = ","
    if text.startswith("^") and "^" in text[1:]:
        # gcloud topic escaping: ^DELIM^ names the delimiter, any non-empty string
        end = text.index("^", 1)
        if end == 1:
            raise ValueError(f"gcloud: {text!r} names an empty delimiter")
        delimiter, text = text[1:end], text[end + 1:]
    items = [item for item in text.split(delimiter) if item != ""]
    if not is_dict:
        return items
    pairs: dict[str, Any] = {}
    for item in items:
        k, sep, v = item.partition("=")
        pairs[k] = v if sep else None
    if isinstance(existing, dict):
        return [existing, pairs]
    if isinstance(existing, list) and existing and isinstance(existing[0], dict):
        return [*existing, pairs]
    return pairs


def _parse_gcloud_tokens(
    tokens: list[str], *, storage: bool = False,
    table: dict[str, Any] | None = None, strict: bool = False,
    lenient: bool = False, passthrough: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """``(metadata, params, positional)``. gcloud takes no abbreviated flag (calliope
    disables argparse's prefixes) and never a word starting with "-" as a value. A flag in
    no table followed by a word is refused (see :data:`_GCLOUD_VALUE_FLAGS`). A ``--no-``
    flag is gcloud's off switch of a boolean and takes no value. Words after ``--`` go to
    the command gcloud runs on a command that has one (``compute ssh``, ``passthrough``),
    kept in ``params["passthrough"]``; anywhere else argparse reads them as positionals.
    ``storage`` reads ``gcloud storage``, whose targets are only ``gs://`` paths: there an
    unknown flag may take a word that is not a path. ``table`` is the command's flags
    (:func:`_gcloud_flag_table`), which decide each flag they list; with ``strict`` a flag
    not in it is refused. ``lenient`` only finds the command's words: an unknown flag then
    takes no word."""
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    seen: dict[str, int] = {}  # how many times each list or map flag was given
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
            if passthrough:
                params["passthrough"] = tokens[i + 1:]  # the command gcloud runs (ssh)
            else:
                positional.extend(tokens[i + 1:])  # argparse: positionals, targets too
            break
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if table is not None:
                # a short or other spelling is its flag (-z is --zone): both record the same
                key = table["alias"].get(key, key)
            if (not lenient and not tok.startswith("--") and len(key) == 1 and key not in ("q", "h")
                    and not (storage and key in _GCLOUD_STORAGE_BOOL_FLAGS)):
                raise ValueError(f"gcloud: -{key} is not a short flag the parser knows on "
                                 f"this command; write its long flag: {tokens!r}")
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
            elif key == "flags-file":
                # a YAML file of more flags (--project too), which is not read
                raise ValueError(f"gcloud: {tok} reads flags from a file the hook cannot see: "
                                 f"{tokens!r}")
            elif table is not None and key in table["bool"]:
                _set_bool_param(params, key, _bool_param(val))
            elif table is not None and key in table["value"]:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                declared = table["types"].get(key)
                if key in table["shape_unresolved"]:
                    # the reference page and the SDK disagree on whether this is a map, a
                    # list or one value: which gcloud parses is not known
                    params[key] = val
                    _mark_unresolved(params, key)
                    _mark_unresolved(params, f"{key}.*")
                elif key in table["list"] or key in table["dict"]:
                    value = _gcloud_arg(val, key in table["dict"], None)
                    element = (declared or "").partition(":")[2] if (declared or "").startswith(
                        "list:") else ""
                    if element in _GCLOUD_KINDS and isinstance(value, list):
                        value = [normalize_typed(_GCLOUD_KINDS[element], v) for v in value]
                        _mark_type(params, key, _GCLOUD_KINDS[element])
                    if isinstance(value, dict):
                        value = _gcloud_dict_members(params, key, value,
                                                     table["specs"].get(key), tokens)
                    if declared == "unresolved":
                        # the SDK builds the type in a way not read statically
                        _mark_unresolved(params, key)
                        _mark_unresolved(params, f"{key}.*")
                    _gcloud_store(params, key, value, table["actions"].get(key), seen, tokens)
                elif declared == "unresolved":
                    params[key] = val  # a type the SDK parses its own way: unresolved
                    _mark_unresolved(params, key)
                elif declared and declared.split(":")[0] in _GCLOUD_KINDS:
                    kind = _GCLOUD_KINDS[declared.split(":")[0]] + (
                        ":" + declared.split(":", 1)[1] if ":" in declared else "")
                    try:
                        params[key] = normalize_typed(kind, val)
                    except ValueError as exc:
                        raise ValueError(f"gcloud: {tok} {val!r}: {exc}") from exc
                    _mark_type(params, key, kind)
                elif table["actions"].get(key) is not None:
                    _gcloud_store(params, key, val, table["actions"][key], seen, tokens)
                else:
                    params[key] = val
                _gcloud_mark_file_flag(params, key, declared)
            elif table is not None and key in table["optional"]:
                if val is None and i + 1 < n and not tokens[i + 1].startswith("-"):
                    i += 1  # argparse takes the next word as the optional value
                    val = tokens[i]
                params[key] = True if val is None else val
            elif table is not None and strict:
                raise ValueError(f"gcloud: {tok} is not a flag of this command, and gcloud "
                                 f"refuses it: {tokens!r}")
            elif key in _GCLOUD_BOOL_FLAGS or (storage and key in _GCLOUD_STORAGE_BOOL_FLAGS):
                _set_bool_param(params, key, _bool_param(val))
            elif key in _GCLOUD_VALUE_FLAGS and tok.startswith("--"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params[key] = val
                _gcloud_mark_file_flag(params, key, None)
            elif val is not None:
                params[key] = val
                _gcloud_mark_file_flag(params, key, None)
            elif key.startswith("no-") and tok.startswith("--"):
                _set_bool_param(params, key, True)
            elif lenient:
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
                    params[key] = tokens[i]
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


def _gcloud_name(name: str, metadata: dict[str, Any]) -> str:
    """A resource gcloud is given by URI or path (``https://www.googleapis.com/compute/v1/
    projects/p/zones/z/instances/web-1``, ``projects/p/zones/z/instances/web-1``) is the
    same resource as its plain name, in that project and zone, which then win over the
    flags as they do in gcloud. ``metadata`` is that one name's own copy: each path
    names its own project and zone."""
    if "/" not in name or name.startswith("gs://"):
        return name
    if "#" in name:
        raise ValueError(f"gcloud: {name!r} has a fragment, which is not part of a resource")
    from urllib.parse import urlsplit

    # a URI's path (a relative name is all path), decoded as the API decodes it; an
    # empty, dot or escaped-slash segment is refused
    path = urlsplit(name).path if "://" in name else name.split("?")[0]
    parts = _url_path_segments(path, "gcloud")
    for i, part in enumerate(parts[:-1]):
        if part == "projects":
            metadata["project"] = parts[i + 1]
        elif part == "zones":
            metadata["zone"] = parts[i + 1]
            metadata["region"] = _region_from_zone(parts[i + 1])
        elif part in ("regions", "locations"):
            metadata["region"] = parts[i + 1]
    return parts[-1]


_GLOB_CHARS_RE = re.compile(r"[*?\[]")


def _glob_literal_prefix(name: str) -> str | None:
    """The text before the first wildcard character of ``name``, or None when it has none.
    Every name the pattern matches starts with it, so a rule that cannot match anything
    starting with it cannot be about the pattern's targets."""
    match = _GLOB_CHARS_RE.search(name)
    return None if match is None else name[:match.start()]


def _mark_unresolved(params: dict[str, Any], key: str) -> None:
    marks = params.setdefault("unresolved_scope", [])
    if key not in marks:
        marks.append(key)


def _mark_key_prefix(params: dict[str, Any], prefix: str) -> None:
    """The command reaches every object whose key starts with ``prefix`` (a recursive copy,
    move or delete, a wildcard's literal start): a rule on a key that may start with it
    escalates, and a rule on any other key is not about this command
    (``params["unresolved_prefix"]``, read by the store)."""
    params.setdefault("unresolved_prefix", {})["key"] = prefix


def _gcs_target(uri: str, params: dict[str, Any],
                recursive: bool = False) -> tuple[str, dict[str, Any]]:
    """A ``gs://bucket[/object]`` operand as ``storage/bucket/<bucket>`` with the object in
    ``params["key"]``, on every gcloud storage and gsutil command alike. A wildcard
    (``*``, ``**``, ``?``, ``[...]``) or ``-r`` in the object reaches every key it matches:
    ``key`` is unresolved. gcloud and gsutil expand a wildcard bucket name when they run:
    the intent is marked with the pattern's literal prefix, so a rule on any bucket the
    pattern may match escalates."""
    bucket, _, key = uri[len("gs://"):].partition("/")
    intent_params = dict(params)
    head, hash_sign, generation = key.rpartition("#")
    if hash_sign and generation.isdigit():
        # gs://b/o#123 is generation 123 of object o: the key is o (gcloud storage, gsutil)
        key = head
        intent_params["generation"] = int(generation)
    if key:
        intent_params["key"] = key
    recursive = recursive or any(params.get(k) is True for k in ("r", "R", "recursive"))
    glob = _glob_literal_prefix(key)
    if glob is not None:
        _mark_key_prefix(intent_params, glob)
    elif recursive:
        _mark_key_prefix(intent_params, key)
    prefix = _glob_literal_prefix(bucket)
    if prefix is not None:
        intent_params["resolved_at_runtime"] = {"from": f"storage/bucket/{bucket}",
                                                "kinds": ["storage/bucket"],
                                                "name_prefix": prefix}
    return f"storage/bucket/{bucket}", intent_params


def _copy_destination_key(params: dict[str, Any], sources: list[str], many: bool,
                          folders: bool) -> None:
    """The object a copy writes, as gcloud storage, gsutil and aws s3 name it: a destination
    ending in ``/`` (or a bucket alone) is a folder, and the object is that prefix plus the
    source's base name. With several sources, ``-r``/``--recursive`` or paths from stdin,
    which objects, only the tool knows: ``key`` is unresolved. ``folders``: gcloud and
    gsutil also treat a destination without the slash as a folder when objects under it
    exist, which only they can see, so that key is unresolved too (aws never does)."""
    key = params.get("key", "")
    if many or len(sources) != 1:
        _mark_unresolved(params, "key")
        return
    base = sources[0].rstrip("/").rsplit("/", 1)[-1]
    head, hash_sign, generation = base.rpartition("#")
    if sources[0].startswith("gs://") and hash_sign and generation.isdigit():
        base = head  # a generation is not part of the object's name
    if key == "" or key.endswith("/"):
        if not base or _GLOB_CHARS_RE.search(base):
            _mark_unresolved(params, "key")
            return
        params["key"] = key + base
    elif folders:
        _mark_unresolved(params, "key")


def _gcs_destination_key(params: dict[str, Any], sources: list[str], from_stdin: bool,
                         recursive: bool = False) -> None:
    recursive = recursive or any(params.get(k) is True for k in ("r", "R", "recursive"))
    key = params.get("key", "")
    if recursive and not from_stdin and not _GLOB_CHARS_RE.search(key):
        # everything lands under the destination: <key>/... or <key>/<source base>/...
        params.get("unresolved_prefix", {}).pop("key", None)
        _mark_key_prefix(params, key)
        return
    _copy_destination_key(params, sources, recursive or from_stdin, folders=True)


def _gcs_uri_intents(
    verb: str,
    operands: list[str],
    metadata: dict[str, Any],
    params: dict[str, Any],
    argv: list[str],
    raw_prefix: str,
) -> list[InfrastructureIntent]:
    """One intent per ``gs://`` path: ``rm a b`` deletes both, ``cp`` and ``mv`` write the
    destination (each source is kept as before), and ``mv`` (and gsutil ``cp -M``) also
    deletes every source, all words but the last. With ``-I`` / ``--read-paths-from-stdin``
    the paths come from stdin, which the argv does not show: ``rm`` and a move then also
    reach ``storage/bucket/*``, marked."""
    action = _GCS_LEGACY_VERB_MAP[verb]
    move = verb == "mv" or (raw_prefix == "gsutil" and verb == "cp" and params.get("M") is True)
    # a move is recursive without -r when its source names a container (objects under the
    # prefix), which only the tool sees: gcloud storage mv sets args.recursive = True itself
    # (surface/storage/mv.py), and gsutil's mv runs "cp -M" (gslib/commands/mv.py line 161),
    # whose cp sets recursion_requested = True "if copy_helper_opts.perform_mv and
    # copy_object_info.names_container" (gslib/commands/cp.py lines 801-807, gsutil
    # 368796d). The key itself may also be a single object: the prefix covers both.
    implicit = move
    from_stdin = params.get("I") is True or params.get("read_paths_from_stdin") is True
    uris = [t for t in operands if t.startswith("gs://")]
    if not uris and not (from_stdin and verb in ("rm", "cp", "mv")):
        raise ValueError(f"could not find a gs:// target in: {argv!r}")
    params = {**params, "raw_action": f"{raw_prefix}-{verb}"}
    intents = []
    targets = [(uri, action) for uri in uris]
    if move:
        sources = operands[:-1] if len(operands) > 1 else []
        targets.extend((src, "delete") for src in sources if src.startswith("gs://"))
    destination = operands[-1] if verb in ("cp", "mv") and operands else None
    for uri, act in targets:
        resource, intent_params = _gcs_target(uri, params, recursive=implicit)
        if uri == destination and act == action:
            _gcs_destination_key(intent_params, operands[:-1], from_stdin, recursive=implicit)
        intents.append(InfrastructureIntent(
            resource=resource, action=act, provider="gcp",
            params=intent_params, metadata=dict(metadata)))
    if from_stdin and (verb == "rm" or move):
        intents.append(InfrastructureIntent(
            resource="storage/bucket/*", action="delete", provider="gcp",
            params={**params, "resolved_at_runtime": {"from": "storage/bucket/*",
                                                       "kinds": ["storage/bucket"]}},
            metadata=dict(metadata)))
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
                    if verb is None and letter in ("h", "o"):
                        params.setdefault(letter, []).append(rest)  # each one counts
                    else:
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
    params = _gsutil_globals(params)
    intents = _gcs_uri_intents(verb, words, {}, params, argv, "gsutil")
    return intents + _gcp_impersonation_intents(params, intents)


def _gsutil_globals(params: dict[str, Any]) -> dict[str, Any]:
    """gsutil's top-level options, recorded (gslib/__main__.py): each ``-h 'Name:value'`` a
    header sent with every request, under ``headers.<lower-cased name>``, an
    ``x-goog-meta-<key>`` header the object's ``metadata.<key>``; ``-u`` the project billed
    (``billing_project``); ``-i`` the service account impersonated; ``-o`` a boto option,
    which can change the credentials or the endpoint: every key is unresolved. ``-m``,
    ``-q``, ``-d``, ``-D`` and ``-v`` have no effect on what gsutil does to which object."""
    out = {k: v for k, v in params.items()
           if k not in ("h", "o", "u", "i", *_NO_EFFECT_FLAGS["gsutil"])}
    for header in params.get("h", []):
        name, sep, value = header.partition(":")
        if not sep:
            raise ValueError(f"gsutil: -h {header!r} is not a 'Name:value' header")
        name, value = name.strip().lower(), value.strip()
        out.setdefault("headers", {})[name] = value
        if name.startswith("x-goog-meta-"):
            out.setdefault("metadata", {})[name[len("x-goog-meta-"):]] = value
    if params.get("o"):
        out["boto_options"] = list(params["o"])
        _mark_unresolved(out, "**")
    if params.get("u") is not None:
        out["billing_project"] = params["u"]
    if params.get("i") is not None:
        out["impersonate"] = {"service_account": params["i"]}
    return out


def _gcp_impersonation_intents(params: dict[str, Any],
                               intents: list[InfrastructureIntent]) -> list[InfrastructureIntent]:
    """The service account a gcloud or gsutil command impersonates
    (``--impersonate-service-account``, gsutil ``-i``), as one more intent: an
    ``impersonate`` of ``iam/service-account/<email>``, so a rule on impersonating it holds
    whatever the command does. Several accounts (a delegation chain) are each one."""
    impersonate = params.get("impersonate")
    accounts = impersonate.get("service_account") if isinstance(impersonate, dict) else None
    if not accounts:
        return []
    metadata = dict(intents[0].metadata) if intents else {}
    return [InfrastructureIntent(resource=f"iam/service-account/{account}",
                                 action="impersonate", provider="gcp",
                                 params={"impersonate": impersonate}, metadata=metadata)
            for account in str(accounts).split(",") if account]


# gcloud run commands whose flags after each --container NAME belong to that container
# (googlecloudsdk/command_lib/run/container_parser.py), and the flags a container takes:
# run deploy's ContainerArgGroup (surface/run/deploy.py), the helper flags it adds
# included (env vars, secrets, build env vars, probes).
_GCLOUD_CONTAINER_COMMANDS = frozenset({"run deploy", "run services update"})
_GCLOUD_CONTAINER_FLAGS = frozenset({
    "add-volume-mount", "args", "automatic-updates", "no-automatic-updates", "base-image",
    "build-env-vars-file", "build-service-account", "build-worker-pool", "clear-base-image",
    "clear-build-service-account", "clear-build-worker-pool", "clear-volume-mounts",
    "command", "cpu", "depends-on", "env-vars-file", "function", "gpu", "image",
    "local-build", "memory", "no-build", "port", "remove-volume-mount", "run-upload",
    "sandbox", "sandbox-identity", "sandbox-launcher", "source", "use-http2",
    "no-use-http2", "workdir", "set-env-vars", "update-env-vars", "remove-env-vars",
    "clear-env-vars", "set-secrets", "update-secrets", "remove-secrets", "clear-secrets",
    "set-build-env-vars", "update-build-env-vars", "remove-build-env-vars",
    "clear-build-env-vars", "startup-probe", "liveness-probe", "readiness-probe",
})


def _gcloud_split_containers(tokens: list[str],
                             argv: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    """The words of a run command split as container_parser.ParseKnownArgs splits them:
    every word after ``--container NAME`` (or ``--container=NAME``) belongs to that
    container until the next ``--container``, and ``--`` ends the split. The rest are the
    command's own words."""
    rest: list[str] = []
    containers: dict[str, list[str]] = {}
    current = rest
    i = 0
    while i < len(tokens):
        word = tokens[i]
        i += 1
        if word == "--container":
            if i >= len(tokens):
                raise ValueError(f"gcloud: --container needs a name: {argv!r}")
            current = containers.setdefault(tokens[i], [])
            i += 1
        elif word.startswith("--container="):
            current = containers.setdefault(word.split("=", 1)[1], [])
        elif word == "--":
            rest.extend(tokens[i - 1:])
            break
        else:
            current.append(word)
    return rest, containers


def _gcloud_container_params(containers: dict[str, list[str]], params: dict[str, Any],
                             table: dict[str, Any] | None, strict: bool,
                             argv: list[str]) -> None:
    """Each container's flags, parsed on their own (a fresh parser per container, as gcloud
    does), into ``params["containers"][NAME]``. A plain key holds every container's value
    (``image`` is the list of their images), so a rule on ``image`` meets any of them,
    and a key a container leaves unresolved is unresolved plainly too. gcloud refuses a
    container flag before the first --container and any other flag or word inside one
    (GA), and so does the parser."""
    early = [k for k in params if k in _GCLOUD_CONTAINER_FLAGS]
    if early:
        raise ValueError(f"gcloud: with --container, --{early[0]} must come after a "
                         f"--container: {argv!r}")
    params["containers"] = {}
    for name, words in containers.items():
        meta, own, positional = _parse_gcloud_tokens(words, table=table, strict=strict)
        marks = own.pop("unresolved_scope", [])
        types = own.pop("value_types", {})
        stray = [k for k in own if k not in _GCLOUD_CONTAINER_FLAGS]
        if meta or positional or stray:
            raise ValueError(f"gcloud: container {name!r} has {stray or positional or meta!r}, "
                             f"which is not a container flag: {argv!r}")
        params["containers"][name] = own
        for key, value in own.items():
            params.setdefault(key, []).append(value)
        for mark in marks:
            _mark_unresolved(params, mark)
            _mark_unresolved(params, f"containers.{name}.{mark}")
        for key, kind in types.items():
            _mark_type(params, key, kind)


def from_gcloud_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """:func:`_from_gcloud_numbered`, and the service account
    ``--impersonate-service-account`` impersonates (a comma-separated delegation chain names
    several), as gsutil's ``-i``: ``params["impersonate"]`` and an ``impersonate`` intent on
    each account."""
    intents = _from_gcloud_numbered(argv)
    account = next((i.params.get("impersonate-service-account") for i in intents
                    if i.params.get("impersonate-service-account")), None)
    if not account:
        return intents
    for intent in intents:
        intent.params["impersonate"] = {"service_account": account}
    return intents + _gcp_impersonation_intents(intents[0].params, intents)


def _from_gcloud_numbered(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``gcloud`` (or legacy ``gsutil``) CLI invocation (see
    :func:`_from_gcloud_multi`). A project given by number (``--project 123456789``) is
    recorded as ``project_number``: which project ID it is, is only known to gcloud, so
    ``project`` is left unresolved and a rule on a project ID escalates."""
    intents = _from_gcloud_multi(argv)
    for intent in intents:
        project = intent.metadata.get("project")
        if isinstance(project, str) and project.isdigit():
            intent.metadata["project_number"] = intent.metadata.pop("project")
    return intents


def _from_gcloud_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``gcloud`` (or legacy ``gsutil``) CLI invocation, e.g.:

    ``gcloud compute instances start web-1 --zone us-central1-a``
      -> resource "compute/instance/web-1", action "start"

    One intent per name: ``gcloud compute instances delete a b`` deletes both. The flags of
    a command in the reference table (:func:`_gcloud_flag_table`) are read by their kind,
    and one the command does not have is refused. For any other command (and for alpha
    and beta, whose flags the table may not list), a flag the parser has no entry for,
    followed by a word, is refused: the word is its value or a name, and the parser cannot
    tell which (``--no-graceful-shutdown`` is a boolean by its name, and takes none).
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
    _md, _params, words = _parse_gcloud_tokens(tokens, storage=storage, lenient=True)
    command = _gcloud_command(words)
    table = _gcloud_flag_table(command) if command else None
    # alpha and beta may have flags the (GA) table does not list: those keep the old rule
    strict = table is not None and words[:1] not in (["alpha"], ["beta"])
    # Only ssh takes a command after "--" (its reference page: "[-- SSH_ARGS ...]"). On a
    # command in the table the words after it are positionals, targets included; on any
    # other command which it is is not known, and the command is refused.
    before = tokens[:tokens.index("--")] if "--" in tokens else tokens
    passthrough = (command.split()[-1] == "ssh" if command else
                   "ssh" in [w for w in before if not w.startswith("-")])
    if "--" in tokens and not passthrough and table is None:
        raise ValueError(f"gcloud: whether this command takes a command after '--' is not "
                         f"known, and the words after it may be targets: {argv!r}")
    containers: dict[str, list[str]] = {}
    if command in _GCLOUD_CONTAINER_COMMANDS:
        tokens, containers = _gcloud_split_containers(tokens, argv)
    metadata, params, positional = _parse_gcloud_tokens(tokens, storage=storage,
                                                        table=table, strict=strict,
                                                        passthrough=passthrough)
    if containers:
        _gcloud_container_params(containers, params, table, strict, argv)

    release_track = None
    if positional and positional[0] in ("alpha", "beta"):
        release_track = positional.pop(0)

    if (
        len(positional) >= 2
        and positional[0] == "storage"
        and positional[1] in _GCS_LEGACY_VERB_MAP
    ):
        metadata, params, positional = _parse_gcloud_tokens(tokens, storage=True,
                                                            table=table, strict=strict,
                                                            passthrough=passthrough)
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
    intents: list[InfrastructureIntent] = []
    seen: set[tuple[str, str]] = set()
    for name in names:
        own = dict(metadata)  # each path names its own project and zone
        if group_words[:1] == ["storage"] and name.startswith("gs://"):
            # a bucket or object by gs:// URI, on every storage command as on storage rm
            resource, own_params = _gcs_target(name, params)
        else:
            resource, own_params = f"{resource_prefix}/{_gcloud_name(name, own)}", dict(params)
        signature = (resource, repr(sorted(own.items())) + repr(own_params.get("key")))
        if signature in seen:
            continue
        seen.add(signature)
        intents.append(InfrastructureIntent(resource=resource, action=action, provider="gcp",
                                            params=own_params, metadata=own))
    stdin = params.get("read_paths_from_stdin") is True or params.get("I") is True
    if not intents or (stdin and group_words[:1] == ["storage"]):
        # no name, or more names from stdin (--read-paths-from-stdin, -I): which, only
        # gcloud knows (marked by mark_unknown_names)
        prefix = "storage/bucket" if group_words[:1] == ["storage"] and stdin else \
            resource_prefix
        intents.append(InfrastructureIntent(resource=f"{prefix}/*", action=action,
                                            provider="gcp", params=dict(params),
                                            metadata=dict(metadata)))
    return intents


def _gcloud_command(words: list[str]) -> str | None:
    """The command the words name, as the flag table spells it (``compute instances
    update``, ``sql import csv``), or None."""
    words = words[1:] if words[:1] in (["alpha"], ["beta"]) else words
    tables = _gcloud_flag_tables()
    for size in (4, 3, 2):
        command = " ".join(words[:size])
        if len(words) >= size and command in tables:
            return command
    return None


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
            short_key = key
            if not is_long:
                # a short letter is recorded as its long flag: both spellings record the same
                long_name = _helm_short_name(key, verb)
                if long_name is None:
                    raise ValueError(f"-{key} is not a short flag the parser knows on this "
                                     f"command; write its long flag: {tokens!r}")
                key = long_name
            key = _pflag_aliases("helm").get(key, key)  # --force is --force-replace (helm 4)
            if key == "namespace":
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
                if key == "kube-apiserver":
                    metadata["server"] = val  # see mark_config_scope
                elif key == "kubeconfig":
                    metadata["kubeconfig"] = val  # as kubectl's
                elif key in ("kube-as-user", "kube-as-group"):
                    # helm impersonates as kubectl --as / --as-group does: one structure
                    imp = params.setdefault("impersonate", {})
                    if key == "kube-as-group":
                        imp.setdefault("groups", []).append(val)
                    else:
                        imp["user"] = val
                else:
                    _record_flag(params, "helm", key, val)
            elif key in _HELM_GLOBAL_BOOL_FLAGS:
                if _bool_param(val) is not False:
                    _record_flag(params, "helm", key, True)
            elif key == "dry-run":
                # helm: --dry-run, =client, =server, =true rehearse;
                # =none / =false run for real.
                _record_dry_run(params, _is_dry_run(val, truthy=_KUBECTL_DRY_RUN_WORDS))
            elif key == "version":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                params["version"] = val
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
            elif key in ("A", "all-namespaces"):
                # every namespace, as kubectl's -A: the last spelling decides
                _record_all_namespaces(metadata, val)
            elif key == "wait":
                params["wait"] = _helm_wait(val)
                _mark_unresolved(params, "wait")  # helm 3 reads it as a boolean
            elif is_long and key in long_bools:
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and short_key in short_bools:
                # Takes no value: in "-i api ./c" the release is "api".
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and short_key in short_values:
                # Always the next token, whatever it looks like, as pflag reads it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                _pflag_store(params, "helm", key, key.replace("-", "_"), val, verb)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, value = _other_flag(
                    tokens, i, values=long_values if is_long else (), bools=(), tool="helm")
                _pflag_store(params, "helm", key, key.replace("-", "_"), value, verb)
        else:
            positional.append(tok)
        i += 1

    _merge_helm_values(params, sets, verb)
    _mirror_aliases(params, _pflag_aliases("helm"))
    return metadata, params, positional


# --- helm values from the command line --------------------------------------------------
# A port of helm's pkg/strvals (helm 4.3.1 and 3.21.1), which reads --set, --set-string,
# --set-json, --set-file and --set-literal into one nested map, so params["set"] has the
# shape helm gives the chart and a rule's dotted scope key (set.securityContext.privileged)
# walks it. What helm refuses is a ValueError.

def _go_json_number(text: str) -> int | float:
    """A JSON number as Go's encoding/json decodes it into an interface{} (helm's strvals
    does not use UseNumber): a float64, so 9007199254740993 is 9007199254740992. An
    integral value is returned as an int, which the store compares equal to the float. A
    number out of float64's range Go refuses, and so does the parser."""
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError(f"JSON number {text} is out of range of a float64")
    return int(value) if value.is_integer() else value


def _go_json_constant(text: str) -> Any:
    raise ValueError(f"{text} is not JSON")  # Python accepts NaN and Infinity; Go does not


_GO_JSON = json.JSONDecoder(parse_int=_go_json_number, parse_float=_go_json_number,
                            parse_constant=_go_json_constant)

_HELM_MAX_INDEX = 65536
_HELM_MAX_NESTED = 30
# The value of a --set-file key: the content of a file nobody read.
_HELM_FILE_VALUE = object()


class _StrvalsParser:
    def __init__(self, text: str, mode: str) -> None:
        self.s = text
        self.i = 0
        self.mode = mode  # "typed", "string", "json", "file" or "literal"
        # the dotted paths written into rather than replaced: a map a nested key is set in,
        # a list an index is set in (strvals ParseInto keeps what is already there)
        self.merged: set[str] = set()
        self._prefix: list[str] = []
        self._in_list = 0

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
                value, end = _GO_JSON.raw_decode(self.s, self.i)
            except ValueError as err:
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
            if not self._in_list:
                self.merged.add(".".join([*self._prefix, name]))
            self._in_list += 1
            try:
                items = self.list_item(list(existing), self.index(), level)
            finally:
                self._in_list -= 1
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
        if not self._in_list:
            self.merged.add(".".join([*self._prefix, name]))
        self._prefix.append(name)
        try:
            self.key(inner, level)
        finally:
            self._prefix.pop()
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


def _helm_dig(values: dict[str, Any], path: str) -> Any:
    node: Any = values
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _merge_helm_values(params: dict[str, Any], sets: dict[str, list[str]],
                       verb: str | None = None) -> None:
    """``params["set"]``: the values the command line sets, as one nested map, merged in
    helm's order (pkg/cli/values MergeValues): --set-json, --set, --set-string, --set-file
    and --set-literal, a later one replacing an earlier one at the same key, a map
    replacing a scalar only through --set-json. A --set-file value is the file's content,
    which is not read, and a values file (-f) or --reuse-values can set any key the command
    line does not: those keys are in ``params["unresolved_scope"]`` (``set.<key>``, or
    ``set.*`` for every key not set), so a rule scoped on them escalates.

    ``upgrade`` also takes the release's previous values (helm 3.21.1 and 4.3.1
    Upgrade.reuseValues): with --reuse-values or --reset-then-reuse-values for every key
    the command line does not set, and with neither when the command line sets no value at
    all; --reset-values, checked first, turns all of it off. ``rollback`` puts back an
    earlier revision's values. Those values are not on the argv either: ``set.*``."""
    base: dict[str, Any] = {}
    merged: set[str] = set()

    def map_paths(value: Any, path: str) -> None:
        # MergeMaps merges each map of a JSON object into the one already there
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, dict):
                    merged.add(f"{path}{k}")
                    map_paths(v, f"{path}{k}.")

    for value in sets["set-json"]:
        stripped = value.strip()
        if stripped.startswith("{"):
            try:
                loaded = _GO_JSON.decode(stripped)
            except ValueError as err:
                raise ValueError(f"helm: --set-json {value!r} is not JSON: {err}") from err
            if not isinstance(loaded, dict):
                raise ValueError(f"helm: --set-json {value!r} is not a JSON object")
            base = _helm_merge_maps(base, loaded)
            map_paths(loaded, "")
        else:
            parser = _StrvalsParser(value, "json")
            parser.parse(base)
            merged |= parser.merged
    for kind, mode in (("set", "typed"), ("set-string", "string"), ("set-file", "file"),
                       ("set-literal", "literal")):
        for value in sets[kind]:
            parser = _StrvalsParser(value, mode)
            parser.parse(base)
            merged |= parser.merged
    unresolved: list[str] = []
    cleaned = _strip_file_values(base, "set", unresolved)
    if cleaned:
        params["set"] = cleaned
    reuse = verb == "rollback" or (
        verb == "upgrade" and params.get("reset_values") is not True
        and (params.get("reuse_values") is True or params.get("reset_then_reuse_values") is True
             or (not base and not params.get("values_files"))))
    if params.get("values_files") or reuse:
        unresolved.append("set.*")
        # keys --set replaced outright stay known: the store spares recorded keys of this
        # one prefix mark (store.param_unresolved); the containers it merged into are
        # marked below
        if cleaned:
            params["unresolved_except_recorded"] = ["set.*"]
        # A --set writes into what the files or the reused values hold: a list index
        # keeps the list's other items, a nested key the map's other keys. Those maps and
        # lists, compared whole, are unknown; only a value set whole (a scalar, a {a,b}
        # list) is known. A container a later --set replaced whole is known again.
        for path in sorted(merged):
            if isinstance(_helm_dig(base, path), (dict, list)):
                unresolved.append(f"set.{path}")
    for mark in unresolved:
        _mark_unresolved(params, mark)


def from_helm_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """:func:`_from_helm_multi`, and each identity ``--kube-as-user`` and
    ``--kube-as-group`` impersonate (:func:`_kube_impersonation_intents`)."""
    intents = _from_helm_multi(argv)
    return intents + _kube_impersonation_intents(intents)


def _from_helm_multi(argv: list[str]) -> list[InfrastructureIntent]:
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
    if params.get("atomic") is True or params.get("rollback_on_failure") is True:
        # --atomic (helm 3) turns --wait on, and --rollback-on-failure (helm 4) waits too:
        # by their final values, so the wait is not what --wait alone says
        _mark_unresolved(params, "wait")

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
            params["revision"] = _go_atoi(positional[1], "revision")
        return [one(positional[0], "rollback")]

    if verb == "repo":
        # helm repo add|update|remove|list: the local repository list, not a release
        sub = positional[0] if positional else None
        names = positional[1:]
        params["raw_action"] = f"repo-{sub}"

        def repo(name: str, action: str) -> InfrastructureIntent:
            return InfrastructureIntent(resource=f"repo/{name}", action=action,
                                        provider="helm", params=dict(params),
                                        metadata=dict(metadata))

        if sub == "add" and len(names) == 2:
            params["url"] = names[1]
            return [repo(names[0], "create")]
        if sub in ("update", "up"):
            return [repo(name, "update") for name in names] or _mark_open_targets(
                [repo("*", "update")])
        if sub in ("remove", "rm") and names:
            return [repo(name, "delete") for name in names]
        if sub in ("list", "ls") and not names:
            return [repo("*", "read")]
        raise ValueError(f"unsupported helm repo invocation: {argv!r}")

    if verb in ("pull", "fetch"):
        # downloads a chart to the local disk
        if len(positional) != 1:
            raise ValueError(f"helm pull takes one chart: {argv!r}")
        return [InfrastructureIntent(resource=f"chart/{positional[0]}", action="read",
                                     provider="helm", params=dict(params),
                                     metadata=dict(metadata))]

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
            if not known:
                raise ValueError(f"argocd: -{key} is not a short flag the parser knows; write "
                                 f"its long flag: {tokens!r}")
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
            elif name in ("server", "app-namespace") and known:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata[name.replace("-", "_")] = val
            elif name in _ARGOCD_GLOBAL_VALUE_FLAGS and known:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if name in ("header", "H"):
                    # each -H is one more header sent with every request
                    params.setdefault("header", []).append(val)
                else:
                    _record_flag(params, "argocd", name, val)
            elif name in _ARGOCD_GLOBAL_BOOL_FLAGS:
                if _bool_param(val) is not False:
                    _record_flag(params, "argocd", name, True)
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
                _pflag_store(params, "argocd", name, name.replace("-", "_"), val,
                             f"app {verb}" if verb else None)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, value = _other_flag(
                    tokens, i, values=_ARGOCD_VALUE_FLAGS if is_long else (), bools=(),
                    tool="argocd")
                _pflag_store(params, "argocd", key, key.replace("-", "_"), value,
                             f"app {verb}" if verb else None)
        else:
            positional.append(tok)
        i += 1

    return metadata, params, positional


def from_argocd_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses an ``argocd`` invocation (see :func:`_from_argocd_multi`). Every intent, from
    every subcommand, then has its app name normalized once: ``NAMESPACE/NAME`` is
    ``app/NAME`` with ``app_namespace``, as argocd's ParseFromQualifiedName reads it, the
    same app as ``NAME -N NAMESPACE`` (the qualified namespace wins over ``-N``)."""
    intents = _from_argocd_multi(argv)
    for intent in intents:
        name = intent.resource.partition("/")[2]
        if "/" in name and name != "*":
            namespace, name = name.split("/", 1)
            intent.metadata["app_namespace"] = namespace
            intent.resource = f"app/{name}"
    return intents


def _from_argocd_multi(argv: list[str]) -> list[InfrastructureIntent]:
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
    if action == "read" and (params.get("refresh") is True or params.get("hard_refresh") is True
                             or params.get("hard-refresh") is True):
        # --refresh / --hard-refresh patch the Application's refresh annotation (app.go)
        action = "update"

    # The apps a selector or a project picks, which argocd lists when it runs.
    picked: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if subverb in _ARGOCD_MULTI_APP_VERBS:
        selector = params.get("selector")
        projects = params.get("projects", []) if subverb == "sync" else []
        for project in projects or ([None] if selector is not None else []):
            where = {**metadata, "project": project} if project is not None else dict(metadata)
            if subverb == "delete":
                # delete lists the selector's apps in every namespace (getAppNamesBySelector
                # passes no AppNamespace) and deletes each by its qualified name: -N does
                # not narrow it. sync passes -N to its List, so there it does.
                where.pop("app_namespace", None)
            picked.append(({**params, "resolved_at_runtime": {"from": "app/*",
                                                               "kinds": ["app"]}}, where))

    from_file = subverb == "create" and params.get("file") is not None
    if from_file:
        # --file reads the Applications (one or more) from a file, a URL or stdin, and the
        # name on the line is not needed: handled before any name is required
        apps = ["*"]
    elif subverb == "list":
        apps = positional if positional else ["*"]
    elif subverb == "rollback":
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]
        if len(positional) > 1:
            params["revision"] = _go_atoi(positional[1], "revision")
    elif subverb in _ARGOCD_MULTI_APP_VERBS:
        if not positional and not picked:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = positional
    else:
        if not positional:
            raise ValueError(f"could not find an argocd app name in: {argv!r}")
        apps = [positional[0]]

    if from_file:
        # which apps, in which project and namespace, only argocd knows when it reads them;
        # the scope flags on the line are not recorded as theirs (argocd's ConstructApps
        # does not apply --project to apps read from stdin)
        params["resolved_at_runtime"] = {"from": "app/*", "kinds": ["app"]}
        params["unresolved_scope"] = [*params.get("unresolved_scope", []), "*"]
        params.pop("projects", None)
        for key in ("project", "app_namespace"):
            metadata.pop(key, None)
    # A selector or a project adds the apps it picks; it says nothing about the apps named,
    # whose project stays unknown (it is the app's own) and which no selector picked.
    named_params, named_metadata = dict(params), dict(metadata)
    if picked:
        for key in ("selector", "projects"):
            named_params.pop(key, None)
        if subverb == "sync":
            named_metadata.pop("project", None)
    intents = [InfrastructureIntent(resource=f"app/{app}", action=action, provider="argocd",
                                    params=dict(named_params), metadata=dict(named_metadata))
               for app in apps]
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
    "n", "namespace", "context", "timeout", "username", "password", "user"}

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
# A HelmRelease's chart is reconciled with its own source as well. The source reference
# may name its own namespace (sourceRef.namespace), so the source's namespace is unknown
# too, whatever -n says: its intents cover every namespace.
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
            short_key = key
            if not is_long:
                # a short letter is recorded as its long flag: both spellings record the same
                long_name = _flux_short_name(key, verb)
                if long_name is None:
                    raise ValueError(f"-{key} is not a short flag the parser knows on this "
                                     f"command; write its long flag: {tokens!r}")
                key = long_name
            if key == "namespace":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["namespace"] = val
            elif key == "context":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["context"] = val
            elif key == "user":
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["user"] = val  # the kubeconfig user, a scope a rule may name
            elif key in _FLUX_DISCARD_VALUE_FLAGS:
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                if key == "server":
                    metadata["server"] = val  # see mark_config_scope
                elif key in ("kubeconfig", "cluster"):
                    metadata[key] = val  # as kubectl's
                elif key in ("as", "as-group", "as-uid", "as-user-extra"):
                    # flux impersonates as kubectl --as does: one structure
                    imp = params.setdefault("impersonate", {})
                    if key == "as-group":
                        imp.setdefault("groups", []).append(val)
                    elif key == "as-user-extra":
                        imp.setdefault("extra", []).append(val)
                    else:
                        imp["user" if key == "as" else "uid"] = val
                else:
                    _record_flag(params, "flux", key, val)
            elif key in ("verbose", "insecure-skip-tls-verify", "disable-compression"):
                if _bool_param(val) is not False:
                    _record_flag(params, "flux", key, True)
            elif key == "dry-run":
                # Not a flag of any verb parsed here: flux refuses it and runs nothing,
                # and so does the parser (it is never read as a rehearsal)
                raise ValueError(f"flux: --dry-run is not a flag of this command, and flux "
                                 f"refuses it: {tokens!r}")
            elif key == "export":
                params["export"] = _bool_param(val)
            elif key in ("A", "all-namespaces"):
                # every namespace, as kubectl's -A: the last spelling decides
                _record_all_namespaces(metadata, val)
            elif is_long and key in _FLUX_BOOL_FLAGS:
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and short_key in short_bools:
                # Takes no value: in "get ks -A a" the name is "a".
                params[key.replace("-", "_")] = _bool_param(val)
            elif not is_long and short_key in short_values:
                # Always the next token, whatever it looks like, as pflag reads it.
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                _pflag_store(params, "flux", key, key.replace("-", "_"), val, verb)
            else:
                # A value flag takes the next word whatever it is (#80); a flag in no
                # table is refused unless "=value" or its place shows its reading.
                i, value = _other_flag(
                    tokens, i, values=_FLUX_VALUE_FLAGS if is_long else (), bools=(),
                    tool="flux")
                _pflag_store(params, "flux", key, key.replace("-", "_"), value, verb)
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
    """:func:`_from_flux_multi`, and each identity ``--as``, ``--as-group`` and ``--as-uid``
    impersonate (:func:`_kube_impersonation_intents`)."""
    intents = _from_flux_multi(argv)
    return intents + _kube_impersonation_intents(intents)


def _from_flux_multi(argv: list[str]) -> list[InfrastructureIntent]:
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
                    for intent in make([f"{source}/*"], action,
                                       {"resolved_at_runtime": marker}):
                        intent.metadata.pop("namespace", None)
                        intent.metadata["all_namespaces"] = True
                        intents.append(intent)
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
    """A git verb without an option table: which of its options take a value, and what each
    letter means, is not known here, so no option is recorded as written (``-n`` is
    --dry-run on one verb and --no-tags on another). Any option leaves every param
    unresolved (``*``), so a rule scoped on one escalates, and the words are the verb's
    arguments only up to the first option, and after ``--``."""
    params: dict[str, Any] = {}
    positional: list[str] = []
    seen_option = False
    for i, tok in enumerate(tokens):
        if tok == "--":
            positional.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and tok != "-":
            seen_option = True
        elif not seen_option:
            positional.append(tok)
    if seen_option:
        params["unresolved_scope"] = ["*"]
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


# Long options that are another name of one option, per verb (git 2.52: push.c registers
# --exec and --receive-pack on one variable; branch.c and tag.c --with and --without as
# hidden names of --contains and --no-contains): the value lands on one key, in order.
_GIT_OPTION_ALIASES = {
    "push": {"exec": "receive-pack"},
    "branch": {"with": "contains", "without": "no-contains"},
    "tag": {"with": "contains", "without": "no-contains"},
}

# The options that take a value each time they are given, per verb (git 2.52's
# documentation, checked by running git): push -o/--push-option ("can be given multiple
# times") and --force-with-lease (one per ref); commit and tag -m ("concatenated as
# separate paragraphs") and --trailer; branch and tag --contains, --no-contains, --merged,
# --no-merged, --points-at and --sort (each adds a filter or a sort key); rebase -x/--exec
# and -X/--strategy-option. Every other value option keeps its last value.
_GIT_ACCUMULATING = {
    "push": frozenset({"push-option", "force-with-lease"}),
    "commit": frozenset({"message", "trailer"}),
    "tag": frozenset({"message", "trailer", "contains", "no-contains", "with", "without",
                      "merged", "no-merged", "points-at", "sort"}),
    "branch": frozenset({"contains", "no-contains", "with", "without", "merged",
                         "no-merged", "points-at", "sort"}),
    "rebase": frozenset({"exec", "strategy-option"}),
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
    """The params a git verb's options set, each by its last spelling. ``--no-x`` is
    ``x: False``, and an option that is the negative of another (``--no-verify`` beside
    ``--verify``, ``-n`` on commit) is that one with ``False``, so one value has one key."""
    longs = _GIT_OPTIONS[verb][1]
    accumulating = _GIT_ACCUMULATING.get(verb, frozenset())
    aliases = _GIT_OPTION_ALIASES.get(verb, {})
    params: dict[str, Any] = {}
    for name, val in options:
        if val is True and name.startswith("no-") and name[3:] in longs:
            name, val = name[3:], None
        name = aliases.get(name, name)  # one option under several names: one key
        key = name.replace("-", "_")
        if name in accumulating:
            # each one adds a value; the --no- form empties the list (OPT_STRING_LIST)
            if val is None:
                params.pop(key, None)
            else:
                params.setdefault(key, []).append(val)
        elif val is None:
            params[key] = False
        else:
            params[key] = val  # git's option values are text
    for alias, canonical in aliases.items():  # every name of the option holds its value
        if canonical.replace("-", "_") in params:
            params[alias.replace("-", "_")] = params[canonical.replace("-", "_")]
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
        # -D, -M and -C are --delete, --move and --copy with --force: recorded that way
        for letter, name in (("D", "delete"), ("M", "move"), ("C", "copy")):
            if params.pop(letter, None) is True and name in ("move", "copy"):
                params[name] = True
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
        if spec == ":":
            ref = None  # ":" pushes every branch that matches one on the remote
        elif spec in ("HEAD", "@") or _git_resolved_name(spec.rpartition(":")[2]):
            # the current branch, its upstream (@{u}, @{push}), the one before (@{-1}, -):
            # which ref, only git knows
            ref = None
        elif spec.startswith(":"):
            delete = True
            ref = spec[1:]
        elif ":" in spec:
            _src, _sep, dst = spec.partition(":")
            ref = dst
        else:
            ref = spec
        if ref and ref.startswith("refs/heads/"):
            ref = ref[len("refs/heads/") :]
        elif ref and ref.startswith("refs/tags/"):
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


def _git_name(kind: str, name: str) -> str:
    """``kind/name`` for a branch, tag or ref name on a git command line, or ``kind/*`` when
    git resolves the name when it runs (:func:`_git_resolved_name`): which one, only git
    knows. The one helper every git name operand goes through."""
    return f"{kind}/*" if _git_resolved_name(name) else f"{kind}/{name}"


def _git_resolved_name(name: str) -> bool:
    """Whether git resolves ``name`` to a ref when it runs: ``@{upstream}``, ``@{push}``,
    ``@{-1}`` and the like, ``-`` (the previous branch), ``HEAD`` and ``@``."""
    return "@{" in name or name in ("-", "HEAD", "@")


def _git_config(leading: list[str]) -> dict[str, str | None]:
    """The ``-c name=value`` settings in front of the verb, names lower-cased (``-c name``
    alone is true). ``--config-env name=VAR`` takes its value from the environment, which
    the argv does not show: None."""
    config: dict[str, str | None] = {}
    i = 0
    while i < len(leading):
        word = leading[i]
        if word in ("-c", "--config-env") and i + 1 < len(leading):
            name, sep, value = leading[i + 1].partition("=")
            config[name.lower()] = None if word == "--config-env" else (value if sep else "true")
            i += 2
            continue
        if word.startswith("--config-env="):
            config[word.split("=", 2)[1].lower()] = None
        i += 1
    return config


def _git_push_mappings(leading: list[str], remote: str | None) -> list[str | None]:
    """The ``remote.<remote>.push`` refspecs given with ``-c`` in front of the verb, in
    order (section and key without case, the remote's name with it, as git compares
    them); None for one ``--config-env`` takes from the environment."""
    if remote is None or _git_remote_is_url(remote):
        return []
    found: list[str | None] = []
    i = 0
    while i < len(leading):
        word = leading[i]
        if word in ("-c", "--config-env") and i + 1 < len(leading):
            name, sep, value = leading[i + 1].partition("=")
            section, _, rest = name.partition(".")
            subsection, _, key = rest.rpartition(".")
            if section.lower() == "remote" and key.lower() == "push" and subsection == remote:
                found.append(None if word == "--config-env" else (value if sep else None))
            i += 2
            continue
        i += 1
    return found


def _git_push_mapped(mappings: list[str | None], src: str) -> tuple[str, bool] | None:
    """The destination (and whether it forces) of the first push refspec in ``mappings``
    whose source matches ``src`` (``safe`` or ``refs/heads/safe``), with a ``*`` in it
    standing for the same text on both sides; None when none does or one is unknown."""
    candidates = {src, f"refs/heads/{src}"} if not src.startswith("refs/") else {src}
    for mapping in mappings:
        if mapping is None:
            return None
        force = mapping.startswith("+")
        msrc, sep, mdst = mapping.lstrip("+").partition(":")
        if not sep:
            mdst = msrc
        for candidate in candidates:
            if "*" in msrc:
                head, _, tail = msrc.partition("*")
                if candidate.startswith(head) and candidate.endswith(tail) and \
                        len(candidate) >= len(head) + len(tail):
                    middle = candidate[len(head):len(candidate) - len(tail)]
                    return mdst.replace("*", middle, 1), force
            elif candidate == msrc:
                return mdst, force
    return None


def _git_config_true(value: str | None) -> bool:
    """git's boolean config: true, yes, on, 1 (or unknown, which can only be stricter)."""
    return value is None or value.strip().lower() in ("true", "yes", "on", "1")


def _from_git_push(
    positional: list[str], params: dict[str, Any], metadata: dict[str, Any],
    options: list[tuple[str, Any]], config: dict[str, str | None],
    leading: list[str] | None = None,
) -> list[InfrastructureIntent]:
    """One intent per refspec: ``git push origin a +b :c`` pushes a, force-pushes b and
    deletes c. Refs the argv does not name are one more intent on ``ref/*``, marked
    ``unknown_target``: every tag (``--tags``), the annotated tags reachable from what is
    pushed (``--follow-tags``, or ``-c push.followTags`` unless ``--no-follow-tags``), the
    remote refs with no local one (``--prune``, a delete), and with no refspec, ``:`` or
    ``HEAD``, whatever push.default, ``--all``/``--branches`` or ``--mirror`` pick (as is
    ``-c remote.<name>.mirror``, a force push that deletes)."""
    remote = positional[0] if positional else None
    if remote is None and isinstance(params.get("repo"), str):
        remote = params["repo"]  # --repo is the remote when none is given after the verb
    if params.get("delete") is True and any(
            params.get(k) is True for k in ("tags", "all", "branches", "mirror")):
        raise ValueError("git push: --delete cannot be used with --all/--branches/--mirror/"
                         "--tags")
    refspecs = _git_push_refspecs(positional[1:], params.get("delete") is True)
    if remote is not None and _git_remote_is_url(remote):
        # a URL or path: which configured remote (if any) it is, is not on the argv
        params = {**params, "remote_url": remote}
    elif remote is not None:
        metadata = {**metadata, "remote": remote}
    mirror_key = f"remote.{(remote or 'origin').lower()}.mirror"
    if mirror_key in config and _git_config_true(config[mirror_key]):
        params = {**params, "mirror": True, "force": True}
    if not refspecs:
        # push.default, remote.<name>.push (a "+" refspec forces) and remote.<name>.mirror
        # in git's config decide what a push with no refspec sends, and whether it forces
        params = {**params, "unresolved_scope": [*params.get("unresolved_scope", []), "force"]}
    intents = [_git_push_intent(refspec, params, metadata) for refspec in refspecs or [None]]
    mappings = _git_push_mappings(leading or [], remote)
    for refspec, intent in list(zip(refspecs, intents, strict=False)):
        spec = refspec.lstrip("+")
        if (":" not in spec and intent.action == "push"
                and not intent.params.get("unknown_target")):
            # A refspec with no destination is mapped when git runs: a remote.<name>.push
            # refspec that matches it (with its +), or push.default's upstream, in any
            # config file git reads (git-push(1), git-config(1) remote.<name>.push and
            # push.default). The source is known;
            # the destination is not, so a rule on any ref may be about it.
            intent.params["resolved_at_runtime"] = {"from": intent.resource, "kinds": ["ref"],
                                                    "destination": True}
            mapped = _git_push_mapped(mappings, spec)
            if mapped is not None:
                # -c remote.<name>.push on the line maps it as git does (a config file's
                # earlier entry could still win: the mark stays)
                dst, force = mapped
                intents.append(_git_push_intent(f"{'+' if force or refspec.startswith('+') else ''}"
                                                f"{spec}:{dst}", params, metadata))
        dst = refspec.lstrip("+").rpartition(":")[2]
        if dst.startswith("refs/tags/"):
            intents.append(_git_push_tag(dst[len("refs/tags/"):], refspec, intent.action,
                                         params, metadata))
        elif dst and not dst.startswith("refs/") and "*" not in dst and \
                not intent.params.get("unknown_target"):
            # git qualifies a short name by what it is: the local ref the source names,
            # or the remote ref of that name, which may be a tag either way
            intent.params["possible_resources"] = [f"tag/{intent.resource[4:]}"]
    negated = ("follow-tags", None) in options or (
        "push.followtags" in config and not _git_config_true(config["push.followtags"]))
    follow = params.get("follow_tags") is True or (
        "push.followtags" in config and _git_config_true(config["push.followtags"])
        and not negated)
    # a push that only deletes sends no tags (git refuses --delete with --tags)
    deleting = bool(refspecs) and all(r.lstrip("+").startswith(":") and r.lstrip("+") != ":"
                                      for r in refspecs)
    if refspecs and not deleting and (params.get("tags") is True or follow):
        intents.append(_git_push_intent(None, params, metadata))
    if not deleting and (params.get("tags") is True or params.get("mirror") is True
                         or not negated):
        # tags: every one with --tags or --mirror; with push.followTags, in any config
        # file git reads, the annotated tags reachable from what is pushed. Only a rule on
        # tag/... is about these: a rule on ref/main is not.
        intents.append(_git_push_tag("*", None, "push", params, metadata))
    if params.get("prune") is True or params.get("mirror") is True:
        intents.append(_git_push_intent(None, {**params, "delete": True}, metadata))
        # the remote tags with no local one go too
        intents.append(_git_push_tag("*", None, "delete", params, metadata))
    elif not refspecs:
        # remote.<name>.mirror makes a push with no refspec delete remote refs too
        delete = _git_push_intent(None, {**params, "delete": True}, metadata)
        delete.params.pop("unknown_target", None)
        delete.params["resolved_at_runtime"] = {"from": "ref/*", "kinds": ["ref"]}
        intents.append(delete)
        intents.append(_git_push_tag("*", None, "delete", params, metadata))
    return intents


def _git_push_refspecs(words: list[str], delete: bool) -> list[str]:
    """The refspecs a push sends for the words after the remote. git-push(1): ``tag <tag>``
    is ``refs/tags/<tag>``, and ``--delete`` deletes every listed ref, the same as a colon
    in front of each. Checked by running git 2.52 against a local bare repository: git
    refuses ``tag`` with nothing after it, ``--delete`` with no refs, and ``--delete`` with
    an empty name or one that holds a colon."""
    names: list[str] = []
    pending_tag = False
    for word in words:
        if pending_tag:
            names.append(f"refs/tags/{word}")
            pending_tag = False
        elif word == "tag":
            pending_tag = True
        else:
            if delete and (not word or ":" in word):
                raise ValueError(f"git push --delete takes ref names only, which {word!r} "
                                 "is not (git refuses it)")
            names.append(word)
    if pending_tag:
        raise ValueError("git push: 'tag' needs a tag name after it (git refuses it)")
    if delete and not names:
        raise ValueError("git push --delete needs at least one ref (git refuses it)")
    return [f":{name}" for name in names] if delete else names


def _git_remote_is_url(remote: str) -> bool:
    """Whether git reads ``remote`` as a URL or a path rather than a remote's name."""
    return "://" in remote or remote.startswith(("/", ".", "~")) or (
        ":" in remote and "/" not in remote.split(":", 1)[0])


def _git_push_tag(name: str, refspec: str | None, action: str, params: dict[str, Any],
                  metadata: dict[str, Any]) -> InfrastructureIntent:
    """A tag a push sends or deletes (``action``), as ``tag/<name>`` (``ref/<name>``
    stays for a named refspec). ``tag/*`` is marked: which tags, is only known when git
    runs."""
    tag_params = {k: v for k, v in params.items() if k != "unknown_target"}
    if (refspec is not None and refspec.startswith("+")) or params.get("mirror") is True:
        tag_params["force"] = True
    if action == "delete":
        tag_params["delete"] = True
    if name == "*":
        tag_params["resolved_at_runtime"] = {"from": "tag/*", "kinds": ["tag"]}
    return InfrastructureIntent(resource=f"tag/{name}", action=action, provider="git",
                                params=tag_params, metadata=dict(metadata))


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

    leading, rest = _split_leading_globals(
        argv[1:],
        value_flags=_GIT_GLOBAL_VALUE_FLAGS,
        bool_flags=_GIT_GLOBAL_BOOL_FLAGS,
        tool="git",
    )
    verb = rest[0]
    tokens = rest[1:]
    options: list[tuple[str, Any]] = []
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
        return _from_git_push(positional, params, metadata, options, _git_config(leading),
                              leading)

    if verb in ("branch", "tag"):
        if params.get("delete"):
            if not positional:
                raise ValueError(f"could not find a {verb} name in: {argv!r}")
            # git deletes every one it is given; a name git resolves (-, @{-1}) is marked
            return _mark_open_targets([one(_git_name(verb, name), "delete")
                                       for name in dict.fromkeys(positional)])
        if params.get("rename") or params.get("copy"):
            return _git_branch_move(positional, one, params, argv)
        return _git_branch_or_tag(verb, positional, params, one)

    if verb == "rebase":
        # "git rebase <upstream> <branch>" rewrites <branch>: both are targets. With no
        # <branch> it rewrites the current branch, which only git knows (history/*,
        # marked), as is a name git resolves (HEAD, @{-1}, -)
        targets = positional[:2] or ["HEAD"]
        intents = [one(f"history/{target}", "rewrite") for target in targets]
        if len(positional) < 2 or any(_git_resolved_name(t) for t in targets):
            intents.append(one("history/*", "rewrite"))
        return _mark_open_targets(intents)

    if verb == "reset" and params.get("hard"):
        # reset --hard moves the current branch to <commit>: the branch is only known to
        # git (history/*, marked)
        target = positional[0] if positional else "HEAD"
        return _mark_open_targets([one(f"history/{target}", "rewrite"),
                                   one("history/*", "rewrite")])

    if verb == "commit" and params.get("amend"):
        return _mark_open_targets([one("history/HEAD", "rewrite"), one("history/*", "rewrite")])

    if verb == "filter-branch":
        # rev-list arguments pick the refs it rewrites, behind options the parser does not
        # read: which refs, only git knows
        return _mark_open_targets([one("history/*", "rewrite")])

    if verb == "filter-repo":
        # git filter-repo rewrites every ref of the repository, whatever it is given
        return _mark_open_targets([one("history/*", "rewrite")])

    if verb in _GIT_READ_VERBS or _git_reads_only(verb, positional, tokens):
        return [one("history/*", "read")]
    # Anything else changes the repository (commit, checkout, merge, pull, fetch, clean,
    # stash, config --set, remote add, update-ref, ...) or is a command the parser does not
    # know: never a read. Its action is the verb, as kubectl's are.
    return [one("history/*", verb)]


# git commands that change nothing, from their documentation: they read the repository
# and print. Every other command is a write (see from_git_multi).
_GIT_READ_VERBS = frozenset({
    "status", "log", "diff", "show", "blame", "annotate", "grep", "ls-files", "ls-tree",
    "ls-remote", "rev-parse", "rev-list", "describe", "shortlog", "cat-file", "show-ref",
    "for-each-ref", "name-rev", "whatchanged", "help", "version", "var", "count-objects",
    "cherry", "diff-tree", "diff-files", "diff-index", "merge-base", "check-ignore",
    "check-attr", "check-ref-format", "verify-commit", "verify-tag", "range-diff",
})

# Commands whose subcommand decides: these subcommands (or none) only read.
_GIT_READ_SUBCOMMANDS = {
    "remote": {None, "show", "get-url"},
    "stash": {"list", "show"},
    "worktree": {"list"},
    "notes": {"list", "show"},
    "reflog": {None, "show", "exists"},
    "submodule": {"status", "summary"},
}

_GIT_CONFIG_READ_OPTIONS = frozenset({
    "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l",
    "--get-color", "--get-colorbool",
})


def _git_reads_only(verb: str, positional: list[str], tokens: list[str]) -> bool:
    """Whether a git command with subcommands only reads (``git remote -v``, ``git stash
    list``, ``git config --get x``, ``git config --list``)."""
    if verb in _GIT_READ_SUBCOMMANDS:
        sub = next((t for t in tokens if not t.startswith("-")), None)
        return sub in _GIT_READ_SUBCOMMANDS[verb]
    if verb == "config":
        if any(t in _GIT_CONFIG_READ_OPTIONS for t in tokens):
            return True
        names = [t for t in tokens if not t.startswith("-")]
        # "git config name" reads the value; "git config name value" sets it
        return len(names) == 1 and not any(t.startswith("--") and t not in (
            "--global", "--system", "--local") for t in tokens)
    return False


# The filters that put git branch and git tag in list mode whatever else is given
# (git-branch(1), git-tag(1), and running git 2.52): --contains/--with, --no-contains/--without,
# --merged, --no-merged and --points-at, each a value, never a boolean's negation.
_GIT_LIST_FILTERS = ("contains", "with", "no_contains", "without", "merged", "no_merged",
                     "points_at")


def _git_lists(verb: str, positional: list[str], params: dict[str, Any]) -> bool:
    """Whether git branch / git tag list, as git decides it: ``--list`` (branch: its last
    value, ``--no-list`` is off) or ``-l`` (tag), no name and no other action, one of the
    list filters, and on tag ``-n`` with any count. ``--column``, ``--sort``,
    ``--format``, ``-v`` and the others only shape a list, and do not make one."""
    if params.get("list") is True:
        return True
    if any(params.get(k) not in (None, False) for k in _GIT_LIST_FILTERS):
        return True
    if verb == "tag" and "n" in params and params["n"] is not False:
        return True
    return not positional


def _git_branch_or_tag(verb: str, positional: list[str], params: dict[str, Any],
                       one) -> list[InfrastructureIntent]:
    """``git branch`` / ``git tag`` with no delete, rename or copy: a list when git lists
    (:func:`_git_lists`), ``git tag -v`` verifies, ``git branch --show-current`` prints,
    and otherwise the name is created, at the commit given or HEAD; ``-f`` replaces one that
    exists (an update, forced). ``git branch -u`` / ``--unset-upstream`` /
    ``--edit-description`` change the branch's configuration (an update)."""
    keys = {canonical_key(k) for k, v in params.items() if v not in (None, False)}
    if verb == "branch" and keys & {"set-upstream-to", "unset-upstream", "edit-description",
                                    "set-upstream"}:
        return _mark_open_targets([one(_git_name("branch", positional[0]) if positional
                                       else "branch/*", "update")])
    if verb == "tag" and "verify" in keys:
        return [one(f"tag/{name}", "read") for name in positional or ["*"]]
    if verb == "branch" and "show-current" in keys:
        return [one("branch/*", "read")]
    if _git_lists(verb, positional, params):
        return [one(f"{verb}/{name}", "read") for name in positional or ["*"]]
    if verb == "branch" and keys & {"all", "remotes"}:
        raise ValueError("git branch: -a and -r do not take a branch name (git refuses it)")
    target = _git_name(verb, positional[0])
    intents = [one(target, "create")]
    if params.get("force") is True:
        replaced = one(target, "update")
        replaced.params["force"] = True
        intents.append(replaced)
        if verb == "branch":
            # git branch -f <name> [<start>] resets an existing branch to <start>
            intents.append(one(target, "delete"))
    return _mark_open_targets(intents)


def _git_branch_move(positional, one, params, argv) -> list[InfrastructureIntent]:
    """``git branch -m|-c [<old>] <new>``: the new branch is created (``create``), and with
    -M, -C or --force an existing branch of that name is overwritten, so it is also a
    ``delete``. A rename also removes the old name (``delete``). With one name the old
    branch is the current one, which the argv does not show: ``branch/*``, marked, so a
    rule on one branch escalates."""
    if not positional or len(positional) > 2:
        raise ValueError(f"could not find the branch names in: {argv!r}")
    new = _git_name("branch", positional[-1])
    intents = [one(new, "create")]
    if params.get("force"):
        intents.append(one(new, "delete"))
    if params.get("rename"):
        if len(positional) == 2:
            intents.append(one(_git_name("branch", positional[0]), "delete"))
        else:
            intents.append(one("branch/*", "delete"))
    return _mark_open_targets(intents)


def from_git(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``git`` invocation that has exactly one target (see
    :func:`from_git_multi`). Raises ValueError for ``git push origin a b``."""
    # The tags and deletes a push may send that the argv does not name (marked) are left
    # out here: from_git is the one named target.
    intents = [i for i in from_git_multi(argv) if "resolved_at_runtime" not in i.params
               or i.params["resolved_at_runtime"].get("destination")]
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
_GH_SUBVERB_GROUPS = {"workflow", "release", "pr", "repo", "secret", "variable", "issue",
                      "run"}


def _gh_fold_globals(group: str, tokens: list[str], leading: list[str]) -> list[str]:
    """Re-inserts leading global option tokens after the group's subcommand
    (or at the front, for groups without one) so they reach
    ``_parse_gh_tokens`` alongside the trailing flags."""
    if group in _GH_SUBVERB_GROUPS and tokens:
        return [tokens[0], *leading, *tokens[1:]]
    return [*leading, *tokens]


# The flags of every gh command are read from gh's own registrations (gh_flags.json, see
# _gh_command_spec): each command's booleans, value flags and short letters, and -R/--repo
# only where gh registers it (not on api, repo clone or gist).


_GH_REPO_SPEC_RE = re.compile(
    r"^(?:(?:https?|ssh|git)://(?:[^@/]+@)?|[^@/]+@)?"
    r"(?:(?P<host>[^/:]+)[/:])?(?P<owner>[^/:]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def _gh_repo(spec: str) -> tuple[str, str | None]:
    """A repository as gh takes it -- ``OWNER/REPO``, ``HOST/OWNER/REPO``, a URL or an
    ``git@HOST:OWNER/REPO.git`` -- as ``(repo, host)``: ``owner/repo`` lower-cased (GitHub
    compares them without case), and the host when it is not github.com. On another host
    the repo is ``host/owner/repo``, so a rule written for a github.com repository never
    takes a GitHub Enterprise one of the same name for it."""
    m = _GH_REPO_SPEC_RE.match(_gh_clean_url(spec.strip()))
    if not m:
        raise ValueError(f"gh: {spec!r} is not a repository gh accepts")
    host = (m.group("host") or "github.com").lower()
    repo = f"{m.group('owner')}/{m.group('repo')}".lower()
    if host in ("github.com", "www.github.com"):
        return repo, None
    return f"{host}/{repo}", host


def _gh_clean_url(spec: str) -> str:
    """An http(s) URL as gh's url.Parse reads it: the fragment and query dropped and the
    path decoded (``pr%6Fd`` is ``prod``); an empty, dot or escaped-slash segment refused
    (:func:`_url_path_segments`). Anything else is returned as it is."""
    from urllib.parse import urlsplit

    if not spec.lower().startswith(("http://", "https://")):
        return spec
    parts = urlsplit(spec)
    segments = _url_path_segments(parts.path, "gh")
    return f"{parts.scheme}://{parts.netloc}/" + "/".join(segments)


def _gh_set_repo(metadata: dict[str, Any], spec: str) -> None:
    repo, host = _gh_repo(spec)
    metadata["repo"] = repo
    if host:
        metadata["github_host"] = host


_GH_NUMBER_URL_RE = re.compile(
    r"^https?://(?P<host>[^/]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<kind>pull|issues)/"
    r"(?P<number>\d+)(?:[/?#].*)?$")
_GH_FULL_REF_RE = re.compile(r"^(?P<owner>[^/]+)/(?P<repo>[^/#]+)#(?P<number>\d+)$")


def _gh_number(selector: str | None, metadata: dict[str, Any]) -> str | None:
    """The number a pull request or issue selector names, as gh's finder reads it: ``42``,
    ``#42``, ``OWNER/REPO#42`` or a ``.../pull/42`` / ``.../issues/42`` URL, whose
    repository then is the one gh acts on. None for a branch name or no selector: gh finds
    the pull request of that branch, or of the current one, when it runs."""
    if selector is None:
        return None
    if re.fullmatch(r"#?[+-]?[0-9]+", selector):
        return str(int(selector.lstrip("#")))
    m = _GH_NUMBER_URL_RE.match(_gh_clean_url(selector)) or _GH_FULL_REF_RE.match(selector)
    if m:
        host = m.groupdict().get("host") or "github.com"
        _gh_set_repo(metadata, f"{host}/{m.group('owner')}/{m.group('repo')}")
        return str(int(m.group("number")))
    return None


def _gh_selected(kind: str, selector: str | None, metadata: dict[str, Any],
                 params: dict[str, Any]) -> str:
    """``kind/<number>``, or ``kind/*`` marked when gh picks the object when it runs."""
    number = _gh_number(selector, metadata)
    if number is not None:
        return f"{kind}/{number}"
    if selector is not None:
        params["branch"] = selector
    params["resolved_at_runtime"] = {"from": f"{kind}/*", "kinds": [kind]}
    return f"{kind}/*"


def _gh_set_name(kind: str, subverb: str, positional: list[str],
                 params: dict[str, Any]) -> str:
    """The name ``gh secret|variable <subverb>`` acts on, upper-cased as GitHub does.
    ``set --env-file`` (``-f``) sets every name in a dotenv file or stdin and ignores the
    one on the line: ``*``, marked. With neither ``--body`` nor ``--env-file``, ``set``
    reads the value from stdin or a prompt: ``body`` is unresolved."""
    if subverb == "set" and params.get("env_file") is not None:
        params["resolved_at_runtime"] = {"from": f"{kind}/*", "kinds": [kind]}
        return "*"
    if subverb == "set" and params.get("body") is None:
        _mark_unresolved(params, "body")
    if not positional:
        if subverb in ("set", "delete", "get"):
            params["resolved_at_runtime"] = {"from": f"{kind}/*", "kinds": [kind]}
        return "*"
    return positional[0].upper()


def _gh_workflow(selector: str, params: dict[str, Any]) -> str:
    """A workflow by file name is ``workflow/<file>``. gh also takes its display name or
    its ID, which name the same workflow another way: then which file it is is only
    known when gh runs, and the intent is marked."""
    base = selector.rsplit("/", 1)[-1]
    if base.endswith((".yml", ".yaml")):
        return f"workflow/{base}"
    params["resolved_at_runtime"] = {"from": f"workflow/{selector}", "kinds": ["workflow"]}
    return f"workflow/{selector}"


def _parse_gh_tokens(
    tokens: list[str], command: tuple[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    metadata, params, positional = _parse_gh_tokens_inner(tokens, command)
    if command in _GH_ARGS:
        low, high = _GH_ARGS[command]
        if len(positional) < low or (high is not None and len(positional) > high):
            count = str(low) if high == low else f"{low} to {'any' if high is None else high}"
            raise ValueError(f"gh {' '.join(command)}: takes {count} argument(s), got "
                             f"{positional!r}, and gh refuses it")
    return metadata, params, positional


# How many arguments each gh command takes (cobra Args in cli v2.103 pkg/cmd): (least,
# most), None for no limit. gh refuses any other count, and so does the parser.
_GH_ARGS: dict[tuple[str, str], tuple[int, int | None]] = {
    **{("issue", v): (1, 1) for v in ("close", "comment", "delete", "develop", "lock",
                                      "unlock", "pin", "unpin", "reopen", "view")},
    ("issue", "edit"): (1, None), ("issue", "transfer"): (2, 2),
    ("issue", "create"): (0, 0), ("issue", "list"): (0, 0), ("issue", "status"): (0, 0),
    **{("pr", v): (0, 1) for v in ("checkout", "checks", "comment", "diff", "edit", "merge",
                                   "ready", "review", "update-branch", "view")},
    ("pr", "close"): (1, 1), ("pr", "reopen"): (1, 1), ("pr", "revert"): (1, 1),
    ("pr", "create"): (0, 0), ("pr", "list"): (0, 0), ("pr", "status"): (0, 0),
    ("release", "delete"): (1, 1), ("release", "edit"): (1, 1),
    ("release", "delete-asset"): (2, 2), ("release", "upload"): (2, None),
    ("release", "list"): (0, 0), ("release", "verify-asset"): (0, 2),
    **{("release", v): (0, 1) for v in ("download", "verify", "view")},
    **{("repo", v): (0, 1) for v in ("archive", "create", "delete", "edit", "list",
                                     "rename", "sync", "unarchive", "view")},
    **{("run", v): (0, 1) for v in ("cancel", "delete", "download", "rerun", "view")},
    ("run", "list"): (0, 0),
    ("secret", "delete"): (1, 1), ("secret", "set"): (0, 1), ("secret", "list"): (0, 0),
    ("variable", "delete"): (1, 1), ("variable", "get"): (1, 1),
    ("variable", "set"): (0, 1), ("variable", "list"): (0, 0),
    ("workflow", "disable"): (0, 1), ("workflow", "enable"): (0, 1),
    ("workflow", "view"): (0, 1), ("workflow", "list"): (0, 0),
}


def _parse_gh_tokens_inner(
    tokens: list[str], command: tuple[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    spec = _gh_command_spec(command) if command else None
    if spec is not None:
        return _parse_gh_command_tokens(tokens, spec, typed_fields=command == ("api", ""),
                                        gh_command=" ".join(command).strip())
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    fields: list[tuple[bool, str]] = []
    gh_command = " ".join(command).strip() if command else None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.startswith("-") and tok != "-":
            key, val = _split_flag(tok)
            if not tok.startswith("--") and key not in ("R", "r", "f", "F", "X"):
                # a command with no flag table: no other letter's meaning is known here
                raise ValueError(f"gh: -{key} is not a short flag the parser knows on this "
                                 f"command; write its long flag: {tokens!r}")
            if key in ("R", "repo"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                _gh_set_repo(metadata, val)
            elif key in ("r", "ref"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                metadata["ref"] = val
            elif key in ("f", "F", "field", "raw-field"):
                if val is None:
                    i += 1
                    val = _value_at(tokens, i, tok)
                fields.append((key in ("F", "field"), val))
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
                _pflag_store(params, "gh", key, key.replace("-", "_"), val, gh_command)
            elif i + 1 < n and not tokens[i + 1].startswith("-"):
                i += 1
                _pflag_store(params, "gh", key, key.replace("-", "_"), tokens[i], gh_command)
            else:
                params[key.replace("-", "_")] = True
        else:
            positional.append(tok)
        i += 1

    _gh_build_fields(params, fields, api=False)
    return metadata, params, positional


_GH_INT_RE = re.compile(r"[+-]?[0-9]+")


def _gh_field_value(text: str, *, typed: bool) -> Any:
    """The value gh sends for a field: ``-f``/``--raw-field`` always a string; ``gh api
    -F``/``--field`` is typed as gh's magicFieldValue types it: true, false and null, an
    integer strconv.Atoi reads (decimal, a sign, within int64), and anything else a
    string (``@file`` is read from a file, marked by the caller). ``gh workflow run -F`` is
    a string too."""
    if not typed:
        return text
    if text in ("true", "false"):
        return text == "true"
    if text == "null":
        return None
    if _GH_INT_RE.fullmatch(text) and -(2**63) <= int(text) < 2**63:
        return int(text)
    return text


def _gh_build_fields(params: dict[str, Any], fields: list[tuple[bool, str]], *,
                     api: bool) -> None:
    """``params["inputs"]`` from the ``-f``/``-F`` fields, in gh's order: every raw field
    (``-f``) first, then every magic one (``-F``), whatever their order on the line
    (cli v2.103 api/fields.go and workflow/run/run.go parseFields). ``gh workflow run``
    keeps the last value of a key, all strings. ``gh api`` builds nested keys
    (``a[b]=1``) and arrays (``a[]=1``), types ``-F`` values (:func:`_gh_field_value`),
    and refuses a key set twice, a field with no ``=`` (bar ``a[]``) and a key it cannot
    read. A ``-F`` value ``@file`` is read from a file or stdin: that key is unresolved."""
    if not fields:
        return
    inputs: dict[str, Any] = {}
    ordered = [f for f in fields if not f[0]] + [f for f in fields if f[0]]
    for magic, text in ordered:
        key, sep, value = text.partition("=")
        from_file = magic and sep and value.startswith("@")
        if not api:
            if not sep:
                raise ValueError(f"gh: field {text!r} requires a value separated by '='")
            inputs[key] = value
            if from_file:
                _mark_unresolved(params, f"inputs.{key}")
            continue
        keys = _gh_api_field_keys(key)
        if not sep and keys[-1] != "":
            raise ValueError(f"gh api: field {text!r} requires a value separated by '='")
        typed: Any = None if not sep else _gh_field_value(value, typed=magic)
        if magic and sep and _GH_API_PLACEHOLDER_RE.search(value):
            # gh fills {owner}, {repo} and {branch} in -F values from the current
            # repository when it runs (fields.go magicFieldValue -> fillPlaceholders)
            from_file = True
        dest, is_array, subkey = inputs, False, ""
        for k in keys:
            if k == "":
                is_array = True
                continue
            if subkey:
                if is_array:
                    items = dest.setdefault(subkey, [])
                    if not isinstance(items, list):
                        raise ValueError(f"gh api: expected an array under {subkey!r}")
                    if not items or not isinstance(items[-1], dict) or k in items[-1]:
                        items.append({})
                    dest, is_array = items[-1], False
                else:
                    inner = dest.setdefault(subkey, {})
                    if not isinstance(inner, dict):
                        raise ValueError(f"gh api: expected a map under {subkey!r}")
                    dest = inner
            subkey = k
        if is_array:
            items = dest.setdefault(subkey, [])
            if not isinstance(items, list):
                raise ValueError(f"gh api: expected an array under {subkey!r}")
            if sep:
                items.append(typed)
        else:
            if subkey in dest:
                raise ValueError(f"gh api: unexpected override of the field {subkey!r}, "
                                 "which gh refuses")
            dest[subkey] = typed
        if from_file:
            _mark_unresolved(params, "inputs." + ".".join(k for k in keys if k))
    params["inputs"] = inputs


def _gh_api_field_keys(key: str) -> list[str]:
    """``a[b][]`` as gh api reads a field's key: ``["a", "b", ""]``."""
    match = re.fullmatch(r"([^\[\]]+)((?:\[[^\[\]]*\])*)", key)
    if not match:
        raise ValueError(f"gh api: invalid field key {key!r}")
    return [match.group(1), *re.findall(r"\[([^\[\]]*)\]", match.group(2))]


_GH_FLAGS_FILE = Path(__file__).parent / "data" / "gh_flags.json"


@lru_cache(maxsize=1)
def _gh_flag_table() -> dict[str, Any]:
    with open(_GH_FLAGS_FILE) as f:
        return json.load(f)


@lru_cache(maxsize=512)
def _gh_command_spec(
    command: tuple[str, ...],
) -> tuple[frozenset[str], frozenset[str], dict[str, str]] | None:
    """``(booleans, value flags, {letter: flag})`` of a gh command, from its flag
    registrations in cli/cli (``gh_flags.json``, scripts/gen_gh_flags.py): its own flags
    and the persistent ones of the commands above it (``-R`` from EnableRepoOverride).
    None for a command gh does not register (an extension, an alias)."""
    entry = _gh_flag_table().get(" ".join(command).strip())
    if not isinstance(entry, dict):
        return None
    bools = frozenset(name for name, (kind, _short) in entry.items() if kind == "bool")
    values = frozenset(name for name, (kind, _short) in entry.items() if kind != "bool")
    shorts = {short: name for name, (_kind, short) in entry.items() if short}
    return bools, values, shorts


# Flags a gh command allows at most one of, by their final values
# (cmdutil.MutuallyExclusive in pr merge and repo create).
_GH_EXCLUSIVE = {
    "pr merge": (("auto", "disable_auto", "admin"),),
    "repo create": (("public", "private", "internal"),),
}


def _gh_derived_flags(command: str | None, params: dict[str, Any],
                      method_flags: dict[str, Any], tokens: list[str]) -> None:
    """What gh derives from several flags, from each flag's final value: pr merge's method
    from --merge, --rebase and --squash (merge.go: more than one true is refused, so
    ``--merge --squash --squash=false`` merges), and the flags gh allows at most one of."""
    if command == "pr merge":
        chosen = [name for name in ("merge", "rebase", "squash") if method_flags.get(name) is True]
        if len(chosen) > 1:
            raise ValueError(f"gh pr merge: only one of --merge, --rebase or --squash can be "
                             f"enabled, and gh refuses {tokens!r}")
        if chosen:
            params["method"] = chosen[0]
    for group in _GH_EXCLUSIVE.get(command or "", ()):
        if sum(params.get(name) is True for name in group) > 1:
            raise ValueError(f"gh {command}: only one of {', '.join(group)} can be given, "
                             f"and gh refuses {tokens!r}")


def _parse_gh_command_tokens(
    tokens: list[str], spec: tuple[frozenset[str], frozenset[str], dict[str, str]],
    *, typed_fields: bool = False, gh_command: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """A gh command read as pflag reads it, with the flags gh registers for it
    (:func:`_gh_command_spec`): short words letter by letter, a value flag takes the next
    word, ``--`` ends the flags, and a flag gh does not register is refused (gh refuses
    it). gh api has no -R/--repo (api.go never calls EnableRepoOverride)."""
    bools, values, shorts = spec
    short_bools = frozenset(letter for letter, name in shorts.items() if name in bools)
    short_values = frozenset(letter for letter, name in shorts.items() if name in values)
    metadata: dict[str, Any] = {}
    params: dict[str, Any] = {}
    positional: list[str] = []
    fields: list[tuple[bool, str]] = []
    method_flags: dict[str, Any] = {}

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
        if is_long and _pflag_aliases("gh").get(key) in bools | values:
            key = _pflag_aliases("gh")[key]  # --confirm is --yes where gh registers both
        if gh_command == "api" and key in ("R", "repo"):
            raise ValueError(f"gh api has no {tok.partition('=')[0]} flag; the path or URL "
                             f"names the repository: {tokens!r}")
        name = key if is_long else shorts.get(key)
        if name is None and not is_long:
            raise ValueError(f"gh: -{key} is not a short flag the parser knows on this "
                             f"command; write its long flag: {tokens!r}")
        if name is None or (name not in bools and name not in values):
            i, value = _other_flag(tokens, i, values=(), bools=(), tool="gh")
            _pflag_store(params, "gh", key, key.replace("-", "_"), value, gh_command)
        elif name in bools:
            on = _bool_param(val)
            if name in ("squash", "merge", "rebase") and gh_command == "pr merge":
                method_flags[name] = on  # the method comes from their final values
            else:
                params[name.replace("-", "_")] = on
        else:
            if val is None:
                i += 1
                val = _value_at(tokens, i, tok)
            if name == "repo":
                _gh_set_repo(metadata, val)
            elif name == "ref":
                metadata["ref"] = val
            elif name in ("field", "raw-field"):
                fields.append((name == "field", val))
            elif name == "method":
                params["_method"] = val.upper()
            else:
                _pflag_store(params, "gh", name, name.replace("-", "_"), val, gh_command)
        i += 1

    _gh_build_fields(params, fields, api=typed_fields)
    _gh_derived_flags(gh_command, params, method_flags, tokens)
    _mirror_aliases(params, {a: k for a, k in _pflag_aliases("gh").items()
                             if a in bools | values})
    return metadata, params, positional


# ``gh api`` REST paths that are the raw spelling of a porcelain command.
# Each maps (path regex, method) -> (resource template over the regex
# groups, action), so ``gh api -X POST
# repos/o/r/actions/workflows/deploy-prod.yml/dispatches`` is
# ``workflow/deploy-prod.yml`` / ``run`` exactly like ``gh workflow run``.
_GH_API_PLACEHOLDER_RE = re.compile(r":(?:owner|repo|branch)\b|\{(?:owner|repo|branch)\}")
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


def _url_path_segments(path: str, where: str) -> list[str]:
    """A URL path's segments as the server reads them: each percent-decoded (Go's url.Parse
    decodes the path, and the server decodes what is sent), with leading and trailing
    slashes dropped. An empty segment (``//``), ``.``, ``..`` or an escaped ``/`` is
    refused: Go's HTTP client sends the path as written, and whether the server cleans it
    is not known."""
    from urllib.parse import unquote

    segments = path.strip("/").split("/") if path.strip("/") else []
    decoded: list[str] = []
    for segment in segments:
        if "%2f" in segment.lower() or "%5c" in segment.lower():
            raise ValueError(f"{where}: an escaped slash in {path!r} is read differently by "
                             "servers")
        try:
            word = unquote(segment, errors="strict")
        except UnicodeDecodeError:
            raise ValueError(f"{where}: {path!r} is not a path a server decodes") from None
        if word in ("", ".", ".."):
            raise ValueError(f"{where}: {path!r} has an empty or dot segment, which the "
                             "client sends as written")
        decoded.append(word)
    return decoded


def _gh_api_target(raw: str, params: dict[str, Any]) -> tuple[str | None, str]:
    """``gh api``'s endpoint as gh sends it: ``(host, path)``. gh takes an argument with
    ``://`` in it as an absolute URL, used as it is (http.go httpRequest), and any other
    as a path under the host's REST prefix; Go's url.Parse then drops a ``#fragment``,
    and the query is sent as it is (kept in ``params["api_query"]``, it does not change
    the endpoint). The path is decoded as the server decodes it (``pr%6Fd`` is ``prod``);
    a scheme Go's client does not speak, or a path with an empty, dot or escaped-slash
    segment, is refused."""
    from urllib.parse import parse_qsl, urlsplit

    host = None
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise ValueError(f"gh api: {raw!r} is not an http or https URL gh can send")
        host = parts.hostname.lower()  # gh names a host without its port
        host = "github.com" if host == "api.github.com" else host
        path, query = parts.path, parts.query
    else:
        path = raw.split("#", 1)[0]
        path, _, query = path.partition("?")
    if query:
        params["api_query"] = dict(parse_qsl(query, keep_blank_values=True))
    return host, "/".join(_url_path_segments(path, "gh api"))


def from_gh_multi(argv: list[str]) -> list[InfrastructureIntent]:
    """Parses a ``gh`` invocation into one intent per object it acts on (see
    :func:`from_gh`): ``gh issue edit 23 34`` edits both."""
    intent = from_gh_one(argv)
    more, base_repo = intent.params.pop("_more_selectors", ([], None))
    intents = [intent]
    for selector in more:
        # each selector on its own: a URL names its repository, a number is in -R's
        metadata = {k: v for k, v in intent.metadata.items() if k != "repo"}
        if base_repo is not None:
            metadata["repo"] = base_repo
        params = {k: v for k, v in intent.params.items()
                  if k not in ("resolved_at_runtime", "unresolved_scope")}
        if "repo" not in metadata:
            params["unresolved_scope"] = [*intent.params.get("unresolved_scope", [])]
            if "repo" not in params["unresolved_scope"]:
                params["unresolved_scope"].append("repo")
        elif intent.params.get("unresolved_scope"):
            params["unresolved_scope"] = [m for m in intent.params["unresolved_scope"]
                                          if m != "repo"]
        kind = intent.resource.partition("/")[0]
        resource = _gh_selected(kind, selector, metadata, params)
        intents.append(InfrastructureIntent(resource=resource, action=intent.action,
                                            provider="github", params=params,
                                            metadata=metadata))
    if intent.params.get("raw_action") == "pr-merge" and intent.params.get("delete_branch"):
        # --delete-branch deletes the pull request's head branch, remote and local, which
        # the argv does not name: a branch only gh finds when it runs
        branch_params = {k: v for k, v in intent.params.items() if k != "resolved_at_runtime"}
        branch_params["resolved_at_runtime"] = {"from": "branch/*", "kinds": ["branch"]}
        intents.append(InfrastructureIntent(resource="branch/*", action="delete",
                                            provider="github", params=branch_params,
                                            metadata=dict(intent.metadata)))
    return intents


def from_gh(argv: list[str]) -> InfrastructureIntent:
    """A ``gh`` invocation that acts on exactly one object (see :func:`from_gh_multi`)."""
    intents = from_gh_multi(argv)
    if len(intents) != 1:
        raise ValueError(f"expected exactly one gh target, found {len(intents)}: {argv!r}")
    return intents[0]


def from_gh_one(argv: list[str]) -> InfrastructureIntent:
    """Parses a ``gh`` (GitHub CLI) invocation, e.g.:

    ``gh pr merge 42 --admin --squash``
      -> resource "pr/42", action "merge", params {"admin": True, "method": "squash"}

    Without ``-R`` (or a ``repos/<owner>/<repo>`` api path) gh acts on the repository of
    the current directory or ``$GH_REPO``, which the argv does not show: ``repo`` is then
    in ``params["unresolved_scope"]``, so a rule scoped on a repository escalates instead
    of not applying, as an unknown namespace does.
    """
    intent = _from_gh(argv)
    if "repo" not in intent.metadata:
        marks = intent.params.setdefault("unresolved_scope", [])
        if "repo" not in marks:
            marks.append("repo")
    return intent


def _from_gh(argv: list[str]) -> InfrastructureIntent:
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
            marks = params.setdefault("unresolved_scope", [])
            if "ref" not in metadata:
                marks.append("ref")  # the repository's default branch
            if params.get("json") is True:
                marks.append("inputs.*")  # --json reads the inputs from stdin
            return InfrastructureIntent(
                resource=_gh_workflow(positional[0], params), action="run",
                provider="github", params=params, metadata=metadata,
            )
        params["raw_action"] = f"workflow-{subverb}"
        action = _gh_action("workflow", subverb)
        resource = _gh_workflow(positional[0], params) if positional else "workflow/*"
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "release":
        if not tokens:
            raise ValueError(f"gh release requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest, ("release", subverb))
        params["raw_action"] = f"release-{subverb}"
        tag = positional[0] if positional else "*"
        action = _gh_action("release", subverb)
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
        resource = _gh_selected("pr", positional[0] if positional else None, metadata, params)
        action = _gh_action("pr", subverb)
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "issue" and tokens:
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest, ("issue", subverb))
        params["raw_action"] = f"issue-{subverb}"
        if len(positional) > 1 and subverb == "edit":
            # gh issue edit takes several issues and edits each (cobra MinimumNArgs(1))
            params["_more_selectors"] = (positional[1:], metadata.get("repo"))
        resource = _gh_selected("issue", positional[0] if positional else None, metadata,
                                params)
        action = _gh_action("issue", subverb)
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "run" and tokens:
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest, ("run", subverb))
        params["raw_action"] = f"run-{subverb}"
        run_id = positional[0] if positional else None
        if run_id is not None and re.fullmatch(r"[0-9]+", run_id):
            resource = f"run/{int(run_id)}"
        else:  # no ID: gh asks which run, or picks it, when it runs
            resource = "run/*"
            params["resolved_at_runtime"] = {"from": "run/*", "kinds": ["run"]}
        action = _gh_action("run", subverb)
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "repo":
        if not tokens:
            raise ValueError(f"gh repo requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest, ("repo", subverb))
        params["raw_action"] = f"repo-{subverb}"
        action = _gh_action("repo", subverb)
        spec = positional[0] if positional else None
        if spec is not None and ("/" in spec or ":" in spec):
            _gh_set_repo(metadata, spec)
            resource = f"repo/{metadata['repo']}"
        elif spec is not None:
            # REPO alone: the owner is the signed-in user, which the argv does not show
            resource = f"repo/*/{spec.lower()}"
            params["resolved_at_runtime"] = {"from": resource, "kinds": ["repo"]}
        else:  # the current directory's repository
            resource = "repo/*"
            params["resolved_at_runtime"] = {"from": "repo/*", "kinds": ["repo"]}
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "secret":
        if not tokens:
            raise ValueError(f"gh secret requires a subcommand: {argv!r}")
        subverb, *rest = tokens
        metadata, params, positional = _parse_gh_tokens(rest, ("secret", subverb))
        params["raw_action"] = f"secret-{subverb}"
        name = _gh_set_name("secret", subverb, positional, params)
        action = _gh_action("secret", subverb)
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
        name = _gh_set_name("variable", subverb, positional, params)
        action = _gh_action("variable", subverb)
        return InfrastructureIntent(
            resource=f"variable/{name}", action=action, provider="github",
            params=params, metadata=metadata,
        )

    if group == "api":
        metadata, params, positional = _parse_gh_tokens(tokens, ("api", ""))
        # gh api sends POST when it has fields or a body and no -X/--method (cli v2.103
        # api.go: "!RequestMethodPassed && (len(params) > 0 || RequestInputFile != "")")
        method = params.pop("_method", None)
        if method is None:
            method = "POST" if params.get("inputs") or params.get("input") else "GET"
        if params.get("input") is not None:
            # --input: the body is a file (or stdin), so are the fields in it. The -f/-F
            # fields then go into the URL query, not the body (api.go: with a body file,
            # params are added with addQuery), so they set nothing the body sets
            fields = params.pop("inputs", None)
            if fields:
                params["api_query"] = {**params.get("api_query", {}), **fields}
            params.setdefault("unresolved_scope", []).extend(["inputs.*", "ref"])
        action = _GH_METHOD_ACTION.get(method, "read")
        params["raw_action"] = f"api-{method.lower()}"
        raw = positional[0] if positional else ""
        # an absolute URL is sent as it is (api.go): its host is the host, whatever
        # --hostname says; api.github.com is github.com, any other host is a GHES one,
        # whose REST paths start with api/v3
        url_host, path = _gh_api_target(raw, params) if positional else (None, "*")
        if url_host and url_host != "github.com" and path.startswith("api/v3/"):
            path = path[len("api/v3/"):]
        params["api_path"] = path
        # {owner}, {repo} and {branch} (or :owner, ...) are filled from the current
        # repository when gh runs, which the argv does not show
        unknown = bool(_GH_API_PLACEHOLDER_RE.search(path))
        path = _GH_API_PLACEHOLDER_RE.sub("*", path)
        repo_match = _GH_API_REPO_RE.match(path)
        if url_host:
            metadata.pop("repo", None)
            metadata["github_host"] = url_host
        if repo_match and not unknown:
            # the path names the repository the request acts on: -R only fills
            # placeholders, so it does not override the path's
            host = url_host or params.get("hostname") or "github.com"
            metadata.pop("repo", None)
            _gh_set_repo(metadata, f"{host}/{repo_match.group(1)}/{repo_match.group(2)}")
        resource = f"api/{path}"
        for pattern, by_method in _GH_API_ROUTES:
            match = pattern.match(path)
            if not match:
                continue
            route = by_method.get(method)
            if route is None:
                break
            resource_template, action = route
            groups = list(match.groups())
            groups[:2] = [g.lower() for g in groups[:2]]  # owner/repo, without case
            resource = resource_template.format(*groups)
            if resource.startswith("workflow/"):
                # the dispatch body is {"ref": ..., "inputs": {...}}: its inputs are what
                # gh workflow run's -f/-F give, so a rule on inputs.<name> meets both
                body = params.get("inputs") or {}
                from_file = "inputs.ref" in params.get("unresolved_scope", [])
                params["body"] = body
                params["inputs"] = dict(body["inputs"]) if isinstance(body.get("inputs"),
                                                                       dict) else {}
                if "unresolved_scope" in params:
                    params["unresolved_scope"] = [
                        "inputs." + m[len("inputs.inputs."):]
                        if m.startswith("inputs.inputs.") else m
                        for m in params["unresolved_scope"]]
                ref = body.get("ref")
                if ref is not None and "ref" not in metadata and not from_file:
                    metadata["ref"] = ref
                elif "ref" not in metadata and "ref" not in params.get("unresolved_scope", []):
                    params.setdefault("unresolved_scope", []).append("ref")
            break
        if unknown and "*" in resource:
            kind = resource.partition("/")[0]
            params["resolved_at_runtime"] = {"from": resource, "kinds": [kind]}
        return InfrastructureIntent(
            resource=resource, action=action, provider="github",
            params=params, metadata=metadata,
        )

    # every other group: a read only where the table says so
    if group == "extension" and tokens[:1] == ["exec"]:
        # extension exec disables flag parsing: every word goes to the extension
        metadata, params, positional = {}, {}, list(tokens)
    else:
        # the command is the first word gh registers under the group (flags may come
        # before it: cobra reads them with the command's own flag set)
        sub = next((t for t in tokens if not t.startswith("-")
                    and _gh_command_spec((group, t)) is not None), None)
        command = (group, sub) if sub is not None else (
            (group,) if _gh_command_spec((group,)) is not None else None)
        metadata, params, positional = _parse_gh_tokens(tokens, command)
    params["raw_action"] = group
    # gh <group> <command> ...: the resource keeps the command word, as before
    subverb = positional[0] if (group, None) not in _GH_ACTIONS and positional else None
    action = _gh_action(group, subverb)
    target = positional[0] if positional else "*"
    return InfrastructureIntent(
        resource=f"{group}/{target}", action=action, provider="github",
        params=params, metadata=metadata,
    )


# The action of each gh command (cli v2.103 manual, https://cli.github.com/manual/). A
# command is a read only if it is listed as one here: it shows or lists and changes
# nothing on GitHub. Any command not in the table, a new one included, takes its
# subcommand (or group) as its action, never "read".
_GH_ACTIONS: dict[tuple[str, str | None], str] = {
    **{("pr", v): "read" for v in ("view", "list", "status", "diff", "checks")},
    ("pr", "merge"): "merge", ("pr", "close"): "stop", ("pr", "reopen"): "start",
    ("pr", "create"): "create", ("pr", "edit"): "update", ("pr", "ready"): "update",
    ("pr", "review"): "update", ("pr", "comment"): "update", ("pr", "lock"): "update",
    ("pr", "unlock"): "update", ("pr", "update-branch"): "update",
    ("pr", "revert"): "create",
    **{("issue", v): "read" for v in ("view", "list", "status")},
    ("issue", "delete"): "delete", ("issue", "close"): "stop", ("issue", "reopen"): "start",
    ("issue", "create"): "create", ("issue", "edit"): "update",
    ("issue", "comment"): "update", ("issue", "transfer"): "update",
    ("issue", "pin"): "update", ("issue", "unpin"): "update", ("issue", "lock"): "update",
    ("issue", "unlock"): "update", ("issue", "develop"): "create",
    **{("release", v): "read" for v in ("view", "list", "verify", "verify-asset")},
    ("release", "create"): "create", ("release", "delete"): "delete",
    ("release", "edit"): "update", ("release", "upload"): "put",
    ("release", "delete-asset"): "delete",
    **{("repo", v): "read" for v in ("view", "list")},
    ("repo", "delete"): "delete", ("repo", "create"): "create", ("repo", "edit"): "update",
    ("repo", "rename"): "update", ("repo", "archive"): "update",
    ("repo", "unarchive"): "update", ("repo", "fork"): "create", ("repo", "sync"): "update",
    **{("run", v): "read" for v in ("view", "list", "watch")},
    ("run", "delete"): "delete", ("run", "cancel"): "stop", ("run", "rerun"): "run",
    **{("workflow", v): "read" for v in ("view", "list")},
    ("workflow", "run"): "run", ("workflow", "enable"): "start",
    ("workflow", "disable"): "stop",
    ("secret", "list"): "read", ("secret", "set"): "put", ("secret", "delete"): "delete",
    ("variable", "list"): "read", ("variable", "get"): "read", ("variable", "set"): "put",
    ("variable", "delete"): "delete",
    **{("search", v): "read" for v in ("repos", "issues", "prs", "code", "commits")},
    ("status", None): "read", ("browse", None): "read",
    **{("gist", v): "read" for v in ("view", "list")},
    ("label", "list"): "read", ("cache", "list"): "read",
    **{("ruleset", v): "read" for v in ("list", "view", "check")},
    ("org", "list"): "read", ("auth", "status"): "read", ("auth", "token"): "read",
    **{("extension", v): "read" for v in ("list", "search", "browse")},
    **{("project", v): "read" for v in ("list", "view", "field-list", "item-list")},
    ("config", "get"): "read", ("config", "list"): "read", ("alias", "list"): "read",
    ("gpg-key", "list"): "read", ("ssh-key", "list"): "read",
    ("help", None): "read", ("version", None): "read",
}


def _gh_action(group: str, subverb: str | None) -> str:
    """The action of ``gh <group> <subverb>`` (:data:`_GH_ACTIONS`): a command not in the
    table is never a read; its subcommand, or its group, is its action."""
    action = _GH_ACTIONS.get((group, subverb))
    return action if action is not None else (subverb or group)


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
            # one directory, one spelling: ./infra, infra/ and infra are the same
            chdir = os.path.normpath(rest[0].split("=", 1)[1])
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


# Scope keys each tool takes from its configuration or environment when the argv does
# not give them: the kubeconfig's context, cluster and user (kubectl, helm and flux; the
# namespace is the store's, see namespace_unresolved), aws's region, profile and account
# (~/.aws/config, $AWS_REGION, $AWS_PROFILE, the credentials), gcloud's project, region,
# zone and account (the active configuration's core/project, compute/region, compute/zone
# and core/account, $CLOUDSDK_*), az's subscription, resource group and location (az
# account, az config defaults), argocd's server and project and the Application's
# namespace (~/.config/argocd, the app itself), gh's repository and host (the current
# directory, $GH_REPO, $GH_HOST) and the remote git pushes to (branch.*.pushRemote,
# remote.pushDefault).
_CONFIG_SCOPE_KEYS = {
    "kubernetes": ("context", "cluster", "user"),
    "helm": ("context", "cluster", "user"),
    "flux": ("context", "cluster", "user"),
    "aws": ("region", "profile", "account"),
    "gcp": ("project", "region", "zone", "account"),
    "azure": ("subscription", "resource_group", "region"),
    "argocd": ("server", "project", "app_namespace"),
    "github": ("repo", "github_host"),
    "git": ("remote",),
}


# The scope keys a tool takes from its configuration when they are not given, for which an
# empty value on the line is no value at all (see mark_config_scope).
_EMPTY_IS_ABSENT = frozenset({
    "namespace", "context", "cluster", "kubeconfig", "region", "zone", "profile", "project",
    "project_number", "subscription", "subscription_name", "resource_group",
    "location_display_name", "server", "app_namespace", "repo", "remote", "remote_url",
    "account", "endpoint_url",
})


def mark_unknown_names(intents: list[InfrastructureIntent]) -> list[InfrastructureIntent]:
    """Marks every ``kind/*`` target ``resolved_at_runtime``: ``*`` stands for objects the
    tool picks when it runs (a list, ``--all``, stdin, a file), so a rule on one of them
    escalates. Done here, once, for every parser, so no branch can leave one unmarked. A
    target already marked, a manifest nobody read and an unknown git target keep theirs."""
    for intent in intents:
        if not intent.resource.endswith("/*"):
            continue
        params = intent.params
        if ("resolved_at_runtime" in params or params.get("unknown_target") is True
                or params.get("manifest_not_inspected") is True):
            continue
        params["resolved_at_runtime"] = {"from": intent.resource,
                                         "kinds": [intent.resource[:-2]]}
    return intents


def mark_config_scope(intents: list[InfrastructureIntent]) -> list[InfrastructureIntent]:
    """Adds to ``params["unresolved_scope"]`` each key of :data:`_CONFIG_SCOPE_KEYS` the
    argv did not give, so a rule scoped on it escalates instead of not applying. A key
    --resolve-current-context fills later is unmarked when it is filled (environments.py
    fill). Every unknown name is marked too (:func:`mark_unknown_names`)."""
    mark_unknown_names(intents)
    for intent in intents:
        # An empty value is no value: client-go ignores --namespace= and uses the context's,
        # and every other tool falls back to its configuration the same way (or fails). So
        # it is removed here, once, for every parser, and the key is unresolved as if it
        # were not given.
        for store in (intent.metadata, intent.params):
            for key in [k for k, v in store.items()
                        if k in _EMPTY_IS_ABSENT and isinstance(v, str) and not v.strip()]:
                del store[key]
        if intent.provider in ("kubernetes", "helm", "flux") and intent.metadata.get("server"):
            # --server (helm --kube-apiserver) sends the request to that URL, whatever
            # cluster the context or --cluster names: the cluster is not theirs
            intent.metadata.pop("cluster", None)
        if intent.provider == "aws" and intent.metadata.get("endpoint_url"):
            # --endpoint-url sends the request to another endpoint (a partition, a proxy, a
            # look-alike): its account and region are not the configuration's
            for key in ("account", "region"):
                intent.metadata.pop(key, None)
                _mark_unresolved(intent.params, key)
        keys = _CONFIG_SCOPE_KEYS.get(intent.provider, ())
        if intent.provider == "git" and intent.params.get("raw_action") != "push":
            keys = ()  # only a push has a remote
        given = {canonical_key(k) for k in (*intent.metadata, *intent.params)}
        missing = [key for key in keys if canonical_key(key) not in given]
        if missing:
            marks = intent.params.setdefault("unresolved_scope", [])
            marks.extend(key for key in missing if key not in marks)
    return intents


def from_argv(argv: list[str]) -> list[InfrastructureIntent]:
    return mark_config_scope(_from_argv(argv))


def _from_argv(argv: list[str]) -> list[InfrastructureIntent]:
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
        return from_gh_multi(argv)
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
