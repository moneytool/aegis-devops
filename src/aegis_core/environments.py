"""Environment identity mapping: turns provider-specific identifiers (a kube
context, an AWS account ID, a GCP project, an Azure subscription, a GitHub
repo, an ArgoCD app, a terraform workspace) into a normalised ``env``
(``prod`` | ``staging`` | ``dev`` | ...) so constraints can scope on
``{env: prod}`` instead of repeating raw IDs that vary per cluster/
account/subscription.

Fail-safe by design: an identifier that isn't in the map resolves to
``None`` (unmapped), never to a default like "dev". Silently treating an
unrecognised prod account as non-prod would be exactly the kind of
under-block this project exists to prevent. (And the interceptor turns
"a rule scoped on ``env`` matched but the intent has no ``env``" into an
ESCALATE -- see ``interceptor.py``, REVIEW-4 T1.3.)

Resolution is **provider-agnostic** (REVIEW-4 T1.3): whatever tool
produced the intent, every identifier its parser put in ``metadata`` is
looked up -- ``context``/``cluster``/``kubeconfig`` (kubectl, helm, flux,
argocd ``--kube-context``, ``KUBECONFIG=…``), ``profile``/``account``
(aws, terraform), ``project`` (gcloud, pulumi, terraform), ``subscription``/
``resource_group`` (az), ``repo`` (gh), ``workspace`` (terraform), and the
ArgoCD app name (glob).

Deliberately NOT included: a kubectl-namespace heuristic (e.g. inferring
``env=prod`` from a namespace literally named ``prod``). Namespace is a
user-controlled string an attacker (or a careless agent) can set to
anything -- inferring trust from it is the same class of poisoning vector
this project's constraint-provenance model exists to defend against, just
moved one field over. Only cluster/context/account/project/subscription
identifiers -- values the agent doesn't choose -- are used here.

:func:`resolve_current_context` is the opt-in (``--resolve-current-context``)
that fills a *missing* ``context``/``profile``/``project``/... from the
invoking environment (``$KUBECONFIG`` current-context, ``$AWS_PROFILE``,
``$CLOUDSDK_CORE_PROJECT``, ...). It **trusts the invoking environment**:
whoever controls the process environment controls what Aegis believes the
target is. Never enabled by default.
"""

import fnmatch
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis_core.intent import InfrastructureIntent
from aegis_core.signing import check_signature


@dataclass
class EnvironmentMap:
    kubernetes_contexts: dict[str, str] = field(default_factory=dict)
    kubernetes_clusters: dict[str, str] = field(default_factory=dict)
    kubernetes_kubeconfigs: dict[str, str] = field(default_factory=dict)
    """kubeconfig *path* -> env (``KUBECONFIG=/etc/kube/prod.yaml kubectl …``)."""
    aws_accounts: dict[str, str] = field(default_factory=dict)
    aws_profiles: dict[str, str] = field(default_factory=dict)
    gcp_projects: dict[str, str] = field(default_factory=dict)
    azure_subscriptions: dict[str, str] = field(default_factory=dict)
    azure_resource_groups: dict[str, str] = field(default_factory=dict)
    github_repos: dict[str, str] = field(default_factory=dict)
    """``owner/repo`` -> env (gh ``-R``/``--repo`` or a URL in the argv)."""
    argocd_apps: dict[str, str] = field(default_factory=dict)
    """glob on the ArgoCD app name (``prod-*``) -> env; first glob that matches wins."""
    terraform_workspaces: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    """Load-time notes, e.g. ``"unsigned: <path>"`` (see load_environment_map)."""

    def _tables(self) -> list[tuple[str, dict[str, str]]]:
        """``(metadata key, table)`` in lookup order: most specific first."""
        return [
            ("context", self.kubernetes_contexts),
            ("cluster", self.kubernetes_clusters),
            ("kubeconfig", self.kubernetes_kubeconfigs),
            ("profile", self.aws_profiles),
            ("account", self.aws_accounts),
            ("project", self.gcp_projects),
            ("subscription", self.azure_subscriptions),
            ("resource_group", self.azure_resource_groups),
            ("repo", self.github_repos),
            ("workspace", self.terraform_workspaces),
        ]

    def resolve(self, intent: InfrastructureIntent) -> str | None:
        """Looks up ``intent``'s environment from the identifiers its parser
        put in ``metadata``, regardless of ``intent.provider``. First hit
        wins (most specific identifier first); returns None if nothing in
        the map matches -- an unmapped identifier is never assumed to be
        any particular env."""
        md = intent.metadata
        for key, table in self._tables():
            value = md.get(key)
            if value is None or not table:
                continue
            value = str(value)
            if value in table:
                return table[value]
            if key == "kubeconfig":
                expanded = os.path.expanduser(value)
                for path, env in table.items():
                    if os.path.expanduser(path) == expanded:
                        return env
        app = _argocd_app_name(intent)
        if app is not None:
            for pattern, env in self.argocd_apps.items():
                if fnmatch.fnmatchcase(app, pattern):
                    return env
        return None

    def annotate(self, intent: InfrastructureIntent) -> InfrastructureIntent:
        """Sets ``intent.metadata["env"]`` from :meth:`resolve` if it isn't
        already set (never overwrites an explicit value) and resolution
        finds a match. Mutates and returns the same intent."""
        if "env" not in intent.metadata:
            env = self.resolve(intent)
            if env is not None:
                intent.metadata["env"] = env
        return intent


def _argocd_app_name(intent: InfrastructureIntent) -> str | None:
    if intent.provider != "argocd":
        return None
    app = intent.metadata.get("app")
    if isinstance(app, str) and app:
        return app
    if intent.resource.startswith("app/"):
        return intent.resource[len("app/"):]
    return None


def _str_table(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def load_environment_map(
    path: str | Path, *, key: bytes | None = None, insecure: bool = False
) -> EnvironmentMap:
    """Reads a YAML file shaped like:

    environments:
      kubernetes:
        contexts: {prod-us-east: prod, staging: staging, kind-local: dev}
        clusters: {gke_acme_us-east1_prod: prod}
        kubeconfigs: {/etc/kubernetes/prod.kubeconfig: prod}
      aws:
        accounts: {"123456789012": prod, "210987654321": staging}
        profiles: {prod-admin: prod, staging: staging}
      gcp:
        projects: {acme-prod: prod, acme-staging: staging}
      azure:
        subscriptions: {"11111111-1111-1111-1111-111111111111": prod}
        resource_groups: {rg-prod: prod, rg1: staging}
      github:
        repos: {acme/shop: prod}
      argocd:
        apps: {"prod-*": prod, "staging-*": staging}
      terraform:
        workspaces: {prod: prod, staging: staging}

    With ``key``, the file must carry a valid ``<path>.sig``
    (:class:`aegis_core.signing.SignatureError` otherwise). Without a key
    and without ``insecure``, ``"unsigned: <path>"`` is recorded in the
    returned map's ``warnings``.
    """
    warnings: list[str] = []
    check_signature(path, key, insecure, warnings)
    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}
    if not isinstance(raw, dict) or not isinstance(raw.get("environments", {}), dict):
        raise ValueError(f"{path}: environments file must be a mapping with an 'environments' key")

    envs = raw.get("environments", {}) or {}

    def section(name: str) -> dict[str, Any]:
        value = envs.get(name) or {}
        if not isinstance(value, dict):
            raise ValueError(f"{path}: environments.{name} must be a mapping")
        return value

    kubernetes, aws, gcp, azure = (section(n) for n in ("kubernetes", "aws", "gcp", "azure"))
    github, argocd, terraform = (section(n) for n in ("github", "argocd", "terraform"))

    return EnvironmentMap(
        kubernetes_contexts=_str_table(kubernetes.get("contexts")),
        kubernetes_clusters=_str_table(kubernetes.get("clusters")),
        kubernetes_kubeconfigs=_str_table(kubernetes.get("kubeconfigs")),
        aws_accounts=_str_table(aws.get("accounts")),
        aws_profiles=_str_table(aws.get("profiles")),
        gcp_projects=_str_table(gcp.get("projects")),
        azure_subscriptions=_str_table(azure.get("subscriptions")),
        azure_resource_groups=_str_table(azure.get("resource_groups")),
        github_repos=_str_table(github.get("repos")),
        argocd_apps=_str_table(argocd.get("apps")),
        terraform_workspaces=_str_table(terraform.get("workspaces")),
        warnings=warnings,
    )


# --- --resolve-current-context ------------------------------------------------------


_KUBE_PROVIDERS = frozenset({"kubernetes", "helm", "flux"})


def kubeconfig_current_context(
    environ: Mapping[str, str] | None = None, home: str | Path | None = None
) -> tuple[str | None, str | None, str | None]:
    """``(kubeconfig path, current-context, its cluster)`` from the first
    path in ``$KUBECONFIG`` (or ``~/.kube/config``), parsed with
    ``yaml.safe_load`` -- ``kubectl`` is never executed. Any missing or
    malformed file yields ``(path, None, None)``."""
    environ = os.environ if environ is None else environ
    raw = environ.get("KUBECONFIG", "")
    first = raw.split(os.pathsep)[0].strip() if raw.strip() else ""
    path = Path(first).expanduser() if first else Path(home or Path.home()) / ".kube" / "config"
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return str(path), None, None
    if not isinstance(doc, dict):
        return str(path), None, None
    current = doc.get("current-context")
    if not isinstance(current, str) or not current:
        return str(path), None, None
    cluster = None
    for entry in doc.get("contexts") or []:
        if isinstance(entry, dict) and entry.get("name") == current:
            ctx = entry.get("context") or {}
            if isinstance(ctx, dict) and isinstance(ctx.get("cluster"), str):
                cluster = ctx["cluster"]
            break
    return str(path), current, cluster


def resolve_current_context(
    intent: InfrastructureIntent,
    environ: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> InfrastructureIntent:
    """Fills identifiers the argv did not carry from the invoking
    environment -- opt-in, because it *trusts that environment*:

    * kubernetes/helm/flux: ``context`` (and ``cluster``) from the
      kubeconfig's ``current-context``; ``kubeconfig`` from ``$KUBECONFIG``;
      helm ``namespace`` from ``$HELM_NAMESPACE``;
    * aws: ``profile`` from ``$AWS_PROFILE``, ``region`` from
      ``$AWS_DEFAULT_REGION`` / ``$AWS_REGION``;
    * gcp: ``project`` from ``$CLOUDSDK_CORE_PROJECT``;
    * azure: ``subscription`` from ``$AZURE_SUBSCRIPTION_ID``;
    * argocd: ``server`` from ``$ARGOCD_SERVER``.

    Only keys that are absent from ``metadata`` are filled (an explicit
    ``--context`` always wins), and the keys that were filled are listed
    in ``metadata["resolved_from_environment"]`` so the decision output
    shows exactly what was trusted. Mutates and returns the intent."""
    environ = os.environ if environ is None else environ
    md = intent.metadata
    filled: list[str] = []

    def fill(key: str, value: str | None) -> None:
        if value and key not in md:
            md[key] = value
            filled.append(key)

    provider = intent.provider
    if provider in _KUBE_PROVIDERS:
        if "context" not in md:
            path, current, cluster = kubeconfig_current_context(environ, home)
            fill("context", current)
            fill("cluster", cluster)
            if current and environ.get("KUBECONFIG", "").strip():
                fill("kubeconfig", path)
        if provider == "helm":
            fill("namespace", environ.get("HELM_NAMESPACE"))
    elif provider == "aws":
        fill("profile", environ.get("AWS_PROFILE"))
        fill("region", environ.get("AWS_DEFAULT_REGION") or environ.get("AWS_REGION"))
    elif provider == "gcp":
        fill("project", environ.get("CLOUDSDK_CORE_PROJECT"))
    elif provider == "azure":
        fill("subscription", environ.get("AZURE_SUBSCRIPTION_ID"))
    elif provider == "argocd":
        fill("server", environ.get("ARGOCD_SERVER"))

    if filled:
        md["resolved_from_environment"] = filled
    return intent
