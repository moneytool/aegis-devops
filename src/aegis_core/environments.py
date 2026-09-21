"""Environment identity mapping: turns provider-specific identifiers (a kube
context, an AWS account ID, a GCP project, an Azure subscription) into a
normalised ``env`` (``prod`` | ``staging`` | ``dev`` | ...) so constraints can
scope on ``{env: prod}`` instead of repeating raw IDs that vary per cluster/
account/subscription.

Fail-safe by design: an identifier that isn't in the map resolves to
``None`` (unmapped), never to a default like "dev". Silently treating an
unrecognised prod account as non-prod would be exactly the kind of
under-block this project exists to prevent.

Deliberately NOT included: a kubectl-namespace heuristic (e.g. inferring
``env=prod`` from a namespace literally named ``prod``). Namespace is a
user-controlled string an attacker (or a careless agent) can set to
anything -- inferring trust from it is the same class of poisoning vector
this project's constraint-provenance model exists to defend against, just
moved one field over. Only cluster/context/account/project/subscription
identifiers -- values the agent doesn't choose -- are used here.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis_core.intent import InfrastructureIntent


@dataclass
class EnvironmentMap:
    kubernetes_contexts: dict[str, str] = field(default_factory=dict)
    kubernetes_clusters: dict[str, str] = field(default_factory=dict)
    aws_accounts: dict[str, str] = field(default_factory=dict)
    aws_profiles: dict[str, str] = field(default_factory=dict)
    gcp_projects: dict[str, str] = field(default_factory=dict)
    azure_subscriptions: dict[str, str] = field(default_factory=dict)
    azure_resource_groups: dict[str, str] = field(default_factory=dict)

    def resolve(self, intent: InfrastructureIntent) -> str | None:
        """Looks up ``intent``'s environment from the identifiers its parser
        put in ``metadata``. First hit wins (most specific identifier per
        provider first); returns None if nothing in the map matches --
        an unmapped identifier is never assumed to be any particular env."""
        md = intent.metadata

        if intent.provider == "kubernetes":
            for key, table in (
                ("context", self.kubernetes_contexts),
                ("cluster", self.kubernetes_clusters),
            ):
                value = md.get(key)
                if value is not None and value in table:
                    return table[value]
        elif intent.provider == "aws":
            for key, table in (
                ("account", self.aws_accounts),
                ("profile", self.aws_profiles),
            ):
                value = md.get(key)
                if value is not None and value in table:
                    return table[value]
        elif intent.provider == "gcp":
            value = md.get("project")
            if value is not None and value in self.gcp_projects:
                return self.gcp_projects[value]
        elif intent.provider == "azure":
            for key, table in (
                ("subscription", self.azure_subscriptions),
                ("resource_group", self.azure_resource_groups),
            ):
                value = md.get(key)
                if value is not None and value in table:
                    return table[value]

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


def load_environment_map(path: str | Path) -> EnvironmentMap:
    """Reads a YAML file shaped like:

    environments:
      kubernetes:
        contexts: {prod-us-east: prod, staging: staging, kind-local: dev}
        clusters: {gke_acme_us-east1_prod: prod}
      aws:
        accounts: {"123456789012": prod, "210987654321": staging}
        profiles: {prod-admin: prod, staging: staging}
      gcp:
        projects: {acme-prod: prod, acme-staging: staging}
      azure:
        subscriptions: {"11111111-1111-1111-1111-111111111111": prod}
        resource_groups: {rg-prod: prod, rg1: staging}
    """
    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    envs = raw.get("environments", {}) or {}
    kubernetes = envs.get("kubernetes", {}) or {}
    aws = envs.get("aws", {}) or {}
    gcp = envs.get("gcp", {}) or {}
    azure = envs.get("azure", {}) or {}

    return EnvironmentMap(
        kubernetes_contexts=dict(kubernetes.get("contexts") or {}),
        kubernetes_clusters=dict(kubernetes.get("clusters") or {}),
        aws_accounts={str(k): v for k, v in (aws.get("accounts") or {}).items()},
        aws_profiles=dict(aws.get("profiles") or {}),
        gcp_projects=dict(gcp.get("projects") or {}),
        azure_subscriptions={str(k): v for k, v in (azure.get("subscriptions") or {}).items()},
        azure_resource_groups=dict(azure.get("resource_groups") or {}),
    )
