from dataclasses import dataclass, field
from typing import Any


def canonical_key(key: str) -> str:
    """The one form two scope keys are compared in: ``-`` and ``_`` are the same
    character in every segment (``dry-run`` / ``dry_run``, ``set.replica_count`` /
    ``set.replica-count``). The store's matching and its unresolved marks, and the
    parser's configuration marks, all go through this function, so they can never
    disagree about whether two spellings name the same key."""
    return key.replace("_", "-")


@dataclass
class InfrastructureIntent:
    """
    Represents a structured DevOps action (e.g., K8s or Terraform).
    Example:
    {
        "resource": "deployment/api-server",
        "action": "scale",
        "params": {"replicas": 5},
        "provider": "kubernetes"
    }
    """
    resource: str
    action: str
    provider: str
    params: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def resource_aliases(self) -> list[str]:
        """The identifiers a matcher should try, in order, against a
        constraint's ``resource_pattern``: the ``resource`` itself and, for
        plan-derived intents, the module-stripped ``metadata["type_name"]``
        (``aws_db_instance.main`` for ``module.app.aws_db_instance.main``,
        ``aws/rds/instance`` for a pulumi URN) so a rule written for the
        normal form catches the resource wherever it lives (REVIEW-4 T1.6)."""
        aliases = [self.resource]
        type_name = self.metadata.get("type_name")
        if isinstance(type_name, str) and type_name and type_name != self.resource:
            aliases.append(type_name)
        # other spellings of the same resource a parser found (an ARN's plain name)
        for alias in self.metadata.get("resource_aliases") or ():
            if isinstance(alias, str) and alias not in aliases:
                aliases.append(alias)
        return aliases

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "action": self.action,
            "provider": self.provider,
            "params": self.params,
            "metadata": self.metadata,
        }
