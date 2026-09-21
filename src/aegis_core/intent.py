from dataclasses import dataclass, field
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "action": self.action,
            "provider": self.provider,
            "params": self.params,
            "metadata": self.metadata,
        }
