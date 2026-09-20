from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class InfrastructureIntent:
    """
    Represents a structural DevOps action (e.g., K8s or Terraform).
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
    params: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource": self.resource,
            "action": self.action,
            "provider": self.provider,
            "params": self.params,
            "metadata": self.metadata
        }
