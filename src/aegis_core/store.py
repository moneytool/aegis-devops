import hashlib
import json
import datetime
from typing import Dict, Any, Optional

class ConstraintStore:
    """
    A secure, integrity-verified store for operational constraints.
    Ensures every constraint is both tamper-evident (Provenance) 
    and authorized (Authority).
    """
    def __init__(self):
        self.constraints: Dict[str, Dict[str, Any]] = {}
        # Mapping of principal -> set of authorized constraint types
        self.authority_map: Dict[str, set] = {
            "admin": {"scaling", "deletion", "configuration"},
            "sre_lead": {"scaling", "configuration"},
            "developer": {"configuration"}
        }

    def _calculate_provenance_hash(self, content: str, timestamp: str) -> str:
        """Creates a SHA-256 hash of the content and timestamp to detect tampering."""
        payload = f"{content}|{timestamp}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def add_constraint(self, 
                       constraint_id: str, 
                       rule_text: str, 
                       principal: str, 
                       source_ref: str) -> str:
        """
        Adds a new constraint with integrity and authority checks.
        
        Args:
            constraint_id: Unique ID for the rule.
            rule_annotated: The text of the rule.
            principal: The user/service asserting the rule.
            source_ref: The external reference (e.g., Git commit, Jira ID).
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # 1. Integrity: Create the provenance hash
        p_hash = self._calculate_provenance_hash(rule_text, timestamp)
        
        # 2. Authority: Verify the principal can actually define rules
        # In a real system, this would involve checking a real IAM/Certificate
        if principal not in self.authority_map:
            raise PermissionError(f"Principal '{principal}' is not authorized to assert constraints.")

        self.constraints[constraint_id] = {
            "rule": rule_text,
            "principal": principal,
            "source_ref": source_ref,
            "timestamp": timestamp,
            "provenance_hash": p_hash
        }
        return p_hash

    def verify_integrity(self, constraint_id: str) -> bool:
        """Checks if the stored rule matches its provenance hash."""
        if constraint_id not in self.constraints:
            return False
        
        data = self.constraints[constraint_id]
        recomputed = self._calculate_provenance_hash(data['rule'], data['timestamp'])
        return recomputed == data['proven_hash'] if 'prov_hash' in data else recomputed == data['provenance_hash']

    def get_rule(self, constraint_id: str) -> Optional[str]:
        return self.constraints.get(constraint_id, {}).get("rule")

    def get_matching_constraints(self, resource: str, action: str) -> list:
        """Returns all constraints that apply to a specific resource and action."""
        matches = []
        for cid, data in self.constraints.items():
            # A simple string-matching implementation for the prototype
            # In production, this would use regex or AST-based matching
            if resource in data['rule'] and action in data['rule']:
                matches.append(data)
        return matches

    def is_authorized(self, principal: str, rule_type: str) -> bool:
        """Checks if a principal is allowed to enforce a specific class of rules."""
        allowed_types = self.authority_map.get(principal, set())
        return rule_type in allowed_types

if __name__ == "__main__":
    # Quick bootstrap test
    store = ConstraintStore()
    try:
        h = store.add_constraint(
            "rule-001", 
            "no-scaling-in-us-east", 
            "sre_lead", 
            "jira-123"
        )
        print(f"Added constraint with hash: {h}")
        print(f"Constraint exists: {'rule-001' in store.constraints}")
    except Exception as e:
        print(f"Error: {e}")
