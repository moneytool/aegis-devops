import sys
import os

# Add src to PYTHONPATH so we can import aegis_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aegis_core.store import ConstraintStore
from aegis_core.intent import InfrastructureIntent

class AegisInterceptor:
    """
    The core decision engine. Intercepts InfrastructureIntents and
    evaluates them against the ConstraintStore.
    """
    def __init__(self, store: ConstraintStore):
        self.store = store

    def intercept(self, intent: InfrastructureIntent) -> str:
        """
        Evaluates an intent.
        Returns: ALLOW, BLOCK, or ESCAL_TO_HUMAN
        """
        # Find all rules that match the resource/action pattern
        # We use the resource name and action from the intent
        matches = self.store.get_matching_constraints(
            resource=intent.resource, 
            action=intent.action
        )

        if not matches:
            return "ALLOW"

        # If we found matches, check if any of them should trigger a BLOCK
        # In this prototype, any match results in a BLOCK for safety
        for match in matches:
            # In a real system, we would evaluate the logic (e.s. regex)
            # Here, we just check if the rule text exists in the intent context
            # For simplicity, we assume if the rule text is found, it's a violation
            return "BLOCK"

        return "ALLOW"

if __name__ == "__main__":
    # Setup Store
    store = ConstraintStore()
    store.add_constraint("rule-1", "scale-deployment", "sre_lead", "jira-1")
    
    interceptor = AegisInterceptor(store)

    # Test 1: Allowed action (no matching rule)
    intent_ok = InfrastructureIntent(
        resource="service/frontend",
        action="get",
        provider="kubernetes"
    )
    decision1 = interceptor.intercept(intent_ok)
    print(f"Test 1 (Allowed): {decision1}")
    assert decision1 == "ALLOW"

    # Test 2: Blocked action (matches rule)
    intent_bad = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes"
    )
    decision2 = interceptor.intercept(intent_bad)
    print(f"Test 2 (Blocked): {decision2}")
    assert decision2 == "BLOCK"

    print("AegisInterceptor integration test: PASSED")
