import sys
import os

# Add src to PYTHONPATH so we can import aegis_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aegis_core.store import ConstraintStore

def test_get_matching_constraints():
    store = ConstraintStore()
    # Add a rule that applies to 'node' and 'scale'
    store.add_constraint("rule-1", "do-not-scale-node", "sre_lead", "jira-1")
    # Add a rule that applies to 'pod'
    store.add_constraint("rule-2", "do-not-delete-pod", "sre_lead", "jira-2")
    
    # Test match
    matches = store.get_matching_constraints("node", "scale")
    assert len(matches) == 1
    assert matches[0]['rule'] == "do-not-scale-node"
    
    # Test no match
    matches_none = store.get_matching_constraints("service", "scale")
    assert len(matches_none) == 0
    print("test_get_matching_constraints: PASSED")

if __name__ == "__main__":
    test_get_matching_constraints()
    print("All tests completed successfully.")
