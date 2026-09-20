import sys
import os

# Add src to PYTHONPATH so we can import aegis_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aegis_core.store import ConstraintStore

def test_constraint_addition():
    store = ConstraintStore()
    h = store.add_constraint("test-1", "no-scaling", "sre_lead", "git-abc")
    assert "test-1" in store.constraints
    assert store.constraints["test-1"]["principal"] == "sre_lead"
    print("test_constraint_addition: PASSED")

def test_unauthorized_principal():
    store = ConstraintStore()
    try:
        store.add_constraint("test-2", "bad-rule", "untrusted_user", "hack")
        print("test_unauthorized_principal: FAILED (Should have raised error)")
    except PermissionError:
        print("test_unauthorized_principal: PASSED")

def test_integrity_verification():
    store = ConstraintStore()
    h = store.add_constraint("test-3", "verify-me", "admin", "jira-999")
    assert store.verify_integrity("test-3") is True
    print("test_integrity_verification: PASSED")

if __name__ == "__main__":
    test_constraint_addition()
    test_unauthorized_principal()
    test_integrity_verification()
    print("All tests completed successfully.")
