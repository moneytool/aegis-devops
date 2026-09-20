import sys
import os

# Add src to PYTHONPATH so we can import aegis_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aegis_core.intent import InfrastructureIntent

def test_intent_serialization():
    intent = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        params={"replic_count": 5}
    )
    data = intent.to_dict()
    assert data["resource"] == "deployment/api-server"
    assert data["params"]["replic_count"] == 5
    print("test_intent_serialization: PASSED")

if __name__ == "__main__":
    test_intent_serialization()
    print("All tests completed successfully.")
