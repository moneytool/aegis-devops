from aegis_core.intent import InfrastructureIntent


def test_intent_serialization():
    intent = InfrastructureIntent(
        resource="deployment/api-server",
        action="scale",
        provider="kubernetes",
        params={"replicas": 5},
    )
    data = intent.to_dict()
    assert data["resource"] == "deployment/api-server"
    assert data["action"] == "scale"
    assert data["provider"] == "kubernetes"
    assert data["params"]["replicas"] == 5


def test_intent_defaults_are_independent_dicts():
    a = InfrastructureIntent(resource="pod/a", action="delete", provider="kubernetes")
    b = InfrastructureIntent(resource="pod/b", action="delete", provider="kubernetes")
    a.params["x"] = 1
    assert b.params == {}
