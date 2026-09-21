from aegis_core.authority import load_authority_map
from aegis_core.environments import EnvironmentMap, load_environment_map
from aegis_core.intent import InfrastructureIntent
from aegis_core.store import ConstraintStore

ENVIRONMENTS = "data/environments.example.yaml"
CONSTRAINTS = "data/constraints.example.yaml"
AUTHORITY = "data/authority.example.yaml"


def _map() -> EnvironmentMap:
    return load_environment_map(ENVIRONMENTS)


def test_load_round_trips_the_example_file():
    env_map = _map()
    assert env_map.kubernetes_contexts["prod-us-east"] == "prod"
    assert env_map.kubernetes_contexts["kind-local"] == "dev"
    assert env_map.kubernetes_clusters["gke_acme_us-east1_prod"] == "prod"
    assert env_map.aws_accounts["123456789012"] == "prod"
    assert env_map.aws_profiles["staging"] == "staging"
    assert env_map.gcp_projects["acme-prod"] == "prod"
    assert env_map.azure_subscriptions["11111111-1111-1111-1111-111111111111"] == "prod"
    assert env_map.azure_resource_groups["rg1"] == "staging"


def test_resolve_kubernetes_context():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="pod/x", action="delete", provider="kubernetes",
        metadata={"context": "prod-us-east"},
    )
    assert env_map.resolve(intent) == "prod"


def test_resolve_kubernetes_cluster():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="pod/x", action="delete", provider="kubernetes",
        metadata={"cluster": "gke_acme_us-east1_prod"},
    )
    assert env_map.resolve(intent) == "prod"


def test_resolve_aws_account():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="ec2/instance/i-1", action="delete", provider="aws",
        metadata={"account": "123456789012"},
    )
    assert env_map.resolve(intent) == "prod"


def test_resolve_aws_profile():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="ec2/instance/i-1", action="delete", provider="aws",
        metadata={"profile": "staging"},
    )
    assert env_map.resolve(intent) == "staging"


def test_resolve_gcp_project():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="sql/instance/db", action="delete", provider="gcp",
        metadata={"project": "acme-staging"},
    )
    assert env_map.resolve(intent) == "staging"


def test_resolve_azure_subscription():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="aks/cluster/x", action="delete", provider="azure",
        metadata={"subscription": "11111111-1111-1111-1111-111111111111"},
    )
    assert env_map.resolve(intent) == "prod"


def test_resolve_azure_resource_group():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="aks/cluster/x", action="delete", provider="azure",
        metadata={"resource_group": "rg-prod"},
    )
    assert env_map.resolve(intent) == "prod"


def test_resolve_unmapped_identifier_returns_none():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="pod/x", action="delete", provider="kubernetes",
        metadata={"context": "some-unknown-context"},
    )
    assert env_map.resolve(intent) is None


def test_resolve_no_relevant_metadata_returns_none():
    env_map = _map()
    intent = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes")
    assert env_map.resolve(intent) is None


def test_annotate_sets_metadata_env_when_resolvable():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="pod/x", action="delete", provider="kubernetes",
        metadata={"context": "prod-us-east"},
    )
    result = env_map.annotate(intent)
    assert result is intent
    assert intent.metadata["env"] == "prod"


def test_annotate_does_not_overwrite_existing_env():
    env_map = _map()
    intent = InfrastructureIntent(
        resource="pod/x", action="delete", provider="kubernetes",
        metadata={"context": "prod-us-east", "env": "staging"},
    )
    env_map.annotate(intent)
    assert intent.metadata["env"] == "staging"


def test_annotate_leaves_metadata_unset_when_unresolvable():
    env_map = _map()
    intent = InfrastructureIntent(resource="pod/x", action="delete", provider="kubernetes")
    env_map.annotate(intent)
    assert "env" not in intent.metadata


def test_example_constraints_still_load_with_zero_quarantined():
    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    assert store.quarantined == []


def test_kubectl_delete_pod_in_prod_context_is_blocked_by_env_scoped_rule():
    from datetime import UTC, datetime

    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.parser import from_kubectl

    env_map = _map()
    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    interceptor = AegisInterceptor(store)
    now = datetime(2026, 3, 16, 22, 0, tzinfo=UTC)  # outside any time-windowed rule

    intent = from_kubectl(["kubectl", "delete", "pod/x", "--context", "prod-us-east"])
    env_map.annotate(intent)
    decision = interceptor.intercept(intent, now=now)

    assert decision.verdict == "BLOCK"
    assert "no-delete-in-prod-env" in decision.citations


def test_kubectl_delete_pod_in_dev_context_is_not_matched_by_env_scoped_rule():
    from datetime import UTC, datetime

    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.parser import from_kubectl

    env_map = _map()
    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    interceptor = AegisInterceptor(store)
    now = datetime(2026, 3, 16, 22, 0, tzinfo=UTC)

    intent = from_kubectl(["kubectl", "delete", "pod/x", "--context", "kind-local"])
    env_map.annotate(intent)
    decision = interceptor.intercept(intent, now=now)

    assert "no-delete-in-prod-env" not in decision.citations
