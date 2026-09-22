import pytest

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


# --- REVIEW-4 T1.1: signed environment files (loader only) ---------------------


def test_signed_environment_map_loads_with_no_warnings(tmp_path):
    from aegis_core.signing import sign_file

    key = b"k" * 32
    path = tmp_path / "environments.yaml"
    path.write_text("environments:\n  kubernetes:\n    contexts: {prod-1: prod}\n")
    sign_file(path, key)
    env_map = load_environment_map(path, key=key)
    assert env_map.kubernetes_contexts == {"prod-1": "prod"}
    assert env_map.warnings == []


def test_tampered_or_unsigned_environment_map_raises_with_key(tmp_path):
    import pytest

    from aegis_core.signing import SignatureError, sign_file

    key = b"k" * 32
    path = tmp_path / "environments.yaml"
    path.write_text("environments:\n  kubernetes:\n    contexts: {prod-1: prod}\n")
    with pytest.raises(SignatureError, match="unsigned"):
        load_environment_map(path, key=key)
    sign_file(path, key)
    path.write_text("environments:\n  kubernetes:\n    contexts: {prod-1: dev}\n")
    with pytest.raises(SignatureError, match="bad signature"):
        load_environment_map(path, key=key)


def test_environment_map_no_key_records_unsigned_warning_unless_insecure(tmp_path):
    path = tmp_path / "environments.yaml"
    path.write_text("environments: {}\n")
    assert load_environment_map(path).warnings == [f"unsigned: {path}"]
    assert load_environment_map(path, insecure=True).warnings == []


def test_example_environment_file_verifies_under_example_key():
    from aegis_core.signing import load_key

    key = load_key("file:data/example-signing.key")
    assert load_environment_map(ENVIRONMENTS, key=key).warnings == []


def test_environment_map_top_level_list_is_value_error(tmp_path):
    import pytest

    path = tmp_path / "environments.yaml"
    path.write_text("- prod\n")
    with pytest.raises(ValueError):
        load_environment_map(path, insecure=True)


# --- REVIEW-4 T1.3: env identity for every provider --------------------------------


def _intent(provider, resource="thing/x", action="delete", **metadata):
    return InfrastructureIntent(resource=resource, action=action, provider=provider,
                                metadata=metadata)


def test_example_file_loads_the_new_sections():
    env_map = _map()
    assert env_map.kubernetes_kubeconfigs["/etc/kubernetes/prod.kubeconfig"] == "prod"
    assert env_map.github_repos["acme/shop"] == "prod"
    assert env_map.argocd_apps["prod-*"] == "prod"
    assert env_map.terraform_workspaces["prod"] == "prod"


@pytest.mark.parametrize(
    "provider, metadata, expected",
    [
        ("helm", {"context": "prod-us-east"}, "prod"),          # helm --kube-context
        ("flux", {"context": "staging"}, "staging"),
        ("argocd", {"context": "kind-local"}, "dev"),
        ("kubernetes", {"kubeconfig": "/etc/kubernetes/prod.kubeconfig"}, "prod"),
        ("kubernetes", {"kubeconfig": "~/.kube/staging.config"}, "staging"),
        ("terraform", {"account": "123456789012"}, "prod"),     # plan metadata
        ("terraform", {"account": 210987654321}, "staging"),     # YAML int vs str
        ("terraform", {"workspace": "prod"}, "prod"),
        ("pulumi", {"project": "acme-staging"}, "staging"),
        ("github", {"repo": "acme/shop"}, "prod"),
        ("aws", {"profile": "prod-admin"}, "prod"),
        ("azure", {"resource_group": "rg1"}, "staging"),
        ("kubernetes", {"context": "nope"}, None),
        ("github", {"repo": "someone/else"}, None),
        ("kubernetes", {"namespace": "prod"}, None),             # never from namespace
    ],
)
def test_resolve_is_provider_agnostic(provider, metadata, expected):
    assert _map().resolve(_intent(provider, **metadata)) == expected


def test_resolve_argocd_app_name_by_glob():
    env_map = _map()
    assert env_map.resolve(_intent("argocd", resource="app/prod-web", action="sync")) == "prod"
    assert env_map.resolve(_intent("argocd", resource="app/staging-web", action="sync")) == (
        "staging"
    )
    assert env_map.resolve(_intent("argocd", resource="app/scratch", action="sync")) is None
    # a kube context on the argv outranks the app-name glob
    assert env_map.resolve(
        _intent("argocd", resource="app/prod-web", action="sync", context="kind-local")
    ) == "dev"


def test_gh_workflow_run_in_mapped_repo_resolves_to_prod():
    from aegis_core.parser import from_gh

    intent = from_gh(["gh", "workflow", "run", "deploy-prod.yml", "-R", "acme/shop"])
    assert _map().annotate(intent).metadata["env"] == "prod"


def test_helm_uninstall_with_kube_context_resolves_and_is_blocked():
    from datetime import UTC, datetime

    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.parser import from_helm

    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    intent = from_helm(["helm", "uninstall", "web", "--kube-context", "prod-us-east"])
    assert _map().annotate(intent).metadata["env"] == "prod"
    decision = AegisInterceptor(store).intercept(intent, now=datetime(2026, 3, 16, tzinfo=UTC))
    assert decision.verdict == "BLOCK"
    assert decision.citations == ["helm-block-release-delete-prod-env"]


def test_env_scoped_rule_with_no_env_escalates_env_unresolved():
    from datetime import UTC, datetime

    from aegis_core.interceptor import AegisInterceptor
    from aegis_core.parser import from_kubectl

    store = ConstraintStore.load(CONSTRAINTS, authority_map=load_authority_map(AUTHORITY))
    intent = _map().annotate(from_kubectl(["kubectl", "delete", "pod/x", "-n", "dev"]))
    assert "env" not in intent.metadata
    decision = AegisInterceptor(store).intercept(intent, now=datetime(2026, 3, 16, tzinfo=UTC))
    assert decision.verdict == "ESCALATE"
    assert decision.citations == []
    assert decision.notes == ["env-unresolved: no-delete-in-prod-env"]
    assert decision.covered is True


# --- --resolve-current-context ------------------------------------------------------


KUBECONFIG_PROD = """\
apiVersion: v1
kind: Config
current-context: prod-us-east
contexts:
- name: prod-us-east
  context: {cluster: gke_acme_us-east1_prod, user: admin}
"""


def _kubeconfig(tmp_path, text=KUBECONFIG_PROD):
    path = tmp_path / "kubeconfig"
    path.write_text(text)
    return path


def test_resolve_current_context_reads_kubeconfig_current_context(tmp_path):
    from aegis_core.environments import resolve_current_context

    path = _kubeconfig(tmp_path)
    intent = _intent("kubernetes")
    resolve_current_context(intent, environ={"KUBECONFIG": f"{path}:/other"})
    assert intent.metadata["context"] == "prod-us-east"
    assert intent.metadata["cluster"] == "gke_acme_us-east1_prod"
    assert intent.metadata["kubeconfig"] == str(path)
    assert intent.metadata["resolved_from_environment"] == ["context", "cluster", "kubeconfig"]
    assert _map().resolve(intent) == "prod"


def test_resolve_current_context_uses_home_kube_config_and_never_overrides_argv(tmp_path):
    from aegis_core.environments import resolve_current_context

    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text(KUBECONFIG_PROD)
    intent = _intent("helm", context="kind-local")
    resolve_current_context(intent, environ={"HELM_NAMESPACE": "team-a"}, home=tmp_path)
    assert intent.metadata["context"] == "kind-local"  # explicit flag wins
    assert intent.metadata["namespace"] == "team-a"
    assert intent.metadata["resolved_from_environment"] == ["namespace"]
    fresh = _intent("kubernetes")
    resolve_current_context(fresh, environ={}, home=tmp_path)
    assert fresh.metadata["context"] == "prod-us-east"
    assert "kubeconfig" not in fresh.metadata  # $KUBECONFIG was not set


def test_resolve_current_context_tolerates_missing_or_malformed_kubeconfig(tmp_path):
    from aegis_core.environments import resolve_current_context

    intent = _intent("kubernetes")
    resolve_current_context(intent, environ={"KUBECONFIG": str(tmp_path / "missing")})
    assert "context" not in intent.metadata and "resolved_from_environment" not in intent.metadata
    bad = _kubeconfig(tmp_path, "- just\n- a list\n")
    resolve_current_context(intent, environ={"KUBECONFIG": str(bad)})
    assert "context" not in intent.metadata


def test_resolve_current_context_cloud_variables():
    from aegis_core.environments import resolve_current_context

    env = {
        "AWS_PROFILE": "prod-admin", "AWS_REGION": "us-east-1",
        "CLOUDSDK_CORE_PROJECT": "acme-prod",
        "AZURE_SUBSCRIPTION_ID": "11111111-1111-1111-1111-111111111111",
        "ARGOCD_SERVER": "argocd.internal",
    }
    aws = resolve_current_context(_intent("aws"), environ=env)
    assert aws.metadata["profile"] == "prod-admin" and aws.metadata["region"] == "us-east-1"
    assert _map().resolve(aws) == "prod"
    assert _map().resolve(resolve_current_context(_intent("gcp"), environ=env)) == "prod"
    assert _map().resolve(resolve_current_context(_intent("azure"), environ=env)) == "prod"
    argocd = resolve_current_context(_intent("argocd", resource="app/x"), environ=env)
    assert argocd.metadata["server"] == "argocd.internal"
    assert resolve_current_context(_intent("aws"), environ={}).metadata == {}
