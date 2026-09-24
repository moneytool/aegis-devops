"""Aegis-DevOps demo: loads the example constraints and the example
authority map, then runs intents through the interceptor -- kubectl and
terraform ones allowed/blocked/escalated, plus one gated action per
additional supported cloud CLI (aws, az, gcloud) and GitOps tool
(helm, argocd, flux, git, gh), a namespace-deletion cascade, and a
tampered rule shown under both untrusted-match policies. Prints the store's health up front, exactly
as the CLI's ``store_health`` output does.

Run with:
    venv/bin/python examples/demo.py
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from aegis_core.authority import load_authority_map
from aegis_core.environments import load_environment_map
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import (
    from_argocd,
    from_aws,
    from_az,
    from_flux,
    from_gcloud,
    from_gh,
    from_git,
    from_helm,
    from_kubectl,
    from_kubectl_multi,
    from_terraform_plan,
)
from aegis_core.store import ConstraintStore


def print_decision(label: str, intent, decision) -> None:
    print(f"\n--- {label} ---")
    print(f"intent:   {intent.provider} {intent.action} {intent.resource}")
    print(f"verdict:  {decision.verdict}")
    print(f"covered:  {decision.covered}")
    print(f"citations: {decision.citations}")
    print(f"discarded: {decision.discarded}")
    if decision.notes:
        print(f"notes:    {decision.notes}")
    print(f"latency_ms: {decision.latency_ms:.4f}")


def print_store_health(store: ConstraintStore) -> None:
    """The same summary the CLI prints as its final STORE line / emits as
    ``store_health``: a degraded store must never look like a clean ALLOW."""
    health = store.health
    print(
        f"STORE: loaded={health.loaded} quarantined={len(health.quarantined)} "
        f"principals={health.principals} sha256={health.constraints_sha256[:12]}..."
    )
    for entry in health.quarantined:
        print(f"  quarantined: {entry['id']} ({entry['reason']})")


def main() -> None:
    authority_map = load_authority_map("data/authority.example.yaml")
    store = ConstraintStore.load("data/constraints.example.yaml", authority_map=authority_map)
    interceptor = AegisInterceptor(store)
    env_map = load_environment_map("data/environments.example.yaml")

    print_store_health(store)

    # 1. ALLOW -- a read-only action nothing in the store has an opinion about.
    allow_intent = from_kubectl(["kubectl", "get", "service/frontend", "-n", "prod"])
    env_map.annotate(allow_intent)
    allow_decision = interceptor.intercept(allow_intent)
    print_decision("Read-only action, no matching constraint", allow_intent, allow_decision)

    # 2. BLOCK -- scaling a prod deployment during business hours (09:00-17:00 ET, weekdays)
    # is blocked by the "no-scale-prod-peak" constraint.
    block_intent = from_kubectl(
        ["kubectl", "scale", "deployment/api-server", "--replicas=5", "-n", "prod"]
    )
    env_map.annotate(block_intent)
    # 2026-03-16 is a Monday.
    during_peak_hours = datetime(2026, 3, 16, 10, 0, tzinfo=ZoneInfo("America/New_York"))
    block_decision = interceptor.intercept(block_intent, now=during_peak_hours)
    print_decision("Scale a prod deployment during business hours", block_intent, block_decision)

    # 3. ESCALATE -- destroying a prod EC2 instance in us-east-1 is escalated for human
    # review by the "escalate-terraform-prod-destroy" constraint.
    plan = {
        "resource_changes": [
            {"address": "aws_instance.web", "change": {"actions": ["delete"]}},
        ]
    }
    escalate_intent = from_terraform_plan(plan)[0]
    escalate_intent.metadata["region"] = "us-east-1"
    env_map.annotate(escalate_intent)
    escalate_decision = interceptor.intercept(escalate_intent)
    print_decision(
        "Destroy a prod EC2 instance in us-east-1", escalate_intent, escalate_decision
    )

    # 4. BLOCK -- terminating an EC2 instance in us-east-1 via the aws CLI is
    # blocked by the "aws-no-delete-ec2-us-east-1" constraint.
    aws_intent = from_aws(
        ["aws", "ec2", "terminate-instances", "--instance-ids", "i-0abc", "--region", "us-east-1"]
    )
    env_map.annotate(aws_intent)
    aws_decision = interceptor.intercept(aws_intent)
    print_decision("Terminate an EC2 instance in us-east-1 (aws)", aws_intent, aws_decision)

    # 5. ESCALATE -- scaling an AKS cluster via the az CLI is escalated by the
    # "azure-escalate-aks-scale-delete" constraint.
    az_intent = from_az(
        ["az", "aks", "scale", "--resource-group", "rg1", "--name", "aks1", "--node-count", "5"]
    )
    env_map.annotate(az_intent)
    az_decision = interceptor.intercept(az_intent)
    print_decision("Scale an AKS cluster (az)", az_intent, az_decision)

    # 6. BLOCK -- deleting a Cloud SQL instance via the gcloud CLI is blocked
    # by the "gcp-no-delete-sql-instance" constraint.
    gcloud_intent = from_gcloud(["gcloud", "sql", "instances", "delete", "prod-db"])
    env_map.annotate(gcloud_intent)
    gcloud_decision = interceptor.intercept(gcloud_intent)
    print_decision("Delete a Cloud SQL instance (gcloud)", gcloud_intent, gcloud_decision)

    # 7. BLOCK -- deleting a pod is only blocked because the kube context
    # ("prod-us-east") resolves to env=prod via the environment map; no rule
    # mentions namespaces or that context directly. The same command against
    # a context that maps to a non-prod env (e.g. "kind-local") is allowed.
    env_block_intent = from_kubectl(
        ["kubectl", "delete", "pod/worker", "--context", "prod-us-east"]
    )
    env_map.annotate(env_block_intent)
    env_block_decision = interceptor.intercept(env_block_intent)
    print_decision(
        "Delete a pod whose context maps to prod (env identity mapping)",
        env_block_intent,
        env_block_decision,
    )

    # 8. ALLOW (dry-run) -- the same scale-in-prod-during-peak-hours action as #2,
    # but as a rehearsal: --dry-run=server can't change infrastructure, so it's
    # never blocked. The decision still reports what the real run would do.
    dry_run_intent = from_kubectl(
        ["kubectl", "scale", "deployment/api-server", "--replicas=5", "-n", "prod",
         "--dry-run=server"]
    )
    env_map.annotate(dry_run_intent)
    dry_run_decision = interceptor.intercept(dry_run_intent, now=during_peak_hours)
    print_decision(
        "Scale a prod deployment during business hours (--dry-run=server)",
        dry_run_intent,
        dry_run_decision,
    )
    print(f"would_be: {dry_run_decision.would_be}")

    # 9. BLOCK -- uninstalling a Helm release in the prod namespace is
    # blocked by the "helm-block-release-delete-prod" constraint.
    helm_intent = from_helm(["helm", "uninstall", "api", "-n", "prod"])
    env_map.annotate(helm_intent)
    helm_decision = interceptor.intercept(helm_intent)
    print_decision("Uninstall a Helm release in prod", helm_intent, helm_decision)

    # 10. ESCALATE -- syncing a prod ArgoCD app with --prune is escalated by
    # the "argocd-escalate-prod-sync-prune" constraint.
    argocd_intent = from_argocd(["argocd", "app", "sync", "prod-web", "--prune"])
    env_map.annotate(argocd_intent)
    argocd_decision = interceptor.intercept(argocd_intent)
    print_decision("Sync a prod ArgoCD app with --prune", argocd_intent, argocd_decision)

    # 11. ALLOW -- reconciling a Flux Kustomization has no matching constraint.
    flux_intent = from_flux(["flux", "reconcile", "kustomization", "podinfo", "-n", "flux-system"])
    env_map.annotate(flux_intent)
    flux_decision = interceptor.intercept(flux_intent)
    print_decision("Reconcile a Flux Kustomization", flux_intent, flux_decision)

    # 12. BLOCK -- force-pushing to main is blocked by the
    # "git-block-force-push-main" constraint.
    git_intent = from_git(["git", "push", "--force", "origin", "main"])
    env_map.annotate(git_intent)
    git_decision = interceptor.intercept(git_intent)
    print_decision("Force-push to main (git)", git_intent, git_decision)

    # 13. ESCALATE -- manually running a production deploy workflow is
    # escalated by the "github-escalate-deploy-prod-workflow" constraint.
    gh_intent = from_gh(["gh", "workflow", "run", "deploy-prod.yml", "-r", "main"])
    env_map.annotate(gh_intent)
    gh_decision = interceptor.intercept(gh_intent)
    print_decision("Manually run a production deploy workflow (gh)", gh_intent, gh_decision)

    # 14. BLOCK -- deleting the prod namespace cascades to every object in
    # it, so the parser emits a second, synthetic "*/*" delete intent scoped
    # to that namespace; the namespace-scoped "no-delete-in-prod-namespace"
    # constraint fires on it. Note the global flag in front of the verb.
    ns_intents = from_kubectl_multi(["kubectl", "--context", "kind-local", "delete", "ns", "prod"])
    for ns_intent in ns_intents:
        env_map.annotate(ns_intent)
    cascade_intent = ns_intents[1]
    cascade_decision = interceptor.intercept(cascade_intent)
    print_decision(
        "Delete the prod namespace (cascade intent, global flag before the verb)",
        cascade_intent,
        cascade_decision,
    )

    # 15. A rule quarantined at load (its provenance hash no longer matches:
    # someone edited it on disk) gets no vote. Whoever edited it cannot steer
    # this decision in either direction -- but the rule is not forgotten
    # either: it is named in discarded[] and in the store's health, which is
    # what a human or a dashboard acts on.
    tampered_store = ConstraintStore.load(
        "data/constraints.example.yaml", authority_map=authority_map
    )
    node_rule = tampered_store.constraints.pop("no-delete-nodes")
    node_rule.rule_text = node_rule.rule_text + " [edited on disk]"  # breaks the hash
    tampered_store.quarantined.append({"id": node_rule.id, "reason": "tampered"})
    tampered_store.quarantined_constraints.append(node_rule)
    print()
    print_store_health(tampered_store)
    # --context kind-local resolves the environment, so the only thing left to
    # decide this intent is the tampered rule itself.
    node_intent = from_kubectl(
        ["kubectl", "delete", "node/worker-1", "--context", "kind-local"]
    )
    env_map.annotate(node_intent)
    node_decision = AegisInterceptor(tampered_store).intercept(node_intent)
    print_decision(
        "Delete a node when the no-delete-nodes rule was tampered with "
        "(discarded: it gets no vote)",
        node_intent,
        node_decision,
    )

    # 16. The same intent under on_untrusted_match="escalate", for operators who
    # want an edited rule to stop the line. The trade-off: anyone who can write
    # a rule can then stop the line, which is why it is not the default.
    strict_decision = AegisInterceptor(
        tampered_store, on_untrusted_match="escalate"
    ).intercept(node_intent)
    print_decision(
        "The same action with on_untrusted_match='escalate' (opt-in)",
        node_intent,
        strict_decision,
    )


if __name__ == "__main__":
    main()
