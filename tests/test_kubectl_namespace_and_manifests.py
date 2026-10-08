"""kubectl commands whose target the argv does not fully show: a namespace
left to the kubeconfig context, and objects that live in a manifest
(``-f <file>``, ``-f -``). Reported by a reader on dev.to, 2026-10-08.

"Unknown" is never "not prod": a rule that would apply except for the
unknown part escalates, as an unresolved ``env`` always has."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis_core.hook import decide
from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_kubectl_multi
from aegis_core.store import Constraint, ConstraintStore

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 8, 12, tzinfo=UTC)
AUTHORITY = {"admin": {"deletion", "configuration", "scaling"}}


def _rule(cid: str, resource: str, actions: list[str], scope: dict | None = None,
          effect: str = "BLOCK") -> Constraint:
    return Constraint.create(id=cid, provider="kubernetes", resource_pattern=resource,
                             actions=set(actions), scope=scope or {}, time_window=None,
                             effect=effect, constraint_class="deletion", principal="admin",
                             source_ref="t", source_timestamp="2026-10-08T00:00:00+00:00",
                             rule_text=cid)


def _decide(rules: list[Constraint], argv: list[str]):
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    for r in rules:
        store.add_constraint(r)
    interceptor = AegisInterceptor(store)
    decisions = [interceptor.intercept(i, now=NOW) for i in from_kubectl_multi(argv)]
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    worst = max(decisions, key=lambda d: order[d.verdict])
    notes = sorted({n for d in decisions for n in d.notes})
    return worst.verdict, notes


# --- the reader's table, against the example policy ---------------------------------


@pytest.mark.parametrize("command,decision,expect", [
    ("kubectl delete deploy web -nprod", "deny", "no-delete-in-prod-namespace"),
    ("kubectl delete deploy web --namespace=prod", "deny", "no-delete-in-prod-namespace"),
    ("sh -c 'kubectl delete deploy web -n prod'", "deny", "no-delete-in-prod-namespace"),
    ("kubectl delete -f ./manifests/ -n prod", "deny", "no-delete-in-prod-namespace"),
    # no namespace: the namespace rule now escalates as well as the env rule
    ("kubectl delete deploy web", "ask", "namespace-unresolved: no-delete-in-prod-namespace"),
    # a manifest's kinds are unknown: kind rules for the same action escalate
    ("kubectl delete -f ./manifests/", "ask", "manifest-not-inspected: no-delete-nodes"),
])
def test_the_readers_cases_with_the_example_policy(command, decision, expect):
    verdict = decide(command, ROOT / "data")
    assert verdict.decision == decision, verdict
    assert expect in verdict.reason or decision == "ask"


# --- gap 1: the namespace -------------------------------------------------------------


PROD_RESTART = _rule("no-restart-prod", "deployment/*", ["rollout-restart"],
                     {"namespace": "prod"})


def test_a_missing_namespace_escalates_a_namespace_scoped_rule():
    verdict, notes = _decide([PROD_RESTART], ["kubectl", "rollout", "restart", "deploy/web"])
    assert verdict == "ESCALATE" and notes == ["namespace-unresolved: no-restart-prod"]


def test_a_given_namespace_decides_normally():
    assert _decide([PROD_RESTART], ["kubectl", "rollout", "restart", "deploy/web",
                                    "-n", "prod"])[0] == "BLOCK"
    assert _decide([PROD_RESTART], ["kubectl", "rollout", "restart", "deploy/web",
                                    "-n", "dev"]) == ("ALLOW", [])


def test_all_namespaces_includes_prod():
    rule = _rule("no-delete-prod-pods", "pod/*", ["delete"], {"namespace": "prod"})
    verdict, notes = _decide([rule], ["kubectl", "delete", "pods", "--all", "-A"])
    assert verdict == "ESCALATE" and notes == ["namespace-unresolved: no-delete-prod-pods"]


def test_a_cluster_scoped_kind_has_no_namespace_to_resolve():
    rule = _rule("no-delete-prod", "*", ["delete"], {"namespace": "prod"})
    assert _decide([rule], ["kubectl", "delete", "node", "worker-1"]) == ("ALLOW", [])


def test_other_scope_keys_must_still_match():
    rule = _rule("prod-ctx-only", "deployment/*", ["rollout-restart"],
                 {"namespace": "prod", "context": "prod-us-east"})
    assert _decide([rule], ["kubectl", "rollout", "restart", "deploy/web",
                            "--context", "dev"]) == ("ALLOW", [])
    verdict, notes = _decide([rule], ["kubectl", "rollout", "restart", "deploy/web",
                                      "--context", "prod-us-east"])
    assert verdict == "ESCALATE" and notes == ["namespace-unresolved: prod-ctx-only"]


def test_an_untrusted_rule_cannot_force_an_escalation():
    rule = _rule("no-restart-prod", "deployment/*", ["rollout-restart"], {"namespace": "prod"})
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.add_constraint(rule)
    rule.effect = "ESCALATE"  # edited after it was loaded: integrity fails at decision time
    [intent] = from_kubectl_multi(["kubectl", "rollout", "restart", "deploy/web"])
    d = AegisInterceptor(store).intercept(intent, now=NOW)
    assert d.verdict == "ALLOW" and d.discarded == [{"id": rule.id, "reason": "tampered"}]


# --- gap 2: manifests -----------------------------------------------------------------


NO_SECRET_DELETE = _rule("no-secret-delete", "secret/*", ["delete", "apply"])


@pytest.mark.parametrize("argv", [
    ["kubectl", "apply", "-f", "-"],
    ["kubectl", "apply", "-f", "-", "-n", "prod"],
    ["kubectl", "delete", "-f", "./manifests/"],
    ["kubectl", "apply", "-k", "overlays/prod"],
])
def test_a_manifest_that_was_not_read_escalates_kind_rules(argv):
    verdict, notes = _decide([NO_SECRET_DELETE], argv)
    assert verdict == "ESCALATE"
    assert "manifest-not-inspected: no-secret-delete" in notes


def test_only_rules_for_the_same_action_are_affected():
    assert _decide([NO_SECRET_DELETE], ["kubectl", "create", "-f", "app.yaml"]) == ("ALLOW", [])


def test_rules_on_manifest_names_and_wildcards_decide_normally():
    by_file = _rule("no-apply-prod-file", "manifest/prod-*.yaml", ["apply"])
    assert _decide([by_file], ["kubectl", "apply", "-f", "dev.yaml"]) == ("ALLOW", [])
    assert _decide([by_file], ["kubectl", "apply", "-f", "prod-db.yaml"])[0] == "BLOCK"
    everything = _rule("no-apply-prod", "*", ["apply"], {"namespace": "prod"})
    assert _decide([everything], ["kubectl", "apply", "-f", "-", "-n", "prod"])[0] == "BLOCK"


def test_a_manifest_rule_with_a_namespace_scope_and_no_namespace_escalates():
    rule = _rule("no-prod-secrets", "secret/*", ["apply"], {"namespace": "prod"})
    verdict, notes = _decide([rule], ["kubectl", "apply", "-f", "-"])
    assert verdict == "ESCALATE" and "manifest-not-inspected: no-prod-secrets" in notes
    assert _decide([rule], ["kubectl", "apply", "-f", "-", "-n", "dev"]) == ("ALLOW", [])
