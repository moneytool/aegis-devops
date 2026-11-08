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
from aegis_core.parser import from_kubectl, from_kubectl_multi
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


# --- --resolve-current-context: which kubeconfig, and when not to infer (review of #38) ------


def _kc(path: Path, namespace: str, current: str = "ctx") -> str:
    path.write_text(f"apiVersion: v1\nkind: Config\ncurrent-context: {current}\ncontexts:\n"
                    f"- name: ctx\n  context: {{cluster: c, user: u, namespace: {namespace}}}\n")
    return str(path)


def _decide_resolved(rules, argv, environ, home):
    from aegis_core.environments import resolve_current_context

    store = ConstraintStore(authority_map=dict(AUTHORITY))
    for r in rules:
        store.add_constraint(r)
    interceptor = AegisInterceptor(store)
    out = []
    for intent in from_kubectl_multi(argv):
        resolve_current_context(intent, environ=environ, home=home)
        out.append((interceptor.intercept(intent, now=NOW), intent))
    return out


@pytest.fixture
def two_kubeconfigs(tmp_path):
    """The same context name in two files: dev in ~/.kube/config, prod in production.yaml."""
    (tmp_path / ".kube").mkdir()
    _kc(tmp_path / ".kube" / "config", "dev")
    return tmp_path, _kc(tmp_path / "production.yaml", "prod")


@pytest.mark.parametrize("with_context", [True, False])
def test_an_explicit_kubeconfig_is_the_file_the_namespace_comes_from(two_kubeconfigs,
                                                                      with_context):
    home, production = two_kubeconfigs
    argv = ["kubectl", "--kubeconfig", production, *(["--context", "ctx"] if with_context
                                                     else []), "rollout", "restart", "deploy/web"]
    [(decision, intent)] = _decide_resolved([PROD_RESTART], argv, {}, home)
    assert intent.metadata["namespace"] == "prod"
    assert decision.verdict == "BLOCK"


def test_an_unreadable_explicit_kubeconfig_leaves_the_namespace_unresolved(two_kubeconfigs):
    home, _ = two_kubeconfigs
    argv = ["kubectl", "--kubeconfig", str(home / "missing.yaml"), "--context", "ctx",
            "rollout", "restart", "deploy/web"]
    [(decision, intent)] = _decide_resolved([PROD_RESTART], argv, {}, home)
    assert "namespace" not in intent.metadata        # no fallback to ~/.kube/config (dev)
    assert decision.verdict == "ESCALATE"
    assert decision.notes == ["namespace-unresolved: no-restart-prod"]


def test_kubeconfig_files_merge_first_definition_wins(two_kubeconfigs):
    home, production = two_kubeconfigs
    env = {"KUBECONFIG": f"{production}:{home / '.kube' / 'config'}"}
    [(decision, intent)] = _decide_resolved(
        [PROD_RESTART], ["kubectl", "rollout", "restart", "deploy/web"], env, home)
    assert intent.metadata["namespace"] == "prod" and decision.verdict == "BLOCK"


def test_an_unread_manifest_never_takes_the_contexts_namespace(two_kubeconfigs):
    """A dev context is only a default: a stdin manifest can create a prod
    Secret, so a prod-scoped secret rule must not be decided as dev."""
    home, _ = two_kubeconfigs
    rule = _rule("no-prod-secrets", "secret/*", ["apply"], {"namespace": "prod"})
    [(decision, intent)] = _decide_resolved([rule], ["kubectl", "apply", "-f", "-"], {}, home)
    assert "namespace" not in intent.metadata
    assert decision.verdict == "ESCALATE"
    assert "manifest-not-inspected: no-prod-secrets" in decision.notes
    # an explicit -n is enforced by kubectl on every object, so it decides normally
    [(explicit, _)] = _decide_resolved([rule], ["kubectl", "apply", "-f", "-", "-n", "dev"],
                                       {}, home)
    assert explicit.verdict == "ALLOW"


# --- what cannot be resolved does not dismiss a rule on a runtime target (#64) ---------------

MONDAY_NY = {"days": ["Mon"], "start": "09:00", "end": "17:00", "tz": "America/New_York"}
IN_WINDOW = datetime(2026, 1, 5, 15, tzinfo=UTC)  # Monday, 10:00 in New York
OUT_OF_WINDOW = datetime(2026, 1, 6, 15, tzinfo=UTC)  # Tuesday
EXEC_DEPLOY = "kubectl exec deploy/web -- id"


def _windowed(pattern: str, action: str, scope: dict | None = None,
              principal: str = "admin") -> Constraint:
    return Constraint.create(id="r", provider="kubernetes", resource_pattern=pattern,
                             actions={action}, scope=scope or {}, time_window=MONDAY_NY,
                             effect="BLOCK", constraint_class="deletion", principal=principal,
                             source_ref="t", source_timestamp="2026-10-08T00:00:00+00:00",
                             rule_text="r")


def _at(rule: Constraint, command: str, now: datetime, *, tzdata: bool = True,
        **kwargs) -> tuple[str, list[str], list[dict]]:
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.add_constraint(rule)
    store.tzdata_available = tzdata
    gate = AegisInterceptor(store, **kwargs)
    decisions = [gate.intercept(i, now=now) for i in from_kubectl_multi(command.split())]
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    return (max((d.verdict for d in decisions), key=order.get),
            sorted({n for d in decisions for n in d.notes}),
            [x for d in decisions for x in d.discarded])


@pytest.mark.parametrize("pattern,action,command,note", [
    ("pod/payments-0", "exec", EXEC_DEPLOY, "target-unresolved: r"),
    ("pod?payments-0", "exec", EXEC_DEPLOY, "target-unresolved: r"),
    ("pod/payments-0", "attach", "kubectl attach svc/web", "target-unresolved: r"),
    ("pod/payments-0", "port-forward", "kubectl port-forward sts/web 80", "target-unresolved: r"),
    ("deployment/payments", "delete", "kubectl delete all --all", "target-unresolved: r"),
    ("widget/*", "delete", "kubectl delete all --all", "target-unresolved: r"),
    # the kind-level intents, and the name written
    ("pod/*", "exec", EXEC_DEPLOY, "time-window-unresolved: r"),
    ("deployment/web", "exec", EXEC_DEPLOY, "time-window-unresolved: r"),
    ("deployment/*", "delete", "kubectl delete all --all", "time-window-unresolved: r"),
    ("all/*", "delete", "kubectl delete all --all", "time-window-unresolved: r"),
    # as a direct command always did
    ("pod/payments-0", "exec", "kubectl exec payments-0 -- id", "time-window-unresolved: r"),
    # a manifest shares the check
    ("secret/*", "delete", "kubectl delete -f x.yaml", "manifest-not-inspected: r"),
])
def test_no_tzdata_asks_on_a_window_that_cannot_be_evaluated(pattern, action, command, note):
    for now in (IN_WINDOW, OUT_OF_WINDOW):  # the day cannot be told without the zone either
        verdict, notes, _ = _at(_windowed(pattern, action), command, now, tzdata=False)
        assert verdict == "ESCALATE" and note in notes, (pattern, command, notes)


@pytest.mark.parametrize("pattern,action,command", [
    ("secret/x", "delete", "kubectl delete all --all"),
    ("pod/payments-0", "delete", EXEC_DEPLOY),
    ("deployment/x", "exec", EXEC_DEPLOY),
])
def test_no_tzdata_leaves_rules_that_cannot_be_about_the_target(pattern, action, command):
    assert _at(_windowed(pattern, action), command, IN_WINDOW, tzdata=False)[0] == "ALLOW"


def test_a_window_that_can_be_evaluated_still_decides():
    for rule, command in ((_windowed("pod/payments-0", "exec"), EXEC_DEPLOY),
                          (_windowed("deployment/payments", "delete"),
                           "kubectl delete all --all")):
        assert _at(rule, command, IN_WINDOW)[0] == "ESCALATE"
        assert _at(rule, command, OUT_OF_WINDOW)[0] == "ALLOW"
    assert _at(_windowed("pod/*", "exec"), EXEC_DEPLOY, IN_WINDOW)[0] == "BLOCK"
    assert _at(_windowed("pod/*", "exec"), EXEC_DEPLOY, OUT_OF_WINDOW)[0] == "ALLOW"


@pytest.mark.parametrize("pattern", ["pod/payments-0", "pod/*"])
@pytest.mark.parametrize("scope,command,verdict", [
    ({"namespace": "prod"}, EXEC_DEPLOY, "ESCALATE"),
    ({"namespace": "prod"}, "kubectl exec deploy/web -n prod -- id", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl exec deploy/web -A -- id", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl exec deploy/web -n dev -- id", "ALLOW"),
    ({"env": "prod"}, EXEC_DEPLOY, "ESCALATE"),
])
def test_no_tzdata_and_a_scope_are_both_unknowns(pattern, scope, command, verdict):
    rule = _windowed(pattern, "exec", scope)
    assert _at(rule, command, IN_WINDOW, tzdata=False)[0] == verdict


@pytest.mark.parametrize("pattern,action,command", [
    ("pod/payments-0", "exec", EXEC_DEPLOY),
    ("deployment/payments", "delete", "kubectl delete all --all"),
])
def test_an_untrusted_rule_cannot_force_a_question(pattern, action, command):
    """Discarded, as when it matches outright."""
    rule = _windowed(pattern, action, principal="intruder")
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.constraints[rule.id] = rule
    store.tzdata_available = False
    decisions = [AegisInterceptor(store).intercept(i, now=IN_WINDOW)
                 for i in from_kubectl_multi(command.split())]
    assert {d.verdict for d in decisions} == {"ALLOW"}
    assert {"id": "r", "reason": "unauthorized"} in [x for d in decisions for x in d.discarded]


@pytest.mark.parametrize("tzdata", [True, False])
@pytest.mark.parametrize("pattern,action,command", [
    ("pod/payments-0", "exec", EXEC_DEPLOY),
    ("pod?payments-0", "exec", EXEC_DEPLOY),
    ("pod/*", "exec", EXEC_DEPLOY),
    ("deployment/payments", "delete", "kubectl delete all --all"),
    ("deployment/*", "delete", "kubectl delete all --all"),
    ("widget/*", "delete", "kubectl delete all --all"),
])
def test_a_quarantined_rule_on_a_runtime_target_fails_closed(pattern, action, command, tzdata):
    rule = _windowed(pattern, action)
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.tzdata_available = tzdata
    store.quarantined.append({"id": rule.id, "reason": "tampered"})
    store.quarantined_constraints.append(rule)

    def run(**kwargs):
        gate = AegisInterceptor(store, **kwargs)
        return [gate.intercept(i, now=IN_WINDOW) for i in from_kubectl_multi(command.split())]

    escalating = run(on_untrusted_match="escalate")
    assert "ESCALATE" in {d.verdict for d in escalating}
    assert "fail-closed: r (tampered)" in {n for d in escalating for n in d.notes}
    discarding = run()
    assert {d.verdict for d in discarding} == {"ALLOW"}
    assert {"id": "r", "reason": "tampered"} in [x for d in discarding for x in d.discarded]


def test_a_quarantined_rule_outside_its_window_or_elsewhere_stays_out():
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    for rule in (_windowed("pod/payments-0", "exec"), _windowed("secret/x", "delete")):
        store.quarantined.append({"id": rule.id, "reason": "tampered"})
        store.quarantined_constraints.append(rule)
    gate = AegisInterceptor(store, on_untrusted_match="escalate")
    for command, now in ((EXEC_DEPLOY, OUT_OF_WINDOW), ("kubectl delete all --all", IN_WINDOW),
                         ("kubectl exec deploy/web -- id", IN_WINDOW)):
        verdicts = {gate.intercept(i, now=now).verdict
                    for i in from_kubectl_multi(command.split())}
        expected = {"ALLOW", "ESCALATE"} if now == IN_WINDOW and "exec" in command else {"ALLOW"}
        assert verdicts == expected, command


# --- a quarantined rule asks wherever the same rule, live, would not allow ------------------


def _live_and_quarantined(rule: Constraint, command: str, now: datetime, tzdata: bool):
    argv = command.split()
    live = ConstraintStore(authority_map=dict(AUTHORITY))
    live.add_constraint(rule)
    live.tzdata_available = tzdata
    quarantined = ConstraintStore(authority_map=dict(AUTHORITY))
    quarantined.quarantined.append({"id": rule.id, "reason": "tampered"})
    quarantined.quarantined_constraints.append(rule)
    quarantined.tzdata_available = tzdata
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    results = []
    for store in (live, quarantined):
        gate = AegisInterceptor(store, on_untrusted_match="escalate")
        results.append(max((gate.intercept(i, now=now).verdict for i in from_kubectl_multi(argv)),
                           key=order.get))
    return results


def _bare(pattern: str, action: str, scope: dict | None = None) -> Constraint:
    return _rule("r", pattern, [action], scope)


NO_DELETE_PROD_SECRETS = _windowed("secret/*", "delete", {"namespace": "prod"})


@pytest.mark.parametrize("rule,command,now,tzdata,live,quarantined", [
    # direct match
    (_bare("pod/x", "exec"), "kubectl exec x -- id", NOW, True, "BLOCK", "ESCALATE"),
    # manifest, with and without the rest being known
    (_bare("secret/*", "delete"), "kubectl delete -f x.yaml", NOW, True, "ESCALATE", "ESCALATE"),
    (NO_DELETE_PROD_SECRETS, "kubectl delete -f x.yaml", IN_WINDOW, True, "ESCALATE", "ESCALATE"),
    (NO_DELETE_PROD_SECRETS, "kubectl delete -f x.yaml", IN_WINDOW, False, "ESCALATE", "ESCALATE"),
    (NO_DELETE_PROD_SECRETS, "kubectl delete -f x.yaml", OUT_OF_WINDOW, True, "ALLOW", "ALLOW"),
    (_bare("manifest/y.yaml", "delete"), "kubectl delete -f x.yaml", NOW, True, "ALLOW", "ALLOW"),
    (_bare("secret/*", "create"), "kubectl delete -f x.yaml", NOW, True, "ALLOW", "ALLOW"),
    # runtime target
    (_bare("pod/p", "exec"), "kubectl exec deploy/w -- id", NOW, True, "ESCALATE", "ESCALATE"),
    (_bare("deployment/p", "delete"), "kubectl delete all --all", NOW, True,
     "ESCALATE", "ESCALATE"),
    (_bare("pod/*", "exec"), "kubectl exec deploy/w -- id", NOW, True, "BLOCK", "ESCALATE"),
    (_bare("secret/*", "delete"), "kubectl delete all --all", NOW, True, "ALLOW", "ALLOW"),
    # scope: namespace, env
    (_bare("pod/x", "exec", {"namespace": "prod"}), "kubectl exec x -- id", NOW, True,
     "ESCALATE", "ESCALATE"),
    (_bare("pod/x", "exec", {"namespace": "prod"}), "kubectl exec x -n dev -- id", NOW, True,
     "ALLOW", "ALLOW"),
    (_bare("pod/x", "exec", {"env": "prod"}), "kubectl exec x -- id", NOW, True,
     "ESCALATE", "ESCALATE"),
    # time window
    (_windowed("pod/x", "exec"), "kubectl exec x -- id", IN_WINDOW, False, "ESCALATE", "ESCALATE"),
    (_windowed("pod/x", "exec"), "kubectl exec x -- id", IN_WINDOW, True, "BLOCK", "ESCALATE"),
    (_windowed("pod/x", "exec"), "kubectl exec x -- id", OUT_OF_WINDOW, True, "ALLOW", "ALLOW"),
    # scope and window together, on a runtime target
    (_windowed("pod/p", "exec", {"namespace": "prod"}), "kubectl exec deploy/w -- id",
     IN_WINDOW, False, "ESCALATE", "ESCALATE"),
])
def test_quarantine_mirrors_every_live_path(rule, command, now, tzdata, live, quarantined):
    assert _live_and_quarantined(rule, command, now, tzdata) == [live, quarantined]


# --- only a kind no table knows may be a custom kind in a category --------------------------


@pytest.mark.parametrize("pattern", [
    "apiservice/*", "customresourcedefinition/*", "endpointslice/*", "podtemplate/*",
    "controllerrevision/*", "runtimeclass/x", "csinode/*", "volumeattachment/*", "ipaddress/*",
    "secret/*", "secrets/*", "node/x", "flowschema/*",
])
def test_a_rule_on_a_builtin_kind_outside_all_stays_out_of_it(pattern):
    assert _decide([_bare(pattern, "delete")], ["kubectl", "delete", "all", "--all"]) == (
        "ALLOW", [])


@pytest.mark.parametrize("pattern", ["widget/*", "widgets/*", "rollout/web", "wid*/x"])
def test_a_rule_on_an_unknown_kind_may_be_in_all(pattern):
    verdict, notes = _decide([_bare(pattern, "delete")], ["kubectl", "delete", "all", "--all"])
    assert verdict == "ESCALATE" and notes == ["target-unresolved: r"]


def test_a_category_kind_outside_it_stays_out_of_the_other_category():
    assert _decide([_bare("deployment/*", "delete")],
                   ["kubectl", "delete", "api-extensions", "--all"]) == ("ALLOW", [])
    assert _decide([_bare("apiservice/*", "delete")],
                   ["kubectl", "delete", "api-extensions", "--all"])[0] == "BLOCK"


def test_the_builtin_table_holds_every_category_kind():
    from aegis_core.parser import _KUBECTL_BUILTIN_KINDS, _KUBECTL_CATEGORIES

    for kinds in _KUBECTL_CATEGORIES.values():
        assert set(kinds) <= set(_KUBECTL_BUILTIN_KINDS)


@pytest.mark.parametrize("spelled,kind", [
    ("endpointslices", "endpointslice"), ("podtemplates", "podtemplate"),
    ("controllerrevisions", "controllerrevision"), ("runtimeclasses", "runtimeclass"),
    ("csinodes", "csinode"), ("volumeattachments", "volumeattachment"), ("ip", "ipaddress"),
    ("ipaddresses", "ipaddress"), ("vac", "volumeattributesclass"), ("cs", "componentstatus"),
    ("flowschemas", "flowschema"), ("resourceclaims", "resourceclaim"), ("ep", "endpoints"),
    ("endpoints", "endpoints"), ("limits", "limitrange"), ("quota", "resourcequota"),
    ("crds", "customresourcedefinition"), ("deploy", "deployment"), ("widgets", "widgets"),
])
def test_every_builtin_spelling_is_normalised(spelled, kind):
    assert [i.resource for i in from_kubectl_multi(["kubectl", "delete", spelled, "x"])] == [
        f"{kind}/x"]


# --- a rule on one object, and a command that picks objects when it runs (#66) ---------------


@pytest.mark.parametrize("pattern,action,command,verdict", [
    # one object of the kind: cannot be told
    ("deployment/payments", "delete", "kubectl delete deployments --all", "ESCALATE"),
    ("deployment/payments", "delete", "kubectl delete deploy -l a=b", "ESCALATE"),
    ("deployment/pay*", "delete", "kubectl delete deploy --field-selector=a=b", "ESCALATE"),
    ("deployment?payments", "delete", "kubectl delete deploy --all", "ESCALATE"),
    ("*/payments", "delete", "kubectl delete deploy --all", "ESCALATE"),
    ("namespace/prod", "delete", "kubectl delete namespaces --all", "ESCALATE"),
    ("node/n1", "taint", "kubectl taint nodes --all a-", "ESCALATE"),
    ("node/n1", "taint", "kubectl taint nodes -l z=a a=b:NoSchedule", "ESCALATE"),
    ("node/n1", "taint", "kubectl taint node decoy --all a-", "ESCALATE"),
    ("node/decoy", "taint", "kubectl taint node decoy --all a-", "BLOCK"),
    ("pod/p", "label", "kubectl label pods --all a=b", "ESCALATE"),
    ("pod/p", "annotate", "kubectl annotate pods -l x=y a-", "ESCALATE"),
    ("deployment/p", "scale", "kubectl scale deploy --all --replicas=0", "ESCALATE"),
    ("deployment/p", "set-image", "kubectl set image deploy --all c=i", "ESCALATE"),
    ("deployment/p", "rollout-restart", "kubectl rollout restart deploy", "ESCALATE"),
    ("deployment/p", "rollout-undo", "kubectl rollout undo deploy -l a=b", "ESCALATE"),
    ("deployment/p", "edit", "kubectl edit deploy", "ESCALATE"),
    ("pod/p", "wait", "kubectl wait pods --all --for=condition=ready", "ESCALATE"),
    # a read rule on one object: the read may show it
    ("secret/db", "get", "kubectl get secrets", "ESCALATE"),
    ("secret/db", "get", "kubectl get secrets -l a=b", "ESCALATE"),
    ("secret/db", "describe", "kubectl describe secrets", "ESCALATE"),
    # the whole kind decides directly
    ("deployment/*", "delete", "kubectl delete deployments --all", "BLOCK"),
    ("deployment/*", "delete", "kubectl delete deploy -l a=b", "BLOCK"),
    ("*", "delete", "kubectl delete deploy -l a=b", "BLOCK"),
    ("node/*", "taint", "kubectl taint nodes --all a-", "BLOCK"),
    ("secret/*", "get", "kubectl get secrets", "BLOCK"),
    # the name decides when there is one
    ("deployment/payments", "delete", "kubectl delete deploy payments", "BLOCK"),
    ("deployment/payments", "delete", "kubectl delete deploy other", "ALLOW"),
    ("deployment/payments", "label", "kubectl label deploy/other a=b --all", "ALLOW"),
    # another kind, another action
    ("secret/db", "delete", "kubectl delete deployments --all", "ALLOW"),
    ("deployment/payments", "get", "kubectl delete deployments --all", "ALLOW"),
    ("deployment/payments", "delete", "kubectl get deployments", "ALLOW"),
    ("pod/p", "delete", "kubectl get pods", "ALLOW"),
    ("deployment/p", "delete", "kubectl logs deploy/p", "ALLOW"),
    # comma lists, and the category from #65
    ("deployment/p", "delete", "kubectl delete deploy,svc --all", "ESCALATE"),
    ("service/p", "delete", "kubectl delete deploy,svc --all", "ESCALATE"),
    ("secret/p", "delete", "kubectl delete deploy,svc --all", "ALLOW"),
    ("deployment/p", "delete", "kubectl delete all -l x=y", "ESCALATE"),
    ("secret/p", "delete", "kubectl delete all -l x=y", "ALLOW"),
    ("secret/p", "delete", "kubectl delete all,secrets -l x=y", "ESCALATE"),
])
def test_a_rule_on_one_object_against_a_command_that_picks(pattern, action, command, verdict):
    got, notes = _decide([_bare(pattern, action)], command.split())
    assert got == verdict, (command, notes)
    if verdict == "ESCALATE":
        assert notes == ["target-unresolved: r"]


@pytest.mark.parametrize("scope,command,verdict", [
    ({"namespace": "prod"}, "kubectl delete deploy --all -n staging", "ALLOW"),
    ({"namespace": "prod"}, "kubectl delete deploy --all -n prod", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl -n prod delete deploy -l a=b", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl delete deploy --all", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl delete deploy --all -A", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl get deploy -A", "ALLOW"),
    ({"env": "prod"}, "kubectl delete deploy --all", "ESCALATE"),
])
def test_a_rule_on_one_object_keeps_its_scope(scope, command, verdict):
    rule = _bare("deployment/p", "delete", scope)
    assert _decide([rule], command.split())[0] == verdict


@pytest.mark.parametrize("pattern,note", [
    ("deployment/payments", "target-unresolved: r"), ("deployment/*", "namespace-unresolved: r"),
])
def test_the_whole_kind_and_one_object_with_an_unknown_namespace(pattern, note):
    rule = _bare(pattern, "get", {"namespace": "prod"})
    verdict, notes = _decide([rule], "kubectl get deploy -A".split())
    assert verdict == "ESCALATE" and notes == [note]


@pytest.mark.parametrize("rule,command,now,tzdata,live,quarantined", [
    (_bare("deployment/p", "delete"), "kubectl delete deploy --all", NOW, True,
     "ESCALATE", "ESCALATE"),
    (_bare("deployment/*", "delete"), "kubectl delete deploy --all", NOW, True,
     "BLOCK", "ESCALATE"),
    (_bare("secret/p", "delete"), "kubectl delete deploy --all", NOW, True, "ALLOW", "ALLOW"),
    (_bare("deployment/p", "delete", {"namespace": "prod"}),
     "kubectl delete deploy -l a=b -n dev", NOW, True, "ALLOW", "ALLOW"),
    (_windowed("deployment/p", "delete"), "kubectl delete deploy --all", IN_WINDOW, True,
     "ESCALATE", "ESCALATE"),
    (_windowed("deployment/p", "delete"), "kubectl delete deploy --all", OUT_OF_WINDOW, True,
     "ALLOW", "ALLOW"),
    (_windowed("deployment/p", "delete"), "kubectl delete deploy --all", IN_WINDOW, False,
     "ESCALATE", "ESCALATE"),
    (_windowed("deployment/p", "delete"), "kubectl delete deploy --all", OUT_OF_WINDOW, False,
     "ESCALATE", "ESCALATE"),
    (_windowed("node/n1", "taint"), "kubectl taint nodes --all a-", IN_WINDOW, False,
     "ESCALATE", "ESCALATE"),
    (_windowed("deployment/p", "delete", {"namespace": "prod"}), "kubectl delete deploy --all",
     IN_WINDOW, False, "ESCALATE", "ESCALATE"),
])
def test_windows_and_quarantine_behave_the_same(rule, command, now, tzdata, live, quarantined):
    assert _live_and_quarantined(rule, command, now, tzdata) == [live, quarantined]


def test_an_untrusted_rule_on_one_object_cannot_force_a_question():
    bad = _windowed("deployment/p", "delete", principal="intruder")
    store = ConstraintStore(authority_map=dict(AUTHORITY))
    store.constraints[bad.id] = bad
    decision = AegisInterceptor(store).intercept(
        from_kubectl("kubectl delete deploy --all".split()), now=IN_WINDOW)
    assert decision.verdict == "ALLOW"
    assert decision.discarded == [{"id": "r", "reason": "unauthorized"}]


# --- the object a command reaches, whatever word names it (#68) ----------------------


@pytest.mark.parametrize("pattern,action,command,verdict", [
    # logs behind a name, as exec
    ("pod/*", "logs", "kubectl logs deploy/web", "BLOCK"),
    ("deployment/web", "logs", "kubectl logs deploy/web", "BLOCK"),
    ("pod/payments-0", "logs", "kubectl logs deploy/web", "ESCALATE"),
    ("pod/payments-0", "logs", "kubectl logs payments-0", "BLOCK"),
    ("pod/payments-0", "logs", "kubectl logs other", "ALLOW"),
    ("pod/payments-0", "logs", "kubectl logs pod/other", "ALLOW"),
    ("secret/x", "logs", "kubectl logs deploy/web", "ALLOW"),
    ("pod/*", "exec", "kubectl logs deploy/web", "ALLOW"),
    # debug
    ("pod/web", "debug", "kubectl debug web --image=busybox", "BLOCK"),
    ("pod/*", "debug", "kubectl debug web --image=busybox", "BLOCK"),
    ("pod/other", "debug", "kubectl debug web --image=busybox", "ALLOW"),
    ("node/*", "debug", "kubectl debug web --image=busybox", "ALLOW"),
    ("node/n1", "debug", "kubectl debug node/n1 --image=busybox", "BLOCK"),
    ("pod/*", "debug", "kubectl debug node/n1 --image=busybox", "ALLOW"),
    ("pod/web", "debug", "kubectl debug web --copy-to=c --image=x", "BLOCK"),
    ("pod/c", "debug", "kubectl debug web --copy-to=c --image=x", "BLOCK"),
    ("pod/d", "debug", "kubectl debug web --copy-to=c --image=x", "ALLOW"),
    # cp, either side
    ("pod/web", "cp", "kubectl cp web:/a b", "BLOCK"),
    ("pod/*", "cp", "kubectl cp web:/a b", "BLOCK"),
    ("pod/web", "cp", "kubectl cp b web:/a", "BLOCK"),
    ("pod/*", "cp", "kubectl cp b web:/a", "BLOCK"),
    ("pod/web", "cp", "kubectl cp b prod/web:/a -c app", "BLOCK"),
    ("pod/web", "cp", "kubectl cp b -- web:/a", "BLOCK"),
    ("pod/other", "cp", "kubectl cp b web:/a", "ALLOW"),
    ("pod/web", "exec", "kubectl cp b web:/a", "ALLOW"),
    # no pod, and kubectl refuses it
    ("pod/*", "cp", "kubectl cp a b", "ALLOW"),
    ("pod/*", "cp", "kubectl cp /tmp/x:y b", "ALLOW"),
    # describe TYPE NAME: rules that can name an object starting with NAME
    ("pod/payments-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("pod/pay*-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("pod/p?y-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("pod/[op]ay-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("pod/*-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("*/payments-0", "describe", "kubectl describe pod pay", "ESCALATE"),
    ("pod/pay", "describe", "kubectl describe pod pay", "BLOCK"),
    ("pod/pay*", "describe", "kubectl describe pod pay", "BLOCK"),
    ("pod/*", "describe", "kubectl describe pod pay", "BLOCK"),
    ("pod/api-0", "describe", "kubectl describe pod pay", "ALLOW"),
    ("pod/pa", "describe", "kubectl describe pod pay", "ALLOW"),
    ("pod/xpayments", "describe", "kubectl describe pod pay", "ALLOW"),
    ("secret/payments-0", "describe", "kubectl describe pod pay", "ALLOW"),
    ("pod/payments-0", "get", "kubectl describe pod pay", "ALLOW"),
    # a name written in the other forms is exact
    ("pod/payments-0", "describe", "kubectl describe pod/pay", "ALLOW"),
    ("pod/payments-0", "describe", "kubectl describe pod pay other", "ALLOW"),
    ("pod/payments-0", "get", "kubectl get pod pay", "ALLOW"),
    # a metacharacter written in the command is only text
    ("pod/payments-0", "describe", "kubectl describe pod p*", "ALLOW"),
    # a kind outside the table
    ("widget/*", "delete", "kubectl delete widgets --all", "ESCALATE"),
    ("widget/one", "delete", "kubectl delete widgets --all", "ESCALATE"),
    ("widget.x.io/*", "delete", "kubectl delete widgets --all", "ESCALATE"),
    ("widget/*", "delete", "kubectl delete wd -l a=b", "ESCALATE"),
    ("widgets/*", "delete", "kubectl delete widget --all", "ESCALATE"),
    ("widgets/*", "delete", "kubectl delete widgets --all", "BLOCK"),
    ("widget/*", "delete", "kubectl delete widget --all", "BLOCK"),
    ("*", "delete", "kubectl delete widgets --all", "BLOCK"),
    ("widget/*", "delete", "kubectl delete widgets foo", "ESCALATE"),
    ("widget/foo", "delete", "kubectl delete widgets foo", "ESCALATE"),
    ("widget/f*", "delete", "kubectl delete wd/foo", "ESCALATE"),
    ("widget/bar", "delete", "kubectl delete widgets foo", "ALLOW"),
    ("widgets/bar", "delete", "kubectl delete widgets foo", "ALLOW"),
    ("widget/foo", "delete", "kubectl delete widget foo", "BLOCK"),
    ("widget/payments-0", "describe", "kubectl describe widgets pay", "ESCALATE"),
    ("widget/api-0", "describe", "kubectl describe widgets pay", "ALLOW"),
    # can't be ruled out: another custom kind may have this short name
    ("gadget/*", "delete", "kubectl delete widgets --all", "ESCALATE"),
    # built-in kinds are in the table, so a custom name is not one of them
    ("deployment/*", "delete", "kubectl delete widgets --all", "ALLOW"),
    ("pod/x", "delete", "kubectl delete widgets --all", "ALLOW"),
    ("manifest/x.yaml", "delete", "kubectl delete widgets --all", "ALLOW"),
    ("widget/*", "get", "kubectl delete widgets --all", "ALLOW"),
    # a built-in kind never asks about a custom rule
    ("widget/*", "delete", "kubectl delete pods --all", "ALLOW"),
    ("widget/*", "delete", "kubectl delete pod web", "ALLOW"),
    # verbs that don't take a custom kind
    ("widget/*", "*", "kubectl config view", "ALLOW"),
    ("widget/*", "*", "kubectl run web --image=x", "ALLOW"),
])
def test_the_object_a_command_reaches(pattern, action, command, verdict):
    got, notes = _decide([_bare(pattern, action)], command.split())
    assert got == verdict, (command, notes)
    if verdict == "ESCALATE":
        assert notes == ["target-unresolved: r"]


@pytest.mark.parametrize("scope,command,verdict", [
    ({"namespace": "prod"}, "kubectl cp b prod/web:/a", "BLOCK"),
    ({"namespace": "prod"}, "kubectl cp -n dev b prod/web:/a", "BLOCK"),
    ({"namespace": "prod"}, "kubectl cp b dev/web:/a", "ALLOW"),
    ({"namespace": "prod"}, "kubectl cp -n prod dev/web:/a b", "ALLOW"),
    ({"namespace": "prod"}, "kubectl cp b web:/a -n prod", "BLOCK"),
    ({"namespace": "prod"}, "kubectl cp b web:/a", "ESCALATE"),
])
def test_cp_takes_its_namespace_from_the_pod_it_names(scope, command, verdict):
    assert _decide([_bare("pod/web", "cp", scope)], command.split())[0] == verdict


@pytest.mark.parametrize("scope,command,verdict", [
    ({"namespace": "prod"}, "kubectl describe pod pay -n prod", "ESCALATE"),
    ({"namespace": "prod"}, "kubectl describe pod pay -n dev", "ALLOW"),
    ({"namespace": "prod"}, "kubectl describe pod pay", "ESCALATE"),
])
def test_a_name_prefix_keeps_the_rules_scope(scope, command, verdict):
    assert _decide([_bare("pod/payments-0", "describe", scope)], command.split())[0] == verdict


@pytest.mark.parametrize("command,rule", [
    ("kubectl describe pod pay", _bare("pod/payments-0", "describe")),
    ("kubectl delete widgets --all", _bare("widget/*", "delete")),
    ("kubectl delete widgets foo", _bare("widget/foo", "delete")),
])
def test_a_quarantined_rule_asks_where_a_live_one_would(command, rule):
    assert _live_and_quarantined(rule, command, NOW, True) == ["ESCALATE", "ESCALATE"]


@pytest.mark.parametrize("pattern,action,command,verdict", [
    # words after "--" are operands
    ("pod/payments-0", "describe", "kubectl describe pod api -- payments-0", "BLOCK"),
    ("widget/bar", "delete", "kubectl delete widgets foo -- bar", "ESCALATE"),
    ("pod/x", "delete", "kubectl delete pod a -- x", "BLOCK"),
    ("pod/x", "delete", "kubectl delete pod -- x", "BLOCK"),
    ("pod/*", "delete", "kubectl delete pod -- x", "BLOCK"),
    ("pod/y", "delete", "kubectl delete pod -- x", "ALLOW"),
    ("node/n2", "cordon", "kubectl cordon n1 -- n2", "BLOCK"),
    ("node/n2", "drain", "kubectl drain n1 -- n2", "BLOCK"),
    ("deployment/b", "scale", "kubectl scale deploy a -- b --replicas=1", "BLOCK"),
    ("pod/web", "cp", "kubectl cp b -- web:/a", "BLOCK"),
    # and they count for the prefix: three words are exact, two are not
    ("pod/payments-0", "describe", "kubectl describe pod pay -- other", "ALLOW"),
    ("pod/payments-0", "describe", "kubectl describe pod -- pay", "ESCALATE"),
    # attach: at most two words
    ("deployment/web", "attach", "kubectl attach deploy -- web", "BLOCK"),
    ("pod/*", "attach", "kubectl attach deploy -- web", "BLOCK"),
    ("pod/web", "attach", "kubectl attach web -- x", "BLOCK"),
    # a command stays a command
    ("pod/ls", "exec", "kubectl exec web -- ls", "ALLOW"),
    ("pod/sh", "debug", "kubectl debug web --image=x -- sh", "ALLOW"),
    ("pod/sleep", "run", "kubectl run web --image=x -- sleep", "ALLOW"),
    ("pod/1", "run", "kubectl run web --image=x -- 1", "ALLOW"),
    # run names a pod (#71)
    ("pod/web", "run", "kubectl run web --image=x", "BLOCK"),
    ("pod/*", "run", "kubectl run web --image=x", "BLOCK"),
    ("pod/*", "run", "kubectl run --image=x -n prod web", "BLOCK"),
    ("pod/web", "run", "kubectl run web --image=x -- sleep 1", "BLOCK"),
    ("pod/all", "run", "kubectl run all --image=x", "BLOCK"),
    ("pod/*", "run", "kubectl run all --image=x", "BLOCK"),
    ("pod/001", "run", "kubectl run 001 --image=x", "BLOCK"),
    ("pod/1", "run", "kubectl run 001 --image=x", "ALLOW"),
    ("pod/other", "run", "kubectl run web --image=x", "ALLOW"),
    # --expose creates a Service too (#73)
    ("service/web", "run", "kubectl run web --image=x --expose --port=80", "BLOCK"),
    ("service/*", "run", "kubectl run web --image=x --expose --port=80", "BLOCK"),
    ("service/web", "run", "kubectl run web --image=x --expose=true --port=80", "BLOCK"),
    ("service/*", "run", "kubectl run web --image=x --expose=1 --port=80", "BLOCK"),
    ("service/*", "run", "kubectl run -n prod web --image=x --expose --port=80", "BLOCK"),
    ("service/*", "run", "kubectl run web -i --rm --image=x --expose --port=80", "BLOCK"),
    ("service/*", "run", "kubectl run web --image=x --expose=maybe --port=80", "BLOCK"),
    ("web/*", "run", "kubectl run web --image=x --expose --port=80", "BLOCK"),
    ("pod/web", "run", "kubectl run web --image=x --expose --port=80", "BLOCK"),
    ("pod/*", "run", "kubectl run web --image=x --expose --port=80", "BLOCK"),
    ("service/other", "run", "kubectl run web --image=x --expose --port=80", "ALLOW"),
    ("service/web", "run", "kubectl run web --image=x", "ALLOW"),
    ("service/*", "run", "kubectl run web --image=x", "ALLOW"),
    ("service/web", "run", "kubectl run web --image=x --expose=false --port=80", "ALLOW"),
    ("service/*", "run", "kubectl run web --image=x --expose=0 --port=80", "ALLOW"),
    ("service/*", "run", "kubectl run web --image=x -- --expose", "ALLOW"),
    ("service/*", "run", "kubectl run deploy/web --image=x --expose --port=80", "ALLOW"),
    # the action stays run, and a rehearsal stays a rehearsal
    ("service/*", "create", "kubectl run web --image=x --expose --port=80", "ALLOW"),
    ("service/*", "delete", "kubectl run web -i --rm --image=x --expose --port=80", "ALLOW"),
    ("service/*", "run", "kubectl run web --image=x --expose --port=80 --dry-run=client", "ALLOW"),
    ("service/*", "run", "kubectl run web --image=x --expose --port=80 --dry-run=none", "BLOCK"),
    # a category is not read: run all is a pod and reaches no deployment
    ("deployment/*", "run", "kubectl run all --image=x", "ALLOW"),
    # the action stays run
    ("pod/*", "create", "kubectl run web --image=x", "ALLOW"),
    # a rehearsal stays a rehearsal
    ("pod/*", "run", "kubectl run web --image=x --dry-run=client", "ALLOW"),
    ("pod/*", "run", "kubectl run web --image=x --dry-run=none", "BLOCK"),
    ("web/*", "run", "kubectl run web --image=x", "BLOCK"),
    ("all/*", "run", "kubectl run all --image=x", "BLOCK"),
    ("web/a", "run", "kubectl run web a --image=x", "BLOCK"),
    ("other/*", "run", "kubectl run web --image=x", "ALLOW"),
    # the spelling earlier versions gave keeps its rule
    ("web:*", "cp", "kubectl cp web:/a b", "BLOCK"),
    ("web:/a", "cp", "kubectl cp web:/a b", "BLOCK"),
    ("b", "cp", "kubectl cp b web:/a", "BLOCK"),
    ("web/*", "debug", "kubectl debug web --image=x", "BLOCK"),
    ("a/b", "debug", "kubectl debug a b --image=x", "BLOCK"),
    ("other:*", "cp", "kubectl cp web:/a b", "ALLOW"),
    ("other/*", "debug", "kubectl debug web --image=x", "ALLOW"),
    # a name from a flag or an operand stays as written
    ("pod/001", "debug", "kubectl debug web --image=x --copy-to=001", "BLOCK"),
    ("pod/1", "debug", "kubectl debug web --image=x --copy-to=001", "ALLOW"),
    # autoscale takes any kind with a scale subresource
    ("widget/foo", "autoscale", "kubectl autoscale widgets foo --max=3", "ESCALATE"),
    ("widget/bar", "autoscale", "kubectl autoscale widgets foo --max=3", "ALLOW"),
    ("deployment/foo", "autoscale", "kubectl autoscale widgets foo --max=3", "ALLOW"),
    ("pod/001", "debug", "kubectl debug 001 --image=x", "BLOCK"),
    ("pod/001", "cp", "kubectl cp b 001:/a", "BLOCK"),
    ("pod/0012", "describe", "kubectl describe pod 001", "ESCALATE"),
    ("widget/001", "delete", "kubectl delete widgets 001", "ESCALATE"),
])
def test_review_of_the_object_a_command_reaches(pattern, action, command, verdict):
    got, notes = _decide([_bare(pattern, action)], command.split())
    assert got == verdict, (command, notes)
    if verdict == "ESCALATE":
        assert notes == ["target-unresolved: r"]


@pytest.mark.parametrize("pattern,scope,verdict", [
    ("web/*", {"copy-to": 1}, "BLOCK"),
    ("web/*", {"copy-to": 2}, "ALLOW"),
    ("pod/001", {}, "BLOCK"),
])
def test_copy_to_stays_a_number_in_a_scope_and_text_in_a_target(pattern, scope, verdict):
    rule = _bare(pattern, "debug", scope)
    command = "kubectl debug web --image=x --copy-to=001".split()
    assert _decide([rule], command)[0] == verdict


def test_a_rule_scoped_to_a_namespace_keeps_the_verdict_on_the_old_spelling():
    rule = _bare("web:*", "cp", {"namespace": "dev"})
    assert _decide([rule], "kubectl cp -n dev web:/a b".split())[0] == "BLOCK"
    assert _decide([rule], "kubectl cp -n prod web:/a b".split())[0] == "ALLOW"


# Everyday commands under rules that aren't about them decide as if no rule were there.
@pytest.mark.parametrize("command", [
    "kubectl get pods -n prod",
    "kubectl describe deployment api -n prod",
    "kubectl logs api-0 -n prod",
    "kubectl logs deploy/web -n prod",
    "kubectl cp b web:/a",
    "kubectl debug web --image=busybox",
    "kubectl describe pod pay",
    "kubectl get widgets",
])
def test_other_actions_and_kinds_stay_quiet(command):
    rules = [_rule("a", "node/*", ["delete", "drain"]), _rule("b", "secret/db", ["delete"]),
             _rule("c", "namespace/*", ["delete"]), _rule("d", "pod/payments-0", ["delete"]),
             _rule("e", "widget/*", ["delete"])]
    assert _decide(rules, command.split())[0] == "ALLOW"


@pytest.mark.parametrize("command,verdict", [
    ("kubectl get pods -n prod", "ALLOW"),
    ("kubectl describe deployment api -n prod", "ALLOW"),
    ("kubectl delete namespace prod", "BLOCK"),
    ("kubectl delete nodes --all", "BLOCK"),
])
def test_the_paper_scenarios_keep_their_verdicts(command, verdict):
    rules = [_rule("n", "namespace/*", ["delete"]), _rule("o", "node/*", ["delete"])]
    assert _decide(rules, command.split())[0] == verdict


# --- flag spellings kubectl reads differently from how they look (#75) ---------------
# Checked on kubectl 1.36 against a local stub API server: which namespace the request
# went to, and whether a DELETE was sent at all.


def _one(command: str):
    return from_kubectl_multi(command.split())[0]


@pytest.mark.parametrize("flags,rehearsal", [
    ("--dry-run=client --dry-run=none", False),
    ("--dry-run=server --dry-run=none", False),
    ("--dry-run=server --dry-run=false", False),
    ("--dry-run --dry-run=none", False),
    ("--dry-run=none --dry-run=client", True),
    ("--dry-run=none --dry-run=server", True),
    ("--dry-run=none --dry-run", True),
    ("--dry-run=client --dry-run=server", True),
    ("--dry-run=none", False),
    ("--dry-run=client", True),
])
def test_the_last_dry_run_decides(flags, rehearsal):
    intent = _one(f"kubectl delete pod x {flags}")
    assert intent.params.get("dry_run", False) is rehearsal
    block = [_rule("no-delete", "pod/*", ["delete"])]
    assert _decide(block, f"kubectl delete pod x {flags}".split())[0] == (
        "ALLOW" if rehearsal else "BLOCK")


@pytest.mark.parametrize("word,namespace", [
    ("-n prod", "prod"),
    ("-nprod", "prod"),
    ("-n=prod", "prod"),
    ("-n dev -n prod", "prod"),
    ("-n dev -qnprod", "prod"),
    ("-qnprod", "prod"),
    ("-qn prod", "prod"),
    ("-qn=prod", "prod"),
    ("-itnprod", "prod"),
    ("-n prod -qndev", "dev"),
    ("-n=", "="),  # pflag strips a "=" only when something follows it
])
def test_a_bundled_namespace_is_the_one_kubectl_uses(word, namespace):
    command = f"kubectl run web --image=x {word}"
    assert _one(command).metadata["namespace"] == namespace


@pytest.mark.parametrize("command", [
    "kubectl run web --image=x -n dev -qnprod",
    "kubectl run web --image=x -qn prod",
    "kubectl delete pod x -n dev -inprod",
    "kubectl exec web -n dev -itnprod -- ls",
    "kubectl rollout restart deploy/web -n dev -qnprod",
])
def test_a_bundled_namespace_meets_a_namespace_rule(command):
    actions = ["run", "delete", "exec", "rollout-restart"]
    rule = _rule("prod-only", "*/*", actions, scope={"namespace": "prod"})
    assert _decide([rule], command.split())[0] == "BLOCK"


def test_a_flag_value_is_not_split_as_a_short_word():
    # kubectl takes the next word as the value, whatever it looks like
    rule = _rule("prod-only", "*/*", ["delete"], scope={"namespace": "prod"})
    intent = _one("kubectl delete pod x -n dev --field-manager -qnprod")
    assert intent.metadata["namespace"] == "dev"
    assert intent.params["field-manager"] == "-qnprod"
    command = "kubectl delete pod x -n prod --field-manager -ndev"
    assert _decide([rule], command.split())[0] == "BLOCK"
    assert _one("kubectl get pods --context -nprod").metadata == {"context": "-nprod"}
    assert _one("kubectl --context -nprod get pods").metadata == {"context": "-nprod"}


IT = {"stdin": True, "tty": True}  # -i and -t are recorded under their long names


@pytest.mark.parametrize("command,resource,params,metadata", [
    # harmless spellings keep their result
    ("kubectl exec web -it -- sh", "pod/web", {"command": ["sh"], **IT}, {}),
    ("kubectl exec web -ti -- sh", "pod/web", {"command": ["sh"], **IT}, {}),
    ("kubectl exec web -i -t -- sh", "pod/web", {"command": ["sh"], **IT}, {}),
    ("kubectl exec -it web -- ls -la", "pod/web", {"command": ["ls", "-la"], **IT}, {}),
    ("kubectl run web --image=x -it", "pod/web", {"image": "x", **IT}, {}),
    ("kubectl get pod/a -oyaml", "pod/a", {}, {}),
    ("kubectl get pod/a -ojson", "pod/a", {}, {}),
    ("kubectl get pod/a -o=json", "pod/a", {}, {}),
    ("kubectl get pod/a -o yaml", "pod/a", {}, {}),
    ("kubectl get pod/a -v9", "pod/a", {}, {}),
    ("kubectl get pod/a -w", "pod/a", {"watch": True}, {}),
    ("kubectl exec web -capp -- ls", "pod/web", {"container": "app", "command": ["ls"]}, {}),
    ("kubectl -nprod get pod/a", "pod/a", {}, {"namespace": "prod"}),
    ("kubectl -n=prod get pod/a", "pod/a", {}, {"namespace": "prod"}),
    ("kubectl -oyaml get pod/a", "pod/a", {}, {}),
    ("kubectl -v9 get pod/a", "pod/a", {}, {}),
    ("kubectl rollout -nprod restart deploy/web", "deployment/web", {}, {"namespace": "prod"}),
    ("kubectl set -nprod image deploy/web a=b", "deployment/web", {"images": {"a": "b"}},
     {"namespace": "prod"}),
    # read as kubectl reads them
    ("kubectl get pod/a -wA", "pod/a", {"watch": True}, {"all_namespaces": True}),
    ("kubectl get pod/a -Aw", "pod/a", {"watch": True}, {"all_namespaces": True}),
    ("kubectl get pod/a -Aoyaml", "pod/a", {}, {"all_namespaces": True}),
    ("kubectl get pod/a -Ao yaml", "pod/a", {}, {"all_namespaces": True}),
    ("kubectl logs -fp web", "pod/web", {"follow": True, "previous": True}, {}),
    ("kubectl logs -pf web", "pod/web", {"follow": True, "previous": True}, {}),
    ("kubectl logs -fc app web", "pod/web", {"follow": True, "container": "app"}, {}),
    ("kubectl logs web -fcapp", "pod/web", {"follow": True, "container": "app"}, {}),
    ("kubectl logs -f=false web", "pod/web", {"follow": False}, {}),
    ("kubectl exec -itc app web -- sh", "pod/web",
     {"container": "app", "command": ["sh"], **IT}, {}),
    ("kubectl patch deploy/web -p{}", "deployment/web", {"patch": "{}"}, {}),
    # pflag skips the dot
    ("kubectl get pod/a -test.nprod", "pod/a", {"tty": True, "env": ["st.nprod"]}, {}),
])
def test_short_words(command, resource, params, metadata):
    intent = _one(command)
    assert intent.resource == resource
    assert intent.metadata == metadata
    recorded = {k: v for k, v in intent.params.items()
                if k not in ("resolved_at_runtime", "value_types")}
    assert recorded == params


@pytest.mark.parametrize("word,verb", [
    ("-Rf dir", "delete"),
    ("-Rfdir", "delete"),
    ("-iRf dir", "delete"),
    ("-Rk dir", "delete"),
    ("-Rf dir", "apply"),
])
def test_a_bundled_manifest_is_a_manifest(word, verb):
    intent = _one(f"kubectl {verb} {word}")
    assert intent.resource == "manifest/dir"
    assert intent.params["manifest_not_inspected"] is True


@pytest.mark.parametrize("flags,every_namespace", [
    ("-A", True),
    ("-A=false", False),
    ("-A --all-namespaces=false", False),
    ("--all-namespaces=false -A", True),
    ("--all-namespaces", True),
])
def test_the_last_all_namespaces_decides(flags, every_namespace):
    intent = _one(f"kubectl get pod/a -n prod {flags}")
    assert intent.metadata.get("all_namespaces", False) is every_namespace
    assert intent.metadata["namespace"] == "prod"


@pytest.mark.parametrize("command", [
    # kubectl 1.36 has no -x or -r here and refuses them; a later one might have them
    "kubectl get pods -xnprod",
    "kubectl get pods -xn prod",
    "kubectl get pods -xn=prod",
    "kubectl get pods -xA",
    "kubectl get pods -qxlapp=x",
    "kubectl delete pod x -rf",
    # only a value letter or A in front of the verb, as before
    "kubectl -qnprod get pods",
    "kubectl -An prod get pods",
    "kubectl -lapp=x get pods",
    "kubectl -fx.yaml apply",
    # -r is only a flag on create deployment
    "kubectl get pods -rf",
    "kubectl create configmap c -rf",
    "kubectl create configmap c -rnprod",
    # the value is missing
    "kubectl run web --image=x -qn",
])
def test_refused_short_words(command):
    with pytest.raises(ValueError):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("command,namespace", [
    ("kubectl logs -l app=x", None),
    ("kubectl logs -fl app=x", None),
    ("kubectl logs -fl app=x -n dev", "dev"),
    ("kubectl logs -n prod --selector=app=x -f", "prod"),
])
def test_logs_by_selector_reads_every_pod_it_matches(command, namespace):
    # Checked on kubectl 1.36 against the stub server: it lists the pods by the selector
    # in that namespace and reads their logs. Every pod is the target, marked.
    intents = from_kubectl_multi(command.split())
    assert [i.resource for i in intents] == ["pod/*"]
    assert intents[0].params["selector"] == "app=x"
    assert intents[0].params["resolved_at_runtime"] == {"from": "pod/*", "kinds": ["pod"]}
    assert intents[0].metadata.get("namespace") == namespace


@pytest.mark.parametrize("rule,command,verdict", [
    (_rule("no-logs", "pod/*", ["logs"]), "kubectl logs -fl app=x -n dev", "BLOCK"),
    (_rule("no-logs-prod", "pod/*", ["logs"], {"namespace": "prod"}),
     "kubectl logs -l app=x -n prod", "BLOCK"),
    (_rule("no-logs-prod", "pod/*", ["logs"], {"namespace": "prod"}),
     "kubectl logs -l app=x -n dev", "ALLOW"),
    (_rule("no-logs-prod", "pod/*", ["logs"], {"namespace": "prod"}),
     "kubectl logs -l app=x", "ESCALATE"),
    (_rule("no-db-logs", "pod/db-0", ["logs"]), "kubectl logs -l app=x -n dev", "ESCALATE"),
])
def test_logs_by_selector_meets_the_rules(rule, command, verdict):
    assert _decide([rule], command.split())[0] == verdict


@pytest.mark.parametrize("flags,replicas", [
    # pflag reads integers with base 0, as strconv.ParseInt does; each was run with
    # kubectl 1.36 create deployment --dry-run=client and gave the same number
    ("-r0xf", 15),
    ("-r0X1F", 31),
    ("-r017", 15),
    ("-r0o17", 15),
    ("-r0b11", 3),
    ("-r1_0", 10),
    ("-r0x_f", 15),
    ("-r0_1", 1),
    ("-r+5", 5),
    ("--replicas=0x0", 0),
    ("--replicas 0x7fffffff", 2147483647),
    ("-r3", 3),
    ("-r 3", 3),
    ("-r=3", 3),
    ("-qr3", 3),  # kubectl refuses -q here, and the word still reads this way
])
@pytest.mark.parametrize("spelling", ["deployment", "deploy"])
def test_r_is_replicas_on_create_deployment(flags, replicas, spelling):
    intents = from_kubectl_multi(
        f"kubectl create {spelling} web --image=nginx {flags} -n dev".split())
    assert [i.resource for i in intents] == ["deployment/web"]
    assert intents[0].params["replicas"] == replicas
    assert intents[0].metadata == {"namespace": "dev"}


def test_r_is_replicas_in_front_of_the_subcommand():
    intent = _one("kubectl create -r3 deployment web --image=nginx -n dev")
    assert intent.resource == "deployment/web"
    assert intent.params["replicas"] == 3


@pytest.mark.parametrize("flags", [
    # kubectl 1.36 refuses each of these as a number and creates nothing
    "-rnprod", "-r08", "-r1e3", "-r0x", "-r_1", "-r1__0", "--replicas=2147483648",
    "--replicas=",
])
def test_a_number_kubectl_refuses_is_refused(flags):
    with pytest.raises(ValueError):
        from_kubectl_multi(["kubectl", "create", "deployment", "web", "--image=x", "-n", "dev",
                            *flags.split(" ", 1)])


@pytest.mark.parametrize("command,replicas", [
    ("kubectl scale deploy/web --replicas=0x0", 0),
    ("kubectl scale deploy/web --replicas 00", 0),
    ("kubectl scale deploy/web --replicas=0b0", 0),
    ("kubectl scale deploy/web --replicas=1_0", 10),
])
def test_scale_reads_replicas_as_kubectl_does(command, replicas):
    intent = _one(command)
    assert intent.params["replicas"] == replicas
    rule = _rule("no-scale-to-zero", "deployment/*", ["scale"], {"replicas": 0})
    assert _decide([rule], command.split())[0] == ("BLOCK" if replicas == 0 else "ALLOW")


def test_a_refused_short_word_reaches_the_hook_as_a_refusal():
    verdict = decide("kubectl delete deploy web -xnprod", ROOT / "data")
    assert verdict.decision == "deny", verdict


@pytest.mark.parametrize("command,decision", [
    ("kubectl delete deploy web -n prod --dry-run=client --dry-run=none", "deny"),
    ("kubectl delete deploy web -n dev -inprod", "deny"),
    ("kubectl delete deploy web -n prod --dry-run=none --dry-run=client", "allow"),
])
def test_the_spellings_against_the_example_policy(command, decision):
    verdict = decide(command, ROOT / "data")
    assert verdict.decision == decision, verdict


# --- several manifests (#75) ---------------------------------------------------------
# Checked on kubectl 1.36 against a local stub API server: both files were deleted for
# each -f spelling, stdin first or last, and only the last directory for -k.


@pytest.mark.parametrize("flags,files", [
    ("-f x.yaml", ["x.yaml"]),
    ("-f x.yaml -f y.yaml", ["x.yaml", "y.yaml"]),
    ("--filename=x.yaml --filename=y.yaml", ["x.yaml", "y.yaml"]),
    ("--filename x.yaml -fy.yaml", ["x.yaml", "y.yaml"]),
    ("-f x.yaml,y.yaml", ["x.yaml", "y.yaml"]),
    ("-f x.yaml,y.yaml -f z.yaml", ["x.yaml", "y.yaml", "z.yaml"]),
    ("-Rf x.yaml -f y.yaml", ["x.yaml", "y.yaml"]),
    ("-Rf x.yaml,y.yaml", ["x.yaml", "y.yaml"]),
    ("-f - -f y.yaml", ["-", "y.yaml"]),
    ("-f y.yaml -f -", ["y.yaml", "-"]),
    ("-f x.yaml -f x.yaml", ["x.yaml", "x.yaml"]),
    ('-f "c,d.yaml"', ["c,d.yaml"]),  # a quoted comma is part of the name
])
@pytest.mark.parametrize("verb", ["apply", "create", "replace", "delete"])
def test_every_manifest_is_an_intent(verb, flags, files):
    argv = ["kubectl", verb, *flags.split(" ")]
    intents = from_kubectl_multi(argv)
    assert [i.params["file"] for i in intents] == files
    assert [i.resource for i in intents] == [f"manifest/{f}" for f in files]
    assert all(i.action == verb and i.params["manifest_not_inspected"] is True for i in intents)


def test_a_single_manifest_keeps_its_result():
    intents = from_kubectl_multi("kubectl delete -f ./m/x.yaml -n prod --force".split())
    assert len(intents) == 1
    assert intents[0].resource == "manifest/x.yaml"
    assert intents[0].action == "delete"
    assert intents[0].params == {"force": True, "file": "./m/x.yaml",
                                 "manifest_not_inspected": True}
    assert intents[0].metadata == {"namespace": "prod"}
    assert from_kubectl("kubectl delete -f ./m/x.yaml".split()).resource == "manifest/x.yaml"


def test_from_kubectl_raises_on_two_manifests():
    with pytest.raises(ValueError):
        from_kubectl("kubectl delete -f x.yaml -f y.yaml".split())


@pytest.mark.parametrize("flags", [
    "-f x.yaml -f y.yaml",
    "-f y.yaml -f x.yaml",
    "--filename=x.yaml --filename=y.yaml",
    "-f x.yaml,y.yaml",
    "-f y.yaml,x.yaml",
    "-Rf x.yaml -f y.yaml",
])
def test_each_manifest_meets_a_rule_on_it(flags):
    rule = _rule("no-x", "manifest/x.yaml", ["delete"])
    assert _decide([rule], f"kubectl delete {flags}".split())[0] == "BLOCK"
    assert _decide([rule], f"kubectl delete {flags} --dry-run=client".split())[0] == "ALLOW"


@pytest.mark.parametrize("argv", [
    ["kubectl", "delete", "--filename=", "-f", "x.yaml"],
    ["kubectl", "delete", "-f", "x.yaml", "--filename="],
    ["kubectl", "delete", "-f", "", "-f", "x.yaml"],
    ["kubectl", "delete", "--filename", "", "--filename=x.yaml"],
])
def test_an_empty_filename_adds_no_manifest(argv):
    """pflag reads an empty StringSlice value as no entries, so kubectl deletes only x.yaml."""
    intents = from_kubectl_multi(argv)
    assert [i.resource for i in intents] == ["manifest/x.yaml"]
    assert from_kubectl(argv).resource == "manifest/x.yaml"


@pytest.mark.parametrize("argv", [
    ["kubectl", "delete", "--filename="],
    ["kubectl", "apply", "-f", ""],
])
def test_only_an_empty_filename_is_refused(argv):
    with pytest.raises(ValueError):
        from_kubectl_multi(argv)


def test_an_empty_filename_leaves_a_named_target():
    argv = ["kubectl", "delete", "--filename=", "pod", "x"]
    assert [i.resource for i in from_kubectl_multi(argv)] == ["pod/x"]


def test_a_kind_rule_still_escalates_on_every_manifest():
    verdict, notes = _decide([_rule("no-pods", "pod/*", ["delete"])],
                             "kubectl delete -f x.yaml -f y.yaml".split())
    assert verdict == "ESCALATE"
    assert "manifest-not-inspected: no-pods" in notes


def test_several_manifests_against_the_example_policy():
    verdict = decide("kubectl delete -f x.yaml -f y.yaml -n prod", ROOT / "data")
    assert verdict.decision == "deny", verdict


@pytest.mark.parametrize("flags,expect", [
    ("-k ka -k kb", ["kb"]),
    ("--kustomize=ka --kustomize=kb", ["kb"]),
    ("-Rk ka", ["ka"]),
    ("-k ka,kb", ["ka,kb"]),  # one path to kubectl, which then fails to find it
])
def test_the_last_kustomize_is_the_one(flags, expect):
    intents = from_kubectl_multi(f"kubectl delete {flags}".split())
    assert [i.params["file"] for i in intents] == expect


def test_get_with_files_stays_refused():
    # get -f has no target the parser can name, as before
    with pytest.raises(ValueError):
        from_kubectl_multi("kubectl get -f x.yaml -f y.yaml".split())


# --- flags the parser has no entry for (#80) ----------------------------------------
# A long flag in neither table is refused unless "=value" or its place at the end shows
# how kubectl reads it: if it takes a value the next word is that value, and if it does
# not the next word is a flag or a target, so either guess can misread the command.


@pytest.mark.parametrize("command", [
    "kubectl delete pod --no-such-flag critical",
    "kubectl delete --no-such-flag pod web",
    "kubectl delete pod web --no-such-flag -n prod",
    "kubectl delete pod web --no-such-flag -- x",
    "kubectl delete pod web -x -n prod",
    "kubectl delete pod -x web",
])
def test_an_unknown_flag_before_another_word_is_refused(command):
    # an unknown short letter is refused wherever it is (round 6)
    with pytest.raises(ValueError, match="cannot tell whether|not a short flag"):
        from_kubectl_multi(command.split())


@pytest.mark.parametrize("command,resource,params", [
    ("kubectl delete pod web --no-such-flag", "pod/web", {"no-such-flag": True}),
    ("kubectl delete pod web --no-such-flag=x", "pod/web", {"no-such-flag": "x"}),
])
def test_an_unknown_flag_that_shows_its_reading_is_kept(command, resource, params):
    intent = _one(command)
    assert intent.resource == resource
    assert {k: v for k, v in intent.params.items() if k != "resolved_at_runtime"} == params


@pytest.mark.parametrize("command,resource,params,metadata", [
    # flags of kubectl 1.36 the tables did not have before
    ("kubectl create secret tls t --cert c.pem --key k.pem -n prod", "secret/t",
     {"cert": "c.pem", "key": "k.pem"}, {"namespace": "prod"}),
    ("kubectl create secret docker-registry r --docker-server -ndev -n prod", "secret/r",
     {"docker-server": "-ndev"}, {"namespace": "prod"}),
    ("kubectl create priorityclass high --value 1000 --global-default --description x",
     "priorityclass/high", {"value": 1000, "global-default": True, "description": "x"}, {}),
    ("kubectl create quota q --hard pods=2 -n prod", "resourcequota/q", {"hard": "pods=2"},
     {"namespace": "prod"}),
    ("kubectl create role r --verb get --resource pods -n prod", "role/r",
     {"verb": ["get"], "resource": ["pods"]}, {"namespace": "prod"}),
    ("kubectl create pdb p --min-available 1 --selector app=x -n prod",
     "poddisruptionbudget/p", {"min-available": 1, "selector": "app=x"}, {"namespace": "prod"}),
    # --current is a flag of its own: this was refused before
    ("kubectl config set-context --current --namespace=prod", "set-context/*",
     {"current": True}, {"namespace": "prod"}),
])
def test_flags_kubectl_has_are_read(command, resource, params, metadata):
    intent = next(i for i in from_kubectl_multi(command.split()) if i.resource == resource)
    recorded = {k: v for k, v in intent.params.items()
                if k not in ("resolved_at_runtime", "value_types")}
    assert recorded == params
    assert intent.metadata == metadata


def test_a_value_flag_kubectl_has_takes_a_dash_word():
    rule = _rule("prod-only", "*/*", ["create"], scope={"namespace": "prod"})
    command = "kubectl create secret docker-registry r --docker-server -ndev -n prod"
    assert _decide([rule], command.split())[0] == "BLOCK"


def test_an_unknown_flag_reaches_the_hook_as_a_refusal():
    verdict = decide("kubectl delete deploy web --no-such-flag -n prod", ROOT / "data")
    assert verdict.decision == "deny", verdict


@pytest.mark.parametrize("command", ["kubectl get pod/a -x", "kubectl get pod/a -xyz"])
def test_an_unknown_short_letter_is_refused(command):
    # what an unknown letter means on the command is not known: never recorded as written
    with pytest.raises(ValueError, match="not a short flag"):
        _one(command)
