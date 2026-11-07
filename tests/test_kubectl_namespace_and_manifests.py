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
