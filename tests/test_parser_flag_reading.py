"""Flags the parser reads as each tool's own parser does (#80 and the sweep after it).

A flag that takes a value takes the next word whatever it looks like, so each tool has a
table of its flags, read from its source, and a flag in no table is refused unless
``=value`` or its place at the end shows how the tool would read it. Words after ``--``
are operands. Behaviour comes from each tool's source unless a test says it was run."""

from datetime import UTC, datetime

import pytest

from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_argv, from_helm
from aegis_core.store import Constraint, ConstraintStore

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)


def _rule(provider: str, resource: str, actions: list[str], scope: dict | None = None,
          cid: str = "r") -> Constraint:
    return Constraint.create(id=cid, provider=provider, resource_pattern=resource,
                             actions=set(actions), scope=scope or {}, time_window=None,
                             effect="BLOCK", constraint_class="deletion", principal="admin",
                             source_ref="t", source_timestamp="2026-11-07T00:00:00+00:00",
                             rule_text=cid)


def _verdict(rules: list[Constraint], command: str | list[str]) -> str:
    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    for r in rules:
        store.add_constraint(r)
    interceptor = AegisInterceptor(store)
    argv = command.split() if isinstance(command, str) else command
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    return max((interceptor.intercept(i, now=NOW).verdict for i in from_argv(argv)),
               key=order.__getitem__)


def _targets(command: str) -> list[tuple[str, str, dict]]:
    return [(i.resource, i.action, i.metadata) for i in from_argv(command.split())]


# --- helm ----------------------------------------------------------------------------


@pytest.mark.parametrize("command,namespace,params", [
    # issue #80: --description takes the next word, so helm runs this in prod
    ("helm upgrade api ./c -n prod --description -ndev", "prod", {"description": "-ndev"}),
    ("helm upgrade api ./c -n prod --description=-ndev", "prod", {"description": "-ndev"}),
    ("helm upgrade api ./c -n prod --timeout -ndev", "prod", {"timeout": "-ndev"}),
    ("helm upgrade api ./c -n prod --post-renderer -ndev", "prod", {"post_renderer": "-ndev"}),
    ("helm install api ./c -n prod --name-template -ndev", "prod", {"name_template": "-ndev"}),
    ("helm upgrade api ./c -n prod --server-side -ndev", "prod", {"server_side": "-ndev"}),
    ("helm rollback api 3 -n prod --server-side -ndev", "prod", {"server_side": "-ndev"}),
    ("helm uninstall api -n prod --cascade -ndev", "prod", {"cascade": "-ndev"}),
])
def test_a_helm_value_flag_takes_the_next_word(command, namespace, params):
    intent = from_argv(command.split())[0]
    assert intent.metadata["namespace"] == namespace
    assert {k: v for k, v in intent.params.items() if k in params} == params


@pytest.mark.parametrize("command,release,params", [
    # a boolean takes no value, so the word after it is the release
    ("helm upgrade --no-hooks api ./c", "api", {"no_hooks": True, "chart": "./c"}),
    ("helm upgrade --wait-for-jobs api ./c", "api", {"wait_for_jobs": True, "chart": "./c"}),
    ("helm upgrade --take-ownership api ./c", "api", {"take_ownership": True, "chart": "./c"}),
    ("helm install --server-side api ./c", "api", {"server_side": True, "chart": "./c"}),
    ("helm upgrade --wait api ./c", "api", {"wait": True, "chart": "./c"}),
    ("helm uninstall --keep-history api", "api", {"keep_history": True}),
])
def test_a_helm_boolean_leaves_the_release_alone(command, release, params):
    intent = from_argv(command.split())[0]
    assert intent.resource == f"release/{release}"
    assert {k: v for k, v in intent.params.items() if k in params} == params


@pytest.mark.parametrize("command", [
    "helm upgrade api ./c -n prod --no-such-flag -ndev",
    "helm upgrade --no-such-flag api ./c",
    "helm uninstall api --no-such-flag x",
    "helm upgrade api ./c -x prod",
])
def test_a_helm_flag_in_no_table_is_refused(command):
    with pytest.raises(ValueError, match="cannot tell whether"):
        from_argv(command.split())


def test_a_helm_flag_in_no_table_at_the_end_or_with_a_value_is_kept():
    assert from_helm("helm upgrade api ./c --no-such-flag".split()).params["no_such_flag"] is True
    assert from_helm("helm upgrade api ./c --no-such-flag=x".split()).params["no_such_flag"] == "x"


@pytest.mark.parametrize("command,verdict", [
    ("helm upgrade api ./c -n prod --description -ndev", "BLOCK"),
    ("helm upgrade api ./c -n dev --description -nprod", "ALLOW"),
    ("helm upgrade api ./c -n prod --no-such-flag -ndev", None),
])
def test_a_helm_namespace_rule_holds(command, verdict):
    rule = _rule("helm", "release/*", ["update"], {"namespace": "prod"})
    if verdict is None:
        with pytest.raises(ValueError):
            _verdict([rule], command)
    else:
        assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,releases,namespace", [
    # helm uninstalls every release it is given
    ("helm uninstall a b -n prod", ["a", "b"], "prod"),
    ("helm uninstall a -n prod b", ["a", "b"], "prod"),
    ("helm delete a b a", ["a", "b"], None),
    # pflag: every word after "--" is an operand
    ("helm uninstall a -n prod -- b", ["a", "b"], "prod"),
    ("helm uninstall a -- -nprod", ["a", "-nprod"], None),
])
def test_helm_uninstall_names_every_release(command, releases, namespace):
    intents = from_argv(command.split())
    assert [i.resource for i in intents] == [f"release/{r}" for r in releases]
    assert all(i.action == "delete" and i.metadata.get("namespace") == namespace
               for i in intents)


def test_helm_uninstall_of_two_releases_meets_a_rule_on_the_second():
    rule = _rule("helm", "release/payments", ["delete"])
    assert _verdict([rule], "helm uninstall web payments -n prod") == "BLOCK"
    assert _verdict([rule], "helm uninstall web -n prod -- payments") == "BLOCK"
    with pytest.raises(ValueError):
        from_helm("helm uninstall web payments".split())


@pytest.mark.parametrize("command", [
    "helm install ./c --generate-name",
    "helm install ./c -g",
    "helm install -g ./c",
    "helm install ./c --name-template rel-x",
])
def test_a_generated_release_name_is_every_release(command):
    # helm's NameAndChart: with --generate-name the only word is the chart
    intents = from_argv(command.split())
    assert [i.resource for i in intents] == ["release/*"]
    assert intents[0].params["chart"] == "./c"
    assert intents[0].params["resolved_at_runtime"] == {"from": "release/*",
                                                        "kinds": ["release"]}
    assert _verdict([_rule("helm", "release/*", ["create"])], command) == "BLOCK"
    assert _verdict([_rule("helm", "release/c", ["create"])], command) == "ESCALATE"


@pytest.mark.parametrize("flags,value", [
    # helm merges --set, then --set-string, then --set-literal (MergeValues)
    ("--set-string replicaCount=0 --set replicaCount=3", "0"),
    ("--set replicaCount=3 --set-string replicaCount=0", "0"),
    ("--set-literal replicaCount=0 --set replicaCount=3", "0"),
    ("--set replicaCount=3 --set replicaCount=0", 0),
])
def test_helm_set_kinds_merge_in_helms_order(flags, value):
    intent = from_helm(f"helm upgrade api ./c {flags}".split())
    assert intent.params["set"]["replicaCount"] == value


def test_helm_set_literal_keeps_its_commas():
    intent = from_helm(["helm", "upgrade", "api", "./c", "--set-literal", "a=b,c=d"])
    assert intent.params["set"] == {"a": "b,c=d"}


def test_helm_values_is_a_list_of_files():
    intent = from_helm("helm upgrade api ./c -f a.yaml,b.yaml --values c.yaml".split())
    assert intent.params["values_files"] == ["a.yaml", "b.yaml", "c.yaml"]


def test_helm_global_color_flag_before_the_verb():
    assert _targets("helm --color never uninstall x -n prod") == [
        ("release/x", "delete", {"namespace": "prod"})]


# --- flux ----------------------------------------------------------------------------
# flux2 v2.10 source, not run.


@pytest.mark.parametrize("command,namespace,params", [
    # issue #80: --url takes the next word, so flux creates this in prod
    ("flux create source git a -n prod --url -ndev --branch main", "prod", {"url": "-ndev"}),
    ("flux create kustomization a -n prod --path -ndev --source GitRepository/a", "prod",
     {"path": "-ndev"}),
    ("flux create hr a -n prod --chart -ndev --source HelmRepository/r", "prod",
     {"chart": "-ndev"}),
    ("flux reconcile ks a -n prod --timeout -ndev", "prod", {"timeout": "-ndev"}),
])
def test_a_flux_value_flag_takes_the_next_word(command, namespace, params):
    intent = from_argv(command.split())[0]
    assert intent.metadata["namespace"] == namespace
    assert {k: v for k, v in intent.params.items() if k in params} == params


@pytest.mark.parametrize("command", [
    "flux create source git a -n prod --no-such-flag -ndev",
    "flux reconcile ks --no-such-flag a",
    "flux suspend ks a -x b",
])
def test_a_flux_flag_in_no_table_is_refused(command):
    with pytest.raises(ValueError, match="cannot tell whether"):
        from_argv(command.split())


def test_a_flux_namespace_rule_holds():
    rule = _rule("flux", "*/*", ["create"], {"namespace": "prod"})
    assert _verdict([rule], "flux create source git a -n prod --url -ndev --branch m") == "BLOCK"
    assert _verdict([rule], "flux create source git a -n dev --url -nprod --branch m") == "ALLOW"


@pytest.mark.parametrize("command,resources", [
    # suspend, resume, reconcile and delete take every name they are given
    ("flux suspend ks a b", ["kustomization/a", "kustomization/b"]),
    ("flux resume kustomization a b a", ["kustomization/a", "kustomization/b"]),
    ("flux reconcile hr a b", ["helmrelease/a", "helmrelease/b"]),
    ("flux delete source git a b --silent", ["source-git/a", "source-git/b"]),
    # flux 2.10 also takes TYPE/NAME and the type's plural or short name
    ("flux suspend ks/a ks/b", ["kustomization/a", "kustomization/b"]),
    ("flux suspend gitrepo/a gitrepo/b", ["source-git/a", "source-git/b"]),
    ("flux reconcile kustomizations podinfo", ["kustomization/podinfo"]),
    ("flux reconcile helmreleases.helm.toolkit.fluxcd.io/podinfo", ["helmrelease/podinfo"]),
    ("flux suspend bucket b", ["source-bucket/b"]),
    # the kinds under a group word
    ("flux reconcile image repository podinfo", ["image-repository/podinfo"]),
    ("flux suspend image update u", ["image-update/u"]),
    ("flux reconcile artifact generator g", ["artifact-generator/g"]),
    ("flux create secret git s --url ssh://h/r", ["secret-git/s"]),
    ("flux create image policy p --image-ref r", ["image-policy/p"]),
    # words after "--" are names
    ("flux delete ks a -- -nprod", ["kustomization/a", "kustomization/-nprod"]),
])
def test_flux_reads_every_object(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


@pytest.mark.parametrize("command", [
    "flux suspend ks/a hr/b",  # flux refuses TYPE/NAME words of two types
    "flux suspend ks/a b",
    "flux reconcile alert/a",  # no reconcile for alerts in TYPE/NAME
    "flux suspend source foo a",
    "flux suspend widget a",
    "flux suspend ks",
])
def test_flux_refuses_what_it_cannot_read(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_flux_suspend_two_names_meets_a_rule_on_the_second():
    rule = _rule("flux", "kustomization/payments", ["stop"])
    assert _verdict([rule], "flux suspend ks web payments") == "BLOCK"
    assert _verdict([rule], "flux suspend ks/web ks/payments") == "BLOCK"


def test_flux_suspend_all_is_every_object_of_the_kind():
    intents = from_argv("flux suspend kustomization --all -n prod".split())
    assert [i.resource for i in intents] == ["kustomization/*"]
    assert intents[0].params["resolved_at_runtime"] == {"from": "kustomization/*",
                                                        "kinds": ["kustomization"]}
    rule = _rule("flux", "kustomization/payments", ["stop"])
    assert _verdict([rule], "flux suspend kustomization --all -n prod") == "ESCALATE"


def test_flux_with_source_reaches_the_source():
    command = "flux reconcile ks a --with-source"
    resources = [i.resource for i in from_argv(command.split())]
    assert resources == ["kustomization/a", "source-git/*", "source-oci/*", "source-bucket/*"]
    assert _verdict([_rule("flux", "source-git/*", ["sync"])], command) == "BLOCK"
    assert _verdict([_rule("flux", "source-git/infra", ["sync"])], command) == "ESCALATE"
    assert _verdict([_rule("flux", "source-git/*", ["sync"])], "flux reconcile ks a") == "ALLOW"


def test_flux_create_export_is_the_rehearsal():
    base = "flux create kustomization a --source=GitRepository/a --path=./k"
    assert from_argv(f"{base} --export".split())[0].params["dry_run"] is True
    assert "dry_run" not in from_argv(f"{base} --export --export=false".split())[0].params


# --- argocd --------------------------------------------------------------------------
# argo-cd v3.6 source (cmd/argocd/commands), not run.


@pytest.mark.parametrize("command,params", [
    # short words read letter by letter, as pflag does
    ("argocd app sync a -lteam=x", {"selector": "team=x"}),
    ("argocd app delete a -yl team=x", {"yes": True, "selector": "team=x"}),
    ("argocd app delete a -yp foreground", {"yes": True, "propagation_policy": "foreground"}),
    ("argocd app sync a -Nargocd", {"app_namespace": "argocd"}),
    ("argocd app create a --repo r --path p -lteam=x -pk=v", {"label": "team=x",
                                                             "parameter": "k=v"}),
    # a value flag takes the next word whatever it is
    ("argocd app sync a --revision -l", {"revision": "-l"}),
    ("argocd app set a --nameprefix -y", {"nameprefix": "-y"}),
])
def test_argocd_flags_are_read_as_pflag_reads_them(command, params):
    intent = from_argv(command.split())[0]
    assert intent.resource == "app/a"
    assert {k: v for k, v in intent.params.items() if k in params} == params


@pytest.mark.parametrize("command", [
    "argocd app sync a -qnprod",  # argocd has no -q
    "argocd app sync a --no-such-flag x",
    "argocd app delete --no-such-flag a",
    "argocd app sync a -x b",
])
def test_argocd_refuses_what_it_cannot_read(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,resources", [
    # sync and delete -l act on every app the selector picks; sync --project on every app
    # in the project, beside the apps named
    ("argocd app sync -l team=x", ["app/*"]),
    ("argocd app sync a -l team=x", ["app/a", "app/*"]),
    ("argocd app delete a -l team=x", ["app/a", "app/*"]),
    ("argocd app sync --project prod --project stage", ["app/*", "app/*"]),
    ("argocd app sync a b", ["app/a", "app/b"]),
    ("argocd app sync -- a b", ["app/a", "app/b"]),
])
def test_argocd_reads_the_apps_a_selector_or_project_picks(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


@pytest.mark.parametrize("command,verdict", [
    ("argocd app delete web -l team=x", "ESCALATE"),
    ("argocd app delete payments", "BLOCK"),
    ("argocd app delete web", "ALLOW"),
    ("argocd app sync -l team=x", "ALLOW"),  # the rule is on delete
])
def test_argocd_delete_by_selector_meets_a_rule_on_one_app(command, verdict):
    assert _verdict([_rule("argocd", "app/payments", ["delete"])], command) == verdict


def test_argocd_sync_by_project_meets_a_project_rule():
    rule = _rule("argocd", "app/*", ["sync"], {"project": "prod"})
    assert _verdict([rule], "argocd app sync web --project prod") == "BLOCK"
    assert _verdict([rule], "argocd app sync --project stage --project prod") == "BLOCK"
    assert _verdict([rule], "argocd app sync --project stage") == "ALLOW"


def test_argocd_dry_run_is_a_rehearsal_only_on_sync():
    assert from_argv("argocd app sync a --dry-run".split())[0].params["dry_run"] is True
    rule = _rule("argocd", "app/*", ["sync"])
    assert _verdict([rule], "argocd app sync a --dry-run") == "ALLOW"
    assert _verdict([rule], "argocd app sync a --dry-run --dry-run=false") == "BLOCK"


# --- git -----------------------------------------------------------------------------
# git's parse-options, from `git <verb> -h` on git 2.52; the push, commit and reset cases
# that change a verdict were also run with git 2.52 against a local bare repository.


@pytest.mark.parametrize("command,resources,params", [
    # bundled short options
    ("git push -fu origin main", ["ref/main"], {"force": True, "set_upstream": True}),
    ("git push -nf origin main", ["ref/main"], {"force": True, "dry_run": True}),
    # an unambiguous prefix of a long option is that option
    ("git push --force-w origin main", ["ref/main"], {"force": True}),
    ("git push --del origin old", ["ref/old"], {"delete": True}),
    ("git push --mirr origin", ["ref/*"], {"force": True, "unknown_target": True}),
    # the last spelling decides
    ("git push --no-force -f origin main", ["ref/main"], {"force": True}),
    ("git push -n --no-dry-run origin main", ["ref/main"], {}),
    ("git push --dry-run --no-dry origin main", ["ref/main"], {}),
    # a value option takes the next word whatever it is
    ("git push --repo -f origin main", ["ref/main"], {"repo": "-f"}),
    ("git push -o ci.skip origin main", ["ref/main"], {"push_option": "ci.skip"}),
    # an option that takes a value only after "=" leaves the next word alone
    ("git push --force-with-lease origin main", ["ref/main"], {"force": True}),
    ("git push --signed=yes origin main", ["ref/main"], {"signed": "yes"}),
    # every refspec is pushed
    ("git push origin safe +main", ["ref/safe", "ref/main"], {}),
    ("git push origin a :b", ["ref/a", "ref/b"], {}),
    ("git push origin -- main", ["ref/main"], {}),
    # a pattern refspec reaches every ref it matches
    ("git push origin +refs/heads/*:refs/heads/*", ["ref/*"],
     {"force": True, "unknown_target": True}),
])
def test_git_push_is_read_as_git_reads_it(command, resources, params):
    intents = from_argv(command.split())
    assert [i.resource for i in intents] == resources
    last = intents[-1].params
    assert {k: last.get(k) for k in params} == params
    for absent in ("force", "dry_run", "delete"):
        if absent not in params and resources == ["ref/main"]:
            assert absent not in last


@pytest.mark.parametrize("command,verdict", [
    ("git push -fu origin main", "BLOCK"),
    ("git push --force-w origin main", "BLOCK"),
    ("git push origin safe +main", "BLOCK"),
    ("git push --dry-run --no-dry -f origin main", "BLOCK"),
    ("git push -f -n origin main", "ALLOW"),
    ("git push origin +refs/heads/*:refs/heads/*", "ESCALATE"),
    ("git push origin main", "ALLOW"),
])
def test_git_force_push_rule_holds(command, verdict):
    store_rule = _rule("git", "ref/main", ["push"], {"force": True})
    assert _verdict([store_rule], command) == verdict


@pytest.mark.parametrize("command,resource,action", [
    ("git commit --amen -m x", "history/HEAD", "rewrite"),
    ("git commit -n --amend -m x", "history/HEAD", "rewrite"),  # -n is --no-verify here
    ("git commit --amend --no-amend -m x", "history/*", "read"),
    ("git commit -am x", "history/*", "read"),
    ("git reset --har HEAD~3", "history/HEAD~3", "rewrite"),
    ("git reset --ha HEAD", "history/HEAD", "rewrite"),
    ("git rebase -x make main", "history/main", "rewrite"),
])
def test_git_history_rewrites_are_read_as_git_reads_them(command, resource, action):
    intent = from_argv(command.split())[0]
    assert (intent.resource, intent.action) == (resource, action)
    assert "dry_run" not in intent.params


def test_git_commit_n_is_not_a_rehearsal():
    rule = _rule("git", "history/*", ["rewrite"])
    assert _verdict([rule], "git commit -n --amend -m x") == "BLOCK"
    assert _verdict([rule], "git commit --amen -m x") == "BLOCK"


@pytest.mark.parametrize("command,resources", [
    ("git branch -D a b", ["branch/a", "branch/b"]),
    ("git branch -d a -- b", ["branch/a", "branch/b"]),
    ("git tag -d v1 v2", ["tag/v1", "tag/v2"]),
    ("git rebase main feature", ["history/main", "history/feature"]),
    ("git filter-repo --path src", ["history/*"]),
])
def test_git_reads_every_target(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


def test_git_branch_delete_of_two_meets_a_rule_on_the_second():
    assert _verdict([_rule("git", "branch/main", ["delete"])], "git branch -D old main") == \
        "BLOCK"


@pytest.mark.parametrize("command", [
    "git push --forc origin main",  # force, force-with-lease and force-if-includes
    "git push --no-such-option origin main",
    "git push -x origin main",
    "git commit --amend=yes -m x",  # --amend takes no value
])
def test_git_refuses_what_git_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())
