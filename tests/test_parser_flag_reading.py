"""Flags the parser reads as each tool's own parser does (#80 and the sweep after it).

A flag that takes a value takes the next word whatever it looks like, so each tool has a
table of its flags, read from its source, and a flag in no table is refused unless
``=value`` or its place at the end shows how the tool would read it. Words after ``--``
are operands. Behaviour comes from each tool's source unless a test says it was run."""

import shlex
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
    ("helm upgrade --wait api ./c", "api", {"wait": "watcher", "chart": "./c"}),
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
    with pytest.raises(ValueError, match="cannot tell whether|not a short flag"):
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
    with pytest.raises(ValueError, match="cannot tell whether|not a short flag"):
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
    ("argocd app create a --repo r --path p -lteam=x -pk=v", {"label": ["team=x"],
                                                             "parameter": ["k=v"]}),
    # a value flag takes the next word whatever it is
    ("argocd app sync a --revision -l", {"revision": "-l"}),
    ("argocd app set a --nameprefix -y", {"nameprefix": "-y"}),
])
def test_argocd_flags_are_read_as_pflag_reads_them(command, params):
    intents = from_argv(command.split())
    assert intents[0].resource == "app/a"
    # a selector is read onto the apps it picks (app/*), never the app named
    got = {k: v for i in intents for k, v in i.params.items() if k in params}
    assert got == params


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
    ("git push --mirr origin", ["ref/*", "ref/*"], {"force": True, "unknown_target": True}),
    # the last spelling decides
    ("git push --no-force -f origin main", ["ref/main"], {"force": True}),
    ("git push -n --no-dry-run origin main", ["ref/main"], {}),
    ("git push --dry-run --no-dry origin main", ["ref/main"], {}),
    # a value option takes the next word whatever it is
    ("git push --repo -f origin main", ["ref/main"], {"repo": "-f"}),
    ("git push -o ci.skip origin main", ["ref/main"], {"push_option": ["ci.skip"]}),
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
    intents = [i for i in from_argv(command.split()) if i.resource != "tag/*"]
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
    ("git commit --amend --no-amend -m x", "history/*", "commit"),
    ("git commit -am x", "history/*", "commit"),
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


# --- aws -----------------------------------------------------------------------------
# Each spelling below was run with aws-cli 2.37 against a closed local port, with fake
# keys, and the request it built (operation, parameters, region) was read from --debug.


@pytest.mark.parametrize("command,resources,region", [
    # argparse reads the global options first and takes a prefix of one
    ("aws ec2 terminate-instances --instance-ids i-1 --regio us-west-1",
     ["ec2/instance/i-1"], "us-west-1"),
    ("aws --reg us-west-2 ec2 terminate-instances --instance-ids i-1",
     ["ec2/instance/i-1"], "us-west-2"),
    ("aws s3 rm s3://bucket-a/x --re us-west-2", ["s3/bucket/bucket-a"], "us-west-2"),
    # and a prefix of an operation's option, here the one that names the target
    ("aws ec2 terminate-instances --instance-id i-1 i-2",
     ["ec2/instance/i-1", "ec2/instance/i-2"], None),
    ("aws ec2 terminate-instances --instance i-1 i-2",
     ["ec2/instance/i-1", "ec2/instance/i-2"], None),
    ("aws iam delete-role --role prod-admin", ["iam/role/prod-admin"], None),
    ("aws lambda delete-function --function prod-fn", ["lambda/function/prod-fn"], None),
    ("aws ec2 delete-volume --vol vol-1", ["ec2/volume/vol-1"], None),
    ("aws s3api delete-bucket --buck prod-b", ["s3/bucket/prod-b"], None),
    ("aws eks delete-nodegroup --cluster-name c --nodegroup ng-1", ["eks/nodegroup/ng-1"],
     None),
    # a full flag that names the target wins over a prefix of another
    ("aws lambda create-function --function-name f --role arn:r --runtime python3.12",
     ["lambda/function/f"], None),
])
def test_aws_reads_prefixes_as_argparse_does(command, resources, region):
    intents = from_argv(command.split())
    assert [i.resource for i in intents] == resources
    assert all(i.metadata.get("region") == region for i in intents)


@pytest.mark.parametrize("command,verdict", [
    ("aws ec2 terminate-instances --instance-ids i-1 --regio us-west-1", "BLOCK"),
    ("aws ec2 terminate-instances --instance-ids i-1 --region us-east-1", "ALLOW"),
    ("aws --reg us-west-1 ec2 terminate-instances --instance-ids i-1", "BLOCK"),
])
def test_an_aws_region_rule_holds_on_an_abbreviated_region(command, verdict):
    rule = _rule("aws", "ec2/instance/*", ["delete"], {"region": "us-west-1"})
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-id prod-1 i-2",
    "aws ec2 terminate-instances --instance i-2 prod-1",
])
def test_an_abbreviated_instance_list_meets_a_rule_on_each(command):
    assert _verdict([_rule("aws", "ec2/instance/prod-1", ["delete"])], command) == "BLOCK"


@pytest.mark.parametrize("command,dry_run", [
    ("aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-d", False),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-dry", False),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry-run", True),
    ("aws s3 rm s3://bucket-a/x --dryrun", True),
])
def test_aws_rehearsals(command, dry_run):
    assert from_argv(command.split())[0].params.get("dry_run", False) is dry_run


@pytest.mark.parametrize("command,targets", [
    # the s3 commands' own options: --recursive takes no value
    ("aws s3 rm --recursive s3://bucket-a", [("s3/bucket/bucket-a", "delete")]),
    ("aws s3 cp --recursive ./d s3://bucket-b/", [("s3/bucket/bucket-b", "put")]),
    # every s3 path: cp writes the destination, mv also deletes its source
    ("aws s3 cp s3://bucket-a/x s3://bucket-b/x",
     [("s3/bucket/bucket-a", "put"), ("s3/bucket/bucket-b", "put")]),
    ("aws s3 mv s3://bucket-a/x s3://bucket-b/x",
     [("s3/bucket/bucket-a", "put"), ("s3/bucket/bucket-b", "put"),
      ("s3/bucket/bucket-a", "delete")]),
    ("aws s3 sync ./d s3://bucket-b --delete",
     [("s3/bucket/bucket-b", "put"), ("s3/bucket/bucket-b", "delete")]),
])
def test_aws_s3_reads_every_path(command, targets):
    assert [(i.resource, i.action) for i in from_argv(command.split())] == targets


def test_aws_s3_copy_meets_a_rule_on_the_destination():
    rule = _rule("aws", "s3/bucket/prod", ["put"])
    assert _verdict([rule], "aws s3 cp s3://staging/x s3://prod/x") == "BLOCK"
    assert _verdict([_rule("aws", "s3/bucket/staging", ["delete"])],
                    "aws s3 mv s3://staging/x s3://prod/x") == "BLOCK"


def test_aws_cli_input_json_target_is_read():
    # B4: inline input is read into the options it stands for (run on aws 2.37)
    command = ["aws", "ec2", "terminate-instances", "--cli-input-json",
               '{"InstanceIds":["i-9"]}']
    intent = from_argv(command)[0]
    assert intent.resource == "ec2/instance/i-9"
    assert "resolved_at_runtime" not in intent.params
    assert _verdict([_rule("aws", "ec2/instance/i-9", ["delete"])], command) == "BLOCK"
    # a flag that names the target wins over the input, as in aws
    named = command[:3] + ["--instance-ids", "i-1"] + command[3:]
    assert _verdict([_rule("aws", "ec2/instance/i-9", ["delete"])], named) == "ALLOW"


def test_aws_cli_input_in_a_file_leaves_target_and_options_unknown():
    command = "aws ec2 terminate-instances --cli-input-json file://in.json"
    intent = from_argv(command.split())[0]
    assert intent.resource == "ec2/instance/*"
    assert _verdict([_rule("aws", "ec2/instance/i-9", ["delete"])], command) == "ESCALATE"


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-ids i-1 --no",  # ambiguous global prefix
    "aws ec2 terminate-instances --instance-ids i-1 -- i-2",  # aws refuses words after --
])
def test_aws_refuses_what_aws_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


# --- az ------------------------------------------------------------------------------
# azure-cli parses with Python's argparse (knack and azure-cli-core leave its defaults),
# from source; az was not run.


@pytest.mark.parametrize("command,resource,metadata,params", [
    # argparse reads -nNAME, -n=NAME and bundled -y as Python reads them
    ("az vm delete -nprod-vm -grg --yes", "compute/vm/prod-vm", {"resource_group": "rg"},
     {"yes": True}),
    ("az vm delete -n=prod-vm -g rg -y", "compute/vm/prod-vm", {"resource_group": "rg"},
     {"yes": True}),
    ("az vm delete -ynprod-vm -g rg", "compute/vm/prod-vm", {"resource_group": "rg"},
     {"yes": True}),
    ("az vm create -n v -g rg -lwestus", "compute/vm/v", {"resource_group": "rg",
                                                         "region": "westus"}, {}),
    ("az sql db delete -sserver -n db -g rg", "sql/db/db", {"resource_group": "rg"},
     {"server": "server"}),
    ("az ad user delete --id x", "iam/user/*", {}, {"id": "x"}),
    # a letter that only ever takes a value (or is a three-state flag) takes the rest
    ("az sql db delete -snprod -g rg -n db", "sql/db/db", {"resource_group": "rg"},
     {"server": "nprod"}),
    # -c is a boolean on one command, but no reading reaches an n, g or l: m, y, c and then
    # o, which takes "ntainer"
    ("az storage container delete -cmycontainer -n x", "storage/container/x", {},
     {"container-name": "mycontainer"}),
])
def test_az_short_words(command, resource, metadata, params):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource
    assert intent.metadata == metadata
    assert {k: v for k, v in intent.params.items() if k in params} == params


@pytest.mark.parametrize("command", [
    # a prefix of --name, --resource-group, --location, --subscription or --ids
    "az vm delete --na prod-vm -g rg",
    "az vm delete -n prod-vm --resource-gr rg",
    "az group delete --n prod",
    "az vm create -n v -g rg --loc westus",
    # -d is a boolean on some commands (vm show -d), and then -n takes "prod"
    "az vm show -dnprod -g rg",
    # no az command has -A
    "az vm delete -Anprod -g rg",
    "az vm delete -n x -g rg -- y",
])
def test_az_refuses_what_it_cannot_read(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_an_az_name_rule_holds_on_a_glued_name():
    rule = _rule("azure", "compute/vm/prod-vm", ["delete"])
    assert _verdict([rule], "az vm delete -nprod-vm -g rg --yes") == "BLOCK"
    assert _verdict([rule], "az vm delete -ynprod-vm -g rg") == "BLOCK"


# --- gcloud and gsutil ---------------------------------------------------------------
# gcloud's calliope turns off argparse's prefixes (parser_extensions.py); from source,
# gcloud was not run.


@pytest.mark.parametrize("command,resources", [
    # every name is a target
    ("gcloud compute instances delete a b --zone us-east1-b",
     ["compute/instance/a", "compute/instance/b"]),
    # a --no- flag takes no value, so the word after it is the name
    ("gcloud compute instances delete --no-graceful-shutdown web-1",
     ["compute/instance/web-1"]),
    # a flag the table has takes its value; the word after that is the name
    ("gcloud compute instances delete --keep-disks boot web-1", ["compute/instance/web-1"]),
    ("gcloud compute networks delete web-1 --some-flag=x prod-1",
     ["compute/network/web-1", "compute/network/prod-1"]),
    ("gcloud compute instances create web --machine-type e2-small",
     ["compute/instance/web"]),
    ("gcloud sql import sql prod-db gs://b/f.sql", ["sql/instance/prod-db"]),
    ("gcloud projects set-iam-policy p1 policy.json", ["project/project/p1"]),
    # storage reads its own booleans and every path
    ("gcloud storage rm --recursive gs://a gs://b",
     ["storage/bucket/a", "storage/bucket/b"]),
    ("gsutil -m rm -r gs://b", ["storage/bucket/b"]),
    ("gsutil rm -rf gs://a gs://b", ["storage/bucket/a", "storage/bucket/b"]),
])
def test_gcloud_reads_every_target(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


def test_gcloud_words_after_dashes_go_to_the_command_it_runs():
    intent = from_argv("gcloud compute ssh vm -- rm -rf /".split())[0]
    assert intent.params["passthrough"] == ["rm", "-rf", "/"]


@pytest.mark.parametrize("command,verdict", [
    ("gcloud compute instances delete web-1 prod-1", "BLOCK"),
    ("gcloud compute instances delete --no-graceful-shutdown prod-1", "BLOCK"),
    ("gcloud storage rm --recursive gs://logs gs://prod-1", None),
    ("gcloud compute instances delete web-1", "ALLOW"),
])
def test_gcloud_rule_on_one_name_holds(command, verdict):
    rule = _rule("gcp", "compute/instance/prod-1", ["delete"])
    if verdict is None:
        rule = _rule("gcp", "storage/bucket/prod-1", ["delete"])
        verdict = "BLOCK"
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command", [
    # a command outside the reference table: an unknown flag followed by a word is its
    # value, or a boolean and then a name
    "gcloud compute networks delete web-1 --graceful prod-1",
    "gcloud compute networks delete --unknown-flag web-1",
    "gcloud beta compute instances delete --unknown-flag web-1",
    # the word may be the command's first: which command it is, is not known
    "gcloud --unknown-global x compute instances delete web-1",
])
def test_gcloud_refuses_an_unknown_flag_before_a_word(command):
    with pytest.raises(ValueError, match="cannot tell whether"):
        from_argv(command.split())


@pytest.mark.parametrize("command", [
    # a command in the reference table: a flag it does not have, gcloud refuses
    "gcloud compute instances delete web-1 --graceful prod-1",
    "gcloud compute instances delete --unknown-flag web-1",
    "gcloud compute instances delete web-1 --unknown-flag",
    "gcloud storage rm --unknown-flag x gs://b",
])
def test_gcloud_refuses_a_flag_the_command_does_not_have(command):
    with pytest.raises(ValueError, match="not a flag of this command"):
        from_argv(command.split())


@pytest.mark.parametrize("command,resources", [
    ("gcloud compute networks delete web-1 --unknown-flag", ["compute/network/web-1"]),
    ("gcloud compute networks delete web-1 --unknown-flag --project p",
     ["compute/network/web-1"]),
    ("gcloud beta storage rm --unknown-flag x gs://b", ["storage/bucket/b"]),
])
def test_gcloud_unknown_flags_that_cannot_hide_a_name_are_kept(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


def test_gsutil_refuses_an_option_it_does_not_know():
    with pytest.raises(ValueError):
        from_argv("gsutil rm -x gs://b".split())


# --- terraform and tofu --------------------------------------------------------------
# Go's flag package; -destroy=T and -destroy=yes were run with terraform 1.x in an empty
# directory (destroy mode, and refused).


@pytest.mark.parametrize("command,destroy,auto_approve", [
    ("terraform apply -destroy", True, False),
    ("terraform apply --destroy -auto-approve", True, True),
    ("terraform apply -destroy=true", True, False),
    ("terraform apply -destroy=T --auto-approve=true", True, True),
    ("terraform apply -destroy -destroy=false", False, False),
    ("tofu destroy -auto-approve=false", True, False),
    ("terraform destroy --auto-approve", True, True),
])
def test_terraform_reads_go_booleans(command, destroy, auto_approve):
    if not destroy:
        with pytest.raises(ValueError, match="plan"):
            from_argv(command.split())
        return
    intent = from_argv(command.split())[0]
    assert (intent.resource, intent.action) == ("workspace/current", "delete")
    assert intent.params["auto_approve"] is auto_approve


# --- gh ------------------------------------------------------------------------------
# cli/cli v2.103 source (pkg/cmd), not run.


@pytest.mark.parametrize("command,resource,action,params", [
    # a boolean takes no value, so the word after it is the target
    ("gh pr merge -s 42", "pr/42", "merge", {"method": "squash"}),
    ("gh pr merge -r 42", "pr/42", "merge", {"method": "rebase"}),  # -r is --rebase here
    ("gh pr merge -sd 42", "pr/42", "merge", {"method": "squash", "delete_branch": True}),
    ("gh repo delete --yes owner/repo", "repo/owner/repo", "delete", {"yes": True}),
    ("gh release delete -y v1", "release/v1", "delete", {"yes": True}),
    ("gh pr close -c bye 42", "pr/42", "stop", {"comment": "bye"}),
    # a short word carries its value
    ("gh api -XDELETE repos/o/r", "repo/o/r", "delete", {}),
])
def test_gh_reads_its_flags_as_pflag_does(command, resource, action, params):
    intent = from_argv(command.split())[0]
    assert (intent.resource, intent.action) == (resource, action)
    assert {k: v for k, v in intent.params.items() if k in params} == params


def test_gh_workflow_run_r_is_the_ref():
    intent = from_argv("gh workflow run deploy.yml -r main -f env=prod".split())[0]
    assert intent.metadata == {"ref": "main"}
    assert intent.params["inputs"] == {"env": "prod"}


@pytest.mark.parametrize("command,verdict", [
    ("gh repo delete --yes owner/repo", "BLOCK"),
    ("gh api -XDELETE repos/owner/repo", "BLOCK"),
    ("gh repo delete --yes owner/other", "ALLOW"),
])
def test_gh_repo_delete_rule_holds(command, verdict):
    assert _verdict([_rule("github", "repo/owner/repo", ["delete"])], command) == verdict


@pytest.mark.parametrize("command", [
    "gh pr merge 42 --no-such-flag x",
    "gh repo delete --no-such-flag owner/repo",
    "gh pr merge -x 42",
])
def test_gh_refuses_a_flag_it_cannot_place(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


# --- flux's namespace when no -n is given ---------------------------------------------
# flux2 main.go: flux-system, or $FLUX_SYSTEM_NAMESPACE, or with --ns-follows-kube-context
# or $FLUX_NS_FOLLOWS_KUBE_CONTEXT the kubeconfig context's namespace. The argv shows none
# of these variables, so the namespace is unresolved, as it is for kubectl.


def _flux_verdict(rule: Constraint, command: str, environ: dict | None = None,
                  home=None) -> tuple[str, list[str]]:
    from aegis_core.environments import resolve_current_context

    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    store.add_constraint(rule)
    interceptor = AegisInterceptor(store)
    decisions = []
    for intent in from_argv(command.split()):
        if environ is not None:
            resolve_current_context(intent, environ=environ, home=home)
        decisions.append(interceptor.intercept(intent, now=NOW))
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    worst = max(decisions, key=lambda d: order[d.verdict])
    return worst.verdict, sorted({n for d in decisions for n in d.notes})


PROD_SUSPEND = _rule("flux", "kustomization/*", ["stop"], {"namespace": "prod"}, cid="prod")


@pytest.mark.parametrize("command,verdict", [
    ("flux suspend ks a", "ESCALATE"),
    ("flux suspend ks a --ns-follows-kube-context", "ESCALATE"),
    ("flux suspend ks a -n prod", "BLOCK"),
    ("flux suspend ks a -n dev", "ALLOW"),
    ("flux suspend ks a -n prod --ns-follows-kube-context", "BLOCK"),  # -n wins
])
def test_a_flux_namespace_rule_escalates_without_a_namespace(command, verdict):
    got, notes = _flux_verdict(PROD_SUSPEND, command)
    assert got == verdict
    if verdict == "ESCALATE":
        assert "namespace-unresolved: prod" in notes


def _kubeconfig(tmp_path, namespace: str | None) -> dict:
    ns = f", namespace: {namespace}" if namespace else ""
    path = tmp_path / "config"
    path.write_text("apiVersion: v1\nkind: Config\ncurrent-context: ctx\ncontexts:\n"
                    f"- name: ctx\n  context: {{cluster: c, user: u{ns}}}\n")
    return {"KUBECONFIG": str(path)}


@pytest.mark.parametrize("extra_env,flag,namespace,verdict", [
    ({}, "", None, "ALLOW"),  # flux-system
    ({"FLUX_SYSTEM_NAMESPACE": "prod"}, "", None, "BLOCK"),
    ({"FLUX_SYSTEM_NAMESPACE": "Not_A_Label"}, "", None, "ALLOW"),  # flux ignores it
    ({}, "--ns-follows-kube-context", "prod", "BLOCK"),
    ({"FLUX_NS_FOLLOWS_KUBE_CONTEXT": "1"}, "", "prod", "BLOCK"),
    ({"FLUX_NS_FOLLOWS_KUBE_CONTEXT": "1"}, "", None, "ALLOW"),  # context sets none
    ({"FLUX_NS_FOLLOWS_KUBE_CONTEXT": "1", "FLUX_SYSTEM_NAMESPACE": "prod"}, "", None,
     "BLOCK"),
])
def test_resolve_current_context_picks_the_namespace_flux_uses(
        tmp_path, extra_env, flag, namespace, verdict):
    environ = {**_kubeconfig(tmp_path, namespace), **extra_env}
    command = f"flux suspend ks a {flag}".strip()
    assert _flux_verdict(PROD_SUSPEND, command, environ, tmp_path)[0] == verdict


def test_an_inline_follow_variable_is_seen_by_the_hook():
    from aegis_core.shell import intents_from_command

    intents = intents_from_command("FLUX_NS_FOLLOWS_KUBE_CONTEXT=1 flux suspend ks a")
    assert intents[0].params["namespace_follows_kubeconfig"] is True


@pytest.mark.parametrize("command,resources", [
    # argparse reads a prefix of the flag that named the target as that flag, and keeps
    # the last value, as aws reads it (run with aws 2.37: DeleteRole b, TerminateInstances
    # i-2 i-3): each abbreviation is resolved to its option against the operation's list
    ("aws iam delete-role --role-name a --role b", ["iam/role/b"]),
    ("aws iam delete-role --role b --role-name a", ["iam/role/a"]),
    ("aws ec2 terminate-instances --instance-ids i-1 --instance i-2 i-3",
     ["ec2/instance/i-2", "ec2/instance/i-3"]),
    ("aws eks delete-nodegroup --cluster-name c --nodegroup-name ng-1 --nodegroup ng-2",
     ["eks/nodegroup/ng-2"]),
    ("aws s3api delete-object --bucket a --buck b --key k", ["s3/object/b/k"]),
    # a prefix of another flag than the one that named the target adds nothing
    ("aws lambda create-function --function-name f --role arn:r --runtime python3.12",
     ["lambda/function/f"]),
])
def test_aws_abbreviation_is_the_option_aws_resolves(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


def test_aws_rule_on_the_abbreviated_name_holds():
    assert _verdict([_rule("aws", "iam/role/b", ["delete"])],
                    "aws iam delete-role --role-name a --role b") == "BLOCK"


# --- git branch rename, copy and force (run with git 2.52 in a scratch repository) ----


@pytest.mark.parametrize("command,targets", [
    ("git branch -m old new", [("branch/new", "create"), ("branch/old", "delete")]),
    ("git branch -M feature main",
     [("branch/main", "create"), ("branch/main", "delete"), ("branch/feature", "delete")]),
    ("git branch --move --force a b",
     [("branch/b", "create"), ("branch/b", "delete"), ("branch/a", "delete")]),
    # one name renames the current branch, which the argv does not show
    ("git branch -m new", [("branch/new", "create"), ("branch/*", "delete")]),
    ("git branch -c a b", [("branch/b", "create")]),
    ("git branch -C a main", [("branch/main", "create"), ("branch/main", "delete")]),
    # -f resets an existing branch
    ("git branch -f main HEAD~3",
     [("branch/main", "create"), ("branch/main", "update"), ("branch/main", "delete")]),
    ("git branch side", [("branch/side", "create")]),
])
def test_git_branch_rename_copy_and_force(command, targets):
    assert [(i.resource, i.action) for i in from_argv(command.split())] == targets


@pytest.mark.parametrize("command,verdict", [
    ("git branch -m main old-main", "BLOCK"),
    ("git branch -M feature main", "BLOCK"),
    ("git branch -C feature main", "BLOCK"),
    ("git branch -f main HEAD~3", "BLOCK"),
    ("git branch -m new-name", "ESCALATE"),  # the current branch may be main
    ("git branch -c main copy", "ALLOW"),
])
def test_a_rule_against_deleting_main_holds_on_renames(command, verdict):
    assert _verdict([_rule("git", "branch/main", ["delete"])], command) == verdict


def test_git_branch_rename_takes_at_most_two_names():
    with pytest.raises(ValueError):
        from_argv("git branch -m a b c".split())


# --- helm values a rule can read, and kubectl create deployment --port ---------------


@pytest.mark.parametrize("flags,verdict", [
    ("--set replicaCount=0", "BLOCK"),
    ("--set-json replicaCount=0", "BLOCK"),  # read as JSON, before --set
    (["--set-json", '{"replicaCount": 0}'], "BLOCK"),
    ("--set-json replicaCount=0 --set replicaCount=3", "ALLOW"),  # --set comes after
    ("--set replicaCount=3", "ALLOW"),
    # a file nobody read: its key, or any key the command line leaves to it
    ("--set replicaCount=3 --set-file replicaCount=r.txt", "ESCALATE"),
    ("--set-file replicaCount=r.txt --set-literal replicaCount=3", "ALLOW"),
    ("-f values.yaml", "ESCALATE"),
    ("-f values.yaml --set replicaCount=3", "ALLOW"),
    ("--reuse-values", "ESCALATE"),
])
def test_a_helm_values_rule_sees_every_way_the_value_is_set(flags, verdict):
    rule = _rule("helm", "release/*", ["update"], {"set.replicaCount": 0})
    extra = flags.split() if isinstance(flags, str) else flags
    assert _verdict([rule], ["helm", "upgrade", "api", "./c", *extra]) == verdict


def test_helm_set_json_refuses_what_helm_refuses():
    with pytest.raises(ValueError):
        from_argv(["helm", "upgrade", "api", "./c", "--set-json", "a=notjson"])


@pytest.mark.parametrize("flags,port", [
    # create deployment's --port is an Int32 read with base 0 (run on kubectl 1.36)
    ("--port=0x50", 80), ("--port 80", 80),
])
def test_create_deployment_port_is_read_as_kubectl_reads_it(flags, port):
    intent = from_argv(f"kubectl create deployment web --image=x {flags}".split())[0]
    assert intent.params["port"] == port


def test_create_deployment_refuses_a_port_kubectl_refuses():
    with pytest.raises(ValueError):
        from_argv("kubectl create deployment web --image=x --port=080".split())


# --- helm values as one nested map (helm's pkg/strvals) ---------------------------------


@pytest.mark.parametrize("flags,expected", [
    # every kind gives the nested map helm gives the chart
    (["--set-json", 'securityContext={"privileged":true}'],
     {"securityContext": {"privileged": True}}),
    (["--set", "securityContext.privileged=true"], {"securityContext": {"privileged": True}}),
    (["--set-string", "a.b=1"], {"a": {"b": "1"}}),
    (["--set-literal", "a.b=x,y=z"], {"a": {"b": "x,y=z"}}),
    # --set-json is merged first whatever its place, then --set into the same map
    (["--set", "a.b=1", "--set-json", 'a={"c":2}'], {"a": {"c": 2, "b": 1}}),
    (["--set-json", '{"a":{"c":2}}', "--set", "a.b=1"], {"a": {"c": 2, "b": 1}}),
    # a later scalar replaces an earlier map
    (["--set", "a.b=2", "--set", "a=1"], {"a": 1}),
    (["--set", "a.b=2,a=1"], {"a": 1}),
    # --set-json is read before --set, and --set-string after --set
    (["--set", "a=1", "--set-json", "a={}"], {"a": 1}),
    (["--set-string", "n=1", "--set", "n=2"], {"n": "1"}),
    # helm's typing: no floats, a leading zero stays text, null is null
    (["--set", "f=1.5,n=010,m=+5,z=null,t=TRUE"],
     {"f": "1.5", "n": "010", "m": 5, "z": None, "t": True}),
    (["--set", "l={a,b},x[1]=y"], {"l": ["a", "b"], "x": [None, "y"]}),
])
def test_helm_values_are_one_nested_map(flags, expected):
    assert from_helm(["helm", "upgrade", "api", "./c", *flags]).params["set"] == expected


def test_helm_refuses_a_map_under_a_scalar_set_by_set():
    # helm's strvals panics on it and reports an error
    with pytest.raises(ValueError):
        from_helm("helm upgrade api ./c --set a=1 --set a.b=2".split())


@pytest.mark.parametrize("flags,verdict", [
    (["--set-json", 'securityContext={"privileged":true}'], "BLOCK"),
    (["--set", "securityContext.privileged=true"], "BLOCK"),
    (["--set-json", '{"securityContext":{"privileged":true}}'], "BLOCK"),
    (["--set", "securityContext.privileged=false"], "ALLOW"),
    (["--set-file", "securityContext.privileged=p.txt"], "ESCALATE"),
])
def test_a_nested_helm_values_rule_holds(flags, verdict):
    rule = _rule("helm", "release/*", ["update"],
                 {"namespace": "prod", "set.securityContext.privileged": True})
    command = ["helm", "upgrade", "api", "./c", "-n", "prod", *flags]
    assert _verdict([rule], command) == verdict


def test_a_scope_key_with_dots_in_one_level_is_found():
    from aegis_core.store import scope_matches
    assert scope_matches({"labels.app.kubernetes.io/name": "x"}, {},
                         {"labels": {"app.kubernetes.io/name": "x"}})


# --- aws: a prefix of any s3 option and of --dry-run (run with aws-cli 2.37) -----------


@pytest.mark.parametrize("command,targets,dry_run", [
    ("aws s3 sync ./empty s3://prod --del",
     [("s3/bucket/prod", "put"), ("s3/bucket/prod", "delete")], False),
    ("aws s3 rm s3://b/x --dryr", [("s3/bucket/b", "delete")], True),
    ("aws s3 rm --rec s3://b", [("s3/bucket/b", "delete")], False),
    ("aws s3 cp --rec s3://a s3://b", [("s3/bucket/a", "put"), ("s3/bucket/b", "put")], False),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry", [("ec2/instance/i-1", "delete")],
     True),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry --no-dry",
     [("ec2/instance/i-1", "delete")], False),
])
def test_aws_reads_every_option_prefix(command, targets, dry_run):
    intents = from_argv(command.split())
    assert [(i.resource, i.action) for i in intents] == targets
    assert all(i.params.get("dry_run", False) is dry_run for i in intents)


@pytest.mark.parametrize("command", [
    "aws s3 cp ./x s3://b/x --del",  # cp has no --delete
    "aws s3 cp ./x s3://b/ --ex x",  # exclude, expires, expected-size
])
def test_aws_s3_refuses_what_aws_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_aws_dry_prefix_is_not_a_rehearsal_where_another_option_starts_with_dry():
    # synthetics update-canary has --dry-run-id and no --dry-run
    intent = from_argv("aws synthetics update-canary --name c --dry x".split())[0]
    assert "dry_run" not in intent.params


def test_aws_sync_del_meets_a_delete_rule():
    assert _verdict([_rule("aws", "s3/bucket/prod", ["delete"])],
                    "aws s3 sync ./empty s3://prod --del") == "BLOCK"


# --- gh api's method, and the repository gh acts on (cli v2.103 api.go) -----------------


@pytest.mark.parametrize("command,resource,action,method", [
    # fields or a body without -X make gh send POST
    ("gh api repos/o/r/actions/workflows/deploy.yml/dispatches -f ref=main",
     "workflow/deploy.yml", "run", "post"),
    ("gh api repos/o/r/actions/workflows/deploy.yml/dispatches -F ref=main",
     "workflow/deploy.yml", "run", "post"),
    ("gh api repos/o/r/releases --input body.json", "release/*", "create", "post"),
    ("gh api repos/o/r/releases --raw-field tag_name=v1", "release/*", "create", "post"),
    # -X wins
    ("gh api repos/o/r/actions/workflows/deploy.yml/dispatches -X GET -f ref=main",
     "api/repos/o/r/actions/workflows/deploy.yml/dispatches", "read", "get"),
    ("gh api -Xdelete repos/o/r", "repo/o/r", "delete", "delete"),
    ("gh api --method=DELETE repos/o/r", "repo/o/r", "delete", "delete"),
    ("gh api repos/o/r", "api/repos/o/r", "read", "get"),
])
def test_gh_api_method_is_the_one_gh_sends(command, resource, action, method):
    intent = from_argv(command.split())[0]
    assert (intent.resource, intent.action) == (resource, action)
    assert intent.params["raw_action"] == f"api-{method}"


def test_gh_api_dispatch_without_x_meets_a_workflow_rule():
    rule = _rule("github", "workflow/deploy.yml", ["run"])
    assert _verdict([rule], "gh api repos/o/r/actions/workflows/deploy.yml/dispatches "
                            "-f ref=main") == "BLOCK"


@pytest.mark.parametrize("command,verdict", [
    # the repository comes from the current directory or $GH_REPO
    ("gh api repos/{owner}/{repo} -X DELETE", "ESCALATE"),
    ("gh repo delete --yes", "ESCALATE"),
    ("gh workflow run deploy.yml", "ESCALATE"),
    ("gh workflow run deploy.yml -R acme/web", "BLOCK"),
    ("gh workflow run deploy.yml -R acme/other", "ALLOW"),
    ("gh api repos/acme/web/actions/workflows/deploy.yml/dispatches -f ref=main", "BLOCK"),
])
def test_a_repository_rule_escalates_when_gh_picks_the_repository(command, verdict):
    rule = _rule("github", "*", ["run", "delete"], {"repo": "acme/web"})
    assert _verdict([rule], command) == verdict


def test_gh_repo_resolves_from_gh_repo():
    from aegis_core.environments import resolve_current_context
    from aegis_core.store import scope_unresolved

    intent = from_argv("gh workflow run deploy.yml".split())[0]
    resolve_current_context(intent, environ={"GH_REPO": "github.com/acme/web"})
    assert intent.metadata["repo"] == "acme/web"
    assert scope_unresolved({"repo": "acme/web"}, intent) == []


# --- git push: refs the argv does not name ----------------------------------------------


@pytest.mark.parametrize("command,targets", [
    ("git push origin main --follow-tags", [("ref/main", "push"), ("ref/*", "push")]),
    ("git -c push.followTags=true push origin main", [("ref/main", "push"), ("ref/*", "push")]),
    ("git -c push.followTags push origin main", [("ref/main", "push"), ("ref/*", "push")]),
    ("git -c push.followTags=true push origin main --no-follow-tags", [("ref/main", "push")]),
    ("git -c push.followTags=false push origin main", [("ref/main", "push")]),
    ("git push origin main --tags", [("ref/main", "push"), ("ref/*", "push")]),
    ("git push origin HEAD", [("ref/*", "push")]),
    ("git push origin :", [("ref/*", "push")]),  # matching branches, not a delete
    ("git push origin", [("ref/*", "push")]),
    ("git push --all origin", [("ref/*", "push")]),
    ("git push --mirror origin", [("ref/*", "push"), ("ref/*", "delete")]),
    ("git -c remote.origin.mirror=true push origin", [("ref/*", "push"), ("ref/*", "delete")]),
    ("git push --prune origin main", [("ref/main", "push"), ("ref/*", "delete")]),
    ("git push origin :old", [("ref/old", "delete")]),
    ("git push --delete origin a b", [("ref/a", "delete"), ("ref/b", "delete")]),
    ("git push origin main --atomic", [("ref/main", "push")]),
])
def test_git_push_marks_every_ref_the_argv_does_not_name(command, targets):
    intents = [i for i in from_argv(command.split())
               if i.resource != "tag/*" and ("resolved_at_runtime" not in i.params
                                             or i.params["resolved_at_runtime"].get(
                                                 "destination"))]
    assert [(i.resource, i.action) for i in intents] == targets
    for intent in intents:
        assert (intent.resource == "ref/*") == (intent.params.get("unknown_target") is True)


@pytest.mark.parametrize("command", [
    "git push origin main --follow-tags",
    "git -c push.followTags=true push origin main",
    "git push origin HEAD",
])
def test_a_tag_rule_escalates_on_tags_the_argv_does_not_name(command):
    assert _verdict([_rule("git", "ref/v1.0", ["push"])], command) == "ESCALATE"


# --- gcloud storage and gsutil moves, and gcloud create commands with a space --------


@pytest.mark.parametrize("command,deleted", [
    ("gcloud storage mv gs://staging/a gs://prod/b gs://archive/",
     ["storage/bucket/staging", "storage/bucket/prod"]),
    ("gsutil mv gs://staging/a gs://prod/b gs://archive/",
     ["storage/bucket/staging", "storage/bucket/prod"]),
    ("gsutil cp -M gs://prod/a gs://archive/a", ["storage/bucket/prod"]),  # cp -M moves
    ("gsutil cp gs://prod/a gs://archive/a", []),
    ("gsutil -m rm -I", ["storage/bucket/*"]),  # the paths come from stdin
    ("gcloud storage rm -I", ["storage/bucket/*"]),
    ("gcloud storage mv -I gs://archive/", ["storage/bucket/*"]),
])
def test_every_moved_source_is_deleted(command, deleted):
    intents = from_argv(command.split())
    assert [i.resource for i in intents if i.action == "delete"] == deleted


def test_a_delete_rule_on_the_second_source_holds():
    rule = _rule("gcp", "storage/bucket/prod", ["delete"])
    assert _verdict([rule], "gcloud storage mv gs://staging/a gs://prod/b gs://archive/") == \
        "BLOCK"
    assert _verdict([rule], "gsutil cp -M gs://prod/a gs://archive/a") == "BLOCK"


@pytest.mark.parametrize("command", [
    # rsync with deletes is not read, so it is refused
    "gsutil rsync -d gs://a gs://b",
    "gcloud storage rsync gs://a gs://b --delete-unmatched-destination-objects",
])
def test_storage_rsync_is_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,resource", [
    ("gcloud container clusters create --enable-autoscaling demo --zone us-central1-a "
     "--num-nodes 3 --min-nodes 1 --max-nodes 5", "container/cluster/demo"),
    ("gcloud compute instances create --preemptible web --machine-type e2-small "
     "--image-family debian-12 --image-project debian-cloud", "compute/instance/web"),
    ("gcloud run deploy --allow-unauthenticated svc --image gcr.io/p/i --region us-central1",
     "run/service/svc"),
    ("gcloud functions deploy fn --gen2 --trigger-http --runtime python312 --source .",
     "functions/function/fn"),
    ("gcloud sql instances create db --database-version POSTGRES_15 --tier db-f1-micro "
     "--deletion-protection", "sql/instance/db"),
])
def test_common_gcloud_creates_with_spaces_are_read(command, resource):
    assert [i.resource for i in from_argv(command.split())] == [resource]


# --- review round 2: one value, every spelling; values from outside the argv ----------


def test_a_literal_dotted_helm_key_cannot_hide_the_nested_value():
    # helm keeps both: the nested securityContext.privileged and the literal key
    command = ["helm", "upgrade", "api", "./c", "-n", "prod", "--set",
               r"securityContext.privileged=true,securityContext\.privileged=false"]
    intent = from_argv(command)[0]
    assert intent.params["set"] == {"securityContext": {"privileged": True},
                                    "securityContext.privileged": False}
    rule = _rule("helm", "release/*", ["update"],
                 {"namespace": "prod", "set.securityContext.privileged": True})
    assert _verdict([rule], command) == "BLOCK"


@pytest.mark.parametrize("scope,params", [
    # a negated boolean and its positive side are one value
    ({"no-verify-ssl": True}, {"verify-ssl": False}),
    ({"verify-ssl": False}, {"no-verify-ssl": True}),
    ({"deletion_protection": False}, {"deletion-protection": False}),
    ({"no_deletion_protection": True}, {"deletion_protection": False}),
    ({"dry-run": True}, {"dry_run": True}),
])
def test_scope_keys_match_every_spelling(scope, params):
    from aegis_core.store import scope_matches
    assert scope_matches(scope, {}, params)
    assert not scope_matches({k: (not v) for k, v in scope.items()}, {}, params)


@pytest.mark.parametrize("scope,metadata", [
    ({"repo": "acme/web"}, {"repo": "Acme/Web"}),
    ({"resource_group": "Prod-RG"}, {"resource_group": "prod-rg"}),
    ({"subscription": "SUB-1"}, {"subscription": "sub-1"}),
])
def test_case_insensitive_scope_keys(scope, metadata):
    from aegis_core.store import scope_matches
    assert scope_matches(scope, metadata, {})


@pytest.mark.parametrize("command,scope,verdict", [
    # what the tool takes from its configuration when the argv does not give it
    ("kubectl delete pod x -n dev", {"context": "prod"}, "ESCALATE"),
    ("kubectl delete pod x -n dev --context prod", {"context": "prod"}, "BLOCK"),
    ("kubectl delete pod x -n dev --context dev", {"context": "prod"}, "ALLOW"),
    ("aws ec2 terminate-instances --instance-ids i-1", {"region": "us-east-1"}, "ESCALATE"),
    ("aws ec2 terminate-instances --instance-ids i-1 --profile p", {"profile": "prod"},
     "ALLOW"),
    ("az vm delete -n v -g rg --yes", {"subscription": "prod"}, "ESCALATE"),
    ("az vm delete -n v --yes", {"resource_group": "prod"}, "ESCALATE"),
    ("gcloud compute instances delete web-1", {"project": "prod"}, "ESCALATE"),
    ("gcloud compute instances delete web-1 --project prod", {"project": "prod"}, "BLOCK"),
    ("argocd app sync web", {"project": "prod"}, "ESCALATE"),
    ("git push --force", {"remote": "origin"}, "ESCALATE"),
])
def test_scope_the_tool_takes_from_its_configuration_escalates(command, scope, verdict):
    provider = {"kubectl": "kubernetes", "aws": "aws", "az": "azure", "gcloud": "gcp",
                "argocd": "argocd", "git": "git"}[command.split()[0]]
    actions = ["delete", "sync", "push"]
    rule = _rule(provider, "*", actions, scope)
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,unresolved", [
    # helm upgrade reuses the release's values unless --reset-values, or when the
    # command line sets none (helm 3.21.1 / 4.3.1 Upgrade.reuseValues)
    ("helm upgrade api ./c -n prod", True),
    ("helm upgrade api ./c -n prod --reset-values", False),
    ("helm upgrade api ./c -n prod --set a=1", False),
    ("helm upgrade api ./c -n prod --set a=1 --reuse-values", True),
    ("helm upgrade api ./c -n prod --set a=1 --reset-then-reuse-values", True),
    ("helm upgrade api ./c -n prod --reuse-values --reset-values", False),
    ("helm rollback api 3 -n prod", True),
    ("helm install api ./c -n prod", False),
])
def test_helm_reused_values_are_unresolved(command, unresolved):
    intent = from_argv(command.split())[0]
    assert ("set.*" in intent.params.get("unresolved_scope", [])) is unresolved


def test_helm_upgrade_without_values_escalates_a_values_rule():
    rule = _rule("helm", "release/*", ["update"], {"set.replicaCount": 0})
    assert _verdict([rule], "helm upgrade api ./c -n prod") == "ESCALATE"
    assert _verdict([rule], "helm upgrade api ./c -n prod --reset-values") == "ALLOW"


@pytest.mark.parametrize("command,every", [
    ("flux get kustomizations -A -n dev", True),
    ("flux get kustomizations --all-namespaces -n dev", True),
    ("flux get kustomizations -A --all-namespaces=false -n dev", False),
    ("helm list -A", True),
    ("helm list --all-namespaces=false -A", True),
])
def test_all_namespaces_is_one_key(command, every):
    intent = from_argv(command.split())[0]
    assert intent.metadata.get("all_namespaces", False) is every
    rule = _rule(intent.provider, "*", ["read"], {"namespace": "prod"})
    assert _verdict([rule], command) == ("ESCALATE" if every else "ALLOW")


# --- gh selectors and repositories (cli v2.103 pr/shared/finder.go, issue/shared) -----


@pytest.mark.parametrize("command,resource,repo,marked", [
    ("gh pr merge https://github.com/o/r/pull/42 --squash", "pr/42", "o/r", False),
    ("gh pr merge 42 -R o/r", "pr/42", "o/r", False),
    ("gh pr merge #42 -R O/R", "pr/42", "o/r", False),
    ("gh pr merge O/R#42", "pr/42", "o/r", False),
    ("gh pr merge 42 -R github.com/o/r", "pr/42", "o/r", False),
    ("gh pr merge 42 -R https://github.com/o/r.git", "pr/42", "o/r", False),
    ("gh pr merge 42 -R git@github.com:o/r.git", "pr/42", "o/r", False),
    ("gh pr merge 42 -R ghe.corp.com/o/r", "pr/42", "ghe.corp.com/o/r", False),
    # a branch, or the current branch: gh finds the pull request when it runs
    ("gh pr merge feature -R o/r", "pr/*", "o/r", True),
    ("gh pr merge -R o/r", "pr/*", "o/r", True),
    ("gh issue delete https://github.com/o/r/issues/7 --yes", "issue/7", "o/r", False),
    ("gh issue close 7 -R o/r", "issue/7", "o/r", False),
    ("gh run cancel 123 -R o/r", "run/123", "o/r", False),
    ("gh run rerun -R o/r", "run/*", "o/r", True),
    ("gh workflow run .github/workflows/deploy.yml -R o/r -r main", "workflow/deploy.yml",
     "o/r", False),
    ("gh workflow run Deploy -R o/r", "workflow/Deploy", "o/r", True),  # a display name
    ("gh repo delete O/R --yes", "repo/o/r", "o/r", False),
    ("gh repo delete https://github.com/o/r --yes", "repo/o/r", "o/r", False),
    ("gh secret set token -b x -R o/r", "secret/TOKEN", "o/r", False),
])
def test_gh_selectors_and_repositories_have_one_spelling(command, resource, repo, marked):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource
    assert intent.metadata["repo"] == repo
    assert ("resolved_at_runtime" in intent.params) is marked


@pytest.mark.parametrize("command,verdict", [
    ("gh pr merge https://github.com/acme/web/pull/42 --squash", "BLOCK"),
    ("gh pr merge 42 -R github.com/Acme/Web --squash", "BLOCK"),
    ("gh pr merge 42 -R ghe.corp.com/acme/web --squash", "ALLOW"),  # another host
    ("gh pr merge feature -R acme/web --squash", "ESCALATE"),
])
def test_a_rule_on_one_pull_request_holds_on_every_spelling(command, verdict):
    rule = _rule("github", "pr/42", ["merge"], {"repo": "acme/web"})
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,mark", [
    ("gh api repos/o/r/actions/workflows/d.yml/dispatches -F ref=@ref.txt", "ref"),
    ("gh api repos/o/r/actions/workflows/d.yml/dispatches --input body.json", "ref"),
    ("gh workflow run d.yml -R o/r --json", "inputs.*"),
    ("gh workflow run d.yml -R o/r", "ref"),  # the default branch
])
def test_gh_values_from_files_or_defaults_are_unresolved(command, mark):
    assert mark in from_argv(command.split())[0].params["unresolved_scope"]


# --- git: what config files can change about a push ------------------------------------


@pytest.mark.parametrize("command,tags", [
    # push.followTags may be set in any config file git reads
    ("git push origin main", True),
    ("git push origin main --no-follow-tags", False),
    ("git -c push.followTags=false push origin main", False),
    ("git push origin main --tags --no-follow-tags", True),
    ("git push", True),
])
def test_git_push_may_send_tags_unless_told_not_to(command, tags):
    resources = [i.resource for i in from_argv(command.split())]
    assert ("tag/*" in resources) is tags


@pytest.mark.parametrize("rule,command,verdict", [
    # only a rule on tags is about the tags config may add
    # a source-only refspec's destination is mapped when git runs (round 10): a rule on
    # another ref may be about it, and escalates
    (_rule("git", "ref/main", ["push"]), "git push origin feature", "ESCALATE"),
    (_rule("git", "ref/main", ["push"]), "git push origin feature:feature", "ALLOW"),
    (_rule("git", "tag/v*", ["push"]), "git push origin feature", "ESCALATE"),
    (_rule("git", "tag/v*", ["push"]), "git push origin feature --no-follow-tags", "ALLOW"),
    (_rule("git", "tag/v1", ["push"]), "git push origin refs/tags/v1 --no-follow-tags",
     "BLOCK"),
    # with no refspec, config decides the refs, whether they are forced, and the remote
    (_rule("git", "ref/main", ["push"], {"force": True}), "git push origin", "ESCALATE"),
    (_rule("git", "ref/main", ["delete"]), "git push origin", "ESCALATE"),
    (_rule("git", "ref/main", ["push"], {"remote": "origin"}),
     "git push https://example.com/o/r main --no-follow-tags", "ESCALATE"),
])
def test_git_config_only_reaches_the_rules_it_could_affect(rule, command, verdict):
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,key,value", [
    ("git push --no-thin origin main", "thin", False),
    ("git commit -n --amend -m x", "verify", False),
    ("git commit --no-verify --verify --amend -m x", "verify", True),
    ("git push --repo=origin", None, None),
])
def test_git_negated_options_have_one_key(command, key, value):
    intent = from_argv(command.split())[0]
    if key is None:
        assert intent.metadata["remote"] == "origin"  # --repo is the remote
    else:
        assert intent.params[key] is value


# --- gcloud, aws, az, argocd: one spelling, and nothing read from a file ----------------


@pytest.mark.parametrize("command,key,value", [
    ("gcloud compute instances update web --no-deletion-protection", "deletion_protection",
     False),
    ("gcloud compute instances update web --deletion-protection=false", "deletion_protection",
     False),
    ("gcloud compute instances update web --no-deletion-protection --deletion-protection",
     "deletion_protection", True),
    ("aws ec2 terminate-instances --instance-ids i-1 --no-verify-ssl", "verify_ssl", False),
    ("aws ec2 terminate-instances --instance-ids i-1 --no-force", "force", False),
])
def test_negated_booleans_have_one_key(command, key, value):
    intent = from_argv(command.split())[0]
    assert intent.params[key] is value
    assert not any(k.startswith("no") and k.replace("-", "_")[3:] == key for k in intent.params)


def test_a_gcloud_deletion_protection_rule_holds_on_both_spellings():
    rule = _rule("gcp", "compute/instance/*", ["update"], {"deletion_protection": False})
    for flag in ("--no-deletion-protection", "--deletion-protection=false"):
        assert _verdict([rule], f"gcloud compute instances update web --project p "
                                f"--region r {flag}") == "BLOCK"


def test_gcloud_flags_file_is_refused():
    with pytest.raises(ValueError, match="file"):
        from_argv("gcloud compute instances delete web --flags-file=prod.yaml".split())


def test_a_gcloud_uri_is_its_name_in_its_project():
    uri = ("https://www.googleapis.com/compute/v1/projects/prod/zones/us-east1-b/instances/"
           "web-1")
    intent = from_argv(["gcloud", "compute", "instances", "delete", uri])[0]
    assert intent.resource == "compute/instance/web-1"
    assert intent.metadata["project"] == "prod"
    assert intent.metadata["region"] == "us-east1"


@pytest.mark.parametrize("command,alias,marked", [
    ("aws lambda delete-function --function-name "
     "arn:aws:lambda:us-west-2:123456789012:function:prod-fn", "lambda/function/prod-fn", False),
    ("aws iam delete-role --role-name arn:aws:iam::123456789012:role/team/prod-admin",
     "iam/role/prod-admin", False),
    ("aws secretsmanager delete-secret --secret-id "
     "arn:aws:secretsmanager:us-east-1:1:secret:prod-db-AbCdEf",
     "secretsmanager/secret/prod-db-AbCdEf", True),
])
def test_an_aws_arn_also_matches_a_rule_on_the_name(command, alias, marked):
    intent = from_argv(command.split())[0]
    assert alias in intent.resource_aliases()
    assert ("resolved_at_runtime" in intent.params) is marked


def test_aws_rule_on_a_name_holds_on_its_arn():
    rule = _rule("aws", "lambda/function/prod-fn", ["delete"])
    assert _verdict([rule], "aws lambda delete-function --function-name "
                            "arn:aws:lambda:us-west-2:123456789012:function:prod-fn") == "BLOCK"
    secret = _rule("aws", "secretsmanager/secret/prod-db", ["delete"])
    assert _verdict([secret], "aws secretsmanager delete-secret --secret-id "
                              "arn:aws:secretsmanager:us-east-1:1:secret:prod-db-AbCdEf") == \
        "ESCALATE"


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-ids file://ids.json",
    "aws kms schedule-key-deletion --key-id alias/prod",
])
def test_aws_targets_known_only_when_aws_runs_are_marked(command):
    assert "resolved_at_runtime" in from_argv(command.split())[0].params


@pytest.mark.parametrize("command", [
    "az vm delete -n @name.txt -g rg --yes",
    "az vm delete -n v -g @rg.txt --yes",
])
def test_az_values_read_from_files_are_refused(command):
    with pytest.raises(ValueError, match="file"):
        from_argv(command.split())


@pytest.mark.parametrize("command,namespace", [
    ("argocd app sync prod/web", "prod"),
    ("argocd app sync web -N prod", "prod"),
    ("argocd app sync web --app-namespace=prod", "prod"),
])
def test_an_argocd_app_has_one_name_and_its_namespace(command, namespace):
    intent = from_argv(command.split())[0]
    assert intent.resource == "app/web"
    assert intent.metadata["app_namespace"] == namespace


# --- variables in front of the command, read only by the tool that reads them ----------


@pytest.mark.parametrize("command,key,value", [
    ("HELM_NAMESPACE=prod helm uninstall web", "namespace", "prod"),
    ("HELM_KUBECONTEXT=prod helm uninstall web -n x", "context", "prod"),
    ("GH_REPO=github.com/Acme/Web gh workflow run d.yml", "repo", "acme/web"),
    ("AZURE_DEFAULTS_GROUP=prod-rg az vm delete -n v --yes", "resource_group", "prod-rg"),
    ("AWS_DEFAULT_REGION=a AWS_REGION=b aws ec2 terminate-instances --instance-ids i-1",
     "region", "b"),
])
def test_an_inline_variable_sets_the_scope_of_the_tool_that_reads_it(command, key, value):
    from aegis_core.shell import intents_from_command
    assert intents_from_command(command)[0].metadata[key] == value


def test_kubectl_does_not_read_helms_namespace_variable():
    from aegis_core.shell import intents_from_command
    intent = intents_from_command("HELM_NAMESPACE=prod kubectl delete pod x")[0]
    assert "namespace" not in intent.metadata


@pytest.mark.parametrize("command", [
    "ARGOCD_OPTS='--server prod' argocd app sync web",
    "KUBERC=./kuberc kubectl delete pod x -n dev",
])
def test_variables_that_add_flags_are_refused(command):
    from aegis_core.shell import intents_from_command
    with pytest.raises(ValueError):
        intents_from_command(command)


def test_kuberc_off_is_fine():
    from aegis_core.shell import intents_from_command
    assert intents_from_command("KUBERC=off kubectl delete pod x -n dev")


@pytest.mark.parametrize("chdir", ["infra", "./infra", "infra/", "./infra/"])
def test_terraform_chdir_has_one_spelling(chdir):
    assert from_argv(["terraform", f"-chdir={chdir}", "destroy"])[0].resource == \
        "workspace/infra"


# --- review round 3 ------------------------------------------------------------------


@pytest.mark.parametrize("flags,rule_key,verdict", [
    # A2: an unresolved mark meets every spelling matching meets
    ("--set-file replica-count=r.txt", "set.replica_count", "ESCALATE"),
    ("--set-file replica_count=r.txt", "set.replica-count", "ESCALATE"),
    ("--set replica-count=0", "set.replica_count", "BLOCK"),
    ("--set a.b_c.d=0", "set.a.b-c.d", "BLOCK"),  # every level, not only the last
    ("--set-file a.b_c.d=r.txt", "set.a.b-c.d", "ESCALATE"),
    ("--set-file replica-count=r.txt --set replica_count=3", "set.replica_count",
     "ESCALATE"),
])
def test_unresolved_marks_meet_every_spelling(flags, rule_key, verdict):
    rule = _rule("helm", "release/*", ["update"], {rule_key: 0})
    assert _verdict([rule], ["helm", "upgrade", "api", "./c", *flags.split()]) == verdict


@pytest.mark.parametrize("rule_key", ["app_namespace", "app-namespace"])
def test_argocd_app_namespace_mark_meets_both_spellings(rule_key):
    rule = _rule("argocd", "app/*", ["delete"], {rule_key: "prod"})
    assert _verdict([rule], "argocd app delete web -y") == "ESCALATE"
    assert _verdict([rule], "argocd app delete web -y --app-namespace prod") == "BLOCK"
    assert _verdict([rule], "argocd app delete web -y --app-namespace dev") == "ALLOW"


def test_flux_with_source_namespace_is_not_the_objects():
    # A1: sourceRef.namespace may name another namespace (reconcile_with_source.go)
    command = "flux reconcile ks app -n dev --with-source"
    intents = from_argv(command.split())
    assert intents[0].metadata["namespace"] == "dev"
    for source in intents[1:]:
        assert "namespace" not in source.metadata
        assert source.metadata["all_namespaces"] is True
    rule = _rule("flux", "source-git/*", ["sync"], {"namespace": "prod"})
    assert _verdict([rule], command) == "ESCALATE"
    assert _verdict([rule], "flux reconcile ks app -n dev") == "ALLOW"
    # filling the environment's namespace does not settle it either
    verdict, _ = _flux_verdict(rule, command, environ={"FLUX_SYSTEM_NAMESPACE": "dev"})
    assert verdict == "ESCALATE"


@pytest.mark.parametrize("command,targets", [
    # B1: "tag <name>" is refs/tags/<name> (builtin/push.c set_refspecs)
    ("git push --no-follow-tags origin tag v1", [("ref/v1", "push"), ("tag/v1", "push")]),
    # B2: a deleted tag is a delete, however it is spelled
    ("git push --delete origin refs/tags/v1", [("ref/v1", "delete"), ("tag/v1", "delete")]),
    ("git push origin :refs/tags/v1", [("ref/v1", "delete"), ("tag/v1", "delete")]),
    ("git push --delete origin tag v1", [("ref/v1", "delete"), ("tag/v1", "delete")]),
    ("git push origin +refs/tags/v1 --no-follow-tags",
     [("ref/v1", "push"), ("tag/v1", "push")]),
    # every tag goes with --mirror, and the remote's other tags are deleted
    ("git push --mirror --no-follow-tags origin",
     [("ref/*", "push"), ("tag/*", "push"), ("ref/*", "delete"), ("tag/*", "delete")]),
    ("git push --prune origin main --no-follow-tags",
     [("ref/main", "push"), ("ref/*", "delete"), ("tag/*", "delete")]),
])
def test_git_push_tags_carry_the_action_git_takes(command, targets):
    # run on git 2.52 against a local bare remote: tag t9, --delete tag t9, and a short
    # name (t8) that is a tag pushing refs/tags/t8
    assert [(i.resource, i.action) for i in from_argv(command.split())] == targets


def test_git_push_tag_force_is_recorded():
    tag = [i for i in from_argv("git push origin +refs/tags/v1".split())
           if i.resource == "tag/v1"][0]
    assert tag.params["force"] is True


@pytest.mark.parametrize("command", [
    "git push origin tag",  # tag shorthand without <tag>
    "git push --delete origin a:b",  # --delete only accepts plain target ref names
    "git push --delete origin",  # --delete doesn't make sense without any refs
    "git push --delete --tags origin x",  # cannot be used together
])
def test_git_push_refuses_what_git_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("rule,command,verdict", [
    (_rule("git", "tag/v1", ["delete"]), "git push --delete origin refs/tags/v1", "BLOCK"),
    (_rule("git", "tag/v1", ["delete"]), "git push origin :refs/tags/v1", "BLOCK"),
    (_rule("git", "tag/v1", ["push"]), "git push --no-follow-tags origin tag v1", "BLOCK"),
    # a short name is a tag when the local (or remote) ref of that name is one
    (_rule("git", "tag/v1*", ["push"]), "git push origin v1.2.0 --no-follow-tags",
     "ESCALATE"),
    (_rule("git", "tag/v1", ["delete"]), "git push --delete origin v1", "ESCALATE"),
    (_rule("git", "tag/v1", ["delete"]), "git push origin :v1", "ESCALATE"),
    (_rule("git", "tag/v2", ["push"]), "git push origin v1 --no-follow-tags", "ALLOW"),
    (_rule("git", "tag/*", ["push"]), "git push origin refs/heads/main --no-follow-tags",
     "ALLOW"),
    (_rule("git", "tag/*", ["delete"]), "git push --mirror origin", "BLOCK"),
])
def test_git_push_tag_rules_hold(rule, command, verdict):
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,key,value", [
    # B3: every option resolved by prefix against the operation's full list (aws-cli
    # 2.37 tables), recorded under its full name (run on aws 2.37)
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g --desired-cap 0",
     "desired_capacity", 0),
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g --desired 0",
     "desired_capacity", 0),
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g "
     "--desired-capacity -1", "desired_capacity", -1),  # a negative number is a value
    ("aws ec2 terminate-instances --instance-ids i-1 --dry", "dry_run", True),
    ("aws lambda update-function-configuration --function-name f --timeo 30",
     "timeout", 30),
])
def test_aws_option_prefix_is_the_full_option(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("command", [
    "aws autoscaling set-desired-capacity --auto-scaling-group-name g --no-such 1",
    "aws ec2 terminate-instances --instance-ids i-1 --cli-input x",  # json or yaml
    "aws autoscaling no-such-operation --x 1",
    "aws autoscaling set-desired-capacity --auto-scaling-group-name g -x",
    "aws ec2 terminate-instances --cli-input-json {\"Bogus\":1}",
    "aws ec2 terminate-instances --cli-input-json {} --cli-input-yaml {}",
    "aws ec2 terminate-instances --cli-input-json [1]",
])
def test_aws_refuses_unknown_options_and_inputs(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,verdict", [
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g --desired-cap 0",
     "BLOCK"),
    (["aws", "autoscaling", "set-desired-capacity", "--cli-input-json",
      '{"AutoScalingGroupName":"g","DesiredCapacity":0}'], "BLOCK"),
    (["aws", "autoscaling", "set-desired-capacity", "--cli-input-yaml",
      "{AutoScalingGroupName: g, DesiredCapacity: 0}"], "BLOCK"),
    (["aws", "autoscaling", "set-desired-capacity", "--cli-input-json",
      '{"AutoScalingGroupName":"g","DesiredCapacity":0}', "--desired-capacity", "3"],
     "ALLOW"),  # the command line wins, as in aws
    # aws reads the input by its full name only: an abbreviation is never used
    (["aws", "autoscaling", "set-desired-capacity", "--cli-input-j",
      '{"DesiredCapacity":3}', "--auto-scaling-group-name", "g", "--desired-capacity", "0"],
     "BLOCK"),
    ("aws autoscaling set-desired-capacity --cli-input-json file://in.json", "ESCALATE"),
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g "
     "--desired-capacity file://n.txt", "ESCALATE"),
])
def test_aws_desired_capacity_rule_holds_in_every_spelling(command, verdict):
    rule = _rule("aws", "autoscaling/auto-scaling-group/*", ["scale"],
                 {"desired_capacity": 0})
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("command,resources,params", [
    # C3: each modeled command's flags, from the gcloud reference pages
    ("gcloud compute instances update --clear-labels web --zone us-east1-b",
     ["compute/instance/web"], {"clear_labels": True}),
    ("gcloud compute instances update --no-deletion-protection web",
     ["compute/instance/web"], {"deletion_protection": False}),
    ("gcloud compute instances update --update-labels a=b web",
     ["compute/instance/web"], {"update-labels": {"a": "b"}}),  # an ArgDict
    # an optional value takes the next word, as argparse does
    ("gcloud compute instances stop web --discard-local-ssd", ["compute/instance/web"],
     {"discard-local-ssd": True}),
    ("gcloud container clusters resize c --num-nodes 0 --region r",
     ["container/cluster/c"], {"num-nodes": 0}),
    ("gcloud storage rm -r gs://b/x", ["storage/bucket/b"], {"recursive": True}),
    ("gcloud compute instances list --filter name=x", ["compute/instance/*"],
     {"filter": "name=x"}),
])
def test_gcloud_flags_are_read_from_the_reference_table(command, resources, params):
    intents = from_argv(command.split())
    assert [i.resource for i in intents] == resources
    assert {k: intents[0].params.get(k) for k in params} == params


def test_gcloud_each_path_names_its_own_project_and_zone():
    # C1: metadata per operand, not the last path's for all
    command = ("gcloud compute instances delete projects/p1/zones/us-east1-b/instances/a "
               "projects/p2/zones/europe-west1-c/instances/b")
    a, b = from_argv(command.split())
    assert (a.metadata["project"], a.metadata["zone"]) == ("p1", "us-east1-b")
    assert (b.metadata["project"], b.metadata["zone"]) == ("p2", "europe-west1-c")
    rule = _rule("gcp", "compute/instance/*", ["delete"], {"project": "p1"})
    assert _verdict([rule], command) == "BLOCK"
    rule = _rule("gcp", "compute/instance/b", ["delete"], {"project": "p1"})
    assert _verdict([rule], command) == "ALLOW"


def test_gcloud_project_number_leaves_the_project_id_unresolved():
    # C2: a number names a project, but which project ID only gcloud knows
    from aegis_core.environments import resolve_current_context

    command = "gcloud compute instances delete web --project 123456789 --zone us-east1-b"
    intent = from_argv(command.split())[0]
    assert "project" not in intent.metadata
    assert intent.metadata["project_number"] == "123456789"
    rule = _rule("gcp", "compute/instance/*", ["delete"], {"project": "prod"})
    assert _verdict([rule], command) == "ESCALATE"
    resolve_current_context(intent, environ={"CLOUDSDK_CORE_PROJECT": "dev"})
    assert "project" not in intent.metadata


GUID = "0b1f6471-1bf0-4dda-aec3-111122223333"


@pytest.mark.parametrize("flags,metadata", [
    # C2: a name or display name is not the ID or name a rule may use
    (f"--subscription {GUID}", {"subscription": GUID}),
    ("--subscription Production", {"subscription_name": "Production"}),
    (["--location", "East US"], {"location_display_name": "East US"}),
    ("--location eastus", {"region": "eastus"}),
])
def test_az_scope_names_are_kept_apart_from_ids(flags, metadata):
    extra = flags.split() if isinstance(flags, str) else flags
    intent = from_argv(["az", "vm", "delete", "-g", "rg", "-n", "vm1", "--yes", *extra])[0]
    assert {k: intent.metadata.get(k) for k in metadata} == metadata
    for absent in ({"subscription", "subscription_name", "region", "location_display_name"}
                   - set(metadata)):
        assert absent not in intent.metadata


@pytest.mark.parametrize("rule_scope,flags,verdict", [
    ({"subscription": GUID}, "--subscription Production", "ESCALATE"),
    ({"subscription": GUID}, f"--subscription {GUID.upper()}", "BLOCK"),
    ({"region": "eastus"}, "--location EastUS", "BLOCK"),  # ARM ignores case
    ({"resource_group": "prod-rg"}, "-g PROD-RG", "BLOCK"),
])
def test_az_scope_rules_hold_for_names(rule_scope, flags, verdict):
    rule = _rule("azure", "compute/vm/*", ["delete"], rule_scope)
    command = ["az", "vm", "delete", "-n", "vm1", "--yes", *flags.split()]
    if "-g" not in command:
        command += ["-g", "rg"]
    assert _verdict([rule], command) == verdict


def test_az_location_display_name_escalates_a_region_rule():
    rule = _rule("azure", "compute/vm/*", ["delete"], {"region": "eastus"})
    command = ["az", "vm", "delete", "-g", "rg", "-n", "vm1", "--yes", "-l", "East US"]
    assert _verdict([rule], command) == "ESCALATE"


def test_az_ids_override_the_subscription_flag():
    # C1: az takes the subscription and group of each ID and ignores the flags
    arm = f"/subscriptions/{GUID}/resourceGroups/prod/providers/Microsoft.Compute"
    command = ["az", "vm", "delete", "--yes", "--subscription", "Other", "-g", "dev",
               "--ids", f"{arm}/virtualMachines/a"]
    rule = _rule("azure", "compute/vm/*", ["delete"], {"resource_group": "prod"})
    assert _verdict([rule], command) == "BLOCK"


# --- review round 4 ------------------------------------------------------------------


@pytest.mark.parametrize("command", [
    # 1: every path is normalized once at the end, the early-returning ones too
    "argocd app actions run prod/payments restart --kind Deployment",
    "argocd app actions run payments restart --kind Deployment -N prod",
    "argocd app delete prod/payments -y",
])
def test_argocd_qualified_name_on_every_subcommand(command):
    intent = from_argv(command.split())[0]
    assert (intent.resource, intent.metadata["app_namespace"]) == ("app/payments", "prod")
    rule = _rule("argocd", "app/payments", ["update", "delete"], {"app_namespace": "prod"})
    assert _verdict([rule], command) == "BLOCK"


def test_az_ids_subscription_name_is_normalized_too():
    command = ["az", "vm", "delete", "--yes", "--ids",
               "/subscriptions/Production/resourceGroups/rg/providers/Microsoft.Compute/"
               "virtualMachines/a"]
    intent = from_argv(command)[0]
    assert intent.metadata["subscription_name"] == "Production"
    rule = _rule("azure", "compute/vm/*", ["delete"], {"subscription": GUID})
    assert _verdict([rule], command) == "ESCALATE"


# --- 2 and 3: every command that maps to read, audited ---------------------------------
# Each entry was checked against the tool's documentation: it shows, lists or prints and
# changes nothing. A verb added to any table as a read fails these tests until it is added
# here, and an unknown verb is refused or keeps its own name as the action, never "read".


def test_the_verbs_that_read_are_the_audited_ones():
    from aegis_core import parser as p

    reads = lambda table: {k for k, v in table.items() if v == "read"}  # noqa: E731
    # aws, az, gcloud: describe/list/get/show/ls read; ssh runs commands (exec) and export
    # writes the data out, so neither is a read
    assert reads(p._VERB_NORMALIZE) == {"describe", "list", "get", "show", "ls",
                                         "get-credentials", "wait"}
    assert reads(p._AWS_S3_VERB_MAP) == {"ls"}
    assert reads(p._GCS_LEGACY_VERB_MAP) == set()
    # argocd: get, list, diff, history (get/diff --refresh are updates, tested below)
    assert reads(p._ARGOCD_ACTION_MAP) == {"get", "list", "diff", "history"}
    assert p._HELM_READ_VERBS == {"history", "status", "list", "get"}
    assert p._FLUX_READ_VERBS == {"get", "logs", "export"}  # flux export prints YAML
    assert p._GIT_READ_VERBS == {
        "status", "log", "diff", "show", "blame", "annotate", "grep", "ls-files", "ls-tree",
        "ls-remote", "rev-parse", "rev-list", "describe", "shortlog", "cat-file",
        "show-ref", "for-each-ref", "name-rev", "whatchanged", "help", "version", "var",
        "count-objects", "cherry", "diff-tree", "diff-files", "diff-index", "merge-base",
        "check-ignore", "check-attr", "check-ref-format", "verify-commit", "verify-tag",
        "range-diff"}
    assert p._GIT_READ_SUBCOMMANDS == {
        "remote": {None, "show", "get-url"}, "stash": {"list", "show"},
        "worktree": {"list"}, "notes": {"list", "show"},
        "reflog": {None, "show", "exists"}, "submodule": {"status", "summary"}}
    assert reads(p._GH_ACTIONS) == {
        *(("pr", v) for v in ("view", "list", "status", "diff", "checks")),
        *(("issue", v) for v in ("view", "list", "status")),
        *(("release", v) for v in ("view", "list", "verify", "verify-asset")),
        ("repo", "view"), ("repo", "list"), ("run", "view"), ("run", "list"),
        ("run", "watch"), ("workflow", "view"), ("workflow", "list"), ("secret", "list"),
        ("variable", "list"), ("variable", "get"),
        *(("search", v) for v in ("repos", "issues", "prs", "code", "commits")),
        ("status", None), ("browse", None), ("gist", "view"), ("gist", "list"),
        ("label", "list"), ("cache", "list"), ("ruleset", "list"), ("ruleset", "view"),
        ("ruleset", "check"), ("org", "list"), ("auth", "status"), ("auth", "token"),
        ("extension", "list"), ("extension", "search"), ("extension", "browse"),
        *(("project", v) for v in ("list", "view", "field-list", "item-list")),
        ("config", "get"), ("config", "list"), ("alias", "list"), ("gpg-key", "list"),
        ("ssh-key", "list"), ("help", None), ("version", None)}


@pytest.mark.parametrize("command,targets", [
    # 2: git tag and git branch with a name create it; -f replaces one (an update)
    ("git tag -f v1 HEAD", [("tag/v1", "create"), ("tag/v1", "update")]),
    ("git tag v1", [("tag/v1", "create")]),
    ("git tag -a v1 -m release", [("tag/v1", "create")]),
    ("git tag", [("tag/*", "read")]),
    ("git tag -l v*", [("tag/v*", "read")]),
    ("git tag -n v*", [("tag/v*", "read")]),
    ("git tag -v v1", [("tag/v1", "read")]),
    ("git branch side", [("branch/side", "create")]),
    ("git branch --list a*", [("branch/a*", "read")]),
    ("git branch -u origin/main", [("branch/*", "update")]),
    ("git branch --unset-upstream side", [("branch/side", "update")]),
    # every other git command changes the repository unless documented as a read
    ("git status", [("history/*", "read")]),
    ("git remote -v", [("history/*", "read")]),
    ("git remote add o https://x", [("history/*", "remote")]),
    ("git config --get user.name", [("history/*", "read")]),
    ("git config user.name x", [("history/*", "config")]),
    ("git stash list", [("history/*", "read")]),
    ("git stash", [("history/*", "stash")]),
    ("git clean -fdx", [("history/*", "clean")]),
    ("git update-ref -d refs/heads/x", [("history/*", "update-ref")]),
    ("git frobnicate", [("history/*", "frobnicate")]),
    # 3: gh commands that change something
    ("gh release edit v1 --draft=false", [("release/v1", "update")]),
    ("gh pr edit 1 --title x", [("pr/1", "update")]),
    ("gh repo edit o/r --visibility public", [("repo/o/r", "update")]),
    ("gh issue edit 3 --title x", [("issue/3", "update")]),
    ("gh pr view 1", [("pr/1", "read")]),
    ("gh label create bug", [("label/create", "create")]),
    ("gh frob x", [("frob/x", "x")]),
    # argocd --refresh patches the Application
    ("argocd app get a --hard-refresh", [("app/a", "update")]),
    ("argocd app get a", [("app/a", "read")]),
    # cloud: ssh runs commands, export writes data out
    ("gcloud compute ssh vm --zone us-east1-b", [("compute/instance/vm", "exec")]),
    ("gcloud sql export sql db gs://b/f.sql", [("sql/instance/db", "export")]),
    ("gcloud compute instances update web --clear-labels", [("compute/instance/web",
                                                              "update")]),
    ("az vm update -g rg -n vm1 --set x=y", [("compute/vm/vm1", "update")]),
    ("aws ec2 modify-instance-attribute --instance-id i-1 --no-disable-api-termination",
     [("ec2/instance-attribute/i-1", "update")]),
    ("aws ec2 create-tags --resources i-1 --tags Key=a,Value=b", [("ec2/tag/*", "create")]),
    ("kubectl annotate pod web a=b", [("pod/web", "annotate")]),
    ("kubectl label pod web a=b", [("pod/web", "label")]),
])
def test_commands_that_change_something_are_never_read(command, targets):
    got = [(i.resource, i.action) for i in from_argv(command.split())]
    assert got[:len(targets)] == targets


@pytest.mark.parametrize("command", [
    "aws ec2 frobnicate-things", "helm frob x", "flux frob ks a", "argocd app frob a",
    "az vm frob -n a -g b", "gcloud compute instances frob a",
])
def test_an_unknown_verb_is_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_kubectl_unknown_verb_keeps_its_name():
    assert from_argv("kubectl frobnicate x".split())[0].action == "frobnicate"


@pytest.mark.parametrize("rule,command", [
    (_rule("git", "tag/v1", ["update"], {"force": True}), "git tag -f v1 HEAD"),
    (_rule("git", "tag/v*", ["create"]), "git tag v1"),
    (_rule("github", "release/*", ["update"]), "gh release edit v1 --draft=false"),
])
def test_rules_on_writes_that_were_reads_now_block(rule, command):
    assert _verdict([rule], command) == "BLOCK"


# --- 4: wildcard targets ---------------------------------------------------------------


@pytest.mark.parametrize("rule,command,verdict", [
    # gcloud storage and gsutil expand a wildcard bucket when they run
    (_rule("gcp", "storage/bucket/prod-logs", ["delete"]),
     "gcloud storage rm gs://prod-*/secret", "ESCALATE"),
    (_rule("gcp", "storage/bucket/prod-logs", ["delete"]),
     "gsutil rm gs://prod-*/secret", "ESCALATE"),
    (_rule("gcp", "storage/bucket/prod-logs", ["delete"]),
     "gcloud storage rm gs://prod-?ogs/x", "ESCALATE"),
    (_rule("gcp", "storage/bucket/prod-logs", ["delete"]),
     "gcloud storage rm gs://[pq]rod-logs/x", "ESCALATE"),
    (_rule("gcp", "storage/bucket/dev-logs", ["delete"]),
     "gcloud storage rm gs://prod-*/secret", "ALLOW"),  # no name can match both
    (_rule("gcp", "storage/bucket/*", ["delete"]),
     "gcloud storage rm gs://prod-*/secret", "BLOCK"),
    (_rule("gcp", "storage/bucket/prod-*", ["delete"]),
     "gcloud storage rm gs://prod-*/secret", "BLOCK"),
    # a wildcard key, or -r, reaches every key it matches
    (_rule("gcp", "storage/bucket/b", ["delete"], {"key": "secret"}),
     "gcloud storage rm gs://b/se*", "ESCALATE"),
    (_rule("gcp", "storage/bucket/b", ["delete"], {"key": "logs/secret"}),
     "gsutil rm -r gs://b/logs", "ESCALATE"),
    (_rule("gcp", "storage/bucket/b", ["delete"], {"key": "secret"}),
     "gcloud storage rm gs://b/other", "ALLOW"),
    # aws s3 --recursive and sync reach every key under the path, by --include/--exclude
    (_rule("aws", "s3/bucket/b", ["delete"], {"key": "logs/secret"}),
     "aws s3 rm s3://b/logs --recursive --exclude * --include secret*", "ESCALATE"),
    (_rule("aws", "s3/bucket/b", ["put"], {"key": "app/config"}),
     "aws s3 sync ./dist s3://b/app", "ESCALATE"),
    (_rule("aws", "s3/bucket/b", ["delete"], {"key": "logs/secret"}),
     "aws s3 rm s3://b/logs", "ALLOW"),  # one object, named
])
def test_wildcard_targets_escalate_every_rule_they_may_match(rule, command, verdict):
    assert _verdict([rule], command) == verdict


# --- review round 5: a short option and its long option record the same -----------------


def _same(short: list[str], long: list[str]) -> None:
    def read(argv):
        try:
            return [(i.resource, i.action, i.params, i.metadata) for i in from_argv(argv)]
        except ValueError:
            return "refused"
    assert read(short) == read(long), (short, long)


@pytest.mark.parametrize("short,long", [
    # kubectl 1.36: every letter and the flag it is
    ("kubectl get pods -A", "kubectl get pods --all-namespaces"),
    ("kubectl delete -R -f d/", "kubectl delete --recursive --filename d/"),
    ("kubectl run x --image i -q", "kubectl run x --image i --quiet"),
    ("kubectl exec -i -t web -- sh", "kubectl exec --stdin --tty web -- sh"),
    ("kubectl delete pod web -i", "kubectl delete pod web --interactive"),
    ("kubectl get pods -w", "kubectl get pods --watch"),
    ("kubectl get pods -L app", "kubectl get pods --label-columns app"),
    ("kubectl logs web -c c1 -f -p", "kubectl logs web --container c1 --follow --previous"),
    ("kubectl apply -k d", "kubectl apply --kustomize d"),
    ("kubectl delete pod -l a=b", "kubectl delete pod --selector a=b"),
    ("kubectl delete pod web -n prod", "kubectl delete pod web --namespace prod"),
    ("kubectl get pods -o yaml", "kubectl get pods --output yaml"),
    ("kubectl get pods -s https://x", "kubectl get pods --server https://x"),
    ("kubectl get pods -v 6", "kubectl get pods --v 6"),
    ("kubectl patch deploy web -p {}", "kubectl patch deploy web --patch {}"),
    ("kubectl create deployment web --image x -r 3",
     "kubectl create deployment web --image x --replicas 3"),
    # helm 4.3.1 / 3.21.1
    ("helm upgrade api ./c -i -f v.yaml -n prod -l a=b",
     "helm upgrade api ./c --install --values v.yaml --namespace prod --labels a=b"),
    ("helm install -g ./c", "helm install --generate-name ./c"),
    ("helm list -A -a -d -q -r -m 5 -f x -l a=b -o json",
     "helm list --all-namespaces --all --date --short --reverse --max 5 --filter x "
     "--selector a=b --output json"),
    ("helm template api ./c -s t.yaml -a v1", "helm template api ./c --show-only t.yaml "
     "--api-versions v1"),
    # flux v2.10
    ("flux get ks -A -w -l a=b", "flux get ks --all-namespaces --watch --label-selector a=b"),
    ("flux logs -f -n prod", "flux logs --follow --namespace prod"),
    ("flux delete ks a -s", "flux delete ks a --silent"),
    ("flux create source git a --url u -u me -p pw",
     "flux create source git a --url u --username me --password pw"),
    # gcloud: from the reference pages
    ("gcloud container clusters delete c -z us-east1-b -q",
     "gcloud container clusters delete c --zone us-east1-b --quiet"),
    ("gcloud storage rm -r -a -c -I gs://b/x",
     "gcloud storage rm --recursive --all-versions --continue-on-error "
     "--read-paths-from-stdin gs://b/x"),
    # az: from azure-cli _params.py
    ("az aks scale -g rg -n c -c 1", "az aks scale --resource-group rg --name c --node-count 1"),
    ("az aks scale -g rg -n c -c1", "az aks scale -g rg -n c --node-count=1"),
    ("az sql db delete -s srv -n db -g rg -y",
     "az sql db delete --server srv --name db --resource-group rg --yes"),
    # git
    ("git push -f origin main", "git push --force origin main"),
    ("git branch -d x", "git branch --delete x"),
    ("git tag -a v1 -m x", "git tag --annotate v1 --message x"),
])
def test_short_and_long_spellings_give_the_same_intents(short, long):
    _same(short.split(), long.split())


def test_every_gcloud_alias_reads_as_its_flag():
    from aegis_core.parser import _gcloud_flag_tables

    for command, entry in _gcloud_flag_tables().items():
        if command in ("_source", "root"):
            continue
        for alias, flag in entry.get("alias", {}).items():
            kind = ("value" if flag in entry["value"] else "bool")
            target = "gs://b/x" if command.startswith("storage") else "x"
            short = f"-{alias}" if len(alias) == 1 else f"--{alias}"
            extra_s = [short, "v"] if kind == "value" else [short]
            extra_l = [f"--{flag}", "v"] if kind == "value" else [f"--{flag}"]
            base = ["gcloud", *command.split(), target]
            _same(base + extra_s, base + extra_l)


def test_every_az_short_option_reads_as_its_long_option():
    from aegis_core.parser import _AZ_VERBS, _az_aliases, _az_short_tables

    for scope in _az_short_tables():
        words = scope.split()
        if scope == "_source" or not words or words[-1] not in _AZ_VERBS:
            continue
        for letter, option in _az_aliases(words).items():
            if letter in "gnl":
                continue  # scope options, tested with their own values above
            base = ["az", *words, "-n", "x", "-g", "rg"]
            _same(base + [f"-{letter}=v"], base + [f"--{option}=v"])


def test_every_gh_short_flag_reads_as_its_long_flag():
    from aegis_core.parser import _gh_command_spec

    for group, sub in (("pr", "merge"), ("pr", "close"), ("repo", "delete"),
                       ("release", "create"), ("release", "delete"), ("secret", "set"),
                       ("secret", "delete"), ("variable", "set"), ("workflow", "run"),
                       ("issue", "delete"), ("issue", "close"), ("run", "delete"),
                       ("run", "cancel"), ("run", "rerun"), ("workflow", "enable"),
                       ("workflow", "disable")):
        bools, _values, shorts = _gh_command_spec((group, sub))
        for letter, flag in shorts.items():
            if flag == "repo":
                continue
            base = ["gh", group, sub, "1", "-R", "o/r"]
            if flag in bools:
                _same(base + [f"-{letter}"], base + [f"--{flag}"])
            else:
                _same(base + [f"-{letter}", "v"], base + [f"--{flag}=v"])


def test_every_argocd_short_flag_reads_as_its_long_flag():
    from aegis_core.parser import _ARGOCD_SHORT_BOOL_LETTERS, _argocd_short_name

    for verb in ("sync", "delete", "get", "set", "create", "list", "rollback"):
        for letter in "HNPcflopr":
            flag = _argocd_short_name(letter, verb)
            base = ["argocd", "app", verb, "a"]
            _same(base + [f"-{letter}", "v"], base + [f"--{flag}=v"])
        for letter in _ARGOCD_SHORT_BOOL_LETTERS - {"h"}:
            flag = _argocd_short_name(letter, verb)
            _same(["argocd", "app", verb, "a", f"-{letter}"],
                  ["argocd", "app", verb, "a", f"--{flag}"])


@pytest.mark.parametrize("short,long", [
    ("git branch -D x", "git branch --delete --force x"),
    ("git branch -M a b", "git branch --move --force a b"),
    ("git branch -C a b", "git branch --copy --force a b"),
])
def test_git_capital_letters_are_their_options_with_force(short, long):
    _same(short.split(), long.split())


# --- round 5: each value as the tool sends it ---------------------------------------------


@pytest.mark.parametrize("flags,value", [
    # helm decodes --set-json with Go's encoding/json: every number is a float64
    (["--set-json", "quota=9007199254740993"], 9007199254740992),
    (["--set-json", '{"quota": 9007199254740993}'], 9007199254740992),
    (["--set-json", "quota=1.0"], 1),
    # --set reads an int64 exactly (strvals typedVal)
    (["--set", "quota=9007199254740993"], 9007199254740993),
])
def test_helm_numbers_are_the_values_helm_gives_the_chart(flags, value):
    intent = from_argv(["helm", "upgrade", "r", "./c", *flags])[0]
    assert intent.params["set"]["quota"] == value


@pytest.mark.parametrize("value", ["quota=1e400", "quota=NaN", "quota=Infinity"])
def test_helm_set_json_refuses_numbers_go_refuses(value):
    with pytest.raises(ValueError):
        from_argv(["helm", "upgrade", "r", "./c", "--set-json", value])


def test_helm_set_json_rule_sees_the_rounded_number():
    rule = _rule("helm", "release/*", ["update"], {"set.quota": 9007199254740992})
    assert _verdict([rule], ["helm", "upgrade", "r", "./c", "--set-json",
                             "quota=9007199254740993"]) == "BLOCK"


@pytest.mark.parametrize("yaml_text,value", [
    # aws-cli v2 reads --cli-input-yaml as YAML 1.2 (run on aws 2.37)
    ("{AutoScalingGroupName: g, DesiredCapacity: 010}", 10),
    ("{AutoScalingGroupName: g, DesiredCapacity: 0o10}", 8),
    ("{AutoScalingGroupName: g, DesiredCapacity: 0x10}", 16),
    ("{AutoScalingGroupName: g, DesiredCapacity: 1_0}", 10),
])
def test_aws_yaml_input_is_read_as_aws_reads_it(yaml_text, value):
    intent = from_argv(["aws", "autoscaling", "set-desired-capacity", "--cli-input-yaml",
                        yaml_text])[0]
    assert intent.params["desired_capacity"] == value


def test_aws_yaml_yes_is_not_a_boolean():
    with pytest.raises(ValueError):  # aws refuses the string "yes" for a boolean
        from_argv(["aws", "autoscaling", "set-desired-capacity", "--cli-input-yaml",
                   "{AutoScalingGroupName: g, DesiredCapacity: 1, HonorCooldown: yes}"])


def test_aws_json_input_numbers_stay_exact():
    intent = from_argv(["aws", "autoscaling", "set-desired-capacity", "--cli-input-json",
                        '{"AutoScalingGroupName":"g","DesiredCapacity":9007199254740993}'])[0]
    assert intent.params["desired_capacity"] == 9007199254740993


@pytest.mark.parametrize("command,inputs", [
    # gh api -F types a value as gh does; -f is always a string
    ("gh api -X POST repos/o/r/x -F n=123 -F b=true -F z=null -F s=1.5 -f r=123",
     {"n": 123, "b": True, "z": None, "s": "1.5", "r": "123"}),
    ("gh api -X POST repos/o/r/x -F big=99999999999999999999",
     {"big": "99999999999999999999"}),  # out of int64: Atoi fails, a string
    # gh workflow run sends every input as a string
    ("gh workflow run d.yml -R o/r -F n=123 -f m=1", {"n": "123", "m": "1"}),
])
def test_gh_fields_are_the_values_gh_sends(command, inputs):
    assert from_argv(command.split())[0].params["inputs"] == inputs


@pytest.mark.parametrize("command,targets", [
    # list mode as builtin/branch.c and builtin/tag.c decide it (run on git 2.52)
    ("git branch --no-column -f prod HEAD~1",
     [("branch/prod", "create"), ("branch/prod", "update"), ("branch/prod", "delete")]),
    ("git branch -v x", [("branch/x", "create")]),
    ("git branch --sort=refname y", [("branch/y", "create")]),
    ("git branch --no-list a", [("branch/a", "create")]),
    ("git branch --no-contains x", [("branch/*", "read")]),
    ("git branch --list --column a*", [("branch/a*", "read")]),
    ("git branch --show-current", [("branch/*", "read")]),
    ("git tag --no-column v1", [("tag/v1", "create")]),
    ("git tag -n0", [("tag/*", "read")]),
    ("git tag --points-at HEAD", [("tag/*", "read")]),
    ("git tag -l v*", [("tag/v*", "read")]),
])
def test_git_list_mode_follows_git(command, targets):
    assert [(i.resource, i.action) for i in from_argv(command.split())] == targets


def test_git_branch_all_with_a_name_is_refused():
    with pytest.raises(ValueError):  # git: -a and -r do not take a branch name
        from_argv("git branch -a x".split())


def test_git_branch_force_rule_holds_with_no_column():
    rule = _rule("git", "branch/prod", ["update"], {"force": True})
    assert _verdict([rule], "git branch --no-column -f prod HEAD~1") == "BLOCK"


def test_gh_issue_edit_edits_every_issue_given():
    # gh issue edit takes several issues (cobra MinimumNArgs(1), cli v2.103)
    command = "gh issue edit 23 34 --add-label bug -R o/r"
    assert [i.resource for i in from_argv(command.split())] == ["issue/23", "issue/34"]
    assert _verdict([_rule("github", "issue/34", ["update"])], command) == "BLOCK"


def test_gh_issue_edit_selector_keeps_its_own_repository():
    a, b = from_argv("gh issue edit https://github.com/o/r/issues/5 6".split())
    assert a.metadata["repo"] == "o/r"
    assert "repo" not in b.metadata and "repo" in b.params["unresolved_scope"]


@pytest.mark.parametrize("command", [
    # every other command takes the count its cobra Args allow
    "gh issue close 1 2", "gh pr edit 1 2", "gh pr merge 1 2", "gh release delete v1 v2",
    "gh repo delete o/a o/b", "gh run cancel 1 2", "gh secret delete A B",
    "gh issue delete", "gh release upload v1",
])
def test_gh_refuses_argument_counts_gh_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


# --- review round 6 ------------------------------------------------------------------


def test_argocd_create_from_a_file_has_unknown_targets():
    # --file reads the Applications from a file or stdin; the name on the line is ignored
    command = "argocd app create decoy --file - --upsert"
    intent = from_argv(command.split())[0]
    assert intent.resource == "app/*"
    assert intent.params["resolved_at_runtime"] == {"from": "app/*", "kinds": ["app"]}
    assert _verdict([_rule("argocd", "app/payments", ["create"])], command) == "ESCALATE"
    rule = _rule("argocd", "app/*", ["create"], {"project": "prod", "sync_policy": "auto"})
    # the file's fields are unknown; a flag given on the line overrides the file's
    assert _verdict([rule], "argocd app create decoy -f a.yaml") == "ESCALATE"


def test_argocd_project_selection_is_not_the_named_apps_project():
    command = "argocd app sync payments --project dev"
    named, picked = from_argv(command.split())
    assert "project" not in named.metadata and "project" in named.params["unresolved_scope"]
    assert picked.metadata["project"] == "dev"
    rule = _rule("argocd", "app/payments", ["sync"], {"project": "prod"})
    assert _verdict([rule], command) == "ESCALATE"


def test_az_value_read_from_a_file_is_unresolved():
    intent = from_argv("az vm update -g rg -n v --set @-".split())[0]
    assert "set" in intent.params["unresolved_scope"]


def test_kubectl_run_l_is_labels():
    intent = from_argv("kubectl run web --image x -l app=web".split())[0]
    assert intent.params["labels"] == "app=web" and "selector" not in intent.params


@pytest.mark.parametrize("command,inputs", [
    # gh reads every -f first, then every -F (cli v2.103 run.go and api/fields.go)
    ("gh workflow run d.yml -R o/r -F environment=prod -f environment=dev",
     {"environment": "prod"}),
    ("gh workflow run d.yml -R o/r -f environment=dev -F environment=prod",
     {"environment": "prod"}),
    # gh api builds nested keys and arrays
    ("gh api -X POST repos/o/r/x -f a[b]=1 -F a[c]=2 -f l[]=x -f l[]=y",
     {"a": {"b": "1", "c": 2}, "l": ["x", "y"]}),
])
def test_gh_fields_follow_gh_order(command, inputs):
    assert from_argv(command.split())[0].params["inputs"] == inputs


def test_gh_workflow_environment_rule_sees_the_value_gh_sends():
    rule = _rule("github", "workflow/*", ["run"], {"inputs.environment": "prod"})
    command = "gh workflow run d.yml -R o/r --ref main -F environment=prod -f environment=dev"
    assert _verdict([rule], command) == "BLOCK"


@pytest.mark.parametrize("command", [
    "gh api -X POST repos/o/r/x -f a=1 -F a=2",  # gh: unexpected override existing field
    "gh api -X POST repos/o/r/x -f a",  # requires a value
])
def test_gh_api_refuses_fields_gh_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_kubectl_run_overrides_leave_the_object_unknown():
    command = "kubectl run web --image=safe --overrides {}"
    rule = _rule("kubernetes", "pod/*", ["run"], {"image": "evil"})
    assert _verdict([rule], command.split()) == "ESCALATE"


def test_gh_api_dispatch_inputs_meet_the_porcelain_rule():
    rule = _rule("github", "workflow/*", ["run"], {"inputs.env": "prod"})
    command = ["gh", "api", "-X", "POST", "repos/o/r/actions/workflows/d.yml/dispatches",
               "-f", "ref=main", "-F", "inputs[env]=prod"]
    assert _verdict([rule], command) == "BLOCK"


def test_az_formatted_scopes_are_read():
    # 'storage fs file delete' is built with .format() in azure-cli's _params.py
    intent = from_argv("az storage fs file delete -f fs -p prod --account-name a -y".split())[0]
    assert intent.params["file-system"] == "fs" and intent.params["path"] == "prod"
    rule = _rule("azure", "*", ["delete"], {"path": "prod"})
    assert _verdict([rule], "az storage fs file delete -f fs -p prod --account-name a -y"
                    .split()) == "BLOCK"


@pytest.mark.parametrize("command", [
    # a short letter with no known meaning on the command is refused, on every tool
    "az vm delete -g rg -n v -q x",
    "kubectl get pods -x",
    "helm upgrade api ./c -x",
    "flux get ks -x",
    "argocd app sync a -x",
    "gh pr merge 1 -x",
    "gh issue edit 1 -x foo",
    "gcloud compute instances delete web -x",
    "gcloud compute networks delete web -x",
])
def test_an_unmapped_short_letter_is_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command", ["git fetch -n origin", "git clean -fn", "git stash -p"])
def test_git_verbs_without_a_table_record_no_option_as_written(command):
    intent = from_argv(command.split())[0]
    assert "dry_run" not in intent.params
    assert intent.params["unresolved_scope"][0] == "*"


@pytest.mark.parametrize("command,resources", [
    # argparse reads the words after "--" as positionals: they are targets
    ("gcloud compute instances delete safe -- prod",
     ["compute/instance/safe", "compute/instance/prod"]),
    ("gcloud storage rm gs://a -- gs://b", ["storage/bucket/a", "storage/bucket/b"]),
])
def test_gcloud_words_after_dashes_are_targets(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources
    rule = _rule("gcp", resources[-1], ["delete"])
    assert _verdict([rule], command) == "BLOCK"


def test_gcloud_dashes_on_an_unknown_command_are_refused():
    with pytest.raises(ValueError):
        from_argv("gcloud compute networks delete a -- b".split())


@pytest.mark.parametrize("command,last", [
    # every other tool reads the words after "--" as its arguments, targets included
    ("kubectl delete pod safe -- prod", "pod/prod"),
    ("helm uninstall safe -- prod", "release/prod"),
    ("flux delete ks safe -- prod", "kustomization/prod"),
    ("argocd app delete safe -- prod", "app/prod"),
    ("gh repo delete -- o/prod", "repo/o/prod"),
    ("git branch -d safe -- prod", "branch/prod"),
])
def test_words_after_dashes_are_targets_on_every_tool(command, last):
    assert from_argv(command.split())[-1].resource == last


# --- review round 7 ------------------------------------------------------------------


def test_an_unresolved_key_is_never_decided_by_a_recorded_value():
    # the store: a key marked unresolved escalates whatever value is recorded for it
    from aegis_core.intent import InfrastructureIntent
    from aegis_core.store import scope_unresolved

    for mark in ("project", "*", "**"):
        intent = InfrastructureIntent(resource="app/*", action="create", provider="argocd",
                                      params={"unresolved_scope": [mark], "p_x": 1},
                                      metadata={"project": "dev"})
        assert scope_unresolved({"project": "prod"}, intent) == ["project"]
        if mark != "project":  # every key, given or not, through canonical_key
            assert scope_unresolved({"p-x": 2}, intent) == ["p-x"]


def test_argocd_stdin_apps_ignore_the_project_flag():
    command = "argocd app create decoy --file - --project dev --upsert"
    intent = from_argv(command.split())[0]
    assert "project" not in intent.metadata
    rule = _rule("argocd", "app/*", ["create"], {"project": "prod"})
    assert _verdict([rule], command) == "ESCALATE"


def test_argocd_create_from_a_file_needs_no_name():
    intent = from_argv("argocd app create -f application.yaml".split())[0]
    assert intent.resource == "app/*" and "resolved_at_runtime" in intent.params


@pytest.mark.parametrize("command,resource", [
    ("gh secret set DECOY --env-file - -R o/r", "secret/*"),
    ("gh variable set DECOY -f .env -R o/r", "variable/*"),
])
def test_gh_env_file_sets_names_from_the_file(command, resource):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource and "resolved_at_runtime" in intent.params
    rule = _rule("github", resource[:-1] + "PROD_KEY", ["put"])
    assert _verdict([rule], command) == "ESCALATE"


def test_gh_secret_body_from_stdin_is_unresolved():
    assert "body" in from_argv("gh secret set A -R o/r".split())[0].params["unresolved_scope"]


@pytest.mark.parametrize("command,resource", [
    ("gcloud storage buckets delete gs://prod", "storage/bucket/prod"),
    ("gcloud storage buckets describe gs://prod", "storage/bucket/prod"),
    ("gcloud storage buckets update gs://prod --no-versioning", "storage/bucket/prod"),
    ("gcloud storage objects delete gs://prod/secret", "storage/bucket/prod"),
])
def test_gcloud_gs_uris_are_buckets_on_every_storage_command(command, resource):
    assert from_argv(command.split())[0].resource == resource
    assert _verdict([_rule("gcp", "storage/bucket/prod", ["delete", "update", "read"])],
                    command) == "BLOCK"


@pytest.mark.parametrize("command", [
    "gcloud storage buckets update --read-paths-from-stdin --no-versioning",
    "gcloud storage buckets update gs://a -I --no-versioning",
])
def test_gcloud_stdin_paths_are_marked(command):
    rule = _rule("gcp", "storage/bucket/prod", ["update"])
    assert _verdict([rule], command) == "ESCALATE"


def test_every_star_target_is_marked_in_one_place():
    # whatever the parser, a kind/* target carries the runtime mark
    for command in ("kubectl get pods", "helm list", "flux get ks", "argocd app list",
                    "gh secret list -R o/r", "gcloud compute instances list",
                    "az vm list -g rg"):
        for intent in from_argv(command.split()):
            if intent.resource.endswith("/*"):
                assert "resolved_at_runtime" in intent.params, command


# --- review round 8 ------------------------------------------------------------------


@pytest.mark.parametrize("argv,key", [
    # an empty value is no value: the tool falls back to its configuration
    (["kubectl", "delete", "pod", "api", "--namespace="], "namespace"),
    (["kubectl", "delete", "pod", "api", "-n", ""], "namespace"),
    (["kubectl", "delete", "pod", "api", "--context="], "context"),
    (["helm", "uninstall", "r", "--namespace", ""], "namespace"),
    (["helm", "uninstall", "r", "--kube-context="], "context"),
    (["flux", "suspend", "ks", "a", "--namespace="], "namespace"),
    (["argocd", "app", "delete", "a", "--server=", "-y"], "server"),
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1", "--region", ""], "region"),
    (["gcloud", "compute", "instances", "delete", "a", "--project="], "project"),
    (["az", "vm", "delete", "-n", "v", "-g", "", "--yes"], "resource_group"),
])
def test_an_empty_scope_value_is_unresolved(argv, key):
    intent = from_argv(argv)[0]
    assert key not in intent.metadata


def test_an_empty_namespace_escalates_a_namespace_rule():
    rule = _rule("kubernetes", "pod/*", ["delete"], {"namespace": "prod"})
    assert _verdict([rule], ["kubectl", "delete", "pod", "api", "--namespace="]) == "ESCALATE"


def test_gh_placeholders_in_magic_fields_are_unresolved():
    command = ["gh", "api", "-X", "POST", "repos/o/r/actions/workflows/d.yml/dispatches",
               "-F", "ref={branch}"]
    intent = from_argv(command)[0]
    assert "ref" not in intent.metadata and "ref" in intent.params["unresolved_scope"]
    rule = _rule("github", "workflow/*", ["run"], {"ref": "main"})
    assert _verdict([rule], command) == "ESCALATE"


@pytest.mark.parametrize("command,resource", [
    ("git push origin @{u}", "ref/*"),
    ("git push origin HEAD:@{push}", "ref/*"),
    ("git branch -d -", "branch/*"),
    ("git branch -d @{-1}", "branch/*"),
])
def test_git_names_git_resolves_are_unknown(command, resource):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource


@pytest.mark.parametrize("command,key", [
    # argparse's allow_abbrev, against the command's declared long options
    ("az aks scale -g rg -n c --node-c 1", "node-count"),
    ("az aks scale -g rg -n c --node-count 1", "node-count"),
])
def test_az_long_option_prefix_is_the_full_option(command, key):
    assert from_argv(command.split())[0].params[key] == 1


def test_az_ambiguous_long_prefix_is_refused():
    with pytest.raises(ValueError):
        from_argv("az aks scale -g rg -n c --no 1".split())


def test_az_long_prefix_rule_holds():
    rule = _rule("azure", "aks/cluster/*", ["scale"], {"node-count": 1})
    assert _verdict([rule], "az aks scale -g rg -n c --node-c 1".split()) == "BLOCK"


@pytest.mark.parametrize("command,key,unresolved", [
    # a folder destination writes prefix + the source's base name
    ("gcloud storage cp /tmp/secret gs://prod/backup/", "backup/secret", False),
    ("gsutil cp /tmp/secret gs://prod/backup/", "backup/secret", False),
    ("gcloud storage cp /tmp/secret gs://prod/", "secret", False),
    ("aws s3 cp /tmp/secret s3://prod/backup/", "backup/secret", False),
    ("aws s3 mv s3://a/secret s3://prod/dir/", "dir/secret", False),
    # aws never treats a key without the slash as a folder
    ("aws s3 cp /tmp/secret s3://prod/backup", "backup", False),
    # gcloud and gsutil do when objects under it exist; several sources or -r: unknown
    ("gcloud storage cp /tmp/secret gs://prod/backup", "backup", True),
    ("gcloud storage cp /tmp/a /tmp/b gs://prod/backup/", "backup/", True),
    ("gsutil cp -r /tmp/d gs://prod/backup/", "backup/", True),
])
def test_copy_destination_key_is_the_object_written(command, key, unresolved):
    intent = [i for i in from_argv(command.split()) if i.resource.endswith("/prod")][-1]
    assert intent.params["key"] == key
    unknown = ("key" in intent.params.get("unresolved_scope", [])
               or "key" in intent.params.get("unresolved_prefix", {}))
    assert unknown is unresolved


def test_copy_into_a_folder_meets_a_rule_on_the_object():
    rule = _rule("gcp", "storage/bucket/prod", ["put"], {"key": "backup/secret"})
    assert _verdict([rule], "gcloud storage cp /tmp/secret gs://prod/backup/") == "BLOCK"



# --- az: every long option, against the command's full list ---------------------------

# Everyday az commands from the az reference, written with full option names: each must
# parse now that an option outside the command's list is refused.
AZ_EVERYDAY = [
    ("az vm create --resource-group rg --name vm1 --image Ubuntu2204 -"
     "-admin-username azureuser --generate-ssh-keys --size Standard_B2s"),
    "az vm delete --resource-group rg --name vm1 --yes",
    "az vm start --resource-group rg --name vm1",
    "az vm stop --resource-group rg --name vm1",
    "az vm deallocate --resource-group rg --name vm1 --no-wait",
    "az vm resize --resource-group rg --name vm1 --size Standard_D4s_v5",
    "az vm restart --resource-group rg --name vm1",
    ("az aks create --resource-group rg --name aks1 --node-c"
     "ount 3 --generate-ssh-keys --kubernetes-version 1.30.0"),
    "az aks scale --resource-group rg --name aks1 --node-count 5",
    "az aks upgrade --resource-group rg --name aks1 --kubernetes-version 1.31.0 --yes",
    "az aks delete --resource-group rg --name aks1 --yes --no-wait",
    "az aks nodepool add --resource-group rg --cluster-name aks1 --name np2 --node-count 2",
    "az aks nodepool delete --resource-group rg --cluster-name aks1 --name np2",
    ("az storage account create --resource-group rg --name sa"
     "1 --location eastus --sku Standard_LRS --kind StorageV2"),
    "az storage account delete --resource-group rg --name sa1 --yes",
    "az storage account update --resource-group rg --name sa1 --https-only true",
    "az keyvault create --resource-group rg --name kv1 --location eastus",
    "az keyvault delete --resource-group rg --name kv1",
    "az keyvault secret set --vault-name kv1 --name s1 --value x",
    "az keyvault secret delete --vault-name kv1 --name s1",
    "az network nsg create --resource-group rg --name nsg1",
    ("az network nsg rule create --resource-group rg --nsg-name nsg1 --name r1 "
     "--priority 100 --access Allow --protocol Tcp --destination-port-ranges 22"),
    "az network nsg rule delete --resource-group rg --nsg-name nsg1 --name r1",
    "az network vnet create --resource-group rg --name vnet1 --address-prefixes 10.0.0.0/16",
    "az group create --name rg --location eastus",
    "az group delete --name rg --yes --no-wait",
    "az webapp create --resource-group rg --plan plan1 --name app1 --runtime PYTHON:3.11",
    "az webapp delete --resource-group rg --name app1",
    "az webapp deploy --resource-group rg --name app1 --src-path app.zip --type zip",
    "az sql db delete --resource-group rg --server srv1 --name db1 --yes",
    "az sql db create --resource-group rg --server srv1 --name db1 --service-objective S0",
    ("az role assignment create --assignee user@example.com --role Re"
     "ader --scope /subscriptions/00000000-0000-0000-0000-000000000000"),
    "az role assignment delete --assignee user@example.com --role Reader --resource-group rg",
    "az functionapp delete --resource-group rg --name fn1",
    "az cosmosdb delete --resource-group rg --name db1 --yes",
    # multi-value options (round 10)
    ("az group create --name rg --locati"
     "on eastus --tags owner=ops env=prod"),
    ("az vm update --resource-group rg --name"
     " vm1 --set tags.env=prod tags.owner=ops"),
    ("az aks create --resource-group rg --n"
     "ame aks2 --zones 1 2 3 --node-count 3"),
    ("az vm create --resource-group rg --name vm2"
     " --image Ubuntu2204 --zone 1 --tags a=b c=d"),
    ("az network nsg rule create --resource-group rg --nsg-name nsg1 --name r2 --priority 20"
     "0 --destination-port-ranges 80 443 --source-address-prefixes 10.0.0.0/8 192.168.0.0/16"),
    ("az storage account update --resource-group r"
     "g --name sa1 --set tags.x=y --remove tags.old"),
]


@pytest.mark.parametrize("command", AZ_EVERYDAY)
def test_everyday_az_commands_parse(command):
    import shlex

    assert from_argv(shlex.split(command))


@pytest.mark.parametrize("command", [
    # neither an option of the command nor a unique prefix of one: refused
    "az aks scale --resource-group rg --name c --bogus 1",
    # --kubernetes-version is declared for the aks group, not on aks scale
    "az aks scale --resource-group rg --name c --kub 1.30",
    "az vm delete --resource-group rg --name v --fo",  # --force-deletion, and only it
])
def test_az_option_outside_the_command_is_refused(command):
    if command.endswith("--fo"):
        assert from_argv(command.split())[0].params["force-deletion"] is True
        return
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_az_option_known_only_from_the_signature_is_accepted():
    # aks scale's --nodepool-name comes from aks_scale's signature, not _params.py
    intent = from_argv("az aks scale -g rg -n c --nodepool-name np1 --node-count 2".split())[0]
    assert intent.params["nodepool-name"] == "np1"


# --- review round 9 ------------------------------------------------------------------


def test_argocd_delete_selector_is_not_narrowed_by_the_namespace():
    # delete lists the selector's apps in every namespace (getAppNamesBySelector)
    command = "argocd app delete -l team=payments -N dev -y"
    picked = from_argv(command.split())[-1]
    assert picked.resource == "app/*" and "app_namespace" not in picked.metadata
    rule = _rule("argocd", "app/*", ["delete"], {"app_namespace": "prod"})
    assert _verdict([rule], command) == "ESCALATE"
    # sync passes -N to its List, so there the selection is in that namespace
    synced = from_argv("argocd app sync -l team=payments -N dev".split())[-1]
    assert synced.metadata["app_namespace"] == "dev"


@pytest.mark.parametrize("command,resource", [
    ("git branch -f @{-1} HEAD~1", "branch/*"),
    ("git branch -m @{-1} new", "branch/*"),
    ("git branch -c @{-1} copy", "branch/copy"),
    ("git branch -u origin/x @{-1}", "branch/*"),
    ("git tag -f @{-1}", "tag/*"),
    ("git branch -d -", "branch/*"),
    ("git push origin HEAD:@{push}", "ref/*"),
])
def test_every_git_name_operand_git_resolves_is_unknown(command, resource):
    resources = [i.resource for i in from_argv(command.split())]
    assert resource in resources
    assert not any("@{" in r for r in resources)


@pytest.mark.parametrize("command", ["git rebase origin/main", "git reset --hard HEAD~1",
                                     "git commit --amend -m x"])
def test_git_rewrites_reach_the_current_branch(command):
    rule = _rule("git", "history/main", ["rewrite"])
    assert _verdict([rule], command) == "ESCALATE"


@pytest.mark.parametrize("command", [
    "gcloud storage rm gs://prod/secret#123456789",
    "gsutil rm gs://prod/secret#123456789",
])
def test_gcs_generation_is_not_part_of_the_key(command):
    intent = from_argv(command.split())[0]
    assert intent.params["key"] == "secret"
    assert intent.params["generation"] == 123456789
    rule = _rule("gcp", "storage/bucket/prod", ["delete"], {"key": "secret"})
    assert _verdict([rule], command) == "BLOCK"


def test_gcs_generation_on_a_copy_source():
    intents = from_argv("gcloud storage cp gs://a/x#5 gs://b/dir/".split())
    assert [i.params["key"] for i in intents] == ["x", "dir/x"]


@pytest.mark.parametrize("command,keys", [
    ("gcloud compute instances delete web --project acme-prod", ["zone", "region", "account"]),
    ("kubectl delete pod x -n prod", ["context", "cluster", "user"]),
    ("helm uninstall r -n prod", ["context", "cluster", "user"]),
    ("flux suspend ks a -n prod", ["context", "cluster", "user"]),
    ("aws ec2 terminate-instances --instance-ids i-1", ["region", "profile", "account"]),
    ("az vm delete -n v --yes", ["subscription", "resource_group", "region"]),
    ("argocd app delete a -y", ["server", "project", "app_namespace"]),
    ("gh repo delete o/r --yes", ["github_host"]),
    ("git push origin main", []),
    ("git push", ["remote"]),
])
def test_every_config_scope_key_is_marked_when_absent(command, keys):
    marks = from_argv(command.split())[0].params.get("unresolved_scope", [])
    assert all(k in marks for k in keys), marks


def test_gcloud_zone_rule_escalates_without_a_zone():
    rule = _rule("gcp", "compute/instance/*", ["delete"], {"zone": "us-east1-b"})
    assert _verdict([rule], "gcloud compute instances delete web --project p") == "ESCALATE"


@pytest.mark.parametrize("command,key", [
    ("kubectl delete pod x --user admin", "user"),
    ("flux suspend ks a --user admin", "user"),
])
def test_the_kubeconfig_user_is_recorded(command, key):
    intent = from_argv(command.split())[0]
    assert intent.metadata[key] == "admin"
    assert key not in intent.params.get("unresolved_scope", [])


# --- review round 10 -----------------------------------------------------------------


def test_git_push_mapping_on_the_line_is_applied():
    # push.c refspec_append_mapped: a remote.<name>.push refspec maps a source-only push
    command = "git -c remote.origin.push=+refs/heads/safe:refs/heads/prod push origin safe"
    intents = from_argv(command.split())
    prod = [i for i in intents if i.resource == "ref/prod"][0]
    assert prod.params["force"] is True
    assert _verdict([_rule("git", "ref/prod", ["push"], {"force": True})], command) == "BLOCK"


@pytest.mark.parametrize("command,verdict", [
    # with no destination, config files may map it: the source is known, the destination not
    ("git push origin safe", "ESCALATE"),
    ("git push origin safe:safe", "ALLOW"),
    ("git push origin refs/heads/safe:refs/heads/safe", "ALLOW"),
])
def test_git_push_destination_unknown_without_a_full_refspec(command, verdict):
    assert _verdict([_rule("git", "ref/prod", ["push"])], command) == verdict


@pytest.mark.parametrize("command,key,value", [
    # repeated flags accumulate exactly where pflag's type does (StringArray, StringSlice)
    ("argocd app sync a --resource apps:Deployment:x --resource apps:Deployment:y",
     "resource", ["apps:Deployment:x", "apps:Deployment:y"]),
    ("kubectl get pods -L a,b -L c", "label-columns", ["a", "b", "c"]),
    ("helm template api ./c --api-versions v1,v2 --api-versions v3", "api_versions",
     ["v1", "v2", "v3"]),
    # integers with base 0, durations in seconds, as pflag reads them
    ("helm upgrade r ./c --history-max 0x0", "history_max", 0),
    ("helm upgrade r ./c --timeout 5m", "timeout", 300),
    ("helm upgrade r ./c --timeout 300s", "timeout", 300),
    ("flux reconcile ks a --timeout 1h", "timeout", 3600),
    ("kubectl logs web --since 1h2m3s", "since", 3723),
])
def test_pflag_types_are_read_from_the_registrations(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("command", [
    "helm upgrade r ./c --history-max ten",  # an Int pflag refuses
    "helm upgrade r ./c --timeout 5",  # a Duration needs its unit
    "flux reconcile ks a --timeout 5x",
])
def test_pflag_refuses_values_pflag_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_every_typed_flag_in_the_tables_is_read_by_its_type():
    # class-level: whatever the tool, the store reads each flag by the type its
    # registration gives it
    from aegis_core.parser import _pflag_store, _pflag_tables

    for tool in ("kubectl", "helm", "flux", "argocd", "gh"):
        for flag, kind in _pflag_tables()[tool].items():
            params: dict = {}
            if kind in ("Int", "Int32", "Int64"):
                _pflag_store(params, tool, flag, "k", "0x10")
                assert params["k"] == 16, (tool, flag)
            elif kind == "Duration":
                _pflag_store(params, tool, flag, "k", "1m30s")
                assert params["k"] == 90, (tool, flag)
            elif kind == "StringSlice":
                _pflag_store(params, tool, flag, "k", "a,b")
                _pflag_store(params, tool, flag, "k", "c")
                assert params["k"] == ["a", "b", "c"], (tool, flag)
            elif kind == "StringArray":
                _pflag_store(params, tool, flag, "k", "a,b")
                _pflag_store(params, tool, flag, "k", "c")
                assert params["k"] == ["a,b", "c"], (tool, flag)


def test_a_rule_meets_any_value_of_a_repeated_flag():
    rule = _rule("argocd", "app/*", ["sync"], {"resource": "apps:Deployment:x"})
    command = "argocd app sync a --resource apps:Deployment:x --resource apps:Deployment:y"
    assert _verdict([rule], command) == "BLOCK"


@pytest.mark.parametrize("command,key,value", [
    # az: every word up to the next option, as argparse gives nargs + / * and append
    ("az group create --name rg --location eastus --tags owner=ops env=prod", "tags",
     {"owner": "ops", "env": "prod"}),  # tags_type's validate_tags
    ("az vm update -g rg -n v --set a=1 b=2 --set c=3", "set", ["a=1", "b=2", "c=3"]),
    ("az aks create -g rg -n c --zones 1 2 3", "zones", ["1", "2", "3"]),
    # aws: a list parameter takes every word up to the next option
    ("aws ec2 create-tags --resources i-1 i-2 --tags Key=a,Value=b Key=c,Value=d",
     "resources", ["i-1", "i-2"]),
    # gcloud: an ArgList or ArgDict is split on commas (or the ^X^ delimiter)
    ("gcloud compute instances create web --zone z --tags a,b", "tags", ["a", "b"]),
    ("gcloud compute instances create web --zone z --labels k=v,k2=v2", "labels",
     {"k": "v", "k2": "v2"}),
    ("gcloud compute instances update web --update-labels ^:^env=prod:team=x",
     "update-labels", {"env": "prod", "team": "x"}),
])
def test_multi_value_options_take_every_value(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("rule,command", [
    (_rule("azure", "resource/group/*", ["create"], {"tags.env": "prod"}),
     "az group create --name rg --location eastus --tags owner=ops env=prod"),
    (_rule("gcp", "compute/instance/*", ["create"], {"labels.env": "prod"}),
     "gcloud compute instances create web --zone z --labels team=x,env=prod"),
])
def test_a_rule_meets_one_value_of_a_multi_value_option(rule, command):
    assert _verdict([rule], command) == "BLOCK"


# --- typed values: one normalizer for the parser's side and the rule's side -----------


@pytest.mark.parametrize("rule_value", ["5m", "300s", "5m0s", 300, "300s"])
def test_a_duration_rule_meets_every_spelling(rule_value):
    rule = _rule("helm", "release/*", ["update"], {"timeout": rule_value})
    assert _verdict([rule], "helm upgrade r ./c --timeout 300s") == "BLOCK"
    assert _verdict([rule], "helm upgrade r ./c --timeout 5m") == "BLOCK"
    assert _verdict([rule], "helm upgrade r ./c --timeout 6m") == "ALLOW"


@pytest.mark.parametrize("rule_value,command,verdict", [
    ("0x0", "helm upgrade r ./c --history-max 0", "BLOCK"),
    (0, "helm upgrade r ./c --history-max 0x0", "BLOCK"),
    ("010", "helm upgrade r ./c --history-max 8", "BLOCK"),  # Go base 0: octal
    ("10", "helm upgrade r ./c --history-max 0xa", "BLOCK"),
])
def test_an_int_rule_is_read_as_go_reads_it(rule_value, command, verdict):
    rule = _rule("helm", "release/*", ["update"], {"history-max": rule_value})
    assert _verdict([rule], command) == verdict


@pytest.mark.parametrize("rule_value", [False, "false", "False", "0", "f", 0])
def test_a_bool_rule_meets_every_spelling(rule_value):
    rule = _rule("helm", "release/*", ["update"], {"install": rule_value})
    assert _verdict([rule], "helm upgrade r ./c --install=false") == "BLOCK"


def test_a_map_rule_meets_a_string_to_string_value():
    rule = _rule("helm", "release/*", ["update"], {"labels": "a=1,b=2"})
    assert _verdict([rule], "helm upgrade r ./c --labels b=2,a=1") == "BLOCK"


def test_a_rule_value_its_type_cannot_hold_escalates():
    # neither a match nor a miss: the rule escalates, as an unknown value does
    rule = _rule("helm", "release/*", ["update"], {"timeout": "soon"})
    assert _verdict([rule], "helm upgrade r ./c --timeout 300s") == "ESCALATE"


# --- review round 11 -----------------------------------------------------------------


@pytest.mark.parametrize("command,resource,key,value", [
    # a value is typed only by the type the tool declares for it
    ("aws s3api delete-object --bucket production --key 001", "s3/object/production/001",
     "key", "001"),
    ("gcloud compute instances create web --zone z --description 001",
     "compute/instance/web", "description", "001"),
    ("aws autoscaling set-desired-capacity --auto-scaling-group-name g --desired-capacity 010",
     "autoscaling/auto-scaling-group/g", "desired_capacity", 10),  # botocore integer
    ("az aks scale -g rg -n c --node-count 03", "aks/cluster/c", "node-count", 3),  # type=int
    ("az group update -n rg --set tags.x=001", "resource/group/rg", "set", ["tags.x=001"]),
    ("kubectl run web --image 001", "pod/web", "image", "001"),
    ("helm upgrade r ./c --version 1.10", "release/r", "version", "1.10"),
    ("git push --push-option 007 origin main", "ref/main", "push_option", ["007"]),
])
def test_values_are_typed_only_by_the_declared_type(command, resource, key, value):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource
    assert intent.params[key] == value


def test_a_rule_on_the_exact_key_text_holds():
    rule = _rule("aws", "s3/object/production/001", ["delete"])
    assert _verdict([rule], "aws s3api delete-object --bucket production --key 001") == "BLOCK"
    rule = _rule("aws", "s3/object/production/1", ["delete"])
    assert _verdict([rule], "aws s3api delete-object --bucket production --key 001") == "ALLOW"


@pytest.mark.parametrize("flags,value", [
    # helm 4's waitValue.Set
    ("--wait", "watcher"), ("--wait=true", "watcher"), ("--wait=false", "hookOnly"),
    ("--wait=legacy", "legacy"), ("--wait=hookOnly", "hookOnly"),
])
def test_helm_wait_is_read_as_helm_4_reads_it(flags, value):
    intent = from_argv(["helm", "upgrade", "r", "./c", flags])[0]
    assert intent.params["wait"] == value
    assert "wait" in intent.params["unresolved_scope"]  # helm 3 reads a boolean


def test_helm_wait_refuses_what_helm_refuses():
    with pytest.raises(ValueError):
        from_argv(["helm", "upgrade", "r", "./c", "--wait=soon"])


def test_an_int_slice_rule_is_normalized():
    rule = _rule("argocd", "app/*", ["sync"], {"source-positions": "0x1"})
    assert _verdict([rule], "argocd app sync a --source-positions 1") == "BLOCK"


def test_every_pflag_type_has_a_normalization():
    # class-level: every type the generator found (custom Values resolved) is known
    from aegis_core.parser import PFLAG_NORMAL_KIND, _pflag_tables

    tables = _pflag_tables()
    for tool in ("kubectl", "helm", "flux", "argocd", "gh"):
        for kind in tables[tool].values():
            for part in (kind[len("mixed:"):].split(",") if kind.startswith("mixed:")
                         else [kind]):
                assert part in PFLAG_NORMAL_KIND, (tool, part)


def test_every_custom_pflag_value_is_handled():
    from aegis_core.parser import _pflag_tables

    tables = _pflag_tables()
    for tool in ("kubectl", "helm", "flux", "argocd", "gh"):
        for flag in tables.get(f"{tool}:custom", []):
            assert not tables[tool][flag].startswith("value"), (tool, flag)


@pytest.mark.parametrize("value,expected", [
    ("^--^env=prod--team=x", {"env": "prod", "team": "x"}),
    ("^:^env=prod:team=x", {"env": "prod", "team": "x"}),
    ("^;;^a=1,2;;b=3", {"a": "1,2", "b": "3"}),
])
def test_gcloud_delimiters_of_any_length(value, expected):
    intent = from_argv(["gcloud", "compute", "instances", "update", "web", "--update-labels",
                        value])[0]
    assert intent.params["update-labels"] == expected


# --- review round 12 -----------------------------------------------------------------


@pytest.mark.parametrize("command,resources", [
    # the subcommand word of create secret/service is not a name
    ("kubectl create secret generic settings --from-literal a=b", ["secret/settings"]),
    ("kubectl create secret tls t --cert c --key k", ["secret/t"]),
    ("kubectl create secret docker-registry r --docker-server s", ["secret/r"]),
    ("kubectl create service clusterip web --tcp 80:80", ["service/web"]),
    ("kubectl create service nodeport web --tcp 80:80", ["service/web"]),
    # --append-hash renames the object NAME-<hash>
    ("kubectl create secret generic settings --append-hash --from-literal a=b",
     ["secret/settings-*"]),
    ("kubectl create configmap c --from-literal a=b --append-hash", ["configmap/c-*"]),
])
def test_kubectl_create_names_the_object_kubectl_creates(command, resources):
    assert [i.resource for i in from_argv(command.split())] == resources


def test_append_hash_escalates_a_rule_on_one_hashed_name():
    command = "kubectl create secret generic settings --append-hash --from-literal a=b"
    assert _verdict([_rule("kubernetes", "secret/settings-abc123", ["create"])],
                    command) == "ESCALATE"
    assert _verdict([_rule("kubernetes", "secret/other-*", ["create"])], command) == "ALLOW"


def test_aws_generate_cli_skeleton_calls_nothing():
    intent = from_argv("aws ec2 terminate-instances --instance-ids i-1 "
                       "--generate-cli-skeleton".split())[0]
    assert intent.params["dry_run"] is True


@pytest.mark.parametrize("argv,key,value", [
    # aws-cli argprocess: JSON for a value starting with [ or {, shorthand otherwise
    (["aws", "ec2", "terminate-instances", "--instance-ids", '["i-1","i-2"]'], None, None),
    (["aws", "ec2", "create-tags", "--resources", "i-1", "--tags", "Key=a,Value=b",
      "Key=c,Value=d"], "tags", [{"Key": "a", "Value": "b"}, {"Key": "c", "Value": "d"}]),
    (["aws", "ec2", "create-tags", "--resources", "i-1", "--tags",
      '[{"Key":"a","Value":"b"}]'], "tags", [{"Key": "a", "Value": "b"}]),
    (["aws", "ec2", "describe-instances", "--filters", "Name=tag:env,Values=prod,dev"],
     "filters", [{"Name": "tag:env", "Values": ["prod", "dev"]}]),
])
def test_aws_complex_values_are_decoded_as_aws_decodes_them(argv, key, value):
    intents = from_argv(argv)
    if key is None:
        assert [i.resource for i in intents] == ["ec2/instance/i-1", "ec2/instance/i-2"]
    else:
        assert intents[0].params[key] == value


def test_aws_json_list_targets_meet_their_rule():
    rule = _rule("aws", "ec2/instance/i-2", ["delete"])
    assert _verdict([rule], ["aws", "ec2", "terminate-instances", "--instance-ids",
                             '["i-1","i-2"]']) == "BLOCK"


@pytest.mark.parametrize("argv", [
    ["aws", "ec2", "terminate-instances", "--instance-ids", "[i-1"],  # not JSON
    ["aws", "ec2", "create-tags", "--resources", "i-1", "--tags", "Key=a,=b"],
])
def test_aws_refuses_values_aws_cannot_decode(argv):
    with pytest.raises(ValueError):
        from_argv(argv)


@pytest.mark.parametrize("command,key,value", [
    # az validators: tags_type makes a map, get_three_state_flag a bool, get_enum_type a
    # choice spelled as declared
    ("az group create --name rg --location eastus --tags env=prod owner", "tags",
     {"env": "prod", "owner": ""}),
    ("az storage account update -g rg -n sa --enable-sftp TRUE", "enable-sftp", True),
    ("az storage account update -g rg -n sa --use-subdomain True", "use-subdomain", "true"),
])
def test_az_validators_convert_values_as_az_does(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


def test_az_tags_rule_meets_the_map():
    rule = _rule("azure", "resource/group/*", ["create"], {"tags.env": "prod"})
    assert _verdict([rule], "az group create --name rg --location eastus --tags env=prod"
                    .split()) == "BLOCK"


@pytest.mark.parametrize("command,key,value", [
    # gcloud: each value by the type the SDK declares (calliope arg_parsers)
    ("gcloud container clusters resize c --num-nodes 03 --region r", "num-nodes", 3),
    ("gcloud compute instances create w --zone z --boot-disk-size 10GB", "boot-disk-size",
     10 * 1024 ** 3),
    ("gcloud compute instances create w --zone z --boot-disk-size 10", "boot-disk-size",
     10 * 1024 ** 3),  # BinarySize's default unit, GB
])
def test_gcloud_values_are_typed_by_the_sdk(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("rule_value,command", [
    ("3", "gcloud container clusters resize c --num-nodes 03 --region r"),
    ("10GB", "gcloud compute instances create w --zone z --boot-disk-size 10240MB"),
])
def test_gcloud_typed_rules_meet_every_spelling(rule_value, command):
    key = "num-nodes" if "num-nodes" in command else "boot-disk-size"
    rule = _rule("gcp", "*", ["scale", "create"], {key: rule_value})
    assert _verdict([rule], command) == "BLOCK"


# --- review round 13 ------------------------------------------------------------------


@pytest.mark.parametrize("command,container", [
    # logs.go Complete: a second word is the container, and it wins over -c
    ("kubectl logs web secret -c public -n prod", "secret"),
    ("kubectl logs -c public web secret -n prod", "secret"),
    ("kubectl logs deploy/web secret -n prod", "secret"),
    ("kubectl logs web -c public -n prod", "public"),
])
def test_kubectl_logs_second_word_is_the_container_over_c(command, container):
    assert all(i.params["container"] == container for i in from_argv(command.split()))


def test_kubectl_logs_rule_on_the_container_meets_the_second_word():
    rule = _rule("kubernetes", "pod/*", ["logs"], {"container": "secret"})
    assert _verdict([rule], "kubectl logs web secret -c public -n prod") == "BLOCK"
    with pytest.raises(ValueError):  # logs takes a pod and a container, no more
        from_argv("kubectl logs web a b -n prod".split())


@pytest.mark.parametrize("command,host,repo", [
    # the absolute URL names the host and the repository, whatever --hostname says
    ("gh api --hostname staging.example https://api.github.com/repos/acme/prod/actions/"
     "secrets/X -X DELETE", "github.com", "acme/prod"),
    # another host is a GitHub Enterprise Server: its repository is host/owner/repo
    ("gh api https://ghe.corp/api/v3/repos/acme/prod/actions/secrets/X -X DELETE",
     "ghe.corp", "ghe.corp/acme/prod"),
])
def test_gh_api_absolute_url_decides_host_and_repo(command, host, repo):
    intent = from_argv(command.split())[0]
    assert intent.metadata["github_host"] == host
    assert intent.metadata["repo"] == repo


@pytest.mark.parametrize("scope,verdict", [
    ({"github_host": "github.com"}, "BLOCK"),
    ({"repo": "acme/prod"}, "BLOCK"),
    ({"github_host": "staging.example"}, "ALLOW"),
])
def test_gh_api_rules_meet_the_url_host_not_hostname(scope, verdict):
    rule = _rule("github", "secret/*", ["delete"], scope)
    command = ("gh api --hostname staging.example https://api.github.com/repos/acme/prod/"
               "actions/secrets/X -X DELETE")
    assert _verdict([rule], command) == verdict


def test_gh_api_ghes_repo_is_not_the_github_com_repo():
    command = "gh api https://ghe.corp/api/v3/repos/acme/prod/actions/secrets/X -X DELETE"
    assert _verdict([_rule("github", "secret/*", ["delete"], {"repo": "acme/prod"})],
                    command) == "ALLOW"
    assert _verdict([_rule("github", "secret/*", ["delete"], {"repo": "ghe.corp/acme/prod"})],
                    command) == "BLOCK"


@pytest.mark.parametrize("command", [
    "kubectl delete pod x --server https://prod:6443 --cluster dev -n a",
    "kubectl delete pod x -s https://prod:6443 --cluster dev -n a",
    "helm uninstall web --kube-apiserver https://prod:6443 -n a",
    "flux suspend kustomization app --server https://prod:6443 -n a",
])
def test_kube_server_override_leaves_the_cluster_unresolved(command):
    intent = from_argv(command.split())[0]
    assert intent.metadata["server"] == "https://prod:6443"
    assert "cluster" not in intent.metadata
    assert "cluster" in intent.params["unresolved_scope"]


def test_kube_server_override_is_not_filled_with_the_kubeconfig_cluster(tmp_path):
    from aegis_core.environments import resolve_current_context

    path = tmp_path / "kubeconfig"
    path.write_text("apiVersion: v1\nkind: Config\ncurrent-context: dev\ncontexts:\n"
                    "- name: dev\n  context: {cluster: dev-cluster, user: me}\n")
    intent = from_argv("kubectl delete pod x --server https://prod:6443 -n a".split())[0]
    resolve_current_context(intent, environ={"KUBECONFIG": str(path)})
    assert intent.metadata["context"] == "dev"
    assert "cluster" not in intent.metadata
    rule = _rule("kubernetes", "pod/*", ["delete"], {"cluster": "dev-cluster"})
    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    store.add_constraint(rule)
    assert AegisInterceptor(store).intercept(intent, now=NOW).verdict == "ESCALATE"


def test_aws_endpoint_url_leaves_account_and_region_unresolved():
    command = ("aws ec2 terminate-instances --instance-ids i-1 --region us-east-1 "
               "--endpoint-url https://x")
    intent = from_argv(command.split())[0]
    assert intent.metadata["endpoint_url"] == "https://x"
    assert "region" not in intent.metadata
    assert {"region", "account"} <= set(intent.params["unresolved_scope"])
    rule = _rule("aws", "ec2/instance/*", ["delete"], {"region": "us-east-1"})
    assert _verdict([rule], command) == "ESCALATE"


@pytest.mark.parametrize("environ", [
    {"AWS_REGION": "us-east-1", "AWS_ENDPOINT_URL": "https://x"},
    {"AWS_REGION": "us-east-1", "AWS_ENDPOINT_URL_EC2": "https://x"},
])
def test_aws_endpoint_override_in_the_environment_is_not_filled_with_a_region(environ):
    from aegis_core.environments import resolve_current_context

    intent = from_argv("aws ec2 terminate-instances --instance-ids i-1".split())[0]
    resolve_current_context(intent, environ=environ)
    assert "region" not in intent.metadata
    assert "region" in intent.params["unresolved_scope"]


@pytest.mark.parametrize("command", [
    "az group update -n rg --tags @tags.txt",
    "az group update -n rg --tags @-",
    "az group update -n rg --tags env=prod @more.txt",
])
def test_az_value_from_a_file_is_not_converted_and_nested_keys_are_unresolved(command):
    intent = from_argv(command.split())[0]
    assert not isinstance(intent.params["tags"], dict)  # not converted as a literal
    assert {"tags", "tags.*"} <= set(intent.params["unresolved_scope"])
    rule = _rule("azure", "resource/group/*", ["update"], {"tags.env": "prod"})
    assert _verdict([rule], command) == "ESCALATE"


def test_az_literal_tags_still_convert():
    rule = _rule("azure", "resource/group/*", ["update"], {"tags.env": "prod"})
    assert _verdict([rule], "az group update -n rg --tags env=prod") == "BLOCK"
    assert _verdict([rule], "az group update -n rg --tags env=dev") == "ALLOW"


@pytest.mark.parametrize("command,key", [
    # paramfile runs before JSON or shorthand, and takes a one-word list as that word
    ("aws ec2 create-tags --resources i-1 --tags file://t.json", "tags"),
    ("aws ec2 run-instances --image-id ami-1 --tag-specifications file://t.json",
     "tag-specifications"),
    ("aws lambda update-function-code --function-name f --zip-file fileb://f.zip",
     "zip-file"),
])
def test_aws_file_value_is_read_before_shorthand(command, key):
    intent = from_argv(command.split())[0]
    assert {key, f"{key}.*"} <= set(intent.params["unresolved_scope"])


def test_aws_file_tags_escalate_a_nested_rule():
    rule = _rule("aws", "ec2/tag/*", ["create"], {"tags.Key": "env"})
    assert _verdict([rule], "aws ec2 create-tags --resources i-1 --tags file://t.json") == \
        "ESCALATE"


@pytest.mark.parametrize("command", [
    "kubectl create configmap cm --from-file=config.yaml -n prod",
    "kubectl create configmap cm --from-file=key=path -n prod",
    "kubectl create secret generic s --from-env-file=.env --from-literal=a=b -n prod",
])
def test_kubectl_data_from_files_is_unresolved(command):
    intent = from_argv(command.split())[0]
    assert {"data", "data.*"} <= set(intent.params["unresolved_scope"])


def test_gh_field_from_a_file_is_unresolved_and_raw_field_is_text():
    typed = from_argv("gh api repos/a/b -F name=@n.txt -X PATCH".split())[0]
    assert "inputs.name" in typed.params["unresolved_scope"]
    raw = from_argv("gh api repos/a/b -f name=@n.txt -X PATCH".split())[0]
    assert raw.params["inputs"] == {"name": "@n.txt"}
    assert "inputs.name" not in raw.params.get("unresolved_scope", [])


# --- review round 14 ------------------------------------------------------------------


@pytest.mark.parametrize("command,resource,action,namespace", [
    # kubectl sends one request to the raw path; the words, -n and --dry-run are not read
    ("kubectl delete pod harmless -n dev --raw=/api/v1/namespaces/prod/pods/protected",
     "pod/protected", "delete", "prod"),
    ("kubectl delete pod harmless -n dev --dry-run=server --raw "
     "/api/v1/namespaces/prod/pods/protected", "pod/protected", "delete", "prod"),
    ("kubectl replace --raw /apis/apps/v1/namespaces/prod/deployments/web -f d.json",
     "deployment/web", "replace", "prod"),
    ("kubectl create --raw /api/v1/namespaces/prod/pods -f p.json", "pod/*", "create",
     "prod"),
    ("kubectl delete --raw /api/v1/nodes/n1", "node/n1", "delete", None),
    ("kubectl delete --raw /apis/rbac.authorization.k8s.io/v1/clusterroles/admin",
     "clusterrole/admin", "delete", None),
    ("kubectl get --raw /api/v1/namespaces/prod/secrets/x", "secret/x", "get", "prod"),
])
def test_kubectl_raw_path_is_the_target(command, resource, action, namespace):
    intents = from_argv(command.split())
    assert [(i.resource, i.action) for i in intents] == [(resource, action)]
    assert intents[0].metadata.get("namespace") == namespace
    assert "dry_run" not in intents[0].params


def test_kubectl_raw_rules_meet_the_path_not_the_words():
    command = "kubectl delete pod harmless -n dev --raw=/api/v1/namespaces/prod/pods/protected"
    assert _verdict([_rule("kubernetes", "pod/protected", ["delete"])], command) == "BLOCK"
    assert _verdict([_rule("kubernetes", "pod/*", ["delete"], {"namespace": "prod"})],
                    command) == "BLOCK"
    assert _verdict([_rule("kubernetes", "pod/harmless", ["delete"])], command) == "ALLOW"


def test_kubectl_raw_collection_is_marked():
    intent = from_argv("kubectl delete --raw /api/v1/pods".split())[0]
    assert intent.resource == "pod/*" and "resolved_at_runtime" in intent.params
    assert intent.metadata.get("all_namespaces") is True


@pytest.mark.parametrize("command", [
    "kubectl delete --raw /api/v1/namespaces/prod/pods?labelSelector=a",  # a query
    "kubectl delete --raw /api/v1/namespaces/dev/pods/../../prod/pods/x",  # dot segments
    "kubectl delete --raw /api/v1/namespaces/prod/pods/x%2Fy",  # escaped
    "kubectl create --raw /api/v1/namespaces/prod/pods/x/eviction -f e.json",  # subresource
    "kubectl delete --raw /api/v1/namespaces/prod/finalize",  # a namespace subresource
    "kubectl delete --raw /healthz",  # not a resource
    "kubectl delete --raw https://elsewhere/api/v1/namespaces/prod/pods/x",  # not a path
    "kubectl create --raw /api/v1/namespaces/prod/pods",  # create --raw needs one -f
    "kubectl create --raw /api/v1/namespaces/prod/pods -f a.json -f b.json",
    "kubectl apply --raw /api/v1/namespaces/prod/pods/x -f a.yaml",  # apply has no --raw
])
def test_kubectl_raw_writes_the_parser_cannot_name_are_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command", [
    "kubectl get --raw /healthz",
    "kubectl get --raw /apis",
    "kubectl get --raw /api/v1/namespaces/prod/pods/x/log",
])
def test_kubectl_get_raw_of_a_path_naming_no_object_stays_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,key,value", [
    # aws-cli's s3 ARG_TABLE: --metadata is a map (shorthand or JSON), --page-size an int
    ("aws s3 cp f s3://b/k --metadata classification=secret,owner=a", "metadata",
     {"classification": "secret", "owner": "a"}),
    ("aws s3 cp f s3://b/k --metadata {\"classification\":\"secret\"}", "metadata",
     {"classification": "secret"}),
    ("aws s3 rm s3://b/k --page-size 010", "page-size", 10),
    ("aws s3 cp f s3://b/k --sse", "sse", "AES256"),  # a bare optional value: its const
    ("aws s3 cp f s3://b/k --request-payer", "request-payer", "requester"),
    ("aws s3 cp f s3://b/k --expires 2026-01-01T00:00:00Z", "expires",
     "2026-01-01T00:00:00Z"),  # a plain string in aws-cli's table
    ("aws s3 mb s3://b --tags env prod --tags team a", "tags", {"env": "prod", "team": "a"}),
    ("aws s3 sync . s3://b --exclude * --include *.txt --exclude x*", "filters",
     [["exclude", "*"], ["include", "*.txt"], ["exclude", "x*"]]),
    ("aws s3 sync . s3://b --delete --size-only", "size-only", True),
])
def test_aws_s3_options_are_typed_as_aws_cli_declares(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


def test_aws_s3_metadata_rule_meets_the_map():
    rule = _rule("aws", "s3/bucket/*", ["put"], {"metadata.classification": "secret"})
    assert _verdict([rule], "aws s3 cp f s3://b/k --metadata classification=secret") == \
        "BLOCK"
    assert _verdict([rule], "aws s3 cp f s3://b/k --metadata classification=public") == \
        "ALLOW"
    assert _verdict([rule], "aws s3 cp f s3://b/k --metadata file://m.json") == "ESCALATE"


@pytest.mark.parametrize("command", [
    "aws s3 cp f s3://b/k --sse AES",  # argparse choices, exactly as written
    "aws s3 cp f s3://b/k --acl Public-Read",
    "aws s3 rm s3://b/k --page-size 0x10",  # int() refuses it
    "aws s3 cp f s3://b/k --recursive=false",  # store_true takes no value
    "aws s3 mb s3://b --tags env",  # two words
])
def test_aws_s3_values_aws_refuses_are_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("command,marks", [
    ("gcloud compute instances create vm --zone z --metadata-from-file "
     "enable-oslogin=oslogin.txt", {"metadata.enable-oslogin"}),
    ("gcloud container clusters create c --region r --metadata-from-file a=x.txt,b=y.txt",
     {"metadata.a", "metadata.b"}),
    ("gcloud storage buckets update gs://b --labels-file l.json", {"labels", "labels.*"}),
    ("gcloud run deploy s --region r --image i --env-vars-file e.yaml",
     {"set-env-vars.*", "update-env-vars.*", "env-vars.*"}),
    ("gcloud iam service-accounts add-iam-policy-binding sa@p.iam.gserviceaccount.com "
     "--member user:a --role r --condition-from-file c.yaml", {"condition", "condition.*"}),
    ("gcloud container node-pools update p --cluster c --region r "
     "--system-config-from-file s.yaml", {"system-config.*"}),
])
def test_gcloud_values_from_files_leave_their_settings_unresolved(command, marks):
    intent = from_argv(command.split())[0]
    assert marks <= set(intent.params["unresolved_scope"])


def test_gcloud_metadata_from_file_escalates_a_metadata_rule():
    rule = _rule("gcp", "compute/instance/*", ["create"], {"metadata.enable-oslogin": "TRUE"})
    assert _verdict([rule], "gcloud compute instances create vm --zone z "
                            "--metadata-from-file enable-oslogin=oslogin.txt") == "ESCALATE"
    assert _verdict([rule], "gcloud compute instances create vm --zone z "
                            "--metadata enable-oslogin=TRUE") == "BLOCK"


# --- review round 15 ------------------------------------------------------------------


def _shape(intents):
    """What a rule can see of each intent, without the spelling-only params."""
    return [(i.resource, i.action, i.metadata.get("namespace"),
             i.metadata.get("all_namespaces"), i.params.get("cascade_from"),
             bool(i.params.get("resolved_at_runtime")))
            for i in intents]


@pytest.mark.parametrize("raw,words", [
    # every expansion the words get, the raw path gets too
    ("kubectl delete --raw /api/v1/namespaces/prod", "kubectl delete namespace prod"),
    ("kubectl delete --raw /api/v1/namespaces/prod/pods/web", "kubectl delete pod web -n prod"),
    ("kubectl delete --raw /api/v1/nodes/n1", "kubectl delete node n1"),
    ("kubectl delete --raw /apis/apps/v1/namespaces/prod/deployments/web",
     "kubectl delete deployment web -n prod"),
    ("kubectl get --raw /api/v1/namespaces/prod/secrets/x", "kubectl get secret x -n prod"),
])
def test_kubectl_raw_and_words_give_the_same_intents(raw, words):
    assert _shape(from_argv(raw.split())) == _shape(from_argv(words.split()))


def test_kubectl_raw_namespace_delete_cascades():
    rule = _rule("kubernetes", "*/*", ["delete"], {"namespace": "prod"})
    assert _verdict([rule], "kubectl delete --raw /api/v1/namespaces/prod") == "BLOCK"
    assert _verdict([rule], "kubectl delete namespace prod") == "BLOCK"


def test_kubectl_raw_drops_flags_kubectl_does_not_send():
    intent = from_argv("kubectl delete --raw /api/v1/namespaces/prod/pods/x --cascade=orphan "
                       "--grace-period=0 --force".split())[0]
    assert not {"cascade", "grace-period", "grace_period", "force"} & set(intent.params)
    with pytest.raises(ValueError):  # a category is kubectl's, not an API resource
        from_argv("kubectl delete --raw /api/v1/namespaces/prod/all".split())


@pytest.mark.parametrize("command,resource,repo", [
    # Go's url.Parse drops the fragment; the server decodes the path
    ("gh api repos/acme/prod#ignored -X DELETE", "repo/acme/prod", "acme/prod"),
    ("gh api repos/acme/pr%6Fd -X DELETE", "repo/acme/prod", "acme/prod"),
    ("gh api repos/acme/prod/ -X DELETE", "repo/acme/prod", "acme/prod"),
    ("gh api https://api.github.com/repos/acme/prod?x=1#frag -X DELETE", "repo/acme/prod",
     "acme/prod"),
    ("gh repo delete https://github.com/acme/prod#x --yes", "repo/acme/prod", "acme/prod"),
    ("gh issue close https://github.com/acme/pr%6Fd/issues/3", "issue/3", "acme/prod"),
])
def test_gh_url_targets_are_read_as_gh_sends_them(command, resource, repo):
    intent = from_argv(command.split())[0]
    assert intent.resource == resource and intent.metadata["repo"] == repo


@pytest.mark.parametrize("command", [
    "gh api repos/acme//prod -X DELETE",
    "gh api repos/acme/safe/../prod -X DELETE",
    "gh api repos/acme/a%2Fb -X DELETE",
    "gh api ftp://x/repos/a/b -X DELETE",
    "gcloud compute instances delete "
    "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/vm#x",
    "gcloud compute instances delete projects/p/zones/z/instances/../instances/vm",
    "az resource delete --ids "
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm#x",
    "az resource delete --ids "
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/v%6D",
    "kubectl delete --raw /api/v1/namespaces/prod/pods/x#y",
])
def test_url_targets_with_parts_the_parser_cannot_place_are_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_gcloud_uri_path_is_decoded():
    intent = from_argv("gcloud compute instances delete "
                       "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/"
                       "v%6D".split())[0]
    assert intent.resource == "compute/instance/vm"


RUN_TWO = ("gcloud run deploy s --region r --container app --image forbidden "
           "--container sidecar --image safe")


def test_gcloud_run_flags_belong_to_their_container():
    intent = from_argv(RUN_TWO.split())[0]
    assert intent.params["containers"] == {"app": {"image": "forbidden"},
                                           "sidecar": {"image": "safe"}}
    assert intent.params["image"] == ["forbidden", "safe"]


@pytest.mark.parametrize("scope,verdict", [
    ({"image": "forbidden"}, "BLOCK"),  # any container's image
    ({"image": "safe"}, "BLOCK"),
    ({"image": "other"}, "ALLOW"),
    ({"containers.app.image": "forbidden"}, "BLOCK"),
    ({"containers.sidecar.image": "forbidden"}, "ALLOW"),
])
def test_gcloud_run_image_rule_meets_every_container(scope, verdict):
    assert _verdict([_rule("gcp", "run/service/*", ["update"], scope)], RUN_TWO) == verdict


@pytest.mark.parametrize("command", [
    # gcloud refuses a container flag before the first --container, and any other flag
    # inside a container
    "gcloud run deploy s --region r --image x --container a --image y",
    "gcloud run deploy s --container a --image y --region r",
])
def test_gcloud_run_container_misplacements_are_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


@pytest.mark.parametrize("scope,command", [
    # a rule on a key of a repeated group meets each group
    ({"create-disk.image": "forbidden"},
     "gcloud compute instances create vm --zone z --create-disk name=a,size=10GB "
     "--create-disk name=b,image=forbidden"),
    ({"network-interface.network": "b"},
     "gcloud compute instances create vm --zone z --network-interface network=a "
     "--network-interface network=b"),
    ({"set-env-vars.A": "2"},
     "gcloud run deploy s --region r --container app --image i --set-env-vars A=1 "
     "--container side --image j --set-env-vars A=2"),
])
def test_rules_reach_into_every_repeated_group(scope, command):
    resource = "compute/instance/*" if "compute" in command else "run/service/*"
    action = "create" if "compute" in command else "update"
    assert _verdict([_rule("gcp", resource, [action], scope)], command) == "BLOCK"


# --- review round 16 ------------------------------------------------------------------


@pytest.mark.parametrize("command,marked,known", [
    # with a values file, --set writes into what the file holds: an index keeps the list's
    # other items, a nested key the map's other keys; only a value set whole is known
    ("helm upgrade web ./c -f values.yaml --set hosts[0]=safe", {"set.hosts"}, set()),
    ("helm upgrade web ./c -f values.yaml --set image.tag=v1", {"set.image"},
     {"set.image.tag"}),
    ("helm upgrade web ./c -f values.yaml --set replicas=3", set(), {"set.replicas"}),
    ("helm upgrade web ./c -f values.yaml --set hosts={a,b}", set(), {"set.hosts"}),
    ("helm upgrade web ./c --reuse-values --set a.b[1].c=x", {"set.a", "set.a.b"}, set()),
    ("helm upgrade web ./c -f v.yaml --set a.b=1 --set a=2", set(), {"set.a"}),
    ("helm upgrade web ./c -f v.yaml --set-json {\"a\":{\"b\":1}}", {"set.a"}, set()),
])
def test_helm_set_into_file_values_leaves_the_container_unresolved(command, marked, known):
    marks = set(from_argv(command.split())[0].params["unresolved_scope"])
    assert marked <= marks
    assert not known & marks


def test_helm_set_without_files_is_known():
    marks = from_argv("helm upgrade web ./c --set hosts[0]=safe".split())[0].params.get(
        "unresolved_scope", [])
    assert "set.hosts" not in marks and "set.*" not in marks


@pytest.mark.parametrize("scope,verdict", [
    ({"set.hosts": "forbidden"}, "ESCALATE"),  # the file's other hosts stay
    ({"set.image": {"tag": "v2", "repository": "x"}}, "ESCALATE"),
    ({"set.image.tag": "v1"}, "BLOCK"),
    ({"set.image.repository": "x"}, "ESCALATE"),
])
def test_helm_rules_on_merged_values(scope, verdict):
    command = "helm upgrade web ./c -f values.yaml --set hosts[0]=safe --set image.tag=v1"
    assert _verdict([_rule("helm", "release/*", ["update"], scope)], command) == verdict


@pytest.mark.parametrize("command,key,value", [
    # git options given several times keep every value (git's documentation)
    ("git push -o a -o b origin main", "push_option", ["a", "b"]),
    ("git push --push-option=a --no-push-option -o c origin main", "push_option", ["c"]),
    ("git commit -m one -m two", "message", ["one", "two"]),
    ("git commit -m t --trailer a=1 --trailer b=2", "trailer", ["a=1", "b=2"]),
    ("git tag -a v1 -m x -m y", "message", ["x", "y"]),
    ("git rebase -x make -x test main", "exec", ["make", "test"]),
    ("git rebase -X ours -X patience main", "strategy_option", ["ours", "patience"]),
    ("git branch --sort=-date --sort=refname", "sort", ["-date", "refname"]),
])
def test_git_options_that_accumulate(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


def test_git_push_option_rule_meets_every_value():
    rule = _rule("git", "ref/*", ["push"], {"push_option": "ci.skip"})
    assert _verdict([rule], "git push -o ci.skip -o other origin main") == "BLOCK"


@pytest.mark.parametrize("command,scope,verdict", [
    # a move is recursive without -r: the source key is a prefix of what moves
    ("gsutil mv gs://prod/oldprefix gs://archive/newprefix", {"key": "oldprefix/secret"},
     "ESCALATE"),
    ("gsutil mv gs://prod/oldprefix gs://archive/newprefix", {"key": "other/x"}, "ALLOW"),
    ("gsutil mv gs://prod/oldprefix gs://archive/newprefix", {"key": "oldprefix"}, "BLOCK"),
    ("gsutil cp -M gs://prod/oldprefix gs://archive/newprefix", {"key": "oldprefix/s"},
     "ESCALATE"),
    ("gcloud storage mv gs://prod/oldprefix gs://archive/newprefix", {"key": "oldprefix/s"},
     "ESCALATE"),
    ("gsutil rm -r gs://prod/logs", {"key": "logs/a"}, "ESCALATE"),
    ("gsutil rm -r gs://prod/logs", {"key": "other"}, "ALLOW"),
    ("gsutil rm gs://prod/logs", {"key": "logs/a"}, "ALLOW"),  # one object
    ("gcloud storage rm --recursive gs://prod/logs", {"key": "logs/a"}, "ESCALATE"),
    ("aws s3 rm s3://prod/logs --recursive", {"key": "logs/a"}, "ESCALATE"),
    ("aws s3 rm s3://prod/logs --recursive", {"key": "other"}, "ALLOW"),
    ("aws s3 mv s3://prod/logs s3://b/x", {"key": "logs/a"}, "ALLOW"),  # one object
])
def test_recursive_storage_keys_are_prefixes(command, scope, verdict):
    provider = "aws" if command.startswith("aws") else "gcp"
    pattern = "s3/bucket/prod" if provider == "aws" else "storage/bucket/prod"
    assert _verdict([_rule(provider, pattern, ["delete"], scope)], command) == verdict


def test_recursive_move_destination_is_a_prefix():
    rule = _rule("gcp", "storage/bucket/archive", ["put"], {"key": "newprefix/a"})
    assert _verdict([rule], "gsutil mv gs://prod/oldprefix gs://archive/newprefix") == \
        "ESCALATE"
    rule = _rule("gcp", "storage/bucket/archive", ["put"], {"key": "elsewhere"})
    assert _verdict([rule], "gsutil mv gs://prod/oldprefix gs://archive/newprefix") == "ALLOW"


EVERYDAY_GH = [
    "gh pr create -t Fix -b Desc -B main -H feature -d -r alice -a @me -l bug",
    "gh pr edit 42 -t Fix -b Desc -B main -m v1",
    "gh pr merge 42 -s -d",
    "gh pr merge 42 -r -t Subject -b Body",
    "gh pr checkout 42 -b local -f",
    "gh pr review 42 -a -b LGTM",
    "gh pr review 42 -r -b Changes",
    "gh pr close 42 -c Done -d",
    "gh pr comment 42 -b Thanks",
    "gh pr list -s open -L 10 -a @me",
    "gh pr view 42 -c -w",
    "gh issue create -t Bug -b Desc -l bug -a @me -m v1",
    "gh issue edit 7 -t New -b Desc -m v2",
    "gh issue close 7 -c Fixed -r completed",
    "gh issue comment 7 -b Ack",
    "gh issue list -s closed -L 5 -l bug",
    "gh repo clone acme/prod -u upstream",
    "gh repo create acme/new --public -d Desc -c",
    "gh repo fork acme/prod --clone",
    "gh repo delete acme/old --yes",
    "gh repo view acme/prod -w",
    "gh release create v1.0.0 -t Release -n Notes -d -p",
    "gh release upload v1.0.0 dist/app.tar.gz --clobber",
    "gh release delete v1.0.0 -y --cleanup-tag",
    "gh workflow run deploy.yml -r main -f env=prod",
    "gh run rerun 123 --failed -d",
    "gh run cancel 123",
    "gh run list -L 5 -w ci.yml",
    "gh secret set TOKEN -b value -e prod",
    "gh variable set NAME -b value -e staging",
    "gh api repos/acme/prod/issues -X POST -f title=Bug -F draft=true",
    "gh label create bug -c FF0000 -d Bugs",
    "gh gist create notes.txt -d Notes -p",
    "gh auth status -a",
    "gh search repos aegis -L 5",
    "gh repo edit acme/prod -d New",
    "gh cache delete --all -R acme/prod",
]
EVERYDAY_OTHERS = [
    "helm install web ./chart -n prod -f values.yaml --set image.tag=v1",
    "helm upgrade web ./chart -n prod -i -f values.yaml",
    "helm upgrade web ./chart -n prod --reuse-values --atomic",
    "helm uninstall web -n prod",
    "helm rollback web 3 -n prod",
    "helm list -n prod -a",
    "helm status web -n prod -o json",
    "helm template web ./chart -f values.yaml",
    "helm get values web -n prod -a",
    "helm history web -n prod",
    "helm repo add bitnami https://charts.bitnami.com/bitnami",
    "helm repo update",
    "helm pull bitnami/nginx -d /tmp",
    "flux reconcile kustomization app -n flux-system --with-source",
    "flux suspend kustomization app -n flux-system",
    "flux resume helmrelease web -n prod",
    "flux get kustomizations -A",
    "flux create source git app -n flux-system --url=https://github.com/acme/app --branch=main",
    "flux delete kustomization app -n flux-system -s",
    "flux logs -n flux-system",
    "argocd app sync web -p prod",
    "argocd app get web -o yaml",
    "argocd app delete web -y",
    "argocd app list -p prod",
    "argocd app set web -p env=prod",
    "argocd app rollback web 3",
    "argocd app create web --repo https://github.com/acme/app --path k8s "
    "--dest-server https://kubernetes.default.svc --dest-namespace prod",
    "argocd app diff web",
    "argocd app history web",
    "kubectl get pods -n prod -o wide -l app=web",
    "kubectl apply -f deploy.yaml -n prod",
    "kubectl delete pod web -n prod",
    "kubectl logs web -n prod -c app -f",
    "kubectl exec web -n prod -c app -it -- sh",
    "kubectl scale deploy web -n prod --replicas=3",
    "kubectl rollout restart deploy/web -n prod",
    "kubectl describe pod web -n prod",
    "kubectl create secret generic s -n prod --from-literal=a=b",
    "kubectl set image deploy/web app=nginx:1.27 -n prod",
    "kubectl port-forward svc/web 8080:80 -n prod",
    "kubectl edit deploy web -n prod",
    "kubectl label pod web -n prod env=prod",
    "kubectl get all -A",
]


@pytest.mark.parametrize("command", EVERYDAY_GH + EVERYDAY_OTHERS)
def test_everyday_commands_with_short_flags_parse(command):
    assert from_argv(shlex.split(command))


def test_gh_flags_come_from_gh_registrations():
    # pr create's letters are gh's own (gh_flags.json, generated from cli/cli)
    intent = from_argv("gh pr create -t Fix -b Desc -B main -d".split())[0]
    assert intent.params["title"] == "Fix" and intent.params["body"] == "Desc"
    assert intent.params["base"] == "main" and intent.params["draft"] is True
    with pytest.raises(ValueError):  # repo clone has no -R
        from_argv("gh repo clone acme/prod -R x/y".split())


# commands whose letters the parser does not take from the registrations, because it
# refuses the command (documented overrides of the generated letters)
_REFUSED_FOR_LETTERS = {("flux", "migrate"), ("argocd", "app logs")}


def test_short_letters_agree_with_the_registrations():
    from aegis_core import parser as p

    tables = p._pflag_tables()
    checks = {
        "helm": (p._helm_short_name, lambda k: k in ("list", "template", "pull", "package",
                                                      "upgrade", "create", "install")),
        "flux": (p._flux_short_name, lambda k: len(k.split()) == 1 and k != "add"),
        "argocd": (lambda letter, k: p._argocd_short_name(letter, k.split()[1]),
                   lambda k: k.startswith("app ") and len(k.split()) == 2),
        "kubectl": (lambda letter, k: p._kubectl_short_name(letter, k, False),
                    lambda k: len(k.split()) == 1 and k not in ("add", "env", "resources")),
    }
    for tool, (name_of, applies) in checks.items():
        for key, letters in tables[f"{tool}:shorts"].items():
            if not applies(key) or (tool, key) in _REFUSED_FOR_LETTERS:
                continue
            for letter, flag in letters.items():
                assert name_of(letter, key) == flag, (tool, key, letter, flag)


# --- kubectl letters from kubectl's --help -------------------------------------------


@pytest.mark.parametrize("command", [
    # each a letter the command does not have: kubectl refuses it (checked on kubectl 1.36)
    "kubectl exec deploy/web -A -- id",
    "kubectl rollout restart deploy/web -n dev -qnprod",
    "kubectl create deployment x -qr3 --image=i",
    "kubectl exec -l app=web -- ls",
    "kubectl attach -l a=b",
])
def test_kubectl_letters_a_command_does_not_have_are_refused(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_kubectl_letters_come_from_each_commands_help():
    from aegis_core.parser import _KUBECTL_TABLE, _kubectl_short_name

    for command, flags in _KUBECTL_TABLE.items():
        if command.startswith("_") or command == "options":
            continue
        for name, (_kind, letter) in flags.items():
            if letter:
                assert _kubectl_short_name(letter, command, False) == name, (command, letter)


def test_pflag_ignores_a_short_word_from_test_dot():
    intent = from_argv("kubectl get pod/a -test.nprod".split())[0]
    assert "namespace" not in intent.metadata


# --- review round 17 ------------------------------------------------------------------


@pytest.mark.parametrize("command,created", [
    # expose creates a Service named by --name or after the source; autoscale an HPA
    ("kubectl expose deployment harmless -n prod --port=80 --name=protected", "service/protected"),
    ("kubectl expose deployment harmless -n prod --port=80", "service/harmless"),
    ("kubectl autoscale deployment web -n prod --max=5 --name=hpa1",
     "horizontalpodautoscaler/hpa1"),
    ("kubectl autoscale deployment web -n prod --max=5", "horizontalpodautoscaler/web"),
    ("kubectl create token sa1 -n prod", "serviceaccount/sa1"),
])
def test_commands_create_objects_besides_the_one_they_name(command, created):
    intents = from_argv(command.split())
    made = [i for i in intents if i.resource == created]
    assert made and made[0].action == "create" and made[0].metadata["namespace"] == "prod"


def test_expose_rule_on_the_service_holds():
    rule = _rule("kubernetes", "service/protected", ["create"])
    assert _verdict([rule], "kubectl expose deployment harmless -n prod --port=80 "
                            "--name=protected") == "BLOCK"
    intent = [i for i in from_argv("kubectl expose deploy web -n prod --port=80 "
                                   "--overrides={}".split()) if i.resource == "service/*"][0]
    assert "**" in intent.params["unresolved_scope"]  # overrides can rename it (round 18)


def test_gh_merge_delete_branch_deletes_an_unnamed_branch():
    intents = from_argv("gh pr merge 42 -s -d".split())
    branch = [i for i in intents if i.resource == "branch/*"]
    assert branch and branch[0].action == "delete"
    assert "resolved_at_runtime" in branch[0].params


@pytest.mark.parametrize("command,method", [
    # gh derives the method from each flag's final value (merge.go)
    ("gh pr merge 42 --merge --squash --squash=false", "merge"),
    ("gh pr merge 42 -s", "squash"),
    ("gh pr merge 42 --rebase=false --squash", "squash"),
])
def test_gh_merge_method_from_final_values(command, method):
    assert from_argv(command.split())[0].params["method"] == method


@pytest.mark.parametrize("command", [
    "gh pr merge 42 --merge --squash",
    "gh pr merge 42 --auto --admin",
    "gh repo create a/b --public --private",
])
def test_gh_flags_it_allows_one_of_are_refused_together(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_helm_atomic_leaves_wait_unresolved():
    marks = from_argv("helm upgrade r ./c --atomic".split())[0].params["unresolved_scope"]
    assert "wait" in marks


@pytest.mark.parametrize("command,key,value", [
    # each flag's argparse action, from the SDK (UpdateAction extends, append keeps each)
    ("gcloud run deploy s --region r --image i --args forbidden --args safe", "args",
     ["forbidden", "safe"]),
    ("gcloud compute instances create vm --zone z --create-disk name=a "
     "--create-disk name=b", "create-disk", [{"name": "a"}, {"name": "b"}]),
])
def test_gcloud_actions_keep_repeats_as_the_sdk_does(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("command", [
    "gcloud run deploy s --region r --image i --args a --args a",  # UpdateAction: a repeat
    "gcloud compute instances create vm --zone z --metadata a=1 --metadata b=2",  # once
])
def test_gcloud_repeats_the_sdk_refuses(command):
    with pytest.raises(ValueError):
        from_argv(command.split())


def test_gcloud_args_rule_meets_every_value():
    rule = _rule("gcp", "run/service/*", ["update"], {"args": "forbidden"})
    assert _verdict([rule], "gcloud run deploy s --region r --image i --args forbidden "
                            "--args safe") == "BLOCK"


@pytest.mark.parametrize("command,key,value", [
    # ArgDict spec types each member (count: int)
    ("gcloud compute instances create vm --zone z --accelerator type=nvidia-tesla-t4,count=01",
     "accelerator", {"type": "nvidia-tesla-t4", "count": 1}),
    ("gcloud compute instances create vm --zone z --create-disk name=a,size=10GB",
     "create-disk", {"name": "a", "size": 10 * 1024 ** 3}),
])
def test_gcloud_argdict_members_are_typed(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


@pytest.mark.parametrize("rule_value", ["1", "01", "0x1x"])
def test_gcloud_argdict_member_rule_is_typed_the_same_way(rule_value):
    rule = _rule("gcp", "compute/instance/*", ["create"], {"accelerator.count": rule_value})
    verdict = _verdict([rule], "gcloud compute instances create vm --zone z "
                               "--accelerator type=t4,count=01")
    assert verdict == ("ESCALATE" if rule_value == "0x1x" else "BLOCK")


def test_gcloud_argdict_member_outside_the_spec_is_refused():
    with pytest.raises(ValueError):
        from_argv("gcloud compute instances create vm --zone z --accelerator type=t4,bogus=1"
                  .split())


@pytest.mark.parametrize("command,key", [
    # their ArgDict spec is built in a way not read statically: the type of each member is
    # not known, so the flag and every member are unresolved
    ("gcloud container clusters create c --region r --addons HttpLoadBalancing=ENABLED",
     "addons"),
    ("gcloud container clusters update c --region r --update-addons HttpLoadBalancing=DISABLED",
     "update-addons"),
])
def test_gcloud_argdict_with_an_unread_spec_is_unresolved(command, key):
    intent = from_argv(command.split())[0]
    assert intent.params[key]
    assert {key, f"{key}.*"} <= set(intent.params["unresolved_scope"])
    rule = _rule("gcp", "container/cluster/*", ["create", "update"],
                 {f"{key}.HttpLoadBalancing": "x"})
    assert _verdict([rule], command) == "ESCALATE"



# --- review round 18 ------------------------------------------------------------------


def test_gh_api_input_fields_go_to_the_query_and_the_body_stays_unknown():
    command = ["gh", "api", "-X", "PATCH", "repos/acme/prod", "--input", "body.json",
               "-F", "delete_branch_on_merge=false"]
    intent = from_argv(command)[0]
    assert intent.params["api_query"] == {"delete_branch_on_merge": False}
    assert "inputs" not in intent.params
    rule = _rule("github", "api/repos/*", ["update"], {"inputs.delete_branch_on_merge": True})
    assert _verdict([rule], command) == "ESCALATE"


def test_a_prefix_mark_covers_recorded_keys_except_helms_set():
    from aegis_core.intent import InfrastructureIntent
    from aegis_core.store import param_unresolved

    other = InfrastructureIntent(resource="x/y", action="update", provider="github",
                                 params={"inputs": {"a": 1}, "unresolved_scope": ["inputs.*"]})
    assert param_unresolved("inputs.a", other)
    helm = from_argv("helm upgrade web ./c -f v.yaml --set image.tag=v1".split())[0]
    assert not param_unresolved("set.image.tag", helm)
    assert param_unresolved("set.image.repository", helm)


@pytest.mark.parametrize("command,created", [
    # --overrides can rename the new Service: any name, marked
    ('kubectl expose deployment harmless -n prod --port=80 '
     '--overrides={"metadata":{"name":"protected"}}', "service/*"),
    # expose cuts the default name to 63 characters (expose.go); autoscale does not
    ("kubectl expose deployment " + "a" * 70 + " -n prod --port=80", "service/" + "a" * 63),
    ("kubectl autoscale deployment " + "a" * 70 + " -n prod --max=3",
     "horizontalpodautoscaler/" + "a" * 70),
])
def test_created_object_names_as_kubectl_derives_them(command, created):
    intents = from_argv(shlex.split(command))
    made = [i for i in intents if i.resource == created]
    assert made and made[0].metadata["namespace"] == "prod"
    if created.endswith("/*"):
        assert "resolved_at_runtime" in made[0].params


def test_expose_overrides_escalate_a_rule_on_any_service_name():
    rule = _rule("kubernetes", "service/protected", ["create"])
    command = ('kubectl expose deployment harmless -n prod --port=80 '
               '--overrides={"metadata":{"name":"protected"}}')
    assert _verdict([rule], shlex.split(command)) == "ESCALATE"


@pytest.mark.parametrize("command,key,value", [
    # the SDK's map type wins over the reference page's list
    ("gcloud storage buckets update gs://b --update-labels env=prod", "update-labels",
     {"env": "prod"}),
    ("gcloud storage buckets create gs://b --labels env=prod", "labels", {"env": "prod"}),
])
def test_gcloud_shape_follows_the_sdk(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


def test_gcloud_shape_that_stays_in_doubt_is_unresolved():
    intent = from_argv("gcloud compute firewall-rules create fw --rules tcp:22".split())[0]
    assert "rules" in intent.params["unresolved_scope"]


def test_gcloud_update_labels_rule_meets_the_map():
    rule = _rule("gcp", "storage/bucket/*", ["update"], {"update-labels.env": "prod"})
    assert _verdict([rule], "gcloud storage buckets update gs://b --update-labels env=prod") \
        == "BLOCK"


# --- review round 19 ------------------------------------------------------------------


@pytest.mark.parametrize("command,scope", [
    # a key with an unresolved key under it is unresolved when a rule compares it whole
    ("helm upgrade web ./c --reset-values --set config.public=safe "
     "--set-file config.secret=/dev/null", {"set.config": {"public": "safe", "secret": "x"}}),
    ("gcloud compute instances create vm --zone z --metadata a=1 --metadata-from-file b=f.txt",
     {"metadata": {"a": "1", "b": "2"}}),
    ("aws ec2 create-tags --resources i-1 --tags file://t.json",
     {"tags": [{"Key": "a", "Value": "b"}]}),
])
def test_an_unresolved_descendant_leaves_the_whole_key_unresolved(command, scope):
    if command.startswith("helm"):
        provider, pattern, action = "helm", "release/*", "update"
    elif command.startswith("gcloud"):
        provider, pattern, action = "gcp", "compute/instance/*", "create"
    else:
        provider, pattern, action = "aws", "ec2/tag/*", "create"
    assert _verdict([_rule(provider, pattern, [action], scope)], shlex.split(command)) == \
        "ESCALATE"


def test_a_resolved_sibling_of_an_unresolved_key_still_decides():
    rule = _rule("helm", "release/*", ["update"], {"set.config.public": "other"})
    assert _verdict([rule], "helm upgrade web ./c --reset-values --set config.public=safe "
                            "--set-file config.secret=/dev/null".split()) == "ALLOW"


@pytest.mark.parametrize("command,scope", [
    # the flag that named the target (or its scope) meets a rule written with its name
    ("aws iam delete-role --role-name protected", {"role-name": "protected"}),
    ("aws ec2 terminate-instances --instance-ids i-1 i-2", {"instance-ids": "i-2"}),
    ("aws s3api delete-bucket --bucket b", {"bucket": "b"}),
    ("aws lambda delete-function --function-name f", {"function-name": "f"}),
    ("az vm delete -n vm1 -g rg", {"name": "vm1"}),
    ("az vm delete -n vm1 -g rg", {"resource-group": "rg"}),
    ("az group create -n rg -l eastus", {"location": "eastus"}),
    ("helm uninstall web --kube-context prod", {"kube-context": "prod"}),
    ("kubectl delete pod x -n prod", {"namespace": "prod"}),
    ("gh pr close 1 -R a/b", {"repo": "a/b"}),
    ("argocd app delete web -N ns -y", {"app-namespace": "ns"}),
])
def test_a_target_or_scope_flag_meets_a_rule_on_its_name(command, scope):
    intent = from_argv(command.split())[0]
    rule = _rule(intent.provider, intent.resource.split("/")[0] + "/*", [intent.action], scope)
    assert _verdict([rule], command) == "BLOCK"


@pytest.mark.parametrize("command,key,value", [
    # several names of one option: one key, the values in order, every name holding it
    ("git push --exec=X --receive-pack=Y origin main", "receive_pack", "Y"),
    ("git push --receive-pack=Y --exec=X origin main", "receive_pack", "X"),
    ("git push --receive-pack=Y --exec=X origin main", "exec", "X"),
    ("git branch --with HEAD --contains main", "contains", ["HEAD", "main"]),
    ("helm upgrade r ./c --force", "force_replace", True),
    ("helm upgrade r ./c --force --force-replace=false", "force", False),
    ("helm upgrade r ./c --atomic", "rollback_on_failure", True),
    ("gh repo delete a/b --confirm", "yes", True),
    ("az compute-fleet delete --name a --fleet-name b -g rg", "name", "b"),
    ("az compute-fleet delete --fleet-name b -g rg", "fleet-name", "b"),
    ("aws mgn start-cutover --source-server-i-ds s-1", "source-server-ids", ["s-1"]),
])
def test_option_aliases_are_one_option(command, key, value):
    assert from_argv(command.split())[0].params[key] == value


def test_az_option_alias_names_the_target():
    intent = from_argv("az compute-fleet delete --name a --fleet-name b -g rg".split())[0]
    assert intent.resource.endswith("/b")
