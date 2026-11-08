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


def test_aws_cli_input_json_target_is_unknown():
    command = ["aws", "ec2", "terminate-instances", "--cli-input-json",
               '{"InstanceIds":["i-9"]}']
    intent = from_argv(command)[0]
    assert intent.resource == "ec2/instance/*"
    assert intent.params["resolved_at_runtime"] == {"from": "ec2/instance/*",
                                                    "kinds": ["ec2/instance"]}
    assert _verdict([_rule("aws", "ec2/instance/i-9", ["delete"])], command) == "ESCALATE"
    # a flag that names the target wins over the input, as in aws
    named = command[:3] + ["--instance-ids", "i-1"] + command[3:]
    assert _verdict([_rule("aws", "ec2/instance/i-9", ["delete"])], named) == "ALLOW"


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
     {"s": "server"}),
    ("az ad user delete --id x", "iam/user/*", {}, {"id": "x"}),
    # a letter that only ever takes a value (or is a three-state flag) takes the rest
    ("az sql db delete -snprod -g rg -n db", "sql/db/db", {"resource_group": "rg"},
     {"s": "nprod"}),
    # -c is a boolean on one command, but no reading reaches an n, g or l: m, y, c and then
    # o, which takes "ntainer"
    ("az storage container delete -cmycontainer -n x", "storage/container/x", {},
     {"c": "mycontainer"}),
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
    ("gcloud compute instances delete web-1 --some-flag=x prod-1",
     ["compute/instance/web-1", "compute/instance/prod-1"]),
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
    # an unknown flag followed by a word: its value, or a boolean and then a name
    "gcloud compute instances delete web-1 --graceful prod-1",
    "gcloud compute instances delete --unknown-flag web-1",
    "gcloud --unknown-global x compute instances delete web-1",
])
def test_gcloud_refuses_an_unknown_flag_before_a_word(command):
    with pytest.raises(ValueError, match="cannot tell whether"):
        from_argv(command.split())


@pytest.mark.parametrize("command,resources", [
    ("gcloud compute instances delete web-1 --unknown-flag", ["compute/instance/web-1"]),
    ("gcloud compute instances delete web-1 --unknown-flag --zone us-east1-b",
     ["compute/instance/web-1"]),
    ("gcloud storage rm --unknown-flag x gs://b", ["storage/bucket/b"]),
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
    # the last value (run with aws 2.37: DeleteRole b, TerminateInstances i-2 i-3); every
    # spelling is a target, so neither is dropped
    ("aws iam delete-role --role-name a --role b", ["iam/role/a", "iam/role/b"]),
    ("aws iam delete-role --role b --role-name a", ["iam/role/a", "iam/role/b"]),
    ("aws ec2 terminate-instances --instance-ids i-1 --instance i-2 i-3",
     ["ec2/instance/i-1", "ec2/instance/i-2", "ec2/instance/i-3"]),
    ("aws eks delete-nodegroup --cluster-name c --nodegroup-name ng-1 --nodegroup ng-2",
     ["eks/nodegroup/ng-1", "eks/nodegroup/ng-2"]),
    ("aws s3api delete-object --bucket a --buck b --key k",
     ["s3/object/a/k", "s3/object/b/k"]),
    # a prefix of another flag than the one that named the target adds nothing
    ("aws lambda create-function --function-name f --role arn:r --runtime python3.12",
     ["lambda/function/f"]),
])
def test_aws_full_flag_and_abbreviation_are_both_read(command, resources):
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
    ("git branch -f main HEAD~3", [("branch/main", "create"), ("branch/main", "delete")]),
    ("git branch side", [("branch/side", "read")]),
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
