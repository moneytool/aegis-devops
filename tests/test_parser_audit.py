"""The sibling audit of review rounds 1-9 (docs/dev/parser-audit.md): one check per class
of finding and per tool where the class applies, so a fix that covers one tool and misses
its siblings fails here. Each row is ``(class, tool, argv, check)``."""

import shlex
from datetime import UTC, datetime

import pytest

from aegis_core.interceptor import AegisInterceptor
from aegis_core.parser import from_argv
from aegis_core.store import Constraint, ConstraintStore

NOW = datetime(2026, 11, 8, 12, tzinfo=UTC)


def _rule(provider, resource, actions, scope=None):
    return Constraint.create(id="r", provider=provider, resource_pattern=resource,
                             actions=set(actions), scope=scope or {}, time_window=None,
                             effect="BLOCK", constraint_class="deletion", principal="admin",
                             source_ref="t", source_timestamp="2026-11-08T00:00:00+00:00",
                             rule_text="r")


def _verdict(rule, argv):
    store = ConstraintStore(authority_map={"admin": {"deletion"}})
    store.add_constraint(rule)
    interceptor = AegisInterceptor(store)
    order = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
    return max((interceptor.intercept(i, now=NOW).verdict for i in from_argv(argv)),
               key=order.__getitem__)


REFUSE = ("refuse",)


def res(*resources):
    return ("res", list(resources))


def param(key, value):
    return ("param", key, value)


def meta(key, value):
    return ("meta", key, value)


def unres(key):
    return ("unres", key)


def marked(resource):
    return ("marked", resource)


def action(name):
    return ("action", name)


def verdict(rule, expected):
    return ("verdict", rule, expected)


AUDIT = [
    # C1 a value flag takes the next word; a flag in no table is refused
    ("C1", "kubectl", "kubectl delete pod web --no-such-flag -n prod", REFUSE),
    ("C1", "helm", "helm upgrade api ./c -n prod --description -ndev", meta("namespace", "prod")),
    ("C1", "flux", "flux create source git a -n prod --url -ndev", meta("namespace", "prod")),
    ("C1", "argocd", "argocd app sync a --revision -l", param("revision", "-l")),
    ("C1", "gh", "gh pr merge -s 42", res("pr/42")),
    ("C1", "git", "git push --no-such origin main", REFUSE),
    ("C1", "aws", "aws autoscaling set-desired-capacity --auto-scaling-group-name g --x 1",
     REFUSE),
    ("C1", "az", "az aks scale -g rg -n c --bogus 1", REFUSE),
    ("C1", "gcloud", "gcloud compute instances delete web --no-such x", REFUSE),
    ("C1", "gsutil", "gsutil rm -x gs://b", REFUSE),
    # C2 an unmapped short letter is refused
    ("C2", "kubectl", "kubectl get pods -x", REFUSE),
    ("C2", "helm", "helm upgrade api ./c -x", REFUSE),
    ("C2", "flux", "flux get ks -x", REFUSE),
    ("C2", "argocd", "argocd app sync a -x", REFUSE),
    ("C2", "gh", "gh pr merge 1 -x", REFUSE),
    ("C2", "git", "git push -x origin main", REFUSE),
    ("C2", "az", "az vm delete -g rg -n v -q x", REFUSE),
    ("C2", "gcloud", "gcloud compute instances delete web -x", REFUSE),
    ("C2", "aws", "aws autoscaling set-desired-capacity -x 1", REFUSE),
    # C3 a short option is recorded as its long option
    ("C3", "kubectl", "kubectl get pods -w", param("watch", True)),
    ("C3", "helm", "helm list -q", param("short", True)),
    ("C3", "flux", "flux delete ks a -s", param("silent", True)),
    ("C3", "argocd", "argocd app sync a -l x=y", ("any_param", "selector", "x=y")),
    ("C3", "gh", "gh pr merge 1 -d", param("delete_branch", True)),
    ("C3", "git", "git branch -D x", param("force", True)),
    ("C3", "az", "az aks scale -g rg -n c -c 1", param("node-count", 1)),
    ("C3", "gcloud", "gcloud container clusters delete c -z us-east1-b",
     meta("zone", "us-east1-b")),
    # C4 an abbreviated long option is the option the tool resolves (argparse, parse-options)
    ("C4", "aws", "aws autoscaling set-desired-capacity --auto-scaling-group-name g "
     "--desired-cap 0", param("desired_capacity", 0)),
    ("C4", "az", "az aks scale -g rg -n c --node-c 1", param("node-count", 1)),
    ("C4", "git", "git commit --amen -m x", res("history/HEAD", "history/*")),
    ("C4", "gcloud", "gcloud compute instances delete web --zon us-east1-b", REFUSE),
    ("C4", "kubectl", "kubectl delete pod web --namesp prod", REFUSE),  # pflag: no prefixes
    # C5 numbers read as the tool reads them
    ("C5", "kubectl", "kubectl scale deploy web --replicas=0x0", param("replicas", 0)),
    ("C5", "helm", "helm upgrade r ./c --set q=007", ("set", "q", "007")),
    ("C5", "aws", "aws autoscaling set-desired-capacity --auto-scaling-group-name g "
     "--desired-capacity -1", param("desired_capacity", -1)),
    ("C5", "helm", "helm upgrade r ./c --history-max 0x0", param("history_max", 0)),
    ("C5", "helm", "helm upgrade r ./c --timeout 5m", param("timeout", 300)),
    ("C5", "flux", "flux reconcile ks a --timeout 1m30s", param("timeout", 90)),
    ("C5", "kubectl", "kubectl logs web --since 2m", param("since", 120)),
    ("C5", "argocd", "argocd app sync a --timeout 0x10", param("timeout", 16)),
    ("C5", "gh", "gh run list -R o/r --limit 0x10", param("limit", 16)),
    # C5 (rule side): a rule's value is read as the flag's value was
    ("C5", "helm", "helm upgrade r ./c --timeout 300s",
     ("verdict_block", "helm", "release/*", "update", {"timeout": "5m"})),
    ("C5", "helm", "helm upgrade r ./c --history-max 0",
     ("verdict_block", "helm", "release/*", "update", {"history-max": "0x0"})),
    ("C5", "kubectl", "kubectl scale deploy web --replicas 0",
     ("verdict_block", "kubernetes", "deployment/*", "scale", {"replicas": "0x0"})),
    ("C5", "helm", "helm upgrade r ./c --install=false",
     ("verdict_block", "helm", "release/*", "update", {"install": "0"})),
    # C6 repeated flags accumulate exactly where pflag's type does
    ("C6", "argocd", "argocd app sync a --resource g:K:x --resource g:K:y",
     param("resource", ["g:K:x", "g:K:y"])),
    ("C6", "kubectl", "kubectl get pods -L a,b -L c", param("label-columns", ["a", "b", "c"])),
    ("C6", "helm", "helm template a ./c --api-versions v1 --api-versions v2",
     param("api_versions", ["v1", "v2"])),
    ("C6", "flux", "flux create source git a --url u --ignore-paths x,y",
     param("ignore_paths", ["x", "y"])),
    ("C6", "gh", "gh pr create -R o/r --label a,b --label c --title t --body b",
     param("label", ["a", "b", "c"])),
    # C6 a boolean's negation and last spelling
    ("C6", "kubectl", "kubectl run web --image x --expose=false", param("expose", False)),
    ("C6", "helm", "helm upgrade api ./c --install=false", param("install", False)),
    ("C6", "argocd", "argocd app delete a --yes=false", param("yes", False)),
    ("C6", "gh", "gh pr merge 1 --delete-branch=false", param("delete_branch", False)),
    ("C6", "git", "git push --no-thin origin main", param("thin", False)),
    ("C6", "aws", "aws ec2 terminate-instances --instance-ids i-1 --no-dry-run",
     ("no_param", "dry_run")),
    ("C6", "az", "az vm delete -g rg -n v --yes=false", param("yes", False)),
    ("C6", "gcloud", "gcloud compute instances update web --no-deletion-protection",
     param("deletion_protection", False)),
    # C7 one intent per object
    ("C7", "kubectl", "kubectl delete pod a b", res("pod/a", "pod/b")),
    ("C7", "helm", "helm uninstall a b", res("release/a", "release/b")),
    ("C7", "flux", "flux delete ks a b", res("kustomization/a", "kustomization/b")),
    ("C7", "argocd", "argocd app delete a b -y", res("app/a", "app/b")),
    ("C7", "gh", "gh issue edit 1 2 -R o/r --add-label x", res("issue/1", "issue/2")),
    ("C7", "git", "git branch -d a b", res("branch/a", "branch/b")),
    ("C7", "aws", "aws ec2 terminate-instances --instance-ids i-1 i-2",
     res("ec2/instance/i-1", "ec2/instance/i-2")),
    ("C7", "gcloud", "gcloud compute instances delete a b", res("compute/instance/a",
                                                               "compute/instance/b")),
    ("C7", "gsutil", "gsutil rm gs://a gs://b", res("storage/bucket/a", "storage/bucket/b")),
    # C8 a selection adds targets; its scope is never the named targets'
    ("C8", "kubectl", "kubectl delete deploy web -l a=b", REFUSE),
    ("C8", "argocd", "argocd app sync payments --project dev", ("named_lacks", "project")),
    ("C8", "argocd", "argocd app delete -l t=x -N dev -y", ("last_lacks", "app_namespace")),
    ("C8", "flux", "flux suspend ks a --all", res("kustomization/a")),
    # C9 targets from a file or stdin are marked
    ("C9", "argocd", "argocd app create -f a.yaml", marked("app/*")),
    ("C9", "kubectl", "kubectl apply -f -", param("manifest_not_inspected", True)),
    ("C9", "helm", "helm upgrade r ./c -f -", unres("set.*")),
    ("C9", "gh", "gh secret set X --env-file - -R o/r", marked("secret/*")),
    ("C9", "aws", "aws autoscaling set-desired-capacity --cli-input-json file:///dev/stdin",
     marked("autoscaling/auto-scaling-group/*")),
    ("C9", "az", "az vm update -g rg -n v --set @-", unres("set")),
    ("C9", "gcloud", "gcloud storage rm -I", marked("storage/bucket/*")),
    ("C9", "gsutil", "gsutil rm -I", marked("storage/bucket/*")),
    # C10 a scope the tool takes from its configuration, absent or empty, is unresolved
    ("C10", "kubectl", "kubectl delete pod x --context=", unres("context")),
    ("C10", "helm", "helm uninstall r --kube-context=", unres("context")),
    ("C10", "flux", "flux suspend ks a", unres("user")),
    ("C10", "argocd", "argocd app delete a --server= -y", unres("server")),
    ("C10", "gh", "gh repo delete o/r --yes", unres("github_host")),
    ("C10", "git", "git push", unres("remote")),
    ("C10", "aws", "aws ec2 terminate-instances --instance-ids i-1 --region=", unres("region")),
    ("C10", "az", "az vm delete -n v -g= --yes", unres("resource_group")),
    ("C10", "gcloud", "gcloud compute instances delete web --project p", unres("zone")),
    # C11 a value the tool fills in when it runs
    ("C11", "gh", "gh api -X POST repos/o/r/x -F a={owner}", unres("inputs.a")),
    ("C11", "git", "git push origin @{u}", res("ref/*", "tag/*")),
    ("C11", "git", "git branch -f @{-1} HEAD", ("all_marked", "branch/*")),
    # C12 one value, every spelling
    ("C12", "aws", "aws iam delete-role --role-name arn:aws:iam::1:role/p/r",
     ("alias", "iam/role/r")),
    ("C12", "gcloud", "gcloud storage buckets delete gs://prod", res("storage/bucket/prod")),
    ("C12", "gcloud", "gcloud storage rm gs://prod/s#12", param("key", "s")),
    ("C12", "argocd", "argocd app delete prod/payments -y", meta("app_namespace", "prod")),
    ("C12", "gh", "gh pr merge https://github.com/O/R/pull/5", meta("repo", "o/r")),
    ("C12", "az", "az vm delete --yes --ids /subscriptions/0b1f6471-1bf0-4dda-aec3-111122223333"
     "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/a", res("compute/vm/a")),
    ("C12", "kubectl", "kubectl delete deploy/web", res("deployment/web")),
    # C14 a decoded value is the value the tool sends
    ("C14", "helm", "helm upgrade r ./c --set-json q=9007199254740993", ("set", "q",
                                                                          9007199254740992)),
    ("C14", "aws", "aws autoscaling set-desired-capacity --cli-input-yaml "
     "'{AutoScalingGroupName: g, DesiredCapacity: 010}'", param("desired_capacity", 10)),
    ("C14", "gh", "gh api -X POST repos/o/r/x -F n=1 -f m=1", param("inputs", {"n": 1, "m": "1"})),
    # C15 the tool's own precedence
    ("C15", "gh", "gh workflow run d.yml -R o/r -F e=prod -f e=dev",
     param("inputs", {"e": "prod"})),
    ("C15", "helm", "helm upgrade r ./c --set-json q=0 --set q=3", ("set", "q", 3)),
    ("C15", "aws", "aws autoscaling set-desired-capacity --cli-input-json "
     "'{\"AutoScalingGroupName\":\"g\",\"DesiredCapacity\":0}' --desired-capacity 3",
     param("desired_capacity", 3)),
    ("C15", "kubectl", "kubectl run web --image x --overrides {}", unres("image")),
    # C16 words after -- as the tool reads them
    ("C16", "kubectl", "kubectl delete pod safe -- prod", res("pod/safe", "pod/prod")),
    ("C16", "helm", "helm uninstall safe -- prod", res("release/safe", "release/prod")),
    ("C16", "flux", "flux delete ks safe -- prod", res("kustomization/safe",
                                                        "kustomization/prod")),
    ("C16", "argocd", "argocd app delete safe -- prod", res("app/safe", "app/prod")),
    ("C16", "gh", "gh repo delete -- o/prod", res("repo/o/prod")),
    ("C16", "git", "git branch -d safe -- prod", res("branch/safe", "branch/prod")),
    ("C16", "aws", "aws ec2 terminate-instances --instance-ids i-1 -- i-2", REFUSE),
    ("C16", "az", "az vm delete -g rg -n v -- x", REFUSE),
    ("C16", "gcloud", "gcloud compute instances delete safe -- prod",
     res("compute/instance/safe", "compute/instance/prod")),
    # C17 no command is a read unless audited as one
    ("C17", "git", "git tag -f v1 HEAD", res("tag/v1", "tag/v1")),
    ("C17", "gh", "gh release edit v1 --draft=false", action("update")),
    ("C17", "argocd", "argocd app get a --hard-refresh", action("update")),
    ("C17", "gcloud", "gcloud compute ssh vm --zone z", action("exec")),
    ("C17", "kubectl", "kubectl frobnicate x", action("frobnicate")),
    ("C17", "helm", "helm frob x", REFUSE),
    ("C17", "flux", "flux frob ks a", REFUSE),
    ("C17", "aws", "aws ec2 frobnicate-things", REFUSE),
    ("C17", "az", "az vm frob -n a -g b", REFUSE),
    # C18 wildcard targets are marked
    ("C18", "gcloud", "gcloud storage rm gs://prod-*/x", marked("storage/bucket/prod-*")),
    ("C18", "gsutil", "gsutil rm gs://prod-*/x", marked("storage/bucket/prod-*")),
    ("C18", "aws", "aws s3 rm s3://b/logs --recursive", unres("key")),
    ("C18", "git", "git push origin +refs/heads/*:refs/heads/*", param("unknown_target", True)),
    # C19 normalization after every path
    ("C19", "argocd", "argocd app actions run prod/payments restart --kind Deployment",
     meta("app_namespace", "prod")),
    ("C19", "az", "az vm delete --yes --ids /subscriptions/Prod/resourceGroups/rg/providers/"
     "Microsoft.Compute/virtualMachines/a", meta("subscription_name", "Prod")),
    # C20 a derived intent's scope is its own
    ("C20", "flux", "flux reconcile ks app -n dev --with-source", ("derived_all_ns",)),
    # C21 a tag's action
    ("C21", "git", "git push origin :refs/tags/v1", ("has", "tag/v1", "delete")),
    # C22 a copy writes prefix plus base name
    ("C22", "gcloud", "gcloud storage cp /tmp/s gs://prod/d/", ("last_param", "key", "d/s")),
    ("C22", "gsutil", "gsutil cp /tmp/s gs://prod/d/", ("last_param", "key", "d/s")),
    ("C22", "aws", "aws s3 cp /tmp/s s3://prod/d/", ("last_param", "key", "d/s")),
    # C23 argument counts the tool allows
    ("C23", "gh", "gh issue close 1 2", REFUSE),
    ("C23", "git", "git branch -m a b c", REFUSE),
    # C24 every kind/* target is marked
    ("C24", "kubectl", "kubectl get pods", marked("pod/*")),
    ("C24", "helm", "helm list", marked("release/*")),
    ("C24", "gcloud", "gcloud storage buckets update --read-paths-from-stdin --no-versioning",
     marked("storage/bucket/*")),
    # C10 (r10): a source-only push's destination is mapped by config when git runs
    ("C10", "git", "git push origin safe", ("first_marked_destination",)),
    # C26 a multi-value option takes every value, as the tool's parser gives it
    ("C26", "az", "az group create --name rg --location eastus --tags a=b c=d",
     param("tags", ["a=b", "c=d"])),
    ("C26", "az", "az vm update -g rg -n v --set a=1 b=2", param("set", ["a=1", "b=2"])),
    ("C26", "aws", "aws ec2 create-tags --resources i-1 i-2 --tags Key=a,Value=b",
     param("resources", ["i-1", "i-2"])),
    ("C26", "gcloud", "gcloud compute instances create w --zone z --tags a,b",
     param("tags", ["a", "b"])),
    ("C26", "gcloud", "gcloud compute instances create w --zone z --labels k=v",
     param("labels", {"k": "v"})),
    # C25 a flag read by its value, not its presence
    ("C25", "git", "git branch --no-column -f prod HEAD~1", res("branch/prod", "branch/prod",
                                                               "branch/prod")),
    ("C25", "git", "git tag --no-column v1", res("tag/v1")),
]


def _check(intents, check):
    kind = check[0]
    first = intents[0]
    if kind == "res":
        return [i.resource for i in intents] == check[1]
    if kind == "param":
        return first.params.get(check[1]) == check[2]
    if kind == "any_param":
        return any(i.params.get(check[1]) == check[2] for i in intents)
    if kind == "no_param":
        return check[1] not in first.params
    if kind == "meta":
        return first.metadata.get(check[1]) == check[2]
    if kind == "unres":
        return check[1] in first.params.get("unresolved_scope", []) or "*" in first.params.get(
            "unresolved_scope", [])
    if kind == "marked":
        return any(i.resource == check[1] and "resolved_at_runtime" in i.params
                   for i in intents)
    if kind == "all_marked":
        return all(i.resource == check[1] and "resolved_at_runtime" in i.params
                   for i in intents)
    if kind == "action":
        return first.action == check[1]
    if kind == "set":
        return first.params["set"][check[1]] == check[2]
    if kind == "named_lacks":
        return check[1] not in first.metadata
    if kind == "last_lacks":
        return check[1] not in intents[-1].metadata
    if kind == "alias":
        return check[1] in first.resource_aliases()
    if kind == "derived_all_ns":
        return all(i.metadata.get("all_namespaces") for i in intents[1:])
    if kind == "has":
        return any(i.resource == check[1] and i.action == check[2] for i in intents)
    if kind == "verdict_block":
        rule = _rule(check[1], check[2], [check[3]], check[4])
        store = ConstraintStore(authority_map={"admin": {"deletion"}})
        store.add_constraint(rule)
        interceptor = AegisInterceptor(store)
        return any(interceptor.intercept(i, now=NOW).verdict == "BLOCK" for i in intents)
    if kind == "first_marked_destination":
        return first.params.get("resolved_at_runtime", {}).get("destination") is True
    if kind == "last_param":
        return intents[-1].params.get(check[1]) == check[2]
    raise AssertionError(kind)


@pytest.mark.parametrize("cls,tool,command,check", AUDIT,
                         ids=[f"{c}-{t}-{i}" for i, (c, t, _cmd, _chk) in enumerate(AUDIT)])
def test_sibling_audit(cls, tool, command, check):
    argv = shlex.split(command)
    if check == REFUSE:
        with pytest.raises(ValueError):
            from_argv(argv)
        return
    intents = from_argv(argv)
    assert _check(intents, check), [(i.resource, i.action, i.params, i.metadata)
                                    for i in intents]


def test_c13_unresolved_beats_recorded():
    # C13 (store): a recorded value never decides a key marked unresolved
    rule = _rule("argocd", "app/*", ["create"], {"project": "prod"})
    assert _verdict(rule, shlex.split("argocd app create d --file - --project dev")) == \
        "ESCALATE"
