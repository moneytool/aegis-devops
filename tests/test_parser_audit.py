"""The sibling audit of review rounds 1-22 (docs/dev/parser-audit.md): one check per class
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
    ("C11", "git", "git push origin @{u}", res("ref/*", "tag/*", "submodule/*")),
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
    ("C18", "aws", "aws s3 rm s3://b/logs --recursive", ("prefix", "key", "logs")),
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
     param("tags", {"a": "b", "c": "d"})),  # validate_tags makes a map
    ("C26", "az", "az vm update -g rg -n v --set a=1 b=2", param("set", ["a=1", "b=2"])),
    ("C26", "aws", "aws ec2 create-tags --resources i-1 i-2 --tags Key=a,Value=b",
     param("resources", ["i-1", "i-2"])),
    ("C26", "gcloud", "gcloud compute instances create w --zone z --tags a,b",
     param("tags", ["a", "b"])),
    ("C26", "gcloud", "gcloud compute instances create w --zone z --labels k=v",
     param("labels", {"k": "v"})),
    # C27 a value is typed only by the type the tool declares
    ("C27", "aws", "aws s3api delete-object --bucket production --key 001",
     res("s3/object/production/001")),
    ("C27", "gcloud", "gcloud compute instances create w --zone z --description 001",
     param("description", "001")),
    ("C27", "az", "az group update -n rg --set tags.x=001", param("set", ["tags.x=001"])),
    ("C27", "kubectl", "kubectl run web --image 001", param("image", "001")),
    ("C27", "helm", "helm upgrade r ./c --version 1.10", param("version", "1.10")),
    ("C27", "flux", "flux create source git a --url u --branch 001", param("branch", "001")),
    ("C27", "argocd", "argocd app set a --revision 001", param("revision", "001")),
    ("C27", "gh", "gh release create 001 -R o/r --title 007", param("title", "007")),
    ("C27", "git", "git push --push-option 007 origin main", param("push_option", ["007"])),
    # C28 custom pflag Values, and slice element types
    ("C28", "helm", "helm upgrade r ./c --wait=false", param("wait", "hookOnly")),
    ("C28", "argocd", "argocd app sync a --source-positions 0x2", param("source_positions", [2])),
    # round 12
    ("C7", "kubectl", "kubectl create secret generic s --from-literal a=b", res("secret/s")),
    ("C11", "kubectl", "kubectl create configmap c --from-literal a=b --append-hash",
     marked("configmap/c-*")),
    ("C11", "aws", "aws ec2 terminate-instances --instance-ids i-1 --generate-cli-skeleton",
     param("dry_run", True)),
    ("C27", "aws", "aws ec2 terminate-instances --instance-ids '[\"i-1\"]'",
     res("ec2/instance/i-1")),
    ("C27", "aws", "aws ec2 create-tags --resources i-1 --tags Key=a,Value=b",
     param("tags", [{"Key": "a", "Value": "b"}])),
    ("C27", "az", "az group create --name rg --location eastus --tags env=prod",
     param("tags", {"env": "prod"})),
    ("C27", "gcloud", "gcloud container clusters resize c --num-nodes 03 --region r",
     param("num-nodes", 3)),
    # C25 a flag read by its value, not its presence
    ("C25", "git", "git branch --no-column -f prod HEAD~1", res("branch/prod", "branch/prod",
                                                               "branch/prod")),
    ("C25", "git", "git tag --no-column v1", res("tag/v1")),
    # round 13
    ("C29", "kubectl", "kubectl logs web secret -c public -n prod", param("container", "secret")),
    ("C29", "kubectl", "kubectl logs web a b -n prod", REFUSE),
    ("C29", "gh", "gh api -R a/b -X DELETE repos/o/r", REFUSE),
    ("C30", "gh", "gh api --hostname staging.example "
     "https://api.github.com/repos/acme/prod/actions/secrets/X -X DELETE",
     meta("github_host", "github.com")),
    ("C30", "gh", "gh api https://ghe.corp/api/v3/repos/acme/prod/actions/secrets/X -X DELETE",
     meta("repo", "ghe.corp/acme/prod")),
    ("C30", "kubectl", "kubectl delete pod x --server https://p:6443 --cluster dev -n a",
     unres("cluster")),
    ("C30", "helm", "helm uninstall web --kube-apiserver https://p:6443 -n a", unres("cluster")),
    ("C30", "flux", "flux suspend kustomization app --server https://p:6443 -n a",
     unres("cluster")),
    ("C30", "aws", "aws ec2 terminate-instances --instance-ids i-1 --region us-east-1 "
     "--endpoint-url https://x", unres("region")),
    ("C31", "az", "az group update -n rg --tags @tags.txt", unres("tags.*")),
    ("C31", "aws", "aws ec2 create-tags --resources i-1 --tags file://t.json", unres("tags.*")),
    ("C31", "kubectl", "kubectl create configmap cm --from-file=c.yaml -n prod",
     unres("data.*")),
    ("C31", "gh", "gh api repos/a/b -F name=@n.txt -X PATCH", unres("inputs.name")),
    ("C31", "helm", "helm upgrade web ./c --set-file replicaCount=r.txt",
     unres("set.replicaCount")),
    # round 14
    ("C32", "kubectl", "kubectl delete pod harmless -n dev "
     "--raw=/api/v1/namespaces/prod/pods/protected", res("pod/protected")),
    ("C32", "kubectl", "kubectl delete pod harmless -n dev "
     "--raw=/api/v1/namespaces/prod/pods/protected", meta("namespace", "prod")),
    ("C32", "kubectl", "kubectl delete --raw /api/v1/namespaces/prod/pods/x/status", REFUSE),
    ("C32", "kubectl", "kubectl apply --raw /api/v1/namespaces/prod/pods/x -f a.yaml", REFUSE),
    ("C32", "az", "az rest --method delete --uri /subscriptions/s/resourceGroups/rg", REFUSE),
    ("C27", "aws", "aws s3 cp f s3://b/k --metadata classification=secret",
     param("metadata", {"classification": "secret"})),
    ("C27", "aws", "aws s3 rm s3://b/k --page-size 010", param("page-size", 10)),
    ("C6", "aws", "aws s3 sync . s3://b --exclude a --include b --exclude c",
     param("exclude", ["a", "c"])),
    ("C31", "gcloud", "gcloud compute instances create vm --zone z "
     "--metadata-from-file enable-oslogin=f.txt", unres("metadata.enable-oslogin")),
    ("C31", "gcloud", "gcloud storage buckets update gs://b --labels-file l.json",
     unres("labels.*")),
    ("C31", "aws", "aws s3 cp f s3://b/k --metadata file://m.json", unres("metadata.*")),
    # round 15
    ("C33", "kubectl", "kubectl delete --raw /api/v1/namespaces/prod",
     ("has", "*/*", "delete")),
    ("C33", "kubectl", "kubectl delete --raw /api/v1/namespaces/prod/all", REFUSE),
    ("C34", "gh", "gh api repos/acme/prod#ignored -X DELETE", res("repo/acme/prod")),
    ("C34", "gh", "gh api repos/acme/safe/../prod -X DELETE", REFUSE),
    ("C34", "gcloud", "gcloud compute instances delete "
     "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/vm#x", REFUSE),
    ("C34", "az", "az resource delete --ids /subscriptions/s/resourceGroups/rg/providers/"
     "Microsoft.Compute/virtualMachines/vm#x", REFUSE),
    ("C34", "kubectl", "kubectl delete --raw /api/v1/namespaces/prod/pods/x#y", REFUSE),
    ("C35", "gcloud", "gcloud run deploy s --region r --container app --image forbidden "
     "--container sidecar --image safe", param("image", ["forbidden", "safe"])),
    ("C35", "gcloud", "gcloud run deploy s --region r --image x --container a --image y",
     REFUSE),
    ("C35", "kubectl", "kubectl set image deploy/web c1=a c2=b -n prod",
     param("images", {"c1": "a", "c2": "b"})),
    # round 16
    ("C36", "helm", "helm upgrade web ./c -f values.yaml --set hosts[0]=safe",
     unres("set.hosts")),
    ("C6", "git", "git push -o a -o b origin main", param("push_option", ["a", "b"])),
    ("C6", "git", "git commit -m one -m two", param("message", ["one", "two"])),
    ("C18", "gsutil", "gsutil mv gs://prod/oldprefix gs://archive/newprefix",
     ("prefix", "key", "oldprefix")),
    ("C18", "gcloud", "gcloud storage mv gs://prod/oldprefix gs://archive/newprefix",
     ("prefix", "key", "oldprefix")),
    ("C1", "gh", "gh pr create -t Fix -b Desc", param("title", "Fix")),
    ("C1", "gh", "gh pr edit 42 -t Fix", param("title", "Fix")),
    ("C1", "helm", "helm pull bitnami/nginx -d /tmp", param("destination", "/tmp")),
    # round 17
    ("C37", "kubectl", "kubectl expose deployment harmless -n prod --port=80 --name=protected",
     ("has", "service/protected", "create")),
    ("C37", "kubectl", "kubectl autoscale deployment web -n prod --max=5",
     ("has", "horizontalpodautoscaler/web", "create")),
    ("C37", "gh", "gh pr merge 42 -s -d", ("has", "branch/*", "delete")),
    ("C38", "gh", "gh pr merge 42 --merge --squash --squash=false", param("method", "merge")),
    ("C38", "helm", "helm upgrade r ./c --atomic", unres("wait")),
    ("C6", "gcloud", "gcloud run deploy s --region r --image i --args a --args b",
     param("args", ["a", "b"])),
    ("C27", "gcloud", "gcloud compute instances create vm --zone z "
     "--accelerator type=t4,count=01", param("accelerator", {"type": "t4", "count": 1})),
    # round 18
    ("C13", "gh", "gh api -X PATCH repos/acme/prod --input body.json -F a=1",
     param("api_query", {"a": 1})),
    ("C37", "kubectl", "kubectl expose deploy web -n prod --port=80 --overrides={}",
     marked("service/*")),
    ("C39", "gcloud", "gcloud storage buckets update gs://b --update-labels env=prod",
     param("update-labels", {"env": "prod"})),
    ("C39", "gcloud", "gcloud compute firewall-rules create fw --rules tcp:22", unres("rules")),
    # round 19
    ("C40", "aws", "aws iam delete-role --role-name protected", param("role-name", "protected")),
    ("C40", "az", "az vm delete -n vm1 -g rg", param("name", "vm1")),
    ("C41", "git", "git push --receive-pack=Y --exec=X origin main", param("receive_pack", "X")),
    ("C41", "helm", "helm upgrade r ./c --force", param("force_replace", True)),
    ("C41", "gh", "gh repo delete a/b --confirm", param("yes", True)),
    ("C41", "az", "az compute-fleet delete --fleet-name b -g rg", param("name", "b")),
    ("C41", "aws", "aws mgn start-cutover --source-server-i-ds s-1",
     param("source-server-ids", ["s-1"])),
    # round 20
    ("C42", "helm", "helm uninstall web -n prod --kube-as-user admin",
     ("has", "user/admin", "impersonate")),
    ("C42", "gsutil", "gsutil -u billp rm gs://b/k", param("billing_project", "billp")),
    ("C42", "kubectl", "kubectl delete pod x --insecure-skip-tls-verify",
     param("insecure-skip-tls-verify", True)),
    ("C40", "aws", "aws ec2 modify-instance-attribute --instance-id i-1 --instance-type t3.large",
     param("instance-id", "i-1")),
    ("C43", "aws", "aws ec2 modify-instance-attribute --instance-id i-1 "
     "--disable-api-termination", param("disable-api-termination", {"Value": True})),
    # round 21
    ("C8", "argocd", "argocd app create dev/protected -N prod --repo r",
     meta("app_namespace", "prod")),
    ("C23", "argocd", "argocd app create decoy ignored --name protected --repo r",
     res("app/protected")),
    ("C23", "helm", "helm upgrade a ./c extra", REFUSE),
    ("C10", "git", "git rebase main feature", ("has", "history/*", "rewrite")),
    ("C37", "gh", "gh pr close 42 -d", ("has", "branch/*", "delete")),
    ("C44", "az", "az group update -n rg --tags env=safe --set tags.env=prod",
     param("tags", {"env": "prod"})),
    ("C44", "gcloud", "gcloud compute instances update vm --zone z "
     "--update-labels env=prod,team=a --remove-labels team", param("labels", {"env": "prod"})),
    # round 22
    ("C37", "kubectl", "kubectl apply -f desired.yaml --prune -l app=web -n prod",
     ("has", "pod/*", "delete")),
    ("C37", "gh", "gh issue transfer 42 --repo acme/source acme/protected",
     param("destination_repo", "acme/protected")),
    ("C44", "az", "az group update -n rg --tags env=safe --se tags.env=prod",
     param("tags", {"env": "prod"})),
    ("C31", "az", "az group update -n rg --tags env=@.git", unres("tags.*")),
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
    if kind == "prefix":
        return first.params.get("unresolved_prefix", {}).get(check[1]) == check[2]
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


def test_attribution_notice_ships_and_aws_header_is_kept():
    # aws_shorthand.py is aws-cli's file: its upstream header stays first, verbatim, and
    # the repository NOTICE (listed as a license file, so it is in the sdist and wheel)
    # names it and every source whose logic was ported
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    header = (root / "src/aegis_core/aws_shorthand.py").read_text().splitlines()
    assert header[0] == "# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved."
    assert header[11] == "# language governing permissions and limitations under the License."
    assert header[13].startswith("# Modifications Copyright")
    notice = (root / "NOTICE").read_text()
    for name in ("aws-cli", "botocore", "azure-cli", "Google Cloud SDK", "pkg/strvals",
                 "spf13/pflag", "time.ParseDuration", "knack", "GitHub CLI", "git"):
        assert name in notice, name
    pyproject = (root / "pyproject.toml").read_text()
    assert 'license-files = ["LICENSE", "NOTICE"]' in pyproject


def test_shipped_files_hold_no_local_paths():
    # the package data, NOTICE and docs ship or are published: a path on the machine that
    # generated them (a home directory, a temp or scratch directory) must never be in them
    import re
    import zipfile
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    local = re.compile(r"/Users/|/home/[a-z]|/private/tmp|/private/var|/tmp/|vampiremac|"
                       r"scratchpad|[A-Z]:\\\\Users", re.I)
    texts: dict[str, str] = {}
    for path in (root / "src/aegis_core/data").iterdir():
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    texts[f"{path.name}:{name}"] = archive.read(name).decode("utf-8", "replace")
        else:
            texts[path.name] = path.read_text()
    for path in [root / "NOTICE", root / "src/aegis_core/aws_shorthand.py"]:
        texts[path.name] = path.read_text()
    for name, text in texts.items():
        found = local.search(text)
        assert found is None, (name, text[max(0, found.start() - 40):found.end() + 40])
