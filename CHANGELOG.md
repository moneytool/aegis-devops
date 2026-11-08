# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From 1.0 the public surface listed
under 1.0.0 below is stable: breaking it needs 2.0. Before 1.0 any release could change
behaviour.

## [Unreleased]

Every parser reads flags the way its tool does: a flag that takes a value takes the next word
whatever it looks like, and a flag the parser cannot place, or a short letter whose meaning on
the command it does not know, is refused instead of guessed or recorded as written (#80).
Values are applied in the tool's own order, and words after `--` are read as the tool reads
them.
What a command takes from outside its argv -- a configuration file, the environment, a file a
value is read from, values reused from an earlier run -- is marked unresolved, so a rule it
could affect escalates, or the command is refused, and a value recorded for a key that is
marked unresolved never decides it; an empty value for such a key counts as not given, and so
does a value the tool fills in when it runs (gh's `{branch}`, git's `@{u}`); so is an ID the tool looks up from a name
when it runs (an az subscription or location by name, a gcloud project by number). One value
written several ways (a negated boolean, a URL or a number, a host-qualified name, an ARN, an
abbreviated option (aws and az, as argparse resolves it), a short option or its long one, a literal or a nested key, `-` or `_`,
a qualified or a flagged namespace) meets a rule written any of those ways, on every
subcommand, and so does a mark that leaves it unresolved. A value decoded from JSON or YAML
is the value the tool sends (helm's JSON numbers are float64, aws reads YAML 1.2). A target the tool expands when it runs (a list, a selector, `--all`, a
wildcard bucket, a recursive path, a file or stdin of objects) is marked, every `kind/*`
target in one place for every parser, so a rule on anything
it may reach escalates, and a selection's scope is never copied onto the targets named beside
it.
No command is read as a read unless it is one of the commands audited as only reading; any
other, an unknown one included, is refused or keeps its own verb as its action. Commands that
act on several objects are one intent per object, which can raise a plan rule's count
(`max_intents`) or change a `ratio`.

What the hook cannot see and does not mark: a helm chart's own default values (`set.*` is what
the command line, files and reuse can set, not what the chart ships); kubectl's kuberc and an
argocd `$ARGOCD_OPTS` set in the environment rather than in front of the command; aliases a
tool reads from its own configuration (`aws` cli aliases, `gh alias`, `git` aliases); and the
key a KMS alias or the secret a Secrets Manager name stands for, which are marked rather than
resolved. The aws option table is aws-cli 2.37.4's, so an option or command added later is
refused until the table is regenerated; the gcloud flag table covers the commands the parser
names resources for, and other gcloud commands, and alpha and beta, keep the rule that an
unknown long flag before a word is refused (an unknown long flag at the end is kept by its
name). git verbs without an option table leave every param unresolved when given an option.

### Fixed
- helm and flux read a long flag with no entry in the parser as a flag with no value, so the
  word after it was read as flags: `helm upgrade api ./c -n prod --description -ndev` was read
  as namespace `dev`, and helm runs it in `prod` with the description `-ndev` (#80). `flux create
  source git a -n prod --url -ndev` was read as `dev` the same way. Both tools now have tables
  of every long flag that takes a value and every one that does not, read from their source
  (helm 4.3.1 and 3.21.1, flux2 v2.10.0), so these read as `prod`. helm's `--server-side` takes a
  value on `upgrade` and `rollback` and none on `install`, as in helm 4. Neither tool was run.

  A flag in no table is now refused unless it carries `=value` or is the last word, on kubectl,
  helm, flux and argocd alike: if it takes a value the next word is that value, and if it does
  not the next word is a flag, a name or an operand, so either guess can misread the namespace
  or the target. Before, kubectl took a following word as the value, so `kubectl delete pod
  --new-bool web` was a delete of every pod, and helm and flux did the same, so `helm upgrade
  --no-hooks api ./c` was `release/./c`. kubectl's tables now hold every flag of kubectl 1.36
  (from `--help` on every command), which also reads flags that were refused before, such as
  `kubectl config set-context --current --namespace=prod`. A short flag in no table is refused
  the same way unless it is last.
- argocd ignored bundled short flags: `argocd app sync a -qnprod` recorded a flag called
  `qnprod`. Short words are now read letter by letter, as for kubectl, helm and flux, from the
  letters argocd's `app` commands have (argo-cd v3.6.1 and main, from source, not run), so
  `-qnprod` is refused, since argocd has no `-q`, and `-yl team=x` is `--yes --selector
  team=x`. argocd's long flags are in tables too.
- `argocd app sync a -l team=x` and `argocd app sync a --project prod` sync every app the
  selector or project picks besides `a`, and `argocd app delete a -l team=x` deletes the apps
  the selector picks. Only `app/a` was read. Each is now an `app/*` intent, marked, so a rule on
  one app escalates, and `sync -l` or `--project` with no app named is read instead of refused.
  `--dry-run` is a rehearsal only on `app sync`, the one verb that has it (from source).
- `kubectl logs -l app=x` and `kubectl logs -fl app=x` were refused, though kubectl reads the
  logs of every pod the selector matches. They are now `pod/*` with the selector, marked, in
  the namespace given, as other selector verbs are, and so are `cordon`, `uncordon` and `drain
  -l` (`node/*`). Checked on kubectl 1.36 against a local stub API server: it listed the pods or
  nodes by the selector in that namespace. `logs` has no `-A`, and kubectl refuses it there.
- `kubectl create deployment -r0xf` and `--replicas=0xf` were recorded as the text `0xf`.
  pflag reads integers with base 0, so kubectl creates 15 replicas, and `kubectl scale
  --replicas=0x0` scales to 0, which a rule on `replicas: 0` did not see. Every kubectl integer
  flag is now read as Go's `strconv.ParseInt(s, 0, …)` reads it (`0x`, `0o`, `0b`, a leading `0`
  for octal, `_` between digits), and a number kubectl refuses (`08`, `1e3`, out of range,
  `-rnprod`) is refused. Each spelling in the tests was run with `kubectl create deployment
  --dry-run=client`.
- helm uninstalls every release it is given, so `helm uninstall web payments` was read as
  `release/web` only. It is now one intent per release, and `from_helm` raises on two, as
  `from_kubectl` does (use `from_helm_multi`). Words after `--` were taken as a flag's value,
  and are now releases, as pflag reads them: `helm uninstall a -- -nprod` uninstalls a release
  called `-nprod` in the default namespace. `helm install ./c --generate-name` (or `-g`, or
  `--name-template`) was read as a release called `./c`; helm names the release when it runs,
  so it is now `release/*`, marked. `--set`, `--set-string` and `--set-literal` are merged in
  helm's order, whatever their order on the line, and `-f a.yaml,b.yaml` is two files.
- flux `suspend`, `resume`, `reconcile`, `delete` and `export` take every name they are given,
  and only the first was read: `flux suspend ks web payments` missed `payments`. flux 2.10 also
  takes `TYPE/NAME` words and plural or short type names (`flux suspend ks/a ks/b`, `flux
  reconcile kustomizations a`, `gitrepo/a`), which were refused or read as a kind called
  `ks/a`. All of these are now one intent per object, and `from_flux` raises on two (use
  `from_flux_multi`). The kinds under `image`, `artifact` and
  `secret` were read as a kind called `image` named `repository`: `flux reconcile image
  repository a` is now `image-repository/a`. `flux suspend <kind> --all` is `<kind>/*`, marked,
  and `flux reconcile ks a --with-source` also reaches the kinds of source it can reference.
  `flux reconcile ... --dry-run` was read as a rehearsal, and flux has no `--dry-run` on any verb
  the parser reads, so it no longer is. From flux2 v2.10 source; flux was not run.
- git read options with its own guesses. Options of `push`, `branch`, `tag`, `rebase`, `reset`
  and `commit` now come from git 2.52's `-h` and completion lists and are read as git's
  parse-options reads them, which was run against a local bare repository: `git push -fu origin
  main` was not a force push (the word `-fu` was a flag of its own, and `origin` its value),
  `git push --force-w origin main` and `git commit --amen` were missed (git takes an unambiguous
  prefix), `git commit -n --amend` was read as a rehearsal (`-n` is `--no-verify` on commit; it
  is `--dry-run` only on push), and `git push --dry-run --no-dry origin x` was a rehearsal, and
  git pushes. An option git refuses is refused. `git push origin safe +main` force-pushes `main`
  and was read as `ref/safe` only: every refspec is now an intent, a pattern refspec
  (`refs/heads/*`) reaches refs the argv does not name, and so do `--tags` and `--prune`. `git
  branch -D a b` and `git tag -d a b` name every branch or tag, `git rebase <upstream> <branch>`
  also rewrites `<branch>`, and `git filter-repo` rewrites every ref (`history/*`, marked).
  `from_git` raises on two targets (use `from_git_multi`).
- aws-cli's argparse takes an unambiguous prefix of an option, and the parser did not: `aws ec2
  terminate-instances --instance-ids i-1 --regio us-west-1` runs in `us-west-1` and was read with
  no region, `aws iam delete-role --role prod-admin` deletes `prod-admin` and was `iam/role/*`,
  and `--instance-id i-1 i-2` terminates both. Global options are now matched as aws matches
  them, over the whole line (`--reg`, and `--re` even on `s3 rm`), a prefix of a flag that names
  the target fills a target no full flag names, and a prefix of `--no-dry-run` ends the
  rehearsal. `aws s3 cp s3://staging/x s3://prod/x` was read as a write to `staging` only: every
  `s3://` path is now an intent, `mv` also deletes its source, and `sync --delete` deletes in the
  destination. The s3 commands' own options are read (`--recursive` takes no value, so `aws s3
  rm --recursive s3://b` is no longer refused, and `--dryrun` rehearses). A target given only in
  `--cli-input-json` or `--cli-input-yaml` was `*`, which a rule on one name never met; it is now
  marked. Words after `--` are refused, as aws refuses them. Each case was run with aws-cli 2.37
  against a closed local port, reading the request it built.
- az: `-nprod-vm`, `-n=prod-vm` and `-ynprod-vm` were read with no name (argparse reads them as
  `-n prod-vm`), so a rule on the VM missed. They are now read as argparse reads them. A prefix of
  `--name`, `--resource-group`, `--location`, `--subscription` or `--ids` (`--resource-gr rg`) is
  refused, since argparse takes it and what it stands for depends on the command. Other short
  words are read from the letters azure-cli's command modules define (every `_params.py`): a
  letter that is only ever a value option takes the rest of the word (`-cmycontainer`,
  `-snprod`), and a word is refused only when a letter that is a plain boolean on some command
  makes another reading set a different name, resource group or location (`-dnprod`), or when
  no az command has the first letter (`-Anprod`). From azure-cli and knack source; az was not
  run.
- gcloud read only the first name: `gcloud compute instances delete web-1 prod-1` missed
  `prod-1`. Every name is now an intent. A `--no-` flag is a boolean and no longer takes the name
  after it as its value (`delete --no-graceful-shutdown prod-1`). Any other flag the parser has
  no entry for, followed by a word, is refused: the word is its value if it takes one and a name
  if it is a boolean, so `delete web-1 --graceful prod-1` could hide `prod-1`. gcloud's source
  tree (and its per-command flag types) is not on GitHub to read, so the parser keeps a table of
  flags the gcloud reference shows taking a value (`--machine-type`, `--keep-disks`, the global
  ones, ...), and any other must be written `--flag=value` or last. Words after `--` (`compute ssh vm -- …`)
  are kept as `passthrough`, not names. `gcloud sql import sql prod-db …` was `sql/sql`, and is
  `sql/instance/prod-db`. `gcloud storage rm --recursive gs://a gs://b` and `gsutil -m rm -r
  gs://b` were refused or read one bucket; both now read their own booleans and every `gs://`
  path, and `mv` also deletes its source. gcloud takes no abbreviated flag (calliope turns them
  off, read in its source), which needed no change. `from_gcloud` raises on two targets (use
  `from_gcloud_multi`). The booleans of `gcloud storage` and gsutil's option letters come from
  their documentation, not their source, and neither gcloud nor gsutil was run: a letter or
  flag missing from those tables is refused (gsutil) or may still take the next word (gcloud
  storage, though never a `gs://` path).
- aws: a full target flag and an abbreviation of the same flag were read as the full one only.
  argparse reads both as that flag and keeps the last, so `aws iam delete-role --role-name a
  --role b` deletes `b`, read as `a`. Every spelling's value is now a target (`iam/role/a` and
  `iam/role/b`), on the target and id flags, `--instance-ids`, and s3api's `--bucket` and
  `--key`. Run with aws-cli 2.37.
- A flux command with no `-n` was read as having no namespace, and a namespace-scoped rule then
  did not apply. flux uses `flux-system`, or `$FLUX_SYSTEM_NAMESPACE`, or with
  `--ns-follows-kube-context` or `$FLUX_NS_FOLLOWS_KUBE_CONTEXT` the kubeconfig context's
  namespace, and the argv shows none of these variables. The namespace is now unresolved, as for
  kubectl and helm, so such a rule escalates with `namespace-unresolved`, and
  `--resolve-current-context` fills the namespace flux would pick (flux2 main.go). An inline
  `FLUX_NS_FOLLOWS_KUBE_CONTEXT=1` is recorded on the intent.
- `git branch -m old new`, `-M`, `-c`, `-C` and `git branch -f main HEAD~3` were reads. A rename
  now creates the new name and deletes the old one (with one name, the current branch,
  `branch/*` marked), a copy creates the new name, and `-M`, `-C`, `--force` and `-f` also
  delete the branch they overwrite, so `git branch -M feature main` meets a rule against
  deleting `branch/main`. Run with git 2.52.
- helm `--set-json` was recorded raw, so `--set-json replicaCount=0` never met a rule scoped on
  `set.replicaCount`. It is now read as JSON and merged into `set` in helm's order. Every
  `--set` kind is read by a port of helm's `pkg/strvals` into one nested map, the shape helm
  gives the chart: `--set-json 'securityContext={"privileged":true}'` had become the literal
  key `securityContext.privileged`, which a rule on `set.securityContext.privileged` (a walk of
  nested maps) did not find, so a BLOCK allowed it. `--set image.tag=v2` is now
  `{"image": {"tag": "v2"}}` where it was the key `image.tag`. Lists (`{a,b}`, `x[1]=y`),
  escapes (`a\,b`), helm's typing (`1.5` and `010` stay text, `null` is null), the order
  (`--set-json` first, a later scalar replacing a map) and a map under a scalar, which helm
  refuses, all follow helm; quotes are not special to helm, so `--set s="x,y"` is refused as
  helm refuses it. The store's dotted lookup also finds a key with dots in it at any level
  (`labels.app.kubernetes.io/name`). A key set by
  `--set-file`, or left to a values file (`-f`) or `--reuse-values`, comes from a file nobody
  read, so a rule scoped on it escalates with `set.<key>-unresolved`. The chart's own defaults
  are still not read: `set.*` is what the command line sets.
- `kubectl create deployment --port=0x50` was the text `0x50`; kubectl reads that flag with base
  0, so it is 80, and `--port=080` is refused, as kubectl refuses it (run on kubectl 1.36). On
  `expose` and `run` `--port` is a string kubectl reads with `Atoi`, which the parser already
  matched.
- aws read a prefix only for global options and target flags. Every option of each `aws s3`
  command is now matched exactly or by its one unambiguous prefix, from aws-cli 2.37's tables:
  `aws s3 sync ./empty s3://prod --del` was a put with a param `del`, and aws deletes in the
  destination; `--dryr` is `--dryrun`, `--rec` is `--recursive`, and an ambiguous or unknown
  prefix is refused as aws refuses it. A prefix of `--dry-run` of three letters or more
  (`aws ec2 terminate-instances ... --dry`) is the rehearsal, except on the seven operations
  botocore gives another `dry-*` option. Run with aws-cli 2.37.
- `gh api <path> -f k=v` (or `-F`, `--field`, `--raw-field`, `--input`) without `-X` was read
  as a GET; gh sends POST then, so `gh api repos/o/r/actions/workflows/deploy.yml/dispatches -f
  ref=main` is now `workflow/deploy.yml` / `run`, as with `-X POST`. `{owner}`, `{repo}` and
  `{branch}` (or `:owner` ...) in an api path are filled by gh from the current repository and
  are no longer read as names. Without `-R` gh acts on the current directory's repository or
  `$GH_REPO`, so `repo` is now unresolved and a repository-scoped rule escalates with
  `repo-unresolved`; `--resolve-current-context` fills it from `$GH_REPO`. From cli/cli
  v2.103 source.
- `git push origin main --follow-tags` (and `-c push.followTags`, unless `--no-follow-tags`)
  also pushes the annotated tags reachable from what is pushed, and now adds an unresolved
  `ref/*` push, as `--tags` does. `git push origin HEAD` (or `@`) pushes the current branch and
  `git push origin :` every matching branch; both were read as named refs (`:` as a delete of
  nothing) and are now unresolved `ref/*`. `--mirror` and `-c remote.<name>.mirror=true` also
  delete every remote ref with no local one, now a `ref/*` delete beside the force push.
- `gcloud storage mv` and `gsutil mv` with several sources deleted only the first; every
  `gs://` source is now a delete, and so is the source of `gsutil cp -M`, which moves. With
  `-I` / `--read-paths-from-stdin`, `rm` and a move also reach `storage/bucket/*`, marked.
  `rsync` with deletes stays refused.
- gcloud: the space form of common create commands is read again (`gcloud container clusters
  create --enable-autoscaling demo --zone ...` was refused). The boolean flags of the commands
  that change something most often (container clusters and node pools, compute instances, sql
  instances, run deploy, functions deploy) and more value flags are listed, from the gcloud
  reference. `gcloud run deploy SVC` is `run/service/SVC` (it was `run/SVC`).
- A literal dotted helm key (`--set 'securityContext\.privileged=false'`) beside the nested
  value of the same path (`securityContext.privileged=true`) hid the nested one, so a BLOCK
  allowed it. The store now reads every value a scope key reaches and matches if any does. A
  scope key also matches its `-`/`_` twin and a boolean's negated spelling (`no-verify-ssl` is
  `verify-ssl` negated), and `repo`, `resource_group` and `subscription` compare without case.
- `helm upgrade` with no values on the command line reuses the release's previous values, and
  so does `--reuse-values` or `--reset-then-reuse-values` for every key it does not set (helm
  3.21.1 and 4.3.1 Upgrade.reuseValues); `--reset-values`, checked first, turns that off.
  `helm rollback` puts back an earlier revision's values. Those are now `set.*`, unresolved.
- `-A` / `--all-namespaces` on flux and helm was a param, so `flux get kustomizations -A -n
  dev` met a prod rule as `dev`. It is now `metadata.all_namespaces`, as on kubectl, and the
  last spelling decides.
- Scope a tool takes from its configuration or environment when the argv does not give it was
  read as absent, so a rule scoped on it did not apply: kubeconfig context and cluster, aws
  region and profile, gcloud project and region (the active configuration, `--configuration`,
  `$CLOUDSDK_*`), az subscription, resource group and location (`az account`, `az config`),
  argocd server, project and the Application's namespace, git's push remote, and gh's
  repository. Each is now in `params.unresolved_scope` when missing, and a rule scoped on it
  escalates; `--resolve-current-context` fills what the environment says.
- gh: `gh pr merge https://github.com/o/r/pull/42` was `pr/https://...`. A pull request or
  issue by `#42`, `OWNER/REPO#42` or URL is `pr/42` (or `issue/42`) with that repository; a
  branch or no selector is `pr/*`, marked. `issue delete`/`close` and `run cancel`/`delete`/
  `rerun` were reads and now delete, stop or run. A workflow by display name or ID is marked.
  `-R` in `HOST/OWNER/REPO`, URL or `git@` form is `owner/repo`; another host than github.com
  is `host/owner/repo` with `github_host`, so a github.com rule never matches it. Secret and
  variable names are upper-cased, as GitHub stores them. `-F k=@file`, `--input`, workflow run
  `--json` and a workflow run without `-r` leave the values they decide unresolved.
- git: `push.followTags` in any config file can make `git push origin main` send tags. Every
  push now adds `tag/*`, marked, unless `--no-follow-tags` or `-c push.followTags=false`, so a
  rule on `tag/...` escalates and one on `ref/main` does not; an explicit `refs/tags/X` is also
  `tag/X`. With no refspec, push.default, `remote.*.push` (a `+` forces) and `remote.*.mirror`
  decide what is sent: `force` is unresolved and a possible delete of `ref/*` is marked. A
  remote given as a URL leaves `remote` unresolved; `--repo` is the remote when none is given.
  `--no-x` is `x: false`, and `--no-verify` / `commit -n` is `verify: false`.
- gcloud `--no-deletion-protection` recorded `no-deletion-protection: true` beside
  `--deletion-protection=false`'s `deletion_protection: false`; both are now
  `deletion_protection: false`, the last spelling winning. `--flags-file` (more flags from a
  YAML file, `--project` too) is refused. A resource by URI or path is its plain name in the
  URI's project, zone and region.
- aws `--no-x` is `x: false` (`--no-verify-ssl` is `verify_ssl: false`). An ARN keeps the
  resource and adds its plain name as an alias, with the ARN's account and region, so a rule
  on the name matches; a target from `file://`/`fileb://`, a KMS alias and a Secrets Manager
  secret by ARN are marked. az: a name, resource group, location, subscription or `--ids` given
  as `@file` is refused. argocd `NAMESPACE/NAME` is `app/NAME` with `app_namespace`, as `-N`
  is, and `--server` is recorded.
- An inline `HELM_NAMESPACE=prod` was the namespace of any command, kubectl's too. Inline
  variables now set only the scope of the tool that reads them, in its precedence, with
  `HELM_KUBECONTEXT`, `GH_REPO`, `AZURE_DEFAULTS_GROUP`/`_LOCATION` and `ARGOCD_SERVER` added;
  `ARGOCD_OPTS` and `KUBERC` (unless `off`) in front of the command are refused. terraform
  `-chdir` is one path (`./infra`, `infra/` and `infra` are `workspace/infra`).
- terraform and tofu `apply -destroy=true` (and `-destroy=T`) were refused as needing a plan, and
  `-destroy -destroy=false` was read as a destroy. Go's flag package reads the last `-destroy`,
  with `strconv.ParseBool`, and so does the parser now; `-auto-approve=true` and
  `--auto-approve` set `auto_approve`. `-destroy=T` and `-destroy=yes` were run with terraform in
  an empty directory.
- gh read an unlisted boolean as taking the next word, which was often the target: `gh pr
  merge -s 42` was a merge of `pr/*` (`42` taken as the value of `-s`), `gh repo delete --yes
  owner/repo` was `repo/*`, and `gh api -XDELETE repos/o/r` was a read of `api/*`. `-r` was read
  as `--ref` on every command, and on `pr merge` it is `--rebase`. The commands that change
  something (`pr merge`, `pr close`, `repo delete`, `release create`/`delete`, `secret
  set`/`delete`, `variable set`, `workflow run`, `api`) now have tables of their flags from
  cli/cli v2.103 source (not run), read as pflag reads them, and a flag in no table is refused
  as on the other pflag tools.
- An unresolved mark was compared with a rule's key letter for letter, while matching treats
  `-` and `_` as one: `helm upgrade api ./c --set-file replica-count=r.txt` left
  `set.replica-count` unknown, and a rule on `set.replica_count: 0` allowed it. One function
  (`canonical_key`) now decides key equality for matching, at every level of a nested key, for
  the unresolved marks (with a boolean's negated side) and for the configuration marks, so
  that command escalates, as does argocd's `app_namespace` against `app-namespace`.
- `flux reconcile ks app -n dev --with-source` gave the source intents namespace `dev`, but a
  source reference may name its own namespace (reconcile_with_source.go). The source intents
  now cover every namespace, so a rule scoped to `prod` escalates. The other intents derived
  from a parent were checked: kubectl's `exec deploy/x` pod and `run --expose` service live in
  the parent's namespace, argocd's selector picks have their namespace unresolved unless
  `--app-namespace` is given, and gh and git targets keep the repository and remote they act on.
- git: `git push origin tag v1` is `refs/tags/v1` (builtin/push.c), and was read as two
  refspecs, `tag` and `v1`. A deleted tag (`git push --delete origin refs/tags/v1`, `git push
  origin :refs/tags/v1`, `--delete ... tag v1`) was `tag/v1` with action `push`; it is now a
  delete. `--mirror` and `--prune` also delete `tag/*`, `--mirror` sends every tag even with
  `--no-follow-tags`, and a push that only deletes sends none. A short name (`git push origin
  v1.2.0`) is a tag when the local or remote ref of that name is one, which only git knows: the
  intent now carries `tag/v1.2.0` as a possible resource, so a rule on it escalates. `--delete`
  with a `:` in a name, with no name, or with `--tags`/`--all`/`--mirror`, and `tag` with no name,
  are refused as git refuses them. Run on git 2.52 against a local bare remote.
- aws read an abbreviated option under the abbreviation: `aws autoscaling set-desired-capacity
  --desired-cap 0` recorded `desired-cap`, so a rule on `desired_capacity: 0` allowed it. Every
  option of every aws command is now resolved as argparse resolves it, against the operation's
  full option list read from aws-cli 2.37.4's own parsers (`src/aegis_core/data/
  aws_cli_options.zip`, written by `scripts/gen_aws_cli_options.py`), and recorded under its
  full name; each option takes the words aws gives it, a negative number included. An
  ambiguous or unknown option, a single-dash word, or a command aws-cli does not have is
  refused. An abbreviation and the full option it stands for were both kept as targets
  (`--role-name a --role b`); the last one is now the target, as in aws.
- aws `--cli-input-json '{"DesiredCapacity":0}'` and `--cli-input-yaml` were not read, and
  `set-desired-capacity` returned before the input target was marked. Inline input is now read
  into the options it stands for, by the operation's member names, before the command line,
  which overrides it as in aws, for every operation; a member the operation does not have, two
  inputs, or input that is not a mapping is refused, and an abbreviated `--cli-input-j` is
  ignored, as aws ignores it. Input in a `file://` file leaves every option the command line
  does not give unresolved (and the target marked), and so does any option whose value is read
  from `file://` or `fileb://`. Each case was run with aws 2.37 against a closed local port.
- gcloud gave every resource path the last path's project and zone: `gcloud compute instances
  delete projects/p1/.../a projects/p2/.../b` was two deletes in `p2`. Each path now keeps its
  own. A project given by number is `project_number`, with `project` unresolved and not filled
  from `$CLOUDSDK_CORE_PROJECT`, so a rule on a project ID escalates; an environment map entry
  matches either.
- gcloud refused `gcloud compute instances update --clear-labels web`, its boolean tables being
  hand-made and partial. Every flag of each command the parser names resources for (compute
  instances, disks and firewall rules, container clusters and node pools, sql instances,
  import and export, storage buckets and `cp`/`mv`/`rm`, functions, run, iam service accounts,
  projects, pubsub topics) is now read from its gcloud reference page
  (`src/aegis_core/data/gcloud_flags.json`, written by `scripts/gen_gcloud_flags.py`, which
  records the date): a boolean, a value, or an optional value, which takes the next word. A
  flag such a command does not have is refused, as gcloud refuses it. gcloud was not run.
- az `--subscription Production` recorded `subscription: Production`, where a rule may name the
  subscription ID, and `--location "East US"` recorded `region: East US`, which az turns into
  `eastus` from the subscription's location list when it runs (core commands/parameters.py).
  A subscription that is not a GUID is now `subscription_name` and a location with a space is
  `location_display_name`; `subscription` and `region` are then unresolved and not filled from
  the environment. Locations compare without case, as resource groups and subscriptions do.
  With `--ids`, az takes the subscription and resource group of each ID and ignores
  `--subscription` and `-g` (core commands/arm.py); the flags used to win. From azure-cli
  source; az was not run.
- `argocd app actions run prod/payments restart` returned before the qualified name was split,
  so it was `app/prod/payments` and a rule on `payments` in `prod` allowed it, while `payments
  -N prod` was blocked. argocd now splits `NAMESPACE/NAME` once, over every intent of every
  subcommand, and az normalizes a subscription name and a location display name once over
  every intent, an `--ids` path included (an ID with a subscription name was recorded as the
  subscription). aws `s3` commands also mark options read from `file://`. From source.
- Several commands that change something were read as reads. `git tag -f v1 HEAD` and `git
  tag v1` were reads of `tag/v1`; they create it, and `-f` also updates it, forced. `git branch
  side` creates `branch/side`; `-u`, `--unset-upstream` and `--edit-description` update the
  branch. Every git command other than push, branch, tag and the history rewrites was a read
  of `history/*`, `commit`, `pull`, `clean`, `stash`, `config x y` and `update-ref`
  included: only the commands git documents as reading (status, log, diff, show, the list
  forms of branch, tag, remote, stash, config ...) are reads now, and any other takes its
  verb as its action. gh's `release edit`, `pr edit`, `repo edit`, `issue edit` and every
  subcommand not listed were reads; gh's actions now come from one table checked against
  the gh manual (edit is `update`, comment and review `update`, reopen `start`, fork
  `create`, ...), and a command not in it is never a read. `argocd app get --refresh` and
  `--hard-refresh` patch the Application and are updates. `gcloud compute ssh` was a read of
  `compute/vm`: it is `exec` on `compute/instance`. `export` (gcloud sql export, aws
  `export-*`) writes the data out and is no longer a read. The verbs every tool reads as
  reads are pinned in a test, so a new one cannot default to read; an unknown verb is
  refused on aws, az, gcloud, helm, flux and argocd, and keeps its name on kubectl, git and
  gh. From each tool's documentation; not run.
- `gcloud storage rm 'gs://prod-*/secret'` and the same with gsutil were recorded as the
  bucket `prod-*`, and a rule on `prod-logs` allowed them: both tools expand `*`, `**`, `?`
  and `[...]` in a bucket name when they run. Such an intent is now marked with the pattern's
  literal prefix, so a rule on any bucket the pattern may match escalates, and a rule whose
  names cannot start with that prefix does not. A wildcard in the object, `-r`/`--recursive`,
  and aws `s3 --recursive` or `sync` (whose keys `--include`/`--exclude` pick) leave the key
  unresolved. The other tools were checked: kubectl `-l` and `--all`, argocd `-l`, git
  pattern refspecs and flux `--all` were already marked; kubectl, helm, argocd, az, aws and
  git names are not expanded by the tools. From gcloud and gsutil documentation; not run.
- helm `--set-json quota=9007199254740993` kept the exact integer, but helm decodes JSON
  with Go's encoding/json into float64, so the chart gets 9007199254740992. `--set-json`
  numbers are now decoded as Go decodes them (an integral value is compared as an int), and
  NaN, Infinity and numbers out of float64's range are refused. Every other decode path was
  checked: aws `--cli-input-json` keeps exact integers, as botocore does, and
  `--cli-input-yaml` is now read as aws-cli v2's YAML 1.2 reads it (`yes` is a string, `010`
  ten, `0o10` eight; it was read as YAML 1.1, so `yes` was true and `010` eight); `gh api -F`
  types fields as gh does (true, false, null, an int64), and `-f`, and every `gh workflow
  run` input, are strings (all were coerced to numbers before). kubectl `-p` patches, argocd
  `-p` parameters and flux values are kept as text. Checked: aws by running aws 2.37
  against a closed local port; helm and gh from source.
- `git branch --no-column -f prod HEAD~1` was read as a list, because `--column` was present
  though false. List mode now follows builtin/branch.c and builtin/tag.c (git 2.52): `--list`
  by its value, no name and no other action, the `--contains`, `--no-contains`, `--merged`,
  `--no-merged` and `--points-at` filters, and on tag `-n` with any count; `--column`,
  `--sort`, `--format` and `-v` only shape a list. `--show-current` is a read and `git branch
  -a`/`-r` with a name is refused. The other parsers were checked for a flag read by its
  presence rather than its value. Run on git 2.52.
- `gh issue edit 23 34 --add-label bug` kept only `issue/23`: gh edits every issue given. Each
  gh command's argument count is now checked against its cobra Args (cli v2.103 source); a
  count gh refuses is refused, and `issue edit`, the one command that takes several, is one
  intent per issue, each with its own repository.
- Short options were recorded under their letter: `az aks scale -c 1` was `c: 1` where
  `--node-count 1` was `node-count: 1`, and `gcloud container clusters delete c -z
  us-east1-b` was refused, `-z` being `--zone`. Every short option of every tool is now
  recorded as its long option, and the long option is what feeds metadata: kubectl (`-w`
  watch, `-i` stdin or interactive, `-p` previous or patch, ...), helm (`-q` short, `-l`
  labels or selector, `-a` all or api-versions, ...), flux (`-s` silent, `-u` username, ...),
  gcloud (each reference page's short spellings), az (every `_params.py` of azure-cli,
  `src/aegis_core/data/az_short_options.json`, written by `scripts/gen_az_short_options.py`;
  where a command's `-n`, `-g` or `-l` is another option, such as `--account-name`, that
  option names the target, group or location in either spelling) and git (`-D`, `-M`, `-C`
  are `--delete`, `--move`, `--copy` with `--force`). argocd and gh already were. Tests check
  that the short and long spellings give the same intents for every alias in the tables.
  From each tool's source or reference pages; not run.
- `argocd app create decoy --file - --upsert` was `app/decoy`, but argocd reads the
  Applications from the file, a URL or stdin and ignores the name: the target is now `app/*`,
  marked, with every field the line does not give unresolved. The other inputs that decide
  targets were checked: kubectl `-f -` is a manifest nobody read, helm `-f -` leaves `set.*`
  unresolved, `gh --input -` its fields, aws `file:///dev/stdin` every option, and gcloud
  `--flags-file` is refused; az values read from `@file` or `@-` are now unresolved. From
  source.
- `argocd app sync payments --project dev` gave `app/payments` the project `dev`, though
  `--project` only picks more apps to sync: the app named keeps its own (unknown) project, and
  only the added selection has `project: dev` (and `-l` the selector). kubectl refuses a name
  beside a selector, and now so does the parser (checked on kubectl 1.36); kubectl `run` and
  `expose -l` is `--labels`. flux `--all` with names acts on the names only, as before.
- `gh workflow run ... -F environment=prod -f environment=dev` was `dev`, the last on the
  line, but gh reads every `-f` first and every `-F` after (cli v2.103 run.go and
  api/fields.go), so `prod` wins. gh api now also builds nested keys and arrays (`a[b]=1`,
  `a[]=1`) and refuses a key set twice, as gh does, and a dispatch body's inputs are the
  porcelain's `inputs`. kubectl `run --overrides` patches the object after every flag, so
  every key and the name are now unresolved (a `**` mark). helm's set order and aws's command
  line over its input were already applied.
- az short options in scopes built with `.format()`, `+`, f-strings or loop variables were
  missed, and fell back to the letter: `az storage fs file delete -f fs -p prod` recorded `f`
  and `p`. The generator now reads those scopes (1363 in all), and a short letter with no
  entry for the command is refused, on az and on kubectl, helm, flux, argocd, gh and gcloud
  alike. knack's `-y` (`--yes`) is one of az's own. git verbs without an option table no
  longer record options as written (`git fetch -n` was read as a dry run): any option leaves
  every param unresolved, and `filter-branch`'s refs are marked.
- `gcloud compute instances delete safe -- prod` kept `prod` as a command to pass on, but
  argparse reads it as a positional: both are targets now. Only `ssh` takes a command after
  `--`; on a command outside the flag table `--` is refused. kubectl, helm, flux, argocd, gh
  and git read the words after `--` as arguments, and aws and az refuse them, as before.
- `argocd app create decoy --file - --project dev --upsert` kept `project: dev` beside the
  mark that every key is unresolved, and the store let the recorded value decide, so a rule
  on `project: prod` allowed it; argocd does not apply `--project` to apps read from stdin.
  The parser no longer records the line's project or app namespace for apps from a file, and
  the store no longer lets any recorded value, in metadata or params, decide a key marked
  unresolved (by name, `*` or `**`, through `canonical_key`): the rule escalates. A key
  `--resolve-current-context` fills is unmarked as it is filled. aws input from a file now
  marks exactly the options the command line does not give, which it overrides.
- `argocd app create -f application.yaml` was refused for want of a name: a file of
  Applications needs none, and is now `app/*`, marked. `gh secret set DECOY --env-file -`
  and `gh variable set DECOY -f .env` set every name in the dotenv input and ignore the one
  on the line: `secret/*` / `variable/*`, marked; `gh secret set` with no `--body` reads the
  value from stdin, which is unresolved. kubectl `-f`, helm and flux have no file that stands
  for a target's name; az `@file` values are unresolved (round 6). From source.
- `gcloud storage buckets delete gs://prod` was `storage/bucket/gs://prod`. A `gs://` URI is
  the bucket (and its object the `key`) on every gcloud storage command, as on `storage rm`,
  wildcards marked the same way. `--read-paths-from-stdin` / `-I` on any storage command adds
  `storage/bucket/*`. Every `kind/*` target, from any parser, now carries the runtime mark,
  added in one place (`mark_unknown_names`), so no command can leave one unmarked:
  `gcloud storage buckets update --read-paths-from-stdin` was an unmarked `storage/bucket/*`
  (ALLOW against a rule on one bucket), and a list such as `kubectl get pods` is marked now
  too. The other URI spellings were checked: aws `s3://` and s3api `--bucket` already meet,
  az IDs and gh URLs are names already, and helm `oci://` and flux `--url` are not targets.
- `kubectl delete pod api --namespace=` recorded the namespace `""` as given, but client-go
  ignores an empty override and uses the context's. An empty value for any scope a tool takes
  from its configuration (`--namespace=`, `-n ""`, `--context=`, `--cluster=`,
  `--kube-context=`, argocd `--server=`, aws `--region ""` and `--profile ""`, gcloud
  `--project=` and `--zone=`, az `--subscription ""` and `-g ""`) is now removed in one place
  (`mark_config_scope`), so the key is unresolved as if it were not given. gh refuses `-R ""`.
- `gh api ... -F 'ref={branch}'` recorded the text `{branch}`: gh fills `{owner}`, `{repo}` and
  `{branch}` (and `:owner`, ...) in `-F` values from the current repository when it runs
  (fields.go). Such a field is now unresolved, and so is the `ref` taken from it. git's own
  substitutions were checked too: `git push origin @{u}` (`@{push}`, `@{-1}`, `-`) pushes a
  ref only git knows, now an unknown target, and `git branch -d -` or `@{-1}` is
  `branch/*`, marked. helm, kubectl and az substitute nothing in targets.
- az recorded an abbreviated long option under the abbreviation: `--node-c 1` was `node-c`.
  knack inherits argparse's allow_abbrev, so every az long option is now resolved by unique
  prefix against the command's full option list, and one that is neither an exact option
  nor a unique prefix of one is refused. The generator (`az_short_options.json`) reads each
  command's options from `_params.py` (its helper functions too), from the function the
  command runs (a custom function without `**kwargs` gives exactly its options, spelled as
  `_params.py` spells them), from AAZ command classes and from generic update commands;
  storage's data-plane account options are added. A command whose options are all known uses
  only its own, so an option declared for a parent group does not apply to it; for any
  other the group's options are included, and a prefix ambiguous among them is refused. A
  test parses 35 everyday commands from the az reference written with full option names.
  aws already resolved prefixes; gcloud disables them and gsutil uses getopt. `az aks
  upgrade` is now read (an update) instead of refused.
- `gcloud storage cp /tmp/secret gs://prod/backup/` recorded the key `backup/`, but the object
  written is `backup/secret`. A copy or move into a folder (a destination ending in `/`, or a
  bucket alone) now writes the prefix plus the source's base name, on gcloud storage, gsutil
  and aws s3 alike. Where the object depends on what the tool finds when it runs, the key is
  unresolved: several sources, `-r`/`--recursive`, paths from stdin, and on gcloud and gsutil
  a destination without the slash, which they treat as a folder when objects under it exist
  (aws never does). `az storage blob upload` is not a modelled command and is refused.
- Siblings of earlier fixes. `argocd app delete -l team=payments -N dev` gave the selection
  namespace `dev`, but delete lists the selector's apps in every namespace
  (getAppNamesBySelector) and deletes each by its qualified name: the selection's
  `app_namespace` is unresolved now (sync's list does take `-N`). `git branch -f '@{-1}'`
  and `git branch -m '@{-1}' new` recorded `branch/@{-1}`: every git name operand now goes
  through one helper, so a name git resolves (`@{-1}`, `-`, `HEAD`) is `kind/*`, marked, on
  branch create, reset, rename, copy and upstream, tag and push; `rebase`, `reset --hard`
  and `commit --amend` also reach the current branch (`history/*`, marked).
  `gcloud storage rm gs://prod/secret#123456789` (and gsutil, and a copy's source) kept
  `#123456789` in the key: it is the object's generation, now a `generation` param, with
  the key `secret`. `gcloud compute instances delete web --project acme-prod` left the zone
  unmarked: gcloud zone and account, aws account, the kubeconfig user (now recorded from
  `--user`) and gh's host joined the table of scopes taken from the configuration, so every
  one of them is unresolved when absent. `docs/dev/parser-audit.md` lists every class of
  finding from the review rounds against every tool, and `tests/test_parser_audit.py` checks
  each cell that applies. From source; not run.
- `argocd app sync a --resource x --resource y` kept only `y`, and helm `--history-max 0x0`
  was recorded as text. Every flag of kubectl, helm, flux, argocd and gh is now read by the
  pflag type its registration gives it (`src/aegis_core/data/pflag_types.json`, written by
  `scripts/gen_pflag_types.py` from each tool's source, with the type each command gives a
  flag whose type differs between commands): a StringArray accumulates every value, a
  StringSlice every value split as CSV, an Int is read with base 0, a Duration with
  time.ParseDuration and recorded in seconds (`--timeout 5m` and `300s` are both 300), a
  Float with ParseFloat, a StringToString as a map, a Count counts; what pflag refuses is
  refused. The store meets a rule against each value of a repeated flag, and reads a rule's
  value for a typed flag with the same normalizer the parser used (`normalize_typed`,
  matched through `canonical_key`): a rule `timeout: "5m"` (or `"300s"`, `"5m0s"`, `300`)
  blocks `--timeout 300s`, `history-max: "0x0"` meets 0, `install: "0"` meets
  `--install=false`, and `labels: "a=1,b=2"` meets the same map. A rule value the flag's
  type cannot hold (`timeout: "soon"`) is neither a match nor a miss: the rule escalates, as
  for any value the store cannot decide (scope values are not typed when a rule is loaded,
  so it is not rejected then). Booleans now read Go's spellings (`1`, `t`, `0`, `f`) on both
  sides. From source.
- `git -c remote.origin.push=+refs/heads/safe:refs/heads/prod push origin safe` was a push to
  `ref/safe`: git maps a refspec with no destination through `remote.<name>.push` (with its
  `+`) or push.default's upstream, from any config file (push.c refspec_append_mapped). A
  source-only refspec's destination is now unknown (the source stays `ref/<source>`), and a
  `-c remote.<name>.push` on the line is applied as git applies it, force included. This
  means a rule on any other ref now escalates for `git push origin <branch>`: only
  `src:dst` names the destination. From source.
- az refused `--tags owner=ops env=prod`, `--set a=1 b=2` and `--zones 1 2 3`. Each az option's
  `nargs` (`+`, `*`, `?`) or `action='append'` is now read from `_params.py`, the argument
  types (`tags_type`, `zones_type`) and AAZ list and dict arguments, with the generic update's
  `--set/--add/--remove`, and the option takes every word up to the next option, as argparse
  does; the everyday az sample gained six multi-value commands, all parsed. aws list
  parameters already took every word. gcloud ArgList and ArgDict values (`--tags a,b`,
  `--labels k=v,k2=v2`, and the `^X^` delimiter) are now a list or a map, so a rule on
  `labels.env` meets them. From source and the gcloud reference.
- Values were typed by how they look: `aws s3api delete-object --key 001` was the key `1`
  and the target `s3/object/production/1`, and gcloud `--description 001` the number 1. A
  value is now typed only by the type the tool declares for it, and otherwise kept exactly as
  written: aws by its botocore shape (integer and long with int(), float and double with
  float(), list members by their type; the option table now records each shape), az by a
  declared `type=int`/`float`, gcloud as text (its reference pages declare no number types)
  with ArgList and ArgDict split, the pflag tools by their registered types, git as text,
  helm and argocd rollback revisions as Go's Atoi. helm `--set` (strvals typedVal) and gh
  `-F` keep their own typing, which the tools declare. Every site is listed in
  `docs/dev/parser-audit.md` (C27). A target built from a value uses its exact text.
- helm 4's `--wait` is a custom pflag value: bare `--wait` is `watcher`, `--wait=false` is
  `hookOnly` (flags.go waitValue.Set), and it was read as a boolean. It is now read as helm
  4 reads it, and because helm 3 reads it as a boolean and which helm runs is not on the
  line, `wait` is also unresolved, so a rule on it escalates. The pflag generator now lists
  every custom value of kubectl, helm, flux, argocd and gh, resolves each by what its Set()
  does, and fails on one it does not know. Slice and map types register their element type
  (an argocd `--source-positions` Int64Slice), and the store normalizes each element of a
  rule's value; a test checks every type in the table has a normalization. gcloud's
  `^DELIM^` escaping takes a delimiter of any length (`^--^env=prod--team=x`). From source.
- `kubectl create secret generic settings` was two targets, `secret/generic` and
  `secret/settings`: the subcommand word of `create secret|service <type>` is no longer a
  name. With `--append-hash` kubectl names the object `settings-<hash of its data>`, from
  files it reads when it runs: the target is now `secret/settings-*`, marked with that
  prefix (configmaps too). aws `--generate-cli-skeleton` calls nothing and is a rehearsal.
- aws `--instance-ids '["i-1"]'` was refused, and `--tags Key=a,Value=b` kept as text.
  Structure, map and list values are now decoded as aws-cli's argprocess does: JSON when the
  value (or a list's one value) starts with `[` or `{`, aws-cli's shorthand syntax
  otherwise (its parser, vendored from aws-cli 2.37.4 as `aegis_core/aws_shorthand.py`,
  Apache-2.0), typed by the botocore shapes, which the option table now records; a member a
  shape does not have, or a value aws cannot decode, is refused. Targets come from the
  decoded values. Run with aws 2.37.
- az `--tags env=prod` stayed a list, though az's `tags_type` validator makes it a map.
  Each az argument's converter is now read from `_params.py` and applied: `tags_type` (a
  map, a bare key an empty value), `get_three_state_flag` (a boolean), `get_enum_type` (a
  declared choice, matched without case; another value refused). A value whose argument
  has another validator, not ported, is unresolved. From azure-cli source.
- gcloud `--num-nodes 03` stayed `"03"`, the reference pages carrying no types. Each value
  flag's type is now read from the SDK source mirror
  (github.com/google-cloud-sdk-unofficial/google-cloud-sdk, its commit recorded in
  `gcloud_flags.json`): int and BoundedInt, float, ArgBoolean, BinarySize (in bytes:
  `10GB`, `10240MB` and a bare `10` are equal), Duration (in seconds, gcloud's ISO
  parser) and ArgList element types, ported from calliope's arg_parsers; the store reads a
  rule's value the same way. A type that cannot be read statically leaves the value
  unresolved. From the SDK source; gcloud was not run.
- Tests that used `flux reconcile ... --dry-run`, `flux get ... --export` and `git push
  --dry-run=false`, which the tools refuse, now use commands the tools accept (`flux create ...
  --export`, `git push --dry-run --no-dry-run`).
- `kubectl logs web secret -c public` reads container `secret`: kubectl takes a second word
  as the container over `-c` (logs.go Complete). It was read as `public`. A third word is
  refused, as kubectl refuses it. From kubectl 1.36 source.
- `gh api --hostname staging.example https://api.github.com/repos/acme/prod/...` acts on
  github.com's `acme/prod`: an absolute URL names the host and the repository whatever
  `--hostname` says. `gh api` has no `-R`/`--repo` and gh refuses it; the parser read it as
  the repository over the path's, and now refuses it too. Another host is a GitHub Enterprise Server, so
  `https://ghe.corp/api/v3/repos/acme/prod/...` is `ghe.corp/acme/prod` and no longer meets a
  rule on github.com's `acme/prod`.
- kubectl `--server`/`-s`, helm `--kube-apiserver` and flux `--server` send the request to
  that URL, whatever cluster the context or `--cluster` names. The URL is recorded as `server`
  and the cluster is unresolved; `resolve_current_context` no longer fills it from the
  kubeconfig then. aws `--endpoint-url` (and `$AWS_ENDPOINT_URL`, `$AWS_ENDPOINT_URL_<SVC>`
  when filling from the environment) leaves account and region unresolved, since the endpoint
  need not be the region's.
- az `--tags @tags.txt` was converted as the literal tag `@tags.txt` before the `@file` check,
  and a rule on `tags.env` did not escalate. A value az reads from a file or stdin is now
  found first, the key and every key nested in it (`tags.*`) are unresolved, and only literal
  values are converted. az also loads an `@file` after the first `=` of a value
  (`--tags env=@.git`), and every spelling (`--tags=@f`) goes through the same check. aws reads `file://` before JSON or shorthand on a list option too
  (`--tags file://t.json` was refused as bad shorthand), marking the key and its nested keys,
  and kubectl `create configmap|secret --from-file`/`--from-env-file` leave `data` and
  `data.*` unresolved.
- `kubectl delete pod harmless -n dev --raw=/api/v1/namespaces/prod/pods/protected` deletes
  `prod`'s `protected`: kubectl sends one DELETE to the raw path and ignores the other words,
  `-n` and `--dry-run`. It was read as a delete of `harmless` in `dev`. kubectl `get`,
  `create`, `replace` and `delete --raw` (the verbs that have it; apply has none and is
  refused) now read the target, namespace and collection from the path; a subresource, a
  non-resource path, a query or an escaped, empty or dot segment is refused, and create and
  replace need exactly one `-f`. `kubectl get --raw` of a kind's path is now read as a read
  of that kind instead of refused. From kubectl 1.36 source. `az rest` stays refused.
- `aws s3 cp --metadata classification=secret` stayed text, so a rule on
  `metadata.classification` did not meet it. The options of the high-level `aws s3` commands
  now come from aws-cli 2.37.4's own s3 argument tables (generated, not written by hand) and
  are read as aws-cli reads them: `--metadata` a map from shorthand or JSON, `--page-size` and
  `--progress-frequency` integers, choices checked exactly (`--sse AES` is refused), a bare
  `--sse` or `--request-payer` its default, `--include`/`--exclude` an ordered `filters` list
  (before, only the last was kept), `mb --tags` a map, and a store-true option given a value
  refused.
  `--expires` and the `--content-*` and `--sse-*` values are plain strings in aws-cli and stay
  text. Checked against aws 2.37.4.
- `gcloud compute instances create --metadata-from-file enable-oslogin=oslogin.txt` sets
  `metadata.enable-oslogin` to the file's contents, which are not read; a rule on it did not
  escalate. Every gcloud flag named `*-from-file` or `*-file`, or typed as file contents in the
  SDK source, now leaves the setting it fills unresolved (`metadata.<key>` for each key given,
  `labels.*` for `--labels-file`, the env vars for `--env-vars-file`). The gcloud table's types
  were refreshed from the same SDK commit with `--types-only`, which keeps the flag lists.
- `kubectl delete --raw /api/v1/namespaces/prod` did not get the namespace cascade that
  `kubectl delete namespace prod` gets, so a `*/*` rule on namespace `prod` allowed it. A raw
  path's target now goes through the same expansions as a target named by words, and the flags
  kubectl does not send with `--raw` (`--cascade`, `--grace-period`, `--force`, `--all`, `-l`,
  `--dry-run`) are dropped; `--raw` on a category such as `all` is refused.
- `gh api 'repos/acme/prod#ignored' -X DELETE` kept `#ignored` in the target. URL and path
  targets are now read as the tool's HTTP client sends them: gh drops the fragment, keeps the
  query apart, and the server decodes the path (`pr%6Fd` is `prod`); a trailing slash is
  dropped; `//`, `.` or `..` segments, an escaped slash and a scheme other than http(s) are
  refused. gh repository, pull request and issue URLs, gcloud resource URIs and az `--ids`
  are read the same way (az refuses `#`, `?` and `%` in an ID, which the request URL would
  read).
- `gcloud run deploy --container app --image forbidden --container sidecar --image safe` was
  read as image `safe` only. Flags after each `--container` now belong to that container
  (`containers.<name>.image`), the plain key holds every container's value, so a rule on
  `image` meets any container, and gcloud's misplacements (a container flag before the first
  `--container`, another flag inside one) are refused. A rule on a key of a repeated group
  now meets each group (`create-disk.image`, `network-interface.network`).
- `helm upgrade -f values.yaml --set 'hosts[0]=safe'` keeps the file's other hosts (helm sets
  one list index into the file's list), but `set.hosts` was read as `[safe]` and known. With
  values files, reused values or a rollback, every list a `--set` writes an index into and
  every map it writes a nested key into is now unresolved as a whole; a value set whole (a
  scalar, a `{a,b}` list) stays known.
- `git push -o a -o b` kept only `b`. git options given several times now keep every value:
  push `-o`/`--push-option` and `--force-with-lease`, commit and tag `-m` and `--trailer`,
  branch and tag filters and `--sort`, rebase `-x` and `-X`.
- `gsutil mv gs://prod/oldprefix gs://archive/newprefix` moves everything under the prefix
  (a move is recursive without `-r`, in gsutil and in gcloud storage), but only the key
  `oldprefix` was read. A recursive or wildcard key is now a prefix: a rule on a key that may
  start with it escalates, and a rule on an unrelated key no longer does (gsutil, gcloud
  storage, aws s3 `--recursive` and sync, before every key escalated). The destination of a
  recursive move or copy is a prefix too.
- `gh pr create -t Fix -b Desc` and `gh pr edit 42 -t Fix` were refused: gh's short letters
  came from a hand table of a few commands. Every gh command's flags and letters now come
  from cli/cli's own registrations (`gh_flags.json`, generated), `-R` only where gh registers
  it. helm's per-command letters come from its registrations too (`helm pull -d` is
  `--destination`), and `helm repo add|update|remove|list` and `helm pull` are read (the
  local repository list and a chart download). Everyday gh, helm, flux, argocd and kubectl
  commands written with short flags parse, and flux and argocd letters are checked against
  the generated registrations.
- kubectl's short letters and its boolean and value flags now come from `kubectl <command>
  --help` of every command (`kubectl_flags.json`, generated), each command with its own
  letters: a letter the command does not have is refused, as kubectl refuses it (`kubectl
  exec -A`, `kubectl create deployment -q` were read before), and a short word from `-test.`
  is ignored, as pflag ignores it (it was read as `-t -e st...`).
- `kubectl expose deployment harmless --name=protected` creates the Service `protected`, but
  only `deployment/harmless` was read. expose now also yields a Service create intent and
  autoscale a HorizontalPodAutoscaler one (named by `--name` or after the source, in its
  namespace; `--overrides` leaves every key unresolved), create token a ServiceAccount one,
  and `gh pr merge --delete-branch` a delete of the head branch, marked, since the argv does
  not name it.
- `gh pr merge --merge --squash --squash=false` was read as a squash. gh's method now comes
  from each flag's final value, and flags gh allows only one of (`--merge`/`--rebase`/
  `--squash`, `--auto`/`--disable-auto`/`--admin`, repo create's visibility) are refused
  together. helm `--atomic` and `--rollback-on-failure` leave `wait` unresolved, since they
  turn waiting on.
- `gcloud run deploy --args forbidden --args safe` kept only `safe`. Each gcloud flag's
  argparse action is now read from the SDK and applied: UpdateAction keeps every value (and
  refuses a repeated one), `append` keeps each, StoreOnceAction refuses a repeat, and a plain
  store keeps the last (a repeated map flag was a list before).
- `gcloud ... --accelerator type=nvidia-tesla-t4,count=01` kept `count` as `01`. ArgDict members
  are now typed by the SDK's spec, on the rule side too, and a member the spec does not
  declare, or a missing required one, is refused. Where the spec is not read statically
  (`container clusters create --addons`, `update --update-addons`), the flag and every member
  are unresolved.
- A prefix mark (`inputs.*`, `tags.*`, `data.*`) spared every key the command recorded under
  it, an exception meant only for helm's `set.*`. `gh api -X PATCH repos/acme/prod --input
  body.json -F delete_branch_on_merge=false` was read as setting it to `false`, but gh sends the
  file as the body and moves the fields into the URL query, so the file's value applies. A
  prefix mark now covers recorded keys too, except helm's `set.*` for keys `--set` replaced
  outright, and gh api's fields with `--input` are recorded as `api_query`.
- `kubectl expose --overrides='{"metadata":{"name":"protected"}}'` can rename the new Service:
  with `--overrides` the Service is now `service/*`, marked. expose's default name is the
  source's cut to 63 characters, as kubectl cuts it.
- gcloud storage `--update-labels env=prod` was read as a list, because the reference page and
  the SDK disagreed on its shape. The SDK's map or list type now wins, a shape still in doubt
  is unresolved (compute firewall-rules `--rules`), and the generator fails on a disagreement
  left without a resolution (32 flags disagreed; 30 follow the SDK now).
- `helm upgrade --reset-values --set config.public=safe --set-file config.secret=/dev/null`
  recorded `set.config` as `{public: safe}`, and a rule comparing `set.config` whole was
  decided on it. A key with any unresolved key under it is now unresolved when a rule compares
  it, or any key above it, whole, for every tool.
- `aws iam delete-role --role-name protected` did not meet a rule on `role-name`: the flag
  named the target and was not kept. A flag that names the target is now in params too (aws
  target and id flags, az `--name` and the name of an `--ids` path), and a rule written with
  `location`, `kube-context` or `kube-apiserver` meets the scope key those are recorded under
  (`region`, `context`, `server`). docs/constraints.md describes the one mechanism.
- `git push --exec=X --receive-pack=Y` kept both: they are one option. Several names of one
  option are now one key, the values in order, every name holding it: git (`--exec`, `--with`,
  `--without`), az (each options_list's long names, generated; a one-string options_list was
  read as none before, which gave 197 commands wrong long options), aws (argrename's hidden
  aliases), helm 4 (`--force`, `--atomic`, `--colour`) and gh (`--confirm`), generated from the
  registrations.
- `helm uninstall web -n prod --kube-as-user admin` impersonates `admin`, but the flag was
  dropped. No flag is dropped now: each is recorded, or is one of a tool's documented no-effect
  flags (output format, verbosity, colour, rate limits, help). helm, flux and kubectl
  impersonation is one structure with one `impersonate` intent per identity; auth, TLS,
  endpoint and kubeconfig flags of kubectl, helm, flux, argocd and aws are recorded (a token's
  value as `[secret]`); gsutil's `-h` headers (`x-goog-meta-*` as `metadata.*`), `-u` and `-i`
  are recorded and `-o` leaves every key unresolved; gcloud `--impersonate-service-account`
  and gsutil `-i` are an impersonate intent on the service account. A test checks every flag
  of every generated table, on every command of the gh, az, aws and gcloud tables (over 230,000
  flag uses); it found az options that are another command's `-n`, `-g` or `-l` (`--service-name`)
  read as the name but not kept under their own names, and aws s3control `--bucket`, hidden
  aliases and autoscaling `--auto-scaling-group-name` not kept; all are now.
- aws `modify-instance-attribute --instance-id i-1` was recorded under `instance-ids`; each flag
  now keeps its own name.
- aws `modify-instance-attribute --disable-api-termination` was refused: aws-cli turns that
  `{"Value": bool}` structure into `--x`/`--no-x` switches. They are now generated from aws-cli
  and read as aws reads them. Everyday aws commands parse.
- az `--ids` with no ID after it and flux `--dry-run` (which flux refuses) were accepted; both
  are refused now, as the tools refuse them.
- `argocd app create dev/protected -N prod` creates the app in `prod`: create sets `-N` over the
  qualified name, the other way round from every other verb. And `argocd app create decoy
  ignored --name protected` creates `protected`: one word is the name, with none or several
  `--name` is. Both are now read per verb from argocd's source, and verbs that take exactly
  one app refuse more. helm's argument counts now come from each command's cobra validator
  (generated), so `helm upgrade a ./c extra` and `helm status a b` are refused, and `helm pull`
  takes several charts.
- `git rebase --update-refs main feature` also rewrites other branches, and rebase.updateRefs
  in a config file can turn it on: every rebase now also rewrites `history/*`, marked, unless
  `--no-update-refs`. A pull may be a rebase (pull.rebase), and a push may push submodules
  (push.recurseSubmodules): both are now marked unless the command line says otherwise.
- gh commands that change more than they name: `pr close -d` deletes the head branch,
  `issue transfer` creates the issue in the target repository (the second argument gh reads,
  whatever flags come before it), `release delete --cleanup-tag`
  deletes the tag, `label clone` writes the destination's labels, `repo rename` takes the new
  name, and `cache delete` names the cache or every cache.
- `az group update --tags env=safe --set tags.env=prod` ends with `env=prod`: az's generic
  update applies `--set`, `--add` and `--remove` after the typed arguments, in order, as
  argparse resolved them (an abbreviation such as `--se` included). A tags path writes the tags
  map; any other path leaves that property unresolved. gcloud's `--update-labels`,
  `--remove-labels` and `--clear-labels` are combined as gcloud combines them.
- `kubectl apply -f desired.yaml --prune -l app=web -n prod` also deletes the objects it applied
  before that the selector matches and the manifest no longer has: a delete rule on one of them
  was allowed. A prune is now a delete of each kind it may prune (`--prune-allowlist`, or
  kubectl's default kinds), marked, with the namespace unresolved; `--prune --applyset`, whose
  members only the cluster knows, and `--prune` without `-l` or `--all`, which kubectl refuses,
  are refused.

### Added
- A `NOTICE` file at the repository root lists the third-party code and data in the package
  and the logic ported from other projects, with their copyright notices and the license
  texts that require it: aws-cli's shorthand parser (which keeps aws-cli's copyright header,
  followed by a note of what was changed), the botocore, azure-cli, Google Cloud SDK and pflag
  registration data, and logic ported from permissively licensed code (Helm strvals, Go
  strconv and time, pflag, gcloud calliope, azure-cli, GitHub CLI). Behaviour taken from
  documentation or from running a tool (kubectl, aws-cli, knack, git) is listed separately:
  no git code is included or translated. It ships in the sdist and wheel (`license-files`).
  The generated `pflag_types.json` records its sources as upstream repository and tag or
  commit, and its generator refuses to write a local path.

## [1.3.4] — 2026-11-07

kubectl, helm and flux flag spellings are read as the tools read them: a repeated `--dry-run`,
bundled short flags and repeated `-f`.

### Known limits
- A long flag that takes a value is still read as a flag of its own when helm or flux has no entry
  for it in the parser, so `helm upgrade api ./c -n prod --description -ndev` is read as namespace
  `dev`, and helm runs it in `prod` with the description `-ndev`. `flux create source git a -n prod
  --url -ndev` is read as `dev` the same way (flux behaviour from source, not run). Every earlier
  release reads these the same way (#80).

### Fixed
- Two kubectl flag spellings were read differently from kubectl, on every verb, so a BLOCK could
  pass (#75). Checked on kubectl 1.36 against a local stub API server.
  - A repeated `--dry-run`: the first rehearsal stuck, so `kubectl delete pod x --dry-run=client
    --dry-run=none` was allowed as a rehearsal, and it is a real delete. The last one now decides,
    both ways. `--no-dry-run` after `--dry-run` was missed on aws and git, and now clears it, which
    was checked on both CLIs. helm `install`, `upgrade` and `rollback` and `argocd app sync` get the
    same reading, and `flux create --export --export=false` no longer counts as a rehearsal. Those
    three come from reading each tool's source, and none of them was run. gcloud now reads
    `--no-dry-run` as a real run, though no gcloud command the parser takes was found with the flag.
  - A bundled short flag: the whole word was ignored, so `kubectl run web --image=x -n dev -qnprod`
    was read as `dev`, and it runs in `prod`. Short words are now read letter by letter as pflag
    reads them, from one table of which letters take a value. `-Rf dir` is now the manifest
    `dir` (it was a kind called `dir`), `-Ao yaml` is every namespace (it was a pod called `yaml`),
    and `logs -fc app web` is `pod/web` (it was `pod/c`). `-r` is `--replicas` on `create
    deployment`, so `-r 3` no longer adds a target called `deployment/3`.

  Also read as kubectl reads them now: `--context -nprod` is a context called `-nprod`, since a flag
  that takes a value takes the next word whatever it looks like, `-n=` is the namespace `=`, and
  `--all-namespaces=false` turns off an earlier `-A`, which used to stick and make a namespace rule
  escalate.

  A word with an unknown letter in front of a value letter or `A` is now refused, because the
  letter's meaning in a later kubectl cannot be known. kubectl 1.36 refuses the ones tried:
  `get pods -xnprod`, `get pods -rf` and `delete pod x -rf`.

  `kubectl logs -fl app=x` is now refused too, where it was read as `pod/l`. kubectl accepts it, and
  it accepts `kubectl logs -l app=x`, which the parser already refused. Both stay refused until the
  parser can read `logs` by selector.
- helm and flux short flags are read as pflag reads them, with the same rules as kubectl (#75). Which
  letters they have comes from reading their source (helm 4.3.1 and 3.22.1, flux2 `main`), and neither
  tool was run. `helm upgrade -i api ./c` was `release/./c`, with `api` taken as the value of `-i`:
  it is now `release/api` with `install` set. `helm upgrade api ./c -n dev -inprod` was read as `dev`,
  and pflag reads it as `prod`. So does `flux get ks -n dev -wnprod`. `-fv.yaml` and `-oyaml` now
  carry their values, and `flux get ks -A a` is `kustomization/a`. A flag's value is never split, so
  `--kube-context -nprod` is a context called `-nprod`.

  A word with an unknown letter in front of a value letter or `A` is refused here too, and that
  includes `flux reconcile ks a -qnprod`, since flux has no `-q`. `helm install -g ./c` stays refused
  as it was, though helm accepts it, because there is no release name to read.
- Every file in a kubectl `--filename` now meets the rules (#75). `kubectl delete -f x.yaml -f y.yaml`
  was only `manifest/y.yaml`, so a rule on `manifest/x.yaml` missed, and kubectl deletes both. Each
  file is now one intent with its own `file` param, also for `--filename=x --filename=y`, `-f x,y` and
  `-f - -f y`. These were run on kubectl 1.36 against the stub server, which saw both deletes. One file
  gives the same intent as before. Repeated `-k` needed no fix: kubectl uses the last one, and so did
  the parser.

  This takes `kubectl delete -f x.yaml -f y.yaml` from one intent to two, which can change a plan rule.
  A count such as `max_intents` can rise, and a `ratio` can drop: the command under a ratio of
  `manifest/y.yaml` over all intents with `max: 0.75` went from BLOCK to ALLOW, because 1/1 became
  1/2. `from_kubectl` now raises `ValueError` on two files. Use `from_kubectl_multi`.

  An empty value adds no file, as pflag reads it, so `kubectl delete --filename= -f x.yaml` is only
  `manifest/x.yaml`, and `--filename=` alone is refused, as kubectl refuses it.

## [1.3.3] — 2026-11-07

`kubectl run --expose` now meets the rules on the Service it creates.

### Fixed
- `kubectl run web --image=x --expose --port=80` creates a pod and a Service, but the hook saw only
  the pod, so a `run` rule on `service/web` or `service/*` allowed a command that a compiled policy
  denies at the Service (#73). `--expose` now adds `service/web`, beside `pod/web` and `web/*`, with
  the same namespace and params, so `--dry-run` and `-n` work as they do on the pod. `--expose=false`
  adds nothing, and neither do `0`, `f`, `F`, `FALSE` or `False`, the other spellings kubectl reads
  as false. Any other value adds the Service, though kubectl refuses every value it cannot read as
  a boolean. In `--expose false` the flag is on and `false` is a word, as in kubectl. A word with a
  slash adds no Service, because kubectl stops when the API refuses the pod. `--rm` needs nothing of
  its own: it deletes what was created, and a `run` rule decides on the same intents. A per-intent
  rule on `pod/web` or `web/*` keeps matching.

  Compile output is unchanged. `client_parity` already left `run` out for a `run` rule on services,
  as a rule's own verb, and this makes that correct for `--expose`. Two flag spellings can still get
  past a rule on any verb: a repeated `--dry-run` and a bundled `-n` (#75).

  This takes `kubectl run --expose` from two intents to three, which can change a plan rule. A count
  such as `max_intents` can rise, and a `ratio` can drop: the command under a ratio of `web/*` over
  all intents with `max: 0.4` went from BLOCK to ALLOW, because 1/2 became 1/3. `from_kubectl` still
  raises `ValueError` on `kubectl run`. Use `from_kubectl_multi`.

## [1.3.2] — 2026-11-07

Six kubectl commands now meet the rules on what they reach.

### Fixed
- Five kubectl commands now meet the rules on what they reach (#68).
  - `kubectl logs deploy/web` reads a pod behind the name, as `kubectl exec deploy/web` does, so it
    is also `pod/*`: a `pod/*` rule matches and a rule on one pod asks (`target-unresolved: <id>`).
  - `kubectl debug web --image=busybox` was `web/*`, reading the name as a kind. It is now
    `pod/web`, and `--copy-to=c` adds `pod/c`, spelled as written (`--copy-to=001` is `pod/001`).
    `web/*` stays beside them, so a per-intent rule on the old spelling keeps matching.
  - `kubectl cp web:/a b` kept the pod inside the path and `kubectl cp b web:/a` lost it, so neither
    met a pod rule. Both are now `pod/web`. `ns/pod:path` sets the namespace, over `-n`, as in
    kubectl, and a word counts as remote by kubectl's own rule. The first word as written stays
    beside the pod, so a per-intent rule on the old spelling, such as `web:*`, keeps matching.
  - `kubectl describe pod pay` falls back to every pod whose name starts with `pay`, so a `describe`
    rule on `pod/payments-0` now asks. A rule that cannot match such a name, like `pod/api-0`, does
    not, and `kubectl describe pod/pay` stays exact.
  - `kubectl delete widgets --all` passed a rule on `widget/*`, because `widget` is not a built-in
    kind and a plural or short name cannot be resolved from the command. A kind outside the built-in
    table now asks under a rule on a custom kind, on the verbs that take one. Naming an object keeps
    it narrow: `kubectl delete widgets foo` asks under `widget/foo` and not under `widget/bar`.

  - Words after `--` were stored as a command on every verb, though only `exec`, `run`, `create`
    and `debug` use them that way. On the other verbs they are operands now: `kubectl describe pod
    api -- payments-0` meets a rule on `pod/payments-0`, `kubectl describe pod pay -- other` is
    exact, and `kubectl delete pod -- x` is `pod/x` where it was `pod/*`. A kind list or category
    with a word after `--`, such as `kubectl delete pods,svc -- x`, is refused, as kubectl refuses
    it. With nothing before the `--` the command stays refused.

  `kubectl debug all --image=x` is `pod/all` beside `all/*`, so it meets a `pod/*` `debug` rule.
  `cp` and `debug` now give one intent more, as `kubectl exec deploy/web` has since #64, and this can
  change a plan rule. A count such as `max_intents` can rise, and a `ratio` can drop:
  `kubectl cp web:/a b` under a ratio of `web:*` over all intents with `max: 0.75` went from BLOCK to
  ALLOW, because 1/1 became 1/2. So the old spelling keeps matching for rules on a resource, and not
  for ratios. Aside from plan rules, commands with no rule about their action and kind decide as
  before.

  `from_kubectl` now raises `ValueError` on `kubectl cp` with a pod and on `kubectl debug <name>`, as
  it does for `kubectl exec deploy/web`, because they give more than one intent. Use
  `from_kubectl_multi`.
- `kubectl run web --image=x` created a pod called `web` but was read as `web/*`, the word taken as a
  kind, so it passed a `run` rule on `pod/*` or `pod/web` (#71). It is now `pod/web`, and
  `kubectl run all --image=x` is `pod/all`, with no kind from the `all` category. The name stays as
  written (`kubectl run 001` is `pod/001`), and `--` operands, `params["command"]` and `--dry-run`
  are as they were. `web/*` stays beside the pod, so a per-intent rule on the old spelling keeps
  matching. A word with a slash, such as `kubectl run deploy/web`, is refused by the API as a pod
  name and stays `deployment/web`.

  This takes `kubectl run` from one intent to two, which can change a plan rule. A count such as
  `max_intents` can rise, and a `ratio` can drop: `kubectl run web` under a ratio of `web/*` over all
  intents with `max: 0.75` went from BLOCK to ALLOW, because 1/1 became 1/2. `from_kubectl` now
  raises `ValueError` on `kubectl run`, as it does for `kubectl debug <name>`. Use
  `from_kubectl_multi`.

## [1.3.1] — 2026-11-06

Three fixes found while preparing the formal model for a conference submission, and two kubectl
hook fixes: one found while building the third (#64), one found while fixing that (#66).

### Fixed
- A constraint changed and rehashed after its source check no longer votes. The provenance hash is
  unkeyed and does not cover the id, so a library caller holding a loaded store could edit a live
  constraint, recompute its hash, rename it, and still pass the integrity check. The store now
  records the hash each source check verified under the store key. A decision discards a
  constraint whose hash differs from that record, that is not the object held under its own id,
  or that was written straight into the store beside verified constraints, with the reason
  `forged` (ESCALATE under `on_untrusted_match: escalate`, never BLOCK). A verified snapshot
  excludes it too. `verify_sources` records the hash again when the source now backs the change
  and quarantines a constraint whose id is not its key. `add_constraint` with different content
  drops that id's source evidence. No removal switches this off for the rest of the store.
  Stores never loaded with a source fetcher or audited behave as before.
- A rejected entry can no longer displace a trusted constraint with the same id, in constraints
  and plan-constraints files. The first entry used to win, so an unauthorized or forged entry
  written ahead of a trusted BLOCK turned it into ALLOW. Each entry is now judged on its own, in
  any order, and keeps its own quarantine reason. Identical survivors keep one (`invalid:
  duplicate id` for the rest), and an unauthorized one beside a differing entry is quarantined as
  `unauthorized`. **Authorized entries that differ now fail the load**, where the first one used
  to win: the check exits with a data error and the hook denies infrastructure commands. A
  file with such duplicates must keep one of them.
- A kubectl rule's own verb aimed at another name no longer gets past the hook (#64). `kubectl exec
  deploy/web`, `attach` and `port-forward` on any kind but a pod run on a pod kubectl finds behind
  the name, so they now match `pod/*` rules as well as rules on the name written. `kubectl delete
  all --all`, and every other verb given the category `all` or `api-extensions`, now counts as each
  kind in the category, so it matches rules like `deployment/*`. What cannot be known before kubectl
  runs asks instead, with the note `target-unresolved: <id>`: a rule on one pod for `exec
  deploy/web`, and a rule on one object or on a custom kind for `delete all --all`. Commands with no
  rule on that action are not affected, and neither are other kinds: `delete all --all` still passes
  a `secret/*` rule, as kubectl does not delete secrets for it. `all/web` and `all web` are refused,
  as kubectl refuses them. Also read correctly now: `attach deploy web` and `attach pod web` (two
  words are a type and a name), `label` and `annotate` removals such as `app-` and the operands of
  `taint`, which used to count as object names, and the plural and short names of every built-in
  kind (`rc`, `cj`, `endpointslices`, `podtemplates`, `ip`, `vac`, ...).
- A rule whose time window cannot be evaluated because timezone data is missing now asks in two
  more cases, where it used to be dismissed: on a manifest (`kubectl delete -f`), and when the
  rule's scope is unresolved too. A quarantined rule under `on_untrusted_match: escalate` now asks
  whenever a live one would, also when its scope, time window, target or manifest cannot be
  resolved.

- A kubectl command that picks objects with `--all` or a selector no longer gets past a rule on one
  object (#66). `kubectl delete deployments --all` and `kubectl delete deploy -l a=b` passed a
  `deployment/payments` delete rule, though both can delete `payments`, and `kubectl taint nodes
  --all a-` passed a `node/n1` taint rule. Such a rule now asks, with the note `target-unresolved:
  <id>`, because the hook cannot tell whether that object is picked. The same holds for a kind with
  no name on the verbs that then act on every object: `kubectl get pods` asks under a `get` rule
  on one pod, and `kubectl rollout restart deploy` under a rule on one deployment. Rules on the
  whole kind decide as before, and a command with no rule on that kind and action is not affected.
  `kubectl taint node n1 --all` also counts as every node, since kubectl ignores the name there.

### Added
- `aegis compile kubernetes`: every rule in `coverage.json` has a `client_parity` record, and
  `coverage.md` shows it. A policy decides on the request, not the kubectl verb, so a `set-image`
  rule reported `exact` also denies `patch`, `edit`, `replace`, `apply` and `rollout undo` when they
  change the image, while the client hook lets those verbs through. Coverage values and existing
  keys are unchanged.

## [1.3.0] — 2026-10-29

The agent hook checks a compound command part by part (#55) and reads scripts and code piped
into a shell (#56); kubectl boolean flags and help/version probes are no longer refused (#53,
#54).

### Added
- Guide (experimental): [check the SQL an LLM writes before your app runs it](docs/guides/app-sql.md),
  with `examples/app_sql_gate.py` and a signed-rule template in `examples/app-sql/`. Aegis
  enforces "reads only" on generated SQL; the guide is explicit that a read's tables, columns and
  cost are the database role's job (the SQL classifier sees only a SELECT's first table, and
  treats `SELECT … INTO` and `SET ROLE` as reads). Every Aegis result in its table is a test.
- Agent hook: a time budget for each decision (`DECISION_BUDGET_SECONDS`, 10 s). The decision
  runs in a worker thread; when it takes longer, the hook answers on its own (asks, or denies
  when the command names an infrastructure tool, in each agent's usual format) instead of
  running into the agent's 30 s hook timeout, past which the agent would run the command. The
  abandoned worker's result is never used, and the reply is written to the streams the hook
  started with. A safety net: the checks are meant to be linear.

### Fixed
- Agent hook: a shell expansion in one part of a compound command no longer refuses the whole
  command (#55). The hook judges a command it cannot parse part by part (`;`, `&&`, `||`, `|`,
  newline): `terraform plan 2>&1; echo "exit=$?"` checks `terraform plan` against the policy
  and lets the `echo` through. A part with an unknown argument stands in for its program only
  when that program treats arguments as data (`echo`, `cat`, `tail`, `grep`, `ls`, `test`, …;
  not `sort`, `cp`, `mv`, `ln`, `tee`, `read` or `printf -v`) and does not redirect output to a
  computed path or a configuration directory (`~/.kube`, `~/.aws`, …); a part that only assigns
  a variable drops out, unless the variable steers an infrastructure tool (`KUBECONFIG`,
  `AWS_*`, `PATH`, …, also after `export`/`declare`/`local`). Any other unknown part (one that
  runs `$(…)`, backticks or `<(…)`, also inside double quotes, an unknown program, `find
  -exec`, `watch`, `ssh`, `trap`, `eval`, …) is refused when the command names an
  infrastructure tool anywhere; the message quotes the part. This refuses `TS=$(date +%s);
  kubectl …` on purpose: any command substitution next to an infrastructure command is.
  Here-docs are judged as a whole, as before.
- Shell parser: the reserved words `if`, `then`, `else`, `elif`, `do`, `while` and `until`, and
  `coproc`, in front of a command are stripped like `{` and `!`, so `if true; then kubectl
  delete namespace prod; fi` and `coproc kubectl …` are checked as the `kubectl` command they
  run (they were unknown binaries, and allowed). A lone `fi`/`done`/`esac` and a `for`/`select`
  header give no command; `function f { …; }` is rejected like `f() { …; }`. A backslash-newline
  outside single quotes and comments is removed as the shell removes it (`kubectl delete \` +
  newline + `namespace prod` was checked with a stray newline argument).
- Shell parser: a `#` comment ends at the newline. Before, the comment ran on past it, so
  `echo hi # note` + newline + `kubectl delete …` hid the `kubectl` line; and a `#` inside a
  word (`pods#x --as=admin`) cut off the rest of the command.
- Shell parser: the launchers `watch` (its arguments run through `sh -c` unless `-x`),
  `setsid`, `stdbuf`, `doas`, `ionice`, `caffeinate`, `unbuffer`, `chronic`, `busybox` and
  `script -c` are unwrapped like `sudo` and `nohup`. A program word the shell could expand into
  another name (`kube{,}ctl`, `kubec?`, `kube[c]tl`) is rejected ("brace/glob in program name");
  the hook refuses it when it is a bare word or could become a tool's name, and asks for a path
  pattern such as `./scripts/*.sh`. The hook asks (it does not refuse) when an unknown program
  has an infrastructure tool among its arguments, also as a path or after an option
  (`setpriv kubectl …`, `setpriv /usr/local/bin/kubectl …`, `proxychains -q kubectl …`, `chrt
  0 kubectl …`, `tmux new -d 'kubectl …'`), except programs that only take a tool's name
  (`man`, `command -v`, `hash`, `find`, `tree`, `make`, `pkill`, `lsof`, `curl`, `wget`,
  `tflint`, `checkov`, `pip`, `apt-cache` and other package tools, …), whose command-running
  options are still read (`rsync -e`/`--rsh`, `scp -o ProxyCommand=`/`-S`, `nix-shell
  --run`/`--command`), and arguments that are URLs, file names or a `-d dir` value naming an
  existing directory.
- Shell parser: package and environment managers that run a command are unwrapped, so the
  command meets the policy: `uv run`, `uv tool run`, `uvx`, `pipx run`, `poetry run`, `bundle
  exec`, `asdf exec`, `gem exec`, `mise exec`/`mise x` (`… -- CMD`, `-c STRING`) and `brew bundle
  exec -- CMD`. `uv run kubectl delete nodes --all` gave only a `uv` intent and was allowed,
  since `uv` and `pipx` take a tool's name in their other subcommands (`uv pip install kubectl`,
  `pipx install kubectl`, which are still allowed). An option these parsers do not know is
  rejected. `uv run -m mod` and `uv
  run script.py` are read as `python -m mod` and `python script.py`. `cargo run` and `go run`,
  which build a program and hand it the remaining words, now ask when those words name an
  infrastructure tool, like any unknown program. The hook also asks when a git configuration
  value names one (`git -c alias.x='!kubectl …' x`, `git -c core.sshCommand=… fetch`, `git config
  alias.x '!kubectl …'`): git runs such values where their argv cannot be checked.
- Agent hook: a local script run inside `$(…)`, backticks, `<(…)`, a subshell,
  a `{ …; }` group, a loop, a `case` branch, `sh -c '…'` (also `source`/`.` there), after `exec` or
  `builtin`, or by `fish`/`csh`/`tcsh`/`mksh`/`yash`/`rbash` is read like `bash x.sh`, and one that
  inline code may rewrite (`python3 -c '…"x.sh"…'; bash x.sh`) asks. `BASH_ENV`/`ENV` before a
  command asks. Commands git runs from its arguments or environment ask when they name an
  infrastructure tool or cannot be read: command-valued configuration only (`alias.*` starting with
  `!`, `core.sshCommand`, `core.pager`, `core.editor`, `*.helper` with `!`, `diff.*.textconv`,
  `filter.*`, …; `user.email=git@…` and `safe.directory=/work/terraform` no longer ask), `bisect
  run`, `submodule foreach`, `rebase -x`, `difftool`/`mergetool -x`, `filter-branch --*-filter`, and
  `GIT_SSH_COMMAND`, `GIT_PAGER`, `PAGER`, `EDITOR`, `VISUAL` and similar variables; this also
  holds inside `bash -c`. `fd -x`, `rg --pre`, `vim -c`/`+cmd`, `hash -p`, `alias NAME=…`, `nix run
  …#tool` and code arguments of `awk`, `sed`, `tmux`, `screen`, `parallel`, `flock`, `su`, … that
  name a tool ask. `cargo +nightly run`, `cargo --color X run` and `go -C dir run` are read as
  `run`. Package launchers accept common options before the subcommand (`uv --directory backend run
  …`, `poetry -C dir run`, `bundle --verbose exec`, `mise -E env exec`) and more `uv run` options,
  and `uvx`/`uv tool run`/`pipx run`/`gem exec` drop a version from the program (`kubectl@latest`,
  `kubectl==1.0`, `kubectl:1.0`). Development tasks of migration tools run instead of being refused
  as unknown migrations: `rails test`/`g`/`routes`/`db:migrate:status`/…, `alembic
  current`/`history`/`revision`/…, `prisma generate`/`migrate status`/…; other unknown tasks
  (`rails db:schema:load`, `rails console`) are still refused. A brace word with many groups is
  denied at once (its expansion was exponential), a `~+` path asks instead of failing, a command
  over 64 KiB is not parsed (asks, or blocks when it names a tool), and more than 32 pieces of
  piped code ask.
- Agent hook: script reading. A `<<` inside `$((…))`, `((…))`, `$[…]` or `${…}` is no longer taken
  for a here-document (`SIZE=$((1<<30))` hid every later line of the script), nor is one inside a
  string that spans lines; a quoted tag's body keeps its trailing backslashes, so `EOF` still ends
  it; a here-document whose end is never found asks, and its lines are checked as commands. A line
  ending in `|`, `|&`, `&&` or `||` is joined with the next (`echo … |` + newline + `sh`). Each
  script is read once per command, and more than 32 scripts in one command ask (a long run of
  `./x.sh;` took longer than the hook timeout). Scripts behind `builtin source`, `exec -a NAME`,
  `exec -c`, `source --`/`. --`, `bash -r` and `posh` are read in a command that parses too.
  More command-valued git settings and options ask when they name a tool: `git config -f FILE`/
  `--file`/`set …`, `diff.external`, `core.gitProxy`, `core.alternateRefsCommand`,
  `remote.*.uploadpack`/`receivepack`, `sendemail.*cmd`, an absolute `credential.helper` path,
  `--upload-pack`, `clone -u`, `push --receive-pack`/`--exec`, `GIT_PROXY_COMMAND`, and `emacs`
  code arguments. `git submodule foreach git pull` (and `fetch`, `status`, …) no longer asks, nor
  does `complete -C …` in a sourced rc file.
- Agent hook: a pipeline stage gets the same asks as the command on its own (`ssh h kubectl … |
  tail -5`, `awk 'BEGIN{system("kubectl …")}' | cat` were allowed), and so does a code argument
  given as `--expression=…`. A here-document read by a shell behind `exec`, `builtin`, `( `, `$(` or
  `sh -c sh` is checked as commands. A file redirected onto a group, subshell, `if` or loop that
  runs a shell (`{ bash; } < x.sh`) is read like `sh < x.sh`, and a shell reading a copied or
  read-write descriptor (`<&3`, `<>`) asks. `export`/`declare` of a command-valued or sourced
  variable (`export GIT_SSH_COMMAND=…; git fetch`, `export BASH_ENV=x; bash -c …`) asks like the
  prefix form. `perl`/`ruby -I DIR -e …` reads the inline code. Joining a script's lines that end
  in `|` or `&&` is linear in the script's size.
- Agent hook: `command source x.sh` / `command . x.sh` read the script; `bash < <(curl …)`, `bash -s
  < <(…)` and `python3 <(curl …)` ask like `bash <(curl …)`. Running a script twice (`bash x.sh;
  bash x.sh`, `./run.sh build && ./run.sh test`) or testing it (`test -f .env && source .env`) no
  longer counts as writing it. Checking which words name a script is linear in the command (32
  scripts next to a long argument list took seconds).
- Agent hook: `eval ./x.sh` / `eval 'bash x.sh'` read the script. In a script, a here-document
  piped into a shell on the line after its body (`cat <<EOF |` … `EOF` / `sh`), one with the reader
  after the redirection (`<<EOF sh`, `0<<EOF sh`) and `source /dev/stdin <<EOF` are checked as
  commands; `… | source /dev/stdin` is refused when the command names a tool, like `… | sh`.
  `PROMPT_COMMAND` counts as a command variable. A script path with `$HOME` or another variable
  the hook's environment sets (and the command does not) is read instead of asking. Finding files
  redirected onto groups is linear (63 KB of `)<a` took 36 s).
- Agent hook: scripts named in literal code piped into a shell are read (`echo 'bash x.sh' | sh`);
  `exec < x.sh` before a shell or interpreter reads x.sh like `sh < x.sh`; a pipe into a group,
  loop or `if` that runs a shell or interpreter asks (`… | while true; do sh; done`). A
  redirection target written as a separate word (`cd sub 2> /dev/null`) is no longer taken for an
  argument.
- Agent hook: only `$HOME` in a script path is filled in from the hook's environment, and only when
  the command names HOME nowhere else; `$PWD`, `$OLDPWD`, `$_` and a variable set by `for`, `read`
  or `unset` ask (`cd sub && source "$PWD/x.sh"` read the wrong file). A process substitution or
  here-string given to `exec` or to a group, loop or `if` that runs a shell asks (`exec < <(curl …);
  sh`, `{ sh; } < <(…)`). In a script, the reader of `cat <<EOF |` may follow blank or comment lines
  or be a group (`{ sh; }`). The pipe-into-a-loop ask only looks inside the loop and only at shells
  and interpreters that read standard input (`… | while read f; do python3 -m mod "$f"; done` runs).
  Many `exec < FILE` words are read in linear time.
- Agent hook: piped code nested inside piped code shares one budget of 32 checks per command (32
  levels of 32 took minutes). A pipe into `exec sh`, `eval sh`, `builtin exec sh` or `bash -c "exec
  sh"` is a shell reading the pipe. Scripts named in piped code are not read from the hook's
  directory after a `cd` in the command (asked), and `HOME=` anywhere in the command keeps `$HOME`
  from being filled in. `bash /dev/stdin` asks; a download named after a script (`wget …/x.sh`,
  `curl -O …/x.sh`) counts as rewriting it.
- Agent hook: a pipe into a group, loop, `if` or subshell asks when any shell or interpreter after it
  reads standard input: after its options (`bash -e`, `sh -l`, `bash -s`) no script, `-c` code or
  `-m` module follows (where the compound ends is no longer worked out, which `$(…)`, `${…}`,
  quotes and nesting got wrong, and which was quadratic). `eval`, `exec`, `builtin` and `sh -c`
  strings are unwrapped up to four levels, and any part of such a string may be the reader (`|
  bash -c 'eval sh'`, `| eval 'true; sh'`), also with `< FILE` (`bash -c 'eval sh' < x.sh` reads
  x.sh). Other redirections before a group's or `exec`'s standard input (`{ sh; } 2>/dev/null <
  x.sh`), a named descriptor (`sh <&$fd`), `~` when the command changes HOME, and a `cd` inside a
  subshell or `-c` string before piped code are no longer missed.
- Agent hook: a directory change is also seen spelt `\cd`, `"cd"` or as `env -C`/`sudo -D` (scripts
  after it ask instead of being read from the hook's directory); a quoted `sh -c` string is read on
  its own before the command is split (`bash -c 'set -e; bash x.sh "$@"'`); a chain of `eval`s is
  joined once (it was quadratic) and followed to four levels; a redirection after a shell reading a
  pipe (`sh 2>/dev/null`) no longer counts as its script. A URL counts as naming a script only for
  `wget` and `curl -O`/`-J`.
- Agent hook: a shell or interpreter given by path (`/bin/sh`, `/usr/bin/python3`) counts as a reader
  in the pipe, group-redirect, `exec <` and descriptor checks; `bash -ec '…' < x.sh` and a `-c` string
  followed by its arguments are read; `--version`/`--help` (and `-V`/`-v`/`-h` of an interpreter) are
  not stdin readers; only env's own `-C`/`--chdir` counts as a directory change (`env FOO=1 make -C
  build` does not).
- Agent hook: the regexes that find shells by path only start at a word, so long runs of `/` stay
  linear (they took over 30 s); an unquoted `<<< $(…)` or `` <<< `…` `` is a here-string, not a
  script argument; `bash -lc`, `--norc`, `-o pipefail` and trailing arguments before `< FILE` are
  read, and a `-c` string reading a process substitution or here-string asks; `| time (sh)` is a
  piped compound; a URL download other than `git clone` and `curl` without `-O` counts as naming a
  script.
- Agent hook: a shell that ends its line inside a piped loop or `if` (the usual multi-line form)
  reads the pipe; `bash -ec`, `-o pipefail`, `--norc` and `$'…'` `-c` strings are read on their own;
  a bare `cd` or `cd ~` after the command changes HOME makes the directory unknown; `python3
  /dev/stdin` reads the pipe; `env -iC` counts as a directory change; many `env`/`sudo` words stay
  linear.
- Agent hook: the regexes that find a shell's `-c` string and a shell or interpreter word are
  linear: runs of backticks, `{` inside quotes and `-o ` (with or without a `-c`) took 6-60 s, past
  the hook's timeout. A shell reading a piped group's input is found before a separator with no
  space (`sh;echo`, `sh&&x`, `sh -s;x`). Any interpreter given `/dev/stdin` or `/dev/fd/0` as its
  script asks, as `bash /dev/stdin` does (`| python3 /dev/stdin`, `| node /dev/stdin`). `env`
  and `sudo` read clusters of short options (`env -iv`, `env -iC DIR`, `env -iCDIR`, `env -u X
  -iC DIR`, `sudo -Eu USER`), and `env -S STRING` / `--split-string` is split into words unless
  it holds `$`, a backslash or options of its own; a cluster with `C` or `D` makes the directory
  unknown. A shell, interpreter or script run under `env`/`sudo` options the hook does not know
  (`env -P DIR bash x.sh`, `sudo -iu USER bash x.sh`, `cat x.sh | env -Q sh`) asks instead of
  being allowed.
- Agent hook: the checks for shells reading standard input match on the words the shell sees,
  not the raw text: `'sh'`, `"sh"` and `\sh` are `sh`, a quoted `';'` is an argument, not a
  separator, and an `env "-iC" DIR` or `sudo "-D" DIR` makes the directory unknown. Redirections
  are read in order, so the last `<` is standard input (`bash -c 'eval sh' < ok.sh < x.sh` and `{
  sh; } < ok.sh < x.sh` read x.sh). The words are read in one pass, also inside `sh -c` strings and
  `eval` words, to four levels. At most 32 launchers (`env`, `sudo`, `nice`, …) are unwrapped in
  front of one command, so a chain of `env -S`/`env -u` words stays linear (it took 5-7 s); a
  longer chain cannot be checked and is judged like any command the parser rejects.
- Agent hook: the shell-word reader follows bash's quoting more closely: here-document bodies
  (`<<`, `<<-`, quoted delimiters, several on one line) are set aside instead of read as commands
  (an apostrophe in one no longer hides the rest of the command), `$'…'` keeps its backslash
  escapes (`$'\''`), and `$(…)` is read as a command line of its own. A quote, `$(…)` or backtick
  never closed asks when the command names a shell, interpreter or infrastructure tool.
  Here-document bodies and command substitutions are checked like `sh -c` strings and `eval`
  words (`x=$(curl … | sh)` asks); `sh -c` strings and `eval` words in a command the parser
  rejects are dequoted the same way (`bash -c 'bash -c '\''sh < x.sh'\'''`, `eval 'bash x.sh;
  true'`), a `<` given to `eval` reaches a shell in its words (`eval 'true; sh' < x.sh`), and a
  pipe into a shell in such a command asks. A file redirected onto a group, loop, `exec` or `-c`
  string after a `cd` is no longer read from the hook's directory (asked).
- Agent hook: a `<<` inside `(( … ))`, `for (( … ))`, `$(( … ))`, `$[ … ]` or `${ … }` is a
  shift or a pattern, not a here-document, so the lines after it are read; a here-document whose
  delimiter never comes leaves the command unclosed (asked when it names a shell, interpreter or
  infrastructure tool). A command goes on past a newline after a trailing `|`, `|&`, `&&` or `||`
  (also after comments and blank lines), in the parser and in the shell-word reader, so `curl … |`
  / `sh` is a pipe into a shell and `kubectl get pods &&` / `kubectl delete …` is judged as the
  delete. `$'…'` is decoded as bash does (`\xHH`, octal `\NNN`, `\uHHHH`, `\UHHHHHHHH`, `\cX`),
  so `| $'\x73h'` is `| sh`; a pipe into a shell the parser does not recognise as one asks.
  `bash -s ARGS` and `bash +x` read the pipe. `python3 - <<'EOF'` and `node <<'EOF'` still
  ask: the hook does not read code in other languages.
- Agent hook: every here-document body, quoted or not, is checked as commands, whatever program
  reads it: which one runs it as code cannot be told reliably (functions, aliases, `PATH`,
  `hash -p`, `>(…)`, `exec 3> >(sh)`, `sort --compress-program`, `ssh`, `sudo -s`, …). The lexer
  still sets bodies aside when it reads the command around them, so an apostrophe in one cannot
  hide what follows. Accepted over-ask: a body that reads like a command asks (`cat > README.md
  <<'EOF'` with `curl … | sh` or `cd sub; bash x.sh` in it); it is denied only when it runs a
  blocked command. `$(…)`, `<(…)`, `>(…)` and backticks inside `$((…))`, `${…}` and `$[…]` are
  read (only a `<<` there loses its here-document meaning); single quotes hide them only in an
  unquoted `${…}`, not in arithmetic, `$[…]` or a double-quoted `"${…}"`. `((…))` and `$((…))`
  count as arithmetic only when they close with an adjacent `))` (`((cmd) )` is a subshell,
  `$((cmd) )` a command substitution). A comment, blank line or backslash-newline between a pipe
  and the command after it no longer hides that command.
- Agent hook: quoting inside `${…}` is followed level by level: double quotes make single quotes
  literal (`${x:-"'$(…)'"}` runs the substitution), and a nested `${…}`, `$[…]` or `$((…))` is
  read with its own rule (single quotes quote only in an unquoted `${…}`). In an unquoted
  here-document body quotes are literal, so its `$(…)` and backticks are read whatever quotes
  surround them (`cat <<E` / `'$(curl … | sh)'` asks); a quoted delimiter (`<<'E'`, `<<"E"`,
  `<<\E`) has no expansions. Command lines nested deeper than the hook reads (more than four
  levels of `sh -c`, `eval`, `$(…)` and here-documents, or more than 128 brackets of `$(…)`,
  `${…}`, `$[…]` and `$((…))`) ask instead of going unread.
- Agent hook: backticks are read the same way everywhere (at the top level, inside double
  quotes, inside `${…}`/`$((…))` and in unquoted here-document bodies): a substitution ends at
  the first backtick no backslash escapes, and its text is unescaped as bash does (`` \` ``,
  `\\`, `\$`), so an escaped backtick inside is a nested substitution that is read in turn
  (`` echo "`echo \`bash x.sh\``" `` reads x.sh). `` "`curl … | sh`" `` asks. Scripts named in
  nested command lines are read like those at the top.
- Agent hook: in a command the parser rejects, scripts (and launchers with unknown options) are
  found from the shell-word reader's simple commands rather than a split of the raw text, for
  the command and every command line nested in it (`sh -c`, `eval`, `$(…)`, backticks,
  subshells, here-document bodies), so a quoted `;`, `|`, `&`, `(`, `)` or backtick is part of
  a word (`echo $(bash x.sh 'a;b')` and `bash x.sh '('` read x.sh). Backticks directly inside
  double quotes also unescape `\"`, as bash does there (`` "`eval \"bash x.sh\"`" ``). A
  shell's options that take a value (`-o`, `+o`, `-O`, `+O`, `--rcfile`, `--init-file`) are
  skipped with it, so `bash --rcfile FILE -c '…'` and `bash -O extglob -c '…'` read the `-c`
  string instead of taking FILE or the option name for the script.
- Agent hook: a launcher's command string (`watch 'cmd'`, `script -c 'cmd'`, `mise exec -c
  'cmd'`, also behind `sudo`/`nohup`) is a nested command line like a `sh -c` string, so every
  check reads it, also in a command the parser rejects (`watch 'bash x.sh' "$HOME"`). A shell
  given a script whose name is only known at run time and a `< FILE` (`sh < x.sh $X`) also has
  FILE read, since with `$X` empty it runs FILE. An interactive shell (`-i`, `-ic`, …) sources
  its `--rcfile`/`--init-file`, which is read as a script (`bash --rcfile x.sh -i`); with `-c`
  alone the file is not read, as bash does.
- Agent hook: a shell's short-option cluster takes one value per `o`/`O` in it, in order, and
  then the `-c` string if it holds a `c` (`bash -co pipefail 'cmd'`, `bash -Oc extglob 'cmd'`,
  `bash -eo pipefail x.sh` runs x.sh), the same in the parser, the script reader and the
  checks for shells reading standard input. `function NAME { …; }` is read like `NAME() { …;
  }`, so the scripts in its body are read.
- Agent hook: in zsh, ksh, mksh and yash an `o`/`O` with letters after it takes them as its value
  and ends the cluster (`zsh -opipefail -c 'cmd'`, `zsh -eopipefail x.sh`); a trailing one, and
  every `o`/`O` in bash, dash and sh, takes the next word. An `i` in a cluster with option values
  (`bash --rcfile x.sh -io pipefail -c …`) still makes the shell interactive, so it sources the
  file. Only the shell in command position sources its `--rcfile` (`echo bash -i --rcfile x`
  runs no shell), and an interpreter's `-O`/`-o` takes no value (`python3 -OO x.py`).
- Agent hook: any `c` in a shell's short-option cluster means `-c`, also after an attached
  value (ksh93 reads `-oc` as `-c`), and the same holds for `i` and `s`. Shells started by
  `find … -exec|-execdir|-ok|-okdir` are nested command lines like `watch`'s, so their
  `--rcfile` and scripts are read. Only bash has `--rcfile`/`--init-file`, and only before its
  short options (`bash -i --rcfile x` is an error and runs nothing). A shell with more option
  words than the hook reads (64), before its `-c` string or script or as a reader in a piped
  group, asks instead of being passed over. Versioned shell names (`zsh5`, `ksh93`, `bash5.2`)
  are read as their shell.
- Agent hook: an `o`/`O` with letters after it that hold `c`, `i` or `s` in zsh, ksh, mksh or
  yash (`-onoclobber`, `-oxtrace`, `-ointeractive`) is read both ways wherever a shell's
  options are read, on the dequoted words of every nested command line (`zsh "-onoclobber"
  x.sh`, `zsh -o noclobber -oxtrace x.sh`, `bash -c 'zsh -onoclobber x.sh'`): as the option's
  value (as zsh and ksh do: x.sh is the script, or the shell reads standard input) and as set
  letters (as ksh93 reads `-oc` as `-c`: x.sh is the command string). Both are checked, so
  `ksh -oc 'cmd'` also asks when `cmd` is harmless (its other reading runs a script named
  `cmd`). `find … -exec` ends at `;` or at a `+` right after `{}`; any other `+` is
  an argument (`find . -exec env -u + cmd \;` runs cmd). Versioned names are mapped only for
  shells that ship them (bash, zsh, ksh, mksh, dash, yash, also `mksh-R59`; not `sh2`).
- Agent hook: a shell's lone `-` ends its options like `--`, and after either every word is an
  operand, so the next word is the script, even one whose name starts with `-` (`bash - x.sh`,
  `zsh -x - x.sh`, `bash -- -x`); a lone `-` with nothing after it still reads standard input
  (`curl … | bash -` asks). An ambiguous zsh/ksh cluster read as a value that leaves `-s` reads
  its `< FILE` as the script. zsh's `noglob`, `nocorrect` and `repeat N` are unwrapped like
  `command` (`noglob bash x.sh`). A long run of `!` or `{` before a command is stripped in one
  pass (65 KB of `! ` took over 2 s).
- Agent hook: `!`, `time [-p]` and grouping words in front of a command are stripped in any
  order (`time ! sh x.sh`, `! time ! sh x.sh`), as are zsh's `repeat N do … done`; `command --`
  (also `command -p --`), `nice --` and `timeout -- N` are unwrapped. A `-` or `--` ends a
  shell's options the same way in every place that reads them, so after `-c` the next word is
  the command string (`bash -c - 'cmd'` runs cmd). `noglob source x.sh` and `noglob . x.sh` read
  x.sh like `source x.sh`.
- Agent hook: assignments, `--`, `!`, `{`, reserved words and `coproc` in front of a command are
  passed over in one pass in any mix (`-- ! A=1 do …` took 3-4 s at 64 KB; `time coproc sh x.sh`
  reads x.sh), as are runs of `exec`/`builtin`; each pass over the launchers counts toward the
  limit of 32, and a pass that changes nothing ends the unwrapping. A program whose path ends in
  such a word (`./-- ; …`) no longer makes the unwrapping loop forever (a hang lets the command
  run); the shell-word reader also never stays on a character. `command` takes repeated or
  clustered `-p` (`command -p -p`, `-pp`), and GNU time (`/usr/bin/time`, `gtime`) takes its
  options (`-f FMT`, `-o FILE`, `--format=`, `--output=`, `-v`, `-l`, `-a`, `-q`, `-p`).
- Agent hook: a program word with glob characters (`kube{,}ctl`, `k*`) is matched against the
  tools' names with a small glob matcher that runs once along the word, not with `fnmatch`,
  which compiled the word to a regex and was quadratic on runs of `[` (64 KB of `[` took 36 s;
  `{a,b}`×8 + 2 KB of `[` took 10 s). More than 16 KB of glob text across the brace
  alternatives counts as possibly a tool's name (denied), as does a POSIX class (`[[:alpha:]]`).
  Quoted glob characters are literal, as in the shell (`"[[[["` and `'k*'` are program names,
  not globs): whether they are quoted is read where the word is read, in the command or in its
  `-c` string, in one pass (`bash -c 'k* …' 'k*'` is still a glob); a program word a launcher
  produces (`uvx 'kube[a]x'`) counts as a glob when it holds one. A `find … -exec` program
  word is a glob as the outer shell spells it (it expands find's words before find runs:
  `find . -exec k* …`, also inside `eval` or `$(…)`), and program words in nested lines the
  parser rejects (`eval` words, a `-c` string in a `-c` string, substitutions, here-document
  bodies) are checked too. For this check a here-document body is shell-run when a shell,
  `eval`, `source`, `.` or `exec` is a program of the pipeline its `<<` is in (`bash <<EOF`,
  `cat <<EOF | sh`: as for a command), data when every program there is a data sink (`cat`,
  `tee`, `jq`, `sort`, …; not `git` or `gh`, which run programs in too many ways; for `sort`
  and `diff`, none of `--compress-program` or `--diff-program`, also abbreviated, nor an
  expansion among the arguments: `sort "$O"`) or an interpreter of another language reading
  the body as its program (`python3`, `python3 -`, `node`; also `python3 -m json.tool`; not
  one given inline code or a script, which may hand the body to a shell: `python3 -c
  '…os.system(input())'`),
  with no `<(…)`/`>(…)` and no descriptor path (not checked: a Markdown `* item`), and otherwise
  unknown (`tee >(sh)`, a function or alias in the command, `sed`, `xargs`, an `eval`
  anywhere, a group or subshell in a command with a pipe: `(cat <<E …) | x`, a
  here-document inside `$(…)`, backticks, `<(…)` or `>(…)`, whose output goes on, and a
  pipe into or out of a compound command: `cat <<E | if …; then …; fi`, a here-document
  attached to a group, subshell, loop or if: `{ …; } <<E`, `done <<E`), where a globbed
  word asks (an `eval` anywhere adds every body to these). A here-string (`<<< word`) is
  read like a one-line body, also inside a substitution. A body whose pipeline goes on past
  its line (`cat <<E |`, the next stage after the body) has an unknown reader too (accepted
  over-ask: `… | tee f` on the next line asks when the body has a globbed word); each body
  and here-string is classified once, from its own command on (`:<<<x|` on 8000 lines took
  11 s). The reader
  of a body is its own
  command and the pipeline stages after it (`echo x | cat <<E`: echo never sees it), and a
  reserved word counts for the compound rule only where a command starts (`echo done`
  does not). Only an unquoted `case` at the start of a command
  (after `do`, `then`, `else`, `{`, `!` or `time` too, spelt bare in reserved-word position:
  `"do" case …` and `echo do case …` are plain words), with no redirect, assignment or
  other word before it, starts a case statement, whose arm patterns (`*)`, `a|b*)`) are
  not program words for this check. A word whose quoting is not known counts as a glob. Each
  text's quoting is read once per decision, and `x+=1` and `a[1]=2` are assignments like
  `x=1`. Two other regexes that
  were quadratic on `[` runs (a package spec in `uv run`/`uvx`, a Terraform address index)
  are plain string scans now. With `--log-json`, a decision ended by the time budget logs its
  ask or deny, and the abandoned worker writes no log line or ledger entry (checked when its
  policy run starts and again before it writes).
- Shell parser: `find … -exec|-execdir|-ok|-okdir CMD … \;|+` yields CMD as a command of its
  own (`{}` stays a literal, unknown file), so `find . -exec kubectl delete … \;` meets the
  policy. A backslash-escaped `;`, `|`, `&`, `<`, `>`, `(` or `)` is a literal word, not a
  separator (`find … -exec rm {} \; -print` was split into a command `-print`).
- Agent hook: "names an infrastructure tool" also matches once quotes, backslashes and line
  continuations are removed (`kube''ctl`, `"kube"ctl`).
- Agent hook: a local shell script is read before it runs (#56). For `bash x.sh`, `sh < x.sh`,
  `./x` (a `#!` shell, `#!/usr/bin/env -S bash`, or no `#!` line), `source x.sh` and `. x.sh`,
  each line that names an infrastructure tool is checked as a command against the policy, in
  one policy run (a few more find the line when it does not allow): a blocked line, or a block
  the lines only reach together, blocks and the message names the line; a line that cannot be
  checked asks (the line is found by bisection on the verdict, so a BLOCK is not blamed on an
  earlier ESCALATE line). A backslash at the end of a line joins the next as the shell does,
  except at the end of a comment; comments are skipped; `<<` is a here-doc only outside quotes
  and comments, its delimiter is read as one shell word (`<<'END DATA'`; an unreadable one,
  such as `<<$'EOF'`, asks and the lines after it are checked as commands), and its body is checked when a shell reads it (also through `cat <<EOF | sh`), asks
  when another interpreter reads one that names a tool or an unquoted body's `$(…)` names one,
  and is data otherwise. A script that does not exist yet, is written, copied, moved, linked,
  edited or otherwise named by the same command (`printf … > x.sh; bash x.sh`, also spelled
  `"$PWD/x.sh"` or `"$(pwd)/x.sh"`; reading it with `cat`, `grep`, `wc`, … does not count), cannot
  be read, is not a regular file, holds a NUL byte (when a shell is named; a `./x` without `#!`
  and with a NUL is a binary and not read), is over 64 KiB, names a tool on more than 64 lines,
  or follows a `cd` the hook cannot follow (computed, in the background or a pipeline, `env
  -C`) asks; a relative path follows a literal `cd DIR` earlier in the command. What a script
  sources or runs in turn is not read, nor are other interpreters' scripts (`python3 x.py`).
- Agent hook (PR #60 review): a file sourced before an infrastructure command (`source env.sh;
  aws s3 rm …`, `. env.sh; …`) is read for what it sets, and its literal `export
  AWS_PROFILE=prod` / `AWS_PROFILE=prod` / `declare -x …` settings of the variables that pick an
  account, cluster or program reach the commands after it, as do the same settings written in
  the command itself (`export AWS_PROFILE=prod; aws …`), so a policy scoped to that profile
  applies with `--resolve-current-context`; before, the later command was judged with the
  invoking environment and allowed. A sourced file that may change the environment in any
  other way (`cd`, `unset`, `alias`, a function, `set -a`, a computed value, control flow,
  another sourced file or program; also a file that is missing or cannot be read), and a
  setting that may not reach the later commands (in the background, a pipeline, after `&&` /
  `||`, inside an if or loop body, in a `sh -c` string) or cannot be followed (`unset`,
  `export -n`), deny the infrastructure commands after it as a computed scope does. A script
  line whose program word is a glob or brace (`/usr/local/bin/kubec?l delete nodes --all`,
  `kube{ctl,x} delete …`) is now kept when a script is read (`bash x.sh`, `./x.sh`, `source
  x.sh`, `sh < x.sh`) and asks like the same command typed directly; a glob in an argument
  (`rm -f *.tmp`) still allows.
- Agent hook: inside a script the hook reads (`bash x.sh`, `./x.sh`, `sh < x.sh`, `source
  x.sh`), a line that may change the account, cluster, program or directory of a later line
  that names an infrastructure tool now refuses the script as a computed scope does ("cannot
  check this command statically"): an assignment, `export`, `declare`, `unset`, `read` or
  `printf -v` of the variables the hook watches, `cd` / `pushd` / `popd`, `set -a`, `alias`, a
  function, `eval`, or a nested `source` / `.`. Literal settings (`export AWS_PROFILE=prod`,
  `AWS_PROFILE=prod`, `declare -x …`) in a script without control flow are followed instead,
  so `export AWS_PROFILE=prod-admin` then `aws s3 rm …` is judged in prod. Before, each line
  was judged with the invoking environment and directory. Scripts that change none of these
  before an infrastructure line (`set -euo pipefail` then `kubectl get pods`, `cd build &&
  make`) are still judged line by line.
- Agent hook (PR #60 council): `local NAME=value` (an error outside a function, so it sets
  nothing) and a declaration with an option other than `-x` (`declare -g`, `-n`, `-a`, `-l`,
  …) are no longer followed as settings of a watched variable; with `unset`, `read` (also
  `read -aNAME`), `mapfile` / `readarray`, `getopts` and `printf -v NAME` / `printf -vNAME`,
  they now count as changes the hook cannot follow whenever a word may name a watched variable
  (also a computed `$N`), typed in the command, in a sourced file or in a script the hook
  reads: the infrastructure commands after them are refused. Before, `local
  HELM_NAMESPACE=staging; helm … uninstall …` was judged in staging, and a sourced or scripted
  `printf -vHELM_NAMESPACE …` was not seen.
- Agent hook (PR #60 council): a command that sources many files stays linear (whether an
  infrastructure tool comes later is worked out in one sweep, and each sourced file is read
  once per directory; past 32 distinct files the rest leave the environment unknown): a
  thousand `source env.sh; ` before `aws …` took 18.8 s. In a script the hook reads, a
  nameref (`declare -n` / `typeset -n` / `local -n`, also when typed) and `printf -vNAME` count
  as changes the hook cannot follow, and a variable whose value names a file or command a
  later program runs (`BASH_ENV`, `ENV`, `GIT_SSH_COMMAND`, `EDITOR`, …) asks as it does when
  typed. A `cd` in a script no longer refuses it: like a typed `cd`, a literal one moves the
  directory later lines are checked from, and a computed one (`cd "$(dirname "$0")"`), one in
  a script with control flow or one after a line naming `CDPATH` makes it unknown, which only
  matters to the checks that depend on it. A typed `cd DIR` to a relative name is unknown when
  `CDPATH` is set or the command names it, since `cd` searches it first.
- Agent hook (PR #60 council): a setting inside a `{ …; }` group (also one an `&&` / `||`
  may skip, `false && { …; export HELM_NAMESPACE=staging; }`) no longer reaches the commands
  after the group: like one in an if or loop body it is a change the hook cannot follow. A
  sourced file, a script, a `KUBECONFIG` file and a `psql -f` file are only read when they are
  regular files: a pipe (`/dev/fd/N`, a FIFO), a device or a directory is never opened, so
  `source /dev/fd/3; kubectl …` asks at once instead of waiting on the pipe. In scripts and
  sourced files, names and command words are matched after quote removal, and a quoted name or
  command word (`export H"ELM_NAMESPACE"=prod`, `sour""ce x.sh`) is never followed as a
  setting. Whether the command names `CDPATH` is worked out once, not once per `cd`
  (`"cd a;"` 12800 times took 5.25 s), and the literal settings kept from a script do not
  count toward its 64-line limit. A `for` / `select` loop whose variable is one the hook
  watches (`for AWS_PROFILE in prod; do …; done`), and a watched variable assigned in front
  of a POSIX special builtin (`AWS_PROFILE=prod :`, which sh and dash keep), are changes the
  hook cannot follow, typed, in a `sh -c` string or in a script: the infrastructure commands in
  the loop and after it are refused. A script's control flow is now read with the shell lexer,
  so `$(…)`, `${…}` and quoted text no longer stop its literal settings from being followed.
- Agent hook (PR #60 council): `env -u NAME` / `-uNAME` / `--unset=NAME`, `env -i` / `env -`,
  `env NAME=` and `sudo` (which resets the environment) in front of an infrastructure command
  are changes the hook cannot follow when they remove or empty a watched variable or drop
  values set earlier in the command: the tool falls back to defaults, so it is refused rather
  than judged with the value set before. A script the command runs (`bash x.sh`, `sh < x.sh`,
  `./x.sh`, `source x.sh`) now starts with the watched settings made before it (`export
  HELM_NAMESPACE=prod; bash x.sh`, `source env.sh; bash x.sh`, `HELM_NAMESPACE=prod bash
  x.sh`), checked as if its first line; after a change the hook cannot follow (`unset`, a
  bare assignment, a sourced file it cannot read) a script that names a tool asks. `CDPATH` is
  watched like the other variables and found also when spelt with quotes (`CDP"ATH"=…`,
  `printf -vCDP"ATH"`).

### Changed
- Agent hook: code piped into a shell or interpreter, or fed to one by a here-string or here-doc
  in a command that cannot be parsed, asks instead of running (#56): `curl … | sh`, `echo … |
  base64 -d | sh`, `base64 -d <<< … | sh`, `cat x.py | python3`. Codex, Gemini CLI and OpenCode,
  which cannot ask, block it. Only a literal `echo` (no `-e`, no backslashes) or `printf` (one
  argument, no `%`) is read: its text blocks when it names an infrastructure tool, and code for
  a shell is checked like a command. Piped code in a command that names an infrastructure tool
  is still blocked. Shell intents' `params.runs_code` for a pipe now carries `producer`, the
  program feeding it.
- `aegis check command` still exits 64 for a command it cannot parse; for a compound command the
  message now ends with the part that caused it (`… inside double quotes in 'echo "exit=$?"'`).

### Fixed
- **kubectl boolean flags were "missing its value"** (#53). `kubectl get pods -n prod
  --no-headers` was a parse error, so the hook denied a read; `--no-headers pods` swallowed the
  kind, and `delete ns --interactive prod staging` lost `prod`. The flag walker now knows which
  kubectl flags are booleans and which take a value (kubectl 1.36's per-verb help): booleans
  (`--no-headers`, `--watch`, `--interactive`, …, `-f` on `logs`) take no value, and value flags
  take the next token even when it starts with `-`, as kubectl does (`--grace-period -1`;
  `label ns prod --field-manager -n staging` labels `namespace/staging`, it does not set the
  namespace). `-c`, `-L` and `-p` on `patch` keep their value instead of leaving it as a target.
  An unknown long flag is a boolean at the end of argv, takes a following word as its value, and
  is refused when another option follows it, since whether it takes that option as its value
  decides the scope; write unknown flags as `--flag=value`, or put them last.
  `kubectl get --raw <path>` is still refused (a URI path can read any kind).
- **Help and version probes were parse errors** (#54). These forms now give one read-only
  `cli/<tool>` intent with `params.informational`, which the example policy allows: the tool's
  lone help or version flag (`helm --help`, `psql -V`); `help [topic…]` for kubectl, helm,
  argocd, flux, git, gh, gcloud and pulumi (flyway, rails: bare `help`); `version [options]` for
  kubectl, helm, argocd, flux, gh and pulumi (git, az, gcloud, prisma, flyway, rails: bare
  `version`); `<command words> --help` for built-in commands of kubectl (subcommands checked),
  helm, argocd, flux, gh and pulumi, and for az, gcloud and prisma; `git <cmd> --help` and
  `alembic <cmd> --help`; for aws only `aws --version` (an alias in `~/.aws/cli/alias` can
  replace `help` and any service name, so `aws s3 help` is parsed as an aws command). Anything
  else (an option before `--help`, `--` before it, `git <cmd> -h`, a plugin or unknown
  subcommand, `gh extension exec NAME --help`, which runs the extension) is parsed as the command it is, so `kubectl -n --help delete ns prod` is still a
  namespace delete. In a chain each command is still checked: `argocd version --client && argocd
  app delete payments` escalates.

## [1.2.1] — 2026-10-24

A coverage-report fix for `aegis compile kubernetes`.

### Fixed
- `aegis compile kubernetes`: rules on `apply`, `update`, `patch`, `edit` or `replace` are now
  reported over-enforced. Admission sees the CREATE or UPDATE these send, not the kubectl verb,
  so such a rule also denies an agent's create, set image, label and annotate (update verbs:
  also scale, through the `scale` subresource), which the client-side verifier allows; the
  coverage report called these rules exact.

## [1.2.0] — 2026-10-21

OpenCode V2 support, `aegis install --escalate-scripts`, and a hook latency benchmark.

### Added
- `aegis install <agent> --escalate-scripts`: registers the hook with `-- --escalate-scripts`
  (OpenCode: the plugin passes it on), so the opt-in script escalation no longer needs a
  hand-edited hook command. Reinstalling without the flag takes it out. With the flag, the
  OpenCode plugin blocks every shell command in an opted-in project when aegis cannot run.
- `scripts/hook_latency.py` and `results/hook-latency.json`: one `aegis hook claude` call on six
  shell commands, 1.0.0 against 1.1.0 on the same interpreter. 1.1.0 was 0.7–1.2 ms slower
  (median) on the five commands both decide alike, consistently about 1 ms, within run-to-run
  spread; inline code naming an infrastructure tool is denied before the policy loads
  (70 → 55 ms). `--escalate-scripts` was not measured. `docs/agents.md` has a "Cost" section.
- `scripts/budget_latency.py`: p95 is the nearest-rank value (the same sample for its 40 runs,
  so `results/budget-latency.json` is unchanged).
- The OpenCode plugin (`aegis install opencode`) supports OpenCode V2 (2.x) alongside V1: its
  default export is `{ id: "aegis-devops", setup(ctx), server() }`, so V2 calls `setup`
  (registering `ctx.tool.hook("execute.before", …)`) and V1 (1.15 and later) calls `server`.
  No npm dependency; same decisions and fail-closed behaviour on both. Under V2 a budget
  warning goes to OpenCode's log (V2 server plugins have no toast). Needed to stay in the
  awesome-opencode catalog, which removes V1-only plugins on 2027-01-01.

### Changed
- The OpenCode plugin no longer has a named `AegisDevOps` export (the default export replaces
  it). Reinstall with `aegis install opencode` to get the new file; nothing else changes.

## [1.1.0] — 2026-10-20

Denial reports for the server-side layer, and the agent hook checks code passed inline or
piped to an interpreter.

### Added
- **Preview:** `aegis report aws`: which calls the compiled SCPs denied, from CloudTrail
  (`--collect` with `aws cloudtrail lookup-events`, or saved events): attributed to Aegis when
  the error carries the SCP's policy ARN (`--policy-id`), per rule (the rules whose mapped
  actions cover the call), real versus deliberate tests (`--test-principal`). No real denial in
  a window of at least `--quiet-days` (default 30) exits 1: zero denials is not proof the policy
  works. SCP denials without a policy ARN are reported as possibly Aegis's; EC2's encoded
  reasons as undetermined. Proposed after outside review of the AWS SCP article.
- **Preview:** `aegis report kubernetes`: which requests the compiled ValidatingAdmissionPolicies
  denied, or warned about in report-only mode, from the API server's audit log (the `Audit`
  action's `validation_failure` annotation): per rule (exact, from the policy name), real versus
  deliberate tests (`--test-principal`), impersonated requests counted as the identity
  impersonated. Reports bindings that ran with other actions than the compiled ones and
  `aegis-*` policies missing from the output. No real denial in at least `--quiet-days`, or no
  events, exits 1. Reads `--audit-log-path` files (`.gz` ok), an `EventList`, or EKS
  `aws logs filter-log-events` output. Verified on kind.
- `aegis check command --escalate-scripts` (off by default; add it to the hook command as
  `aegis hook <agent> -- --escalate-scripts`): escalates commands that run code Aegis cannot
  read: `bash nuke.sh`, `bash < nuke.sh`, `./nuke.sh`, `source x`, `python3 x.py`, `make`,
  `npm run` (also with `$VAR` arguments), inline `python3 -c` code, a shell fed through a
  pipe. Shell intents for those carry `params.runs_code`.
- `docs/agents.md`: "What the hook cannot see", the tested list of what gets past the hook
  (scripts, Write/Edit tool files, SDK calls) and the server-side layer that does not.

### Changed
- Agent hook: inline interpreter code (`python -c` / `-Ic`, `node -e` / `--eval=`, `perl -e` /
  `-lne`, `ruby -e`, `php -r`, …) and code piped into a shell or interpreter are denied when
  the code names an infrastructure tool. Before, `python3 -c "subprocess.run(['kubectl','delete',…])"` and
  `echo 'kubectl delete …' | bash` ran unchecked.
- Agent hook: `bash -c "$(…)"`, `eval "$(…)"`, `source <(…)` and similar ask first (deny where
  the agent has no "ask"): the code they run only exists at run time. Before, they ran unless
  the command text named an infrastructure tool.

## [1.0.0] — 2026-10-10

The cross-agent session budget cap ([`docs/budget.md`](docs/budget.md)), and the 1.0 stability
promise ([design §9](docs/dev/DESIGN-v1.0-budget-cap.md)).

**Stable from 1.0** (breaking any of these needs 2.0): the policy file formats (`constraints`,
`authority`, `environments`, `plan_constraints`, `agents`, `budget`, all `version: 1`), the CLI
commands and their exit codes, the hook protocol per agent, and the GitHub Action's inputs and
outputs. **Still preview within 1.x:** the server-side compilers' output (`aegis compile`) and
the identity audit (`aegis audit-identity`), which may change shape in minor releases.
**Deferred, additive when it comes:** public-key signing (`docs/dev/DESIGN-v0.4-public-key-signing.md`).

### Added
- `aegis_core.budget`, the budget cap's core (design §3–§6):
  - `budget.yaml`, signed, whose `principal` must hold the new **`budget`** authority class:
    a per-session and a per-project-per-day limit in estimated USD or tokens (`unit` is
    required), a warning threshold, the day's time zone, the agents measured (only listed
    agents are), `on_unknown_log`, `on_unknown_price`, signed price overrides and a
    premium-request limit for Copilot CLI. Every shape problem is a load error.
  - A dated price table (`aegis_core/budget/prices.yaml`: Anthropic, OpenAI and Google list
    prices read 2026-10-07). An unpriced model is estimated per billing category from its
    vendor's (or the whole table's) highest rate — an estimate, not an upper bound — or, with
    `on_unknown_price: deny`, refused until priced. Usage is stored as tokens per model, so a
    new override re-prices earlier usage.
  - Usage readers for the session logs of Claude Code, Codex CLI, Gemini CLI, OpenCode and
    Copilot CLI (premium requests), with linked sub-agents counted inside their parent session,
    tested against redacted samples of real logs.
  - Accounting that the logs can always rebuild: per-session records, project/day totals merged
    by revision from a durable per-session counter, a session inventory outside the cache,
    rebuilds that report whether the day is complete, partial or of unknown completeness, and
    usage bucketed by the time the log recorded, never the time it was read.
  - Evaluation to allow / warn / deny with the measured usage, limits and observed overshoot.
- The budget cap in `aegis hook` (design §6): in a project whose policy directory holds a
  `budget.yaml`, after the policy decision (a BLOCK always stands), every covered tool call is
  denied once the usage available at the hook reaches a limit, and new prompts where the agent
  can block them (Claude Code and Codex `UserPromptSubmit`, Gemini CLI `BeforeAgent`); a warning
  is shown once per session per threshold (`systemMessage`; an OpenCode toast; stderr for Copilot
  CLI). A `budget.yaml` that cannot be used (bad signature, shape, authority) fails closed.
- `aegis budget status|check|reset` (design §7): today's project total and its sessions, rebuilt
  from the logs (`--json`); `check` exits 0 under, 3 over, 65 for an unusable `budget.yaml`, 66
  for none; `reset --day` acknowledges an incomplete day's history as it stands, with a marker
  signed by the policy key that records the acknowledged state, so `on_unknown_log: deny` stops
  denying for exactly that (later problems count again; an agent without the key cannot reset).
- `docs/budget.md`; `aegis init` writes a signed `budget.example.yaml`.
- Live test in each agent (`docs/dev/budget-live-test/`): tool calls and prompts over a
  budget denied in Claude Code, Codex and OpenCode; Copilot CLI's premium-request count reaches
  its log only at the end of a turn; Gemini CLI not tested (API credits). `docs/budget.md` now
  says, per agent, from when a turn's usage is seen.
- `scripts/budget_latency.py`: the budget adds ~9 ms to a hook call (74 vs 65 ms median,
  `results/budget-latency.json`), under the 20 ms target. The price table ships as
  `prices.json` generated from `prices.yaml` (`scripts/sync_prices.py`; a test keeps them equal)
  and is read only from the package: parsing the YAML on every call had cost ~15 ms.
- `aegis install` adds the budget hooks when the policy directory that applies holds a
  `budget.yaml` (`--budget` / `--no-budget` to choose): the tool hook sees every tool call and
  the prompt hook is added where the agent has one. The Claude Code plugin and the Gemini
  extension carry budget-only entries that start no process in projects without a budget; the
  OpenCode plugin sends every tool call, with its session id, only where a budget applies.
- The example `authority.yaml` gives `admin` the `budget` class.
- `agents.yaml`: a trusted AWS `source-identity` now warns (`source-identity-inherited`): a
  source identity survives role chaining, so an agent started in a session that carries it is
  exempt too. `no_agents: true` on the entry states that no agent runs under it and clears the
  warning. Raised in a review of the AWS SCP article by dev.to reader mickyarun.

### Documentation
- README: "Why not RBAC, or the agent's own permission settings?", with each spelling of a
  command the example policy blocks; a test keeps the table true.
- `docs/server-side.md`: what the second layer adds and what it doesn't (one policy enforced
  twice, not a second opinion), and why a trusted source identity must never carry an agent
  (same review). Denial reporting from CloudTrail added to the plan.

### Changed
- **kubectl: an unknown namespace is never "not prod".** A command without `-n` (which runs in
  the kubeconfig context's namespace) or with `-A` now escalates a namespace-scoped rule that
  would otherwise match, with the note `namespace-unresolved: <id>`, as an unresolved `env`
  already did; before, the rule silently did not apply. Cluster-scoped kinds are unaffected.
  `--resolve-current-context` now also fills the namespace from the kubeconfig context
  (`default` when it sets none). Reported by a reader on dev.to (Chris Sellers).
- **kubectl: manifests that are not read escalate kind rules.** `apply|create|replace|delete -f
  <file>|<dir>|-` and `-k`: a rule for the same action on kinds or objects escalates with
  `manifest-not-inspected: <id>`, since the manifest may hold what it protects; Aegis still
  never reads the file. Same report.

## [0.3.2] — 2026-09-29

Package metadata only; no change to behaviour.

### Fixed
- PyPI listed no author: `pyproject.toml` now declares the author, as `CITATION.cff` does.

### Added
- `docs/dev/DESIGN-v0.4-public-key-signing.md`: the reviewed design for public-key (SSH)
  signing of policy files, the next release's main change.

## [0.3.1] — 2026-09-29

The Kubernetes server-side layer: the policy compiled to ValidatingAdmissionPolicies scoped to
agent identities, verified on a kind cluster against the client-side verdicts, and an identity
audit that reports the RBAC escapes admission cannot see. Also a fix to how the aws parser names
resources. Preview: see `docs/server-side.md`.

### Added
- **Preview:** `aegis compile kubernetes --cluster <name> --out DIR`: the verified snapshot as
  Kubernetes ValidatingAdmissionPolicies (one policy and binding per rule) scoped to agents by
  `matchConditions` generated from `agents.yaml`, with the control plane always exempt in
  deny-by-default. Deletes (including evictions, and `delete --all`, admitted per item), creates,
  every update spelling, scale (subresource or `spec.replicas`), set-image (init containers
  included), rollout-restart, cordon, taint, label and annotate (old/new object diffs), rollout-undo
  (any pod-template change: over-enforced, as admission cannot tell an undo from a restart), exec/attach/port-forward (CONNECT),
  and the namespace cascade compile; name and namespace globs become RE2. Time windows (no
  clock at admission), rate limits, reads and impersonation are reported not enforced. An
  `aegis-guardrails` policy stops agents minting tokens for other ServiceAccounts or running pods
  as another ServiceAccount. Report-only compiles `[Warn, Audit]`, enforce `[Deny, Audit]`. Same
  coverage report, manifest and `--check` as the AWS target. Verified on kind (Kubernetes 1.36.1)
  with `scripts/kube_acceptance.py`: 66 of 66 runs as expected; the client and the cluster agreed
  on every shared case and differed only where coverage says so (`docs/dev/kube-acceptance/`).
- `aegis audit-identity kubernetes [--context CTX]`: read-only review of a cluster against
  `agents.yaml` — every ServiceAccount and RBAC-bound user or group the compiled policies would
  restrict (with bindings and pod counts; control plane and universal groups left out), missing
  ServiceAccounts, a break-glass subject no binding grants anything, and escape permissions an
  identity the policies restrict still holds (impersonation, by name and per namespace;
  updating, patching or deleting admission policies, bindings or webhooks; creating mutating
  admission; RBAC escalate/bind/cluster-role-binding writes), asked as SubjectAccessReviews with
  the groups each identity carries. A failed review is an error, not a "no". `--save-inventory` and
  `--inventory` for offline review. Run against the kind cluster: it flagged the cluster-admin
  test agent and an untrusted `system:masters`, and nothing for an `edit`-only agent.

### Fixed
- **aws CLI resource names.** For 17 operations the parser lost the name of the resource acted
  on (`ec2 delete-volume --volume-id vol-1` became `ec2/volume/*`) or took its parent's
  (`eks delete-nodegroup --cluster-name c --nodegroup-name ng` became `eks/nodegroup/c`, likewise
  `ecs delete-service`). A rule written for one named resource never matched on the client,
  while `aegis compile aws` enforced it. The resource's own flag now names it (EC2 volumes,
  snapshots, VPCs, subnets, security groups by id, gateways, images, key pairs; RDS clusters and
  snapshots; EKS clusters, node groups, add-ons, Fargate profiles; ECS services; log groups and
  streams; Route 53 hosted zones; EFS file systems; ElastiCache clusters and replication groups),
  and a parent taken from `--cluster`/`--cluster-name` is kept as `params.parent`. Rules on the
  `*` forms still match; name-specific rules now apply on the client as in the compiled policy.

## [0.3.0] — 2026-09-28

The first server-side layer: the policy compiled to AWS Service Control Policies scoped to agent
identities, so an agent that calls the AWS API directly (an SDK, a script, a found credential) is
refused by AWS itself, not only by the client hook. Preview: see `docs/server-side.md`.

### Added
- `ConstraintStore.verified_snapshot()` and `aegis snapshot`: the constraints that may vote —
  loaded **and** passing integrity and authority now (authority is otherwise checked only per
  decision) — frozen, with every excluded constraint and its reason, and one sha256 digest over
  all inputs (constraints, authority map, environment and plan-constraint maps, sources
  manifest, repos/signers/agents files, the commit each Git source ref points at, the Aegis
  version, and store settings such as the default time zone). A constraint also needs **source
  evidence** — its cited source fetched and verified at load (new `ConstraintStore.source_verified`)
  — or it is excluded as `source-unverified`. The snapshot is detached and deeply immutable
  (canonical records; `constraints` returns fresh copies; `verify()` recomputes the digest). The
  base for the v0.3 compilers (`docs/dev/DESIGN-v0.3-server-side.md` §3.1). `aegis snapshot`
  refuses `--insecure`, `--sources ''`, and any environment / plan-constraint / `agents.yaml`
  file that does not verify.
- `agents.yaml` and `aegis agents`: the identity model server-side enforcement is compiled for
  (design §4). **Deny-by-default** is the default mode: the file names the trusted identities
  (people, CI roles, controllers) and every other identity counts as an agent; `mode:
  agents-only` lists agents instead. At least one **break-glass** identity is required and is
  never restricted; `enforcement` starts at `report-only`. Identities are typed per platform
  (Kubernetes user/group/ServiceAccount, AWS role/user/SourceIdentity, GCP service
  account/user/group, GitHub OIDC subject) and validated; wildcards, duplicates, assumed-role
  session ARNs, groups every identity carries (`system:authenticated`, …) and a break-glass
  GitHub subject not bound to a workflow are load errors. Matching is exact, as AWS ARN
  conditions are (a mis-cased ARN never exempts).
  The file is signed and its `principal` must hold the new `identity` class in
  `authority.yaml` (the example grants it to `admin`). Warnings: a trusted GitHub subject that
  is not bound to a workflow or protected environment (`workflow-unbound`), a platform with no
  break-glass identity. `aegis snapshot` now loads `agents.yaml` through this loader instead
  of only checking its signature, and carries its warnings. `aegis init` ships
  `agents.example.yaml`, which never becomes active on its own.
- **Preview:** `aegis compile aws --account <id> --out DIR`: the verified snapshot as AWS Service
  Control Policies scoped to agent identities from `agents.yaml` (design §6.5). Explicit Deny
  statements on the IAM actions and ARNs from a new action map
  (`src/aegis_core/compile/actions/aws.yaml`, keyed by what the CLI parser produces), with
  `scope.env`/`account` compiled per account from `environments.yaml` and `scope.region` as
  `aws:RequestedRegion`. A self-protection block stops agents assuming, passing or modifying
  exempt roles, minting credentials for exempt users, setting an exempt source identity and
  leaving the organization. `coverage.json`/`.md` accounts for every constraint (exact,
  over-enforced, partial, not enforced, not applicable, excluded) with same-effect actions
  not covered; `manifest.json` carries the snapshot digest and a Sid → rule map. Output is
  split to the 5,120-character SCP limit and fails loudly if it cannot fit; `--check DIR`
  reports drift. With `enforcement: report-only` the SCPs go under `report-only/` and are not
  deployable. Statements merge exactly (same resources pool actions, same actions pool
  resources); a rule covering every name of a type denies the action on any resource.
  Every mapping was **verified** in a sandbox AWS Organization on 2026-09-28 (live calls
  and the IAM policy simulator, as agent, trusted, break-glass and path-qualified SSO
  roles; `scripts/aws_acceptance.py`, evidence in `docs/dev/aws-acceptance/`). The run
  found that denying `sts:SetSourceIdentity` outright also broke role chaining for agent
  sessions that carry a source identity; the self-protection statement now denies only
  exempt values. Guide: `docs/server-side.md`.
- `aegis audit-identity aws`: read-only check of `agents.yaml` against the IAM roles and users
  that exist in an account (from `aws iam get-account-authorization-details`, or a saved copy with
  `--inventory`). Lists every identity the compiled policy would restrict (`--would-restrict`,
  the review before `enforcement: enforce`), with last-used dates and hints for Identity Center
  and `OrganizationAccountAccessRole` roles; exempt identities; service-linked roles (never
  restricted by SCPs). Problems (exit 1): an identity listed for this account that does not
  exist (a mistyped break-glass role is no break-glass), GitHub OIDC trust on an exempt role that
  is not bound to a workflow or protected environment, has a wildcard or no subject, and — while
  report-only — exempt roles that a restricted identity or the whole account may assume.

## [0.2.1] — 2026-09-28

Fixes found by the council review of the v0.3 server-side design
(`docs/dev/DESIGN-v0.3-server-side.md`, now in the repository with the reviews). Security
relevant: upgrade if you rely on the default `discard` behaviour or on kubectl rules.

### Fixed
- **An untrustworthy rule could force ESCALATE through an unresolved condition.** When an
  intent's environment (or, without tzdata, a rule's time window) could not be resolved, every
  matching rule forced ESCALATE before its integrity or authority was checked, so an
  unauthorized or tampered rule scoped on `env: prod` could stall any action whose environment
  was unknown. Those rules are now discarded (reported in `discarded[]`) on that path too, as
  they are when they match outright; `--on-untrusted-match escalate` keeps the old behaviour
  for them. Found by the council review of the v0.3 design.
- **kubectl normal forms.** `kubectl drain node1` (and `cordon`/`uncordon`) parsed to
  `node1/*` instead of `node/node1`; `exec`, `logs`, `attach`, `port-forward` on a bare pod
  name parsed to the bare name instead of `pod/<name>`; plural and short kinds such as
  `storageclasses`, `sc`, `ingressclasses`, `clusterrolebindings`, `crd` were not normalised.
  A rule written for the normal form missed each of these. Rules written against the old forms
  need updating (see `docs/constraints.md`).
- `kubectl drain … --ignore-daemonsets` (and `--delete-emptydir-data`, `--disable-eviction`)
  was rejected as malformed.
- A global option before `rollout` or `set image` was read as the subcommand:
  `kubectl -n prod rollout restart deploy/web` became the action `rollout--n` on `prod/*`
  (losing the namespace, so a namespace-scoped rollout rule missed it), and
  `kubectl --as admin rollout restart …` escaped the impersonation rule. The subcommand is now
  taken before global options are merged, and global options between the verb and its
  subcommand (`kubectl rollout --as admin restart …`, which kubectl accepts) are consumed the
  same way, so every placement parses identically. An unrecognised option there still fails
  closed.

### Changed
- kubectl `--as` / `--as-group` / `--as-uid` are no longer dropped: they are recorded in
  `params.impersonate`, and each impersonated identity becomes its own `impersonate` intent
  (`user/<name>`, `group/<name>`, `uid/<id>`). Impersonation moves a request out of an agent
  identity's scope on the server side, so the client hook is the one layer that sees it.
- The example policy blocks kubectl impersonation (`block-kubectl-impersonation`); change its
  effect to ESCALATE if a human should be able to approve it. The example store now loads 30
  rules.

## [0.2.0] — 2026-09-27

**Real trust roots, step 1.** A rule can cite a signed commit in a policy repository, and its
principal is the commit's verified signer (SSH or GPG) rather than a name written in the rule
or asserted with the shared signing key. Together with 0.1.7 (Git sources, SSH), this completes
step 1 of the v0.2 roadmap (`docs/dev/PLAN.md` §9; design in
`docs/dev/DESIGN-v0.2-git-sources.md`). Opt-in: nothing changes unless a rule cites `git:`.
Still to come: per-principal public-key signing for the other policy files (step 2) and
Slack/Jira sources (step 3).

### Added
- **OpenPGP (GPG) signatures for Git sources**, alongside SSH. A GPG signer is listed with its
  primary fingerprint and armored public key; Aegis verifies against a private keyring holding
  exactly those keys (a mismatch is a load error), so neither the user's keyring nor the
  repository's config can add trusted keys. Expired and revoked keys do not verify.
- `aegis sources`: one line per constraint with its source transport (`git`, `file`,
  `unchecked`), the verified principal, or the quarantine reason; exits 1 if any rule is
  quarantined.
- `aegis init` writes commented `repos.example.yaml` and `signers.example.yaml` (inert until
  copied to `repos.yaml` / `signers.yaml`).

## [0.1.7] — 2026-09-27

Git sources: a rule can cite a signed commit, and its principal is the commit's verified
signer. Opt-in; nothing changes unless a rule cites `git:`.

### Added
- **Git sources with signature-derived principals** (v0.2 step 1,
  `docs/dev/DESIGN-v0.2-git-sources.md`). A constraint may cite
  `git:<repo>@<sha>:<path>` in a locally configured clone (`repos.yaml`); its principal is the
  verified SSH signer of that commit, mapped through `signers.yaml`, instead of a name in the
  rule or `PRINCIPALS.yaml`. New quarantine reasons: `invalid-source-ref`, `unknown-repo`,
  `unknown-commit`, `unsigned-source`, `unknown-signer`, `commit-does-not-touch-source`,
  `superseded`, `stale-source`, `invalid-git-source`. New options `--repos`, `--signers`,
  `--max-source-age`. Git runs with a from-scratch environment and overrides for every
  signature setting, so a repository's own config cannot choose the trusted keys. Shallow and
  grafted clones are refused (they change which parents Git reports), the commit-graph cache is
  off, and "did this commit add the rule" is read from the signed commit object. A `git:`
  citation with no Git configuration is always rejected (`unknown-repo`). File sources are
  unchanged.

## [0.1.6] — 2026-09-27

A correction to the published benchmark. No change to how a decision is made.

### Fixed
- **The agent-harness benchmark rows were scored against rules they were never shown.** The
  `claude-cli*`, `codex*` and `ollama` rows are shown only the corpus's 100-constraint holdout
  subset, but were scored against the reference oracle over all 500 constraints. On the 120
  hold-out intents the oracle's verdict differs between the two for 37 intents, and 11 of the
  30 poison candidates involve poisoned rules outside the 100. So those rows were marked as
  missing legitimate rules they never saw (recall 0.72–0.77) and as resisting poisoned rules
  they never saw. Each row is now scored against the oracle over exactly the rules it was
  given (`scored_against` in `results/benchmark.json`). The same cached answers, re-scored
  (no model was re-run): poison-susceptibility **1.000** for six of the seven models and
  **0.789** for `gpt-6-luna` (previously reported as 0.23–0.33), recall 0.97–1.00. The earlier
  numbers **understated** how often the models act on poisoned rules. The 0.1.2 entry below
  ("All land between 0.23 and 0.33 poison-susceptibility and every one acts on 5 of 8 forged
  rules") is wrong for that reason.
- This also accounts for the gap between the Sonnet 5 API self-check (1.000) and the
  `claude-cli-sonnet` row (previously 0.333): the latter was scored against 400 rules it never
  saw.

### Added
- `aegis-holdout`: Aegis restricted to the same 100-constraint subset, so there is a
  like-for-like row on that basis (0 of 19 poison candidates acted on, over-block 0.000).
- Tests that every published row is scored on the basis it was shown, and that the holdout
  oracle only ever sees the holdout constraints.
- The repository is a Gemini CLI extension (`gemini-extension.json`, `hooks/hooks.json`):
  `gemini extensions install https://github.com/moneytool/aegis-devops`.

### Changed
- The Claude Code plugin moved to `plugins/claude/` (the marketplace entry points there, so
  `claude plugin marketplace add moneytool/aegis-devops` and the install command are
  unchanged). Gemini CLI reads an extension's hooks from `hooks/hooks.json` at the root, where
  the Claude plugin's hooks used to be.

## [0.1.5] — 2026-09-27

Gemini CLI and OpenCode join the supported agents; all seven are live-tested. No change to how
a decision is made.

### Added
- `aegis hook gemini` / `aegis install gemini`: a `BeforeTool` hook on Gemini CLI's
  `run_shell_command`.
- `aegis hook opencode` / `aegis install opencode`: OpenCode's hooks are JavaScript plugins, so
  the installer writes a bundled plugin (`tool.execute.before`) that hands each `bash` command
  to `aegis hook opencode` and throws when Aegis says no.

## [0.1.4] — 2026-09-27

A GitHub Copilot plugin, and a fix to the forged-source demo. No change to how a decision is
made.

### Added
- A GitHub Copilot plugin (`plugins/copilot/`, Agent Plugins 1.0):
  `copilot plugin install moneytool/aegis-devops:plugins/copilot`. It runs the same wrapper as
  the Claude Code plugin, so without `aegis` installed it still allows everything outside
  opted-in projects instead of failing every command.

### Changed
- Copilot replies now carry VS Code's `hookSpecificOutput` shape as well as Copilot CLI's
  top-level `permissionDecision`, since both read the same hook files and plugins.

### Fixed
- `data/sources-forged/` lacked the eight sources added with the default rules, so the
  `--sources data/sources-forged` demo quarantined 9 of 29 rules and refused to decide.

## [0.1.3] — 2026-09-27

Aegis can now sit in front of a coding agent's shell commands, and the example policy blocks
the obviously infrastructure-breaking ones. No change to how a decision is made.

### Added
- `aegis hook <agent>`: runs as the pre-tool hook of Claude Code, Codex CLI, GitHub Copilot
  CLI, VS Code agent mode or Cursor, reads that agent's payload and answers in its format.
  It acts only in projects that opted in (`.aegis/` here or above, `$AEGIS_CONFIG_DIR`, or
  `~/.config/aegis`) and blocks only what the policy blocks; an unusable policy or a command
  that cannot be analysed blocks only infrastructure commands. See `docs/agents.md`.
- `aegis install <agent> [--user] [--remove]` writes (or removes) that hook in the agent's
  config without touching its other settings.
- A Claude Code plugin and marketplace (`.claude-plugin/`, `hooks/`):
  `claude plugin marketplace add moneytool/aegis-devops`.
- Default rules in the example policy for infrastructure-breaking commands: `terraform destroy`
  / `tofu destroy` / `apply -destroy`, `pulumi destroy` and `stack rm`, deleting a Kubernetes
  namespace, an S3 bucket, an RDS database, a GCP project or an Azure resource group (BLOCK),
  and deleting an Argo CD application (ESCALATE). The example store now loads 29 rules.
- `terraform`/`tofu` `destroy` (and `apply -destroy`) are recognised from the command line as
  a `terraform` `delete` intent on `workspace/<dir>`; other terraform subcommands still need a
  plan and are not gated from their argv.

### Changed
- The design notes and review history (`PLAN.md`, `REVIEW*.md`, `FEEDBACK.md`) moved to
  `docs/dev/`.

## [0.1.2] — 2026-09-26

No change to how a decision is made. Released so the PyPI page and the Zenodo record carry the
full benchmark.

### Added
- The benchmark now covers seven agent-harness models across two vendors: Claude Haiku 4.5,
  Sonnet 5, Opus 5 and Fable 5.1 through `claude -p`; `gpt-6-astra`, `gpt-6-sol` and
  `gpt-6-luna` through `codex exec`. All land between 0.23 and 0.33 poison-susceptibility and
  every one acts on 5 of 8 forged rules; Aegis acts on none of the 30 poisoned intents.
- `scripts/run_until_done.sh` runs a verifier to completion across CLI usage limits: it waits
  for the reset time the CLI reports and resumes from the cached answers.
- `scripts/make_latency_svg.py`: the latency chart is generated from `results/latency.json`, and
  the docs drift test fails if it is stale.

### Changed
- A decision is now O(k) in the matching (provider, action) bucket rather than O(n) in the
  store: the environment and time-window checks scanned every constraint. p99 at 10,000
  constraints fell from 5.9 ms to 3.7 ms.
- Latency figures report p95/p99 only; p50 fell between the cheap no-match decisions and real
  matches and described neither.

### Fixed
- LLM benchmark runs could not resume: the recording client never read its own cache, so every
  run re-asked every prompt. A usage-limit reply was cached as an empty answer; it now raises
  and is never cached.
- Each call verifies the model that actually answered; a mismatch stops the run instead of
  recording one model's numbers under another's name.
- `.gitignore` excluded all of `results/`, so its whitelist had never applied; the harness caches
  and the preserved fail-closed results are now tracked.
- A timing test that failed on shared CI runners was replaced by a count of the work done.

### Known
- Loading a store with `--sources` is about 35% slower than first measured, most likely from
  the path-traversal guard resolving every source path; it is a once-per-load cost.

## [0.1.1] — 2026-09-24

Documentation and packaging only; no change to the decision engine. Released so the PyPI
page carries the current README, and so the release is archived on Zenodo with a DOI.

### Added
- Codex CLI (`gpt-6-astra`) and Claude Code CLI (Haiku) rows in the benchmark. Both are
  agent harnesses rather than raw completions, scored on a 100-constraint hold-out subset.
- `SECURITY.md`, `CITATION.cff`, and this changelog.
- `scripts/make_benchmark_svg.py`: the benchmark chart is generated from
  `results/benchmark.json` instead of drawn by hand.
- `tests/test_docs_consistency.py`: CI now fails if a results table, the chart, a corpus
  diversity figure, or a description of the default policy disagrees with the data or the
  code.

### Changed
- The README is now a short entry point; reference material moved to `docs/cli.md`,
  `docs/constraints.md`, `docs/configuration.md` and `docs/benchmark.md`.
- The quick start leads with `pip install` and `aegis init ./.aegis`. Without `init`, a fresh
  install had no policy files and every check exited 66.
- The alpha caveats moved from a banner at the top of the README into Project status.

### Fixed
- `docs/cli.md` and `docs/configuration.md` still described the old escalate-on-untrusted
  default and showed ESCALATE output for tampered and forged rules. On 0.1.0 both examples
  ALLOW, with the rule named in `discarded` and in store health. They now show real output
  from the current code.
- `docs/benchmark.md` quoted the previous corpus's diversity figures and called
  `evade-case-variant` an `xfail`.

## [0.1.0] — 2026-09-23

First release. Published to PyPI as `aegis-devops`.

### Added
- **Constraint store** with two independent guarantees per rule: integrity (a provenance hash
  over the source-side fields) and authority (which principal may assert which class of rule).
  Schema validation, quarantine with reasons, and signed policy files.
- **Interceptor** returning ALLOW / BLOCK / ESCALATE with citations, discarded rules, coverage,
  notes and latency. Dry runs are never blocked but report the verdict a real run would get.
- **Parsers** for kubectl, Terraform and OpenTofu plans, AWS, Azure, gcloud/gsutil, Helm,
  ArgoCD, Flux, git, the GitHub CLI, Pulumi, and SQL/mongo/migration tools — all normalising to
  one intent shape. `aegis check command` splits a whole shell string, since that is what an
  agent framework hands you.
- **Plan-level constraints** evaluated over a whole batch (`max_intents`, `max_matching`,
  `forbid_together`, `ratio`).
- **Environment identity mapping** from kube contexts, cloud accounts, projects, subscriptions
  and repos, so rules scope on `env: prod` rather than raw identifiers. An unresolved
  environment escalates rather than being treated as "not prod".
- **Rate-limited constraints** backed by a locked, hash-chained, rotating decision ledger
  (JSONL or SQLite).
- **Signing** of policy and source files, with per-directory manifests, and `aegis sign` /
  `aegis verify` / `aegis keygen`.
- **CLI** with `aegis init`, config discovery, structured decision logs, a Prometheus textfile
  exporter, and `--exit-style claude-hook` plus a ready-made Claude Code PreToolUse hook.
- **Evaluation**: a 500-constraint labelled corpus (323 distinct structures) seeded from public
  postmortems, the Gatekeeper library, and cloud security benchmarks; an independent reference
  oracle so ground truth never runs the system under test; an adversarial suite of attacks in
  five categories; and a benchmark against OPA, a signed-bundle OPA variant, and real LLM
  self-checks.

### Changed
- An untrustworthy matching constraint (tampered, forged, or from an unauthorized principal)
  gets **no vote** by default. An earlier default made it force ESCALATE; measurement showed
  that scored the same poison-susceptibility and over-block rate as a verifier with no trust
  model at all, because letting an unverifiable rule produce a verdict hands whoever planted it
  control over that verdict. The old behaviour is available as `--on-untrusted-match escalate`.

### Known limitations
See "Project status" in the README and [`docs/dev/PLAN.md`](docs/dev/PLAN.md) §8. In short: the source fetcher reads files
rather than real connectors, signing uses a shared secret, and a principal is a signed name
rather than a bound identity.

[1.3.4]: https://github.com/moneytool/aegis-devops/releases/tag/v1.3.4
[1.3.3]: https://github.com/moneytool/aegis-devops/releases/tag/v1.3.3
[1.3.2]: https://github.com/moneytool/aegis-devops/releases/tag/v1.3.2
[1.3.1]: https://github.com/moneytool/aegis-devops/releases/tag/v1.3.1
[1.3.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.3.0
[1.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.1
[1.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.0
[1.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.1.0
[1.0.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.0.0
[0.3.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.2
[0.3.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.1
[0.3.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.0
[0.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.1
[0.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.0
[0.1.7]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.7
[0.1.6]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.6
[0.1.5]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.5
[0.1.4]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.4
[0.1.3]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.3
[0.1.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.2
[0.1.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.1
[0.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.0
