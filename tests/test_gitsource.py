"""Git sources with signature-derived principals (docs/dev/DESIGN-v0.2-git-sources.md).

Every test builds a real repository in a temp directory and signs commits
with real SSH keys generated for the test, so nothing depends on the
developer's own keys or Git configuration."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from aegis_core.gitsource import (
    DispatchingSourceFetcher,
    GitSourceFetcher,
    RepoConfig,
    SourceRejected,
    load_repos,
    load_signers,
    parse_git_ref,
)
from aegis_core.provenance import compute_provenance_hash
from aegis_core.store import ConstraintStore

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and shutil.which("ssh-keygen")), reason="needs git and ssh-keygen"
)

AUTHORITY = {"admin": {"deletion", "scaling", "configuration"}, "developer": {"configuration"}}
RULE = {
    "provider": "kubernetes",
    "resource_pattern": "node/*",
    "actions": ["delete"],
    "scope": {},
    "time_window": None,
    "effect": "BLOCK",
    "constraint_class": "deletion",
    "source_timestamp": "2026-09-27T12:00:00+00:00",
    "rule_text": "Never delete cluster nodes directly.",
}


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / "policy"
        self.keys: dict[str, Path] = {}
        # isolate test commits from the developer's own git config
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(var, None)
        self.git("init", "-q", "-b", "main", str(self.path), cwd=root)

    def key(self, name: str) -> Path:
        if name not in self.keys:
            k = self.root / f"{name}_key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f",
                            str(k)], check=True)
            self.keys[name] = k
        return self.keys[name]

    def pub(self, name: str) -> str:
        return (self.key(name).with_suffix(".pub")).read_text().strip()

    def git(self, *args, cwd=None) -> str:
        return subprocess.run(["git", *args], cwd=cwd or self.path, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message: str, signer: str | None, *, allow_empty=False) -> str:
        cfg = ["-c", "user.name=someone", "-c", "user.email=s@example.com"]
        args = ["commit", "-q", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        if signer:
            cfg += ["-c", "gpg.format=ssh", "-c", f"user.signingkey={self.key(signer)}"]
            args.append("-S")
        self.git(*cfg, *args)
        return self.git("rev-parse", "HEAD")

    def write_rule(self, name: str, fields: dict | None = None, raw: str | None = None) -> str:
        (self.path / "rules").mkdir(exist_ok=True)
        p = self.path / "rules" / f"{name}.yaml"
        p.write_text(raw if raw is not None else yaml.safe_dump(fields or RULE, sort_keys=False))
        self.git("add", ".")
        return f"rules/{name}.yaml"


@pytest.fixture
def repo(tmp_path):
    r = Repo(tmp_path)
    r.write_rule("seed", {**RULE, "rule_text": "seed"})
    r.commit("seed", "admin")
    # the tracked ref: a local branch stands in for refs/remotes/origin/main
    return r


def signers(repo: Repo, **principals: str) -> dict[str, str]:
    """name=principal -> {pubkey: principal}"""
    return {" ".join(repo.pub(name).split()[:2]): p for name, p in principals.items()}


def fetcher(repo: Repo, sig: dict[str, str], **kw) -> GitSourceFetcher:
    repos = {"policy": RepoConfig("policy", repo.path, "refs/heads/main")}
    return GitSourceFetcher(repos, sig, **kw)


def ref(sha: str, path: str) -> str:
    return f"git:policy@{sha}:{path}"


def constraint_for(source_ref: str, principal: str, cid="r1", **overrides) -> dict:
    fields = {**RULE, **overrides, "principal": principal, "source_ref": source_ref}
    return {"id": cid, **fields, "provenance_hash": compute_provenance_hash(**fields)}


def load(tmp_path, entries, f) -> ConstraintStore:
    path = tmp_path / "constraints.yaml"
    path.write_text(yaml.safe_dump({"constraints": entries}, sort_keys=False))
    return ConstraintStore.load(
        path, AUTHORITY, source_fetcher=DispatchingSourceFetcher(None, f), insecure=True
    )


def reasons(store) -> dict[str, str]:
    return {q["id"]: q["reason"] for q in store.health.quarantined}


# --- verification ---------------------------------------------------------------


def test_signed_commit_backs_the_rule_and_names_the_principal(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("admin adds r1", "admin")
    f = fetcher(repo, signers(repo, admin="admin"))
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")], f)
    assert list(store.constraints) == ["r1"]
    assert reasons(store) == {}
    assert f.principal_for(ref(sha, path)) == "admin"


def test_unsigned_commit(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("unsigned", None)
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "unsigned-source"}


def test_key_not_in_signers(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("mallory", "mallory")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "unknown-signer"}


def test_signer_is_a_different_principal_than_the_rule_claims(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("dev", "dev")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin", dev="developer")))
    assert reasons(store) == {"r1": "principal-mismatch"}


def test_signed_commit_that_does_not_touch_the_rule(repo, tmp_path):
    path = repo.write_rule("r1")
    repo.commit("dev adds r1 unsigned", None)
    unrelated = repo.commit("admin, unrelated", "admin", allow_empty=True)
    store = load(tmp_path, [constraint_for(ref(unrelated, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "commit-does-not-touch-source"}


def test_later_edit_supersedes_and_deletion_revokes(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("admin adds r1", "admin")
    repo.write_rule("r1", {**RULE, "rule_text": "edited"})
    repo.commit("edit", "admin")
    sig = signers(repo, admin="admin")
    assert reasons(load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                        fetcher(repo, sig))) == {"r1": "superseded"}
    repo.git("rm", "-q", path)
    repo.commit("revoke", "admin")
    assert reasons(load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                        fetcher(repo, sig))) == {"r1": "superseded"}


def test_rule_fields_rewritten_after_ingest_are_forged(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("admin adds r1", "admin")
    # the attacker edits the stored constraint and recomputes its own hash
    forged = constraint_for(ref(sha, path), "admin", resource_pattern="node/never-matches")
    store = load(tmp_path, [forged], fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "forged"}


def test_signed_merge_makes_the_merger_the_principal(repo, tmp_path):
    repo.git("checkout", "-q", "-b", "feature")
    path = repo.write_rule("r1")
    repo.commit("dev adds r1 unsigned", None)
    repo.git("checkout", "-q", "main")
    repo.git("-c", "user.name=m", "-c", "user.email=m@x", "-c", "gpg.format=ssh",
             "-c", f"user.signingkey={repo.key('admin')}", "merge", "-q", "--no-ff", "-S",
             "-m", "admin merges r1", "feature")
    merge = repo.git("rev-parse", "HEAD")
    store = load(tmp_path, [constraint_for(ref(merge, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert list(store.constraints) == ["r1"]


def test_unquoted_yaml_timestamp_still_verifies(repo, tmp_path):
    raw = yaml.safe_dump(RULE, sort_keys=False).replace(
        "'2026-09-27T12:00:00+00:00'", "2026-09-27T12:00:00+00:00")
    assert "'" not in raw.split("source_timestamp:")[1].splitlines()[0]
    path = repo.write_rule("r1", raw=raw)
    sha = repo.commit("admin", "admin")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert list(store.constraints) == ["r1"]


def test_rule_file_naming_a_principal_is_invalid(repo, tmp_path):
    path = repo.write_rule("r1", {**RULE, "principal": "admin"})
    sha = repo.commit("admin", "admin")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "invalid-git-source"}


def test_file_outside_the_rule_glob_is_refused(repo, tmp_path):
    (repo.path / "notes.yaml").write_text(yaml.safe_dump(RULE))
    repo.git("add", ".")
    sha = repo.commit("admin", "admin")
    store = load(tmp_path, [constraint_for(ref(sha, "notes.yaml"), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "invalid-source-ref"}


def test_unknown_repo_and_commit(repo, tmp_path):
    f = fetcher(repo, signers(repo, admin="admin"))
    with pytest.raises(SourceRejected) as exc:
        f.fetch(f"git:other@{'a' * 40}:rules/x.yaml")
    assert exc.value.reason == "unknown-repo"
    with pytest.raises(SourceRejected) as exc:
        f.fetch(ref("b" * 40, "rules/x.yaml"))
    assert exc.value.reason == "unknown-commit"


# --- hostile environment and configuration ----------------------------------------


def test_repository_config_cannot_choose_the_trusted_keys(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("mallory", "mallory")
    # the repository's own config vouches for mallory, and swaps the verifier
    evil = tmp_path / "evil_signers"
    evil.write_text(f'admin namespaces="git" {repo.pub("mallory")}\n')
    repo.git("config", "gpg.ssh.allowedSignersFile", str(evil))
    repo.git("config", "gpg.ssh.program", "/usr/bin/true")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "unknown-signer"}


def test_process_environment_cannot_redirect_git(repo, tmp_path, monkeypatch):
    path = repo.write_rule("r1")
    sha = repo.commit("admin", "admin")
    decoy = tmp_path / "decoy"
    subprocess.run(["git", "init", "-q", str(decoy)], check=True)
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'gpg.ssh.program'='/usr/bin/true'")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert list(store.constraints) == ["r1"]


@pytest.mark.parametrize("bad", [
    "git:policy@abc123:rules/x.yaml",                       # abbreviated sha
    "git:policy@main:rules/x.yaml",                         # branch name
    "git:policy@" + "a" * 40 + ":../x.yaml",
    "git:policy@" + "a" * 40 + ":/etc/passwd",
    "git:policy@" + "a" * 40 + ":rules/-x.yaml",
    "git:policy@" + "a" * 40 + ":rules//x.yaml",
    "git:Policy@" + "a" * 40 + ":rules/x.yaml",
    "git:policy@" + "a" * 40,
    "jira-1001",
])
def test_source_ref_grammar(bad):
    with pytest.raises(SourceRejected) as exc:
        parse_git_ref(bad)
    assert exc.value.reason == "invalid-source-ref"


def test_stale_clone_warns_and_max_age_quarantines(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("admin", "admin")
    sig = signers(repo, admin="admin")
    later = __import__("time").time() + 3 * 24 * 3600
    warned = fetcher(repo, sig, now=later)
    assert any("stale git source" in w for w in warned.warnings)
    assert list(load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                     warned).constraints) == ["r1"]
    strict = fetcher(repo, sig, now=later, max_source_age=24 * 3600)
    assert reasons(load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                        strict)) == {"r1": "stale-source"}


def test_configuration_errors_fail_the_load(repo, tmp_path):
    with pytest.raises(ValueError, match="not a git clone"):
        GitSourceFetcher({"policy": RepoConfig("policy", tmp_path, "refs/heads/main")},
                         signers(repo, admin="admin"))
    with pytest.raises(ValueError, match="not a git clone"):
        GitSourceFetcher({"policy": RepoConfig("policy", repo.path, "refs/heads/nope")},
                         signers(repo, admin="admin"))
    dup = tmp_path / "signers.yaml"
    key = repo.pub("admin")
    dup.write_text(yaml.safe_dump({"signers": [
        {"principal": "admin", "keys": [{"type": "ssh", "key": key}]},
        {"principal": "developer", "keys": [{"type": "ssh", "key": key}]},
    ]}))
    with pytest.raises(ValueError, match="listed twice"):
        load_signers(dup, insecure=True)
    gpg = tmp_path / "gpg.yaml"
    gpg.write_text(yaml.safe_dump({"signers": [
        {"principal": "admin", "keys": [{"type": "gpg", "fingerprint": "ABCD"}]}]}))
    with pytest.raises(ValueError, match="only 'type: ssh'"):
        load_signers(gpg, insecure=True)
    repos = tmp_path / "repos.yaml"
    repos.write_text(yaml.safe_dump({"repos": {"policy": {"path": str(repo.path),
                                                          "ref": "main"}}}))
    with pytest.raises(ValueError, match="full ref"):
        load_repos(repos, insecure=True)


def test_mixed_store_file_and_git_sources(repo, tmp_path):
    from aegis_core.provenance import FileSourceFetcher

    path = repo.write_rule("r1")
    sha = repo.commit("admin", "admin")
    sources = tmp_path / "sources"
    sources.mkdir()
    file_fields = {**RULE, "principal": "admin", "source_ref": "jira-1"}
    (sources / "jira-1.json").write_text(__import__("json").dumps(file_fields))
    file_constraint = {"id": "f1", **file_fields,
                       "provenance_hash": compute_provenance_hash(**file_fields)}
    f = DispatchingSourceFetcher(FileSourceFetcher(sources, insecure=True),
                                 fetcher(repo, signers(repo, admin="admin")))
    cpath = tmp_path / "constraints.yaml"
    cpath.write_text(yaml.safe_dump({"constraints": [
        constraint_for(ref(sha, path), "admin"), file_constraint]}, sort_keys=False))
    store = ConstraintStore.load(cpath, AUTHORITY, source_fetcher=f, insecure=True)
    assert sorted(store.constraints) == ["f1", "r1"]


def test_citing_the_authors_commit_stays_current_after_a_merge(repo, tmp_path):
    repo.git("checkout", "-q", "-b", "feature")
    path = repo.write_rule("r1")
    authored = repo.commit("admin authors r1", "admin")
    repo.git("checkout", "-q", "main")
    repo.git("-c", "user.name=m", "-c", "user.email=m@x", "merge", "-q", "--no-ff",
             "-m", "unsigned merge", "feature")
    store = load(tmp_path, [constraint_for(ref(authored, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert list(store.constraints) == ["r1"]


def test_commit_not_on_the_tracked_ref_is_superseded(repo, tmp_path):
    repo.git("checkout", "-q", "-b", "unmerged")
    path = repo.write_rule("r1")
    sha = repo.commit("admin, never merged", "admin")
    repo.git("checkout", "-q", "main")
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")],
                 fetcher(repo, signers(repo, admin="admin")))
    assert reasons(store) == {"r1": "superseded"}


# --- through the CLI ----------------------------------------------------------------


def _cli_setup(repo, tmp_path, signer):
    path = repo.write_rule("r1")
    sha = repo.commit("adds r1", signer)
    conf = tmp_path / "conf"
    conf.mkdir()
    # plus one file-sourced rule, which (with no sources/ dir) is not
    # source-checked, as before git sources existed
    other = {**RULE, "resource_pattern": "namespace/*", "principal": "admin",
             "source_ref": "jira-1"}
    other = {"id": "f1", **other, "provenance_hash": compute_provenance_hash(**other)}
    (conf / "constraints.yaml").write_text(yaml.safe_dump(
        {"constraints": [constraint_for(ref(sha, path), "admin"), other]}, sort_keys=False))
    (conf / "authority.yaml").write_text(yaml.safe_dump(
        {"principals": {k: sorted(v) for k, v in AUTHORITY.items()}}))
    (conf / "repos.yaml").write_text(yaml.safe_dump(
        {"repos": {"policy": {"path": str(repo.path), "ref": "refs/heads/main"}}}))
    (conf / "signers.yaml").write_text(yaml.safe_dump({"signers": [
        {"principal": "admin", "keys": [{"type": "ssh", "key": repo.pub("admin")}]}]}))
    return conf


def _check(conf, capsys):
    import json

    from aegis_core.cli import main

    code = main(["check", "kubectl", "--config-dir", str(conf), "--insecure", "--sources", "",
                 "--plan-constraints", "", "--environments", "", "--max-quarantine-ratio", "1",
                 "--", "kubectl", "delete", "node", "worker-1"])
    out = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    return code, out[0]


def test_cli_blocks_on_a_rule_backed_by_a_signed_commit(repo, tmp_path, capsys):
    conf = _cli_setup(repo, tmp_path, "admin")
    code, line = _check(conf, capsys)
    assert (code, line["decision"]["verdict"], line["decision"]["citations"]) == (3, "BLOCK",
                                                                                  ["r1"])


def test_cli_ignores_a_rule_signed_by_an_unknown_key(repo, tmp_path, capsys):
    conf = _cli_setup(repo, tmp_path, "mallory")
    code, line = _check(conf, capsys)
    assert line["decision"]["verdict"] == "ALLOW"
    assert line["decision"]["discarded"] == [{"id": "r1", "reason": "unknown-signer"}]


def test_cli_repos_without_signers_is_a_data_error(repo, tmp_path, capsys):
    conf = _cli_setup(repo, tmp_path, "admin")
    (conf / "signers.yaml").unlink()
    from aegis_core.cli import main

    code = main(["check", "kubectl", "--config-dir", str(conf), "--insecure", "--sources", "",
                 "--", "kubectl", "get", "pods"])
    assert code == 65
    assert "signers" in capsys.readouterr().err


def test_file_sourced_rules_are_not_source_checked_when_only_git_is_configured(repo, tmp_path):
    fields = {**RULE, "principal": "admin", "source_ref": "jira-1"}
    plain = {"id": "f1", **fields, "provenance_hash": compute_provenance_hash(**fields)}
    store = load(tmp_path, [plain], fetcher(repo, signers(repo, admin="admin")))
    assert list(store.constraints) == ["f1"]


def test_git_failure_quarantines_one_rule_instead_of_failing_the_load(repo, tmp_path,
                                                                      monkeypatch):
    path = repo.write_rule("r1")
    sha = repo.commit("admin", "admin")
    f = fetcher(repo, signers(repo, admin="admin"))
    import aegis_core.gitsource as gs

    def boom(self, *args, check=True):
        raise subprocess.TimeoutExpired(args, 60)

    monkeypatch.setattr(gs._Git, "run", boom)
    store = load(tmp_path, [constraint_for(ref(sha, path), "admin")], f)
    assert reasons(store) == {"r1": "git-error"}


# --- review findings (PR #10): rewritten history and missing configuration ---------


def _unsigned_rule_then_empty_admin_commit(repo):
    path = repo.write_rule("r1")
    repo.commit("dev adds r1 unsigned", None)
    admin = repo.commit("admin, unrelated", "admin", allow_empty=True)
    return path, admin


def test_shallow_clone_is_refused(repo, tmp_path):
    path, admin = _unsigned_rule_then_empty_admin_commit(repo)
    shallow = tmp_path / "shallow"
    repo.git("clone", "-q", "--depth", "1", f"file://{repo.path}", str(shallow), cwd=tmp_path)
    with pytest.raises(ValueError, match="shallow"):
        GitSourceFetcher({"policy": RepoConfig("policy", shallow, "refs/heads/main")},
                         signers(repo, admin="admin"))


def test_grafts_are_refused(repo, tmp_path):
    path, admin = _unsigned_rule_then_empty_admin_commit(repo)
    grafts = repo.path / ".git" / "info" / "grafts"
    grafts.parent.mkdir(exist_ok=True)
    grafts.write_text(admin + "\n")  # pretend the admin commit is a root
    with pytest.raises(ValueError, match="graft"):
        fetcher(repo, signers(repo, admin="admin"))


def test_git_citation_without_git_configuration_is_rejected(repo, tmp_path):
    path = repo.write_rule("r1")
    sha = repo.commit("mallory", "mallory")
    cpath = tmp_path / "constraints.yaml"
    cpath.write_text(yaml.safe_dump(
        {"constraints": [constraint_for(ref(sha, path), "admin")]}, sort_keys=False))
    store = ConstraintStore.load(cpath, AUTHORITY, insecure=True)  # no fetcher at all
    assert reasons(store) == {"r1": "unknown-repo"}


def test_cli_git_citation_without_repos_yaml_is_not_trusted(repo, tmp_path, capsys):
    conf = _cli_setup(repo, tmp_path, "mallory")
    (conf / "repos.yaml").unlink()
    code, line = _check(conf, capsys)
    assert line["decision"]["verdict"] == "ALLOW"
    assert line["decision"]["discarded"] == [{"id": "r1", "reason": "unknown-repo"}]


def test_git_citation_with_only_file_sources_is_unknown_repo(repo, tmp_path, capsys):
    conf = _cli_setup(repo, tmp_path, "admin")
    (conf / "repos.yaml").unlink()
    (conf / "sources").mkdir()
    import json as _json

    # back the file-sourced rule so the store keeps one trusted constraint
    (conf / "sources" / "jira-1.json").write_text(_json.dumps(
        {**RULE, "resource_pattern": "namespace/*", "principal": "admin",
         "source_ref": "jira-1"}))
    from aegis_core.cli import main

    main(["check", "kubectl", "--config-dir", str(conf), "--insecure",
          "--plan-constraints", "", "--environments", "", "--max-quarantine-ratio", "1",
          "--", "kubectl", "delete", "node", "worker-1"])
    import json

    line = json.loads(capsys.readouterr().out.splitlines()[0])
    assert {"id": "r1", "reason": "unknown-repo"} in line["decision"]["discarded"]


# --- aegis sources and aegis init ---------------------------------------------------


def test_sources_report_lists_principals_and_quarantine_reasons(repo, tmp_path, capsys):
    import json

    from aegis_core.cli import main

    conf = _cli_setup(repo, tmp_path, "admin")
    assert main(["sources", "--config-dir", str(conf), "--insecure", "--sources", ""]) == 0
    rows = {r["id"]: r for r in map(json.loads, capsys.readouterr().out.splitlines())}
    assert rows["r1"]["status"] == "ok"
    assert (rows["r1"]["principal"], rows["r1"]["transport"]) == ("admin", "git")
    assert rows["f1"]["transport"] == "unchecked"


def test_sources_report_exits_1_and_names_the_reason(tmp_path, capsys):
    from aegis_core.cli import main

    other = tmp_path / "other"
    other.mkdir()
    r = Repo(other)
    r.write_rule("seed", {**RULE, "rule_text": "seed"})
    r.commit("seed", "admin")
    conf = _cli_setup(r, other, "mallory")
    assert main(["sources", "--config-dir", str(conf), "--insecure", "--sources", "",
                 "--pretty"]) == 1
    out = capsys.readouterr().out
    assert "QUARANTINED (unknown-signer)" in out
    assert "STORE: loaded=1 quarantined=1" in out


def test_init_writes_inert_git_examples(tmp_path, capsys):
    from aegis_core.cli import main

    target = tmp_path / ".aegis"
    main(["init", str(target)])
    assert (target / "repos.example.yaml").exists()
    assert (target / "signers.example.yaml").exists()
    assert not (target / "repos.yaml").exists()  # examples are never loaded
    assert "aegis sources" in capsys.readouterr().out
