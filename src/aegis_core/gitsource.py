"""Git source connector: rules backed by signed commits (v0.2 step 1).

Design and threat model: ``docs/dev/DESIGN-v0.2-git-sources.md``.

A constraint may cite ``git:<repo-id>@<commit-sha>:<path>``. The source is
the file at that commit in a locally configured clone (``repos.yaml``), and
the source's principal is **the verified signer of that commit**, mapped
through the operator's ``signers.yaml`` -- never a name written in the rule,
the file, or the commit's author/committer fields.

A citation is refused (the constraint is quarantined with the reason) when:

* ``invalid-source-ref`` -- the reference does not follow the grammar;
* ``unknown-repo`` -- the repo id is not configured;
* ``unknown-commit`` -- the clone has no such commit;
* ``unsigned-source`` -- the commit carries no signature;
* ``unknown-signer`` -- the signature is bad, or made by a key that
  ``signers.yaml`` does not list;
* ``commit-does-not-touch-source`` -- the commit did not add or change the
  rule's file (a signed commit that merely *contains* it vouches for
  nothing);
* ``superseded`` -- a later commit on the tracked ref changed or removed
  the file (that is how a rule is revoked);
* ``stale-source`` -- only with ``max_source_age``: the clone's tracked ref
  is older than that;
* ``git-error`` -- git itself failed or timed out on this citation.

Git runs with a minimal environment built from scratch, and with ``-c``
overrides for every setting that decides how a signature is verified, so
neither the repository's own ``.git/config`` nor the user's configuration
can choose the verifier or the trusted keys (design §4.6).
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegis_core.signing import check_signature

GIT_PREFIX = "git:"
REPOS_FILE = "repos.yaml"
SIGNERS_FILE = "signers.yaml"
DEFAULT_RULE_GLOB = "rules/*.yaml"
STALE_WARNING_SECONDS = 24 * 3600

_REPO_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PRINCIPAL_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_SSH_KEY_RE = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com"
                         r"|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/=]+")

# Fields a rule file carries: a sources/<ref>.json payload minus
# ``principal`` (which comes from the signature) and ``source_ref`` (which
# is the citation itself).
_REQUIRED_FIELDS = (
    "provider", "resource_pattern", "actions", "scope", "effect", "constraint_class",
    "source_timestamp", "rule_text",
)

REASON_MESSAGES = {
    "invalid-source-ref": "git source reference does not follow git:<repo>@<sha>:<path>",
    "unknown-repo": "git source names a repository that repos.yaml does not configure",
    "unknown-commit": "the configured clone has no such commit",
    "unsigned-source": "the cited commit is not signed",
    "unknown-signer": "the cited commit's signature is bad or made by a key signers.yaml "
    "does not list",
    "commit-does-not-touch-source": "the cited commit did not add or change the rule's file",
    "superseded": "a later commit on the tracked ref changed or removed the rule's file",
    "stale-source": "the repository clone is older than --max-source-age",
    "invalid-git-source": "the rule file at the cited commit is not a valid rule mapping",
    "git-error": "git failed while verifying the citation",
}


class SourceRejected(KeyError):
    """A git citation that cannot back its constraint. ``reason`` is the
    quarantine reason. A ``KeyError`` so :class:`CachingSourceFetcher`
    memoises it like a missing file."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SourceNotChecked(Exception):
    """No fetcher is configured for this kind of reference, so it is not
    source-checked -- exactly as when a store is loaded with no source
    fetcher at all. Raised for non-``git:`` references when only git
    sources are configured, so adding a ``repos.yaml`` never changes how
    file-sourced constraints are treated."""


@dataclass(frozen=True)
class GitRef:
    repo: str
    sha: str
    path: str


def parse_git_ref(source_ref: str) -> GitRef:
    """``git:<repo-id>@<commit-sha>:<path>``, strictly: full SHA only (no
    branch names, no abbreviations, no ``HEAD~1``), and a relative path
    with no ``..``, backslash, NUL, empty or dash-leading component."""
    if not source_ref.startswith(GIT_PREFIX):
        raise SourceRejected("invalid-source-ref", source_ref)
    body = source_ref[len(GIT_PREFIX):]
    repo, sep, rest = body.partition("@")
    sha, sep2, path = rest.partition(":")
    if not (sep and sep2 and _REPO_ID_RE.fullmatch(repo) and _SHA_RE.fullmatch(sha)):
        raise SourceRejected("invalid-source-ref", source_ref)
    parts = path.split("/")
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(p in ("", ".", "..") or p.startswith("-") for p in parts)
    ):
        raise SourceRejected("invalid-source-ref", source_ref)
    return GitRef(repo, sha, path)


class _RuleLoader(yaml.SafeLoader):
    """``safe_load`` without implicit timestamps: ``source_timestamp`` must
    stay the exact string that was hashed, not become a ``datetime``."""


_RuleLoader.yaml_implicit_resolvers = {
    ch: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _path_matches(path: str, pattern: str) -> bool:
    """Whole-path glob match, one component at a time (``*`` never crosses
    a ``/``)."""
    parts, pats = path.split("/"), pattern.split("/")
    return len(parts) == len(pats) and all(
        fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pats, strict=True)
    )


# --- configuration -----------------------------------------------------------------


@dataclass(frozen=True)
class RepoConfig:
    repo_id: str
    path: Path
    ref: str
    rule_glob: str = DEFAULT_RULE_GLOB


def _load_yaml_mapping(path: Path, key: bytes | None, insecure: bool,
                       warnings: list[str]) -> dict:
    check_signature(path, key, insecure, warnings)
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: must be a mapping")
    return raw


def load_repos(path: str | Path, *, key: bytes | None = None, insecure: bool = False,
               warnings: list[str] | None = None) -> dict[str, RepoConfig]:
    path = Path(path)
    raw = _load_yaml_mapping(path, key, insecure, warnings if warnings is not None else [])
    repos = raw.get("repos")
    if not isinstance(repos, dict) or not repos:
        raise ValueError(f"{path}: 'repos' must be a non-empty mapping")
    out: dict[str, RepoConfig] = {}
    for repo_id, spec in repos.items():
        if not isinstance(repo_id, str) or not _REPO_ID_RE.fullmatch(repo_id):
            raise ValueError(f"{path}: invalid repo id {repo_id!r}")
        if not isinstance(spec, dict) or not isinstance(spec.get("path"), str):
            raise ValueError(f"{path}: repo {repo_id!r} needs a 'path'")
        ref = spec.get("ref", "refs/remotes/origin/main")
        glob = spec.get("rule_glob", DEFAULT_RULE_GLOB)
        if not isinstance(ref, str) or not ref.startswith("refs/"):
            raise ValueError(f"{path}: repo {repo_id!r}: 'ref' must be a full ref (refs/...)")
        if not isinstance(glob, str) or ".." in glob or glob.startswith("/"):
            raise ValueError(f"{path}: repo {repo_id!r}: invalid 'rule_glob'")
        out[repo_id] = RepoConfig(repo_id, Path(spec["path"]).expanduser(), ref, glob)
    return out


def load_signers(path: str | Path, *, key: bytes | None = None, insecure: bool = False,
                 warnings: list[str] | None = None) -> dict[str, str]:
    """``signers.yaml`` -> ``{"<ssh key type> <base64>": principal}``. A key
    listed twice (under any principals) is a load error, not a guess."""
    path = Path(path)
    raw = _load_yaml_mapping(path, key, insecure, warnings if warnings is not None else [])
    entries = raw.get("signers")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: 'signers' must be a non-empty list")
    out: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: every signer must be a mapping")
        principal = entry.get("principal")
        if not isinstance(principal, str) or not _PRINCIPAL_RE.fullmatch(principal):
            raise ValueError(f"{path}: invalid principal {principal!r}")
        for k in entry.get("keys") or []:
            if not isinstance(k, dict) or k.get("type") != "ssh":
                raise ValueError(
                    f"{path}: {principal}: only 'type: ssh' keys are supported so far"
                )
            m = _SSH_KEY_RE.match(str(k.get("key", "")).strip())
            if not m:
                raise ValueError(f"{path}: {principal}: not an SSH public key: {k.get('key')!r}")
            canonical = m.group(0)
            if canonical in out:
                raise ValueError(f"{path}: key listed twice ({out[canonical]} and {principal})")
            out[canonical] = principal
    if not out:
        raise ValueError(f"{path}: no keys")
    return out


# --- running git ----------------------------------------------------------------


def _find(program: str) -> str:
    found = shutil.which(program)
    if not found:
        raise ValueError(f"'{program}' is required for git sources but is not on PATH")
    return found


class _Git:
    """Runs git for one repository with an environment built from scratch
    (nothing inherited: GIT_DIR, GIT_OBJECT_DIRECTORY, GIT_CONFIG_* etc.
    from the calling process could otherwise redirect it) and overrides
    for every setting that decides how signatures are verified."""

    def __init__(self, repo: Path, allowed_signers: Path, empty_file: Path, home: Path):
        self.repo = repo
        self.git = _find("git")
        ssh_keygen = _find("ssh-keygen")
        false = shutil.which("false") or "/usr/bin/false"
        self.env = {
            "PATH": os.pathsep.join(sorted({str(Path(self.git).parent),
                                             str(Path(ssh_keygen).parent), "/usr/bin", "/bin"})),
            "HOME": str(home),
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            # paths after "--" are literal, never ":(glob)"-style pathspec magic
            "GIT_LITERAL_PATHSPECS": "1",
        }
        self.overrides = [
            f"safe.directory={repo}",
            "core.hooksPath=" + os.devnull,
            "core.fsmonitor=false",
            "gpg.format=ssh",
            f"gpg.ssh.program={ssh_keygen}",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            f"gpg.ssh.revocationFile={empty_file}",
            f"gpg.program={false}",
            f"gpg.openpgp.program={false}",
            f"gpg.x509.program={false}",
            "log.showSignature=false",
        ]

    def run(self, *args: str, check: bool = True) -> str:
        cmd = [self.git, "--no-replace-objects", "--no-pager", "-C", str(self.repo)]
        for o in self.overrides:
            cmd += ["-c", o]
        proc = subprocess.run(
            [*cmd, *args], env=self.env, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL, check=False,
        )
        if check and proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, args, proc.stdout, proc.stderr)
        return proc.stdout


# --- the fetcher ------------------------------------------------------------------


class GitSourceFetcher:
    """``SourceFetcher`` for ``git:`` references (see the module docstring).

    Construction validates the configuration (every repo is a Git
    repository whose tracked ref resolves; ``git`` and ``ssh-keygen`` are
    available) and raises ``ValueError`` otherwise: those are the
    operator's mistakes, not an attacker's, and fail the load."""

    def __init__(
        self,
        repos: dict[str, RepoConfig],
        signers: dict[str, str],
        *,
        max_source_age: float | None = None,
        now: float | None = None,
    ):
        self.repos = repos
        self.signers = signers
        self.max_source_age = max_source_age
        self.warnings: list[str] = []
        self._tmp = tempfile.TemporaryDirectory(prefix="aegis-git-")
        tmp = Path(self._tmp.name)
        allowed = tmp / "allowed_signers"
        # principals are validated to [A-Za-z0-9_.@-], so no quoting needed
        allowed.write_text("".join(
            f'{principal} namespaces="git" {k}\n' for k, principal in signers.items()
        ))
        empty = tmp / "revoked"
        empty.write_text("")
        (tmp / "home").mkdir()
        self._git = {
            rid: _Git(cfg.path, allowed, empty, tmp / "home") for rid, cfg in repos.items()
        }
        self._stale: set[str] = set()
        self._principals: dict[str, str] = {}
        now = time.time() if now is None else now
        for rid, cfg in repos.items():
            git = self._git[rid]
            try:
                git.run("rev-parse", "--verify", "--quiet", cfg.ref + "^{commit}")
                newest = int(git.run("log", "-1", "--format=%ct", cfg.ref).strip())
            except (subprocess.CalledProcessError, ValueError, OSError) as exc:
                raise ValueError(
                    f"repos.yaml: {rid}: {cfg.path} is not a git clone with ref {cfg.ref}"
                ) from exc
            age = now - newest
            if max_source_age is not None and age > max_source_age:
                self._stale.add(rid)
                self.warnings.append(
                    f"stale git source: {rid} newest commit on {cfg.ref} is "
                    f"{age / 3600:.0f}h old (> --max-source-age); its rules are quarantined"
                )
            elif age > STALE_WARNING_SECONDS:
                self.warnings.append(
                    f"stale git source: {rid} newest commit on {cfg.ref} is {age / 3600:.0f}h "
                    "old; revocations upstream are not visible until the clone is fetched"
                )
        for var in ("SSH_AUTH_SOCK", "GPG_AGENT_INFO"):
            if os.environ.get(var):
                self.warnings.append(
                    f"{var} is set: if the agent this gates can use a signing key in that "
                    "agent, it can sign as that key's principal"
                )

    @staticmethod
    def _is_ancestor(git: _Git, sha: str, ref: str) -> bool:
        try:
            git.run("merge-base", "--is-ancestor", sha, ref)
        except subprocess.CalledProcessError:
            return False
        return True

    def principal_for(self, source_ref: str) -> str:
        """The verified signer's principal for a fetched ``git:`` ref;
        ``""`` (never ``None``, which would fall back to the payload) if the
        ref has not verified."""
        return self._principals.get(source_ref, "")

    def fetch(self, source_ref: str) -> dict[str, Any]:
        try:
            return self._fetch(source_ref)
        except (subprocess.SubprocessError, OSError) as exc:
            # one citation git cannot process must not fail the whole load
            raise SourceRejected("git-error", f"{source_ref}: {exc.__class__.__name__}") from None

    def _fetch(self, source_ref: str) -> dict[str, Any]:
        ref = parse_git_ref(source_ref)
        cfg = self.repos.get(ref.repo)
        if cfg is None:
            raise SourceRejected("unknown-repo", ref.repo)
        if ref.repo in self._stale:
            raise SourceRejected("stale-source", ref.repo)
        if not _path_matches(ref.path, cfg.rule_glob):
            raise SourceRejected("invalid-source-ref", f"{ref.path} is not {cfg.rule_glob}")
        git = self._git[ref.repo]

        kind = git.run("cat-file", "-t", ref.sha, check=False).strip()
        if kind != "commit":
            raise SourceRejected("unknown-commit", ref.sha)

        # 1. the signature, verified against signers.yaml only
        status, _, signer = git.run("log", "-1", "--format=%G?%x00%GS", ref.sha).strip().partition(
            "\x00")
        if status == "N":
            raise SourceRejected("unsigned-source", ref.sha)
        if status != "G" or signer not in set(self.signers.values()):
            raise SourceRejected("unknown-signer", f"{ref.sha} status {status}")

        # 2. the commit added or changed the rule's file (first-parent diff)
        parents = git.run("rev-list", "--parents", "-n", "1", ref.sha).split()[1:]
        if parents:
            touched = git.run("diff-tree", "--no-commit-id", "--name-only", "-r",
                              parents[0], ref.sha, "--", ref.path).split("\n")
        else:
            touched = git.run("diff-tree", "--root", "--no-commit-id", "--name-only", "-r",
                              ref.sha, "--", ref.path).split("\n")
        if ref.path not in touched:
            raise SourceRejected("commit-does-not-touch-source", ref.path)

        # 3. still current: the cited commit is in the tracked ref's history
        #    and the rule file there is byte-identical to the cited version.
        #    (Comparing blobs, not "the last commit touching the path", so a
        #    rule cited by its author's own commit stays current after a
        #    merge, and any later edit or deletion revokes it.)
        if not self._is_ancestor(git, ref.sha, cfg.ref):
            raise SourceRejected("superseded", f"{ref.sha} is not on {cfg.ref}")
        cited = git.run("rev-parse", "--verify", "--quiet", f"{ref.sha}:{ref.path}",
                        check=False).strip()
        current = git.run("rev-parse", "--verify", "--quiet", f"{cfg.ref}:{ref.path}",
                          check=False).strip()
        if not cited:
            raise SourceRejected("superseded", f"{ref.path} was deleted in {ref.sha}")
        if cited != current:
            raise SourceRejected(
                "superseded", f"{ref.path} on {cfg.ref} differs from {ref.sha} (edited or removed)"
            )

        # 4. the content
        try:
            payload = yaml.load(  # noqa: S506 - _RuleLoader is a SafeLoader
                git.run("cat-file", "blob", f"{ref.sha}:{ref.path}"), Loader=_RuleLoader
            )
        except (subprocess.CalledProcessError, yaml.YAMLError) as exc:
            raise SourceRejected("invalid-git-source", str(exc)) from None
        if not isinstance(payload, dict) or any(f not in payload for f in _REQUIRED_FIELDS):
            raise SourceRejected("invalid-git-source", f"{ref.path} lacks the rule fields")
        if "principal" in payload:
            raise SourceRejected(
                "invalid-git-source", f"{ref.path} names a principal; it comes from the signature"
            )
        self._principals[source_ref] = signer
        return {**payload, "principal": signer, "source_ref": source_ref}


class DispatchingSourceFetcher:
    """Routes ``git:`` references to a :class:`GitSourceFetcher` and every
    other reference to the file fetcher, so one store can mix both."""

    def __init__(self, file_fetcher: Any | None, git_fetcher: GitSourceFetcher | None):
        self.file_fetcher = file_fetcher
        self.git_fetcher = git_fetcher

    @property
    def warnings(self) -> list[str]:
        out: list[str] = []
        for f in (self.file_fetcher, self.git_fetcher):
            out += getattr(f, "warnings", None) or []
        return out

    def _pick(self, source_ref: str):
        if source_ref.startswith(GIT_PREFIX):
            if self.git_fetcher is None:
                raise SourceRejected("unknown-repo", "no repos.yaml configured")
            return self.git_fetcher
        if self.file_fetcher is None:
            raise SourceNotChecked(source_ref)
        return self.file_fetcher

    def principal_for(self, source_ref: str) -> str | None:
        fetcher = self._pick(source_ref)
        inner = getattr(fetcher, "principal_for", None)
        return inner(source_ref) if inner is not None else None

    def fetch(self, source_ref: str) -> dict[str, Any]:
        return self._pick(source_ref).fetch(source_ref)
