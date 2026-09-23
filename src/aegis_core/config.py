"""Config directory discovery, ``aegis init``/``aegis keygen``, and the
packaged example files ``aegis init`` copies from (REVIEW-4 T2.6).

Aegis ships with a working example config (``data/*.example.yaml`` in the
repo checkout), but once installed as a wheel there is no ``data/`` next to
the interpreter. :func:`find_config_dir` locates a directory of policy
files by a fixed search order, and :func:`resolve_defaults` turns that
directory into concrete ``--constraints``/``--authority``/... paths (a real
file if one has been created, else the packaged example). ``aegis init
<dir>`` seeds a fresh directory from the package's bundled copy of the
example files (see ``src/aegis_core/_examples/`` and
``scripts/sync_package_examples.py``, which keeps that copy in sync with
``data/``).
"""

from __future__ import annotations

import importlib.resources
import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_ENV_VAR = "AEGIS_CONFIG_DIR"
SIGNING_KEY_ENV = "AEGIS_SIGNING_KEY"
EXAMPLES_PACKAGE = "aegis_core._examples"

# (config-dir filename without ".example", packaged example filename)
_POLICY_FILES = (
    "constraints.yaml",
    "authority.yaml",
    "environments.yaml",
    "plan_constraints.yaml",
)
EXAMPLE_KEY_NAME = "example-signing.key"
SOURCES_DIR_NAME = "sources"


@dataclass
class ConfigDirSearch:
    """The ordered list of directories :func:`find_config_dir` tried, and
    which one (if any) was found -- so callers can render a precise
    "searched: ..." message without re-deriving the search order."""

    searched: list[Path] = field(default_factory=list)
    found: Path | None = None


def _candidate_dirs(explicit: str | None) -> list[Path]:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
        return candidates
    env = os.environ.get(CONFIG_ENV_VAR)
    if env:
        candidates.append(Path(env))
    candidates.append(Path.cwd() / ".aegis")
    data_dir = Path.cwd() / "data"
    if data_dir.is_dir() and any(data_dir.glob("constraints*.yaml")):
        candidates.append(data_dir)
    candidates.append(Path.home() / ".config" / "aegis")
    candidates.append(Path("/etc/aegis"))
    return candidates


def search_config_dir(explicit: str | None = None) -> ConfigDirSearch:
    """Runs the full search order and reports what it found, without
    raising -- used both by :func:`find_config_dir` and by the CLI's
    error message when nothing is found."""
    result = ConfigDirSearch()
    for candidate in _candidate_dirs(explicit):
        result.searched.append(candidate)
        if candidate.is_dir():
            result.found = candidate
            return result
    return result


def find_config_dir(explicit: str | None = None) -> Path | None:
    """The search order: ``explicit`` (``--config-dir``), then
    ``$AEGIS_CONFIG_DIR``, then ``$PWD/.aegis``, then ``$PWD/data`` (only
    when it already contains a ``constraints*.yaml``, so a repo checkout
    keeps working without a ``.aegis`` directory), then
    ``~/.config/aegis``, then ``/etc/aegis``. Returns ``None`` if none of
    those exist; the caller decides what "no config" means (exit 66)."""
    return search_config_dir(explicit).found


def _pick(config_dir: Path, real_name: str, example_name: str) -> str | None:
    real = config_dir / real_name
    if real.exists():
        return str(real)
    example = config_dir / example_name
    if example.exists():
        return str(example)
    return None


@dataclass
class ResolvedConfig:
    constraints: str | None = None
    authority: str | None = None
    environments: str | None = None
    plan_constraints: str | None = None
    sources: str | None = None
    signing_key: str | None = None


def resolve_defaults(config_dir: Path) -> ResolvedConfig:
    """Turns a config directory into concrete file paths: a real file
    (``constraints.yaml``) if present, else the packaged/checked-out
    example (``constraints.example.yaml``); ``None`` for anything
    missing entirely so the caller's own default stays in force."""
    sources_dir = config_dir / SOURCES_DIR_NAME
    key_path = config_dir / EXAMPLE_KEY_NAME
    return ResolvedConfig(
        constraints=_pick(config_dir, "constraints.yaml", "constraints.example.yaml"),
        authority=_pick(config_dir, "authority.yaml", "authority.example.yaml"),
        environments=_pick(config_dir, "environments.yaml", "environments.example.yaml"),
        plan_constraints=_pick(
            config_dir, "plan_constraints.yaml", "plan_constraints.example.yaml"
        ),
        sources=str(sources_dir) if sources_dir.is_dir() else None,
        signing_key=str(key_path) if key_path.exists() else None,
    )


# --- aegis init / aegis keygen ----------------------------------------------


def _iter_example_resources():
    """Yields (relative_path, resource) for every file packaged under
    ``aegis_core._examples`` -- ``sources/`` included, recursively."""
    root = importlib.resources.files(EXAMPLES_PACKAGE)

    def _walk(node, prefix: str):
        for entry in sorted(node.iterdir(), key=lambda e: e.name):
            if entry.name in ("__init__.py", "__pycache__"):
                continue
            rel = f"{prefix}{entry.name}"
            if entry.is_dir():
                yield from _walk(entry, rel + "/")
            else:
                yield rel, entry

    yield from _walk(root, "")


def init_config_dir(target: str | Path) -> list[Path]:
    """Copies every packaged example file into ``target`` (created if
    needed), preserving the ``sources/`` subdirectory. Returns the list of
    files written. Refuses to overwrite a file that already exists, so
    re-running ``aegis init`` on a live directory is a no-op for anything
    the operator has already customised."""
    target_dir = Path(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rel_path, resource in _iter_example_resources():
        dest = target_dir / rel_path
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with importlib.resources.as_file(resource) as src_path:
            shutil.copyfile(src_path, dest)
        written.append(dest)
    return written


def generate_signing_key(out_path: str | Path) -> Path:
    """Writes 32 random hex bytes (64 hex chars) to ``out_path`` with mode
    0600 -- a real signing key, distinct from the public example key that
    ``aegis init`` copies in."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_hex = secrets.token_hex(32)
    # Create with 0600 from the start rather than chmod-after, so the key
    # is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key_hex)
    except BaseException:
        raise
    os.chmod(path, 0o600)
    return path
