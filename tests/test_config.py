"""Tests for aegis_core.config: config-dir discovery, aegis init/keygen,
and the packaged-examples sync (REVIEW-4 T2.6)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core.config import (
    EXAMPLE_KEY_NAME,
    ResolvedConfig,
    find_config_dir,
    generate_signing_key,
    init_config_dir,
    resolve_defaults,
    search_config_dir,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def isolated_cwd(tmp_path, monkeypatch):
    """A tmp directory with no ancestor relationship to the repo, so
    ``$PWD/data`` can't accidentally resolve to the real ``data/``."""
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.delenv("AEGIS_CONFIG_DIR", raising=False)
    return work


# ---------------------------------------------------------------------------
# find_config_dir / search order
# ---------------------------------------------------------------------------


def test_explicit_config_dir_wins_over_everything(isolated_cwd, monkeypatch):
    explicit = isolated_cwd / "explicit"
    explicit.mkdir()
    env_dir = isolated_cwd / "env"
    env_dir.mkdir()
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(env_dir))
    assert find_config_dir(str(explicit)) == explicit


def test_env_var_used_when_no_explicit_dir(isolated_cwd, monkeypatch):
    env_dir = isolated_cwd / "env"
    env_dir.mkdir()
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(env_dir))
    assert find_config_dir(None) == env_dir


def test_dot_aegis_found_before_home_or_etc(isolated_cwd):
    dot_aegis = isolated_cwd / ".aegis"
    dot_aegis.mkdir()
    assert find_config_dir(None) == dot_aegis


def test_pwd_data_only_used_when_it_has_constraints(isolated_cwd):
    data_dir = isolated_cwd / "data"
    data_dir.mkdir()
    # No constraints*.yaml yet -- must not be picked up (this is what keeps
    # an arbitrary directory named "data" from being treated as config).
    assert find_config_dir(None) != data_dir

    (data_dir / "constraints.example.yaml").write_text("constraints: []\n")
    assert find_config_dir(None) == data_dir


def test_no_config_dir_found_returns_none(isolated_cwd):
    assert find_config_dir(None) is None


def test_search_config_dir_reports_every_candidate_tried(isolated_cwd):
    result = search_config_dir(None)
    assert result.found is None
    # $PWD/.aegis must always be among the searched candidates.
    assert isolated_cwd / ".aegis" in result.searched


# ---------------------------------------------------------------------------
# resolve_defaults
# ---------------------------------------------------------------------------


def test_resolve_defaults_prefers_real_file_over_example(tmp_path):
    (tmp_path / "constraints.example.yaml").write_text("constraints: []\n")
    (tmp_path / "constraints.yaml").write_text("constraints: []\n")
    resolved = resolve_defaults(tmp_path)
    assert resolved.constraints == str(tmp_path / "constraints.yaml")


def test_resolve_defaults_falls_back_to_example(tmp_path):
    (tmp_path / "authority.example.yaml").write_text("principals: {}\n")
    resolved = resolve_defaults(tmp_path)
    assert resolved.authority == str(tmp_path / "authority.example.yaml")


def test_resolve_defaults_none_for_missing_files(tmp_path):
    resolved = resolve_defaults(tmp_path)
    assert resolved == ResolvedConfig()


def test_resolve_defaults_finds_sources_dir_and_signing_key(tmp_path):
    (tmp_path / "sources").mkdir()
    (tmp_path / EXAMPLE_KEY_NAME).write_text("a" * 64)
    resolved = resolve_defaults(tmp_path)
    assert resolved.sources == str(tmp_path / "sources")
    assert resolved.signing_key == str(tmp_path / EXAMPLE_KEY_NAME)


# ---------------------------------------------------------------------------
# init_config_dir
# ---------------------------------------------------------------------------


def test_init_config_dir_writes_every_packaged_example(tmp_path):
    target = tmp_path / "cfg"
    written = init_config_dir(target)
    assert written  # non-empty
    assert (target / "constraints.example.yaml").exists()
    assert (target / "constraints.example.yaml.sig").exists()
    assert (target / "authority.example.yaml").exists()
    assert (target / "example-signing.key").exists()
    assert (target / "sources").is_dir()
    assert (target / "sources" / "PRINCIPALS.yaml").exists()
    # No package plumbing files leaked into the config dir.
    assert not (target / "__init__.py").exists()
    assert not (target / "__pycache__").exists()


def test_init_config_dir_never_overwrites_existing_files(tmp_path):
    target = tmp_path / "cfg"
    target.mkdir()
    (target / "constraints.example.yaml").write_text("custom content\n")
    written = init_config_dir(target)
    assert (target / "constraints.example.yaml").read_text() == "custom content\n"
    assert all(p.name != "constraints.example.yaml" for p in written)


def test_init_config_dir_result_loads_and_checks_cleanly(tmp_path):
    """End-to-end: a freshly-init'd directory is immediately usable by the
    CLI with no further setup (REVIEW-4 T2.6 acceptance)."""
    target = tmp_path / "cfg"
    init_config_dir(target)
    env = dict(os.environ, AEGIS_CONFIG_DIR=str(target))
    result = subprocess.run(
        [sys.executable, "-m", "aegis_core.cli", "check", "kubectl", "--", "kubectl",
         "delete", "node/x"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr  # BLOCK, per the shipped example rules
    assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# generate_signing_key
# ---------------------------------------------------------------------------


def test_generate_signing_key_writes_64_hex_chars_mode_0600(tmp_path):
    out = tmp_path / "sub" / "key.hex"
    path = generate_signing_key(out)
    assert path == out
    content = out.read_text()
    assert len(content) == 64
    int(content, 16)  # valid hex
    mode = out.stat().st_mode & 0o777
    assert mode == 0o600


def test_generate_signing_key_is_random_each_time(tmp_path):
    a = generate_signing_key(tmp_path / "a.key").read_text()
    b = generate_signing_key(tmp_path / "b.key").read_text()
    assert a != b


# ---------------------------------------------------------------------------
# Packaged examples stay in sync with data/ (REVIEW-4 T2.6)
# ---------------------------------------------------------------------------


def test_examples_package_in_sync_with_data_dir():
    """Guards against src/aegis_core/_examples/ drifting from data/ --
    run `venv/bin/python scripts/sync_package_examples.py` to fix."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "sync_package_examples.py"), "--check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "src/aegis_core/_examples/ is out of sync with data/; run "
        "`venv/bin/python scripts/sync_package_examples.py`:\n" + result.stdout
    )
