"""Session-wide test setup (REVIEW-4 T2.6).

Several tests (and the CLI's own default config discovery, which walks
``$PWD/data``) assume a current working directory of the repo root, e.g.
``data/constraints.example.yaml``. Without this, ``pytest`` only passes when
invoked *from* the repo root; ``cd /tmp && pytest <repo>/tests`` would fail
every one of those tests with an unrelated-looking FileNotFoundError. This
chdirs once, for the whole session, to the repo root (two levels up from
this file), so the suite is invocable from anywhere.
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

os.chdir(REPO_ROOT)


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _private_budget_dirs(tmp_path_factory, monkeypatch):
    """The budget cap writes a cache and a state directory (default under
    ~/.cache and ~/.local/state). Point both at a per-test temporary
    directory so no test touches the real ones; tests that set HOME or the
    XDG variables themselves still override this."""
    base = tmp_path_factory.mktemp("xdg")
    monkeypatch.setenv("XDG_CACHE_HOME", str(base / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
