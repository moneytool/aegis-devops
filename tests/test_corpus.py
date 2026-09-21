"""Tests for the labeled evaluation corpus built by scripts/build_corpus.py
(PLAN.md §4).

These tests exercise the *committed* corpus under data/corpus/ (regenerating
it once, deterministically, into a scratch directory to check reproducibility)
rather than regenerating the committed files themselves.
"""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from aegis_core.authority import load_authority_map
from aegis_core.provenance import FileSourceFetcher, verify_source
from aegis_core.store import ConstraintStore

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "data" / "corpus"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_corpus.py"
SEED = 20260920


def _read_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.fixture(scope="module")
def labels() -> list[dict]:
    return _read_jsonl(CORPUS_DIR / "labels.jsonl")


@pytest.fixture(scope="module")
def split() -> dict:
    with open(CORPUS_DIR / "split.json") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def authority_map():
    return load_authority_map(CORPUS_DIR / "authority.yaml")


@pytest.fixture(scope="module")
def store(authority_map):
    return ConstraintStore.load(CORPUS_DIR / "constraints.yaml", authority_map=authority_map)


def _safe_verify_source(constraint, fetcher) -> bool:
    """verify_source raises if the source file is missing outright (the
    'absent source' flavor of a forged constraint); treat that the same as
    a failed verification."""
    try:
        return verify_source(constraint, fetcher)
    except (FileNotFoundError, KeyError):
        return False


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------

def test_generator_is_deterministic(tmp_path):
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    for out in (out1, out2):
        subprocess.run(
            [sys.executable, str(BUILD_SCRIPT), "--seed", str(SEED), "--out-dir", str(out)],
            check=True,
            cwd=REPO_ROOT,
            capture_output=True,
        )

    for name in ("constraints.yaml", "labels.jsonl", "split.json", "intents.jsonl"):
        content1 = (out1 / name).read_bytes()
        content2 = (out2 / name).read_bytes()
        assert content1 == content2, f"{name} differs between two runs with the same seed"

    sources1 = sorted((out1 / "sources").glob("*.json"))
    sources2 = sorted((out2 / "sources").glob("*.json"))
    assert [p.name for p in sources1] == [p.name for p in sources2]
    for p1, p2 in zip(sources1, sources2):
        assert p1.read_bytes() == p2.read_bytes()


def test_committed_corpus_matches_regeneration(tmp_path):
    """The committed data/corpus/constraints.yaml etc. should match what the
    generator produces right now for the frozen seed."""
    out = tmp_path / "regen"
    subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--seed", str(SEED), "--out-dir", str(out)],
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
    )
    names = ("constraints.yaml", "labels.jsonl", "split.json", "intents.jsonl", "authority.yaml")
    for name in names:
        assert (out / name).read_bytes() == (CORPUS_DIR / name).read_bytes(), name


# ---------------------------------------------------------------------------
# Quarantine / provenance / authority semantics
# ---------------------------------------------------------------------------

def test_load_quarantines_exactly_the_tampered_ids(store, labels):
    expected_tampered = {r["id"] for r in labels if r["reason"] == "tampered"}
    actual_quarantined = {q["id"] for q in store.quarantined}
    assert actual_quarantined == expected_tampered


def test_verify_source_false_for_exactly_forged_ids(store, labels):
    fetcher = FileSourceFetcher(CORPUS_DIR / "sources")
    forged_ids = {r["id"] for r in labels if r["reason"] == "forged"}
    ok_ids = {r["id"] for r in labels if r["reason"] in ("authorized", "unauthorized")}

    # Only non-quarantined constraints are loaded into the store.
    for cid in forged_ids:
        assert cid in store.constraints, f"{cid} should have loaded (self-consistent hash)"
        assert _safe_verify_source(store.constraints[cid], fetcher) is False

    for cid in ok_ids:
        assert cid in store.constraints
        assert _safe_verify_source(store.constraints[cid], fetcher) is True


def test_unauthorized_ids_are_not_authorized(store, labels):
    for r in labels:
        if r["reason"] != "unauthorized":
            continue
        c = store.constraints[r["id"]]
        assert store.is_authorized(c.principal, c.constraint_class) is False


def test_authorized_ids_are_authorized(store, labels):
    for r in labels:
        if r["reason"] != "authorized":
            continue
        c = store.constraints[r["id"]]
        assert store.is_authorized(c.principal, c.constraint_class) is True


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------

def test_holdout_is_20_percent_per_label_within_tolerance(labels, split):
    by_label = Counter(r["label"] for r in labels)
    label_of = {r["id"]: r["label"] for r in labels}
    holdout_by_label = Counter(label_of[i] for i in split["holdout"])

    for label, total in by_label.items():
        expected = total * 0.2
        actual = holdout_by_label[label]
        assert abs(actual - expected) <= 2, (label, actual, expected)


def test_dev_and_holdout_are_disjoint_and_cover_all_ids(labels, split):
    all_ids = {r["id"] for r in labels}
    holdout = set(split["holdout"])
    dev = set(split["dev"])

    assert holdout & dev == set()
    assert holdout | dev == all_ids
    assert len(holdout) + len(dev) == len(all_ids)


# ---------------------------------------------------------------------------
# Corpus-wide counts
# ---------------------------------------------------------------------------

def test_corpus_has_exactly_500_constraints(labels):
    assert len(labels) == 500


def test_label_proportions_within_5_percent_of_50_25_25(labels):
    counts = Counter(r["label"] for r in labels)
    total = sum(counts.values())
    targets = {"Trusted": 0.50, "Untrusted": 0.25, "Malicious": 0.25}
    for label, target_frac in targets.items():
        actual_frac = counts[label] / total
        assert abs(actual_frac - target_frac) <= 0.05, (label, actual_frac, target_frac)
