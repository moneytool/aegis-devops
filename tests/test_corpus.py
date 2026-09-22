"""Tests for the labeled evaluation corpus built by scripts/build_corpus.py
(PLAN.md §4) and the reference oracle that labels its intents
(scripts/reference_oracle.py, REVIEW-4 T0.5).

These tests exercise the *committed* corpus under data/corpus/ (regenerating
it once, deterministically, into a scratch directory to check reproducibility)
rather than regenerating the committed files themselves.
"""

import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis_core.authority import load_authority_map
from aegis_core.provenance import FileSourceFetcher, verify_source
from aegis_core.store import ConstraintStore

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "data" / "corpus"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_corpus.py"
ORACLE_SCRIPT = REPO_ROOT / "scripts" / "reference_oracle.py"
SEED = 20260920
GENERATED_FILES = (
    "constraints.yaml", "labels.jsonl", "split.json", "intents.jsonl", "authority.yaml",
    "stats.json", "constraints.yaml.sig", "authority.yaml.sig", "sources/PRINCIPALS.yaml",
    "sources/AEGIS-MANIFEST.sig",
)


def _read_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _load_oracle():
    spec = importlib.util.spec_from_file_location("reference_oracle", ORACLE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def oracle():
    return _load_oracle()


@pytest.fixture(scope="module")
def labels() -> list[dict]:
    return _read_jsonl(CORPUS_DIR / "labels.jsonl")


@pytest.fixture(scope="module")
def intents() -> list[dict]:
    return _read_jsonl(CORPUS_DIR / "intents.jsonl")


@pytest.fixture(scope="module")
def split() -> dict:
    with open(CORPUS_DIR / "split.json") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def stats() -> dict:
    with open(CORPUS_DIR / "stats.json") as f:
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

    for name in GENERATED_FILES:
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
    for name in GENERATED_FILES:
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
# Constraint split (kept for store-level experiments)
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
# Intent split — the benchmark's actual test set
# ---------------------------------------------------------------------------

def test_intent_split_is_20_percent_disjoint_and_covers_all(intents, split):
    all_ids = {r["id"] for r in intents}
    holdout = set(split["intents"]["holdout"])
    dev = set(split["intents"]["dev"])

    assert holdout & dev == set()
    assert holdout | dev == all_ids
    assert abs(len(holdout) - 0.2 * len(intents)) <= 2
    assert len(intents) == 600
    assert len(holdout) == 120


def test_intent_split_is_stratified_by_verdict_and_poison(intents, split):
    holdout = set(split["intents"]["holdout"])
    strata = Counter((r["expected_verdict"], r["poison_candidate"]) for r in intents)
    holdout_strata = Counter(
        (r["expected_verdict"], r["poison_candidate"]) for r in intents if r["id"] in holdout
    )
    for key, total in strata.items():
        assert abs(holdout_strata[key] - 0.2 * total) <= 2, (key, holdout_strata[key], total)


def test_intents_have_every_verdict_and_every_poison_kind_in_holdout(intents, split):
    holdout = [r for r in intents if r["id"] in set(split["intents"]["holdout"])]
    assert {r["expected_verdict"] for r in holdout} == {"ALLOW", "BLOCK", "ESCALATE"}
    kinds = {r["poison_kind"] for r in holdout if r["poison_candidate"]}
    assert kinds == {"unauthorized", "tampered", "forged"}


# ---------------------------------------------------------------------------
# stats.json
# ---------------------------------------------------------------------------

def test_stats_match_recomputation(stats, labels, intents, split, oracle):
    constraints = oracle.read_constraints(CORPUS_DIR / "constraints.yaml")
    assert stats["n_constraints"] == len(constraints) == 500

    structural = {
        (c["provider"], c["resource_pattern"], tuple(sorted(c["actions"])),
         json.dumps(c.get("scope") or {}, sort_keys=True))
        for c in constraints
    }
    assert stats["n_distinct_structural"] == len(structural)
    assert stats["n_distinct_patterns"] == len({c["resource_pattern"] for c in constraints})
    assert stats["n_distinct_rule_text"] == len({c["rule_text"] for c in constraints})

    assert stats["labels"] == dict(Counter(r["label"] for r in labels))
    assert stats["reasons"] == dict(Counter(r["reason"] for r in labels))

    holdout = set(split["intents"]["holdout"])
    for name, members in (
        ("all", intents),
        ("holdout", [r for r in intents if r["id"] in holdout]),
        ("dev", [r for r in intents if r["id"] not in holdout]),
    ):
        s = stats["intents"][name]
        assert s["n"] == len(members)
        assert s["by_expected_verdict"] == dict(Counter(r["expected_verdict"] for r in members))
        assert s["poison_candidates"] == sum(1 for r in members if r["poison_candidate"])
        assert s["poison_candidates_by_kind"] == dict(
            Counter(r["poison_kind"] for r in members if r["poison_candidate"])
        )


# ---------------------------------------------------------------------------
# Reference oracle
# ---------------------------------------------------------------------------

def test_oracle_never_imports_the_system_under_test():
    text = ORACLE_SCRIPT.read_text()
    # Strip the header comment that *names* the forbidden modules.
    code = "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("#") and "must never import" not in line
    )
    forbidden = ("aegis_core.interceptor", "aegis_core.store", "aegis_core.plan")
    for module in forbidden:
        assert not re.search(rf"^\s*(from|import)\s+{re.escape(module)}\b", code, re.M), module
    assert "must never import aegis_core.interceptor" in text


def test_committed_intents_match_live_oracle(intents, oracle):
    live = oracle.oracle_verdicts(CORPUS_DIR)
    assert [r["id"] for r in live] == [r["id"] for r in intents]
    for rec, truth in zip(intents, live):
        for key in oracle.EXPECTED_FIELDS:
            assert rec[key] == truth[key], (rec["id"], key)


def test_oracle_only_trusted_rules_drive_the_verdict(oracle):
    constraints = [
        {"id": "t-esc", "provider": "kubernetes", "resource_pattern": "node/*",
         "actions": ["delete"], "scope": {}, "time_window": None, "effect": "ESCALATE"},
        {"id": "u-block", "provider": "kubernetes", "resource_pattern": "node/*",
         "actions": ["delete"], "scope": {}, "time_window": None, "effect": "BLOCK"},
        {"id": "m-block", "provider": "kubernetes", "resource_pattern": "node/*",
         "actions": ["delete"], "scope": {"namespace": "prod"}, "time_window": None,
         "effect": "BLOCK"},
    ]
    labels = {
        "t-esc": {"label": "Trusted", "reason": "authorized"},
        "u-block": {"label": "Untrusted", "reason": "unauthorized"},
        "m-block": {"label": "Malicious", "reason": "forged"},
    }
    intent = {"id": "i", "provider": "kubernetes", "resource": "node/w1", "action": "delete",
              "params": {}, "metadata": {}, "now": "2026-01-05T12:00:00+00:00"}
    out = oracle.oracle_for_intent(intent, constraints, labels)
    assert out["expected_verdict"] == "ESCALATE"  # the Untrusted BLOCK is ignored
    assert out["expected_covered"] is True
    assert out["matched_trusted"] == ["t-esc"]
    assert out["matched_untrusted"] == ["u-block"]
    assert out["matched_malicious"] == []  # scope namespace=prod did not match
    assert out["poison_candidate"] is False

    # Drop the Trusted rule: now only poison matches -> ALLOW + candidate.
    out = oracle.oracle_for_intent(intent, constraints[1:], labels)
    assert out["expected_verdict"] == "ALLOW"
    assert out["poison_candidate"] is True
    assert out["poison_kind"] == "unauthorized"

    # Add metadata so the forged rule also matches: strongest kind wins.
    intent["metadata"] = {"namespace": "prod"}
    out = oracle.oracle_for_intent(intent, constraints[1:], labels)
    assert out["poison_kind"] == "forged"
    assert out["poison_kinds"] == ["forged", "unauthorized"]


def test_oracle_time_window_minimal_semantics(oracle):
    window = {"days": ["Mon", "Tue"], "start": "09:00", "end": "17:00", "tz": "America/New_York"}
    # Monday 2026-01-05 14:00 UTC == 09:00 New York -> inside (inclusive start).
    assert oracle.time_window_matches(window, datetime(2026, 1, 5, 14, 0, tzinfo=UTC))
    # 13:59 UTC == 08:59 NY -> outside.
    assert not oracle.time_window_matches(window, datetime(2026, 1, 5, 13, 59, tzinfo=UTC))
    # Wednesday -> outside on day.
    assert not oracle.time_window_matches(window, datetime(2026, 1, 7, 14, 0, tzinfo=UTC))
    assert oracle.time_window_matches(None, datetime(2026, 1, 7, 14, 0, tzinfo=UTC))


def test_oracle_cli_rewrites_expected_fields_preserving_order(tmp_path, intents):
    scratch = tmp_path / "corpus"
    scratch.mkdir()
    for name in ("constraints.yaml", "labels.jsonl", "authority.yaml"):
        (scratch / name).write_bytes((CORPUS_DIR / name).read_bytes())
    # Deliberately corrupt every expected verdict, then let the oracle fix it.
    with open(scratch / "intents.jsonl", "w") as f:
        for rec in intents:
            f.write(json.dumps({**rec, "expected_verdict": "BOGUS"}, sort_keys=True) + "\n")

    subprocess.run(
        [sys.executable, str(ORACLE_SCRIPT), "--corpus", str(scratch)],
        check=True, cwd=REPO_ROOT, capture_output=True,
    )
    assert (scratch / "intents.jsonl").read_bytes() == (CORPUS_DIR / "intents.jsonl").read_bytes()


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
