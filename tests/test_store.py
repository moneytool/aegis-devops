import json

import pytest

from aegis_core.authority import load_authority_map
from aegis_core.provenance import FileSourceFetcher
from aegis_core.store import Constraint, ConstraintStore

AUTHORITY = {
    "admin": {"scaling", "deletion", "configuration"},
    "sre_lead": {"scaling", "configuration"},
    "developer": {"configuration"},
}


def make_constraint(**overrides) -> Constraint:
    defaults = dict(
        id="test-1",
        provider="kubernetes",
        resource_pattern="node/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="no-scaling",
    )
    defaults.update(overrides)
    return Constraint.create(**defaults)


def test_add_constraint_stores_it():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint()
    store.add_constraint(constraint)
    assert "test-1" in store.constraints
    assert store.constraints["test-1"].principal == "sre_lead"


def test_add_constraint_by_unauthorized_principal_raises():
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint(
        id="test-2", principal="developer", constraint_class="scaling"
    )
    with pytest.raises(PermissionError):
        store.add_constraint(constraint)


def test_add_constraint_denies_by_default_with_no_authority_map():
    store = ConstraintStore()  # default: empty authority map, deny all
    constraint = make_constraint(id="test-3", principal="admin")
    with pytest.raises(PermissionError):
        store.add_constraint(constraint)


def test_integrity_verification_passes_for_untouched_constraint():
    constraint = make_constraint(id="test-4")
    assert constraint.verify_integrity() is True


def test_integrity_verification_fails_after_tamper():
    constraint = make_constraint(id="test-5")
    constraint.rule_text = "an attacker rewrote this rule"
    assert constraint.verify_integrity() is False


def test_is_authorized_reflects_authority_map():
    store = ConstraintStore(authority_map=AUTHORITY)
    assert store.is_authorized("sre_lead", "scaling") is True
    assert store.is_authorized("developer", "scaling") is False
    assert store.is_authorized("unknown_principal", "scaling") is False


def test_unauthorized_principal_bypassing_add_constraint_is_still_in_store():
    """A constraint inserted directly into the store's dict, bypassing
    add_constraint, is accepted into storage -- authority is enforced again
    at decision time by the interceptor (see test_interceptor.py)."""
    store = ConstraintStore(authority_map=AUTHORITY)
    constraint = make_constraint(id="test-6", principal="developer", constraint_class="scaling")
    store.constraints[constraint.id] = constraint
    assert "test-6" in store.constraints
    assert store.is_authorized(constraint.principal, constraint.constraint_class) is False


# --------------------------------------------------------------------------
# A1: forged-source quarantine at load (PLAN §7.3).
# --------------------------------------------------------------------------


def test_load_with_fetcher_quarantines_exactly_the_tampered_and_forged_corpus_ids():
    labels = {}
    with open("data/corpus/labels.jsonl") as f:
        for line in f:
            entry = json.loads(line)
            labels[entry["id"]] = entry["reason"]
    expected_quarantined = {
        cid for cid, reason in labels.items() if reason in {"tampered", "forged"}
    }
    expected_forged = {cid for cid, reason in labels.items() if reason == "forged"}
    expected_tampered = {cid for cid, reason in labels.items() if reason == "tampered"}

    authority_map = load_authority_map("data/corpus/authority.yaml")
    fetcher = FileSourceFetcher(base_dir="data/corpus/sources")
    store = ConstraintStore.load(
        "data/corpus/constraints.yaml", authority_map=authority_map, source_fetcher=fetcher
    )

    quarantined_ids = {entry["id"] for entry in store.quarantined}
    assert quarantined_ids == expected_quarantined

    quarantined_forged = {
        entry["id"] for entry in store.quarantined if entry["reason"] == "forged"
    }
    quarantined_tampered = {
        entry["id"] for entry in store.quarantined if entry["reason"] == "tampered"
    }
    assert quarantined_forged == expected_forged
    assert quarantined_tampered == expected_tampered

    # None of the quarantined ids made it into the live store.
    assert quarantined_ids.isdisjoint(store.constraints.keys())


def test_load_without_fetcher_does_not_quarantine_forged_constraints():
    labels = {}
    with open("data/corpus/labels.jsonl") as f:
        for line in f:
            entry = json.loads(line)
            labels[entry["id"]] = entry["reason"]
    expected_tampered = {cid for cid, reason in labels.items() if reason == "tampered"}

    authority_map = load_authority_map("data/corpus/authority.yaml")
    store = ConstraintStore.load("data/corpus/constraints.yaml", authority_map=authority_map)

    quarantined_ids = {entry["id"] for entry in store.quarantined}
    # Only integrity (tampered) failures are caught without a fetcher.
    assert quarantined_ids == expected_tampered


def test_load_with_fetcher_fetches_each_source_ref_at_most_once():
    class CountingFetcher:
        def __init__(self, real_fetcher):
            self._real = real_fetcher
            self.calls: dict[str, int] = {}

        def fetch(self, source_ref):
            self.calls[source_ref] = self.calls.get(source_ref, 0) + 1
            return self._real.fetch(source_ref)

    real_fetcher = FileSourceFetcher(base_dir="data/corpus/sources")
    counting_fetcher = CountingFetcher(real_fetcher)
    authority_map = load_authority_map("data/corpus/authority.yaml")

    ConstraintStore.load(
        "data/corpus/constraints.yaml",
        authority_map=authority_map,
        source_fetcher=counting_fetcher,
    )

    # Every source_ref in the 500-constraint corpus is unique, so this also
    # confirms nothing is fetched more than once per constraint -- but the
    # real point of the cache is exercised in the next test.
    assert all(count == 1 for count in counting_fetcher.calls.values())


def test_load_caches_fetches_across_constraints_sharing_a_source_ref(tmp_path):
    shared_source_ref = "shared-src"

    def make_with_ref(cid, resource_pattern):
        return Constraint.create(
            id=cid,
            provider="kubernetes",
            resource_pattern=resource_pattern,
            actions={"scale"},
            effect="BLOCK",
            constraint_class="scaling",
            principal="sre_lead",
            source_ref=shared_source_ref,
            source_timestamp="2026-01-01T00:00:00+00:00",
            rule_text="Do not scale.",
        )

    c1 = make_with_ref("shared-1", "deployment/a-*")
    c2 = make_with_ref("shared-2", "deployment/b-*")
    c3 = make_with_ref("shared-3", "deployment/c-*")

    store = ConstraintStore()
    for c in (c1, c2, c3):
        store.constraints[c.id] = c
    path = tmp_path / "constraints.yaml"
    store.save(path)

    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    (sources_dir / f"{shared_source_ref}.json").write_text(
        json.dumps(
            {
                "provider": c1.provider,
                "resource_pattern": c1.resource_pattern,
                "actions": sorted(c1.actions),
                "scope": c1.scope,
                "time_window": c1.time_window,
                "effect": c1.effect,
                "constraint_class": c1.constraint_class,
                "principal": c1.principal,
                "source_ref": c1.source_ref,
                "source_timestamp": c1.source_timestamp,
                "rule_text": c1.rule_text,
            }
        )
    )

    class CountingFetcher:
        def __init__(self, base_dir):
            self._real = FileSourceFetcher(base_dir=base_dir)
            self.calls: dict[str, int] = {}

        def fetch(self, source_ref):
            self.calls[source_ref] = self.calls.get(source_ref, 0) + 1
            return self._real.fetch(source_ref)

    counting_fetcher = CountingFetcher(sources_dir)
    ConstraintStore.load(path, source_fetcher=counting_fetcher)

    assert counting_fetcher.calls == {shared_source_ref: 1}


def test_verify_sources_moves_forged_constraints_to_quarantined(tmp_path):
    base = Constraint.create(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="jira-real",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    store = ConstraintStore()
    store.constraints[base.id] = base

    # No source file at all for "jira-real" -> counts as forged (missing).
    fetcher = FileSourceFetcher(base_dir=tmp_path)
    result = store.verify_sources(fetcher)

    assert result == [{"id": "rule-1", "reason": "forged"}]
    assert "rule-1" not in store.constraints
    assert {"id": "rule-1", "reason": "forged"} in store.quarantined
