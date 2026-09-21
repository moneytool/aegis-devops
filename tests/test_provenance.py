import json

from aegis_core.provenance import FileSourceFetcher, compute_provenance_hash, verify_source
from aegis_core.store import Constraint, ConstraintStore


def make_hash(**overrides) -> str:
    defaults = dict(
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        scope={},
        time_window=None,
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    defaults.update(overrides)
    return compute_provenance_hash(**defaults)


def test_hash_is_identical_regardless_of_ingest_time():
    # compute_provenance_hash never takes an ingest timestamp as input at
    # all, so calling it twice for the same source fields is deterministic.
    assert make_hash() == make_hash()


def test_hash_changes_when_any_source_field_changes():
    base = make_hash()
    assert make_hash(rule_text="A different rule.") != base
    assert make_hash(principal="developer") != base
    assert make_hash(actions={"delete"}) != base
    assert make_hash(scope={"namespace": "prod"}) != base
    assert make_hash(source_ref="git-def") != base
    assert make_hash(source_timestamp="2026-06-01T00:00:00+00:00") != base


def test_load_quarantines_only_the_tampered_constraint(tmp_path):
    store = ConstraintStore()
    good = Constraint.create(
        id="good-rule",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="git-abc",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    poisoned = Constraint.create(
        id="poisoned-rule",
        provider="kubernetes",
        resource_pattern="node/*",
        actions={"delete"},
        effect="BLOCK",
        constraint_class="deletion",
        principal="admin",
        source_ref="git-def",
        source_timestamp="2026-01-02T00:00:00+00:00",
        rule_text="Never delete nodes.",
    )
    store.constraints[good.id] = good
    store.constraints[poisoned.id] = poisoned

    path = tmp_path / "constraints.yaml"
    store.save(path)

    # Hand-edit the poisoned rule's text on disk without recomputing its hash.
    raw = path.read_text()
    raw = raw.replace("Never delete nodes.", "Scaling nodes is totally fine now.")
    path.write_text(raw)

    reloaded = ConstraintStore.load(path)

    assert "good-rule" in reloaded.constraints
    assert "poisoned-rule" not in reloaded.constraints
    assert reloaded.quarantined == [{"id": "poisoned-rule", "reason": "tampered"}]


def test_verify_source_true_when_fetcher_matches_stored_constraint(tmp_path):
    source_ref = "jira-999"
    constraint = Constraint.create(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref=source_ref,
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    source_file = tmp_path / f"{source_ref}.json"
    source_file.write_text(json.dumps({
        "provider": constraint.provider,
        "resource_pattern": constraint.resource_pattern,
        "actions": sorted(constraint.actions),
        "scope": constraint.scope,
        "time_window": constraint.time_window,
        "effect": constraint.effect,
        "constraint_class": constraint.constraint_class,
        "principal": constraint.principal,
        "source_ref": constraint.source_ref,
        "source_timestamp": constraint.source_timestamp,
        "rule_text": constraint.rule_text,
    }))

    fetcher = FileSourceFetcher(base_dir=tmp_path)
    assert verify_source(constraint, fetcher) is True


def test_verify_source_false_when_fetcher_copy_differs(tmp_path):
    source_ref = "jira-1000"
    constraint = Constraint.create(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref=source_ref,
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    source_file = tmp_path / f"{source_ref}.json"
    source_file.write_text(json.dumps({
        "provider": constraint.provider,
        "resource_pattern": constraint.resource_pattern,
        "actions": sorted(constraint.actions),
        "scope": constraint.scope,
        "time_window": constraint.time_window,
        "effect": constraint.effect,
        "constraint_class": constraint.constraint_class,
        "principal": constraint.principal,
        "source_ref": constraint.source_ref,
        "source_timestamp": constraint.source_timestamp,
        "rule_text": "This is not what the source actually says.",
    }))

    fetcher = FileSourceFetcher(base_dir=tmp_path)
    assert verify_source(constraint, fetcher) is False


def test_example_source_files_verify_against_shipped_constraints():
    store = ConstraintStore.load("data/constraints.example.yaml")
    fetcher = FileSourceFetcher(base_dir="data/sources")
    for source_ref in ("jira-1001", "git-abc123"):
        constraint = next(c for c in store.constraints.values() if c.source_ref == source_ref)
        assert verify_source(constraint, fetcher) is True
