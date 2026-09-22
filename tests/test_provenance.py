import json

import pytest

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


# --------------------------------------------------------------------------
# REVIEW-4 T1.1: transport principals and signed sources.
# --------------------------------------------------------------------------


def _write_payload(directory, constraint, **overrides):
    payload = {
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
    }
    payload.update(overrides)
    path = directory / f"{constraint.source_ref}.json"
    path.write_text(json.dumps(payload))
    return path


def _constraint(**overrides):
    defaults = dict(
        id="rule-1",
        provider="kubernetes",
        resource_pattern="deployment/*",
        actions={"scale"},
        effect="BLOCK",
        constraint_class="scaling",
        principal="sre_lead",
        source_ref="jira-42",
        source_timestamp="2026-01-01T00:00:00+00:00",
        rule_text="Do not scale deployments.",
    )
    defaults.update(overrides)
    return Constraint.create(**defaults)


def test_verify_source_reason_uses_transport_principal_not_payload(tmp_path):
    from aegis_core.provenance import verify_source_reason

    c = _constraint()
    # Payload lies about its principal; the transport says sre_lead -- the
    # constraint verifies because only the transport is believed.
    _write_payload(tmp_path, c, principal="admin")
    fetcher = FileSourceFetcher(tmp_path, principal_map={"jira-42": "sre_lead"}, insecure=True)
    assert verify_source_reason(c, fetcher) is None
    # Transport says developer -> principal-mismatch, before any hashing.
    fetcher = FileSourceFetcher(tmp_path, principal_map={"jira-42": "developer"}, insecure=True)
    assert verify_source_reason(c, fetcher) == "principal-mismatch"
    assert verify_source(c, fetcher) is False


def test_verify_source_reason_forged_when_content_differs(tmp_path):
    from aegis_core.provenance import verify_source_reason

    c = _constraint()
    _write_payload(tmp_path, c, rule_text="something else")
    fetcher = FileSourceFetcher(tmp_path, principal_map={"jira-42": "sre_lead"}, insecure=True)
    assert verify_source_reason(c, fetcher) == "forged"


def test_fallback_to_payload_principal_records_a_warning(tmp_path):
    from aegis_core.provenance import verify_source_reason

    c = _constraint()
    _write_payload(tmp_path, c)
    fetcher = FileSourceFetcher(tmp_path, insecure=True)
    assert fetcher.principal_for("jira-42") is None
    warnings: list[str] = []
    assert verify_source_reason(c, fetcher, warnings) is None
    assert warnings == ["principal-from-payload: jira-42"]


def test_principals_yaml_in_base_dir_is_loaded_automatically(tmp_path):
    (tmp_path / "PRINCIPALS.yaml").write_text("principals:\n  jira-42: sre_lead\n")
    fetcher = FileSourceFetcher(tmp_path, insecure=True)
    assert fetcher.principal_map == {"jira-42": "sre_lead"}
    assert fetcher.principal_for("jira-42") == "sre_lead"
    assert fetcher.principal_for("jira-99") == ""  # listed nowhere: unattributed


def test_principals_yaml_signature_is_enforced_with_a_key(tmp_path):
    from aegis_core.signing import SignatureError, sign_file

    key = b"k" * 32
    (tmp_path / "PRINCIPALS.yaml").write_text("principals:\n  jira-42: sre_lead\n")
    with pytest.raises(SignatureError):
        FileSourceFetcher(tmp_path, key=key)
    sign_file(tmp_path / "PRINCIPALS.yaml", key)
    assert FileSourceFetcher(tmp_path, key=key).principal_map == {"jira-42": "sre_lead"}
    # No key: recorded as unsigned on the fetcher for the store to surface.
    assert FileSourceFetcher(tmp_path).warnings == [f"unsigned: {tmp_path / 'PRINCIPALS.yaml'}"]


def test_source_file_signature_is_enforced_with_a_key(tmp_path):
    from aegis_core.signing import SignatureError, sign_file

    key = b"k" * 32
    c = _constraint()
    path = _write_payload(tmp_path, c)
    with pytest.raises(SignatureError, match="unsigned"):
        FileSourceFetcher(tmp_path, key=key).fetch("jira-42")
    sign_file(path, key)
    assert FileSourceFetcher(tmp_path, key=key).fetch("jira-42")["source_ref"] == "jira-42"
    path.write_text(path.read_text().replace("Do not", "Please do"))
    with pytest.raises(SignatureError, match="bad signature"):
        FileSourceFetcher(tmp_path, key=key).fetch("jira-42")
    # per-call override of the fetcher-wide setting: a key passed to fetch()
    # is enforced even when the fetcher itself was built insecure.
    with pytest.raises(SignatureError, match="bad signature"):
        FileSourceFetcher(tmp_path, insecure=True).fetch("jira-42", key=key)


def test_unsigned_fetch_without_key_records_warning(tmp_path):
    c = _constraint()
    path = _write_payload(tmp_path, c)
    fetcher = FileSourceFetcher(tmp_path)
    fetcher.fetch("jira-42")
    assert fetcher.warnings == [f"unsigned: {path}"]
    assert FileSourceFetcher(tmp_path, insecure=True).warnings == []


@pytest.mark.parametrize("bad_ref", ["../../etc/passwd", "a/b", "..", "", "x\\y"])
def test_source_ref_with_path_separators_is_rejected(tmp_path, bad_ref):
    with pytest.raises(KeyError):
        FileSourceFetcher(tmp_path, insecure=True).fetch(bad_ref)


def test_caching_fetcher_delegates_principal_for_and_warnings(tmp_path):
    from aegis_core.provenance import CachingSourceFetcher

    c = _constraint()
    _write_payload(tmp_path, c)
    inner = FileSourceFetcher(tmp_path, principal_map={"jira-42": "sre_lead"})
    caching = CachingSourceFetcher(inner)
    caching.fetch("jira-42")
    assert caching.principal_for("jira-42") == "sre_lead"
    assert caching.warnings is inner.warnings and len(inner.warnings) == 1


def test_shipped_principals_files_match_payloads():
    from aegis_core.provenance import load_principal_map
    from aegis_core.signing import load_key

    key = load_key("file:data/example-signing.key")
    for base in ("data/sources", "data/corpus/sources"):
        principals = load_principal_map(f"{base}/PRINCIPALS.yaml", key=key)
        fetcher = FileSourceFetcher(base, key=key)
        assert fetcher.principal_map == principals
        for ref, principal in list(principals.items())[:5]:
            assert fetcher.fetch(ref)["principal"] == principal
