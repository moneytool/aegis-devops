import json

import pytest

from aegis_core.authority import load_authority_map
from aegis_core.provenance import FileSourceFetcher
from aegis_core.store import Constraint, ConstraintStore

AUTHORITY_PATH = "data/authority.example.yaml"
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


# --------------------------------------------------------------------------
# REVIEW-4 T0.3: store health and quarantined-constraint matching.
# --------------------------------------------------------------------------


def _bit_flip_hash(path, constraint_id: str) -> None:
    import re

    text = path.read_text()
    m = re.search(
        rf"- id: {re.escape(constraint_id)}\n(?:.*\n)*?  provenance_hash: ([0-9a-f]{{64}})\n", text
    )
    h = m.group(1)
    path.write_text(text.replace(h, h[:-1] + ("0" if h[-1] != "0" else "1")))


def test_store_health_reports_loaded_quarantined_principals_and_sha256(tmp_path):
    import hashlib

    from aegis_core.store import StoreHealth

    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="a", resource_pattern="node/*"))
    store.add_constraint(make_constraint(id="b", resource_pattern="pod/*"))
    path = tmp_path / "constraints.yaml"
    store.save(path)
    _bit_flip_hash(path, "b")

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY, insecure=True)
    health = reloaded.health
    assert isinstance(health, StoreHealth)
    assert health.loaded == 1
    assert health.quarantined == [{"id": "b", "reason": "tampered"}]
    assert health.principals == 3
    assert health.constraints_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert health.warnings == ["Quarantined constraint b: provenance hash mismatch"]
    assert health.quarantine_ratio == 0.5
    assert health.to_dict()["quarantined"] == [{"id": "b", "reason": "tampered"}]


def test_store_health_of_example_store_is_clean():
    store = ConstraintStore.load(
        "data/constraints.example.yaml", authority_map=load_authority_map(AUTHORITY_PATH)
    )
    health = store.health
    assert health.loaded == 21
    assert health.quarantined == []
    assert health.principals == 3
    assert len(health.constraints_sha256) == 64
    assert health.quarantine_ratio == 0.0


def test_quarantined_constraints_are_kept_and_matched(tmp_path):
    from datetime import UTC, datetime

    from aegis_core.intent import InfrastructureIntent

    store = ConstraintStore(authority_map=AUTHORITY)
    store.add_constraint(make_constraint(id="nodes", resource_pattern="node/*"))
    path = tmp_path / "constraints.yaml"
    store.save(path)
    _bit_flip_hash(path, "nodes")

    reloaded = ConstraintStore.load(path, authority_map=AUTHORITY)
    assert [c.id for c in reloaded.quarantined_constraints] == ["nodes"]
    now = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
    node_intent = InfrastructureIntent(resource="node/w1", action="scale", provider="kubernetes")
    pod_intent = InfrastructureIntent(resource="pod/x", action="scale", provider="kubernetes")
    assert [(c.id, r) for c, r in reloaded.get_matching_quarantined(node_intent, now)] == [
        ("nodes", "tampered")
    ]
    assert reloaded.get_matching_quarantined(pod_intent, now) == []
    assert reloaded.get_matching_constraints(node_intent, now) == []


def test_verify_sources_keeps_the_forged_constraint_object(tmp_path):
    base = make_constraint(id="rule-1", source_ref="jira-real")
    store = ConstraintStore()
    store.constraints[base.id] = base
    store.verify_sources(FileSourceFetcher(base_dir=tmp_path))
    assert [c.id for c in store.quarantined_constraints] == ["rule-1"]
    assert store.health.loaded == 0
    assert store.health.quarantined == [{"id": "rule-1", "reason": "forged"}]


def test_load_rejects_a_top_level_list(tmp_path):
    path = tmp_path / "constraints.yaml"
    path.write_text("- id: x\n")
    with pytest.raises(ValueError):
        ConstraintStore.load(path)


def test_load_of_empty_file_has_zero_loaded():
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
        store = ConstraintStore.load(f.name, authority_map=AUTHORITY)
    assert store.health.loaded == 0
    assert store.health.quarantined == []


# --------------------------------------------------------------------------
# REVIEW-4 T1.1: root of trust -- signed constraint files.
# --------------------------------------------------------------------------


def _key():
    from aegis_core.signing import load_key

    return load_key("file:data/example-signing.key")


def _saved_store(tmp_path, *constraints):
    store = ConstraintStore(authority_map=AUTHORITY)
    for c in constraints:
        store.add_constraint(c)
    path = tmp_path / "constraints.yaml"
    store.save(path)
    return path


def test_signed_load_ok_and_records_no_unsigned_warning(tmp_path):
    from aegis_core.signing import sign_file

    path = _saved_store(tmp_path, make_constraint(id="a"))
    sign_file(path, _key())
    store = ConstraintStore.load(path, authority_map=AUTHORITY, key=_key())
    assert store.health.loaded == 1
    assert store.health.warnings == []


def test_tampered_file_with_stale_signature_raises_signature_error(tmp_path):
    from aegis_core.signing import SignatureError, sign_file

    path = _saved_store(tmp_path, make_constraint(id="a"))
    sign_file(path, _key())
    _bit_flip_hash(path, "a")  # any edit after signing, even one character
    with pytest.raises(SignatureError, match="bad signature"):
        ConstraintStore.load(path, authority_map=AUTHORITY, key=_key())


def test_missing_signature_with_key_raises_signature_error(tmp_path):
    from aegis_core.signing import SignatureError

    path = _saved_store(tmp_path, make_constraint(id="a"))
    with pytest.raises(SignatureError, match="unsigned"):
        ConstraintStore.load(path, authority_map=AUTHORITY, key=_key())


def test_no_key_records_unsigned_warning_unless_insecure(tmp_path):
    path = _saved_store(tmp_path, make_constraint(id="a"))
    store = ConstraintStore.load(path, authority_map=AUTHORITY)
    assert store.health.warnings == [f"unsigned: {path}"]
    assert store.health.loaded == 1  # library callers still get a working store
    store = ConstraintStore.load(path, authority_map=AUTHORITY, insecure=True)
    assert store.health.warnings == []


def test_unsigned_authority_map_warning_is_folded_into_store_health(tmp_path):
    from aegis_core.signing import sign_file

    path = _saved_store(tmp_path, make_constraint(id="a"))
    sign_file(path, _key())
    authority_map = load_authority_map(AUTHORITY_PATH)  # no key -> unsigned warning
    store = ConstraintStore.load(path, authority_map=authority_map, key=_key())
    assert store.health.warnings == [f"unsigned: {AUTHORITY_PATH}"]


def test_shipped_example_store_loads_signed_with_sources_and_no_warnings():
    key = _key()
    store = ConstraintStore.load(
        "data/constraints.example.yaml",
        authority_map=load_authority_map(AUTHORITY_PATH, key=key),
        source_fetcher=FileSourceFetcher("data/sources", key=key),
        key=key,
    )
    assert store.health.loaded == 21
    assert store.health.quarantined == []
    assert store.health.warnings == []


def test_principal_mismatch_between_transport_and_constraint_is_quarantined(tmp_path):
    """The source payload says `admin` (self-asserted) and so does the
    constraint, but the transport attributes the source to `developer`."""
    c = make_constraint(id="rule-1", principal="admin", constraint_class="deletion",
                        source_ref="git-x")
    path = _saved_store(tmp_path, c)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "git-x.json").write_text(json.dumps({
        "provider": c.provider, "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
        "effect": c.effect, "constraint_class": c.constraint_class,
        "principal": "admin", "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp, "rule_text": c.rule_text,
    }))
    fetcher = FileSourceFetcher(sources, principal_map={"git-x": "developer"}, insecure=True)
    store = ConstraintStore.load(path, authority_map=AUTHORITY, source_fetcher=fetcher,
                                 insecure=True)
    assert store.quarantined == [{"id": "rule-1", "reason": "principal-mismatch"}]
    assert [q.id for q in store.quarantined_constraints] == ["rule-1"]
    assert "rule-1" not in store.constraints
    # ... and the same source, attributed by the transport to admin, verifies.
    ok = FileSourceFetcher(sources, principal_map={"git-x": "admin"}, insecure=True)
    store = ConstraintStore.load(path, authority_map=AUTHORITY, source_fetcher=ok, insecure=True)
    assert store.quarantined == []


def test_source_missing_from_principal_map_is_a_principal_mismatch(tmp_path):
    c = make_constraint(id="rule-1", source_ref="git-x")
    path = _saved_store(tmp_path, c)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "git-x.json").write_text(json.dumps({
        "provider": c.provider, "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
        "effect": c.effect, "constraint_class": c.constraint_class,
        "principal": c.principal, "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp, "rule_text": c.rule_text,
    }))
    fetcher = FileSourceFetcher(sources, principal_map={}, insecure=True)
    store = ConstraintStore.load(path, source_fetcher=fetcher, insecure=True)
    assert store.quarantined == [{"id": "rule-1", "reason": "principal-mismatch"}]


def test_fetcher_without_principal_map_falls_back_to_payload_with_warning(tmp_path):
    c = make_constraint(id="rule-1", source_ref="git-x")
    path = _saved_store(tmp_path, c)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "git-x.json").write_text(json.dumps({
        "provider": c.provider, "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
        "effect": c.effect, "constraint_class": c.constraint_class,
        "principal": c.principal, "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp, "rule_text": c.rule_text,
    }))
    fetcher = FileSourceFetcher(sources, insecure=True)  # no PRINCIPALS.yaml in the dir
    store = ConstraintStore.load(path, source_fetcher=fetcher, insecure=True)
    assert store.quarantined == []
    assert store.health.warnings == ["principal-from-payload: git-x"]


def test_verify_sources_reports_principal_mismatch(tmp_path):
    c = make_constraint(id="rule-1", source_ref="git-x")
    sources = tmp_path
    (sources / "git-x.json").write_text(json.dumps({
        "provider": c.provider, "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
        "effect": c.effect, "constraint_class": c.constraint_class,
        "principal": c.principal, "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp, "rule_text": c.rule_text,
    }))
    store = ConstraintStore()
    store.constraints[c.id] = c
    fetcher = FileSourceFetcher(sources, principal_map={"git-x": "developer"}, insecure=True)
    assert store.verify_sources(fetcher) == [{"id": "rule-1", "reason": "principal-mismatch"}]


# --------------------------------------------------------------------------
# REVIEW-4 T1.8: validation at load.
# --------------------------------------------------------------------------


def _valid_entry(**overrides):
    c = make_constraint(id="ok")
    entry = {
        "id": c.id, "provider": c.provider, "resource_pattern": c.resource_pattern,
        "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
        "effect": c.effect, "constraint_class": c.constraint_class,
        "principal": c.principal, "source_ref": c.source_ref,
        "source_timestamp": c.source_timestamp, "rule_text": c.rule_text,
        "provenance_hash": c.provenance_hash,
    }
    entry.update(overrides)
    return entry


def _load_entries(tmp_path, *entries):
    import yaml

    path = tmp_path / "constraints.yaml"
    path.write_text(yaml.safe_dump({"constraints": list(entries)}, sort_keys=False))
    return ConstraintStore.load(path, authority_map=AUTHORITY, insecure=True)


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"effect": "Block"}, "invalid: effect must be BLOCK or ESCALATE, got 'Block'"),
        ({"effect": "DENY"}, "invalid: effect must be BLOCK or ESCALATE, got 'DENY'"),
        ({"provider": ""}, "invalid: provider must be a non-empty string"),
        ({"provider": None}, "invalid: missing provider"),
        ({"actions": []}, "invalid: actions must be a non-empty list of strings"),
        ({"actions": "delete"}, "invalid: actions must be a non-empty list of strings"),
        ({"actions": [1]}, "invalid: actions must be a non-empty list of strings"),
        ({"resource_pattern": ""}, "invalid: resource_pattern must be a non-empty string"),
        ({"scope": ["prod"]}, "invalid: scope must be a mapping"),
        ({"time_window": "weekdays"}, "invalid: time_window must be a mapping"),
        ({"time_window": {"days": ["Friday"]}}, "invalid: days must be Mon..Sun"),
        ({"time_window": {"days": ["mon"]}}, "invalid: days must be Mon..Sun"),
        ({"time_window": {"days": "Mon"}}, "invalid: days must be Mon..Sun"),
        ({"time_window": {"start": 600, "end": "17:00"}},
         "invalid: start must be HH:MM (quote it in YAML)"),
        ({"time_window": {"start": "9am", "end": "17:00"}},
         "invalid: start must be HH:MM (quote it in YAML)"),
        ({"time_window": {"start": "09:00", "end": "25:00"}},
         "invalid: end must be HH:MM (quote it in YAML)"),
        ({"time_window": {"start": "09:00"}}, "invalid: start and end must be given together"),
        ({"time_window": {"tz": "Mars/Olympus"}}, "invalid: unknown tz 'Mars/Olympus'"),
        ({"rate_limit": {"max": "3", "per": "1h"}},
         "invalid: rate_limit.max must be a non-negative integer"),
        ({"rate_limit": {"max": 3, "per": "hourly"}},
         "invalid: rate_limit.per must look like 15m, 1h or 24h"),
        ({"rate_limit": {"max": 3, "per": "1h", "key": "namespace"}},
         "invalid: rate_limit.key must be a list of field names"),
        ({"rate_limit": [3]}, "invalid: rate_limit must be a mapping"),
        ({"id": ""}, "invalid: id must be a non-empty string"),
    ],
)
def test_each_invalid_shape_is_quarantined_with_its_reason(tmp_path, overrides, reason):
    store = _load_entries(tmp_path, _valid_entry(**overrides))
    assert store.constraints == {}
    assert len(store.quarantined) == 1
    assert store.quarantined[0]["reason"] == reason
    assert store.quarantined_constraints == []  # nothing constructible to match
    assert store.health.quarantine_ratio == 1.0


def test_unquoted_yaml_time_is_caught_as_invalid_not_traceback(tmp_path):
    """YAML reads an unquoted `start: 10:00` as the integer 600."""
    path = tmp_path / "constraints.yaml"
    entry = _valid_entry(time_window={"start": "10:00", "end": "17:00", "tz": "UTC"})
    import yaml

    text = yaml.safe_dump({"constraints": [entry]}, sort_keys=False).replace("'10:00'", "10:00")
    path.write_text(text)
    store = ConstraintStore.load(path, insecure=True)
    assert store.quarantined == [
        {"id": "ok", "reason": "invalid: start must be HH:MM (quote it in YAML)"}
    ]


@pytest.mark.parametrize("missing", ["id", "actions", "effect", "principal", "provenance_hash",
                                     "rule_text", "source_ref", "constraint_class"])
def test_missing_required_key_is_quarantined_not_a_traceback(tmp_path, missing):
    entry = _valid_entry()
    del entry[missing]
    store = _load_entries(tmp_path, entry)
    expected_id = "<no id>" if missing == "id" else "ok"
    assert store.quarantined == [{"id": expected_id, "reason": f"invalid: missing {missing}"}]


def test_non_mapping_entry_is_quarantined(tmp_path):
    store = _load_entries(tmp_path, "just a string", _valid_entry())
    assert store.quarantined == [{"id": "<no id>", "reason": "invalid: entry must be a mapping"}]
    assert list(store.constraints) == ["ok"]


def test_duplicate_id_quarantines_the_later_entry_only(tmp_path):
    first = _valid_entry()
    second = make_constraint(id="ok", resource_pattern="pod/*")
    later = _valid_entry(resource_pattern="pod/*", provenance_hash=second.provenance_hash)
    store = _load_entries(tmp_path, first, later)
    assert store.constraints["ok"].resource_pattern == "node/*"  # first wins
    assert store.quarantined == [{"id": "ok", "reason": "invalid: duplicate id"}]


def test_valid_time_window_and_rate_limit_shapes_load(tmp_path):
    good = make_constraint(
        id="ok",
        time_window={"days": ["Mon", "Fri"], "start": "09:00", "end": "17:00", "tz": "UTC"},
        rate_limit={"max": 3, "per": "24h", "key": ["namespace"]},
    )
    entry = _valid_entry(time_window=good.time_window, rate_limit=good.rate_limit,
                         provenance_hash=good.provenance_hash)
    store = _load_entries(tmp_path, entry)
    assert store.quarantined == []
    assert store.constraints["ok"].rate_limit == {"max": 3, "per": "24h", "key": ["namespace"]}


def test_constraint_post_init_rejects_invalid_effect():
    with pytest.raises(ValueError, match="effect must be BLOCK or ESCALATE"):
        make_constraint(effect="Block")
    with pytest.raises(ValueError):
        make_constraint(effect="DENY")


def test_effect_block_in_mixed_case_never_reaches_the_interceptor(tmp_path):
    """REVIEW-4 T1.8: `effect: Block` used to be *cited as the reason to
    ALLOW*. Now it is quarantined at load, has no Constraint object, and
    the intent it would have covered is simply uncovered."""
    from datetime import UTC, datetime

    from aegis_core.intent import InfrastructureIntent
    from aegis_core.interceptor import AegisInterceptor

    store = _load_entries(tmp_path, _valid_entry(effect="Block"))
    intent = InfrastructureIntent(resource="node/w1", action="scale", provider="kubernetes")
    decision = AegisInterceptor(store).intercept(intent, now=datetime(2026, 1, 5, tzinfo=UTC))
    assert decision.citations == []
    assert decision.covered is False
    assert store.health.quarantined[0]["reason"].startswith("invalid: effect")


# --------------------------------------------------------------------------
# REVIEW-4 T1.5 / T2.5: scope matching semantics.
# --------------------------------------------------------------------------


def _intent(**kw):
    from aegis_core.intent import InfrastructureIntent

    return InfrastructureIntent(
        resource=kw.pop("resource", "pod/x"), action=kw.pop("action", "delete"),
        provider=kw.pop("provider", "kubernetes"),
        params=kw.pop("params", {}), metadata=kw.pop("metadata", {}),
    )


def _matches(scope, **kw):
    from datetime import UTC, datetime

    store = ConstraintStore()
    store.constraints["r"] = make_constraint(
        id="r", resource_pattern="*", actions={"delete"}, scope=scope,
        provider=kw.get("provider", "kubernetes"),
    )
    return bool(store.get_matching_constraints(_intent(**kw), datetime(2026, 1, 5, tzinfo=UTC)))


def test_h4_metadata_env_is_not_shadowed_by_params_env():
    assert _matches({"env": "prod"}, metadata={"env": "prod"}, params={"env": "dev"})
    assert not _matches({"env": "dev"}, metadata={"env": "prod"}, params={"env": "dev"})


def test_params_only_supply_keys_metadata_lacks():
    assert _matches({"replicas": 5}, metadata={"env": "prod"}, params={"replicas": 5})
    assert not _matches({"replicas": 5}, metadata={}, params={})


def test_scope_int_and_str_are_compared_as_strings():
    assert _matches({"account": 123456789012}, metadata={"account": "123456789012"})
    assert _matches({"account": "123456789012"}, metadata={"account": 123456789012})
    assert _matches({"replicas": 5}, params={"replicas": "5"})
    assert not _matches({"account": 123456789012}, metadata={"account": "999"})


def test_scope_booleans_match_true_false_strings_case_insensitively():
    assert _matches({"prune": True}, params={"prune": "true"})
    assert _matches({"prune": True}, params={"prune": "True"})
    assert _matches({"prune": "true"}, params={"prune": True})
    assert _matches({"prune": False}, params={"prune": "FALSE"})
    assert not _matches({"prune": True}, params={"prune": "false"})
    assert not _matches({"prune": True}, params={"prune": "yes"})


def test_scope_list_is_an_or():
    assert _matches({"namespace": ["prod", "prod-eu"]}, metadata={"namespace": "prod-eu"})
    assert not _matches({"namespace": ["prod", "prod-eu"]}, metadata={"namespace": "dev"})
    assert _matches({"account": [123, "456"]}, metadata={"account": "123"})


def test_scope_glob_values_use_fnmatch():
    assert _matches({"namespace": "prod-*"}, metadata={"namespace": "prod-eu"})
    assert _matches({"context": "gke_*_prod"}, metadata={"context": "gke_acme_prod"})
    assert _matches({"region": "us-east-?"}, metadata={"region": "us-east-1"})
    assert not _matches({"namespace": "prod-*"}, metadata={"namespace": "staging"})
    assert not _matches({"namespace": "prod*"}, metadata={"namespace": "Prod"})  # case-sensitive


def test_scope_dotted_path_reaches_into_nested_params():
    assert _matches({"set.replicaCount": 0}, params={"set": {"replicaCount": "0"}})
    assert _matches({"set.replicaCount": "0"}, params={"set": {"replicaCount": 0, "image": "x"}})
    assert not _matches({"set.replicaCount": 0}, params={"set": {"replicaCount": 3}})
    assert not _matches({"set.replicaCount": 0}, params={"set": "replicaCount=0"})
    assert not _matches({"set.replicaCount": 0}, params={})
    # a literal dotted key wins over path traversal
    assert _matches({"a.b": 1}, params={"a.b": 1, "a": {"b": 2}})


def test_scope_key_absent_from_both_never_matches_and_nested_values_dont_equal_strings():
    assert not _matches({"env": "prod"}, metadata={}, params={})
    assert not _matches({"set": "x"}, params={"set": {"x": 1}})
    assert not _matches({"env": None}, metadata={"env": "prod"})
