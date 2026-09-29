"""ConstraintStore.verified_snapshot (docs/dev/DESIGN-v0.3-server-side.md §3.1):
the frozen set of constraints that may vote, with everything else excluded
and a digest over all inputs."""

import dataclasses

import pytest

from aegis_core.store import ConstraintStore
from tests.test_interceptor import make_constraint

AUTHORITY = {"admin": {"deletion", "scaling"}, "sre_lead": {"scaling"}}


def _store(*constraints, authority=AUTHORITY, source_verified=True):
    store = ConstraintStore(authority_map={p: set(c) for p, c in authority.items()})
    for c in constraints:
        store.constraints[c.id] = c
        if source_verified:  # as ConstraintStore.load records after a source check
            store.source_verified.add(c.id)
    return store


def _rule(**overrides):
    fields = dict(id="r1", actions={"delete"}, resource_pattern="node/*",
                  constraint_class="deletion", principal="admin")
    fields.update(overrides)
    return make_constraint(**fields)


def test_only_authorized_intact_constraints_are_verified():
    ok = _rule()
    unauthorized = _rule(id="r2", principal="sre_lead")  # sre_lead may not assert deletion
    tampered = _rule(id="r3")
    tampered.effect = "ESCALATE"  # mutated after hashing
    snap = _store(ok, unauthorized, tampered).verified_snapshot()
    assert [c.id for c in snap.constraints] == ["r1"]
    assert list(snap.excluded) == [
        {"id": "r2", "reason": "unauthorized"},
        {"id": "r3", "reason": "tampered"},
    ]


def test_load_time_quarantine_is_listed_as_excluded():
    store = _store(_rule())
    store.quarantined.append({"id": "poison", "reason": "forged"})
    assert {"id": "poison", "reason": "forged"} in store.verified_snapshot().excluded


def test_snapshot_is_immutable():
    snap = _store(_rule()).verified_snapshot()
    assert isinstance(snap.constraints, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.digest = "x"


# --- review of #15 ------------------------------------------------------------------


def test_snapshot_is_detached_from_the_store():
    """P1: mutating the store's constraint after the snapshot must not change
    what the snapshot holds (it used to share the objects, digest unchanged)."""
    rule = _rule()
    snap = _store(rule).verified_snapshot()
    rule.effect = "ESCALATE"
    rule.actions.add("scale")
    [c] = snap.constraints
    assert c.effect == "BLOCK" and c.actions == {"delete"}
    assert snap.verify()


def test_objects_handed_out_by_the_snapshot_cannot_change_it():
    snap = _store(_rule()).verified_snapshot(inputs={"environments": "aa"})
    [c] = snap.constraints
    c.effect = "ESCALATE"
    c.scope["namespace"] = "prod"
    snap.inputs["environments"] = "zz"
    snap.excluded  # read-only view
    [again] = snap.constraints
    assert again.effect == "BLOCK" and again.scope == {}
    assert snap.inputs == {"environments": "aa"}
    assert again.verify_integrity()
    assert snap.verify()


def test_constraints_without_source_evidence_are_excluded():
    """P1: a signed, self-consistent constraint is not proof its source
    backs it; without source verification at load it may not vote."""
    snap = _store(_rule(), source_verified=False).verified_snapshot()
    assert snap.constraints == ()
    assert list(snap.excluded) == [{"id": "r1", "reason": "source-unverified"}]
    # the evidence requirement can be waived only explicitly
    loose = _store(_rule(), source_verified=False).verified_snapshot(
        require_source_evidence=False)
    assert [c.id for c in loose.constraints] == ["r1"]


def test_digest_covers_store_settings():
    """P2: default_tz changes how a time window without its own tz is
    evaluated, so two stores that differ only in it must not share a digest."""
    rule = _rule(time_window={"days": ["Mon"], "start": "09:00", "end": "17:00"})
    utc, ny = _store(rule), _store(rule)
    utc.default_tz, ny.default_tz = "UTC", "America/New_York"
    a, b = utc.verified_snapshot(), ny.verified_snapshot()
    assert a.digest != b.digest
    assert a.to_dict()["settings"]["default_tz"] == "UTC"
    no_tz = _store(rule)
    no_tz.tzdata_available = False
    assert no_tz.verified_snapshot().digest != _store(rule).verified_snapshot().digest


def test_digest_is_stable_and_order_independent():
    a, b = _rule(id="a"), _rule(id="b")
    assert _store(a, b).verified_snapshot().digest == _store(b, a).verified_snapshot().digest
    assert (_store(a).verified_snapshot(inputs={"x": "1", "y": "2"}).digest
            == _store(a).verified_snapshot(inputs={"y": "2", "x": "1"}).digest)


@pytest.mark.parametrize("change", ["constraint", "authority", "input", "exclusion"])
def test_digest_changes_with_every_input(change):
    base = _store(_rule()).verified_snapshot(inputs={"environments": "aa"}).digest
    if change == "constraint":
        other = _store(_rule(resource_pattern="node/w*"))
        inputs = {"environments": "aa"}
    elif change == "authority":
        other = _store(_rule(), authority={**AUTHORITY, "dev": {"scaling"}})
        inputs = {"environments": "aa"}
    elif change == "input":
        other, inputs = _store(_rule()), {"environments": "bb"}
    else:
        other, inputs = _store(_rule()), {"environments": "aa"}
        other.quarantined.append({"id": "p", "reason": "forged"})
    assert other.verified_snapshot(inputs=inputs).digest != base


def test_to_dict_names_everything():
    d = _store(_rule(), _rule(id="r2", principal="sre_lead")).verified_snapshot(
        inputs={"environments": "aa"}).to_dict()
    assert d["verified"] == ["r1"]
    assert d["excluded"] == [{"id": "r2", "reason": "unauthorized"}]
    assert d["inputs"] == {"environments": "aa"}
    assert len(d["digest"]) == 64 and d["aegis_version"]


# --- aegis snapshot (CLI) -----------------------------------------------------------


def _cli(argv, capsys):
    import json

    from aegis_core.cli import main

    code = main(argv)
    out = capsys.readouterr()
    return code, (json.loads(out.out) if code == 0 and out.out.startswith("{") else None), out


@pytest.fixture
def policy_dir(tmp_path, monkeypatch):
    """The example policy copied to a temp dir, signed with the example key."""
    import shutil

    from aegis_core.signing import load_key

    key = load_key("file:data/example-signing.key")
    monkeypatch.setenv("AEGIS_SIGNING_KEY", key.hex())
    d = tmp_path / "policy"
    shutil.copytree("data", d, ignore=shutil.ignore_patterns("corpus", "sources-forged"))
    return d, key


def test_snapshot_cli_reports_verified_rules_and_inputs(policy_dir, capsys):
    d, _key = policy_dir
    code, doc, _ = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert code == 0
    assert len(doc["verified"]) == 30 and doc["excluded"] == []
    assert {"environments", "plan_constraints", "sources_manifest"} <= set(doc["inputs"])


def test_snapshot_digest_follows_the_environment_map(policy_dir, capsys):
    from aegis_core.signing import sign_file

    d, key = policy_dir
    _, before, _ = _cli(["snapshot", "--config-dir", str(d)], capsys)
    env = d / "environments.example.yaml"
    env.write_text(env.read_text() + "\n# edited\n")
    sign_file(env, key)
    _, after, _ = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert before["digest"] != after["digest"]
    assert before["inputs"]["environments"] != after["inputs"]["environments"]


def test_snapshot_refuses_insecure(policy_dir, capsys):
    d, _ = policy_dir
    code, _, out = _cli(["snapshot", "--config-dir", str(d), "--insecure"], capsys)
    assert code == 64
    assert "refusing --insecure" in out.err


@pytest.mark.parametrize("name", ["environments.example.yaml",
                                  "plan_constraints.example.yaml"])
def test_snapshot_rejects_an_edited_unsigned_auxiliary_file(policy_dir, capsys, name):
    """P1: the environment and plan maps are decision-shaping inputs; an edit
    without re-signing used to be hashed into a 'trusted' snapshot."""
    d, _ = policy_dir
    f = d / name
    f.write_text(f.read_text() + "\n# edited, not re-signed\n")
    code, _, out = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert code == 65
    assert "signature" in out.err.lower()


def test_snapshot_requires_a_signed_agents_file(policy_dir, capsys):
    d, key = policy_dir
    (d / "agents.yaml").write_text("trusted: []\n")
    code, _, out = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert code == 65
    from aegis_core.signing import sign_file

    sign_file(d / "agents.yaml", key)
    code, doc, _ = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert code == 0 and "agents" in doc["inputs"]


def test_snapshot_refuses_disabled_sources_and_excludes_unchecked_rules(policy_dir, capsys):
    """P1: --sources '' used to list every file-sourced rule as verified."""
    import shutil

    d, _ = policy_dir
    code, _, out = _cli(["snapshot", "--config-dir", str(d), "--sources", ""], capsys)
    assert code == 64 and "--sources" in out.err
    shutil.rmtree(d / "sources")  # no sources directory at all
    code, doc, _ = _cli(["snapshot", "--config-dir", str(d)], capsys)
    assert code == 0
    assert doc["verified"] == []
    assert {e["reason"] for e in doc["excluded"]} == {"source-unverified"}
