"""ConstraintStore.verified_snapshot (docs/dev/DESIGN-v0.3-server-side.md §3.1):
the frozen set of constraints that may vote, with everything else excluded
and a digest over all inputs."""

import dataclasses

import pytest

from aegis_core.store import ConstraintStore
from tests.test_interceptor import make_constraint

AUTHORITY = {"admin": {"deletion", "scaling"}, "sre_lead": {"scaling"}}


def _store(*constraints, authority=AUTHORITY):
    store = ConstraintStore(authority_map={p: set(c) for p, c in authority.items()})
    for c in constraints:
        store.constraints[c.id] = c
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
