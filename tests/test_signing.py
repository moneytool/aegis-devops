"""REVIEW-4 T1.1: detached keyed signatures for policy files."""

import json
from pathlib import Path

import pytest

from aegis_core.signing import (
    MANIFEST_NAME,
    SIG_HEADER,
    SignatureError,
    _main,
    load_key,
    manifest_path,
    read_manifest,
    require_signature,
    sig_path,
    sign_file,
    sign_tree,
    verify_file,
)

KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
OTHER_KEY = bytes.fromhex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
EXAMPLE_KEY_PATH = "data/example-signing.key"


def test_sign_then_verify_round_trip(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("principals: {}\n")
    sig = sign_file(f, KEY)
    assert sig == sig_path(f) == tmp_path / "policy.yaml.sig"
    lines = sig.read_text().splitlines()
    assert lines[0] == SIG_HEADER
    assert len(lines[1]) == 64
    assert verify_file(f, KEY) is True
    require_signature(f, KEY)  # no raise


def test_verify_fails_after_tamper_with_old_signature(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("principals: {admin: [deletion]}\n")
    sign_file(f, KEY)
    f.write_text("principals: {admin: [deletion], intern: [deletion]}\n")
    assert verify_file(f, KEY) is False
    with pytest.raises(SignatureError, match="bad signature"):
        require_signature(f, KEY)


def test_verify_fails_with_wrong_key_or_missing_or_garbage_sig(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("x: 1\n")
    assert verify_file(f, KEY) is False  # no .sig at all
    with pytest.raises(SignatureError, match="unsigned"):
        require_signature(f, KEY)
    sign_file(f, KEY)
    assert verify_file(f, OTHER_KEY) is False
    sig_path(f).write_text("not-a-signature\n")
    assert verify_file(f, KEY) is False
    sig_path(f).write_text(f"{SIG_HEADER}\n")  # header only
    assert verify_file(f, KEY) is False


def test_load_key_from_hex_env_and_file(tmp_path, monkeypatch):
    hexkey = KEY.hex()
    assert load_key(hexkey) == KEY
    assert load_key(f"  {hexkey}\n") == KEY
    monkeypatch.setenv("AEGIS_SIGNING_KEY", hexkey)
    assert load_key("env:AEGIS_SIGNING_KEY") == KEY
    keyfile = tmp_path / "k.key"
    keyfile.write_text(f"# comment line\n{hexkey}\n")
    assert load_key(f"file:{keyfile}") == KEY
    assert len(load_key(f"file:{EXAMPLE_KEY_PATH}")) == 32


def test_load_key_rejects_unset_env_bad_hex_and_short_keys(monkeypatch):
    monkeypatch.delenv("AEGIS_NOPE", raising=False)
    with pytest.raises(SignatureError, match="unset"):
        load_key("env:AEGIS_NOPE")
    with pytest.raises(SignatureError, match="hex"):
        load_key("not-hex-at-all")
    with pytest.raises(SignatureError, match="at least 16 bytes"):
        load_key("deadbeef")


def test_sign_tree_writes_one_manifest_covering_every_json_and_yaml(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "PRINCIPALS.yaml").write_text("principals: {}\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.json").write_text("{}")
    (tmp_path / "README.md").write_text("ignored")
    stale = sign_file(tmp_path / "a.json", OTHER_KEY)  # a per-file sig from an older run
    written = sign_tree(tmp_path, KEY)
    assert written == [manifest_path(tmp_path)] == [tmp_path / MANIFEST_NAME]
    assert not stale.exists(), "sign_tree removes stale per-file .sig files"
    assert sorted(read_manifest(written[0], KEY)) == ["PRINCIPALS.yaml", "a.json", "sub/b.json"]
    for name in ("a.json", "PRINCIPALS.yaml", "sub/b.json"):
        assert verify_file(tmp_path / name, KEY), name
        require_signature(tmp_path / name, KEY)
    assert not (tmp_path / "README.md.sig").exists()
    assert verify_file(tmp_path / "README.md", KEY) is False  # not listed


def test_manifest_detects_edited_added_and_wrong_key_files(tmp_path):
    (tmp_path / "a.json").write_text('{"x": 1}')
    sign_tree(tmp_path, KEY)
    assert verify_file(tmp_path / "a.json", OTHER_KEY) is False
    with pytest.raises(SignatureError, match="bad manifest"):
        require_signature(tmp_path / "a.json", OTHER_KEY)
    # A file added after signing is unsigned, not silently accepted.
    (tmp_path / "new.json").write_text("{}")
    with pytest.raises(SignatureError, match="not listed"):
        require_signature(tmp_path / "new.json", KEY)
    # Editing a listed file breaks its sha256 entry.
    (tmp_path / "a.json").write_text('{"x": 2}')
    with pytest.raises(SignatureError, match="bad signature"):
        require_signature(tmp_path / "a.json", KEY)
    # Editing the manifest itself breaks its MAC.
    doc = json.loads(manifest_path(tmp_path).read_text())
    doc["files"]["a.json"] = "0" * 64
    manifest_path(tmp_path).write_text(json.dumps(doc))
    with pytest.raises(SignatureError, match="MAC does not verify"):
        require_signature(tmp_path / "a.json", KEY)
    manifest_path(tmp_path).write_text("garbage")
    with pytest.raises(SignatureError, match="bad manifest"):
        require_signature(tmp_path / "a.json", KEY)


def test_detached_sig_is_authoritative_over_a_manifest(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    sign_tree(tmp_path, KEY)
    sign_file(tmp_path / "a.json", OTHER_KEY)  # a wrong detached sig beats a good manifest
    with pytest.raises(SignatureError, match="does not match a.json.sig"):
        require_signature(tmp_path / "a.json", KEY)


def test_main_sign_and_verify_commands(tmp_path, capsys):
    f = tmp_path / "c.yaml"
    f.write_text("constraints: []\n")
    assert _main(["sign", "--key", KEY.hex(), str(f)]) == 0
    assert _main(["verify", "--key", KEY.hex(), str(tmp_path)]) == 0
    assert "ok" in capsys.readouterr().out
    assert _main(["sign", "--key", KEY.hex(), str(tmp_path)]) == 0
    assert (tmp_path / MANIFEST_NAME).exists() and not sig_path(f).exists()
    assert _main(["verify", "--key", KEY.hex(), str(tmp_path)]) == 0
    capsys.readouterr()
    f.write_text("constraints: [{}]\n")
    assert _main(["verify", "--key", KEY.hex(), str(f)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_shipped_example_and_corpus_files_verify_under_the_example_key():
    key = load_key(f"file:{EXAMPLE_KEY_PATH}")
    for path in (
        "data/constraints.example.yaml",
        "data/authority.example.yaml",
        "data/environments.example.yaml",
        "data/plan_constraints.example.yaml",
        "data/sources/PRINCIPALS.yaml",
        "data/sources/jira-1001.json",
        "data/corpus/constraints.yaml",
        "data/corpus/authority.yaml",
        "data/corpus/sources/PRINCIPALS.yaml",
        "data/corpus/sources/src-0003.json",
    ):
        assert verify_file(path, key), path
    assert not any(p.name.endswith(".json.sig") for p in Path("data").rglob("*.sig"))
    assert len(list(Path("data").rglob("*.sig"))) <= 8
