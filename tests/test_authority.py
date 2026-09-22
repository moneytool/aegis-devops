from aegis_core.authority import load_authority_map


def test_load_authority_map_from_yaml(tmp_path):
    path = tmp_path / "authority.yaml"
    path.write_text(
        "principals:\n"
        "  admin:\n"
        "    - scaling\n"
        "    - deletion\n"
        "  developer:\n"
        "    - configuration\n"
    )
    authority_map = load_authority_map(path)
    assert authority_map == {
        "admin": {"scaling", "deletion"},
        "developer": {"configuration"},
    }


def test_example_authority_file_loads():
    authority_map = load_authority_map("data/authority.example.yaml")
    assert authority_map["admin"] == {"scaling", "deletion", "configuration"}
    assert authority_map["sre_lead"] == {"scaling", "configuration"}
    assert authority_map["developer"] == {"configuration"}


# --- REVIEW-4 T1.1: signed authority files -------------------------------------


def _write(tmp_path):
    path = tmp_path / "authority.yaml"
    path.write_text("principals:\n  admin: [deletion]\n")
    return path


def test_signed_authority_map_loads_with_no_warnings(tmp_path):
    from aegis_core.signing import sign_file

    key = b"k" * 32
    path = _write(tmp_path)
    sign_file(path, key)
    authority_map = load_authority_map(path, key=key)
    assert authority_map == {"admin": {"deletion"}}
    assert authority_map.warnings == []
    assert authority_map.path == str(path)


def test_tampered_or_unsigned_authority_map_raises_with_key(tmp_path):
    import pytest

    from aegis_core.signing import SignatureError, sign_file

    key = b"k" * 32
    path = _write(tmp_path)
    with pytest.raises(SignatureError, match="unsigned"):
        load_authority_map(path, key=key)
    sign_file(path, key)
    path.write_text("principals:\n  admin: [deletion]\n  intern: [deletion]\n")
    with pytest.raises(SignatureError, match="bad signature"):
        load_authority_map(path, key=key)


def test_no_key_records_unsigned_warning_unless_insecure(tmp_path):
    path = _write(tmp_path)
    assert load_authority_map(path).warnings == [f"unsigned: {path}"]
    assert load_authority_map(path, insecure=True).warnings == []


def test_example_authority_file_verifies_under_example_key():
    from aegis_core.signing import load_key

    key = load_key("file:data/example-signing.key")
    authority_map = load_authority_map("data/authority.example.yaml", key=key)
    assert authority_map["admin"] == {"scaling", "deletion", "configuration"}
    assert authority_map.warnings == []


def test_malformed_authority_shapes_raise_value_error(tmp_path):
    import pytest

    path = tmp_path / "authority.yaml"
    path.write_text("- admin\n")
    with pytest.raises(ValueError):
        load_authority_map(path, insecure=True)
    path.write_text("principals:\n  admin: deletion\n")
    with pytest.raises(ValueError):
        load_authority_map(path, insecure=True)
    path.write_text("principals:\n  admin:\n")  # null -> grants nothing, but loads
    assert load_authority_map(path, insecure=True) == {"admin": set()}
