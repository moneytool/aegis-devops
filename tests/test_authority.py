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
