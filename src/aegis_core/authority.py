"""Loads the authority policy: which principal may assert which constraint class."""

from pathlib import Path

import yaml


def load_authority_map(path: str | Path) -> dict[str, set[str]]:
    """Reads a YAML file shaped like:

    principals:
      admin: [scaling, deletion, configuration]
      sre_lead: [scaling, configuration]
      developer: [configuration]
    """
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    return {
        principal: set(classes)
        for principal, classes in raw.get("principals", {}).items()
    }
