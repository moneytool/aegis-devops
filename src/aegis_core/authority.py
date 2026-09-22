"""Loads the authority policy: which principal may assert which constraint class."""

from pathlib import Path

import yaml

from aegis_core.signing import check_signature


class AuthorityMap(dict[str, set[str]]):
    """``{principal: {constraint_class, ...}}`` -- a plain ``dict`` (equal
    to, and usable as, one) that also carries the load's ``warnings``
    (e.g. ``"unsigned: <path>"``) and the ``path`` it came from."""

    def __init__(self, *args, path: str = "", warnings: list[str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.path = path
        self.warnings: list[str] = list(warnings or [])


def load_authority_map(
    path: str | Path, *, key: bytes | None = None, insecure: bool = False
) -> AuthorityMap:
    """Reads a YAML file shaped like:

    principals:
      admin: [scaling, deletion, configuration]
      sre_lead: [scaling, configuration]
      developer: [configuration]

    With ``key``, the file must carry a valid ``<path>.sig``
    (:class:`aegis_core.signing.SignatureError` otherwise). Without a key
    and without ``insecure``, ``"unsigned: <path>"`` is recorded in the
    returned map's ``warnings``. Malformed shapes raise ``ValueError``.
    """
    warnings: list[str] = []
    check_signature(path, key, insecure, warnings)
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict) or not isinstance(raw.get("principals", {}), dict):
        raise ValueError(f"{path}: authority file must be a mapping with a 'principals' mapping")
    result = AuthorityMap(path=str(path), warnings=warnings)
    for principal, classes in (raw.get("principals") or {}).items():
        if classes is None:
            classes = []
        if not isinstance(classes, list) or not all(isinstance(c, str) for c in classes):
            raise ValueError(f"{path}: principals.{principal} must be a list of class names")
        result[str(principal)] = set(classes)
    return result
