"""Provenance hashing and source verification.

The provenance hash proves a constraint has not been altered since it was
derived from its source (a Git commit, a Slack message, a ticket). It is
computed only from the *source-side* fields — never from ingest-time
bookkeeping like "when did our store first see this" — so that re-deriving
the hash from the original source (see ``verify_source``) is meaningful.
"""

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol


def compute_provenance_hash(
    *,
    provider: str,
    resource_pattern: str,
    actions: Iterable[str],
    scope: dict[str, Any],
    time_window: dict[str, Any] | None,
    effect: str,
    constraint_class: str,
    principal: str,
    source_ref: str,
    source_timestamp: str,
    rule_text: str,
) -> str:
    """SHA-256 of the canonical JSON serialisation of the source fields."""
    payload = {
        "provider": provider,
        "resource_pattern": resource_pattern,
        "actions": sorted(actions),
        "scope": scope,
        "time_window": time_window,
        "effect": effect,
        "constraint_class": constraint_class,
        "principal": principal,
        "source_ref": source_ref,
        "source_timestamp": source_timestamp,
        "rule_text": rule_text,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class SourceFetcher(Protocol):
    """Re-fetches the original source content for a ``source_ref``."""

    def fetch(self, source_ref: str) -> dict[str, Any]:
        ...


class FileSourceFetcher:
    """Reads ``<base_dir>/<source_ref>.json`` as the source of truth.

    Stands in for a real Git/Slack connector in v1. The adversarial test
    suite forges files under this directory to simulate a poisoned or
    edited source.
    """

    def __init__(self, base_dir: str | Path = "data/sources"):
        self.base_dir = Path(base_dir)

    def fetch(self, source_ref: str) -> dict[str, Any]:
        path = self.base_dir / f"{source_ref}.json"
        with open(path) as f:
            return json.load(f)


def verify_source(constraint, fetcher: SourceFetcher) -> bool:
    """Re-derives the provenance hash from the original source and compares it.

    Returns False if the source's current content would hash to something
    other than what the constraint claims — whether because the source
    changed after ingest or because the constraint's own fields were
    tampered with.
    """
    source = fetcher.fetch(constraint.source_ref)
    recomputed = compute_provenance_hash(
        provider=source["provider"],
        resource_pattern=source["resource_pattern"],
        actions=source["actions"],
        scope=source["scope"],
        time_window=source.get("time_window"),
        effect=source["effect"],
        constraint_class=source["constraint_class"],
        principal=source["principal"],
        source_ref=source["source_ref"],
        source_timestamp=source["source_timestamp"],
        rule_text=source["rule_text"],
    )
    return recomputed == constraint.provenance_hash
