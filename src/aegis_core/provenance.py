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

import yaml

from aegis_core.signing import check_signature

PRINCIPALS_FILE = "PRINCIPALS.yaml"


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
    rate_limit: dict[str, Any] | None = None,
) -> str:
    """SHA-256 of the canonical JSON serialisation of the source fields.

    ``rate_limit`` is included in the hashed payload only when it is not
    ``None``. This keeps the hash of every constraint that predates the
    rate-limit field (PLAN §7.6) byte-for-byte identical to before —
    omitting a key from the payload, rather than hashing it as
    ``"rate_limit": null``, is what makes that guarantee hold.
    """
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
    if rate_limit is not None:
        payload["rate_limit"] = rate_limit
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

    **Transport principal (REVIEW-4 T1.1).** A source payload's own
    ``principal`` field is self-asserted and therefore untrusted. The
    principal a source is attributed to comes from the *transport* -- for
    the file transport, a signed ``<base_dir>/PRINCIPALS.yaml`` mapping
    ``source_ref -> principal`` (``principal_map``). :meth:`principal_for`
    returns ``None`` when the fetcher has no map at all, in which case
    :func:`verify_source` falls back to the payload (and says so).

    **Signatures.** With ``key`` set, every fetched ``.json`` and the
    principals file must carry a valid ``.sig`` (:class:`SignatureError`
    otherwise). Without a key and without ``insecure``, each unsigned load
    is recorded in ``warnings`` for the store to surface.
    """

    def __init__(
        self,
        base_dir: str | Path = "data/sources",
        *,
        key: bytes | None = None,
        insecure: bool = False,
        principal_map: dict[str, str] | None = None,
    ):
        self.base_dir = Path(base_dir)
        self.key = key
        self.insecure = insecure
        self.warnings: list[str] = []
        self.principal_map: dict[str, str] | None = principal_map
        if principal_map is None:
            principals_path = self.base_dir / PRINCIPALS_FILE
            if principals_path.exists():
                self.principal_map = load_principal_map(
                    principals_path, key=key, insecure=insecure, warnings=self.warnings
                )

    def principal_for(self, source_ref: str) -> str | None:
        """The transport's principal for ``source_ref``: ``None`` if this
        fetcher has no principal map; ``""`` if it has one that doesn't
        list ``source_ref`` (an unattributed source never verifies)."""
        if self.principal_map is None:
            return None
        return self.principal_map.get(source_ref, "")

    def fetch(
        self, source_ref: str, *, key: bytes | None = None, insecure: bool | None = None
    ) -> dict[str, Any]:
        """``key``/``insecure`` override the fetcher-wide settings for one
        fetch. A ``source_ref`` containing a path separator, ``..``, a
        leading ``~``, an absolute path, or a NUL byte is rejected
        (``KeyError``) so a constraint can't cite ``../../x``, ``~/.ssh/id``,
        ``/etc/passwd``, or similar (REVIEW-4 L2). The resolved path is also
        confirmed to stay inside ``base_dir`` as defense-in-depth against any
        shape the string checks above don't anticipate."""
        if (
            "/" in source_ref
            or "\\" in source_ref
            or "\x00" in source_ref
            or source_ref in ("", ".", "..")
            or source_ref.startswith("~")
            or Path(source_ref).is_absolute()
        ):
            raise KeyError(f"invalid source_ref {source_ref!r}")
        path = self.base_dir / f"{source_ref}.json"
        resolved_base = self.base_dir.resolve()
        resolved_path = path.resolve()
        if not resolved_path.is_relative_to(resolved_base):
            raise KeyError(f"invalid source_ref {source_ref!r}")
        if not path.exists():
            raise FileNotFoundError(path)
        check_signature(
            path,
            self.key if key is None else key,
            self.insecure if insecure is None else insecure,
            self.warnings,
        )
        with open(path) as f:
            return json.load(f)


def load_principal_map(
    path: str | Path,
    *,
    key: bytes | None = None,
    insecure: bool = False,
    warnings: list[str] | None = None,
) -> dict[str, str]:
    """Reads ``PRINCIPALS.yaml`` (``principals: {source_ref: principal}``),
    enforcing/recording its signature like every other loader."""
    warnings = warnings if warnings is not None else []
    check_signature(path, key, insecure, warnings)
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict) or not isinstance(raw.get("principals", {}), dict):
        raise ValueError(f"{path}: must be a mapping with a 'principals' mapping")
    return {str(ref): str(principal) for ref, principal in (raw.get("principals") or {}).items()}


class CachingSourceFetcher:
    """Wraps a :class:`SourceFetcher`, memoising both successful fetches and
    the exceptions raised by missing/unreadable sources, keyed by
    ``source_ref``.

    Used by ``ConstraintStore.load``/``verify_sources`` so that many
    constraints citing the same ``source_ref`` only hit the underlying
    fetcher once per load or audit pass.
    """

    def __init__(self, fetcher: SourceFetcher):
        self._fetcher = fetcher
        self._cache: dict[str, Any] = {}

    @property
    def warnings(self) -> list[str]:
        return getattr(self._fetcher, "warnings", [])

    def principal_for(self, source_ref: str) -> str | None:
        inner = getattr(self._fetcher, "principal_for", None)
        return inner(source_ref) if inner is not None else None

    def fetch(self, source_ref: str) -> dict[str, Any]:
        if source_ref in self._cache:
            cached = self._cache[source_ref]
            if isinstance(cached, Exception):
                raise cached
            return cached
        try:
            result = self._fetcher.fetch(source_ref)
        except (FileNotFoundError, KeyError) as exc:
            self._cache[source_ref] = exc
            raise
        self._cache[source_ref] = result
        return result


def verify_source_reason(
    constraint, fetcher: SourceFetcher, warnings: list[str] | None = None
) -> str | None:
    """Re-derives the provenance hash from the original source and compares
    it. Returns ``None`` when the source backs the constraint, else the
    quarantine reason:

    * ``"principal-mismatch"`` -- the transport attributes the source to a
      different principal than the constraint claims (or to nobody);
    * ``"forged"`` -- the source's content hashes to something else, so
      either the source changed after ingest or the constraint's fields
      were rewritten.

    When the fetcher has no transport principal (no ``PRINCIPALS.yaml``,
    or a fetcher that doesn't implement ``principal_for``) the payload's
    own ``principal`` is used and ``"principal-from-payload: <ref>"`` is
    appended to ``warnings`` (if given).
    """
    source = fetcher.fetch(constraint.source_ref)
    principal_for = getattr(fetcher, "principal_for", None)
    transport_principal = principal_for(constraint.source_ref) if principal_for else None
    if transport_principal is None:
        principal = source["principal"]
        if warnings is not None:
            warnings.append(f"principal-from-payload: {constraint.source_ref}")
    else:
        principal = transport_principal
        if principal != constraint.principal:
            return "principal-mismatch"
    recomputed = compute_provenance_hash(
        provider=source["provider"],
        resource_pattern=source["resource_pattern"],
        actions=source["actions"],
        scope=source["scope"],
        time_window=source.get("time_window"),
        effect=source["effect"],
        constraint_class=source["constraint_class"],
        principal=principal,
        source_ref=source["source_ref"],
        source_timestamp=source["source_timestamp"],
        rule_text=source["rule_text"],
        rate_limit=source.get("rate_limit"),
    )
    return None if recomputed == constraint.provenance_hash else "forged"


def verify_source(constraint, fetcher: SourceFetcher) -> bool:
    """``True`` iff :func:`verify_source_reason` finds nothing wrong."""
    return verify_source_reason(constraint, fetcher) is None
