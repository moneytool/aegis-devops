"""Root of trust for policy files (REVIEW-4 T1.1).

Every file a loader trusts -- constraints, plan constraints, authority map,
environment map, source snapshots and the sources' ``PRINCIPALS.yaml`` --
must be covered by a keyed ``blake2b`` MAC. Two forms exist:

* a **detached signature** ``<file>.sig`` (``aegis-sig-v1`` header + hex
  MAC of the file bytes) for the handful of top-level policy files;
* a **manifest** ``<dir>/AEGIS-MANIFEST.sig`` for a directory of source
  snapshots: one JSON document ``{"header": "aegis-manifest-v1", "files":
  {relpath: sha256}, "sig": <MAC of the canonical files mapping>}``.
  :func:`sign_tree` writes one; :func:`check_signature` finds the nearest
  manifest above a file and verifies both the manifest MAC and the
  file's sha256 entry. Hundreds of per-file ``.sig`` files become one.

A loader given a ``key`` refuses a file that is neither detached-signed nor
listed in a valid manifest (:class:`SignatureError`); a loader given no
key still works for library callers but records ``"unsigned: <path>"``
so the CLI can refuse to decide unless ``--insecure``.

The key is a shared secret (MAC, not a public-key signature): whoever can
sign can also verify. That is the v1 boundary REVIEW-4 T1.1 accepts --
Aegis defends against poisoned *content* from sources the operator chose
to trust, not against an attacker holding the signing key.

``python -m aegis_core.signing sign --key file:K path...`` (re)generates
signatures (a manifest for a directory, a detached ``.sig`` for a file);
``verify`` checks them. ``aegis sign`` / ``aegis verify`` are the same.
"""

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

SIG_HEADER = "aegis-sig-v1"
MANIFEST_HEADER = "aegis-manifest-v1"
MANIFEST_NAME = "AEGIS-MANIFEST.sig"
_SIGNED_SUFFIXES = (".json", ".yaml", ".yml")


class SignatureError(Exception):
    """A required signature is missing or does not verify."""


def sig_path(path: str | Path) -> Path:
    return Path(f"{path}.sig")


def _mac(data: bytes, key: bytes) -> str:
    return hashlib.blake2b(data, key=key, digest_size=32).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_key(source: str) -> bytes:
    """``env:VAR`` (hex in the environment), ``file:<path>`` (hex, ``#``
    comment lines ignored), or a raw hex string."""
    if source.startswith("env:"):
        text = os.environ.get(source[4:], "")
        if not text:
            raise SignatureError(f"signing key: environment variable {source[4:]} is unset")
    elif source.startswith("file:"):
        lines = Path(source[5:]).read_text().splitlines()
        text = "".join(line.strip() for line in lines if not line.lstrip().startswith("#"))
    else:
        text = source.strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise SignatureError("signing key must be hex") from None
    if len(key) < 16:
        raise SignatureError("signing key must be at least 16 bytes (32 hex chars)")
    return key


# --- detached signatures ----------------------------------------------------------


def sign_file(path: str | Path, key: bytes) -> Path:
    """Writes ``<path>.sig`` (``aegis-sig-v1`` header + hex MAC) and returns it."""
    out = sig_path(path)
    out.write_text(f"{SIG_HEADER}\n{_mac(Path(path).read_bytes(), key)}\n")
    return out


def _verify_detached(path: Path, key: bytes) -> bool:
    try:
        lines = sig_path(path).read_text().splitlines()
    except FileNotFoundError:
        return False
    if len(lines) < 2 or lines[0].strip() != SIG_HEADER:
        return False
    return hmac.compare_digest(lines[1].strip(), _mac(path.read_bytes(), key))


# --- manifests --------------------------------------------------------------------


def _canonical_files(files: dict[str, str]) -> bytes:
    return json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signable_files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(
            p for p in path.rglob("*")
            if p.is_file() and p.suffix in _SIGNED_SUFFIXES and p.name != MANIFEST_NAME
        )
    return [path]


def _verifiable_files(path: Path) -> list[Path]:
    """The files ``aegis verify`` actually checks under ``path`` (REVIEW-4
    L1) -- unlike :func:`_signable_files` (used by ``sign``, which covers
    everything under a directory the operator explicitly pointed it at),
    ``verify`` only looks at files that were *actually signed*: one with
    its own ``<file>.sig``, or one listed in an ``AEGIS-MANIFEST.sig``
    found at or below ``path``.

    A policy directory can legitimately contain unrelated, unsigned
    content -- e.g. ``data/corpus/seeds.yaml``, ``split.json``,
    ``stats.json`` are corpus-generation artifacts no Aegis loader ever
    reads -- and those must never be reported ``FAILED`` just because they
    happen to be ``.yaml``/``.json`` files sitting near real policy files.
    Explicit file arguments are unaffected: passing one directly (not via a
    directory walk) always checks it, signed or not (a real gap will still
    surface as ``FAILED`` on the file itself, or by naming the directory
    that has -- or should have -- a manifest covering it).
    """
    if not path.is_dir():
        return [path]
    found: dict[Path, None] = {}
    for p in sorted(path.rglob("*")):
        if p.is_file() and p.suffix in _SIGNED_SUFFIXES and p.name != MANIFEST_NAME:
            if sig_path(p).exists():
                found[p] = None
    for manifest in sorted(path.rglob(MANIFEST_NAME)):
        try:
            document = json.loads(manifest.read_text())
        except (OSError, ValueError):
            continue
        files = document.get("files") if isinstance(document, dict) else None
        if not isinstance(files, dict):
            continue
        for rel in files:
            candidate = (manifest.parent / str(rel)).resolve()
            found[candidate] = None
    return sorted(found)


def manifest_path(directory: str | Path) -> Path:
    return Path(directory) / MANIFEST_NAME


def sign_tree(directory: str | Path, key: bytes) -> list[Path]:
    """Writes one ``<directory>/AEGIS-MANIFEST.sig`` covering every
    ``.json``/``.yaml`` under ``directory`` (recursively) and returns
    ``[manifest_path]``. Stale per-file ``.sig`` files next to the covered
    files are removed so a detached signature can never contradict the
    manifest."""
    directory = Path(directory)
    files: dict[str, str] = {}
    for p in _signable_files(directory):
        files[p.relative_to(directory).as_posix()] = _sha256(p)
        stale = sig_path(p)
        if stale.exists():
            stale.unlink()
    document = {
        "header": MANIFEST_HEADER,
        "files": files,
        "sig": _mac(_canonical_files(files), key),
    }
    out = manifest_path(directory)
    out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return [out]


def read_manifest(path: str | Path, key: bytes) -> dict[str, str]:
    """The ``files`` mapping of a manifest whose MAC verifies under ``key``;
    :class:`SignatureError` otherwise."""
    path = Path(path)
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SignatureError(f"bad manifest: {path}: {exc}") from None
    if (
        not isinstance(document, dict)
        or document.get("header") != MANIFEST_HEADER
        or not isinstance(document.get("files"), dict)
        or not isinstance(document.get("sig"), str)
    ):
        raise SignatureError(f"bad manifest: {path}: not an {MANIFEST_HEADER} document")
    files = {str(k): str(v) for k, v in document["files"].items()}
    if not hmac.compare_digest(document["sig"], _mac(_canonical_files(files), key)):
        raise SignatureError(f"bad manifest: {path}: MAC does not verify")
    return files


def _nearest_manifest(path: Path) -> Path | None:
    for parent in path.resolve().parents:
        candidate = parent / MANIFEST_NAME
        if candidate.exists():
            return candidate
    return None


def _verify_via_manifest(path: Path, key: bytes) -> str | None:
    """``None`` when ``path`` is listed in the nearest valid manifest with a
    matching sha256, else why not."""
    manifest = _nearest_manifest(path)
    if manifest is None:
        return f"unsigned: {path} (no {sig_path(path).name} and no {MANIFEST_NAME} above it)"
    files = read_manifest(manifest, key)
    rel = path.resolve().relative_to(manifest.parent.resolve()).as_posix()
    expected = files.get(rel)
    if expected is None:
        return f"unsigned: {path} (not listed in {manifest})"
    if not hmac.compare_digest(expected, _sha256(path)):
        return f"bad signature: {path} does not match its entry in {manifest}"
    return None


# --- the shared gate -----------------------------------------------------------------


def verify_file(path: str | Path, key: bytes) -> bool:
    """True iff ``path`` carries a valid detached ``.sig`` or is listed
    (with a matching sha256) in a valid ``AEGIS-MANIFEST.sig`` above it."""
    try:
        require_signature(path, key)
    except SignatureError:
        return False
    return True


def require_signature(path: str | Path, key: bytes) -> None:
    """Raises :class:`SignatureError` unless ``path`` verifies under ``key``:
    a detached ``<path>.sig`` is checked first (and is authoritative when
    present); otherwise the nearest manifest above the file."""
    path = Path(path)
    if sig_path(path).exists():
        if not _verify_detached(path, key):
            raise SignatureError(f"bad signature: {path} does not match {sig_path(path).name}")
        return
    problem = _verify_via_manifest(path, key)
    if problem is not None:
        raise SignatureError(problem)


def check_signature(
    path: str | Path, key: bytes | None, insecure: bool, warnings: list[str]
) -> None:
    """The loaders' shared gate: with a key, enforce; with none, record
    ``"unsigned: <path>"`` unless the caller opted into ``insecure``."""
    if key is not None:
        require_signature(path, key)
    elif not insecure:
        warnings.append(f"unsigned: {path}")


def _main(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m aegis_core.signing")
    ap.add_argument("command", choices=["sign", "verify"])
    ap.add_argument("--key", required=True, help="env:VAR | file:PATH | hex")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args(argv)
    key = load_key(args.key)
    return run(args.command, key, args.paths)


def run(command: str, key: bytes, paths: list[str], out=None) -> int:
    """``sign``/``verify`` each path (a directory gets a manifest, a file a
    detached ``.sig``). Prints one line per item; returns 1 if any verify
    failed, else 0."""
    out = out or sys.stdout
    failed = 0
    for raw in paths:
        target = Path(raw)
        if command == "sign":
            written = sign_tree(target, key) if target.is_dir() else [sign_file(target, key)]
            for p in written:
                print(f"signed  {p}", file=out)
            continue
        for f in _verifiable_files(target):
            if verify_file(f, key):
                print(f"ok      {f}", file=out)
            else:
                print(f"FAILED  {f}", file=out)
                failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
