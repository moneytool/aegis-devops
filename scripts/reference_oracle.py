#!/usr/bin/env python3
"""Reference oracle: independent ground truth for the benchmark corpus.

This file must never import aegis_core.interceptor, aegis_core.store, or
aegis_core.plan. It exists so the benchmark's ground truth is not the
system under test.

It is a deliberately naive re-implementation of the constraint-matching
semantics PLAN.md §4 defines, driven off the *labels* rather than off
Aegis's own hash / authority machinery:

  * constraints  — ``constraints.yaml`` read with plain ``yaml.safe_load``
                   (every entry, tampered / forged / unauthorized included,
                   exactly as the file has them);
  * labels       — ``labels.jsonl`` decides which constraints are Trusted.
                   No hash is recomputed, no authority map is consulted;
  * matching     — ``provider ==``, ``fnmatch(resource, resource_pattern)``,
                   ``action in actions``, every scope key equal in
                   ``{**metadata, **params}``, and a minimal time-window
                   check (weekday abbreviation in ``days``,
                   ``start <= HH:MM <= end`` in ``tz`` via ``zoneinfo``).

Per intent it emits:

  expected_verdict   BLOCK if any matched Trusted rule is BLOCK, else
                     ESCALATE if any matched Trusted rule is ESCALATE,
                     else ALLOW.  Only Trusted rules drive the verdict.
  expected_covered   any constraint of ANY label matched.
  matched_trusted / matched_untrusted / matched_malicious   id lists.
  poison_candidate   expected_verdict == ALLOW and a non-Trusted rule
                     matched — i.e. the only rules that applied are ones a
                     provenance/authority-blind verifier would obey.
  poison_kind        strongest matched non-Trusted reason
                     (forged > tampered > unauthorized), or "none".
  poison_kinds       every non-Trusted reason that matched (sorted), so a
                     candidate covered by both a forged and an unauthorized
                     rule can be told apart from a pure case.

Usage:
    python scripts/reference_oracle.py --corpus data/corpus \\
        --out data/corpus/intents.jsonl
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

WEEKDAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

# Strongest-first ordering for poison_kind when several poisoned rules match.
POISON_KIND_ORDER = ("forged", "tampered", "unauthorized")

EXPECTED_FIELDS = (
    "expected_verdict",
    "expected_covered",
    "matched_trusted",
    "matched_untrusted",
    "matched_malicious",
    "poison_candidate",
    "poison_kind",
    "poison_kinds",
)


# ---------------------------------------------------------------------------
# Plain readers
# ---------------------------------------------------------------------------


def read_constraints(path: Path) -> list[dict[str, Any]]:
    with open(path) as f:
        payload = yaml.safe_load(f) or {}
    return list(payload.get("constraints") or [])


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def read_labels(path: Path) -> dict[str, dict[str, str]]:
    return {rec["id"]: rec for rec in read_jsonl(path)}


def read_authority(path: Path) -> dict[str, list[str]]:
    """Read for completeness / cross-checks only; the oracle does NOT use
    it to decide Trusted-ness (labels.jsonl does)."""
    with open(path) as f:
        payload = yaml.safe_load(f) or {}
    return dict(payload.get("principals") or {})


# ---------------------------------------------------------------------------
# Minimal matcher
# ---------------------------------------------------------------------------


def time_window_matches(window: dict[str, Any] | None, now: datetime) -> bool:
    if not window:
        return True
    tz_name = window.get("tz")
    local = now.astimezone(ZoneInfo(tz_name)) if tz_name else now
    days = window.get("days")
    if days and WEEKDAY_ABBR[local.weekday()] not in days:
        return False
    start, end = window.get("start"), window.get("end")
    if start and end:
        hhmm = local.strftime("%H:%M")
        if not (str(start) <= hhmm <= str(end)):
            return False
    return True


def constraint_matches(c: dict[str, Any], intent: dict[str, Any], now: datetime) -> bool:
    if c.get("provider") != intent["provider"]:
        return False
    if not fnmatchcase(intent["resource"], c.get("resource_pattern", "")):
        return False
    if intent["action"] not in (c.get("actions") or []):
        return False
    combined = {**(intent.get("metadata") or {}), **(intent.get("params") or {})}
    for key, value in (c.get("scope") or {}).items():
        if combined.get(key) != value:
            return False
    return time_window_matches(c.get("time_window"), now)


def parse_now(value: str) -> datetime:
    now = datetime.fromisoformat(value)
    if now.tzinfo is None:
        now = now.replace(tzinfo=ZoneInfo("UTC"))
    return now


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------


def oracle_for_intent(
    intent: dict[str, Any],
    constraints: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
) -> dict[str, Any]:
    now = parse_now(intent["now"])
    matched_trusted: list[str] = []
    matched_untrusted: list[str] = []
    matched_malicious: list[str] = []
    trusted_effects: list[str] = []
    poison_reasons: list[str] = []

    for c in constraints:
        if not constraint_matches(c, intent, now):
            continue
        cid = c["id"]
        label_rec = labels.get(cid, {})
        label = label_rec.get("label")
        if label == "Trusted":
            matched_trusted.append(cid)
            trusted_effects.append(str(c.get("effect")))
        elif label == "Untrusted":
            matched_untrusted.append(cid)
            poison_reasons.append(label_rec.get("reason", "unauthorized"))
        else:
            matched_malicious.append(cid)
            poison_reasons.append(label_rec.get("reason", "tampered"))

    if "BLOCK" in trusted_effects:
        verdict = "BLOCK"
    elif "ESCALATE" in trusted_effects:
        verdict = "ESCALATE"
    else:
        verdict = "ALLOW"

    poison_candidate = verdict == "ALLOW" and bool(matched_untrusted or matched_malicious)
    poison_kind = "none"
    if poison_candidate:
        for kind in POISON_KIND_ORDER:
            if kind in poison_reasons:
                poison_kind = kind
                break

    return {
        "expected_verdict": verdict,
        "expected_covered": bool(matched_trusted or matched_untrusted or matched_malicious),
        "matched_trusted": matched_trusted,
        "matched_untrusted": matched_untrusted,
        "matched_malicious": matched_malicious,
        "poison_candidate": poison_candidate,
        "poison_kind": poison_kind,
        "poison_kinds": sorted(set(poison_reasons)) if poison_candidate else [],
    }


def oracle_verdicts_for(
    intents: list[dict[str, Any]],
    constraints: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """Returns one dict per intent (same order): ``{"id": ..., **EXPECTED_FIELDS}``."""
    out = []
    for intent in intents:
        rec = {"id": intent["id"]}
        rec.update(oracle_for_intent(intent, constraints, labels))
        out.append(rec)
    return out


def oracle_verdicts(corpus_dir: str | Path) -> list[dict[str, Any]]:
    corpus_dir = Path(corpus_dir)
    constraints = read_constraints(corpus_dir / "constraints.yaml")
    labels = read_labels(corpus_dir / "labels.jsonl")
    read_authority(corpus_dir / "authority.yaml")  # readable; unused for verdicts
    intents = read_jsonl(corpus_dir / "intents.jsonl")
    return oracle_verdicts_for(intents, constraints, labels)


def annotate_intents(
    intents: list[dict[str, Any]],
    constraints: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """Returns new intent records with every ``expected_*`` / oracle field
    (re)written, preserving ids and order."""
    annotated = []
    for intent, verdict in zip(intents, oracle_verdicts_for(intents, constraints, labels)):
        rec = {k: v for k, v in intent.items() if k not in EXPECTED_FIELDS}
        for key in EXPECTED_FIELDS:
            rec[key] = verdict[key]
        annotated.append(rec)
    return annotated


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None,
                        help="defaults to <corpus>/intents.jsonl (rewritten in place)")
    args = parser.parse_args()

    corpus = args.corpus
    out = args.out or corpus / "intents.jsonl"
    constraints = read_constraints(corpus / "constraints.yaml")
    labels = read_labels(corpus / "labels.jsonl")
    intents = read_jsonl(corpus / "intents.jsonl")
    annotated = annotate_intents(intents, constraints, labels)
    write_jsonl(out, annotated)

    from collections import Counter

    verdicts = Counter(r["expected_verdict"] for r in annotated)
    kinds = Counter(r["poison_kind"] for r in annotated if r["poison_candidate"])
    print(f"intents: {len(annotated)}  verdicts: {dict(sorted(verdicts.items()))}")
    print(f"poison candidates by kind: {dict(sorted(kinds.items()))}")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
