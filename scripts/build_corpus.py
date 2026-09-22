#!/usr/bin/env python3
"""Builds the Aegis evaluation corpus described in PLAN.md §4.

Expands the hand-derived seeds in ``data/corpus/seeds.yaml`` (themselves
drawn from the Kubernetes failure-stories index and the OPA Gatekeeper
policy library) into exactly 500 labeled constraints, using
``aegis_core.store`` and ``aegis_core.provenance`` directly so every hash
is real, not simulated.

Labels (operational definitions, PLAN.md §4):
  * Trusted   (~50%) — valid provenance, principal IS authorized.
  * Untrusted (~25%) — valid provenance, principal is NOT authorized.
  * Malicious (~25%) — provenance fails, split evenly between:
      - tampered: hash computed over the original fields, then one field
        mutated afterward (so ``verify_integrity`` fails and
        ``ConstraintStore.load`` quarantines it). The source file matches
        the ORIGINAL (pre-mutation) fields.
      - forged: the constraint's own fields and hash are self-consistent
        (loads fine), but its source file is either absent or contains
        different content, so only ``verify_source`` catches it.

Everything is driven off a single ``random.Random(seed)`` instance in a
fixed sequence of operations, so re-running with the same ``--seed``
produces byte-identical ``constraints.yaml``, ``labels.jsonl``,
``split.json``, ``intents.jsonl`` and ``stats.json``.

Ground truth for the intents (``expected_verdict`` etc.) comes from
``scripts/reference_oracle.py`` — an independent, label-driven matcher that
never imports the interceptor — so the benchmark's ground truth is not the
system under test (REVIEW-4 T0.5).
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from aegis_core.signing import load_key, sign_file, sign_tree
from aegis_core.store import Constraint, ConstraintStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_oracle  # noqa: E402  (scripts/reference_oracle.py)

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "data" / "corpus"
SEEDS_PATH = CORPUS_DIR / "seeds.yaml"
SOURCES_DIR = CORPUS_DIR / "sources"
EXAMPLE_KEY_PATH = REPO_ROOT / "data" / "example-signing.key"
PRINCIPALS_HEADER = """\
# Transport-level attribution for the source snapshots in this directory
# (REVIEW-4 T1.1): which principal each source_ref is attributed to by the
# transport (repo owner, ticket author, Slack user), independently of the
# self-asserted `principal` inside the payload. Signed like every other
# policy file; loaded by aegis_core.provenance.FileSourceFetcher.
"""

TOTAL_CONSTRAINTS = 500
TRUSTED_COUNT = 250
UNTRUSTED_COUNT = 125
MALICIOUS_COUNT = 125
TAMPERED_COUNT = 62
FORGED_COUNT = MALICIOUS_COUNT - TAMPERED_COUNT  # 63

NUM_INTENTS = 600
INTENTS_ON_TRUSTED = 300
INTENTS_ON_NONTRUSTED = 150
INTENTS_ON_NOTHING = 150
# When drawing an intent aimed at a non-Trusted constraint, retry this many
# times looking for one that no Trusted rule also covers (a real poison
# candidate); the corpus shares structure across labels, so a blind draw
# is usually shadowed by a Trusted rule with the same shape.
POISON_SEEK_ATTEMPTS = 25

AUTHORITY = {
    "platform_admin": [
        "scaling", "deletion", "configuration", "deployment", "networking", "access",
    ],
    "sre_lead": ["scaling", "deletion", "deployment", "networking"],
    "sre_oncall": ["scaling", "deployment"],
    "security_lead": ["access", "networking", "configuration"],
    "developer": ["configuration"],
    "contractor": [],
    "ci_bot": ["deployment"],
}

NAMESPACES = ["prod", "staging", "dev", "kube-system"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
CLUSTERS = ["prod-us-east-1", "prod-eu-west-1", "staging-us-west-2"]
RESOURCE_NAMES = ["api", "web", "worker", "cache", "billing", "auth", "gateway", "ingest"]

_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri"]
TIME_WINDOW_POOL = [
    {"days": _WEEKDAYS, "start": "09:00", "end": "17:00", "tz": "America/New_York"},
    {"days": ["Sat", "Sun"], "start": "00:00", "end": "23:59", "tz": "UTC"},
    {"days": _WEEKDAYS, "start": "00:00", "end": "06:00", "tz": "UTC"},
    {"days": _WEEKDAYS, "start": "08:00", "end": "20:00", "tz": "America/Los_Angeles"},
]

_WEEKDAY_ABBR = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

TAMPER_MUTATIONS = ["rule_text", "effect", "actions", "scope"]


# ---------------------------------------------------------------------------
# Seed loading & variation
# ---------------------------------------------------------------------------

def load_seeds() -> list[dict]:
    with open(SEEDS_PATH) as f:
        payload = yaml.safe_load(f)
    return payload["seeds"]


def narrow_pattern(pattern: str, rng: random.Random) -> str:
    """Occasionally narrows a `kind/*` pattern to `kind/name-*`."""
    if pattern.endswith("/*") and rng.random() < 0.3:
        prefix = pattern[:-1]  # keep trailing "/"
        name = rng.choice(RESOURCE_NAMES)
        return f"{prefix}{name}-*"
    return pattern


def vary_scope(seed_scope: dict, rng: random.Random) -> dict:
    scope = dict(seed_scope)
    for key in list(scope.keys()):
        if key == "namespace":
            scope[key] = rng.choice(NAMESPACES)
        elif key == "region":
            scope[key] = rng.choice(REGIONS)
        elif key == "cluster":
            scope[key] = rng.choice(CLUSTERS)
    return scope


def vary_time_window(seed_tw: dict | None, rng: random.Random) -> dict | None:
    if seed_tw is None:
        return None
    if rng.random() < 0.5:
        return dict(seed_tw)
    return copy.deepcopy(rng.choice(TIME_WINDOW_POOL))


def deterministic_timestamp(n: int) -> str:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    ts = base + timedelta(hours=3 * n)
    return ts.strftime("%Y-%m-%dT%H:%M:%S+00:00")


# ---------------------------------------------------------------------------
# Source file helpers
# ---------------------------------------------------------------------------

def constraint_source_payload(fields: dict) -> dict:
    """Builds the JSON shape used under data/sources/*.json (and
    data/corpus/sources/*.json), matching FileSourceFetcher's expectations."""
    return {
        "provider": fields["provider"],
        "resource_pattern": fields["resource_pattern"],
        "actions": sorted(fields["actions"]),
        "scope": fields["scope"],
        "time_window": fields["time_window"],
        "effect": fields["effect"],
        "constraint_class": fields["constraint_class"],
        "principal": fields["principal"],
        "source_ref": fields["source_ref"],
        "source_timestamp": fields["source_timestamp"],
        "rule_text": fields["rule_text"],
    }


SOURCE_PRINCIPALS: dict[str, str] = {}
"""``source_ref -> principal`` for every source file written this run --
the transport attribution ``PRINCIPALS.yaml`` is generated from."""


def write_source_file(source_ref: str, payload: dict) -> None:
    path = SOURCES_DIR / f"{source_ref}.json"
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    SOURCE_PRINCIPALS[source_ref] = payload["principal"]


def write_principals_file() -> Path:
    """``sources/PRINCIPALS.yaml``: the transport's attribution of every
    written source, sorted so the output is byte-stable."""
    path = SOURCES_DIR / "PRINCIPALS.yaml"
    with open(path, "w") as f:
        f.write(PRINCIPALS_HEADER)
        yaml.safe_dump(
            {"principals": dict(sorted(SOURCE_PRINCIPALS.items()))}, f, sort_keys=False
        )
    return path


def sign_outputs(out_dir: Path) -> None:
    """Signs ``constraints.yaml``/``authority.yaml`` (detached ``.sig``) and
    the sources directory (one ``AEGIS-MANIFEST.sig``) with the public
    example key, so the shipped corpus verifies out of the box."""
    key = load_key(f"file:{EXAMPLE_KEY_PATH}")
    sign_file(out_dir / "constraints.yaml", key)
    sign_file(out_dir / "authority.yaml", key)
    sign_tree(out_dir / "sources", key)


def apply_tamper(constraint: Constraint, rng: random.Random) -> str:
    """Mutates one field on ``constraint`` in place, *after* its
    provenance_hash was already computed, so verify_integrity() will fail.
    Returns which field was mutated."""
    candidates = list(TAMPER_MUTATIONS)
    if not constraint.scope:
        candidates.remove("scope")
    mutation = rng.choice(candidates)
    if mutation == "rule_text":
        constraint.rule_text = constraint.rule_text + " [unreviewed emergency override]"
    elif mutation == "effect":
        constraint.effect = "ESCALATE" if constraint.effect == "BLOCK" else "BLOCK"
    elif mutation == "actions":
        widened = set(constraint.actions)
        widened.add("exec" if "exec" not in widened else "delete")
        constraint.actions = widened
    elif mutation == "scope":
        scope = dict(constraint.scope)
        for key in ("namespace", "region", "cluster"):
            if key in scope:
                del scope[key]
                break
        constraint.scope = scope
    return mutation


def forge_mutated_payload(payload: dict, rng: random.Random) -> dict:
    """Returns a copy of ``payload`` with one field changed, so that
    re-hashing it will NOT match the constraint's real provenance_hash."""
    forged = copy.deepcopy(payload)
    forged["rule_text"] = forged["rule_text"] + " (forged source content)"
    return forged


# ---------------------------------------------------------------------------
# Constraint generation
# ---------------------------------------------------------------------------

def build_label_sequence(rng: random.Random) -> list[str]:
    labels = (
        ["Trusted"] * TRUSTED_COUNT
        + ["Untrusted"] * UNTRUSTED_COUNT
        + ["Malicious"] * MALICIOUS_COUNT
    )
    rng.shuffle(labels)
    assert len(labels) == TOTAL_CONSTRAINTS
    return labels


def build_malicious_subtype_sequence(rng: random.Random) -> list[str]:
    subtypes = ["tampered"] * TAMPERED_COUNT + ["forged"] * FORGED_COUNT
    rng.shuffle(subtypes)
    assert len(subtypes) == MALICIOUS_COUNT
    return subtypes


def class_to_authorized_map() -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for principal, classes in AUTHORITY.items():
        for cls in classes:
            mapping.setdefault(cls, []).append(principal)
    return mapping


def unauthorized_principal_for(cls: str, rng: random.Random) -> str:
    candidates = [p for p in AUTHORITY if cls not in AUTHORITY[p]]
    return rng.choice(candidates)


def build_constraints(seeds: list[dict], rng: random.Random):
    labels = build_label_sequence(rng)
    malicious_subtypes = iter(build_malicious_subtype_sequence(rng))
    class_authorized = class_to_authorized_map()

    constraints: list[Constraint] = []
    label_records: list[dict] = []

    for i in range(TOTAL_CONSTRAINTS):
        n = i + 1
        cid = f"c-{n:04d}"
        seed = rng.choice(seeds)
        label = labels[i]

        material = {
            "provider": seed["provider"],
            "resource_pattern": narrow_pattern(seed["resource_pattern"], rng),
            "actions": set(seed["actions"]),
            "scope": vary_scope(seed.get("scope") or {}, rng),
            "time_window": vary_time_window(seed.get("time_window"), rng),
            "effect": seed["effect"],
            "constraint_class": seed["constraint_class"],
            "rule_text": seed["rule_text"],
            "source_ref": f"src-{n:04d}",
            "source_timestamp": deterministic_timestamp(n),
        }
        constraint_class = material["constraint_class"]
        authorized_for_class = class_authorized[constraint_class]

        if label == "Trusted":
            principal = rng.choice(authorized_for_class)
            reason = "authorized"
            constraint = Constraint.create(id=cid, principal=principal, **material)
            payload = constraint_source_payload({**material, "principal": principal})
            write_source_file(material["source_ref"], payload)

        elif label == "Untrusted":
            principal = unauthorized_principal_for(constraint_class, rng)
            reason = "unauthorized"
            constraint = Constraint.create(id=cid, principal=principal, **material)
            payload = constraint_source_payload({**material, "principal": principal})
            write_source_file(material["source_ref"], payload)

        else:  # Malicious
            principal = rng.choice(authorized_for_class)
            subtype = next(malicious_subtypes)
            constraint = Constraint.create(id=cid, principal=principal, **material)
            original_payload = constraint_source_payload({**material, "principal": principal})

            if subtype == "tampered":
                apply_tamper(constraint, rng)
                reason = "tampered"
                # Source file matches the ORIGINAL, pre-mutation fields.
                write_source_file(material["source_ref"], original_payload)
            else:
                reason = "forged"
                if rng.random() < 0.5:
                    # Source is absent entirely.
                    pass
                else:
                    forged_payload = forge_mutated_payload(original_payload, rng)
                    write_source_file(material["source_ref"], forged_payload)

        constraints.append(constraint)
        label_records.append({"id": cid, "label": label, "reason": reason})

    return constraints, label_records


# ---------------------------------------------------------------------------
# Held-out split
# ---------------------------------------------------------------------------

def build_split(label_records: list[dict], rng: random.Random, seed: int) -> dict:
    by_label: dict[str, list[str]] = {}
    for rec in label_records:
        by_label.setdefault(rec["label"], []).append(rec["id"])

    holdout: list[str] = []
    for label, ids in by_label.items():
        k = round(len(ids) * 0.2)
        holdout.extend(rng.sample(ids, k))

    holdout_set = set(holdout)
    dev = [rec["id"] for rec in label_records if rec["id"] not in holdout_set]
    holdout_sorted = [rec["id"] for rec in label_records if rec["id"] in holdout_set]

    return {"seed": seed, "holdout": holdout_sorted, "dev": dev}


# ---------------------------------------------------------------------------
# Intents
# ---------------------------------------------------------------------------

def concretize_resource(pattern: str, rng: random.Random) -> str:
    if "*" in pattern:
        name = rng.choice(RESOURCE_NAMES)
        return pattern.replace("*", name)
    return pattern


def now_for_time_window(tw: dict | None) -> datetime:
    if tw is None:
        return datetime(2026, 6, 15, 12, 0, tzinfo=UTC)

    days = tw.get("days") or ["Mon"]
    target_idx = _WEEKDAY_ABBR.index(days[0])
    day = datetime(2026, 1, 1)
    while day.weekday() != target_idx:
        day += timedelta(days=1)

    start = tw.get("start") or "00:00"
    hh, mm = (int(x) for x in start.split(":"))
    naive = datetime(day.year, day.month, day.day, hh, mm) + timedelta(minutes=15)

    tz_name = tw.get("tz")
    tzinfo = ZoneInfo(tz_name) if tz_name else UTC
    localized = naive.replace(tzinfo=tzinfo)
    return localized.astimezone(UTC)


def build_intent_record(idx: int, provider: str, resource: str, action: str,
                         metadata: dict, now: datetime) -> dict:
    return {
        "id": f"i-{idx:04d}",
        "provider": provider,
        "resource": resource,
        "action": action,
        "params": {},
        "metadata": metadata,
        "now": now.isoformat(),
    }


def intent_from_constraint(idx: int, c: Constraint, rng: random.Random) -> dict:
    resource = concretize_resource(c.resource_pattern, rng)
    action = rng.choice(sorted(c.actions))
    metadata = dict(c.scope)
    now = now_for_time_window(c.time_window)
    return build_intent_record(idx, c.provider, resource, action, metadata, now)


def build_intents(constraints: list[Constraint], label_records: list[dict],
                   constraint_dicts: list[dict], labels: dict[str, dict],
                   rng: random.Random) -> list[dict]:
    """Builds the intent set and annotates it with the reference oracle's
    ``expected_*`` fields. The interceptor is never consulted."""
    by_id = {c.id: c for c in constraints}
    trusted_ids = [r["id"] for r in label_records if r["label"] == "Trusted"]
    nontrusted_ids = [r["id"] for r in label_records if r["label"] in ("Untrusted", "Malicious")]

    intents: list[dict] = []
    idx = 0

    for _ in range(INTENTS_ON_TRUSTED):
        idx += 1
        intents.append(intent_from_constraint(idx, by_id[rng.choice(trusted_ids)], rng))

    for _ in range(INTENTS_ON_NONTRUSTED):
        idx += 1
        chosen = None
        for _attempt in range(POISON_SEEK_ATTEMPTS):
            candidate = intent_from_constraint(idx, by_id[rng.choice(nontrusted_ids)], rng)
            verdict = reference_oracle.oracle_for_intent(candidate, constraint_dicts, labels)
            if chosen is None:
                chosen = candidate
            if verdict["poison_candidate"]:
                chosen = candidate
                break
        intents.append(chosen)

    for _ in range(INTENTS_ON_NOTHING):
        idx += 1
        provider = rng.choice(["kubernetes", "terraform"])
        resource = f"unmatched-kind-{idx:04d}/{rng.choice(RESOURCE_NAMES)}"
        action = "describe"  # never used by any generated constraint
        now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
        intents.append(build_intent_record(idx, provider, resource, action, {}, now))

    return reference_oracle.annotate_intents(intents, constraint_dicts, labels)


def build_intent_split(intents: list[dict], rng: random.Random) -> dict:
    """20% holdout, stratified by (expected_verdict, poison_candidate)."""
    strata: dict[tuple[str, bool], list[str]] = {}
    for rec in intents:
        key = (rec["expected_verdict"], rec["poison_candidate"])
        strata.setdefault(key, []).append(rec["id"])

    holdout: list[str] = []
    for key in sorted(strata):
        ids = strata[key]
        holdout.extend(rng.sample(ids, round(len(ids) * 0.2)))

    holdout_set = set(holdout)
    return {
        "holdout": [r["id"] for r in intents if r["id"] in holdout_set],
        "dev": [r["id"] for r in intents if r["id"] not in holdout_set],
    }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def structural_key(c: dict) -> tuple:
    return (
        c["provider"],
        c["resource_pattern"],
        tuple(sorted(c["actions"])),
        json.dumps(c.get("scope") or {}, sort_keys=True),
    )


def build_stats(constraint_dicts: list[dict], label_records: list[dict],
                intents: list[dict], split: dict) -> dict:
    label_counts = Counter(r["label"] for r in label_records)
    reason_counts = Counter(r["reason"] for r in label_records)
    holdout = set(split["intents"]["holdout"])

    def verdict_counts(records):
        return dict(sorted(Counter(r["expected_verdict"] for r in records).items()))

    def poison_counts(records):
        kinds = Counter(r["poison_kind"] for r in records if r["poison_candidate"])
        return dict(sorted(kinds.items()))

    per_split = {}
    for name, members in (
        ("all", intents),
        ("holdout", [r for r in intents if r["id"] in holdout]),
        ("dev", [r for r in intents if r["id"] not in holdout]),
    ):
        per_split[name] = {
            "n": len(members),
            "by_expected_verdict": verdict_counts(members),
            "poison_candidates_by_kind": poison_counts(members),
            "poison_candidates": sum(1 for r in members if r["poison_candidate"]),
        }

    return {
        "n_constraints": len(constraint_dicts),
        "n_distinct_structural": len({structural_key(c) for c in constraint_dicts}),
        "n_distinct_patterns": len({c["resource_pattern"] for c in constraint_dicts}),
        "n_distinct_rule_text": len({c["rule_text"] for c in constraint_dicts}),
        "labels": dict(sorted(label_counts.items())),
        "reasons": dict(sorted(reason_counts.items())),
        "constraint_split": {"holdout": len(split["holdout"]), "dev": len(split["dev"])},
        "intents": per_split,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260920)
    parser.add_argument("--out-dir", type=Path, default=CORPUS_DIR)
    args = parser.parse_args()

    out_dir = args.out_dir
    sources_dir = out_dir / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)
    global SOURCES_DIR
    SOURCES_DIR = sources_dir

    # Clean previously generated source files so stale files from a
    # different run/seed don't linger and pollute forged/absent cases.
    for f in sources_dir.glob("src-*.json"):
        f.unlink()
    for f in sources_dir.glob("*.sig"):
        f.unlink()
    SOURCE_PRINCIPALS.clear()

    rng = random.Random(args.seed)
    seeds = load_seeds()

    constraints, label_records = build_constraints(seeds, rng)

    # constraints.yaml — written via ConstraintStore.save so the format is
    # exactly what ConstraintStore.load expects.
    store = ConstraintStore()
    for c in constraints:
        store.constraints[c.id] = c
    store.save(out_dir / "constraints.yaml")

    # labels.jsonl
    with open(out_dir / "labels.jsonl", "w") as f:
        for rec in label_records:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    # authority.yaml
    with open(out_dir / "authority.yaml", "w") as f:
        yaml.safe_dump({"principals": AUTHORITY}, f, sort_keys=False)

    # split.json — constraint split (kept for store-level experiments) plus
    # the intent split the benchmark reports on.
    split = build_split(label_records, rng, args.seed)

    # intents.jsonl — ground truth from the reference oracle, reading the
    # just-written constraints.yaml and labels.jsonl with plain readers.
    constraint_dicts = reference_oracle.read_constraints(out_dir / "constraints.yaml")
    labels = reference_oracle.read_labels(out_dir / "labels.jsonl")
    intents = build_intents(constraints, label_records, constraint_dicts, labels, rng)
    split["intents"] = build_intent_split(intents, rng)

    with open(out_dir / "split.json", "w") as f:
        json.dump(split, f, indent=2, sort_keys=True)
        f.write("\n")
    reference_oracle.write_jsonl(out_dir / "intents.jsonl", intents)

    # stats.json
    stats = build_stats(constraint_dicts, label_records, intents, split)
    with open(out_dir / "stats.json", "w") as f:
        json.dump(stats, f, indent=2, sort_keys=True)
        f.write("\n")

    # sources/PRINCIPALS.yaml + signatures (REVIEW-4 T1.1)
    write_principals_file()
    sign_outputs(out_dir)

    # Summary
    print(f"seed = {args.seed}")
    print(f"seeds used = {len(seeds)}")
    print()
    print("Label counts:")
    for label in ("Trusted", "Untrusted", "Malicious"):
        print(f"  {label:10s} {stats['labels'][label]:4d}")
    print("Reason counts:")
    for reason in ("authorized", "unauthorized", "tampered", "forged"):
        print(f"  {reason:12s} {stats['reasons'][reason]:4d}")
    print(f"Total constraints: {stats['n_constraints']}  "
          f"distinct structural: {stats['n_distinct_structural']}  "
          f"patterns: {stats['n_distinct_patterns']}  "
          f"rule_text: {stats['n_distinct_rule_text']}")
    print()
    print(f"Constraint split — holdout: {len(split['holdout'])}  dev: {len(split['dev'])}")
    print(f"Intent split     — holdout: {len(split['intents']['holdout'])}  "
          f"dev: {len(split['intents']['dev'])}")
    print()
    for name in ("all", "holdout", "dev"):
        s_ = stats["intents"][name]
        print(f"Intents[{name}]: n={s_['n']} verdicts={s_['by_expected_verdict']} "
              f"poison={s_['poison_candidates_by_kind']}")


if __name__ == "__main__":
    main()
