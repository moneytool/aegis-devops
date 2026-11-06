"""The source check binds a hash, and a duplicated id is judged entry by entry.

Both were found by comparing the engine with a reference definition of its
verdict: the maximum effect over the constraints that are intact, backed by
their source and authorized."""

import json
from datetime import UTC, datetime

import pytest
import yaml

from aegis_core.gitsource import SourceNotChecked
from aegis_core.intent import InfrastructureIntent
from aegis_core.interceptor import AegisInterceptor
from aegis_core.provenance import FileSourceFetcher
from aegis_core.store import Constraint, ConstraintStore, _constraint_to_dict

NOW = datetime(2026, 11, 6, 12, tzinfo=UTC)
AUTHORITY = {"sre_lead": {"deletion"}, "contractor": set()}


def _authority():
    return {p: set(v) for p, v in AUTHORITY.items()}


def _rule(cid="r", *, principal="sre_lead", effect="BLOCK", pattern="deployment/api-*",
          text=None, scope=None):
    return Constraint.create(
        id=cid, provider="kubernetes", resource_pattern=pattern, actions={"delete"},
        effect=effect, constraint_class="deletion", principal=principal,
        source_ref=f"src-{cid}", source_timestamp="2026-09-01T00:00:00Z",
        rule_text=text or f"rule {cid}", scope={} if scope is None else scope)


def _source(c):
    return {"provider": c.provider, "resource_pattern": c.resource_pattern,
            "actions": sorted(c.actions), "scope": c.scope, "time_window": c.time_window,
            "effect": c.effect, "constraint_class": c.constraint_class,
            "principal": c.principal, "source_ref": c.source_ref,
            "source_timestamp": c.source_timestamp, "rule_text": c.rule_text}


def _write(tmp_path, entries, sources=()):
    srcdir = tmp_path / "sources"
    srcdir.mkdir(exist_ok=True)
    for c in sources:
        (srcdir / f"{c.source_ref}.json").write_text(json.dumps(_source(c)))
    path = tmp_path / "constraints.yaml"
    path.write_text(yaml.safe_dump(
        {"constraints": [e if isinstance(e, dict) else _constraint_to_dict(e) for e in entries]},
        sort_keys=False))
    return path, FileSourceFetcher(srcdir)


def _load(tmp_path, entries, sources=None):
    """Loads with a source fetcher when ``sources`` is given."""
    path, fetcher = _write(tmp_path, entries, sources or ())
    return ConstraintStore.load(path, _authority(), insecure=True,
                                source_fetcher=fetcher if sources is not None else None)


def _intent(resource="deployment/api-1", **kw):
    return InfrastructureIntent(resource=resource, action="delete", provider="kubernetes", **kw)


def _decide(store, mode="discard", intent=None):
    return AegisInterceptor(store, on_untrusted_match=mode).intercept(intent or _intent(), now=NOW)


def _rehash(live, **changes):
    for field, value in changes.items():
        setattr(live, field, value)
    live.provenance_hash = Constraint.create(
        id=live.id, provider=live.provider, resource_pattern=live.resource_pattern,
        actions=set(live.actions), effect=live.effect, constraint_class=live.constraint_class,
        principal=live.principal, source_ref=live.source_ref,
        source_timestamp=live.source_timestamp, rule_text=live.rule_text,
        scope=live.scope).provenance_hash
    assert live.verify_integrity()


# --- the source check binds a hash ------------------------------------------------------------


def test_rehashed_mutation_after_a_source_check_gets_no_vote(tmp_path):
    c = _rule(effect="ESCALATE")
    store = _load(tmp_path, [c], sources=[c])
    assert _decide(store).verdict == "ESCALATE"
    _rehash(store.constraints["r"], effect="BLOCK")
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("ALLOW", [], [{"id": "r", "reason": "forged"}])


def test_rehashed_mutation_under_fail_closed_escalates_and_never_blocks(tmp_path):
    c = _rule(effect="ESCALATE")
    store = _load(tmp_path, [c], sources=[c])
    _rehash(store.constraints["r"], effect="BLOCK")
    d = _decide(store, "escalate")
    assert (d.verdict, d.citations) == ("ESCALATE", [])
    assert d.discarded == [{"id": "r", "reason": "forged"}]
    assert d.notes == ["fail-closed: r (forged)"]


def test_rehashed_mutation_is_reported_on_a_dry_run(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    _rehash(store.constraints["r"], rule_text="weakened")
    d = _decide(store, intent=_intent(params={"dry_run": True}))
    assert (d.verdict, d.would_be) == ("ALLOW", "ALLOW")
    assert d.discarded == [{"id": "r", "reason": "forged"}]


def test_rehashed_mutation_cannot_force_an_unresolved_escalate(tmp_path):
    """As with a tampered rule: discarded before its unresolved scope counts."""
    c = _rule(scope={"env": "prod"})
    store = _load(tmp_path, [c], sources=[c])
    assert _decide(store).verdict == "ESCALATE"  # env-unresolved, on a rule that may vote
    _rehash(store.constraints["r"], rule_text="edited")
    d = _decide(store)
    assert d.verdict == "ALLOW" and d.discarded == [{"id": "r", "reason": "forged"}]


def test_replacing_the_object_in_the_store_is_caught_too(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    store.constraints["r"] = _rule(text="another rule under this id")
    assert _decide(store).discarded == [{"id": "r", "reason": "forged"}]


@pytest.mark.parametrize("build", ["load-no-fetcher", "direct", "add_constraint"])
def test_a_store_never_source_verified_is_not_affected(tmp_path, build):
    c = _rule(effect="ESCALATE")
    if build == "load-no-fetcher":
        store = _load(tmp_path, [c])
    else:
        store = ConstraintStore(authority_map=_authority())
        if build == "direct":
            store.constraints[c.id] = c
        else:
            store.add_constraint(c)
    assert store.source_verified_hashes == {}
    _rehash(store.constraints["r"], effect="BLOCK")
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["r"], [])


def test_an_added_constraint_beside_verified_ones_votes_unverified(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    store.add_constraint(_rule("new", effect="ESCALATE"))
    d = _decide(store)
    assert sorted(d.citations) == ["r"] and d.discarded == []
    assert store.source_verified_hashes.keys() == {"r"}


def test_add_constraint_with_new_content_drops_the_source_evidence(tmp_path):
    c = _rule(effect="ESCALATE")
    store = _load(tmp_path, [c], sources=[c])
    store.add_constraint(_rule(effect="BLOCK"))  # the sanctioned way to replace a rule
    assert store.source_verified == set() and store.source_verified_hashes == {}
    d = _decide(store)
    assert (d.verdict, d.discarded) == ("BLOCK", [])
    snapshot = store.verified_snapshot()
    assert snapshot.excluded == ({"id": "r", "reason": "source-unverified"},)


def test_add_constraint_with_the_same_content_keeps_the_source_evidence(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    store.add_constraint(_rule())
    assert store.source_verified == {"r"}
    assert store.source_verified_hashes == {"r": c.provenance_hash}
    assert _decide(store).verdict == "BLOCK"


def test_an_audit_quarantines_a_rehash_its_source_does_not_back(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    _, fetcher = _write(tmp_path, [c])
    _rehash(store.constraints["r"], rule_text="edited")
    assert store.verify_sources(fetcher) == [{"id": "r", "reason": "forged"}]
    assert store.source_verified_hashes == {} and store.source_verified == set()
    assert _decide(store).discarded == [{"id": "r", "reason": "forged"}]


def test_an_audit_records_a_change_its_source_now_backs(tmp_path):
    c = _rule(effect="ESCALATE")
    store = _load(tmp_path, [c], sources=[c])
    live = store.constraints["r"]
    _rehash(live, effect="BLOCK")
    assert _decide(store).verdict == "ALLOW"
    _, fetcher = _write(tmp_path, [c], sources=[live])  # the source now says BLOCK
    assert store.verify_sources(fetcher) == []
    assert store.source_verified_hashes == {"r": live.provenance_hash}
    assert _decide(store).verdict == "BLOCK"


def test_a_fetcher_that_cannot_check_it_keeps_the_record(tmp_path):
    class NotChecked:
        def fetch(self, source_ref):
            raise SourceNotChecked(source_ref)

    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    _rehash(store.constraints["r"], rule_text="edited")
    assert store.verify_sources(NotChecked()) == []
    assert _decide(store).discarded == [{"id": "r", "reason": "forged"}]


def test_a_snapshot_excludes_a_rehashed_constraint(tmp_path):
    c = _rule()
    store = _load(tmp_path, [c], sources=[c])
    assert [x.id for x in store.verified_snapshot().constraints] == ["r"]
    _rehash(store.constraints["r"], rule_text="edited")
    snapshot = store.verified_snapshot()
    assert snapshot.constraints == ()
    assert snapshot.excluded == ({"id": "r", "reason": "forged"},)


# --- the evidence belongs to the store key, not to the mutable Constraint.id -------------------


def _verified(tmp_path, *rules):
    return _load(tmp_path, list(rules), sources=list(rules))


def _assert_no_vote(store, key):
    """ALLOW under discard; ESCALATE and never BLOCK under escalate."""
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == (
        "ALLOW", [], [{"id": key, "reason": "forged"}])
    d = _decide(store, "escalate")
    assert (d.verdict, d.citations, d.notes) == ("ESCALATE", [], [f"fail-closed: {key} (forged)"])


def test_the_hash_does_not_cover_the_id():
    c = _rule("a")
    before = c.provenance_hash
    c.id = "renamed"
    assert c.verify_integrity() and c.provenance_hash == before


def test_rehashed_and_renamed_in_place_gets_no_vote(tmp_path):
    """The repro: the evidence lookup used the rewritten id, found nothing and
    took the constraint for one never verified."""
    c = _rule(effect="ESCALATE")
    store = _verified(tmp_path, c)
    live = store.constraints["r"]
    _rehash(live, effect="BLOCK")
    live.id = "renamed"
    _assert_no_vote(store, "r")


def test_renamed_only_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule())
    store.constraints["r"].id = "renamed"
    _assert_no_vote(store, "r")


def test_renamed_to_another_verified_id_gets_no_vote_and_leaves_that_one_alone(tmp_path):
    victim = _rule("victim", effect="ESCALATE")
    store = _verified(tmp_path, _rule("r", pattern="deployment/web-*"), victim)
    live = store.constraints["r"]
    _rehash(live, effect="BLOCK", resource_pattern=victim.resource_pattern)
    live.id = "victim"
    d = _decide(store)
    assert d.discarded == [{"id": "r", "reason": "forged"}]
    assert d.verdict == "ESCALATE" and d.citations == ["victim"]  # the real one still votes
    assert store.constraints["victim"].effect == "ESCALATE"


def test_swapped_ids_get_no_vote(tmp_path):
    store = _verified(tmp_path, _rule("a"), _rule("b", effect="ESCALATE"))
    a, b = store.constraints["a"], store.constraints["b"]
    a.id, b.id = "b", "a"
    d = _decide(store)
    assert (d.verdict, d.citations) == ("ALLOW", [])
    assert sorted(x["id"] for x in d.discarded) == ["a", "b"]
    assert {x["reason"] for x in d.discarded} == {"forged"}
    assert _decide(store, "escalate").verdict == "ESCALATE"


def test_direct_replacement_with_a_mutated_constraint_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    store.constraints["r"] = _rule(effect="BLOCK")
    _assert_no_vote(store, "r")


def test_direct_replacement_under_another_id_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    store.constraints["r"] = _rule("other", effect="BLOCK")
    _assert_no_vote(store, "r")


def test_direct_replacement_with_the_same_content_keeps_its_vote(tmp_path):
    store = _verified(tmp_path, _rule())
    store.constraints["r"] = _rule()
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["r"], [])


def test_a_new_key_naming_a_verified_id_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    store.constraints["new"] = _rule(effect="BLOCK")  # its own id is "r"
    d = _decide(store)
    assert (d.verdict, d.citations) == ("ESCALATE", ["r"])
    assert d.discarded == [{"id": "new", "reason": "forged"}]


def test_a_new_key_written_straight_in_gets_no_vote(tmp_path):
    """No record, and not by a way that may vote without one."""
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    store.constraints["new"] = _rule("new", effect="BLOCK")
    d = _decide(store)
    assert (d.verdict, d.citations) == ("ESCALATE", ["r"])
    assert d.discarded == [{"id": "new", "reason": "forged"}]
    assert {"id": "new", "reason": "forged"} in store.verified_snapshot().excluded


def test_a_rename_and_write_under_the_new_id_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule())
    live = store.constraints.pop("r")
    live.id = "renamed"
    store.constraints["renamed"] = live
    assert _decide(store).discarded == [{"id": "renamed", "reason": "forged"}]


def test_an_audit_gives_a_directly_written_id_a_record(tmp_path):
    new = _rule("new", effect="BLOCK")
    store = _verified(tmp_path, _rule("r", pattern="deployment/web-*"))
    store.constraints["new"] = new
    assert _decide(store).verdict == "ALLOW"
    _, fetcher = _write(tmp_path, [new], sources=[new])
    assert store.verify_sources(fetcher) == []
    assert _decide(store).citations == ["new"]


class _ChecksOnly:
    """A fetcher that can check one source_ref and no other."""

    def __init__(self, fetcher, ref):
        self.fetcher, self.ref = fetcher, ref

    def fetch(self, source_ref):
        if source_ref != self.ref:
            raise SourceNotChecked(source_ref)
        return self.fetcher.fetch(source_ref)


def test_a_source_no_fetcher_can_check_still_votes_beside_verified_ones(tmp_path):
    checked, unchecked = _rule("a", pattern="deployment/web-*"), _rule("b")
    path, fetcher = _write(tmp_path, [checked, unchecked], sources=[checked])
    store = ConstraintStore.load(path, _authority(), insecure=True,
                                 source_fetcher=_ChecksOnly(fetcher, checked.source_ref))
    assert store.source_verified == {"a"}
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["b"], [])


def test_the_same_at_an_audit_of_a_store_built_directly(tmp_path):
    checked, unchecked = _rule("a", pattern="deployment/web-*"), _rule("b")
    _, fetcher = _write(tmp_path, [checked], sources=[checked])
    store = ConstraintStore(authority_map=_authority())
    store.constraints["a"], store.constraints["b"] = checked, unchecked
    assert store.verify_sources(_ChecksOnly(fetcher, checked.source_ref)) == []
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["b"], [])


def test_a_new_key_under_a_different_id_gets_no_vote(tmp_path):
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    store.constraints["new"] = _rule("other", effect="BLOCK")
    d = _decide(store)
    assert (d.verdict, d.citations) == ("ESCALATE", ["r"])
    assert d.discarded == [{"id": "new", "reason": "forged"}]


def test_renamed_constraint_cannot_force_an_unresolved_escalate(tmp_path):
    store = _verified(tmp_path, _rule(scope={"env": "prod"}))
    store.constraints["r"].id = "renamed"
    d = _decide(store)
    assert d.verdict == "ALLOW" and d.discarded == [{"id": "r", "reason": "forged"}]
    d = _decide(store, "escalate")
    assert d.verdict == "ESCALATE" and d.notes == ["fail-closed: r (forged)"]


def test_a_snapshot_excludes_a_renamed_constraint_under_its_key(tmp_path):
    store = _verified(tmp_path, _rule())
    store.constraints["r"].id = "renamed"
    snapshot = store.verified_snapshot()
    assert snapshot.constraints == ()
    assert snapshot.excluded == ({"id": "r", "reason": "forged"},)


def test_an_audit_quarantines_a_renamed_constraint_and_attaches_no_evidence(tmp_path):
    c = _rule()
    store = _verified(tmp_path, c)
    _, fetcher = _write(tmp_path, [c])
    store.constraints["r"].id = "renamed"
    assert store.verify_sources(fetcher) == [{"id": "r", "reason": "forged"}]
    assert store.constraints == {}
    assert store.source_verified == set() and store.source_verified_hashes == {}
    assert store.quarantined == [{"id": "r", "reason": "forged"}]
    d = _decide(store, "escalate")
    assert d.verdict == "ESCALATE" and d.discarded == [{"id": "r", "reason": "forged"}]


def test_renaming_a_quarantined_constraint_changes_neither_its_reason_nor_its_report(tmp_path):
    good, forged = _rule("good", pattern="deployment/web-*"), _rule("bad")
    path, fetcher = _write(tmp_path, [good, forged], sources=[good])
    store = ConstraintStore.load(path, _authority(), insecure=True, source_fetcher=fetcher)
    store.quarantined_constraints[0].id = "good"
    d = _decide(store, "escalate")
    assert d.discarded == [{"id": "bad", "reason": "forged"}]
    assert d.notes == ["fail-closed: bad (forged)"]


def test_a_rename_in_a_store_with_no_evidence_behaves_as_before(tmp_path):
    direct = ConstraintStore(authority_map=_authority())
    direct.constraints["r"] = _rule()
    added = ConstraintStore(authority_map=_authority())
    added.add_constraint(_rule())
    for store in (_load(tmp_path, [_rule()]), direct, added):
        store.constraints["r"].id = "renamed"
        d = _decide(store)
        assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["renamed"], [])


def test_a_key_mismatch_with_no_evidence_behaves_as_before():
    store = ConstraintStore(authority_map=_authority())
    store.constraints["key"] = _rule("other")
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == ("BLOCK", ["other"], [])


def test_plan_evaluation_gets_the_same_verdict_for_its_intents(tmp_path):
    """evaluate_plan decides each intent through the interceptor."""
    from aegis_core.plan import PlanConstraintStore, evaluate_plan

    store = _verified(tmp_path, _rule())
    store.constraints["r"].id = "renamed"
    gate = AegisInterceptor(store)
    d = evaluate_plan(gate, PlanConstraintStore(authority_map=_authority()), [_intent()], now=NOW)
    assert d.verdict == "ALLOW"
    gate = AegisInterceptor(store, on_untrusted_match="escalate")
    d = evaluate_plan(gate, PlanConstraintStore(authority_map=_authority()), [_intent()], now=NOW)
    assert d.verdict == "ESCALATE"


# --- removing evidence never switches source binding off ---------------------------------------


def _evil_insert(store):
    store.constraints["evil"] = _rule("evil", effect="BLOCK")


def _assert_only_evil_discarded(store):
    d = _decide(store)
    assert (d.verdict, d.citations, d.discarded) == (
        "ALLOW", [], [{"id": "evil", "reason": "forged"}])
    d = _decide(store, "escalate")
    assert (d.verdict, d.citations) == ("ESCALATE", [])


def test_replacing_the_last_record_does_not_authorize_a_direct_insert(tmp_path):
    """The repro: add_constraint removed the last record, which used to disable
    the check for the whole store."""
    store = _verified(tmp_path, _rule(effect="ESCALATE"))
    live = store.constraints["r"]
    _rehash(live, effect="BLOCK")
    live.id = "renamed"
    _evil_insert(store)
    store.add_constraint(_rule(pattern="deployment/web-*"))
    assert store.source_verified_hashes == {}
    _assert_only_evil_discarded(store)


def test_a_failed_audit_of_the_last_record_does_not_authorize_a_direct_insert(tmp_path):
    c = _rule(pattern="deployment/web-*")
    store = _verified(tmp_path, c)
    _, fetcher = _write(tmp_path, [c])
    _rehash(store.constraints["r"], rule_text="edited")
    assert store.verify_sources(fetcher) == [{"id": "r", "reason": "forged"}]
    assert store.source_verified_hashes == {}
    _evil_insert(store)
    _assert_only_evil_discarded(store)
    # the id itself cannot come back by a direct write either
    store.constraints["r"] = _rule(effect="BLOCK")
    assert {"id": "r", "reason": "forged"} in _decide(store).discarded
    assert _decide(store).verdict == "ALLOW"


def test_an_audit_quarantining_a_rename_does_not_authorize_a_direct_insert(tmp_path):
    c = _rule(pattern="deployment/web-*")
    store = _verified(tmp_path, c)
    _, fetcher = _write(tmp_path, [c])
    store.constraints["r"].id = "renamed"
    store.verify_sources(fetcher)
    assert store.source_verified_hashes == {}
    _evil_insert(store)
    _assert_only_evil_discarded(store)


def test_an_audit_where_nothing_passed_still_binds(tmp_path):
    forged = _rule("a", pattern="deployment/web-*")
    _, fetcher = _write(tmp_path, [forged])  # no source file for it
    store = ConstraintStore(authority_map=_authority())
    store.constraints["a"] = forged
    assert store.verify_sources(fetcher) == [{"id": "a", "reason": "forged"}]
    _evil_insert(store)
    _assert_only_evil_discarded(store)


def test_a_load_with_a_fetcher_where_nothing_passed_still_binds(tmp_path):
    store = _load(tmp_path, [_rule("a", pattern="deployment/web-*")], sources=[])
    assert store.source_verified_hashes == {}
    assert store.quarantined == [{"id": "a", "reason": "forged"}]
    _evil_insert(store)
    _assert_only_evil_discarded(store)


def test_a_failed_audit_removes_an_admission_too(tmp_path):
    """An added id that fails an audit does not stay admitted."""
    good = _rule("good", pattern="deployment/web-*")
    store = _verified(tmp_path, good)
    added = _rule("added")
    store.add_constraint(added)
    _, fetcher = _write(tmp_path, [good])
    assert store.verify_sources(fetcher) == [{"id": "added", "reason": "forged"}]
    store.constraints["added"] = _rule("added", effect="ESCALATE")
    d = _decide(store)
    assert {"id": "added", "reason": "forged"} in d.discarded and d.verdict == "ALLOW"


def test_an_admitted_id_is_bound_to_the_hash_it_came_in_with(tmp_path):
    store = _verified(tmp_path, _rule(pattern="deployment/web-*"))
    store.add_constraint(_rule(pattern="deployment/api-*", text="replaced", effect="ESCALATE"))
    assert _decide(store).verdict == "ESCALATE"
    store.constraints["r"] = _rule(effect="BLOCK")  # a direct write over the added one
    _assert_no_vote(store, "r")


def test_a_rehash_of_an_added_constraint_gets_no_vote_in_a_checked_store(tmp_path):
    store = _verified(tmp_path, _rule("r", pattern="deployment/web-*"))
    store.add_constraint(_rule("added", effect="ESCALATE"))
    _rehash(store.constraints["added"], effect="BLOCK")
    _assert_no_vote(store, "added")


def test_add_constraint_of_the_quarantined_id_is_a_fresh_admission(tmp_path):
    c = _rule()
    store = _verified(tmp_path, c)
    _, fetcher = _write(tmp_path, [c])
    _rehash(store.constraints["r"], rule_text="edited")
    store.verify_sources(fetcher)
    store.add_constraint(_rule(text="reinstated", effect="ESCALATE"))
    d = _decide(store)
    assert d.verdict == "ESCALATE" and d.citations == ["r"]


def test_a_direct_insert_is_not_admitted_by_a_later_audit_that_cannot_check_it(tmp_path):
    class NotChecked:
        def fetch(self, source_ref):
            raise SourceNotChecked(source_ref)

    store = _verified(tmp_path, _rule(pattern="deployment/web-*"))
    _evil_insert(store)
    assert store.verify_sources(NotChecked()) == []
    assert _decide(store).discarded == [{"id": "evil", "reason": "forged"}]


def test_a_store_never_checked_keeps_voting_through_add_and_direct_writes():
    store = ConstraintStore(authority_map=_authority())
    store.add_constraint(_rule("a", effect="ESCALATE"))
    store.add_constraint(_rule("a", effect="ESCALATE", text="replaced"))
    _evil_insert(store)
    d = _decide(store)
    assert (d.verdict, sorted(d.citations), d.discarded) == ("BLOCK", ["evil"], [])


# --- duplicate ids: every entry on its own merits, in any order -------------------------------


LEGIT = _rule("c", effect="BLOCK")
UNAUTHORIZED = _rule("c", principal="contractor", pattern="deployment/zzz-*")
FORGED = _rule("c", pattern="deployment/zzz-*", text="not what the source says")
TAMPERED = {**_constraint_to_dict(LEGIT), "resource_pattern": "deployment/zzz-*"}


@pytest.mark.parametrize("first_is_rejected", [True, False],
                         ids=["rejected-first", "trusted-first"])
@pytest.mark.parametrize("rejected,reason,fetch", [
    (UNAUTHORIZED, "unauthorized", False),
    (TAMPERED, "tampered", False),
    (FORGED, "forged", True),
    ({"id": "c", "effect": "Block"}, "invalid: missing provider", False),
], ids=["unauthorized", "tampered", "forged", "bad-shape"])
def test_a_rejected_entry_never_displaces_a_trusted_one(tmp_path, rejected, reason, fetch,
                                                        first_is_rejected):
    entries = [rejected, LEGIT] if first_is_rejected else [LEGIT, rejected]
    store = _load(tmp_path, entries, sources=[LEGIT] if fetch else None)
    assert store.constraints["c"].provenance_hash == LEGIT.provenance_hash
    assert store.quarantined == [{"id": "c", "reason": reason}]
    assert any("Duplicate id c: 2 entries" in w for w in store.warnings) or reason.startswith(
        "invalid: ")
    d = _decide(store)
    assert (d.verdict, d.citations) == ("BLOCK", ["c"])
    if fetch:
        assert store.source_verified_hashes == {"c": LEGIT.provenance_hash}
    if not reason.startswith("invalid: "):
        assert [c.id for c in store.quarantined_constraints] == ["c"]


def test_a_rejected_duplicate_stays_visible_to_fail_closed(tmp_path):
    """Its own match still counts under escalate, for a trusted rule that does
    not apply to this intent."""
    legit = _rule("c", pattern="deployment/web-*")
    evil = _rule("c", principal="contractor")
    for entries in ([evil, legit], [legit, evil]):
        store = _load(tmp_path, entries)
        assert _decide(store).verdict == "ALLOW"
        d = _decide(store, "escalate")
        assert d.verdict == "ESCALATE" and d.notes == ["fail-closed: c (unauthorized)"]
        assert d.discarded == [{"id": "c", "reason": "unauthorized"}]


def test_quarantined_entries_of_one_id_keep_their_own_reasons(tmp_path):
    evil = _rule("c", principal="contractor")
    other = _rule("c", principal="contractor", text="another")
    broken = {**_constraint_to_dict(_rule("c", text="third")), "rule_text": "edited"}
    store = _load(tmp_path, [broken, evil, other])
    assert store.constraints == {}
    d = _decide(store)
    assert d.verdict == "ALLOW"
    assert sorted(x["reason"] for x in d.discarded) == ["tampered", "unauthorized", "unauthorized"]


def test_identical_trusted_entries_keep_one(tmp_path):
    store = _load(tmp_path, [LEGIT, _constraint_to_dict(LEGIT)], sources=[LEGIT])
    assert list(store.constraints) == ["c"]
    assert store.quarantined == [{"id": "c", "reason": "invalid: duplicate id"}]
    assert store.quarantined_constraints == []  # its twin is the loaded constraint
    assert store.source_verified == {"c"}
    assert _decide(store).verdict == "BLOCK"


def test_identical_unauthorized_entries_load_as_one_and_are_discarded_at_decision(tmp_path):
    evil = _rule("c", principal="contractor")
    store = _load(tmp_path, [evil, _constraint_to_dict(evil)])
    assert list(store.constraints) == ["c"]  # as a single unauthorized entry would
    assert _decide(store).discarded == [{"id": "c", "reason": "unauthorized"}]


def test_differing_unauthorized_entries_load_neither(tmp_path):
    one = _rule("c", principal="contractor")
    two = _rule("c", principal="contractor", text="another")
    store = _load(tmp_path, [one, two])
    assert store.constraints == {}
    assert [q["reason"] for q in store.quarantined] == ["unauthorized", "unauthorized"]
    assert len(store.quarantined_constraints) == 2


@pytest.mark.parametrize("flip", [False, True], ids=["ab", "ba"])
def test_differing_trusted_entries_refuse_the_whole_file(tmp_path, flip):
    one, two = _rule("c"), _rule("c", effect="ESCALATE")
    entries = [two, one] if flip else [one, two]
    with pytest.raises(ValueError, match=r"constraints\.yaml: id 'c' has 2 entries .* differ"):
        _load(tmp_path, entries)


def test_differing_trusted_entries_decide_nothing_even_with_a_rejected_third(tmp_path):
    entries = [_rule("c", principal="contractor"), _rule("c"), _rule("c", effect="ESCALATE")]
    with pytest.raises(ValueError, match="id 'c' has 2 entries"):
        _load(tmp_path, entries)


def test_a_source_rejected_variant_is_not_a_conflict(tmp_path):
    """The source decides which of two otherwise valid entries is the rule."""
    other = _rule("c", effect="ESCALATE")
    store = _load(tmp_path, [other, LEGIT], sources=[LEGIT])
    assert store.constraints["c"].effect == "BLOCK"
    assert store.quarantined == [{"id": "c", "reason": "forged"}]


def test_entries_with_distinct_ids_load_in_file_order(tmp_path):
    store = _load(tmp_path, [_rule("b"), _rule("a"), _rule("c")])
    assert list(store.constraints) == ["b", "a", "c"]
    assert not any("Duplicate" in w for w in store.warnings)
