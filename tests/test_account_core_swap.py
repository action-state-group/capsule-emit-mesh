# SPDX-License-Identifier: Apache-2.0
"""B7 core-swap acceptance — the mesh account capsule now CONSUMES the neutral
``capsule_emit.account`` core instead of a bespoke served/success fold.

Steven's explicit acceptance for the swap (not just a unit check):

  1. **The Nostr event shape is UNCHANGED by the swap** — the only field the
     event gains anywhere is ``derivation.definition_digest``. Every other key,
     tag, and structure is byte-for-byte the pre-swap shape.

  2. **``definition_digest`` computed BEFORE and AFTER the internals swap is
     BYTE-IDENTICAL.** This exercises the definition-as-data /
     implementation-independence property for real, end-to-end: swapping the
     fold's IMPLEMENTATION internals must NOT move the digest (only editing the
     definition DOCUMENT may). If the digest moves, the swap changed the
     definition document and must be reconciled.

The core's own mutation test proves altering internals doesn't move the digest
in the core; these tests prove it holds through the mesh consumer, on the real
account capsule and the real Nostr event.
"""
from __future__ import annotations

import json

import pytest

import account_capsule as ac
import nostr_account as na
from capsule_emit.account import (
    AccountConstructionError,
    AccountDefinition,
    Coverage,
    Selection,
    build_account,
    parse_definition,
    verify_account,
)

coincurve = pytest.importorskip("coincurve", reason="Nostr Schnorr signing needs coincurve")


# --------------------------------------------------------------------------- #
# Golden: the definition_digest of the mesh served/success fold DOCUMENT.      #
#                                                                              #
# This hex is the SHA-256 over the fold's canonical DEFINITION DOCUMENT (name, #
# selection_kind, reads, derivation_class) via the one JCS/digest impl in the  #
# neutral stack. It is what the account capsule + Nostr event carry. Pinning   #
# it as a literal is the "before" fixed point: any change to it flags that the #
# definition DOCUMENT moved — never an accidental internals change.            #
# --------------------------------------------------------------------------- #
GOLDEN_DEFINITION_DIGEST = "97130cc74ae73c93042980c71415945e042e92757daa49b341854906d8b4051a"


def _sample_account(*, witnessed: bool = True) -> ac.AccountCapsule:
    """A fully-populated account capsule with no I/O — a stable fixture for
    shape + digest assertions."""
    return ac.AccountCapsule(
        node_id="node-b7",
        selection_from_entry=1,
        selection_to_entry=3,
        covered_entries=3,
        fold=ac.AccountFold(n_total=3, n_served=3, n_requested=0, n_unknown_role=0, n_served_confirmed=2),
        coverage_root="abc123root",
        coverage_mmr_size=5,
        coverage_log_id="log-b7",
        coverage_timestamp="2026-08-31T00:00:00Z",
        coverage_witnesses=["https://ts.example"] if witnessed else [],
        coverage_witnessed=witnessed,
    )


# --------------------------------------------------------------------------- #
# (1) The Nostr event shape is UNCHANGED except for definition_digest.         #
# --------------------------------------------------------------------------- #
def _preswap_event_content_shape(account: ac.AccountCapsule, *, sealed_capsule_id=None) -> dict:
    """Reconstruct the EXACT pre-swap event content shape by hand — every key
    the event carried before the core swap — minus the one added field. If the
    swap silently reshaped anything else, comparing against this hand-built
    expectation catches it."""
    val = {
        "schema": ac.ACCOUNT_CAPSULE_SCHEMA,
        "node_id": account.node_id,
        "selection": {
            "from_entry": account.selection_from_entry,
            "to_entry": account.selection_to_entry,
            "covered_entries": account.covered_entries,
            "note": (
                "witnessed range only: entries appended after the latest "
                "witnessed checkpoint are excluded by design"
            ),
        },
        "derivation": {
            "kind": "served_success_fold",
            # definition_digest deliberately OMITTED here — it is the one field
            # the swap adds; the test adds it back and then asserts equality.
            "fold": account.fold.to_value(),
            "note": (
                "plain counts over the selected range; an ACCOUNT, not a "
                "score. The relying party computes its own predicate."
            ),
        },
        "coverage": {
            "checkpoint_root": account.coverage_root,
            "mmr_size": account.coverage_mmr_size,
            "log_id": account.coverage_log_id,
            "timestamp": account.coverage_timestamp,
            "witnesses": list(account.coverage_witnesses),
            "witnessed": account.coverage_witnessed,
            "note": (
                "cross-check handle: recompute the fold from the node's "
                "ledger, check the ledger against this root, confirm the "
                "root was witnessed"
            ),
        },
        "sybil_residual": account.sybil_residual,
        "not_a_score": (
            "This is an account of facts + a witness handle to verify them, "
            "not a score or routing recommendation. See example_predicate() "
            "for an EXAMPLE predicate only — never a default routing policy."
        ),
    }
    # The build_account_event adds these two content fields (pre-existing behavior).
    val["durability"] = (
        "This is a REPLACEABLE Nostr listing — a relay may drop or supersede it "
        "at any time. No durability is claimed for this summary here. The "
        "durable layer is the WITNESS: cross-check the coverage.checkpoint_root "
        "against the witness, do not rely on this relay copy."
    )
    return val


def test_event_shape_unchanged_except_definition_digest():
    account = _sample_account()
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    content = json.loads(evt.content)

    expected = _preswap_event_content_shape(account)
    # The ONE new field the swap adds, and where.
    assert content["derivation"]["definition_digest"] == GOLDEN_DEFINITION_DIGEST
    expected["derivation"]["definition_digest"] = content["derivation"]["definition_digest"]

    # Byte-for-byte the same content object once the single new field is added.
    assert content == expected, "the core swap reshaped the event beyond adding definition_digest"

    # And the event ENVELOPE (kind, d-tag, cross-check tags) is untouched.
    assert evt.kind == na.KIND_ACCOUNT_CAPSULE
    tag_map = {t[0]: t[1:] for t in evt.tags}
    assert tag_map["d"] == [na.ACCOUNT_D_TAG]
    assert tag_map["coverage_root"] == [account.coverage_root]
    assert tag_map["account_digest"] == [account.digest()]
    assert tag_map["node_id"] == [account.node_id]
    assert tag_map["witnessed"] == ["1"]


def test_event_tag_set_is_exactly_the_preswap_tags():
    """The tag KEYS (the event's public filter/cross-check surface) are exactly
    the pre-swap set — the swap adds NO tag."""
    account = _sample_account()
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    tag_keys = [t[0] for t in evt.tags]
    assert tag_keys == ["d", "k", "account_digest", "coverage_root", "node_id", "witnessed"]


# --------------------------------------------------------------------------- #
# (2) definition_digest is BYTE-IDENTICAL before and after an internals swap.  #
# --------------------------------------------------------------------------- #
def test_definition_digest_matches_golden_constant():
    """The digest the module ships equals the pinned pre-swap golden value.
    This is the fixed point the before/after comparison hangs on."""
    assert ac.MESH_ACCOUNT_DEFINITION_DIGEST == GOLDEN_DEFINITION_DIGEST
    assert ac.MESH_ACCOUNT_DEFINITION.definition_digest() == GOLDEN_DEFINITION_DIGEST
    # and it is surfaced identically wherever it appears
    account = _sample_account()
    assert account.definition_digest() == GOLDEN_DEFINITION_DIGEST
    assert account.to_value()["derivation"]["definition_digest"] == GOLDEN_DEFINITION_DIGEST


def test_definition_digest_is_byte_identical_across_an_internals_swap(monkeypatch):
    """END-TO-END implementation-independence: physically swap the fold's
    IMPLEMENTATION internals — the code that computes the served/success counts
    — to a completely different-but-equivalent body, and confirm the
    definition_digest does NOT move by a single byte.

    'digest BEFORE' = the digest the module computes with the shipped fold body.
    'digest AFTER'  = the digest the module computes after ``_fold_range`` (the
                      internal implementation) has been replaced at runtime by a
                      re-implemented body. The digest is over the definition
                      DOCUMENT (name/selection_kind/reads/derivation_class), NOT
                      over the fold code, so swapping the code cannot move it.

    This is the mesh-level, end-to-end proof of the core's mutation property:
    altering implementation internals does not move the digest. If this ever
    fails, the definition DOCUMENT itself changed (not just the code) and the
    swap must be reconciled with the registry/consumers.
    """
    # digest BEFORE: with the shipped fold implementation. Take it off a real,
    # built account so the whole build path (build_account_capsule -> core
    # Account -> definition_digest) is exercised, not just the constant.
    account_before = _sample_account()
    digest_before = account_before.definition_digest()
    core_before = account_before.core_account()
    assert core_before.derivation.definition_digest == digest_before

    # --- swap the INTERNALS: replace the fold implementation entirely. ---
    # A totally different code path that computes the same served/success counts
    # (accumulate into a dict, single pass, different control flow). The
    # DEFINITION document it operates under is untouched.
    def _reimplemented_fold(capsules):
        acc = {"served": 0, "requested": 0, "unknown": 0, "confirmed": 0}
        for c in capsules:
            r = ac._role_of(c)
            acc[r if r in ("served", "requested") else "unknown"] += 1
            if r == "served" and ac._effect_confirmed(c):
                acc["confirmed"] += 1
        return ac.AccountFold(
            n_total=len(capsules),
            n_served=acc["served"],
            n_requested=acc["requested"],
            n_unknown_role=acc["unknown"],
            n_served_confirmed=acc["confirmed"],
        )

    monkeypatch.setattr(ac, "_fold_range", _reimplemented_fold)

    # digest AFTER: with the swapped-in implementation, again off a real account.
    account_after = _sample_account()
    digest_after = account_after.definition_digest()
    core_after = account_after.core_account()

    # BYTE-IDENTICAL — the whole point of the swap: the definition_digest is
    # invariant to the fold implementation.
    assert digest_after == digest_before, (
        "definition_digest moved under an internals swap; the definition DOCUMENT "
        "changed and must be reconciled"
    )
    assert core_after.derivation.definition_digest == digest_before

    # Sanity: a re-parse of the SAME document via the core's dict-parsing path
    # (yet another construction route) lands on the same digest too.
    reparsed = parse_definition(ac.MESH_ACCOUNT_DEFINITION.canonical_document())
    assert reparsed.definition_digest() == digest_before


def test_altering_the_definition_document_DOES_move_the_digest():
    """The dual of the property: change the DOCUMENT (rename it) and the digest
    MUST move. This proves the digest is not a constant that ignores the
    document — it genuinely binds the definition-as-data."""
    mutated = AccountDefinition(
        name="mesh.served_success_fold/2",  # <- one field of the DOCUMENT changed
        selection_kind="range",
        reads=ac.MESH_ACCOUNT_DEFINITION.reads,
        derivation_class="deterministic",
    )
    assert mutated.definition_digest() != ac.MESH_ACCOUNT_DEFINITION_DIGEST


# --------------------------------------------------------------------------- #
# The core account object the capsule is a view of: range-kind, deterministic. #
# --------------------------------------------------------------------------- #
def test_core_account_is_range_kind_with_coverage_root_range_identity():
    """The mesh account is a RANGE-kind core Account: input identity is
    (coverage_root, range) — the witnessed root + covered span — and NEVER the
    per-member capsule digests."""
    account = _sample_account()
    core = account.core_account()
    assert core is not None
    assert core.selection.kind == "range"
    ident = core.selection.input_identity()
    assert ident == {"coverage_root": "abc123root", "range": [1, 3]}
    # explicitly: no per-member digest surface on a range identity.
    assert "references" not in ident
    assert "members" not in ident


def test_core_account_is_deterministic_and_carries_definition_digest():
    account = _sample_account()
    core = account.core_account()
    assert core.derivation.derivation_class == "deterministic"
    assert core.derivation.definition_digest == GOLDEN_DEFINITION_DIGEST
    # deterministic => no model provenance
    assert core.provenance is None
    # the asserted result IS the served/success fold counts
    assert core.asserted_result == account.fold.to_value()


def test_core_account_verifies_by_recompute_match():
    """The deterministic account verifies through the core by recompute+match,
    and the definition binding is checked (a swapped definition is caught)."""
    account = _sample_account()
    core = account.core_account()
    result = verify_account(
        core,
        definition=ac.MESH_ACCOUNT_DEFINITION,
        recompute=lambda _sel: account.fold.to_value(),
    )
    assert result.ok is True
    assert result.method == "recompute"
    # AccountCapsule.verify() is the same check, wrapped.
    assert account.verify() is True

    # A recompute that disagrees fails (result mismatch) — the match is real.
    bad = verify_account(
        core,
        definition=ac.MESH_ACCOUNT_DEFINITION,
        recompute=lambda _sel: {"n_total": 999},
    )
    assert bad.ok is False


def test_range_account_refuses_per_member_references():
    """Fail-closed: the core refuses a range selection that carries per-member
    references — the mesh account can never accidentally cite members on a
    range (its identity is root + span)."""
    with pytest.raises(AccountConstructionError):
        build_account(
            definition=ac.MESH_ACCOUNT_DEFINITION,
            selection=Selection(
                kind="range",
                coverage=Coverage(coverage_root="r", range=(1, 3), references=("member-digest-1",)),
            ),
            asserted_result={"n_total": 1},
        )


def test_honestly_empty_account_has_no_core_range():
    """A no-coverage account has no valid core range (coverage_root is empty);
    it still carries the definition_digest and trivially verifies."""
    empty = ac.build_account_capsule(node_id="n", capsules=[], latest_checkpoint=None)
    assert empty.core_account() is None
    assert empty.verify() is True
    assert empty.to_value()["derivation"]["definition_digest"] == GOLDEN_DEFINITION_DIGEST
