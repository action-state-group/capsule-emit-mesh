# SPDX-License-Identifier: Apache-2.0
"""[mesh-join-card] The `card` record + `card_consistency` verifier.

Exchange ledger lines are hand-built in the REAL Rust-producer nested shape
(`serving_provenance.model.{canonical_ref,weights_digest}`,
`serving_provenance.hardware.{gpu,vram_bytes,is_soc}`,
`evidence_refs.binary_attestation.measurement_class`) -- the same fixture
convention `tests/test_advertisement.py::_served()` already uses for the
identical tolerant-shape reason. Card ledger lines are sealed through the
REAL `seal_card()` (not hand-built), so a regression in the envelope shape
(e.g. `model_attestation.compute_attestation` nesting) is caught here too.
"""
from __future__ import annotations

from agent_action_capsule.verify import verify as verify_capsule

from join_card import (
    ANNOUNCEMENT_ABSENT,
    ANNOUNCEMENT_MATCH,
    ANNOUNCEMENT_MISMATCH,
    CARD_TRANSITION_LINEAGE_BROKEN,
    CARD_TRANSITION_NODE_ID_MISMATCH,
    CARD_TRANSITION_OK,
    CARD_TRANSITION_WIDENED,
    STATUS_BROKEN,
    STATUS_NO_CARD_SEALED,
    STATUS_NOTHING_COMPARED,
    STATUS_OK,
    ModelRef,
    build_card,
    card_consistency,
    check_announcement_consistency,
    latest_card,
    seal_card,
)


def _card(**overrides):
    kwargs = dict(
        node_id="mesh-node-demo-1",
        hardware_inventory={
            "source": "os_reported",
            "capture_method": "system_profiler",
            "grade": "os_measured",
            "chip": "Apple M4 Max",
            "memory_bytes": 42_949_672_960,
        },
        models=[ModelRef(name="meta/Llama-3.2-3B", weights_digest="a" * 64)],
        measurement_rung="os_measured",
        announcement_digest="d" * 64,
    )
    kwargs.update(overrides)
    return build_card(**kwargs)


def _sealed_card_line(card, *, prior_card_capsule_id=None, capsule_id_hint="card"):
    cap = seal_card(
        card,
        operator="op",
        developer="dev",
        signing_node_id="mesh-node-demo-1",
        prior_card_capsule_id=prior_card_capsule_id,
    )
    assert verify_capsule(cap).ok
    return cap


def _exchange_line(
    *,
    capsule_id,
    model_canonical_ref=None,
    weights_digest=None,
    gpu=None,
    vram_bytes=None,
    is_soc=None,
    measurement_class=None,
    served_by_node_id="mesh-node-demo-1",
):
    return {
        "capsule_id": capsule_id,
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "serving_provenance": {
                        "served_by_node_id": served_by_node_id,
                        "model": {"canonical_ref": model_canonical_ref, "weights_digest": weights_digest},
                        "hardware": {"gpu": gpu, "vram_bytes": vram_bytes, "is_soc": is_soc},
                    },
                    "evidence_refs": {"binary_attestation": {"measurement_class": measurement_class}},
                },
            },
        },
    }


# ── Card: build / seal / digest / supersedes ────────────────────────────────


def test_card_digest_changes_with_content():
    a = _card()
    b = _card(models=[ModelRef(name="mistralai/Mistral-7B", weights_digest="b" * 64)])
    assert a.digest() != b.digest()


def test_seal_card_first_has_no_supersedes_then_second_supersedes_first():
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    assert verify_capsule(cap1).ok
    assert card1.supersedes is None

    card2 = _card(
        models=[ModelRef(name="mistralai/Mistral-7B", weights_digest="c" * 64)],
        supersedes=card1.digest(),
    )
    cap2 = _sealed_card_line(card2, prior_card_capsule_id=cap1["capsule_id"])
    assert card2.supersedes == card1.digest()
    assert cap2["capsule_id"] != cap1["capsule_id"]


def test_latest_card_walks_to_the_last_one_sealed():
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    card2 = _card(measurement_rung="tee_measured", supersedes=card1.digest())
    cap2 = _sealed_card_line(card2, prior_card_capsule_id=cap1["capsule_id"])

    found, digest, capsule_id = latest_card([cap1, cap2])
    assert found.measurement_rung == "tee_measured"
    assert digest == card2.digest()
    assert capsule_id == cap2["capsule_id"]


def test_latest_card_none_when_ledger_has_no_card():
    found, digest, capsule_id = latest_card([_exchange_line(capsule_id="e1", model_canonical_ref="m")])
    assert found is None and digest is None and capsule_id is None


# ── card_consistency: the positional walk ───────────────────────────────────


def test_exchange_before_any_card_is_no_card_sealed():
    ledger = [_exchange_line(capsule_id="e1", model_canonical_ref="meta/Llama-3.2-3B")]
    result = card_consistency(ledger)
    assert result.ok is True  # no_card_sealed never flips ok to False
    assert result.no_card_sealed_count == 1
    assert result.entries[0].status == STATUS_NO_CARD_SEALED
    assert result.entries[0].card_digest is None


def test_exchange_matching_current_card_is_ok():
    card = _card()
    cap = _sealed_card_line(card)
    ledger = [
        cap,
        _exchange_line(
            capsule_id="e1",
            model_canonical_ref="meta/Llama-3.2-3B",
            weights_digest="a" * 64,
            gpu="Apple M4 Max",
            vram_bytes=42_949_672_960,
            is_soc=True,
            measurement_class="os_measured",
        ),
    ]
    result = card_consistency(ledger)
    assert result.ok is True
    assert result.entries[0].status == STATUS_OK
    assert result.entries[0].card_digest == card.digest()


def test_card_consistency_never_compares_to_the_latest_card():
    """THE acceptance shape: card #1, an exchange matching #1, card #2
    (supersedes #1), an exchange matching #2 -- each exchange must be graded
    against the card that was actually current AT ITS OWN POSITION, not
    whatever the newest card in the ledger later turns out to be."""
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    exchange1 = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
    )

    card2 = _card(
        models=[ModelRef(name="mistralai/Mistral-7B", weights_digest="b" * 64)],
        supersedes=card1.digest(),
    )
    cap2 = _sealed_card_line(card2, prior_card_capsule_id=cap1["capsule_id"])
    exchange2 = _exchange_line(
        capsule_id="e2",
        model_canonical_ref="mistralai/Mistral-7B",
        weights_digest="b" * 64,
    )

    result = card_consistency([cap1, exchange1, cap2, exchange2])
    assert result.ok is True
    e1_verdict, e2_verdict = result.entries
    assert e1_verdict.card_digest == card1.digest()
    assert e2_verdict.card_digest == card2.digest()
    # If exchange1 were (wrongly) checked against card2 it would report a
    # model mismatch (Llama vs the Mistral card2 claims) -- assert it did not.
    assert e1_verdict.status == STATUS_OK


# ── card_consistency: mutants ────────────────────────────────────────────────


def test_mutant_weights_digest_changed_without_a_new_card_is_broken():
    card = _card()
    cap = _sealed_card_line(card)
    tampered = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="f" * 64,  # swapped weights file, no new card sealed
    )
    result = card_consistency([cap, tampered])
    assert result.ok is False
    assert result.broken_count == 1
    entry = result.entries[0]
    assert entry.status == STATUS_BROKEN
    assert entry.card_digest == card.digest()
    fields = {m["field"] for m in entry.mismatches}
    assert "weights_digest" in fields
    mismatch = next(m for m in entry.mismatches if m["field"] == "weights_digest")
    assert mismatch["exchange"] == "f" * 64
    assert mismatch["card"] == "a" * 64


def test_mutant_hardware_changed_on_soc_without_a_new_card_is_broken():
    card = _card()  # memory_bytes=42_949_672_960, chip="Apple M4 Max"
    cap = _sealed_card_line(card)
    tampered = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
        gpu="Apple M4 Max",
        vram_bytes=8_589_934_592,  # claims a different (smaller) memory size
        is_soc=True,
    )
    result = card_consistency([cap, tampered])
    assert result.ok is False
    fields = {m["field"] for m in result.entries[0].mismatches}
    assert "hardware_memory_vs_vram" in fields


def test_hardware_not_compared_when_not_soc_never_fabricated():
    """A non-unified-memory host: vram_bytes and system memory_bytes name
    genuinely different quantities, so a difference must NOT be reported as
    a broken promise (that would be a fabricated equivalence)."""
    card = _card()
    cap = _sealed_card_line(card)
    exchange = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
        gpu="NVIDIA RTX 4090",
        vram_bytes=24_000_000_000,
        is_soc=False,
    )
    result = card_consistency([cap, exchange])
    assert result.ok is True
    assert result.entries[0].mismatches == ()


def test_mismatched_model_name_not_on_the_card_is_broken():
    card = _card()  # only advertises meta/Llama-3.2-3B
    cap = _sealed_card_line(card)
    exchange = _exchange_line(capsule_id="e1", model_canonical_ref="some/other-model")
    result = card_consistency([cap, exchange])
    assert result.ok is False
    entry = result.entries[0]
    assert entry.status == STATUS_BROKEN
    mismatch = next(m for m in entry.mismatches if m["field"] == "model")
    assert mismatch["exchange"] == "some/other-model"
    assert mismatch["card"] == ["meta/Llama-3.2-3B"]


def test_absent_claims_are_not_compared_never_a_false_mismatch():
    """A host predating weights_digest / measurement_class simply omits the
    field -- absence must not be reported as a broken promise."""
    card = _card()
    cap = _sealed_card_line(card)
    exchange = _exchange_line(capsule_id="e1", model_canonical_ref="meta/Llama-3.2-3B")
    result = card_consistency([cap, exchange])
    assert result.ok is True
    assert result.entries[0].status == STATUS_OK
    assert result.entries[0].mismatches == ()


# ── announcement consistency (the "PeerAnnouncement" mutant) ───────────────


def test_announcement_consistency_match():
    card = _card(announcement_digest="d" * 64)
    result = check_announcement_consistency(card, "d" * 64)
    assert result["status"] == ANNOUNCEMENT_MATCH


def test_announcement_consistency_mismatch_labeled_advertised_mismatch():
    card = _card(announcement_digest="d" * 64)
    result = check_announcement_consistency(card, "e" * 64)
    assert result["status"] == ANNOUNCEMENT_MISMATCH
    assert result["status"] == "advertised_mismatch"
    assert result["card_announcement_digest"] == "d" * 64
    assert result["observed_digest"] == "e" * 64


def test_announcement_consistency_absent_when_either_side_missing():
    card = _card(announcement_digest=None)
    assert check_announcement_consistency(card, "e" * 64)["status"] == ANNOUNCEMENT_ABSENT
    card2 = _card(announcement_digest="d" * 64)
    assert check_announcement_consistency(card2, None)["status"] == ANNOUNCEMENT_ABSENT


# ── card_consistency: card-transition lineage (CARD-2) ──────────────────────


def test_first_card_transition_is_ok_even_with_no_supersedes():
    cap = _sealed_card_line(_card())
    result = card_consistency([cap])
    assert result.ok is True
    assert len(result.card_transitions) == 1
    assert result.card_transitions[0].status == CARD_TRANSITION_OK
    assert result.card_transitions[0].prior_card_digest is None


def test_first_card_claiming_a_supersedes_is_lineage_broken():
    """No prior card ever existed in this ledger -- a `supersedes` here
    names a predecessor that does not exist."""
    fabricated = _card(supersedes="f" * 64)
    cap = _sealed_card_line(fabricated)
    result = card_consistency([cap])
    assert result.ok is False
    assert result.card_transitions[0].status == CARD_TRANSITION_LINEAGE_BROKEN
    assert result.broken_transition_count == 1


def test_honest_supersede_chain_stays_green():
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    card2 = _card(measurement_rung="tee_measured", supersedes=card1.digest())
    cap2 = _sealed_card_line(card2, prior_card_capsule_id=cap1["capsule_id"])
    result = card_consistency([cap1, cap2])
    assert result.ok is True
    assert [t.status for t in result.card_transitions] == [CARD_TRANSITION_OK, CARD_TRANSITION_OK]


def test_mutant_supersede_to_nonexistent_digest_is_lineage_broken():
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    forged = _card(supersedes="bad" + "0" * 61)  # not card1.digest()
    cap2 = _sealed_card_line(forged, prior_card_capsule_id=cap1["capsule_id"])
    result = card_consistency([cap1, cap2])
    assert result.ok is False
    assert result.card_transitions[1].status == CARD_TRANSITION_LINEAGE_BROKEN
    assert result.card_transitions[1].prior_card_digest == card1.digest()


def test_mutant_fork_two_cards_claiming_the_same_predecessor_is_lineage_broken():
    """card2 validly supersedes card1; card3 ALSO claims to supersede card1
    (a fork off an earlier link, not the actual current card card2)."""
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    card2 = _card(models=[ModelRef(name="mistralai/Mistral-7B", weights_digest="c" * 64)], supersedes=card1.digest())
    cap2 = _sealed_card_line(card2, prior_card_capsule_id=cap1["capsule_id"])
    card3 = _card(models=[ModelRef(name="forked/model", weights_digest="e" * 64)], supersedes=card1.digest())
    cap3 = _sealed_card_line(card3, prior_card_capsule_id=cap1["capsule_id"])

    result = card_consistency([cap1, cap2, cap3])
    assert result.ok is False
    assert result.card_transitions[0].status == CARD_TRANSITION_OK  # card1: first card
    assert result.card_transitions[1].status == CARD_TRANSITION_OK  # card2: honest supersede of card1
    assert result.card_transitions[2].status == CARD_TRANSITION_LINEAGE_BROKEN  # card3: forks off card1, not card2


def test_mutant_supersede_with_wrong_node_id_is_node_id_mismatch():
    card1 = _card(node_id="mesh-node-demo-1")
    cap1 = _sealed_card_line(card1)
    mallory_card = _card(node_id="mallory-node", supersedes=card1.digest())
    cap2 = _sealed_card_line(mallory_card, prior_card_capsule_id=cap1["capsule_id"])

    result = card_consistency([cap1, cap2])
    assert result.ok is False
    assert result.card_transitions[1].status == CARD_TRANSITION_NODE_ID_MISMATCH


# ── card_consistency: supersede-to-vagueness (CARD-1) ───────────────────────


def test_mutant_supersede_widens_models_to_empty_is_labeled_and_red():
    """The prior card pinned a model; the successor supersedes-to-vagueness
    with `models: []`, which would otherwise disable the model/weights_digest
    checks entirely for every exchange sealed after it."""
    card1 = _card()  # pins meta/Llama-3.2-3B
    cap1 = _sealed_card_line(card1)
    vague = _card(models=[], supersedes=card1.digest())
    cap2 = _sealed_card_line(vague, prior_card_capsule_id=cap1["capsule_id"])

    result = card_consistency([cap1, cap2])
    assert result.ok is False
    transition = result.card_transitions[1]
    assert transition.status == CARD_TRANSITION_WIDENED
    assert "models" in transition.widened_fields


def test_mutant_supersede_widens_every_pinned_field_lists_them_all():
    card1 = _card()
    cap1 = _sealed_card_line(card1)
    vague = _card(
        models=[],
        hardware_inventory=None,
        measurement_rung=None,
        announcement_digest=None,
        supersedes=card1.digest(),
    )
    cap2 = _sealed_card_line(vague, prior_card_capsule_id=cap1["capsule_id"])

    result = card_consistency([cap1, cap2])
    transition = result.card_transitions[1]
    assert transition.status == CARD_TRANSITION_WIDENED
    assert set(transition.widened_fields) == {
        "models",
        "hardware_inventory",
        "measurement_rung",
        "announcement_digest",
    }


def test_honest_narrowing_supersede_is_not_widened():
    """Dropping from two models to one that is STILL pinned is narrowing,
    not vagueness -- must not be flagged as a widen."""
    card1 = _card(
        models=[
            ModelRef(name="meta/Llama-3.2-3B", weights_digest="a" * 64),
            ModelRef(name="mistralai/Mistral-7B", weights_digest="b" * 64),
        ]
    )
    cap1 = _sealed_card_line(card1)
    narrowed = _card(models=[ModelRef(name="meta/Llama-3.2-3B", weights_digest="a" * 64)], supersedes=card1.digest())
    cap2 = _sealed_card_line(narrowed, prior_card_capsule_id=cap1["capsule_id"])

    result = card_consistency([cap1, cap2])
    assert result.ok is True
    assert result.card_transitions[1].status == CARD_TRANSITION_OK


# ── card_consistency: exchange bound to served_by_node_id (CARD-2) ──────────


def test_exchange_served_by_wrong_node_id_is_broken():
    card = _card()
    cap = _sealed_card_line(card)
    stolen = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
        served_by_node_id="mallory-node",
    )
    result = card_consistency([cap, stolen])
    assert result.ok is False
    entry = result.entries[0]
    assert entry.status == STATUS_BROKEN
    mismatch = next(m for m in entry.mismatches if m["field"] == "served_by_node_id")
    assert mismatch["exchange"] == "mallory-node"
    assert mismatch["card"] == "mesh-node-demo-1"


def test_exchange_served_by_honest_node_id_is_ok():
    card = _card()
    cap = _sealed_card_line(card)
    exchange = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
        served_by_node_id="mesh-node-demo-1",
    )
    result = card_consistency([cap, exchange])
    assert result.ok is True
    assert result.entries[0].status == STATUS_OK


# ── card_consistency: vacuous OK (CARD-3) ───────────────────────────────────


def test_mutant_exchange_with_nothing_comparable_is_not_status_ok():
    """The shipped sidecar path for a requester's own-half record: no model,
    no weights_digest, no hardware, no measurement_class, and
    `served_by_node_id` left at the honest "unknown" sentinel (cleaned to
    absent). Zero fields are reconcilable -- this must render as a distinct
    verdict, never byte-identical to a genuinely verified STATUS_OK."""
    card = _card()
    cap = _sealed_card_line(card)
    vacuous = _exchange_line(capsule_id="e1", served_by_node_id="unknown")
    result = card_consistency([cap, vacuous])
    assert result.entries[0].status == STATUS_NOTHING_COMPARED
    assert result.entries[0].status != STATUS_OK
    assert result.nothing_compared_count == 1
    # Nothing-comparable is not itself evidence of a broken promise.
    assert result.ok is True


def test_genuinely_comparable_exchange_stays_status_ok_not_nothing_compared():
    card = _card()
    cap = _sealed_card_line(card)
    exchange = _exchange_line(
        capsule_id="e1",
        model_canonical_ref="meta/Llama-3.2-3B",
        weights_digest="a" * 64,
    )
    result = card_consistency([cap, exchange])
    assert result.entries[0].status == STATUS_OK
    assert result.nothing_compared_count == 0
