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
    STATUS_BROKEN,
    STATUS_NO_CARD_SEALED,
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
):
    return {
        "capsule_id": capsule_id,
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "serving_provenance": {
                        "served_by_node_id": "mesh-node-demo-1",
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
