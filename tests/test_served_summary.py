# SPDX-License-Identifier: Apache-2.0
"""``served_summary()``: "what did this stranger actually serve" -- the
per-model served/completed/failed fold + latency distribution, witness-
bounded exactly like ``account_capsule.py``, verified by recompute+match
through the same neutral ``capsule_emit.account`` core ``history_card.py``
already uses.

Focus of these tests: (1) the fold only counts records this node SERVED,
never requested; (2) recompute+match flips to failure on a tampered
asserted result, never silently passes; (3) the floor redacts a
below-threshold model's counts/latency to "fewer than 5", never an exact
number; (4) no requester-identity field ever reaches the folded result even
when the raw records carry one; (5) the sampled check (``verify_served_summary``)
flags a record whose model/status/latency contradicts the summary's claims;
(6) ``answer_served_summary_request`` is fail-closed on ``expected_pin``,
same discipline as ``history_card.answer_full_history_request``; (7) no
field anywhere in the summary looks like a rating (``assert_no_rating_fields``).

Builds REAL checkpoint chains through ``checkpointing.CheckpointState``, same
convention ``test_history_card.py`` uses -- never a hand-rolled
``CheckpointRecord`` that would let witness-bounding pass trivially.
"""
from __future__ import annotations

import dataclasses
import json

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, CheckpointRecord, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

from peer_accountability_tab import assert_no_rating_fields as pane_b_assert_no_rating_fields
from self_accountability import RatingFieldError, assert_no_rating_fields
from served_summary import (
    COVERAGE_UNSATISFIABLE,
    FLOOR,
    MESH_SERVED_SUMMARY_DEFINITION_DIGEST,
    REQUEST_MALFORMED,
    answer_served_summary_request,
    build_served_summary,
    sample_positions,
    seal_served_summary,
    verify_served_summary,
    verify_served_summary_recompute,
)


def _capsule(
    i: int,
    *,
    status: str = "confirmed",
    model: str = "m/1",
    quantization: str = "Q4",
    latency_ms: str = "10.0",
    weights_digest: str | None = None,
    served: bool = True,
    initiator_ref: str | None = None,
) -> dict:
    """A capsule shaped like ``capsule_sidecar.py``'s real output -- the six
    declared-read fields plus, when `initiator_ref` is set, a requester-
    identity field the fold must NEVER read or leak."""
    poc: dict = {
        "latency_ms": latency_ms,
        "serving_provenance": {
            "model_canonical_ref": model,
            "quantization": quantization,
            "role": "provider" if served else "requester",
        },
        # top-level poc role: "served"/"requested" -- what capsule_mesh_view.label_role()
        # actually reads. Set explicitly so requested-role records are excluded
        # regardless of the default-by-source-log fallback.
        "role": "served" if served else "requested",
    }
    if weights_digest is not None:
        poc["serving_provenance"]["weights_digest"] = weights_digest
    if initiator_ref is not None:
        poc["cross_party"] = {"initiator_ref": initiator_ref}
    return {
        "capsule_id": f"{i:064x}",
        "effect": {"status": status},
        "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": poc}},
    }


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _checkpoint_over(tmp_path, capsules: list[dict], *, log_id: str = "log-a"):
    """Seal `capsules` into a real JsonlLogSource and force ONE checkpoint
    over all of them (cadence == len), returning `(latest_checkpoint,
    checkpoint_lines)`. Mirrors `test_history_card.py`'s `_build_chain` but
    forces exactly one checkpoint over the whole set, which is what
    `build_served_summary`'s witness-bounded selection needs to cover
    every capsule under test."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=len(capsules), max_lag_entries=10_000, ts_urls=["https://fake-ts.example"])
    signer = Ed25519Signer(tmp_path / "node-a.pem")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id=log_id)
    for c in capsules:
        log.append(c)
        state.record_appended()
    lines = [json.loads(line) for line in (tmp_path / "checkpoints.jsonl").read_text().splitlines()]
    return CheckpointRecord.from_dict(lines[-1]), lines


# --------------------------------------------------------------------------- #
# The fold: served-only, per-model, status buckets, latency distribution.    #
# --------------------------------------------------------------------------- #


def test_fold_counts_only_served_records_never_requested(tmp_path, fake_witness):
    caps = [_capsule(i, served=True) for i in range(6)] + [_capsule(100 + i, served=False) for i in range(3)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    assert set(summary.by_model) == {"m/1"}
    assert summary.by_model["m/1"].n_served == 6


def test_fold_splits_completed_and_failed_by_effect_status(tmp_path, fake_witness):
    caps = [_capsule(i, status="confirmed" if i % 2 == 0 else "failed") for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    stats = summary.by_model["m/1"]
    assert stats.n_completed == 3
    assert stats.n_failed == 3
    assert stats.n_refused == 0  # EFFECT_STATUSES carries no "refused" value today


def test_fold_computes_latency_percentiles_per_model(tmp_path, fake_witness):
    caps = [_capsule(i, latency_ms=str(10 + i)) for i in range(6)]  # 10..15
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    stats = summary.by_model["m/1"]
    assert stats.latency_max_ms == 15.0
    assert stats.latency_p50_ms == pytest.approx(12.5)


def test_fold_never_fabricates_a_weights_digest(tmp_path, fake_witness):
    """No capsule this sidecar seals today carries `weights_digest` -- same
    honest absence `self_accountability.rung_summary` documents. Every
    record's weights_digest must fold to absent, never invented."""
    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    stats = summary.by_model["m/1"]
    assert stats.weights_digest_present == 0
    assert stats.weights_digest_absent == 6


def test_fold_counts_a_present_weights_digest_when_a_future_producer_seals_one(tmp_path, fake_witness):
    """The extraction reads the field rather than hardcoding None -- proves
    it stops being a no-op automatically the day a producer starts sealing
    it, with no code change required here."""
    caps = [_capsule(i, weights_digest="sha256:" + "a" * 64) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    stats = summary.by_model["m/1"]
    assert stats.weights_digest_present == 6
    assert stats.weights_digest_absent == 0


def test_fold_separates_models_into_distinct_buckets(tmp_path, fake_witness):
    caps = [_capsule(i, model="m/1") for i in range(6)] + [_capsule(100 + i, model="m/2") for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    assert set(summary.by_model) == {"m/1", "m/2"}
    assert summary.by_model["m/1"].n_served == 6
    assert summary.by_model["m/2"].n_served == 6


def test_no_checkpoint_yet_is_honestly_empty_not_a_fabricated_zero():
    summary = build_served_summary(node_id="n1", capsule_records=[_capsule(0)], latest_checkpoint=None)
    assert summary.coverage_root == ""
    assert summary.by_model == {}
    assert summary.verify()


def test_entries_after_the_latest_checkpoint_are_excluded_witness_bounded(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    # Append MORE served exchanges after the checkpoint was taken -- these
    # must not be folded in, same discipline account_capsule.py enforces.
    caps_plus_unwitnessed = caps + [_capsule(900 + i) for i in range(4)]

    summary = build_served_summary(node_id="n1", capsule_records=caps_plus_unwitnessed, latest_checkpoint=latest)

    assert summary.covered_entries == 6
    assert summary.by_model["m/1"].n_served == 6


# --------------------------------------------------------------------------- #
# No requester identifiers -- ever.                                          #
# --------------------------------------------------------------------------- #


def test_no_requester_identifier_ever_reaches_the_folded_result_or_reads(tmp_path, fake_witness):
    """`initiator_ref`/`requesting_party` VALUES injected into the raw
    records must never leak into the folded output -- the summary's own
    `no_requester_identifiers` disclaimer text legitimately NAMES those
    field paths in prose, so this checks for the injected VALUE, not the
    field-name substring."""
    caps = [_capsule(i, initiator_ref="deadbeefcafe" * 5) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    dumped = json.dumps(summary.to_value())

    assert "deadbeefcafe" not in dumped
    assert set(MESH_SERVED_SUMMARY_DEFINITION_DIGEST) <= set("0123456789abcdef")  # sanity: it's a hex digest
    assert "cross_party" not in summary.by_model  # only ever a model-name key, never smuggled in as one


# --------------------------------------------------------------------------- #
# Recompute+match -- must fail its mutant.                                   #
# --------------------------------------------------------------------------- #


def test_verify_passes_on_an_honest_summary(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    assert summary.verify()


def test_core_account_verify_confirms_wrapper_shape_but_is_not_the_mutant_check(tmp_path, fake_witness):
    """`ServedSummary.verify()` recomputes from the object's OWN current
    fields (same pattern `account_capsule.py`/`history_card.py` use for
    their `.verify()`) -- it confirms the neutral-core wrapper's internal
    consistency (selection shape, definition-digest citation), but a
    tampered object recomputes from ITSELF and so trivially agrees with
    itself. `verify_served_summary_recompute` (below) is the real
    mutant-catching check, run against the RAW ledger independently."""
    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    assert summary.verify()

    tampered = dataclasses.replace(
        summary,
        by_model={"m/1": dataclasses.replace(summary.by_model["m/1"], n_completed=999)},
    )
    assert tampered.verify()  # self-consistent with its OWN (tampered) fields -- documented limit


def test_verify_served_summary_recompute_passes_on_an_honest_published_summary(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    latest, lines = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    result = verify_served_summary_recompute(summary.to_value(), caps, lines)
    assert result.ok, result.errors


def test_verify_served_summary_recompute_fails_when_the_published_value_is_tampered(tmp_path, fake_witness):
    """THE real mutant-catching check: a summary published with an inflated
    count must be caught by rebuilding from the raw ledger + checkpoints
    independently -- never a silent pass."""
    caps = [_capsule(i) for i in range(6)]
    latest, lines = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    overclaimed = summary.to_value()
    overclaimed["derivation"]["by_model"]["m/1"]["completed"] = 999  # lie about the count

    result = verify_served_summary_recompute(overclaimed, caps, lines)
    assert not result.ok
    assert any("does not match" in e for e in result.errors)


def test_verify_served_summary_recompute_catches_a_tampered_ledger_behind_a_stale_published_summary(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    latest, lines = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    published = summary.to_value()  # honest at publish time

    tampered_caps = list(caps)
    tampered_caps[0] = _capsule(0, status="failed")  # ledger rewritten after publish

    result = verify_served_summary_recompute(published, tampered_caps, lines)
    assert not result.ok


def test_verify_history_card_style_definition_digest_is_stable_and_hex():
    # The digest is over the DEFINITION document, not this module's code --
    # recomputing it twice must be byte-identical.
    from served_summary import MESH_SERVED_SUMMARY_DEFINITION

    assert MESH_SERVED_SUMMARY_DEFINITION.definition_digest() == MESH_SERVED_SUMMARY_DEFINITION_DIGEST


# --------------------------------------------------------------------------- #
# Floor redaction -- "fewer than 5", never an exact number, below threshold. #
# --------------------------------------------------------------------------- #


def test_below_floor_model_is_redacted_to_fewer_than_5(tmp_path, fake_witness):
    caps = [_capsule(i, model="rare") for i in range(FLOOR - 1)] + [_capsule(50, model="common")] * 0
    caps += [_capsule(200 + i, model="common") for i in range(FLOOR)]
    latest, _ = _checkpoint_over(tmp_path, caps)

    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    rare = value["derivation"]["by_model"]["rare"]
    assert rare["served"] == "fewer than 5"
    assert rare["completed"] == "fewer than 5"
    assert rare["latency_p50_ms"] is None
    assert rare["floor_applied"] is True

    common = value["derivation"]["by_model"]["common"]
    assert common["served"] == FLOOR
    assert common["floor_applied"] is False


def test_floor_is_a_display_transform_recompute_match_still_holds(tmp_path, fake_witness):
    """Floored publication and full-precision verification are the same
    deterministic function of the selected inputs -- recompute+match must
    still pass even though the published counts are redacted."""
    caps = [_capsule(i, model="rare") for i in range(FLOOR - 1)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    assert summary.verify()


# --------------------------------------------------------------------------- #
# Sampled check -- a relying party's own spot-check.                        #
# --------------------------------------------------------------------------- #


def test_sample_positions_is_deterministic_for_the_same_nonce():
    a = sample_positions(20, 5, nonce="shared-nonce")
    b = sample_positions(20, 5, nonce="shared-nonce")
    assert a == b
    assert len(a) == 5
    assert a == sorted(a)


def test_sample_positions_differs_for_a_different_nonce():
    a = sample_positions(20, 5, nonce="nonce-a")
    b = sample_positions(20, 5, nonce="nonce-b")
    assert a != b


def test_sample_positions_clamps_k_to_n_total():
    assert sample_positions(3, 10, nonce="x") == [0, 1, 2]
    assert sample_positions(0, 10, nonce="x") == []


def test_verify_served_summary_ok_on_a_genuine_sample(tmp_path, fake_witness):
    caps = [_capsule(i, latency_ms=str(10 + i)) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    positions = sample_positions(summary.covered_entries, 4, nonce="verify")
    sampled = [caps[i] for i in positions]

    result = verify_served_summary(value, sampled)
    assert result.ok
    assert result.sampled == 4
    assert result.contradictions == []


def test_verify_served_summary_contradicted_on_a_model_absent_from_the_summary(tmp_path, fake_witness):
    caps = [_capsule(i, model="m/1") for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    forged = _capsule(999, model="never-served-this")
    result = verify_served_summary(value, [forged])

    assert not result.ok
    assert any("never-served-this" in c and "not present" in c for c in result.contradictions)


def test_verify_served_summary_contradicted_on_a_latency_exceeding_claimed_max(tmp_path, fake_witness):
    caps = [_capsule(i, latency_ms=str(10 + i)) for i in range(6)]  # max 15.0
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    tampered = json.loads(json.dumps(caps[0]))
    tampered["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["latency_ms"] = "999999"

    result = verify_served_summary(value, [tampered])
    assert not result.ok
    assert any("exceeds" in c for c in result.contradictions)


def test_verify_served_summary_contradicted_on_a_status_bucket_claimed_zero(tmp_path, fake_witness):
    # Every sealed record is "confirmed" -- summary claims 0 failed for m/1.
    caps = [_capsule(i, status="confirmed") for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    forged_failed = _capsule(999, status="failed")
    result = verify_served_summary(value, [forged_failed])

    assert not result.ok
    assert any("failed" in c and "claims 0" in c for c in result.contradictions)


def test_verify_served_summary_below_floor_only_checks_model_presence(tmp_path, fake_witness):
    """Below the floor, counts/latency are redacted -- the sampled check can
    only still confirm the model is present, a documented weakening, never a
    silent false pass presented as a full check."""
    caps = [_capsule(i, model="rare") for i in range(FLOOR - 1)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)
    value = summary.to_value()

    # A wildly out-of-range latency for a below-floor model is NOT flagged --
    # documented limitation of the floor's privacy guarantee.
    tampered = json.loads(json.dumps(caps[0]))
    tampered["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["latency_ms"] = "999999"
    result = verify_served_summary(value, [tampered])
    assert result.ok


# --------------------------------------------------------------------------- #
# answer_served_summary_request -- fail-closed on expected_pin.             #
# --------------------------------------------------------------------------- #


def test_answer_refuses_without_expected_pin(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    _, lines = _checkpoint_over(tmp_path, caps)
    result = answer_served_summary_request(capsule_records=caps, checkpoint_lines=lines, expected_pin=None)
    assert result["status"] == REQUEST_MALFORMED


def test_answer_refuses_a_stale_or_wrong_pin(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    _, lines = _checkpoint_over(tmp_path, caps)
    result = answer_served_summary_request(capsule_records=caps, checkpoint_lines=lines, expected_pin="00" * 32)
    assert result["status"] == COVERAGE_UNSATISFIABLE


def test_answer_refuses_with_no_checkpoints_at_all():
    result = answer_served_summary_request(capsule_records=[], checkpoint_lines=[], expected_pin="ab" * 32)
    assert result["status"] == COVERAGE_UNSATISFIABLE


def test_answer_ok_under_a_matching_pin(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    _, lines = _checkpoint_over(tmp_path, caps)
    pin = lines[-1]["root"]
    result = answer_served_summary_request(capsule_records=caps, checkpoint_lines=lines, expected_pin=pin)
    assert result["status"] == "ok"
    assert result["served_summary"]["derivation"]["by_model"]["m/1"]["served"] == 6


def test_answer_never_answers_on_demand_even_with_perfect_data(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(10)]
    _, lines = _checkpoint_over(tmp_path, caps)
    result = answer_served_summary_request(capsule_records=caps, checkpoint_lines=lines, expected_pin="")
    assert result["status"] == REQUEST_MALFORMED


# --------------------------------------------------------------------------- #
# Never a rating field, anywhere in the summary.                             #
# --------------------------------------------------------------------------- #


def test_summary_never_carries_a_rating_field(tmp_path, fake_witness):
    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    assert_no_rating_fields(summary.to_value())
    pane_b_assert_no_rating_fields(summary.to_value())


def test_summary_rejects_an_actual_smuggled_rating_field():
    with pytest.raises(RatingFieldError):
        assert_no_rating_fields({"by_model": {"m/1": {"trust_score": 0.9}}})


# --------------------------------------------------------------------------- #
# Sealing -- a capsule, not an out-of-band JSON summary.                    #
# --------------------------------------------------------------------------- #


def test_seal_served_summary_produces_a_capsule_that_verifies(tmp_path, fake_witness):
    from agent_action_capsule.verify import verify as verify_capsule

    caps = [_capsule(i) for i in range(6)]
    latest, _ = _checkpoint_over(tmp_path, caps)
    summary = build_served_summary(node_id="n1", capsule_records=caps, latest_checkpoint=latest)

    sealed = seal_served_summary(summary, operator="acme", developer="dev/0.1.0", signing_node_id="n1")

    assert sealed["action_type"] == "fyi"
    result = verify_capsule(sealed)
    assert result.ok, result.findings
