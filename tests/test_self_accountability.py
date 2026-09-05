# SPDX-License-Identifier: Apache-2.0
"""[mesh-pane-a-self-accountability-tab] Pane A "This node" card.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant. Each acceptance mutant from the inbox item gets its own test:

  - an unsealed request -> card shows `coverage: N unsealed`
  - a sealing gap inside a runtime-shutdown window -> labeled runtime-down
    line, not a bare "unsealed"
  - every fact carries source/capture_method (or an honest absent + reason)
  - no field can hold a rating
"""
from __future__ import annotations

import json

import checkpointing
import pytest
from capsule_emit.checkpoint import WitnessRecord
from checkpointing import CheckpointConfig, CheckpointState, Ed25519Signer, JsonlLogSource

from self_accountability import (
    HONESTY_LINE,
    RatingFieldError,
    adjudications_summary,
    assert_no_rating_fields,
    build_self_accountability_card,
    history_summary,
    rung_summary,
    sealing_summary,
    shared_summary,
)


def _native(request_id: str, *, status: str, request_digest: str | None, timestamp: str) -> dict:
    return {"request_id": request_id, "timestamp": timestamp, "status": status, "request_digest": request_digest}


def _capsule(*, request_digest: str, verdict_class: str, capsule_id: str, timestamp: str) -> dict:
    return {
        "capsule_id": capsule_id,
        "timestamp": timestamp,
        "effect": {"request_digest": request_digest},
        "disposition": {"verdict_class": verdict_class},
    }


# ── sealing_summary -- MUTANT: unsealed request -> coverage: N unsealed ────


def test_mutant_unsealed_request_shows_coverage_count():
    native = [_native("r1", status="SUCCESS", request_digest="a" * 64, timestamp="2026-09-02T00:00:00Z")]
    summary = sealing_summary(native, [], [])
    assert summary["coverage_summary"] == "coverage: 1 request(s) unsealed"
    assert summary["unsealed_count"] == 1


def test_fully_sealed_reports_fully_sealed():
    native = [_native("r1", status="SUCCESS", request_digest="a" * 64, timestamp="2026-09-02T00:00:00Z")]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="executed", capsule_id="cap-1", timestamp="2026-09-02T00:00:01Z")]
    summary = sealing_summary(native, capsules, [])
    assert summary["coverage_summary"] == "coverage: fully sealed"
    assert summary["unsealed_count"] == 0
    assert summary["last_sealed"] == "2026-09-02T00:00:01Z"


# ── sealing_summary -- MUTANT: gap inside a runtime-shutdown window -------


def test_mutant_gap_inside_shutdown_window_is_labeled_runtime_down():
    native = [_native("r1", status="FAILED", request_digest=None, timestamp="2026-09-02T08:37:00Z")]
    lifecycle = [
        {"event": "runtime_shutdown_begin", "timestamp": "2026-09-02T08:35:32Z"},
        {"event": "runtime_shutdown_end", "timestamp": "2026-09-02T08:41:10Z"},
    ]
    summary = sealing_summary(native, [], lifecycle)
    [row] = summary["unsealed_rows"]
    assert "runtime down" in row["finding"]
    assert row["finding"] == "sealing was off between 2026-09-02T08:35:32Z and 2026-09-02T08:41:10Z (runtime down)"
    assert summary["failed_sealed"] is True


def test_unexplained_gap_is_not_folded_into_runtime_down():
    native = [_native("r1", status="FAILED", request_digest=None, timestamp="2026-09-02T09:00:00Z")]
    summary = sealing_summary(native, [], [])
    [row] = summary["unsealed_rows"]
    assert row["finding"] == "unsealed"
    assert "runtime down" not in row["finding"]


# ── history_summary -- reuses history_card verbatim -----------------------


def _fake_capsule(i: int) -> dict:
    return {"capsule_id": f"{i:064x}", "n": i}


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


def _build_chain(tmp_path, n_checkpoints: int, *, log_id: str = "log-a", entries_per_checkpoint: int = 2):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=entries_per_checkpoint, max_lag_entries=10_000, ts_urls=["https://fake-ts.example"])
    signer = Ed25519Signer(tmp_path / "node-a.pem")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id=log_id)

    n = 0
    made = 0
    while made < n_checkpoints:
        log.append(_fake_capsule(n))
        n += 1
        if state.record_appended() is not None:
            made += 1

    lines = (tmp_path / "checkpoints.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def test_history_summary_reports_unbroken_witnessed_chain(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=lines)
    assert summary["continuity"] == "unbroken"
    assert summary["unforked"] is True
    assert summary["checkpoint_count"] == 3
    assert summary["witnessed"] is True
    assert summary["continuous_since"] == lines[0]["timestamp"]
    assert summary["source"] == "history_card"


def test_history_summary_on_empty_log_is_honestly_empty():
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[])
    assert summary["checkpoint_count"] == 0
    assert summary["witnessed"] is False
    assert summary["continuous_since"] is None


# ── history_summary.pair_sequencing -- [mesh-sequence-per-counterparty] ──


def _pair_capsule(*, self_id: str, counterparty_id: str, seq: int, prev_seq: int | None) -> dict:
    return {
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "serving_provenance": {
                        "role": "provider",
                        "served_by_node_id": self_id,
                        "requesting_party": counterparty_id,
                        "seq": seq,
                        "prev_seq": prev_seq,
                    }
                }
            }
        }
    }


def test_history_summary_omits_pair_sequencing_when_ledger_records_not_supplied():
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[])
    assert "pair_sequencing" not in summary, "never a fabricated zero when the caller gave no ledger to check"


def test_mutant_dropping_a_record_from_a_bundle_reports_gaps_detected_one():
    """ACCEPTANCE MUTANT: drop one record from a bundle -> history row shows
    `gaps_detected: 1` -- a labeled count, not a broken-continuity claim."""
    records = [
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=1, prev_seq=None),
        # seq=2 dropped from this bundle -- the bundle delivers 1, 3.
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=3, prev_seq=2),
    ]
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[], ledger_records=records)
    assert summary["pair_sequencing"]["gaps_detected"] == 1
    assert summary["pair_sequencing"]["broken_pairs"] == []
    assert summary["pair_sequencing"]["pairs_checked"] == 1


def test_mutant_reset_counter_reports_a_broken_pair_not_a_fresh_start():
    records = [
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=1, prev_seq=None),
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=2, prev_seq=1),
        # Counter cache wiped; sealing resumed as if this pair were new.
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=1, prev_seq=None),
    ]
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[], ledger_records=records)
    assert summary["pair_sequencing"]["broken_pairs"] == ["m4::m3"]


def test_mutant_exchanges_filed_under_unknown_are_counted_and_labeled_not_blended():
    """[adv-stream-membership-authenticated] ADV-6's concealment attack: a
    dishonest provider files exchanges it wants deniable under the shared
    `unknown` counterparty bucket while keeping a named pair's stream fully
    contiguous. `m4` here has a clean 3-record `m4::m3` stream AND 2 records
    filed under `m4::unknown` -- those 2 must show up as their own labeled
    total, not vanish into `gaps_detected`/`broken_pairs` (both of which
    stay green for a stream that, in isolation, IS unbroken)."""
    records = [
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=1, prev_seq=None),
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=2, prev_seq=1),
        _pair_capsule(self_id="m4", counterparty_id="m3", seq=3, prev_seq=2),
        _pair_capsule(self_id="m4", counterparty_id="unknown", seq=1, prev_seq=None),
        _pair_capsule(self_id="m4", counterparty_id="unknown", seq=2, prev_seq=1),
    ]
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[], ledger_records=records)
    pair_sequencing = summary["pair_sequencing"]
    assert pair_sequencing["gaps_detected"] == 0
    assert pair_sequencing["broken_pairs"] == []
    assert pair_sequencing["pairs_checked"] == 2
    assert pair_sequencing["unauthenticated_pairs"] == ["m4::unknown"]
    assert pair_sequencing["unauthenticated_records"] == 2


def test_pair_sequencing_never_holds_a_rating_field():
    records = [_pair_capsule(self_id="m4", counterparty_id="m3", seq=1, prev_seq=None)]
    summary = history_summary(node_id="node-a", log_id="log-a", checkpoint_lines=[], ledger_records=records)
    assert_no_rating_fields(summary)


# ── rung_summary -- weights_digest always honestly absent -----------------


def test_rung_summary_on_no_capsules_is_honestly_absent():
    rung = rung_summary(None)
    assert rung["weights_digest"]["state"] == "absent"
    assert rung["identity"]["owner_status"] == "absent"
    assert rung["identity"]["owner_id"] is None


def test_rung_summary_weights_digest_never_fabricated_even_with_a_real_record():
    record = {
        "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {"model": {"canonical_ref": "m"}}}}}
    }
    rung = rung_summary(record)
    assert rung["weights_digest"]["state"] == "absent"
    assert rung["weights_digest"]["reason"]


# ── shared_summary -- honestly absent, cites the E14 blocker --------------


def test_shared_summary_is_honestly_absent_not_a_fabricated_zero():
    shared = shared_summary()
    for field in ("cards_served", "bundles_served", "refusals_issued"):
        assert shared[field]["state"] == "absent"
        assert "mesh-e14-evidence-responder" in shared[field]["reason"]


# ── adjudications_summary -- involving-me filter ---------------------------


def _adjudication_capsule(*, verdict: str, half_a: str, half_b: str) -> dict:
    return {
        "capsule_id": "adj-" + verdict,
        "chain": {"relation": "adjudicates"},
        "model_attestation": {
            "compute_attestation": {
                "adjudication": {"verdict": verdict, "half_a_capsule_id": half_a, "half_b_capsule_id": half_b}
            }
        },
    }


def test_adjudications_summary_tallies_by_verdict():
    records = [
        _adjudication_capsule(verdict="corroborated", half_a="mine-1", half_b="theirs-1"),
        _adjudication_capsule(verdict="inconclusive", half_a="mine-2", half_b="theirs-2"),
        _adjudication_capsule(verdict="contradicted:owner-x", half_a="mine-3", half_b="theirs-3"),
    ]
    summary = adjudications_summary(records, own_capsule_ids={"mine-1", "mine-2", "mine-3"})
    assert summary["corroborated"] == 1
    assert summary["inconclusive"] == 1
    assert summary["contradicted"] == 1


def test_adjudications_not_involving_me_are_excluded():
    records = [_adjudication_capsule(verdict="corroborated", half_a="theirs-1", half_b="theirs-2")]
    summary = adjudications_summary(records, own_capsule_ids={"mine-1"})
    assert summary["corroborated"] == 0


# ── assert_no_rating_fields -- MUTANT: a rating field must be caught ------


def test_assert_no_rating_fields_passes_on_a_clean_card():
    assert_no_rating_fields({"sealing": {"coverage_summary": "coverage: fully sealed"}})


@pytest.mark.parametrize("key", ["score", "trust_score", "rating", "grade_percent", "trust_level"])
def test_mutant_rating_field_anywhere_in_the_tree_is_caught(key):
    with pytest.raises(RatingFieldError):
        assert_no_rating_fields({"sealing": {"history": {key: 0.9}}})


# ── build_self_accountability_card -- end to end ---------------------------


def test_end_to_end_card_carries_the_fixed_honesty_line_and_all_rows(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    native = [
        _native("r1", status="SUCCESS", request_digest="a" * 64, timestamp="2026-09-02T00:00:00Z"),
        _native("r2", status="SUCCESS", request_digest="b" * 64, timestamp="2026-09-02T00:05:00Z"),
    ]
    capsules = [
        _capsule(request_digest="a" * 64, verdict_class="executed", capsule_id="cap-1", timestamp="2026-09-02T00:00:01Z")
    ]
    card = build_self_accountability_card(
        node_id="node-a",
        log_id="log-a",
        ledger_records=capsules,
        native_entries=native,
        lifecycle_events=[],
        checkpoint_lines=lines,
    )
    assert card["honesty_line"] == HONESTY_LINE
    assert card["sealing"]["unsealed_count"] == 1
    assert card["history"]["checkpoint_count"] == 2
    assert card["shared"]["refusals_issued"]["state"] == "absent"
    assert set(card) == {"node_id", "sealing", "history", "rung", "shared", "adjudications", "honesty_line"}


def test_end_to_end_card_never_smuggles_a_rating_field(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 1)
    card = build_self_accountability_card(
        node_id="node-a", log_id="log-a", ledger_records=[], native_entries=[], checkpoint_lines=lines
    )
    assert_no_rating_fields(card)  # would raise if build_self_accountability_card had not already
