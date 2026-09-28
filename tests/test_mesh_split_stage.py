#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Split-stage reference tests, over the fixtures the Rust producer also runs.

Every expected verdict in `tests/fixtures/split-stage/*.json` is written by
hand in `generate.py` from docs/DESIGN-split-stage-records.md; this file
checks the Python reference against them, and checks that the fixtures on
disk are exactly what the generator writes (so nobody edits one by hand).
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

from mesh_coordinator_receipt_emitter import (
    StageEntry,
    TopologyEntry,
    default_node_state,
    emit_coordinator_receipt,
)
from mesh_split_stage import (
    CarriedStageRecord,
    ReceiptError,
    StageBlockError,
    fold_frames,
    validate_block,
    validate_receipt,
    verify_split,
)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "split-stage"


def _cases(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def _ids(cases: list[dict]) -> list[str]:
    return [c["name"] for c in cases]


FOLDS = _cases("fold-vectors.json")
BLOCKS = _cases("block-cases.json")
RECEIPTS = _cases("receipt-cases.json")
HOPS = _cases("hop-cases.json")


def test_fixtures_on_disk_are_what_the_generator_writes(tmp_path):
    before = {p.name: p.read_text() for p in FIXTURES.glob("*.json")}
    subprocess.run([sys.executable, str(FIXTURES / "generate.py")], check=True, capture_output=True)
    after = {p.name: p.read_text() for p in FIXTURES.glob("*.json")}
    assert before == after


@pytest.mark.parametrize("case", FOLDS, ids=_ids(FOLDS))
def test_fold_vectors(case):
    got = fold_frames(
        [bytes.fromhex(f) for f in case["frames_hex"]],
        coordinator_node_id=case["coordinator_node_id"],
        run_id=case["run_id"],
        request_id=int(case["request_id"]),
        hop_index=case["hop_index"],
        lane=case["lane"],
    )
    assert got == case["expect"]


def test_fold_binds_hop_lane_and_order():
    frames = [b"a", b"b"]
    base = dict(coordinator_node_id="c", run_id="r", request_id=1)
    reference = fold_frames(frames, hop_index=0, lane="forward", **base)
    assert fold_frames(frames, hop_index=1, lane="forward", **base) != reference
    assert fold_frames(frames, hop_index=0, lane="reply", **base) != reference
    assert fold_frames(frames[::-1], hop_index=0, lane="forward", **base) != reference
    assert fold_frames(frames, hop_index=0, lane="forward", salt=b"s", **base) != reference


@pytest.mark.parametrize("case", BLOCKS, ids=_ids(BLOCKS))
def test_block_rules(case):
    if case["valid"]:
        validate_block(case["block"])
    else:
        with pytest.raises(StageBlockError):
            validate_block(case["block"])


@pytest.mark.parametrize("case", RECEIPTS, ids=_ids(RECEIPTS))
def test_receipt_rules(case):
    if case["valid"]:
        validate_receipt(case["receipt"])
    else:
        with pytest.raises(ReceiptError):
            validate_receipt(case["receipt"])


@pytest.mark.parametrize("case", HOPS, ids=_ids(HOPS))
def test_hop_check(case):
    carried = [CarriedStageRecord(**c) for c in case["carried"]]
    assert verify_split(case["own"], case["receipt"], carried) == case["expect"]


def test_reference_emitter_carries_assignment_and_conflict():
    """The receipt the Rust producer seals is one the reference emitter builds."""
    receipt = next(c for c in RECEIPTS if c["name"] == "conflict_two_refs")["receipt"]
    capsule = emit_coordinator_receipt(
        default_node_state(),
        run_id=receipt["run_id"],
        topology=[TopologyEntry(**t) for t in receipt["topology"]],
        stages=[
            StageEntry(
                hop_id=s["hop_id"],
                bundle=s["bundle"],
                bundle_ref=s.get("bundle_ref"),
                bundle_refs=tuple(s["bundle_refs"]) if "bundle_refs" in s else None,
            )
            for s in receipt["stages"]
        ],
        extra={k: receipt[k] for k in ("coordinator_node_id", "request_id", "stage_seal_deadline_ms")},
    )
    block = capsule["model_attestation"]["compute_attestation"]["x-mesh-coordinator-receipt-v1"]
    assert block == receipt


def test_reference_emitter_conflict_needs_two_distinct_refs():
    ref = {"type": "capsule", "digest_alg": "SHA-256", "digest": "ab" * 32}
    with pytest.raises(ValueError):
        StageEntry(hop_id="h", bundle="conflict", bundle_refs=(ref,))
    with pytest.raises(ValueError):
        StageEntry(hop_id="h", bundle="conflict", bundle_refs=(ref, dict(ref)))
    with pytest.raises(ValueError):
        StageEntry(hop_id="h", bundle="absent", bundle_refs=(ref, ref))
