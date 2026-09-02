#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule_coordinator_verify.py -- the ask->verify CLI's honest per-stage grades.

PURPOSE
    Prove each of the four trust-ladder grades (cross_party_rung, runtime,
    log_integrity, freshness) reads exactly what it claims to read off a
    disclosed stage bundle -- including the DEGRADED unilateral_fallback case
    (no requester commitment, the honest floor) that must never be rounded
    up -- and that the CLI's headline/exit-code distinguishes "fully
    verified" from "gap, not proven" from "mismatch caught", never
    collapsing the three into one ambiguous "ok".
"""
from __future__ import annotations

import copy
import dataclasses
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capsule_emit.checkpoint import CheckpointConfig

import capsule_coordinator_verify as ccv
import capsule_disclosure_endpoint as cde
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from mesh_coordinator_bundle_flow import (
    StageBundle,
    compose_receipt_from_disclosures,
    stage_bundle_to_dict,
    verify_coordinator_receipt,
)
from mesh_coordinator_receipt_emitter import TopologyEntry, default_node_state as coord_state
from mesh_record_emitter import default_node_state, emit_lifecycle_record, make_transcript_summary
from mesh_record_verifier import FULL_BILATERAL, UNILATERAL_FALLBACK
from requester_commitment import RequesterKey, make_requester_commitment
from requester_identity_binding import RequesterIdentityKey, make_requester_identity_binding

RUN_ID = "run-cv-test-0001"
REQUEST_DIGEST = "a" * 64
FAR_FUTURE_MS = 32_503_680_000_000  # 3000-01-01T00:00:00Z -- outlives any real test run


def _seal(hop_id: str, *, requester_commitment=None, requester_identity_binding=None) -> dict:
    node = default_node_state(node_id=f"prov/{hop_id}")
    return emit_lifecycle_record(
        node,
        terminal_state="completed",
        exchange_id=RUN_ID,
        hop_id=hop_id,
        local_peer_id=f"host-{hop_id}",
        transcript=make_transcript_summary(2, 2),
        request_digest=REQUEST_DIGEST,
        requester_commitment=requester_commitment,
        requester_identity_binding=requester_identity_binding,
    )


def _bundle(hop_id: str, sealed: dict, inclusion_proof: dict | None = None) -> StageBundle:
    return StageBundle(hop_id=hop_id, stage_capsule=sealed, inclusion_proof=inclusion_proof)


def _topology(n: int) -> list[TopologyEntry]:
    return [TopologyEntry(seq=i, hop_id=f"stage-{i}", role="provider") for i in range(n)]


def _honest_receipt_and_bundles(n: int = 1):
    topo = _topology(n)
    bundles = {t.hop_id: _bundle(t.hop_id, _seal(t.hop_id)) for t in topo}
    receipt = compose_receipt_from_disclosures(
        coord_state(node_id="coord"), run_id=RUN_ID, topology=topo, disclosures=bundles
    )
    return receipt, bundles


# ---------------------------------------------------------------------------
# grade_cross_party_rung -- reused from mesh_record_verifier, never invented
# ---------------------------------------------------------------------------

class TestGradeCrossPartyRung:
    def test_degraded_unilateral_fallback_no_commitment(self):
        """The honest floor: no requester_commitment at all -- must read
        unilateral_fallback, never anything upgraded."""
        grade = ccv.grade_cross_party_rung(_bundle("stage-0", _seal("stage-0")))
        assert grade == UNILATERAL_FALLBACK

    def test_full_bilateral_with_valid_commitment_carries_caveat(self):
        """A valid requester_commitment alone only reaches acknowledged_receipt
        since #70 (requester_identity_binding closes the zero-effort self-mint
        gap) -- full_bilateral now also requires a verified identity binding
        citing that exact commitment key. Build both, the "registered
        identity" case, per tests/test_requester_commitment.py's
        _bound_commitment_and_binding() pattern."""
        key = RequesterKey.generate()
        commitment = make_requester_commitment(key, request_digest=REQUEST_DIGEST, exchange_id=RUN_ID)
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="requester-owner-1",
            commitment_public_key=commitment["public_key"],
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        sealed = _seal("stage-0", requester_commitment=commitment, requester_identity_binding=binding)
        grade = ccv.grade_cross_party_rung(_bundle("stage-0", sealed))
        assert grade.startswith(FULL_BILATERAL)
        assert "caveat:" in grade  # identity_limitation must ride along, never silently dropped

    def test_invalid_commitment_degrades_to_unilateral_fallback(self):
        """Present-but-invalid evidence is never worth partial credit."""
        key = RequesterKey.generate()
        commitment = make_requester_commitment(key, request_digest=REQUEST_DIGEST, exchange_id=RUN_ID)
        commitment["signature"] = "0" * len(commitment["signature"])
        sealed = _seal("stage-0", requester_commitment=commitment)
        grade = ccv.grade_cross_party_rung(_bundle("stage-0", sealed))
        assert grade == UNILATERAL_FALLBACK

    def test_no_lifecycle_block_is_na(self):
        bundle = _bundle("stage-0", {"capsule_id": "0" * 64, "action_id": "x"})
        assert ccv.grade_cross_party_rung(bundle).startswith("n/a")


# ---------------------------------------------------------------------------
# grade_runtime -- read verbatim, always labeled self-attested/unverified
# ---------------------------------------------------------------------------

class TestGradeRuntime:
    def test_present_is_labeled_self_attested(self):
        grade = ccv.grade_runtime(_bundle("stage-0", _seal("stage-0")))
        assert grade.startswith("self-attested (unverified):")

    def test_absent_when_no_compute_attestation(self):
        bundle = _bundle("stage-0", {"model_attestation": {}})
        assert ccv.grade_runtime(bundle).startswith("absent")

    def test_absent_when_no_model_attestation_at_all(self):
        assert ccv.grade_runtime(_bundle("stage-0", {})).startswith("absent")


# ---------------------------------------------------------------------------
# grade_log_integrity -- reuses checkpointing.describe_witness_state verbatim
# ---------------------------------------------------------------------------

class TestGradeLogIntegrity:
    def test_no_inclusion_proof_is_unwitnessed(self):
        grade = ccv.grade_log_integrity(_bundle("stage-0", _seal("stage-0")))
        assert grade.startswith("unwitnessed")

    def test_self_checkpointed_matches_checkpointing_module_exactly(self, tmp_path):
        sealed = _seal("stage-0")
        log_path = tmp_path / "capsules.jsonl"
        log_path.write_text(json.dumps(sealed) + "\n")
        signer = Ed25519Signer(tmp_path / "key.pem")
        cfg = CheckpointConfig(cadence_entries=1, ts_urls=[])
        state = CheckpointState.load(
            ledger_dir=tmp_path, log_source=JsonlLogSource(log_path), cfg=cfg, signer=signer, log_id="log-a"
        )
        cp = state.reconnect()
        proof = {"checkpoint": dataclasses.asdict(cp)}
        grade = ccv.grade_log_integrity(_bundle("stage-0", sealed, inclusion_proof=proof))
        # Reused, not re-derived: the CLI's grade must equal the same module's own sentence.
        assert grade == state.witness_status()
        assert "NOT independently witnessed" in grade

    def test_malformed_checkpoint_is_na_not_a_crash(self):
        proof = {"checkpoint": {"not": "a real checkpoint record"}}
        grade = ccv.grade_log_integrity(_bundle("stage-0", _seal("stage-0"), inclusion_proof=proof))
        assert grade.startswith("n/a")

    def test_toy_shape_without_checkpoint_key_is_unwitnessed(self):
        # e.g. examples/coordinator_3way_demo.py's toy {"witness": "toy-checkpoint", ...}
        proof = {"witness": "toy-checkpoint", "capsule_id": "x"}
        grade = ccv.grade_log_integrity(_bundle("stage-0", _seal("stage-0"), inclusion_proof=proof))
        assert grade.startswith("unwitnessed")


# ---------------------------------------------------------------------------
# grade_freshness -- the record's own committed timestamp, bucketed
# ---------------------------------------------------------------------------

class TestGradeFreshness:
    def test_fresh_bucket(self):
        sealed = _seal("stage-0")
        grade = ccv.grade_freshness(_bundle("stage-0", sealed), now=datetime.now(timezone.utc))
        assert grade.startswith("fresh (<5m)")

    def test_stale_bucket_over_a_day(self):
        sealed = _seal("stage-0")
        now = datetime.now(timezone.utc) + timedelta(days=2)
        grade = ccv.grade_freshness(_bundle("stage-0", sealed), now=now)
        assert grade.startswith("stale (>=1d)")

    def test_aging_bucket_under_an_hour(self):
        sealed = _seal("stage-0")
        now = datetime.now(timezone.utc) + timedelta(minutes=10)
        grade = ccv.grade_freshness(_bundle("stage-0", sealed), now=now)
        assert grade.startswith("aging (<1h)")

    def test_no_timestamp_is_na(self):
        assert ccv.grade_freshness(_bundle("stage-0", {}), now=datetime.now(timezone.utc)).startswith("n/a")

    def test_unparseable_timestamp_is_na_not_a_crash(self):
        bundle = _bundle("stage-0", {"timestamp": "not-a-timestamp"})
        assert ccv.grade_freshness(bundle, now=datetime.now(timezone.utc)).startswith("n/a")


# ---------------------------------------------------------------------------
# summarize() -- the honest headline, distinct from ReceiptVerdict.ok
# ---------------------------------------------------------------------------

class TestSummarize:
    def test_all_green(self):
        receipt, bundles = _honest_receipt_and_bundles(2)
        verdict = verify_coordinator_receipt(receipt, bundles)
        headline, code = ccv.summarize(verdict)
        assert headline.startswith("ALL GREEN")
        assert code == 0

    def test_gap_is_incomplete_never_reported_as_green(self):
        receipt, bundles = _honest_receipt_and_bundles(2)
        withheld = {h: b for h, b in bundles.items() if h != "stage-1"}
        verdict = verify_coordinator_receipt(receipt, withheld)
        assert verdict.ok  # the library's own `ok` stays True for an honest gap --
        headline, code = ccv.summarize(verdict)  # exactly why summarize() must not just echo it.
        assert headline.startswith("INCOMPLETE")
        assert code == 2

    def test_mismatch_detected(self):
        receipt, bundles = _honest_receipt_and_bundles(1)
        tampered = copy.deepcopy(bundles["stage-0"].stage_capsule)
        tampered["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]["local_peer_id"] = "IMPOSTER"
        verdict = verify_coordinator_receipt(receipt, {"stage-0": StageBundle(hop_id="stage-0", stage_capsule=tampered)})
        headline, code = ccv.summarize(verdict)
        assert headline.startswith("MISMATCH DETECTED")
        assert code == 1


# ---------------------------------------------------------------------------
# print_report() -- never grades a non-green stage
# ---------------------------------------------------------------------------

class TestPrintReport:
    def test_gap_stage_is_not_graded(self, capsys):
        receipt, _bundles = _honest_receipt_and_bundles(1)
        verdict = verify_coordinator_receipt(receipt, {})
        ccv.print_report(verdict, {}, now=datetime.now(timezone.utc))
        out = capsys.readouterr().out
        assert "grades: n/a" in out
        assert "cross_party_rung" not in out

    def test_green_stage_prints_all_four_grades(self, capsys):
        receipt, bundles = _honest_receipt_and_bundles(1)
        verdict = verify_coordinator_receipt(receipt, bundles)
        ccv.print_report(verdict, bundles, now=datetime.now(timezone.utc))
        out = capsys.readouterr().out
        for label in ("cross_party_rung", "runtime", "log_integrity", "freshness"):
            assert label in out


# ---------------------------------------------------------------------------
# main() end-to-end -- local --bundle files and a live --bundle-url fetch
# ---------------------------------------------------------------------------

class TestMainCLI:
    def test_main_green_via_local_bundle_file(self, tmp_path, capsys):
        receipt, bundles = _honest_receipt_and_bundles(1)
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(json.dumps(stage_bundle_to_dict(bundles["stage-0"])))

        code = ccv.main([str(receipt_path), f"--bundle=stage-0={bundle_path}"])

        assert code == 0
        assert "ALL GREEN" in capsys.readouterr().out

    def test_main_no_bundles_is_incomplete_not_a_crash(self, tmp_path, capsys):
        receipt, _ = _honest_receipt_and_bundles(1)
        receipt_path = tmp_path / "receipt.json"
        receipt_path.write_text(json.dumps(receipt))

        code = ccv.main([str(receipt_path)])

        assert code == 2
        assert "INCOMPLETE" in capsys.readouterr().out

    def test_main_fetches_bundle_over_http_from_disclosure_endpoint(self, tmp_path, capsys):
        receipt, bundles = _honest_receipt_and_bundles(1)
        bundles_dir = tmp_path / "bundles"
        bundles_dir.mkdir()
        (bundles_dir / "stage-0.json").write_text(json.dumps(stage_bundle_to_dict(bundles["stage-0"])))
        node = cde.directory_stage_node(bundles_dir, run_id=RUN_ID)
        server = cde.run_disclosure_endpoint(host="127.0.0.1", port=0, node=node, run_id=RUN_ID, hop_ids=["stage-0"])
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            receipt_path = tmp_path / "receipt.json"
            receipt_path.write_text(json.dumps(receipt))
            code = ccv.main([str(receipt_path), f"--bundle-url=stage-0=http://127.0.0.1:{port}"])
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert code == 0
        assert "ALL GREEN" in capsys.readouterr().out

    def test_main_declined_hop_over_http_is_incomplete_not_a_false_green(self, tmp_path, capsys):
        receipt, _ = _honest_receipt_and_bundles(1)
        bundles_dir = tmp_path / "bundles"  # empty: the node has no stage-0.json to disclose
        bundles_dir.mkdir()
        node = cde.directory_stage_node(bundles_dir, run_id=RUN_ID)
        server = cde.run_disclosure_endpoint(host="127.0.0.1", port=0, node=node, run_id=RUN_ID, hop_ids=[])
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            receipt_path = tmp_path / "receipt.json"
            receipt_path.write_text(json.dumps(receipt))
            code = ccv.main([str(receipt_path), f"--bundle-url=stage-0=http://127.0.0.1:{port}"])
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert code == 2
        out = capsys.readouterr().out
        assert "declined/absent" in out
        assert "INCOMPLETE" in out
