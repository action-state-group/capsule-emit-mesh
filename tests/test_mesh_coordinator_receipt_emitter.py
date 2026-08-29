#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Coordinator-receipt artifact-type producer tests.

PURPOSE
    [mesh-b3-coordinator-receipt-producer] (Phase B6-code). Prove
    mesh_coordinator_receipt_emitter.py builds the record shape defined in
    `_work/mesh-coordinator-receipt-artifact-type-2026-08-28.md` §3.1/§3.2/§6
    and — the load-bearing part — that the two producer invariants from §6
    cannot be silently violated: a `present` stage without a `bundle_ref`,
    and an `absent`/`not_requested` stage carrying one, both raise instead
    of emitting a record a naive verifier would wrongly accept.

WHAT IS TESTED
    1. HAPPY PATH — topology + stages round-trips through
       capsule_to_bytes()/json.loads() with the exact shape §3.1 defines:
       two separate arrays, ordered topology, one stages[] entry per hop.
    2. THREE-STATE FIELD — present/absent/not_requested each build; absent
       and not_requested carry NO bundle_ref key at all (§3.2: "there is
       nothing carried and nothing to cite"), not a null placeholder.
    3. MUTANT: present without bundle_ref — StageEntry construction raises.
    4. MUTANT: absent/not_requested WITH a bundle_ref attached — StageEntry
       construction raises for both non-present states.
    5. MUTANT: malformed bundle_ref (missing key, wrong digest_alg, non-hex
       or wrong-length digest) — each individually raises.
    6. MUTANT: stages[] not matching topology[] one-for-one (missing hop,
       extra hop, duplicate hop_id) — emit_coordinator_receipt() raises.
    7. MUTANT: topology[] out of seq order — emit_coordinator_receipt()
       raises.
    8. observation_point validated against the existing four-value closed
       set; an unknown value raises at TopologyEntry construction.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mesh_coordinator_receipt_emitter import (  # noqa: E402
    StageEntry,
    TopologyEntry,
    capsule_to_bytes,
    default_node_state,
    emit_coordinator_receipt,
)


def _digest(byte: str = "a") -> str:
    return byte * 64


def _bundle_ref(digest: str | None = None) -> dict:
    return {"type": "capsule", "digest_alg": "SHA-256", "digest": digest or _digest()}


def _two_hop_topology() -> list[TopologyEntry]:
    return [
        TopologyEntry(seq=0, hop_id="hop-0", role="requester", observation_point="gateway_ingress"),
        TopologyEntry(seq=1, hop_id="hop-1", role="responder", observation_point="serving_host_ingress"),
    ]


# ===========================================================================
# 1-2. Happy path + three-state shape
# ===========================================================================

class TestHappyPath:
    def test_present_absent_not_requested_round_trip(self):
        node = default_node_state()
        topology = _two_hop_topology()
        stages = [
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref=_bundle_ref(_digest("a"))),
            StageEntry(hop_id="hop-1", bundle="absent"),
        ]
        capsule = emit_coordinator_receipt(node, run_id="run-0001", topology=topology, stages=stages)

        raw = capsule_to_bytes(capsule)
        import json

        reloaded = json.loads(raw)
        block = reloaded["model_attestation"]["compute_attestation"]["x-mesh-coordinator-receipt-v1"]

        assert block["v"] == 1
        assert block["kind"] == "mesh-coordinator-receipt"
        assert block["run_id"] == "run-0001"
        assert [t["hop_id"] for t in block["topology"]] == ["hop-0", "hop-1"]
        assert {s["hop_id"]: s for s in block["stages"]}.keys() == {"hop-0", "hop-1"}

        present_entry = next(s for s in block["stages"] if s["hop_id"] == "hop-0")
        absent_entry = next(s for s in block["stages"] if s["hop_id"] == "hop-1")
        assert present_entry["bundle"] == "present"
        assert present_entry["bundle_ref"] == _bundle_ref(_digest("a"))
        assert absent_entry["bundle"] == "absent"
        # §3.2: "absent/not_requested carry no bundle_ref at all" — key
        # absent entirely, not present-with-null.
        assert "bundle_ref" not in absent_entry

    def test_not_requested_carries_no_bundle_ref_key(self):
        stage = StageEntry(hop_id="hop-2", bundle="not_requested")
        assert stage.bundle_ref is None

    def test_chains_across_calls_like_the_lifecycle_emitter(self):
        node = default_node_state()
        topology = [TopologyEntry(seq=0, hop_id="hop-0", role="requester")]
        stages = [StageEntry(hop_id="hop-0", bundle="not_requested")]

        first = emit_coordinator_receipt(node, run_id="run-a", topology=topology, stages=stages)
        second = emit_coordinator_receipt(node, run_id="run-b", topology=topology, stages=stages)

        assert second["chain"]["parent_capsule_id"] == first["capsule_id"]
        assert second["chain"]["relation"] == "confirms"


# ===========================================================================
# 3-4. MUTANT: the §6 producer invariant on bundle_ref presence
# ===========================================================================

class TestBundleRefPresenceInvariant:
    def test_present_without_bundle_ref_raises(self):
        with pytest.raises(ValueError, match="requires bundle_ref"):
            StageEntry(hop_id="hop-0", bundle="present")

    @pytest.mark.parametrize("bundle", ["absent", "not_requested"])
    def test_non_present_with_bundle_ref_raises(self, bundle):
        with pytest.raises(ValueError, match="MUST NOT carry bundle_ref"):
            StageEntry(hop_id="hop-0", bundle=bundle, bundle_ref=_bundle_ref())

    def test_unknown_bundle_value_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            StageEntry(hop_id="hop-0", bundle="forgotten")


# ===========================================================================
# 5. MUTANT: malformed bundle_ref shape
# ===========================================================================

class TestBundleRefShape:
    def test_missing_key_raises(self):
        with pytest.raises(ValueError, match="missing required key"):
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref={"type": "capsule", "digest_alg": "SHA-256"})

    def test_wrong_digest_alg_raises(self):
        ref = _bundle_ref()
        ref["digest_alg"] = "SHA-1"
        with pytest.raises(ValueError, match="digest_alg must be"):
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref=ref)

    def test_short_digest_raises(self):
        ref = _bundle_ref(digest="ab")
        with pytest.raises(ValueError, match="64-char lowercase hex"):
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref=ref)

    def test_non_hex_digest_raises(self):
        ref = _bundle_ref(digest="g" * 64)
        with pytest.raises(ValueError, match="64-char lowercase hex"):
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref=ref)

    def test_empty_type_raises(self):
        ref = _bundle_ref()
        ref["type"] = ""
        with pytest.raises(ValueError, match="type must be a non-empty string"):
            StageEntry(hop_id="hop-0", bundle="present", bundle_ref=ref)


# ===========================================================================
# 6-7. MUTANT: topology[] <-> stages[] correspondence and ordering
# ===========================================================================

class TestTopologyStagesCorrespondence:
    def test_missing_stage_entry_raises(self):
        node = default_node_state()
        topology = _two_hop_topology()
        stages = [StageEntry(hop_id="hop-0", bundle="not_requested")]
        with pytest.raises(ValueError, match="missing="):
            emit_coordinator_receipt(node, run_id="run-x", topology=topology, stages=stages)

    def test_extra_stage_entry_raises(self):
        node = default_node_state()
        topology = [TopologyEntry(seq=0, hop_id="hop-0", role="requester")]
        stages = [
            StageEntry(hop_id="hop-0", bundle="not_requested"),
            StageEntry(hop_id="hop-1", bundle="not_requested"),
        ]
        with pytest.raises(ValueError, match="unexpected="):
            emit_coordinator_receipt(node, run_id="run-x", topology=topology, stages=stages)

    def test_duplicate_stage_hop_id_raises(self):
        node = default_node_state()
        topology = [TopologyEntry(seq=0, hop_id="hop-0", role="requester")]
        stages = [
            StageEntry(hop_id="hop-0", bundle="not_requested"),
            StageEntry(hop_id="hop-0", bundle="not_requested"),
        ]
        with pytest.raises(ValueError, match="must be unique"):
            emit_coordinator_receipt(node, run_id="run-x", topology=topology, stages=stages)

    def test_duplicate_topology_hop_id_raises(self):
        node = default_node_state()
        topology = [
            TopologyEntry(seq=0, hop_id="hop-0", role="requester"),
            TopologyEntry(seq=1, hop_id="hop-0", role="responder"),
        ]
        stages = [StageEntry(hop_id="hop-0", bundle="not_requested")]
        with pytest.raises(ValueError, match="must be unique"):
            emit_coordinator_receipt(node, run_id="run-x", topology=topology, stages=stages)

    def test_out_of_order_seq_raises(self):
        node = default_node_state()
        topology = [
            TopologyEntry(seq=1, hop_id="hop-0", role="requester"),
            TopologyEntry(seq=0, hop_id="hop-1", role="responder"),
        ]
        stages = [
            StageEntry(hop_id="hop-0", bundle="not_requested"),
            StageEntry(hop_id="hop-1", bundle="not_requested"),
        ]
        with pytest.raises(ValueError, match="ordered by seq"):
            emit_coordinator_receipt(node, run_id="run-x", topology=topology, stages=stages)

    def test_empty_topology_raises(self):
        node = default_node_state()
        with pytest.raises(ValueError, match="at least one entry"):
            emit_coordinator_receipt(node, run_id="run-x", topology=[], stages=[])

    def test_empty_run_id_raises(self):
        node = default_node_state()
        topology = [TopologyEntry(seq=0, hop_id="hop-0", role="requester")]
        stages = [StageEntry(hop_id="hop-0", bundle="not_requested")]
        with pytest.raises(ValueError, match="run_id"):
            emit_coordinator_receipt(node, run_id="", topology=topology, stages=stages)


# ===========================================================================
# 8. observation_point closed-set validation
# ===========================================================================

class TestObservationPointValidation:
    def test_unknown_observation_point_raises(self):
        with pytest.raises(ValueError, match="not in the known four-value set"):
            TopologyEntry(seq=0, hop_id="hop-0", role="requester", observation_point="made_up_point")

    def test_null_observation_point_is_allowed(self):
        entry = TopologyEntry(seq=0, hop_id="hop-0", role="requester", observation_point=None)
        assert entry.observation_point is None

    @pytest.mark.parametrize(
        "point",
        ["gateway_ingress", "serving_host_ingress", "backend_dispatch", "client_egress"],
    )
    def test_each_known_observation_point_is_allowed(self, point):
        entry = TopologyEntry(seq=0, hop_id="hop-0", role="requester", observation_point=point)
        assert entry.observation_point == point
