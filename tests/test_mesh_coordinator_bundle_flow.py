#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disclosure-on-request bundle flow + offline verifier tests.

PURPOSE
    Prove mesh_coordinator_bundle_flow.py's two halves — the coordinator
    asking each stage-node for its bundle (disclosure-on-request, NOT
    live-log access) and the independent offline verifier — behave to the
    honest contract AND, load-bearingly, cannot be fooled into a false green:
      * a tampered disclosed bundle (digest != committed)   -> mismatch
      * a present stage whose bundle is withheld            -> gap, not green
      * a stage that declines to disclose                   -> absent (gap)
      * a stage never asked                                 -> not_requested
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mesh_record_emitter import (  # noqa: E402
    default_node_state,
    emit_lifecycle_record,
    make_transcript_summary,
)
from mesh_coordinator_receipt_emitter import (  # noqa: E402
    TopologyEntry,
    default_node_state as coord_state,
)
from mesh_coordinator_bundle_flow import (  # noqa: E402
    StageBundle,
    ask_stage_for_bundle,
    bundle_digest,
    collect_disclosed_bundles,
    compose_receipt_from_disclosures,
    verify_coordinator_receipt,
)

RUN = "run-test-0001"


def _topology(n=3):
    return [
        TopologyEntry(seq=i, hop_id=f"stage-{i}", role="provider")
        for i in range(n)
    ]


def _seal(hop_id: str):
    st = default_node_state(node_id=f"prov/{hop_id}")
    return emit_lifecycle_record(
        st,
        terminal_state="completed",
        exchange_id=RUN,
        hop_id=hop_id,
        local_peer_id=f"host-{hop_id}",
        transcript=make_transcript_summary(2, 2),
    )


def _node_for(hop_id: str, sealed, *, run=RUN):
    def disclose(run_id, asked_hop):
        if run_id != run or asked_hop != hop_id:
            return None
        return StageBundle(hop_id=hop_id, stage_capsule=sealed)
    return disclose


def _honest_run(n=3):
    topo = _topology(n)
    sealed = {t.hop_id: _seal(t.hop_id) for t in topo}
    nodes = {t.hop_id: _node_for(t.hop_id, sealed[t.hop_id]) for t in topo}
    disclosures = collect_disclosed_bundles(nodes, run_id=RUN, topology=topo)
    receipt = compose_receipt_from_disclosures(
        coord_state(node_id="coord"), run_id=RUN, topology=topo, disclosures=disclosures
    )
    bundles = {h: b for h, b in disclosures.items() if b is not None}
    return topo, sealed, receipt, bundles


# ---------------------------------------------------------------------------
# Honest path
# ---------------------------------------------------------------------------

class TestHonestPath:
    def test_three_way_all_green(self):
        _, _, receipt, bundles = _honest_run(3)
        v = verify_coordinator_receipt(receipt, bundles)
        assert v.ok
        assert v.ordered_hops == ["stage-0", "stage-1", "stage-2"]
        assert v.present_count == 3
        assert v.green_count == 3
        assert v.mismatch_count == 0
        assert all(s.status == "green" for s in v.stages)

    def test_reconstructed_order_follows_seq(self):
        # Build topology deliberately out of listing order; verifier must sort by seq.
        topo = [
            TopologyEntry(seq=2, hop_id="c", role="provider"),
            TopologyEntry(seq=0, hop_id="a", role="provider"),
            TopologyEntry(seq=1, hop_id="b", role="provider"),
        ]
        topo_sorted = sorted(topo, key=lambda t: t.seq)
        sealed = {t.hop_id: _seal(t.hop_id) for t in topo}
        nodes = {t.hop_id: _node_for(t.hop_id, sealed[t.hop_id]) for t in topo}
        disc = collect_disclosed_bundles(nodes, run_id=RUN, topology=topo_sorted)
        receipt = compose_receipt_from_disclosures(
            coord_state(node_id="coord"), run_id=RUN, topology=topo_sorted, disclosures=disc
        )
        v = verify_coordinator_receipt(receipt, {h: b for h, b in disc.items() if b})
        assert v.ordered_hops == ["a", "b", "c"]
        assert v.ok


# ---------------------------------------------------------------------------
# Disclosure-on-request semantics
# ---------------------------------------------------------------------------

class TestDisclosureOnRequest:
    def test_declining_node_yields_absent_gap_not_false_green(self):
        topo = _topology(3)
        sealed = {t.hop_id: _seal(t.hop_id) for t in topo}
        nodes = {t.hop_id: _node_for(t.hop_id, sealed[t.hop_id]) for t in topo}
        # stage-1 declines everything.
        nodes["stage-1"] = lambda run_id, hop: None
        disc = collect_disclosed_bundles(nodes, run_id=RUN, topology=topo)
        receipt = compose_receipt_from_disclosures(
            coord_state(node_id="coord"), run_id=RUN, topology=topo, disclosures=disc
        )
        block = receipt["model_attestation"]["compute_attestation"]["x-mesh-coordinator-receipt-v1"]
        stage1 = next(s for s in block["stages"] if s["hop_id"] == "stage-1")
        assert stage1["bundle"] == "absent"
        assert "bundle_ref" not in stage1
        v = verify_coordinator_receipt(receipt, {h: b for h, b in disc.items() if b})
        s1 = next(s for s in v.stages if s.hop_id == "stage-1")
        assert s1.status == "gap"
        # honest holes do not fail the receipt.
        assert v.ok

    def test_not_requested_stage_maps_correctly(self):
        topo = _topology(3)
        sealed = {t.hop_id: _seal(t.hop_id) for t in topo}
        nodes = {t.hop_id: _node_for(t.hop_id, sealed[t.hop_id]) for t in topo}
        disc = collect_disclosed_bundles(nodes, run_id=RUN, topology=topo)
        # Coordinator only asked stage-0 and stage-2; stage-1 was never asked.
        receipt = compose_receipt_from_disclosures(
            coord_state(node_id="coord"),
            run_id=RUN,
            topology=topo,
            disclosures={"stage-0": disc["stage-0"], "stage-2": disc["stage-2"]},
            requested={"stage-0", "stage-2"},
        )
        block = receipt["model_attestation"]["compute_attestation"]["x-mesh-coordinator-receipt-v1"]
        stage1 = next(s for s in block["stages"] if s["hop_id"] == "stage-1")
        assert stage1["bundle"] == "not_requested"

    def test_node_answering_wrong_hop_is_rejected(self):
        sealed = _seal("stage-0")
        # A node that always answers for stage-9 regardless of the ask.
        wrong = lambda run_id, hop: StageBundle(hop_id="stage-9", stage_capsule=sealed)
        with pytest.raises(ValueError, match="answer the question it was asked"):
            ask_stage_for_bundle(wrong, run_id=RUN, hop_id="stage-0")


# ---------------------------------------------------------------------------
# Adversarial — the load-bearing failures
# ---------------------------------------------------------------------------

class TestAdversarial:
    def test_tampered_disclosure_digest_mismatch_caught(self):
        _, sealed, receipt, bundles = _honest_run(3)
        tampered = copy.deepcopy(sealed["stage-1"])
        tampered["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"][
            "local_peer_id"
        ] = "IMPOSTER"
        bundles = dict(bundles)
        bundles["stage-1"] = StageBundle(hop_id="stage-1", stage_capsule=tampered)
        v = verify_coordinator_receipt(receipt, bundles)
        assert not v.ok
        s1 = next(s for s in v.stages if s.hop_id == "stage-1")
        assert s1.status == "mismatch"
        # the other two remain green — the failure is localized, not smeared.
        assert {s.status for s in v.stages if s.hop_id != "stage-1"} == {"green"}

    def test_withheld_present_bundle_is_visible_gap_not_green(self):
        _, _, receipt, bundles = _honest_run(3)
        withheld = {h: b for h, b in bundles.items() if h != "stage-2"}
        v = verify_coordinator_receipt(receipt, withheld)
        s2 = next(s for s in v.stages if s.hop_id == "stage-2")
        assert s2.status == "gap"
        # a withheld present bundle must NOT be silently green, but it is an
        # honest hole (the verifier lacks bytes), not a mismatch — three-state.
        assert s2.status != "green"

    def test_tampered_bundle_that_still_hashes_but_fails_capsule_verify(self):
        # Construct a bundle whose committed digest we forge to match tampered
        # bytes, but whose capsule is internally broken -> AAC verify() fails.
        _, sealed, _, _ = _honest_run(1)
        broken = copy.deepcopy(sealed["stage-0"])
        # Corrupt the capsule_id so content-address no longer matches contents.
        broken["capsule_id"] = "0" * len(broken["capsule_id"])
        b = StageBundle(hop_id="stage-0", stage_capsule=broken)
        # Emit a receipt that commits to THIS broken bundle's digest.
        receipt = compose_receipt_from_disclosures(
            coord_state(node_id="coord"),
            run_id=RUN,
            topology=_topology(1),
            disclosures={"stage-0": b},
        )
        v = verify_coordinator_receipt(receipt, {"stage-0": b})
        s0 = v.stages[0]
        # digest matches (we committed to the broken bytes) but the capsule
        # itself fails AAC verification -> still a mismatch, not green.
        assert s0.status == "mismatch"
        assert not v.ok


def test_bundle_digest_is_stable_64_hex():
    d = bundle_digest(StageBundle(hop_id="x", stage_capsule=_seal("x")))
    assert len(d) == 64
    assert all(c in "0123456789abcdef" for c in d)
