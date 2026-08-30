#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""3-way split-inference demo: coordinator asks each node for its bundle.

The disclosure-on-request flow, end to end, entirely local and offline-
verifiable — no live-log access, no real cross-host networking, no payload
ever leaving a node.

STORY (TRUST-MODEL §2.4 "what the coordinator fears", §4.3 split inference,
R10 "split across strangers, and I cannot see who held what"):

  A coordinator (skippy) plans a 3-stage split run over the correlation spine
  (run_id + per-hop hop_id / stage order). It routes stages to three provider
  nodes. Each node runs its OWN slice and SEALS its own stage record
  (serving_provenance for its slice) — the node's private business, no payload
  shared.

  Then the coordinator ASKS each node for its bundle (disclosure-on-request).
  Each node CHOOSES to disclose a bounded, self-contained StageBundle: its
  sealed stage-record bytes (+ optional inclusion proof). The coordinator
  composes a signed COORDINATOR RECEIPT binding stage ORDER to each present
  stage's committed digest — closing C2/C3's "correlation exists but nothing
  signs it". No payload; the relay never sees a token.

  Finally an INDEPENDENT OFFLINE VERIFIER — holding only the receipt + the
  disclosed bundles — reconstructs stage order and checks each stage's
  inclusion (recompute digest == committed digest, and the disclosed capsule
  verifies). Green summary printed.

Then two ADVERSARIAL checks prove the binding is load-bearing, never a false
green:
  A. a node discloses a TAMPERED record whose digest no longer matches the
     receipt's committed digest  -> caught as MISMATCH.
  B. a stage the receipt marks PRESENT is simply not disclosed to the verifier
     -> visible GAP, not a pass.

Run:  python3 examples/coordinator_3way_demo.py
Exit code 0 iff the honest run verifies green AND both adversarial cases are
caught.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mesh_record_emitter import (  # noqa: E402
    default_node_state,
    emit_lifecycle_record,
    make_transcript_summary,
)
from mesh_coordinator_receipt_emitter import TopologyEntry, default_node_state as coord_state  # noqa: E402
from mesh_coordinator_bundle_flow import (  # noqa: E402
    StageBundle,
    collect_disclosed_bundles,
    compose_receipt_from_disclosures,
    verify_coordinator_receipt,
)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

RUN_ID = "run-3way-demo-0001"

# The coordinator's plan: a 3-stage split over three provider nodes, in order.
TOPOLOGY = [
    TopologyEntry(seq=0, hop_id="stage-0", role="provider", observation_point="serving_host_ingress"),
    TopologyEntry(seq=1, hop_id="stage-1", role="provider", observation_point="backend_dispatch"),
    TopologyEntry(seq=2, hop_id="stage-2", role="provider", observation_point="client_egress"),
]


# ---------------------------------------------------------------------------
# Provider nodes: each seals its OWN stage record, then discloses on request.
# ---------------------------------------------------------------------------

def make_provider(hop_id: str, obs_point: str):
    """Build one provider node that has sealed its own stage record.

    The node holds its sealed record privately. When the coordinator asks
    (disclosure-on-request), it hands back a bounded StageBundle — its own
    record bytes + a toy inclusion proof — and nothing more. No live-log
    access; the node returns an object.
    """
    state = default_node_state(node_id=f"mesh-provider/{hop_id}")
    sealed = emit_lifecycle_record(
        state,
        terminal_state="completed",
        observation_point=obs_point,
        exchange_id=RUN_ID,
        hop_id=hop_id,
        local_peer_id=f"serving-host-{hop_id}",
        transcript=make_transcript_summary(4, 4),
    )
    inclusion_proof = {"witness": "toy-checkpoint", "capsule_id": sealed["capsule_id"]}

    def disclose(run_id: str, asked_hop: str):
        # Standing check: only answer for the run this node participated in.
        if run_id != RUN_ID or asked_hop != hop_id:
            return None
        return StageBundle(hop_id=hop_id, stage_capsule=sealed, inclusion_proof=inclusion_proof)

    return disclose, sealed


def print_stage_lines(verdict):
    icon = {"green": f"{GREEN}✔{RESET}", "gap": f"{YELLOW}◌{RESET}", "mismatch": f"{RED}✗{RESET}"}
    for s in sorted(verdict.stages, key=lambda x: x.seq):
        mark = icon.get(s.status, "?")
        print(f"    {mark} seq {s.seq}  {s.hop_id:<9} [{s.claimed_bundle:<13}] {DIM}{s.detail}{RESET}")


def main() -> int:
    nodes = {}
    sealed_by_hop = {}
    for entry in TOPOLOGY:
        disclose, sealed = make_provider(entry.hop_id, entry.observation_point)
        nodes[entry.hop_id] = disclose
        sealed_by_hop[entry.hop_id] = sealed

    coordinator = coord_state(node_id="mesh-coordinator/skippy")

    print(f"\n{BOLD}=== 3-way split-inference coordinator demo (disclosure-on-request) ==={RESET}")
    print(f"run_id: {RUN_ID}")
    print(f"topology (stage order IS the graph): {' -> '.join(t.hop_id for t in TOPOLOGY)}\n")

    # -------- Honest run --------
    print(f"{BOLD}[1] Coordinator asks each stage-node for its bundle (standing: party to the run){RESET}")
    disclosures = collect_disclosed_bundles(nodes, run_id=RUN_ID, topology=TOPOLOGY)
    for hop, b in disclosures.items():
        state = "disclosed" if b is not None else "declined"
        print(f"    ask {hop:<9} -> {state}")

    print(f"\n{BOLD}[2] Coordinator composes signed receipt (binds order -> per-stage digest, NO payload){RESET}")
    receipt = compose_receipt_from_disclosures(
        coordinator, run_id=RUN_ID, topology=TOPOLOGY, disclosures=disclosures
    )
    print(f"    receipt capsule_id: {receipt['capsule_id'][:24]}…")

    print(f"\n{BOLD}[3] Independent offline verifier (holds only receipt + disclosed bundles){RESET}")
    # The verifier receives ONLY the bundles the coordinator relays — model that
    # explicitly by passing the disclosed (non-None) bundles.
    verifier_bundles = {h: b for h, b in disclosures.items() if b is not None}
    verdict = verify_coordinator_receipt(receipt, verifier_bundles)
    print(f"    reconstructed order: {' -> '.join(verdict.ordered_hops)}")
    print_stage_lines(verdict)

    honest_ok = (
        verdict.ok
        and verdict.present_count == 3
        and verdict.green_count == 3
        and verdict.mismatch_count == 0
    )
    if honest_ok:
        print(f"\n    {GREEN}{BOLD}GREEN — 3/3 stages: order verified, each stage's inclusion verified offline.{RESET}")
    else:
        print(f"\n    {RED}{BOLD}UNEXPECTED: honest run did not verify green.{RESET}")

    # -------- Adversarial A: tampered disclosure, digest mismatch --------
    print(f"\n{BOLD}[4] Adversarial A — a node discloses a TAMPERED record (digest won't match){RESET}")
    tampered_capsule = copy.deepcopy(sealed_by_hop["stage-1"])
    # Flip a payload-free field inside the mesh block -> different bytes -> different digest.
    tampered_capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"][
        "local_peer_id"
    ] = "serving-host-IMPOSTER"
    tampered_bundles = dict(verifier_bundles)
    tampered_bundles["stage-1"] = StageBundle(hop_id="stage-1", stage_capsule=tampered_capsule)
    adv_a = verify_coordinator_receipt(receipt, tampered_bundles)
    print_stage_lines(adv_a)
    caught_a = (not adv_a.ok) and any(
        s.hop_id == "stage-1" and s.status == "mismatch" for s in adv_a.stages
    )
    if caught_a:
        print(f"    {GREEN}CAUGHT — tampered stage-1 fails digest binding; receipt is NOT green.{RESET}")
    else:
        print(f"    {RED}NOT CAUGHT — adversarial tamper slipped through (false green).{RESET}")

    # -------- Adversarial B: a present stage's bundle is withheld -> visible gap --------
    print(f"\n{BOLD}[5] Adversarial B — a stage marked present is NOT disclosed to the verifier{RESET}")
    missing_bundles = {h: b for h, b in verifier_bundles.items() if h != "stage-2"}
    adv_b = verify_coordinator_receipt(receipt, missing_bundles)
    print_stage_lines(adv_b)
    gap_b = any(s.hop_id == "stage-2" and s.status == "gap" for s in adv_b.stages)
    # A withheld present-bundle is a visible hole (gap), never silently green.
    green_stage2 = any(s.hop_id == "stage-2" and s.status == "green" for s in adv_b.stages)
    caught_b = gap_b and not green_stage2
    if caught_b:
        print(f"    {GREEN}CAUGHT — stage-2 is a visible GAP, not a false green (three-state).{RESET}")
    else:
        print(f"    {RED}NOT CAUGHT — missing stage did not surface as a gap.{RESET}")

    ok = honest_ok and caught_a and caught_b
    print(f"\n{BOLD}=== SUMMARY ==={RESET}")
    print(f"  honest 3-way run verifies green ....... {GREEN + 'PASS' + RESET if honest_ok else RED + 'FAIL' + RESET}")
    print(f"  adversarial digest-mismatch caught .... {GREEN + 'PASS' + RESET if caught_a else RED + 'FAIL' + RESET}")
    print(f"  missing stage surfaces as a gap ....... {GREEN + 'PASS' + RESET if caught_b else RED + 'FAIL' + RESET}")
    print(f"\n{BOLD}{(GREEN + 'ALL GREEN' if ok else RED + 'DEMO FAILED')}{RESET}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
