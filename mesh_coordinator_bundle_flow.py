#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disclosure-on-request bundle flow + offline verifier for the coordinator receipt.

This is the Phase B6-final glue that `mesh_coordinator_receipt_emitter.py`
deliberately leaves out (see that module's SCOPE note). The emitter builds and
signs the record from an *already-resolved* per-stage bundle state; it does not
ask anyone for anything. This module supplies the two missing halves, both
kept offline-verifiable and free of any live-log access:

  1. DISCLOSURE-ON-REQUEST (`ask_stage_for_bundle` / `collect_disclosed_bundles`)
     The coordinator — a party to the run, so it has standing (TRUST-MODEL
     §2.4 correlation spine, §4.3 split inference) — asks each stage-node for
     its bundle. The node CHOOSES to disclose: it hands back a `StageBundle`
     (its own sealed stage-record bytes + capsule_id + any inclusion proof).
     This is NOT a live query into the node's log. The node returns a bounded,
     self-contained, offline-verifiable object and nothing more. A node may
     decline (return None) → that stage is `absent`, never a false `present`.

  2. OFFLINE VERIFIER (`verify_coordinator_receipt`)
     A third party who holds ONLY (a) the signed coordinator receipt and (b)
     the disclosed bundles reconstructs stage order from `topology[]` and, for
     every `present` stage, recomputes the bundle digest over the disclosed
     bytes and checks it against the digest the receipt committed to. A
     mismatch, a missing bundle for a `present` stage, or a bundle whose own
     capsule fails AAC verification is caught — three-state, never a false
     green.

WHAT IS BOUND vs WHAT IS SELF-ATTESTED (honest gaps)
  BOUND: stage ORDER (topology seq), and for each present stage the exact
  bytes of that stage's sealed record (via its SHA-256 digest committed in the
  receipt). Tampering with a disclosed bundle, dropping one, or reordering the
  claimed topology is detectable offline.
  NOT BOUND: node IDENTITY is self-attested unless a stage record itself
  carries a verified requester/provider commitment (mesh_record_verifier's
  cross_party_rung). The coordinator's own signature over the receipt is
  likewise self-attested unless anchored to a registration/witness (§8). This
  module verifies the *binding of order to bytes*; it does not manufacture
  identity that the underlying records do not already carry.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from agent_action_capsule.verify import verify as verify_capsule

from mesh_coordinator_receipt_emitter import (
    RecordNodeState,
    StageEntry,
    TopologyEntry,
    capsule_to_bytes,
    emit_coordinator_receipt,
)

__all__ = [
    "StageBundle",
    "bundle_digest",
    "bundle_ref_for",
    "ask_stage_for_bundle",
    "collect_disclosed_bundles",
    "compose_receipt_from_disclosures",
    "StageVerdict",
    "ReceiptVerdict",
    "verify_coordinator_receipt",
]

_DIGEST_ALG = "SHA-256"


# ---------------------------------------------------------------------------
# The disclosed bundle
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StageBundle:
    """A bounded, offline-verifiable bundle a stage-node CHOSE to disclose.

    This is the whole of what crosses the wire in response to the
    coordinator's ask. It carries the stage's own sealed record (the capsule
    dict) and, optionally, an inclusion proof (e.g. a witness checkpoint /
    receipt) the node also chose to include. It carries NO live handle into
    the node's log — reconstructing the digest and re-verifying the capsule
    needs only these bytes.
    """

    hop_id: str
    stage_capsule: dict[str, Any]
    inclusion_proof: dict[str, Any] | None = None

    @property
    def canonical_bytes(self) -> bytes:
        """The exact bytes the receipt's digest is computed over."""
        return capsule_to_bytes(self.stage_capsule)


def bundle_digest(bundle: StageBundle) -> str:
    """SHA-256 (64-char lowercase hex) over the disclosed stage-record bytes."""
    return hashlib.sha256(bundle.canonical_bytes).hexdigest()


def bundle_ref_for(bundle: StageBundle) -> dict[str, Any]:
    """Build the CPB typed digest ref the receipt cites for a present stage."""
    return {"type": "capsule", "digest_alg": _DIGEST_ALG, "digest": bundle_digest(bundle)}


# ---------------------------------------------------------------------------
# Disclosure-on-request
# ---------------------------------------------------------------------------

#: A stage-node modelled as a pure function: given the coordinator's run_id and
#: the hop it is being asked about, it returns the bundle it CHOOSES to
#: disclose, or None to decline. Local objects/closures stand in for real
#: cross-host nodes; the shape of the interaction is identical.
StageNode = Callable[[str, str], StageBundle | None]


def ask_stage_for_bundle(node: StageNode, *, run_id: str, hop_id: str) -> StageBundle | None:
    """The coordinator asks ONE stage-node for its bundle (disclosure-on-request).

    Standing: the coordinator is a party to `run_id`, so it is entitled to
    ask. The node answers by CHOICE — returning a self-contained StageBundle
    or declining with None. There is no live-log access here: the node returns
    an object, the coordinator never reaches into the node.
    """
    disclosed = node(run_id, hop_id)
    if disclosed is None:
        return None
    if disclosed.hop_id != hop_id:
        raise ValueError(
            f"stage-node disclosed a bundle for hop {disclosed.hop_id!r} when asked "
            f"about hop {hop_id!r} — a node must answer the question it was asked"
        )
    return disclosed


def collect_disclosed_bundles(
    nodes: dict[str, StageNode],
    *,
    run_id: str,
    topology: list[TopologyEntry],
) -> dict[str, StageBundle | None]:
    """Ask every stage in topology order; collect what each chose to disclose.

    Returns hop_id -> StageBundle (disclosed) or None (declined / no node).
    Order follows topology seq so the collection mirrors the run's stage order.
    """
    ordered = sorted(topology, key=lambda t: t.seq)
    out: dict[str, StageBundle | None] = {}
    for entry in ordered:
        node = nodes.get(entry.hop_id)
        out[entry.hop_id] = (
            ask_stage_for_bundle(node, run_id=run_id, hop_id=entry.hop_id)
            if node is not None
            else None
        )
    return out


def compose_receipt_from_disclosures(
    state: RecordNodeState,
    *,
    run_id: str,
    topology: list[TopologyEntry],
    disclosures: dict[str, StageBundle | None],
    requested: set[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Turn collected disclosures into StageEntry[] and emit the signed receipt.

    Three-state mapping (never a false green):
      disclosed bundle present            -> bundle='present' + committed digest
      asked but declined / no bundle back -> bundle='absent'
      never asked                         -> bundle='not_requested'

    `requested` names the hops the coordinator actually asked; hops not in it
    (default: all topology hops are considered asked) map to 'not_requested'
    when no bundle came back.
    """
    asked = requested if requested is not None else {t.hop_id for t in topology}
    stages: list[StageEntry] = []
    for entry in topology:
        bundle = disclosures.get(entry.hop_id)
        if bundle is not None:
            stages.append(
                StageEntry(hop_id=entry.hop_id, bundle="present", bundle_ref=bundle_ref_for(bundle))
            )
        elif entry.hop_id in asked:
            stages.append(StageEntry(hop_id=entry.hop_id, bundle="absent"))
        else:
            stages.append(StageEntry(hop_id=entry.hop_id, bundle="not_requested"))
    return emit_coordinator_receipt(
        state, run_id=run_id, topology=topology, stages=stages, extra=extra
    )


# ---------------------------------------------------------------------------
# Offline verifier
# ---------------------------------------------------------------------------

@dataclass
class StageVerdict:
    """Per-stage offline verdict."""

    hop_id: str
    seq: int
    claimed_bundle: str  # present | absent | not_requested (from the receipt)
    #: green | gap | mismatch — three states, never conflated. green only when
    #: a present stage's disclosed bytes reproduce the committed digest AND the
    #: disclosed capsule itself verifies. gap = an honest hole (absent /
    #: not_requested / a present stage whose bundle was not disclosed to the
    #: verifier). mismatch = the load-bearing failure: bytes do not reproduce
    #: the committed digest, or the disclosed capsule fails AAC verification.
    status: str
    detail: str = ""


@dataclass
class ReceiptVerdict:
    """Whole-receipt offline verdict."""

    ok: bool
    run_id: str
    ordered_hops: list[str]
    stages: list[StageVerdict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def present_count(self) -> int:
        return sum(1 for s in self.stages if s.claimed_bundle == "present")

    @property
    def green_count(self) -> int:
        return sum(1 for s in self.stages if s.status == "green")

    @property
    def mismatch_count(self) -> int:
        return sum(1 for s in self.stages if s.status == "mismatch")


def _read_receipt_block(receipt_capsule: dict[str, Any]) -> dict[str, Any]:
    try:
        block = (
            receipt_capsule["model_attestation"]["compute_attestation"][
                "x-mesh-coordinator-receipt-v1"
            ]
        )
    except (KeyError, TypeError) as exc:  # pragma: no cover - shape guard
        raise ValueError("receipt is missing x-mesh-coordinator-receipt-v1 block") from exc
    if block.get("kind") != "mesh-coordinator-receipt":
        raise ValueError("not a mesh-coordinator-receipt")
    return block


def verify_coordinator_receipt(
    receipt_capsule: dict[str, Any],
    disclosed_bundles: dict[str, StageBundle],
) -> ReceiptVerdict:
    """Offline: reconstruct stage order + check each present stage's inclusion.

    The verifier holds ONLY the signed receipt capsule and whatever bundles
    were disclosed to it. It:
      1. verifies the coordinator receipt capsule itself (AAC verify()),
      2. reconstructs stage order from topology[] (ordered by seq),
      3. for every stage the receipt marks `present`, recomputes the digest
         over the disclosed bundle bytes and checks it equals the digest the
         receipt committed, AND re-verifies the disclosed stage capsule.

    A `present` stage with no disclosed bundle is a GAP (visible hole), not a
    pass. A digest mismatch or a failing disclosed capsule is a MISMATCH.
    """
    errors: list[str] = []

    # 1. The receipt itself must verify.
    receipt_res = verify_capsule(receipt_capsule)
    if not receipt_res.ok:
        errors.append(f"coordinator receipt capsule failed verification: {receipt_res.errors}")

    block = _read_receipt_block(receipt_capsule)
    run_id = block.get("run_id", "")
    topology = sorted(block.get("topology", []), key=lambda t: t["seq"])
    ordered_hops = [t["hop_id"] for t in topology]
    stage_index = {s["hop_id"]: s for s in block.get("stages", [])}

    stage_verdicts: list[StageVerdict] = []
    for topo in topology:
        hop_id = topo["hop_id"]
        seq = topo["seq"]
        stage_rec = stage_index.get(hop_id)
        if stage_rec is None:
            stage_verdicts.append(
                StageVerdict(hop_id, seq, "missing", "mismatch", "no stages[] entry for this hop")
            )
            continue

        claimed = stage_rec["bundle"]
        if claimed != "present":
            # absent / not_requested — an honest hole, three-state.
            stage_verdicts.append(
                StageVerdict(hop_id, seq, claimed, "gap", f"stage disclosed nothing ({claimed})")
            )
            continue

        committed = stage_rec.get("bundle_ref", {}).get("digest")
        bundle = disclosed_bundles.get(hop_id)
        if bundle is None:
            stage_verdicts.append(
                StageVerdict(
                    hop_id, seq, claimed, "gap",
                    "receipt marks this stage present but no bundle was disclosed to the verifier",
                )
            )
            continue

        recomputed = bundle_digest(bundle)
        if recomputed != committed:
            stage_verdicts.append(
                StageVerdict(
                    hop_id, seq, claimed, "mismatch",
                    f"disclosed bytes digest {recomputed[:16]}… != committed {str(committed)[:16]}…",
                )
            )
            continue

        stage_res = verify_capsule(bundle.stage_capsule)
        if not stage_res.ok:
            stage_verdicts.append(
                StageVerdict(
                    hop_id, seq, claimed, "mismatch",
                    f"disclosed stage capsule failed AAC verification: {stage_res.errors}",
                )
            )
            continue

        stage_verdicts.append(
            StageVerdict(hop_id, seq, claimed, "green", f"digest {recomputed[:16]}… matches, capsule verifies")
        )

    ok = not errors and all(s.status != "mismatch" for s in stage_verdicts)
    return ReceiptVerdict(
        ok=ok,
        run_id=run_id,
        ordered_hops=ordered_hops,
        stages=stage_verdicts,
        errors=errors,
    )
