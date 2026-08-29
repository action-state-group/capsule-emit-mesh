#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Coordinator-receipt artifact-type producer.

Implements the record shape and producer invariants defined in
`_work/mesh-coordinator-receipt-artifact-type-2026-08-28.md` §3.1/§3.2/§6
(design draft, cleared 2026-08-28) — the record the coordinator (skippy)
produces over a split-inference run's own stage order: which hops happened,
in what order, and whether each stage's bundle was obtained.

SCOPE — [mesh-b3-coordinator-receipt-producer] (Phase B6-code)
    This module only builds and emits the record from an already-resolved
    topology and per-stage bundle state. It does NOT request bundles from
    participants, does NOT call received() to carry them into the
    coordinator's own log, and does NOT call push(). That auto-request /
    carry logic is Phase B6-final
    ([mesh-b6-coordinator-autorequest-composer-log]) — a caller of
    emit_coordinator_receipt() is expected to have already carried each
    `present` stage's bundle bytes via capsule_emit.surface.received() and
    to pass in the resulting capsule_id as that stage's bundle_ref.

CITATION, NOT COMPOSITION (design doc §5.4)
    The coordinator does not compose the N stage bundles into seal()'s
    who/can/did/audit legs. Having carried each stage bundle into its own
    log, it *cites* them as an N-ary, ordered `stages[]` array of CPB typed
    digest references — the shape AAC's `references[]` / `citation_purpose`
    seam ({{xref}}, agent-action-capsule #85) defines for exactly this kind
    of cross-record citation. AAC's `emit()` does not yet carry a top-level
    `references` field in code, and this repo's own coordinator/per-hop
    records are bespoke-serialized (capsule_to_bytes: plain
    `json.dumps(sort_keys=True)`, no JCS — design doc §5.2 Branch B), so the
    citation lives in a private extension block
    (`x-mesh-coordinator-receipt-v1`) inside `compute_attestation`, mirroring
    how `mesh_record_emitter.py` carries `x-mesh-lifecycle-v1`. The typed
    digest reference SHAPE inside that block (`{type, digest_alg, digest}`)
    is unchanged from AAC's own CPB typed digest ref.

FIELD DESIGN  (x-mesh-coordinator-receipt-v1 inside compute_attestation)
    v                 int   Always 1.
    kind              str   "mesh-coordinator-receipt" (working name, design
                             doc §5.1 — naming is an owner call, not fixed
                             here).
    run_id            str   Correlation spine for the whole split run — the
                             coordinator-level counterpart to the per-hop
                             exchange_id already provisional in
                             mesh-inference-exchange.
    topology          list  Stage order = the graph; present regardless of
                             what came back. One entry per hop:
                             {seq, hop_id, role, observation_point}.
    stages            list  What was actually obtained. One entry per
                             topology hop (enforced — a missing or extra
                             entry is rejected): {hop_id, bundle,
                             bundle_ref?}.

    `topology` and `stages` are kept as two separate arrays, never merged
    (design doc §3.1): a verifier can compute how much of the claimed
    topology is backed by a returned bundle without the coordinator ever
    conflating "I routed this" with "I have proof of this."
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from agent_action_capsule.emit import emit

from mesh_record_emitter import RecordNodeState, capsule_to_bytes, default_node_state
from mesh_record_verifier import OBSERVATION_POINTS

__all__ = [
    "RecordNodeState",
    "default_node_state",
    "capsule_to_bytes",
    "BUNDLE_STATES",
    "TopologyEntry",
    "StageEntry",
    "emit_coordinator_receipt",
]

# Three-state `bundle` field (design doc §3.2, §5.3 — flagged [OWNER/DE TO
# CONFIRM] at registry-filing time; this is the producer's enforcement of the
# draft shape, not a claim the enum is finalized).
BUNDLE_STATES = frozenset({"present", "absent", "not_requested"})

_DIGEST_ALG = "SHA-256"
_HEX_DIGITS = frozenset("0123456789abcdef")


def _validate_bundle_ref(bundle_ref: dict[str, Any]) -> None:
    """CPB typed digest ref shape: {type, digest_alg, digest} (design doc §3.2).

    This validates SHAPE only — that the ref looks like a well-formed CPB
    typed digest reference. It cannot validate that the digest resolves to a
    capsule the coordinator actually carried into its own log (the second
    producer invariant, design doc §6) — that is a verifier-side check
    against the coordinator's log, out of scope for a producer that has no
    log to check against at construction time.
    """
    if not isinstance(bundle_ref, dict):
        raise ValueError(f"bundle_ref must be a dict — got {type(bundle_ref).__name__}")
    missing = {"type", "digest_alg", "digest"} - bundle_ref.keys()
    if missing:
        raise ValueError(f"bundle_ref missing required key(s): {sorted(missing)}")
    if not isinstance(bundle_ref["type"], str) or not bundle_ref["type"].strip():
        raise ValueError("bundle_ref.type must be a non-empty string")
    if bundle_ref["digest_alg"] != _DIGEST_ALG:
        raise ValueError(
            f"bundle_ref.digest_alg must be {_DIGEST_ALG!r} — got {bundle_ref['digest_alg']!r}"
        )
    digest = bundle_ref["digest"]
    if not isinstance(digest, str) or len(digest) != 64 or set(digest) - _HEX_DIGITS:
        raise ValueError("bundle_ref.digest must be 64-char lowercase hex (SHA-256)")


@dataclass(frozen=True)
class TopologyEntry:
    """One hop in the coordinator's own claim of what it routed (§3.1).

    `role` reuses [mesh-exchange-role-field] A1's registry-defined enum once
    it lands in this repo's code (design doc §3.1) — not validated against a
    closed set here because that enum does not exist in code yet; only
    non-empty-string is enforced. `observation_point`, when given, reuses
    the already-provisional four-value closed set verbatim
    (mesh_record_verifier.OBSERVATION_POINTS) and IS validated here, since
    that enum already exists in this repo.
    """

    seq: int
    hop_id: str
    role: str
    observation_point: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.hop_id, str) or not self.hop_id:
            raise ValueError("TopologyEntry.hop_id must be a non-empty string")
        if not isinstance(self.role, str) or not self.role:
            raise ValueError("TopologyEntry.role must be a non-empty string")
        if self.observation_point is not None and self.observation_point not in OBSERVATION_POINTS:
            raise ValueError(
                f"TopologyEntry.observation_point {self.observation_point!r} not in "
                f"the known four-value set {sorted(OBSERVATION_POINTS)}"
            )


@dataclass(frozen=True)
class StageEntry:
    """One hop's actually-obtained bundle state (§3.2) — the three-state field.

    Enforces the design doc §6 FIRST producer invariant at construction: a
    `present` entry MUST carry a `bundle_ref` (a stage the coordinator has
    not yet carried into its own log cannot honestly be labeled `present`);
    `absent`/`not_requested` MUST NOT carry one — there is nothing carried
    and nothing to cite. A record violating this can never be constructed
    through this class, so it can never reach emit_coordinator_receipt().
    """

    hop_id: str
    bundle: str
    bundle_ref: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.hop_id, str) or not self.hop_id:
            raise ValueError("StageEntry.hop_id must be a non-empty string")
        if self.bundle not in BUNDLE_STATES:
            raise ValueError(
                f"StageEntry.bundle must be one of {sorted(BUNDLE_STATES)} — got {self.bundle!r}"
            )
        if self.bundle == "present":
            if self.bundle_ref is None:
                raise ValueError(
                    "StageEntry.bundle='present' requires bundle_ref — a present "
                    "stage must already have been carried into the coordinator's "
                    "own log (received()) and cite that carried copy (§3.2, §6)"
                )
            _validate_bundle_ref(self.bundle_ref)
        elif self.bundle_ref is not None:
            raise ValueError(
                f"StageEntry.bundle={self.bundle!r} MUST NOT carry bundle_ref — "
                "there is nothing carried and nothing to cite (§3.2, §6 producer "
                "invariant); a naive verifier that only checks bundle_ref presence "
                "would wrongly accept this"
            )


def emit_coordinator_receipt(
    state: RecordNodeState,
    *,
    run_id: str,
    topology: list[TopologyEntry],
    stages: list[StageEntry],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit one signed capsule carrying the coordinator receipt (§3.1).

    Requires exactly one `stages[]` entry per `topology[]` hop_id ("one
    entry per topology hop", §3.1) — a missing or extra stage entry is
    rejected rather than silently tolerated, and `topology[]` must already
    be ordered by `seq` (stage order IS the graph).

    Returns the capsule dict. As with mesh_record_emitter's per-hop
    records, the record bytes are `capsule_to_bytes(capsule)` — plain
    `json.dumps(sort_keys=True)`, not JCS (design doc §5.2 Branch B).
    """
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string")
    if not topology:
        raise ValueError("topology must have at least one entry")

    topology_hop_ids = [t.hop_id for t in topology]
    if len(set(topology_hop_ids)) != len(topology_hop_ids):
        raise ValueError(f"topology[] hop_id values must be unique — got {topology_hop_ids}")
    seqs = [t.seq for t in topology]
    if seqs != sorted(seqs):
        raise ValueError("topology[] must be ordered by seq — stage order is the graph (§3.1)")

    stage_hop_ids = [s.hop_id for s in stages]
    if len(set(stage_hop_ids)) != len(stage_hop_ids):
        raise ValueError(f"stages[] hop_id values must be unique — got {stage_hop_ids}")
    missing = set(topology_hop_ids) - set(stage_hop_ids)
    unexpected = set(stage_hop_ids) - set(topology_hop_ids)
    if missing or unexpected:
        raise ValueError(
            "stages[] must have exactly one entry per topology[] hop (§3.1) — "
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}"
        )

    mesh_block: dict[str, Any] = {
        "v": 1,
        "kind": "mesh-coordinator-receipt",
        "run_id": run_id,
        "topology": [
            {
                "seq": t.seq,
                "hop_id": t.hop_id,
                "role": t.role,
                "observation_point": t.observation_point,
            }
            for t in topology
        ],
        "stages": [
            {
                "hop_id": s.hop_id,
                "bundle": s.bundle,
                **({"bundle_ref": s.bundle_ref} if s.bundle_ref is not None else {}),
            }
            for s in stages
        ],
    }
    if extra:
        mesh_block.update(extra)

    compute_attestation: dict[str, Any] = {
        "runtime": "mesh-record-side-test:0000000000000000",
        "x-mesh-coordinator-receipt-v1": mesh_block,
    }

    capsule = emit(
        action_id=f"mesh-coordinator-receipt/{state.node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=state.operator,
        developer=state.developer,
        model_id=state.model_id,
        provider="mesh-llm",
        compute_attestation=compute_attestation,
        prior_capsule_id=state.last_capsule_id,
        chain_relation="confirms" if state.last_capsule_id else None,
        domain="action",
        provenance="collector",
    )
    state.last_capsule_id = capsule["capsule_id"]
    return capsule
