#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record-side emitter for mesh-llm lifecycle state and observation binding.

Bridges #1331's LifecycleTrace objects (from the mock rig) to signed capsule
records whose bytes carry enough information for an offline verifier to reach
the correct verdict independently of the rig.

The record bytes are the product.  The rig is the harness that produces them.
This module proves the second half: the emitted record is distinguishable by
state and observation point to a reader who has only the record bytes.

FIELD DESIGN  (x-mesh-lifecycle-v1 inside compute_attestation)
  terminal_state    str   One of the eight TerminalState values, or "unknown".
  terminal_reason   str|None  Sub-reason (e.g. "internal_hook_failure").
  observation_point str|None  One of the four ObservationPoint values, or None
                              when the record covers the whole exchange rather
                              than one vantage point.
  exchange_id       str   Stable identifier across all records for this exchange.
  hop_id            str   Which hop in a routed request produced this record.
                          Two records of the same exchange can share exchange_id
                          but MUST differ in at least one of
                          (hop_id, attempt, local_peer_id) to be distinguishable.
  attempt           int   Retry-attempt number for this hop (0-based).
  local_peer_id     str   The peer (node) that produced this record.
  transcript        dict  {event_count, expected_count, complete}
                          complete MUST be False when event_count < expected_count.
                          See TranscriptSummary and the producer-side safety
                          enforced in make_transcript_summary().
  requester_commitment  dict|None  Rung-2 evidence (requester_commitment.py):
                          the requester's signed commitment over this record's
                          own request_digest, or None when the requester
                          contributed nothing beyond (at most) a nonce. A
                          record MAY carry this on any hop of an exchange;
                          mesh_record_verifier.py verifies it against the
                          record's own agent_input_digest and derives
                          cross_party_rung from that verification — it is
                          NEVER read as pre-asserted trust.
  requester_identity_binding  dict|None  Optional evidence
                          (requester_identity_binding.py) that the
                          requester_commitment's public key is cited by a
                          persistent, self-signed identity — closing the
                          zero-effort self-mint gap [mesh-rung12-adversarial-
                          review] D1 disclosed: a bare commitment key with no
                          binding behind it grades at most acknowledged_
                          receipt, never full_bilateral. Still self-asserted
                          (no external anchor) — see TRUST-MODEL.md §4.1a.
  identity_limitation    str|None  Present whenever requester_commitment is
                          not None (requester_commitment.IDENTITY_LIMITATION_
                          CAVEAT). States plainly that cross_party_rung=
                          full_bilateral proves a commitment was made and
                          matches this record, not that an independent party
                          made it — a lone actor can self-mint both halves
                          with no external identity anchor. Mirrors the
                          identity_limitation capsule_sidecar.build_capsule()
                          already attaches for the #1233 receipt tuple; see
                          [mesh-rung12-adversarial-review] D1.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule

from requester_commitment import IDENTITY_LIMITATION_CAVEAT


# ---------------------------------------------------------------------------
# TranscriptSummary
# ---------------------------------------------------------------------------

@dataclass
class TranscriptSummary:
    """Producer-side transcript completion claim.

    The ONLY way to set complete=True is through make_transcript_summary().
    Direct construction is not prevented by Python, but the emitter asserts
    the invariant before writing the record — ensuring the producer cannot
    accidentally emit a complete-looking record for a truncated transcript.

    The verifier (mesh_record_verifier.py) re-checks the invariant from the
    record bytes.  A record that says complete=True but has
    event_count < expected_count is caught at both ends.

    _deliberate_lie is an internal marker set only by make_transcript_summary
    when _override_complete=True is passed.  It tells emit_lifecycle_record to
    skip the producer invariant — simulating a malicious or buggy producer for
    verifier guard testing.  Normal code never touches this field.
    """

    event_count: int
    expected_count: int | None  # None means "count not known at emit time"
    complete: bool
    _deliberate_lie: bool = False


def make_transcript_summary(
    event_count: int,
    expected_count: int | None,
    *,
    _override_complete: bool | None = None,
) -> TranscriptSummary:
    """Build a TranscriptSummary with the producer-side safety enforced.

    NORMAL USAGE
        expected_count=8, event_count=8  → complete=True
        expected_count=8, event_count=3  → complete=False  (overflow / truncation)
        expected_count=None              → complete=False  (count unknown)

    _override_complete (TEST USE ONLY — for the deliberately-broken truncation
        scenario).  Calling code must name the param to make the lie obvious.
        Passing _override_complete=True with event_count < expected_count
        creates the broken record that the verifier's guard must catch.
    """
    if _override_complete is not None:
        return TranscriptSummary(
            event_count=event_count,
            expected_count=expected_count,
            complete=_override_complete,
            _deliberate_lie=True,
        )
    if expected_count is None:
        complete = False
    else:
        complete = event_count >= expected_count
    return TranscriptSummary(
        event_count=event_count,
        expected_count=expected_count,
        complete=complete,
    )


# ---------------------------------------------------------------------------
# NodeState (minimal — no live HTTP server needed for record-side tests)
# ---------------------------------------------------------------------------

@dataclass
class RecordNodeState:
    """Minimal signing state for emitting lifecycle records without a sidecar."""

    node_id: str
    operator: str
    developer: str
    signing_key_pem: bytes
    model_id: str
    last_capsule_id: str | None = None


def _default_signing_key() -> bytes:
    """Generate a fresh Ed25519 key for test use (in-memory, never persisted)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def default_node_state(node_id: str = "mesh-node-record-side-test/0.1") -> RecordNodeState:
    return RecordNodeState(
        node_id=node_id,
        operator="capsule-emit-mesh-poc-test",
        developer="mesh_record_emitter/0.1",
        signing_key_pem=_default_signing_key(),
        model_id="test-model/record-side",
    )


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------

def emit_lifecycle_record(
    state: RecordNodeState,
    *,
    terminal_state: str,
    terminal_reason: str | None = None,
    observation_point: str | None = None,
    exchange_id: str,
    hop_id: str = "hop-0",
    attempt: int = 0,
    local_peer_id: str,
    transcript: TranscriptSummary,
    request_digest: str | None = None,
    response_digest: str | None = None,
    requester_commitment: dict[str, Any] | None = None,
    requester_identity_binding: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit one signed capsule record for a lifecycle state / observation point.

    Returns the capsule dict (the record bytes are json.dumps(capsule, ...).encode()).
    The record carries an x-mesh-lifecycle-v1 block that lets an offline verifier
    read terminal_state, observation_point, exchange_id, hop_id, attempt,
    local_peer_id, and transcript.complete without access to the rig or any other
    side-channel.

    ``requester_commitment`` (optional): rung-2 evidence built with
    requester_commitment.make_requester_commitment(), bound to this call's own
    request_digest and exchange_id. Passing one signed against a DIFFERENT
    request_digest or exchange_id is exactly the forged-evidence case
    mesh_record_verifier.verify_record_bytes() must catch — this emitter does
    not check the binding itself; only the offline verifier does, because the
    producer's own claim is never the evidence.

    ``requester_identity_binding`` (optional): evidence built with
    requester_identity_binding.make_requester_identity_binding(), citing the
    SAME public key as ``requester_commitment``. Like the commitment itself,
    this emitter does not check it — only mesh_record_verifier.py does, and
    only a verified binding lets a valid commitment reach full_bilateral
    rather than acknowledged_receipt.

    Producer-side invariant enforced here:
        if transcript.expected_count is not None and transcript.complete is True:
            assert transcript.event_count >= transcript.expected_count
    The only escape hatch is _override_complete=True in make_transcript_summary(),
    which must be named explicitly to signal deliberate breakage for testing the
    verifier's guard.
    """
    # Enforce the producer-side invariant before writing — but skip it when
    # _deliberate_lie=True, which is only set by make_transcript_summary with
    # _override_complete=True.  That explicit keyword is the signal that the
    # caller is deliberately simulating a broken producer for guard testing.
    if (
        not transcript._deliberate_lie
        and transcript.complete
        and transcript.expected_count is not None
        and transcript.event_count < transcript.expected_count
    ):
        raise ValueError(
            f"Producer invariant violated: transcript.complete=True but "
            f"event_count={transcript.event_count} < "
            f"expected_count={transcript.expected_count}. "
            f"Use make_transcript_summary(_override_complete=True) to "
            f"intentionally break this for verifier guard testing."
        )

    mesh_block: dict[str, Any] = {
        "terminal_state": terminal_state,
        "terminal_reason": terminal_reason,
        "observation_point": observation_point,
        "exchange_id": exchange_id,
        "hop_id": hop_id,
        "attempt": attempt,
        "local_peer_id": local_peer_id,
        "transcript": {
            "event_count": transcript.event_count,
            "expected_count": transcript.expected_count,
            "complete": transcript.complete,
        },
        "requester_commitment": requester_commitment,
        "requester_identity_binding": requester_identity_binding,
        # [mesh-rung12-adversarial-review] D1(a) — restores the honesty
        # caveat the old capsule_sidecar.build_capsule() path already
        # carries (identity_limitation, attached whenever bilateral evidence
        # is present). Attached whenever a requester_commitment is passed,
        # regardless of whether it later verifies — this emitter cannot
        # verify it; only mesh_record_verifier.py can, and it independently
        # re-derives this same caveat at verify time (see
        # LifecycleVerdict.identity_limitation) so a reader is never solely
        # dependent on the producer having chosen to disclose it.
        "identity_limitation": IDENTITY_LIMITATION_CAVEAT if requester_commitment is not None else None,
    }
    if extra:
        mesh_block.update(extra)

    req_digest = request_digest or ("0" * 64)
    resp_digest = response_digest or ("0" * 64)

    # Map terminal state to capsule disposition fields.
    #
    # IMPORTANT: verdict_class='denied' is in NEVER_DISPATCH_VERDICT_CLASSES
    # (§5.4.2) and is incompatible with effect.status='failed'.  The sidecar
    # comment explains the same constraint:
    #   "a sidecar cannot claim pre-dispatch denial from outside the process;
    #    all it can honestly say is that a request was received and the outcome
    #    was a refusal — 'ran and threw' per the verdict_class registry."
    # The fine-grained lifecycle truth (policy_denied vs errored) lives in
    # x-mesh-lifecycle-v1.terminal_state, which the verifier reads.  The
    # capsule verdict_class is a coarser classification.
    if terminal_state == "completed":
        effect_status = "confirmed"
        verdict_class = "executed"
        disposition_decision = "accept"
    else:
        # All non-completed states: policy_denied, request_invalid,
        # backend_error, transport_error, client_cancelled, timed_out,
        # evidence_unavailable — capsule says "errored"; lifecycle field
        # carries the specific state.
        effect_status = "failed"
        verdict_class = "errored"
        disposition_decision = "reject"

    compute_attestation: dict[str, Any] = {
        "agent_input_digest": req_digest,
        "agent_output_digest": resp_digest,
        "runtime": "mesh-record-side-test:0000000000000000",
        "x-mesh-lifecycle-v1": mesh_block,
    }

    effect = EffectRecord(
        status=effect_status,
        type="inference_completion",
        request_digest=req_digest,
        response_digest=resp_digest,
        effect_attestation="gate_executed",
    )
    disposition = Disposition(
        decision=disposition_decision,
        approver="policy",
        human_disposed=False,
        verdict_class=verdict_class,
    )

    capsule = emit(
        action_id=f"mesh-poc/{state.node_id}/{uuid.uuid4()}",
        action_type="decide",
        operator=state.operator,
        developer=state.developer,
        model_id=state.model_id,
        provider="mesh-llm",
        compute_attestation=compute_attestation,
        effect=effect,
        disposition=disposition,
        prior_capsule_id=state.last_capsule_id,
        chain_relation="confirms" if state.last_capsule_id else None,
        domain="action",
        provenance="collector",
    )
    state.last_capsule_id = capsule["capsule_id"]
    return capsule


def capsule_to_bytes(capsule: dict[str, Any]) -> bytes:
    """Serialize capsule to the canonical bytes a verifier would receive."""
    return json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Emit from LifecycleTrace (bridge to the rig)
# ---------------------------------------------------------------------------

def emit_from_trace(
    state: RecordNodeState,
    trace: Any,  # LifecycleTrace — avoid hard import of rig module
    *,
    observation_record: Any | None = None,  # ObservationRecord | None
    local_peer_id: str = "serving-host-A",
    hop_id: str = "hop-0",
    attempt: int = 0,
    transcript_event_count: int | None = None,
    transcript_expected_count: int | None = None,
    _transcript_override_complete: bool | None = None,
    requester_commitment: dict[str, Any] | None = None,
    requester_identity_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit a capsule record from a LifecycleTrace + optional ObservationRecord.

    transcript_event_count: how many events were observed in this transcript.
        Defaults to the number of observations in the trace.
    transcript_expected_count: how many were expected.
        Defaults to transcript_event_count (normal, complete case).
    """
    ts_value = trace.terminal_state.value if trace.terminal_state else "unknown"
    obs_value = (
        observation_record.observation_point.value
        if observation_record is not None
        else None
    )
    t_count = transcript_event_count if transcript_event_count is not None else len(trace.observations)
    e_count = (
        transcript_expected_count
        if transcript_expected_count is not None
        else t_count
    )
    transcript = make_transcript_summary(
        t_count,
        e_count,
        _override_complete=_transcript_override_complete,
    )

    req_digest = trace.request_metadata.get("body_digest")
    resp_digest = trace.response_metadata.get("body_digest")

    return emit_lifecycle_record(
        state,
        terminal_state=ts_value,
        terminal_reason=trace.terminal_reason,
        observation_point=obs_value,
        exchange_id=trace.exchange_id,
        hop_id=hop_id,
        attempt=attempt,
        local_peer_id=local_peer_id,
        transcript=transcript,
        request_digest=req_digest,
        response_digest=resp_digest,
        requester_commitment=requester_commitment,
        requester_identity_binding=requester_identity_binding,
    )
