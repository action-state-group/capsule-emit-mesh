#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline record-side verifier for mesh-llm lifecycle state and observation binding.

A verifier that reads ONLY the record bytes and produces a structured verdict.
No access to the rig, no side-channel information.  This is the property that
mesh-record-side-state-and-observation-binding exists to demonstrate.

Key responsibilities:
1. Extract terminal_state, observation_point, exchange_id, hop_id, attempt,
   local_peer_id from the x-mesh-lifecycle-v1 block in the record.
2. Verify the requester_commitment (rung-2, requester_commitment.py) against
   the record's own request digest and derive cross_party_rung — see
   derive_cross_party_rung() below. A record without a valid commitment stays
   unilateral_fallback; the label is NEVER upgraded on absent or invalid
   evidence.
3. Enforce the transcript completeness guard:
       complete=True AND event_count < expected_count → IncompleteTranscriptError
   This guard is what distinguishes "complete evidence" from "incomplete evidence
   that a bad producer labelled complete".  The deliberately-broken truncation
   test in test_record_side_state_binding.py proves this guard can fire by first
   showing it ABSENT (the lie passes a naive verifier) and then PRESENT (the
   guard catches it).
4. Enforce the observation-point provenance check:
       observation_point in {gateway_ingress} AND local_peer_id != gateway → warning
   (recorded in findings, not a hard error — the spec rule is "must not present
   as proof from the serving target", which is enforced at the record level by
   checking whether the observation_point is consistent with local_peer_id's role.)

This module has no import from the mock rig.  It operates solely on bytes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from requester_commitment import IDENTITY_LIMITATION_CAVEAT, verify_requester_commitment


# ---------------------------------------------------------------------------
# Known sets
# ---------------------------------------------------------------------------

TERMINAL_STATES = frozenset({
    "completed",
    "policy_denied",
    "request_invalid",
    "backend_error",
    "transport_error",
    "client_cancelled",
    "timed_out",
    "evidence_unavailable",
})

OBSERVATION_POINTS = frozenset({
    "gateway_ingress",
    "serving_host_ingress",
    "backend_dispatch",
    "client_egress",
})

GATEWAY_OBSERVATION_POINTS = frozenset({
    "gateway_ingress",
})

HOST_OBSERVATION_POINTS = frozenset({
    "serving_host_ingress",
    "backend_dispatch",
    "client_egress",
})

#: Mutuality axis (docs/ASSURANCE-VOCABULARY.md §5, capsule_sidecar.py's
#: existing cross_party_rung vocabulary) — reused verbatim, not reforked.
#: Ordering: UNILATERAL_FALLBACK < FULL_BILATERAL. This record family has no
#: separate client-acknowledgment step (that is #1233/capsule_sidecar.py's
#: Move 4, a different mechanism), so ``acknowledged_receipt`` is not a value
#: this deriver produces — the requester's rung-2 commitment IS the evidence,
#: and either it verifies or it does not.
UNILATERAL_FALLBACK = "unilateral_fallback"
FULL_BILATERAL = "full_bilateral"

# IDENTITY_LIMITATION_CAVEAT is imported above from requester_commitment —
# see its docstring there for the full rationale ([mesh-rung12-adversarial-
# review] D1): full_bilateral proves a commitment was made and matches this
# record, never that an independent party made it. derive_cross_party_rung()
# below attaches it automatically whenever it returns FULL_BILATERAL.


def derive_cross_party_rung(
    requester_commitment: dict[str, Any] | None,
    *,
    request_digest: str,
    exchange_id: str,
) -> tuple[str, bool, str, str | None]:
    """Derive cross_party_rung from the requester_commitment's own bytes.

    Returns (rung, commitment_valid, reason, identity_limitation). The rung
    is DERIVED here, never read off a producer-asserted label — there is no
    such label in the record to trust in the first place;
    ``requester_commitment`` is evidence, and this function IS the
    derivation, exactly the discipline capsule_sidecar.derive_cross_party_rung()
    already established for the #1233 receipt tuple.

    full_bilateral
        The record carries a requester_commitment whose signature verifies
        under its own embedded public key AND whose request_digest and
        exchange_id match this record's own values. ``identity_limitation``
        is ALWAYS populated (IDENTITY_LIMITATION_CAVEAT) alongside this rung
        — see that constant's docstring for why: this check cannot and does
        not confirm the key belongs to a second, independent party.

    unilateral_fallback
        No commitment, or a commitment present but invalid (bad signature,
        wrong key, or bound to a different request/exchange). Invalid
        evidence is never worth partial credit — it is treated identically
        to absent evidence, matching capsule_sidecar.py's own rule that a
        present-but-invalid bilateral evaluation still yields
        unilateral_fallback. ``identity_limitation`` is None here.
    """
    valid, reason = verify_requester_commitment(
        requester_commitment,
        expected_request_digest=request_digest,
        expected_exchange_id=exchange_id,
    )
    rung = FULL_BILATERAL if valid else UNILATERAL_FALLBACK
    identity_limitation = IDENTITY_LIMITATION_CAVEAT if rung == FULL_BILATERAL else None
    return rung, valid, reason, identity_limitation


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RecordVerificationError(Exception):
    """Base class for record-side verification failures."""


class MissingLifecycleBlock(RecordVerificationError):
    """The record does not contain an x-mesh-lifecycle-v1 block."""


class UnknownTerminalState(RecordVerificationError):
    """terminal_state value is not in the known set of eight states."""


class UnknownObservationPoint(RecordVerificationError):
    """observation_point value is not in the known set of four points."""


class IncompleteTranscriptError(RecordVerificationError):
    """The transcript claims complete=True but event_count < expected_count.

    This is the error the guard exists to raise.  Proving it fires requires:
    1. Show a record with complete=True, event_count=3, expected_count=8.
    2. Show a naive verifier (no guard) returns complete=True — the lie passes.
    3. Add the guard — show the same record raises IncompleteTranscriptError.
    Step 2 uses verify_transcript_naive(); step 3 uses verify_transcript().
    """


class VantagePointConflict(RecordVerificationError):
    """A record claims a gateway observation point but a non-gateway peer_id,
    or vice versa — indicating a provenance conflict."""


class MissingExchangeId(RecordVerificationError):
    """The record's x-mesh-lifecycle-v1 block has no exchange_id, or it is
    an empty string.

    [mesh-rung12-adversarial-review] D2 — exchange_id is the correlator two
    records of an exchange are joined on AND the value a rung-2
    requester_commitment is bound against. Defaulting an absent value to ""
    would let any two records that both omit exchange_id collapse onto the
    same fixed correlator (a latent splice risk if request_digest were ever
    also degenerate). Fail closed instead: a record MUST set a real
    exchange_id to be verified at all.
    """


# ---------------------------------------------------------------------------
# Verdict dataclass
# ---------------------------------------------------------------------------

@dataclass
class LifecycleVerdict:
    """Structured verdict produced by reading only record bytes.

    Every field is extracted from the x-mesh-lifecycle-v1 block.  Nothing is
    inferred from context outside the record.
    """

    terminal_state: str
    terminal_reason: str | None
    observation_point: str | None
    exchange_id: str
    hop_id: str
    attempt: int
    local_peer_id: str
    transcript_event_count: int
    transcript_expected_count: int | None
    transcript_complete: bool
    cross_party_rung: str
    requester_commitment_present: bool
    requester_commitment_valid: bool
    requester_commitment_reason: str
    identity_limitation: str | None
    findings: list[str] = field(default_factory=list)

    def is_joinable_with(self, other: "LifecycleVerdict") -> bool:
        """True if two records are records of the SAME exchange (joinable)."""
        return self.exchange_id == other.exchange_id

    def is_distinguishable_from(self, other: "LifecycleVerdict") -> bool:
        """True if two records are records from DIFFERENT vantage points.

        Two records of the same exchange must differ in at least one of
        (observation_point, hop_id, attempt, local_peer_id) to be
        distinguishable as different vantage points.
        """
        return (
            self.observation_point != other.observation_point
            or self.hop_id != other.hop_id
            or self.attempt != other.attempt
            or self.local_peer_id != other.local_peer_id
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_lifecycle_block(record: dict[str, Any]) -> dict[str, Any]:
    """Pull the x-mesh-lifecycle-v1 block from the record dict.

    Capsules emitted by agent_action_capsule.emit() nest compute_attestation
    under model_attestation.compute_attestation, not at the top level.
    """
    ma = record.get("model_attestation") or {}
    ca = ma.get("compute_attestation") or {}
    block = ca.get("x-mesh-lifecycle-v1")
    if block is None:
        raise MissingLifecycleBlock(
            "Record has no model_attestation.compute_attestation"
            "['x-mesh-lifecycle-v1'] block. "
            "This record was not emitted by mesh_record_emitter.emit_lifecycle_record()."
        )
    return block


def _check_terminal_state(value: str | None) -> str:
    if value is None:
        raise UnknownTerminalState("terminal_state is null in the record.")
    if value not in TERMINAL_STATES:
        raise UnknownTerminalState(
            f"terminal_state={value!r} is not one of the eight known states: "
            f"{sorted(TERMINAL_STATES)}"
        )
    return value


def _check_observation_point(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in OBSERVATION_POINTS:
        raise UnknownObservationPoint(
            f"observation_point={value!r} is not one of the four known points: "
            f"{sorted(OBSERVATION_POINTS)}"
        )
    return value


# ---------------------------------------------------------------------------
# Transcript completeness — two variants for the before/after demonstration
# ---------------------------------------------------------------------------

def verify_transcript_naive(block: dict[str, Any]) -> bool:
    """NAIVE verifier: trusts the record's complete flag without checking
    internal consistency.  Used in the deliberately-broken test to show the
    lie passes BEFORE the guard is present.

    Returns the raw value of transcript.complete.
    """
    transcript = block.get("transcript") or {}
    return bool(transcript.get("complete", False))


def verify_transcript(block: dict[str, Any]) -> bool:
    """GUARDED verifier: checks internal consistency of the transcript block.

    If complete=True but event_count < expected_count, raises
    IncompleteTranscriptError — catching any record where the producer
    asserted completeness for a truncated or overflowed transcript.

    Returns True only when complete=True AND the count check passes.
    """
    transcript = block.get("transcript") or {}
    complete = bool(transcript.get("complete", False))
    event_count = int(transcript.get("event_count", 0))
    expected_count = transcript.get("expected_count")

    if complete and expected_count is not None:
        if event_count < int(expected_count):
            raise IncompleteTranscriptError(
                f"Transcript completeness invariant violated in record bytes: "
                f"complete=True but event_count={event_count} < "
                f"expected_count={expected_count}. "
                f"This record claims a complete transcript for a truncated or "
                f"overflowed observation sequence."
            )
    return complete


# ---------------------------------------------------------------------------
# Vantage-point provenance check
# ---------------------------------------------------------------------------

def check_vantage_point_provenance(
    observation_point: str | None,
    local_peer_id: str,
) -> list[str]:
    """Check whether observation_point is consistent with local_peer_id's role.

    Returns a list of finding strings (empty if no issues).  The findings are
    informational — the verifier records them rather than raising, because the
    spec rule is about presentation ("must not present as proof from the
    serving target"), not about static field consistency.

    The hard integrity check is at the trace level in the rig; here we detect
    the residue in the record bytes: a record whose local_peer_id suggests a
    non-gateway node but whose observation_point is gateway_ingress is
    suspicious and should be flagged.
    """
    findings: list[str] = []
    if observation_point in GATEWAY_OBSERVATION_POINTS:
        if not local_peer_id.startswith("gateway"):
            findings.append(
                f"Provenance warning: observation_point={observation_point!r} is a "
                f"gateway observation but local_peer_id={local_peer_id!r} does not "
                f"begin with 'gateway'. A record at gateway_ingress should originate "
                f"from a gateway peer, not a serving host. "
                f"(#1331: 'the host must not present a gateway observation as proof "
                f"from the serving target')"
            )
    return findings


# ---------------------------------------------------------------------------
# Main verifier entry point
# ---------------------------------------------------------------------------

def verify_record_bytes(
    record_bytes: bytes,
    *,
    require_known_terminal_state: bool = True,
    require_known_observation_point: bool = True,
    check_provenance: bool = True,
) -> LifecycleVerdict:
    """Read ONLY the record bytes and return a LifecycleVerdict.

    This is the function the 8×1 and 4×1 tables call.  No rig, no sidecar,
    no side-channel — just the bytes.

    Raises:
        json.JSONDecodeError         if bytes are not valid JSON
        MissingLifecycleBlock        if x-mesh-lifecycle-v1 is absent
        MissingExchangeId            if exchange_id is absent or empty
        UnknownTerminalState         if terminal_state not in known set
        UnknownObservationPoint      if observation_point not in known set
        IncompleteTranscriptError    if complete=True but count check fails
    """
    record = json.loads(record_bytes.decode("utf-8"))
    block = _extract_lifecycle_block(record)
    compute_attestation = (record.get("model_attestation") or {}).get("compute_attestation") or {}

    terminal_state = block.get("terminal_state")
    if require_known_terminal_state:
        terminal_state = _check_terminal_state(terminal_state)
    else:
        terminal_state = terminal_state or "unknown"

    observation_point = block.get("observation_point")
    if require_known_observation_point and observation_point is not None:
        observation_point = _check_observation_point(observation_point)

    exchange_id = block.get("exchange_id")
    if not exchange_id:
        raise MissingExchangeId(
            "x-mesh-lifecycle-v1.exchange_id is missing or empty. "
            "exchange_id is the correlator two records of an exchange are "
            "joined on and the value a rung-2 requester_commitment is bound "
            "against — a record must set a real value, not rely on a "
            "default. This record was not emitted by "
            "mesh_record_emitter.emit_lifecycle_record() (it requires "
            "exchange_id as a mandatory argument)."
        )
    hop_id = block.get("hop_id", "hop-0")
    attempt = int(block.get("attempt", 0))
    local_peer_id = block.get("local_peer_id", "")

    transcript = block.get("transcript") or {}
    event_count = int(transcript.get("event_count", 0))
    expected_count = transcript.get("expected_count")
    if expected_count is not None:
        expected_count = int(expected_count)

    # Guarded transcript check.
    transcript_complete = verify_transcript(block)

    # Rung-2: derive cross_party_rung from the requester_commitment's own
    # bytes, bound against this record's own agent_input_digest and
    # exchange_id — never against a claim the commitment makes about itself.
    requester_commitment = block.get("requester_commitment")
    cross_party_rung, commitment_valid, commitment_reason, identity_limitation = derive_cross_party_rung(
        requester_commitment,
        request_digest=compute_attestation.get("agent_input_digest", ""),
        exchange_id=exchange_id,
    )

    findings: list[str] = []
    if check_provenance and observation_point:
        findings.extend(
            check_vantage_point_provenance(observation_point, local_peer_id)
        )

    return LifecycleVerdict(
        terminal_state=terminal_state,
        terminal_reason=block.get("terminal_reason"),
        observation_point=observation_point,
        exchange_id=exchange_id,
        hop_id=hop_id,
        attempt=attempt,
        local_peer_id=local_peer_id,
        transcript_event_count=event_count,
        transcript_expected_count=expected_count,
        transcript_complete=transcript_complete,
        cross_party_rung=cross_party_rung,
        requester_commitment_present=requester_commitment is not None,
        requester_commitment_valid=commitment_valid,
        requester_commitment_reason=commitment_reason,
        identity_limitation=identity_limitation,
        findings=findings,
    )


def verify_record_bytes_naive(record_bytes: bytes) -> bool:
    """Naive check: returns the raw complete flag without the consistency guard.

    Used ONLY for the deliberately-broken test's "before" phase to show the
    lie passes before the guard is introduced.  The same _extract_lifecycle_block
    path is used — the only difference is verify_transcript_naive() vs
    verify_transcript().
    """
    record = json.loads(record_bytes.decode("utf-8"))
    block = _extract_lifecycle_block(record)
    return verify_transcript_naive(block)
