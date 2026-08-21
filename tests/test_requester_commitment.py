#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rung-2 requester request-commitment tests.

PURPOSE
    Prove the gap docs/TRUST-MODEL.md flags as "Not built" (P1: "the receipt
    tuple has no requester identity field at all") is closed for the
    exchange_id-correlated record family (mesh_record_emitter.py /
    mesh_record_verifier.py), without blurring rung-1 (a nonce; equivocation
    resistance, anonymous) into rung-2 (a signed commitment; identity,
    request binding, and an authorization bound).

WHAT IS TESTED
    1. UNIT: requester_commitment.py's make/verify round-trips, and every
       forged-evidence case (bad signature, wrong key, wrong request_digest,
       wrong exchange_id) is individually rejected with a reason, not a
       crash.
    2. RED-BEFORE-GREEN: a record with NO commitment, and a record with an
       INVALID commitment, must both fail to reach full_bilateral — shown as
       the mutant a naive "commitment present → trust it" verifier would
       pass, and the guarded verifier catches.
    3. TWO-NODE EXCHANGE: an ingress record and a completion record sharing
       one exchange_id both carry the requester bound into their own half —
       proving the binding survives across hops, not just within one record.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mesh_record_emitter import (  # noqa: E402
    capsule_to_bytes,
    default_node_state,
    emit_lifecycle_record,
    make_transcript_summary,
)
from mesh_record_verifier import (  # noqa: E402
    FULL_BILATERAL,
    UNILATERAL_FALLBACK,
    verify_record_bytes,
)
from requester_commitment import (  # noqa: E402
    RequesterKey,
    make_requester_commitment,
    verify_requester_commitment,
)


REQUEST_DIGEST = "a" * 64
EXCHANGE_ID = "exchange-rung2-0001"


# ===========================================================================
# 1. UNIT — requester_commitment.py round-trip and forged-evidence rejection
# ===========================================================================

class TestCommitmentUnit:
    def test_valid_commitment_verifies(self) -> None:
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        valid, reason = verify_requester_commitment(
            commitment,
            expected_request_digest=REQUEST_DIGEST,
            expected_exchange_id=EXCHANGE_ID,
        )
        assert valid, reason

    def test_missing_commitment_is_not_valid(self) -> None:
        valid, reason = verify_requester_commitment(
            None, expected_request_digest=REQUEST_DIGEST
        )
        assert not valid
        assert "no requester commitment" in reason

    def test_mutant_tampered_signature_rejected(self) -> None:
        """Flip a byte in the signature — must fail, never crash."""
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        good_sig = bytes.fromhex(commitment["signature"])
        tampered = bytes([good_sig[0] ^ 0xFF]) + good_sig[1:]
        commitment["signature"] = tampered.hex()

        valid, reason = verify_requester_commitment(
            commitment, expected_request_digest=REQUEST_DIGEST
        )
        assert not valid, "tampered signature must not verify"
        assert "signature" in reason

    def test_mutant_wrong_key_signs_but_claims_original_pubkey(self) -> None:
        """A different key signs; the commitment still claims the original
        requester's public key — signature must fail under that key."""
        key = RequesterKey.generate()
        attacker_key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        forged_sig = attacker_key.sign(
            bytes.fromhex(commitment["signature"])  # arbitrary different bytes
        )
        commitment["signature"] = forged_sig.hex()

        valid, reason = verify_requester_commitment(
            commitment, expected_request_digest=REQUEST_DIGEST
        )
        assert not valid, "a signature from a different key must not verify"

    def test_mutant_request_digest_mismatch_rejected(self) -> None:
        """A commitment signed over ONE request must not verify against a
        DIFFERENT request_digest — the exact forged-binding case."""
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        valid, reason = verify_requester_commitment(
            commitment, expected_request_digest="b" * 64
        )
        assert not valid, "a commitment must not verify against a different request_digest"
        assert "request_digest mismatch" in reason

    def test_mutant_exchange_id_mismatch_rejected(self) -> None:
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        valid, reason = verify_requester_commitment(
            commitment,
            expected_request_digest=REQUEST_DIGEST,
            expected_exchange_id="some-other-exchange",
        )
        assert not valid, "a commitment must not verify against a different exchange_id"
        assert "exchange_id mismatch" in reason

    def test_mutant_malformed_commitment_does_not_raise(self) -> None:
        """A commitment missing required keys is a verification RESULT, not
        an exception — the verifier must be able to read the rest of an
        adversarial record without crashing."""
        valid, reason = verify_requester_commitment(
            {"type": "x-mesh-requester-commitment/1"},
            expected_request_digest=REQUEST_DIGEST,
        )
        assert not valid
        assert "malformed" in reason


# ===========================================================================
# 2. RED-BEFORE-GREEN — the assurance label must never be silently upgraded
# ===========================================================================

class TestAssuranceLabelNeverSilentlyUpgraded:
    def _emit(self, *, node, requester_commitment=None, request_digest=REQUEST_DIGEST):
        return emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id=EXCHANGE_ID,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=request_digest,
            requester_commitment=requester_commitment,
        )

    def test_no_commitment_stays_unilateral_fallback(self) -> None:
        node = default_node_state()
        capsule = self._emit(node=node, requester_commitment=None)
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.cross_party_rung == UNILATERAL_FALLBACK
        assert verdict.requester_commitment_present is False
        assert verdict.requester_commitment_valid is False

    def test_valid_commitment_reaches_full_bilateral(self) -> None:
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        capsule = self._emit(node=node, requester_commitment=commitment)
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.cross_party_rung == FULL_BILATERAL, verdict.requester_commitment_reason
        assert verdict.requester_commitment_present is True
        assert verdict.requester_commitment_valid is True

    def test_mutant_invalid_commitment_does_not_reach_full_bilateral(self) -> None:
        """A present-but-forged commitment (wrong signature) must NOT upgrade
        the rung — this is the RED-before-green case the task exists to
        prove: a naive verifier that checks only 'is a commitment present'
        would wrongly report full_bilateral here."""
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        # Naive check the guard replaces: "presence alone" would pass this.
        assert commitment is not None, "sanity: the forged case still has a present commitment"

        # Corrupt the signature after signing — simulates a replayed/forged commitment.
        bad_byte = bytes.fromhex(commitment["signature"])
        commitment["signature"] = (bytes([bad_byte[0] ^ 0xFF]) + bad_byte[1:]).hex()

        capsule = self._emit(node=node, requester_commitment=commitment)
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.requester_commitment_present is True, "commitment IS present in the record"
        assert verdict.cross_party_rung == UNILATERAL_FALLBACK, (
            "an invalid commitment must not reach full_bilateral — "
            f"got {verdict.cross_party_rung!r}"
        )

    def test_mutant_commitment_bound_to_different_request_does_not_upgrade(self) -> None:
        """A commitment that is perfectly valid — but signed over a DIFFERENT
        request_digest than this record's own — must not reach full_bilateral.
        This is the forged-binding case: an attacker replaying a legitimate
        signed commitment from a different request onto this record."""
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest="c" * 64, exchange_id=EXCHANGE_ID
        )
        capsule = self._emit(
            node=node, requester_commitment=commitment, request_digest=REQUEST_DIGEST
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.requester_commitment_present is True
        assert verdict.cross_party_rung == UNILATERAL_FALLBACK, (
            "a commitment bound to a different request_digest must not "
            f"upgrade this record — got {verdict.cross_party_rung!r}"
        )
        assert "request_digest mismatch" in verdict.requester_commitment_reason


# ===========================================================================
# 3. TWO-NODE EXCHANGE — requester bound into BOTH halves
# ===========================================================================

class TestTwoNodeExchange:
    def test_ingress_and_completion_both_carry_the_requester(self) -> None:
        """One exchange_id, two records (ingress + completion, different
        observation_point/hop), the SAME requester commitment (same
        exchange_id and request_digest — one request travels through both
        hops) bound into both halves and independently verified in each."""
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )

        gateway_node = default_node_state("gateway-A")
        host_node = default_node_state("serving-host-A")

        ingress = emit_lifecycle_record(
            gateway_node,
            terminal_state="completed",
            observation_point="gateway_ingress",
            exchange_id=EXCHANGE_ID,
            hop_id="hop-0",
            local_peer_id="gateway-A",
            transcript=make_transcript_summary(1, 1),
            request_digest=REQUEST_DIGEST,
            requester_commitment=commitment,
        )
        completion = emit_lifecycle_record(
            host_node,
            terminal_state="completed",
            observation_point="client_egress",
            exchange_id=EXCHANGE_ID,
            hop_id="hop-1",
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=REQUEST_DIGEST,
            requester_commitment=commitment,
        )

        ingress_verdict = verify_record_bytes(capsule_to_bytes(ingress))
        completion_verdict = verify_record_bytes(capsule_to_bytes(completion))

        # Joinable: same exchange.
        assert ingress_verdict.is_joinable_with(completion_verdict)
        # Distinguishable: different vantage points.
        assert ingress_verdict.is_distinguishable_from(completion_verdict)

        # The requester is bound into BOTH halves independently.
        assert ingress_verdict.cross_party_rung == FULL_BILATERAL
        assert completion_verdict.cross_party_rung == FULL_BILATERAL
        assert ingress_verdict.requester_commitment_valid is True
        assert completion_verdict.requester_commitment_valid is True

    def test_completion_alone_cannot_be_upgraded_by_a_foreign_exchanges_commitment(self) -> None:
        """A commitment valid for a DIFFERENT exchange_id must not bind into
        this exchange's completion record — exchange_id is the correlator,
        and a verifier must check it, not assume it."""
        key = RequesterKey.generate()
        foreign_commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id="some-other-exchange"
        )
        node = default_node_state()
        completion = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="client_egress",
            exchange_id=EXCHANGE_ID,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=REQUEST_DIGEST,
            requester_commitment=foreign_commitment,
        )
        verdict = verify_record_bytes(capsule_to_bytes(completion))

        assert verdict.cross_party_rung == UNILATERAL_FALLBACK
        assert "exchange_id mismatch" in verdict.requester_commitment_reason
