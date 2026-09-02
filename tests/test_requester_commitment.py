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
    ACKNOWLEDGED_RECEIPT,
    FULL_BILATERAL,
    UNILATERAL_FALLBACK,
    verify_record_bytes,
)
from requester_commitment import (  # noqa: E402
    IDENTITY_LIMITATION_CAVEAT,
    RequesterKey,
    make_requester_commitment,
    verify_requester_commitment,
)
from requester_identity_binding import (  # noqa: E402
    RequesterIdentityKey,
    make_requester_identity_binding,
)


REQUEST_DIGEST = "a" * 64
EXCHANGE_ID = "exchange-rung2-0001"
NOW_MS = 1_800_000_000_000
FAR_FUTURE_MS = NOW_MS + 365 * 24 * 60 * 60 * 1000


def _bound_commitment_and_binding(*, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID, owner_id="requester-owner-1"):
    """A genuinely-bound pair: a fresh commitment key, and a persistent
    identity key whose binding cites that exact commitment key. This is the
    "registered identity" case — the ONLY way to reach full_bilateral now."""
    commitment_key = RequesterKey.generate()
    commitment = make_requester_commitment(
        commitment_key, request_digest=request_digest, exchange_id=exchange_id
    )
    identity_key = RequesterIdentityKey.generate()
    binding = make_requester_identity_binding(
        identity_key,
        owner_id=owner_id,
        commitment_public_key=commitment["public_key"],
        issued_at_unix_ms=NOW_MS,
        expires_at_unix_ms=FAR_FUTURE_MS,
    )
    return commitment, binding


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
    def _emit(self, *, node, requester_commitment=None, requester_identity_binding=None, request_digest=REQUEST_DIGEST):
        return emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id=EXCHANGE_ID,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=request_digest,
            requester_commitment=requester_commitment,
            requester_identity_binding=requester_identity_binding,
        )

    def test_no_commitment_stays_unilateral_fallback(self) -> None:
        node = default_node_state()
        capsule = self._emit(node=node, requester_commitment=None)
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.cross_party_rung == UNILATERAL_FALLBACK
        assert verdict.requester_commitment_present is False
        assert verdict.requester_commitment_valid is False

    def test_valid_commitment_alone_reaches_only_acknowledged_receipt(self) -> None:
        """[requester-identity-binding] AFTER: a valid commitment with no
        identity binding behind its key no longer reaches full_bilateral —
        see TestIdentityBindingClosesTheSelfMintGap for the exact
        [mesh-rung12-adversarial-review] repro this closes."""
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        capsule = self._emit(node=node, requester_commitment=commitment)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT, verdict.requester_commitment_reason
        assert verdict.requester_commitment_present is True
        assert verdict.requester_commitment_valid is True
        assert verdict.requester_identity_binding_present is False
        assert verdict.identity_limitation is None

    def test_commitment_plus_identity_binding_reaches_full_bilateral(self) -> None:
        """A valid commitment WHOSE key is cited by a verified, persistent
        identity binding reaches full_bilateral — the only path there now."""
        node = default_node_state()
        commitment, binding = _bound_commitment_and_binding()
        capsule = self._emit(
            node=node, requester_commitment=commitment, requester_identity_binding=binding
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == FULL_BILATERAL, verdict.requester_identity_binding_reason
        assert verdict.requester_commitment_valid is True
        assert verdict.requester_identity_binding_present is True
        assert verdict.requester_identity_binding_valid is True
        assert verdict.requester_identity_owner_id == "requester-owner-1"


class TestIdentityLimitationCaveat:
    """[mesh-rung12-adversarial-review] D1 — a lone node can self-mint a
    fully self-consistent requester_commitment (fresh keypair, signs over
    its own record's request_digest/exchange_id) with no real requester
    ever involved.

    [requester-identity-binding, 2026-09-01] BEFORE this change that
    self-minted commitment reached full_bilateral outright (inherent, no
    external anchor — the fix was disclosure only, via this caveat). AFTER:
    a commitment with no requester_identity_binding behind its key now
    grades at acknowledged_receipt, never full_bilateral — see
    TestIdentityBindingClosesTheSelfMintGap below for the exact repro and
    what remains open. This class now covers the caveat's OWN behavior
    (present exactly when full_bilateral is reached, never otherwise).
    """

    def _emit(self, *, node, requester_commitment=None, requester_identity_binding=None, request_digest=REQUEST_DIGEST):
        return emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id=EXCHANGE_ID,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=request_digest,
            requester_commitment=requester_commitment,
            requester_identity_binding=requester_identity_binding,
        )

    def test_full_bilateral_via_identity_binding_carries_the_verifier_caveat(self) -> None:
        """A commitment reaching full_bilateral through a verified identity
        binding still carries a caveat — even a verified binding cannot
        prove owner_id corresponds to a real, independent party (see
        requester_identity_binding.IDENTITY_LIMITATION_CAVEAT)."""
        node = default_node_state()
        commitment, binding = _bound_commitment_and_binding()
        capsule = self._emit(
            node=node, requester_commitment=commitment, requester_identity_binding=binding
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == FULL_BILATERAL
        assert verdict.identity_limitation is not None, (
            "a full_bilateral verdict must always carry an identity-limitation "
            "caveat -- reaching this rung still never proves an independent party"
        )

    def test_emitted_record_carries_the_caveat_on_its_own_bytes(self) -> None:
        """The RECORD itself (not just the verifier's derived verdict) must
        state the caveat -- restores the identity_limitation label the old
        capsule_sidecar.build_capsule() path already carries, which the new
        mesh_record_emitter.py path had dropped."""
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        capsule = self._emit(node=node, requester_commitment=commitment)
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]
        assert block["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT

    def test_no_commitment_no_caveat(self) -> None:
        """unilateral_fallback makes no independent-party claim -- no
        caveat should be attached (nothing to caveat)."""
        node = default_node_state()
        capsule = self._emit(node=node, requester_commitment=None)
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]
        assert block["identity_limitation"] is None

        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.identity_limitation is None

    def test_invalid_commitment_no_caveat_on_verdict(self) -> None:
        """A present-but-invalid commitment stays unilateral_fallback --
        the verifier's derived identity_limitation must be None (it only
        applies to a rung that actually claims independent-party evidence).
        The emitted record still carries the caveat (it can't know validity
        at emit time), but the verdict must not."""
        node = default_node_state()
        key = RequesterKey.generate()
        commitment = make_requester_commitment(
            key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        bad_byte = bytes.fromhex(commitment["signature"])
        commitment["signature"] = (bytes([bad_byte[0] ^ 0xFF]) + bad_byte[1:]).hex()
        capsule = self._emit(node=node, requester_commitment=commitment)
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.cross_party_rung == UNILATERAL_FALLBACK
        assert verdict.identity_limitation is None

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
        observation_point/hop), the SAME requester commitment AND identity
        binding (same exchange_id and request_digest — one request travels
        through both hops) bound into both halves and independently
        verified in each."""
        commitment, binding = _bound_commitment_and_binding()

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
            requester_identity_binding=binding,
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
            requester_identity_binding=binding,
        )

        ingress_verdict = verify_record_bytes(capsule_to_bytes(ingress), now_unix_ms=NOW_MS)
        completion_verdict = verify_record_bytes(capsule_to_bytes(completion), now_unix_ms=NOW_MS)

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


# ===========================================================================
# 4. [requester-identity-binding] IDENTITY BINDING CLOSES THE SELF-MINT GAP
#
# TRUST-MODEL.md §4.1a / [mesh-rung12-adversarial-review] D1 disclosed that a
# lone node can mint a fresh requester_commitment keypair inline, sign a
# fully self-consistent commitment, and reach full_bilateral with no real
# requester ever involved. This section proves the exact repro now fails to
# reach full_bilateral, a genuinely-bound identity DOES reach it, a revoked
# or unrecognized identity binding degrades, and states plainly what remains
# open (an attacker who ALSO self-registers an identity — see
# requester_identity_binding.IDENTITY_LIMITATION_CAVEAT).
# ===========================================================================

class TestIdentityBindingClosesTheSelfMintGap:
    def _emit(self, *, node, requester_commitment, requester_identity_binding=None):
        return emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id=EXCHANGE_ID,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
            request_digest=REQUEST_DIGEST,
            requester_commitment=requester_commitment,
            requester_identity_binding=requester_identity_binding,
        )

    def test_exact_d1_self_mint_repro_no_longer_reaches_full_bilateral(self) -> None:
        """The exact [mesh-rung12-adversarial-review] D1 repro: the node
        mints its own fresh commitment key and signs a self-consistent
        commitment -- no identity binding at all, no real requester ever
        involved. BEFORE this change: full_bilateral (labeled). AFTER: this
        is precisely acknowledged_receipt -- the zero-effort attack fails to
        reach full_bilateral."""
        node = default_node_state("attacker-node")
        node_self_key = RequesterKey.generate()
        self_minted = make_requester_commitment(
            node_self_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        capsule = self._emit(node=node, requester_commitment=self_minted)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT, (
            f"the exact D1 self-mint repro must not reach full_bilateral -- "
            f"got {verdict.cross_party_rung!r}"
        )
        assert verdict.cross_party_rung != FULL_BILATERAL
        assert verdict.requester_identity_binding_present is False

    def test_genuinely_bound_identity_reaches_full_bilateral(self) -> None:
        """A commitment key cited by a persistent, independently-signed
        identity binding -- the honest positive case -- reaches
        full_bilateral."""
        node = default_node_state()
        commitment, binding = _bound_commitment_and_binding(owner_id="requester-owner-real")
        capsule = self._emit(node=node, requester_commitment=commitment, requester_identity_binding=binding)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == FULL_BILATERAL, verdict.requester_identity_binding_reason
        assert verdict.requester_identity_binding_valid is True
        assert verdict.requester_identity_owner_id == "requester-owner-real"

    def test_revoked_identity_binding_degrades_to_acknowledged_receipt(self) -> None:
        """A structurally valid, unexpired identity binding whose cert_id is
        on the caller-supplied revocation set must not reach full_bilateral
        -- revocation is the operator's live decision (never fabricated
        here), but once supplied it must be enforced."""
        node = default_node_state()
        commitment_key = RequesterKey.generate()
        commitment = make_requester_commitment(
            commitment_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="requester-owner-revoked",
            commitment_public_key=commitment["public_key"],
            cert_id="cert-revoked-0001",
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        capsule = self._emit(node=node, requester_commitment=commitment, requester_identity_binding=binding)
        verdict = verify_record_bytes(
            capsule_to_bytes(capsule),
            now_unix_ms=NOW_MS,
            revoked_identity_cert_ids=frozenset({"cert-revoked-0001"}),
        )

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT
        assert verdict.requester_identity_binding_present is True
        assert verdict.requester_identity_binding_valid is False
        assert "revoked" in verdict.requester_identity_binding_reason

    def test_unrecognized_identity_binding_degrades_to_acknowledged_receipt(self) -> None:
        """A present-but-unrecognized identity binding (unsupported version
        -- e.g. a future format this verifier does not understand) must not
        be treated as a trust upgrade. Unknown evidence gets no partial
        credit, same rule as an invalid requester_commitment."""
        node = default_node_state()
        commitment_key = RequesterKey.generate()
        commitment = make_requester_commitment(
            commitment_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="requester-owner-unknown-version",
            commitment_public_key=commitment["public_key"],
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        binding["version"] = 999  # a version this verifier does not understand
        capsule = self._emit(node=node, requester_commitment=commitment, requester_identity_binding=binding)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT
        assert verdict.requester_identity_binding_valid is False
        assert "unsupported" in verdict.requester_identity_binding_reason

    def test_expired_identity_binding_degrades_to_acknowledged_receipt(self) -> None:
        node = default_node_state()
        commitment_key = RequesterKey.generate()
        commitment = make_requester_commitment(
            commitment_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="requester-owner-expired",
            commitment_public_key=commitment["public_key"],
            issued_at_unix_ms=NOW_MS - 2_000,
            expires_at_unix_ms=NOW_MS - 1_000,  # already expired at NOW_MS
        )
        capsule = self._emit(node=node, requester_commitment=commitment, requester_identity_binding=binding)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT
        assert verdict.requester_identity_binding_valid is False
        assert "expired" in verdict.requester_identity_binding_reason

    def test_binding_for_a_different_commitment_key_cannot_be_replayed(self) -> None:
        """A binding minted for ONE commitment key must not upgrade a
        record carrying a DIFFERENT commitment key -- the binding-to-key
        replay case, mirroring the commitment-to-request replay guard
        above."""
        node = default_node_state()
        this_commitment_key = RequesterKey.generate()
        this_commitment = make_requester_commitment(
            this_commitment_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        other_commitment_key = RequesterKey.generate()
        other_commitment = make_requester_commitment(
            other_commitment_key, request_digest=REQUEST_DIGEST, exchange_id=EXCHANGE_ID
        )
        identity_key = RequesterIdentityKey.generate()
        binding_for_other_key = make_requester_identity_binding(
            identity_key,
            owner_id="requester-owner-1",
            commitment_public_key=other_commitment["public_key"],
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        capsule = self._emit(
            node=node, requester_commitment=this_commitment, requester_identity_binding=binding_for_other_key
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == ACKNOWLEDGED_RECEIPT
        assert verdict.requester_identity_binding_valid is False
        assert "commitment_public_key mismatch" in verdict.requester_identity_binding_reason

    def test_still_open_attacker_who_also_self_mints_the_identity_binding(self) -> None:
        """HONEST RESIDUAL, documented rather than hidden (same discipline as
        REDTEAM-RUNG2.md's B4 key-substitution case): this module closes the
        ZERO-EFFORT self-mint (no binding at all). It does NOT and cannot
        close a more determined attacker who generates BOTH a fresh
        commitment key AND a fresh identity key and signs a binding between
        them -- the identity is still self-asserted, exactly as
        node_ownership.py's owner cert is. That still reaches full_bilateral.
        Closing THIS residual requires an external trust anchor /
        third-party attestation root, out of scope for this record layer --
        see TRUST-MODEL.md §4.1a. This test exists so the residual is proven
        and visible, not silently assumed away."""
        node = default_node_state("attacker-node")
        commitment, binding = _bound_commitment_and_binding(owner_id="attacker-self-registered")
        capsule = self._emit(node=node, requester_commitment=commitment, requester_identity_binding=binding)
        verdict = verify_record_bytes(capsule_to_bytes(capsule), now_unix_ms=NOW_MS)

        assert verdict.cross_party_rung == FULL_BILATERAL, (
            "documenting the known-open residual: a fully self-registered "
            "identity still reaches full_bilateral -- see TRUST-MODEL.md §4.1a"
        )
