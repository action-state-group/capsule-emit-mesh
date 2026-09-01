#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for requester_identity_binding.py — the module that closes the
zero-effort self-mint gap in mesh_record_verifier.derive_cross_party_rung()
([mesh-rung12-adversarial-review] D1). See test_requester_commitment.py's
TestIdentityBindingClosesTheSelfMintGap for the verifier-integration/
adversarial coverage; this file is unit-level, round-trip and mutant testing
of make_requester_identity_binding() / verify_requester_identity_binding()
in isolation, matching test_requester_commitment.py's TestCommitmentUnit and
test_node_ownership.py's style for their respective sibling mechanisms.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from requester_commitment import RequesterKey  # noqa: E402
from requester_identity_binding import (  # noqa: E402
    IDENTITY_LIMITATION_CAVEAT,
    RequesterIdentityKey,
    make_requester_identity_binding,
    verify_requester_identity_binding,
)

NOW_MS = 1_800_000_000_000
FAR_FUTURE_MS = NOW_MS + 365 * 24 * 60 * 60 * 1000


def _commitment_public_key() -> str:
    return RequesterKey.generate().public_key_hex


class TestRoundTrip:
    def test_valid_binding_verifies(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert verdict.valid, verdict.reason
        assert verdict.owner_id == "owner-1"
        assert verdict.cert_id == binding["cert_id"]

    def test_missing_binding_is_not_valid(self) -> None:
        verdict = verify_requester_identity_binding(
            None, expected_commitment_public_key=_commitment_public_key(), now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "no requester identity binding" in verdict.reason

    def test_auto_generated_cert_id_and_issued_at(self) -> None:
        """cert_id and issued_at_unix_ms default sensibly when omitted."""
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        assert binding["cert_id"]
        assert isinstance(binding["issued_at_unix_ms"], int)
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key
        )
        assert verdict.valid, verdict.reason


class TestMutants:
    def test_tampered_signature_rejected(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        good_sig = bytes.fromhex(binding["signature"])
        binding["signature"] = (bytes([good_sig[0] ^ 0xFF]) + good_sig[1:]).hex()

        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "signature" in verdict.reason

    def test_wrong_key_signs_but_claims_original_owner_key(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        attacker_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        forged_sig = attacker_key.sign(bytes.fromhex(binding["signature"]))
        binding["signature"] = forged_sig.hex()

        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert not verdict.valid

    def test_key_substitution_owner_id_still_bound_to_the_signing_key(self) -> None:
        """Mirrors REDTEAM-RUNG2.md's B4 attack #10: keep owner_id but embed
        + sign with an ATTACKER's identity key over a commitment the
        attacker controls. Internally consistent -- signature checks out --
        but this only ever proves binding to whichever key signed it, never
        that owner_id is the real party (see IDENTITY_LIMITATION_CAVEAT)."""
        commitment_key = _commitment_public_key()
        attacker_identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            attacker_identity_key,
            owner_id="victim-owner-id",  # claims someone else's label
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        # Structurally this DOES verify -- self-consistent, signed by the
        # embedded key -- which is exactly why IDENTITY_LIMITATION_CAVEAT
        # exists: owner_id is a self-asserted label, never verified against
        # a real identity.
        assert verdict.valid, verdict.reason
        assert verdict.owner_id == "victim-owner-id"

    def test_commitment_public_key_mismatch_rejected(self) -> None:
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=_commitment_public_key(),
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=_commitment_public_key(), now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "commitment_public_key mismatch" in verdict.reason

    def test_expired_binding_rejected(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS - 2_000,
            expires_at_unix_ms=NOW_MS - 1_000,
        )
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "expired" in verdict.reason

    def test_unsupported_version_rejected(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        binding["version"] = 2
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "unsupported" in verdict.reason

    def test_wrong_type_rejected(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        binding["type"] = "x-mesh-requester-commitment/1"  # a different artifact's tag
        verdict = verify_requester_identity_binding(
            binding, expected_commitment_public_key=commitment_key, now_unix_ms=NOW_MS
        )
        assert not verdict.valid
        assert "unrecognized" in verdict.reason

    def test_malformed_binding_does_not_raise(self) -> None:
        commitment_key = _commitment_public_key()
        verdict = verify_requester_identity_binding(
            {
                "type": "x-mesh-requester-identity-binding/1",
                "version": 1,
                "commitment_public_key": commitment_key,
            },
            expected_commitment_public_key=commitment_key,
            now_unix_ms=NOW_MS,
        )
        assert not verdict.valid
        assert "malformed" in verdict.reason

    def test_revoked_cert_id_rejected(self) -> None:
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            cert_id="cert-abc",
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        verdict = verify_requester_identity_binding(
            binding,
            expected_commitment_public_key=commitment_key,
            now_unix_ms=NOW_MS,
            revoked_cert_ids=frozenset({"cert-abc"}),
        )
        assert not verdict.valid
        assert "revoked" in verdict.reason

    def test_revocation_set_only_affects_listed_cert_ids(self) -> None:
        """A non-empty revocation set must not reject certs NOT on it."""
        commitment_key = _commitment_public_key()
        identity_key = RequesterIdentityKey.generate()
        binding = make_requester_identity_binding(
            identity_key,
            owner_id="owner-1",
            commitment_public_key=commitment_key,
            cert_id="cert-innocent",
            issued_at_unix_ms=NOW_MS,
            expires_at_unix_ms=FAR_FUTURE_MS,
        )
        verdict = verify_requester_identity_binding(
            binding,
            expected_commitment_public_key=commitment_key,
            now_unix_ms=NOW_MS,
            revoked_cert_ids=frozenset({"cert-someone-else"}),
        )
        assert verdict.valid, verdict.reason


class TestCaveat:
    def test_caveat_states_self_asserted_and_zero_effort_scope(self) -> None:
        """The caveat text must not overclaim -- it should name both what
        this module closes (zero-effort inline self-mint) and what it does
        not (an attacker who also self-registers an identity)."""
        assert "self-asserted" in IDENTITY_LIMITATION_CAVEAT
        assert "zero-effort" in IDENTITY_LIMITATION_CAVEAT
        assert "does not" in IDENTITY_LIMITATION_CAVEAT
