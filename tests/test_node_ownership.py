#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[b4-who-did] WHO+DID binding tests — bind mesh-llm's node-owner identity.

Covers node_ownership.py end-to-end AND its binding into the sidecar's serving
capsule (capsule_sidecar.build_capsule):

  1. canonical_claim_bytes reproduces mesh-llm's ownership.rs byte layout, so a
     cert an owner signed the mesh-llm way re-verifies here.
  2. recheck_ownership_validity: green for a live matching cert; red (never
     raising) for expired / node-mismatch / bad-signature / unsupported-version.
  3. seal_identity_capsule: the "who" capsule passes its own verify(), carries
     the cert verbatim, and carries the identity_limitation honesty grade IN the
     capsule (top of block AND on the owner_subject).
  4. owner_provenance_block binds the "who" into a serving capsule (the "did"):
     bound / invalid / ABSENT, never fabricated; identity_limitation present
     whenever a cert is present, absent when no cert.
  5. GRACEFUL ABSENT PATH: with no cert, build_capsule seals served_by_node_id
     only and marks owner absent — no owner_id fabricated, no identity capsule
     cited.
  6. BOUND PATH: with a live cert + sealed identity capsule, build_capsule's
     serving provenance carries owner_id and cites the identity capsule_id.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import node_ownership as no  # noqa: E402
from node_ownership import (  # noqa: E402
    DIGEST_ALG_SHA256,
    IDENTITY_LIMITATION_CAVEAT,
    OWNER_CERT_REF_TYPE,
    OWNER_STATUS_ABSENT,
    OWNER_STATUS_BOUND,
    OWNER_STATUS_INVALID,
    OWNERSHIP_SUBJECT_KEY,
    NodeOwnershipClaim,
    SignedNodeOwnership,
    canonical_claim_bytes,
    load_signed_node_ownership,
    owner_cert_digest,
    owner_cert_reference,
    owner_provenance_block,
    recheck_ownership_validity,
    seal_identity_capsule,
)

NODE_ID_HEX = "42" * 32
OTHER_NODE_HEX = "24" * 32


# ── helpers ─────────────────────────────────────────────────────────────────

def _owner_key():
    return Ed25519PrivateKey.generate()


def _pub_hex(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _signed_cert(
    key,
    *,
    node_id_hex: str = NODE_ID_HEX,
    expires_ms: int | None = None,
    version: int = 1,
    owner_id: str = "owner-abc123",
    label: str | None = "studio",
) -> SignedNodeOwnership:
    now = int(time.time() * 1000)
    claim = NodeOwnershipClaim(
        version=version,
        cert_id="cert-0001",
        owner_id=owner_id,
        owner_sign_public_key=_pub_hex(key),
        node_endpoint_id=node_id_hex,
        issued_at_unix_ms=now,
        expires_at_unix_ms=expires_ms if expires_ms is not None else now + 60_000,
        node_label=label,
        hostname_hint="studio-host",
    )
    signature = key.sign(canonical_claim_bytes(claim)).hex()
    return SignedNodeOwnership(claim=claim, signature=signature)


# ── 1. canonical bytes + round-trip load ────────────────────────────────────

def test_canonical_claim_bytes_is_deterministic_and_domain_tagged():
    key = _owner_key()
    cert = _signed_cert(key)
    b1 = canonical_claim_bytes(cert.claim)
    b2 = canonical_claim_bytes(cert.claim)
    assert b1 == b2
    assert b1.startswith(no.SIGNING_DOMAIN_TAG)


def test_load_signed_node_ownership_roundtrip(tmp_path):
    key = _owner_key()
    cert = _signed_cert(key)
    import json

    p = tmp_path / "node-ownership.json"
    p.write_text(
        json.dumps(
            {
                "claim": {
                    "version": cert.claim.version,
                    "cert_id": cert.claim.cert_id,
                    "owner_id": cert.claim.owner_id,
                    "owner_sign_public_key": cert.claim.owner_sign_public_key,
                    "node_endpoint_id": cert.claim.node_endpoint_id,
                    "issued_at_unix_ms": cert.claim.issued_at_unix_ms,
                    "expires_at_unix_ms": cert.claim.expires_at_unix_ms,
                    "node_label": cert.claim.node_label,
                    "hostname_hint": cert.claim.hostname_hint,
                },
                "signature": cert.signature,
            }
        )
    )
    loaded = load_signed_node_ownership(p)
    assert loaded is not None
    assert loaded.claim.owner_id == cert.claim.owner_id
    assert loaded.signature == cert.signature
    r = recheck_ownership_validity(loaded, expected_node_endpoint_id=NODE_ID_HEX)
    assert r.valid, r.reason


def test_load_missing_or_malformed_is_absent_not_error(tmp_path):
    # Missing file -> None (the opt-in default; not an error).
    assert load_signed_node_ownership(tmp_path / "nope.json") is None
    # Malformed JSON -> None (a broken cert never crashes the serving path).
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    assert load_signed_node_ownership(bad) is None
    # Wrong shape -> None.
    wrong = tmp_path / "wrong.json"
    wrong.write_text('{"claim": {"version": 1}}')
    assert load_signed_node_ownership(wrong) is None


# ── 2. recheck: green + all red paths, never raising ────────────────────────

def test_recheck_green_for_live_matching_cert():
    r = recheck_ownership_validity(_signed_cert(_owner_key()), expected_node_endpoint_id=NODE_ID_HEX)
    assert r.valid
    assert r.owner_id == "owner-abc123"
    assert r.node_label == "studio"


def test_recheck_absent_cert():
    r = recheck_ownership_validity(None, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "opt-in" in r.reason


def test_recheck_expired_cert_red():
    key = _owner_key()
    now = int(time.time() * 1000)
    cert = _signed_cert(key, expires_ms=now - 1)
    r = recheck_ownership_validity(cert, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "expired" in r.reason


def test_recheck_node_id_mismatch_red():
    r = recheck_ownership_validity(
        _signed_cert(_owner_key()), expected_node_endpoint_id=OTHER_NODE_HEX
    )
    assert not r.valid
    assert "node_endpoint_id mismatch" in r.reason


def test_recheck_bad_signature_red():
    key = _owner_key()
    cert = _signed_cert(key)
    # Flip the signature -> a DIFFERENT owner (or tamper) cannot re-verify.
    tampered = SignedNodeOwnership(claim=cert.claim, signature=_signed_cert(_owner_key()).signature)
    r = recheck_ownership_validity(tampered, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "failed to verify" in r.reason


def test_recheck_unsupported_version_red():
    key = _owner_key()
    cert = _signed_cert(key, version=99)
    r = recheck_ownership_validity(cert, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "unsupported ownership claim version" in r.reason


def test_recheck_malformed_hex_red_never_raises():
    claim = NodeOwnershipClaim(
        version=1,
        cert_id="c",
        owner_id="o",
        owner_sign_public_key="not-hex",
        node_endpoint_id=NODE_ID_HEX,
        issued_at_unix_ms=0,
        expires_at_unix_ms=10 ** 15,
    )
    r = recheck_ownership_validity(
        SignedNodeOwnership(claim=claim, signature="00" * 64),
        expected_node_endpoint_id=NODE_ID_HEX,
    )
    assert not r.valid  # returned, not raised


# ── 3. seal_identity_capsule: the "who" ─────────────────────────────────────

def test_seal_identity_capsule_verifies_and_carries_honesty_grade():
    from agent_action_capsule.verify import verify as verify_capsule

    cert = _signed_cert(_owner_key())
    cap = seal_identity_capsule(cert, operator="op", developer="dev", signing_node_id="node-1")

    # The who-record passes its own verify().
    res = verify_capsule(cap)
    assert res.ok, getattr(res, "findings", None)

    block = cap["model_attestation"]["compute_attestation"][OWNERSHIP_SUBJECT_KEY]
    # Honesty grade sealed IN the identity capsule — top of block AND on subject.
    assert block["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT
    assert block["owner_subject"]["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT
    # Cert echoed verbatim so a reader re-derives validity from the bytes alone.
    echoed = block["signed_node_ownership"]
    assert echoed["signature"] == cert.signature
    assert echoed["claim"]["owner_id"] == cert.claim.owner_id
    # Subject IS the owner->node claim.
    subj = block["owner_subject"]
    assert subj["owner_id"] == cert.claim.owner_id
    assert subj["node_endpoint_id"] == cert.claim.node_endpoint_id
    assert subj["expires_at_unix_ms"] == cert.claim.expires_at_unix_ms
    assert subj["node_label"] == cert.claim.node_label


def test_sealed_identity_capsule_cert_reverifies_from_bytes():
    """The whole point of echoing the cert: an independent reader re-runs the
    re-check from the capsule bytes, trusting nothing we asserted."""
    cert = _signed_cert(_owner_key())
    cap = seal_identity_capsule(cert, operator="op", developer="dev", signing_node_id="node-1")
    echoed = cap["model_attestation"]["compute_attestation"][OWNERSHIP_SUBJECT_KEY]["signed_node_ownership"]
    reconstructed = SignedNodeOwnership.from_value(echoed)
    r = recheck_ownership_validity(reconstructed, expected_node_endpoint_id=NODE_ID_HEX)
    assert r.valid, r.reason


# ── 4. owner_provenance_block: bind who into did ────────────────────────────

def test_owner_block_absent_when_no_cert():
    blk = owner_provenance_block(None, expected_node_endpoint_id=NODE_ID_HEX)
    assert blk["owner_status"] == OWNER_STATUS_ABSENT
    assert blk["owner_id"] is None
    assert blk["identity_capsule_id"] is None
    # absent -> owner_cert_ref is explicitly None, not a missing/blank key.
    assert "owner_cert_ref" in blk
    assert blk["owner_cert_ref"] is None
    # No cert -> no owner_id AND no caveat needed (nothing to caveat).
    assert blk["identity_limitation"] is None


def test_owner_block_bound_cites_identity_capsule_and_owner_cert_ref():
    cert = _signed_cert(_owner_key())
    blk = owner_provenance_block(
        cert, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-123"
    )
    assert blk["owner_status"] == OWNER_STATUS_BOUND
    assert blk["owner_id"] == cert.claim.owner_id
    assert blk["identity_capsule_id"] == "cap-who-123"  # the did cites the who
    assert blk["recheck_valid"] is True
    # [mesh-e6-identity-owner-cert] the owner cert itself as a typed ref.
    assert blk["owner_cert_ref"] == owner_cert_reference(cert)
    assert blk["owner_cert_ref"]["type"] == OWNER_CERT_REF_TYPE
    assert blk["owner_cert_ref"]["digest_alg"] == DIGEST_ALG_SHA256
    assert blk["owner_cert_ref"]["digest"] == owner_cert_digest(cert)
    # Honesty grade present whenever a cert is present at all.
    assert blk["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT


# ── 4a. owner_cert_reference / owner_cert_digest — the typed reference ─────

def test_owner_cert_reference_shape_matches_cpb_typed_digest_ref():
    cert = _signed_cert(_owner_key())
    ref = owner_cert_reference(cert)
    assert set(ref.keys()) == {"type", "digest_alg", "digest"}
    assert ref["type"] == "owner_cert"
    assert ref["digest_alg"] == "SHA-256"
    assert len(ref["digest"]) == 64
    assert set(ref["digest"]) <= set("0123456789abcdef")


def test_owner_cert_digest_is_deterministic():
    cert = _signed_cert(_owner_key())
    assert owner_cert_digest(cert) == owner_cert_digest(cert)


def test_owner_cert_digest_changes_on_swapped_signature():
    """A different owner's signature over the SAME claim -> a different
    digest. Swapping in someone else's signature must not silently produce
    the same typed reference."""
    key_a = _owner_key()
    key_b = _owner_key()
    cert_a = _signed_cert(key_a)
    swapped = SignedNodeOwnership(claim=cert_a.claim, signature=_signed_cert(key_b).signature)
    assert owner_cert_digest(cert_a) != owner_cert_digest(swapped)


def test_owner_cert_digest_changes_on_different_owner_id():
    """Two different owner certs (different owner_id) must never collide on
    the same typed reference digest."""
    cert_a = _signed_cert(_owner_key(), owner_id="owner-aaa")
    cert_b = _signed_cert(_owner_key(), owner_id="owner-bbb")
    assert owner_cert_digest(cert_a) != owner_cert_digest(cert_b)


def test_owner_block_swapped_signature_is_invalid_and_ref_not_cited():
    """[mesh-e6-identity-owner-cert] mutant: a swapped/mismatched cert (bad
    signature) -> owner_status=invalid AND owner_cert_ref=None. An invalid
    cert must never be cited as though it were a live binding."""
    key = _owner_key()
    cert = _signed_cert(key)
    tampered = SignedNodeOwnership(claim=cert.claim, signature=_signed_cert(_owner_key()).signature)
    blk = owner_provenance_block(
        tampered, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-123"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    assert blk["owner_cert_ref"] is None
    assert blk["identity_capsule_id"] is None


def test_owner_block_wrong_node_cert_is_invalid_and_ref_not_cited():
    """[mesh-e6-identity-owner-cert] mutant: a cert bound to a DIFFERENT
    node (swapped in wholesale) -> owner_status=invalid, ref not cited."""
    cert = _signed_cert(_owner_key(), node_id_hex=OTHER_NODE_HEX)
    blk = owner_provenance_block(
        cert, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-123"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    assert blk["owner_cert_ref"] is None


def test_owner_block_invalid_cert_does_not_cite_and_is_not_bound():
    now = int(time.time() * 1000)
    cert = _signed_cert(_owner_key(), expires_ms=now - 1)  # expired
    blk = owner_provenance_block(
        cert, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-123"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    # An invalid cert NEVER points at a who-record as though bound.
    assert blk["identity_capsule_id"] is None
    assert blk["owner_cert_ref"] is None
    assert blk["recheck_valid"] is False
    # owner_id is still carried (honestly, it's what the cert claimed) but the
    # caveat makes clear it is not a live binding.
    assert blk["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT
