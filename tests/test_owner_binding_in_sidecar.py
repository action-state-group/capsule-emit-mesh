#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[b4-who-did] The WHO+DID binding as it lands in the sidecar serving capsule.

These tests drive the REAL capsule_sidecar.build_capsule() and assert on the
owner block it seals into x-mesh-poc-v1 provenance:

  GRACEFUL ABSENT (default): no cert -> served_by_node_id sealed, owner ABSENT,
    no owner_id fabricated, no identity capsule cited, no stray caveat.
  BOUND: live matching cert + a sealed identity capsule -> owner_id sealed and
    the identity capsule_id cited (the did cites the who), honesty grade present.
  INVALID: expired cert -> owner not bound, identity capsule NOT cited.
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

import capsule_sidecar as cs  # noqa: E402
import node_ownership as no  # noqa: E402
from node_ownership import (  # noqa: E402
    IDENTITY_LIMITATION_CAVEAT,
    OWNER_STATUS_ABSENT,
    OWNER_STATUS_BOUND,
    OWNER_STATUS_INVALID,
    NodeOwnershipClaim,
    SignedNodeOwnership,
    canonical_claim_bytes,
)

NODE_ID_HEX = "42" * 32


def _cert(*, expires_ms: int | None = None) -> SignedNodeOwnership:
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    now = int(time.time() * 1000)
    claim = NodeOwnershipClaim(
        version=1,
        cert_id="cert-1",
        owner_id="owner-zzz",
        owner_sign_public_key=pub_hex,
        node_endpoint_id=NODE_ID_HEX,
        issued_at_unix_ms=now,
        expires_at_unix_ms=expires_ms if expires_ms is not None else now + 60_000,
        node_label="studio",
        hostname_hint="host",
    )
    return SignedNodeOwnership(claim=claim, signature=key.sign(canonical_claim_bytes(claim)).hex())


def _make_state(**overrides) -> cs.NodeState:
    import json

    d = pathlib.Path(tempfile.mkdtemp())
    # NodeState.__post_init__ loads the manifest for real; write a minimal one.
    (d / "manifest.json").write_text(
        json.dumps(
            {
                "model_id": "m/1",
                "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"},
                "skippy_abi_version": "1",
            }
        )
    )
    kwargs = dict(
        node_id="mesh-node-demo-1",
        operator="op",
        developer="dev",
        signing_key_pem=b"unused",
        signing_key_path=d / "keys" / "node-key.pem",
        manifest_path=d / "manifest.json",
        runtime_label="rt",
        runtime_digest="0" * 64,
        ledger_dir=d / "ledger",
    )
    kwargs.update(overrides)
    return cs.NodeState(**kwargs)


def _build(state) -> dict:
    return cs.build_capsule(
        state,
        client_nonce="n",
        client_nonce_source="client_supplied",
        request_json={"model": "m", "temperature": 0.7},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )


def _owner_block(capsule) -> dict:
    return capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["owner"]


def _served_by(capsule) -> str:
    # served_by_node_id lives in the reconciliation block; the capsule always
    # seals the endpoint id regardless of owner presence.
    poc = capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    return poc["advertisement_reconciliation"]["served_node_id"]


# ── graceful absent (default) ───────────────────────────────────────────────

def test_serving_capsule_owner_absent_by_default():
    """No cert configured -> the did (served_by_node_id) is sealed, the who is
    ABSENT, and nothing is fabricated."""
    state = _make_state()  # node_ownership defaults to None
    assert state.node_ownership is None
    cap = _build(state)

    # The did is still sealed.
    assert _served_by(cap) == "mesh-node-demo-1"

    blk = _owner_block(cap)
    assert blk["owner_status"] == OWNER_STATUS_ABSENT
    assert blk["owner_id"] is None
    assert blk["identity_capsule_id"] is None
    # No cert -> no honesty-grade caveat needed (nothing self-asserted).
    assert blk["identity_limitation"] is None
    # The whole capsule still verifies.
    from agent_action_capsule.verify import verify as verify_capsule

    assert verify_capsule(cap).ok


# ── bound path (opt-in cert present) ────────────────────────────────────────

def test_serving_capsule_binds_owner_and_cites_identity_capsule():
    cert = _cert()
    state = _make_state(node_ownership=cert)
    # __post_init__ defaults the expected endpoint id from the cert.
    assert state.owner_node_endpoint_id == NODE_ID_HEX
    # Simulate startup having sealed the identity capsule.
    state.identity_capsule_id = "cap-who-abc"

    cap = _build(state)
    blk = _owner_block(cap)
    assert blk["owner_status"] == OWNER_STATUS_BOUND
    assert blk["owner_id"] == "owner-zzz"
    assert blk["identity_capsule_id"] == "cap-who-abc"  # did cites who
    assert blk["node_label"] == "studio"
    assert blk["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT
    # did still sealed alongside the who.
    assert _served_by(cap) == "mesh-node-demo-1"

    from agent_action_capsule.verify import verify as verify_capsule

    assert verify_capsule(cap).ok


def test_serving_capsule_expired_cert_not_bound_and_not_cited():
    now = int(time.time() * 1000)
    cert = _cert(expires_ms=now - 1)
    state = _make_state(node_ownership=cert)
    state.identity_capsule_id = "cap-who-abc"

    cap = _build(state)
    blk = _owner_block(cap)
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    # Expired cert must NOT be presented as a live binding.
    assert blk["identity_capsule_id"] is None
    assert blk["recheck_valid"] is False
    assert blk["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT


# ── startup sealing helper ──────────────────────────────────────────────────

def test_maybe_seal_identity_capsule_records_and_sets_id(monkeypatch):
    """maybe_seal_identity_capsule seals + records the who-capsule and sets
    state.identity_capsule_id so serving capsules can cite it."""
    recorded = {}

    def fake_sign(state, capsule):
        return b"signed-bytes"

    def fake_record(state, capsule, signed):
        recorded["capsule"] = capsule
        recorded["signed"] = signed

    monkeypatch.setattr(cs, "sign_capsule", fake_sign)
    monkeypatch.setattr(cs, "record_capsule", fake_record)

    cert = _cert()
    state = _make_state(node_ownership=cert)
    cap_id = cs.maybe_seal_identity_capsule(state)

    assert cap_id is not None
    assert state.identity_capsule_id == cap_id
    assert recorded["capsule"]["capsule_id"] == cap_id
    # No cert -> returns None, sets nothing.
    state2 = _make_state()
    assert cs.maybe_seal_identity_capsule(state2) is None


# ── rung 3b: tee_key_custody wiring ──────────────────────────────────────────

def _real_signing_key_pem() -> bytes:
    """_make_state()'s default `b"unused"` is not a parseable PEM (fine for
    tests that never touch signing); rung 3b needs a real Ed25519 key so
    tee_key_custody actually gets computed."""
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _tee_block(capsule) -> dict:
    return capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["tee_key_custody"]


def test_serving_capsule_cites_tee_key_custody_computed_once():
    """A real signing key -> state.tee_key_custody is populated at
    __post_init__ time, and build_capsule() CITES that same block (does not
    re-sign per capsule)."""
    state = _make_state(signing_key_pem=_real_signing_key_pem())
    assert state.tee_key_custody is not None
    assert state.tee_key_custody["custody"] in ("secure_enclave", "software")
    assert "tee_protected" in state.tee_key_custody

    cap1 = _build(state)
    cap2 = _build(state)
    assert _tee_block(cap1) == state.tee_key_custody
    assert _tee_block(cap2) == state.tee_key_custody, "must cite the SAME cached attestation, not re-sign"


def test_placeholder_signing_key_degrades_to_no_tee_block():
    """The `b"unused"` placeholder used by tests that never sign must not
    crash NodeState construction -- it degrades to tee_key_custody=None,
    never a fabricated claim."""
    state = _make_state()  # default signing_key_pem=b"unused" (not a real PEM)
    assert state.tee_key_custody is None
    cap = _build(state)
    assert _tee_block(cap) is None


def test_identity_capsule_carries_tee_key_custody(monkeypatch):
    """The sealed "who" identity capsule also carries the tee_key_custody
    block (rung 3b binds the node identity itself, not only serving
    capsules)."""
    recorded = {}
    monkeypatch.setattr(cs, "sign_capsule", lambda state, capsule: b"signed-bytes")
    monkeypatch.setattr(cs, "record_capsule", lambda state, capsule, signed: recorded.update(capsule=capsule))

    cert = _cert()
    state = _make_state(node_ownership=cert, signing_key_pem=_real_signing_key_pem())
    cs.maybe_seal_identity_capsule(state)

    who = recorded["capsule"]["model_attestation"]["compute_attestation"][no.OWNERSHIP_SUBJECT_KEY]
    assert who["tee_key_custody"] == state.tee_key_custody
    assert who["tee_key_custody"]["tee_protected"] in (True, False)
