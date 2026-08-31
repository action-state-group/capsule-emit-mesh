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
    state = cs.NodeState(
        node_id="mesh-node-demo-1",
        operator="op",
        developer="dev",
        signing_key_pem=b"unused",
        signing_key_path=d / "keys" / "node-key.pem",
        manifest_path=d / "manifest.json",
        runtime_label="rt",
        runtime_digest="0" * 64,
        ledger_dir=d / "ledger",
        **overrides,
    )
    return state


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
