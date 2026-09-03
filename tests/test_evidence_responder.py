# SPDX-License-Identifier: Apache-2.0
"""Tests for E14's sidecar wiring — ``evidence_responder.handle_evidence_request``.

These exercise the REAL responder core (``capsule_emit.evidence_request
.answer``) against a real ``capsule_sidecar.NodeState``'s ledger + signing
key — confirming the wiring (paths, key identity), not re-deriving the
responder's own decision logic (that is ``capsule-emit``'s test suite).
Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.
"""
from __future__ import annotations

import json

import pytest
from capsule_emit import seal, witness
from capsule_emit.evidence_request import Artifact, Refusal

import capsule_sidecar as cs
from evidence_responder import handle_evidence_request


@pytest.fixture(autouse=True)
def _clean_witness_state():
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False
    yield
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False


@pytest.fixture
def stub_witness(monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "stub")


@pytest.fixture
def node_state(tmp_path, stub_witness):
    # NodeState.__post_init__ loads the manifest for real; write a minimal one.
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
    )
    return state


def _record_request(capsule_id: str) -> bytes:
    return json.dumps({"subject": {"kind": "record", "capsule_id": capsule_id}, "coverage": {}}).encode()


def _resolve_signer(state):
    from capsule_emit.signing import resolve_signer

    return resolve_signer(str(state.ledger_path), key_path=state.signing_key_path)


def test_handle_evidence_request_uses_the_sidecar_own_ledger_and_key(node_state):
    caps = [
        seal(
            None,
            action=f"act-{i}",
            operator="acme",
            anchor=False,
            ledger=node_state.ledger_path,
            signing_key_path=node_state.signing_key_path,
        ).capsule
        for i in range(2)
    ]
    cp = witness.push(str(node_state.ledger_path), signer=_resolve_signer(node_state))
    assert cp is not None

    result = handle_evidence_request(node_state, _record_request(caps[0]["capsule_id"]))
    assert isinstance(result, Artifact)
    assert result.bundles[0].capsule_id == caps[0]["capsule_id"]


def test_handle_evidence_request_refusal_signed_with_node_key(node_state):
    result = handle_evidence_request(node_state, _record_request("ff" * 32))
    assert isinstance(result, Refusal)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(node_state.signing_key_path.read_bytes(), password=None)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    node_public_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert result.key_id == node_public_hex

    from capsule_emit.evidence_request import verify_refusal_offline

    assert verify_refusal_offline(result)


def test_handle_evidence_request_caller_invariance(node_state):
    caps = [
        seal(
            None,
            action=f"act-{i}",
            operator="acme",
            anchor=False,
            ledger=node_state.ledger_path,
            signing_key_path=node_state.signing_key_path,
        ).capsule
        for i in range(2)
    ]
    witness.push(str(node_state.ledger_path), signer=_resolve_signer(node_state))
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    req_a = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "a"}).encode()
    req_b = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "b"}).encode()

    result_a = handle_evidence_request(node_state, req_a, now=now)
    result_b = handle_evidence_request(node_state, req_b, now=now)
    assert json.dumps(result_a.to_dict(), sort_keys=True) == json.dumps(result_b.to_dict(), sort_keys=True)
