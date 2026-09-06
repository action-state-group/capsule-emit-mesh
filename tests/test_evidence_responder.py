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
import tempfile

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
    checkpoint_config_path = tmp_path / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )
    return state


def _record_request(capsule_id: str) -> bytes:
    return json.dumps({"subject": {"kind": "record", "capsule_id": capsule_id}, "coverage": {}}).encode()


def _resolve_signer(state):
    from capsule_emit.signing import resolve_signer

    return resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path)


def _seal_into_sidecar_store(state, *, action: str) -> dict:
    """Mint a well-formed capsule via capsule_emit's own ``seal()`` (a
    convenient, already-verified builder), but land it in the sidecar's
    REAL cll.ledger.store.LedgerStore -- ``state.log_source`` -- rather than
    capsule_emit's own flat-file+in-band-checkpoint-stamp convention.
    ``seal()`` still needs a ``ledger=`` to write its own copy to; a scratch
    tempfile it owns exclusively (never read back) satisfies that without
    colliding with the store this test actually asserts against."""
    scratch_ledger = tempfile.mktemp(suffix="-capsule-emit-seal-scratch.jsonl")
    capsule = seal(
        None,
        action=action,
        operator="acme",
        anchor=False,
        ledger=scratch_ledger,
        signing_key_path=state.signing_key_path,
    ).capsule
    state.log_source.append(capsule)
    return capsule


def test_handle_evidence_request_uses_the_sidecar_own_ledger_and_key(node_state):
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(2)]
    # bundle() needs an in-band checkpoint to answer a `record` subject --
    # materialize_flat_view synthesizes one from this sidecar's OWN (real,
    # out-of-band) checkpoint, so it has to actually exist first.
    assert node_state.checkpoint.reconnect() is not None

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
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(2)]
    assert node_state.checkpoint.reconnect() is not None
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    req_a = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "a"}).encode()
    req_b = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "b"}).encode()

    result_a = handle_evidence_request(node_state, req_a, now=now)
    result_b = handle_evidence_request(node_state, req_b, now=now)
    assert json.dumps(result_a.to_dict(), sort_keys=True) == json.dumps(result_b.to_dict(), sort_keys=True)
