"""witness_pin: Mesh pins the default witness's key itself, because
checkpointed-local-log 0.5+ trusts only caller-supplied witness keys."""
from __future__ import annotations

import base64

from capsule_emit.checkpoint import StampVerdict
from capsule_emit.checkpoint import emit as checkpoint_emit_mod
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose import build_receipt

from capsule_mesh_viewer import verify_witness_checkpoint
from test_capsule_mesh_viewer import _entry_hash_for, _real_checkpoint_dict
from witness_pin import default_witness_pin

DEFAULT = "https://witness.agentactioncapsule.org"


def _key():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def _checkpoint_witnessed_by(ts_url: str, private_pem: bytes) -> dict:
    checkpoint = _real_checkpoint_dict()
    entry_hash = _entry_hash_for(checkpoint)
    receipt = build_receipt(
        leaf_entry_hex=entry_hash, leaf_index=0, tree_entries_hex=[entry_hash], alg="EdDSA",
        log_private_key_pem=private_pem,
    )
    checkpoint["witnesses"] = [
        {"ts_url": ts_url, "entry_hash": entry_hash, "receipt_b64": base64.b64encode(receipt).decode(),
         "leaf_index": 0, "tree_size": 1}
    ]
    return checkpoint


def test_only_the_default_witness_is_pinned(monkeypatch):
    _, public = _key()
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_URL", "https://witness.example")
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_PUBLIC_KEY_PEM", public)
    assert default_witness_pin("https://witness.example") == public
    assert default_witness_pin("https://other.example") is None
    assert default_witness_pin(None) is None


def test_viewer_grades_the_default_witness_witnessed_under_its_key(monkeypatch):
    private, public = _key()
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_URL", DEFAULT)
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_PUBLIC_KEY_PEM", public)
    verdict, errors = verify_witness_checkpoint(_checkpoint_witnessed_by(DEFAULT, private))
    assert verdict is StampVerdict.WITNESSED, errors


def test_viewer_grades_an_impostor_of_the_default_witness_invalid(monkeypatch):
    _, public = _key()
    impostor, _ = _key()
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_URL", DEFAULT)
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_PUBLIC_KEY_PEM", public)
    verdict, errors = verify_witness_checkpoint(_checkpoint_witnessed_by(DEFAULT, impostor))
    assert verdict is StampVerdict.INVALID
    assert errors
