# SPDX-License-Identifier: Apache-2.0
"""Push-a-bundle at the record-push door.

A bundle is the pushed half + its inclusion proof + the sender's signed
checkpoint covering it. The door verifies all three and, on success, holds the
proof and checkpoint as artifacts and names the verified inclusion in its reply
(what the Rust plugin cites as ``counterparty_inclusion``).

Mutants that must flip:
  - a proof for a different leaf, a tampered root, a checkpoint signed by a
    key other than the half's, or a tampered checkpoint signature ->
    ``inclusion_unverified``, and NOTHING is stored (not even the half).
  - an unknown bundle version -> ``request_malformed``.
  - a bare push still gets the old ``{"status": "received"}`` reply with no
    ``inclusion`` member (older senders keep working).
  - the Rust plugin's own bundle (committed fixture) verifies here unchanged.
"""
from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

from cll.checkpoint.core import add_leaf, inclusion_proof, leaf_hash, peaks, root_from_peaks
from cll.checkpoint.index import MemoryNodeStore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose import cll

import evidence_server as es
from peer_keys import ENV_PEER_KEYS
from record_push import (
    REASON_INCLUSION_UNVERIFIED,
    REASON_REQUEST_MALFORMED,
    RECEIVED_CAPSULES_FILENAME,
    RECEIVED_INCLUSION_FILENAME,
    RECEIVED_PROVENANCE_FILENAME,
    REJECTED_PUSHES_FILENAME,
    handle_record_push,
)

RUST_FIXTURE = Path(__file__).parent / "fixtures" / "record_push_bundle_rust.json"


def _keys(tmp_path):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    return keys_dir / NODE_KEY_FILENAME


def _signed_capsule(key_path) -> dict:
    import tempfile

    from capsule_emit import seal

    scratch = tempfile.mktemp(suffix="-bundle-seal-scratch.jsonl")
    return seal(
        None, action="serve-half", operator="acme", anchor=False, ledger=scratch, signing_key_path=key_path
    ).capsule


def _private_key(key_path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(key_path).read_bytes(), None)


def _sign_checkpoint(cp: dict, private_key: Ed25519PrivateKey) -> dict:
    digest = cll.Checkpoint.from_dict(cp).digest()
    return {**cp, "signature": private_key.sign(digest.encode("utf-8")).hex()}


def _bundle(capsule: dict, private_key: Ed25519PrivateKey, *, preceding: int = 4) -> dict:
    """The half at leaf ``preceding`` of a small log, a signed checkpoint over
    the whole log, and the half's inclusion proof -- the shape the Rust
    plugin's ``bundle_body`` produces."""
    store = MemoryNodeStore()
    ids = [hashlib.sha256(f"other-{i}".encode()).hexdigest() for i in range(preceding)]
    ids += [capsule["capsule_id"], hashlib.sha256(b"after").hexdigest()]
    for capsule_id in ids:
        add_leaf(store, leaf_hash(bytes.fromhex(capsule_id)))
    size = store.size()
    root = root_from_peaks([store.node(p) for p in peaks(size)])
    public_hex = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    checkpoint = _sign_checkpoint(
        {
            "v": 1,
            "kind": "mmr_checkpoint",
            "log_id": "sender-log",
            "mmr_size": size,
            "root": root.hex(),
            "prev_size": 0,
            "prev_root": "",
            "key_id": public_hex,
            "timestamp": "2026-09-27T00:00:00Z",
        },
        private_key,
    )
    proof = inclusion_proof(store, preceding, size)
    return {
        "record_push_bundle": 1,
        "capsule": capsule,
        "inclusion": {
            "leaf_index": preceding,
            "proof": {
                "v": proof.v,
                "kind": proof.kind,
                "size": proof.size,
                "leaf_index": proof.leaf_index,
                "witness": list(proof.witness),
                "peaks_left": list(proof.peaks_left),
                "peaks_right": list(proof.peaks_right),
            },
        },
        "checkpoint": checkpoint,
    }


def _lines(ledger_dir: Path, name: str) -> list[dict]:
    path = ledger_dir / name
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class _Setup:
    def __init__(self, tmp_path, monkeypatch):
        self.key_path = _keys(tmp_path)
        self.ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        self.ledger_path.parent.mkdir(parents=True)
        self.ledger_path.write_bytes(b"")
        self.ledger_dir = self.ledger_path.parent
        self.capsule = _signed_capsule(self.key_path)
        self.private_key = _private_key(self.key_path)
        self.state = es.EvidenceServerState(
            ledger_dir=self.ledger_dir, ledger_path=self.ledger_path, signing_key_path=self.key_path
        )
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": self.capsule["key_id"]}))

    def push(self, body: dict) -> dict:
        return handle_record_push(self.state, json.dumps(body).encode("utf-8"), sender_peer_id="m3")

    def nothing_stored(self) -> bool:
        return (
            _lines(self.ledger_dir, RECEIVED_CAPSULES_FILENAME) == []
            and _lines(self.ledger_dir, RECEIVED_PROVENANCE_FILENAME) == []
            and _lines(self.ledger_dir, RECEIVED_INCLUSION_FILENAME) == []
        )


def test_verified_bundle_is_received_holds_proof_and_checkpoint_and_names_the_inclusion(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)

    result = s.push(bundle)

    assert result["status"] == "received"
    inclusion = result["inclusion"]
    assert inclusion["half_capsule_id"] == s.capsule["capsule_id"]
    assert inclusion["leaf_index"] == 4
    assert inclusion["mmr_size"] == bundle["checkpoint"]["mmr_size"]
    assert inclusion["checkpoint_digest"] == cll.Checkpoint.from_dict(bundle["checkpoint"]).digest()
    proof = bundle["inclusion"]["proof"]
    assert inclusion["inclusion_proof_digest"] == hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    # The half is held exactly as for a bare push ...
    assert [c["capsule_id"] for c in _lines(s.ledger_dir, RECEIVED_CAPSULES_FILENAME)] == [s.capsule["capsule_id"]]
    # ... the sender's checkpoint + proof are held artifacts (peer-retained) ...
    held = _lines(s.ledger_dir, RECEIVED_INCLUSION_FILENAME)
    assert len(held) == 1
    assert held[0]["checkpoint"] == bundle["checkpoint"]
    assert held[0]["inclusion_proof"] == proof
    assert held[0]["received_from"] == "m3"
    # ... and the foreign bytes never enter our chain.
    assert s.ledger_path.read_bytes() == b""


def test_held_inclusion_reverifies_offline_from_the_artifact_alone(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    s.push(_bundle(s.capsule, s.private_key))
    held = _lines(s.ledger_dir, RECEIVED_INCLUSION_FILENAME)[0]
    result = cll.verify_leaf_against_checkpoint(
        body_digest=bytes.fromhex(held["half_capsule_id"]),
        leaf_index=held["leaf_index"],
        checkpoint=cll.Checkpoint.from_dict(held["checkpoint"]),
        proof=cll.InclusionProof.from_dict(held["inclusion_proof"]),
    )
    assert result.ok


def test_bare_push_still_gets_the_plain_reply_and_stores_no_inclusion(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    assert s.push(s.capsule) == {"status": "received"}
    assert _lines(s.ledger_dir, RECEIVED_INCLUSION_FILENAME) == []


def _assert_refused_inclusion_unverified(s: _Setup, result: dict) -> None:
    assert result["reason"] == REASON_INCLUSION_UNVERIFIED
    assert s.nothing_stored(), "a bundle that fails is refused whole -- the half is not stored either"
    rejected = _lines(s.ledger_dir, REJECTED_PUSHES_FILENAME)
    assert rejected[-1]["reason"] == REASON_INCLUSION_UNVERIFIED


def test_proof_for_a_different_leaf_is_refused(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    bundle["inclusion"]["leaf_index"] = 3
    bundle["inclusion"]["proof"]["leaf_index"] = 3
    _assert_refused_inclusion_unverified(s, s.push(bundle))


def test_tampered_checkpoint_root_is_refused(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    # Re-signed so only the proof check can catch it.
    bundle["checkpoint"] = _sign_checkpoint({**bundle["checkpoint"], "root": "0" * 64}, s.private_key)
    _assert_refused_inclusion_unverified(s, s.push(bundle))


def test_checkpoint_signed_by_another_key_is_refused(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    other = Ed25519PrivateKey.generate()
    bundle = _bundle(s.capsule, other)
    _assert_refused_inclusion_unverified(s, s.push(bundle))


def test_checkpoint_with_a_bad_signature_is_refused(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    bundle["checkpoint"]["timestamp"] = "2026-09-27T00:00:01Z"  # signature now stale
    _assert_refused_inclusion_unverified(s, s.push(bundle))


def test_bundle_with_a_mismatched_leaf_index_pair_is_refused(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    bundle["inclusion"]["leaf_index"] = 3  # proof still says 4
    _assert_refused_inclusion_unverified(s, s.push(bundle))


def test_unknown_bundle_version_is_malformed(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    bundle["record_push_bundle"] = 2
    assert s.push(bundle)["reason"] == REASON_REQUEST_MALFORMED
    assert s.nothing_stored()


def test_bundle_with_no_capsule_is_malformed(tmp_path, monkeypatch):
    s = _Setup(tmp_path, monkeypatch)
    bundle = _bundle(s.capsule, s.private_key)
    del bundle["capsule"]
    assert s.push(bundle)["reason"] == REASON_REQUEST_MALFORMED


def test_the_rust_plugins_own_bundle_verifies_at_this_door(tmp_path, monkeypatch):
    """Cross-language: ``record_push_bundle_rust.json`` is a bundle the Rust
    plugin built (`bundle_body` over a real `checkpoint_covering`); regenerate
    it with the ignored `writes_the_cross_language_bundle_fixture` test in
    `plugins/admission-policy/src/record_push_bridge.rs`."""
    fixture = json.loads(RUST_FIXTURE.read_text())
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = es.EvidenceServerState(ledger_dir=ledger_path.parent, ledger_path=ledger_path, signing_key_path=key_path)
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"rust-node": fixture["capsule"]["key_id"]}))

    result = handle_record_push(state, json.dumps(fixture).encode("utf-8"), sender_peer_id="rust-node")

    assert result["status"] == "received", result
    assert result["inclusion"]["half_capsule_id"] == fixture["capsule"]["capsule_id"]
    assert result["inclusion"]["mmr_size"] == fixture["checkpoint"]["mmr_size"]
