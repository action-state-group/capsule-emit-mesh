# SPDX-License-Identifier: Apache-2.0
"""Shared helper: mint a REAL, verifiable COSE Receipt for stub-TS test
doubles ([stamp-authenticity-on-read-not-presence]).

Before this fix, every stub Transparency Service in this test suite
returned literal garbage for ``receipt_b64``
(``base64.b64encode(b"stub-receipt-not-a-real-cose-receipt")``) — which made
every "successfully witnessed" checkpoint built in tests byte-for-byte
indistinguishable from a file-forger's fabricated stamp. Once
``grade()``/``verify_bundle`` actually check stamp authenticity, tests that
exercise a genuinely-witnessed checkpoint need their stub TS to mint a real,
structurally valid COSE_Sign1 Receipt (RFC 9162 SHA-256, via
``scitt_cose.build_receipt``) — this module is that, using a fixed
per-process test-only Ed25519 keypair so tests can also exercise the
stronger pubkey-pinned verification path.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from scitt_cose import build_receipt

from capsule_emit.checkpoint.cose_wire import verify_checkpoint_cose_offline

#: The CLL CheckpointRecord fields a signature covers -- MUST match
#: ``capsule_emit.checkpoint.emit.CheckpointRecord.signing_body()`` /
#: capsule-anchor's ``_CHECKPOINT_RECORD_FIELDS`` field-for-field.
_CHECKPOINT_SIGNING_FIELDS = (
    "v",
    "kind",
    "log_id",
    "mmr_size",
    "root",
    "prev_size",
    "prev_root",
    "key_id",
    "timestamp",
)


def checkpoint_entry_hash(cp: dict) -> str:
    """Reproduce capsule-anchor's ``/checkpoints`` ``entry_hash`` derivation
    for a posted ``CheckpointRecord`` dict: ``sha256(bytes.fromhex(digest))``
    where ``digest`` is ``sha256`` of the checkpoint's own canonical signing
    body (sorted-key, compact-separator JSON). A stub-TS handler uses this to
    mint a matching ``entry_hash``/receipt for whatever checkpoint
    ``capsule_emit.checkpoint.emit.register_checkpoint`` posts to
    ``/checkpoints``."""
    body = {k: cp[k] for k in _CHECKPOINT_SIGNING_FIELDS}
    signing_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(signing_body).hexdigest()
    return hashlib.sha256(bytes.fromhex(digest)).hexdigest()


def checkpoint_dict_from_cose(cose_bytes: bytes) -> dict:
    """Decode+verify a COSE-wire checkpoint (real signature check, same as
    what capsule-anchor's witness route will independently do) and
    reconstruct the JSON ``CheckpointRecord``-shaped dict a stub-TS
    ``do_POST`` handler's own ``checkpoint_entry_hash``/receipt logic
    expects -- the wire body ``capsule_emit.checkpoint.emit
    .register_checkpoint`` now POSTs to ``/checkpoints`` is real COSE_Sign1/
    CBOR bytes, not a plain JSON dict ([cll-checkpoint-cose-wire]). Raises
    ``ValueError`` if the COSE statement does not verify."""
    result = verify_checkpoint_cose_offline(cose_bytes)
    if not result.ok:
        raise ValueError(f"stub TS could not verify COSE checkpoint: {result.errors}")
    return result.decoded.to_checkpoint_record().to_dict()


_TEST_TS_PRIVATE_KEY = Ed25519PrivateKey.generate()

#: PEM of the fixed test TS keypair -- for tests that want the full
#: pubkey-pinned ``verify_witness_stamp_offline(..., ts_pubkey_pem=...)`` path.
TEST_TS_PRIVATE_KEY_PEM = _TEST_TS_PRIVATE_KEY.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
)
TEST_TS_PUBLIC_KEY_PEM = _TEST_TS_PRIVATE_KEY.public_key().public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
)


def build_stub_receipt_b64(entry_hash: str) -> str:
    """Mint a real, single-leaf COSE Receipt over ``entry_hash`` with the
    fixed test TS key, base64-encoded -- a drop-in replacement for the old
    garbage stub bytes in a stub-TS HTTP handler's response."""
    receipt_bytes = build_receipt(
        leaf_entry_hex=entry_hash,
        leaf_index=0,
        tree_entries_hex=[entry_hash],
        alg="EdDSA",
        log_private_key_pem=TEST_TS_PRIVATE_KEY_PEM,
    )
    return base64.b64encode(receipt_bytes).decode()
