#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-verify DIRECTION helper (inline signature envelope):
have the PYTHON reference PRODUCE a COSE_Sign1 producer envelope so the RUST
verifier can be pointed at it. This is the missing direction: the conformance
oracle only ever had Python (and Go) verify a Rust-produced envelope; this lets
Rust verify a Python-produced one -- and, critically, a NON-CANONICAL one.

REGENERATOR ONLY -- DO NOT CALL FROM THE TEST. The Rust test
``rust_verifies_a_python_produced_noncanonical_envelope`` loads a COMMITTED
fixture (``tests/fixtures/python_produced_noncanonical_envelope.hex``), it does
NOT invoke this script. Run this ONCE to (re)generate that fixture -- a stored
insertion-order envelope that Rust verifies is a golden vector for as-received
behavior and stays useful even if the Python reference later moves to canonical
order. See ``tests/fixtures/README.md`` for the exact regeneration command and
the known seed/digest/kid values.

The Python ``LocalKeypairSigner.sign_envelope`` (reused here via the same
``scitt_cose.cose_sign1.sign_sign1`` machinery) emits the protected-header map
in INSERTION order (3, 4, 1): it sets ``{3: content_type, 4: kid}`` and lets
``sign_sign1`` append the forced ``alg`` (label 1) LAST. That is a NON-canonical
CBOR map order (RFC 9052 §9 requires 1, 3, 4) -- exactly the header Rust must
accept as-received.

Usage:
    produce_python_envelope.py <seed_hex_32B> <digest_hex_32B> <out_envelope_path>

Writes the raw COSE_Sign1 (CBOR tag 18) bytes to <out_envelope_path> and prints
one JSON line describing the produced envelope, including the observed
protected-header key order, so the caller can ASSERT it is non-canonical.
"""
from __future__ import annotations

import json
import sys

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE
from scitt_cose.cose_sign1 import sign_sign1

COSE_SIGN1_TAG = 18


def main() -> int:
    seed_hex, digest_hex, out_path = sys.argv[1:4]

    seed = bytes.fromhex(seed_hex)
    digest = bytes.fromhex(digest_hex)

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    key_id = public_key.public_bytes_raw()  # raw 32-byte Ed25519 public key
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    # The frozen AAC producer-envelope profile, built EXACTLY as
    # LocalKeypairSigner.sign_envelope does: protected = {3: media_type, 4: kid},
    # then sign_sign1 sets protected[1] = alg LAST -> insertion order (3, 4, 1).
    protected = {3: CAPSULE_ID_MEDIA_TYPE, 4: key_id}
    envelope = sign_sign1(
        digest,
        alg="EdDSA",
        private_key_pem=private_pem,
        protected=protected,
        unprotected={},
    )

    with open(out_path, "wb") as fh:
        fh.write(envelope)

    # Read back the protected-header key order straight off the wire so the
    # caller can prove it is the NON-canonical (3, 4, 1) order.
    decoded = cbor2.loads(envelope)
    tag = decoded.tag if isinstance(decoded, cbor2.CBORTag) else None
    protected_bstr = decoded.value[0] if isinstance(decoded, cbor2.CBORTag) else decoded[0]
    protected_map = cbor2.loads(protected_bstr) if protected_bstr else {}
    order = list(protected_map.keys())

    print(
        json.dumps(
            {
                "tag": tag,
                "protected_key_order": order,
                "key_id_hex": key_id.hex(),
                "envelope_len": len(envelope),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
