#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Milestone 2 anchor-client conformance oracle: verify a COSE Receipt this
crate's `AnchorClient` obtained from a real `capsule-anchor` instance --
independent of the Rust code that requested it -- using `scitt_cose`'s own
inclusion-proof verifier.

Usage:
    verify_anchor_receipt.py <receipt_b64> <entry_hash_hex> <authority_pubkey_hex>

`entry_hash_hex` is capsule-anchor's own documented offline-verification
value: SHA256(bytes.fromhex(capsule_id)) -- the CT log entry hash the
inclusion proof covers (see capsule_anchor.anchoring.router's `/v1/digest`
docstring).

Prints one JSON line: {"ok": bool, "errors": [...], "error": str|null}.
Exit 0 iff ok.
"""
from __future__ import annotations

import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scitt_cose import verify_receipt


def main() -> int:
    receipt_b64, entry_hash_hex, pubkey_hex = sys.argv[1:4]
    out = {"ok": False, "errors": [], "error": None}
    try:
        receipt_bytes = base64.b64decode(receipt_b64)
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pubkey_pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        result = verify_receipt(
            receipt_bytes,
            leaf_entry_hex=entry_hash_hex,
            log_public_key_pem=pubkey_pem,
        )
        out["ok"] = result.ok
        out["errors"] = list(result.errors)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the oracle
        out["error"] = f"{type(exc).__name__}: {exc}"

    print(json.dumps(out))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
