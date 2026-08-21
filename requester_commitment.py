#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Requester request-commitment — rung-2 of the client capability ladder.

docs/TRUST-MODEL.md §1 draws the ladder: rung-0 (nothing), rung-1 (a fresh
unpredictable nonce — equivocation resistance, still anonymous), rung-2 (the
requester signs a commitment over the exact request — identity, request
binding, and an authorization bound arrive together). This module is rung-2.

THE COMMITMENT
    The requester signs, over the exact bytes the node digests into
    ``request_digest``:
        {type, request_digest, nonce, exchange_id, public_key}
    ``nonce`` still buys freshness (rung-1's property) — signing over it does
    not collapse the two-step ladder into one; it is what lets a rung-2
    commitment also stand in for rung-1 when both are checked. ``exchange_id``
    ties the commitment to a specific two-node exchange, reusing the
    correlator the record format already has rather than inventing a second
    one.

NON-CONFORMANT IDENTITY (same caveat as bilateral_demo.py / capsule_sidecar.py)
    The requester key here is self-generated and self-held — an identifier,
    not a vouched identity. draft-mih-agent-bilateral-attestation-01 §4.1
    requires a credential chaining to a root the relying party accepts and
    says first-use acceptance of a bare key MUST NOT be treated as conformant.
    This module gives pseudonymous accountability (a stable identity that
    asked), not attribution to a person. See TRUST-MODEL.md §4.1.

VERIFICATION NEVER RAISES
    verify_requester_commitment() returns (valid, reason) rather than
    throwing — a missing or forged commitment is a verification RESULT the
    assurance ladder must be able to represent, not an exception that aborts
    reading the rest of the record.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Type tag carried inside the commitment, mirroring the request-attestation
#: shape already used by bilateral_demo.py's Move 1 (request_digest + nonce,
#: signed) — same fields, same meaning, a different type tag because this
#: commitment additionally carries exchange_id for the exchange_id-correlated
#: record family (mesh_record_emitter.py / mesh_record_verifier.py) rather
#: than the single-hop #1233 receipt tuple.
COMMITMENT_TYPE = "x-mesh-requester-commitment/1"


def _jcs(obj: dict[str, Any]) -> bytes:
    """JSON Canonical Serialization (RFC 8785): sorted keys, no whitespace.

    Same convention as delegation_chain_verifier.py's _jcs() — one signing
    convention for hex-keyed Ed25519 commitments across this repo.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass
class RequesterKey:
    """An Ed25519 keypair the requester signs commitments with.

    Self-generated and self-held — see the module docstring's identity
    caveat. Encoded as raw hex bytes (delegation_chain_verifier.py's
    convention), not PEM.
    """

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "RequesterKey":
        return cls(private_key=Ed25519PrivateKey.generate())

    @property
    def public_key_hex(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def make_requester_commitment(
    key: RequesterKey,
    *,
    request_digest: str,
    exchange_id: str,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Rung-2: sign a commitment over the exact request the node digests.

    ``request_digest`` MUST be the same digest the node computes and carries
    as the record's own request digest — the verifier's job is to confirm
    they match, not to trust that they do.
    """
    body: dict[str, Any] = {
        "type": COMMITMENT_TYPE,
        "request_digest": request_digest,
        "exchange_id": exchange_id,
        "nonce": nonce or uuid.uuid4().hex,
        "public_key": key.public_key_hex,
    }
    signature = key.sign(_jcs(body))
    return {**body, "signature": signature.hex()}


def verify_requester_commitment(
    commitment: dict[str, Any] | None,
    *,
    expected_request_digest: str,
    expected_exchange_id: str | None = None,
) -> tuple[bool, str]:
    """Verify a requester commitment. Returns (valid, reason) — never raises.

    Checks, in order: the commitment is present and well-formed; the Ed25519
    signature over the commitment body (minus ``signature``) verifies under
    the embedded public key; ``request_digest`` matches the record's own
    digest of the same bytes the node digested; and, when the caller supplies
    one, ``exchange_id`` matches too. A producer MUST NOT claim a rung this
    function does not confirm — the assurance label is DERIVED from this
    result, never asserted.
    """
    if commitment is None:
        return False, "no requester commitment present"

    if commitment.get("type") != COMMITMENT_TYPE:
        return False, f"unrecognized commitment type: {commitment.get('type')!r}"

    try:
        sig_hex = commitment["signature"]
        pub_hex = commitment["public_key"]
    except KeyError as exc:
        return False, f"malformed commitment: missing {exc}"

    body = {k: v for k, v in commitment.items() if k != "signature"}

    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pubkey.verify(bytes.fromhex(sig_hex), _jcs(body))
    except InvalidSignature:
        return False, "signature verification failed"
    except (ValueError, TypeError) as exc:
        return False, f"malformed key or signature: {exc}"

    if commitment.get("request_digest") != expected_request_digest:
        return False, (
            f"request_digest mismatch: commitment attests "
            f"{commitment.get('request_digest')!r}, record's own digest is "
            f"{expected_request_digest!r}"
        )

    if expected_exchange_id is not None and commitment.get("exchange_id") != expected_exchange_id:
        return False, (
            f"exchange_id mismatch: commitment attests "
            f"{commitment.get('exchange_id')!r}, record's exchange_id is "
            f"{expected_exchange_id!r}"
        )

    return True, "requester commitment verified: signature valid, bound to request_digest"
