#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Requester identity binding — closing the self-mint gap in rung-2.

docs/TRUST-MODEL.md §4.1a / [mesh-rung12-adversarial-review] D1 disclosed a
gap in requester_commitment.py's rung-2: ``verify_requester_commitment()``
confirms a commitment's signature is internally self-consistent and bound to
a record's own ``request_digest``/``exchange_id`` — it does NOT confirm the
embedded public key belongs to anyone other than whoever produced the
record. A single actor (the node itself) can generate a FRESH throwaway
keypair inline, sign a fully self-consistent commitment, and reach
``full_bilateral`` with no real requester ever involved.

THIS MODULE does not and cannot make that impossible — there is still no
third-party-issued credential or trusted root behind any of it (that is the
Authority tier: out of scope for this record layer, see TRUST-MODEL.md
§4.1). What it closes is the ZERO-EFFORT version of the attack: a bare
commitment key with no registration step at all.

THE MECHANISM — reuses node_ownership.py's exact pattern (self-signed,
time-bounded, revocable cert; a persistent "who" a reader can independently
re-verify from bytes alone), applied to the REQUESTER side instead of the
node-owner side:

  1. A requester holds a persistent, self-generated ``RequesterIdentityKey``
     — separate from (and longer-lived than) the per-commitment key
     ``requester_commitment.RequesterKey``. This is the "who" — an identity
     that outlives any single exchange.
  2. That identity key signs a ``RequesterIdentityBinding`` claim: "the
     commitment key embedded in THIS requester_commitment belongs to
     identity ``owner_id``." The claim is bound to the commitment's own
     public key, so a binding cannot be replayed onto a different
     commitment's key.
  3. A verifier re-checks the binding's own signature, expiry, and the key
     match — structurally, never a trust decision — and, when a caller
     supplies a revocation set (the operator's live decision, never
     fabricated here), that the binding's cert_id has not been revoked.

WHAT THIS BUYS: a commitment key minted inline, in the same breath as the
record it accompanies, with nothing behind it, no longer reaches
full_bilateral — it grades at acknowledged_receipt (mesh_record_verifier.py).
Reaching full_bilateral now requires a SEPARATE, persistent identity cert
that predates the exchange and binds specifically to this commitment's key.

WHAT THIS DOES NOT BUY: a sufficiently motivated single attacker can still
self-generate BOTH the identity key AND the commitment key and produce a
binding between them — the identity itself is still self-asserted, exactly
as node_ownership.py's owner cert is (see its IDENTITY_LIMITATION_CAVEAT).
This closes the trivial/inline self-mint path the redteam review
demonstrated, not the "attacker also self-registers an identity" path,
which remains open pending an external anchor (see TRUST-MODEL.md §4.1a).
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Type tag carried inside the binding, distinguishing it from
#: requester_commitment.COMMITMENT_TYPE (a different signed artifact, over a
#: different key, with a different lifetime).
IDENTITY_BINDING_TYPE = "x-mesh-requester-identity-binding/1"

#: Only version this module understands. A binding of any other version
#: re-checks as invalid — never fabricated, never "best effort" parsed.
IDENTITY_BINDING_VERSION = 1

#: [mesh-rung12-adversarial-review] D1, closed for the inline/zero-effort
#: case only — see module docstring. Carried alongside a verified binding so
#: a reader knows precisely what is and is not proven: a persistent,
#: independently-checkable identity was cited and its own signature holds,
#: NOT that owner_id corresponds to any real person or organisation.
IDENTITY_LIMITATION_CAVEAT = (
    "self-asserted-requester-identity: this requester identity binding is "
    "signed under the requester's OWN self-generated, self-held key, with no "
    "third-party-issued credential or trusted root behind it (mirrors "
    "node_ownership.IDENTITY_LIMITATION_CAVEAT for the owner->node leg). "
    "verify_requester_identity_binding() confirms the binding's own "
    "signature verifies, it is bound to THIS commitment's exact public key, "
    "the claim is unexpired, and (when a revocation set is supplied) the "
    "cert_id is not revoked — it does NOT and cannot prove owner_id "
    "corresponds to any real person or organisation. It closes the "
    "zero-effort inline self-mint case ([mesh-rung12-adversarial-review]): "
    "a commitment key with no persistent identity behind it can no longer "
    "reach full_bilateral. It does not close the case of an attacker who "
    "self-registers an identity too — that requires an external anchor "
    "(the Authority tier), out of scope here. See TRUST-MODEL.md §4.1a."
)


def _jcs(obj: dict[str, Any]) -> bytes:
    """JSON Canonical Serialization (RFC 8785): sorted keys, no whitespace.

    Same convention as requester_commitment._jcs() / delegation_chain_verifier
    ._jcs() — one signing convention for hex-keyed Ed25519 artifacts across
    this repo.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass
class RequesterIdentityKey:
    """A persistent Ed25519 keypair a requester's identity is rooted in.

    Deliberately a DIFFERENT key from requester_commitment.RequesterKey — the
    identity key is long-lived (spans many exchanges); the commitment key
    may be fresh per exchange. The binding is what connects them.
    """

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> RequesterIdentityKey:
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


def make_requester_identity_binding(
    identity_key: RequesterIdentityKey,
    *,
    owner_id: str,
    commitment_public_key: str,
    cert_id: str | None = None,
    issued_at_unix_ms: int | None = None,
    expires_at_unix_ms: int,
    label: str | None = None,
) -> dict[str, Any]:
    """Sign a binding: "the commitment key ``commitment_public_key`` speaks
    for identity ``owner_id``." Binds to the commitment's OWN public key —
    not to a request_digest or exchange_id (identity outlives one exchange;
    requester_commitment.py already binds the commitment to the exchange).

    ``issued_at_unix_ms`` defaults to now (test callers pass it explicitly
    for reproducibility, exactly as node_ownership.py's re-check accepts an
    explicit ``now_unix_ms``).
    """
    body: dict[str, Any] = {
        "type": IDENTITY_BINDING_TYPE,
        "version": IDENTITY_BINDING_VERSION,
        "cert_id": cert_id or uuid.uuid4().hex,
        "owner_id": owner_id,
        "owner_sign_public_key": identity_key.public_key_hex,
        "commitment_public_key": commitment_public_key,
        "issued_at_unix_ms": issued_at_unix_ms if issued_at_unix_ms is not None else int(time.time() * 1000),
        "expires_at_unix_ms": expires_at_unix_ms,
        "label": label,
    }
    signature = identity_key.sign(_jcs(body))
    return {**body, "signature": signature.hex()}


@dataclass
class IdentityBindingVerdict:
    """Result of verify_requester_identity_binding(). Never raised — a
    missing or forged binding is a RESULT the caller derives a rung from,
    same discipline as verify_requester_commitment / OwnershipRecheck."""

    valid: bool
    reason: str
    owner_id: str | None = None
    cert_id: str | None = None


def verify_requester_identity_binding(
    binding: dict[str, Any] | None,
    *,
    expected_commitment_public_key: str,
    now_unix_ms: int | None = None,
    revoked_cert_ids: frozenset[str] = frozenset(),
) -> IdentityBindingVerdict:
    """Verify a requester identity binding. Returns a verdict, never raises.

    Checks, in order: the binding is present and well-formed; the type/
    version tags are ones this module understands; the binding is bound to
    THIS commitment's exact public key (not replayed from a different
    commitment); the owner's own Ed25519 signature over the binding body
    verifies under its own embedded key; the binding is unexpired; and, when
    the caller supplies a non-empty revocation set (the operator's live
    decision — never fabricated here, mirrors node_ownership.py's discipline
    of not consulting a trust-store on its own), the cert_id is not in it.

    A binding that fails ANY of these is simply not a valid identity
    binding — the caller (mesh_record_verifier.derive_cross_party_rung)
    treats that identically to no binding at all: never a lower rung, never
    a crash, just "not bound."
    """
    if binding is None:
        return IdentityBindingVerdict(valid=False, reason="no requester identity binding present")

    if binding.get("type") != IDENTITY_BINDING_TYPE:
        return IdentityBindingVerdict(
            valid=False, reason=f"unrecognized identity binding type: {binding.get('type')!r}"
        )

    if binding.get("version") != IDENTITY_BINDING_VERSION:
        return IdentityBindingVerdict(
            valid=False, reason=f"unsupported identity binding version: {binding.get('version')!r}"
        )

    owner_id = binding.get("owner_id")
    cert_id = binding.get("cert_id")

    if binding.get("commitment_public_key") != expected_commitment_public_key:
        return IdentityBindingVerdict(
            valid=False,
            reason=(
                f"commitment_public_key mismatch: binding cites "
                f"{binding.get('commitment_public_key')!r}, this commitment's "
                f"own key is {expected_commitment_public_key!r} — a binding "
                f"for a different commitment cannot be replayed onto this one"
            ),
            owner_id=owner_id,
            cert_id=cert_id,
        )

    try:
        sig_hex = binding["signature"]
        pub_hex = binding["owner_sign_public_key"]
    except KeyError as exc:
        return IdentityBindingVerdict(
            valid=False, reason=f"malformed identity binding: missing {exc}", owner_id=owner_id, cert_id=cert_id
        )

    body = {k: v for k, v in binding.items() if k != "signature"}

    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pubkey.verify(bytes.fromhex(sig_hex), _jcs(body))
    except InvalidSignature:
        return IdentityBindingVerdict(
            valid=False, reason="identity binding signature verification failed", owner_id=owner_id, cert_id=cert_id
        )
    except (ValueError, TypeError) as exc:
        return IdentityBindingVerdict(
            valid=False, reason=f"malformed identity binding key or signature: {exc}", owner_id=owner_id, cert_id=cert_id
        )

    now = now_unix_ms if now_unix_ms is not None else int(time.time() * 1000)
    expires_at = binding.get("expires_at_unix_ms")
    if not isinstance(expires_at, (int, float)) or expires_at <= now:
        return IdentityBindingVerdict(
            valid=False,
            reason=f"identity binding expired or malformed expiry: expires_at_unix_ms={expires_at!r}, now={now}",
            owner_id=owner_id,
            cert_id=cert_id,
        )

    if cert_id in revoked_cert_ids:
        return IdentityBindingVerdict(
            valid=False, reason=f"identity binding cert_id={cert_id!r} is revoked", owner_id=owner_id, cert_id=cert_id
        )

    return IdentityBindingVerdict(
        valid=True,
        reason="requester identity binding verified: signature valid, bound to this commitment's key, unexpired, not revoked",
        owner_id=owner_id,
        cert_id=cert_id,
    )
