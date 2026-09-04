#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""WHO+DID binding — bind mesh-llm's node-owner identity into our capsules.

mesh-llm ships an OPT-IN, off-by-default owner-identity layer (``mesh-llm auth
init``): it generates an Ed25519 ``OwnerKeypair`` and signs a time-bounded,
revocable ``SignedNodeOwnership`` cert binding an owner to a node endpoint (see
mesh-serving-provenance/crates/mesh-llm-identity/src/ownership.rs and
crates/mesh-llm-commands/src/auth.rs). The cert is written to
``~/.mesh-llm/node-ownership.json``.

Our serving capsules already seal ``served_by_node_id`` — the endpoint id, the
"did" (this node served this exchange). They do NOT bind the OWNER identity, the
"who". This module adds that binding, reusing the SAME citation/caveat seam the
requester-commitment / cross-party block already established (requester_commitment.py),
never inventing new machinery:

  1. SEAL AN IDENTITY CAPSULE (seal_identity_capsule): a capsule whose subject is
     the owner->node claim (owner_id, endpoint_id, expiry, label) — our signed
     "who" record. Emitted once, at `auth init` / first time a node has a cert.

  2. BIND WHO INTO DID (owner_provenance_block): every serving capsule's
     provenance carries owner_id + a reference to the identity capsule/cert — the
     "did" cites the "who". Rides inside the existing x-mesh-poc-v1 block.

  3. CHEAP VALIDITY RE-CHECK AT FIRST SERVE (recheck_ownership_validity): certs
     expire and rotate before some nodes ever serve. A structural + expiry
     re-check (NOT a trust decision) so a serving capsule never cites a cert that
     is already expired/mismatched, and degrades to owner-absent if so.

HONESTY GRADE — owner identity here is OPT-IN and SELF-ASSERTED. The owner key is
self-generated and self-held; the cert binds owner->node under the owner's OWN
key, with no third-party-issued credential or trusted root behind it. We verify
the cert's own signature and expiry (that the claim is internally consistent and
live) — we do NOT and CANNOT verify that the owner_id corresponds to any real
person or organisation. The ``identity_limitation`` caveat below is carried INTO
the identity capsule itself and INTO every serving capsule that cites it, exactly
as requester_commitment.IDENTITY_LIMITATION_CAVEAT is carried for the cross-party
block. An account of facts is only as durable as identity: never imply the
owner binding is externally verified.

If no cert is present on a node (the default), we degrade gracefully: the serving
capsule seals ``served_by_node_id`` only and marks the owner ABSENT
(``owner_status="absent"``). We never fabricate an owner.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit

# ---------------------------------------------------------------------------
# Constants mirroring mesh-llm-identity/src/ownership.rs
# ---------------------------------------------------------------------------

#: mesh-llm's NODE_OWNERSHIP_VERSION. We only understand version 1; a cert of any
#: other version re-checks as unsupported (owner absent, never fabricated).
NODE_OWNERSHIP_VERSION = 1

#: Domain-separation tag mesh-llm signs the canonical claim under
#: (SIGNING_DOMAIN_TAG in ownership.rs). We reproduce the exact canonical byte
#: layout so we can re-verify the owner's own signature from Python.
SIGNING_DOMAIN_TAG = b"mesh-llm-node-ownership-v1:"

#: Default location mesh-llm writes the signed cert to (ownership.rs
#: default_node_ownership_path()).
DEFAULT_NODE_OWNERSHIP_PATH = Path.home() / ".mesh-llm" / "node-ownership.json"

#: HONESTY GRADE — carried INTO the identity capsule (as a caveat field on the
#: owner->node subject) AND into every serving capsule that cites it. Same
#: discipline as requester_commitment.IDENTITY_LIMITATION_CAVEAT for the
#: cross-party block: an account of facts is only as durable as identity.
IDENTITY_LIMITATION_CAVEAT = (
    "opt-in-self-asserted-owner-identity: this owner->node binding is an "
    "OPT-IN mesh-llm feature (off by default) whose owner key is "
    "self-generated and self-held. The cert is signed under the owner's OWN "
    "key with no third-party-issued credential or trusted root behind it. "
    "recheck_ownership_validity() confirms the cert's own signature verifies, "
    "the claimed owner_id matches its embedded key, the node_endpoint_id "
    "matches this node, and the cert is unexpired — it does NOT prove the "
    "owner_id corresponds to any real person or organisation. First-use "
    "acceptance of a self-asserted owner MUST NOT be treated as externally "
    "verified identity; any account of facts attached to it is only as "
    "durable as that self-assertion. Mirrors requester_commitment.IDENTITY_LIMITATION_CAVEAT "
    "for the cross-party block."
)

#: Capsule marker for the identity capsule's owner->node subject block.
OWNERSHIP_SUBJECT_KEY = "x-mesh-owner-identity-v1"

#: Status values for the owner-provenance block bound into serving capsules.
OWNER_STATUS_ABSENT = "absent"          # no cert present -> did-only, never fabricate
OWNER_STATUS_BOUND = "bound"            # cert present, re-check passed, cited
OWNER_STATUS_INVALID = "invalid"        # cert present but re-check failed -> owner not bound

#: [mesh-e6-identity-owner-cert] CPB typed digest reference shape
#: ({type, digest_alg, digest}) — the same shape
#: mesh_coordinator_receipt_emitter._validate_bundle_ref enforces for its
#: `bundle_ref` citations, reused here rather than inventing a second
#: convention.
OWNER_CERT_REF_TYPE = "owner_cert"
DIGEST_ALG_SHA256 = "SHA-256"


# ---------------------------------------------------------------------------
# NodeOwnershipClaim / SignedNodeOwnership — Python mirror of the Rust structs
# ---------------------------------------------------------------------------

@dataclass
class NodeOwnershipClaim:
    """Python mirror of mesh-llm's NodeOwnershipClaim (ownership.rs).

    Field names match the Rust serde field names verbatim so we can load the
    JSON mesh-llm writes without a translation layer.
    """

    version: int
    cert_id: str
    owner_id: str
    owner_sign_public_key: str      # hex, 32 bytes
    node_endpoint_id: str           # hex, 32 bytes
    issued_at_unix_ms: int
    expires_at_unix_ms: int
    node_label: str | None = None
    hostname_hint: str | None = None

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "NodeOwnershipClaim":
        return cls(
            version=int(value["version"]),
            cert_id=str(value["cert_id"]),
            owner_id=str(value["owner_id"]),
            owner_sign_public_key=str(value["owner_sign_public_key"]),
            node_endpoint_id=str(value["node_endpoint_id"]),
            issued_at_unix_ms=int(value["issued_at_unix_ms"]),
            expires_at_unix_ms=int(value["expires_at_unix_ms"]),
            node_label=value.get("node_label"),
            hostname_hint=value.get("hostname_hint"),
        )


@dataclass
class SignedNodeOwnership:
    """Python mirror of mesh-llm's SignedNodeOwnership (ownership.rs)."""

    claim: NodeOwnershipClaim
    signature: str  # hex, 64 bytes

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "SignedNodeOwnership":
        return cls(
            claim=NodeOwnershipClaim.from_value(value["claim"]),
            signature=str(value["signature"]),
        )


def load_signed_node_ownership(path: Path | None = None) -> SignedNodeOwnership | None:
    """Load mesh-llm's ``node-ownership.json`` if present. Returns None if absent.

    Absent (the DEFAULT — the feature is opt-in) is not an error: it is exactly
    the graceful-degrade path. A malformed file is also treated as absent rather
    than raising, so a broken cert never takes down the serving path — the owner
    is simply not bound (never fabricated).
    """
    p = path or DEFAULT_NODE_OWNERSHIP_PATH
    try:
        if not p.exists():
            return None
        raw = json.loads(p.read_text(encoding="utf-8"))
        return SignedNodeOwnership.from_value(raw)
    except (OSError, ValueError, KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Canonical claim bytes + cheap validity re-check
# ---------------------------------------------------------------------------

def _write_string(buf: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    buf.extend(len(encoded).to_bytes(8, "little"))
    buf.extend(encoded)


def _write_optional_string(buf: bytearray, value: str | None) -> None:
    if value is None:
        buf.append(0)
    else:
        buf.append(1)
        _write_string(buf, value)


def canonical_claim_bytes(claim: NodeOwnershipClaim) -> bytes:
    """Reproduce mesh-llm's canonical_claim_bytes() byte-for-byte.

    Matches ownership.rs exactly: domain tag, then version (u32 LE), cert_id and
    owner_id as length-prefixed strings, then the 32-byte owner key and 32-byte
    node id as RAW bytes (decoded from hex), then the two u64 LE timestamps, then
    the two optional strings. This is what the owner signed; we re-verify against
    it. Raises ValueError on malformed hex/length (caught by the re-check).
    """
    owner_key = bytes.fromhex(claim.owner_sign_public_key)
    node_id = bytes.fromhex(claim.node_endpoint_id)
    if len(owner_key) != 32:
        raise ValueError("owner_sign_public_key must be 32 bytes")
    if len(node_id) != 32:
        raise ValueError("node_endpoint_id must be 32 bytes")
    buf = bytearray()
    buf.extend(SIGNING_DOMAIN_TAG)
    buf.extend(int(claim.version).to_bytes(4, "little"))
    _write_string(buf, claim.cert_id)
    _write_string(buf, claim.owner_id)
    buf.extend(owner_key)
    buf.extend(node_id)
    buf.extend(int(claim.issued_at_unix_ms).to_bytes(8, "little"))
    buf.extend(int(claim.expires_at_unix_ms).to_bytes(8, "little"))
    _write_optional_string(buf, claim.node_label)
    _write_optional_string(buf, claim.hostname_hint)
    return bytes(buf)


def owner_cert_digest(ownership: SignedNodeOwnership) -> str:
    """SHA-256 digest over the owner cert's own bytes (claim || signature).

    This digests the cert exactly as the owner signed it plus the signature
    itself, so tampering either half (a swapped claim OR a swapped signature)
    changes the digest. Computed directly from the cert — independent of
    whether an identity capsule has been sealed for it — so the typed
    reference below does not depend on capsule-sealing order.
    """
    claim_bytes = canonical_claim_bytes(ownership.claim)
    sig_bytes = bytes.fromhex(ownership.signature)
    return hashlib.sha256(claim_bytes + sig_bytes).hexdigest()


def owner_cert_reference(ownership: SignedNodeOwnership) -> dict[str, Any]:
    """The owner cert as a CPB typed digest reference: {type, digest_alg,
    digest} (mesh_coordinator_receipt_emitter._validate_bundle_ref shape).

    This is what binds node key <- owner cert on the serving capsule: the
    digest is computed over exactly the bytes the owner's key signed
    (canonical_claim_bytes, which embeds node_endpoint_id) plus the
    signature, so the reference is unforgeable without the owner key and
    changes if either the claim or signature is swapped.
    """
    return {
        "type": OWNER_CERT_REF_TYPE,
        "digest_alg": DIGEST_ALG_SHA256,
        "digest": owner_cert_digest(ownership),
    }


@dataclass
class OwnershipRecheck:
    """Result of the cheap first-serve re-check. Never raises; a result, not an
    exception — a bad cert is a verdict the binding must be able to represent
    (same discipline as verify_requester_commitment)."""

    valid: bool
    reason: str
    owner_id: str | None = None
    cert_id: str | None = None
    expires_at_unix_ms: int | None = None
    node_label: str | None = None


def recheck_ownership_validity(
    ownership: SignedNodeOwnership | None,
    *,
    expected_node_endpoint_id: str,
    now_unix_ms: int | None = None,
) -> OwnershipRecheck:
    """Cheap first-serve validity re-check. Returns OwnershipRecheck — never raises.

    Certs are time-bounded and revocable; a node may sit idle past its cert's
    expiry before it ever serves, or rotate keys. Before a serving capsule cites
    the owner cert we re-confirm, cheaply:
      - the claim version is one we understand;
      - the embedded owner key and node id are well-formed;
      - the node_endpoint_id matches THIS node (no cert-swapping);
      - the owner's OWN Ed25519 signature over the canonical claim verifies;
      - the cert is not expired.

    This is a STRUCTURAL + LIVENESS check, NOT a trust decision — see
    IDENTITY_LIMITATION_CAVEAT. It deliberately does NOT consult mesh-llm's
    revocation trust-store or trust policy (that is the operator's live decision,
    not something a passive wire-side sidecar can honestly re-derive offline).
    """
    if ownership is None:
        return OwnershipRecheck(valid=False, reason="no owner cert present (owner identity is opt-in / off by default)")

    claim = ownership.claim
    recheck = OwnershipRecheck(
        valid=False,
        reason="",
        owner_id=claim.owner_id,
        cert_id=claim.cert_id,
        expires_at_unix_ms=claim.expires_at_unix_ms,
        node_label=claim.node_label,
    )

    if claim.version != NODE_OWNERSHIP_VERSION:
        recheck.reason = f"unsupported ownership claim version: {claim.version!r}"
        return recheck

    if claim.node_endpoint_id != expected_node_endpoint_id:
        recheck.reason = (
            f"node_endpoint_id mismatch: cert binds {claim.node_endpoint_id!r}, "
            f"this node is {expected_node_endpoint_id!r}"
        )
        return recheck

    try:
        canonical = canonical_claim_bytes(claim)
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim.owner_sign_public_key))
        pubkey.verify(bytes.fromhex(ownership.signature), canonical)
    except InvalidSignature:
        recheck.reason = "owner signature over the canonical claim failed to verify"
        return recheck
    except (ValueError, TypeError) as exc:
        recheck.reason = f"malformed cert key/signature: {exc}"
        return recheck

    now = now_unix_ms if now_unix_ms is not None else int(time.time() * 1000)
    if claim.expires_at_unix_ms <= now:
        recheck.reason = (
            f"cert expired: expires_at_unix_ms={claim.expires_at_unix_ms} <= now={now}"
        )
        return recheck

    recheck.valid = True
    recheck.reason = "owner cert re-check passed: self-signature valid, node id matches, unexpired"
    return recheck


# ---------------------------------------------------------------------------
# 1. Seal the identity capsule (the "who")
# ---------------------------------------------------------------------------

def build_owner_subject(claim: NodeOwnershipClaim) -> dict[str, Any]:
    """The owner->node claim as it rides inside the identity capsule's subject.

    Carries the identity_limitation caveat INTO the identity capsule itself —
    the honesty grade travels with the "who" record, not just alongside it.
    """
    return {
        "owner_id": claim.owner_id,
        "cert_id": claim.cert_id,
        "node_endpoint_id": claim.node_endpoint_id,
        "owner_sign_public_key": claim.owner_sign_public_key,
        "issued_at_unix_ms": claim.issued_at_unix_ms,
        "expires_at_unix_ms": claim.expires_at_unix_ms,
        "node_label": claim.node_label,
        "hostname_hint": claim.hostname_hint,
        # HONESTY GRADE, sealed INTO the who-record.
        "identity_limitation": IDENTITY_LIMITATION_CAVEAT,
    }


def seal_identity_capsule(
    ownership: SignedNodeOwnership,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal an identity capsule whose subject is the owner->node claim.

    Emitted at ``mesh-llm auth init`` time (or the first time a node acquires a
    ``SignedNodeOwnership``) — our signed "who" record. The serving capsules'
    owner-provenance block later cites this capsule's ``capsule_id`` (the did
    cites the who), reusing the existing citation seam.

    action_type="fyi": the identity capsule ASSERTS a fact (an owner claims this
    node) rather than deciding or running an inference — §5.1 admits only 'fyi'
    or 'decide', and an informational who-record is 'fyi'. The owner cert is
    carried verbatim so a verifier can independently re-run
    recheck_ownership_validity() from the capsule bytes alone.
    """
    owner_subject = build_owner_subject(ownership.claim)
    compute_attestation = {
        OWNERSHIP_SUBJECT_KEY: {
            # The full signed cert, verbatim — so a reader re-derives validity
            # from these bytes, never from our say-so.
            "signed_node_ownership": {
                "claim": {
                    "version": ownership.claim.version,
                    "cert_id": ownership.claim.cert_id,
                    "owner_id": ownership.claim.owner_id,
                    "owner_sign_public_key": ownership.claim.owner_sign_public_key,
                    "node_endpoint_id": ownership.claim.node_endpoint_id,
                    "issued_at_unix_ms": ownership.claim.issued_at_unix_ms,
                    "expires_at_unix_ms": ownership.claim.expires_at_unix_ms,
                    "node_label": ownership.claim.node_label,
                    "hostname_hint": ownership.claim.hostname_hint,
                },
                "signature": ownership.signature,
            },
            "owner_subject": owner_subject,
            # HONESTY GRADE at the top of the block too, so it is unmissable.
            "identity_limitation": IDENTITY_LIMITATION_CAVEAT,
        },
    }

    return emit(
        action_id=f"mesh-poc/owner-identity/{signing_node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        domain="action",
        provenance="collector",
    )


# ---------------------------------------------------------------------------
# 2. Bind who into did — the owner-provenance block for serving capsules
# ---------------------------------------------------------------------------

def owner_provenance_block(
    ownership: SignedNodeOwnership | None,
    *,
    expected_node_endpoint_id: str,
    identity_capsule_id: str | None = None,
    now_unix_ms: int | None = None,
) -> dict[str, Any]:
    """The owner block bound into a serving capsule's provenance (the did cites
    the who). Runs the cheap first-serve re-check and NEVER fabricates an owner.

    Three honest outcomes:
      - no cert (default)        -> owner_status="absent", owner_id=None
      - cert present, re-check   -> owner_status="bound",  owner_id set,
        passes                      identity_capsule_id + owner_cert_ref cited
      - cert present, re-check   -> owner_status="invalid", owner_id carried but
        fails                       NOT treated as bound; reason recorded

    The identity_limitation caveat is present whenever a cert is present at all —
    a reader must never see an owner_id without the honesty grade attached.

    [mesh-e6-identity-owner-cert] `owner_cert_ref` carries the owner cert
    itself as a CPB typed digest reference ({type, digest_alg, digest} —
    see owner_cert_reference()), binding node key <- owner cert directly
    from the cert's own bytes. It is separate from `identity_capsule_id`
    (which cites the sealed "who" capsule, an auxiliary artifact that may
    not exist yet) so the binding does not depend on sealing order.
    """
    if ownership is None:
        return {
            "owner_status": OWNER_STATUS_ABSENT,
            "owner_id": None,
            "identity_capsule_id": None,
            "owner_cert_ref": None,
            "recheck_reason": "no owner cert present (owner identity is opt-in / off by default)",
            "identity_limitation": None,
        }

    recheck = recheck_ownership_validity(
        ownership,
        expected_node_endpoint_id=expected_node_endpoint_id,
        now_unix_ms=now_unix_ms,
    )

    return {
        "owner_status": OWNER_STATUS_BOUND if recheck.valid else OWNER_STATUS_INVALID,
        "owner_id": recheck.owner_id,
        "cert_id": recheck.cert_id,
        "node_endpoint_id": expected_node_endpoint_id,
        "expires_at_unix_ms": recheck.expires_at_unix_ms,
        "node_label": recheck.node_label,
        # The did cites the who: reference to the sealed identity capsule. Only
        # cited when the re-check passed AND a capsule id was supplied — an
        # invalid cert never gets to point at a "who" record as though bound.
        "identity_capsule_id": identity_capsule_id if recheck.valid else None,
        # The owner cert itself, as a typed reference. Only cited when the
        # re-check passed — a swapped/mismatched cert (bad signature, wrong
        # node, expired) is NEVER cited as though it were a live binding.
        "owner_cert_ref": owner_cert_reference(ownership) if recheck.valid else None,
        "recheck_valid": recheck.valid,
        "recheck_reason": recheck.reason,
        # HONESTY GRADE — present whenever a cert is present at all.
        "identity_limitation": IDENTITY_LIMITATION_CAVEAT,
    }
