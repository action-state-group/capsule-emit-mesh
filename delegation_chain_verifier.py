#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline verifier for the mesh-llm plugin delegation chain.

Chain specified in Mesh-LLM/mesh-llm#1331 §"Host identity and signing delegation":

    owner -> SignedNodeOwnership -> node endpoint
    owner -> PluginSigningDelegationV1 -> receipt key -> COSE capsule

Six-step verifier chain, followed AS WRITTEN from #1331:
  1. verify the receipt/COSE statement with the delegated plugin public key;
  2. verify PluginSigningDelegation with the owner public key;
  3. verify owner_id is derived from that owner public key;
  4. verify SignedNodeOwnership binds the same owner and node endpoint ID;
  5. apply expiry and local owner/node/delegation revocation policy;
  6. verify release build attestation independently when supplied.

See docs/SPEC-FEEDBACK-1331.md for items #1331 leaves underspecified.

Usage:
    python delegation_chain_verifier.py \\
        --capsule delegation_chain/fixtures/happy/capsule.cbor \\
        --delegation delegation_chain/fixtures/happy/delegation.json \\
        --node-ownership delegation_chain/fixtures/happy/node_ownership.json \\
        --revocation-list delegation_chain/fixtures/happy/revocation_list.json \\
        --expected-scope mesh.inference.capsule.sign.v1 \\
        --expected-plugin-id net.example.capsule-emit \\
        --expected-node-id <hex>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Domain tag exactly as written in #1331 (the spec says "such as" — we use it verbatim).
DELEGATION_DOMAIN_TAG = b"mesh-llm-plugin-signing-delegation-v1:"

# Scope for Capsule Emit, as named in #1331.
CAPSULE_EMIT_SCOPE = "mesh.inference.capsule.sign.v1"

# COSE algorithm label for EdDSA (RFC 8152 table 2).
COSE_ALG_EDDSA = -8


class VerifyStep(str, Enum):
    COSE_SIGNATURE = "step_1_cose_signature"
    DELEGATION_SIGNATURE = "step_2_delegation_signature"
    OWNER_ID_DERIVATION = "step_3_owner_id_derivation"
    NODE_OWNERSHIP = "step_4_node_ownership"
    EXPIRY_REVOCATION = "step_5_expiry_revocation"
    RELEASE_ATTESTATION = "step_6_release_attestation"


class RejectionCode(str, Enum):
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MISMATCHED_NODE = "mismatched_node"
    MISMATCHED_PLUGIN = "mismatched_plugin"
    WRONG_SCOPE = "wrong_scope"
    OWNER_ID_MISMATCH = "owner_id_mismatch"
    DELEGATION_SIGNATURE_INVALID = "delegation_signature_invalid"
    NODE_OWNERSHIP_SIGNATURE_INVALID = "node_ownership_signature_invalid"
    MALFORMED = "malformed"


@dataclass
class VerifyResult:
    ok: bool
    rejection: RejectionCode | None
    step: VerifyStep | None
    detail: str


def _jcs(obj: Any) -> bytes:
    """JSON Canonical Serialization (RFC 8785): sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _raw_public_key_bytes(hex_pub: str) -> bytes:
    """Decode a hex-encoded raw Ed25519 public key (32 bytes)."""
    raw = bytes.fromhex(hex_pub)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return raw


def _load_ed25519_pubkey(hex_pub: str) -> Ed25519PublicKey:
    """Load Ed25519PublicKey from hex-encoded raw 32-byte public key."""
    raw = _raw_public_key_bytes(hex_pub)
    return Ed25519PublicKey.from_public_bytes(raw)


def _derive_owner_id(hex_pub: str) -> str:
    """Derive owner_id from owner public key.

    #1331: "verify owner_id is derived from that owner public key"
    Derivation: SHA-256 of the raw 32-byte Ed25519 public key, hex-encoded.

    NOTE: #1331 does not specify the derivation function.
    See docs/SPEC-FEEDBACK-1331.md §2.
    """
    raw = _raw_public_key_bytes(hex_pub)
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Step 1: verify COSE capsule with delegated plugin public key
# ---------------------------------------------------------------------------

def _verify_cose_capsule(capsule_bytes: bytes, delegated_pub_hex: str) -> VerifyResult:
    """Step 1: verify the receipt/COSE statement with the delegated plugin public key.

    Expects a CBOR-tagged COSE_Sign1 (CBOR tag 18) structure:
        [protected_bstr, unprotected_map, payload_bstr, signature_bstr]

    Sig_Structure (RFC 9052 §4.4):
        ["Signature1", protected_bstr, b"", payload_bstr]
    """
    try:
        msg = cbor2.loads(capsule_bytes)
        # unwrap CBOR tag 18 if present
        if isinstance(msg, cbor2.CBORTag):
            msg = msg.value
        protected_bstr, _unprotected, payload_bstr, sig_bstr = msg
        sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
        pubkey = _load_ed25519_pubkey(delegated_pub_hex)
        pubkey.verify(bytes(sig_bstr), sig_structure)
    except InvalidSignature:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.BAD_SIGNATURE,
            step=VerifyStep.COSE_SIGNATURE,
            detail="COSE_Sign1 signature did not verify with delegated signing public key",
        )
    except Exception as exc:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MALFORMED,
            step=VerifyStep.COSE_SIGNATURE,
            detail=f"malformed COSE capsule: {exc}",
        )
    return VerifyResult(ok=True, rejection=None, step=VerifyStep.COSE_SIGNATURE, detail="ok")


# ---------------------------------------------------------------------------
# Step 2: verify PluginSigningDelegationV1 with owner public key
# ---------------------------------------------------------------------------

def _verify_delegation_signature(delegation: dict[str, Any]) -> VerifyResult:
    """Step 2: verify PluginSigningDelegation with the owner public key.

    Signed bytes: DELEGATION_DOMAIN_TAG + JCS(delegation_without_sig)
    #1331: "use canonical serialization with a fixed domain tag such as
            mesh-llm-plugin-signing-delegation-v1:"
    """
    try:
        sig_hex = delegation.get("_sig")
        if not sig_hex:
            return VerifyResult(
                ok=False,
                rejection=RejectionCode.MALFORMED,
                step=VerifyStep.DELEGATION_SIGNATURE,
                detail="delegation document missing _sig field",
            )
        body = {k: v for k, v in delegation.items() if k != "_sig"}
        signed_bytes = DELEGATION_DOMAIN_TAG + _jcs(body)
        pubkey = _load_ed25519_pubkey(delegation["owner_sign_public_key"])
        pubkey.verify(bytes.fromhex(sig_hex), signed_bytes)
    except InvalidSignature:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.DELEGATION_SIGNATURE_INVALID,
            step=VerifyStep.DELEGATION_SIGNATURE,
            detail="PluginSigningDelegationV1 signature did not verify with owner public key",
        )
    except Exception as exc:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MALFORMED,
            step=VerifyStep.DELEGATION_SIGNATURE,
            detail=f"malformed delegation document: {exc}",
        )
    return VerifyResult(ok=True, rejection=None, step=VerifyStep.DELEGATION_SIGNATURE, detail="ok")


# ---------------------------------------------------------------------------
# Step 3: verify owner_id is derived from owner public key
# ---------------------------------------------------------------------------

def _verify_owner_id_derivation(delegation: dict[str, Any]) -> VerifyResult:
    """Step 3: verify owner_id is derived from that owner public key."""
    expected = _derive_owner_id(delegation["owner_sign_public_key"])
    actual = delegation.get("owner_id")
    if actual != expected:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.OWNER_ID_MISMATCH,
            step=VerifyStep.OWNER_ID_DERIVATION,
            detail=f"owner_id {actual!r} does not match derivation from owner public key {expected!r}",
        )
    return VerifyResult(ok=True, rejection=None, step=VerifyStep.OWNER_ID_DERIVATION, detail="ok")


# ---------------------------------------------------------------------------
# Step 4: verify SignedNodeOwnership binds the same owner and node endpoint ID
# ---------------------------------------------------------------------------

def _verify_node_ownership(
    node_ownership: dict[str, Any],
    delegation: dict[str, Any],
) -> VerifyResult:
    """Step 4: verify SignedNodeOwnership binds the same owner and node endpoint ID.

    NOTE: SignedNodeOwnership shape is NOT defined in #1331. This verifier uses a
    working assumption documented in docs/SPEC-FEEDBACK-1331.md §1.

    Working-assumption fields used here:
      owner_id, owner_sign_public_key, node_endpoint_id, cert_id, _sig
    """
    try:
        # 4a. Verify node_ownership signature with owner public key
        sig_hex = node_ownership.get("_sig")
        if not sig_hex:
            return VerifyResult(
                ok=False,
                rejection=RejectionCode.MALFORMED,
                step=VerifyStep.NODE_OWNERSHIP,
                detail="node_ownership missing _sig field",
            )
        # cert_id is NOT in the signed body (it is SHA-256 of the signed bytes).
        # Strip both _sig and cert_id to recover the canonical signed body.
        body = {k: v for k, v in node_ownership.items() if k not in ("_sig", "cert_id")}
        # Domain tag: #1331 does not specify one for SignedNodeOwnership.
        # Using JCS-only (no domain tag). See SPEC-FEEDBACK-1331.md §1.
        signed_bytes = _jcs(body)
        pubkey = _load_ed25519_pubkey(delegation["owner_sign_public_key"])
        pubkey.verify(bytes.fromhex(sig_hex), signed_bytes)
    except InvalidSignature:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.NODE_OWNERSHIP_SIGNATURE_INVALID,
            step=VerifyStep.NODE_OWNERSHIP,
            detail="SignedNodeOwnership signature did not verify with owner public key",
        )
    except Exception as exc:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MALFORMED,
            step=VerifyStep.NODE_OWNERSHIP,
            detail=f"malformed node_ownership document: {exc}",
        )

    # 4b. Check owner_id matches
    if node_ownership.get("owner_id") != delegation.get("owner_id"):
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_NODE,
            step=VerifyStep.NODE_OWNERSHIP,
            detail=(
                f"SignedNodeOwnership.owner_id {node_ownership.get('owner_id')!r} "
                f"!= delegation.owner_id {delegation.get('owner_id')!r}"
            ),
        )

    # 4c. Check node_endpoint_id matches
    if node_ownership.get("node_endpoint_id") != delegation.get("node_endpoint_id"):
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_NODE,
            step=VerifyStep.NODE_OWNERSHIP,
            detail=(
                f"SignedNodeOwnership.node_endpoint_id {node_ownership.get('node_endpoint_id')!r} "
                f"!= delegation.node_endpoint_id {delegation.get('node_endpoint_id')!r}"
            ),
        )

    # 4d. Verify cert_id = SHA-256(signed_bytes) and check delegation references it.
    expected_cert_id = hashlib.sha256(signed_bytes).hexdigest()
    actual_cert_id = node_ownership.get("cert_id")
    if actual_cert_id != expected_cert_id:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_NODE,
            step=VerifyStep.NODE_OWNERSHIP,
            detail=f"node_ownership.cert_id {actual_cert_id!r} != SHA-256(signed_bytes) {expected_cert_id!r}",
        )
    if delegation.get("node_ownership_cert_id") != expected_cert_id:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_NODE,
            step=VerifyStep.NODE_OWNERSHIP,
            detail=(
                f"delegation.node_ownership_cert_id {delegation.get('node_ownership_cert_id')!r} "
                f"!= SHA-256(node_ownership signed bytes) {expected_cert_id!r}"
            ),
        )

    return VerifyResult(ok=True, rejection=None, step=VerifyStep.NODE_OWNERSHIP, detail="ok")


# ---------------------------------------------------------------------------
# Step 5: expiry and revocation policy
# ---------------------------------------------------------------------------

def _verify_expiry_and_revocation(
    delegation: dict[str, Any],
    node_ownership: dict[str, Any],
    revocation_list: dict[str, Any],
    *,
    now_ms: int | None = None,
) -> VerifyResult:
    """Step 5: apply expiry and local owner/node/delegation revocation policy."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    # 5a. Delegation expiry
    expires_ms = delegation.get("expires_at_unix_ms")
    if expires_ms is not None and now_ms > expires_ms:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.EXPIRED,
            step=VerifyStep.EXPIRY_REVOCATION,
            detail=f"delegation expired at {expires_ms}ms, now={now_ms}ms",
        )

    # 5b. Delegation revocation
    revoked_ids: list[str] = revocation_list.get("revoked_delegations", [])
    if delegation.get("delegation_id") in revoked_ids:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.REVOKED,
            step=VerifyStep.EXPIRY_REVOCATION,
            detail=f"delegation_id {delegation.get('delegation_id')!r} is in revocation list",
        )

    # 5c. Node identity revocation
    revoked_nodes: list[str] = revocation_list.get("revoked_nodes", [])
    if delegation.get("node_endpoint_id") in revoked_nodes:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.REVOKED,
            step=VerifyStep.EXPIRY_REVOCATION,
            detail=f"node_endpoint_id {delegation.get('node_endpoint_id')!r} is in revocation list",
        )

    # 5d. Owner identity revocation
    revoked_owners: list[str] = revocation_list.get("revoked_owners", [])
    if delegation.get("owner_id") in revoked_owners:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.REVOKED,
            step=VerifyStep.EXPIRY_REVOCATION,
            detail=f"owner_id {delegation.get('owner_id')!r} is in revocation list",
        )

    # 5e. Node ownership expiry (if present in the shape)
    node_expires_ms = node_ownership.get("expires_at_unix_ms")
    if node_expires_ms is not None and now_ms > node_expires_ms:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.EXPIRED,
            step=VerifyStep.EXPIRY_REVOCATION,
            detail=f"node_ownership expired at {node_expires_ms}ms, now={now_ms}ms",
        )

    return VerifyResult(ok=True, rejection=None, step=VerifyStep.EXPIRY_REVOCATION, detail="ok")


# ---------------------------------------------------------------------------
# Step 6: release build attestation (optional)
# ---------------------------------------------------------------------------

def _verify_release_attestation(
    release_attestation: dict[str, Any] | None,
    delegation: dict[str, Any],
) -> VerifyResult:
    """Step 6: verify release build attestation independently when supplied.

    #1331: "The release attestation remains build provenance. Linking it into the
    evidence bundle does not convert it into remote runtime attestation."

    NOTE: #1331 does not define the shape of the release build attestation.
    This step is a stub. See docs/SPEC-FEEDBACK-1331.md §5.
    """
    if release_attestation is None:
        # Optional: not supplied is not a failure per #1331 ("when supplied").
        return VerifyResult(
            ok=True,
            rejection=None,
            step=VerifyStep.RELEASE_ATTESTATION,
            detail="not supplied (optional)",
        )
    # Stub: accept any well-formed attestation that references the right plugin.
    # Full verification requires a trust anchor not defined in #1331.
    # See SPEC-FEEDBACK-1331.md §5.
    plugin_id = release_attestation.get("plugin_id")
    if plugin_id != delegation.get("plugin_id"):
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_PLUGIN,
            step=VerifyStep.RELEASE_ATTESTATION,
            detail=(
                f"release_attestation.plugin_id {plugin_id!r} "
                f"!= delegation.plugin_id {delegation.get('plugin_id')!r}"
            ),
        )
    return VerifyResult(
        ok=True,
        rejection=None,
        step=VerifyStep.RELEASE_ATTESTATION,
        detail="present (stub: trust anchor not yet defined by #1331)",
    )


# ---------------------------------------------------------------------------
# Semantic checks (not a numbered step in #1331, but required for a useful verifier)
# ---------------------------------------------------------------------------

def _verify_scope(delegation: dict[str, Any], expected_scope: str) -> VerifyResult:
    """Check delegation scope matches the required scope.

    #1331: "requests one registered signing scope"
    """
    actual_scope = delegation.get("scope")
    if actual_scope != expected_scope:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.WRONG_SCOPE,
            step=None,
            detail=f"delegation scope {actual_scope!r} != expected scope {expected_scope!r}",
        )
    return VerifyResult(ok=True, rejection=None, step=None, detail="ok")


def _verify_plugin_id(delegation: dict[str, Any], expected_plugin_id: str) -> VerifyResult:
    """Check delegation plugin_id matches the plugin presenting the delegation.

    #1331: "authenticate plugin_id from the live plugin connection, not request JSON"
    In offline verification, the caller supplies the expected plugin_id.
    """
    actual = delegation.get("plugin_id")
    if actual != expected_plugin_id:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_PLUGIN,
            step=None,
            detail=f"delegation.plugin_id {actual!r} != expected {expected_plugin_id!r}",
        )
    return VerifyResult(ok=True, rejection=None, step=None, detail="ok")


def _verify_node_id(delegation: dict[str, Any], expected_node_id: str) -> VerifyResult:
    """Check delegation node_endpoint_id matches the presenting node."""
    actual = delegation.get("node_endpoint_id")
    if actual != expected_node_id:
        return VerifyResult(
            ok=False,
            rejection=RejectionCode.MISMATCHED_NODE,
            step=None,
            detail=f"delegation.node_endpoint_id {actual!r} != expected {expected_node_id!r}",
        )
    return VerifyResult(ok=True, rejection=None, step=None, detail="ok")


# ---------------------------------------------------------------------------
# Top-level verifier
# ---------------------------------------------------------------------------

def verify_chain(
    *,
    capsule_bytes: bytes,
    delegation: dict[str, Any],
    node_ownership: dict[str, Any],
    revocation_list: dict[str, Any],
    expected_scope: str,
    expected_plugin_id: str,
    expected_node_id: str,
    release_attestation: dict[str, Any] | None = None,
    now_ms: int | None = None,
) -> list[VerifyResult]:
    """Run the six-step chain, returning one VerifyResult per step.

    Stops at the first failure. A complete chain has len(results) == 7
    (6 steps + 3 semantic checks). A failed chain is shorter.
    """
    results: list[VerifyResult] = []

    def _run(result: VerifyResult) -> bool:
        results.append(result)
        return result.ok

    # Semantic pre-checks (not numbered in #1331 but essential for meaningful rejection labels)
    if not _run(_verify_scope(delegation, expected_scope)):
        return results
    if not _run(_verify_plugin_id(delegation, expected_plugin_id)):
        return results
    if not _run(_verify_node_id(delegation, expected_node_id)):
        return results

    # Step 1: COSE capsule signature with delegated key
    if not _run(_verify_cose_capsule(capsule_bytes, delegation["delegated_signing_public_key"])):
        return results

    # Step 2: delegation signature with owner key
    if not _run(_verify_delegation_signature(delegation)):
        return results

    # Step 3: owner_id derived from owner public key
    if not _run(_verify_owner_id_derivation(delegation)):
        return results

    # Step 4: SignedNodeOwnership binds same owner and node endpoint ID
    if not _run(_verify_node_ownership(node_ownership, delegation)):
        return results

    # Step 5: expiry and revocation
    if not _run(_verify_expiry_and_revocation(delegation, node_ownership, revocation_list, now_ms=now_ms)):
        return results

    # Step 6: release build attestation (optional)
    _run(_verify_release_attestation(release_attestation, delegation))

    return results


def chain_verdict(results: list[VerifyResult]) -> VerifyResult:
    """Return the first failed step, or the last step if all passed."""
    for r in results:
        if not r.ok:
            return r
    return results[-1] if results else VerifyResult(
        ok=False, rejection=RejectionCode.MALFORMED, step=None, detail="no steps ran"
    )


# ---------------------------------------------------------------------------
# Identity mode and evidence state — #1331 §"Host identity and signing delegation"
# ---------------------------------------------------------------------------

class EvidenceState(str, Enum):
    """Six evidence states #1331 requires the identity bundle to distinguish.

    #1331: "The response must preserve distinctions between missing,
    present-unverified, verified, expired, revoked, and invalid. It must not
    forward a boolean such as owner_verified without the signed evidence
    needed to verify it."
    """
    MISSING = "missing"                        # no delegation provided
    PRESENT_UNVERIFIED = "present_unverified"  # present but NOT checked
    VERIFIED = "verified"                      # full six-step chain passed
    EXPIRED = "expired"                        # delegation has expired (step 5)
    REVOKED = "revoked"                        # delegation in revocation list (step 5)
    INVALID = "invalid"                        # structural/signature failure (steps 1-4)


class IdentityMode(str, Enum):
    """Identity modes from #1331 §"Fallback and policy".

    Strings are used VERBATIM from #1331 — do not rename.

    #1331 defines four modes:
      self_attested           — plugin uses an independent key; no owner binding
      owner_delegated         — valid PluginSigningDelegationV1 + SignedNodeOwnership
      owner_delegated_required — HOST POLICY, not an evidence label (see note below)
      hardware_delegated      — RESERVED; unrepresentable in software

    "owner_delegated_required" is a deployment floor that the operator sets on
    the HOST, not a label this verifier can produce from evidence. It answers
    "what is the minimum acceptable mode?" not "what does the evidence show?"
    This verifier never returns it.

    "hardware_delegated" is reserved for future TPM/TEE-backed or non-exportable
    keys. A software Ed25519 key, however validated, is NOT hardware_delegated.
    This verifier never approximates it — it is unrepresentable here.

    #1331 rule: "No mode silently upgrades its assurance label."
    """
    SELF_ATTESTED = "self_attested"
    OWNER_DELEGATED = "owner_delegated"
    UNKNOWN = "unknown"  # delegation present but insufficient/invalid for a mode claim

    # The two values below are excluded from the enum deliberately.
    # owner_delegated_required: policy floor, not an evidence label
    # hardware_delegated: reserved/unrepresentable — see SPEC-FEEDBACK-1331.md §9


# Cross-party rung ladder (from the existing assurance vocabulary).
_RUNG_LADDER = ("unilateral_fallback", "acknowledged_receipt", "full_bilateral")

# Prose mapping from identity mode to cross-party rung.
# See SPEC-FEEDBACK-1331.md §9 for why this does not map cleanly.
IDENTITY_MODE_RUNG_MAP: dict[IdentityMode, tuple[str | None, str]] = {
    IdentityMode.SELF_ATTESTED: (
        None,
        "self_attested is about key delegation, not counterparty binding. "
        "A self_attested plugin can still produce unilateral_fallback records. "
        "The mode does not determine the rung — the exchange evidence does.",
    ),
    IdentityMode.OWNER_DELEGATED: (
        None,
        "owner_delegated binds the plugin key to the node owner, improving "
        "attributability. It does NOT grant a higher cross-party rung: "
        "unilateral_fallback (one-party signature) is the floor; "
        "acknowledged_receipt and full_bilateral require counterparty co-signing, "
        "which is independent of how the plugin key is delegated. "
        "The mode addresses identity axis B (B2: owner-delegated software key); "
        "the cross-party rung addresses mutuality axis D. They are orthogonal.",
    ),
    IdentityMode.UNKNOWN: (
        None,
        "Mode is unknown/unverified — no rung can be determined from evidence.",
    ),
}


@dataclass
class IdentityModeResult:
    """Explicit identity-mode output — never inferred by the reader.

    #1331 rule: "No mode silently upgrades its assurance label."
    This object NEVER sets mode=owner_delegated unless evidence_state=verified.
    It NEVER sets mode=owner_delegated when evidence_state=present_unverified.
    It NEVER degrades an expired delegation to mode=self_attested.
    It NEVER includes an owner_verified boolean without the signed evidence.
    """
    mode: IdentityMode
    evidence_state: EvidenceState
    rung: str | None    # cross-party rung value if determinable, else None
    rung_note: str      # prose explaining the mapping or why it does not apply


def assess_identity_mode(
    chain_results: list[VerifyResult],
    delegation: dict[str, Any] | None,
) -> IdentityModeResult:
    """Derive the identity mode from the completed verification chain.

    Must be called AFTER verify_chain() so evidence_state is based on actual
    verification, not on the mere presence of a delegation document.

    #1331: "No mode silently upgrades its assurance label."
    #1331: "must not forward a boolean such as owner_verified without the
            signed evidence needed to verify it."
    """
    if delegation is None:
        return IdentityModeResult(
            mode=IdentityMode.SELF_ATTESTED,
            evidence_state=EvidenceState.MISSING,
            **_rung(IdentityMode.SELF_ATTESTED),
        )

    verdict = chain_verdict(chain_results)

    if verdict.ok:
        # All six steps passed — mode is owner_delegated.
        return IdentityModeResult(
            mode=IdentityMode.OWNER_DELEGATED,
            evidence_state=EvidenceState.VERIFIED,
            **_rung(IdentityMode.OWNER_DELEGATED),
        )

    # Chain failed — identify WHY and preserve the distinct state.
    # RULE: expired/revoked/invalid must NOT silently degrade to self_attested.
    if verdict.rejection == RejectionCode.EXPIRED:
        return IdentityModeResult(
            mode=IdentityMode.UNKNOWN,
            evidence_state=EvidenceState.EXPIRED,
            **_rung(IdentityMode.UNKNOWN),
        )

    if verdict.rejection == RejectionCode.REVOKED:
        return IdentityModeResult(
            mode=IdentityMode.UNKNOWN,
            evidence_state=EvidenceState.REVOKED,
            **_rung(IdentityMode.UNKNOWN),
        )

    if verdict.rejection in (
        RejectionCode.BAD_SIGNATURE,
        RejectionCode.DELEGATION_SIGNATURE_INVALID,
        RejectionCode.NODE_OWNERSHIP_SIGNATURE_INVALID,
        RejectionCode.OWNER_ID_MISMATCH,
        RejectionCode.MALFORMED,
    ):
        return IdentityModeResult(
            mode=IdentityMode.UNKNOWN,
            evidence_state=EvidenceState.INVALID,
            **_rung(IdentityMode.UNKNOWN),
        )

    # Remaining: semantic failures (wrong scope, mismatched node/plugin).
    # Delegation is present but cannot be tied to the expected identity.
    return IdentityModeResult(
        mode=IdentityMode.UNKNOWN,
        evidence_state=EvidenceState.PRESENT_UNVERIFIED,
        **_rung(IdentityMode.UNKNOWN),
    )


def assess_identity_mode_without_verifying(
    delegation: dict[str, Any] | None,
) -> IdentityModeResult:
    """Report evidence state WITHOUT running any verification.

    This represents a consumer that has received a delegation document but
    has not yet (or deliberately chose not to) verify it. The mode MUST NOT
    be owner_delegated — presence alone is not evidence of validity.

    Use this to confirm that a naive "is there a delegation? → owner_delegated"
    shortcut is wrong.
    """
    if delegation is None:
        return IdentityModeResult(
            mode=IdentityMode.SELF_ATTESTED,
            evidence_state=EvidenceState.MISSING,
            **_rung(IdentityMode.SELF_ATTESTED),
        )
    # Delegation present but UNCHECKED — mode is unknown, not owner_delegated.
    return IdentityModeResult(
        mode=IdentityMode.UNKNOWN,
        evidence_state=EvidenceState.PRESENT_UNVERIFIED,
        **_rung(IdentityMode.UNKNOWN),
    )


def _rung(mode: IdentityMode) -> dict[str, Any]:
    """Unpack the rung tuple for a given mode into keyword args."""
    rung_val, rung_note = IDENTITY_MODE_RUNG_MAP[mode]
    return {"rung": rung_val, "rung_note": rung_note}


def mode_output_dict(mr: IdentityModeResult) -> dict[str, Any]:
    """Serialisable representation of an IdentityModeResult.

    NEVER includes a boolean owner_verified field.
    The evidence_state IS the evidence — callers must read it, not an
    opaque boolean derived from it.
    """
    return {
        "identity_mode": mr.mode.value,
        "evidence_state": mr.evidence_state.value,
        "rung": mr.rung,
        "rung_note": mr.rung_note,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for mesh-llm delegation chain (Mesh-LLM/mesh-llm#1331)."
    )
    parser.add_argument("--capsule", required=True, help="Path to COSE capsule (.cbor)")
    parser.add_argument("--delegation", required=True, help="Path to PluginSigningDelegationV1 JSON")
    parser.add_argument("--node-ownership", required=True, help="Path to SignedNodeOwnership JSON")
    parser.add_argument("--revocation-list", required=True, help="Path to revocation list JSON")
    parser.add_argument("--expected-scope", required=True, help="Required delegation scope")
    parser.add_argument("--expected-plugin-id", required=True, help="Expected plugin_id")
    parser.add_argument("--expected-node-id", required=True, help="Expected node_endpoint_id (hex)")
    parser.add_argument("--release-attestation", help="Optional path to release build attestation JSON")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    delegation = _load_json(args.delegation)
    node_ownership = _load_json(args.node_ownership)
    revocation_list = _load_json(args.revocation_list)
    capsule_bytes = Path(args.capsule).read_bytes()
    release_attestation = _load_json(args.release_attestation) if args.release_attestation else None

    results = verify_chain(
        capsule_bytes=capsule_bytes,
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope=args.expected_scope,
        expected_plugin_id=args.expected_plugin_id,
        expected_node_id=args.expected_node_id,
        release_attestation=release_attestation,
    )

    verdict = chain_verdict(results)
    mode_result = assess_identity_mode(results, delegation)

    if args.verbose:
        for r in results:
            label = "OK  " if r.ok else "FAIL"
            step = r.step.value if r.step else "pre"
            print(f"  [{label}] {step}: {r.detail}")
    else:
        for r in results:
            if not r.ok:
                print(f"REJECTED [{r.rejection.value}] at {r.step.value if r.step else 'pre'}: {r.detail}")
                break

    if verdict.ok:
        print("VERIFIED: chain ok")
    else:
        print(f"REJECTED: {verdict.rejection.value}")

    # Always emit the identity mode — never a boolean, always the full evidence state.
    print(f"IDENTITY_MODE: {mode_result.mode.value}")
    print(f"EVIDENCE_STATE: {mode_result.evidence_state.value}")
    if mode_result.rung:
        print(f"RUNG: {mode_result.rung}")
    else:
        print(f"RUNG: none (see rung_note)")

    return 0 if verdict.ok else 1


if __name__ == "__main__":
    sys.exit(main())
