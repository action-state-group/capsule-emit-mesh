#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rung 3b — Secure Enclave key custody for the node/owner signing key.

Rung 3a (elsewhere) hardens WHAT RAN (``os_measured``). This module hardens
WHO SIGNED: it binds a hardware-custodied attestation onto the node's
existing Ed25519 signing key (``capsule_sidecar.load_or_create_signing_key``)
without changing that key, its wire format, or any verifier — pure ADDITION.

HARD CONSTRAINT (see docs/REDTEAM-RUNG3.md and the task brief this
implements): Apple's Secure Enclave supports only NIST P-256 ECC keys, not
Ed25519. So the SEP key does not *replace* the node's Ed25519 identity; a
SEP-resident P-256 key CO-SIGNS a binding statement over
(owner Ed25519 public key, node_endpoint_id, owner_id) and that co-signature
rides alongside the existing Ed25519 material in the node identity and in
every serving capsule's provenance.

HONESTY GRADE — ``tee_protected`` means KEY CUSTODY is hardware-backed (the
private half was generated in, and never left, the Secure Enclave; it cannot
be exported or cloned from a compromised host). It does NOT mean the running
binary or the served model was measured — that is ``os_measured`` /
``tee_measured``, a different claim entirely; key custody and code/model
measurement are independent. See TEE_KEY_CUSTODY_LABEL below, which is
carried INTO every block this module produces.

Custody tiers, in the order this module tries them:

  1. ``secure_enclave`` — an EPHEMERAL P-256 key generated inside the Secure
     Enclave (tools/sep_attestation_helper.swift), used to sign one binding
     statement, then discarded. "Ephemeral" describes key REUSE, not
     hardware backing: the keygen and the signature both happen inside the
     SEP chip. It is not made keychain-permanent because that requires a
     keychain-access-groups entitlement this ad-hoc-signed helper does not
     have (verified: SecKeyCreateRandomKey with kSecAttrIsPermanent=true
     fails -34018 "missing entitlement" without one). Signing once and
     caching the resulting ATTESTATION (never the key) avoids needing that
     entitlement at all -- see tee_key_custody_block().
  2. ``software`` -- the honest fallback whenever tier 1 is unavailable for
     any reason: non-macOS host, no Secure Enclave (e.g. a VM), the `swift`
     toolchain missing, or any Security.framework failure. A software P-256
     key is generated in-process with `cryptography` and used the same way.
     ``tee_protected`` is ALWAYS False here and ``software_fallback_reason``
     names why -- this block is never silently upgraded to look
     hardware-backed.

Signing happens ONCE per (ed25519 key, node_endpoint_id, owner_id) tuple --
not per capsule. tee_key_custody_block() caches the resulting attestation to
``<keys_dir>/node-key-tee-binding.json`` (gitignored, same as node-key.pem's
directory) and every subsequent capsule cites a COPY of that one block,
exactly as the B4 identity capsule is sealed once and cited by every serving
capsule rather than re-signed per record (see node_ownership.py).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CUSTODY_SECURE_ENCLAVE = "secure_enclave"
CUSTODY_SOFTWARE = "software"

ALGORITHM = "ecdsa-p256-sha256"

#: Domain-separation tag for the canonical bytes the SEP/software key signs.
TEE_KEY_BINDING_DOMAIN_TAG = b"capsule-emit-mesh-tee-key-binding-v1:"

#: The Swift helper this module shells out to for the secure_enclave tier.
HELPER_PATH = Path(__file__).resolve().parent / "tools" / "sep_attestation_helper.swift"

#: Cache filename inside keys_dir -- public material only (pubkey +
#: signature), never a private key. keys_dir is already gitignored wholesale.
CACHE_FILENAME = "node-key-tee-binding.json"

#: HONESTY GRADE, carried INTO every tee_key_custody block this module
#: produces -- same discipline as node_ownership.IDENTITY_LIMITATION_CAVEAT.
TEE_KEY_CUSTODY_LABEL = (
    "tee_protected_key: this P-256 signature co-signs the node's existing "
    "Ed25519 identity. When custody=='secure_enclave', the P-256 PRIVATE key "
    "was generated in and never left Apple's Secure Enclave -- it cannot be "
    "exported or cloned from a compromised host. This is a KEY-CUSTODY claim "
    "ONLY: it does NOT attest the running binary (see os_measured / "
    "self_measured) and does NOT attest a loaded model or its weights (see "
    "tee_measured). Key custody and code/model measurement are independent "
    "claims. When custody=='software' (Secure Enclave unavailable on this "
    "host), tee_protected is ALWAYS False and software_fallback_reason names "
    "why -- this block is never silently upgraded to look hardware-backed."
)


class SepUnavailable(Exception):
    """Raised internally when the secure_enclave tier cannot be used. Never
    escapes this module -- always caught and turned into a labeled software
    fallback."""


@dataclass
class SepAttestationResult:
    custody: str
    tee_protected: bool
    algorithm: str
    public_key_x963_hex: str
    signature_der_hex: str
    software_fallback_reason: str | None = None


# ---------------------------------------------------------------------------
# Canonical binding bytes
# ---------------------------------------------------------------------------

def canonical_binding_bytes(
    *,
    owner_ed25519_public_key_hex: str,
    node_endpoint_id: str,
    owner_id: str | None,
) -> bytes:
    """The exact bytes the SEP/software P-256 key signs: a domain-tagged,
    canonical (RFC 8785-style: sorted keys, no whitespace) binding of the
    node's existing Ed25519 identity to this attestation key."""
    body = {
        "owner_ed25519_public_key": owner_ed25519_public_key_hex,
        "node_endpoint_id": node_endpoint_id,
        "owner_id": owner_id,
    }
    jcs = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return TEE_KEY_BINDING_DOMAIN_TAG + jcs


# ---------------------------------------------------------------------------
# Tier 1 -- secure_enclave, via the Swift helper
# ---------------------------------------------------------------------------

def _secure_enclave_available() -> bool:
    """Cheap pre-check -- does NOT guarantee the helper will succeed (a Mac
    without a Secure Enclave, e.g. a VM, still passes this check and only
    fails when the helper actually calls into Security.framework)."""
    return sys.platform == "darwin" and shutil.which("swift") is not None and HELPER_PATH.exists()


def _sign_with_secure_enclave(message: bytes, *, timeout: float = 15.0) -> SepAttestationResult:
    if not _secure_enclave_available():
        raise SepUnavailable(
            "not macOS, no `swift` toolchain on PATH, or helper script missing"
        )

    swift_bin = shutil.which("swift")
    try:
        proc = subprocess.run(
            [swift_bin, str(HELPER_PATH), "attest", message.hex()],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SepUnavailable(f"failed to run sep_attestation_helper.swift: {exc}") from exc

    try:
        payload = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
    except (ValueError, IndexError) as exc:
        raise SepUnavailable(
            f"sep_attestation_helper.swift produced unparseable output "
            f"(exit {proc.returncode}): {proc.stdout!r} / {proc.stderr!r}"
        ) from exc

    if not payload.get("ok"):
        raise SepUnavailable(
            f"sep_attestation_helper.swift reported failure: {payload.get('error', proc.stderr)!r}"
        )

    try:
        return SepAttestationResult(
            custody=CUSTODY_SECURE_ENCLAVE,
            tee_protected=True,
            algorithm=payload["algorithm"],
            public_key_x963_hex=payload["public_key_x963_hex"],
            signature_der_hex=payload["signature_der_hex"],
        )
    except KeyError as exc:
        raise SepUnavailable(f"sep_attestation_helper.swift output missing field {exc}") from exc


# ---------------------------------------------------------------------------
# Tier 2 -- software fallback
# ---------------------------------------------------------------------------

def _sign_with_software(message: bytes, *, reason: str) -> SepAttestationResult:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return SepAttestationResult(
        custody=CUSTODY_SOFTWARE,
        tee_protected=False,
        algorithm=ALGORITHM,
        public_key_x963_hex=pub.hex(),
        signature_der_hex=signature.hex(),
        software_fallback_reason=reason,
    )


def sign_binding(message: bytes) -> SepAttestationResult:
    """Sign ``message`` with the Secure Enclave when available, else a
    clearly-labeled software key. Never raises -- a result, not an
    exception, mirroring node_ownership.OwnershipRecheck."""
    try:
        return _sign_with_secure_enclave(message)
    except SepUnavailable as exc:
        return _sign_with_software(message, reason=str(exc))


# ---------------------------------------------------------------------------
# tee_key_custody_block -- sign once, cache, cite everywhere
# ---------------------------------------------------------------------------

def tee_key_custody_block(
    keys_dir: Path,
    *,
    ed25519_public_key_hex: str,
    node_endpoint_id: str,
    owner_id: str | None = None,
) -> dict[str, Any]:
    """Get-or-create the tee_key_custody attestation for this node identity.

    Signs ONCE per (ed25519_public_key_hex, node_endpoint_id, owner_id)
    tuple and persists the result (public material only) to
    ``<keys_dir>/node-key-tee-binding.json``. A later call with the SAME
    tuple returns the cached block without invoking the Secure Enclave
    again; a call after the node's Ed25519 key, endpoint, or owner changes
    regenerates it -- the same "cite the same attestation everywhere, don't
    re-sign per record" discipline as the B4 identity capsule.
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    cache_path = keys_dir / CACHE_FILENAME
    attests = {
        "owner_ed25519_public_key": ed25519_public_key_hex,
        "node_endpoint_id": node_endpoint_id,
        "owner_id": owner_id,
    }

    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("attests") == attests:
                return cached
        except (OSError, ValueError):
            pass  # fall through and regenerate a fresh attestation

    message = canonical_binding_bytes(
        owner_ed25519_public_key_hex=ed25519_public_key_hex,
        node_endpoint_id=node_endpoint_id,
        owner_id=owner_id,
    )
    result = sign_binding(message)

    block: dict[str, Any] = {
        "custody": result.custody,
        "tee_protected": result.tee_protected,
        "algorithm": result.algorithm,
        "public_key_x963_hex": result.public_key_x963_hex,
        "signature_der_hex": result.signature_der_hex,
        "attests": attests,
        "software_fallback_reason": result.software_fallback_reason,
        "label": TEE_KEY_CUSTODY_LABEL,
    }
    cache_path.write_text(json.dumps(block, indent=2, sort_keys=True), encoding="utf-8")
    return block
