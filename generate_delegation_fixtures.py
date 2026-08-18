#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate committed test fixtures for the mesh-llm delegation chain verifier.

Run this once to (re-)produce delegation_chain/fixtures/. The output is
deterministic given a seed; all fixtures are committed so tests run offline
without regeneration.

Usage:
    python generate_delegation_fixtures.py [--out delegation_chain/fixtures]

Each subdirectory under --out contains a DISTINCT failure mode (or the happy
path). The test suite asserts exactly which rejection code each case produces,
so every rejection is individually demonstrated.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from typing import Any

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Match the domain tag used by the verifier.
DELEGATION_DOMAIN_TAG = b"mesh-llm-plugin-signing-delegation-v1:"

# Fixed "now" so fixtures don't expire with the calendar.
# 2026-08-17 00:00:00 UTC = 1787011200 seconds from Unix epoch.
NOW_MS = 1787011200000
# Happy-path expiry: 2027-08-17 (1 year out) — well past any CI run.
FUTURE_MS = NOW_MS + 60 * 60 * 24 * 365 * 1000  # +1 year
PAST_MS = 1000  # 1ms after Unix epoch — expired before any real run

EXPECTED_SCOPE = "mesh.inference.capsule.sign.v1"
EXPECTED_PLUGIN_ID = "net.example.capsule-emit"

# COSE algorithm -8 = EdDSA.
COSE_ALG_EDDSA = -8


# ---------------------------------------------------------------------------
# Deterministic key derivation from a seed phrase
# ---------------------------------------------------------------------------

def _deterministic_key(seed: bytes) -> Ed25519PrivateKey:
    """Derive a deterministic Ed25519 private key from 32 seed bytes."""
    raw = hashlib.sha256(seed).digest()
    return Ed25519PrivateKey.from_private_bytes(raw)


def _pubkey_hex(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def _sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return key.sign(data).hex()


def _jcs(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _owner_id(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


# ---------------------------------------------------------------------------
# Build document helpers
# ---------------------------------------------------------------------------

def _build_node_ownership(
    owner_key: Ed25519PrivateKey,
    owner_pub_hex: str,
    node_pub_hex: str,
    *,
    expires_ms: int = FUTURE_MS,
) -> dict[str, Any]:
    """Build a SignedNodeOwnership document.

    NOTE: Shape is a WORKING ASSUMPTION — #1331 does not define these fields.
    See docs/SPEC-FEEDBACK-1331.md §1.
    """
    oid = _owner_id(owner_pub_hex)
    # Signed body does NOT include cert_id (avoids circular dependency).
    # cert_id = SHA-256(jcs(signed_body)) is appended as an unsigned convenience field.
    signed_body: dict[str, Any] = {
        "owner_id": oid,
        "owner_sign_public_key": owner_pub_hex,
        "node_endpoint_id": node_pub_hex,
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": expires_ms,
    }
    signed_bytes = _jcs(signed_body)
    cert_id = hashlib.sha256(signed_bytes).hexdigest()
    sig = _sign(owner_key, signed_bytes)
    return {**signed_body, "cert_id": cert_id, "_sig": sig}


def _build_delegation(
    owner_key: Ed25519PrivateKey,
    owner_pub_hex: str,
    node_pub_hex: str,
    plugin_pub_hex: str,
    cert_id: str,
    *,
    delegation_id: str = "deleg-0001",
    plugin_id: str = EXPECTED_PLUGIN_ID,
    plugin_version: str = "0.1.0",
    scope: str = EXPECTED_SCOPE,
    expires_ms: int = FUTURE_MS,
    plugin_artifact_digest: str | None = None,
) -> dict[str, Any]:
    """Build a PluginSigningDelegationV1 using exact field names from #1331."""
    oid = _owner_id(owner_pub_hex)
    body: dict[str, Any] = {
        "delegation_id": delegation_id,
        "owner_id": oid,
        "owner_sign_public_key": owner_pub_hex,
        "node_endpoint_id": node_pub_hex,
        "node_ownership_cert_id": cert_id,
        "plugin_id": plugin_id,
        "plugin_version": plugin_version,
        "delegated_signing_public_key": plugin_pub_hex,
        "scope": scope,
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": expires_ms,
    }
    if plugin_artifact_digest is not None:
        body["plugin_artifact_digest"] = plugin_artifact_digest
    signed_bytes = DELEGATION_DOMAIN_TAG + _jcs(body)
    sig = _sign(owner_key, signed_bytes)
    return {**body, "_sig": sig}


def _build_capsule(plugin_key: Ed25519PrivateKey, payload: dict[str, Any]) -> bytes:
    """Build a COSE_Sign1 capsule (CBOR tag 18) signed with the plugin key."""
    payload_bytes = _jcs(payload)
    protected = cbor2.dumps({1: COSE_ALG_EDDSA})  # alg: EdDSA
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    sig = plugin_key.sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(18, [protected, {}, payload_bytes, sig])
    return cbor2.dumps(cose_sign1)


def _empty_revocation() -> dict[str, Any]:
    return {
        "revoked_delegations": [],
        "revoked_nodes": [],
        "revoked_owners": [],
    }


def _write_fixture(
    out_dir: Path,
    name: str,
    node_ownership: dict[str, Any],
    delegation: dict[str, Any],
    capsule_bytes: bytes,
    revocation_list: dict[str, Any],
    node_id: str,
    readme: str,
) -> None:
    d = out_dir / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "node_ownership.json").write_text(json.dumps(node_ownership, indent=2))
    (d / "delegation.json").write_text(json.dumps(delegation, indent=2))
    (d / "capsule.cbor").write_bytes(capsule_bytes)
    (d / "revocation_list.json").write_text(json.dumps(revocation_list, indent=2))
    (d / "node_id.txt").write_text(node_id)
    (d / "README.txt").write_text(readme)
    print(f"  wrote {name}/")


# ---------------------------------------------------------------------------
# Generate all fixtures
# ---------------------------------------------------------------------------

def generate(out_dir: Path) -> str:
    """Generate all fixtures and return the expected node_endpoint_id (hex)."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate three deterministic keypairs.
    owner_key = _deterministic_key(b"mesh-llm-fixture-owner-key-2026")
    node_key = _deterministic_key(b"mesh-llm-fixture-node-key-2026")
    plugin_key = _deterministic_key(b"mesh-llm-fixture-plugin-key-2026")
    alt_plugin_key = _deterministic_key(b"mesh-llm-fixture-alt-plugin-key-2026")

    owner_pub = _pubkey_hex(owner_key)
    node_pub = _pubkey_hex(node_key)
    plugin_pub = _pubkey_hex(plugin_key)
    alt_plugin_pub = _pubkey_hex(alt_plugin_key)

    capsule_payload = {
        "exchange_id": "exch-00000001",
        "observation_point": "client_egress",
        "plugin_id": EXPECTED_PLUGIN_ID,
    }

    # -----------------------------------------------------------------------
    # happy — all six steps pass
    # -----------------------------------------------------------------------
    node_own = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id = node_own["cert_id"]
    deleg = _build_delegation(owner_key, owner_pub, node_pub, plugin_pub, cert_id)
    capsule = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "happy",
        node_own, deleg, capsule, _empty_revocation(),
        node_id=node_pub,
        readme="Happy path: all six steps verify cleanly. Expected result: VERIFIED.",
    )

    # -----------------------------------------------------------------------
    # expired — delegation expires_at_unix_ms is in the past
    # -----------------------------------------------------------------------
    node_own_e = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_e = node_own_e["cert_id"]
    deleg_e = _build_delegation(
        owner_key, owner_pub, node_pub, plugin_pub, cert_id_e,
        delegation_id="deleg-expired-0001",
        expires_ms=PAST_MS,
    )
    capsule_e = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "expired",
        node_own_e, deleg_e, capsule_e, _empty_revocation(),
        node_id=node_pub,
        readme=(
            "Expired delegation: expires_at_unix_ms is 1ms before NOW_MS.\n"
            "Step 5 must reject with EXPIRED."
        ),
    )

    # -----------------------------------------------------------------------
    # revoked — delegation_id appears in revocation_list
    # -----------------------------------------------------------------------
    node_own_r = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_r = node_own_r["cert_id"]
    deleg_r = _build_delegation(
        owner_key, owner_pub, node_pub, plugin_pub, cert_id_r,
        delegation_id="deleg-revoked-0001",
    )
    revoc_r = {
        "revoked_delegations": ["deleg-revoked-0001"],
        "revoked_nodes": [],
        "revoked_owners": [],
    }
    capsule_r = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "revoked",
        node_own_r, deleg_r, capsule_r, revoc_r,
        node_id=node_pub,
        readme=(
            "Revoked delegation: delegation_id is in revocation_list.revoked_delegations.\n"
            "Step 5 must reject with REVOKED."
        ),
    )

    # -----------------------------------------------------------------------
    # mismatched_node — delegation.node_endpoint_id != SignedNodeOwnership.node_endpoint_id
    # The delegation references node_pub but node_ownership uses alt_plugin_pub as
    # a stand-in for a DIFFERENT node key. We use a fresh key to generate this.
    # -----------------------------------------------------------------------
    alt_node_key = _deterministic_key(b"mesh-llm-fixture-alt-node-key-2026")
    alt_node_pub = _pubkey_hex(alt_node_key)
    # node_ownership is for node_pub (the real node)
    node_own_mn = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_mn = node_own_mn["cert_id"]
    # But delegation references a DIFFERENT node (alt_node_pub)
    deleg_mn = _build_delegation(
        owner_key, owner_pub, alt_node_pub, plugin_pub, cert_id_mn,
        delegation_id="deleg-mismatch-node-0001",
    )
    capsule_mn = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "mismatched_node",
        node_own_mn, deleg_mn, capsule_mn, _empty_revocation(),
        node_id=alt_node_pub,  # verifier is told to expect alt_node_pub
        readme=(
            "Mismatched node: delegation.node_endpoint_id references a different node\n"
            "than what SignedNodeOwnership attests. Step 4 must reject with MISMATCHED_NODE."
        ),
    )

    # -----------------------------------------------------------------------
    # mismatched_plugin — delegation.plugin_id does not match expected_plugin_id
    # -----------------------------------------------------------------------
    node_own_mp = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_mp = node_own_mp["cert_id"]
    deleg_mp = _build_delegation(
        owner_key, owner_pub, node_pub, plugin_pub, cert_id_mp,
        delegation_id="deleg-mismatch-plugin-0001",
        plugin_id="net.example.OTHER-plugin",  # wrong plugin_id
    )
    capsule_mp = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "mismatched_plugin",
        node_own_mp, deleg_mp, capsule_mp, _empty_revocation(),
        node_id=node_pub,
        readme=(
            "Mismatched plugin: delegation.plugin_id is 'net.example.OTHER-plugin',\n"
            "but the verifier expects 'net.example.capsule-emit'.\n"
            "Semantic check must reject with MISMATCHED_PLUGIN."
        ),
    )

    # -----------------------------------------------------------------------
    # wrong_scope — delegation.scope is not the required scope
    # -----------------------------------------------------------------------
    node_own_ws = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_ws = node_own_ws["cert_id"]
    deleg_ws = _build_delegation(
        owner_key, owner_pub, node_pub, plugin_pub, cert_id_ws,
        delegation_id="deleg-wrong-scope-0001",
        scope="mesh.some.other.scope.v1",
    )
    capsule_ws = _build_capsule(plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "wrong_scope",
        node_own_ws, deleg_ws, capsule_ws, _empty_revocation(),
        node_id=node_pub,
        readme=(
            "Wrong scope: delegation.scope is 'mesh.some.other.scope.v1',\n"
            "not the required 'mesh.inference.capsule.sign.v1'.\n"
            "Semantic check must reject with WRONG_SCOPE."
        ),
    )

    # -----------------------------------------------------------------------
    # bad_signature — COSE capsule signed with the WRONG key
    # The capsule is signed with alt_plugin_key, but the delegation declares plugin_pub.
    # Step 1 must reject.
    # -----------------------------------------------------------------------
    node_own_bs = _build_node_ownership(owner_key, owner_pub, node_pub)
    cert_id_bs = node_own_bs["cert_id"]
    deleg_bs = _build_delegation(
        owner_key, owner_pub, node_pub, plugin_pub, cert_id_bs,
        delegation_id="deleg-bad-sig-0001",
    )
    # Capsule signed with alt_plugin_key, but delegation says plugin_pub
    capsule_bs = _build_capsule(alt_plugin_key, capsule_payload)
    _write_fixture(
        out_dir, "bad_signature",
        node_own_bs, deleg_bs, capsule_bs, _empty_revocation(),
        node_id=node_pub,
        readme=(
            "Bad signature: COSE capsule is signed with a key that does NOT match\n"
            "delegation.delegated_signing_public_key. Step 1 must reject with BAD_SIGNATURE."
        ),
    )

    # Write a manifest so tests can locate the expected node_id without hardcoding hex.
    manifest = {
        "now_ms": NOW_MS,
        "expected_scope": EXPECTED_SCOPE,
        "expected_plugin_id": EXPECTED_PLUGIN_ID,
        "expected_node_id": node_pub,
        "note": (
            "Fixtures are deterministic. Regenerate with: "
            "python generate_delegation_fixtures.py"
        ),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"  wrote manifest.json")
    return node_pub


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate delegation chain test fixtures.")
    parser.add_argument("--out", default="delegation_chain/fixtures", help="Output directory")
    args = parser.parse_args()
    out = Path(args.out)
    print(f"Generating fixtures -> {out}/")
    node_id = generate(out)
    print(f"Done. expected_node_id={node_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
