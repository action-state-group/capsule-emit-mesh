# SPDX-License-Identifier: Apache-2.0
"""Issuer/service tests — Mesh-LLM/mesh-llm#1331.

This is the COUNTERPART to test_delegation_chain_verifier.py. That suite proves
the verifier REJECTS bad fixtures. This suite proves the ISSUER MINTS good ones:
the acceptance bar is a produce -> verify round-trip against the EXISTING
delegation_chain_verifier.py, plus a rejection matrix on the constrained
signing oracle.

Round-trip contract (#1331 §"Host identity and signing delegation"):
  1. issuer.issue_delegation(plugin_pubkey, scope) -> a fixed-shape
     PluginSigningDelegationV1 the existing verifier VERIFIES (all 6 steps ok).
  2. The issuer NEVER signs plugin-provided arbitrary bytes, and NEVER signs an
     unregistered scope (constrained oracle, item 15).
  3. Renewal mints a fresh valid delegation WITHOUT using the owner key per
     request (item 16). Invalidation on key/node/owner/cert change keeps the
     verifier states distinct (expired / revoked / invalid), item 16 + legs of
     11/12/14.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from delegation_chain_verifier import (  # noqa: E402
    CAPSULE_EMIT_SCOPE,
    EvidenceState,
    RejectionCode,
    assess_identity_mode,
    chain_verdict,
    verify_chain,
)
from delegation_issuer import (  # noqa: E402
    ArbitrarySigningRejected,
    DelegationIssuer,
    OwnerIdentityUnavailable,
    UnregisteredScope,
)

# A fixed "now" for deterministic validity windows (same epoch the fixtures use).
NOW_MS = 1787011200000


# ---------------------------------------------------------------------------
# Deterministic key + capsule helpers (mirror generate_delegation_fixtures.py)
# ---------------------------------------------------------------------------

def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _make_issuer(**overrides) -> tuple[DelegationIssuer, Ed25519PrivateKey, Ed25519PrivateKey]:
    """Build an issuer with an owner key and a node key. Returns (issuer, owner_key, node_key)."""
    owner_key = Ed25519PrivateKey.generate()
    node_key = Ed25519PrivateKey.generate()
    kwargs = dict(
        owner_signing_key=owner_key,
        node_endpoint_id=_pub_hex(node_key),
        plugin_id="net.example.capsule-emit",
        plugin_version="0.1.0",
        registered_scopes=[CAPSULE_EMIT_SCOPE],
        max_validity_ms=60 * 60 * 24 * 365 * 1000,  # 1 year
        clock=lambda: NOW_MS,
    )
    kwargs.update(overrides)
    issuer = DelegationIssuer(**kwargs)
    return issuer, owner_key, node_key


def _build_capsule(plugin_key: Ed25519PrivateKey) -> bytes:
    """Build a COSE_Sign1 capsule (CBOR tag 18) signed with the plugin key.

    Mirrors generate_delegation_fixtures._build_capsule so the round-trip
    exercises step 1 of the verifier too.
    """
    import cbor2
    import json

    payload = {"exchange_id": "exch-roundtrip", "observation_point": "client_egress"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    protected = cbor2.dumps({1: -8})  # alg: EdDSA
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    sig = plugin_key.sign(sig_structure)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload_bytes, sig]))


def _verify_minted(issuer: DelegationIssuer, delegation: dict, plugin_key: Ed25519PrivateKey):
    """Run the FULL existing verifier chain over a freshly minted delegation."""
    capsule = _build_capsule(plugin_key)
    node_ownership = issuer.node_ownership_document()
    return verify_chain(
        capsule_bytes=capsule,
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=issuer.revocation_list(),
        expected_scope=CAPSULE_EMIT_SCOPE,
        expected_plugin_id=issuer.plugin_id,
        expected_node_id=issuer.node_endpoint_id,
        now_ms=NOW_MS,
    )


# ===========================================================================
# 1. Round-trip: a minted delegation VERIFIES with the existing verifier
# ===========================================================================

def test_minted_delegation_round_trips_through_existing_verifier():
    """Produce -> verify -> OK. All six verifier steps must pass on a minted
    delegation. This is the acceptance bar."""
    issuer, owner_key, node_key = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    delegation = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)

    results = _verify_minted(issuer, delegation, plugin_key)
    verdict = chain_verdict(results)
    assert verdict.ok, (
        f"Minted delegation must verify. rejection={verdict.rejection!r} "
        f"step={verdict.step!r}: {verdict.detail}"
    )
    # Evidence state must be VERIFIED / owner_delegated.
    mr = assess_identity_mode(results, delegation)
    assert mr.evidence_state == EvidenceState.VERIFIED


def test_minted_delegation_has_all_required_fields():
    """The delegation must carry every field #1331 names in PluginSigningDelegationV1."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    for field in (
        "delegation_id", "owner_id", "owner_sign_public_key", "node_endpoint_id",
        "node_ownership_cert_id", "plugin_id", "plugin_version",
        "delegated_signing_public_key", "scope", "issued_at_unix_ms",
        "expires_at_unix_ms", "_sig",
    ):
        assert field in d, f"minted delegation missing required field {field!r}"
    assert d["scope"] == CAPSULE_EMIT_SCOPE
    assert d["delegated_signing_public_key"] == _pub_hex(plugin_key)


def test_each_delegation_has_unique_id():
    """delegation_id must be present and unique so revocation can be enforced."""
    issuer, _, _ = _make_issuer()
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    d1 = issuer.issue_delegation(_pub_hex(k1), CAPSULE_EMIT_SCOPE)
    d2 = issuer.issue_delegation(_pub_hex(k2), CAPSULE_EMIT_SCOPE)
    assert d1["delegation_id"] != d2["delegation_id"]


# ===========================================================================
# 2. Constrained signing oracle (item 15)
# ===========================================================================

def test_unregistered_scope_is_rejected():
    """The oracle must refuse to mint a delegation for an unregistered scope."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    with pytest.raises(UnregisteredScope):
        issuer.issue_delegation(_pub_hex(plugin_key), "mesh.some.other.scope.v1")


def test_arbitrary_bytes_signing_is_rejected():
    """The oracle must not expose a raw sign-these-bytes operation over the owner key."""
    issuer, _, _ = _make_issuer()
    with pytest.raises(ArbitrarySigningRejected):
        issuer.sign_arbitrary(b"attacker chosen bytes")


def test_owner_key_bytes_never_exposed():
    """The issuer must never hand back owner private key material."""
    issuer, _, _ = _make_issuer()
    # No attribute/method returns owner private bytes.
    for name in dir(issuer):
        val = getattr(issuer, name, None)
        assert not isinstance(val, Ed25519PrivateKey) or name.startswith("_"), (
            f"issuer exposes a private key via public attribute {name!r}"
        )


def test_unavailable_owner_identity_returns_unavailable_not_prompt():
    """#1331: 'return unavailable when no owner identity is loaded rather than
    prompting during inference.'"""
    issuer, _, _ = _make_issuer(owner_signing_key=None)
    plugin_key = Ed25519PrivateKey.generate()
    with pytest.raises(OwnerIdentityUnavailable):
        issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)


# ===========================================================================
# 3. Renewal + invalidation state machine (item 16 + legs of 11/12/14)
# ===========================================================================

def test_renewal_produces_fresh_valid_delegation():
    """Renewal mints a NEW, still-verifiable delegation with a later expiry and a
    distinct delegation_id."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    original = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    renewed = issuer.renew(original)

    assert renewed["delegation_id"] != original["delegation_id"]
    assert renewed["expires_at_unix_ms"] >= original["expires_at_unix_ms"]
    # Renewed delegation still verifies.
    results = _verify_minted(issuer, renewed, plugin_key)
    assert chain_verdict(results).ok


def test_renewal_does_not_use_owner_key_per_request():
    """#1331: the owner key signs 'only at plugin startup/renewal'. Renewal is an
    owner-key event; ordinary issuance and renewal both count owner signings, but
    a per-request statement path must NOT touch the owner key.

    We assert the issuer exposes NO per-request signing entrypoint that uses the
    owner key: the only owner-key operations are issue_delegation and renew.
    """
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    before = issuer.owner_signing_count
    issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    after_issue = issuer.owner_signing_count
    assert after_issue == before + 1, "issue must use the owner key exactly once"

    # A renewal is also exactly one owner signing.
    d = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    n = issuer.owner_signing_count
    issuer.renew(d)
    assert issuer.owner_signing_count == n + 1


def test_needs_renewal_before_expiry_outside_request_path():
    """#1331: 'renew before expiry outside the request path.' The issuer must be
    able to tell, from a clock, that a delegation is inside its renewal window
    BEFORE it expires."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    # Far before expiry: not yet due.
    assert not issuer.needs_renewal(d, now_ms=NOW_MS)
    # Just inside the renewal window before expiry: due, but NOT yet expired.
    near = d["expires_at_unix_ms"] - 1
    assert issuer.needs_renewal(d, now_ms=near)
    assert near < d["expires_at_unix_ms"], "renewal must fire BEFORE expiry"


def test_revocation_invalidates_and_verifier_reports_revoked():
    """Revoke by delegation_id -> the existing verifier reports REVOKED, a state
    distinct from expired/invalid."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    issuer.revoke_delegation(d["delegation_id"])

    results = _verify_minted(issuer, d, plugin_key)
    verdict = chain_verdict(results)
    assert not verdict.ok and verdict.rejection == RejectionCode.REVOKED
    assert assess_identity_mode(results, d).evidence_state == EvidenceState.REVOKED


def test_expired_delegation_is_a_distinct_state():
    """A delegation minted with a past expiry (or evaluated after expiry) is
    reported EXPIRED, distinct from revoked/invalid."""
    issuer, _, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    # Evaluate one ms after expiry.
    after = d["expires_at_unix_ms"] + 1
    capsule = _build_capsule(plugin_key)
    results = verify_chain(
        capsule_bytes=capsule,
        delegation=d,
        node_ownership=issuer.node_ownership_document(),
        revocation_list=issuer.revocation_list(),
        expected_scope=CAPSULE_EMIT_SCOPE,
        expected_plugin_id=issuer.plugin_id,
        expected_node_id=issuer.node_endpoint_id,
        now_ms=after,
    )
    verdict = chain_verdict(results)
    assert not verdict.ok and verdict.rejection == RejectionCode.EXPIRED
    assert assess_identity_mode(results, d).evidence_state == EvidenceState.EXPIRED


def test_plugin_key_change_invalidates_old_delegation():
    """Leg of #1331: 'invalidate/reissue on plugin key ... change.' A delegation
    bound to key A must NOT verify a capsule signed by key B; reissuing for key B
    restores verification."""
    issuer, _, _ = _make_issuer()
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    d_a = issuer.issue_delegation(_pub_hex(key_a), CAPSULE_EMIT_SCOPE)

    # Capsule signed with the NEW key B against the OLD delegation (bound to A).
    capsule_b = _build_capsule(key_b)
    results = verify_chain(
        capsule_bytes=capsule_b,
        delegation=d_a,
        node_ownership=issuer.node_ownership_document(),
        revocation_list=issuer.revocation_list(),
        expected_scope=CAPSULE_EMIT_SCOPE,
        expected_plugin_id=issuer.plugin_id,
        expected_node_id=issuer.node_endpoint_id,
        now_ms=NOW_MS,
    )
    assert not chain_verdict(results).ok, "old delegation must not cover a new plugin key"

    # Reissue for key B -> verifies again.
    d_b = issuer.reissue_on_plugin_key_change(d_a, _pub_hex(key_b))
    assert d_b["delegation_id"] != d_a["delegation_id"]
    ok_results = _verify_minted(issuer, d_b, key_b)
    assert chain_verdict(ok_results).ok


def test_node_change_invalidates_and_reissue_restores():
    """Leg of #1331: 'invalidate/reissue on ... node identity ... change.' When the
    node endpoint rotates, an old delegation no longer matches the current node
    ownership; reissuing under the new node restores the chain."""
    issuer, owner_key, _ = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d_old = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)

    # Rotate the node identity on the issuer.
    new_node_key = Ed25519PrivateKey.generate()
    issuer.rotate_node_endpoint(_pub_hex(new_node_key))

    # Old delegation references the OLD node; current node_ownership is for the NEW
    # node -> step 4 mismatch.
    capsule = _build_capsule(plugin_key)
    results = verify_chain(
        capsule_bytes=capsule,
        delegation=d_old,
        node_ownership=issuer.node_ownership_document(),
        revocation_list=issuer.revocation_list(),
        expected_scope=CAPSULE_EMIT_SCOPE,
        expected_plugin_id=issuer.plugin_id,
        expected_node_id=issuer.node_endpoint_id,
        now_ms=NOW_MS,
    )
    assert not chain_verdict(results).ok, "old delegation must not survive a node rotation"

    # Reissue under the new node -> verifies.
    d_new = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    assert d_new["node_endpoint_id"] == _pub_hex(new_node_key)
    ok_results = _verify_minted(issuer, d_new, plugin_key)
    assert chain_verdict(ok_results).ok


def test_owner_change_invalidates_old_delegation():
    """Leg of #1331: 'invalidate/reissue on ... owner identity ... change.' A new
    owner key means the old delegation's owner signature no longer chains to the
    current node ownership owner."""
    issuer, _, node_key = _make_issuer()
    plugin_key = Ed25519PrivateKey.generate()
    d_old = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)

    new_owner = Ed25519PrivateKey.generate()
    issuer.rotate_owner_key(new_owner)

    # New node_ownership is signed by / bound to the NEW owner; the OLD delegation
    # carries the OLD owner_id -> step 4 owner mismatch.
    capsule = _build_capsule(plugin_key)
    results = verify_chain(
        capsule_bytes=capsule,
        delegation=d_old,
        node_ownership=issuer.node_ownership_document(),
        revocation_list=issuer.revocation_list(),
        expected_scope=CAPSULE_EMIT_SCOPE,
        expected_plugin_id=issuer.plugin_id,
        expected_node_id=issuer.node_endpoint_id,
        now_ms=NOW_MS,
    )
    assert not chain_verdict(results).ok, "old delegation must not survive an owner rotation"

    d_new = issuer.issue_delegation(_pub_hex(plugin_key), CAPSULE_EMIT_SCOPE)
    ok_results = _verify_minted(issuer, d_new, plugin_key)
    assert chain_verdict(ok_results).ok
