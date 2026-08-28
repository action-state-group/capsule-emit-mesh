#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owner-signed plugin-delegation issuance/renewal service.

This is the COUNTERPART to delegation_chain_verifier.py. The verifier only
*checks* delegations; nothing in this repo *minted* one. This module mints
them, so a produce -> verify round-trip is possible offline.

Specified in Mesh-LLM/mesh-llm#1331 §"Host identity and signing delegation",
operation DelegatePluginSigningKey:

    "The plugin supplies an Ed25519 public key and requests one registered
     signing scope. The host constructs and signs a fixed-shape
     PluginSigningDelegation; it does not sign plugin-provided arbitrary bytes."

Design constraints taken VERBATIM from #1331 and enforced here:

  - fixed shape only: the issuer builds PluginSigningDelegationV1 itself; the
    plugin supplies only a public key and a scope name (item 15 / oracle);
  - registered scope only: an unregistered scope is REJECTED, never signed;
  - no arbitrary-byte oracle: there is NO "sign these bytes with the owner key"
    entrypoint; sign_arbitrary() exists solely to REJECT and prove the absence;
  - canonical serialization + domain tag: byte-identical to the verifier
    (mesh-llm-plugin-signing-delegation-v1: + JCS), imported from the verifier
    so the two can never drift;
  - owner key signs only at issuance/renewal, never per request;
  - validity capped by host policy (max_validity_ms);
  - return unavailable when no owner identity is loaded, never prompt;
  - delegation_id present so revocation can be enforced;
  - invalidate/reissue on plugin key/artifact, node, owner, or cert change;
  - never expose owner/node private key material.

Serialization is DELIBERATELY reused from delegation_chain_verifier rather than
re-derived: the acceptance bar is that the existing verifier accepts what this
issues, so the two MUST share the exact same domain tag and JCS function.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Reuse the verifier's canonical bytes EXACTLY. Do not re-implement these here —
# any divergence would break the produce<->verify round-trip that is the whole
# point of this module.
from delegation_chain_verifier import (
    CAPSULE_EMIT_SCOPE,
    DELEGATION_DOMAIN_TAG,
    _derive_owner_id,
    _jcs,
    _raw_public_key_bytes,
)

# How long before expiry a delegation is considered "due for renewal". Renewal
# runs OUTSIDE the request path (#1331), so a comfortable window is fine.
DEFAULT_RENEWAL_WINDOW_MS = 60 * 60 * 24 * 1000  # 24h


class UnregisteredScope(Exception):
    """Raised when a delegation is requested for a scope the host has not registered.

    #1331: "requests one registered signing scope" and "never allow a plugin to
    choose ... arbitrary claims".
    """


class ArbitrarySigningRejected(Exception):
    """Raised by sign_arbitrary(). The owner key MUST NOT sign plugin-provided bytes.

    #1331 non-goal: "Providing an arbitrary-byte signing oracle backed by the
    owner or node transport key."
    """


class OwnerIdentityUnavailable(Exception):
    """Raised when no owner signing key is loaded.

    #1331: "return unavailable when no owner identity is loaded rather than
    prompting during inference."
    """


class InvalidPublicKey(Exception):
    """Raised when a supplied plugin public key is not a valid 32-byte Ed25519 key."""


def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _validate_plugin_pubkey(hex_pub: str) -> str:
    """Ensure the plugin-supplied public key is a well-formed raw Ed25519 key.

    Returns the normalized lowercase hex. The plugin controls ONLY this value
    and the scope name; everything else in the delegation is host-owned.
    """
    try:
        raw = _raw_public_key_bytes(hex_pub)  # enforces 32 bytes
        Ed25519PublicKey.from_public_bytes(raw)  # enforces valid point
    except Exception as exc:  # noqa: BLE001
        raise InvalidPublicKey(f"invalid plugin public key: {exc}") from exc
    return raw.hex()


class DelegationIssuer:
    """Constrained, owner-signed delegation issuer for one node.

    The issuer holds the owner signing key and the current node/owner/cert
    identity. It exposes exactly two owner-key operations — issue_delegation and
    renew — plus revocation and identity-rotation management. It has NO operation
    that signs plugin-chosen bytes.
    """

    def __init__(
        self,
        *,
        owner_signing_key: Ed25519PrivateKey | None,
        node_endpoint_id: str,
        plugin_id: str,
        plugin_version: str,
        registered_scopes: list[str] | None = None,
        max_validity_ms: int = 60 * 60 * 24 * 365 * 1000,
        renewal_window_ms: int = DEFAULT_RENEWAL_WINDOW_MS,
        plugin_artifact_digest: str | None = None,
        node_ownership_expires_at_unix_ms: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        # Owner key is PRIVATE. It is stored under a name-mangled attribute and
        # is never returned by any public method. sign_arbitrary() is the only
        # method that could conceivably use it for caller-chosen bytes, and it
        # refuses.
        self.__owner_signing_key = owner_signing_key
        self.node_endpoint_id = _validate_plugin_pubkey(node_endpoint_id)
        self.plugin_id = plugin_id
        self.plugin_version = plugin_version
        self._registered_scopes: set[str] = set(registered_scopes or [CAPSULE_EMIT_SCOPE])
        self.max_validity_ms = max_validity_ms
        self.renewal_window_ms = renewal_window_ms
        self.plugin_artifact_digest = plugin_artifact_digest
        self._node_ownership_expires_at_unix_ms = node_ownership_expires_at_unix_ms
        self._clock: Callable[[], int] = clock or (lambda: int(time.time() * 1000))

        # Revocation state — #1331: "include a delegation ID so revocation can be
        # added or enforced explicitly."
        self._revoked_delegations: set[str] = set()
        self._revoked_nodes: set[str] = set()
        self._revoked_owners: set[str] = set()

        # Audit counter so callers/tests can prove the owner key is used only at
        # issuance/renewal, never per request. #1331: "The existing owner key
        # signs delegations only at plugin startup/renewal."
        self.owner_signing_count = 0

    # ------------------------------------------------------------------ owner identity

    @property
    def owner_available(self) -> bool:
        return self.__owner_signing_key is not None

    def owner_public_key_hex(self) -> str:
        """Public owner signing key (never the private bytes)."""
        self._require_owner()
        return _pub_hex(self.__owner_signing_key)

    def owner_id(self) -> str:
        """owner_id derived from the owner public key, using the verifier's derivation."""
        return _derive_owner_id(self.owner_public_key_hex())

    def _require_owner(self) -> Ed25519PrivateKey:
        if self.__owner_signing_key is None:
            raise OwnerIdentityUnavailable(
                "no owner signing identity loaded; returning unavailable "
                "(delegation issuance/renewal cannot proceed)"
            )
        return self.__owner_signing_key

    def _owner_sign(self, data: bytes) -> str:
        """The ONLY place the owner key signs. Every caller supplies host-built,
        domain-tagged, fixed-shape bytes — never plugin-chosen bytes."""
        key = self._require_owner()
        self.owner_signing_count += 1
        return key.sign(data).hex()

    # ------------------------------------------------------------------ node ownership

    def node_ownership_document(self) -> dict[str, Any]:
        """Build the SignedNodeOwnership the verifier's step 4 checks.

        Byte-for-byte compatible with generate_delegation_fixtures._build_node_ownership:
          - signed body excludes cert_id and _sig;
          - signed over JCS(body) with NO domain tag (per the verifier);
          - cert_id = SHA-256(JCS(signed_body)).
        """
        owner_pub = self.owner_public_key_hex()
        now = self._clock()
        expires = self._node_ownership_expires_at_unix_ms
        if expires is None:
            expires = now + self.max_validity_ms
        signed_body: dict[str, Any] = {
            "owner_id": _derive_owner_id(owner_pub),
            "owner_sign_public_key": owner_pub,
            "node_endpoint_id": self.node_endpoint_id,
            "issued_at_unix_ms": now,
            "expires_at_unix_ms": expires,
        }
        signed_bytes = _jcs(signed_body)
        cert_id = hashlib.sha256(signed_bytes).hexdigest()
        sig = self._owner_sign(signed_bytes)
        return {**signed_body, "cert_id": cert_id, "_sig": sig}

    def _current_cert_id(self) -> str:
        """cert_id of the current node ownership, WITHOUT counting an owner signing.

        Recomputes the deterministic signed bytes and hashes them; does not sign.
        """
        owner_pub = self.owner_public_key_hex()
        now = self._clock()
        expires = self._node_ownership_expires_at_unix_ms
        if expires is None:
            expires = now + self.max_validity_ms
        signed_body = {
            "owner_id": _derive_owner_id(owner_pub),
            "owner_sign_public_key": owner_pub,
            "node_endpoint_id": self.node_endpoint_id,
            "issued_at_unix_ms": now,
            "expires_at_unix_ms": expires,
        }
        return hashlib.sha256(_jcs(signed_body)).hexdigest()

    # ------------------------------------------------------------------ issuance

    def issue_delegation(
        self,
        delegated_signing_public_key_hex: str,
        scope: str,
        *,
        validity_ms: int | None = None,
        delegation_id: str | None = None,
    ) -> dict[str, Any]:
        """Construct and owner-sign a fixed-shape PluginSigningDelegationV1.

        The plugin supplies ONLY the public key and the scope name. Everything
        else — owner_id, owner key, node endpoint, cert id, plugin identity,
        validity, domain tag — is host-owned (#1331: "never allow a plugin to
        choose arbitrary claims, owner/node IDs, plugin identity, validity beyond
        policy, or signing domain").
        """
        self._require_owner()

        # Constrained oracle: registered scope only.
        if scope not in self._registered_scopes:
            raise UnregisteredScope(
                f"scope {scope!r} is not registered; registered scopes: "
                f"{sorted(self._registered_scopes)}"
            )

        plugin_pub = _validate_plugin_pubkey(delegated_signing_public_key_hex)

        now = self._clock()
        # Validity capped by host policy.
        if validity_ms is None:
            validity_ms = self.max_validity_ms
        validity_ms = min(validity_ms, self.max_validity_ms)

        owner_pub = self.owner_public_key_hex()
        body: dict[str, Any] = {
            "delegation_id": delegation_id or self._new_delegation_id(),
            "owner_id": _derive_owner_id(owner_pub),
            "owner_sign_public_key": owner_pub,
            "node_endpoint_id": self.node_endpoint_id,
            "node_ownership_cert_id": self._current_cert_id(),
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "delegated_signing_public_key": plugin_pub,
            "scope": scope,
            "issued_at_unix_ms": now,
            "expires_at_unix_ms": now + validity_ms,
        }
        # Optional artifact-digest binding, when the host knows it (#1331:
        # "bind installed plugin version/artifact identity from host-owned metadata").
        if self.plugin_artifact_digest is not None:
            body["plugin_artifact_digest"] = self.plugin_artifact_digest

        signed_bytes = DELEGATION_DOMAIN_TAG + _jcs(body)
        sig = self._owner_sign(signed_bytes)
        return {**body, "_sig": sig}

    @staticmethod
    def _new_delegation_id() -> str:
        return "deleg-" + secrets.token_hex(16)

    # ------------------------------------------------------------------ renewal

    def needs_renewal(self, delegation: dict[str, Any], *, now_ms: int | None = None) -> bool:
        """True when the delegation is inside its renewal window but not yet expired.

        #1331: "renew before expiry outside the request path."
        """
        if now_ms is None:
            now_ms = self._clock()
        expires = delegation["expires_at_unix_ms"]
        return now_ms < expires and now_ms >= (expires - self.renewal_window_ms)

    def renew(
        self,
        delegation: dict[str, Any],
        *,
        validity_ms: int | None = None,
    ) -> dict[str, Any]:
        """Mint a FRESH delegation for the same plugin key + scope, with a new
        delegation_id and a later expiry, bound to the CURRENT node/owner/cert.

        Renewal is an owner-key event (one owner signing) run outside the request
        path — never a per-request operation.
        """
        return self.issue_delegation(
            delegation["delegated_signing_public_key"],
            delegation["scope"],
            validity_ms=validity_ms,
        )

    # --------------------------------------------------- invalidation / reissue

    def reissue_on_plugin_key_change(
        self,
        old_delegation: dict[str, Any],
        new_delegated_signing_public_key_hex: str,
    ) -> dict[str, Any]:
        """Invalidate (revoke) the old delegation and issue a new one bound to the
        new plugin key. #1331: "invalidate/reissue on plugin ... key ... change."
        """
        self.revoke_delegation(old_delegation["delegation_id"])
        return self.issue_delegation(new_delegated_signing_public_key_hex, old_delegation["scope"])

    def rotate_node_endpoint(self, new_node_endpoint_id: str) -> None:
        """Rotate the node identity. Any delegation bound to the old node no longer
        matches the current node ownership (verifier step 4 mismatch).
        #1331: "invalidate/reissue on ... node identity ... change."
        """
        self.node_endpoint_id = _validate_plugin_pubkey(new_node_endpoint_id)

    def rotate_owner_key(self, new_owner_signing_key: Ed25519PrivateKey) -> None:
        """Rotate the owner identity. The old owner_id no longer chains to the new
        node ownership. #1331: "invalidate/reissue on ... owner identity ... change."
        """
        self.__owner_signing_key = new_owner_signing_key

    # ------------------------------------------------------------------ revocation

    def revoke_delegation(self, delegation_id: str) -> None:
        self._revoked_delegations.add(delegation_id)

    def revoke_node(self, node_endpoint_id: str) -> None:
        self._revoked_nodes.add(node_endpoint_id)

    def revoke_owner(self, owner_id: str) -> None:
        self._revoked_owners.add(owner_id)

    def revocation_list(self) -> dict[str, Any]:
        """The revocation list in the exact shape the verifier's step 5 reads."""
        return {
            "revoked_delegations": sorted(self._revoked_delegations),
            "revoked_nodes": sorted(self._revoked_nodes),
            "revoked_owners": sorted(self._revoked_owners),
        }

    # --------------------------------------------------- constrained oracle guard

    def sign_arbitrary(self, data: bytes) -> bytes:  # noqa: ARG002
        """REFUSE. The owner key is not an arbitrary-byte signing oracle.

        This method exists ONLY to make the absence of an arbitrary-byte oracle
        testable and explicit. #1331 non-goal: "Providing an arbitrary-byte
        signing oracle backed by the owner or node transport key."
        """
        raise ArbitrarySigningRejected(
            "the owner key signs only fixed-shape PluginSigningDelegationV1 "
            "documents for registered scopes; it will not sign arbitrary bytes"
        )
