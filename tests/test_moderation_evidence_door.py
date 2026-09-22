# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] `moderation_evidence_door.py` unit tests."""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from moderation_decision import DECISION_REMOVE, ModerationDecision, PolicyRef, SubjectRef, seal_moderation_decision
from moderation_evidence_door import (
    REASON_NO_SUCH_RECORD,
    REASON_POLICY_DECLINE,
    REASON_REQUEST_MALFORMED,
    SUBJECT_KIND_MESSAGE_DIGEST,
    RedressRequest,
    answer_redress_request,
    redress_request_signing_body,
)

MSG_DIGEST = hashlib.sha256(b"the message the door is about").hexdigest()


class FakeSigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._key.sign(body).hex(), "test-node-key"


def _pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sealed_decision(principal_ref: str | None) -> dict:
    sr = SubjectRef(message_digest=MSG_DIGEST, room_ref="room:general", principal_ref=principal_ref)
    pr = PolicyRef(policy_id="hate-speech-v1", version="2026.1")
    ma = {"model_id": "buzz-mod-classifier-a", "provider": "buzz", "weights_digest": "b" * 64}
    d = ModerationDecision(
        subject_ref=sr,
        policy_ref=pr,
        model_attestation=ma,
        decision=DECISION_REMOVE,
        basis="clause 4.2",
        confidence=0.9,
        automated=True,
        redress_ref="https://buzz.example/appeal",
    )
    return seal_moderation_decision(d, operator="buzz-node-1", developer="buzz-mesh-mod/0.1", signing_node_id="node-1")


def _signed_request(key: Ed25519PrivateKey, principal_ref: str, *, message_digest: str = MSG_DIGEST) -> RedressRequest:
    body = redress_request_signing_body(message_digest, principal_ref)
    sig = key.sign(body).hex()
    return RedressRequest(
        subject_kind=SUBJECT_KIND_MESSAGE_DIGEST,
        message_digest=message_digest,
        requester_principal_ref=principal_ref,
        requester_signature=sig,
    )


def test_subject_gets_satisfied_bundle() -> None:
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    decision_cap = _sealed_decision(principal_ref)
    req = _signed_request(author_key, principal_ref)

    answer = answer_redress_request(
        [decision_cap], req, signer=FakeSigner(), request_digest="r1", issued_at="2026-09-22T00:00:00Z"
    )
    wire = answer.to_wire()
    assert wire["status"] == "SATISFIED"
    assert wire["bundles"][0]["decision"]["capsule_id"] == decision_cap["capsule_id"]


def test_non_subject_with_a_different_valid_identity_is_withheld() -> None:
    """[R4] acceptance: "a non-subject asking for the same digest -> WITHHELD."
    The stranger's signature is real (they control THEIR OWN key) -- they
    are simply not the principal the decision was bound to."""
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    decision_cap = _sealed_decision(principal_ref)

    stranger_key = Ed25519PrivateKey.generate()
    stranger_principal_ref = "nostr-pubkey:" + _pubkey_hex(stranger_key)
    req = _signed_request(stranger_key, stranger_principal_ref)

    answer = answer_redress_request(
        [decision_cap], req, signer=FakeSigner(), request_digest="r2", issued_at="2026-09-22T00:00:00Z"
    )
    wire = answer.to_wire()
    assert wire["status"] == "WITHHELD"
    assert wire["reason"] == REASON_POLICY_DECLINE
    assert "bundles" not in wire


def test_forged_signature_claiming_the_real_subject_is_withheld() -> None:
    """A stranger who merely learned the digest (rooms aren't private) and
    the CORRECT principal_ref string cannot forge possession without the
    author's private key."""
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    decision_cap = _sealed_decision(principal_ref)

    forger_key = Ed25519PrivateKey.generate()
    # Forger claims the AUTHOR's principal_ref but signs with their OWN key.
    body = redress_request_signing_body(MSG_DIGEST, principal_ref)
    forged_sig = forger_key.sign(body).hex()
    req = RedressRequest(
        subject_kind=SUBJECT_KIND_MESSAGE_DIGEST,
        message_digest=MSG_DIGEST,
        requester_principal_ref=principal_ref,
        requester_signature=forged_sig,
    )

    answer = answer_redress_request(
        [decision_cap], req, signer=FakeSigner(), request_digest="r3", issued_at="2026-09-22T00:00:00Z"
    )
    wire = answer.to_wire()
    assert wire["status"] == "WITHHELD"


def test_no_decision_for_digest_is_not_found() -> None:
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    other_digest = hashlib.sha256(b"a different message entirely").hexdigest()
    req = _signed_request(author_key, principal_ref, message_digest=other_digest)

    answer = answer_redress_request([], req, signer=FakeSigner(), request_digest="r4", issued_at="2026-09-22T00:00:00Z")
    wire = answer.to_wire()
    assert wire["status"] == "NOT_FOUND"
    assert wire["reason"] == REASON_NO_SUCH_RECORD


def test_decision_with_no_bound_principal_never_satisfies() -> None:
    """A decision sealed with no `principal_ref` at all has no requester
    this door could ever recognize as "the subject" -- always WITHHELD,
    never a false SATISFIED from an absent binding."""
    decision_cap = _sealed_decision(None)
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    req = _signed_request(author_key, principal_ref)

    answer = answer_redress_request(
        [decision_cap], req, signer=FakeSigner(), request_digest="r5", issued_at="2026-09-22T00:00:00Z"
    )
    assert answer.to_wire()["status"] == "WITHHELD"


def test_per_user_history_subject_kind_is_refused_by_construction() -> None:
    """[R4] acceptance: "a request for a per-user history -> refused by
    construction (no such subject kind)." `RedressRequest.subject_kind` is
    a plain string field -- nothing stops a caller from typing an arbitrary
    value, but the door has no dispatch branch for anything except
    `SUBJECT_KIND_MESSAGE_DIGEST`; every other value is
    `request_malformed`, never a bundle."""
    author_key = Ed25519PrivateKey.generate()
    principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)
    decision_cap = _sealed_decision(principal_ref)
    body = redress_request_signing_body(MSG_DIGEST, principal_ref)
    sig = author_key.sign(body).hex()
    req = RedressRequest(
        subject_kind="principal_history",
        message_digest=MSG_DIGEST,
        requester_principal_ref=principal_ref,
        requester_signature=sig,
    )

    answer = answer_redress_request(
        [decision_cap], req, signer=FakeSigner(), request_digest="r6", issued_at="2026-09-22T00:00:00Z"
    )
    wire = answer.to_wire()
    assert wire["reason"] == REASON_REQUEST_MALFORMED
    assert "bundles" not in wire
