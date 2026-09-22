# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] The redress-scoped evidence door.

Design doc §4: "why was my message removed?" -> an Evidence Request
(``purpose: redress``, subject = message digest) -> a bundle: the decision
record, the policy version, the adjudication if any, with
``SATISFIED``/``NOT_FOUND``/``WITHHELD`` honesty. Reuses
``evidence_responder.py``'s ``STATUS_*``/``augment_evidence_answer_dict``
wire vocabulary directly -- this door's own success/refusal dicts are shaped
exactly like ``capsule_emit.evidence_request.answer()``'s own
(``{"bundles": [...]}`` / ``{"reason": ...}``) so the SAME wire-status
mapping applies without reimplementing it.

**Not the E14/E15 generic responder.** That module's own docstring is
explicit: it "has no requester-identity parameter at all" -- by design, for
a bilateral counterparty door where identity is out of scope. A redress
request is the opposite case: the whole point is to answer ONLY the
message's own author, refuse everyone else who merely learned the same
digest. This module is a purpose-built door for that one narrow case,
reusing the wire vocabulary, not the identity-blind dispatch.

**Possession, not a bare claim.** A requester does not just ASSERT
``principal_ref`` -- they sign the request under the SAME key the claimed
``nostr-pubkey:<hex>`` names, so a stranger who merely observed the message
digest (rooms are not private) cannot forge a match. This is the
requester-held-half pattern design doc §2 cites, made concrete: signature
verification proves the requester CONTROLS the claimed identity;
comparing that identity against the decision's own bound ``principal_ref``
(set once, at seal time, by the platform -- never by the requester) proves
they are the SAME identity the decision was actually about.

Scope note: ``principal_ref``'s wire form (``join_card.
nostr_pubkey_principal_ref``) names a Nostr (secp256k1) key; this module's
own request-signature check uses Ed25519 (the one signature primitive this
repo already depends on everywhere else -- ``requester_identity_binding.py``,
``node_ownership.py``). Verifying an actual Nostr signature is a real Nostr
client concern, out of scope for this spike (principal_ref binding itself
is an "HONEST GAP... absent by default" per `[mesh-fabric-vocab-alignment]`'s
own DONE stanza) -- this door proves "the requester controls the private key
behind the exact identity string the decision cites," which is the
structural property redress scoping needs, independent of which curve a
production deployment eventually binds.

**Refused by construction, not by a runtime check: per-user history.**
``SUBJECT_KIND_MESSAGE_DIGEST`` is the ONLY subject kind this module's
request type can even represent -- there is no field, anywhere in
``RedressRequest``, that could name a principal and ask for everything they
were ever moderated for. A caller cannot construct the request this would
require; there is no code path to refuse at runtime because there is no
code path at all (design doc §5, "No user scores").
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evidence_responder import augment_evidence_answer_dict
from moderation_decision import MODERATION_SUBJECT_KEY
from moderation_twin import find_adjudication_for_decision

__all__ = [
    "SUBJECT_KIND_MESSAGE_DIGEST",
    "REASON_NO_SUCH_RECORD",
    "REASON_POLICY_DECLINE",
    "REASON_REQUEST_MALFORMED",
    "Signer",
    "RedressRequest",
    "redress_request_signing_body",
    "RedressAnswer",
    "answer_redress_request",
]

#: The one subject kind this door understands. There is deliberately no
#: second value naming a principal/account -- see the module docstring's
#: "Refused by construction" note.
SUBJECT_KIND_MESSAGE_DIGEST = "message_digest"

#: Refusal reasons -- the SAME strings `evidence_responder.
#: status_for_refusal_reason` already maps to NOT_FOUND/WITHHELD, so this
#: door's refusals wire-serialize identically to the generic responder's.
REASON_NO_SUCH_RECORD = "no_such_record"
REASON_POLICY_DECLINE = "policy_decline"
REASON_REQUEST_MALFORMED = "request_malformed"


class Signer(Protocol):
    def sign(self, body: bytes) -> tuple[str, str]:
        """Return `(sig_hex, key_id)` -- same duck-typed contract
        `evidence_responder._refuse_served_summary` calls `capsule_emit.
        signing.resolve_signer(...)` for."""
        ...


@dataclass(frozen=True)
class RedressRequest:
    """A redress request. `subject_kind` MUST be
    `SUBJECT_KIND_MESSAGE_DIGEST` -- any other value is
    `REASON_REQUEST_MALFORMED`, never dispatched (see module docstring).

    `requester_principal_ref` is what the requester CLAIMS to be
    (`join_card.nostr_pubkey_principal_ref`'s wire form);
    `requester_signature` is a hex Ed25519 signature, under the key that
    string names, over `redress_request_signing_body()` -- proof of
    possession, not a bare claim.
    """

    subject_kind: str
    message_digest: str
    requester_principal_ref: str
    requester_signature: str


def redress_request_signing_body(message_digest: str, requester_principal_ref: str) -> bytes:
    """Canonical bytes a redress request's `requester_signature` covers --
    JSON, sorted keys, same convention as every other hex-keyed Ed25519
    artifact in this repo (`moderation_twin._jcs`,
    `requester_identity_binding._jcs`)."""
    body = {"message_digest": message_digest, "requester_principal_ref": requester_principal_ref}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _requester_controls_claimed_identity(req: RedressRequest) -> bool:
    """True iff `req.requester_signature` verifies under the Ed25519 key
    named by `req.requester_principal_ref` itself -- proof the requester
    holds that private key, never trusted from the string alone. See the
    module docstring's scope note on the Nostr/Ed25519 curve boundary."""
    if not req.requester_principal_ref.startswith("nostr-pubkey:"):
        return False
    pub_hex = req.requester_principal_ref.split(":", 1)[1]
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pubkey.verify(
            bytes.fromhex(req.requester_signature),
            redress_request_signing_body(req.message_digest, req.requester_principal_ref),
        )
    except (InvalidSignature, ValueError, TypeError):
        # A malformed hex string, a wrong-length key, or a signature that
        # doesn't verify are all the SAME outcome here: the requester does
        # not control the claimed identity. The caller only ever needs that
        # boolean to decide SATISFIED vs. WITHHELD -- same discipline as
        # `moderation_twin.verify_human_report` / `node_ownership.
        # recheck_ownership_validity`, which likewise collapse these into
        # one first-class "not valid" result rather than a distinct reason
        # per exception type.
        return False
    return True


def _moderation_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get(MODERATION_SUBJECT_KEY, {})


def _find_decisions_for_digest(ledger: list[dict[str, Any]], message_digest: str) -> list[dict[str, Any]]:
    return [
        capsule
        for capsule in ledger
        if _moderation_block(capsule).get("subject_ref", {}).get("message_digest") == message_digest
    ]


def _find_citing(ledger: list[dict[str, Any]], capsule_id: str | None) -> dict[str, Any] | None:
    if capsule_id is None:
        return None
    for capsule in ledger:
        if capsule.get("capsule_id") == capsule_id:
            return capsule
    return None


@dataclass(frozen=True)
class RedressAnswer:
    """A pre-wire-status answer -- shaped exactly like
    `capsule_emit.evidence_request.answer()`'s own return contract
    (`{"bundles": [...]}` / `{"reason": ...}`) so
    `evidence_responder.augment_evidence_answer_dict` applies unchanged."""

    payload: dict[str, Any]

    def to_wire(self) -> dict[str, Any]:
        return augment_evidence_answer_dict(self.payload)


def _refuse(reason: str, *, signer: Signer, request_digest: str, issued_at: str) -> RedressAnswer:
    from capsule_emit.evidence_request import Refusal

    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    refusal = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)
    return RedressAnswer(payload=refusal.to_dict())


def answer_redress_request(
    ledger: list[dict[str, Any]],
    req: RedressRequest,
    *,
    signer: Signer,
    request_digest: str,
    issued_at: str,
) -> RedressAnswer:
    """Answer one redress request against *ledger* (this node's own sealed
    `moderation_decision`/adjudication/human_report capsules).

    Returns a `RedressAnswer` whose `.to_wire()` carries the fabric's
    `status`: `SATISFIED` (the requester IS the subject, bundle attached),
    `NOT_FOUND` (no decision exists for this digest), or `WITHHELD` (a
    decision exists but the requester is not its bound principal -- the
    "non-subject asking for the same digest" case).
    """
    if req.subject_kind != SUBJECT_KIND_MESSAGE_DIGEST:
        return _refuse(REASON_REQUEST_MALFORMED, signer=signer, request_digest=request_digest, issued_at=issued_at)

    decisions = _find_decisions_for_digest(ledger, req.message_digest)
    if not decisions:
        return _refuse(REASON_NO_SUCH_RECORD, signer=signer, request_digest=request_digest, issued_at=issued_at)

    if not _requester_controls_claimed_identity(req):
        return _refuse(REASON_POLICY_DECLINE, signer=signer, request_digest=request_digest, issued_at=issued_at)

    bound_principal_ref = _moderation_block(decisions[0]).get("subject_ref", {}).get("principal_ref")
    if bound_principal_ref is None or bound_principal_ref != req.requester_principal_ref:
        return _refuse(REASON_POLICY_DECLINE, signer=signer, request_digest=request_digest, issued_at=issued_at)

    bundles = []
    for decision_capsule in decisions:
        block = _moderation_block(decision_capsule)
        bundle: dict[str, Any] = {
            "decision": decision_capsule,
            "policy_ref": block.get("policy_ref"),
        }
        adjudication_cap = find_adjudication_for_decision(ledger, decision_capsule["capsule_id"])
        if adjudication_cap is not None:
            bundle["adjudication"] = adjudication_cap
            referee_id = _moderation_block_adjudication(adjudication_cap).get("referee_capsule_id")
            human_report_cap = _find_citing(ledger, referee_id)
            if human_report_cap is not None:
                bundle["human_report"] = human_report_cap
        bundles.append(bundle)

    payload: dict[str, Any] = {
        "v": 1,
        "subject_kind": SUBJECT_KIND_MESSAGE_DIGEST,
        "bundles": bundles,
        "next_page_token": None,
    }
    return RedressAnswer(payload=payload)


def _moderation_block_adjudication(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get("adjudication", {})
