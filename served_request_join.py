#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""B2 — the served<->request cryptographic join.

[mesh-b1-requestor-capsule-ledger] sealed two independent half-records for
one exchange — the provider's served-half capsule and the requester's own
own-half capsule — correlated only by a shared, unauthenticated string:
`serving_provenance.exchange_id`. That correlator ties the two halves for a
reader who already trusts both logs; it is not itself a signed claim either
producer makes about the other.

This module adds the missing cryptographic half: `join_served_request()`
mints ONE new capsule — chained onto the REQUESTER's own ledger — whose
top-level `references` array cites the PROVIDER's served-half `capsule_id`
by CPB typed digest reference with `citation_purpose: "responds_to"`, per
draft-mih-scitt-agent-action-capsule-04's {{xref}} section (landed as spec
text in agent-action-capsule#85; there is no python-library constructor for
it yet, hence `_with_references` below). The reference is a claim this new
capsule's own digest covers: citing a record is itself a digest-committed
assertion.

[adv-served-join-signed] The join capsule alone is still only a
self-attestation, exactly like every other `emit()`-sealed capsule in this
codebase — no key material, digest-only. A stranger checking ONLY the join
capsule's bytes cannot tell it apart from a join anyone could mint over
records they merely hold (the join content is copyable; `exchange_id` is
provider-chosen and relay-visible). `sign_served_request_join()` below is
what makes the module's original claim ("a stranger checks the join's
signature") actually true: it produces a COSE_Sign1 signed statement over
the join capsule's exact bytes, under the JOINER's own node key — the same
signing convention `capsule_sidecar.sign_capsule()` uses for every other
capsule this node mints. The join capsule ALSO carries, inside its own
sealed content, an honest `asserted_by_node_id` field naming who that
joiner is — see `JOIN_ASSERTION_CAVEAT`. This is a ONE-PARTY assertion: it
proves the named joiner signed exactly these bytes, never that the provider
agrees, countersigned, or was even aware a join was minted. A stranger
holding all three records (provider half, requester half, join) plus the
join's signed statement and the joiner's known public key checks, in order:
`verify_served_request_join_signature()` (the signature is real, covers
these exact bytes, and its authenticated issuer matches the capsule's own
`asserted_by_node_id` claim — so the plaintext "who asserts this" label
cannot be swapped independently of the key that actually signed), then that
`references[0].digest` equals the provider capsule's own `capsule_id`, and
that `chain.parent_capsule_id` equals the requester capsule's own
`capsule_id`. `join_served_request()` also refuses to mint unless the
joiner IS the node the requester half itself names as the requesting party
(`JoinerNotRequesterError`) — a different node holding a real, disclosed
requester-half capsule cannot mint a join claiming to have been that
requester; it can still mint a join over those same bytes, but only under
its OWN `asserted_by_node_id`, honestly labeled as its own one-party claim
about someone else's exchange, never as if it were the requester.

Boundary rule this module enforces structurally (the {{xref}} section's own
rule): `chain` is exclusively same-producer-stream (here: the requester's own
prior capsule); `references` is exclusively for the OTHER producer's record.
The join capsule's `chain.parent_capsule_id` and `references[0].digest` are
therefore always two DIFFERENT capsule_ids — see
`test_join_reference_target_differs_from_chain_parent`.

NO Move-4 upgrade here (spec-first pending, per the task): this module never
has the requester counter-sign or acknowledge the provider's `capsule_id` as
its own claim (that would be `cross_party.counterparty_ref`) — it only cites
the provider's bytes by digest, the {{xref}} mechanism, nothing more.

WHAT THIS IS NOT
  - NOT a real-time capture path. `build_capsule` (capsule_sidecar.py) seals
    each half at request/response time, before either side could possibly
    hold the other's `capsule_id`. The join is necessarily a second,
    later step over two ALREADY-SEALED capsules — same "offline, from
    already-sealed bytes" shape as `twin_adjudicator.adjudicate()`.
  - NOT a mutation. Capsules are immutable once sealed; this mints a new
    record, exactly like `twin_adjudicator.seal_adjudication_capsule`.
  - NOT a trust upgrade for either half. `join_served_request` refuses to
    mint over a half that does not already verify on its own bytes (see
    `UnverifiableHalfError`) — the join can only add a citation between two
    records that were each already sound.
"""
from __future__ import annotations

import json
from typing import Any

import scitt_cose

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule

__all__ = [
    "CITATION_PURPOSE_RESPONDS_TO",
    "JOIN_ASSERTION_CAVEAT",
    "JOIN_CHAIN_RELATION",
    "JOIN_CONTENT_TYPE",
    "JOIN_SCHEMA",
    "REFERENCE_DIGEST_ALG",
    "REFERENCE_TYPE_CAPSULE",
    "SIG_ALG",
    "ExchangeIdMismatchError",
    "JoinerNotRequesterError",
    "RoleMismatchError",
    "SignerMismatchError",
    "UnverifiableHalfError",
    "build_reference",
    "join_served_request",
    "sign_served_request_join",
    "verify_served_request_join_signature",
]

#: CPB Artifact Type registry value for "another Agent Action Capsule"
#: (the same value `capsule-emit`'s composition layer already uses for its
#: own member typed digest references — `capsule_emit/surface.py`'s
#: `_MEMBER_TYPE`/`_DIGEST_ALG`; this module cites the same registry entry
#: for the same reason, a different field).
REFERENCE_TYPE_CAPSULE = "capsule"
REFERENCE_DIGEST_ALG = "SHA-256"

#: draft-mih-scitt-agent-action-capsule-04 {{xref}}'s seeded `citation_purpose`
#: value for "this Capsule addresses or answers the cited record without a
#: same-stream chain relationship to it" — exactly the served<->request
#: relationship: the requester's own-half capsule responds to what the
#: provider's served-half capsule attests it served.
CITATION_PURPOSE_RESPONDS_TO = "responds_to"

#: The join capsule is a same-stream, non-terminal continuation of the
#: requester's own ledger (§{{hitl}}'s `confirms`: "this Capsule observes or
#: records the outcome of the parent; the parent's open state remains") —
#: it never uses `chain` to cite the provider's (a different producer's)
#: capsule; that citation is exclusively the `references` entry below.
JOIN_CHAIN_RELATION = "confirms"

JOIN_SCHEMA = "capsule-emit-mesh/served-request-join/v1"

#: EdDSA (Ed25519) — same alg name capsule_sidecar.SIG_ALG uses for every
#: other capsule this node signs. One signing convention, one verifier.
SIG_ALG = "EdDSA"

#: COSE content_type for a join's signed statement, mirroring
#: capsule_sidecar.sign_capsule()'s "application/vnd.agent-action-capsule
#: +json; profile=..." convention with this module's own schema tag.
JOIN_CONTENT_TYPE = f"application/vnd.agent-action-capsule+json; profile={JOIN_SCHEMA}"

#: [adv-served-join-signed] Sealed INTO the join capsule's own content
#: (compute_attestation.served_request_join.assertion_limitation) so the
#: honesty grade travels with the bytes, same discipline as
#: node_ownership.IDENTITY_LIMITATION_CAVEAT / requester_commitment.
#: IDENTITY_LIMITATION_CAVEAT. Names exactly what a verified join signature
#: does and does not prove — see sign_served_request_join() /
#: verify_served_request_join_signature().
JOIN_ASSERTION_CAVEAT = (
    "one-party-join-assertion: this join is signed by the JOINER named in "
    "asserted_by_node_id alone. verify_served_request_join_signature() "
    "confirms that node's signature is real, covers these exact bytes, and "
    "was issued as this capsule's own capsule_id -- it does NOT and cannot "
    "prove the provider agrees with, countersigned, or was even aware this "
    "join exists. A verified join signature means 'the joiner stands behind "
    "this citation', never 'both parties agree these halves belong "
    "together'. join_served_request() additionally refuses to mint unless "
    "the joiner is the node the requester half itself names as the "
    "requesting party (JoinerNotRequesterError) -- so this label can never "
    "read as if a stranger asserted someone else's exchange -- but the "
    "requester half's own requesting_party is itself self-attested, exactly "
    "as requester_commitment.IDENTITY_LIMITATION_CAVEAT / "
    "requester_identity_binding.IDENTITY_LIMITATION_CAVEAT already disclose: "
    "cross-checking both halves' independently-authenticated identities "
    "against EACH OTHER, rather than trusting either producer's own "
    "self-attested name for itself, remains open."
)


class UnverifiableHalfError(RuntimeError):
    """A supplied half fails its own `agent_action_capsule.verify()`.

    The join can only add a citation between two records that were already
    independently sound — it is never the mechanism that makes a forged or
    malformed half trustworthy.
    """


class RoleMismatchError(ValueError):
    """*provider_capsule*/*requester_capsule* are not the roles they claim.

    Guards against a caller accidentally swapping the two arguments (or
    passing the same capsule for both): each half's own
    `serving_provenance.role` (b6a-requester-seal) must match the position
    it was passed in.
    """


class ExchangeIdMismatchError(ValueError):
    """The two halves do not share one `serving_provenance.exchange_id`.

    Joining two capsules from DIFFERENT exchanges would fabricate a
    served<->request relationship that never happened at the wire — refused
    rather than minted.
    """


class JoinerNotRequesterError(ValueError):
    """*joiner_node_id* is not the node the requester half names as itself.

    [adv-served-join-signed]: the join chains onto the REQUESTER's own
    ledger stream ({{xref}}'s same-producer-stream rule), so only the node
    the requester half's own `serving_provenance.requesting_party` names may
    mint it. Refusing this up front — rather than minting a join a
    different node could later sign under a false `asserted_by_node_id` —
    is what stops a party who merely HOLDS a disclosed requester-half
    capsule (relay-visible, or fetched via an evidence door) from minting a
    join that claims to have been that requester.
    """


class SignerMismatchError(ValueError):
    """*signing_node_id* does not match this join's own `asserted_by_node_id`.

    `sign_served_request_join()` refuses to sign a join under an identity
    different from the one already sealed into its content — an "asserted
    by X" label and "signed by Y" signature must never travel together.
    """


def _serving_provenance(capsule: dict[str, Any]) -> dict[str, Any]:
    poc = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("x-mesh-poc-v1") or {}
    return poc.get("serving_provenance") or {}


def _asserted_by_node_id(joined_capsule: dict[str, Any]) -> str | None:
    """The `asserted_by_node_id` a join capsule's own sealed content names —
    i.e. who this specific join claims to be asserted by. Read from the
    same `compute_attestation.served_request_join` block `join_served_
    request()` writes it into, so a stranger and this module agree on where
    to look."""
    ca = (joined_capsule.get("model_attestation") or {}).get("compute_attestation") or {}
    return (ca.get("served_request_join") or {}).get("asserted_by_node_id")


def _canonical_join_payload(joined_capsule: dict[str, Any]) -> bytes:
    """The exact bytes `sign_served_request_join()` signs and
    `verify_served_request_join_signature()` re-checks against — full
    capsule JSON, sorted keys, no whitespace. Same convention `capsule_
    sidecar.sign_capsule()` uses, so a join's signed statement is byte-
    comparable the same way every other capsule's is."""
    return json.dumps(joined_capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_reference(capsule_id: str, *, citation_purpose: str = CITATION_PURPOSE_RESPONDS_TO) -> dict[str, Any]:
    """One CPB typed digest reference citing *capsule_id* (AAC {{xref}} shape)."""
    return {
        "type": REFERENCE_TYPE_CAPSULE,
        "digest_alg": REFERENCE_DIGEST_ALG,
        "digest": capsule_id,
        "citation_purpose": citation_purpose,
    }


def _with_references(sealed: dict[str, Any], references: list[dict[str, Any]]) -> dict[str, Any]:
    """Add a top-level `references` array to an already-`emit()`-sealed
    capsule and recompute `capsule_id` over the resulting bytes.

    `agent_action_capsule.emit()` (and the `Capsule` dataclass behind it) has
    no `references` parameter — the {{xref}} section landed as spec text
    only (agent-action-capsule#85), with no python-library constructor yet.
    `compute_capsule_id` (canonical.py) is generic over whatever top-level
    keys the dict carries: given a `jcs`-declared capsule it excludes only
    `capsule_id` and the local-only signature/key_id fields, so adding
    `references` here and recomputing produces EXACTLY the digest
    `Capsule.seal()` would produce if the dataclass had the field —
    `references` participates in `capsule_id` like the rest of the payload,
    per {{xref}}'s own requirement.
    """
    joined = dict(sealed)
    joined["references"] = references
    joined["capsule_id"] = compute_capsule_id(joined)
    return joined


def join_served_request(
    provider_capsule: dict[str, Any],
    requester_capsule: dict[str, Any],
    *,
    joiner_node_id: str,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Mint the served<->request join capsule.

    *provider_capsule* is the provider's already-sealed served-half capsule
    (`serving_provenance.role == "provider"`); *requester_capsule* is the
    requester's already-sealed own-half capsule for the SAME exchange
    (`serving_provenance.role == "requester"`, same `exchange_id`).
    *joiner_node_id* is who this join capsule will claim, in its own sealed
    content, to be asserted by (`compute_attestation.served_request_join.
    asserted_by_node_id`) — pass `sign_served_request_join()`'s
    `signing_node_id` this same value, since a stranger checks that the two
    match. Returns a new capsule, chained onto the requester's own stream
    (`chain.parent_capsule_id == requester_capsule["capsule_id"]`,
    `chain.relation == "confirms"`), whose `references` array cites the
    provider capsule by CPB typed digest reference
    (`citation_purpose == "responds_to"`).

    This capsule is still, on its own, only a self-attestation — call
    `sign_served_request_join()` on the return value to produce the actual
    signed statement a stranger can check (see the module docstring and
    `JOIN_ASSERTION_CAVEAT`).

    Raises :class:`UnverifiableHalfError` if either half fails its own
    `verify()`, :class:`RoleMismatchError` if the two arguments are not the
    roles they claim, :class:`ExchangeIdMismatchError` if they do not share
    one `exchange_id`, and :class:`JoinerNotRequesterError` if
    *joiner_node_id* is not the node the requester half itself names as the
    requesting party — never silently joins two records that should not be
    joined, and never lets a party mint a join claiming to have been a
    requester it was not.
    """
    for half, label in ((provider_capsule, "provider"), (requester_capsule, "requester")):
        result = verify_capsule(half)
        if not result.ok:
            raise UnverifiableHalfError(f"{label} half fails verify(): {result.findings}")

    provider_role = _serving_provenance(provider_capsule).get("role")
    if provider_role != "provider":
        raise RoleMismatchError(
            f"provider_capsule.serving_provenance.role == {provider_role!r}, expected 'provider'"
        )
    requester_role = _serving_provenance(requester_capsule).get("role")
    if requester_role != "requester":
        raise RoleMismatchError(
            f"requester_capsule.serving_provenance.role == {requester_role!r}, expected 'requester'"
        )

    requesting_party = _serving_provenance(requester_capsule).get("requesting_party")
    if joiner_node_id != requesting_party:
        raise JoinerNotRequesterError(
            f"joiner_node_id {joiner_node_id!r} != requester_capsule's own "
            f"serving_provenance.requesting_party {requesting_party!r} -- "
            f"only the node the requester half itself names may mint a join "
            f"chained onto it"
        )

    provider_exchange_id = _serving_provenance(provider_capsule).get("exchange_id")
    requester_exchange_id = _serving_provenance(requester_capsule).get("exchange_id")
    if not provider_exchange_id or provider_exchange_id != requester_exchange_id:
        raise ExchangeIdMismatchError(
            f"provider exchange_id {provider_exchange_id!r} != "
            f"requester exchange_id {requester_exchange_id!r} -- refusing to join"
        )

    compute_attestation = {
        "served_request_join": {
            "schema": JOIN_SCHEMA,
            # Carried directly (not just reachable by dereferencing
            # chain.parent_capsule_id) so a stranger reading only this join
            # capsule already knows which exchange it is about.
            "exchange_id": requester_exchange_id,
            # HONESTY GRADE, sealed INTO the join itself (same discipline as
            # node_ownership.seal_identity_capsule's identity_limitation):
            # who is making this specific assertion, and what that assertion
            # does and does not prove. Committed to capsule_id below, so
            # tampering either field post-seal is caught by verify() same as
            # tampering `references`.
            "asserted_by_node_id": joiner_node_id,
            "assertion_limitation": JOIN_ASSERTION_CAVEAT,
        }
    }
    disposition = Disposition(
        decision="accept",
        approver="policy",
        human_disposed=False,
        verdict_class="executed",
    )

    sealed = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        disposition=disposition,
        prior_capsule_id=requester_capsule["capsule_id"],
        chain_relation=JOIN_CHAIN_RELATION,
        domain="action",
        provenance="collector",
        tool_name="served_request_join",
    )
    joined = _with_references(sealed, [build_reference(provider_capsule["capsule_id"])])

    # verify-before-return discipline (matches twin_adjudicator.
    # seal_adjudication_capsule): a join capsule that fails its own
    # verify() must never be handed to a caller that might persist it.
    result = verify_capsule(joined)
    if not result.ok:
        raise RuntimeError(f"join_served_request emitted a capsule that fails its own verify(): {result.findings}")
    return joined


def sign_served_request_join(
    joined_capsule: dict[str, Any],
    *,
    signing_key_pem: bytes | str,
    signing_node_id: str,
) -> bytes:
    """Sign *joined_capsule* under the joiner's own node key.

    This is the piece the module docstring always claimed existed — a real
    COSE_Sign1 signed statement, over these exact capsule bytes, under the
    identity that names itself in the capsule's own `asserted_by_node_id`.
    Mirrors `capsule_sidecar.sign_capsule()`'s exact convention (full-
    capsule-JSON payload, EdDSA, issuer/subject CWT claims) so a join's
    signed statement sits alongside every other capsule this node signs,
    checked the same way (see `verify_served_request_join_signature()`).

    Raises :class:`SignerMismatchError` if *signing_node_id* is not this
    join's own `asserted_by_node_id` — refusing to let a plaintext "asserted
    by X" label and an actual "signed by Y" signature travel together under
    different names.
    """
    asserted_by = _asserted_by_node_id(joined_capsule)
    if signing_node_id != asserted_by:
        raise SignerMismatchError(
            f"signing_node_id {signing_node_id!r} != this join's own "
            f"asserted_by_node_id {asserted_by!r} -- refusing to sign a "
            f"join under an identity different from the one already sealed "
            f"into its content"
        )
    return scitt_cose.build_signed_statement(
        _canonical_join_payload(joined_capsule),
        alg=SIG_ALG,
        private_key_pem=signing_key_pem,
        issuer=signing_node_id,
        subject=joined_capsule["capsule_id"],
        content_type=JOIN_CONTENT_TYPE,
    )


def verify_served_request_join_signature(
    joined_capsule: dict[str, Any],
    signed_statement: bytes,
    *,
    public_key_pem: bytes | str,
) -> tuple[bool, str]:
    """Verify a join's signature. Returns `(valid, reason)` — never raises,
    same discipline as `requester_commitment.verify_requester_commitment()`.

    Confirms, in order: the COSE_Sign1 signature verifies under
    *public_key_pem*; the signed payload is these EXACT capsule bytes (not
    some other capsule's, and not a tampered copy — `join_served_request()`
    commits `asserted_by_node_id`/`assertion_limitation` into `capsule_id`,
    so a tampered field also fails `agent_action_capsule.verify()`
    separately); the signed subject is this capsule's own `capsule_id`; and
    the signature's authenticated issuer matches this capsule's own
    `asserted_by_node_id` claim — so a forged "who asserts this" label can
    never ride along with a signature from a different key.

    A `True` result proves ONLY that `asserted_by_node_id` holds the signing
    key behind *public_key_pem* and produced these exact bytes — see
    `JOIN_ASSERTION_CAVEAT` for what it does not prove.
    """
    parsed = scitt_cose.parse_signed_statement(signed_statement, public_key_pem=public_key_pem)
    if not parsed["signature_verified"]:
        return False, "join signature does not verify under the supplied public key"
    if parsed["payload"] != _canonical_join_payload(joined_capsule):
        return False, "join signature covers different bytes than this capsule"
    if parsed["subject"] != joined_capsule.get("capsule_id"):
        return False, (
            f"signed subject {parsed['subject']!r} != this capsule's own "
            f"capsule_id {joined_capsule.get('capsule_id')!r}"
        )
    asserted_by = _asserted_by_node_id(joined_capsule)
    if parsed["issuer"] != asserted_by:
        return False, (
            f"signature issuer {parsed['issuer']!r} does not match this "
            f"join's own asserted_by_node_id claim {asserted_by!r} -- the "
            f"plaintext 'who asserts this' label does not match who "
            f"actually signed"
        )
    return True, (
        f"join signature verified: {asserted_by!r} signed these exact "
        f"bytes, subject == this capsule's own capsule_id"
    )
