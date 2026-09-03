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
capsule's own signature covers: citing a record is itself a digest-committed
assertion, so a stranger holding all three records (provider half, requester
half, join) can verify the join is real without trusting either producer's
say-so — they check the join's signature, then that its `references[0].digest`
equals the provider capsule's own `capsule_id`, and that its `chain.
parent_capsule_id` equals the requester capsule's own `capsule_id`.

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

from typing import Any

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule

__all__ = [
    "CITATION_PURPOSE_RESPONDS_TO",
    "JOIN_CHAIN_RELATION",
    "JOIN_SCHEMA",
    "REFERENCE_DIGEST_ALG",
    "REFERENCE_TYPE_CAPSULE",
    "ExchangeIdMismatchError",
    "RoleMismatchError",
    "UnverifiableHalfError",
    "build_reference",
    "join_served_request",
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


def _serving_provenance(capsule: dict[str, Any]) -> dict[str, Any]:
    poc = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("x-mesh-poc-v1") or {}
    return poc.get("serving_provenance") or {}


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
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Mint the served<->request join capsule.

    *provider_capsule* is the provider's already-sealed served-half capsule
    (`serving_provenance.role == "provider"`); *requester_capsule* is the
    requester's already-sealed own-half capsule for the SAME exchange
    (`serving_provenance.role == "requester"`, same `exchange_id`). Returns
    a new capsule, chained onto the requester's own stream
    (`chain.parent_capsule_id == requester_capsule["capsule_id"]`,
    `chain.relation == "confirms"`), whose `references` array cites the
    provider capsule by CPB typed digest reference
    (`citation_purpose == "responds_to"`).

    Raises :class:`UnverifiableHalfError` if either half fails its own
    `verify()`, :class:`RoleMismatchError` if the two arguments are not the
    roles they claim, and :class:`ExchangeIdMismatchError` if they do not
    share one `exchange_id` — never silently joins two records that should
    not be joined.
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
