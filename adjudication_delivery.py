# SPDX-License-Identifier: Apache-2.0
"""[mesh-adjudication-delivery-ack] -- deliver a sealed twin-adjudication
capsule (`twin_adjudicator.seal_adjudication_capsule`) to each cited
party's evidence door, so the verdict actually reaches the judged node's
own chain instead of staying stranded on the requester's alone ("the twin
is half a protocol" without this leg).

Route: ``POST /evidence/deliver``
    body = the adjudication capsule's own canonical JSON bytes -- opaque at
        the transport level, the same convention ``/evidence-request``
        uses for its request map.
    200 + ``{"status": "received"}`` -- the recipient found its own served
        half among the capsule's cited ``*_capsule_id`` fields and folded
        the capsule, AS TRANSMITTED (signature untouched, never re-signed
        by the recipient), into its own ledger, followed by ITS OWN
        ``adjudication_delivery_receipt`` (see
        ``seal_adjudication_delivery_receipt``) -- sealed unconditionally,
        right here, so "this arrived by delivery" is on the record before
        the subject has even decided whether to ack or dispute it.
    200 + a signed ``Refusal`` (``{request_digest, reason, issued_at,
        key_id, sig}``) -- either

          * ``request_malformed`` -- the delivery does not cite this node's
            own half (unparseable body, a capsule that fails its own
            ``verify()``, or citations that simply don't include a capsule
            this node ever sealed). Refused BEFORE this node's ledger is
            ever touched -- it never ``received()``s a verdict about
            someone else.
          * ``policy_decline`` -- citations resolve fine (this node's own
            half IS cited), but this node's own policy declines to hold a
            verdict that names it as the contradicted party. A NEW reason,
            scoped to this delivery protocol only -- not one of E14's own
            closed ``capsule_emit.evidence_request.REFUSAL_REASONS`` (this
            is a different responder with its own decline vocabulary); it
            reuses that module's ``Refusal`` shape verbatim so it verifies
            offline the same way.

Requester side (`deliver_adjudication`) is the one POST above. On a
refusal, the caller -- not this module, see `seal_adjudication_ack_refused`
-- seals a NEW ``adjudication_ack_refused`` capsule citing the original
verdict, so the requester's OWN chain holds a record of the decline even
where the judged node's chain shows nothing.

**On an ACCEPTED delivery** (``{"status": "received"}``, never a
``policy_decline``), the SUBJECT's own follow-up is one of
``seal_adjudication_ack`` (does not dispute the verdict) or
``seal_adjudication_rebuttal`` (disputes it, with a stated ``basis``) --
``[mesh-adjudications-on-history-card-design]``, ``deliver_to_subjects:
default on``. Same "the caller, not this module" discipline as the refused
path: `handle_delivery` folds and transports; it never judges a verdict's
correctness, so it never seals ack/rebuttal itself. `history_card.py`'s own
provenance split (authored vs. delivered-with-ack/rebuttal-state) keys
"delivered" off the ``adjudication_delivery_receipt`` above -- NOT off
whether an ack/rebuttal exists yet, so a verdict this node has accepted but
not yet acked/disputed still reads as delivered, never misclassified as
authored -- reading these relations plus `twin_adjudicator.RELATION_
ADJUDICATES` back out of a node's ledger via `twin_adjudicator.
classify_capsule_kind`.

**Trust scope of the authored/delivered split, stated plainly:** like every
other self-reported property in this repo (`temporal_provenance:
producer_asserted`, `node_ownership`'s `IDENTITY_LIMITATION_CAVEAT`), this
is `self_attested` -- a node's own ledger is not cryptographically hardened
against that SAME node calling `handle_delivery` on a capsule it authored
itself to make its own verdict read as "delivered". Nothing in this repo
signs a delivery event with the SENDER's key (there is no sender identity
to check against -- see the module's "Only the citations this repo mints
today are checked" note above), so this split is honest about a node's own
bookkeeping, not a cross-party attestation.

**Only the citations this repo mints today are checked.** The full
twin-adjudication design (``_work/mesh-referee-build-2026-09-02.md`` §2.1)
cites FOUR records -- requester commitment, half A, half B, referee half --
but ``twin_adjudicator.seal_adjudication_capsule`` (E17a, offline-only, no
live twin-send or referee step yet -- see that module's docstring) only
ever embeds ``half_a_capsule_id``/``half_b_capsule_id``. `_cited_capsule_ids`
reads every ``*_capsule_id``-suffixed key off the capsule's own
``compute_attestation.adjudication`` block rather than hard-coding those
two names, so a future commitment/referee citation is picked up unchanged,
with no rework here, once E17b/E17c wire them.

**Policy-decline's owner check shares a known limitation with
`twin_adjudicator.AdjudicationHalf`**: it reads `owner_id` from
`compute_attestation.owner.owner_id` directly (the test-fixture and E17a
convention) -- NOT the richer, nested `x-mesh-poc-v1.owner.owner_id` block
`capsule_sidecar.build_capsule` actually seals in production today. Wiring
that reconciliation is E6/E17a's gap, not this module's; when `owner_id` is
absent (`None`), `policy_decline` is simply never reached -- honest
absence, never a fabricated verdict.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.evidence_request import Refusal
from capsule_emit.signing import resolve_signer

from evidence_responder import status_for_refusal_reason
from ledger_store_backend import append_capsule, read_all_capsules

__all__ = [
    "EVIDENCE_DELIVER_PATH",
    "REASON_POLICY_DECLINE",
    "REASON_REQUEST_MALFORMED",
    "RELATION_ADJUDICATION_ACK",
    "RELATION_ADJUDICATION_ACK_REFUSED",
    "RELATION_ADJUDICATION_DELIVERY_RECEIPT",
    "RELATION_ADJUDICATION_REBUTTAL",
    "deliver_adjudication",
    "handle_delivery",
    "seal_adjudication_ack",
    "seal_adjudication_ack_refused",
    "seal_adjudication_delivery_receipt",
    "seal_adjudication_rebuttal",
]

EVIDENCE_DELIVER_PATH = "/evidence/deliver"

#: NEW reason, scoped to this delivery protocol only -- see module docstring.
REASON_POLICY_DECLINE = "policy_decline"
#: Reused verbatim from `capsule_emit.evidence_request.REASON_REQUEST_MALFORMED`
#: (same meaning: the request itself doesn't check out) -- named locally so
#: this module never imports a private symbol to get it.
REASON_REQUEST_MALFORMED = "request_malformed"

#: The new chain.relation value for the requester's own record of a refused
#: delivery -- mirrors `twin_adjudicator.RELATION_ADJUDICATES`.
RELATION_ADJUDICATION_ACK_REFUSED = "adjudication_ack_refused"

#: [mesh-adjudications-on-history-card-design] The chain.relation values for
#: the JUDGED SUBJECT's own record of an ACCEPTED delivery (`handle_delivery`
#: returned `{"status": "received"}`, i.e. this was never `policy_decline`d)
#: -- `deliver_to_subjects`'s default-on behaviour (design note §3): every
#: judged node seals ONE of these citing the delivered verdict, never both.
#: Distinct from `RELATION_ADJUDICATION_ACK_REFUSED` above, which is the
#: REQUESTER's own record of a delivery the subject refused to even hold.
RELATION_ADJUDICATION_ACK = "adjudication_ack"
RELATION_ADJUDICATION_REBUTTAL = "adjudication_rebuttal"

#: [mesh-adjudications-on-history-card-design] The chain.relation for
#: `handle_delivery`'s OWN receipt of an accepted delivery -- sealed
#: unconditionally, at fold time, BEFORE the subject has decided ack vs.
#: rebuttal (see `seal_adjudication_delivery_receipt`). This is the
#: signal `history_card.adjudication_provenance_from_ledger` reads to tell
#: "delivered" (provenance b) from "authored" (provenance a): capsules
#: carry no per-capsule signature (`agent_action_capsule.emit()` signs
#: nothing at the record level), so authorship cannot be read off a
#: `key_id`. Keying "delivered" off the ack/rebuttal decision ALONE was
#: tried first and is wrong even in the honest case -- a delivered verdict
#: this node has not yet acked/rebutted would misclassify as "authored"
#: (adversarial council finding, [mesh-adjudications-on-history-card-
#: design]-review). Keying off THIS receipt instead is correct as soon as
#: `handle_delivery` folds the capsule, independent of whether/when the
#: subject later acks or disputes it.
RELATION_ADJUDICATION_DELIVERY_RECEIPT = "adjudication_delivery_receipt"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _adjudication_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("adjudication") or {}


def _cited_capsule_ids(capsule: dict[str, Any]) -> list[str]:
    """Every ``*_capsule_id`` value cited by this capsule's own
    ``adjudication`` block -- forward-compatible with citations this repo
    does not mint yet (see module docstring)."""
    block = _adjudication_block(capsule)
    return [v for k, v in block.items() if k.endswith("_capsule_id") and isinstance(v, str) and v]


def _owner_id(capsule: dict[str, Any]) -> str | None:
    owner = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("owner") or {}
    return owner.get("owner_id")


def seal_adjudication_delivery_receipt(
    adjudication_capsule: dict[str, Any],
    *,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Seal this node's OWN receipt of an accepted delivery -- citing the
    adjudication by id, no verdict-bearing content beyond that citation.
    Called by `handle_delivery` itself, unconditionally, at fold time (see
    `RELATION_ADJUDICATION_DELIVERY_RECEIPT`'s own docstring for why this
    must not wait for the subject's later ack/rebuttal decision).

    Distinct from `seal_adjudication_ack`/`seal_adjudication_rebuttal`: this
    is minted automatically, by the transport itself, the instant a delivery
    is accepted; ack/rebuttal are minted LATER, by the caller, once the
    subject has actually decided whether it disputes the verdict.
    """
    receipt_block = {"adjudication_capsule_id": adjudication_capsule["capsule_id"]}
    compute_attestation = {"adjudication_delivery_receipt": receipt_block}
    capsule = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        prior_capsule_id=adjudication_capsule["capsule_id"],
        chain_relation=RELATION_ADJUDICATION_DELIVERY_RECEIPT,
        domain="action",
        provenance="referee",
        tool_name="adjudication_delivery_receipt",
    )
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"adjudicator emitted a delivery-receipt capsule that fails its own verify(): {result.findings}")
    return capsule


def _refuse(request_digest: str, reason: str, *, state: Any, issued_at: str) -> dict[str, Any]:
    """Sign a refusal and return its wire dict, with the fabric's additive
    `status` (`[mesh-fabric-vocab-alignment]`) layered on beside `reason` --
    `WITHHELD` for `policy_decline`, absent for `request_malformed` (see
    `evidence_responder.status_for_refusal_reason`'s own docstring)."""
    signer = resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path)
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    refusal = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)
    d = refusal.to_dict()
    status = status_for_refusal_reason(reason)
    if status is not None:
        d["status"] = status
    return d


def handle_delivery(state: Any, body: bytes, *, now: str | None = None) -> dict[str, Any]:
    """Handle one ``POST /evidence/deliver`` body against ``state``'s own
    ledger -- duck-typed like ``evidence_server.EvidenceServerState``
    (``ledger_path`` + ``signing_key_path``, nothing else).

    Returns ``{"status": "received"}`` or a signed refusal dict (``Refusal
    .to_dict()`` plus an additive fabric ``status``, see ``_refuse``) --
    never raises on malformed input, mirroring E14 ``answer()``'s
    discipline of one signed answer for every well-formed OR malformed
    request.
    """
    issued_at = now or _now_iso()
    request_digest = hashlib.sha256(body).hexdigest()

    try:
        capsule = json.loads(body)
    except Exception:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    if not isinstance(capsule, dict) or not capsule.get("capsule_id"):
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    result = verify_capsule(capsule)
    if not result.ok:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    cited = _cited_capsule_ids(capsule)
    if not cited:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    own_records, _archived_segments = read_all_capsules(state.ledger_dir)
    own_entries = {e["capsule_id"]: e for e in own_records}
    own_half = next((own_entries[cid] for cid in cited if cid in own_entries), None)
    if own_half is None:
        # Own half not among the citations -- never received() a verdict
        # about someone else.
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    own_owner_id = _owner_id(own_half)
    verdict = _adjudication_block(capsule).get("verdict")
    if own_owner_id and verdict == f"contradicted:{own_owner_id}":
        return _refuse(request_digest, REASON_POLICY_DECLINE, state=state, issued_at=issued_at)

    append_capsule(state.ledger_dir, capsule)
    # [mesh-adjudications-on-history-card-design] Seal the delivery receipt
    # UNCONDITIONALLY, right here at fold time -- see
    # RELATION_ADJUDICATION_DELIVERY_RECEIPT's own docstring for why this
    # must not wait for the subject's later ack/rebuttal decision.
    append_capsule(state.ledger_dir, seal_adjudication_delivery_receipt(capsule))
    return {"status": "received"}


def deliver_adjudication(capsule: dict[str, Any], door_base_url: str, *, timeout: float = 30) -> dict[str, Any]:
    """POST ``capsule`` (its own canonical JSON bytes) to
    ``door_base_url``'s ``/evidence/deliver``; return the parsed JSON
    response unmodified -- ``{"status": "received"}`` or a Refusal dict
    (distinguish by ``"reason" in response``, the same convention
    ``ask_history.py`` uses for ``/evidence-request``)."""
    body = json.dumps(capsule, sort_keys=True).encode("utf-8")
    url = door_base_url.rstrip("/") + EVIDENCE_DELIVER_PATH
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def seal_adjudication_ack(
    adjudication_capsule: dict[str, Any],
    *,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Seal the JUDGED SUBJECT's own record of an ACCEPTED delivered
    adjudication -- citing the verdict by id, never restating it as a score.

    ``deliver_to_subjects: default on`` (design note §3): every node a twin
    adjudication judges receives the verdict via ``handle_delivery``; once
    that call has folded the capsule into this node's own ledger (i.e.
    returned ``{"status": "received"}``, never a ``policy_decline`` --
    ``handle_delivery`` itself already refuses to hold a verdict that names
    THIS node as the contradicted party, so an accepted delivery is never
    one this node disputes on citation grounds alone), the subject seals
    ONE follow-up record: this ``ack`` when it does not dispute the verdict,
    or ``seal_adjudication_rebuttal`` when it does. Never both, and never
    automatic -- same "the caller, not this module" discipline
    ``seal_adjudication_ack_refused`` already documents: this module folds
    and transports, it does not itself judge whether a verdict is correct.
    """
    ack_block = {
        "adjudication_capsule_id": adjudication_capsule["capsule_id"],
        "verdict": _adjudication_block(adjudication_capsule).get("verdict"),
    }
    compute_attestation = {"adjudication_ack": ack_block}
    capsule = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        prior_capsule_id=adjudication_capsule["capsule_id"],
        chain_relation=RELATION_ADJUDICATION_ACK,
        domain="action",
        provenance="referee",
        tool_name="adjudication_ack",
    )
    # [adv-run-2-fix-batch] discipline: verify BEFORE returning -- matches
    # twin_adjudicator.seal_adjudication_capsule.
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"adjudicator emitted an ack capsule that fails its own verify(): {result.findings}")
    return capsule


def seal_adjudication_rebuttal(
    adjudication_capsule: dict[str, Any],
    *,
    basis: str,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Seal the JUDGED SUBJECT's own record DISPUTING an accepted delivered
    adjudication -- citing the verdict by id plus a STATED ``basis`` (a
    reason the subject supplies for why it disputes the verdict).

    **What "no free-text score" actually means here, stated precisely so
    this docstring does not overclaim:** the record's SCHEMA carries no
    score/rating field at all -- ``rebuttal_block`` below has exactly
    ``adjudication_capsule_id``/``verdict``/``basis``, nothing numeric or
    ordinal. This function does NOT content-validate ``basis`` -- it is a
    free-form string, and nothing stops a caller from writing a score-
    shaped value INTO it (e.g. ``basis="2/10"``). The only enforced
    invariant is non-emptiness (``ValueError`` on ``basis=""``): an
    unreasoned dispute is indistinguishable from noise and would let a node
    contest any verdict it dislikes with no accountable trail. Content
    discipline over what a `basis` string actually says is a caller/policy
    concern, not something this function checks.

    See ``seal_adjudication_ack``'s docstring for how this fits the
    ``deliver_to_subjects`` default-on flow -- the two are mutually
    exclusive follow-ups to the SAME accepted delivery, chosen by the
    caller (this module never judges a verdict's correctness itself).
    """
    if not basis:
        raise ValueError("seal_adjudication_rebuttal requires a non-empty basis")
    rebuttal_block = {
        "adjudication_capsule_id": adjudication_capsule["capsule_id"],
        "verdict": _adjudication_block(adjudication_capsule).get("verdict"),
        "basis": basis,
    }
    compute_attestation = {"adjudication_rebuttal": rebuttal_block}
    capsule = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        prior_capsule_id=adjudication_capsule["capsule_id"],
        chain_relation=RELATION_ADJUDICATION_REBUTTAL,
        domain="action",
        provenance="referee",
        tool_name="adjudication_rebuttal",
    )
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"adjudicator emitted a rebuttal capsule that fails its own verify(): {result.findings}")
    return capsule


def seal_adjudication_ack_refused(
    adjudication_capsule: dict[str, Any],
    refusal: dict[str, Any],
    *,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Seal the record the REQUESTER holds when a cited party refuses
    delivery -- citing the original verdict (``prior_capsule_id``) so the
    requester's own chain shows the decline even where the judged node's
    chain shows nothing (mutant: a ``policy_decline``'d ``contradicted``
    twin -- the contradicted party's own chain never carries it; this
    capsule is where it lives instead, discoverable later by a
    ``correlation`` evidence-request subject naming this requester's
    counterparty).

    ``counterparty_ref`` names that declining counterparty explicitly --
    the ``contradicted:<owner_id>`` suffix of the original verdict, parsed
    back out once here rather than making every caller re-parse it. Without
    this field a ``correlation{by: counterparty, value: <owner_id>}`` ask
    of the REQUESTER's own door has nothing to match against
    (``capsule_emit.evidence_request``'s ``counterparty`` alias set is
    ``{counterparty_ref}`` plus its own separate scan for a nested
    ``adjudication.verdict`` -- this block is named
    ``adjudication_ack_refused``, not ``adjudication``, so that second path
    never sees it either); this is what makes the docstring's own
    "discoverable later" claim actually true. `None` when the original
    verdict was not a ``contradicted:<owner_id>`` shape (never fabricated).
    """
    original_block = _adjudication_block(adjudication_capsule)
    original_verdict = original_block.get("verdict")
    counterparty_ref = (
        original_verdict.split(":", 1)[1]
        if isinstance(original_verdict, str) and original_verdict.startswith("contradicted:")
        else None
    )
    # [mesh-referee-attribution] Forward referee_id from the original
    # adjudication block so verifiers querying ack_refusal records can
    # confirm the refused verdict was produced by an attributed referee --
    # `ask_history._classify_receipt_for_x` gates ack_refusal tallies on
    # this field being present and non-empty.
    ack_refused_block: dict[str, Any] = {
        "adjudication_capsule_id": adjudication_capsule["capsule_id"],
        "verdict": original_verdict,
        "counterparty_ref": counterparty_ref,
        "refusal": refusal,
    }
    if original_block.get("referee_id"):
        ack_refused_block["referee_id"] = original_block["referee_id"]
    compute_attestation = {"adjudication_ack_refused": ack_refused_block}
    capsule = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        prior_capsule_id=adjudication_capsule["capsule_id"],
        chain_relation=RELATION_ADJUDICATION_ACK_REFUSED,
        domain="action",
        provenance="referee",
        tool_name="adjudication_ack_refused",
    )
    # [adv-run-2-fix-batch] discipline: verify BEFORE returning -- matches
    # twin_adjudicator.seal_adjudication_capsule.
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"adjudicator emitted an ack-refused capsule that fails its own verify(): {result.findings}")
    return capsule
