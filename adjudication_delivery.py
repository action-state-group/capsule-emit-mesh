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
        by the recipient), into its own ledger.
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
from capsule_emit.ledger import read_ledger
from capsule_emit.signing import resolve_signer

from checkpointing import JsonlLogSource

__all__ = [
    "EVIDENCE_DELIVER_PATH",
    "REASON_POLICY_DECLINE",
    "REASON_REQUEST_MALFORMED",
    "RELATION_ADJUDICATION_ACK_REFUSED",
    "deliver_adjudication",
    "handle_delivery",
    "seal_adjudication_ack_refused",
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


def _refuse(request_digest: str, reason: str, *, state: Any, issued_at: str) -> Refusal:
    signer = resolve_signer(str(state.ledger_path), key_path=state.signing_key_path)
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    return Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)


def handle_delivery(state: Any, body: bytes, *, now: str | None = None) -> dict[str, Any]:
    """Handle one ``POST /evidence/deliver`` body against ``state``'s own
    ledger -- duck-typed like ``evidence_server.EvidenceServerState``
    (``ledger_path`` + ``signing_key_path``, nothing else).

    Returns ``{"status": "received"}`` or a signed ``Refusal.to_dict()`` --
    never raises on malformed input, mirroring E14 ``answer()``'s
    discipline of one signed answer for every well-formed OR malformed
    request.
    """
    issued_at = now or _now_iso()
    request_digest = hashlib.sha256(body).hexdigest()

    try:
        capsule = json.loads(body)
    except Exception:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at).to_dict()

    if not isinstance(capsule, dict) or not capsule.get("capsule_id"):
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at).to_dict()

    result = verify_capsule(capsule)
    if not result.ok:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at).to_dict()

    cited = _cited_capsule_ids(capsule)
    if not cited:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at).to_dict()

    own_entries = {e["capsule_id"]: e for e in read_ledger(state.ledger_path)}
    own_half = next((own_entries[cid] for cid in cited if cid in own_entries), None)
    if own_half is None:
        # Own half not among the citations -- never received() a verdict
        # about someone else.
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at).to_dict()

    own_owner_id = _owner_id(own_half)
    verdict = _adjudication_block(capsule).get("verdict")
    if own_owner_id and verdict == f"contradicted:{own_owner_id}":
        return _refuse(request_digest, REASON_POLICY_DECLINE, state=state, issued_at=issued_at).to_dict()

    JsonlLogSource(state.ledger_path).append(capsule)
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
    counterparty)."""
    compute_attestation = {
        "adjudication_ack_refused": {
            "adjudication_capsule_id": adjudication_capsule["capsule_id"],
            "verdict": _adjudication_block(adjudication_capsule).get("verdict"),
            "refusal": refusal,
        }
    }
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
