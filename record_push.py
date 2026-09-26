# SPDX-License-Identifier: Apache-2.0
"""the sharing-policy Record-push-at-completion (design note
``_work/mesh-sharing-policy-history-and-money-2026-09-24.md`` S2;
``docs/SHARING-POLICY.md``).

**What:** when an exchange ends, each side pushes its own SEALED record --
not a bundle, just the one capsule -- to the other's evidence door
(``POST /evidence/record-push``). The provider's half to the requester; the
requester's half to the provider. CLOSED becomes the default row state
instead of the exception, and each side holds the other's signed digests as
its own defence.

**Why not a bundle:** the bundle needs the inclusion proof and a covering
checkpoint, and at completion the record isn't checkpointed yet. Proof
arrives on the clock or on request (``chain_segment``/``correlation``, see
``evidence_responder.py``).

**Symmetry rule:** a node with ``record_at_completion: off`` does not
receive the other side's push either (it can still ask -- fetch-on-request
is untouched). ``_effective_policy`` resolves an unset (``None``) policy to
``share_policy.DEFAULT_SHARE_POLICY`` -- the documented default is ON
(``counterparty``) -- so both :func:`handle_record_push` and
:func:`push_record_if_policy_allows` refuse/no-op ONLY when a policy is
explicitly configured to ``off``.

**What this module does NOT do: trigger itself automatically at exchange
completion.** The provider seals *after* the stream ends -- wiring the
actual trigger needs a trailing completion frame or a follow-up
plugin-stream message from the host, a small upstream host seam sequenced
after the provider-side lifecycle events (#2017), same class as the marker.
Out of scope here by the task's own boundary ("do not build it here"). This
module ships the complete, tested MECHANISM -- sender, receiver, HTTP door,
policy gate -- ready for that trigger (or a demo/CLI/test) to call, exactly
as ``adjudication_delivery.py``'s ``deliver_adjudication``/``handle_delivery``
exist as a complete mechanism independent of what calls them.

Route: ``POST /evidence/record-push``
    body = the pushed capsule's own canonical JSON bytes -- opaque at the
        transport level, same convention as ``/evidence/deliver``.
    200 + ``{"status": "received"}`` -- verified and folded into this node's
        own ledger, AS TRANSMITTED (signature untouched, never re-signed).
    200 + a signed ``Refusal`` -- either
          * ``request_malformed`` -- unparseable body, no ``capsule_id``, or
            a capsule that fails its own ``verify()``. Refused BEFORE this
            node's ledger is ever touched.
          * ``policy_decline`` -- structurally fine, but this node's own
            ``record_at_completion`` is ``off`` (symmetry rule above).
          * ``signature_unverified`` -- a claimed sender identity
            (``sender_peer_id``) whose announced key
            (``peer_keys.announced_key_for``) does not match the capsule's
            own ``key_id``, or whose self-attested COSE_Sign1 signature does
            not verify (``capsule_emit.signing.verify_capsule_signature``).
            Refused, and the attempt is recorded to
            ``rejected-record-pushes.jsonl`` (see
            :func:`_append_rejected_push`) -- NEVER folded into
            ``capsules.jsonl`` as a sibling.

**[mesh-closed-wiring-four-gaps] Seam A2 -- provenance + identity
verification.** ``sender_peer_id`` (new, optional kwarg on
:func:`handle_record_push`) is the claimed sender's mesh peer id --
self-declared the same way ``/evidence-request``'s own
``X-Mesh-Requester-Id`` already is (``evidence_server.py``'s "relationship
gate" doc note), never itself mesh-authenticated. When a caller supplies it
(the mesh-delivered path, wired via `record_push_bridge.rs` on the plugin
side), this door holds the push to a HIGHER bar than the original
unidentified mechanism: the capsule's ``key_id`` must match
``sender_peer_id``'s registered :func:`peer_keys.announced_key_for` key, AND
its self-attested signature must actually verify
(:func:`capsule_emit.signing.verify_capsule_signature`) -- either failing
refuses ``signature_unverified`` and records the rejection, never appending
the capsule. On success, a provenance sibling record --
``{capsule_id, received_from, via: "push", received_at, signature_ok:
true}`` -- is appended to ``received-provenance.jsonl`` (see
:func:`_append_provenance`), the ONLY fact the pane's local-sibling CLOSED
gate (``exchange-row-state.ts``) trusts to treat a locally-held capsule as a
verified counterparty half.

**Backward compatible by construction.** When ``sender_peer_id`` is omitted
(``None``, the default -- every caller that predates this task, including
every existing test and a direct unidentified HTTP push), this door's
behavior is BYTE FOR BYTE UNCHANGED from before this task: structural
verify, policy gate, append -- no identity check, no provenance record. An
unidentified push was never eligible for the pane's local-sibling gate
before this task and still is not; this task only adds a HIGHER bar for
pushes that DO carry a claimed identity, it never loosens the unidentified
path.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from typing import Any

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.evidence_request import Refusal
from capsule_emit.signing import resolve_signer, verify_capsule_signature

from evidence_responder import status_for_refusal_reason
from ledger_store_backend import append_capsule
from peer_keys import announced_key_for
from share_policy import DEFAULT_SHARE_POLICY, SharePolicy

__all__ = [
    "EVIDENCE_RECORD_PUSH_PATH",
    "REASON_POLICY_DECLINE",
    "REASON_REQUEST_MALFORMED",
    "REASON_SIGNATURE_UNVERIFIED",
    "handle_record_push",
    "push_record",
    "push_record_if_policy_allows",
]

EVIDENCE_RECORD_PUSH_PATH = "/evidence/record-push"

#: Reused verbatim from ``adjudication_delivery``'s own reason vocabulary --
#: same meaning, a different delivery protocol's own decline/malformed pair.
REASON_POLICY_DECLINE = "policy_decline"
REASON_REQUEST_MALFORMED = "request_malformed"
#: [mesh-closed-wiring-four-gaps] Seam A2 -- a claimed sender identity whose
#: announced key does not match, or whose signature does not verify. Only
#: reachable when a caller supplies ``sender_peer_id`` (see module doc's
#: "backward compatible by construction" note).
REASON_SIGNATURE_UNVERIFIED = "signature_unverified"

#: [mesh-closed-wiring-four-gaps] Seam A2 -- the provenance sibling file,
#: co-located with ``capsules.jsonl`` (same convention as
#: ``checkpoints.jsonl``) -- one line per successfully identity-verified
#: received push. This is the ONLY source `exchange-row-state.ts`'s
#: local-sibling CLOSED gate trusts.
RECEIVED_PROVENANCE_FILENAME = "received-provenance.jsonl"
#: A claimed-identity push that failed the signature/announced-key check --
#: recorded, but NEVER folded into ``capsules.jsonl`` as a sibling.
REJECTED_PUSHES_FILENAME = "rejected-record-pushes.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _effective_policy(policy: SharePolicy | None) -> SharePolicy:
    """An unset policy resolves to the documented default (S1:
    ``record_at_completion: counterparty``) -- see the module docstring's
    "symmetry rule" note. Unlike ``evidence_responder``'s relationship gate
    (whose ``None`` means "this pre-existing function's gate never runs, at
    all"), record-push has no pre-existing caller to stay byte-for-byte
    compatible with -- it is new surface this task adds, so its own default
    is simply the design's documented default, not "always permit."""
    return policy or DEFAULT_SHARE_POLICY


def _refuse(request_digest: str, reason: str, *, state: Any, issued_at: str) -> dict[str, Any]:
    """Sign a refusal and return its wire dict, with the fabric's additive
    ``status`` layered on beside ``reason`` -- same shape as
    ``adjudication_delivery._refuse``, duplicated per this repo's own
    "duplicated here rather than reached into" precedent (that one is
    module-private)."""
    signer = resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path)
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    refusal = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)
    d = refusal.to_dict()
    status = status_for_refusal_reason(reason)
    if status is not None:
        d["status"] = status
    return d


def _append_jsonl(ledger_dir: Any, filename: str, entry: dict[str, Any]) -> None:
    """Append one JSON line to ``filename`` beside ``capsules.jsonl`` in
    ``ledger_dir`` -- same co-located-sibling convention as
    ``checkpoints.jsonl`` (module doc). Not best-effort like
    ``evidence_server._append_received_log``: a failure here means the
    provenance/rejection record this task exists to produce was NOT written,
    so it must surface, not be silently swallowed."""
    from pathlib import Path

    path = Path(ledger_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _append_provenance(state: Any, capsule: dict[str, Any], sender_peer_id: str, issued_at: str) -> None:
    """[mesh-closed-wiring-four-gaps] Seam A2 -- record the provenance triple
    for a successfully identity-verified received push. ``signature_ok`` is
    always ``true`` here -- this is only ever called AFTER
    :func:`capsule_emit.signing.verify_capsule_signature` passed; a failed
    verify goes to :func:`_append_rejected_push` instead, never here."""
    _append_jsonl(
        state.ledger_dir,
        RECEIVED_PROVENANCE_FILENAME,
        {
            "capsule_id": capsule["capsule_id"],
            "received_from": sender_peer_id,
            "via": "push",
            "received_at": issued_at,
            "signature_ok": True,
        },
    )


def _append_rejected_push(
    state: Any, capsule_id: str | None, sender_peer_id: str | None, reason: str, issued_at: str
) -> None:
    """[mesh-closed-wiring-four-gaps] Seam A2 -- record a claimed-identity
    push that failed signature/announced-key verification. Never folded into
    ``capsules.jsonl`` -- this file is the honest record of "someone claimed
    to be X and pushed something that did not check out", never a sibling
    any CLOSED gate may read."""
    _append_jsonl(
        state.ledger_dir,
        REJECTED_PUSHES_FILENAME,
        {
            "capsule_id": capsule_id,
            "claimed_sender_peer_id": sender_peer_id,
            "reason": reason,
            "rejected_at": issued_at,
        },
    )


def handle_record_push(
    state: Any,
    body: bytes,
    *,
    policy: SharePolicy | None = None,
    now: str | None = None,
    sender_peer_id: str | None = None,
) -> dict[str, Any]:
    """Handle one ``POST /evidence/record-push`` body against ``state``'s
    own ledger -- duck-typed like ``evidence_server.EvidenceServerState``
    (``ledger_dir`` + ``signing_key_path``, nothing else).

    ``sender_peer_id`` [mesh-closed-wiring-four-gaps] -- the claimed sender's
    mesh peer id (self-declared, see module doc's "provenance + identity
    verification" section). ``None`` (the default) reproduces this
    function's pre-task behavior exactly -- see the module doc's "backward
    compatible by construction" note.

    Returns ``{"status": "received"}`` or a signed refusal dict -- never
    raises on malformed input, same discipline as
    ``adjudication_delivery.handle_delivery``. Structural refusal
    (``request_malformed``) is always checked BEFORE the policy gate, which
    in turn is always checked BEFORE the identity-verification gate -- a
    request this door could not even verify structurally is never evaluated
    against policy, and a node with ``record_at_completion: off`` refuses
    ``policy_decline`` regardless of whether the sender's identity would
    have checked out (mirrors ``evidence_responder``'s own ordering
    discipline, and keeps this function's already-tested policy-off
    behavior unchanged by the identity gate this task adds after it).
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

    if _effective_policy(policy).record_at_completion == "off":
        return _refuse(request_digest, REASON_POLICY_DECLINE, state=state, issued_at=issued_at)

    if sender_peer_id is not None:
        # [mesh-closed-wiring-four-gaps] Seam A2 -- a CLAIMED identity is
        # held to the higher bar: its announced key must match what the
        # capsule itself carries, AND the capsule's self-attested signature
        # must actually verify. Either failing is refused and recorded as
        # REJECTED, never folded into capsules.jsonl as a sibling.
        announced_key = announced_key_for(sender_peer_id)
        if (
            announced_key is None
            or capsule.get("key_id") != announced_key
            or not verify_capsule_signature(capsule)
        ):
            _append_rejected_push(
                state, capsule.get("capsule_id"), sender_peer_id, REASON_SIGNATURE_UNVERIFIED, issued_at
            )
            return _refuse(request_digest, REASON_SIGNATURE_UNVERIFIED, state=state, issued_at=issued_at)

    append_capsule(state.ledger_dir, capsule)
    if sender_peer_id is not None:
        _append_provenance(state, capsule, sender_peer_id, issued_at)
    return {"status": "received"}


def push_record(capsule: dict[str, Any], door_base_url: str, *, timeout: float = 30) -> dict[str, Any]:
    """POST ``capsule``'s own canonical JSON bytes to ``door_base_url``'s
    :data:`EVIDENCE_RECORD_PUSH_PATH`; return the parsed JSON response
    unmodified -- ``{"status": "received"}`` or a Refusal dict (distinguish
    by ``"reason" in response``, same convention as
    ``adjudication_delivery.deliver_adjudication``). Raises
    ``urllib.error.URLError``/``TimeoutError`` on transport failure --
    unlike ``handle_record_push``, this is the caller-facing send path, and
    a caller deciding whether to retry needs the real exception, not a
    swallowed ``None``."""
    body = json.dumps(capsule, sort_keys=True).encode("utf-8")
    url = door_base_url.rstrip("/") + EVIDENCE_RECORD_PUSH_PATH
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def push_record_if_policy_allows(
    capsule: dict[str, Any],
    door_base_url: str,
    *,
    policy: SharePolicy | None,
    timeout: float = 30,
) -> dict[str, Any] | None:
    """:func:`push_record`, gated by ``record_at_completion`` (see
    ``_effective_policy``). Returns ``None`` -- no network call made at all
    -- when the effective policy is ``off``; this is the OFF path,
    structurally a no-op, never a silent partial push."""
    if _effective_policy(policy).record_at_completion == "off":
        return None
    return push_record(capsule, door_base_url, timeout=timeout)
