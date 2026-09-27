# SPDX-License-Identifier: Apache-2.0
"""Record-push-at-completion (``docs/SHARING-POLICY.md``).

**What:** when an exchange ends, each side pushes its own SEALED record to
the other's evidence door (``POST /evidence/record-push``). The provider's
half to the requester; the requester's half to the provider. CLOSED becomes
the default row state instead of the exception, and each side holds the
other's signed digests as its own defence.

**Push a bundle.** A sender whose
checkpoint cadence is on checkpoints at push and sends a BUNDLE -- the half,
its inclusion proof, and the signed checkpoint covering it::

    {"record_push_bundle": 1, "capsule": <the half, as sealed>,
     "inclusion": {"leaf_index": n, "proof": <cll inclusion proof>},
     "checkpoint": <the sender's signed checkpoint>}

This door verifies all three (:func:`_verify_bundle_inclusion`): the half as
below, the checkpoint's signature under the SAME key as the half, and the
proof reconstructing the checkpoint's root from the half's ``capsule_id``.
The proof and checkpoint are then held artifacts
(:data:`RECEIVED_INCLUSION_FILENAME`) -- this node thereby retains the
sender's checkpoint -- and the success reply names the verified inclusion so
the Rust plugin seals a ``counterparty_inclusion`` citing record beside the
``counterparty_half`` one. A bare-capsule push (a sender with its cadence
off, or one that predates bundles) is still received exactly as before;
proof for it arrives on the clock or on request (``chain_segment``/
``correlation``, see ``evidence_responder.py``). A bundle whose checkpoint or
proof does not verify is refused ``inclusion_unverified`` as a WHOLE -- the
half inside it is not stored either, so a broken sender is visible rather
than silently downgraded to a bare push.

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
    200 + ``{"status": "received"}`` -- verified and stored in this node's
        HELD-ARTIFACT store (``received-capsules.jsonl``) by ``capsule_id``,
        AS TRANSMITTED (signature untouched, never re-signed). The foreign
        body NEVER enters ``capsules.jsonl`` (our chain); the chained record
        for this received half is a LOCAL CITING record the Rust plugin seals
        onto OUR chain (see the citing-record rule below).
    200 + a signed ``Refusal`` -- either
          * ``request_malformed`` -- unparseable body, no ``capsule_id``, or
            a capsule that fails its own ``verify()``. Refused BEFORE this
            node's ledger is ever touched.
          * ``policy_decline`` -- structurally fine, but this node's own
            ``record_at_completion`` is ``off`` (symmetry rule above).
          * ``signature_unverified`` -- the sender identity does not check
            out. UNCONDITIONAL as of the door-hardening fix: a push with NO
            claimed identity at all (``sender_peer_id`` absent/empty -- the
            old bypass, where the door skipped verification entirely and
            stored the body) is refused here too, exactly like a claimed
            identity (``sender_peer_id``) whose announced key
            (``peer_keys.announced_key_for``) does not match the capsule's
            own ``key_id``, or whose self-attested COSE_Sign1 signature does
            not verify (``capsule_emit.signing.verify_capsule_signature``).
            Refused, and the attempt is recorded to
            ``rejected-record-pushes.jsonl`` (see
            :func:`_append_rejected_push`) -- NEVER stored as a held artifact,
            and NEVER folded into ``capsules.jsonl``.

**A received half is a citing record.** A received
foreign capsule half is *evidence we HOLD, not a record we MADE*. Three
invariants this door upholds:

  1. **Foreign bytes never enter our chain.** A peer's pushed capsule is an
     ARTIFACT, stored by ``capsule_id`` in the held-artifact store
     :data:`RECEIVED_CAPSULES_FILENAME` (same ``_append_jsonl`` convention as
     :data:`RECEIVED_PROVENANCE_FILENAME`). That file is an artifact store,
     NOT a second ledger -- nothing chains it, nothing checkpoints it. The
     Python door writes ONLY the artifact store + provenance; it NEVER writes
     ``capsules.jsonl``.
  2. **Receiving one produces a LOCAL record in OUR chain.** The chained,
     checkpoint-covered record for a received half is a CITING record --
     sealed by OUR key, chained (parent = current head, ``chain.relation:
     follows`` -- per AAC-05 a cross-stream citation is a ``references[]``
     entry, never a relation value), identified
     as this record kind by ``citation_purpose: counterparty_half`` ALONE: a
     top-level ``references`` entry citing the foreign ``capsule_id`` by CPB
     typed digest, carrying ``received_from``/``via``/``received_at``/
     ``signature_ok``/``digest_match``. "cite, never mutate."
  3. **The Rust plugin seals the citing record** (``record_push_bridge.rs``
     calls back into ``capsule_emit.rs``'s ``seal`` +
     ``attach_producer_envelope`` + ``Ledger::append`` AFTER this door
     confirms verified+stored), because the Rust plugin owns
     ``capsules.jsonl`` + the MMR + ``checkpoint_cadence`` -- ONE WRITER per
     chain. The Python door MUST NEVER write ``capsules.jsonl``.

**Seam A2 -- provenance + identity
verification.** ``sender_peer_id`` (kwarg on :func:`handle_record_push`) is
the claimed sender's mesh peer id -- self-declared the same way
``/evidence-request``'s own ``X-Mesh-Requester-Id`` already is
(``evidence_server.py``'s "relationship gate" doc note), never itself
mesh-authenticated. This door holds EVERY push to the signature-verified
bar: the capsule's ``key_id`` must match ``sender_peer_id``'s registered
:func:`peer_keys.announced_key_for` key, AND its self-attested signature
must actually verify (:func:`capsule_emit.signing.verify_capsule_signature`)
-- either failing refuses ``signature_unverified`` and records the
rejection, never storing the artifact. On success the foreign body is
stored in the held-artifact store :data:`RECEIVED_CAPSULES_FILENAME` by
``capsule_id`` (never in ``capsules.jsonl``), and a provenance sibling
record -- ``{capsule_id, received_from, via: "push", received_at,
signature_ok: true}`` -- is appended to ``received-provenance.jsonl`` (see
:func:`_append_provenance`). Provenance + the held artifact are what the
Rust plugin's citing-record seal
(the citing-record rule) and the pane's CLOSED gate
(``exchange-row-state.ts``) then read to treat the received half as a
verified counterparty half.

**The identity gate is UNCONDITIONAL (door hardening; supersedes the
original "backward compatible by construction" note).** The first cut ran
the announced-key + signature checks only when a ``sender_peer_id`` was
supplied -- so a pusher could BYPASS verification entirely by just omitting
the ``X-Mesh-Requester-Id`` header, and the door stored the body anyway.
Now an unidentified push (``sender_peer_id`` ``None``/empty) is refused
``signature_unverified`` and recorded to ``rejected-record-pushes.jsonl``
like any other failed identity -- never stored as a held artifact. There is
no unverified storage path left.
"""
from __future__ import annotations

import hashlib
import json
import math
import urllib.request
from datetime import datetime, timezone
from typing import Any

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.evidence_request import Refusal
from capsule_emit.signing import resolve_signer, verify_capsule_signature

from evidence_responder import status_for_refusal_reason
from peer_keys import announced_key_for
from share_policy import DEFAULT_SHARE_POLICY, SharePolicy

__all__ = [
    "EVIDENCE_RECORD_PUSH_PATH",
    "REASON_POLICY_DECLINE",
    "REASON_REQUEST_MALFORMED",
    "REASON_INCLUSION_UNVERIFIED",
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
#: Seam A2 -- the sender's identity does not
#: check out: no claimed identity at all (an unidentified push -- refused
#: unconditionally since the door hardening; see the module doc), an
#: announced key that does not match, or a signature that does not verify.
REASON_SIGNATURE_UNVERIFIED = "signature_unverified"
#: A bundle push whose checkpoint signature or inclusion proof does not
#: verify against the half it carries (see the module doc's bundle note).
REASON_INCLUSION_UNVERIFIED = "inclusion_unverified"

#: The top-level member that marks a push body as a bundle (a capsule never
#: carries it) and the one bundle version this door reads.
BUNDLE_MARKER = "record_push_bundle"
BUNDLE_VERSION = 1

#: Seam A2 -- the provenance sibling file,
#: co-located with ``capsules.jsonl`` (same convention as
#: ``checkpoints.jsonl``) -- one line per successfully identity-verified
#: received push. This is the ONLY source `exchange-row-state.ts`'s
#: local-sibling CLOSED gate trusts.
RECEIVED_PROVENANCE_FILENAME = "received-provenance.jsonl"
#: The HELD-ARTIFACT store for
#: received foreign capsule bodies, co-located with ``capsules.jsonl`` (same
#: ``_append_jsonl`` convention as :data:`RECEIVED_PROVENANCE_FILENAME`). A
#: peer's pushed capsule is an ARTIFACT we HOLD, not a record we MADE -- it is
#: stored here by ``capsule_id``, NEVER folded into ``capsules.jsonl`` (which
#: is the Rust plugin's single-writer CHAIN). This is an artifact store, not a
#: second ledger: nothing chains it, nothing checkpoints it. The chained,
#: checkpoint-covered record for a received half is a LOCAL CITING record the
#: Rust plugin seals onto OUR chain (``record_push_bridge.rs`` calls back into
#: ``capsule_emit.rs``'s ``seal`` + ``attach_producer_envelope`` +
#: ``Ledger::append`` after this door confirms verified+stored) -- that citing
#: record, plus this artifact for recompute, is what the CLOSED gate reads.
#: "cite, never mutate."
RECEIVED_CAPSULES_FILENAME = "received-capsules.jsonl"
#: A claimed-identity push that failed the signature/announced-key check --
#: recorded, but NEVER folded into ``capsules.jsonl`` as a sibling.
REJECTED_PUSHES_FILENAME = "rejected-record-pushes.jsonl"
#: The held-artifact store for a bundle's verified inclusion evidence: one
#: line per received bundle -- the half it is about, the inclusion proof, the
#: sender's signed checkpoint (kept whole, so it re-verifies offline), and
#: the digests the ``counterparty_inclusion`` citing record cites them by.
#: An artifact store like :data:`RECEIVED_CAPSULES_FILENAME`: nothing chains
#: or checkpoints it.
RECEIVED_INCLUSION_FILENAME = "received-inclusion.jsonl"

_PROOF_FIELDS = ("v", "kind", "size", "leaf_index", "witness", "peaks_left", "peaks_right")
#: The exact member sets of a bundle and its parts. Nothing unsigned rides
#: along: an extra member is refused, never stored.
_BUNDLE_FIELDS = frozenset({BUNDLE_MARKER, "capsule", "inclusion", "checkpoint"})
_INCLUSION_FIELDS = frozenset({"leaf_index", "proof"})
_CHECKPOINT_FIELDS = frozenset(
    {"v", "kind", "log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp", "signature"}
)

#: serde_json's default recursion limit: the Rust plugin parses at most this
#: many nested arrays/objects (measured: 127 parses, 128 does not).
MAX_JSON_DEPTH = 127


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _object_pairs_reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads`` object_pairs_hook that raises on a duplicate key at any
    nesting level. Python's default silently keeps the LAST duplicate while
    other implementations keep the first (or reject) -- a cross-implementation
    id-collision hazard at this door: a body crafted with two ``capsule_id``
    (or ``signature``) keys could verify under one reading and be stored/cited
    under another. A duplicate-key body is refused ``request_malformed``."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    """``json.loads`` parse_constant hook: NaN / Infinity / -Infinity are not
    JSON, and serde_json refuses them."""
    raise ValueError(f"non-JSON constant {name}")


def _check_rust_parseable(value: Any, depth: int = 0) -> None:
    """Raise ``ValueError`` for anything the Rust plugin's serde_json would
    refuse, so the door never stores bytes our chain cannot cite: nesting
    deeper than :data:`MAX_JSON_DEPTH`, a non-finite float (``1e400`` parses
    to ``inf`` here), an integer outside 64 bits (stricter than serde_json,
    which degrades it to a float), or a string holding a lone surrogate."""
    if isinstance(value, (dict, list)):
        depth += 1
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nested too deeply")
        if isinstance(value, dict):
            for key, item in value.items():
                _check_rust_parseable(key, depth)
                _check_rust_parseable(item, depth)
        else:
            for item in value:
                _check_rust_parseable(item, depth)
    elif isinstance(value, bool):
        return
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
    elif isinstance(value, int):
        if not -(2**63) <= value < 2**64:
            raise ValueError("integer outside 64 bits")
    elif isinstance(value, str):
        value.encode("utf-8")  # UnicodeEncodeError (a ValueError) on a lone surrogate


def _strict_loads(body: bytes) -> Any:
    """Parse a push body under the rules the Rust side will apply to the same
    bytes -- duplicate keys, non-JSON constants, and everything
    :func:`_check_rust_parseable` refuses raise ``ValueError``. Python's
    recursion guard covers nesting far past the limit."""
    value = json.loads(
        body, object_pairs_hook=_object_pairs_reject_duplicates, parse_constant=_reject_constant
    )
    _check_rust_parseable(value)
    return value


def _bundle_members_exact(bundle: dict[str, Any]) -> bool:
    """A bundle, its ``inclusion`` and ``proof``, and its ``checkpoint`` carry
    exactly their known members -- no unsigned extras anywhere."""
    inclusion = bundle.get("inclusion")
    checkpoint = bundle.get("checkpoint")
    return (
        set(bundle) == _BUNDLE_FIELDS
        and isinstance(inclusion, dict)
        and set(inclusion) == _INCLUSION_FIELDS
        and isinstance(inclusion["proof"], dict)
        and set(inclusion["proof"]) == set(_PROOF_FIELDS)
        and isinstance(checkpoint, dict)
        and set(checkpoint) == _CHECKPOINT_FIELDS
    )


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
    """Seam A2 -- record the provenance triple
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
    """Seam A2 -- record a claimed-identity
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


def _canonical_digest(obj: dict[str, Any]) -> str:
    """SHA-256 of sorted-key compact JSON -- the JCS form for objects that
    hold only strings, integers and lists of strings (a proof)."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _checkpoint_signature_ok(checkpoint: Any) -> bool:
    """Ed25519 over the checkpoint's ``digest()`` (hex string, UTF-8), under
    the raw public key its ``key_id`` names -- the same check as the Rust
    ``CheckpointRecord::verify_signature_offline``. Never raises."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(checkpoint.key_id))
        key.verify(bytes.fromhex(checkpoint.signature), checkpoint.digest().encode("utf-8"))
        return True
    except Exception:  # noqa: BLE001 -- any malformed input is a failed check
        return False


def _verify_bundle_inclusion(capsule: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any] | None:
    """The bundle's two extra checks, after the half itself has passed:
    (1) the checkpoint is signed by the half's own key; (2) the proof puts
    the half's ``capsule_id`` at ``leaf_index`` under the checkpoint's root.
    Returns the facts to store and cite, or ``None`` when either fails."""
    from scitt_cose import cll

    try:
        checkpoint_dict = bundle["checkpoint"]
        inclusion = bundle["inclusion"]
        # A leaf_index that disagrees with the proof's own fails
        # verify_inclusion below; no separate check.
        leaf_index = inclusion["leaf_index"]
        proof_dict = {k: inclusion["proof"][k] for k in _PROOF_FIELDS}
        checkpoint = cll.Checkpoint.from_dict(checkpoint_dict)
        proof = cll.InclusionProof.from_dict(proof_dict)
        body_digest = bytes.fromhex(capsule["capsule_id"])
    except Exception:  # noqa: BLE001 -- malformed bundle parts fail the check
        return None
    if checkpoint.key_id != capsule.get("key_id") or not _checkpoint_signature_ok(checkpoint):
        return None
    result = cll.verify_leaf_against_checkpoint(
        body_digest=body_digest, leaf_index=leaf_index, checkpoint=checkpoint, proof=proof
    )
    if not result.ok:
        return None
    return {
        "leaf_index": leaf_index,
        "mmr_size": checkpoint.mmr_size,
        "checkpoint": checkpoint_dict,
        "checkpoint_digest": checkpoint.digest(),
        "inclusion_proof": proof_dict,
        "inclusion_proof_digest": _canonical_digest(proof_dict),
    }


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

    ``sender_peer_id`` -- the claimed sender's
    mesh peer id (self-declared, see module doc's "provenance + identity
    verification" section). REQUIRED for a push to be received: ``None`` or
    empty (an unidentified push) is refused ``signature_unverified`` and
    recorded -- the identity+signature gate is UNCONDITIONAL (see the module
    doc's door-hardening note; the old skip-when-absent behavior was a
    verification bypass).

    Returns ``{"status": "received"}`` or a signed refusal dict -- never
    raises on malformed input, same discipline as
    ``adjudication_delivery.handle_delivery``. Structural refusal
    (``request_malformed``) is always checked BEFORE the policy gate, which
    in turn is always checked BEFORE the identity-verification gate -- a
    request this door could not even verify structurally is never evaluated
    against policy, and a node with ``record_at_completion: off`` refuses
    ``policy_decline`` regardless of whether the sender's identity would
    have checked out (mirrors ``evidence_responder``'s own ordering
    discipline; the unconditional identity gate keeps this slot in the
    ordering, it just no longer has a skip path).
    """
    issued_at = now or _now_iso()
    request_digest = hashlib.sha256(body).hexdigest()

    try:
        # object_pairs_hook: a duplicate JSON key anywhere in the body is
        # malformed (cross-implementation id-collision hazard -- see
        # :func:`_object_pairs_reject_duplicates`).
        capsule = _strict_loads(body)
    except Exception:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    # A bundle carries the half under "capsule"; every check below runs on
    # the half exactly as for a bare push, then the bundle's own checks.
    bundle: dict[str, Any] | None = None
    if isinstance(capsule, dict) and BUNDLE_MARKER in capsule:
        if capsule.get(BUNDLE_MARKER) != BUNDLE_VERSION or not _bundle_members_exact(capsule):
            return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)
        bundle = capsule
        capsule = bundle.get("capsule")

    if not isinstance(capsule, dict) or not capsule.get("capsule_id"):
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    result = verify_capsule(capsule)
    if not result.ok:
        return _refuse(request_digest, REASON_REQUEST_MALFORMED, state=state, issued_at=issued_at)

    if _effective_policy(policy).record_at_completion == "off":
        return _refuse(request_digest, REASON_POLICY_DECLINE, state=state, issued_at=issued_at)

    # Seam A2, made UNCONDITIONAL by the door
    # hardening: EVERY push is held to the signature-verified bar. No
    # identity claimed at all, an announced key that does not match what the
    # capsule itself carries, or a self-attested signature that does not
    # verify -- any of these is refused and recorded as REJECTED, never
    # stored as a held artifact, never folded into capsules.jsonl.
    if not sender_peer_id:
        _append_rejected_push(
            state, capsule.get("capsule_id"), sender_peer_id, REASON_SIGNATURE_UNVERIFIED, issued_at
        )
        return _refuse(request_digest, REASON_SIGNATURE_UNVERIFIED, state=state, issued_at=issued_at)
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

    # The received foreign body is an
    # ARTIFACT we HOLD, not a record we MADE: store it by capsule_id in the
    # held-artifact store (:data:`RECEIVED_CAPSULES_FILENAME`), NEVER in
    # ``capsules.jsonl``. The Python door writes ONLY the artifact store +
    # provenance; the CHAINED, checkpoint-covered citing record is sealed by
    # the Rust plugin onto OUR chain (``record_push_bridge.rs`` ->
    # ``capsule_emit.rs``), preserving ONE WRITER per chain. "cite, never
    # mutate."
    inclusion: dict[str, Any] | None = None
    if bundle is not None:
        inclusion = _verify_bundle_inclusion(capsule, bundle)
        if inclusion is None:
            _append_rejected_push(
                state, capsule.get("capsule_id"), sender_peer_id, REASON_INCLUSION_UNVERIFIED, issued_at
            )
            return _refuse(request_digest, REASON_INCLUSION_UNVERIFIED, state=state, issued_at=issued_at)

    _append_jsonl(state.ledger_dir, RECEIVED_CAPSULES_FILENAME, capsule)
    _append_provenance(state, capsule, sender_peer_id, issued_at)
    if inclusion is None:
        return {"status": "received"}

    held = {
        "half_capsule_id": capsule["capsule_id"],
        "received_from": sender_peer_id,
        "via": "push",
        "received_at": issued_at,
        **inclusion,
    }
    _append_jsonl(state.ledger_dir, RECEIVED_INCLUSION_FILENAME, held)
    # What the Rust plugin cites (record_push_bridge.rs's DoorInclusion):
    # the facts, never the artifacts themselves.
    return {
        "status": "received",
        "inclusion": {
            k: held[k]
            for k in (
                "half_capsule_id",
                "leaf_index",
                "mmr_size",
                "checkpoint_digest",
                "inclusion_proof_digest",
                "received_at",
            )
        },
    }


def push_record(
    capsule: dict[str, Any],
    door_base_url: str,
    *,
    timeout: float = 30,
    sender_peer_id: str | None = None,
) -> dict[str, Any]:
    """POST ``capsule``'s own canonical JSON bytes to ``door_base_url``'s
    :data:`EVIDENCE_RECORD_PUSH_PATH`; return the parsed JSON response
    unmodified -- ``{"status": "received"}`` or a Refusal dict (distinguish
    by ``"reason" in response``, same convention as
    ``adjudication_delivery.deliver_adjudication``). Raises
    ``urllib.error.URLError``/``TimeoutError`` on transport failure --
    unlike ``handle_record_push``, this is the caller-facing send path, and
    a caller deciding whether to retry needs the real exception, not a
    swallowed ``None``.

    ``sender_peer_id``: this node's own self-declared mesh peer id, sent as
    the ``X-Mesh-Requester-Id`` header (the same self-attestation convention
    the mesh bridge and ``/evidence-request`` use). The receiving door's
    identity gate is unconditional (see module doc), so a push sent WITHOUT
    it will be refused ``signature_unverified`` -- the parameter exists so a
    legitimate sender can identify itself; omitting it is only useful to
    exercise the refusal path."""
    body = json.dumps(capsule, sort_keys=True).encode("utf-8")
    url = door_base_url.rstrip("/") + EVIDENCE_RECORD_PUSH_PATH
    headers = {"Content-Type": "application/json"}
    if sender_peer_id:
        headers["X-Mesh-Requester-Id"] = sender_peer_id
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def push_record_if_policy_allows(
    capsule: dict[str, Any],
    door_base_url: str,
    *,
    policy: SharePolicy | None,
    timeout: float = 30,
    sender_peer_id: str | None = None,
) -> dict[str, Any] | None:
    """:func:`push_record`, gated by ``record_at_completion`` (see
    ``_effective_policy``). Returns ``None`` -- no network call made at all
    -- when the effective policy is ``off``; this is the OFF path,
    structurally a no-op, never a silent partial push."""
    if _effective_policy(policy).record_at_completion == "off":
        return None
    return push_record(capsule, door_base_url, timeout=timeout, sender_peer_id=sender_peer_id)
