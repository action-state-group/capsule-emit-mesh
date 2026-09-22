# SPDX-License-Identifier: Apache-2.0
"""Sidecar wiring for E14's evidence-request responder.

The responder's decision logic (request parsing, coverage resolution,
signed refusals, dispatch to ``bundle()``) lives entirely in
``capsule_emit.evidence_request`` — this module is capsule-emit-mesh's
half: it supplies WHICH ledger and WHICH signing key ``answer()`` runs
against for one running sidecar, and nothing else.

``issuer: node_key`` — ``state.signing_key_path`` is the SAME persisted
Ed25519 key (``<keys_dir>/node-key.pem``, ``load_or_create_signing_key``)
every capsule this sidecar already seals is signed with, so a refusal and
a capsule from the same node verify against the same identity.

**Carrier wiring is out of scope here.** This makes the responder
reachable against a real sidecar's ``NodeState`` — not yet reachable over
the wire (the ``HttpBindingManifest`` route / ``evidence-request/1``
subprotocol are separate, later work: E15/E16).

**[mesh-served-summary-derivation] derivation-token dispatch.** The merged
``capsule_emit.evidence_request.answer()`` parses a request's ``derivation``
field but never dispatches on it — it only ever builds ``bundle()``-shaped
answers for ``record``/``range`` subjects. This module is the one place a
derivation TOKEN actually gets answered: a request naming
``derivation: "served_summary/1"`` is intercepted here, BEFORE falling
through to the generic bundle path, and answered from
``served_summary.answer_served_summary_request`` against this same ledger's
checkpoint chain. Any other (or absent) derivation falls through to
``answer()`` unchanged.

**[mesh-fabric-vocab-alignment] additive `status`/`coverage_descriptor`.**
``answer()``'s own ``Artifact``/``Refusal`` objects (and this module's
``Refusal``-shaped served-summary refusal) never change — the fabric's
shared record-header and per-answer status vocabulary convention is layered on ONLY at the
wire-serialization boundary, by ``augment_evidence_answer_dict`` below,
never inside ``handle_evidence_request``'s own return value (so every
existing caller of this module that reads an ``Artifact``/``Refusal``
object directly, rather than its wire JSON, is unaffected). The mapping:
``Artifact`` (an answer WAS satisfied) -> ``status: SATISFIED``;
``reason=no_such_record`` -> ``NOT_FOUND``; ``reason=coverage_unsatisfiable``
-> ``NOT_COMMITTED``; ``reason=policy_decline`` (the delivery door's own
reason, see ``adjudication_delivery.py``) -> ``WITHHELD``;
``reason=request_malformed`` stays a bare refusal reason -- no additive
status, since a request this door could not even parse was never resolved
one way or the other.
"""
from __future__ import annotations

from typing import Any

#: The one derivation token this module dispatches on directly. Any other
#: value (including ``None``) falls through to the generic bundle-based
#: ``answer()`` below, unchanged.
SERVED_SUMMARY_DERIVATION_TOKEN = "served_summary/1"

#: [mesh-fabric-vocab-alignment] the fabric's additive per-answer status
#: vocabulary -- see the module docstring.
STATUS_SATISFIED = "SATISFIED"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_WITHHELD = "WITHHELD"
STATUS_NOT_COMMITTED = "NOT_COMMITTED"

#: Refusal `reason` -> additive `status`. `request_malformed` is
#: deliberately absent -- see the module docstring.
_STATUS_BY_REFUSAL_REASON: dict[str, str] = {
    "no_such_record": STATUS_NOT_FOUND,
    "coverage_unsatisfiable": STATUS_NOT_COMMITTED,
    "policy_decline": STATUS_WITHHELD,
}


def status_for_refusal_reason(reason: str) -> str | None:
    """The additive `status` for a signed refusal's `reason`, or `None` when
    *reason* stays a bare refusal reason (`request_malformed`, or anything
    this mapping does not recognize -- never guessed)."""
    return _STATUS_BY_REFUSAL_REASON.get(reason)


#: [mesh-fabric-vocab-alignment] the fabric's `coverage_descriptor` vocabulary
#: -- what a bundle-tier answer can name
#: itself as establishing. See `coverage_descriptor_for`'s docstring for
#: which of these THIS responder is ever entitled to claim.
COVERAGE_DESCRIPTOR_RECORD_INCLUSION = "record_inclusion"
COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS = "range_completeness"
COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE = "capture_coverage"
COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE = "reconciliation_coverage"
COVERAGE_DESCRIPTOR_CORROBORATION = "corroboration"
ALL_COVERAGE_DESCRIPTORS = frozenset(
    {
        COVERAGE_DESCRIPTOR_RECORD_INCLUSION,
        COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS,
        COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE,
        COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE,
        COVERAGE_DESCRIPTOR_CORROBORATION,
    }
)
#: Descriptors a UNILATERAL, single-ledger bundle-tier answer can never
#: establish -- each requires a second party's ledger (`capture_coverage`,
#: `reconciliation_coverage`) or a third party's judgment (`corroboration`),
#: none of which this door alone ever has. Reconcile/Close v0
#: (`[mesh-reconcile-and-close-v0]`) and the twin/referee path are the
#: features that will eventually be entitled to claim these -- not this
#: responder.
_BILATERAL_ONLY_COVERAGE_DESCRIPTORS = frozenset(
    {
        COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE,
        COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE,
        COVERAGE_DESCRIPTOR_CORROBORATION,
    }
)


def coverage_descriptor_for(subject_kind: str, *, is_final_page: bool) -> list[str] | None:
    """Which `ALL_COVERAGE_DESCRIPTORS` values a bundle-tier answer for
    *subject_kind* establishes -- **never more than it does**. A
    `record`/`range`/`correlation` bundle from this responder proves log
    inclusion, and -- once its own page reaches the end of the resolved
    selection (`is_final_page`) -- that the full selection was returned; it
    never proves bilateral capture completeness, cross-ledger
    reconciliation, or independent corroboration (see
    `_BILATERAL_ONLY_COVERAGE_DESCRIPTORS`). A `chain_segment` subject
    resolves to `capsule_emit.chain_segment.ChainSegment` objects, not
    `Bundle`s (see `_build_chain_segment` in `capsule_emit.evidence_request`)
    -- this responder emits no `coverage_descriptor` for it (`None`,
    absent, never fabricated for a shape this function does not reason
    about)."""
    if subject_kind == "chain_segment":
        return None
    establishes = [COVERAGE_DESCRIPTOR_RECORD_INCLUSION]
    if subject_kind in ("range", "correlation") and is_final_page:
        establishes.append(COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS)
    return establishes


def _validate_coverage_descriptor(subject_kind: str, establishes: list[str]) -> None:
    """Defense in depth for `coverage_descriptor_for`'s own contract: a
    `record`/`range`/`correlation` bundle over ONE node's own ledger is a
    UNILATERAL view. Raises rather than silently stripping a forbidden
    claim, so a future change to `coverage_descriptor_for` that tries to
    assert bilateral coverage fails loudly instead of shipping a false one."""
    claimed = _BILATERAL_ONLY_COVERAGE_DESCRIPTORS.intersection(establishes)
    if claimed:
        raise ValueError(
            f"coverage_descriptor for subject.kind={subject_kind!r} claims {sorted(claimed)} -- "
            "a unilateral, single-ledger bundle-tier answer can never establish bilateral coverage"
        )


#: [mesh-fabric-vocab-alignment] the fabric's request `purpose` vocabulary
#: (see `log_request_purpose`'s docstring for how this responder handles it).
PURPOSE_COUNTERPARTY_CHECK = "counterparty_check"
PURPOSE_STRANGER_SELECTION = "stranger_selection"
PURPOSE_ADJUDICATION = "adjudication"
PURPOSE_RECONCILIATION = "reconciliation"
REQUEST_PURPOSES = frozenset(
    {PURPOSE_COUNTERPARTY_CHECK, PURPOSE_STRANGER_SELECTION, PURPOSE_ADJUDICATION, PURPOSE_RECONCILIATION}
)


def log_request_purpose(request_bytes: bytes) -> None:
    """Read optional `purpose`/`contract_ref` off the raw request JSON, if
    present, and log them -- NEVER parsed into, validated by, or allowed to
    affect `capsule_emit.evidence_request.RequestMap`/`answer()`'s own
    bundle resolution (that module's own `parse_request` already documents
    "unknown fields are ignored, per the draft's shape"; this rides on that
    tolerance rather than changing it). `purpose` is caller-supplied context
    about WHY a request was made (this node's own audit trail), not a
    coverage or subject parameter: two requests identical except for
    `purpose` resolve to byte-identical bundles BY CONSTRUCTION -- this
    function only ever prints, it is never on the path that builds
    `RequestMap`/dispatches to `_build_bundles`. An unrecognized `purpose`
    value is logged as-is and never refused -- the same "unknown fields
    ignored" tolerance, not a new refusal path this module invents."""
    import json as _json

    try:
        data = _json.loads(request_bytes)
    except Exception:
        # Malformed JSON is handled (as request_malformed) by the real
        # parse further down this call's stack -- this function is
        # best-effort logging only, so it declines to log rather than
        # raise or duplicate that decision.
        return
    if not isinstance(data, dict):
        return
    purpose = data.get("purpose")
    contract_ref = data.get("contract_ref")
    if purpose is None and contract_ref is None:
        return
    unrecognized = "" if purpose is None or purpose in REQUEST_PURPOSES else " (unrecognized purpose)"
    print(f"[mesh-fabric-vocab-alignment] evidence-request purpose={purpose!r} contract_ref={contract_ref!r}{unrecognized}")


def augment_evidence_answer_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Additive-only, wire-serialization-time augmentation of an
    `Artifact`/`Refusal`'s own `.to_dict()` output (or this module's plain
    served-summary success dict, left unchanged -- it carries neither
    `bundles` nor `reason`) with the fabric's `status`/`coverage_descriptor`
    vocabulary. Never mutates *d* in place; never changes an EXISTING key's
    value. See the module docstring for the full mapping."""
    out = dict(d)
    if "bundles" in out:
        out["status"] = STATUS_SATISFIED
        is_final_page = out.get("next_page_token") is None
        subject_kind = out.get("subject_kind", "")
        establishes = coverage_descriptor_for(subject_kind, is_final_page=is_final_page)
        if establishes is not None:
            _validate_coverage_descriptor(subject_kind, establishes)
            out["bundles"] = [{**b, "coverage_descriptor": establishes} for b in out["bundles"]]
    elif "reason" in out:
        status = status_for_refusal_reason(out["reason"])
        if status is not None:
            out["status"] = status
    return out


def _refuse_served_summary(request_bytes: bytes, reason: str, *, state: Any, issued_at: str) -> Any:
    """Sign a ``served_summary/1`` refusal with the SAME shape and the SAME
    node key every other refusal/capsule from this sidecar carries.

    ``capsule_emit.evidence_request._refuse`` is private and does exactly
    this three-line stub-then-sign dance; duplicated here rather than
    reached into, same precedent that module's own ``_record_exists`` cites
    for not reaching into a sibling package's private helper.
    """
    import hashlib
    import os

    from capsule_emit import signing as _signing
    from capsule_emit.evidence_request import Refusal

    request_digest = hashlib.sha256(request_bytes).hexdigest()
    signer = _signing.resolve_signer(os.fspath(state.ledger_dir), key_path=state.signing_key_path)
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    return Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)


def _read_jsonl(path: Any) -> list[dict[str, Any]]:
    import json

    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _handle_served_summary_request(state: Any, request_bytes: bytes, req: Any, *, now: str | None = None) -> Any:
    from datetime import datetime, timezone

    from served_summary import COVERAGE_UNSATISFIABLE, REQUEST_MALFORMED, answer_served_summary_request

    from ledger_store_backend import read_all_capsules

    issued_at = now or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    capsule_records, _archived_segments = read_all_capsules(state.ledger_dir)
    checkpoint_lines = _read_jsonl(state.ledger_dir / "checkpoints.jsonl")
    expected_pin = (req.coverage or {}).get("expected_pin", {}).get("root") if req.coverage else None

    result = answer_served_summary_request(
        capsule_records=capsule_records,
        checkpoint_lines=checkpoint_lines,
        expected_pin=expected_pin,
    )
    if result["status"] == "ok":
        return {"v": 1, "subject_kind": req.subject.get("kind"), "derivation": SERVED_SUMMARY_DERIVATION_TOKEN, "served_summary": result["served_summary"]}
    reason = REQUEST_MALFORMED if result["status"] == REQUEST_MALFORMED else COVERAGE_UNSATISFIABLE
    return _refuse_served_summary(request_bytes, reason, state=state, issued_at=issued_at)


def handle_evidence_request(state: Any, request_bytes: bytes, *, now: str | None = None) -> Any:
    """Answer one evidence request against ``state``'s own ledger.

    Returns a ``capsule_emit.evidence_request.Artifact``/``Refusal``, or —
    for a ``derivation: "served_summary/1"`` request — a plain dict carrying
    the served summary (see module docstring). ``now`` overrides the wall
    clock (for deterministic tests); defaults to the real UTC time.

    Deliberately passes no ``allow_forced_checkpoint`` — that parameter is
    unreleased on capsule-emit's PyPI floor this repo pins
    (``[adv-evidence-door-caps-and-subjects]``; ``requirements.txt``'s
    ``capsule-emit[mcp]>=0.7.1`` predates it). Once a release carrying it
    ships and the floor bumps, ``answer()``'s own default
    (``allow_forced_checkpoint=False``, pull-only) applies here
    automatically — no code change needed to get the safe behavior; wiring
    an explicit opt-in is a separate follow-up for whenever a node actually
    wants one.
    """
    from capsule_emit.evidence_request import RequestMalformedError, answer, parse_request

    from ledger_store_backend import materialize_flat_view

    # [mesh-fabric-vocab-alignment] side-effecting only -- see
    # log_request_purpose's docstring for the caller-invariance guarantee.
    log_request_purpose(request_bytes)

    try:
        req = parse_request(request_bytes)
    except RequestMalformedError:
        req = None

    if req is not None and req.derivation == SERVED_SUMMARY_DERIVATION_TOKEN:
        return _handle_served_summary_request(state, request_bytes, req, now=now)

    # [mesh-ledger-store-migration] answer() only understands a flat JSONL
    # file -- materialize_flat_view is a no-op passthrough for a still-flat
    # ledger dir, and a fresh scratch re-derivation (never cached) for a
    # cll.ledger.store.LedgerStore-backed one, so this call's contract is
    # unchanged either way.
    return answer(
        request_bytes,
        ledger=materialize_flat_view(state.ledger_dir),
        signing_key_path=state.signing_key_path,
        now=now,
    )
