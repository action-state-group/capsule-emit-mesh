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
"""
from __future__ import annotations

from typing import Any

#: The one derivation token this module dispatches on directly. Any other
#: value (including ``None``) falls through to the generic bundle-based
#: ``answer()`` below, unchanged.
SERVED_SUMMARY_DERIVATION_TOKEN = "served_summary/1"


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
