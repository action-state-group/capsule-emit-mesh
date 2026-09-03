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
"""
from __future__ import annotations

from typing import Any


def handle_evidence_request(state: Any, request_bytes: bytes, *, now: str | None = None) -> Any:
    """Answer one evidence request against ``state``'s own ledger.

    Returns a ``capsule_emit.evidence_request.Artifact`` or ``Refusal`` —
    see that module for the full contract. ``now`` overrides the wall
    clock (for deterministic tests); defaults to the real UTC time.
    """
    from capsule_emit.evidence_request import answer

    return answer(
        request_bytes,
        ledger=state.ledger_path,
        signing_key_path=state.signing_key_path,
        now=now,
    )
