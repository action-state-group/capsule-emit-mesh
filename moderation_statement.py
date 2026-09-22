# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] The Art. 17 statement of reasons.

Design doc §4/§6: "the Art. 17 statement of reasons is generated from the
records alone." DSA Art. 17 requires, for every content restriction: the
facts and circumstances, whether automated means were used, the legal or
contractual ground, and the redress options available.

**Rendered from the bundle alone -- a pure function, nothing else.** Given
the SAME bundle (the shape `moderation_evidence_door.answer_redress_request`
returns for a SATISFIED answer), `render_statement_of_reasons` always
returns the SAME statement, byte for byte -- no wall clock, no random data,
no live system lookup. That is what "regenerates byte-identical from the
bundle" (the spike's own acceptance line) means: a regulator or an auditor
holding nothing but a delivered bundle can recompute the exact statement
Buzz would have shown the user, and confirm the two match.
"""
from __future__ import annotations

import json
from typing import Any

from moderation_decision import MODERATION_SUBJECT_KEY

__all__ = [
    "STATEMENT_SCHEMA",
    "render_statement_of_reasons",
    "statement_of_reasons_bytes",
]

STATEMENT_SCHEMA = "capsule-emit-mesh/dsa-art17-statement-of-reasons/v1"


def _moderation_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get(MODERATION_SUBJECT_KEY, {})


def _adjudication_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get("adjudication", {})


def render_statement_of_reasons(bundle: dict[str, Any]) -> dict[str, Any]:
    """Render the Art. 17 statement of reasons for one redress bundle
    (`moderation_evidence_door.answer_redress_request`'s per-decision
    bundle shape). Reads ONLY fields already present in the bundle -- never
    the message text (never present in the bundle to begin with), never a
    fresh timestamp, never a live re-query.
    """
    decision_capsule = bundle["decision"]
    moderation = _moderation_block(decision_capsule)
    subject_ref = moderation["subject_ref"]
    policy_ref = moderation["policy_ref"]

    statement: dict[str, Any] = {
        "schema": STATEMENT_SCHEMA,
        "facts": {
            "message_digest": subject_ref["message_digest"],
            "room_ref": subject_ref["room_ref"],
        },
        "automated_means": moderation["automated"],
        "legal_ground": {
            "policy_id": policy_ref["policy_id"],
            "version": policy_ref["version"],
        },
        "decision": moderation["decision"],
        "basis": moderation["basis"],
        "redress": moderation["redress_ref"],
        "decision_capsule_id": decision_capsule["capsule_id"],
    }

    adjudication_capsule = bundle.get("adjudication")
    if adjudication_capsule is not None:
        adjudication = _adjudication_block(adjudication_capsule)
        statement["adjudication"] = {
            "verdict": adjudication.get("verdict"),
            "status": adjudication.get("status"),
            "referee_id": adjudication.get("referee_id"),
            "adjudication_capsule_id": adjudication_capsule["capsule_id"],
        }

    return statement


def statement_of_reasons_bytes(bundle: dict[str, Any]) -> bytes:
    """Canonical bytes of `render_statement_of_reasons(bundle)` -- sorted
    keys, no whitespace, same convention every signed artifact in this repo
    canonicalizes with. Two independent regenerations from the SAME bundle
    produce identical bytes by construction (a pure function over the
    bundle's own already-sealed fields)."""
    return json.dumps(render_statement_of_reasons(bundle), sort_keys=True, separators=(",", ":")).encode("utf-8")
