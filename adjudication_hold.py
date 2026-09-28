# SPDX-License-Identifier: Apache-2.0
"""A referee's verdict, delivered to a node it concerns, over the
``record-push/1`` stream (``record_push.handle_record_push`` routes a body
carrying :data:`DELIVERY_MARKER` here)::

    {"adjudication_delivery": 1, "verdict_capsule": <the signed verdict>}

The node that delivers it is only the courier. What this door checks:

  1. The verdict record verifies, and the REFEREE it names signed it with
     that node's announced key.
  2. The referee is neither of the twins it judged, and the ruling is
     ``corroborated``, ``inconclusive``, ``not_comparable``, or a
     contradiction naming one of those twins.
  3. The verdict concerns this node: one of the halves it cites is a record
     this node holds -- its own served record, or a half pushed to it.

Then the verdict is HELD beside the ledger
(``received-adjudications.jsonl``), never written into ``capsules.jsonl``;
the plugin seals an ``adjudication_received`` record citing it before the
courier is told "received" (``record_push_bridge.rs``). A repeat delivery
of the same verdict is answered from what is already held.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.signing import verify_capsule_signature

from ledger_store_backend import read_all_capsules
from peer_keys import announced_key_for
from twin_adjudicator import (
    VERDICT_CONTRADICTED_PREFIX,
    VERDICT_CORROBORATED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_COMPARABLE,
)

__all__ = [
    "DELIVERY_MARKER",
    "RECEIVED_ADJUDICATIONS_FILENAME",
    "REASON_NOT_ABOUT_THIS_NODE",
    "REASON_VERDICT_UNVERIFIED",
    "hold_delivered_verdict",
    "is_delivery",
]

DELIVERY_MARKER = "adjudication_delivery"
DELIVERY_VERSION = 1
RECEIVED_ADJUDICATIONS_FILENAME = "received-adjudications.jsonl"
#: Held-half store (``record_push.RECEIVED_CAPSULES_FILENAME``).
_RECEIVED_CAPSULES_FILENAME = "received-capsules.jsonl"

REASON_VERDICT_UNVERIFIED = "verdict_unverified"
REASON_NOT_ABOUT_THIS_NODE = "not_about_this_node"


def is_delivery(body: Any) -> bool:
    return isinstance(body, dict) and DELIVERY_MARKER in body


def _block(capsule: dict[str, Any]) -> dict[str, Any]:
    block = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("adjudication")
    return block if isinstance(block, dict) else {}


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def verdict_facts(capsule: Any) -> dict[str, Any] | None:
    """The facts a delivered verdict must carry, or ``None`` when it does
    not verify as a verdict signed by the referee it names."""
    if not isinstance(capsule, dict) or not _str(capsule.get("capsule_id")):
        return None
    block = _block(capsule)
    referee = _str(block.get("referee_node_id"))
    verdict = _str(block.get("verdict"))
    halves = [_str(block.get("half_a_capsule_id")), _str(block.get("half_b_capsule_id"))]
    nodes = [_str(block.get("half_a_node_id")), _str(block.get("half_b_node_id"))]
    if referee is None or verdict is None or None in halves or None in nodes:
        return None
    if referee in nodes or nodes[0] == nodes[1]:
        return None
    rulings = {VERDICT_CORROBORATED, VERDICT_INCONCLUSIVE, VERDICT_NOT_COMPARABLE}
    if verdict not in rulings and verdict not in {VERDICT_CONTRADICTED_PREFIX + n for n in nodes}:
        # A contradiction must name one of the twins it judged.
        return None
    if not verify_capsule(capsule).ok or not verify_capsule_signature(capsule):
        return None
    if announced_key_for(referee) != capsule.get("key_id"):
        return None
    return {
        "verdict": verdict,
        "verdict_capsule_id": capsule["capsule_id"],
        "referee_node_id": referee,
        "halves": halves,
        "half_node_ids": nodes,
        "twin_bracket_id": _str(block.get("twin_bracket_id")),
    }


def _held_ids(ledger_dir: Path) -> set[str]:
    """Capsule ids this node holds: its own records and the halves pushed
    to it."""
    records, _archived = read_all_capsules(ledger_dir)
    ids = {r["capsule_id"] for r in records if isinstance(r, dict) and isinstance(r.get("capsule_id"), str)}
    path = ledger_dir / _RECEIVED_CAPSULES_FILENAME
    if path.is_file():
        for line in path.read_text().splitlines():
            try:
                held = json.loads(line)
            except Exception:
                continue
            if isinstance(held, dict) and isinstance(held.get("capsule_id"), str):
                ids.add(held["capsule_id"])
    return ids


def _already_held(path: Path, verdict_capsule_id: str) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    for line in path.read_text().splitlines():
        try:
            held = json.loads(line)
        except Exception:
            continue
        if isinstance(held, dict) and held.get("verdict_capsule_id") == verdict_capsule_id:
            return held
    return None


def _received_reply(held: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "received",
        "adjudication": {k: v for k, v in held.items() if k != "verdict_capsule"},
    }


def hold_delivered_verdict(
    state: Any, body: dict[str, Any], *, sender_peer_id: str, issued_at: str
) -> tuple[dict[str, Any] | None, str | None]:
    """``(reply, None)`` when the verdict is held (or already was), or
    ``(None, reason)`` for the caller to refuse with."""
    if body.get(DELIVERY_MARKER) != DELIVERY_VERSION or set(body) != {DELIVERY_MARKER, "verdict_capsule"}:
        return None, "request_malformed"
    capsule = body["verdict_capsule"]
    facts = verdict_facts(capsule)
    if facts is None:
        return None, REASON_VERDICT_UNVERIFIED

    ledger_dir = Path(state.ledger_dir)
    path = ledger_dir / RECEIVED_ADJUDICATIONS_FILENAME
    held = _already_held(path, facts["verdict_capsule_id"])
    if held is not None:
        return _received_reply(held), None

    held_ids = _held_ids(ledger_dir)
    own = [h for h in facts["halves"] if h in held_ids]
    if not own:
        return None, REASON_NOT_ABOUT_THIS_NODE

    held = {
        **facts,
        "held_half_capsule_id": own[0],
        "received_from": sender_peer_id,
        "received_at": issued_at,
        "verdict_capsule": capsule,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(held) + "\n")
    return _received_reply(held), None
