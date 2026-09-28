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
  3. Every cited half this node holds is the record of the node the verdict
     names for it (``half_node_ids``).
  4. The verdict concerns this node, one of two ways:
     - this node ASKED that referee about exactly that half pair (its plugin
       records each adjudicate request it sends, in
       ``requested-adjudications.jsonl``) and holds both halves -- the
       requester; or
     - one half is this node's OWN served record -- a judged provider.
     A verdict from a referee nobody here asked, about records this node
     merely holds, is refused: a peer cannot mint rulings about others.
  5. At most one verdict per referee and half pair (requester), or per
     referee and own record (provider); a different one is refused.

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
from peer_keys import announced_key_for, peer_id_for_key
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
REASON_HALVES_MISATTRIBUTED = "halves_misattributed"
REASON_VERDICT_ALREADY_HELD = "verdict_already_held"
#: What this node's plugin records for each adjudicate request it sends.
REQUESTED_ADJUDICATIONS_FILENAME = "requested-adjudications.jsonl"


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


def _served_by(record: dict[str, Any]) -> str | None:
    value = ((((record.get("model_attestation") or {}).get("compute_attestation") or {})
              .get("x-mesh-poc-v1") or {}).get("serving_provenance") or {}).get("served_by_node_id")
    return value if isinstance(value, str) and value else None


def _held_records(ledger_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """``(own records, halves pushed to this node)``, each by capsule id."""
    records, _archived = read_all_capsules(ledger_dir)
    own = {r["capsule_id"]: r for r in records if isinstance(r, dict) and isinstance(r.get("capsule_id"), str)}
    pushed: dict[str, dict[str, Any]] = {}
    path = ledger_dir / _RECEIVED_CAPSULES_FILENAME
    if path.is_file():
        for line in path.read_text().splitlines():
            try:
                held = json.loads(line)
            except Exception:
                continue
            if isinstance(held, dict) and isinstance(held.get("capsule_id"), str):
                pushed[held["capsule_id"]] = held
    return own, pushed


def _asked(ledger_dir: Path, referee: str, halves: list[str]) -> bool:
    """True when this node itself asked *referee* about exactly this half
    pair (the plugin records each adjudicate request it sends)."""
    path = ledger_dir / REQUESTED_ADJUDICATIONS_FILENAME
    if not path.is_file():
        return False
    for line in path.read_text().splitlines():
        try:
            asked = json.loads(line)
        except Exception:
            continue
        if (
            isinstance(asked, dict)
            and asked.get("referee") == referee
            and isinstance(asked.get("halves"), list)
            and sorted(asked["halves"]) == sorted(halves)
        ):
            return True
    return False


def _held_verdicts(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            held = json.loads(line)
        except Exception:
            continue
        if isinstance(held, dict):
            out.append(held)
    return out


def _hold_key(held: dict[str, Any]) -> tuple[Any, ...] | None:
    key = held.get("hold_key")
    if not isinstance(key, list) or len(key) != 3:
        return None
    kind, referee, what = key
    return (kind, referee, tuple(what) if isinstance(what, list) else what)


def _own_key_id(state: Any) -> str | None:
    try:
        from capsule_emit.signing import resolve_signer

        return resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path).key_id
    except Exception:
        return None


def _received_reply(held: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "received",
        "adjudication": {k: v for k, v in held.items() if k not in ("verdict_capsule", "hold_key")},
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
    already = _held_verdicts(path)
    for held in already:
        if held.get("verdict_capsule_id") == facts["verdict_capsule_id"]:
            return _received_reply(held), None

    own, pushed = _held_records(ledger_dir)
    # Every cited half this node holds must be the record of the node the
    # verdict says served it: a verdict cannot pin one node's record on
    # another.
    for half, node in zip(facts["halves"], facts["half_node_ids"]):
        record = own.get(half) or pushed.get(half)
        if record is not None and _served_by(record) != node:
            return None, REASON_HALVES_MISATTRIBUTED

    referee = facts["referee_node_id"]
    self_id = peer_id_for_key(_own_key_id(state))
    if _asked(ledger_dir, referee, facts["halves"]):
        # The requester: it chose this referee for this pair, and holds both.
        if not all(h in own or h in pushed for h in facts["halves"]):
            return None, REASON_NOT_ABOUT_THIS_NODE
        held_half = facts["halves"][0]
        key = ("pair", referee, tuple(sorted(facts["halves"])))
    else:
        # A judged provider: the verdict must be about its own served record.
        mine = [h for h in facts["halves"] if h in own and self_id is not None and _served_by(own[h]) == self_id]
        if not mine:
            return None, REASON_NOT_ABOUT_THIS_NODE
        held_half = mine[0]
        key = ("own", referee, held_half)
    # One verdict per referee and pair (requester) or per referee and own
    # record (provider): a referee cannot pile up rulings on one record.
    for held in already:
        if _hold_key(held) == key:
            return None, REASON_VERDICT_ALREADY_HELD

    held = {
        **facts,
        "held_half_capsule_id": held_half,
        "hold_key": list(key),
        "received_from": sender_peer_id,
        "received_at": issued_at,
        "verdict_capsule": capsule,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(held) + "\n")
    return _received_reply(held), None
