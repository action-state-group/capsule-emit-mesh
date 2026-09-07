#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-pane-b-peers-accountability-tab] Pane B "Peers" -- one row per node
this machine has exchanged capsules with, every cell recomputed from THAT
peer's own artifacts and carrying an explicit honesty state -- never a
blank cell, and never a trust score.

Composes verbs that already exist; re-derives none of their evidence:

  - **peer identity**: ``capsule_mesh_view.label_counterparty()`` -- the
    same best-effort counterparty label the per-exchange machine view
    already computes from ``cross_party.initiator_ref`` (a digest over the
    initiator's OWN signed request attestation). Reused byte-for-byte, not
    re-derived. Records with no such evidence group under ``UNKNOWN_PEER``
    -- an explicit "not one identified node" bucket, never silently
    presented as though it were a single peer.
  - **rung**: ``capsule_accountability_tab.cross_party_grade()`` (reused
    byte-for-byte) applied to every exchange with a peer, folded to the
    WORST rung seen -- never rounds up a peer's row past its weakest
    exchange.
  - **role + directional counts**: ``role_and_count_cell()`` -- this node's
    own ``x-mesh-poc-v1.role``/``label_role()`` per record, folded to "you
    asked them" / "they asked you" / "both" plus a count each way. Never a
    trust signal, purely a direction-of-exchange fact.
  - **history (theirs)**: v2 (mesh-accountability-panes-v2-2026-09-05.md
    §2/§4) calls out that today's cell shows THIS node's own
    ``history_card.build_history_card()`` chain on every peer row -- a
    documented shortcut, not the peer's own card. There is still no evidence
    subject a peer's OWN history card can be fetched over (the merged
    responder answers ``record``/``range`` only, never ``checkpoints`` /
    ``full_history``), so this cell is now honestly ``pending`` rather than
    silently mislabeling this node's chain as theirs -- see
    ``peer_history_cell`` / ``THEIRS_HISTORY_PENDING_REASON``. The real
    grading logic (``history_cell`` / ``continuity_cell`` / ``witnessed_cell``)
    stays, unchanged and still tested, as the "mine, for reference" detail
    under that pending cell.
  - **served (theirs)**: ``served_summary.py`` now exists
    ([mesh-served-summary-derivation]), but this cell is still honestly
    ``pending`` -- same peer-fetch gap as History (theirs): nothing here
    SENDS a ``served_summary/1`` request to a peer, the merged responder
    only ANSWERS one sent to it. This node's OWN served summary rides along
    as ``mine_for_reference``, same discipline as the history cell's
    ``mine_for_reference``.
  - **pair (me<->them)**: real now. Reuses
    ``capsule_exchange_tab.digest_match_grade`` (never re-derived) over
    every ``exchange_id`` this peer's records carry, folded to a per-peer
    reconciliation count -- the only cell that can say "missing".
  - **verdicts**: real for the half this node itself sealed (adjudication
    capsules in this node's own ledger naming one of this peer's capsule
    ids), via the same detection ``capsule_accountability_tab``'s
    counterparty-held block uses. The "held by others" half -- what my
    counterparties report when *I* ask them -- is pending
    [mesh-ask-the-references].
  - **asked**: this node's own evidence-request carrier now exists
    ([mesh-e14-evidence-responder] / [mesh-e15-evidence-http-route], both
    merged) -- but that carrier only ANSWERS requests a peer sends to this
    node; nothing yet logs requests this node SENDS to a peer, so this cell
    stays honestly ``absent`` for a different, current reason (see
    ``ASKED_ABSENT_REASON``), not the stale pre-merge one.

Every cell is a small dict carrying ``state`` + ``text`` (plus whatever
detail backs it) so a renderer never has to guess what an empty cell means
-- ``render_cell_text`` is a total function over that shape and never
returns a blank string.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import assurance_map
from capsule_accountability_tab import STATE_FAILED, STATE_VERIFIED, cross_party_grade
from capsule_exchange_tab import digest_match_grade, exchange_id_for, half_by_role, records_for_exchange
from capsule_mesh_view import _poc_block, label_counterparty, label_role
from history_card import HistoryCard, build_history_card

__all__ = [
    "ASKED_ABSENT_REASON",
    "CELL_ABSENT",
    "CELL_CONTRADICTED",
    "CELL_FAILED",
    "CELL_PENDING",
    "CELL_PRESENT",
    "CELL_REFUSED",
    "CELL_UNILATERAL",
    "CELL_VERIFIED",
    "FORBIDDEN_RATING_KEYS",
    "FORBIDDEN_SORT_KEYS",
    "SERVED_PENDING_REASON",
    "THEIRS_HISTORY_PENDING_REASON",
    "VERDICTS_REFERENCES_PENDING_REASON",
    "RatingFieldError",
    "UNKNOWN_PEER",
    "asked_cell",
    "assert_no_rating_fields",
    "build_peer_row",
    "build_peers_payload",
    "continuity_cell",
    "group_by_peer",
    "history_cell",
    "node_cell",
    "pair_cell",
    "peer_history_cell",
    "render_cell_text",
    "render_peers_tab_html",
    "role_and_count_cell",
    "rung_cell",
    "served_cell",
    "sort_peer_rows",
    "verdicts_cell",
    "witnessed_cell",
]

# The honesty states a Pane B cell can carry (mesh-accountability-build-plan
# §6, the batch-3 tab spec): a refusal is never folded into "absent", an
# absence names its own transport/timeout, "unilateral" is a first-class
# state (not a lesser "present"), and a contradicted cell always carries the
# adjudication it disagrees with. ``CELL_PRESENT``/``CELL_VERIFIED``/
# ``CELL_FAILED`` reuse the same three(+failed)-state vocabulary
# ``capsule_accountability_tab.py`` already established.
CELL_REFUSED = "refused"
CELL_ABSENT = "absent"
CELL_PRESENT = "present"
CELL_VERIFIED = "verified"
CELL_FAILED = "failed"
CELL_UNILATERAL = "unilateral"
CELL_CONTRADICTED = "contradicted"
CELL_PENDING = "pending"

#: The peer key for exchanges with no attributable counterparty evidence.
#: Grouped together because there is nowhere else honest to put them, but
#: NEVER rendered as though it names one identified node -- see `node_cell`.
UNKNOWN_PEER = "unknown"

#: STALE REASON, SUPERSEDED (kept only in this comment so the history is
#: legible): "[mesh-e14-evidence-responder] is not merged yet (capsule-emit-
#: mesh PR #83 CI red, pending upstream capsule-emit PR #148)". Both #83 and
#: [mesh-e15-evidence-http-route] are MERGED on `main` today -- the carrier
#: that ANSWERS a peer's request exists. The current, real gap is different:
#: nothing yet logs the requests THIS node SENDS to a peer (no evidence
#: client, no send-log persistence) -- see `ASKED_ABSENT_REASON` below.
ASKED_ABSENT_REASON = (
    "no log of evidence-requests this node has SENT to this peer exists yet: the responder "
    "that answers a peer's request is merged (capsule-emit-mesh #83, [mesh-e15-evidence-http-route]), "
    "but nothing persists a per-peer send/answer log for requests this node initiates"
)

#: v2 (mesh-accountability-panes-v2-2026-09-05.md §4): "History (theirs) must
#: be THEIR card fetched via the evidence client (checkpoints subject,
#: cached per pin)". No such subject exists yet -- the merged responder
#: (capsule_emit.evidence_request.SUBJECT_KINDS) answers only
#: `record`/`range`, never `checkpoints`/`full_history`. Rather than keep
#: silently showing this node's OWN card as if it were the peer's (the
#: documented shortcut the doc calls out to fix), this cell is honestly
#: pending a peer-fetch carrier that does not exist in this repo yet.
THEIRS_HISTORY_PENDING_REASON = (
    "this node cannot fetch the peer's OWN history card yet: the evidence-request carrier only "
    "answers record/range subjects, not checkpoints/full_history -- showing this node's own chain "
    "here would misrepresent it as the peer's, so this cell is pending a peer-fetch carrier "
    "(no task id filed yet for this gap -- flagged in the outbox)"
)

#: [mesh-served-summary-derivation] ``served_summary.py`` now exists, but
#: there is still no evidence-request CLIENT on this node to PULL a peer's
#: OWN served summary -- the same peer-fetch gap
#: ``THEIRS_HISTORY_PENDING_REASON`` documents for history (the merged
#: responder only ANSWERS a request sent to it; nothing here sends one to a
#: peer yet). This node's own summary rides along as ``mine_for_reference``,
#: same discipline ``peer_history_cell`` already follows -- never presented
#: as though it were the peer's.
SERVED_PENDING_REASON = (
    "this node cannot fetch the peer's OWN served summary yet: the evidence-request carrier "
    "only ANSWERS a request sent to it, and nothing here sends served_summary/1 requests to a "
    "peer -- same peer-fetch gap as history's THEIRS_HISTORY_PENDING_REASON"
)

VERDICTS_REFERENCES_PENDING_REASON = (
    "what my counterparties report when asked about this peer is not available on this view yet: "
    "pending [mesh-ask-the-references]"
)

#: Rung ordering per `capsule_sidecar.derive_cross_party_rung`'s own
#: docstring: unilateral_fallback < acknowledged_receipt < full_bilateral.
#: Duplicated as an ordered tuple (not imported) because the source of
#: truth is the STRING VALUES `cross_party_grade` returns, not a rank int
#: that module exposes.
_RUNG_ORDER = ("unilateral_fallback", "acknowledged_receipt", "full_bilateral")

#: Same "properties, not scores" discipline as `self_accountability.py`'s
#: `FORBIDDEN_RATING_KEYS` -- duplicated locally rather than imported
#: because that module is a sibling in-flight branch, not yet on `main`.
#: A trust-rating-named field is barred by the neutrality gate at the repo
#: level as well as here; this list catches the general scoring shape.
FORBIDDEN_RATING_KEYS = ("score", "rating", "trust_level", "grade_percent")

#: Same exact-match allowlist as `self_accountability.SAFE_DISCLAIMER_KEYS`,
#: duplicated for the same sibling-branch reason as `FORBIDDEN_RATING_KEYS`
#: above. Needed here because `served_cell`'s `mine_for_reference` now
#: embeds a `served_summary.ServedSummary.to_value()` verbatim, which
#: carries a `not_a_score` disclaimer key (contains "score").
SAFE_DISCLAIMER_KEYS = frozenset({"not_a_score"})

#: "No sort by trust — sort by any property." A sort key containing any of
#: these substrings is refused outright, never silently ignored.
FORBIDDEN_SORT_KEYS = ("trust", "score", "rating")

_BREAK_MMR_SIZE_RE = re.compile(r"broken at mmr_size=(\d+)")


class RatingFieldError(ValueError):
    """Raised when a payload would carry a field that could hold a rating."""


def assert_no_rating_fields(value: Any, *, _path: str = "$") -> None:
    """Walk *value* recursively and raise `RatingFieldError` on the first key
    whose name contains one of `FORBIDDEN_RATING_KEYS`. Recursive: a rating
    buried three dicts deep must be caught exactly like a top-level one.
    `SAFE_DISCLAIMER_KEYS` is checked by exact match first -- a key naming
    the ABSENCE of a rating is not the thing this guards against."""
    if isinstance(value, dict):
        for key, sub in value.items():
            if key in SAFE_DISCLAIMER_KEYS:
                continue
            lowered = str(key).lower()
            for forbidden in FORBIDDEN_RATING_KEYS:
                if forbidden in lowered:
                    raise RatingFieldError(f"{_path}.{key} looks like a rating field (matches {forbidden!r})")
            assert_no_rating_fields(sub, _path=f"{_path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            assert_no_rating_fields(item, _path=f"{_path}[{i}]")


def render_cell_text(cell: dict[str, Any]) -> str:
    """Total function from a cell dict to its display text. Never returns an
    empty string -- a cell with no ``text`` at all falls back to an explicit
    "no evidence recorded" rather than rendering blank."""
    text = cell.get("text")
    return text if text else "no evidence recorded"


# ---------------------------------------------------------------------------
# Peer grouping
# ---------------------------------------------------------------------------


def group_by_peer(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group ledger records by `capsule_mesh_view.label_counterparty()`,
    reused unmodified -- never a second, competing peer-identity derivation."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault(label_counterparty(record), []).append(record)
    return groups


# ---------------------------------------------------------------------------
# Per-column cells
# ---------------------------------------------------------------------------


def node_cell(peer_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Node (owner/member) column.

    No capsule field this sidecar seals today names a REMOTE peer's own
    node-ownership cert (`node_ownership.py`'s owner binding is always the
    SEALING node's own cert -- never the counterparty's), so "owner" is not
    reachable from local data alone yet; every identified peer renders
    "member" (a bare mesh identity backed by their own signed request
    attestation), never a fabricated ownership claim.
    """
    if peer_id == UNKNOWN_PEER:
        return {
            "state": CELL_ABSENT,
            "text": f"no counterparty evidence for these {len(records)} exchange(s) -- unattributed, not one identified peer",
            "peer_id": None,
            "member_kind": None,
            "exchange_count": len(records),
        }
    return {
        "state": CELL_PRESENT,
        "text": peer_id,
        "peer_id": peer_id,
        "member_kind": "member",
        "source": "cross_party.initiator_ref",
        "capture_method": "label_counterparty",
        "exchange_count": len(records),
    }


def rung_cell(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Rung column: the WORST cross-party rung across every exchange with
    this peer -- never rounds a peer's row up past its weakest exchange."""
    grades = [cross_party_grade(_poc_block(r), capsule_id=r.get("capsule_id")) for r in records]
    ranked = sorted(grades, key=lambda g: _RUNG_ORDER.index(g["rung"]) if g["rung"] in _RUNG_ORDER else -1)
    worst = ranked[0]
    distinct = sorted({g["rung"] for g in grades}, key=lambda r: _RUNG_ORDER.index(r) if r in _RUNG_ORDER else -1)
    text = worst["rung"] if len(distinct) == 1 else f"{worst['rung']} (worst of {len(distinct)} distinct rungs across {len(records)} exchanges)"
    return {
        "state": CELL_UNILATERAL if worst["rung"] == "unilateral_fallback" else CELL_PRESENT,
        "text": text,
        "rung": worst["rung"],
        "distinct_rungs": distinct,
        "identity_limitation": worst["identity_limitation"],
    }


def _checkpoint_ref_from_line(line: dict[str, Any] | None) -> dict[str, Any] | None:
    if line is None:
        return None
    return {
        "mmr_size": line.get("mmr_size"),
        "root": line.get("root"),
        "timestamp": line.get("timestamp"),
        "signed": bool(line.get("checkpoint_cose")),
    }


def _fork_checkpoint_pair(
    card: HistoryCard, checkpoint_lines: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None] | None:
    """The two signed checkpoints either side of a detected break: the last
    checkpoint that still chained cleanly, and the one whose link to it
    failed. Re-scans the raw checkpoint lines rather than editing
    `history_card.py` -- that module is already merged and this repo's
    fixed integration order names `capsule_sidecar.py` as the only touch
    point for the batch, not the checkpoint verb."""
    match = _BREAK_MMR_SIZE_RE.search(card.properties.continuity)
    if not match:
        return None
    broken_size = int(match.group(1))
    ordered = sorted(checkpoint_lines, key=lambda ln: ln.get("mmr_size", -1))
    idx = next((i for i, ln in enumerate(ordered) if ln.get("mmr_size") == broken_size), None)
    if idx is None:
        return None
    prev_line = ordered[idx - 1] if idx > 0 else None
    return _checkpoint_ref_from_line(prev_line), _checkpoint_ref_from_line(ordered[idx])


def history_cell(card: HistoryCard) -> dict[str, Any]:
    """History column: checkpoints + depth since size S, from
    `history_card.build_history_card()`'s own properties."""
    broken = card.properties.continuity.startswith("broken at")
    if broken:
        text = f"fork/break detected: {card.properties.continuity}"
        state = CELL_FAILED
    elif card.checkpoint_count == 0:
        text = "no checkpoints since the requested size"
        state = CELL_ABSENT
    else:
        text = f"{card.properties.history_depth} checkpoint(s) since size {card.since_size}"
        state = CELL_VERIFIED
    return {
        "state": state,
        "text": text,
        "history_depth": card.properties.history_depth,
        "checkpoint_count": card.checkpoint_count,
        "cadence": dict(card.properties.cadence),
    }


def continuity_cell(card: HistoryCard, checkpoint_lines: list[dict[str, Any]]) -> dict[str, Any]:
    """Continuity column: "unbroken" or an honest "broken at ..." -- never
    silently green. A break carries the two SIGNED checkpoints either side
    of it, so a reader never has to take the label's word for the fork.
    Zero checkpoints is `absent`, same as `history_cell` -- there is
    nothing to have verified as continuous yet, so it must not render the
    same "verified" state an actually-walked chain earns."""
    broken = card.properties.continuity.startswith("broken at")
    state = CELL_FAILED if broken else (CELL_ABSENT if card.checkpoint_count == 0 else CELL_VERIFIED)
    cell: dict[str, Any] = {
        "state": state,
        "text": card.properties.continuity,
        "unforked": card.properties.unforked,
    }
    if broken:
        pair = _fork_checkpoint_pair(card, checkpoint_lines)
        if pair is not None:
            cell["last_good_checkpoint"], cell["broken_checkpoint"] = pair
    return cell


def witnessed_cell(card: HistoryCard) -> dict[str, Any]:
    """Witnessed column: whether the latest covered checkpoint carries an
    independent timestamp-authority witness."""
    return {
        "state": CELL_VERIFIED if card.witnessed else CELL_ABSENT,
        "text": ("witnessed by " + ", ".join(card.witnesses)) if card.witnessed else "not witnessed",
        "witnesses": list(card.witnesses),
    }


def asked_cell(evidence_requests: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Asked column: evidence requests THIS node sent to this peer.

    ``evidence_requests``, when supplied, is a list of already-answered
    ``{request, response}`` pairs for THIS peer, ``response`` shaped
    ``{status: "refused"|"no_answer"|"ok", ...}`` (the evidence-request
    carrier's own shape). ``None``/``[]`` is the honest, and today ONLY
    reachable, state: see ``ASKED_ABSENT_REASON`` for why (not the stale
    pre-merge reason this cell used to cite).
    """
    if not evidence_requests:
        return {"state": CELL_ABSENT, "text": ASKED_ABSENT_REASON, "count": 0}

    refused = [r for r in evidence_requests if (r.get("response") or {}).get("status") == "refused"]
    if refused:
        reason = refused[-1]["response"].get("reason") or "no reason given"
        return {
            "state": CELL_REFUSED,
            "text": f"card refused: {reason}",
            "reason": reason,
            "signed": bool(refused[-1]["response"].get("sig")),
            "count": len(evidence_requests),
        }

    no_answer = [r for r in evidence_requests if (r.get("response") or {}).get("status") == "no_answer"]
    if no_answer:
        resp = no_answer[-1]["response"]
        transport = resp.get("transport", "?")
        timeout_seconds = resp.get("timeout_seconds", "?")
        return {
            "state": CELL_ABSENT,
            "text": f"no answer within {timeout_seconds}s over {transport}",
            "transport": transport,
            "timeout_seconds": timeout_seconds,
            "count": len(evidence_requests),
        }

    return {
        "state": CELL_PRESENT,
        "text": f"{len(evidence_requests)} evidence-request(s) answered",
        "count": len(evidence_requests),
    }


def peer_history_cell(card: HistoryCard, checkpoint_lines: list[dict[str, Any]]) -> dict[str, Any]:
    """History (theirs) column -- v2. Honestly ``pending``: see
    ``THEIRS_HISTORY_PENDING_REASON``. This node's own chain state (the old
    shortcut's data) rides along as ``mine_for_reference``, computed via the
    unchanged, still-real ``history_cell``/``continuity_cell``/
    ``witnessed_cell`` graders -- never discarded, just no longer presented
    as though it were the peer's."""
    return {
        "state": CELL_PENDING,
        "text": THEIRS_HISTORY_PENDING_REASON,
        "mine_for_reference": {
            "history": history_cell(card),
            "continuity": continuity_cell(card, checkpoint_lines),
            "witnessed": witnessed_cell(card),
        },
    }


def _own_served_summary_value(
    node_id: str, records: list[dict[str, Any]], checkpoint_lines: list[dict[str, Any]], source_log: str
) -> dict[str, Any]:
    """This node's own ``served_summary`` -- computed once per payload
    (never re-derived per peer row) and threaded into every row's ``served``
    cell as ``mine_for_reference``, same as ``peer_history_cell`` does for
    the history chain."""
    from capsule_emit.checkpoint import CheckpointRecord
    from served_summary import build_served_summary

    latest_checkpoint = CheckpointRecord.from_dict(checkpoint_lines[-1]) if checkpoint_lines else None
    summary = build_served_summary(
        node_id=node_id, capsule_records=records, latest_checkpoint=latest_checkpoint, source_log=source_log
    )
    return summary.to_value()


def served_cell(own_summary_value: dict[str, Any] | None = None) -> dict[str, Any]:
    """Served (theirs) column. Honestly ``pending``: see
    ``SERVED_PENDING_REASON``. ``own_summary_value``, when supplied, is THIS
    node's own ``served_summary.ServedSummary.to_value()`` -- carried as
    ``mine_for_reference`` exactly like ``peer_history_cell`` carries this
    node's own chain, never presented as though it were the peer's."""
    cell: dict[str, Any] = {"state": CELL_PENDING, "text": SERVED_PENDING_REASON, "source": "self_derived"}
    if own_summary_value is not None:
        cell["mine_for_reference"] = own_summary_value
    return cell


def role_and_count_cell(records: list[dict[str, Any]], source_log: str = "sidecar") -> dict[str, Any]:
    """Role + directional-count column: `label_role()` per record, folded to
    "you asked them" / "they asked you" / "both", with a count each way.
    Never a trust signal -- purely which direction each exchange ran."""
    served = sum(1 for r in records if label_role(r, source_log) == "served")
    requested = sum(1 for r in records if label_role(r, source_log) == "requested")
    total = len(records)
    if served and requested:
        role, text = "both", f"both · {total} ({requested} you→them, {served} them→you)"
    elif requested:
        role, text = "you_to_them", f"you→them · {requested}"
    elif served:
        role, text = "them_to_you", f"them→you · {served}"
    else:
        role, text = "unknown", f"unknown role · {total}"
    return {
        "state": CELL_PRESENT,
        "text": text,
        "role": role,
        "you_to_them_count": requested,
        "them_to_you_count": served,
        "exchange_count": total,
    }


def pair_cell(records: list[dict[str, Any]], all_records: list[dict[str, Any]], source_log: str = "sidecar") -> dict[str, Any]:
    """Pair (me<->them) column -- real. Folds
    ``capsule_exchange_tab.digest_match_grade`` (never re-derived) over
    every ``exchange_id`` this peer's records carry -- the only cell that
    can say "missing", since a lone half is exactly what ``digest_match_grade``
    grades ``absent``."""
    exchange_ids = sorted({eid for eid in (exchange_id_for(r) for r in records) if eid and eid != "unknown"})
    if not exchange_ids:
        return {"state": CELL_ABSENT, "text": "no exchange_id on these records -- nothing to reconcile", "verified": 0, "failed": 0, "missing": 0}

    verified = failed = missing = 0
    details: list[dict[str, Any]] = []
    for exchange_id in exchange_ids:
        group = records_for_exchange(all_records, exchange_id)
        requester_half, provider_half = half_by_role(group, source_log)
        grade = digest_match_grade(requester_half[0] if requester_half else None, provider_half[0] if provider_half else None)
        if grade["state"] == STATE_VERIFIED:
            verified += 1
        elif grade["state"] == STATE_FAILED:
            failed += 1
        else:
            missing += 1
        details.append({"exchange_id": exchange_id, "state": grade["state"]})

    if failed:
        state, text = CELL_FAILED, f"{failed} pair(s) digest-mismatched, {verified} reconciled"
    elif missing:
        state, text = CELL_PRESENT, f"{verified} reconciled, {missing} missing a half on this view"
    else:
        state, text = CELL_VERIFIED, f"{verified} pair(s) reconciled, 0 missing"
    return {"state": state, "text": text, "verified": verified, "failed": failed, "missing": missing, "details": details}


def _adjudications_about(capsule_ids: set[str], all_records: list[dict[str, Any]]) -> tuple[int, dict[str, int], str | None]:
    """Sealed adjudication capsules (anywhere in ``all_records``) naming one
    of *capsule_ids* as either half -- same detection
    ``capsule_accountability_tab.build_counterparty_held_block`` uses."""
    tally = {"corroborated": 0, "contradicted": 0, "inconclusive": 0}
    sealed = 0
    contradicted_capsule_id: str | None = None
    for record in all_records:
        adjudication = (record.get("model_attestation") or {}).get("compute_attestation", {}).get("adjudication")
        if not adjudication:
            continue
        if adjudication.get("half_a_capsule_id") not in capsule_ids and adjudication.get("half_b_capsule_id") not in capsule_ids:
            continue
        sealed += 1
        verdict = adjudication.get("verdict") or ""
        if verdict.startswith("contradicted"):
            tally["contradicted"] += 1
            contradicted_capsule_id = record.get("capsule_id")
        elif verdict == "corroborated":
            tally["corroborated"] += 1
        elif verdict == "inconclusive":
            tally["inconclusive"] += 1
    return sealed, tally, contradicted_capsule_id


def verdicts_cell(records: list[dict[str, Any]], all_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Verdicts column -- real for the half this node itself sealed
    (adjudication capsules in this node's own ledger naming one of this
    peer's capsule ids); ``VERDICTS_REFERENCES_PENDING_REASON`` for the
    "held by others" half (pending [mesh-ask-the-references])."""
    peer_capsule_ids = {r.get("capsule_id") for r in records if r.get("capsule_id")}
    sealed, tally, contradicted_capsule_id = _adjudications_about(peer_capsule_ids, all_records)
    if sealed == 0:
        return {"state": CELL_PENDING, "text": VERDICTS_REFERENCES_PENDING_REASON, "tally": tally, "source": "self_sealed"}
    text = f"{tally['corroborated']} ✓ · {tally['contradicted']} ✗ · {tally['inconclusive']} ? (self-sealed) -- {VERDICTS_REFERENCES_PENDING_REASON}"
    cell: dict[str, Any] = {
        "state": CELL_CONTRADICTED if tally["contradicted"] else CELL_PRESENT,
        "text": text,
        "tally": tally,
        "source": "self_sealed",
        "references_pending_reason": VERDICTS_REFERENCES_PENDING_REASON,
    }
    if contradicted_capsule_id:
        cell["adjudication_capsule_id"] = contradicted_capsule_id
    return cell


# ---------------------------------------------------------------------------
# Row / payload assembly
# ---------------------------------------------------------------------------


def build_peer_row(
    peer_id: str,
    records: list[dict[str, Any]],
    *,
    history_card: HistoryCard,
    checkpoint_lines: list[dict[str, Any]],
    all_records: list[dict[str, Any]],
    source_log: str = "sidecar",
    evidence_requests: list[dict[str, Any]] | None = None,
    own_served_summary_value: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One Pane B row for *peer_id* -- the 7 columns of
    mesh-accountability-panes-v2-2026-09-05.md §2, plus a row-expand pair
    ledger (the "their card in Pane A layout" half of row-expand stays
    pending the same peer-fetch gap as ``peer_history_cell``)."""
    timestamps = [r.get("timestamp") for r in records if r.get("timestamp")]
    pair = pair_cell(records, all_records, source_log)
    return {
        "peer_id": peer_id if peer_id != UNKNOWN_PEER else None,
        "node": node_cell(peer_id, records),
        "rung": rung_cell(records),
        "role": role_and_count_cell(records, source_log),
        "history": peer_history_cell(history_card, checkpoint_lines),
        "served": served_cell(own_served_summary_value),
        "pair": pair,
        "verdicts": verdicts_cell(records, all_records),
        "asked": asked_cell(evidence_requests),
        "exchange_count": len(records),
        "first_seen": min(timestamps, default=None),
        "last_seen": max(timestamps, default=None),
        "expand": {
            "pair_ledger": pair.get("details", []),
            "their_card": {
                "state": CELL_PENDING,
                "text": THEIRS_HISTORY_PENDING_REASON,
            },
        },
    }


def build_peers_payload(
    records: list[dict[str, Any]],
    *,
    node_id: str,
    log_id: str,
    checkpoint_lines: list[dict[str, Any]] | None = None,
    since_size: int = 0,
    source_log: str = "sidecar",
    evidence_requests_by_peer: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Assemble the whole Pane B payload: one row per peer this node has
    exchanged capsules with, default-sorted most-recent-first (never by
    trust -- `sort_peer_rows` refuses that regardless of this default).

    Raises `RatingFieldError` (never returns a payload that could) if any
    composed cell smuggled in a field that looks like a rating.
    """
    checkpoint_lines = checkpoint_lines or []
    card = build_history_card(node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size)
    own_served_summary_value = _own_served_summary_value(node_id, records, checkpoint_lines, source_log)
    groups = group_by_peer(records)
    rows = [
        build_peer_row(
            peer_id,
            peer_records,
            history_card=card,
            checkpoint_lines=checkpoint_lines,
            all_records=records,
            source_log=source_log,
            evidence_requests=(evidence_requests_by_peer or {}).get(peer_id),
            own_served_summary_value=own_served_summary_value,
        )
        for peer_id, peer_records in groups.items()
    ]
    rows = sort_peer_rows(rows, "last_seen", reverse=True)
    payload = {"node_id": node_id, "peer_count": len(rows), "default_sort": "last_seen", "rows": rows}
    assert_no_rating_fields(payload)
    return payload


def sort_peer_rows(rows: list[dict[str, Any]], key: str, *, reverse: bool = False) -> list[dict[str, Any]]:
    """Sort peer rows by ANY column -- but never by trust. `key` names a
    top-level row field; a dict-valued field sorts by its own `text`."""
    lowered = key.lower()
    for forbidden in FORBIDDEN_SORT_KEYS:
        if forbidden in lowered:
            raise ValueError(f"cannot sort by {key!r}: properties are sortable, trust/score fields are not")

    def sort_value(row: dict[str, Any]) -> tuple[bool, Any]:
        value = row.get(key)
        if isinstance(value, dict):
            value = value.get("text") or value.get("state") or ""
        return (value is None, value if value is not None else "")

    return sorted(rows, key=sort_value, reverse=reverse)


# ---------------------------------------------------------------------------
# Self-contained HTML shell -- same dark "control room ledger" styling as
# capsule_accountability_tab.py's shell, re-skinned for the Peers table.
# ---------------------------------------------------------------------------


def render_peers_tab_html(payload: dict[str, Any]) -> str:
    """Return the self-contained Peers-tab HTML for *payload*. Offline, no
    fetch -- the row data is inlined as plain JSON, same discipline as
    `capsule_accountability_tab.render_accountability_tab_html`."""
    if "@@PAYLOAD@@" not in _HTML_SHELL or _HTML_SHELL.count("@@PAYLOAD@@") != 1:
        raise RuntimeError(
            "embed invariant broken: exactly one @@PAYLOAD@@ placeholder must "
            f"exist in the shell, found {_HTML_SHELL.count('@@PAYLOAD@@')}"
        )
    payload_json = json.dumps(payload, separators=(",", ":")).replace("<", "\\u003c")
    shell = _HTML_SHELL.replace("@@CHIP_TONE@@", assurance_map.tone_js_object())
    return shell.replace("@@PAYLOAD@@", payload_json)


_HTML_SHELL = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mesh-llm · Accountability · Peers</title>
<style>
  :root {
    --bg: oklch(0.17 0.015 250); --panel: oklch(0.2 0.018 250);
    --panel-strong: oklch(0.23 0.02 250); --border: oklch(0.3 0.02 250 / 0.9);
    --border-soft: oklch(0.3 0.02 250 / 0.45); --fg: oklch(0.96 0.005 80);
    --fg-dim: oklch(0.78 0.01 80); --fg-faint: oklch(0.6 0.01 80);
    --good: oklch(0.78 0.14 150); --warn: oklch(0.8 0.12 80); --bad: oklch(0.7 0.18 25);
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 13.5px/1.55 "Inter Tight","Inter",system-ui,sans-serif; }
  main { max-width: 1200px; margin: 0 auto; padding: 20px 16px 40px; }
  h1 { font-size: 16.5px; margin: 0 0 4px; }
  p.caption { color: var(--fg-dim); font-size: 12px; margin: 0 0 18px; }
  table { width: 100%; border-collapse: collapse; }
  thead th { text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em;
    color: var(--fg-faint); background: var(--panel-strong); padding: 9px 12px; border-bottom: 1px solid var(--border);
    cursor: pointer; user-select: none; }
  thead th:hover { color: var(--fg); }
  tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
  .pill { display: inline-flex; padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
  .pill-good { color: var(--good); background: color-mix(in oklab, var(--good) 14%, transparent); }
  .pill-warn { color: var(--warn); background: color-mix(in oklab, var(--warn) 14%, transparent); }
  .pill-bad { color: var(--bad); background: color-mix(in oklab, var(--bad) 14%, transparent); }
  .pill-neutral { color: var(--fg-dim); background: color-mix(in oklab, var(--fg-dim) 10%, transparent); }
  .rerun-btn { margin-left: 6px; font-size: 11px; padding: 1px 7px; border-radius: 5px; border: 1px solid var(--border-soft);
    background: var(--panel-strong); color: var(--fg-dim); cursor: pointer; }
  .empty { padding: 30px; text-align: center; color: var(--fg-faint); }
  tbody tr.row { cursor: pointer; }
  tbody tr.row:hover { background: var(--panel-strong); }
  tbody tr.detail-row { display: none; background: var(--bg); }
  tbody tr.detail-row.open { display: table-row; }
  .expand-block { padding: 10px 4px; font-size: 12px; color: var(--fg-dim); }
</style>
</head>
<body>
<main>
  <h1>Accountability · Peers</h1>
  <p class="caption" data-meta>loading…</p>
  <table>
    <thead><tr data-headrow></tr></thead>
    <tbody data-rows></tbody>
  </table>
  <div class="empty" data-empty hidden>No peers exchanged with yet.</div>
</main>
<script>window.__PEERS_PAYLOAD__ = @@PAYLOAD@@;</script>
<script>
(function () {
  "use strict";
  var COLUMNS = ["node","role","history","served","pair","verdicts","asked"];
  var LABELS = {node:"Node",role:"Role · exchanges",history:"History (theirs)",served:"Served (theirs)",
    pair:"Pair (me↔them)",verdicts:"Verdicts",asked:"Asked"};
  var TONE = @@CHIP_TONE@@;

  function cellText(cell) { return (cell && cell.text) ? cell.text : "no evidence recorded"; }

  function pill(cell) {
    var tone = TONE[(cell && cell.state) || ""] || "neutral";
    var span = document.createElement("span");
    span.className = "pill pill-" + tone;
    span.textContent = cellText(cell);
    return span;
  }

  var currentSort = null;
  function sortRows(rows, key) {
    if (/trust|score|rating/i.test(key)) { return rows; }
    return rows.slice().sort(function (a, b) {
      var av = a[key], bv = b[key];
      if (av && typeof av === "object") av = av.text || av.state || "";
      if (bv && typeof bv === "object") bv = bv.text || bv.state || "";
      if (av == null) return 1;
      if (bv == null) return -1;
      return av > bv ? 1 : av < bv ? -1 : 0;
    });
  }

  function buildExpandRow(row) {
    var tr = document.createElement("tr");
    tr.className = "detail-row";
    var td = document.createElement("td");
    td.colSpan = COLUMNS.length;
    var expand = row.expand || {};
    var ledger = (expand.pair_ledger || []).map(function (e) { return e.exchange_id + ": " + e.state; }).join(", ") || "no exchanges to reconcile";
    td.innerHTML = "<div class='expand-block'><strong>Pair ledger (my halves ↔ their halves):</strong> " + ledger +
      "<br><strong>Their card (Pane A layout):</strong> " + cellText(expand.their_card) + "</div>";
    tr.appendChild(td);
    return tr;
  }

  function renderRow(row, tbody) {
    var tr = document.createElement("tr");
    tr.className = "row";
    COLUMNS.forEach(function (col) {
      var td = document.createElement("td");
      var cell = row[col];
      td.appendChild(pill(cell));
      if (cell && cell.state === "contradicted") {
        var btn = document.createElement("button");
        btn.className = "rerun-btn";
        btn.type = "button";
        btn.textContent = "re-run one step";
        btn.dataset.adjudicationCapsuleId = cell.adjudication_capsule_id || "";
        td.appendChild(btn);
      }
      tr.appendChild(td);
    });
    var detailTr = buildExpandRow(row);
    tr.addEventListener("click", function () { detailTr.classList.toggle("open"); });
    tbody.appendChild(tr);
    tbody.appendChild(detailTr);
  }

  function renderAll() {
    var payload = window.__PEERS_PAYLOAD__;
    var meta = document.querySelector("[data-meta]");
    var tbody = document.querySelector("[data-rows]");
    var headRow = document.querySelector("[data-headrow]");
    COLUMNS.forEach(function (col) {
      var th = document.createElement("th");
      th.textContent = LABELS[col];
      th.addEventListener("click", function () {
        currentSort = col;
        tbody.innerHTML = "";
        sortRows(payload.rows, col).forEach(function (row) { renderRow(row, tbody); });
      });
      headRow.appendChild(th);
    });
    if (!payload || !payload.rows || !payload.rows.length) {
      meta.textContent = "no peers";
      document.querySelector("[data-empty]").hidden = false;
      return;
    }
    meta.textContent = payload.peer_count + " peer(s) · default sort: " + (payload.default_sort || "unsorted");
    payload.rows.forEach(function (row) { renderRow(row, tbody); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderAll);
  } else {
    renderAll();
  }
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _cmd_build(args: argparse.Namespace) -> int:
    try:
        from capsule_emit.ledger import read_ledger

        ledger_records = read_ledger(args.ledger)
    except Exception:
        ledger_records = _read_jsonl(Path(args.ledger))

    payload = build_peers_payload(
        ledger_records,
        node_id=args.node_id,
        log_id=args.log_id,
        checkpoint_lines=_read_jsonl(Path(args.checkpoints)) if args.checkpoints else [],
        since_size=args.since_size,
        source_log=args.source_log,
    )

    if args.html:
        text = render_peers_tab_html(payload)
    else:
        text = json.dumps(payload, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="peer-accountability-tab",
        description='Build Pane B ("Peers") -- one row per node exchanged with, computed from one node\'s own ledger.',
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build the payload and write it as JSON or HTML")
    build.add_argument("--node-id", required=True)
    build.add_argument("--log-id", required=True)
    build.add_argument("--ledger", required=True, metavar="PATH", help="the sealed capsule JSONL ledger (capsules.jsonl)")
    build.add_argument("--checkpoints", metavar="PATH", default=None, help="checkpoints.jsonl")
    build.add_argument("--since-size", type=int, default=0)
    build.add_argument("--source-log", default="sidecar", choices=["plugin", "sidecar"])
    build.add_argument("--html", action="store_true", help="render the self-contained HTML tab instead of JSON")
    build.add_argument("--out", metavar="PATH", default=None, help="write output here instead of stdout")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "build":
        return _cmd_build(args)
    parser = _build_parser()
    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
