#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-pane-c-exchange-subtab] Pane C "This exchange" -- the per-capsule
record view, kept as the existing leaf viewer (``capsule_mesh_viewer.py``'s
single-capsule fragment view + ``capsule_accountability_tab.py``'s rung
grading), extended to show the PAIR: the requester half and the provider
half of one exchange, side by side.

Composes verbs that already exist; re-derives none of their evidence:

  - the two orange/green verdict lines ("signed + anchored", "who asked")
    are ``capsule_mesh_viewer.build_verdict`` -- called here exactly as the
    existing leaf already calls it, per record, so nothing about how they
    render changes; this module adds no second implementation.
  - the rung grades (freshness / cross-party / runtime-binding) are
    ``capsule_accountability_tab``'s own ``freshness_grade`` /
    ``cross_party_grade`` / ``measurement_class_grade``, reused byte-for-
    byte.
  - the requester/provider role label is ``capsule_mesh_view.label_role``;
    the exchange correlator is ``serving_provenance()["exchange_id"]``
    ([b6a-requester-seal] / [mesh-b1-requestor-capsule-ledger]).
  - the identity chain is ``node_ownership``'s ``owner_provenance_block``,
    already carried at ``x-mesh-poc-v1.owner`` ([mesh-e6-identity-owner-cert]).

Two pieces are genuinely new here:

  - ``digest_match_grade`` -- compares each half's own ``effect.
    request_digest`` / ``effect.response_digest`` (the bytes BOTH halves
    independently observed at the wire for the SAME exchange -- sealed
    identically into both the requester's and the provider's own capsule)
    and grades the match honestly: ``verified`` only when both halves are
    present AND every digest agrees, ``failed`` the instant one disagrees,
    ``absent`` when only one half has been sealed (or supplied to this
    view) so far -- never a fabricated match from a lone half.
  - ``sequence_position`` -- a LOCAL ordinal: this half's position, by
    timestamp, among every record sharing its ``exchange_id`` in the
    record set this view was built from. This is deliberately NOT the
    cross-signed monotonic per-(node,counterparty) sequence number the
    omission-detection proposal (``mesh-history-proposal-2026-09-05.md``
    §1, unbuilt -- E9) would provide: that mechanism needs a new sealed
    capsule field and counterparty-held copies neither side has today.
    Labelled ``local_derivation`` / ``position_within_exchange_id_group``
    throughout, and every payload carries the caveat text, so a reader
    never mistakes this ordinal for that stronger, not-yet-built guarantee
    -- in particular, it does NOT detect an omitted or reordered record.

Two pieces are honest STUBS, pending upstream branches that are neither
merged nor re-implemented here (labelled ``pending``, never fabricated):

  - ``twin_adjudication_placeholder`` -- [mesh-e17a-offline-adjudicator]
    (capsule-emit-mesh PR #84, HELD).
  - ``witness_receipt_reverify_placeholder`` -- [mesh-e2-witness-checkpoints]
    (capsule-emit-mesh PR #87, HELD) upgrades the existing presence-only
    witness line (``build_verdict``'s line 2, unchanged and still real
    here) to an actually re-verified tristate. Until that lands, this
    module surfaces the upgrade itself as pending.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from capsule_accountability_tab import (
    STATE_ABSENT,
    STATE_FAILED,
    STATE_PRESENT_UNVERIFIED,
    STATE_VERIFIED,
    cross_party_grade,
    freshness_grade,
    measurement_class_grade,
)
from capsule_mesh_view import _poc_block, label_counterparty, label_role
from capsule_mesh_viewer import build_verdict, friendly_model_name, serving_provenance

try:  # same reader the sibling viewers use for their CLIs
    from capsule_emit.ledger import read_ledger
except Exception:  # pragma: no cover - only when capsule-emit isn't installed
    read_ledger = None  # type: ignore[assignment]

__all__ = [
    "EXCHANGE_ROLE_ASKED",
    "EXCHANGE_ROLE_SERVED",
    "FILTER_ALL",
    "FILTER_ASKED",
    "FILTER_ISSUES",
    "FILTER_SERVED",
    "PENDING",
    "SEQUENCE_CAPTURE_METHOD",
    "SEQUENCE_SOURCE",
    "TWIN_ADJUDICATION_PENDING_REASON",
    "WITNESS_REVERIFY_PENDING_REASON",
    "build_exchange_list_payload",
    "build_exchange_row",
    "build_exchange_view",
    "digest_match_grade",
    "exchange_id_for",
    "exchange_key_for",
    "filter_exchange_rows",
    "group_exchanges",
    "half_by_role",
    "identity_chain_for",
    "records_for_exchange",
    "render_exchange_list_html",
    "render_exchange_subtab_html",
    "sequence_position",
    "twin_adjudication_placeholder",
    "witness_receipt_reverify_placeholder",
    "worst_state",
]

#: A fifth state, distinct from the four-state discipline
#: (capsule_accountability_tab.py's STATE_* / TRUST-MODEL.md §10 Rule 1):
#: work an upstream branch will do, once merged -- never "absent" (which
#: means no claim was made) and never "failed" (a claim that did not hold
#: up). Exists so a reviewer can tell "this node made no claim" apart from
#: "the mechanism to check this claim isn't wired into this view yet".
PENDING = "pending"

SEQUENCE_SOURCE = "local_derivation"
SEQUENCE_CAPTURE_METHOD = "position_within_exchange_id_group_by_timestamp"
SEQUENCE_CAVEAT = (
    "position within this view's own copy of the exchange, sorted by timestamp -- NOT a "
    "cross-signed monotonic sequence number (that mechanism is the unbuilt omission-detection "
    "proposal, mesh-history-proposal-2026-09-05.md §1). An omitted or reordered record would "
    "not be caught by this number alone."
)

#: STALE REASON, SUPERSEDED (kept in this comment only so the history is
#: legible): both [mesh-e17a-offline-adjudicator] (PR #84) and
#: [mesh-e2-witness-checkpoints] (PR #87) are MERGED on `main` today.
#: `twin_adjudicator.py` and the re-verified witness path both exist -- the
#: real, current gap is that THIS per-exchange view does not yet call them
#: (a twin comparison needs the served weights + logprobs this view does
#: not have on hand; the witness re-verify needs the checkpoint chain this
#: view does not currently thread through). Still honestly `pending` for
#: THIS integration, just not for the reason the old text gave.
TWIN_ADJUDICATION_PENDING_REASON = (
    "twin_adjudicator.py exists on main (PR #84 merged) but is not wired into this per-exchange "
    "view yet -- a comparison needs the served weights/logprobs this view does not have on hand"
)
WITNESS_REVERIFY_PENDING_REASON = (
    "the presence-only witness line above is real and unchanged; RE-VERIFYING the receipt is "
    "possible now that [mesh-e2-witness-checkpoints] (PR #87) is merged, but this per-exchange "
    "view does not yet thread the checkpoint chain through to call it"
)

#: effect.* fields both halves of one exchange independently observe at the
#: wire and seal identically -- the pair's shared ground truth.
DIGEST_FIELDS = ("request_digest", "response_digest")


def _effect_block(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("effect") or {}


def exchange_id_for(record: dict[str, Any]) -> str | None:
    """The shared correlator both halves of one exchange record identically
    ([b6a-requester-seal]/[mesh-b1-requestor-capsule-ledger]), or ``None``/
    ``"unknown"`` when the record carries none."""
    return serving_provenance(record).get("exchange_id")


def records_for_exchange(records: list[dict[str, Any]], exchange_id: str | None) -> list[dict[str, Any]]:
    """Every record in *records* sharing *exchange_id*, sorted by timestamp
    (capsule_id as a stable tiebreak). Empty for a falsy/"unknown" id --
    "unknown" never groups records that merely failed to correlate."""
    if not exchange_id or exchange_id == "unknown":
        return []
    matches = [r for r in records if exchange_id_for(r) == exchange_id]
    matches.sort(key=lambda r: (r.get("timestamp") or "", r.get("capsule_id") or ""))
    return matches


def half_by_role(records_in_exchange: list[dict[str, Any]], source_log: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split *records_in_exchange* into (requester-half records, provider-
    half records) via ``capsule_mesh_view.label_role``. A well-formed
    exchange holds exactly one of each; retries on either side all ride in
    their list rather than being silently dropped."""
    requested: list[dict[str, Any]] = []
    served: list[dict[str, Any]] = []
    for record in records_in_exchange:
        role = label_role(record, source_log)
        if role == "requested":
            requested.append(record)
        elif role == "served":
            served.append(record)
    return requested, served


def sequence_position(records_in_exchange: list[dict[str, Any]], record: dict[str, Any]) -> dict[str, Any]:
    """This record's 1-based ordinal among *records_in_exchange* (already
    grouped + sorted by ``records_for_exchange``). See the module docstring
    for why this is a local ordinal, not a cross-signed sequence number."""
    capsule_id = record.get("capsule_id")
    for index, candidate in enumerate(records_in_exchange, start=1):
        if candidate.get("capsule_id") == capsule_id:
            return {
                "position": index,
                "of": len(records_in_exchange),
                "source": SEQUENCE_SOURCE,
                "capture_method": SEQUENCE_CAPTURE_METHOD,
                "caveat": SEQUENCE_CAVEAT,
            }
    raise ValueError("record is not a member of records_in_exchange")


def digest_match_grade(half_a: dict[str, Any] | None, half_b: dict[str, Any] | None) -> dict[str, Any]:
    """Compare ``effect.request_digest`` / ``effect.response_digest``
    between the two halves of one exchange.

    ``verified`` only when BOTH halves are present and every digest agrees;
    ``failed`` the instant one disagrees (even if the other field matches --
    one broken field makes the pair untrustworthy, never averaged away);
    ``absent`` when a counterparty half hasn't been sealed, or wasn't
    supplied to this view, yet -- never a fabricated match from a lone half.
    """
    if half_a is None or half_b is None:
        present = "one half" if (half_a is not None or half_b is not None) else "neither half"
        return {
            "state": STATE_ABSENT,
            "fields": {},
            "reason": f"only {present} of this exchange is present in this view",
        }
    fields: dict[str, Any] = {}
    any_failed = False
    any_absent = False
    for field in DIGEST_FIELDS:
        value_a = _effect_block(half_a).get(field)
        value_b = _effect_block(half_b).get(field)
        if value_a is None or value_b is None:
            fields[field] = {"state": STATE_ABSENT, "a": value_a, "b": value_b}
            any_absent = True
        elif value_a == value_b:
            fields[field] = {"state": STATE_VERIFIED, "a": value_a, "b": value_b}
        else:
            fields[field] = {"state": STATE_FAILED, "a": value_a, "b": value_b}
            any_failed = True
    if any_failed:
        overall = STATE_FAILED
    elif any_absent:
        overall = STATE_PRESENT_UNVERIFIED
    else:
        overall = STATE_VERIFIED
    return {"state": overall, "fields": fields}


def identity_chain_for(record: dict[str, Any]) -> dict[str, Any]:
    """The identity chain for one half -- node <- owner <- owner cert,
    exactly as ``node_ownership.owner_provenance_block`` already sealed it
    ([mesh-e6-identity-owner-cert]). Re-read here, never re-derived."""
    poc = _poc_block(record)
    sp = serving_provenance(record)
    owner = poc.get("owner") or {
        "owner_status": "absent",
        "owner_id": None,
        "identity_capsule_id": None,
        "owner_cert_ref": None,
        "identity_limitation": None,
    }
    return {
        "node_id": sp.get("served_by_node_id") or sp.get("requesting_party"),
        "owner_status": owner.get("owner_status"),
        "owner_id": owner.get("owner_id"),
        "identity_capsule_id": owner.get("identity_capsule_id"),
        "owner_cert_ref": owner.get("owner_cert_ref"),
        "identity_limitation": owner.get("identity_limitation"),
    }


def twin_adjudication_placeholder() -> dict[str, Any]:
    """[mesh-e17a-offline-adjudicator] STUB -- see module docstring."""
    return {"state": PENDING, "source": None, "capture_method": None, "reason": TWIN_ADJUDICATION_PENDING_REASON}


def witness_receipt_reverify_placeholder() -> dict[str, Any]:
    """[mesh-e2-witness-checkpoints] STUB -- see module docstring. Distinct
    from (and does not replace) the real presence-only witness line already
    carried in ``verdict``."""
    return {"state": PENDING, "source": None, "capture_method": None, "reason": WITNESS_REVERIFY_PENDING_REASON}


def build_exchange_view(
    record: dict[str, Any],
    *,
    all_records: list[dict[str, Any]],
    source_log: str,
    verify_ok: bool | None = None,
    has_witness_checkpoint: bool = False,
) -> dict[str, Any]:
    """Assemble the whole Pane C card for *record* ("this half"), including
    its pair. ``all_records`` is the record pool this view was built from --
    the counterparty half, when sealed, is found by grouping on
    ``exchange_id`` within it (never fetched over the network; this stays
    offline like every other viewer here)."""
    exchange_id = exchange_id_for(record)
    group = records_for_exchange(all_records, exchange_id)
    if not any(r.get("capsule_id") == record.get("capsule_id") for r in group):
        group = sorted(group + [record], key=lambda r: (r.get("timestamp") or "", r.get("capsule_id") or ""))

    requested, served = half_by_role(group, source_log)
    this_role = label_role(record, source_log)
    counterpart = (served if this_role == "requested" else requested)
    counterpart = next((r for r in counterpart if r.get("capsule_id") != record.get("capsule_id")), None)
    half_a, half_b = (record, counterpart) if this_role == "requested" else (counterpart, record)

    sp = serving_provenance(record)
    poc = _poc_block(record)
    verdict = build_verdict(
        sp,
        verify_ok=verify_ok,
        # build_verdict now takes the RE-VERIFIED witness_verdict, not mere presence
        # (mesh-e2 "re-verify the receipt, not just presence"). Pane C's witness re-verify is
        # still a PENDING placeholder (witness_receipt_reverify below), so there is no re-verified
        # verdict to assert here yet -- None is the honest value; presence alone is never rendered
        # as "witnessed". has_witness_checkpoint stays plumbed for that future wiring.
        witness_verdict=None,
        counterparty=label_counterparty(record),
    )

    return {
        "capsule_id": record.get("capsule_id"),
        "exchange_id": exchange_id,
        "role": this_role,
        "model_claimed": friendly_model_name(sp),
        "verdict": verdict,
        "sequence": sequence_position(group, record),
        "pair": {
            "requester_half_capsule_id": (requested[0].get("capsule_id") if requested else None),
            "provider_half_capsule_id": (served[0].get("capsule_id") if served else None),
            "digest_match": digest_match_grade(half_a, half_b),
        },
        "identity_chain": {
            "this_half": identity_chain_for(record),
            "counterpart": identity_chain_for(counterpart) if counterpart is not None else None,
        },
        "twin_adjudication": twin_adjudication_placeholder(),
        "witness_receipt_reverify": witness_receipt_reverify_placeholder(),
        "rungs": {
            "freshness": freshness_grade(poc.get("client_nonce_source")),
            "cross_party": cross_party_grade(poc, capsule_id=record.get("capsule_id")),
            "runtime_binding": measurement_class_grade(poc),
        },
    }


# ---------------------------------------------------------------------------
# Regroup by exchange (mesh-accountability-panes-v2-2026-09-05.md §3/§4):
# one row per exchange_id (fallback: request_digest), a role tag
# (SERVED/ASKED), and the two halves as two COLUMNS inside the row --
# double-entry as one line, never two rows. ``received()`` foreign capsules
# (this node's own copy of a counterparty's half -- passed here via
# `counterparty_records` since no live receive-into-ledger mechanism is
# wired yet) render in the `theirs` column of their exchange, never as
# their own row.
# ---------------------------------------------------------------------------

EXCHANGE_ROLE_SERVED = "SERVED"
EXCHANGE_ROLE_ASKED = "ASKED"

FILTER_ALL = "all"
FILTER_SERVED = "served"
FILTER_ASKED = "asked"
FILTER_ISSUES = "issues"

#: The worst-line fold rule ([mesh-exchange-card-mismatch-bug]'s principle,
#: reapplied here for the list header -- that fix lives in
#: mesh_viewer_static/mesh_verify.js for a different page; this is an
#: independent implementation of the same principle for this module's own
#: list view). `pending` is intentionally rank 0: an upstream branch not yet
#: wired into this view is a view limitation, not a failed check, and must
#: never force a red/amber header on its own.
#: Rank tiers mirror this codebase's own established tone conventions
#: (capsule_accountability_tab.py's client-side TONE map): unilateral_fallback
#: is neutral/absent-tier here, same as everywhere else it renders -- it is
#: the honest default absent cross-party evidence produces, not a warning.
_STATE_RANK = {
    STATE_FAILED: 3,
    "bad": 3,
    STATE_PRESENT_UNVERIFIED: 2,
    "warn": 2,
    "acknowledged_receipt": 2,
    "self_measured": 2,
    "os_measured": 2,
    STATE_ABSENT: 1,
    "unilateral_fallback": 1,
    PENDING: 0,
    STATE_VERIFIED: 0,
    "ok": 0,
    "full_bilateral": 0,
    "tee_measured": 0,
}


def worst_state(view: dict[str, Any]) -> str:
    """The row header state = the worst line among this exchange's checks
    ([mesh-exchange-card-mismatch-bug]'s rule): any real failure (a digest
    mismatch, a failed verdict line, a failed rung) forces
    ``STATE_FAILED`` regardless of what any other line says; any
    unverified/warn-shaped line (with nothing worse) forces
    ``STATE_PRESENT_UNVERIFIED``; only when every line is either verified/ok
    or honestly absent/pending does the header read ``STATE_VERIFIED``.
    Never rounds up.

    ``build_verdict``'s line 2 (the witness line) always reads ``warn`` today
    because this view's witness re-verify is still the
    ``witness_receipt_reverify`` PENDING placeholder -- doc §3's own color
    rule says that exact case ("witness receipt isn't in this bundle") is
    grey (a view limitation), not amber (a real limitation of the record).
    So line 2 is excluded from the fold ONLY while that placeholder is
    pending; a real ``bad`` witness verdict (a receipt that fails to
    verify), once wired, still forces ``STATE_FAILED`` like any other line.
    """
    candidates = [view["pair"]["digest_match"]["state"]]
    witness_pending = view["witness_receipt_reverify"]["state"] == PENDING
    for index, line in enumerate(view["verdict"]):
        if index == 1 and witness_pending and line["mark"] != "bad":
            continue
        candidates.append(line["mark"])
    for key, rung in view["rungs"].items():
        candidates.append(rung.get("rung") if key == "cross_party" else rung.get("state"))
    worst = max((_STATE_RANK.get(c, 1) for c in candidates), default=0)
    if worst >= 3:
        return STATE_FAILED
    if worst >= 2:
        return STATE_PRESENT_UNVERIFIED
    return STATE_VERIFIED


def exchange_key_for(record: dict[str, Any]) -> str | None:
    """The exchange correlator, with the doc's fallback: `exchange_id`, or
    (when absent/"unknown") `effect.request_digest` -- never both mixed
    silently, and `None` when neither is present (nothing to group this
    record by)."""
    eid = exchange_id_for(record)
    if eid and eid != "unknown":
        return eid
    digest = (record.get("effect") or {}).get("request_digest")
    return f"digest:{digest}" if digest else None


def build_exchange_row(
    exchange_key: str,
    mine_records: list[dict[str, Any]],
    theirs_records: list[dict[str, Any]],
    group: list[dict[str, Any]],
    source_log: str,
) -> dict[str, Any]:
    """One list row: role tag, `mine`/`theirs` as two columns, header state =
    the worst line among the checks. A row with only one half says so in the
    empty column (`unilateral`), never blank."""
    mine = mine_records[0] if mine_records else None
    theirs = theirs_records[0] if theirs_records else None
    anchor = mine or theirs
    view = build_exchange_view(anchor, all_records=group, source_log=source_log) if anchor is not None else None

    if mine is not None:
        # `mine`'s role field already reflects THIS node's own perspective.
        role_tag = EXCHANGE_ROLE_SERVED if label_role(mine, source_log) == "served" else EXCHANGE_ROLE_ASKED
    elif theirs is not None:
        # No half of mine sealed -- `theirs`' role is from THEIR perspective,
        # so this node's role tag is the inverse: they served means I asked.
        role_tag = EXCHANGE_ROLE_ASKED if label_role(theirs, source_log) == "served" else EXCHANGE_ROLE_SERVED
    else:
        role_tag = EXCHANGE_ROLE_ASKED

    def _side(record: dict[str, Any] | None, *, side: str) -> dict[str, Any]:
        if record is not None:
            return {"state": STATE_PRESENT_UNVERIFIED, "capsule_id": record.get("capsule_id"), "role": label_role(record, source_log)}
        text = "none (unilateral)" if side == "theirs" else "none — received without a commitment"
        return {"state": STATE_ABSENT, "text": text, "capsule_id": None}

    timestamps = [r.get("timestamp") for r in (mine, theirs) if r and r.get("timestamp")]
    return {
        "exchange_key": exchange_key,
        "role_tag": role_tag,
        "header_state": worst_state(view) if view is not None else STATE_ABSENT,
        "mine": _side(mine, side="mine"),
        "theirs": _side(theirs, side="theirs"),
        "unilateral": mine is None or theirs is None,
        "timestamp": max(timestamps, default=None),
        "view": view,
    }


def group_exchanges(
    my_records: list[dict[str, Any]],
    *,
    counterparty_records: list[dict[str, Any]] | None = None,
    source_log: str = "sidecar",
) -> list[dict[str, Any]]:
    """Group every record sharing an exchange key into one row each --
    `my_records` (this node's own ledger) anchors a row's role tag;
    `counterparty_records` (a received foreign half, when this view has one)
    fills the `theirs` column of the SAME row, never a row of its own."""
    counterparty_records = counterparty_records or []
    my_ids = {r.get("capsule_id") for r in my_records if r.get("capsule_id")}
    all_records = my_records + counterparty_records

    keys: list[str] = []
    seen: set[str] = set()
    for record in all_records:
        key = exchange_key_for(record)
        if key is not None and key not in seen:
            seen.add(key)
            keys.append(key)

    rows = []
    for key in keys:
        group = [r for r in all_records if exchange_key_for(r) == key]
        mine_records = [r for r in group if r.get("capsule_id") in my_ids]
        theirs_records = [r for r in group if r.get("capsule_id") not in my_ids]
        rows.append(build_exchange_row(key, mine_records, theirs_records, group, source_log))

    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return rows


def filter_exchange_rows(rows: list[dict[str, Any]], filter_name: str) -> list[dict[str, Any]]:
    """The four filter chips: All · Served · Asked · Issues. `Issues` is any
    row whose header is NOT `STATE_VERIFIED` -- an honest `absent`/`pending`
    row (nothing to check yet) is not an issue, only a real warn/failed is."""
    if filter_name == FILTER_ALL:
        return rows
    if filter_name == FILTER_SERVED:
        return [r for r in rows if r["role_tag"] == EXCHANGE_ROLE_SERVED]
    if filter_name == FILTER_ASKED:
        return [r for r in rows if r["role_tag"] == EXCHANGE_ROLE_ASKED]
    if filter_name == FILTER_ISSUES:
        return [r for r in rows if r["header_state"] in (STATE_FAILED, STATE_PRESENT_UNVERIFIED)]
    raise ValueError(f"unknown filter {filter_name!r}")


def build_exchange_list_payload(
    my_records: list[dict[str, Any]],
    *,
    counterparty_records: list[dict[str, Any]] | None = None,
    source_log: str = "sidecar",
) -> dict[str, Any]:
    """Assemble the whole Pane C list payload: rows grouped by exchange,
    default-sorted most recent first."""
    rows = group_exchanges(my_records, counterparty_records=counterparty_records, source_log=source_log)
    return {"row_count": len(rows), "default_sort": "timestamp", "filters": [FILTER_ALL, FILTER_SERVED, FILTER_ASKED, FILTER_ISSUES], "rows": rows}


# ---------------------------------------------------------------------------
# Presentation -- a small self-contained HTML fragment styled to match
# capsule_accountability_tab.py's pill vocabulary (state -> tone), plain
# server-rendered (this panel's fields are already Python-side graded, so --
# unlike the accountability tab's capsule_id recompute -- there is no
# in-browser check to wire up here).
# ---------------------------------------------------------------------------

_TONE_BY_STATE = {
    STATE_ABSENT: "neutral",
    "unilateral_fallback": "neutral",
    STATE_PRESENT_UNVERIFIED: "warn",
    "acknowledged_receipt": "warn",
    "self_measured": "warn",
    "os_measured": "warn",
    PENDING: "warn",
    STATE_VERIFIED: "good",
    "full_bilateral": "good",
    "tee_measured": "good",
    STATE_FAILED: "bad",
}


def _esc(value: Any) -> str:
    return "" if value is None else str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pill(state: str, text: str | None = None) -> str:
    tone = _TONE_BY_STATE.get(state, "neutral")
    return f'<span class="pill pill-{tone}">{_esc(text or state)}</span>'


def render_exchange_subtab_html(view: dict[str, Any]) -> str:
    """Render one Pane C "This exchange" card as a self-contained HTML
    fragment (no fetch, no external state) -- meant to be embedded as the
    subtab/drill-down leaf under the Accountability tab."""
    verdict_lines = "".join(
        f'<div class="verdict-line verdict-{line["mark"]}">{_esc(line["text"])}</div>' for line in view["verdict"]
    )

    digest = view["pair"]["digest_match"]
    digest_rows = "".join(
        f"<tr><td>{_esc(field)}</td><td class='mono'>{_esc(info.get('a'))}</td>"
        f"<td class='mono'>{_esc(info.get('b'))}</td><td>{_pill(info['state'])}</td></tr>"
        for field, info in digest["fields"].items()
    )
    if not digest_rows:
        digest_rows = f"<tr><td colspan='4'>{_esc(digest.get('reason', digest['state']))}</td></tr>"

    seq = view["sequence"]
    identity_this = view["identity_chain"]["this_half"]
    identity_other = view["identity_chain"]["counterpart"]

    def identity_block(label: str, chain: dict[str, Any] | None) -> str:
        if chain is None:
            return f'<div class="identity-col"><div class="label">{_esc(label)}</div>{_pill(STATE_ABSENT, "no counterparty half yet")}</div>'
        owner_cert = "cited" if chain.get("owner_cert_ref") else "not cited"
        return (
            f'<div class="identity-col"><div class="label">{_esc(label)}</div>'
            f"<div class='mono'>node: {_esc(chain.get('node_id') or '—')}</div>"
            f"<div>owner: {_esc(chain.get('owner_id') or '—')} ({_esc(chain.get('owner_status'))})</div>"
            f"<div>owner cert: {_esc(owner_cert)}</div></div>"
        )

    return f"""<section class="exchange-card" data-capsule-id="{_esc(view['capsule_id'])}">
  <header>
    <h2>This exchange — {_esc(view['model_claimed'])}</h2>
    <p class="mono">exchange_id: {_esc(view['exchange_id'])} · this half: {_esc(view['role'])} · capsule_id: {_esc(view['capsule_id'])}</p>
    <p>sequence: {seq['position']} of {seq['of']} <span class="caveat">({_esc(seq['caveat'])})</span></p>
  </header>
  <div class="verdict">{verdict_lines}</div>
  <section class="pair">
    <h3>Requester ↔ provider half {_pill(digest['state'])}</h3>
    <table>
      <thead><tr><th>field</th><th>requester half</th><th>provider half</th><th>match</th></tr></thead>
      <tbody>{digest_rows}</tbody>
    </table>
  </section>
  <section class="identity-chain">
    <h3>Identity chain</h3>
    <div class="identity-row">
      {identity_block("This half", identity_this)}
      {identity_block("Counterpart", identity_other)}
    </div>
  </section>
  <section class="pending">
    <h3>Twin &amp; adjudication {_pill(view['twin_adjudication']['state'])}</h3>
    <p>{_esc(view['twin_adjudication']['reason'])}</p>
    <h3>Witness receipt re-verify {_pill(view['witness_receipt_reverify']['state'])}</h3>
    <p>{_esc(view['witness_receipt_reverify']['reason'])}</p>
  </section>
</section>"""


_LIST_STYLE = """
  :root {
    --bg: oklch(0.17 0.015 250); --panel: oklch(0.2 0.018 250); --panel-strong: oklch(0.23 0.02 250);
    --border: oklch(0.3 0.02 250 / 0.9); --border-soft: oklch(0.3 0.02 250 / 0.45);
    --fg: oklch(0.96 0.005 80); --fg-dim: oklch(0.78 0.01 80); --fg-faint: oklch(0.6 0.01 80);
    --good: oklch(0.78 0.14 150); --warn: oklch(0.8 0.12 80); --bad: oklch(0.7 0.18 25);
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 13.5px/1.55 "Inter Tight","Inter",system-ui,sans-serif; }
  main { max-width: 980px; margin: 0 auto; padding: 20px 16px 40px; }
  h1 { font-size: 16.5px; margin: 0 0 4px; }
  p.caption { color: var(--fg-dim); font-size: 12px; margin: 0 0 14px; }
  .filters { display: flex; gap: 6px; margin-bottom: 14px; }
  .filter-chip { font-size: 12px; padding: 4px 12px; border-radius: 999px; border: 1px solid var(--border-soft);
    background: var(--panel-strong); color: var(--fg-dim); cursor: pointer; }
  .filter-chip.active { color: var(--fg); border-color: var(--fg-dim); }
  details.exchange-row { border: 1px solid var(--border); border-radius: 8px; background: var(--panel); margin-bottom: 8px; padding: 8px 12px; }
  details.exchange-row summary { cursor: pointer; display: flex; align-items: center; gap: 10px; list-style: none; }
  details.exchange-row summary::-webkit-details-marker { display: none; }
  .role-tag { font-size: 11px; font-weight: 700; letter-spacing: 0.05em; padding: 1px 8px; border-radius: 5px; background: var(--panel-strong); color: var(--fg-dim); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fg-faint); font-size: 12px; }
  .halves { display: flex; gap: 24px; padding: 8px 0; font-size: 12.5px; color: var(--fg-dim); }
  .pill { display: inline-flex; padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600; margin-left: auto; }
  .pill-good { color: var(--good); background: color-mix(in oklab, var(--good) 14%, transparent); }
  .pill-warn { color: var(--warn); background: color-mix(in oklab, var(--warn) 14%, transparent); }
  .pill-bad { color: var(--bad); background: color-mix(in oklab, var(--bad) 14%, transparent); }
  .pill-neutral { color: var(--fg-dim); background: color-mix(in oklab, var(--fg-dim) 10%, transparent); }
  .drawer { border-top: 1px solid var(--border-soft); margin-top: 8px; padding-top: 8px; }
"""


def render_exchange_list_html(payload: dict[str, Any]) -> str:
    """Pane C's list view: one `<details>` row per exchange, role-tagged,
    `mine`/`theirs` as two columns, filter chips (All/Served/Asked/Issues),
    the header pill = `worst_state`. The drawer (opened by clicking the row,
    the same component reached from Logs' `CAPSULE` line or the answer-
    footer `receipt` link) is `render_exchange_subtab_html`'s unchanged
    fragment for that exchange's anchor record -- "Show the security
    checks" and everything under it keep their existing logic verbatim."""
    rows_html = []
    for row in payload["rows"]:
        drawer = render_exchange_subtab_html(row["view"]) if row["view"] is not None else "<p>no view available for this exchange</p>"
        mine, theirs = row["mine"], row["theirs"]
        mine_text = f"capsule_id: {_esc(mine['capsule_id'])}" if mine.get("capsule_id") else _esc(mine.get("text"))
        theirs_text = f"capsule_id: {_esc(theirs['capsule_id'])}" if theirs.get("capsule_id") else _esc(theirs.get("text"))
        rows_html.append(
            f"""<details class="exchange-row" data-role="{_esc(row['role_tag'])}" data-state="{_esc(row['header_state'])}">
  <summary>
    <span class="role-tag">{_esc(row['role_tag'])}</span>
    <span class="mono">{_esc(row['exchange_key'])} · {_esc(row['timestamp'])}</span>
    {_pill(row['header_state'])}
  </summary>
  <div class="halves">
    <div>mine: {mine_text}</div>
    <div>theirs: {theirs_text}</div>
  </div>
  <div class="drawer">{drawer}</div>
</details>"""
        )
    filters_html = "".join(f'<button class="filter-chip" data-filter="{_esc(f)}">{_esc(f.capitalize())}</button>' for f in payload["filters"])
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mesh-llm · Accountability · This exchange</title>
<style>{_LIST_STYLE}</style>
</head>
<body>
<main>
  <h1>Accountability · This exchange</h1>
  <p class="caption">{payload['row_count']} exchange(s) · default sort: {_esc(payload['default_sort'])}</p>
  <div class="filters" data-filters>{filters_html}</div>
  <div class="rows" data-rows>{"".join(rows_html)}</div>
</main>
<script>
(function () {{
  "use strict";
  var chips = document.querySelectorAll("[data-filters] .filter-chip");
  var rows = document.querySelectorAll("[data-rows] .exchange-row");
  function apply(filterName) {{
    chips.forEach(function (c) {{ c.classList.toggle("active", c.dataset.filter === filterName); }});
    rows.forEach(function (row) {{
      var show = filterName === "all"
        || (filterName === "issues" ? row.dataset.state !== "verified" : row.dataset.role.toLowerCase() === filterName);
      row.style.display = show ? "" : "none";
    }});
  }}
  chips.forEach(function (chip) {{ chip.addEventListener("click", function () {{ apply(chip.dataset.filter); }}); }});
  apply("all");
}})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _read_records(path: str) -> list[dict[str, Any]]:
    if read_ledger is not None:
        try:
            return read_ledger(path)
        except Exception:
            pass
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _read_first_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    first = text.splitlines()[0] if "\n" in text else text
    return json.loads(first)


def _cmd_html(args: argparse.Namespace) -> int:
    records = _read_records(args.ledger)
    if args.counterparty_ledger:
        records = records + _read_records(args.counterparty_ledger)
    record = next((r for r in records if r.get("capsule_id") == args.capsule_id), None)
    if record is None:
        print(f"capsule-exchange-tab: capsule_id {args.capsule_id!r} not found in supplied ledger(s)", file=sys.stderr)
        return 1
    witness = _read_first_json(args.witness) if args.witness else None
    view = build_exchange_view(
        record,
        all_records=records,
        source_log=args.source_log,
        has_witness_checkpoint=witness is not None,
    )
    html = render_exchange_subtab_html(view)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"exchange subtab: capsule_id {args.capsule_id} -> {args.out}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    my_records = _read_records(args.ledger)
    counterparty_records = _read_records(args.counterparty_ledger) if args.counterparty_ledger else None
    payload = build_exchange_list_payload(my_records, counterparty_records=counterparty_records, source_log=args.source_log)
    html = render_exchange_list_html(payload)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"exchange list: {payload['row_count']} exchange(s) -> {args.out}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule-exchange-tab",
        description='Render Pane C ("This exchange") -- regrouped by exchange (list), or the '
        "requester/provider pair drill-down for one capsule (single).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    single = sub.add_parser("single", help="render one exchange's drill-down card")
    single.add_argument("--ledger", required=True, metavar="PATH", help="this node's mesh capsule JSONL ledger")
    single.add_argument(
        "--counterparty-ledger",
        metavar="PATH",
        default=None,
        help="optional second ledger (the counterparty's) to find the other half of the pair in",
    )
    single.add_argument("--capsule-id", required=True, help="capsule_id of the half to drill into")
    single.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    single.add_argument("--witness", metavar="PATH", default=None, help="optional COSE checkpoint receipt (json/jsonl)")
    single.add_argument("--source-log", default="sidecar", choices=["plugin", "sidecar"])

    list_cmd = sub.add_parser("list", help="render the exchange list, regrouped by exchange_id/request_digest")
    list_cmd.add_argument("--ledger", required=True, metavar="PATH", help="this node's mesh capsule JSONL ledger")
    list_cmd.add_argument(
        "--counterparty-ledger",
        metavar="PATH",
        default=None,
        help="optional second ledger -- received foreign halves render in the theirs column",
    )
    list_cmd.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    list_cmd.add_argument("--source-log", default="sidecar", choices=["plugin", "sidecar"])

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "single":
        return _cmd_html(args)
    if args.command == "list":
        return _cmd_list(args)
    parser = _build_parser()
    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
