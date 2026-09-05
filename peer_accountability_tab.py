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
  - **history / continuity / witnessed**: ``history_card.build_history_card()``
    over THIS node's own checkpoint chain. Computed ONCE per payload and
    shown on every peer row: a fork or gap in this node's own chain is not
    a per-peer fact, it degrades accountability toward every peer equally,
    so hiding it on some rows would be the silent-green failure TRUST-
    MODEL.md's three-state discipline exists to prevent.
  - **evidence-requests**: honestly ``absent`` until
    [mesh-e14-evidence-responder] is wired (see ``EVIDENCE_REQUEST_ABSENT_REASON``);
    the cell function itself is real and tested against synthetic
    request/response pairs so the refusal/absence rendering is exercised
    now, not left for whenever the responder lands.
  - **adjudications / pair**: STUB cells, labeled ``pending`` -- placeholders
    for [mesh-e17a-offline-adjudicator] (PR #84, held) and E9
    (sequence-continuity, held) respectively. Neither module exists on
    ``main`` yet; nothing here imports them.

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

from capsule_accountability_tab import cross_party_grade
from capsule_mesh_view import _poc_block, label_counterparty
from history_card import HistoryCard, build_history_card

__all__ = [
    "CELL_ABSENT",
    "CELL_CONTRADICTED",
    "CELL_FAILED",
    "CELL_PENDING",
    "CELL_PRESENT",
    "CELL_REFUSED",
    "CELL_UNILATERAL",
    "CELL_VERIFIED",
    "EVIDENCE_REQUEST_ABSENT_REASON",
    "FORBIDDEN_RATING_KEYS",
    "FORBIDDEN_SORT_KEYS",
    "RatingFieldError",
    "UNKNOWN_PEER",
    "adjudications_cell",
    "assert_no_rating_fields",
    "build_peer_row",
    "build_peers_payload",
    "continuity_cell",
    "evidence_request_cell",
    "group_by_peer",
    "history_cell",
    "node_cell",
    "pair_cell",
    "render_cell_text",
    "render_peers_tab_html",
    "rung_cell",
    "sort_peer_rows",
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

#: [mesh-e14-evidence-responder] is not merged yet (capsule-emit-mesh PR #83
#: CI red, pending upstream capsule-emit PR #148) -- cited here, not
#: re-litigated, so this stays a single place to update once it lands.
EVIDENCE_REQUEST_ABSENT_REASON = (
    "no evidence-request log is wired to this peer yet: [mesh-e14-evidence-responder] "
    "is not merged (capsule-emit-mesh #83 CI red pending capsule-emit #148)"
)

#: pending-column reasons, named so a future coder wiring the real module
#: only has to delete these two constants and their call sites.
ADJUDICATIONS_PENDING_REASON = "pending twin_adjudicator (E17a, PR #84 held)"
PAIR_PENDING_REASON = "pending sequence-continuity (E9, held)"

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

#: "No sort by trust — sort by any property." A sort key containing any of
#: these substrings is refused outright, never silently ignored.
FORBIDDEN_SORT_KEYS = ("trust", "score", "rating")

_BREAK_MMR_SIZE_RE = re.compile(r"broken at mmr_size=(\d+)")


class RatingFieldError(ValueError):
    """Raised when a payload would carry a field that could hold a rating."""


def assert_no_rating_fields(value: Any, *, _path: str = "$") -> None:
    """Walk *value* recursively and raise `RatingFieldError` on the first key
    whose name contains one of `FORBIDDEN_RATING_KEYS`. Recursive: a rating
    buried three dicts deep must be caught exactly like a top-level one."""
    if isinstance(value, dict):
        for key, sub in value.items():
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


def evidence_request_cell(evidence_requests: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Evidence-requests column.

    ``evidence_requests``, when supplied, is a list of already-answered
    ``{request, response}`` pairs for THIS peer, ``response`` shaped
    ``{status: "refused"|"no_answer"|"ok", ...}`` (the evidence-request
    carrier's own shape, per [mesh-e14-evidence-responder] -- cited by
    shape, not imported; that module is not merged). ``None``/``[]`` is the
    honest, and today ONLY reachable, state: no responder is wired yet.
    """
    if not evidence_requests:
        return {"state": CELL_ABSENT, "text": EVIDENCE_REQUEST_ABSENT_REASON, "count": 0}

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


def adjudications_cell() -> dict[str, Any]:
    """Adjudications column -- STUB. Placeholder for
    [mesh-e17a-offline-adjudicator] (`twin_adjudicator`, PR #84, held).
    ``twin_adjudicator.py`` does not exist on `main`; nothing here imports
    it."""
    return {"state": CELL_PENDING, "text": ADJUDICATIONS_PENDING_REASON}


def pair_cell() -> dict[str, Any]:
    """Pair (me<->them) column -- STUB. Placeholder for E9
    (sequence-continuity, held)."""
    return {"state": CELL_PENDING, "text": PAIR_PENDING_REASON}


# ---------------------------------------------------------------------------
# Row / payload assembly
# ---------------------------------------------------------------------------


def build_peer_row(
    peer_id: str,
    records: list[dict[str, Any]],
    *,
    history_card: HistoryCard,
    checkpoint_lines: list[dict[str, Any]],
    evidence_requests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """One Pane B row for *peer_id*."""
    timestamps = [r.get("timestamp") for r in records if r.get("timestamp")]
    return {
        "peer_id": peer_id if peer_id != UNKNOWN_PEER else None,
        "node": node_cell(peer_id, records),
        "rung": rung_cell(records),
        "history": history_cell(history_card),
        "continuity": continuity_cell(history_card, checkpoint_lines),
        "witnessed": witnessed_cell(history_card),
        "evidence_requests": evidence_request_cell(evidence_requests),
        "adjudications": adjudications_cell(),
        "pair": pair_cell(),
        "exchange_count": len(records),
        "first_seen": min(timestamps, default=None),
        "last_seen": max(timestamps, default=None),
    }


def build_peers_payload(
    records: list[dict[str, Any]],
    *,
    node_id: str,
    log_id: str,
    checkpoint_lines: list[dict[str, Any]] | None = None,
    since_size: int = 0,
    evidence_requests_by_peer: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Assemble the whole Pane B payload: one row per peer this node has
    exchanged capsules with, per the module docstring's history/continuity/
    witnessed sharing rationale.

    Raises `RatingFieldError` (never returns a payload that could) if any
    composed cell smuggled in a field that looks like a rating.
    """
    checkpoint_lines = checkpoint_lines or []
    card = build_history_card(node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size)
    groups = group_by_peer(records)
    rows = [
        build_peer_row(
            peer_id,
            peer_records,
            history_card=card,
            checkpoint_lines=checkpoint_lines,
            evidence_requests=(evidence_requests_by_peer or {}).get(peer_id),
        )
        for peer_id, peer_records in groups.items()
    ]
    payload = {"node_id": node_id, "peer_count": len(rows), "rows": rows}
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
    return _HTML_SHELL.replace("@@PAYLOAD@@", payload_json)


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
  var COLUMNS = ["node","rung","history","continuity","witnessed","pair","adjudications","evidence_requests"];
  var LABELS = {node:"Node",rung:"Rung",history:"History",continuity:"Continuity",witnessed:"Witnessed",
    pair:"Pair (me↔them)",adjudications:"Adjudications",evidence_requests:"Evidence-requests"};
  var TONE = {absent:"neutral", present:"good", verified:"good", unilateral:"warn", pending:"neutral",
    failed:"bad", refused:"bad", contradicted:"bad"};

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

  function renderRow(row, tbody) {
    var tr = document.createElement("tr");
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
    tbody.appendChild(tr);
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
    meta.textContent = payload.peer_count + " peer(s)";
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
