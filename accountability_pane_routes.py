#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-live-tab-pane-proxy] L1 -- the JSON this repo's sidecar serves at
``GET /accountability/pane-a``, ``/pane-b``, ``/pane-c?exchange_id=`` for the
fork tab's Ledger panes (Q2 ruling: the proxy lives in the SIDECAR's own
HTTP surface; the tab calls it directly, never through a mesh-llm host
route). Every payload here is byte-for-byte what the existing Python panes
already build and render as static HTML
(``capsule_accountability_tab.build_tab_payload`` / Pane A,
``peer_accountability_tab.build_peers_payload`` / Pane B,
``capsule_exchange_tab.build_exchange_list_payload``/``build_exchange_view``
/ Pane C) -- this module derives nothing a second time, it only reads this
node's own ledger fresh on every call (same "never cache" discipline as
``evidence_server._merged_evidence_view``/``capsule_sidecar._handle_finder``)
and hands the records to those existing builders.

Local-only tranche (§7 Q1/Q2/Q3 rulings, ``_work/mesh-ledger-tab-design-
2026-09-07.md``): own ledger, own join-card/history, verified peer
artifacts already on disk -- no on-demand peer fetch here (peer tranche is
E9/E10, deferred pending Steven's Q4 ruling).

Pane A and Pane B are whole-node summaries (one card; a handful of peer
rows) -- both read the WHOLE ledger every call, same as the CLI always has,
because their aggregate counts (checkpoint/adjudication/peer tallies) would
silently undercount against a capped read. Pane C's list mode is the one
surface that can grow unbounded over a long-running node's lifetime, so it
is the one that takes L0's ``limit``/``after_seq`` cap+paging
(``ledger_store_backend.read_capsules_page``) -- Pane C's drill-down
(``exchange_id`` supplied) still reads the whole ledger to find that
exchange's records, same reasoning ``ledger_finder.find_capsules`` already
documents for why an id lookup can't rely on a capped window.

``assert_no_rating_fields`` runs on every payload this module returns,
regardless of whether the builder it called already runs its own (Pane
A's card and Pane B's payload do; Pane C's do not) -- build item 3's own
words: "runs on every pane response before it leaves the sidecar," a
sidecar-boundary guarantee that must not depend on which builder happened
to remember its own internal check.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import capsule_accountability_tab
import capsule_exchange_tab
import ledger_store_backend
import peer_accountability_tab
from self_accountability import assert_no_rating_fields

if TYPE_CHECKING:
    from capsule_sidecar import NodeState

__all__ = [
    "build_pane_a_json",
    "build_pane_b_json",
    "build_pane_c_json",
]

#: Pane C's list mode, uncapped, could walk an unbounded ledger on every
#: request; this is the safety default when a caller's query string omits
#: ``limit`` -- generous enough that a fresh/demo node never notices it.
DEFAULT_PANE_C_PAGE_LIMIT = 200


def _log_id_for(state: "NodeState") -> str:
    """This node's own log identity for the history/checkpoint blocks --
    ``state.checkpoint.log_id`` when checkpointing is configured (it may
    override the plain ``node_id``, e.g. a shared-plugin log_id suffix),
    else ``state.node_id`` -- the same default ``NodeState.__post_init__``
    itself opens the ledger store with (``open_ledger_store(self.ledger_dir,
    log_id=self.node_id)``)."""
    checkpoint = getattr(state, "checkpoint", None)
    if checkpoint is not None:
        return checkpoint.log_id
    return state.node_id


def _read_jsonl_if_present(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line:
            out.append(json.loads(line))
    return out


def build_pane_a_json(state: "NodeState") -> dict[str, Any]:
    """Pane A ("My node") -- ``capsule_accountability_tab.build_tab_payload``
    over this node's own ledger, fresh every call. No ``--witness`` receipt
    file exists on a live node by default, same as the CLI's own optional
    ``--witness`` -- omitted here, not fabricated."""
    records, _archived_segments = ledger_store_backend.read_all_capsules(state.ledger_dir)
    log_id = _log_id_for(state)
    payload = capsule_accountability_tab.build_tab_payload(
        records,
        ledger_dir=state.ledger_dir,
        operator=state.operator,
        node_id=state.node_id,
        log_id=log_id,
        checkpoint_lines=_read_jsonl_if_present(state.ledger_dir / "checkpoints.jsonl"),
        native_log_entries=_read_jsonl_if_present(state.ledger_dir / "native_log.jsonl"),
    )
    assert_no_rating_fields(payload)
    return payload


def build_pane_b_json(state: "NodeState") -> dict[str, Any]:
    """Pane B ("Peers") -- ``peer_accountability_tab.build_peers_payload``
    over this node's own ledger, fresh every call."""
    records, _archived_segments = ledger_store_backend.read_all_capsules(state.ledger_dir)
    log_id = _log_id_for(state)
    payload = peer_accountability_tab.build_peers_payload(
        records,
        node_id=state.node_id,
        log_id=log_id,
        checkpoint_lines=_read_jsonl_if_present(state.ledger_dir / "checkpoints.jsonl"),
        source_log="sidecar",
    )
    assert_no_rating_fields(payload)
    return payload


def build_pane_c_json(
    state: "NodeState", *, exchange_id: str | None = None, limit: int | None = None, after_seq: int = 0
) -> dict[str, Any]:
    """Pane C ("This exchange"). With no ``exchange_id``: the regrouped list
    (``build_exchange_list_payload``), capped/paginated via L0's
    ``read_capsules_page`` -- ``limit`` defaults to
    :data:`DEFAULT_PANE_C_PAGE_LIMIT`; pass ``limit=None`` explicitly for an
    uncapped read. The response's own ``next_after_seq``/``archived_segments``
    keys (added here, alongside the list payload's existing ``rows``/
    ``row_count``) are the paging cursor and gap descriptors L0 defined --
    ``None`` means this page reached the end of the log.

    With ``exchange_id`` (an exchange's ``exchange_key`` field, exactly as
    every list row already carries it -- never re-derived): the single
    drill-down (``build_exchange_view``), found by a full, uncapped read --
    same reasoning ``ledger_finder.find_capsules`` documents for why an id
    lookup can't rely on a capped window (the matching records could sit
    anywhere in an arbitrarily large log). ``found: false`` (never a 404
    with no body) when nothing in this node's own ledger carries that key
    -- a live tab can render "not on this node" rather than treating it as
    a transport error.
    """
    if exchange_id:
        records, _archived_segments = ledger_store_backend.read_all_capsules(state.ledger_dir)
        group = [r for r in records if capsule_exchange_tab.exchange_key_for(r) == exchange_id]
        group.sort(key=lambda r: (r.get("timestamp") or "", r.get("capsule_id") or ""))
        if not group:
            payload: dict[str, Any] = {"exchange_key": exchange_id, "found": False}
        else:
            anchor = group[0]
            view = capsule_exchange_tab.build_exchange_view(
                anchor, all_records=records, source_log="sidecar", ledger_dir=state.ledger_dir
            )
            payload = {"exchange_key": exchange_id, "found": True, "view": view}
        assert_no_rating_fields(payload)
        return payload

    effective_limit = DEFAULT_PANE_C_PAGE_LIMIT if limit is None else limit
    records, archived_segments, next_after_seq = ledger_store_backend.read_capsules_page(
        state.ledger_dir, limit=effective_limit, after_seq=after_seq
    )
    payload = capsule_exchange_tab.build_exchange_list_payload(records, source_log="sidecar", ledger_dir=state.ledger_dir)
    payload["archived_segments"] = archived_segments
    payload["next_after_seq"] = next_after_seq
    assert_no_rating_fields(payload)
    return payload
