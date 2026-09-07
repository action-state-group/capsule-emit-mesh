#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-ui-ledger-finder] The Accountability page's Finder: a small query
bar (never a pane -- mesh-accountability-panes-v2-2026-09-05.md §3) over
this node's own capsule ledger: time range · exchange id / capsule id /
digest · peer. A hit opens the same Pane C ("This exchange") drawer
``capsule_exchange_tab.py`` already renders -- this module builds no second
drill-down view, it only finds the record and hands it to
``build_exchange_view``/``render_exchange_subtab_html`` unchanged. Also
lists archived (rotated-out) segments, labeled, so an old exchange is one
click away after rotation even when this reader can't open its bytes.

**Why this reads ``ledger_store_backend.read_all_capsules`` and never calls
``cll.ledger.store.LedgerStore.by_time``/``by_digest``/``by_correlation``
directly**, even though those are the lookup-index methods the store
exists to offer:

- ``by_time`` (and ``by_digest``/``by_correlation``) resolve every lookup-
  index hit inside one eager list comprehension under one lock; the instant
  ANY hit lands on an unmounted segment, ``_resolve_lookup_hit`` raises
  ``SegmentUnmounted`` for the WHOLE call and every already-resolved record
  in that batch is lost with it (see that method's own docstring). That is
  exactly the failure mode ``read_all_capsules``/``_read_store_page``
  ([mesh-ledger-store-migration]) was already written to avoid -- "one
  archived segment never blocks reading the records before or after it".
  Filtering ``read_all_capsules``'s already-segment-safe output in Python
  keeps that property for every Finder query, not just a full scan.
- ``by_correlation``'s declared ``correlation_fields``
  (``ledger_store_backend.CORRELATION_FIELDS`` = ``("exchange_id",
  "capsule_id", "nonce", "counterparty")``) are BARE top-level field names.
  A mesh capsule nests all of this instead, under
  ``model_attestation.compute_attestation["x-mesh-poc-v1"].
  serving_provenance`` (see ``capsule_mesh_viewer.serving_provenance``) --
  confirmed empirically against both real, git-tracked demo ledgers that
  ``by_correlation(<a real exchange_id>)`` returns nothing for a mesh
  capsule. This is a pre-existing gap in what
  ``[mesh-ledger-store-migration]`` declared, not something to invent a fix
  for here -- flagging it rather than silently working around it with a
  correlation-field rename this task was never scoped to make. ``capsule_id``
  digest lookup still works fine either way, since that field IS top-level;
  this module resolves it the same way (exact-or-prefix over
  ``read_all_capsules``'s output) purely for one shared code path.

**capsule_id / digest are the same field.** Matched exact-or-prefix, the
same convention ``capsule_emit.ledger.show()`` uses (``rid == capsule_id or
rid.startswith(capsule_id)``) -- so a Finder hit for an id is byte-identical
to what the CLI ``ledger show <id>`` prints for the same id, and the same
"not found -- N archived segment(s) not mounted, it may be among them"
honesty when it isn't among the mounted records.

**The single id field matches capsule_id/digest OR exchange_id** (never
both required) -- the design's "exchange id / capsule id / digest" is one
bar group, not three, since a user rarely knows in advance which kind of id
they're holding.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from capsule_exchange_tab import (
    build_exchange_view,
    exchange_id_for,
    render_exchange_subtab_html,
)
from capsule_mesh_viewer import serving_provenance
from ledger_store_backend import read_all_capsules

__all__ = [
    "capsule_matches_id",
    "find_capsules",
    "peer_for",
    "render_archived_segments_html",
    "render_finder_bar_html",
    "render_finder_page_html",
    "render_finder_results_html",
]


def capsule_matches_id(record: dict[str, Any], id_query: str) -> bool:
    """Exact-or-prefix match on ``capsule_id`` -- identical convention to
    ``capsule_emit.ledger.show()``, so a Finder id hit is the same record
    that CLI would show for the same id."""
    rid = record.get("capsule_id", "")
    return rid == id_query or rid.startswith(id_query)


def peer_for(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """``(served_by_node_id, requesting_party)`` for *record* -- the two
    node-identity fields a "peer" query can match, since a caller typing a
    peer id doesn't know in advance which side of the exchange that peer
    played here."""
    sp = serving_provenance(record)
    return sp.get("served_by_node_id"), sp.get("requesting_party")


def _peer_matches(record: dict[str, Any], peer: str) -> bool:
    served_by, requesting = peer_for(record)
    for candidate in (served_by, requesting):
        if candidate and (candidate == peer or candidate.startswith(peer)):
            return True
    return False


def _record_matches(
    record: dict[str, Any],
    *,
    start: str | None,
    end: str | None,
    id_query: str | None,
    peer: str | None,
) -> bool:
    if id_query and not (capsule_matches_id(record, id_query) or exchange_id_for(record) == id_query):
        return False
    if peer and not _peer_matches(record, peer):
        return False
    timestamp = record.get("timestamp") or ""
    if start is not None and timestamp < start:
        return False
    return not (end is not None and timestamp > end)


def find_capsules(
    ledger_dir: Path,
    *,
    start: str | None = None,
    end: str | None = None,
    id_query: str | None = None,
    peer: str | None = None,
) -> dict[str, Any]:
    """Query this node's own ledger: every mounted record matching every
    supplied filter (AND'ed), plus every archived (unmounted) segment this
    reader could not open -- never raises, spans every mounted segment a
    rotated ledger holds (see the module docstring for why this filters
    ``read_all_capsules`` rather than calling the store's own ``by_*``
    lookup methods).

    ``all_records`` rides along so a caller can build a Pane C drawer
    (``capsule_exchange_tab.build_exchange_view``) for a hit without a
    second read of the ledger; it is not meant to be serialized back to a
    client as part of the query response.

    With every filter omitted (the bar's empty, just-loaded state), this
    deliberately returns no results rather than the whole ledger -- a bar
    is not a pane (mesh-accountability-panes-v2-2026-09-05.md §3); Pane C's
    own list view is where "everything" already lives.
    """
    records, archived_segments = read_all_capsules(Path(ledger_dir))
    has_filter = any((start, end, id_query, peer))
    results = (
        [record for record in records if _record_matches(record, start=start, end=end, id_query=id_query, peer=peer)]
        if has_filter
        else []
    )
    not_found_but_maybe_archived = bool(id_query) and not results and bool(archived_segments)
    return {
        "query": {"start": start, "end": end, "id_query": id_query, "peer": peer},
        "results": results,
        "all_records": records,
        "archived_segments": archived_segments,
        "not_found_but_maybe_archived": not_found_but_maybe_archived,
    }


# ---------------------------------------------------------------------------
# Presentation -- self-contained HTML, no fetch, no external state (same
# philosophy as capsule_exchange_tab.render_exchange_subtab_html: this
# view's fields are already Python-side resolved, so there is nothing to
# check in-browser). The bar is a plain GET form -- submitting it is itself
# "backed by the sidecar's local endpoint" (mesh-accountability-panes-v2-
# 2026-09-05.md §3), no client-side JS required to issue the query.
# ---------------------------------------------------------------------------

_STYLE = """
  :root {
    --bg: oklch(0.17 0.015 250); --panel: oklch(0.2 0.018 250); --panel-strong: oklch(0.23 0.02 250);
    --border: oklch(0.3 0.02 250 / 0.9); --border-soft: oklch(0.3 0.02 250 / 0.45);
    --fg: oklch(0.96 0.005 80); --fg-dim: oklch(0.78 0.01 80); --fg-faint: oklch(0.6 0.01 80);
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 13.5px/1.55 "Inter Tight","Inter",system-ui,sans-serif; }
  main { max-width: 980px; margin: 0 auto; padding: 20px 16px 40px; }
  h1 { font-size: 16.5px; margin: 0 0 4px; }
  h3 { font-size: 13px; margin: 18px 0 6px; color: var(--fg-dim); }
  p.caption { color: var(--fg-dim); font-size: 12px; margin: 0 0 14px; }
  form.finder-bar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
  form.finder-bar input { background: var(--panel-strong); border: 1px solid var(--border-soft); border-radius: 6px;
    color: var(--fg); padding: 5px 9px; font-size: 12.5px; }
  form.finder-bar button { border-radius: 6px; border: 1px solid var(--border-soft); background: var(--panel-strong);
    color: var(--fg); padding: 5px 14px; cursor: pointer; }
  details.finder-result { border: 1px solid var(--border); border-radius: 8px; background: var(--panel); margin-bottom: 8px; padding: 8px 12px; }
  details.finder-result summary { cursor: pointer; list-style: none; }
  details.finder-result summary::-webkit-details-marker { display: none; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fg-faint); font-size: 12px; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  table th, table td { border-bottom: 1px solid var(--border-soft); padding: 4px 8px; text-align: left; }
"""


def _esc(value: Any) -> str:
    return "" if value is None else str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_finder_bar_html(query: dict[str, Any] | None = None) -> str:
    """The bar itself: time range · exchange id / capsule id / digest ·
    peer -- one GET form, not a pane."""
    query = query or {}

    def value(name: str) -> str:
        return _esc(query.get(name) or "")

    return f"""<form class="finder-bar" method="get" action="/accountability/finder">
  <input type="text" name="start" placeholder="start (ISO8601)" value="{value('start')}">
  <input type="text" name="end" placeholder="end (ISO8601)" value="{value('end')}">
  <input type="text" name="id_query" placeholder="exchange id / capsule id / digest" value="{value('id_query')}">
  <input type="text" name="peer" placeholder="peer" value="{value('peer')}">
  <button type="submit">Find</button>
</form>"""


def render_archived_segments_html(archived_segments: list[dict[str, Any]]) -> str:
    """Archived segments: date range, checkpoint root, mounted/not -- so an
    old exchange is one click away after rotation, even though this reader
    cannot open its bytes."""
    if not archived_segments:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{_esc(seg['segment'])}</td>"
        f"<td>{_esc(seg.get('first_ts') or '?')} – {_esc(seg.get('last_ts') or '?')}</td>"
        f"<td class='mono'>{_esc(seg['checkpoint_root'])}</td>"
        f"<td>{_esc(seg['note'])}</td></tr>"
        for seg in archived_segments
    )
    return f"""<h3>Archived segments ({len(archived_segments)})</h3>
<table>
  <thead><tr><th>segment</th><th>date range</th><th>checkpoint root</th><th>state</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def render_finder_results_html(result: dict[str, Any], *, source_log: str = "sidecar") -> str:
    """Results open the Pane C drawer (``render_exchange_subtab_html``,
    unchanged) -- this renders no second drill-down view."""
    query = result["query"]
    results = result["results"]
    all_records = result["all_records"]
    archived_segments = result["archived_segments"]

    if not results:
        if result["not_found_but_maybe_archived"]:
            body = (
                f"<p>id {_esc(query.get('id_query'))!r} not found in the mounted ledger — "
                f"{len(archived_segments)} archived segment(s) not mounted, it may be among them "
                "(archived — mount to view)</p>"
            )
        elif any(query.get(k) for k in ("start", "end", "id_query", "peer")):
            body = "<p>no matching exchanges</p>"
        else:
            body = ""
    else:
        cards = []
        for record in results:
            view = build_exchange_view(record, all_records=all_records, source_log=source_log)
            cards.append(
                f'<details class="finder-result" data-capsule-id="{_esc(record.get("capsule_id"))}">'
                f'<summary><span class="mono">{_esc(record.get("capsule_id"))}</span> · '
                f'{_esc(record.get("timestamp"))}</summary>'
                f"{render_exchange_subtab_html(view)}"
                f"</details>"
            )
        body = "".join(cards)

    return f'<section class="finder-results">{body}</section>{render_archived_segments_html(archived_segments)}'


def render_finder_page_html(result: dict[str, Any], *, source_log: str = "sidecar") -> str:
    """The whole Finder page: bar at the top, results (each opening its own
    Pane C drawer) and the archived-segments list below."""
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mesh-llm · Accountability · Finder</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
  <h1>Accountability</h1>
  <p class="caption">Finder — time range · exchange id / capsule id / digest · peer</p>
  {render_finder_bar_html(result["query"])}
  {render_finder_results_html(result, source_log=source_log)}
</main>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI -- same shape as capsule_exchange_tab.py's own: render a static file
# from a ledger dir, for the demo/screenshot and for ad-hoc inspection.
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ledger-finder",
        description="Render the Accountability page's Finder bar + results against a ledger.",
    )
    parser.add_argument("--ledger", required=True, metavar="PATH", help="this node's ledger dir or flat ledger file")
    parser.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    parser.add_argument("--start", default=None, help="ISO8601 lower bound (inclusive)")
    parser.add_argument("--end", default=None, help="ISO8601 upper bound (inclusive)")
    parser.add_argument("--id-query", dest="id_query", default=None, help="exchange id / capsule id / digest")
    parser.add_argument("--peer", default=None, help="peer node id (served_by_node_id or requesting_party)")
    parser.add_argument("--source-log", default="sidecar", choices=["plugin", "sidecar"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    result = find_capsules(
        Path(args.ledger), start=args.start, end=args.end, id_query=args.id_query, peer=args.peer
    )
    html = render_finder_page_html(result, source_log=args.source_log)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(
        f"finder: {len(result['results'])} result(s), "
        f"{len(result['archived_segments'])} archived segment(s) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
