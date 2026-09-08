#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-acct-dashboard] Combined accountability dashboard served at
GET /accountability/ (and /accountability/dashboard as an alias).

The page is fully self-contained (no CDN, works offline). It fetches Pane A/B/C
JSON client-side from the same origin sidecar, then renders four tabs:

  - "This node"   -- Pane A card (promise line, history, served summary, exchanges)
  - "Peers"       -- Pane B peer rows with honest-state cells
  - "This exchange" -- Finder bar + Pane C exchange list / drill-down
  - "History"     -- Four sections built from Pane A data

Honest-state discipline enforced client-side:
  - Any cell whose ``state`` is ``"pending"`` or ``"absent"`` renders in grey
    with its reason text -- never fabricated as a PASS/green.
  - ``NOT_PRESENT`` / ``NOT_CHECKED`` chip states use neutral tone (grey).
  - Only ``PASS`` maps to green; only ``FAIL`` maps to red.

Vocabulary-clean (no private product terms). Apache-2.0.
"""
from __future__ import annotations

import json
from typing import Any

import assurance_map

__all__ = [
    "DASHBOARD_PATHS",
    "render_dashboard_html",
]

#: URL paths this module serves -- the canonical path and its alias.
DASHBOARD_PATHS = ("/accountability/", "/accountability/dashboard")


def render_dashboard_html(node_id: str, listen_port: int) -> str:  # noqa: ARG001
    """Return the full, self-contained dashboard HTML page.

    Inlines all CSS/JS.  Client-side fetch() calls /accountability/pane-a,
    /pane-b, /pane-c to populate each tab on demand.

    Parameters
    ----------
    node_id:
        This node's own identity string, embedded in the page for display.
    listen_port:
        The sidecar's own listen port (embedded so the page can form
        fully-qualified URLs if needed -- same-origin by design so plain
        ``/accountability/pane-a`` always works without it).
    """
    chip_tone_js = assurance_map.tone_js_object()
    chip_css = assurance_map.CHIP_CSS

    # Escape node_id for safe HTML embedding.
    safe_node_id = str(node_id).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    safe_port = str(int(listen_port))

    html = _DASHBOARD_SHELL
    html = html.replace("@@CHIP_TONE@@", chip_tone_js)
    html = html.replace("@@CHIP_CSS@@", chip_css)
    html = html.replace("@@NODE_ID@@", safe_node_id)
    html = html.replace("@@LISTEN_PORT@@", safe_port)
    return html


# ---------------------------------------------------------------------------
# HTML shell -- the single-file dashboard.  All CSS/JS inlined.
# ---------------------------------------------------------------------------

_DASHBOARD_SHELL = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mesh-llm · Evidence</title>
<style>
  :root {
    --bg: oklch(0.17 0.015 250);
    --panel: oklch(0.2 0.018 250);
    --panel-strong: oklch(0.23 0.02 250);
    --border: oklch(0.3 0.02 250 / 0.9);
    --border-soft: oklch(0.3 0.02 250 / 0.45);
    --fg: oklch(0.96 0.005 80);
    --fg-dim: oklch(0.78 0.01 80);
    --fg-faint: oklch(0.6 0.01 80);
    --accent: oklch(0.8 0.14 200);
    --accent-ink: oklch(0.2 0.04 220);
    --good: oklch(0.78 0.14 150);
    --warn: oklch(0.8 0.12 80);
    --bad: oklch(0.7 0.18 25);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 13.5px/1.55 "Inter Tight", "Inter", system-ui, -apple-system, sans-serif;
  }
  .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; font-variant-numeric: tabular-nums; }
  header.topbar {
    display: flex; align-items: center; gap: 16px; padding: 10px 16px;
    border-bottom: 1px solid var(--border); background: var(--panel);
    position: sticky; top: 0; z-index: 10;
  }
  .brand { font-weight: 700; font-size: 14px; letter-spacing: 0.01em; }
  .brand .dim { color: var(--fg-faint); font-weight: 500; }
  .node-id-small { font-size: 11px; color: var(--fg-faint); font-family: ui-monospace, monospace; }
  nav.tabs { display: inline-flex; gap: 2px; background: var(--bg); border-radius: 8px; padding: 3px; }
  nav.tabs button {
    padding: 5px 12px; border-radius: 6px; font-size: 12.5px; font-weight: 600;
    color: var(--fg-faint); background: transparent; border: none; cursor: pointer;
    font-family: inherit;
  }
  nav.tabs button.active { background: var(--panel-strong); color: var(--fg); box-shadow: 0 1px 0 var(--border-soft); }
  main { max-width: 1140px; margin: 0 auto; padding: 20px 16px 40px; }
  h1.type-headline { font-size: 16.5px; font-weight: 700; margin: 0 0 4px; }
  p.type-caption { color: var(--fg-dim); font-size: 12px; margin: 0 0 18px; }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }
  .panel-shell { border: 1px solid var(--border); border-radius: 10px; background: var(--panel); overflow: hidden; margin-bottom: 18px; }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.07em; color: var(--fg-faint); background: var(--panel-strong);
    padding: 9px 12px; border-bottom: 1px solid var(--border);
  }
  tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
  tbody tr.clickable-row { cursor: pointer; }
  tbody tr.clickable-row:hover { background: var(--panel-strong); }
  tbody tr.detail-row { display: none; background: var(--bg); }
  tbody tr.detail-row.open { display: table-row; }
  .pill {
    display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px;
    border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap;
  }
  .pill-good { color: var(--good); background: color-mix(in oklab, var(--good) 14%, transparent); border: 1px solid color-mix(in oklab, var(--good) 40%, transparent); }
  .pill-warn { color: var(--warn); background: color-mix(in oklab, var(--warn) 14%, transparent); border: 1px solid color-mix(in oklab, var(--warn) 40%, transparent); }
  .pill-bad  { color: var(--bad);  background: color-mix(in oklab, var(--bad)  14%, transparent); border: 1px solid color-mix(in oklab, var(--bad)  40%, transparent); }
  .pill-neutral { color: var(--fg-dim); background: color-mix(in oklab, var(--fg-dim) 10%, transparent); border: 1px solid var(--border-soft); }
  .empty { padding: 30px; text-align: center; color: var(--fg-faint); }
  .error { padding: 18px; color: var(--bad); font-size: 13px; }
  footer.note { margin-top: 14px; font-size: 12px; color: var(--fg-faint); }

  /* Card face (Pane A) */
  .card-face { border: 1px solid var(--border); border-radius: 10px; background: var(--panel); padding: 14px 16px; margin-bottom: 16px; }
  .card-face .promise-line { font-size: 14px; font-weight: 700; margin-bottom: 10px; }
  .card-block { display: flex; align-items: baseline; gap: 8px; padding: 5px 0; border-bottom: 1px solid var(--border-soft); font-size: 13px; }
  .card-block:last-of-type { border-bottom: none; }
  .card-block .block-label { color: var(--fg-faint); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; min-width: 118px; }

  /* Rung grid */
  .rung-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; padding: 14px 16px 18px; }
  .rung-card { border: 1px solid var(--border-soft); border-radius: 8px; padding: 10px 12px; background: var(--panel); }
  .rung-card .label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--fg-faint); margin-bottom: 6px; }
  .rung-card .caveat { margin-top: 6px; font-size: 12px; color: var(--fg-dim); }

  /* History tab sections */
  .history-section { margin-bottom: 22px; }
  .history-section h3 { font-size: 13px; font-weight: 700; margin: 0 0 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.06em; }
  .history-kv { display: flex; gap: 24px; flex-wrap: wrap; }
  .history-kv .kv { display: flex; flex-direction: column; min-width: 120px; }
  .history-kv .kv .k { font-size: 11px; color: var(--fg-faint); text-transform: uppercase; letter-spacing: 0.06em; }
  .history-kv .kv .v { font-size: 18px; font-weight: 700; margin-top: 2px; }

  /* Finder bar */
  .finder-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-end; padding: 14px 16px; background: var(--panel-strong); border-bottom: 1px solid var(--border); }
  .finder-bar label { font-size: 11px; color: var(--fg-faint); display: flex; flex-direction: column; gap: 3px; }
  .finder-bar input { background: var(--bg); border: 1px solid var(--border); color: var(--fg); border-radius: 6px; padding: 5px 9px; font: inherit; font-size: 12px; width: 180px; }
  .finder-bar input:focus { outline: 2px solid var(--accent); }
  .finder-bar button.search-btn { padding: 6px 14px; background: var(--accent); color: var(--accent-ink); border: none; border-radius: 6px; font: inherit; font-weight: 600; font-size: 12.5px; cursor: pointer; align-self: flex-end; }
  .finder-result-area { padding: 14px 16px; }

  /* Pending / absent cell */
  .cell-pending { color: var(--fg-faint); font-size: 12px; }

  /* Role tag */
  .role-tag { display: inline-block; font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; padding: 1px 6px; border-radius: 4px; }
  .role-served { background: color-mix(in oklab, var(--good) 18%, transparent); color: var(--good); border: 1px solid color-mix(in oklab, var(--good) 35%, transparent); }
  .role-asked  { background: color-mix(in oklab, var(--accent) 18%, transparent); color: var(--accent); border: 1px solid color-mix(in oklab, var(--accent) 35%, transparent); }

  /* Chip CSS injected below */
  @@CHIP_CSS@@
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">mesh-llm <span class="dim">/ Evidence</span></div>
  <nav class="tabs" id="tab-nav">
    <button class="active" data-tab="node">This node</button>
    <button data-tab="peers">Peers</button>
    <button data-tab="exchange">This exchange</button>
    <button data-tab="history">History</button>
  </nav>
  <div class="node-id-small mono" id="node-id-display">node: @@NODE_ID@@</div>
</header>
<main>
  <h1 class="type-headline">Evidence</h1>
  <p class="type-caption">Everything here is recomputed from sealed records. Nothing is a score.</p>

  <!-- Tab: This node -->
  <div class="tab-pane active" id="tab-node">
    <div id="pane-a-loading" class="empty">Loading…</div>
    <div id="pane-a-content" hidden></div>
    <div id="pane-a-error" class="error" hidden></div>
  </div>

  <!-- Tab: Peers -->
  <div class="tab-pane" id="tab-peers">
    <div id="pane-b-loading" class="empty">Loading…</div>
    <div id="pane-b-content" hidden></div>
    <div id="pane-b-error" class="error" hidden></div>
  </div>

  <!-- Tab: This exchange -->
  <div class="tab-pane" id="tab-exchange">
    <div class="panel-shell">
      <div class="finder-bar">
        <label>Time from<input type="text" id="finder-start" placeholder="2026-09-01T00:00:00Z"></label>
        <label>Time to<input type="text" id="finder-end" placeholder="2026-09-08T23:59:59Z"></label>
        <label>ID / exchange key<input type="text" id="finder-id" placeholder="capsule or exchange id"></label>
        <label>Peer node<input type="text" id="finder-peer" placeholder="peer node id"></label>
        <button class="search-btn" id="finder-search-btn">Search</button>
      </div>
      <div class="finder-result-area" id="finder-result-area">
        <span style="color:var(--fg-faint);font-size:12px;">Enter a query above and click Search.</span>
      </div>
    </div>
    <div id="pane-c-loading" class="empty">Loading…</div>
    <div id="pane-c-content" hidden></div>
    <div id="pane-c-error" class="error" hidden></div>
  </div>

  <!-- Tab: History -->
  <div class="tab-pane" id="tab-history">
    <div id="history-loading" class="empty">Loading…</div>
    <div id="history-content" hidden></div>
    <div id="history-error" class="error" hidden></div>
  </div>
</main>

<script>
(function() {
"use strict";

// ---------------------------------------------------------------------------
// Tone map (generated from assurance_map.py -- single source of truth)
// ---------------------------------------------------------------------------
const TONE = @@CHIP_TONE@@;

const CHIP_GLYPH = {
  "PASS": "✓",
  "FAIL": "✕",
  "NOT_PRESENT": "∅",
  "NOT_CHECKED": "…",
  "INCONCLUSIVE": "?",
};

const PROPERTY_ORDER = [
  "content_binding", "producer_signature", "local_inclusion",
  "checkpoint_signature", "external_registration", "continuity",
  "identity_authority", "capture_coverage", "outcome_corroboration",
];

const PROPERTY_SHORT_LABEL = {
  "content_binding": "binding",
  "producer_signature": "sig",
  "local_inclusion": "local incl.",
  "checkpoint_signature": "chkpt sig",
  "external_registration": "registered",
  "continuity": "continuity",
  "identity_authority": "identity",
  "capture_coverage": "capture",
  "outcome_corroboration": "outcome",
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function esc(v) {
  if (v == null) return "";
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function toneFor(state) {
  return TONE[state] || "neutral";
}

function pillHtml(state, text) {
  const tone = toneFor(state);
  const label = esc(text || state);
  return `<span class="pill pill-${tone}">${label}</span>`;
}

// Honest cell rendering: pending/absent → grey, never a green fabrication.
function cellHtml(cell) {
  if (!cell) return '<span class="cell-pending">—</span>';
  const s = cell.state || "";
  const t = cell.text || s;
  if (s === "pending" || s === "absent") {
    return `<span class="cell-pending" title="${esc(t)}">${esc(t)}</span>`;
  }
  return pillHtml(s, t);
}

function chipStripHtml(properties) {
  if (!properties) return "";
  const segs = [];
  for (const key of PROPERTY_ORDER) {
    const entry = properties[key];
    if (!entry) continue;
    const state = entry.state || "NOT_CHECKED";
    const glyph = CHIP_GLYPH[state] || "?";
    const tone = toneFor(state);
    const short = PROPERTY_SHORT_LABEL[key] || key;
    const title = `${key}: ${state}` + (entry.text ? ` -- ${entry.text}` : "");
    segs.push(`<span class="chip-seg chip-${tone}" title="${esc(title)}">${esc(short)} ${glyph}</span>`);
  }
  return `<span class="chip-strip">${segs.join(" · ")}</span>`;
}

function setVisible(el, visible) {
  if (visible) { el.removeAttribute("hidden"); }
  else { el.setAttribute("hidden", ""); }
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

const tabNav = document.getElementById("tab-nav");
const TABS = ["node", "peers", "exchange", "history"];
const _loaded = {};

tabNav.addEventListener("click", function(e) {
  const btn = e.target.closest("button[data-tab]");
  if (!btn) return;
  const tab = btn.dataset.tab;
  tabNav.querySelectorAll("button").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  TABS.forEach(t => {
    const el = document.getElementById("tab-" + t);
    if (el) el.classList.toggle("active", t === tab);
  });
  loadTab(tab);
});

function loadTab(tab) {
  if (_loaded[tab]) return;
  if (tab === "node") { loadPaneA(); }
  else if (tab === "peers") { loadPaneB(); }
  else if (tab === "exchange") { loadPaneC(); }
  else if (tab === "history") { loadHistory(); }
}

// ---------------------------------------------------------------------------
// Pane A -- "This node"
// ---------------------------------------------------------------------------

function loadPaneA() {
  _loaded["node"] = true;
  const loading = document.getElementById("pane-a-loading");
  const content = document.getElementById("pane-a-content");
  const errEl = document.getElementById("pane-a-error");
  fetch("/accountability/pane-a")
    .then(r => r.json())
    .then(payload => {
      setVisible(loading, false);
      content.innerHTML = renderPaneA(payload);
      setVisible(content, true);
      attachRowToggle(content);
    })
    .catch(err => {
      setVisible(loading, false);
      errEl.textContent = "Failed to load Pane A: " + err;
      setVisible(errEl, true);
    });
}

function renderPaneA(payload) {
  const parts = [];

  // Card face
  const face = payload.card_face;
  if (face) {
    const promiseState = face.promise_state || "nothing_promised";
    const promiseLine = face.promise_line || "";
    const promiseCls = "promise-" + esc(promiseState);
    parts.push(`<div class="card-face">`);
    parts.push(`<div class="promise-line ${promiseCls}">${esc(promiseLine)}</div>`);
    // blocks
    for (const block of (face.blocks || [])) {
      const label = esc(block.label || "");
      const val = block.value || "";
      const valHtml = typeof val === "string"
        ? pillHtml(val, val)
        : esc(JSON.stringify(val));
      parts.push(`<div class="card-block"><span class="block-label">${label}</span><span>${valHtml}</span></div>`);
    }
    parts.push(`</div>`);
  }

  // History block
  const histBlock = payload.history_block;
  if (histBlock) {
    parts.push(renderNamedBlock("History", histBlock));
  }

  // Served summary block
  const servBlock = payload.served_summary_block;
  if (servBlock) {
    parts.push(renderNamedBlock("Served summary", servBlock));
  }

  // Exchange rows table
  const rows = payload.rows || [];
  if (rows.length === 0) {
    parts.push(`<div class="panel-shell"><div class="empty">No exchange records in this ledger yet.</div></div>`);
  } else {
    parts.push(`<div class="panel-shell"><table>`);
    parts.push(`<thead><tr>
      <th>Capsule ID</th>
      <th>Time</th>
      <th>Role</th>
      <th>Promise</th>
      <th>Assurance</th>
    </tr></thead><tbody>`);
    for (const row of rows) {
      const cid = row.capsule_id || "";
      const ts = (row.timestamp || "").replace("T", " ").replace("Z", "");
      const role = row.role || "";
      const ps = row.promise_state || "";
      const rid = "row-" + esc(cid);
      const roleCls = role === "provider" ? "role-served" : "role-asked";
      const roleLabel = role === "provider" ? "SERVED" : "ASKED";
      parts.push(`<tr class="clickable-row" data-detail="${rid}">`);
      parts.push(`<td class="mono" style="font-size:11.5px;">${esc(cid.slice(0,12))}…</td>`);
      parts.push(`<td style="font-size:11.5px;white-space:nowrap;">${esc(ts)}</td>`);
      parts.push(`<td><span class="role-tag ${roleCls}">${roleLabel}</span></td>`);
      parts.push(`<td>${pillHtml(ps, ps)}</td>`);
      parts.push(`<td>${chipStripHtml(row.assurance_map)}</td>`);
      parts.push(`</tr>`);
      // detail row
      parts.push(`<tr class="detail-row" id="${rid}"><td colspan="5" style="padding:12px 16px;">`);
      parts.push(`<div style="font-size:12px;color:var(--fg-dim);">`);
      parts.push(`<strong>Capsule ID:</strong> <span class="mono">${esc(cid)}</span>`);
      if (row.assurance_map) {
        parts.push(`<br><br>${chipStripHtml(row.assurance_map)}`);
      }
      parts.push(`</div></td></tr>`);
    }
    parts.push(`</tbody></table></div>`);
  }
  return parts.join("\n");
}

function renderNamedBlock(title, block) {
  if (!block) return "";
  if (block.state === "pending" || block.state === "absent") {
    return `<div class="panel-shell"><div class="empty cell-pending">${esc(title)}: ${esc(block.text || block.state)}</div></div>`;
  }
  const lines = [];
  for (const [k, v] of Object.entries(block)) {
    if (k === "state" || k === "text") continue;
    lines.push(`<div class="card-block"><span class="block-label">${esc(k)}</span><span>${esc(JSON.stringify(v))}</span></div>`);
  }
  return `<div class="panel-shell" style="padding:12px 16px;"><strong style="font-size:12px;color:var(--fg-faint);text-transform:uppercase;letter-spacing:0.06em;">${esc(title)}</strong>${lines.join("")}</div>`;
}

// ---------------------------------------------------------------------------
// Pane B -- "Peers"
// ---------------------------------------------------------------------------

function loadPaneB() {
  _loaded["peers"] = true;
  const loading = document.getElementById("pane-b-loading");
  const content = document.getElementById("pane-b-content");
  const errEl = document.getElementById("pane-b-error");
  fetch("/accountability/pane-b")
    .then(r => r.json())
    .then(payload => {
      setVisible(loading, false);
      content.innerHTML = renderPaneB(payload);
      setVisible(content, true);
    })
    .catch(err => {
      setVisible(loading, false);
      errEl.textContent = "Failed to load Pane B: " + err;
      setVisible(errEl, true);
    });
}

function renderPaneB(payload) {
  const rows = payload.rows || [];
  const peerCount = payload.peer_count != null ? payload.peer_count : rows.length;
  const parts = [];
  parts.push(`<p style="font-size:12px;color:var(--fg-faint);margin:0 0 12px;">${esc(peerCount)} peer(s) seen in this ledger.</p>`);
  if (rows.length === 0) {
    parts.push(`<div class="panel-shell"><div class="empty">No peer exchanges recorded yet.</div></div>`);
    return parts.join("\n");
  }
  parts.push(`<div class="panel-shell"><table>`);
  parts.push(`<thead><tr>
    <th>Node</th>
    <th>Role · Exchanges</th>
    <th>History (theirs)</th>
    <th>Served (theirs)</th>
    <th>Pair</th>
    <th>Verdicts</th>
    <th>Asked</th>
  </tr></thead><tbody>`);
  for (const row of rows) {
    const node = row.node_id || row.peer_id || "unknown";
    const roleExch = row.role_and_count || {};
    const roleExchHtml = renderPeerRoleCell(roleExch);
    parts.push(`<tr>`);
    parts.push(`<td class="mono" style="font-size:11.5px;">${esc(node)}</td>`);
    parts.push(`<td>${roleExchHtml}</td>`);
    parts.push(`<td>${cellHtml(row.history_theirs)}</td>`);
    parts.push(`<td>${cellHtml(row.served_theirs)}</td>`);
    parts.push(`<td>${cellHtml(row.pair)}</td>`);
    parts.push(`<td>${cellHtml(row.verdicts)}</td>`);
    parts.push(`<td>${cellHtml(row.asked)}</td>`);
    parts.push(`</tr>`);
  }
  parts.push(`</tbody></table></div>`);
  return parts.join("\n");
}

function renderPeerRoleCell(roleExch) {
  if (!roleExch || typeof roleExch !== "object") return esc(String(roleExch || "—"));
  if (roleExch.state === "pending" || roleExch.state === "absent") {
    return `<span class="cell-pending">${esc(roleExch.text || roleExch.state)}</span>`;
  }
  const parts = [];
  if (roleExch.served_count != null) parts.push(`served ${roleExch.served_count}`);
  if (roleExch.asked_count != null) parts.push(`asked ${roleExch.asked_count}`);
  return parts.length ? esc(parts.join(", ")) : esc(roleExch.text || JSON.stringify(roleExch));
}

// ---------------------------------------------------------------------------
// Pane C -- "This exchange"
// ---------------------------------------------------------------------------

function loadPaneC() {
  _loaded["exchange"] = true;
  const loading = document.getElementById("pane-c-loading");
  const content = document.getElementById("pane-c-content");
  const errEl = document.getElementById("pane-c-error");
  fetch("/accountability/pane-c")
    .then(r => r.json())
    .then(payload => {
      setVisible(loading, false);
      content.innerHTML = renderPaneC(payload);
      setVisible(content, true);
      attachRowToggle(content);
    })
    .catch(err => {
      setVisible(loading, false);
      errEl.textContent = "Failed to load Pane C: " + err;
      setVisible(errEl, true);
    });

  // Finder search button
  document.getElementById("finder-search-btn").addEventListener("click", runFinder);
}

function runFinder() {
  const start   = document.getElementById("finder-start").value.trim();
  const end     = document.getElementById("finder-end").value.trim();
  const idQuery = document.getElementById("finder-id").value.trim();
  const peer    = document.getElementById("finder-peer").value.trim();
  const area = document.getElementById("finder-result-area");
  area.innerHTML = '<span style="color:var(--fg-faint);font-size:12px;">Searching…</span>';

  const params = new URLSearchParams();
  if (start)   params.set("start",    start);
  if (end)     params.set("end",      end);
  if (idQuery) params.set("id_query", idQuery);
  if (peer)    params.set("peer",     peer);
  const url = "/accountability/finder" + (params.toString() ? "?" + params.toString() : "");

  fetch(url)
    .then(r => r.text())
    .then(html => {
      // Extract the finder result content (between body tags) and embed it.
      const m = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
      area.innerHTML = m ? m[1] : html;
    })
    .catch(err => {
      area.innerHTML = `<span style="color:var(--bad);">Finder error: ${esc(String(err))}</span>`;
    });
}

function renderPaneC(payload) {
  const rows = payload.rows || [];
  const parts = [];
  if (rows.length === 0) {
    parts.push(`<div class="panel-shell"><div class="empty">No exchange records in this ledger yet.</div></div>`);
    return parts.join("\n");
  }
  parts.push(`<div class="panel-shell"><table>`);
  parts.push(`<thead><tr>
    <th>Exchange key</th>
    <th>Time</th>
    <th>Role</th>
    <th>Header state</th>
    <th>Mine</th>
    <th>Theirs</th>
    <th>Assurance</th>
  </tr></thead><tbody>`);
  for (const row of rows) {
    const key = row.exchange_key || row.exchange_id || "—";
    const ts = (row.timestamp || "").replace("T"," ").replace("Z","");
    const role = row.role || "";
    const headerState = row.header_state || {};
    const mine = row.mine || {};
    const theirs = row.theirs || {};
    const rid = "exc-" + esc(key);
    const roleCls = role === "provider" ? "role-served" : "role-asked";
    const roleLabel = role === "provider" ? "SERVED" : "ASKED";
    parts.push(`<tr class="clickable-row" data-detail="${rid}">`);
    parts.push(`<td class="mono" style="font-size:11px;">${esc(String(key).slice(0,18))}…</td>`);
    parts.push(`<td style="font-size:11.5px;white-space:nowrap;">${esc(ts)}</td>`);
    parts.push(`<td><span class="role-tag ${roleCls}">${roleLabel}</span></td>`);
    parts.push(`<td>${cellHtml(headerState)}</td>`);
    parts.push(`<td>${renderExchangeHalf(mine)}</td>`);
    parts.push(`<td>${renderExchangeHalf(theirs)}</td>`);
    parts.push(`<td>${chipStripHtml(row.assurance_map)}</td>`);
    parts.push(`</tr>`);
    parts.push(`<tr class="detail-row" id="${rid}"><td colspan="7" style="padding:12px 16px;">`);
    parts.push(`<div style="font-size:12px;color:var(--fg-dim);"><strong>Exchange key:</strong> <span class="mono">${esc(key)}</span></div>`);
    parts.push(`</td></tr>`);
  }
  parts.push(`</tbody></table></div>`);
  if (payload.next_after_seq != null) {
    parts.push(`<footer class="note">Showing up to page limit. next_after_seq=${esc(String(payload.next_after_seq))}</footer>`);
  }
  return parts.join("\n");
}

function renderExchangeHalf(half) {
  if (!half) return '<span class="cell-pending">—</span>';
  if (half.state === "pending" || half.state === "absent") {
    return `<span class="cell-pending">${esc(half.text || half.state)}</span>`;
  }
  const text = half.capsule_id
    ? `<span class="mono" style="font-size:11px;">${esc(String(half.capsule_id).slice(0,10))}…</span>`
    : esc(half.text || half.state || "—");
  return text;
}

// ---------------------------------------------------------------------------
// History tab -- four sections from Pane A + B + C
// ---------------------------------------------------------------------------

function loadHistory() {
  _loaded["history"] = true;
  const loading = document.getElementById("history-loading");
  const content = document.getElementById("history-content");
  const errEl = document.getElementById("history-error");

  // Fetch all three panes in parallel
  Promise.all([
    fetch("/accountability/pane-a").then(r => r.json()),
    fetch("/accountability/pane-b").then(r => r.json()),
    fetch("/accountability/pane-c").then(r => r.json()),
  ])
    .then(([paneA, paneB, paneC]) => {
      setVisible(loading, false);
      content.innerHTML = renderHistory(paneA, paneB, paneC);
      setVisible(content, true);
    })
    .catch(err => {
      setVisible(loading, false);
      errEl.textContent = "Failed to load history data: " + err;
      setVisible(errEl, true);
    });
}

function renderHistory(paneA, paneB, paneC) {
  const parts = [];

  // --- Balance section: served/token counts from served_summary_block ---
  parts.push(`<div class="history-section">`);
  parts.push(`<h3>Balance</h3>`);
  const servBlock = paneA.served_summary_block;
  if (!servBlock || servBlock.state === "pending" || servBlock.state === "absent") {
    parts.push(`<div class="panel-shell"><div class="empty cell-pending">${esc(servBlock ? (servBlock.text || servBlock.state) : "No served summary yet")}</div></div>`);
  } else {
    const kvs = [];
    for (const [k, v] of Object.entries(servBlock)) {
      if (k === "state" || k === "text") continue;
      kvs.push(`<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(String(v))}</span></div>`);
    }
    parts.push(`<div class="panel-shell" style="padding:16px;"><div class="history-kv">${kvs.join("")}</div></div>`);
  }
  parts.push(`</div>`);

  // --- Peers section: peer count from Pane B ---
  parts.push(`<div class="history-section">`);
  parts.push(`<h3>Peers</h3>`);
  const peerCount = paneB.peer_count != null ? paneB.peer_count : (paneB.rows || []).length;
  const peerRows = (paneB.rows || []).map(row => {
    const node = row.node_id || row.peer_id || "unknown";
    const rungCell = row.role_and_count || {};
    return `<div class="card-block"><span class="block-label mono">${esc(node)}</span><span>${renderPeerRoleCell(rungCell)}</span></div>`;
  });
  parts.push(`<div class="panel-shell" style="padding:12px 16px;">`);
  parts.push(`<div class="history-kv" style="margin-bottom:12px;"><div class="kv"><span class="k">Total peers</span><span class="v">${esc(String(peerCount))}</span></div></div>`);
  if (peerRows.length) parts.push(peerRows.join(""));
  else parts.push(`<span class="cell-pending">No peers seen yet.</span>`);
  parts.push(`</div></div>`);

  // --- Exchanges section: count + bilateral ratio from Pane C ---
  parts.push(`<div class="history-section">`);
  parts.push(`<h3>Exchanges</h3>`);
  const cRows = paneC.rows || [];
  const rowCount = paneC.row_count != null ? paneC.row_count : cRows.length;
  // bilateral ratio = rows that have BOTH mine and theirs halves
  const bilateralCount = cRows.filter(r => {
    const mine = r.mine || {};
    const theirs = r.theirs || {};
    return mine.state && mine.state !== "absent" && mine.state !== "pending"
        && theirs.state && theirs.state !== "absent" && theirs.state !== "pending";
  }).length;
  const bilateralRatio = rowCount > 0 ? (bilateralCount / rowCount * 100).toFixed(0) + "%" : "—";
  parts.push(`<div class="panel-shell" style="padding:16px;">`);
  parts.push(`<div class="history-kv">`);
  parts.push(`<div class="kv"><span class="k">Total exchanges</span><span class="v">${esc(String(rowCount))}</span></div>`);
  parts.push(`<div class="kv"><span class="k">Bilateral (both halves)</span><span class="v">${esc(String(bilateralCount))}</span></div>`);
  parts.push(`<div class="kv"><span class="k">Bilateral ratio</span><span class="v">${esc(bilateralRatio)}</span></div>`);
  parts.push(`</div></div></div>`);

  // --- Integrity section: history card state from Pane A ---
  parts.push(`<div class="history-section">`);
  parts.push(`<h3>Integrity</h3>`);
  const histBlock = paneA.history_block;
  if (!histBlock || histBlock.state === "pending" || histBlock.state === "absent") {
    parts.push(`<div class="panel-shell"><div class="empty cell-pending">${esc(histBlock ? (histBlock.text || histBlock.state) : "History block not yet computed")}</div></div>`);
  } else {
    const intKvs = [];
    for (const [k, v] of Object.entries(histBlock)) {
      if (k === "state" || k === "text") continue;
      intKvs.push(`<div class="kv"><span class="k">${esc(k)}</span><span class="v" style="font-size:14px;">${esc(String(v))}</span></div>`);
    }
    parts.push(`<div class="panel-shell" style="padding:16px;"><div class="history-kv">${intKvs.join("")}</div></div>`);
  }
  parts.push(`</div>`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Row toggle for expand/collapse
// ---------------------------------------------------------------------------

function attachRowToggle(root) {
  root.querySelectorAll("tr.clickable-row").forEach(row => {
    row.addEventListener("click", function() {
      const detailId = this.dataset.detail;
      if (!detailId) return;
      const detail = document.getElementById(detailId);
      if (!detail) return;
      detail.classList.toggle("open");
    });
  });
}

// ---------------------------------------------------------------------------
// Boot: load the first tab
// ---------------------------------------------------------------------------

loadTab("node");

})();
</script>
</body>
</html>
"""
