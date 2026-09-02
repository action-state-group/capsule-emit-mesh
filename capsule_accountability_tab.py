#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule-accountability-tab -- a dead-simple, self-contained HTML page that
re-skins ONE node's mesh capsule log as an "Accountability" TAB inside
mesh-llm's own dashboard (mesh-llm-ui's dark "control room ledger" look), so
a stranger checking another node's log sees a table they'd recognise, not a
bespoke verifier UI.

Presentation only. Nothing here re-derives evidence that already has a home:

  - log-integrity (``verify_ok``) comes from
    ``capsule_mesh_view.verify_results_for`` / ``_verify_ok_map`` -- the same
    best-effort signed/chained verify ``capsule-mesh view`` already runs;
  - claimed model/hardware comes from ``capsule_mesh_viewer.serving_provenance``
    / ``friendly_model_name``;
  - the cross-party rung comes from ``capsule_sidecar.derive_cross_party_rung``
    / ``identity_limitation_for_rung`` -- the producer's OWN derivation, run
    here exactly as documented. ``has_verified_ack`` (the input that alone
    can reach ``full_bilateral``) is read from the record's own
    ``cross_party.ack_verified`` field, since a ledger-only offline viewer
    has no other evidence of a Move-4 client ack to offer. Real captures
    today never set it, so this tab honestly caps at ``acknowledged_receipt``
    for them -- the same "shown honestly-absent, never hidden" discipline
    the runtime/binding rung below already follows;
  - the in-browser ``capsule_id`` recompute is
    ``mesh_viewer_static/mesh_verify.js``, included byte-for-byte unmodified
    (see ``_load_verify_js``, reused from ``capsule_mesh_viewer``). This page
    never sets ``window.__MESH_FRAGMENT_B64U__`` and never touches
    ``location.hash``, so that file's own ``boot()`` finds no payload and
    returns without touching the DOM; only its exposed
    ``window.__mesh_recomputeCapsuleId`` is used, by this module's own JS.

Deliberately out of scope: no permalink/share chrome, no live fetch, no
network round trip of any kind -- the ledger rows are inlined as plain JSON
in a ``<script>`` tag (not the base64url URL-fragment mechanism, which exists
to keep data out of a request URL; this page has no URL to protect).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from capsule_mesh_view import _poc_block, _verify_ok_map, verify_results_for
from capsule_mesh_viewer import _load_verify_js, friendly_model_name, serving_provenance
from capsule_sidecar import derive_cross_party_rung, identity_limitation_for_rung

try:  # same reader capsule_mesh_view / capsule_mesh_viewer use for their CLIs
    from capsule_emit.ledger import read_ledger
except Exception:  # pragma: no cover - only when capsule-emit isn't installed
    read_ledger = None  # type: ignore[assignment]

__all__ = [
    "build_row",
    "build_tab_payload",
    "cross_party_grade",
    "freshness_grade",
    "log_integrity_grade",
    "measurement_class_grade",
    "render_accountability_tab_html",
]

# The three-state discipline (TRUST-MODEL.md §10 Rule 1), plus an explicit
# fourth for evidence that was checked and came back bad -- "absent" and
# "failed" must never be the same colour: absent means no claim was made,
# failed means a claim was made and did not hold up.
STATE_ABSENT = "absent"
STATE_PRESENT_UNVERIFIED = "present-unverified"
STATE_VERIFIED = "verified"
STATE_FAILED = "failed"


def freshness_grade(client_nonce_source: str | None) -> dict[str, Any]:
    """Rung 1 -- freshness/anti-replay (capsule_sidecar.py's nonce-source ladder).

    ``client_supplied`` is the only state this tool calls verified: a fresh,
    client-contributed nonce the node did not mint itself. A DETECTED replay
    (``client_supplied_replayed``) is an honest FAILURE, never folded into
    "present-unverified" -- the node saying "I saw a replay" is worse than
    the node saying nothing about freshness at all, and must render that way.
    """
    if client_nonce_source == "client_supplied":
        state = STATE_VERIFIED
    elif client_nonce_source == "client_supplied_replayed":
        state = STATE_FAILED
    elif client_nonce_source in ("sidecar_generated_fallback", "local_ingress"):
        state = STATE_PRESENT_UNVERIFIED
    else:
        state = STATE_ABSENT
    return {"state": state, "client_nonce_source": client_nonce_source}


def cross_party_grade(poc: dict[str, Any]) -> dict[str, Any]:
    """Rung 2 -- cross-party mutuality, via the producer's OWN
    ``derive_cross_party_rung`` (never re-implemented here).

    ``unilateral_fallback < acknowledged_receipt < full_bilateral``. The
    caveat text is always RE-DERIVED from the resulting rung via
    ``identity_limitation_for_rung`` -- never read from whatever the record's
    own ``identity_limitation`` field happens to say -- so a record whose
    ``cross_party`` block was stripped or tampered can never keep a
    full_bilateral caveat it no longer supports.
    """
    cross_party = poc.get("cross_party")
    has_verified_ack = bool(cross_party and cross_party.get("ack_verified"))
    rung = derive_cross_party_rung(cross_party, has_verified_ack=has_verified_ack)
    return {"rung": rung, "identity_limitation": identity_limitation_for_rung(rung)}


def measurement_class_grade(poc: dict[str, Any]) -> dict[str, Any]:
    """Rung 3 -- runtime/binding, graded self_measured < os_measured < tee_measured.

    Every record the Python sidecar emits today carries no
    ``binary_attestation`` at all (that evidence is Rust-producer-only) --
    this renders "absent" for those records, never a fabricated default and
    never hidden from the table.
    """
    evidence_refs = poc.get("evidence_refs") or {}
    binary_class = (evidence_refs.get("binary_attestation") or {}).get("measurement_class")
    tee_class = (evidence_refs.get("tee_attestation") or {}).get("measurement_class")
    if tee_class == "tee_measured":
        state = "tee_measured"
    elif binary_class in ("os_measured", "self_measured"):
        state = binary_class
    else:
        state = STATE_ABSENT
    return {"state": state}


def log_integrity_grade(verify_ok: bool | None, has_witness_checkpoint: bool) -> dict[str, Any]:
    """Rung 4 -- log integrity: signed/chained verify + whether a witness
    checkpoint was supplied to THIS view (a property of the view, not of the
    record -- never derived from record bytes)."""
    if verify_ok is True:
        state = STATE_VERIFIED
    elif verify_ok is False:
        state = STATE_FAILED
    else:
        state = STATE_PRESENT_UNVERIFIED
    return {"state": state, "witness_checkpoint_supplied": bool(has_witness_checkpoint)}


def build_row(record: dict[str, Any], *, verify_ok: bool | None, has_witness_checkpoint: bool) -> dict[str, Any]:
    """One exchange row: claimed model/hardware + when, the rung detail that
    backs the row's expand panel, and the record itself (so the browser can
    recompute ``capsule_id`` live -- the row never trusts a Python-side claim
    of "matches" without the client re-deriving it)."""
    poc = _poc_block(record)
    sp = serving_provenance(record)
    hardware_bits = [b for b in (sp.get("gpu"), "SoC" if sp.get("is_soc") else None) if b]
    return {
        "capsule_id": record.get("capsule_id", ""),
        "timestamp": record.get("timestamp"),
        "model_claimed": friendly_model_name(sp),
        "hardware_claimed": ", ".join(hardware_bits) if hardware_bits else None,
        "verify_ok": verify_ok,
        "rungs": {
            "freshness": freshness_grade(poc.get("client_nonce_source")),
            "cross_party": cross_party_grade(poc),
            "runtime_binding": measurement_class_grade(poc),
            "log_integrity": log_integrity_grade(verify_ok, has_witness_checkpoint),
        },
        "record": record,
    }


def build_tab_payload(
    records: list[dict[str, Any]],
    *,
    ledger_dir: Path | None = None,
    witness_checkpoint: dict[str, Any] | None = None,
    operator: str | None = None,
) -> dict[str, Any]:
    """Assemble the whole tab's payload for one node's log."""
    verify_results = verify_results_for(records, ledger_dir=ledger_dir)
    vmap = _verify_ok_map(records, verify_results)
    has_witness = witness_checkpoint is not None
    rows = [
        build_row(record, verify_ok=vmap.get(record.get("capsule_id", "")), has_witness_checkpoint=has_witness)
        for record in records
    ]
    rows.sort(key=lambda row: row.get("timestamp") or "")
    return {
        "operator": operator or (records[0].get("operator") if records else None),
        "witness_checkpoint_supplied": has_witness,
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# The self-contained HTML shell. Styled to mimic mesh-llm-ui's dark "control
# room ledger" look (DESIGN.md / src/styles/globals.css): flat bordered
# panels, one accent colour used sparingly, Inter-Tight-first type with a
# monospace stack for machine values -- approximated with system font
# fallbacks only, so nothing here ever fetches a font over the network.
# ---------------------------------------------------------------------------


def render_accountability_tab_html(payload: dict[str, Any]) -> str:
    """Return the self-contained Accountability-tab HTML for *payload*.

    Offline, no fetch: the row data is inlined as plain JSON (there is no
    URL to protect here, unlike the fragment-carried permalink viewer), and
    ``mesh_verify.js`` is inlined byte-for-byte unmodified purely for its
    ``window.__mesh_recomputeCapsuleId`` export.
    """
    verify_js = _load_verify_js()
    shell = _HTML_SHELL.replace("@@VERIFY_JS@@", verify_js)
    if "@@PAYLOAD@@" not in shell or shell.count("@@PAYLOAD@@") != 1:
        raise RuntimeError(
            "embed invariant broken: exactly one @@PAYLOAD@@ placeholder must "
            f"exist in the shell, found {shell.count('@@PAYLOAD@@')}"
        )
    # Escape "<" so a hostile string value (e.g. a crafted hostname/model ref
    # in an untrusted record) can never break out of the <script> tag it's
    # embedded in.
    payload_json = json.dumps(payload, separators=(",", ":")).replace("<", "\\u003c")
    return shell.replace("@@PAYLOAD@@", payload_json)


_HTML_SHELL = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mesh-llm · Accountability</title>
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
  }
  .brand { font-weight: 700; font-size: 14px; letter-spacing: 0.01em; }
  .brand .dim { color: var(--fg-faint); font-weight: 500; }
  nav.tabs { display: inline-flex; gap: 2px; background: var(--bg); border-radius: 8px; padding: 3px; }
  nav.tabs a {
    padding: 5px 12px; border-radius: 6px; font-size: 12.5px; font-weight: 600;
    color: var(--fg-faint); text-decoration: none; cursor: default;
  }
  nav.tabs a.active { background: var(--panel-strong); color: var(--fg); box-shadow: 0 1px 0 var(--border-soft); }
  main { max-width: 1080px; margin: 0 auto; padding: 20px 16px 40px; }
  h1.type-headline { font-size: 16.5px; font-weight: 700; margin: 0 0 4px; }
  p.type-caption { color: var(--fg-dim); font-size: 12px; margin: 0 0 18px; }
  .panel-shell { border: 1px solid var(--border); border-radius: 10px; background: var(--panel); overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.07em; color: var(--fg-faint); background: var(--panel-strong);
    padding: 9px 12px; border-bottom: 1px solid var(--border);
  }
  tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
  tbody tr.row { cursor: pointer; }
  tbody tr.row:hover { background: var(--panel-strong); }
  tbody tr.detail-row { display: none; background: var(--bg); }
  tbody tr.detail-row.open { display: table-row; }
  .pill {
    display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px;
    border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap;
  }
  .pill-good { color: var(--good); background: color-mix(in oklab, var(--good) 14%, transparent); border: 1px solid color-mix(in oklab, var(--good) 40%, transparent); }
  .pill-warn { color: var(--warn); background: color-mix(in oklab, var(--warn) 14%, transparent); border: 1px solid color-mix(in oklab, var(--warn) 40%, transparent); }
  .pill-bad { color: var(--bad); background: color-mix(in oklab, var(--bad) 14%, transparent); border: 1px solid color-mix(in oklab, var(--bad) 40%, transparent); }
  .pill-neutral { color: var(--fg-dim); background: color-mix(in oklab, var(--fg-dim) 10%, transparent); border: 1px solid var(--border-soft); }
  .rung-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; padding: 14px 16px 18px; }
  .rung-card { border: 1px solid var(--border-soft); border-radius: 8px; padding: 10px 12px; background: var(--panel); }
  .rung-card .label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--fg-faint); margin-bottom: 6px; }
  .rung-card .caveat { margin-top: 6px; font-size: 12px; color: var(--fg-dim); }
  .empty { padding: 30px; text-align: center; color: var(--fg-faint); }
  footer.note { margin-top: 14px; font-size: 12px; color: var(--fg-faint); }
</style>
</head>
<body>
  <header class="topbar">
    <div class="brand">mesh-llm <span class="dim">/ node dashboard</span></div>
    <nav class="tabs">
      <a>Overview</a>
      <a>Network</a>
      <a class="active">Accountability</a>
      <a>Settings</a>
    </nav>
  </header>
  <main>
    <h1 class="type-headline">Accountability</h1>
    <p class="type-caption" data-meta>loading…</p>
    <div class="panel-shell">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Model claimed</th>
            <th>Hardware claimed</th>
            <th>Checked</th>
          </tr>
        </thead>
        <tbody data-rows></tbody>
      </table>
      <div class="empty" data-empty hidden>No exchanges in this log.</div>
    </div>
    <footer class="note" data-foot></footer>
  </main>
<script>window.__ACCOUNTABILITY_PAYLOAD__ = @@PAYLOAD@@;</script>
<script>
@@VERIFY_JS@@
</script>
<script>
(function () {
  "use strict";

  // Never rounds up: "verified" requires BOTH the browser's own capsule_id
  // recompute to match AND the server-side signed/chained verify to have
  // passed. Any other combination is an honest "present-unverified" or an
  // explicit "failed" -- it is never silently collapsed into the other.
  async function checkedFor(row) {
    var idMatches = null;
    try {
      var recomputed = await window.__mesh_recomputeCapsuleId(row.record);
      idMatches = recomputed === row.capsule_id;
    } catch (e) {
      idMatches = null;
    }
    if (idMatches === false) {
      return { state: "failed", text: "capsule_id does not recompute from this record" };
    }
    if (row.verify_ok === false) {
      return { state: "failed", text: "signed/chained verify failed" };
    }
    if (idMatches === true && row.verify_ok === true) {
      return { state: "verified", text: "capsule_id recomputes + signature verifies offline" };
    }
    return { state: "present-unverified", text: "present — not independently verified" };
  }

  var TONE = {
    absent: "neutral", unilateral_fallback: "neutral",
    "present-unverified": "warn", acknowledged_receipt: "warn",
    self_measured: "warn", os_measured: "warn",
    verified: "good", full_bilateral: "good", tee_measured: "good",
    failed: "bad"
  };

  function pill(state, text) {
    var tone = TONE[state] || "neutral";
    var span = document.createElement("span");
    span.className = "pill pill-" + tone;
    span.textContent = text || state;
    return span;
  }

  function rungCard(label, state, text, caveat) {
    var card = document.createElement("div");
    card.className = "rung-card";
    var lab = document.createElement("div");
    lab.className = "label";
    lab.textContent = label;
    card.appendChild(lab);
    card.appendChild(pill(state, text || state));
    if (caveat) {
      var cav = document.createElement("div");
      cav.className = "caveat";
      cav.textContent = caveat;
      card.appendChild(cav);
    }
    return card;
  }

  async function renderRow(row, tbody) {
    var tr = document.createElement("tr");
    tr.className = "row";

    var tdTime = document.createElement("td");
    tdTime.className = "mono";
    tdTime.textContent = row.timestamp || "—";
    tr.appendChild(tdTime);

    var tdModel = document.createElement("td");
    tdModel.textContent = row.model_claimed || "—";
    tr.appendChild(tdModel);

    var tdHw = document.createElement("td");
    tdHw.textContent = row.hardware_claimed || "—";
    tr.appendChild(tdHw);

    var tdChecked = document.createElement("td");
    var checked = await checkedFor(row);
    tdChecked.appendChild(pill(checked.state, checked.state === "verified" ? "checked" : checked.state === "failed" ? "failed" : "unverified"));
    tr.appendChild(tdChecked);

    var detailTr = document.createElement("tr");
    detailTr.className = "detail-row";
    var detailTd = document.createElement("td");
    detailTd.colSpan = 4;
    var grid = document.createElement("div");
    grid.className = "rung-grid";
    var r = row.rungs || {};
    if (r.freshness) {
      grid.appendChild(rungCard("Freshness", r.freshness.state, r.freshness.client_nonce_source || r.freshness.state));
    }
    if (r.cross_party) {
      grid.appendChild(rungCard("Cross-party", r.cross_party.rung, r.cross_party.rung, r.cross_party.identity_limitation));
    }
    if (r.runtime_binding) {
      grid.appendChild(rungCard("Runtime / binding", r.runtime_binding.state, r.runtime_binding.state));
    }
    if (r.log_integrity) {
      var liText = r.log_integrity.state + (r.log_integrity.witness_checkpoint_supplied ? " · witness checkpoint supplied" : " · no witness checkpoint");
      grid.appendChild(rungCard("Log integrity", r.log_integrity.state, liText));
    }
    grid.appendChild(rungCard("capsule_id", checked.state, checked.text));
    detailTd.appendChild(grid);
    detailTr.appendChild(detailTd);

    tr.addEventListener("click", function () {
      detailTr.classList.toggle("open");
    });

    tbody.appendChild(tr);
    tbody.appendChild(detailTr);
  }

  function el(sel) { return document.querySelector(sel); }

  async function boot() {
    var payload = window.__ACCOUNTABILITY_PAYLOAD__;
    var meta = el("[data-meta]");
    var tbody = el("[data-rows]");
    if (!payload || !payload.rows || !payload.rows.length) {
      meta.textContent = "no exchanges";
      el("[data-empty]").hidden = false;
      return;
    }
    meta.textContent =
      (payload.operator ? "operator " + payload.operator + " · " : "") +
      payload.rows.length + " exchange(s)" +
      (payload.witness_checkpoint_supplied ? " · witness checkpoint supplied" : " · no witness checkpoint supplied");
    for (var i = 0; i < payload.rows.length; i++) {
      await renderRow(payload.rows[i], tbody);
    }
    el("[data-foot]").textContent =
      "Checked = this browser recomputed capsule_id from the record itself and the log's own signature/chain verified. " +
      "Click a row for the rung detail behind it.";
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
</script>
</body>
</html>
"""


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
    if not records:
        print(f"capsule-accountability-tab: no records in {args.ledger}", file=sys.stderr)
        return 1
    witness = _read_first_json(args.witness) if args.witness else None
    payload = build_tab_payload(
        records,
        ledger_dir=Path(args.ledger).resolve().parent,
        witness_checkpoint=witness,
        operator=args.operator,
    )
    html = render_accountability_tab_html(payload)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    n_witness = "with witness checkpoint" if witness else "no witness checkpoint"
    print(f"accountability tab: {len(records)} exchange(s), {n_witness} -> {args.out}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule-accountability-tab",
        description="Render one node's mesh capsule log as a dead-simple, self-contained "
        "'Accountability' tab styled to match mesh-llm-ui's own dashboard.",
    )
    parser.add_argument("--ledger", required=True, metavar="PATH", help="mesh capsule JSONL ledger")
    parser.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    parser.add_argument("--witness", metavar="PATH", default=None, help="optional COSE checkpoint receipt (json/jsonl)")
    parser.add_argument("--operator", default=None, help="operator label for the view header")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return _cmd_html(args)


if __name__ == "__main__":
    raise SystemExit(main())
