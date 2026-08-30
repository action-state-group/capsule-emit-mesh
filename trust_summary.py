# SPDX-License-Identifier: Apache-2.0
"""trust-summary -- a WHOLE-HISTORY trust summary over a mesh capsule ledger.

Where ``capsule_mesh_viewer`` renders ONE exchange per card (the words-first
role/question view), this module answers the different question Steven's
trust-dashboard design asks: *across everything this node has sent as a
requester and served as a provider, what is the earned trust?* It is a thin
SUMMARY layer over the same neutral core -- it re-uses, never re-forks:

  * ``serving_provenance`` / ``friendly_model_name`` / ``plain_model_line``
    -- the field extraction + human model naming (imported from
    ``capsule_mesh_viewer``);
  * ``verify_results_for`` / ``_verify_ok_map`` / ``label_role`` /
    ``label_counterparty`` -- the per-record verify + display labels
    (imported from ``capsule_mesh_view``);
  * ``served_facts_digest`` -- the same served-facts (``response_digest``)
    recompute the viewer uses;
  * ``mesh_verify.js`` -- the SAME in-browser ``capsule_id`` recompute core
    the single-exchange viewer ships. The permalink this module renders
    inlines that exact file and calls its exported
    ``window.__mesh_recomputeCapsuleId`` -- the trust value is never
    hand-ported a second time, it is re-derived in the browser from the
    record itself, so a forged co-carried chip/level is caught here.

The shared data model is ``TrustSummary`` (see ``build_trust_summary``):

    TrustSummary = {
      "view_version": "trust-summary-1",
      "operator": str | None,
      "node_id": str | None,          # this node's served_by_node_id, when one
      "source_log": "plugin" | "sidecar",
      "exchanges": [ Exchange, ... ], # the whole history, newest first
      "gradient": Gradient,           # the earned-trust headline
      "honest_gaps": [ str, ... ],    # never a fake all-green
      "witness": WitnessSummary | None,
      "entries": [ ViewerEntry, ... ],# the viewer's own entries, so the SAME
                                      #   page can recompute each capsule_id
    }

    Exchange = {
      "capsule_id": str,
      "timestamp": str | None,
      "direction": "sent" | "served",   # requester (sent) vs provider (served)
      "counterparty": str,              # node/initiator label, or "unknown"
      "friendly_model": str,            # "Llama-3B · Q4_K_M", never a raw hash
      "settings": str,                  # "temp 0.0 · seed …", meter-not-price
      "tokens_in": int | None,
      "tokens_out": int | None,
      "chip": {"kind": "...", "mark": "✓|⚠|◷", "label": "..."},
      "evidence_capsule_id": str,       # link target: the exchange's capsule_id
    }

    Gradient = {
      "level": "unknown" | "earned-over-N" | "anchored",
      "level_label": str,               # the headline sentence
      "n_verifiable": int,              # exchanges whose capsule_id verifies
      "n_exchanges": int,
      "n_verified_in_browser": int,     # ✓ chips (offline-recomputable)
      "n_self_attested": int,           # ⚠ chips
      "n_witnessed": int,               # ◷ chips (anchored)
      "anchored": bool,
    }

Neutral / meter-not-price: the summary counts input/output tokens and names
settings, and carries NO currency, price, or rate -- the same boundary
``TRUST-MODEL.md §12.4`` holds ("the record counts, it does not price").
"""
from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from typing import Any

# Re-use the neutral single-exchange core -- field extraction, human naming,
# the served-facts digest, the fragment codec, and the viewer entry builder.
# NOTHING here re-implements any of it.
from capsule_mesh_viewer import (
    encode_fragment,
    friendly_model_name,
    serving_provenance,
    to_fragment_payload,
)

# Verify + the display-only role/counterparty labels live in capsule_mesh_view.
from capsule_mesh_view import (
    SOURCE_PLUGIN,
    SOURCE_SIDECAR,
    _verify_ok_map,
    label_counterparty,
    label_role,
    verify_results_for,
)

try:  # the same reader the viewer CLI uses
    from capsule_emit.ledger import read_ledger
except Exception:  # pragma: no cover - only when capsule-emit isn't installed
    read_ledger = None  # type: ignore[assignment]

__all__ = [
    "exchange_chip",
    "build_exchange",
    "compute_gradient",
    "honest_gaps",
    "build_trust_summary",
    "render_trust_summary_html",
    "GRADIENT_UNKNOWN",
    "GRADIENT_EARNED",
    "GRADIENT_ANCHORED",
]

# ---------------------------------------------------------------------------
# The earned-trust gradient levels (TRUST-MODEL.md §12): trust "starts at
# unknown, climbs on evidence each party can check for itself, and rests at the
# top on an anchor no party -- including us -- controls the outcome of."
#   unknown       -- first contact / nothing offline-verifiable yet.
#   earned-over-N -- an accruing set of offline-verifiable records: a real,
#                    portable track record (§12.2) -- but not yet witnessed.
#   anchored      -- the same, plus a public witness checkpoint the node does
#                    not control (§8): tamper-evident, third-party-checkable.
# ---------------------------------------------------------------------------
GRADIENT_UNKNOWN = "unknown"
GRADIENT_EARNED = "earned-over-N"
GRADIENT_ANCHORED = "anchored"


# ---------------------------------------------------------------------------
# Per-exchange trust chip -- the compact BOTH-halves signal the design asks
# for, sitting on each row (the gradient level is the headline, above).
#
#   ✓ verified-in-browser -- this record's capsule_id + served facts recompute
#                            here, offline, from the record itself.
#   ◷ witnessed           -- a public witness checkpoint covering this log was
#                            supplied: anchored, tamper-evident.
#   ⚠ self-attested       -- the honest default: the provider's signed claim,
#                            no offline recompute confirmed / no witness in
#                            this view. Never a fake green.
# ---------------------------------------------------------------------------
def exchange_chip(*, verify_ok: bool | None, has_witness_checkpoint: bool) -> dict[str, str]:
    """The per-exchange chip. ``◷ witnessed`` supersedes ``✓`` only when a
    witness checkpoint anchors the log AND the record itself verifies -- an
    anchor over a record that does not recompute is not a green.
    """
    if has_witness_checkpoint and verify_ok is True:
        return {"kind": "witnessed", "mark": "◷", "label": "witnessed (anchored)"}
    if verify_ok is True:
        return {"kind": "verified", "mark": "✓", "label": "verified in browser"}
    if verify_ok is False:
        return {"kind": "failed", "mark": "✗", "label": "verify FAILED"}
    return {"kind": "self_attested", "mark": "⚠", "label": "self-attested"}


def _settings_line(sp: dict[str, Any], record: dict[str, Any]) -> str:
    """A neutral one-line settings summary -- generation params only, never a
    price or currency. Reads temperature/seed/top_p from the record's
    generation_parameters when present, else says so honestly.
    """
    poc = (
        record.get("model_attestation", {})
        .get("compute_attestation", {})
        .get("x-mesh-poc-v1", {})
        or {}
    )
    gp = poc.get("generation_parameters") or {}
    bits: list[str] = []
    if gp.get("temperature") is not None:
        bits.append(f"temp {gp['temperature']}")
    if gp.get("seed") is not None:
        bits.append(f"seed {gp['seed']}")
    if gp.get("top_p") is not None:
        bits.append(f"top_p {gp['top_p']}")
    if sp.get("quantization") and sp["quantization"] != "unknown":
        bits.append(str(sp["quantization"]))
    return " · ".join(bits) if bits else "settings not in record"


def build_exchange(
    record: dict[str, Any],
    *,
    source_log: str,
    verify_ok: bool | None,
    has_witness_checkpoint: bool,
) -> dict[str, Any]:
    """One row of the whole-history summary for a single capsule.

    ``direction`` is the viewer's own ``label_role`` mapped to the design's
    vocabulary (served -> the node was the provider; requested -> the node
    sent the request). ``counterparty`` and the friendly model name are the
    SAME labels the single-exchange viewer shows -- re-used, not re-derived.
    """
    sp = serving_provenance(record)
    role = label_role(record, source_log)  # "served" | "requested" | "unknown"
    direction = "served" if role == "served" else ("sent" if role == "requested" else role)
    return {
        "capsule_id": record.get("capsule_id", ""),
        "timestamp": record.get("timestamp"),
        "direction": direction,
        "counterparty": label_counterparty(record),
        "friendly_model": friendly_model_name(sp),
        "settings": _settings_line(sp, record),
        "tokens_in": sp.get("prompt_tokens"),
        "tokens_out": sp.get("completion_tokens"),
        "node_id": sp.get("served_by_node_id"),
        "chip": exchange_chip(verify_ok=verify_ok, has_witness_checkpoint=has_witness_checkpoint),
        "evidence_capsule_id": record.get("capsule_id", ""),
    }


def compute_gradient(exchanges: list[dict[str, Any]], *, anchored: bool) -> dict[str, Any]:
    """The earned-trust HEADLINE over the whole history.

    ``n_verifiable`` counts exchanges whose chip is ✓ (verified-in-browser) or
    ◷ (witnessed) -- the offline-checkable ones. The level:
      * ``anchored``      when a witness checkpoint anchors the log AND at
                          least one exchange verifies -- the top rung.
      * ``earned-over-N`` when >=1 exchange is offline-verifiable but no
                          witness rides along -- a real, portable track record,
                          not yet tamper-evident.
      * ``unknown``       when nothing is offline-verifiable yet (first contact
                          / verify unavailable) -- the honest floor.
    """
    n = len(exchanges)
    n_verified = sum(1 for e in exchanges if e["chip"]["kind"] == "verified")
    n_witnessed = sum(1 for e in exchanges if e["chip"]["kind"] == "witnessed")
    n_self = sum(1 for e in exchanges if e["chip"]["kind"] == "self_attested")
    n_verifiable = n_verified + n_witnessed

    if anchored and n_witnessed > 0:
        level = GRADIENT_ANCHORED
        label = (
            f"Anchored — {n_witnessed} of {n} exchange(s) witnessed to a public checkpoint "
            "this node does not control, and offline-verifiable here. Tamper-evident."
        )
    elif n_verifiable > 0:
        level = GRADIENT_EARNED
        label = (
            f"Earned over {n_verifiable} exchange(s) — a portable track record you can recompute "
            "in this browser. Not yet witnessed to a public checkpoint (no anchor in this view)."
        )
    else:
        level = GRADIENT_UNKNOWN
        label = (
            "Unknown — no exchange in this view is offline-verifiable yet. "
            "Trust starts at unknown and climbs on evidence."
        )

    return {
        "level": level,
        "level_label": label,
        "n_exchanges": n,
        "n_verifiable": n_verifiable,
        "n_verified_in_browser": n_verified,
        "n_witnessed": n_witnessed,
        "n_self_attested": n_self,
        "anchored": bool(anchored and n_witnessed > 0),
    }


def honest_gaps(exchanges: list[dict[str, Any]], gradient: dict[str, Any]) -> list[str]:
    """The honest-gaps line(s) -- what this summary CANNOT prove, said out loud
    (TRUST-MODEL.md §0/§12.6: a record that shows what it cannot prove is worth
    more than one that hides the gap). Never a fake all-green.
    """
    gaps: list[str] = []
    n_unknown_cp = sum(1 for e in exchanges if e["counterparty"] == "unknown")
    if n_unknown_cp:
        gaps.append(
            f"Who asked is self-attested on {n_unknown_cp} of {len(exchanges)} exchange(s) "
            "(no bilateral counterparty attestation) — identity is not proven."
        )
    if not gradient["anchored"]:
        gaps.append(
            "No public-witness checkpoint in this view — the record is provider-signed and "
            "offline-verifiable, but not yet anchored (not tamper-evident against equivocation)."
        )
    if gradient["n_self_attested"]:
        gaps.append(
            f"{gradient['n_self_attested']} exchange(s) are self-attested only — the provider's "
            "signed claim, not confirmed by an in-browser recompute in this view."
        )
    # Constant honest gaps that hold for every mesh capsule today.
    gaps.append(
        "Hardware identity is not hardware-rooted (no TEE attestation); the signing key is "
        "self-attested, not rooted to a manufacturer."
    )
    gaps.append(
        "This is a metered history (input/output tokens), not a priced one — it carries no "
        "currency or rate by design."
    )
    return gaps


def _resolve_issuer_key(ledger_dir: Any, issuer_key: Any) -> Any:
    """Resolve the PEM pubkey that verifies the detached
    ``signed-statements/<capsule_id>.cose`` producer signatures.

    ``capsule_mesh_view._issuer_key_for`` defaults to
    ``<ledger_dir>/../keys/node-key.pub.pem`` (the stranger-verify convention).
    Real mesh demo ledgers also keep the pubkey ALONGSIDE the log
    (``<ledger_dir>/node-key.pub.pem`` -- e.g. the 2-way demo ledger), so try
    that as a fallback before giving up. Returns a path (str) or None; never
    fabricates one.
    """
    if issuer_key is not None:
        return issuer_key
    if ledger_dir is None:
        return None
    import os

    beside = os.path.join(str(ledger_dir), "node-key.pub.pem")
    if os.path.exists(beside):
        return beside
    return None  # let verify_results_for fall back to its own ../keys lookup


def build_trust_summary(
    records: list[dict[str, Any]],
    *,
    source_log: str = SOURCE_SIDECAR,
    witness_checkpoint: dict[str, Any] | None = None,
    operator: str | None = None,
    ledger_dir: Any = None,
    issuer_key: Any = None,
    disclose: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the shared ``TrustSummary`` model over a WHOLE ledger.

    Verify runs once (``verify_results_for``) and feeds BOTH the per-exchange
    chips and the gradient. The viewer's own ``to_fragment_payload`` builds the
    ``entries`` (each carrying its full ``record``) so the SAME permalink can
    recompute every ``capsule_id`` in-browser -- the trust values are never
    trusted as co-carried, they are re-derived. Exchanges are newest-first.
    """
    from pathlib import Path as _Path

    resolved_key = _resolve_issuer_key(ledger_dir, issuer_key)
    try:
        verify_results = verify_results_for(
            records,
            ledger_dir=_Path(ledger_dir) if ledger_dir is not None else None,
            issuer_key=_Path(resolved_key) if resolved_key is not None else None,
        )
    except TypeError:  # pragma: no cover - older signature
        verify_results = verify_results_for(records)
    vmap = _verify_ok_map(records, verify_results)
    has_witness = witness_checkpoint is not None

    exchanges: list[dict[str, Any]] = []
    node_id: str | None = None
    for rec in records:
        cid = rec.get("capsule_id", "")
        ex = build_exchange(
            rec,
            source_log=source_log,
            verify_ok=vmap.get(cid),
            has_witness_checkpoint=has_witness,
        )
        node_id = node_id or ex.get("node_id")
        exchanges.append(ex)

    # Newest-first, so the most recent activity leads the history.
    exchanges.sort(key=lambda e: e.get("timestamp") or "", reverse=True)

    gradient = compute_gradient(exchanges, anchored=has_witness)
    gaps = honest_gaps(exchanges, gradient)

    # Re-use the viewer's own payload builder for the entries + witness summary,
    # so the recompute-in-browser core has exactly the shape it already reads.
    viewer_payload = to_fragment_payload(
        records,
        source_log=source_log,
        witness_checkpoint=witness_checkpoint,
        disclose=disclose,
        operator=operator,
        ledger_dir=ledger_dir,
    )

    return {
        "view_version": "trust-summary-1",
        "operator": operator or (records[0].get("operator") if records else None),
        "node_id": node_id,
        "source_log": source_log,
        "exchanges": exchanges,
        "gradient": gradient,
        "honest_gaps": gaps,
        "witness": viewer_payload.get("witness"),
        # The viewer entries travel too, so the SAME page recomputes each
        # capsule_id in-browser (the forged-value guard) using mesh_verify.js.
        "entries": viewer_payload.get("entries", []),
    }


# ---------------------------------------------------------------------------
# The self-contained, offline permalink. Carries NO capsule data outside the
# fragment; inlines the EXACT mesh_verify.js recompute core; renders the
# gradient headline, the exchange list with chips, and the honest gaps.
# ---------------------------------------------------------------------------


def _load_verify_js() -> str:
    return (
        resources.files("mesh_viewer_static")
        .joinpath("mesh_verify.js")
        .read_text(encoding="utf-8")
    )


def render_trust_summary_html(fragment: str) -> str:
    """Return the self-contained trust-summary HTML for *fragment*.

    Open it as ``<file>#<fragment>``. No external references, no server, no
    network: the page reads the fragment, renders the gradient headline + the
    exchange rows + honest gaps, and RE-DERIVES every ``capsule_id`` in-browser
    by calling ``mesh_verify.js``'s exported ``__mesh_recomputeCapsuleId`` over
    each entry's own record -- a forged co-carried chip/level is caught here.
    """
    verify_js = _load_verify_js()
    embed = json.dumps(fragment)  # a JSON string literal "<base64url>"
    shell = _HTML_SHELL.replace("@@VERIFY_JS@@", verify_js)
    if shell.count("@@FRAGMENT@@") != 1:
        raise RuntimeError(
            "embed invariant broken: exactly one @@FRAGMENT@@ placeholder must exist, "
            f"found {shell.count('@@FRAGMENT@@')}"
        )
    html = shell.replace("@@FRAGMENT@@", embed)
    # Belt-and-suspenders: the base64 must appear only in the placeholder
    # assignment, never leaked into a boot-guard comparison (the .bak bug).
    if fragment and (f'!== "{fragment}"' in html or f"!=='{fragment}'" in html):
        raise RuntimeError("embed invariant broken: fragment leaked into a guard condition")
    return html


_HTML_SHELL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trust summary — this node's whole history</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background:#F4F4F0; color:#161B25; font-family:system-ui,-apple-system,sans-serif; -webkit-font-smoothing:antialiased; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .wrap { max-width:960px; margin:0 auto; padding:40px 28px 90px; }
  .share { display:flex; justify-content:space-between; align-items:center; gap:12px; font-size:11px; color:#5C6573; margin-bottom:10px; flex-wrap:wrap; }
  .share button { font:inherit; font-size:11px; background:none; border:none; color:#3A5BD9; cursor:pointer; padding:0; font-family:ui-monospace,monospace; }
  .disclosure { font-size:12px; color:#5C6573; line-height:1.6; border-left:2px solid #3A5BD9; padding-left:12px; margin-bottom:22px; }
  h1 { font-size:30px; letter-spacing:-1px; color:#0B0E14; margin-bottom:6px; }
  h1 em { color:#3A5BD9; font-style:normal; }
  .sub { font-size:14px; color:#5C6573; margin-bottom:8px; }
  .meta { font-size:11px; color:#5C6573; margin-bottom:26px; }
  .empty { background:#FCFCFA; border:1px solid #E3E3DC; border-radius:16px; padding:60px 30px; text-align:center; color:#5C6573; }
  /* The earned-gradient HEADLINE. */
  .gradient { border-radius:16px; padding:22px 24px; margin-bottom:22px; border:1px solid #E3E3DC; background:#FCFCFA; }
  .grad-level { display:inline-flex; align-items:center; gap:8px; font-size:12px; text-transform:uppercase; letter-spacing:1.4px; font-weight:700; padding:4px 12px; border-radius:100px; margin-bottom:12px; }
  .grad-level.anchored { color:#127A52; background:#E6F2EC; border:1px solid #B8DCC9; }
  .grad-level.earned   { color:#3A5BD9; background:#E9EDFB; border:1px solid #C6D2F5; }
  .grad-level.unknown  { color:#7A6355; background:#F1F1EC; border:1px solid #E3DDD4; }
  .grad-label { font-size:17px; line-height:1.5; color:#0B0E14; }
  .grad-counts { display:flex; gap:16px; flex-wrap:wrap; margin-top:14px; }
  .grad-counts .c { font-size:12px; color:#5C6573; }
  .grad-counts .c b { color:#161B25; font-weight:600; font-variant-numeric:tabular-nums; }
  /* The exchange list. */
  .ex-head { font-size:13px; text-transform:uppercase; letter-spacing:1.2px; color:#5C6573; font-weight:600; margin:8px 2px 12px; }
  .ex { background:#FCFCFA; border:1px solid #E3E3DC; border-radius:14px; padding:15px 18px; margin-bottom:12px; display:flex; align-items:flex-start; gap:14px; flex-wrap:wrap; }
  .ex-dir { flex:0 0 auto; font-size:10px; text-transform:uppercase; letter-spacing:1px; padding:3px 10px; border-radius:100px; font-weight:700; }
  .ex-dir.served { color:#127A52; background:#E6F2EC; border:1px solid #B8DCC9; }
  .ex-dir.sent   { color:#3A5BD9; background:#E9EDFB; border:1px solid #C6D2F5; }
  .ex-dir.unknown{ color:#7A6355; background:#F1F1EC; border:1px solid #E3DDD4; }
  .ex-body { flex:1 1 320px; min-width:240px; }
  .ex-model { font-size:15px; color:#0B0E14; font-weight:600; }
  .ex-meta { font-size:12px; color:#5C6573; margin-top:3px; line-height:1.5; }
  .ex-meta .mono { font-size:11px; }
  .ex-right { flex:0 0 auto; display:flex; flex-direction:column; align-items:flex-end; gap:6px; }
  .chip { display:inline-flex; align-items:center; gap:5px; font-size:11px; border-radius:100px; padding:3px 11px; border:1px solid #E3E3DC; white-space:nowrap; }
  .chip.verified  { color:#127A52; border-color:#B8DCC9; background:#E6F2EC; }
  .chip.witnessed { color:#0B5F86; border-color:#B7D8E8; background:#E4F1F7; }
  .chip.self_attested { color:#9A6B12; border-color:#EBD9AE; background:#FBF3E2; }
  .chip.failed    { color:#B3261E; border-color:#F0C4C0; background:#FBEAE8; }
  .ex-evidence { font-size:11px; }
  .ex-evidence a, .ex-evidence span { color:#3A5BD9; font-family:ui-monospace,monospace; text-decoration:none; }
  .ex-recompute { font-size:10.5px; color:#8A8A80; font-family:ui-monospace,monospace; }
  .ex-recompute.ok { color:#127A52; }
  .ex-recompute.fail { color:#B3261E; }
  /* Honest gaps. */
  .gaps { border-radius:14px; padding:18px 22px; margin-top:22px; background:#FBFBF9; border:1px solid #ECECE6; }
  .gaps h2 { font-size:13px; text-transform:uppercase; letter-spacing:1.2px; color:#9A6B12; font-weight:600; margin-bottom:10px; }
  .gaps li { list-style:none; font-size:13px; color:#5B4A2A; line-height:1.5; margin-bottom:8px; padding-left:18px; position:relative; }
  .gaps li::before { content:"⚠"; position:absolute; left:0; color:#9A6B12; }
  .foot { font-size:11px; color:#5C6573; margin-top:20px; line-height:1.6; }
  [hidden] { display:none !important; }
</style>
</head>
<body>
<div class="wrap">
  <div class="share">
    <span class="mono" data-permalink>(open the full shared link to load the history)</span>
    <span><button type="button" data-copy>copy permalink</button></span>
  </div>
  <div class="disclosure">
    This page reads the node's history from the link fragment (after <span class="mono">#</span>) — a
    browser never sends that part over the wire, so even a hosted copy never receives the capsules.
    Every <span class="mono">capsule_id</span> is recomputed in your browser from the record itself, so a
    forged trust chip or gradient level cannot survive: the values are re-derived here, not trusted.
  </div>

  <h1>Trust summary — <em>this node's whole history</em></h1>
  <p class="sub">Everything this node sent as a requester and served as a provider, with a per-exchange trust chip and the earned-trust headline. The honest gaps are stated, never hidden.</p>
  <div class="meta mono" data-meta></div>

  <div class="empty" data-empty>
    No history in this URL. Open the full shared link (the part after <span class="mono">#</span>) to load
    the summary — this page never fetches from a server.
  </div>

  <div class="gradient" data-gradient hidden>
    <span class="grad-level" data-grad-level></span>
    <div class="grad-label" data-grad-label></div>
    <div class="grad-counts" data-grad-counts></div>
  </div>

  <div class="ex-head" data-ex-head hidden>Exchanges (newest first)</div>
  <div data-exchanges></div>

  <div class="gaps" data-gaps hidden>
    <h2>Honest gaps — what this does not prove</h2>
    <ul data-gaps-list></ul>
  </div>

  <div class="foot" data-foot hidden></div>
</div>

<template id="ex-template">
  <div class="ex">
    <span class="ex-dir" data-ex-dir></span>
    <div class="ex-body">
      <div class="ex-model" data-ex-model></div>
      <div class="ex-meta" data-ex-meta></div>
    </div>
    <div class="ex-right">
      <span class="chip" data-ex-chip></span>
      <span class="ex-evidence" data-ex-evidence></span>
      <span class="ex-recompute" data-ex-recompute></span>
    </div>
  </div>
</template>

<script>window.__MESH_FRAGMENT_B64U__=@@FRAGMENT@@;</script>
<script>
@@VERIFY_JS@@
</script>
<script>
// SPDX-License-Identifier: Apache-2.0
// The trust-summary renderer. It reuses mesh_verify.js's EXPORTED recompute
// core (window.__mesh_recomputeCapsuleId) rather than hand-porting the digest
// a second time -- each exchange's capsule_id is re-derived in-browser from the
// record carried in `entries`, and the row's chip is downgraded (and marked)
// if the co-carried value does not match. A forged chip/level is caught here.
(function () {
  "use strict";

  function el(s) { return document.querySelector(s); }
  function tmpl(id) { return document.getElementById(id).content; }
  function short(cid) { return cid ? cid.slice(0, 12) + "…" : "(no id)"; }

  function decodeFragment(token) {
    token = (token || "").replace(/^#/, "");
    if (!token) return null;
    var std = token.replace(/-/g, "+").replace(/_/g, "/");
    var pad = std.length % 4;
    if (pad) std += "====".slice(pad);
    var bin = atob(std);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  function fmtTokens(inn, out) {
    var parts = [];
    if (inn != null) parts.push(inn + " in");
    if (out != null) parts.push(out + " out");
    return parts.length ? parts.join(" / ") + " tokens" : "tokens not in record";
  }

  function renderGradient(g) {
    var box = el("[data-gradient]");
    box.hidden = false;
    var lvl = el("[data-grad-level]");
    var cls = g.level === "anchored" ? "anchored" : (g.level === "earned-over-N" ? "earned" : "unknown");
    lvl.className = "grad-level " + cls;
    lvl.textContent = (g.level === "earned-over-N" ? "earned over N" : g.level);
    el("[data-grad-label]").textContent = g.level_label;
    var counts = el("[data-grad-counts]");
    function c(label, n) {
      var s = document.createElement("span");
      s.className = "c";
      var b = document.createElement("b");
      b.textContent = String(n);
      s.appendChild(b);
      s.appendChild(document.createTextNode(" " + label));
      counts.appendChild(s);
    }
    c("exchanges", g.n_exchanges);
    c("verifiable", g.n_verifiable);
    c("✓ verified-in-browser", g.n_verified_in_browser);
    c("◷ witnessed", g.n_witnessed);
    c("⚠ self-attested", g.n_self_attested);
  }

  // entries[] carry the full record; index them by capsule_id so each row can
  // re-derive its own id and catch a forged co-carried chip.
  function indexEntries(entries) {
    var by = {};
    (entries || []).forEach(function (e) { if (e && e.capsule_id) by[e.capsule_id] = e; });
    return by;
  }

  async function renderExchange(ex, entriesById) {
    var node = tmpl("ex-template").cloneNode(true).querySelector(".ex");
    var dir = node.querySelector("[data-ex-dir]");
    var dcls = ex.direction === "served" ? "served" : (ex.direction === "sent" ? "sent" : "unknown");
    dir.className = "ex-dir " + dcls;
    dir.textContent = ex.direction;

    node.querySelector("[data-ex-model]").textContent = ex.friendly_model || "local model";
    var metaBits = [];
    if (ex.counterparty) metaBits.push("counterparty: " + ex.counterparty);
    metaBits.push(fmtTokens(ex.tokens_in, ex.tokens_out));
    if (ex.settings) metaBits.push(ex.settings);
    node.querySelector("[data-ex-meta]").textContent = metaBits.join(" · ");

    var chip = node.querySelector("[data-ex-chip]");
    chip.className = "chip " + (ex.chip.kind || "self_attested");
    chip.textContent = ex.chip.mark + " " + ex.chip.label;

    var ev = node.querySelector("[data-ex-evidence]");
    ev.textContent = "capsule " + short(ex.evidence_capsule_id);

    // Re-derive the capsule_id in-browser from the carried record -- the
    // forged-value guard. Reuse mesh_verify.js's exported core; never re-port.
    var rc = node.querySelector("[data-ex-recompute]");
    var entry = entriesById[ex.capsule_id];
    if (entry && entry.record && window.__mesh_recomputeCapsuleId) {
      try {
        var got = await window.__mesh_recomputeCapsuleId(entry.record);
        if (got === ex.capsule_id) {
          rc.className = "ex-recompute ok";
          rc.textContent = "✓ id recomputed in browser";
        } else {
          rc.className = "ex-recompute fail";
          rc.textContent = "✗ id MISMATCH — re-derived " + short(got);
          // A mismatch downgrades the chip: a co-carried "verified"/"witnessed"
          // that does not recompute is demoted to a failed chip, here, live.
          chip.className = "chip failed";
          chip.textContent = "✗ id mismatch — not verified";
        }
      } catch (e) {
        rc.textContent = "— id not recomputable";
      }
    } else {
      rc.textContent = "— record not carried for recompute";
    }
    return node;
  }

  async function boot() {
    var payload = null;
    try {
      var embedded = (typeof window !== "undefined" && window.__MESH_FRAGMENT_B64U__) || "";
      var UNFILLED = "@@" + "FRAGMENT" + "@@";
      if (embedded && embedded !== UNFILLED) payload = decodeFragment(embedded);
      var hash = location.hash.slice(1);
      if (hash) payload = decodeFragment(hash);
    } catch (e) { payload = null; }
    if (!payload || !payload.exchanges) return; // empty-state stays shown

    el("[data-empty]").hidden = true;
    var w = payload.witness;
    el("[data-meta]").textContent =
      (payload.operator ? "operator " + payload.operator + " · " : "") +
      (payload.node_id ? "node " + short(payload.node_id) + " · " : "") +
      payload.exchanges.length + " exchange(s) · source log: " + (payload.source_log || "?") +
      (w ? " · witness " + (w.log_id || "?") + (w.cose_present ? " (COSE)" : "")
         : " · no witness checkpoint in this view");

    renderGradient(payload.gradient || {});

    el("[data-ex-head]").hidden = false;
    var entriesById = indexEntries(payload.entries);
    var container = el("[data-exchanges]");
    for (var i = 0; i < payload.exchanges.length; i++) {
      container.appendChild(await renderExchange(payload.exchanges[i], entriesById));
    }

    var gaps = payload.honest_gaps || [];
    if (gaps.length) {
      el("[data-gaps]").hidden = false;
      var list = el("[data-gaps-list]");
      gaps.forEach(function (g) {
        var li = document.createElement("li");
        li.textContent = g;
        list.appendChild(li);
      });
    }

    var foot = el("[data-foot]");
    foot.hidden = false;
    foot.innerHTML =
      "This page recomputed every capsule_id in your browser from the record itself. The gradient " +
      "level and each chip are re-derived here — a forged co-carried value is caught, not trusted. " +
      (w ? "A witness checkpoint was supplied, so anchoring is shown."
         : "No witness checkpoint was supplied, so the history stays self-attested/earned, not anchored, in this view.");

    var link = el("[data-permalink]");
    if (link) link.textContent = location.href;
    var copy = el("[data-copy]");
    if (copy) copy.addEventListener("click", function () {
      navigator.clipboard && navigator.clipboard.writeText(location.href);
      copy.textContent = "copied";
      setTimeout(function () { copy.textContent = "copy permalink"; }, 1500);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  if (typeof window !== "undefined") {
    window.__trust_boot = boot;
    window.__trust_renderExchange = renderExchange;
  }
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI -- `trust-summary html --ledger PATH --out PATH`
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
    import os

    records = _read_records(args.ledger)
    if not records:
        print(f"trust-summary: no records in {args.ledger}", file=sys.stderr)
        return 1
    witness = _read_first_json(args.witness) if args.witness else None
    summary = build_trust_summary(
        records,
        source_log=args.source_log,
        witness_checkpoint=witness,
        operator=args.operator,
        ledger_dir=os.path.dirname(os.path.abspath(args.ledger)),
        issuer_key=args.issuer_key,
    )
    fragment = encode_fragment(summary)
    html = render_trust_summary_html(fragment)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    permalink = f"file://{os.path.abspath(args.out)}#{fragment}"
    if args.permalink_out:
        with open(args.permalink_out, "w", encoding="utf-8") as fh:
            fh.write(permalink + "\n")
    g = summary["gradient"]
    print(
        f"trust-summary: {len(records)} exchange(s), gradient={g['level']} "
        f"({g['n_verifiable']} verifiable) -> {args.out}"
    )
    print(f"  {permalink}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trust-summary",
        description="Render a whole-history TrustSummary (exchanges + earned-gradient + honest "
        "gaps) as a self-contained, offline, in-browser-verifiable permalink HTML.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    html = sub.add_parser("html", help="emit the offline trust-summary HTML + permalink")
    html.add_argument("--ledger", required=True, metavar="PATH", help="mesh capsule JSONL ledger")
    html.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    html.add_argument("--witness", metavar="PATH", default=None, help="optional COSE checkpoint receipt (json/jsonl)")
    html.add_argument(
        "--source-log",
        default=SOURCE_SIDECAR,
        choices=[SOURCE_PLUGIN, SOURCE_SIDECAR],
        help="which single-writer log these records came from (drives the direction label)",
    )
    html.add_argument("--operator", default=None, help="operator label for the header")
    html.add_argument(
        "--issuer-key",
        metavar="PATH",
        default=None,
        help="PEM pubkey for the detached signed-statements/*.cose; defaults to "
        "<ledger_dir>/node-key.pub.pem then <ledger_dir>/../keys/node-key.pub.pem",
    )
    html.add_argument("--permalink-out", metavar="PATH", default=None, help="write the file:// permalink here")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "html":
        return _cmd_html(args)
    _build_parser().error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
