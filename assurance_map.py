#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""assurance_map -- the shared "assurance map" chip component used by all
three Accountability panes (``capsule_accountability_tab.py`` Pane A,
``peer_accountability_tab.py`` Pane B, ``capsule_exchange_tab.py`` Pane C).

[mesh-panes-map-chips]. Replaces the ladder-shaped four-state discipline
(``verified``/``present-unverified``/``absent``/``failed`` plus the ad hoc
``pending``) with the orthogonal nine-property map from the 2026-09-06
vocabulary realignment (``_work/consistency-realignment-2026-09-06.md`` §1):
content binding, producer signature, local inclusion, checkpoint signature,
external registration, continuity, identity/authority, capture coverage,
outcome corroboration -- each independently ``PASS``/``FAIL``/``NOT_PRESENT``/
``NOT_CHECKED``/``INCONCLUSIVE``. A ladder implies one axis and rounds up
(the source bug this task fixes: a per-exchange row whose only real gap was
"this view hasn't verified yet" read identically to a row with a genuine
failure, so the Issues filter returned the whole set). The map never rounds
up: only ``FAIL`` counts as an issue, and ``NOT_PRESENT``/``NOT_CHECKED`` are
never conflated -- the first means the record made no claim, the second
means this view's own wiring doesn't check it (yet).

This module owns ONE tone map and ONE pill/chip renderer so the three panes
cannot drift into three hand-maintained copies (the failure mode that made
the pre-existing ``present-unverified``/``pending`` inconsistency possible in
the first place). Python callers get ``render_pill``/``render_chip_strip``/
``render_chip_table``; the two JS-templated panes (A/B) embed
``tone_js_object()`` in place of a locally hand-written ``TONE`` dict.
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "CHIP_GLYPH",
    "CHIP_STATES",
    "CHIP_TONE",
    "PROMISE_ISSUE_STATES",
    "PROPERTY_CAPTURE_COVERAGE",
    "PROPERTY_CHECKPOINT_SIGNATURE",
    "PROPERTY_CONTENT_BINDING",
    "PROPERTY_CONTINUITY",
    "PROPERTY_EXTERNAL_REGISTRATION",
    "PROPERTY_IDENTITY_AUTHORITY",
    "PROPERTY_LABEL",
    "PROPERTY_LOCAL_INCLUSION",
    "PROPERTY_ORDER",
    "PROPERTY_OUTCOME_CORROBORATION",
    "PROPERTY_PRODUCER_SIGNATURE",
    "PROPERTY_SHORT_LABEL",
    "STATE_FAIL",
    "STATE_INCONCLUSIVE",
    "STATE_NOT_CHECKED",
    "STATE_NOT_PRESENT",
    "STATE_PASS",
    "assert_map_complete",
    "chip",
    "has_issue",
    "render_chip_strip",
    "render_chip_table",
    "render_pill",
    "tone_for",
    "tone_js_object",
]

# ---------------------------------------------------------------------------
# The five states. Exactly these five strings, nothing else, ever -- a
# rendered "pending" or "present-unverified" string is the regression this
# module exists to prevent (see tests/test_assurance_map.py's grep gate).
# ---------------------------------------------------------------------------

STATE_PASS = "PASS"
STATE_FAIL = "FAIL"
STATE_NOT_PRESENT = "NOT_PRESENT"
STATE_NOT_CHECKED = "NOT_CHECKED"
STATE_INCONCLUSIVE = "INCONCLUSIVE"

CHIP_STATES = (STATE_PASS, STATE_FAIL, STATE_NOT_PRESENT, STATE_NOT_CHECKED, STATE_INCONCLUSIVE)

#: Never rounds up: FAIL is the only bad tone; NOT_PRESENT ("no claim was
#: made") and NOT_CHECKED ("this view doesn't check it yet") are both grey --
#: distinct facts, same neutral tone, so neither reads as a record defect.
CHIP_TONE = {
    STATE_PASS: "good",
    STATE_FAIL: "bad",
    STATE_NOT_PRESENT: "neutral",
    STATE_NOT_CHECKED: "neutral",
    STATE_INCONCLUSIVE: "warn",
}

CHIP_GLYPH = {
    STATE_PASS: "✓",  # check
    STATE_FAIL: "✕",  # cross
    STATE_NOT_PRESENT: "∅",  # empty set
    STATE_NOT_CHECKED: "…",  # ellipsis -- a view limitation, not a record gap
    STATE_INCONCLUSIVE: "?",
}

#: The pre-existing four-state discipline plus every ad hoc tone-alike label
#: this codebase already renders (capsule_accountability_tab.py's BLOCK_TONE,
#: peer_accountability_tab.py's TONE, capsule_exchange_tab.py's
#: _TONE_BY_STATE) -- merged here so ``tone_for`` is the ONE place either
#: vocabulary resolves to a colour, instead of three copies that can drift.
#: Kept only for panes/blocks this task does not migrate (Pane A/B's
#: served_summary/references/history-theirs stubs remain their own honest
#: "not built yet" -- a different fact from the map's NOT_CHECKED, which
#: names a *specific* unwired property on an otherwise-computed exchange).
_LEGACY_TONE = {
    "absent": "neutral",
    "unilateral_fallback": "neutral",
    "unattested": "neutral",
    "pending": "neutral",
    "present-unverified": "warn",
    "acknowledged_receipt": "warn",
    "self_measured": "warn",
    "os_measured": "warn",
    "platform-attested": "warn",
    "unilateral": "warn",
    "verified": "good",
    "full_bilateral": "good",
    "tee_measured": "good",
    "attested": "good",
    "present": "good",
    "failed": "bad",
    "refused": "bad",
    "contradicted": "bad",
}


def tone_for(state: str) -> str:
    """Resolve any state string (map or legacy) to one of good/warn/bad/neutral."""
    return CHIP_TONE.get(state) or _LEGACY_TONE.get(state, "neutral")


# ---------------------------------------------------------------------------
# The nine orthogonal properties (consistency-realignment.md §1's map, named
# for this repo's own verification chain -- docs/VERIFICATION-CHAIN.md links
# 1/3/5/6/7/4 plus identity, capture, and outcome corroboration).
# ---------------------------------------------------------------------------

PROPERTY_CONTENT_BINDING = "content_binding"
PROPERTY_PRODUCER_SIGNATURE = "producer_signature"
PROPERTY_LOCAL_INCLUSION = "local_inclusion"
PROPERTY_CHECKPOINT_SIGNATURE = "checkpoint_signature"
PROPERTY_EXTERNAL_REGISTRATION = "external_registration"
PROPERTY_CONTINUITY = "continuity"
PROPERTY_IDENTITY_AUTHORITY = "identity_authority"
PROPERTY_CAPTURE_COVERAGE = "capture_coverage"
PROPERTY_OUTCOME_CORROBORATION = "outcome_corroboration"

PROPERTY_ORDER = (
    PROPERTY_CONTENT_BINDING,
    PROPERTY_PRODUCER_SIGNATURE,
    PROPERTY_LOCAL_INCLUSION,
    PROPERTY_CHECKPOINT_SIGNATURE,
    PROPERTY_EXTERNAL_REGISTRATION,
    PROPERTY_CONTINUITY,
    PROPERTY_IDENTITY_AUTHORITY,
    PROPERTY_CAPTURE_COVERAGE,
    PROPERTY_OUTCOME_CORROBORATION,
)

PROPERTY_LABEL = {
    PROPERTY_CONTENT_BINDING: "content binding",
    PROPERTY_PRODUCER_SIGNATURE: "producer signature",
    PROPERTY_LOCAL_INCLUSION: "local inclusion",
    PROPERTY_CHECKPOINT_SIGNATURE: "checkpoint signature",
    PROPERTY_EXTERNAL_REGISTRATION: "external registration",
    PROPERTY_CONTINUITY: "continuity",
    PROPERTY_IDENTITY_AUTHORITY: "identity/authority",
    PROPERTY_CAPTURE_COVERAGE: "capture coverage",
    PROPERTY_OUTCOME_CORROBORATION: "outcome corroboration",
}

#: Short labels for the compact row strip (task spec's own example:
#: "binding ✓ · sig ✓ · registered ∅ · continuity ∅").
PROPERTY_SHORT_LABEL = {
    PROPERTY_CONTENT_BINDING: "binding",
    PROPERTY_PRODUCER_SIGNATURE: "sig",
    PROPERTY_LOCAL_INCLUSION: "local incl.",
    PROPERTY_CHECKPOINT_SIGNATURE: "chkpt sig",
    PROPERTY_EXTERNAL_REGISTRATION: "registered",
    PROPERTY_CONTINUITY: "continuity",
    PROPERTY_IDENTITY_AUTHORITY: "identity",
    PROPERTY_CAPTURE_COVERAGE: "capture",
    PROPERTY_OUTCOME_CORROBORATION: "outcome",
}

#: The promise line's two "outranks everything" states (join_card.py /
#: docs/ACCOUNTABILITY-PANES.md §1) -- the only non-map input the Issues
#: filter also honors, per this task's build item 3.
PROMISE_ISSUE_STATES = ("broken", "changed_without_saying")


def chip(state: str, text: str | None = None) -> dict[str, Any]:
    """Build one property's chip value. Raises on any state outside the five
    -- this is the mutant the grep-gate test flips to confirm the check can
    fail (QUEUE_PROTOCOL §7)."""
    if state not in CHIP_STATES:
        raise ValueError(f"assurance_map.chip: {state!r} is not one of {CHIP_STATES}")
    return {"state": state, "text": text}


def assert_map_complete(properties: dict[str, dict[str, Any]]) -> None:
    """Raise unless *properties* names all nine keys with a valid state each."""
    missing = [key for key in PROPERTY_ORDER if key not in properties]
    if missing:
        raise ValueError(f"assurance map missing properties: {missing}")
    bad = {k: v.get("state") for k, v in properties.items() if v.get("state") not in CHIP_STATES}
    if bad:
        raise ValueError(f"assurance map has invalid states: {bad}")


def has_issue(properties: dict[str, dict[str, Any]], promise_state: str | None = None) -> bool:
    """The Issues filter's whole definition: any property FAIL, or a promise
    line that read broken/changed_without_saying. An honest NOT_PRESENT/
    NOT_CHECKED is never an issue -- that was the bug (an Issues filter that
    returned the whole set because "present-unverified" was treated as a
    failure)."""
    if promise_state in PROMISE_ISSUE_STATES:
        return True
    return any(entry.get("state") == STATE_FAIL for entry in properties.values())


def _esc(value: Any) -> str:
    return "" if value is None else str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_pill(state: str, text: str | None = None) -> str:
    tone = tone_for(state)
    return f'<span class="pill pill-{tone}">{_esc(text or state)}</span>'


def render_chip_strip(properties: dict[str, dict[str, Any]]) -> str:
    """The row's compact strip: every property, short-labelled, glyphed,
    joined with " · " -- e.g. "binding ✓ · sig ✓ · registered ∅ ·
    continuity ∅". Properties missing from *properties* are skipped rather
    than fabricated."""
    segments = []
    for key in PROPERTY_ORDER:
        entry = properties.get(key)
        if entry is None:
            continue
        state = entry["state"]
        glyph = CHIP_GLYPH.get(state, "?")
        tone = tone_for(state)
        title = f"{PROPERTY_LABEL[key]}: {state}" + (f" -- {entry['text']}" if entry.get("text") else "")
        segments.append(
            f'<span class="chip-seg chip-{tone}" title="{_esc(title)}">{_esc(PROPERTY_SHORT_LABEL[key])} {glyph}</span>'
        )
    return '<span class="chip-strip">' + " · ".join(segments) + "</span>"


def render_chip_table(properties: dict[str, dict[str, Any]]) -> str:
    """The card's full table: one row per property, full label, pill, detail
    text (falls back to the bare state when no detail was given -- never a
    blank cell)."""
    rows = []
    for key in PROPERTY_ORDER:
        entry = properties.get(key)
        if entry is None:
            continue
        detail = entry.get("text") or entry["state"]
        rows.append(
            f"<tr><td>{_esc(PROPERTY_LABEL[key])}</td><td>{render_pill(entry['state'])}</td>"
            f"<td>{_esc(detail)}</td></tr>"
        )
    return (
        "<table class='assurance-map'><thead><tr><th>property</th><th>state</th><th>detail</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


#: Shared CSS for the chip strip/table -- expects the panes' own :root vars
#: (--good/--warn/--bad/--fg-faint/--border-soft), already defined identically
#: in all three shells.
CHIP_CSS = """
  .chip-strip { display: inline-flex; flex-wrap: wrap; gap: 3px 10px; font-size: 11.5px; }
  .chip-seg { white-space: nowrap; cursor: default; }
  .chip-good { color: var(--good); }
  .chip-warn { color: var(--warn); }
  .chip-bad { color: var(--bad); }
  .chip-neutral { color: var(--fg-faint); }
  table.assurance-map { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  table.assurance-map td, table.assurance-map th { padding: 4px 8px; border-bottom: 1px solid var(--border-soft); text-align: left; }
"""


def tone_js_object() -> str:
    """The one JS tone map, for Pane A/B to embed verbatim in place of a
    locally hand-written ``TONE``/``BLOCK_TONE`` dict literal -- so three
    panes read from one generated object instead of three copies that can
    drift out of sync (exactly how ``present-unverified`` and ``pending``
    ended up meaning different things in different panes)."""
    merged = {**_LEGACY_TONE, **CHIP_TONE}
    pairs = ", ".join(f'"{key}": "{value}"' for key, value in sorted(merged.items()))
    return "{" + pairs + "}"
