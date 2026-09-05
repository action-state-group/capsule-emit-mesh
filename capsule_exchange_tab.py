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
    "PENDING",
    "SEQUENCE_CAPTURE_METHOD",
    "SEQUENCE_SOURCE",
    "TWIN_ADJUDICATION_PENDING_REASON",
    "WITNESS_REVERIFY_PENDING_REASON",
    "build_exchange_view",
    "digest_match_grade",
    "exchange_id_for",
    "half_by_role",
    "identity_chain_for",
    "records_for_exchange",
    "render_exchange_subtab_html",
    "sequence_position",
    "twin_adjudication_placeholder",
    "witness_receipt_reverify_placeholder",
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

TWIN_ADJUDICATION_PENDING_REASON = (
    "twin comparison / adjudication is not available on this view: "
    "[mesh-e17a-offline-adjudicator] (capsule-emit-mesh PR #84) is not yet merged"
)
WITNESS_REVERIFY_PENDING_REASON = (
    "the presence-only witness line above is real and unchanged; RE-VERIFYING the receipt "
    "(rather than just checking one rides along) is not available on this view: "
    "[mesh-e2-witness-checkpoints] (capsule-emit-mesh PR #87) is not yet merged"
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule-exchange-tab",
        description='Render Pane C ("This exchange") -- the requester/provider pair drill-down '
        "for one capsule, as a subtab under the Accountability tab.",
    )
    parser.add_argument("--ledger", required=True, metavar="PATH", help="this node's mesh capsule JSONL ledger")
    parser.add_argument(
        "--counterparty-ledger",
        metavar="PATH",
        default=None,
        help="optional second ledger (the counterparty's) to find the other half of the pair in",
    )
    parser.add_argument("--capsule-id", required=True, help="capsule_id of the half to drill into")
    parser.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    parser.add_argument("--witness", metavar="PATH", default=None, help="optional COSE checkpoint receipt (json/jsonl)")
    parser.add_argument("--source-log", default="sidecar", choices=["plugin", "sidecar"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return _cmd_html(args)


if __name__ == "__main__":
    raise SystemExit(main())
