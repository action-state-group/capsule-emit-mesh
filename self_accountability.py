#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-pane-a-self-accountability-tab] Pane A "This node" -- one card,
computed entirely from this node's own ledger + receipts, answering "what
can I show others about myself".

Composes verbs that already exist; re-derives none of their evidence:

  - **sealing**: ``native_log_join.coverage_report()`` -- the
    request-count-vs-capsule-count self-coverage finding, plus the
    runtime-shutdown-window labelling for expected gaps.
  - **history**: ``history_card.build_history_card()`` -- checkpoint-chain
    continuity, depth, cadence, witness state.
  - **rung**: ``capsule_accountability_tab``'s own
    ``freshness_grade`` / ``cross_party_grade`` / ``measurement_class_grade``
    (reused byte-for-byte, never re-implemented) applied to the most recent
    sealed record, plus the owner-provenance block that record's
    ``x-mesh-poc-v1.owner`` already carries ([mesh-e6-identity-owner-cert]).
    ``weights_digest`` is graded ``absent`` for every record: no capsule
    field named ``weights_digest`` exists in what this sidecar seals today
    (it is declared only at adjudication-fixture time in
    ``twin_adjudicator.AdjudicationHalf``) -- never fabricated here.
  - **shared**: cards/bundles served and refusals issued, via
    [mesh-e14-evidence-responder]. **Honestly absent today**: the responder
    depends on ``capsule_emit.evidence_request``, an upstream ``capsule-emit``
    module that has not merged (capsule-emit-mesh PR #83 is CI-red pending
    capsule-emit PR #148) -- this card must not fabricate a zero for a count
    it cannot yet take.
  - **adjudications**: a tally of sealed adjudication capsules
    (``chain.relation == "adjudicates"``, [mesh-e17a-offline-adjudicator])
    that name one of this node's own sealed capsule_ids as either half.

Every field carries its own ``source``/``capture_method`` (or is graded
``absent`` with a reason) and none is, or ever becomes, a rating: see
``assert_no_rating_fields``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from capsule_accountability_tab import (
    cross_party_grade,
    freshness_grade,
    measurement_class_grade,
)
from capsule_mesh_view import _poc_block
from history_card import build_history_card
from native_log_join import SEALED_VERDICT_CLASSES, coverage_report
from twin_adjudicator import RELATION_ADJUDICATES

__all__ = [
    "FORBIDDEN_RATING_KEYS",
    "HONESTY_LINE",
    "RatingFieldError",
    "adjudications_summary",
    "assert_no_rating_fields",
    "build_self_accountability_card",
    "history_summary",
    "rung_summary",
    "sealing_summary",
    "shared_summary",
]

#: The fixed honesty line every Pane A card carries, verbatim (the ux/ui
#: design docs' own wording -- not paraphrased card to card).
HONESTY_LINE = "coverage is checked by counterparties, not by this node; hardware is OS-reported."

#: [mesh-e14-evidence-responder] is blocked on an upstream capsule-emit
#: merge (capsule-emit-mesh PR #83 CI red pending capsule-emit PR #148) --
#: cited here, not re-litigated, so this stays a single place to update
#: once E14 lands.
SHARED_ABSENT_REASON = (
    "evidence-request responder counts are not yet available on this node: "
    "[mesh-e14-evidence-responder] depends on capsule_emit.evidence_request, "
    "an upstream capsule-emit module not yet merged (capsule-emit-mesh #83 "
    "CI red pending capsule-emit #148)"
)

#: Substrings that must never appear as a dict key anywhere in a Pane A
#: card -- "properties, not scores" (rules block, batch draft). Checked by
#: `assert_no_rating_fields`, not just documented. A trust-rating-named
#: field is barred by the neutrality gate at the repo level as well as
#: here; this list catches the general scoring shape.
FORBIDDEN_RATING_KEYS = ("score", "rating", "trust_level", "grade_percent")


class RatingFieldError(ValueError):
    """Raised when a card would carry a field that could hold a rating."""


def assert_no_rating_fields(value: Any, *, _path: str = "$") -> None:
    """Walk *value* recursively and raise `RatingFieldError` on the first key
    whose name contains one of `FORBIDDEN_RATING_KEYS`. Total and recursive:
    a rating buried three dicts deep must be caught exactly like a top-level
    one."""
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


def sealing_summary(
    native_entries: list[dict[str, Any]],
    capsule_records: list[dict[str, Any]],
    lifecycle_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Sealing row: every request seals / last sealed / failed-sealed
    yes-no -- ``native_log_join.coverage_report()``'s own finding, folded
    into the card shape."""
    report = coverage_report(native_entries, capsule_records, lifecycle_events)
    # "last sealed" is this node's own sealed-capsule clock, not the native
    # request's clock the join happens to echo alongside it -- a capsule
    # that took real wall-clock time to seal after its request must not
    # under-report how recently sealing last actually happened.
    sealed_timestamps = [
        record.get("timestamp")
        for record in capsule_records
        if (record.get("disposition") or {}).get("verdict_class") in SEALED_VERDICT_CLASSES and record.get("timestamp")
    ]
    return {
        "source": "native_log_join",
        "capture_method": "request_capsule_join",
        "coverage_summary": report["coverage_summary"],
        "unsealed_count": report["unsealed_count"],
        "last_sealed": max(sealed_timestamps) if sealed_timestamps else None,
        "failed_sealed": len(report["failed_unsealed"]) > 0,
        "unsealed_rows": report["rows"] and [row for row in report["rows"] if row["capsule_id"] == "unsealed"],
    }


def history_summary(
    *,
    node_id: str,
    log_id: str,
    checkpoint_lines: list[dict[str, Any]],
    since_size: int = 0,
) -> dict[str, Any]:
    """History row: continuous since / N checkpoints / unforked / witnessed
    -- ``history_card.build_history_card()``'s own properties, folded into
    the card shape."""
    card = build_history_card(node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size)
    return {
        "source": "history_card",
        "capture_method": "checkpoint_chain_walk",
        "continuous_since": card.from_checkpoint.timestamp if card.from_checkpoint else None,
        "checkpoint_count": card.checkpoint_count,
        "continuity": card.properties.continuity,
        "unforked": card.properties.unforked,
        "witnessed": card.witnessed,
        "witnesses": list(card.witnesses),
        "cadence": dict(card.properties.cadence),
    }


def rung_summary(latest_record: dict[str, Any] | None) -> dict[str, Any]:
    """Rung row: freshness / cross-party / runtime-binding / weights /
    identity -- each independently graded, never blended into one field.

    ``latest_record`` is this node's own most recently sealed capsule (or
    `None` for a node with no capsules yet, which grades every sub-field
    honestly absent rather than raising).
    """
    poc = _poc_block(latest_record) if latest_record is not None else {}
    owner = poc.get("owner") or {"owner_status": "absent", "owner_id": None, "identity_limitation": None}
    return {
        "freshness": freshness_grade(poc.get("client_nonce_source")),
        "cross_party": cross_party_grade(poc),
        "runtime_binding": measurement_class_grade(poc),
        "weights_digest": {
            "state": "absent",
            "source": None,
            "capture_method": None,
            "reason": "no capsule field named weights_digest exists in records this sidecar emits today",
        },
        "identity": {
            "source": "node_ownership",
            "capture_method": "owner_provenance_block",
            "owner_status": owner.get("owner_status"),
            "owner_id": owner.get("owner_id"),
            "identity_limitation": owner.get("identity_limitation"),
        },
    }


def shared_summary() -> dict[str, Any]:
    """Shared row: cards/bundles served, refusals issued -- honestly absent
    until [mesh-e14-evidence-responder] can be wired (see module docstring).
    """
    return {
        "cards_served": {"state": "absent", "source": None, "capture_method": None, "reason": SHARED_ABSENT_REASON},
        "bundles_served": {"state": "absent", "source": None, "capture_method": None, "reason": SHARED_ABSENT_REASON},
        "refusals_issued": {"state": "absent", "source": None, "capture_method": None, "reason": SHARED_ABSENT_REASON},
    }


def adjudications_summary(
    ledger_records: list[dict[str, Any]],
    *,
    own_capsule_ids: set[str],
) -> dict[str, Any]:
    """Adjudications row: corroborated / contradicted / inconclusive counts,
    tallied from sealed adjudication capsules
    (``chain.relation == "adjudicates"``) that name one of this node's OWN
    sealed capsule_ids as either half -- "involving me", not every
    adjudication this node happens to hold a copy of."""
    corroborated = 0
    contradicted = 0
    inconclusive = 0
    for record in ledger_records:
        chain = record.get("chain") or {}
        if chain.get("relation") != RELATION_ADJUDICATES:
            continue
        adjudication = (
            (record.get("model_attestation") or {}).get("compute_attestation") or {}
        ).get("adjudication")
        if not adjudication:
            continue
        half_a = adjudication.get("half_a_capsule_id")
        half_b = adjudication.get("half_b_capsule_id")
        if half_a not in own_capsule_ids and half_b not in own_capsule_ids:
            continue
        verdict = adjudication.get("verdict") or ""
        if verdict == "corroborated":
            corroborated += 1
        elif verdict.startswith("contradicted:"):
            contradicted += 1
        elif verdict == "inconclusive":
            inconclusive += 1
    return {
        "source": "twin_adjudicator",
        "capture_method": "adjudication_capsule_scan",
        "corroborated": corroborated,
        "contradicted": contradicted,
        "inconclusive": inconclusive,
    }


def build_self_accountability_card(
    *,
    node_id: str,
    log_id: str,
    ledger_records: list[dict[str, Any]],
    native_entries: list[dict[str, Any]],
    lifecycle_events: list[dict[str, Any]] | None = None,
    checkpoint_lines: list[dict[str, Any]] | None = None,
    since_size: int = 0,
) -> dict[str, Any]:
    """Assemble the whole Pane A card. Raises `RatingFieldError` (never
    returns a card that could) if any composed row smuggled in a field that
    looks like a rating."""
    own_capsule_ids = {r.get("capsule_id") for r in ledger_records if r.get("capsule_id")}
    latest_record = max(
        (r for r in ledger_records if r.get("timestamp")),
        key=lambda r: r["timestamp"],
        default=(ledger_records[-1] if ledger_records else None),
    )
    card = {
        "node_id": node_id,
        "sealing": sealing_summary(native_entries, ledger_records, lifecycle_events),
        "history": history_summary(
            node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines or [], since_size=since_size
        ),
        "rung": rung_summary(latest_record),
        "shared": shared_summary(),
        "adjudications": adjudications_summary(ledger_records, own_capsule_ids=own_capsule_ids),
        "honesty_line": HONESTY_LINE,
    }
    assert_no_rating_fields(card)
    return card


# ---------------------------------------------------------------------------
# CLI -- writes accountability_self.json next to the ledger, the same
# read-only-artifact pattern the sidecar's ledger/disclosures/signed-
# statements files already follow (see mesh-llm-ui's capsules.rs route).
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

    card = build_self_accountability_card(
        node_id=args.node_id,
        log_id=args.log_id,
        ledger_records=ledger_records,
        native_entries=_read_jsonl(Path(args.native_log)) if args.native_log else [],
        lifecycle_events=_read_jsonl(Path(args.lifecycle)) if args.lifecycle else [],
        checkpoint_lines=_read_jsonl(Path(args.checkpoints)) if args.checkpoints else [],
        since_size=args.since_size,
    )

    text = json.dumps(card, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="self-accountability",
        description='Build Pane A ("This node") -- the self-accountability card computed from one node\'s own ledger + receipts.',
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build the card and write it as JSON")
    build.add_argument("--node-id", required=True)
    build.add_argument("--log-id", required=True)
    build.add_argument("--ledger", required=True, metavar="PATH", help="the sealed capsule JSONL ledger (capsules.jsonl)")
    build.add_argument("--native-log", metavar="PATH", default=None, help="capsule_sidecar.py's native_log.jsonl")
    build.add_argument("--lifecycle", metavar="PATH", default=None, help="optional lifecycle_events.jsonl")
    build.add_argument("--checkpoints", metavar="PATH", default=None, help="checkpoints.jsonl")
    build.add_argument("--since-size", type=int, default=0)
    build.add_argument("--out", metavar="PATH", default=None, help="write JSON here instead of stdout")

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
