#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule-mesh view -- thin wrapper over `capsule-emit ledger view`.

One machine runs TWO single-writer logs today (§7d/§3a: one writer per log,
never two writers sharing a log):

  - the Rust plugin's ledger (admission-policy / capsule-producer -- gates
    and seals exchanges on this node's serving path, in-process);
  - the Python sidecar's ledger (capsule_sidecar.py -- a reverse proxy in
    front of this node's own /v1 surface, sealing the completed exchange).

"One CLL per machine" is a PRESENTATION truth this viewer provides, never a
storage merge: the two on-disk logs are read and rendered exactly as
`capsule-emit ledger view` already renders each of them, and are combined
into one additional "machine view" summary here -- assembled in memory,
joined by each record's own content address (`capsule_id`), never written
back to either log.

This module adds exactly two DISPLAY-ONLY labels per record -- `role`
(requested|served) and `counterparty` -- neither of which is a capsule
field. Do NOT add a `role` field to any capsule here; that is the separate,
gated registry-entry track ([mesh-exchange-role-field], scitt-payload-
binding's `mesh-inference-exchange` provisional). Per that track's LOCKED
ruling, `role` is a genuine party-role axis and is NOT derivable from
`observation_point` alone (`gateway_ingress` maps to neither requested nor
served) -- so the label here also weighs which log produced the record.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from capsule_emit.ledger import read_ledger
from capsule_emit.signing import verify_store_signed
from capsule_emit.viewer import render_table

SOURCE_PLUGIN = "plugin"
SOURCE_SIDECAR = "sidecar"

# Every observation_point value (mesh_record_emitter.py's x-mesh-lifecycle-v1
# namespace, the #1331 lifecycle-bridge rig) names a vantage point WITHIN one
# served exchange's lifecycle on this machine: gateway admits it, the host
# receives it, a backend is dispatched, the client is answered. None of the
# four represents this machine acting as a requestor elsewhere -- confirmed
# by the [mesh-exchange-role-field] LOCKED ruling. So an explicit
# observation_point, when a future record carries one, always reads as
# "served" here; it is still consulted (not just source log) so a genuine
# requestor-side observation point added later fails closed instead of
# silently mislabeling.
_SERVED_OBSERVATION_POINTS = frozenset(
    {"gateway_ingress", "serving_host_ingress", "backend_dispatch", "client_egress"}
)

# Per-source-log default, used whenever a record carries no observation_point
# at all -- true of every record capsule_sidecar.py / capsule-producer emit
# today (mesh-accountability-build-plan-2026-08-28.md §3: the requestor-side
# log is not built yet, A4). Both of today's real writers observe THIS
# machine acting as the provider: the sidecar proxies its own node's /v1
# ingress; the plugin gates admission on the same serving path (it
# advertises itself as a mesh-llm inference PROVIDER). Neither writer speaks
# for a request this machine issued elsewhere.
_DEFAULT_ROLE_BY_SOURCE = {
    SOURCE_PLUGIN: "served",
    SOURCE_SIDECAR: "served",
}


def _lifecycle_block(record: dict[str, Any]) -> dict[str, Any]:
    return (
        record.get("model_attestation", {})
        .get("compute_attestation", {})
        .get("x-mesh-lifecycle-v1", {})
        or {}
    )


def _poc_block(record: dict[str, Any]) -> dict[str, Any]:
    return (
        record.get("model_attestation", {})
        .get("compute_attestation", {})
        .get("x-mesh-poc-v1", {})
        or {}
    )


def label_role(record: dict[str, Any], source_log: str) -> str:
    """Display-only role label -- never persisted, never a new capsule field."""
    observation_point = _lifecycle_block(record).get("observation_point")
    if observation_point in _SERVED_OBSERVATION_POINTS:
        return "served"
    return _DEFAULT_ROLE_BY_SOURCE.get(source_log, "unknown")


def label_counterparty(record: dict[str, Any]) -> str:
    """Best-effort counterparty label from bilateral evidence, else "unknown".

    No capsule field names a human/node identity for the other party today
    -- `cross_party.initiator_ref` (draft-mih-agent-bilateral-attestation-01
    Move 2) is the only cross-party evidence a capsule carries, and it is a
    digest over the initiator's request attestation, not a claimed identity.
    "unknown" is the honest label absent that evidence -- it matches the
    self-attested rung on the trust ladder (TRANSLATION.md), not a bug.
    """
    cross_party = _poc_block(record).get("cross_party")
    if not cross_party:
        return "unknown"
    initiator_ref = cross_party.get("initiator_ref")
    if not initiator_ref:
        return "unknown"
    return f"initiator:{initiator_ref[:12]}"


def verify_results_for(records: list[dict[str, Any]]) -> list | None:
    """Best-effort ``verify_store_signed(records)``, or None on any error.

    Mirrors capsule-emit's own `ledger view` CLI (`_cmd_ledger_view`): verify
    is best-effort for a viewer, never fatal to rendering the ledger. Callers
    that also need a capsule_id -> ok mapping should build it from this same
    result list (see ``_verify_ok_map``) rather than calling verify twice.
    """
    if not records:
        return None
    try:
        return verify_store_signed(records)
    except Exception:
        return None


def _verify_ok_map(records: list[dict[str, Any]], verify_results: list | None) -> dict[str, bool | None]:
    """capsule_id -> verify_ok, from an already-computed verify_results list."""
    vmap: dict[str, bool | None] = {}
    if not verify_results:
        return vmap
    for i, result in enumerate(verify_results):
        cid = getattr(result, "capsule_id", None) or (
            records[i].get("capsule_id", "") if i < len(records) else ""
        )
        if cid:
            vmap[cid] = bool(result.ok)
    return vmap


def build_machine_view(
    sources: list[tuple[str, list[dict[str, Any]], list | None]],
) -> list[dict[str, Any]]:
    """Assemble "what my machine did" across N single-writer logs.

    Presentation-only: verification runs per source log BEFORE merging --
    chain linkage (`prior_capsule_id`) is per single-writer log, so verifying
    an interleaved cross-writer list would break continuity for every writer
    but the first. The merge itself is keyed by each record's own
    `capsule_id` (content address): a capsule_id already seen from an
    earlier source is the same content by definition and is not duplicated.
    """
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for source_log, records, verify_results in sources:
        vmap = _verify_ok_map(records, verify_results)
        for record in records:
            capsule_id = record.get("capsule_id", "")
            if not capsule_id or capsule_id in seen:
                continue
            seen[capsule_id] = {
                "capsule_id": capsule_id,
                "timestamp": record.get("timestamp"),
                "source_log": source_log,
                "role": label_role(record, source_log),
                "counterparty": label_counterparty(record),
                "verify_ok": vmap.get(capsule_id),
            }
            order.append(capsule_id)
    order.sort(key=lambda cid: seen[cid].get("timestamp") or "")
    return [seen[cid] for cid in order]


def render_machine_view(rows: list[dict[str, Any]], *, out: Any = None) -> None:
    if out is None:
        out = sys.stdout

    if not rows:
        print("machine view: no records in either log", file=out)
        return

    col_id, col_log, col_role, col_cp = 14, 8, 9, 24
    print(f"\nmachine view  ({len(rows)} record(s) across both logs)\n", file=out)
    header = (
        f"  {'capsule_id':<{col_id}}  {'log':<{col_log}}  {'role':<{col_role}}  "
        f"{'counterparty':<{col_cp}}  verify  timestamp"
    )
    print(header, file=out)
    print("-" * len(header), file=out)
    for row in rows:
        vok = row["verify_ok"]
        v_str = "✓" if vok is True else ("✗" if vok is False else "—")
        print(
            f"  {row['capsule_id'][:col_id]:<{col_id}}  "
            f"{row['source_log']:<{col_log}}  "
            f"{row['role']:<{col_role}}  "
            f"{row['counterparty'][:col_cp]:<{col_cp}}  "
            f"{v_str:<6}  "
            f"{row.get('timestamp') or ''}",
            file=out,
        )
    print(file=out)


def _cmd_view(args: argparse.Namespace) -> int:
    sources: list[tuple[str, str, list[dict[str, Any]], list | None]] = []
    if args.plugin_log:
        records = read_ledger(args.plugin_log)
        sources.append((SOURCE_PLUGIN, args.plugin_log, records, verify_results_for(records)))
    if args.sidecar_log:
        records = read_ledger(args.sidecar_log)
        sources.append((SOURCE_SIDECAR, args.sidecar_log, records, verify_results_for(records)))

    if not sources:
        print("capsule-mesh view: give at least one of --plugin-log / --sidecar-log", file=sys.stderr)
        return 1

    rows = build_machine_view([(label, records, vr) for label, _path, records, vr in sources])

    if args.as_json:
        print(json.dumps(rows, indent=2, default=str))
        return 0

    if not args.no_logs:
        for label, path, records, verify_results in sources:
            print(f"=== {label} log: {path} ===")
            render_table(records, verify_results=verify_results, path=str(path))

    render_machine_view(rows)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule-mesh",
        description="capsule-mesh -- mesh-aware thin wrapper over capsule-emit's ledger view.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    view = sub.add_parser(
        "view",
        help="assemble one machine's view across its plugin + sidecar logs "
        "(role/counterparty labels are display-only; no new capsule field)",
    )
    view.add_argument("--plugin-log", metavar="PATH", default=None, help="the Rust plugin's JSONL ledger")
    view.add_argument("--sidecar-log", metavar="PATH", default=None, help="the Python sidecar's JSONL ledger")
    view.add_argument("--json", dest="as_json", action="store_true", help="raw JSON output of the machine view")
    view.add_argument(
        "--no-logs",
        action="store_true",
        help="skip printing each log's own capsule-emit ledger view; machine view only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "view":
        return _cmd_view(args)
    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
