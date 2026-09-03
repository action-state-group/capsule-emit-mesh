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
(requested|served) and `counterparty` -- neither of which was a capsule
field when this module was written. This viewer never ADDS a `role` field
to any capsule here; that promotion is the separate, gated registry-entry
track ([mesh-exchange-role-field], scitt-payload-binding's
`mesh-inference-exchange` provisional, CPB #70). Per that track's LOCKED
ruling, `role` is a genuine party-role axis and is NOT derivable from
`observation_point` alone (`gateway_ingress` maps to neither requested nor
served) -- so the label here also weighs which log produced the record.

2026-09-03 update ([mesh-b1-requestor-capsule-ledger]): capsule_sidecar.py
now PROVISIONALLY emits its own `x-mesh-poc-v1.role` /
`.observation_point` pair, hard-coded ahead of CPB #70's promotion (see
its `# PROVISIONAL: pending CPB #70 promotion` definition site). This
viewer's `label_role()` below reads that field as authoritative when
present, falling back to the pre-existing source-log/observation_point
heuristic only for records that don't carry it (e.g. the Rust plugin,
which this task did not touch) -- so a genuine requester record is no
longer silently mislabeled "served".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from advertisement import Advertisement, reconcile_advertised_vs_served
from agent_action_capsule import Finding
from agent_action_capsule.transparent import SubstrateInputError, verify_transparent
from agent_action_capsule.verify import verify_store
from capsule_emit.ledger import read_ledger
from capsule_emit.signing import verify_capsule_signature
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
    """Display-only role label -- never persisted here.

    [mesh-b1-requestor-capsule-ledger] capsule_sidecar.py now provisionally
    seals its own `x-mesh-poc-v1.role` (see its `PROVISIONAL: pending CPB
    #70 promotion` definition site) -- when a record carries that field, it
    is the authoritative source-of-truth and is returned as-is. Records
    without it (e.g. the Rust plugin's, or older sidecar records) fall back
    to the pre-existing observation_point/source-log heuristic below.
    """
    poc_role = _poc_block(record).get("role")
    if poc_role in ("requested", "served"):
        return poc_role
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


def reconcile_record(record: dict[str, Any]) -> dict[str, Any]:
    """Re-derive the advertised-vs-served reconciliation from a record's OWN bytes.

    verify-after-advertise (TRUST-MODEL.md §12.3): a node's ``advertisement``
    (its CLAIM) and its ``serving_provenance`` (what ran) are co-carried in the
    same ``x-mesh-poc-v1`` block, so this reconciliation is self-contained --
    it never trusts the producer's own co-carried ``advertisement_reconciliation``
    verdict, it RE-DERIVES it here from the advertisement + serving_provenance,
    exactly what an offline third party would do (§10 Rule 3: the advertised
    name is a claim; the record says which it holds).

    Returns the ``reconcile_advertised_vs_served`` dict -- ``overall`` is
    ``advertisement_absent`` when the record co-carries no advertisement (a
    missing claim is NOT a silent green; §10 Rule 1).
    """
    poc = _poc_block(record)
    advertisement = poc.get("advertisement")
    ad = Advertisement.from_value(advertisement) if advertisement else None
    return reconcile_advertised_vs_served(ad, poc.get("serving_provenance"))


def label_advertised_vs_served(record: dict[str, Any]) -> str:
    """Compact one-word-ish label for the machine-view row.

    ``mismatch(field,...)`` names the broken-promise fields loudly (never a
    silent green); ``match`` is a kept promise in what was both claimed and
    served; ``advertisement_absent`` / ``no_served_facts`` are the honest
    three-state non-passes.
    """
    result = reconcile_record(record)
    overall = result["overall"]
    if overall == "mismatch":
        return "mismatch(" + ",".join(result["mismatches"]) + ")"
    return overall


def _issuer_key_for(ledger_dir: Path, issuer_key: Path | None) -> Path | None:
    """Default issuer pubkey lookup for a ledger_dir's detached statements --
    the same convention `stranger_verify_bundle.py::_issuer_key_for` uses, so
    both tools resolve one node's key the same way."""
    if issuer_key is not None:
        return issuer_key
    candidate = ledger_dir.parent / "keys" / "node-key.pub.pem"
    return candidate if candidate.exists() else None


def _detached_statement_verified(ledger_dir: Path, capsule_id: str, issuer_key: Path | None) -> bool | None:
    """Verify capsule_id's DETACHED COSE_Sign1 Signed Statement
    (`signed-statements/<capsule_id>.cose`) -- neither the Rust plugin nor
    the Python sidecar embeds a self-attested `signature`/`key_id` inline
    (see `stranger_verify_bundle.py::_transparent_check`, which this
    mirrors); the producer signature for these ledgers lives here instead.

    Returns True/False on a definitive verdict, or None when there is
    nothing to check (no statement on disk, or no issuer key resolvable) --
    the caller then falls back to the honest "no signature evidence" False
    rather than treating "nothing to check" as a pass.
    """
    if issuer_key is None:
        return None
    statement_path = ledger_dir / "signed-statements" / f"{capsule_id}.cose"
    if not statement_path.exists():
        return None
    try:
        report = verify_transparent(statement_path=str(statement_path), issuer_key_path=str(issuer_key))
    except (OSError, SubstrateInputError):
        return False
    return bool(report.ok)


def verify_results_for(
    records: list[dict[str, Any]],
    *,
    ledger_dir: Path | None = None,
    issuer_key: Path | None = None,
) -> list | None:
    """Best-effort per-record verify, or None on any error.

    Content-hash/chain integrity (`agent_action_capsule.verify_store`) runs
    first and gates everything else -- a signature over self-inconsistent
    content is never reported ok. On top of that, two independent producer-
    signature rungs, same split as `stranger_verify_bundle.py`: a record
    carrying an inline `signature`/`key_id` envelope is checked in place
    (`verify_capsule_signature`); a record with neither falls back to its
    DETACHED `signed-statements/<capsule_id>.cose` Signed Statement, when
    ``ledger_dir`` is given. A record with no inline envelope AND no
    verifiable detached statement reports ok=False -- honest fail-closed,
    not a False that only means "the viewer didn't look."

    Mirrors capsule-emit's own `ledger view` CLI (`_cmd_ledger_view`): verify
    is best-effort for a viewer, never fatal to rendering the ledger. Callers
    that also need a capsule_id -> ok mapping should build it from this same
    result list (see ``_verify_ok_map``) rather than calling verify twice.
    """
    if not records:
        return None
    try:
        results = verify_store(records)
        resolved_key = _issuer_key_for(ledger_dir, issuer_key) if ledger_dir is not None else issuer_key
        for record, result in zip(records, results):
            if not isinstance(record, dict):
                result.ok = False
                continue
            capsule_id = record.get("capsule_id", "<none>")
            if "signature" in record and "key_id" in record:
                if not verify_capsule_signature(record):
                    result.ok = False
                    result.findings.append(
                        Finding(
                            code="producer_signature_invalid",
                            detail=(
                                f"capsule_id={capsule_id}: self-attested Ed25519 signature "
                                "does not verify against key_id"
                            ),
                            severity="error",
                        )
                    )
                continue
            detached_ok = (
                _detached_statement_verified(ledger_dir, capsule_id, resolved_key)
                if ledger_dir is not None
                else None
            )
            if detached_ok is not True:
                result.ok = False
                reason = (
                    "detached signed-statements/<capsule_id>.cose did not verify"
                    if detached_ok is False
                    else "no inline producer signature and no verifiable detached signed statement"
                )
                result.findings.append(
                    Finding(
                        code="producer_signature_invalid",
                        detail=f"capsule_id={capsule_id}: {reason}",
                        severity="error",
                    )
                )
        return results
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
    `capsule_id` (content address).

    A capsule_id seen from more than one source is not a duplicate to
    discard -- it is the strongest accountability signal this viewer can
    show: BOTH of this machine's writers independently recorded the same
    content. Such a row is marked `witnessed_by_both` and keeps every
    source's own verify result (`verify_ok` is True only if every source
    that recorded it verified True, False if any source failed verify,
    else None) rather than silently keeping the first source and dropping
    the second.
    """
    seen: dict[str, dict[str, Any]] = {}
    verify_by_source: dict[str, dict[str, bool | None]] = {}
    order: list[str] = []
    for source_log, records, verify_results in sources:
        vmap = _verify_ok_map(records, verify_results)
        for record in records:
            capsule_id = record.get("capsule_id", "")
            if not capsule_id:
                continue
            verify_ok = vmap.get(capsule_id)
            if capsule_id in seen:
                row = seen[capsule_id]
                if source_log not in row["source_logs"]:
                    row["source_logs"].append(source_log)
                verify_by_source[capsule_id][source_log] = verify_ok
                continue
            seen[capsule_id] = {
                "capsule_id": capsule_id,
                "timestamp": record.get("timestamp"),
                "source_logs": [source_log],
                "role": label_role(record, source_log),
                "counterparty": label_counterparty(record),
                # verify-after-advertise (§12.3): the compact advertised-vs-served
                # verdict, re-derived from this record's own advertisement +
                # serving_provenance (never the co-carried producer verdict).
                "advertised_vs_served": label_advertised_vs_served(record),
            }
            verify_by_source[capsule_id] = {source_log: verify_ok}
            order.append(capsule_id)
    order.sort(key=lambda cid: seen[cid].get("timestamp") or "")
    rows = []
    for cid in order:
        row = seen[cid]
        oks = list(verify_by_source[cid].values())
        if any(ok is False for ok in oks):
            row["verify_ok"] = False
        elif all(ok is True for ok in oks):
            row["verify_ok"] = True
        else:
            row["verify_ok"] = None
        row["witnessed_by_both"] = len(row["source_logs"]) > 1
        row["source_log"] = "+".join(row["source_logs"])
        rows.append(row)
    return rows


def render_machine_view(rows: list[dict[str, Any]], *, out: Any = None) -> None:
    if out is None:
        out = sys.stdout

    if not rows:
        print("machine view: no records in either log", file=out)
        return

    col_id, col_log, col_role, col_cp, col_avs = 14, 15, 9, 20, 22
    print(f"\nmachine view  ({len(rows)} record(s) across both logs)\n", file=out)
    header = (
        f"  {'capsule_id':<{col_id}}  {'log':<{col_log}}  {'role':<{col_role}}  "
        f"{'counterparty':<{col_cp}}  {'advertised_vs_served':<{col_avs}}  verify  timestamp"
    )
    print(header, file=out)
    print("-" * len(header), file=out)
    for row in rows:
        vok = row["verify_ok"]
        v_str = "✓" if vok is True else ("✗" if vok is False else "—")
        avs = row.get("advertised_vs_served") or "—"
        print(
            f"  {row['capsule_id'][:col_id]:<{col_id}}  "
            f"{row['source_log']:<{col_log}}  "
            f"{row['role']:<{col_role}}  "
            f"{row['counterparty'][:col_cp]:<{col_cp}}  "
            f"{avs[:col_avs]:<{col_avs}}  "
            f"{v_str:<6}  "
            f"{row.get('timestamp') or ''}",
            file=out,
        )
    print(file=out)


def _cmd_view(args: argparse.Namespace) -> int:
    issuer_key = Path(args.issuer_key) if args.issuer_key else None
    sources: list[tuple[str, str, list[dict[str, Any]], list | None]] = []
    if args.plugin_log:
        records = read_ledger(args.plugin_log)
        ledger_dir = Path(args.plugin_log).parent
        sources.append(
            (SOURCE_PLUGIN, args.plugin_log, records, verify_results_for(records, ledger_dir=ledger_dir, issuer_key=issuer_key))
        )
    if args.sidecar_log:
        records = read_ledger(args.sidecar_log)
        ledger_dir = Path(args.sidecar_log).parent
        sources.append(
            (SOURCE_SIDECAR, args.sidecar_log, records, verify_results_for(records, ledger_dir=ledger_dir, issuer_key=issuer_key))
        )

    if not sources:
        print("capsule-mesh view: give at least one of --plugin-log / --sidecar-log", file=sys.stderr)
        return 1

    if getattr(args, "html", None):
        # Thin composition of the words-first, role-organised offline viewer.
        # One neutral core (the fragment mechanism + capsule_mesh_view labels);
        # this is only the label -> HTML entry point, no logic duplicated here.
        from capsule_mesh_viewer import encode_fragment, load_disclosures, render_mesh_viewer_html, to_fragment_payload

        # Prefer the plugin log when both are given (it is the serving-side
        # producer whose serving_provenance the roles read).
        label, path, records, _vr = next(
            (s for s in sources if s[0] == SOURCE_PLUGIN), sources[0]
        )
        witness = None
        if args.witness:
            with open(args.witness, encoding="utf-8") as fh:
                text = fh.read().strip()
            witness = json.loads(text.splitlines()[0] if "\n" in text else text)
        ledger_dir = Path(path).parent
        # [disclosure-default-on] Auto-load whatever capsule_sidecar.py's
        # DEFAULT-ON preimage capture wrote next to this log's ledger dir, so a
        # fresh sidecar-sealed capsule shows disclosed text without extra flags.
        payload = to_fragment_payload(
            records,
            source_log=label,
            witness_checkpoint=witness,
            disclose=load_disclosures(ledger_dir) or None,
            operator=records[0].get("operator") if records else None,
            ledger_dir=ledger_dir,
        )
        fragment = encode_fragment(payload)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_mesh_viewer_html(fragment))
        permalink = f"file://{Path(args.html).resolve()}#{fragment}"
        if args.permalink_out:
            with open(args.permalink_out, "w", encoding="utf-8") as fh:
                fh.write(permalink + "\n")
        print(f"capsule-mesh view --html: {len(records)} capsule(s) from the {label} log -> {args.html}")
        print(f"  {permalink}")
        return 0

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
    view.add_argument(
        "--issuer-key",
        metavar="PATH",
        default=None,
        help="PEM pubkey for detached signed-statements/*.cose; defaults to "
        "<log's dir>/../keys/node-key.pub.pem for each log",
    )
    view.add_argument("--json", dest="as_json", action="store_true", help="raw JSON output of the machine view")
    view.add_argument(
        "--no-logs",
        action="store_true",
        help="skip printing each log's own capsule-emit ledger view; machine view only",
    )
    view.add_argument(
        "--html",
        metavar="PATH",
        default=None,
        help="instead of the ASCII machine view, emit the words-first, role-organised "
        "OFFLINE HTML viewer (4 roles x 3 questions, fragment-carried, verifies in-browser) "
        "to PATH -- composes capsule_mesh_viewer over these logs' labels",
    )
    view.add_argument(
        "--witness",
        metavar="PATH",
        default=None,
        help="optional COSE checkpoint receipt (json/jsonl) to anchor the third-party "
        "completeness answer in --html",
    )
    view.add_argument(
        "--permalink-out",
        metavar="PATH",
        default=None,
        help="with --html, also write the file:// permalink here",
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
