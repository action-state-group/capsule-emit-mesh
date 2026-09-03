#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""native-log-join -- join a node's operational request truth to sealed
capsule truth, and report the gap as a self-coverage FINDING.

[mesh-native-log-join] Two sources, never blended:

  - ``native_log.jsonl`` (``source: native_log``) -- capsule_sidecar.py's OWN
    record of every ``/v1/chat/completions`` request it handled, written
    regardless of whether sealing succeeded. This is "the node's operational
    /logs truth": what was actually asked of this node, including requests
    the sidecar itself failed to seal (a bad-JSON body, an uncaught sidecar
    exception, a crash mid-stream).
  - the sealed capsule ledger (``source: sealed_ledger``, ``capsules.jsonl``)
    -- what actually got attested.

A request-record count that does not equal the sealed-capsule count for a
window is not a rendering quirk; it is the coverage finding this module
exists to surface. Self-coverage is reported as a PROPERTY (a count + labeled
rows), never a score -- there is no pass/fail threshold here, only an honest
count of what is and is not backed by a capsule.

Every native_log row gets exactly one ``capsule_id`` column: either the
capsule_id of a matching sealed capsule, or the literal string
``"unsealed"`` -- never blank, never silently dropped. A ``FAILED`` native
request (the sidecar returned a non-2xx / error response) with no matching
BLOCKED/errored capsule is exactly as "unsealed" as a missing SUCCESS
capsule would be -- refusals are first-class evidence gaps here, not a
different, lesser category (see capsule-emit-mesh's [mesh-e14-evidence-
responder] item for the analogous rule on the responder side).

A gap that falls inside a ``runtime_shutdown_begin`` -> ``runtime_shutdown_end``
lifecycle window is a NAMED, expected reason ("sealing was off between T1
and T2 (runtime down)") -- stated plainly in the row's own finding text,
never hidden inside the same bucket as an unexplained gap.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SOURCE_NATIVE_LOG = "native_log"
SOURCE_SEALED_LEDGER = "sealed_ledger"

NATIVE_STATUS_SUCCESS = "SUCCESS"
NATIVE_STATUS_FAILED = "FAILED"

#: The capsule_id column's value when no sealed capsule backs a native_log
#: row -- a finding in its own right, never an empty string.
UNSEALED = "unsealed"

#: verdict_class values that count as "this request WAS sealed, one way or
#: another" -- the capsule takes an honest position on the outcome (ran
#: clean, ran and errored, or was refused pre-dispatch). A capsule that
#: merely shares a request_digest but carries none of these is not evidence
#: of coverage for that request.
SEALED_VERDICT_CLASSES = frozenset({"executed", "errored", "blocked"})

LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN = "runtime_shutdown_begin"
LIFECYCLE_RUNTIME_SHUTDOWN_END = "runtime_shutdown_end"


def _capsule_request_digest(capsule: dict[str, Any]) -> str | None:
    return (capsule.get("effect") or {}).get("request_digest")


def _capsule_verdict_class(capsule: dict[str, Any]) -> str | None:
    return (capsule.get("disposition") or {}).get("verdict_class")


def capsule_id_for_request(request_digest: str | None, capsule_records: list[dict[str, Any]]) -> str | None:
    """The sealed capsule_id for *request_digest*, or None.

    Matches on ``effect.request_digest`` AND requires a genuine
    ``disposition.verdict_class`` from ``SEALED_VERDICT_CLASSES`` -- matching
    on the digest alone would count a capsule that happens to share bytes
    with this request but never took a verdict on it (should not occur
    today, but the join must not silently trust digest equality as coverage
    on its own).
    """
    if not request_digest:
        return None
    for capsule in capsule_records:
        if not isinstance(capsule, dict):
            continue
        if _capsule_request_digest(capsule) != request_digest:
            continue
        if _capsule_verdict_class(capsule) not in SEALED_VERDICT_CLASSES:
            continue
        return capsule.get("capsule_id")
    return None


def join_native_log(
    native_entries: list[dict[str, Any]],
    capsule_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Every native_log entry, unmodified, plus its ``capsule_id`` column."""
    rows = []
    for entry in native_entries:
        found = capsule_id_for_request(entry.get("request_digest"), capsule_records)
        rows.append({**entry, "capsule_id": found or UNSEALED})
    return rows


def shutdown_windows(lifecycle_events: list[dict[str, Any]]) -> list[tuple[str, str | None]]:
    """Pair chronological ``runtime_shutdown_begin`` -> ``runtime_shutdown_end``
    events into ``[begin, end)`` windows.

    A ``begin`` with no later ``end`` is still open -- returned as
    ``(begin, None)``: down as of ``begin`` and, as far as this lifecycle log
    is concerned, still down. An ``end`` with no preceding open ``begin`` is
    ignored -- it names a boot this log has no matching shutdown for, so
    there is nothing to bound.
    """
    windows: list[tuple[str, str | None]] = []
    open_begin: str | None = None
    for event in sorted(lifecycle_events, key=lambda e: e.get("timestamp") or ""):
        kind = event.get("event")
        if kind == LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN:
            open_begin = event.get("timestamp")
        elif kind == LIFECYCLE_RUNTIME_SHUTDOWN_END and open_begin is not None:
            windows.append((open_begin, event.get("timestamp")))
            open_begin = None
    if open_begin is not None:
        windows.append((open_begin, None))
    return windows


def _in_window(timestamp: str | None, window: tuple[str, str | None]) -> bool:
    if not timestamp:
        return False
    begin, end = window
    if timestamp < begin:
        return False
    return end is None or timestamp < end


def label_unsealed(row: dict[str, Any], windows: list[tuple[str, str | None]]) -> str:
    """The honest label for one unsealed row.

    A ``runtime_shutdown`` window the row's timestamp falls inside is named
    explicitly; anything else is an unexplained gap, labeled plainly as such
    rather than folded into the same bucket.
    """
    for begin, end in windows:
        if _in_window(row.get("timestamp"), (begin, end)):
            return f"sealing was off between {begin} and {end or 'now'} (runtime down)"
    return "unsealed"


def coverage_report(
    native_entries: list[dict[str, Any]],
    capsule_records: list[dict[str, Any]],
    lifecycle_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The self-coverage finding for one window of native_log entries.

    Self-coverage is a PROPERTY (a count + labeled rows), never a score --
    there is no pass/fail threshold, only an honest accounting of what is
    and is not backed by a sealed capsule.
    """
    windows = shutdown_windows(lifecycle_events or [])
    rows = join_native_log(native_entries, capsule_records)
    unsealed_rows = [row for row in rows if row["capsule_id"] == UNSEALED]
    for row in unsealed_rows:
        row["finding"] = label_unsealed(row, windows)
    failed_unsealed = [row for row in unsealed_rows if row.get("status") == NATIVE_STATUS_FAILED]
    unsealed_count = len(unsealed_rows)
    coverage_summary = (
        "coverage: fully sealed"
        if unsealed_count == 0
        else f"coverage: {unsealed_count} request(s) unsealed"
    )
    return {
        "rows": rows,
        "unsealed_count": unsealed_count,
        "coverage_summary": coverage_summary,
        "failed_unsealed": failed_unsealed,
        "shutdown_windows": windows,
    }


def render_coverage_table(report: dict[str, Any], *, out: Any = None) -> None:
    if out is None:
        out = sys.stdout
    rows = report["rows"]
    if not rows:
        print("native-log join: no native_log entries", file=out)
        return
    col_req, col_status, col_cap = 34, 8, 14
    print(f"\n{report['coverage_summary']}  ({len(rows)} native request(s))\n", file=out)
    header = f"  {'request_id':<{col_req}}  {'status':<{col_status}}  {'capsule_id':<{col_cap}}  finding"
    print(header, file=out)
    print("-" * len(header), file=out)
    for row in rows:
        print(
            f"  {str(row.get('request_id', ''))[:col_req]:<{col_req}}  "
            f"{str(row.get('status', '')):<{col_status}}  "
            f"{str(row['capsule_id'])[:col_cap]:<{col_cap}}  "
            f"{row.get('finding', '')}",
            file=out,
        )
    if report["failed_unsealed"]:
        print(f"\n{len(report['failed_unsealed'])} FAILED request(s) with no BLOCKED/errored capsule:", file=out)
        for row in report["failed_unsealed"]:
            print(f"  - {row.get('request_id')}  {row.get('finding')}", file=out)
    print(file=out)


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


def _cmd_join(args: argparse.Namespace) -> int:
    native_entries = _read_jsonl(Path(args.native_log))
    try:
        from capsule_emit.ledger import read_ledger

        capsule_records = read_ledger(args.ledger)
    except Exception:
        capsule_records = _read_jsonl(Path(args.ledger))
    lifecycle_events = _read_jsonl(Path(args.lifecycle)) if args.lifecycle else []

    report = coverage_report(native_entries, capsule_records, lifecycle_events)

    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    render_coverage_table(report)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="native-log-join",
        description="Join a node's operational native_log to its sealed capsule ledger "
        "and report the self-coverage finding.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    join = sub.add_parser("join", help="join native_log.jsonl to a capsule ledger and report coverage")
    join.add_argument("--native-log", required=True, metavar="PATH", help="capsule_sidecar.py's native_log.jsonl")
    join.add_argument("--ledger", required=True, metavar="PATH", help="the sealed capsule JSONL ledger (capsules.jsonl)")
    join.add_argument(
        "--lifecycle",
        metavar="PATH",
        default=None,
        help="optional lifecycle_events.jsonl (runtime_shutdown_begin/end) to bound expected sealing gaps",
    )
    join.add_argument("--json", dest="as_json", action="store_true", help="raw JSON output of the coverage report")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "join":
        return _cmd_join(args)
    parser = _build_parser()
    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
