#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""`coordinator verify` — the offline half of the ask->verify quickstart.

Takes a signed coordinator receipt (mesh_coordinator_receipt_emitter.py) and
whatever stage bundles were disclosed to it (either local files or fetched
live from a `capsule_disclosure_endpoint.py`), runs the existing offline
verifier (`mesh_coordinator_bundle_flow.verify_coordinator_receipt`), and
prints the per-stage trust-ladder grades HONESTLY — never rounding a grade up
past what the disclosed bytes actually support.

This module adds NO new verification logic of its own for the binding
question (order <-> bytes <-> hop): that is entirely
`verify_coordinator_receipt`, unchanged. What it adds is presentation plus
four extra, per-stage grades read directly off a stage's own disclosed bytes
— and ONLY for stages `verify_coordinator_receipt` already marked `green`.
A `gap` or `mismatch` stage's bundle (if any was even disclosed) is NOT
trustworthy enough to grade further; printing grades for it would dress up a
failure as a partial pass, which is exactly the false-green failure mode this
whole flow exists to avoid.

The four grades, and exactly what backs each one (no invented rungs):

  cross_party_rung
      Reused verbatim from `mesh_record_verifier.verify_record_bytes()` --
      DERIVED from the stage record's own requester_commitment bytes, never
      read off a self-declared label. `unilateral_fallback` or
      `full_bilateral` (+ the identity-limitation caveat when applicable).
      "n/a" only when the record carries no lifecycle block to derive from.

  runtime
      The record's own `model_attestation.compute_attestation.runtime`
      string, printed labeled "self-attested (unverified)". This repo's
      Python producer path has no independent-measurer rung (the
      `self_measured` / `os_measured` / `tee_measured` ladder in
      docs/REDTEAM-RUNG3.md is the Rust mesh-llm plugin producer's own rung
      and is not surfaced by this Python record path) -- so this grade never
      claims more than "the producer says this", which is what it is.

  log_integrity
      Reuses `checkpointing.describe_witness_state()` verbatim against a
      checkpoint record the stage node chose to disclose inside
      `StageBundle.inclusion_proof["checkpoint"]` (capsule_emit.checkpoint's
      own CheckpointRecord/WitnessRecord shape) -- unwitnessed <
      self-checkpointed < independently witnessed, exactly the three-state
      grading checkpointing.py already established. "unwitnessed" when no
      inclusion proof was disclosed at all -- an honest floor, not a penalty.

  freshness
      The record's own top-level `timestamp` (committed into capsule_id,
      §5.1), bucketed against wall-clock age. This is the producer's OWN
      claim of when it made the record -- self-reported, not witnessed --
      labeled as such.
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from capsule_emit.checkpoint import CheckpointRecord, WitnessRecord, leaf_count

from checkpointing import describe_witness_state
from mesh_coordinator_bundle_flow import (
    StageBundle,
    _read_receipt_block,  # same 3-line field-path knowledge verify_coordinator_receipt already has -- reused, not re-derived
    stage_bundle_from_dict,
    verify_coordinator_receipt,
)
from mesh_record_verifier import RecordVerificationError, verify_record_bytes

__all__ = [
    "grade_cross_party_rung",
    "grade_runtime",
    "grade_log_integrity",
    "grade_freshness",
    "print_report",
    "main",
]


# ---------------------------------------------------------------------------
# The four honest, per-stage grades (only ever called on a `green` stage)
# ---------------------------------------------------------------------------

def grade_cross_party_rung(bundle: StageBundle) -> str:
    try:
        verdict = verify_record_bytes(bundle.canonical_bytes)
    except RecordVerificationError as exc:
        return f"n/a ({exc})"
    grade = verdict.cross_party_rung
    if verdict.identity_limitation:
        grade += f"\n        caveat: {verdict.identity_limitation}"
    return grade


def grade_runtime(bundle: StageBundle) -> str:
    compute_attestation = (bundle.stage_capsule.get("model_attestation") or {}).get("compute_attestation") or {}
    runtime = compute_attestation.get("runtime")
    if not runtime:
        return "absent (no compute_attestation.runtime in this record)"
    return f"self-attested (unverified): {runtime}"


def grade_log_integrity(bundle: StageBundle) -> str:
    proof = bundle.inclusion_proof or {}
    cp_dict = proof.get("checkpoint") if isinstance(proof, dict) else None
    if not cp_dict:
        return "unwitnessed (no inclusion proof disclosed for this stage)"
    try:
        witnesses = [WitnessRecord(**w) for w in cp_dict.get("witnesses", [])]
        cp = CheckpointRecord(**{**cp_dict, "witnesses": witnesses})
        current_entries = leaf_count(cp.mmr_size)
    except (TypeError, KeyError) as exc:
        return f"n/a (disclosed inclusion proof carries a malformed checkpoint record: {exc})"
    return describe_witness_state(cp, current_entries)


def _parse_capsule_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def grade_freshness(bundle: StageBundle, *, now: datetime) -> str:
    ts = bundle.stage_capsule.get("timestamp")
    if not ts:
        return "n/a (record carries no timestamp)"
    try:
        made_at = _parse_capsule_timestamp(ts)
    except ValueError:
        return f"n/a (unparseable timestamp {ts!r})"
    age_seconds = (now - made_at).total_seconds()
    if age_seconds < 0:
        bucket = "n/a"
    elif age_seconds < 300:
        bucket = "fresh (<5m)"
    elif age_seconds < 3600:
        bucket = "aging (<1h)"
    elif age_seconds < 86400:
        bucket = "stale (<1d)"
    else:
        bucket = "stale (>=1d)"
    return f"{bucket} -- {int(age_seconds)}s since producer's own committed timestamp {ts} (self-reported, not witnessed)"


# ---------------------------------------------------------------------------
# Gathering bundles: local files and/or a capsule_disclosure_endpoint fetch
# ---------------------------------------------------------------------------

def _fetch_bundle(base_url: str, *, run_id: str, hop_id: str, timeout: float) -> StageBundle | None:
    url = f"{base_url.rstrip('/')}/bundle/{run_id}/{hop_id}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # operator-supplied endpoint, same trust boundary as a local file
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # declined / absent -- a stage-node "no bundle" answer, not an error
        raise
    return stage_bundle_from_dict(data)


def _parse_kv_args(specs: list[str], *, flag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for spec in specs:
        hop_id, sep, value = spec.partition("=")
        if not sep:
            raise SystemExit(f"{flag} expects HOP_ID=VALUE, got {spec!r}")
        out[hop_id] = value
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def summarize(verdict) -> tuple[str, int]:
    """(headline, exit_code) -- distinct from `verdict.ok`, which only means

    "no mismatch was found" and stays True even when every present stage is
    an unresolved gap (see verify_coordinator_receipt's own docstring). A
    headline that just echoed `ok` as "GREEN" would round an all-gap result
    up into looking like a pass, exactly what this CLI must not do.
    """
    if verdict.mismatch_count > 0:
        return f"MISMATCH DETECTED -- {verdict.mismatch_count} of {verdict.present_count} present stage(s) failed binding", 1
    if verdict.present_count == 0:
        return "NO STAGES PRESENT -- nothing to verify", 2
    if verdict.green_count < verdict.present_count:
        gaps = verdict.present_count - verdict.green_count
        return f"INCOMPLETE -- {gaps} of {verdict.present_count} present stage(s) not disclosed to this verifier (gap, not a failure)", 2
    return f"ALL GREEN -- {verdict.green_count}/{verdict.present_count} present stages verified", 0


def print_report(verdict, bundles: dict[str, StageBundle], *, now: datetime) -> None:
    print(f"run_id: {verdict.run_id}")
    print(f"order:  {' -> '.join(verdict.ordered_hops)}")
    print("signer: UNVERIFIED (Class-1 payload verify only -- see verify_coordinator_receipt docstring)\n")
    icon = {"green": "PASS", "gap": "GAP ", "mismatch": "FAIL"}
    for stage in sorted(verdict.stages, key=lambda s: s.seq):
        mark = icon.get(stage.status, "??? ")
        print(f"[{mark}] seq {stage.seq}  {stage.hop_id}  claimed_bundle={stage.claimed_bundle}  {stage.detail}")
        if stage.status != "green":
            print("        grades: n/a -- stage did not verify green, not graded further\n")
            continue
        bundle = bundles[stage.hop_id]
        print(f"        cross_party_rung : {grade_cross_party_rung(bundle)}")
        print(f"        runtime          : {grade_runtime(bundle)}")
        print(f"        log_integrity    : {grade_log_integrity(bundle)}")
        print(f"        freshness        : {grade_freshness(bundle, now=now)}\n")
    headline, _ = summarize(verdict)
    print(f"=== {headline} ===")
    if verdict.errors:
        for err in verdict.errors:
            print(f"error: {err}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="capsule-coordinator-verify",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("receipt", help="path to the signed coordinator receipt capsule JSON")
    parser.add_argument(
        "--bundle", action="append", default=[], metavar="HOP_ID=PATH",
        help="a locally-held disclosed StageBundle JSON file for one hop (repeatable)",
    )
    parser.add_argument(
        "--bundle-url", action="append", default=[], metavar="HOP_ID=BASE_URL",
        help="ask a running capsule_disclosure_endpoint at BASE_URL for this hop's bundle (repeatable)",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="seconds to wait per --bundle-url fetch")
    args = parser.parse_args(argv)

    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    run_id = _read_receipt_block(receipt).get("run_id", "")

    bundles: dict[str, StageBundle] = {}
    for hop_id, path in _parse_kv_args(args.bundle, flag="--bundle").items():
        bundles[hop_id] = stage_bundle_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    for hop_id, base_url in _parse_kv_args(args.bundle_url, flag="--bundle-url").items():
        fetched = _fetch_bundle(base_url, run_id=run_id, hop_id=hop_id, timeout=args.timeout)
        if fetched is None:
            print(f"ask {hop_id} @ {base_url} -> declined/absent (404)")
            continue
        bundles[hop_id] = fetched

    verdict = verify_coordinator_receipt(receipt, bundles)
    print_report(verdict, bundles, now=datetime.now(timezone.utc))
    _, exit_code = summarize(verdict)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
