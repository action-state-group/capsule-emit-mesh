#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-native-log-join] Join the node's operational native_log truth to
sealed capsule truth + self-coverage count.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant. The three tests marked MUTANT below each assert the specific
behaviour the task's acceptance criteria name; removing the corresponding
logic in native_log_join.py flips each one to failure.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import native_log_join as nlj  # noqa: E402


def _native(request_id: str, *, status: str, request_digest: str | None, timestamp: str = "2026-09-02T00:00:00Z") -> dict:
    return {"request_id": request_id, "timestamp": timestamp, "status": status, "request_digest": request_digest}


def _capsule(*, request_digest: str, verdict_class: str, capsule_id: str) -> dict:
    return {
        "capsule_id": capsule_id,
        "effect": {"request_digest": request_digest},
        "disposition": {"verdict_class": verdict_class},
    }


# ── join_native_log / capsule_id_for_request ───────────────────────────────

def test_matching_capsule_fills_capsule_id_column():
    native = [_native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64)]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="executed", capsule_id="cap-1")]
    rows = nlj.join_native_log(native, capsules)
    assert rows[0]["capsule_id"] == "cap-1"


def test_no_matching_capsule_is_literal_unsealed_not_blank():
    native = [_native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64)]
    rows = nlj.join_native_log(native, [])
    assert rows[0]["capsule_id"] == nlj.UNSEALED
    assert rows[0]["capsule_id"] != ""


def test_capsule_sharing_digest_but_no_real_verdict_does_not_count_as_coverage():
    """A capsule that happens to share request_digest bytes but carries no
    genuine verdict_class is not evidence this request was sealed."""
    native = [_native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64)]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="unknown_thing", capsule_id="cap-1")]
    rows = nlj.join_native_log(native, capsules)
    assert rows[0]["capsule_id"] == nlj.UNSEALED


# ── MUTANT 1: request-record count != capsule count -> coverage finding ───

def test_mutant_unsealed_count_produces_coverage_finding():
    native = [
        _native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64),
        _native("r2", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="b" * 64),
        _native("r3", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="c" * 64),
    ]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="executed", capsule_id="cap-1")]
    report = nlj.coverage_report(native, capsules)
    assert report["unsealed_count"] == 2
    assert report["coverage_summary"] == "coverage: 2 request(s) unsealed"


def test_mutant_fully_sealed_reports_no_unsealed_findings():
    native = [_native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64)]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="executed", capsule_id="cap-1")]
    report = nlj.coverage_report(native, capsules)
    assert report["unsealed_count"] == 0
    assert report["coverage_summary"] == "coverage: fully sealed"


# ── MUTANT 2: a FAILED native request with no BLOCKED/errored capsule ─────

def test_mutant_failed_request_with_no_capsule_is_surfaced_not_dropped():
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64)]
    report = nlj.coverage_report(native, [])
    assert len(report["failed_unsealed"]) == 1
    assert report["failed_unsealed"][0]["request_id"] == "r1"
    assert report["failed_unsealed"][0]["capsule_id"] == nlj.UNSEALED


def test_mutant_failed_request_backed_by_errored_capsule_is_not_a_failed_unsealed_finding():
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64)]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="errored", capsule_id="cap-1")]
    report = nlj.coverage_report(native, capsules)
    assert report["failed_unsealed"] == []


def test_mutant_failed_request_backed_by_blocked_capsule_is_not_a_failed_unsealed_finding():
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64)]
    capsules = [_capsule(request_digest="a" * 64, verdict_class="blocked", capsule_id="cap-1")]
    report = nlj.coverage_report(native, capsules)
    assert report["failed_unsealed"] == []


def test_mutant_successful_native_request_with_no_capsule_is_unsealed_but_not_failed_unsealed():
    """The failed_unsealed list is specifically about FAILED requests --
    a SUCCESS request with no capsule is still an unsealed coverage finding
    (counted in unsealed_count), just not double-reported in failed_unsealed."""
    native = [_native("r1", status=nlj.NATIVE_STATUS_SUCCESS, request_digest="a" * 64)]
    report = nlj.coverage_report(native, [])
    assert report["unsealed_count"] == 1
    assert report["failed_unsealed"] == []


# ── MUTANT 3: a runtime_shutdown gap is labeled, not hidden ───────────────

def test_mutant_unsealed_gap_inside_shutdown_window_is_labeled_runtime_down():
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64, timestamp="2026-09-02T10:05:00Z")]
    lifecycle = [
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN, "timestamp": "2026-09-02T10:00:00Z"},
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END, "timestamp": "2026-09-02T10:10:00Z"},
    ]
    report = nlj.coverage_report(native, [], lifecycle)
    row = report["rows"][0]
    assert row["capsule_id"] == nlj.UNSEALED
    assert row["finding"] == "sealing was off between 2026-09-02T10:00:00Z and 2026-09-02T10:10:00Z (runtime down)"
    assert "runtime down" in row["finding"]


def test_mutant_unsealed_gap_outside_shutdown_window_is_labeled_unsealed_not_hidden():
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64, timestamp="2026-09-02T11:00:00Z")]
    lifecycle = [
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN, "timestamp": "2026-09-02T10:00:00Z"},
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END, "timestamp": "2026-09-02T10:10:00Z"},
    ]
    report = nlj.coverage_report(native, [], lifecycle)
    row = report["rows"][0]
    # Outside the window -- must NOT be silently folded into "runtime down".
    assert row["finding"] == "unsealed"


def test_mutant_open_shutdown_window_with_no_end_still_bounds_and_labels_a_gap():
    """A begin with no matching end yet (still down as of this lifecycle
    log) must still label a gap inside it, not fall through unlabeled."""
    native = [_native("r1", status=nlj.NATIVE_STATUS_FAILED, request_digest="a" * 64, timestamp="2026-09-02T10:30:00Z")]
    lifecycle = [{"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN, "timestamp": "2026-09-02T10:00:00Z"}]
    report = nlj.coverage_report(native, [], lifecycle)
    row = report["rows"][0]
    assert "runtime down" in row["finding"]
    assert "2026-09-02T10:00:00Z" in row["finding"]


# ── shutdown_windows pairing ────────────────────────────────────────────────

def test_shutdown_windows_pairs_chronologically_and_ignores_orphan_end():
    events = [
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END, "timestamp": "2026-09-01T00:00:00Z"},  # orphan boot marker
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN, "timestamp": "2026-09-02T10:00:00Z"},
        {"event": nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END, "timestamp": "2026-09-02T10:10:00Z"},
    ]
    windows = nlj.shutdown_windows(events)
    assert windows == [("2026-09-02T10:00:00Z", "2026-09-02T10:10:00Z")]


# ── coverage is a property, not a score ─────────────────────────────────────

def test_coverage_report_has_no_pass_fail_field():
    """Self-coverage as a PROPERTY, not a score -- the report carries a count
    and labeled rows, never a pass/fail/score verdict."""
    report = nlj.coverage_report([], [])
    for banned in ("score", "pass", "passed", "grade"):
        assert banned not in report
