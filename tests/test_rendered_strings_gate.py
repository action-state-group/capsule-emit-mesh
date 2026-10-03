# SPDX-License-Identifier: Apache-2.0
"""Grep gate: no task-id strings reach rendered UI output.

Checks that SHARED_ABSENT_REASON, ASKED_ABSENT_REASON, and the
weights_digest reason string do not contain internal task IDs or
PR references, and that the accountability card JSON outputs are
likewise clean.
"""
from __future__ import annotations

import re
import sys
import os

import pytest

# Pattern that must NOT appear in any rendered/user-visible string
FORBIDDEN_PATTERN = re.compile(r"\[mesh-|\bcapsule-emit-mesh\s*#|\[mesh-e[0-9]")


# ---------------------------------------------------------------------------
# Constant checks
# ---------------------------------------------------------------------------


def test_shared_absent_reason_clean() -> None:
    """SHARED_ABSENT_REASON must not contain internal task IDs."""
    from self_accountability import SHARED_ABSENT_REASON

    assert not FORBIDDEN_PATTERN.search(SHARED_ABSENT_REASON), (
        f"SHARED_ABSENT_REASON contains forbidden task-ID vocabulary: "
        f"{SHARED_ABSENT_REASON!r}"
    )


def test_asked_absent_reason_clean() -> None:
    """ASKED_ABSENT_REASON must not contain internal task IDs."""
    from peer_accountability_tab import ASKED_ABSENT_REASON

    assert not FORBIDDEN_PATTERN.search(ASKED_ABSENT_REASON), (
        f"ASKED_ABSENT_REASON contains forbidden task-ID vocabulary: "
        f"{ASKED_ABSENT_REASON!r}"
    )


# ---------------------------------------------------------------------------
# JSON output checks — build_pane_a_json must not carry task IDs in output
# ---------------------------------------------------------------------------


def _check_dict_for_forbidden(obj: object, path: str = "$") -> list[str]:
    """Walk *obj* recursively and return paths where a string value
    matches FORBIDDEN_PATTERN."""
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(_check_dict_for_forbidden(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_check_dict_for_forbidden(v, f"{path}[{i}]"))
    elif isinstance(obj, str) and FORBIDDEN_PATTERN.search(obj):
        hits.append(f"{path} = {obj!r}")
    return hits


def test_pane_a_json_no_task_ids(tmp_path: "pytest.TempPathFactory") -> None:
    """build_pane_a_json output must not contain internal task IDs."""
    import json

    from accountability_pane_routes import build_pane_a_json
    from capsule_sidecar import default_state

    # A real NodeState over an empty ledger (same shape as
    # test_accountability_pane_routes.py's node_state fixture); the builder
    # degrades gracefully with no records. This used to construct
    # NodeState(ledger_dir=..., serve_port=0) inside a try/skip -- NodeState
    # has no such constructor, so the gate silently never ran.
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    state = default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
    )
    payload = build_pane_a_json(state)

    hits = _check_dict_for_forbidden(payload)
    assert not hits, (
        "build_pane_a_json output contains task-ID strings:\n"
        + "\n".join(hits)
    )
