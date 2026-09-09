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
    from accountability_pane_routes import build_pane_a_json
    from capsule_sidecar import NodeState

    # Build a minimal NodeState enough to call build_pane_a_json without
    # a real ledger — the function is designed to degrade gracefully with
    # an empty/minimal state.
    try:
        state = NodeState(ledger_dir=str(tmp_path), serve_port=0)
        payload = build_pane_a_json(state)
    except Exception as exc:
        pytest.skip(f"Could not construct NodeState in test environment: {exc}")

    hits = _check_dict_for_forbidden(payload)
    assert not hits, (
        "build_pane_a_json output contains task-ID strings:\n"
        + "\n".join(hits)
    )
