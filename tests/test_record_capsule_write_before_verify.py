#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[adv-run-2-fix-batch] B3 regression: capsule_sidecar.record_capsule() must
verify a capsule BEFORE writing anything to disk, not after.

Before the fix, record_capsule() appended to the ledger and wrote a signed
.cose statement, THEN called verify_capsule() and raised if it failed -- by
which point the failing capsule was already permanently on disk with a
valid-looking signed statement next to it, even though in-memory chain state
(state.last_capsule_id, state.emitted) correctly skipped past it.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.

MODULE-POLLUTION GUARD
    Some sibling test files (test_forwarded_copy_and_keys.py,
    test_bilateral_demo.py, test_replay_spot_check.py) unconditionally
    `setattr` fake implementations onto agent_action_capsule.canonical/
    contracts/emit/verify and model_identity at collection time -- these are
    the REAL modules in sys.modules, not stand-ins, so this permanently
    corrupts them for the rest of the session regardless of collection order
    (pytest collects every file before running any test). capsule_sidecar
    imports names from all five modules at module level, so a plain `import
    capsule_sidecar` after any of those files collect silently binds to the
    fakes. `_real_capsule_sidecar()` reloads all five real modules, then
    capsule_sidecar itself, immediately before use at test EXECUTION time --
    so this file's tests build a genuine capsule no matter what any other
    file did during collection.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

import capsule_sidecar as cs

# `agent_action_capsule/__init__.py` does `from .emit import emit`, which
# shadows the `emit` SUBMODULE attribute on the package with the `emit`
# FUNCTION -- `import agent_action_capsule.emit as x` binds `x` to that
# function, not the submodule, so reloading it would fail. sys.modules is
# unaffected by that shadowing and always holds the real submodule objects.
_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _real_capsule_sidecar():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


def _build_state(tmp_path: Path) -> cs.NodeState:
    _real_capsule_sidecar()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
    )


def _build_signed_capsule(state: cs.NodeState) -> tuple[dict, bytes]:
    capsule = cs.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="sidecar_generated_fallback",
        request_json={"model": "test-model", "messages": []},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )
    signed_statement = cs.sign_capsule(state, capsule)
    return capsule, signed_statement


class TestRecordCapsuleVerifiesBeforeWriting:

    def test_genuine_capsule_records_and_verifies_clean(self, tmp_path: Path) -> None:
        # positive control: record_capsule isn't vacuously a no-op guard.
        state = _build_state(tmp_path)
        capsule, signed_statement = _build_signed_capsule(state)
        assert cs.verify_capsule(capsule).ok

        cs.record_capsule(state, capsule, signed_statement)

        assert state.ledger_path.exists()
        assert len(state.ledger_path.read_text().splitlines()) == 1
        assert state.last_capsule_id == capsule["capsule_id"]
        assert capsule in state.emitted

    def test_capsule_failing_verify_is_never_persisted_to_the_ledger(self, tmp_path: Path) -> None:
        state = _build_state(tmp_path)
        capsule, signed_statement = _build_signed_capsule(state)

        # ATTACK: corrupt the capsule post-build so it fails its own verify(),
        # exactly as the report's repro did.
        capsule["model_attestation"]["compute_attestation"]["agent_output_digest"] = "c" * 64
        assert not cs.verify_capsule(capsule).ok

        with pytest.raises(RuntimeError, match="fails its own verify"):
            cs.record_capsule(state, capsule, signed_statement)

        assert not state.ledger_path.exists(), (
            "a capsule that fails verify() must never reach the ledger file"
        )
        statement_path = state.statements_dir / f"{capsule['capsule_id']}.cose"
        assert not statement_path.exists(), (
            "a capsule that fails verify() must never get a signed .cose statement on disk"
        )
        assert state.last_capsule_id is None
        assert capsule not in state.emitted
