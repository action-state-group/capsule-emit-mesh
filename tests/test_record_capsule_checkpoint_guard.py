#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[adv-witness-outage-serving-path] regression: a due checkpoint with an
unreachable witness must never fail the serving request.

Before the fix, capsule_sidecar.record_capsule() called
`state.checkpoint.record_appended()` unguarded -- contrast the plugin-ledger
leg a few lines below it, which already wraps the equivalent call in a broad
`except Exception`. Any exception out of the node's OWN checkpoint call
(including the too-narrow-except gap fixed in checkpointing.py: a
connection-refused/DNS-down witness raises urllib.error.URLError, which
`except CheckpointError` alone does not catch) propagated straight out of
record_capsule() and failed the exchange this sidecar was otherwise done
recording.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant
-- see the MODULE-POLLUTION GUARD note below for why capsule_sidecar/its
dependents are reloaded fresh, mirroring test_record_capsule_write_before_verify.py.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import capsule_sidecar as cs

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


class _RaisingCheckpoint:
    """Stands in for a CheckpointState whose due checkpoint hits an
    unreachable witness -- exactly the urllib.error.URLError gap ADV-11
    found, reproduced directly here rather than through the network stack."""

    def record_appended(self):
        import urllib.error

        raise urllib.error.URLError(ConnectionRefusedError("connection refused (witness down)"))


def test_checkpoint_registration_failure_never_fails_the_serving_request(tmp_path: Path, capsys) -> None:
    state = _build_state(tmp_path)
    state.checkpoint = _RaisingCheckpoint()
    capsule, signed_statement = _build_signed_capsule(state)

    # Must NOT raise -- this is the serving request itself.
    cs.record_capsule(state, capsule, signed_statement)

    # The capsule this call was actually responsible for is still recorded,
    # unaffected by the checkpoint call's failure.
    assert state.ledger_path.exists()
    assert state.last_capsule_id == capsule["capsule_id"]
    assert capsule in state.emitted
    assert "checkpoint record_appended failed" in capsys.readouterr().out
