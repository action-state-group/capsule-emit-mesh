"""Producers emit draft-mih-scitt-agent-action-capsule-05; verifiers accept
-04 and -05.

The sidecar seals through agent_action_capsule's emit(), which stamps -05
(format 4) from 0.6.0 on -- the floor in requirements.txt and pyproject.toml.
The revision never selects a digest or verification algorithm, so a -04
capsule still verifies. Released vectors and ledgers keep the revision they
were sealed with.

Uses the real modules, as test_record_capsule_write_before_verify.py does
(see its MODULE-POLLUTION GUARD): some sibling files install stand-ins at
collection time.
"""
from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path

import capsule_sidecar as cs

SPEC_05 = "draft-mih-scitt-agent-action-capsule-05"
SPEC_04 = "draft-mih-scitt-agent-action-capsule-04"


def _real_state(tmp_path: Path) -> cs.NodeState:
    importlib.reload(sys.modules["model_identity"])
    importlib.reload(cs)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
    )


def _seal(state: cs.NodeState) -> dict:
    return cs.build_capsule(
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


def test_sidecar_seal_stamps_spec_version_05(tmp_path: Path) -> None:
    capsule = _seal(_real_state(tmp_path))
    assert capsule["spec_version"] == SPEC_05
    assert capsule["format_version"] == "4"
    assert capsule["canonicalization_id"] == "jcs"
    assert cs.verify_capsule(capsule).ok


def test_the_installed_emit_defaults_to_05() -> None:
    # The floor (agent-action-capsule>=0.6.0) is what makes the sidecar's
    # capsules -05: build_capsule passes no spec_version of its own.
    emit_module = sys.modules["agent_action_capsule.emit"]
    assert inspect.signature(emit_module.emit).parameters["spec_version"].default == SPEC_05
    assert "spec_version" not in inspect.getsource(cs.build_capsule)


def test_a_04_capsule_still_verifies() -> None:
    emit_module = sys.modules["agent_action_capsule.emit"]
    for spec in (SPEC_04, SPEC_05):
        capsule = emit_module.emit("mesh/spec-version/1", "decide", "op", "dev", spec_version=spec)
        assert capsule["spec_version"] == spec
        assert cs.verify_capsule(capsule).ok, spec
