# SPDX-License-Identifier: Apache-2.0
"""Tests for ``ask_history.py`` -- the requester side of E15's HTTP
evidence door: posts to a REAL running ``evidence_server.py``, verifies the
response offline, renders the history card.

Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.

Alphabetically ahead of ``test_bilateral_demo.py``/``test_forwarded_copy_
and_keys.py``/``test_replay_spot_check.py`` -- the three files that stub
``model_identity`` (a no-op ``load_manifest``) at collection time when it
is not yet installed, and whose OWN tests depend on that stub staying in
place (see ``tests/conftest.py``'s note on why that stub is never bound to
the real module globally). Since THIS file collects first and imports
``capsule_sidecar`` for real, it must install the SAME stub itself before
doing so -- otherwise it would import the real ``model_identity`` first and
permanently deny those three files their stub for the rest of the process.
"""
from __future__ import annotations

import json
import sys
import threading
import types

_stubbed_model_identity = "model_identity" not in sys.modules
if _stubbed_model_identity:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from capsule_emit import seal, witness

import ask_history as ah
import capsule_sidecar as cs
import evidence_server as es


@pytest.fixture(autouse=True)
def _clean_witness_state():
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False
    yield
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False


@pytest.fixture
def stub_witness(monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "stub")


@pytest.fixture
def node_state(tmp_path, stub_witness):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
    )


def _resolve_signer(state):
    from capsule_emit.signing import resolve_signer

    return resolve_signer(str(state.ledger_path), key_path=state.signing_key_path)


def _seal_and_checkpoint(state, n: int) -> list[str]:
    caps = [
        seal(
            None,
            action=f"act-{i}",
            operator="acme",
            anchor=False,
            ledger=state.ledger_path,
            signing_key_path=state.signing_key_path,
        ).capsule
        for i in range(n)
    ]
    witness.push(str(state.ledger_path), signer=_resolve_signer(state))
    return [c["capsule_id"] for c in caps]


@pytest.fixture
def peer(node_state):
    state = es.EvidenceServerState(ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path)
    server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", node_state
    server.shutdown()
    thread.join(timeout=5)


class TestEndToEnd:
    def test_record_request_verifies_and_renders_history_card(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        req = ah._build_request_map(
            subject_kind="record", capsule_id=cids[0], selector=None,
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_evidence_request(base_url, req)
        assert "bundles" in payload
        rendered = ah.render_artifact(payload, node_id="m4")
        assert "ARTIFACT" in rendered
        assert "history card" in rendered
        assert "continuity=" in rendered

    def test_range_request_multiple_bundles(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 3)
        req = ah._build_request_map(
            subject_kind="range", capsule_id=None, selector=f"{cids[0]}..{cids[-1]}",
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_evidence_request(base_url, req)
        assert len(payload["bundles"]) == 3

    def test_unknown_record_renders_signed_refusal(self, peer):
        base_url, _state = peer
        req = ah._build_request_map(
            subject_kind="record", capsule_id="ff" * 32, selector=None,
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_evidence_request(base_url, req)
        assert "reason" in payload
        rendered = ah.render_refusal(payload)
        assert "REFUSAL reason=no_such_record" in rendered
        assert "signature verifies offline: True" in rendered

    def test_tamper_check_detects_a_flipped_byte(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        req = ah._build_request_map(
            subject_kind="record", capsule_id=cids[0], selector=None,
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_evidence_request(base_url, req)
        rendered = ah.render_artifact(payload, node_id="m4", tamper_check=True)
        assert "verify.ok=False (expected False)" in rendered

    def test_main_cli_smoke(self, peer, capsys):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        rc = ah.main([base_url, "--subject", "record", "--capsule-id", cids[0]])
        assert rc == 0
        out = capsys.readouterr().out
        assert "ARTIFACT" in out

    def test_main_cli_requires_selector_for_range(self, peer):
        base_url, _state = peer
        with pytest.raises(SystemExit):
            ah.main([base_url, "--subject", "range"])
