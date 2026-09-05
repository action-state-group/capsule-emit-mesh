# SPDX-License-Identifier: Apache-2.0
"""Tests for E15 -- ``evidence_server.py``'s ``POST /evidence-request`` door
and its plugin-ledger bridge (``_merged_evidence_view``).

Two ledger shapes are exercised, matching the two callers named in
[mesh-e15-evidence-http-route]:

  * a SELF-checkpointed ledger (``capsule_sidecar.NodeState``'s own log,
    checkpointed in-band via ``capsule_emit.witness.push()``) -- the
    straightforward case, ``answer()`` unchanged;
  * a PLUGIN-shaped ledger (capsules written directly, checkpointed
    read-only via ``checkpointing.CheckpointState`` into a SIBLING
    ``checkpoints.jsonl`` -- the exact shape ``capsule_sidecar.NodeState.
    plugin_checkpoint`` uses for the Rust plugin's live ledger) -- the
    Step 0 finding this module's ``_merged_evidence_view`` bridges.

Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.

See ``test_ask_history.py``'s top matter for why this file also guards
``model_identity`` before importing ``capsule_sidecar`` for real.
"""
from __future__ import annotations

import json
import sys
import threading
import types
import urllib.error
import urllib.request

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from capsule_emit import seal, witness
from capsule_emit.bundle import Bundle, verify_bundle
from cll.checkpoint import CheckpointConfig

import capsule_sidecar as cs
import evidence_server as es
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource


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


class _RunningServer:
    def __init__(self, state: es.EvidenceServerState):
        self.server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(f"{self.base_url}{path}", data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def get(self, path: str) -> tuple[int, bytes]:
        req = urllib.request.Request(f"{self.base_url}{path}", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()


@pytest.fixture
def running_server(node_state):
    state = es.EvidenceServerState(ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path)
    server = _RunningServer(state)
    yield server, node_state
    server.close()


class TestSelfCheckpointedLedgerOverHTTP:
    def test_record_request_returns_artifact_200(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 2)
        status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}})
        assert status == 200
        assert body["subject_kind"] == "record"
        assert len(body["bundles"]) == 1
        assert body["bundles"][0]["capsule_id"] == cids[0]

    def test_unknown_capsule_id_refuses_no_such_record_never_500(self, running_server):
        server, _state = running_server
        status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": "ff" * 32}, "coverage": {}})
        assert status == 200  # a signed refusal, not an HTTP-level error
        assert body["reason"] == "no_such_record"
        assert "sig" in body and "key_id" in body

    def test_malformed_body_refuses_request_malformed(self, running_server):
        server, _state = running_server
        req = urllib.request.Request(
            f"{server.base_url}/evidence-request", data=b"not json", method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
        assert body["reason"] == "request_malformed"

    def test_wrong_expected_pin_refuses_coverage_unsatisfiable(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 1)
        status, body = server.post(
            "/evidence-request",
            {
                "subject": {"kind": "record", "capsule_id": cids[0]},
                "coverage": {"expected_pin": {"root": "0" * 64, "mmr_size": 999}},
            },
        )
        assert status == 200
        assert body["reason"] == "coverage_unsatisfiable"

    def test_unknown_path_404(self, running_server):
        server, _state = running_server
        req = urllib.request.Request(f"{server.base_url}/nope", method="POST", data=b"{}")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 404

    def test_caller_invariance_over_the_wire(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 1)
        _s1, body_a = server.post(
            "/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}, "nonce": "a"}
        )
        _s2, body_b = server.post(
            "/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}, "nonce": "b"}
        )
        assert json.dumps(body_a, sort_keys=True) == json.dumps(body_b, sort_keys=True)

    def test_returned_bundle_tamper_detected(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 1)
        _status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}})
        tampered = json.loads(json.dumps(body["bundles"][0]))
        tampered["receipt"] = {**tampered["receipt"], "capsule_id": "0" * 64}
        ok, _errors = verify_bundle(Bundle.from_dict(tampered))
        assert ok is False

    def test_get_root_never_leaks_the_ledger_filesystem_path(self, running_server):
        """[adv-evidence-door-caps-and-subjects] ADV-10: GET / used to echo
        this node's absolute ledger path -- a gratuitous local-filesystem
        disclosure a neutral witness has no reason to make. It must carry
        no evidence, and in particular no path."""
        server, state = running_server
        status, body = server.get("/")
        assert status == 200
        text = body.decode()
        assert str(state.ledger_path) not in text
        assert "ledger" not in text  # no field even naming the concept, let alone its value
        assert text == "capsule-evidence-server: ready\n"


class TestServerWithNoLedgerAtAll:
    def test_missing_ledger_dir_refuses_never_500(self, tmp_path):
        # Point straight at a ledger_dir that was never created -- the
        # "server with no such ledger" mutant guard.
        keys_dir = tmp_path / "keys"
        from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

        load_or_create_signing_key(keys_dir)
        state = es.EvidenceServerState(
            ledger_path=tmp_path / "nonexistent-ledger" / "capsules.jsonl",
            signing_key_path=keys_dir / NODE_KEY_FILENAME,
        )
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": "ab" * 32}, "coverage": {}})
            assert status == 200
            assert body["reason"] == "no_such_record"
        finally:
            server.close()


class TestPluginLedgerBridge:
    """[mesh-e15-evidence-http-route] Step 0's finding: a ledger checkpointed
    READ-ONLY via ``checkpointing.CheckpointState`` into a sibling
    ``checkpoints.jsonl`` (the Rust-plugin shape) is invisible to
    ``bundle()`` unless bridged -- ``_merged_evidence_view`` does that."""

    def _plugin_shaped_ledger(self, tmp_path, stub_witness):
        ledger_dir = tmp_path / "plugin-ledger"
        ledger_dir.mkdir()
        keys_dir = tmp_path / "keys"
        from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

        load_or_create_signing_key(keys_dir)
        key_path = keys_dir / NODE_KEY_FILENAME

        caps = [
            seal(None, action=f"act-{i}", operator="acme", anchor=False, ledger=ledger_dir / "capsules.jsonl", signing_key_path=key_path).capsule
            for i in range(2)
        ]
        # Checkpoint READ-ONLY, the plugin_checkpoint wiring's own shape --
        # never capsule_emit.witness.push() (that would write in-band and
        # defeat the point of this fixture).
        signer = Ed25519Signer(key_path)
        log = JsonlLogSource(ledger_dir / "capsules.jsonl")
        cfg = CheckpointConfig(cadence_entries=1, max_lag_entries=10, ts_urls=[])
        state = CheckpointState.load(ledger_dir=ledger_dir, log_source=log, cfg=cfg, signer=signer, log_id="plugin-log")
        state.reconnect()
        assert (ledger_dir / "checkpoints.jsonl").exists()
        return ledger_dir, key_path, [c["capsule_id"] for c in caps]

    def test_unbridged_ledger_path_would_never_see_the_checkpoint(self, tmp_path, stub_witness):
        # Establishes the FAILURE this bridge fixes: bundle() against the
        # RAW ledger path (no bridge) never finds a checkpoint at all.
        ledger_dir, _key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        from capsule_emit.bundle import BundleError, bundle

        with pytest.raises(BundleError):
            bundle(ledger_dir / "capsules.jsonl", cids[0])

    def test_bridged_request_over_http_returns_artifact(self, tmp_path, stub_witness):
        ledger_dir, key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        state = es.EvidenceServerState(ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}})
        finally:
            server.close()
        assert status == 200
        assert "bundles" in body, f"expected an Artifact, got a refusal: {body}"
        assert body["bundles"][0]["capsule_id"] == cids[0]

    def test_bridge_never_writes_into_the_plugin_ledger_dir(self, tmp_path, stub_witness):
        ledger_dir, key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        before_capsules = (ledger_dir / "capsules.jsonl").read_bytes()
        before_entries = sorted(p.name for p in ledger_dir.iterdir())

        state = es.EvidenceServerState(ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[0]}, "coverage": {}})
            server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cids[1]}, "coverage": {}})
        finally:
            server.close()

        assert (ledger_dir / "capsules.jsonl").read_bytes() == before_capsules
        assert sorted(p.name for p in ledger_dir.iterdir()) == before_entries

    def test_no_checkpoints_yet_refuses_coverage_unsatisfiable_never_crashes(self, tmp_path, stub_witness):
        ledger_dir = tmp_path / "fresh-plugin-ledger"
        ledger_dir.mkdir()
        keys_dir = tmp_path / "keys"
        from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

        load_or_create_signing_key(keys_dir)
        key_path = keys_dir / NODE_KEY_FILENAME
        cap = seal(None, action="act-0", operator="acme", anchor=False, ledger=ledger_dir / "capsules.jsonl", signing_key_path=key_path).capsule

        state = es.EvidenceServerState(ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", {"subject": {"kind": "record", "capsule_id": cap["capsule_id"]}, "coverage": {}})
        finally:
            server.close()
        assert status == 200
        assert body["reason"] in ("no_such_record", "coverage_unsatisfiable")
