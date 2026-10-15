# SPDX-License-Identifier: Apache-2.0
"""Tests for E15 -- ``evidence_server.py``'s ``POST /evidence-request`` door,
answering -00 requests with a signed envelope or refusal.

Two ledger shapes are exercised, matching the two callers named in
[mesh-e15-evidence-http-route]:

  * the sidecar's own ``LedgerStore``, checkpointed into its sibling
    ``checkpoints.jsonl``;
  * a PLUGIN-shaped ledger (a flat ``capsules.jsonl`` written directly,
    checkpointed read-only via ``checkpointing.CheckpointState`` into a
    SIBLING ``checkpoints.jsonl`` -- the shape ``capsule_sidecar.NodeState.
    plugin_checkpoint`` uses for the Rust plugin's live ledger).

Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.

See ``test_ask_history.py``'s top matter for why this file also guards
``model_identity`` before importing ``capsule_sidecar`` for real.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.request

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from agent_action_capsule import evidence_request as er
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
    checkpoint_config_path = tmp_path / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )


def _seal_and_checkpoint(state, n: int) -> list[str]:
    """Mint N well-formed capsules via capsule_emit's own ``seal()`` (a
    convenient, already-verified builder), land them in the sidecar's REAL
    cll.ledger.store.LedgerStore -- ``state.log_source`` -- and force a real
    checkpoint through the sidecar's OWN (out-of-band) checkpointing, same
    as [mesh-ledger-store-migration]'s test_evidence_responder.py."""
    caps = []
    for i in range(n):
        scratch_ledger = tempfile.mktemp(suffix="-capsule-emit-seal-scratch.jsonl")
        capsule = seal(
            None,
            action=f"act-{i}",
            operator="acme",
            anchor=False,
            ledger=scratch_ledger,
            signing_key_path=state.signing_key_path,
        ).capsule
        state.log_source.append(capsule)
        caps.append(capsule)
    assert state.checkpoint.reconnect() is not None
    return [c["capsule_id"] for c in caps]


def _rec(capsule_id: str, **members) -> dict:
    return {"subject": {"record": capsule_id}, "coverage": {"min_freshness": 0}, **members}


def _artifact(body: dict) -> dict:
    """The artifact JSON of an envelope reply, after checking the envelope."""
    envelope = er.parse_reply(json.dumps(body).encode())
    assert isinstance(envelope, er.Envelope), f"expected an envelope, got: {body}"
    envelope.verify()
    return json.loads(envelope.artifact)


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
    state = es.EvidenceServerState(
        ledger_dir=node_state.ledger_dir, ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path
    )
    server = _RunningServer(state)
    yield server, node_state
    server.close()


class TestSelfCheckpointedLedgerOverHTTP:
    def test_record_request_returns_artifact_200(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 2)
        status, body = server.post("/evidence-request", _rec(cids[0]))
        assert status == 200
        assert body["subject"] == {"record": cids[0]}
        assert body["status"] == "SATISFIED"
        bundles = _artifact(body)["bundles"]
        assert len(bundles) == 1
        assert bundles[0]["capsule_id"] == cids[0]

    def test_unknown_capsule_id_refuses_no_such_subject_never_500(self, running_server):
        server, _state = running_server
        status, body = server.post("/evidence-request", _rec("ff" * 32))
        assert status == 200  # a signed refusal, not an HTTP-level error
        assert body["reason"] == "no_such_subject"
        assert body["status"] == "NOT_FOUND"
        assert er.check_refusal(body).conformant

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
            {"subject": {"record": cids[0]}, "coverage": {"expected_pin": "0" * 64}},
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
            "/evidence-request", _rec(cids[0], nonce="a")
        )
        _s2, body_b = server.post(
            "/evidence-request", _rec(cids[0], nonce="b")
        )
        # Same artifact; only the request digest (and the signature over it) differs.
        assert body_a["artifact"] == body_b["artifact"]
        assert body_a["request_digest"] != body_b["request_digest"]

    def test_returned_bundle_tamper_detected(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 1)
        _status, body = server.post("/evidence-request", _rec(cids[0]))
        tampered = _artifact(body)["bundles"][0]
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


class TestUnreadableLedger:
    def test_a_corrupt_checkpoints_file_is_a_500_not_a_dropped_connection(self, running_server):
        server, state = running_server
        cids = _seal_and_checkpoint(state, 1)
        (state.ledger_dir / "checkpoints.jsonl").write_text("{not json\n")
        status, body = server.post("/evidence-request", _rec(cids[0]))
        assert status == 500
        assert body["error"] == "ledger_unreadable"


class TestServerWithNoLedgerAtAll:
    def test_missing_ledger_dir_refuses_never_500(self, tmp_path):
        # Point straight at a ledger_dir that was never created -- the
        # "server with no such ledger" mutant guard.
        keys_dir = tmp_path / "keys"
        from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

        load_or_create_signing_key(keys_dir)
        state = es.EvidenceServerState(
            ledger_dir=tmp_path / "nonexistent-ledger",
            ledger_path=tmp_path / "nonexistent-ledger" / "capsules.jsonl",
            signing_key_path=keys_dir / NODE_KEY_FILENAME,
        )
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", _rec("ab" * 32))
            assert status == 200
            assert body["reason"] == "no_such_subject"
        finally:
            server.close()


class TestPluginShapedLedger:
    """[mesh-e15-evidence-http-route] Step 0's finding: a ledger checkpointed
    READ-ONLY via ``checkpointing.CheckpointState`` into a sibling
    ``checkpoints.jsonl`` (the Rust-plugin shape) is invisible to
    ``capsule_emit.bundle.bundle()``, which only reads in-band checkpoint
    stamps. The responder reads the sibling file itself."""

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
        # Why the responder reads checkpoints.jsonl itself: bundle() against
        # the raw ledger path never finds a checkpoint at all.
        ledger_dir, _key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        from capsule_emit.bundle import BundleError, bundle

        with pytest.raises(BundleError):
            bundle(ledger_dir / "capsules.jsonl", cids[0])

    def test_plugin_shaped_request_over_http_returns_artifact(self, tmp_path, stub_witness):
        ledger_dir, key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        state = es.EvidenceServerState(ledger_dir=ledger_dir, ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", _rec(cids[0]))
        finally:
            server.close()
        assert status == 200
        assert _artifact(body)["bundles"][0]["capsule_id"] == cids[0]

    def test_door_never_writes_into_the_plugin_ledger_dir(self, tmp_path, stub_witness):
        ledger_dir, key_path, cids = self._plugin_shaped_ledger(tmp_path, stub_witness)
        before_capsules = (ledger_dir / "capsules.jsonl").read_bytes()
        before_entries = sorted(p.name for p in ledger_dir.iterdir())

        state = es.EvidenceServerState(ledger_dir=ledger_dir, ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            server.post("/evidence-request", _rec(cids[0]))
            server.post("/evidence-request", _rec(cids[1]))
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

        state = es.EvidenceServerState(ledger_dir=ledger_dir, ledger_path=ledger_dir / "capsules.jsonl", signing_key_path=key_path)
        server = _RunningServer(state)
        try:
            status, body = server.post("/evidence-request", _rec(cap["capsule_id"]))
        finally:
            server.close()
        assert status == 200
        assert body["reason"] == "coverage_unsatisfiable"
