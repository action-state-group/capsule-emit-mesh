# SPDX-License-Identifier: Apache-2.0
"""Tests for ``ask_history.py`` -- the requester side of the -00 evidence
request exchange: posts to a REAL running ``evidence_server.py``, checks the
signed envelope or refusal offline, renders the history card.

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

import dataclasses
import http.server
import json
import sys
import tempfile
import threading
import types
from typing import Any

_stubbed_model_identity = "model_identity" not in sys.modules
if _stubbed_model_identity:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from agent_action_capsule import evidence_request as er
from capsule_emit import seal, witness

import ask_history as ah
import capsule_sidecar as cs
import evidence_server as es
from evidence_responder import handle_evidence_request, reply_to_wire


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
    """Mint N well-formed capsules via capsule_emit's own ``seal()``, land
    them in the sidecar's REAL cll.ledger.store.LedgerStore -- ``state.
    log_source`` -- and force a real checkpoint through the sidecar's OWN
    (out-of-band) checkpointing -- see [mesh-ledger-store-migration]'s
    test_evidence_responder.py for the same pattern."""
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


@pytest.fixture
def peer(node_state):
    state = es.EvidenceServerState(
        ledger_dir=node_state.ledger_dir, ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path
    )
    server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", node_state
    server.shutdown()
    thread.join(timeout=5)


def _record(cid: str, **coverage) -> dict:
    return ah.build_request(er.Subject("record", cid), **coverage)


def _anchor_of(state) -> str:
    """The digest of the latest anchor the node holds: its checkpoint's COSE
    statement, hashed."""
    import hashlib

    lines = [json.loads(line) for line in (state.ledger_dir / "checkpoints.jsonl").read_text().splitlines() if line]
    return hashlib.sha256(bytes.fromhex(lines[-1]["checkpoint_cose"])).hexdigest()


class TestBuildRequest:
    def test_default_coverage_is_min_freshness_zero(self):
        assert ah.build_request(er.Subject("full_history")) == {
            "subject": {"full_history": None},
            "coverage": {"min_freshness": 0},
        }

    def test_expected_pin_and_options(self):
        req = ah.build_request(
            er.Subject("range", (0, 4)), expected_pin="ab" * 32, derivation="served_summary/1", nonce="n1"
        )
        assert req == {
            "subject": {"range": [0, 4]},
            "coverage": {"expected_pin": "ab" * 32},
            "derivation": "served_summary/1",
            "nonce": "n1",
        }
        er.parse_request(json.dumps(req).encode())  # a well-formed -00 request

    def test_both_coverage_members_is_an_error(self):
        with pytest.raises(ValueError):
            ah.build_request(er.Subject("full_history"), expected_pin="ab" * 32, min_freshness=1)


class TestEndToEnd:
    def test_record_request_verifies_and_renders_history_card(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0])))
        assert reply.ok, reply.errors
        assert reply.envelope is not None and reply.envelope.anchor_digest == _anchor_of(state)
        rendered = ah.render_artifact(reply, node_id="m4")
        assert "ARTIFACT subject=record" in rendered
        assert "verify_bundle.ok=True" in rendered
        assert "history card" in rendered
        assert "continuity=" in rendered

    def test_range_request_multiple_bundles(self, peer):
        base_url, state = peer
        _seal_and_checkpoint(state, 3)
        reply = ah.read_reply(ah.post_evidence_request(base_url, ah.build_request(er.Subject("range", (0, 2)))))
        assert reply.ok, reply.errors
        assert len(ah.verified_bundles(reply)) == 3

    def test_expected_pin_serves_under_that_anchor(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        anchor = _anchor_of(state)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0], expected_pin=anchor)))
        assert reply.ok and reply.envelope.anchor_digest == anchor

    def test_unheld_pin_is_a_signed_coverage_refusal(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0], expected_pin="ab" * 32)))
        assert reply.ok and reply.refusal.reason == "coverage_unsatisfiable"

    def test_unknown_record_renders_signed_refusal(self, peer):
        base_url, state = peer
        _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record("ff" * 32)))
        assert reply.refusal is not None
        rendered = ah.render_refusal(reply)
        assert "REFUSAL reason=no_such_subject" in rendered
        assert "signed, conformant and answering this request: True" in rendered

    def test_reply_to_another_request_is_flagged(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_evidence_request(base_url, _record(cids[0]))
        reply = ah.read_reply(ah.Exchange("00" * 32, exchange.reply))
        assert not reply.ok
        assert "the envelope answers another request" in reply.errors

    def test_pinned_responder_key(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_evidence_request(base_url, _record(cids[0]))
        responder = ah.read_reply(exchange).envelope.responder
        assert ah.read_reply(exchange, responder_key=responder).ok
        assert not ah.read_reply(exchange, responder_key="ab" * 32).ok

    def test_tamper_check_detects_a_flipped_byte(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0])))
        rendered = ah.render_artifact(reply, node_id="m4", tamper_check=True)
        assert "envelope verifies=False (expected False)" in rendered
        assert "verify.ok=False (expected False)" in rendered

    def test_checkpoints_subject_renders_the_chain(self, peer):
        base_url, state = peer
        _seal_and_checkpoint(state, 2)
        reply = ah.read_reply(ah.post_evidence_request(base_url, ah.build_request(er.Subject("checkpoints"))))
        assert reply.ok, reply.errors
        rendered = ah.render_artifact(reply, node_id="m4")
        assert "checkpoints=" in rendered and "history card:" in rendered

    def test_main_cli_smoke(self, peer, capsys):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        rc = ah.main([base_url, "--subject", "record", "--capsule-id", cids[0]])
        assert rc == 0
        out = capsys.readouterr().out
        assert "ARTIFACT" in out

    def test_main_cli_requires_range_for_range(self, peer):
        base_url, _state = peer
        with pytest.raises(SystemExit):
            ah.main([base_url, "--subject", "range"])


class _MeshToolCallHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for mesh-llm's ``POST /api/plugins/<name>/tools/<tool>``
    route driving the Mesh-LLM plugin's ``mesh_evidence_request`` tool
    (``mesh_evidence_bridge::handle_mesh_evidence_request``): unwraps the
    ``{"peer_id", "request"}`` arguments, adds a ``requester_id`` and
    re-serializes the request as the plugin does, answers with the REAL
    ``evidence_responder.handle_evidence_request`` against a REAL ledger, and
    reports ``{"answer", "request_digest"}`` for the bytes it sent. Proves
    ``ask_history.py``'s mesh-carrier wiring without a compiled plugin.
    """

    server_version = "fake-mesh-llm-host/0.1"

    def do_POST(self) -> None:  # BaseHTTPRequestHandler API names this do_POST
        expected_path = f"/api/plugins/{self.server.plugin_name}/tools/mesh_evidence_request"  # type: ignore[attr-defined]
        if self.path != expected_path:
            self._write(404, json.dumps({"error": "not_found"}).encode())
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        arguments = json.loads(self.rfile.read(length) if length else b"{}")
        self.server.calls.append(arguments)  # type: ignore[attr-defined]

        if arguments.get("peer_id") == self.server.unreachable_peer_id:  # type: ignore[attr-defined]
            self._write(502, json.dumps({"error": "peer does not answer evidence requests"}).encode())
            return

        if self.server.passthrough:  # type: ignore[attr-defined]
            # This repo's admission-policy plugin: serde_json::to_vec of the
            # request as given, and the peer's reply returned as is.
            request_bytes = json.dumps(arguments["request"], separators=(",", ":")).encode("utf-8")
            result = handle_evidence_request(self.server.state, request_bytes)  # type: ignore[attr-defined]
            self._write(200, json.dumps(reply_to_wire(result)).encode())
            return
        request = {**arguments["request"], "requester_id": "local-node"}
        request_bytes = json.dumps(request).encode("utf-8")
        result = handle_evidence_request(self.server.state, request_bytes)  # type: ignore[attr-defined]
        answer = {"answer": reply_to_wire(result), "request_digest": er.request_digest(request_bytes)}
        self._write(200, json.dumps(answer).encode())

    def _write(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        pass


class TestMeshCarrier:
    """``--via mesh`` -- the plugin-mesh-stream carrier."""

    @pytest.fixture
    def mesh_host(self, node_state):
        state = es.EvidenceServerState(
            ledger_dir=node_state.ledger_dir, ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MeshToolCallHandler)
        server.plugin_name = "admission-policy"
        server.state = state
        server.calls = []
        server.unreachable_peer_id = "ff" * 32
        server.passthrough = False
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}", server, node_state
        server.shutdown()
        thread.join(timeout=5)

    def test_post_mesh_evidence_request_wraps_peer_id_and_request(self, mesh_host):
        local_host_api, server, state = mesh_host
        cids = _seal_and_checkpoint(state, 1)
        req = _record(cids[0])
        exchange = ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, req)
        assert server.calls == [{"peer_id": "aa" * 32, "request": req}]
        # The digest is of the bytes the plugin sent, requester_id included.
        assert ah.read_reply(exchange).ok

    def test_passthrough_carrier_binds_the_request_it_forwarded(self, mesh_host):
        """This repo's admission-policy plugin returns the peer's reply as
        is: the digest is of the compact JSON it sent."""
        local_host_api, server, state = mesh_host
        server.passthrough = True
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, _record(cids[0]))
        reply = ah.read_reply(exchange)
        assert reply.ok, reply.errors
        assert reply.envelope is not None

    def test_main_cli_via_mesh_renders_artifact(self, mesh_host, capsys):
        local_host_api, _server, state = mesh_host
        cids = _seal_and_checkpoint(state, 1)
        rc = ah.main([
            "aa" * 32, "--subject", "record", "--capsule-id", cids[0],
            "--via", "mesh", "--local-host-api", local_host_api,
        ])
        assert rc == 0
        assert "ARTIFACT" in capsys.readouterr().out

    def test_main_cli_via_mesh_reports_a_peer_that_never_answers(self, mesh_host, capsys):
        local_host_api, server, _state = mesh_host
        rc = ah.main([
            server.unreachable_peer_id, "--subject", "range", "--range", "0", "1",
            "--via", "mesh", "--local-host-api", local_host_api,
        ])
        assert rc == 1
        assert "failed" in capsys.readouterr().err

    def test_via_mesh_tamper_check_detects_a_flipped_byte(self, mesh_host):
        """Tamper detection is carrier-independent: it inspects the reply
        that arrived, never how it arrived."""
        local_host_api, _server, state = mesh_host
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, _record(cids[0]))
        rendered = ah.render_artifact(ah.read_reply(exchange), node_id="m4", tamper_check=True)
        assert "envelope verifies=False (expected False)" in rendered
        assert "verify.ok=False (expected False)" in rendered


class TestReadReply:
    def test_unreadable_reply(self):
        reply = ah.read_reply(ah.Exchange("00" * 32, {"bundles": []}))
        assert not reply.ok and reply.envelope is None and reply.refusal is None

    def test_forged_refusal(self):
        forged = {"request_digest": "00" * 32, "reason": "no_such_subject", "issued_at": "2026-10-15T00:00:00Z",
                  "key_id": "ab" * 32, "sig": "cd" * 64}
        reply = ah.read_reply(ah.Exchange("00" * 32, forged))
        assert not reply.ok
        assert "the refusal's signature does not verify" in reply.errors

    def test_bundle_not_under_the_anchor_is_left_out(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0])))
        moved = ah.Reply(ok=True, errors=(), envelope=reply.envelope, body={**reply.body, "anchor": "x"})
        assert len(ah.verified_bundles(moved)) == 1
        other = ah.Reply(ok=True, errors=(), envelope=dataclasses.replace(reply.envelope, anchor_digest="ab" * 32),
                         body=reply.body)
        bundles, problems = ah.artifact_bundles(other)
        assert bundles == [] and "not proven under the envelope's anchor" in problems[0]


def test_signed_envelope_with_malformed_bundles_is_read_not_raised():
    from agent_action_capsule.canonical import jcs
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    class _Signer:
        def __init__(self) -> None:
            self._key = Ed25519PrivateKey.generate()
            self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        def sign(self, body: bytes) -> tuple[str, str]:
            return self._key.sign(body).hex(), self.key_id

    request_bytes = json.dumps(ah.build_request(er.Subject("full_history"))).encode()
    envelope = er.sign_envelope(
        request_bytes, er.Subject("full_history"), "ab" * 32, jcs({"bundles": [None, {"v": 1}]}),
        signer=_Signer(), issued_at="2026-10-15T00:00:00Z",
    )
    reply = ah.read_reply(ah.Exchange(er.request_digest(request_bytes), json.loads(envelope.encode("json"))))
    assert reply.ok
    bundles, problems = ah.artifact_bundles(reply)
    assert bundles == [] and len(problems) == 2
    assert ah.verified_bundles(reply) == []
