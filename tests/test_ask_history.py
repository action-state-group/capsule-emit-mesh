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
from evidence_responder import answer_wire


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
        assert f"record {cids[0]} (leaf 0): proven under the anchor" in rendered
        assert "anchor checkpoint: log_id=test-node" in rendered
        assert reply.cll.status == "NOT_CHECKED"  # a ledger line is not the committed entry itself

    def test_range_request_multiple_records(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 3)
        reply = ah.read_reply(ah.post_evidence_request(base_url, ah.build_request(er.Subject("range", (0, 2)))))
        assert reply.ok, reply.errors
        assert [r.capsule_id for r in ah.verified_records(reply)] == cids

    def test_expected_pin_serves_under_that_anchor(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        anchor = _anchor_of(state)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0], expected_pin=anchor)))
        assert reply.ok and reply.envelope.anchor_digest == anchor

    def test_min_freshness_time_reports_the_anchors_time(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        req = _record(cids[0], min_freshness="2000-01-01T00:00:00Z")
        reply = ah.read_reply(ah.post_evidence_request(base_url, req))
        assert reply.ok, reply.errors
        freshness = reply.envelope.freshness
        assert isinstance(freshness, str) and freshness.endswith("Z") and "." not in freshness
        late = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0], min_freshness="2999-01-01T00:00:00Z")))
        assert late.refusal is not None and late.refusal.reason == "coverage_unsatisfiable"

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
        assert "records check=False (expected False)" in rendered

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
    ``evidence_responder.answer_wire`` against a REAL ledger, and
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
            self._write(200, json.dumps(answer_wire(self.server.state, request_bytes)).encode())  # type: ignore[attr-defined]
            return
        request = {**arguments["request"], "requester_id": "local-node"}
        request_bytes = json.dumps(request).encode("utf-8")
        answer = {
            "answer": answer_wire(self.server.state, request_bytes),  # type: ignore[attr-defined]
            "request_digest": er.request_digest(request_bytes),
        }
        body = json.dumps(answer).encode()
        if self.server.duplicate_in_answer:  # type: ignore[attr-defined]
            body = body.replace(b'"answer": {', b'"answer": {"sig": "00", ', 1)
        self._write(200, body)

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
        server.duplicate_in_answer = False
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

    def test_wrapped_answer_with_a_duplicate_member_is_refused(self, mesh_host):
        """The capsules plugin's wrapper is decoded with duplicates refused,
        so a duplicate inside its answer is not collapsed away."""
        local_host_api, server, state = mesh_host
        server.duplicate_in_answer = True
        cids = _seal_and_checkpoint(state, 1)
        with pytest.raises(ValueError, match="duplicate"):
            ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, _record(cids[0]))

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
        assert "records check=False (expected False)" in rendered


class TestReadReply:
    def test_unreadable_reply(self):
        reply = ah.read_reply(ah.Exchange("00" * 32, b'{"records": []}'))
        assert not reply.ok and reply.envelope is None and reply.refusal is None

    def test_forged_refusal(self):
        forged = {"request_digest": "00" * 32, "reason": "no_such_subject", "issued_at": "2026-10-15T00:00:00Z",
                  "key_id": "ab" * 32, "sig": "cd" * 64}
        reply = ah.read_reply(ah.Exchange("00" * 32, json.dumps(forged).encode()))
        assert not reply.ok
        assert "the refusal's signature does not verify" in reply.errors

    def test_duplicate_member_is_not_a_reply(self, peer):
        """The reply is read as carried: a duplicate member, which a decoded
        dict would collapse, makes it not well formed."""
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_evidence_request(base_url, _record(cids[0]))
        duplicated = exchange.reply[:-1] + b',"issued_at":"2026-10-15T00:00:00Z"}'
        reply = ah.read_reply(ah.Exchange(exchange.request_digest, duplicated))
        assert not reply.ok and reply.envelope is None
        assert "duplicate" in reply.errors[0]

    def test_a_record_not_under_the_envelopes_anchor_is_not_trusted(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        reply = ah.read_reply(ah.post_evidence_request(base_url, _record(cids[0])))
        assert len(ah.verified_records(reply)) == 1
        other = dataclasses.replace(reply, envelope=dataclasses.replace(reply.envelope, anchor_digest="ab" * 32))
        records, _anchor, problems = ah.served_records(other)
        assert records == [] and problems == ["the envelope names another anchor than its checkpoint"]
        assert ah.verified_records(other) == []

    def test_a_malformed_witness_receipts_member_is_an_error(self, peer):
        base_url, state = peer
        cids = _seal_and_checkpoint(state, 1)
        exchange = ah.post_evidence_request(base_url, _record(cids[0]))
        wire = {**json.loads(exchange.reply), "witness_receipts": [{"checkpoint": "x"}]}
        reply = ah.read_reply(ah.Exchange(exchange.request_digest, json.dumps(wire).encode()))
        assert not reply.ok and "a witness receipt is malformed" in reply.errors


def _signer():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.generate()

    class _Signer:
        key_id = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        def sign(self, data: bytes) -> tuple[str, str]:
            return key.sign(data).hex(), self.key_id

    return _Signer()


@pytest.mark.parametrize("records", [[None, {"v": 1}], [{"body": "zz", "digest": "ab" * 32, "leaf_index": 0}], []])
def test_signed_envelope_with_malformed_records_is_read_not_raised(records):
    from agent_action_capsule.canonical import jcs

    request_bytes = json.dumps(ah.build_request(er.Subject("full_history"))).encode()
    body = {"anchor": "ab" * 32, "evidence_stream": "s", "records": records, "subject": {"full_history": None}}
    material = [("cll-checkpoint", b"\xd2")] + [("cll-inclusion-proof", b"\x82\x00\x80")] * len(records)
    envelope = er.sign_envelope(
        request_bytes, er.Subject("full_history"), "ab" * 32, jcs(body),
        signer=_signer(), issued_at="2026-10-15T00:00:00Z", verification=material,
    )
    reply = ah.read_reply(ah.Exchange(er.request_digest(request_bytes), envelope.encode("json")))
    records_read, _anchor, problems = ah.served_records(reply)
    assert records_read == [] and problems
    assert ah.verified_records(reply) == []


def _signed_checkpoints_reply(body: dict, *, anchor: str = "ab" * 32) -> ah.Exchange:
    from agent_action_capsule.canonical import jcs

    request_bytes = json.dumps(ah.build_request(er.Subject("checkpoints"))).encode()
    envelope = er.sign_envelope(
        request_bytes, er.Subject("checkpoints"), anchor, jcs(body), signer=_signer(), issued_at="2026-10-15T00:00:00Z"
    )
    return ah.Exchange(er.request_digest(request_bytes), envelope.encode("json"))


@pytest.mark.parametrize("checkpoints", [{"unexpected": {}}, [], ["not hex"], ["d2"], [{"mmr_size": 3}]])
def test_malformed_checkpoints_answer_is_a_runtime_error_for_the_default_pull(checkpoints):
    exchange = _signed_checkpoints_reply({"checkpoints": checkpoints})
    with pytest.raises(RuntimeError, match="does not check out"):
        ah._x_checkpoints(lambda _request: exchange, "x")
    _lines, problems = ah.answer_checkpoints(ah.read_reply(exchange))
    assert problems


def test_checkpoints_signed_by_another_key_than_the_responder_are_refused(node_state):
    """Statements the node signed, in an envelope another key signed: the
    statements are not the responder's."""
    import hashlib

    _seal_and_checkpoint(node_state, 1)
    lines = [json.loads(x) for x in (node_state.ledger_dir / "checkpoints.jsonl").read_text().splitlines() if x]
    anchor = hashlib.sha256(bytes.fromhex(lines[-1]["checkpoint_cose"])).hexdigest()
    body = {"anchor": anchor, "checkpoints": [line["checkpoint_cose"] for line in lines],
            "evidence_stream": "test-node", "subject": {"checkpoints": None}}
    _lines, problems = ah.answer_checkpoints(ah.read_reply(_signed_checkpoints_reply(body, anchor=anchor)))
    assert problems == ["checkpoint 0 is not the responder's, or does not verify"]


def test_a_checkpoint_list_that_skips_a_link_is_refused(node_state):
    import hashlib

    for _ in range(3):
        _seal_and_checkpoint(node_state, 1)
    request_bytes = json.dumps(ah.build_request(er.Subject("checkpoints"))).encode()
    wire = answer_wire(node_state, request_bytes)
    exchange = ah.Exchange(er.request_digest(request_bytes), json.dumps(wire).encode())
    lines, problems = ah.answer_checkpoints(ah.read_reply(exchange))
    assert len(lines) == 3 and not problems
    # Drop the middle statement and re-sign the envelope with the node key.
    from evidence_responder import node_signer

    statements = [line["checkpoint_cose"] for line in lines]
    anchor = hashlib.sha256(bytes.fromhex(statements[-1])).hexdigest()
    from agent_action_capsule.canonical import jcs

    body = {"anchor": anchor, "checkpoints": [statements[0], statements[2]], "evidence_stream": "test-node",
            "subject": {"checkpoints": None}}
    envelope = er.sign_envelope(request_bytes, er.Subject("checkpoints"), anchor, jcs(body),
                                signer=node_signer(node_state), issued_at="2026-10-15T00:00:00Z")
    _lines, problems = ah.answer_checkpoints(ah.read_reply(ah.Exchange(er.request_digest(request_bytes), envelope.encode("json"))))
    assert problems == ["a checkpoint does not extend the one listed before it"]


def test_default_pull_sizes_the_window_from_the_signed_anchor(node_state):
    """The window and the pin come from the anchor's own verified statement."""
    import hashlib

    _seal_and_checkpoint(node_state, 1)
    _seal_and_checkpoint(node_state, 2)
    request_bytes = json.dumps(ah.build_request(er.Subject("checkpoints"))).encode()
    exchange = ah.Exchange(er.request_digest(request_bytes), json.dumps(answer_wire(node_state, request_bytes)).encode())
    _reply, lines = ah._x_checkpoints(lambda _request: exchange, "x")
    assert len(lines) == 2
    request = ah._recent_records_request(lines, "x")
    raw = [json.loads(x) for x in (node_state.ledger_dir / "checkpoints.jsonl").read_text().splitlines() if x]
    anchor = hashlib.sha256(bytes.fromhex(raw[-1]["checkpoint_cose"])).hexdigest()
    from cll.checkpoint.core import leaf_count

    last = leaf_count(raw[-1]["mmr_size"]) - 1
    assert request["subject"] == {"range": [max(0, last - ah.DEFAULT_PULL_RECORDS + 1), last]}
    assert request["coverage"] == {"expected_pin": anchor}


@pytest.mark.parametrize("leaf", [0, 1, 2, 3, 7, 8, 1000, (1 << 52) - 1, 1 << 52])
def test_leaf_of_node_index_inverts_the_leaf_index(leaf):
    assert ah._leaf_of_node_index(2 * leaf - bin(leaf).count("1")) == leaf


@pytest.mark.parametrize("index", [2, 5, 6, -1, 1 << 53, True, "3", None])
def test_leaf_of_node_index_refuses_what_is_no_leaf(index):
    assert ah._leaf_of_node_index(index) is None
