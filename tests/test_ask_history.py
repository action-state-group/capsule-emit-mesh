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

import http.server
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
from evidence_responder import handle_evidence_request


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


class _MeshToolCallHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for mesh-llm's ``POST /api/plugins/<name>/tools/<tool>``
    route driving the Rust admission-policy plugin's ``mesh_evidence_request``
    tool (``mesh_evidence_bridge::handle_mesh_evidence_request``): unwraps the
    SAME ``{"peer_id", "request"}`` arguments shape the real handler parses,
    then answers with the REAL ``evidence_responder.handle_evidence_request``
    against a REAL ledger -- exactly what the Rust bridge's proxy-to-
    ``evidence_server.py`` does, minus the Rust process itself. Proves
    ``ask_history.py``'s mesh-carrier URL/body wiring against the real
    request/response shape without needing a compiled plugin binary.
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

        request_bytes = json.dumps(arguments["request"]).encode("utf-8")
        result = handle_evidence_request(self.server.state, request_bytes)  # type: ignore[attr-defined]
        self._write(200, json.dumps(result.to_dict()).encode())

    def _write(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        pass


class TestMeshCarrier:
    """``--via mesh`` -- the plugin-mesh-stream carrier, ask #5's build."""

    @pytest.fixture
    def mesh_host(self, node_state):
        state = es.EvidenceServerState(ledger_path=node_state.ledger_path, signing_key_path=node_state.signing_key_path)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MeshToolCallHandler)
        server.plugin_name = "admission-policy"
        server.state = state
        server.calls = []
        server.unreachable_peer_id = "ff" * 32
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}", server, node_state
        server.shutdown()
        thread.join(timeout=5)

    def test_post_mesh_evidence_request_wraps_peer_id_and_request(self, mesh_host):
        local_host_api, server, state = mesh_host
        cids = _seal_and_checkpoint(state, 1)
        req = ah._build_request_map(
            subject_kind="record", capsule_id=cids[0], selector=None,
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, req)
        assert "bundles" in payload
        assert server.calls == [{"peer_id": "aa" * 32, "request": req}]

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
            server.unreachable_peer_id, "--subject", "range", "--selector", "a" * 64 + ".." + "b" * 64,
            "--via", "mesh", "--local-host-api", local_host_api,
        ])
        assert rc == 1
        assert "failed" in capsys.readouterr().err

    def test_via_mesh_tamper_check_detects_a_flipped_byte(self, mesh_host):
        """Mutant proof for the mesh carrier: tamper a COPY of the response
        the (stubbed) plugin-mesh-stream carrier delivered, in memory, and
        confirm offline verify flags it -- the SAME discriminating
        `verify_bundle` the direct-HTTP path uses
        (`test_tamper_check_detects_a_flipped_byte`), proving verify's
        tamper-detection is carrier-independent: it inspects the bytes that
        arrived, never how they arrived.
        """
        local_host_api, _server, state = mesh_host
        cids = _seal_and_checkpoint(state, 1)
        req = ah._build_request_map(
            subject_kind="record", capsule_id=cids[0], selector=None,
            expected_pin_root=None, expected_pin_mmr_size=None, nonce=None,
        )
        payload = ah.post_mesh_evidence_request(local_host_api, "admission-policy", "aa" * 32, req)
        rendered = ah.render_artifact(payload, node_id="m4", tamper_check=True)
        assert "verify.ok=False (expected False)" in rendered


class TestFetchAllPages:
    """Unit tests for ``fetch_all_pages`` against a FAKE door -- the real
    ``evidence_server.py`` in this repo still talks to a capsule-emit
    release that predates paging (see ``evidence_responder.py``'s note), so
    the client-side pagination-following logic is exercised standalone
    here rather than end to end. Once a node's capsule-emit floor carries
    the door-side cap+page fix, these same semantics apply over the wire
    unchanged -- ``fetch_all_pages`` only ever reads ``next_page_token``
    off whatever payload it is handed."""

    def _paging_door(self, pages: list[list[str]]):
        """A fake ``post`` callable serving ``pages`` (each a list of
        capsule ids) round by round, keyed off the request's ``page.token``
        (``"0"``, ``"1"``, ... -- absent token means page 0)."""

        def post(request_map: dict) -> dict:
            token = request_map.get("page", {}).get("token", "0")
            index = int(token)
            ids = pages[index]
            body = {
                "v": 1,
                "subject_kind": "range",
                "bundles": [{"capsule_id": cid} for cid in ids],
            }
            if index + 1 < len(pages):
                body["next_page_token"] = str(index + 1)
            return body

        return post

    def test_follows_next_page_token_until_absent(self):
        post = self._paging_door([["a", "b"], ["c", "d"], ["e"]])
        merged = ah.fetch_all_pages(post, {"subject": {"kind": "range", "selector": "a..e"}, "coverage": {}})
        assert [b["capsule_id"] for b in merged["bundles"]] == ["a", "b", "c", "d", "e"]
        assert "next_page_token" not in merged

    def test_single_page_door_runs_once(self):
        calls = []

        def post(request_map: dict) -> dict:
            calls.append(request_map)
            return {"v": 1, "subject_kind": "record", "bundles": [{"capsule_id": "a"}]}

        merged = ah.fetch_all_pages(post, {"subject": {"kind": "record", "capsule_id": "a"}, "coverage": {}})
        assert len(calls) == 1
        assert [b["capsule_id"] for b in merged["bundles"]] == ["a"]

    def test_refusal_never_pages(self):
        def post(request_map: dict) -> dict:
            return {"request_digest": "d", "reason": "no_such_record", "issued_at": "t", "key_id": "k", "sig": "s"}

        merged = ah.fetch_all_pages(post, {"subject": {"kind": "record", "capsule_id": "ff"}, "coverage": {}})
        assert merged["reason"] == "no_such_record"

    def test_max_pages_guards_against_a_runaway_token(self):
        def post(request_map: dict) -> dict:
            # Always claims more is coming -- the pathological door.
            return {"v": 1, "subject_kind": "range", "bundles": [], "next_page_token": "0"}

        with pytest.raises(RuntimeError, match="max-pages"):
            ah.fetch_all_pages(
                post, {"subject": {"kind": "range", "selector": "a..z"}, "coverage": {}}, max_pages=3
            )
