# SPDX-License-Identifier: Apache-2.0
"""door_auth.py and evidence_server.py's --token-file mode: the plugin and
its local evidence door prove a shared token to each other, so a process
that grabs the door's port neither gets served nor can answer in its name.

The two fixed vectors are the protocol's cross-language pins: the Rust
plugin's tests assert the same hex for the same inputs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import evidence_server as es
from door_auth import (
    AUTH_HEADER,
    NONCE_HEADER,
    PROOF_HEADER,
    DoorAuth,
    DoorTokenError,
)

TOKEN = "0" * 64
NONCE = "11" * 16
# Cross-checked with `openssl dgst -sha256 -hmac`.
VECTOR_AUTH = "44ffac9a4f0c74d4418a5a918d8e30624f8394ef80608c3773d328abed75ae6b"
VECTOR_PROOF = "9aec425e9b7ab34ffeeaadee5c646e7553ce3a6ff99dec51abab0f2e2d404f39"


def _independent_mac(message: str) -> str:
    return hmac.new(TOKEN.encode("ascii"), message.encode(), hashlib.sha256).hexdigest()


class TestVectors:
    def test_pinned_cross_language_vectors(self):
        auth = DoorAuth(TOKEN)
        assert auth.request_mac("POST", "/evidence/record-push", NONCE) == VECTOR_AUTH
        assert auth.reply_proof(NONCE, 200, b"{}") == VECTOR_PROOF

    def test_request_mac_matches_an_independent_hmac(self):
        auth = DoorAuth(TOKEN)
        expected = _independent_mac(f"plugin\nPOST\n/evidence/record-push\n{NONCE}")
        assert auth.request_mac("POST", "/evidence/record-push", NONCE) == expected

    def test_reply_proof_binds_nonce_status_and_body_digest(self):
        auth = DoorAuth(TOKEN)
        body_digest = hashlib.sha256(b"{}").hexdigest()
        expected = _independent_mac(f"door\n{NONCE}\n200\n{body_digest}")
        assert auth.reply_proof(NONCE, 200, b"{}") == expected
        assert auth.reply_proof(NONCE, 200, b"{ }") != expected
        assert auth.reply_proof(NONCE, 401, b"{}") != expected


class TestCheckRequest:
    def test_valid_request_passes_once_then_replay_fails(self):
        auth = DoorAuth(TOKEN)
        mac = auth.request_mac("POST", "/evidence-request", NONCE)
        assert auth.check_request("POST", "/evidence-request", NONCE, mac)
        assert not auth.check_request("POST", "/evidence-request", NONCE, mac)

    @pytest.mark.parametrize(
        ("method", "path", "nonce", "mac_for"),
        [
            ("POST", "/evidence-request", None, ("POST", "/evidence-request")),
            ("POST", "/evidence-request", "zz" * 16, ("POST", "/evidence-request")),
            ("GET", "/evidence-request", NONCE, ("POST", "/evidence-request")),
            ("POST", "/evidence/record-push", NONCE, ("POST", "/evidence-request")),
        ],
    )
    def test_wrong_or_missing_parts_fail(self, method, path, nonce, mac_for):
        auth = DoorAuth(TOKEN)
        mac = auth.request_mac(mac_for[0], mac_for[1], nonce or NONCE)
        assert not auth.check_request(method, path, nonce, mac)

    def test_mac_under_another_token_fails(self):
        other = DoorAuth("f" * 64)
        mac = other.request_mac("POST", "/evidence-request", NONCE)
        assert not DoorAuth(TOKEN).check_request(
            "POST", "/evidence-request", NONCE, mac
        )

    def test_missing_mac_fails(self):
        assert not DoorAuth(TOKEN).check_request("POST", "/x", NONCE, None)


class TestToken:
    @pytest.mark.parametrize("token", ["", "0" * 63, "0" * 64 + "\n", "A" * 64])
    def test_malformed_token_is_refused(self, token):
        with pytest.raises(DoorTokenError):
            DoorAuth(token)

    def test_missing_token_file_is_refused(self, tmp_path: Path):
        with pytest.raises(DoorTokenError):
            DoorAuth.from_file(tmp_path / "absent")


class _Door:
    def __init__(self, auth: DoorAuth | None, tmp_path: Path):
        state = es.EvidenceServerState(
            ledger_dir=tmp_path,
            ledger_path=tmp_path / "capsules.jsonl",
            signing_key_path=tmp_path / "node-key.pem",
            door_auth=auth,
        )
        self.server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)

    def call(
        self, method: str, path: str, headers: dict[str, str]
    ) -> tuple[int, bytes, str | None]:
        data = b"{}" if method == "POST" else None
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read(), resp.headers.get(PROOF_HEADER)
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers.get(PROOF_HEADER)


def _signed(auth: DoorAuth, method: str, path: str) -> tuple[str, dict[str, str]]:
    nonce = secrets.token_hex(16)
    return nonce, {
        NONCE_HEADER: nonce,
        AUTH_HEADER: auth.request_mac(method, path, nonce),
    }


@pytest.fixture
def door(tmp_path: Path):
    auth = DoorAuth(TOKEN)
    running = _Door(auth, tmp_path)
    yield running, auth
    running.close()


class TestDoorOverHTTP:
    def test_unauthenticated_post_is_refused_401_without_proof(self, door):
        running, _ = door
        status, body, proof = running.call("POST", "/evidence/record-push", {})
        assert status == 401
        assert b"door_auth_failed" in body
        assert proof is None

    def test_unauthenticated_health_is_refused(self, door):
        running, _ = door
        status, _, proof = running.call("GET", "/health", {})
        assert (status, proof) == (401, None)

    def test_authenticated_health_carries_a_valid_proof(self, door):
        running, auth = door
        nonce, headers = _signed(auth, "GET", "/health")
        status, body, proof = running.call("GET", "/health", headers)
        assert status == 200
        assert proof == auth.reply_proof(nonce, 200, body)

    def test_authenticated_post_reply_is_proved_even_when_not_found(self, door):
        running, auth = door
        nonce, headers = _signed(auth, "POST", "/no-such-route")
        status, body, proof = running.call("POST", "/no-such-route", headers)
        assert status == 404
        assert proof == auth.reply_proof(nonce, 404, body)

    def test_replayed_request_is_refused(self, door):
        running, auth = door
        _, headers = _signed(auth, "GET", "/health")
        assert running.call("GET", "/health", headers)[0] == 200
        assert running.call("GET", "/health", headers)[0] == 401

    def test_a_door_without_the_token_cannot_prove_its_reply(self, tmp_path: Path):
        # The hijack case from the plugin's side: something answers on the
        # port but does not hold the token, so its reply has no valid proof.
        impostor = _Door(None, tmp_path)
        try:
            auth = DoorAuth(TOKEN)
            nonce, headers = _signed(auth, "GET", "/health")
            status, body, proof = impostor.call("GET", "/health", headers)
            assert status == 200
            assert proof != auth.reply_proof(nonce, 200, body)
        finally:
            impostor.close()


def test_open_door_without_token_keeps_serving_direct_callers(tmp_path: Path):
    running = _Door(None, tmp_path)
    try:
        status, body, proof = running.call("GET", "/", {})
        assert (status, proof) == (200, None)
        assert b"ready" in body
    finally:
        running.close()
