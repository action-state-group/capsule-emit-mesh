# SPDX-License-Identifier: Apache-2.0
"""Tests for the sharing-policy record-push-at-completion --
``record_push.py`` and its ``POST /evidence/record-push`` door on
``evidence_server.py``.

Acceptance / mutants that must flip (design note S2, symmetry rule):
  - a well-formed, self-verifying capsule pushed to a node with
    ``record_at_completion`` unset or ``counterparty`` -> received, folded
    into the recipient's own ledger, AS TRANSMITTED (byte-identical).
  - the same capsule pushed to a node with ``record_at_completion: off`` ->
    refused ``policy_decline``, signed, ledger UNCHANGED -- the symmetry
    rule ("a node that has record_at_completion: off does not receive the
    other side's push either").
  - a forged capsule (signature stale after a content change) -> refused
    ``request_malformed``, BEFORE the policy gate even runs, ledger
    unchanged.
  - malformed / non-JSON / no-capsule_id bodies -> refused
    ``request_malformed``, never raises.
  - ``push_record_if_policy_allows`` makes NO network call at all when the
    effective policy is ``off`` (returns ``None``, not a refusal it fetched).
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
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit.evidence_request import Refusal, verify_refusal_offline
from capsule_emit.ledger import read_ledger

import evidence_server as es
from record_push import (
    REASON_POLICY_DECLINE,
    REASON_REQUEST_MALFORMED,
    handle_record_push,
    push_record,
    push_record_if_policy_allows,
)
from share_policy import SharePolicy

REQUEST_DIGEST = "b" * 64


def _make_capsule(text: str, *, owner_id: str = "owner-a") -> dict:
    """A self-consistent, verifiable capsule -- the same shape
    ``test_adjudication_delivery.py``'s ``_make_served_half`` builds,
    minus the disclosure preimage this module never needs."""
    from capsule_sidecar import digest_json

    body = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    digest = digest_json(body)
    effect = EffectRecord(status="confirmed", type="inference_completion", request_digest=REQUEST_DIGEST, response_digest=digest)
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    return emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation={"owner": {"owner_id": owner_id}},
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )


def _state(ledger_path, signing_key_path, *, share_policy=None, received_log_dir=None) -> "es.EvidenceServerState":
    return es.EvidenceServerState(
        ledger_dir=ledger_path.parent,
        ledger_path=ledger_path,
        signing_key_path=signing_key_path,
        share_policy=share_policy,
        received_log_dir=received_log_dir,
    )


def _keys(tmp_path):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    return keys_dir / NODE_KEY_FILENAME


# ---------------------------------------------------------------------------
# handle_record_push -- pure, no HTTP
# ---------------------------------------------------------------------------


def test_valid_push_with_no_policy_configured_is_received_and_folded(tmp_path):
    capsule = _make_capsule("hello world")
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = _state(ledger_path, key_path, share_policy=None)

    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy)

    assert result == {"status": "received"}
    ledger_ids = [c["capsule_id"] for c in read_ledger(ledger_path)]
    assert capsule["capsule_id"] in ledger_ids


def test_valid_push_with_explicit_counterparty_policy_is_received(tmp_path):
    capsule = _make_capsule("hello world")
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="counterparty"))

    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy)
    assert result == {"status": "received"}


def test_policy_off_refuses_policy_decline_and_ledger_unchanged(tmp_path):
    capsule = _make_capsule("hello world")
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_bytes(b"")
    state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="off"))
    before = ledger_path.read_bytes()

    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy)

    assert result["reason"] == REASON_POLICY_DECLINE
    assert "sig" in result and "key_id" in result
    assert ledger_path.read_bytes() == before


def test_forged_capsule_refuses_malformed_before_policy_gate(tmp_path):
    capsule = _make_capsule("hello world")
    forged = dict(capsule)
    forged["operator"] = "attacker-org"  # content changed, signature stale

    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_bytes(b"")
    # Policy is OFF, so if the malformed check did not run FIRST, this
    # would (incorrectly) come back policy_decline instead -- the mutant
    # this test is designed to catch.
    state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="off"))

    result = handle_record_push(state, json.dumps(forged).encode("utf-8"), policy=state.share_policy)
    assert result["reason"] == REASON_REQUEST_MALFORMED


def test_malformed_body_refuses_never_raises(tmp_path):
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    state = _state(ledger_path, key_path)
    result = handle_record_push(state, b"not json", policy=state.share_policy)
    assert result["reason"] == REASON_REQUEST_MALFORMED


def test_missing_capsule_id_refuses_malformed(tmp_path):
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    state = _state(ledger_path, key_path)
    result = handle_record_push(state, json.dumps({"not_a_capsule": True}).encode("utf-8"), policy=state.share_policy)
    assert result["reason"] == REASON_REQUEST_MALFORMED


def test_refusal_verifies_offline(tmp_path):
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="off"))
    capsule = _make_capsule("hello world")
    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy)
    refusal = Refusal(**{k: result[k] for k in ("request_digest", "reason", "issued_at", "key_id", "sig")})
    assert verify_refusal_offline(refusal)


# ---------------------------------------------------------------------------
# push_record_if_policy_allows -- the send side's own gate
# ---------------------------------------------------------------------------


def test_push_if_policy_allows_makes_no_network_call_when_off():
    capsule = {"capsule_id": "irrelevant"}
    # An unroutable URL -- if this function made a real network call
    # despite the off policy, it would raise a URLError, failing this test.
    result = push_record_if_policy_allows(
        capsule, "http://127.0.0.1:1", policy=SharePolicy(record_at_completion="off")
    )
    assert result is None


def test_push_if_policy_allows_reaches_the_network_when_on(tmp_path):
    capsule = _make_capsule("hello world")
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "recipient-ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = _state(ledger_path, key_path)
    server = _RunningServer(state)
    try:
        result = push_record_if_policy_allows(
            capsule, server.base_url, policy=SharePolicy(record_at_completion="counterparty")
        )
    finally:
        server.close()
    assert result == {"status": "received"}
    assert capsule["capsule_id"] in [c["capsule_id"] for c in read_ledger(ledger_path)]


def test_push_if_policy_allows_defaults_to_on_when_policy_is_none(tmp_path):
    # _effective_policy(None) == DEFAULT_SHARE_POLICY -> record_at_completion
    # == "counterparty" -- the documented default is ON, not off.
    capsule = _make_capsule("hello world")
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "recipient-ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = _state(ledger_path, key_path)
    server = _RunningServer(state)
    try:
        result = push_record_if_policy_allows(capsule, server.base_url, policy=None)
    finally:
        server.close()
    assert result == {"status": "received"}


# ---------------------------------------------------------------------------
# Over HTTP -- POST /evidence/record-push on evidence_server.py
# ---------------------------------------------------------------------------


class _RunningServer:
    def __init__(self, state: "es.EvidenceServerState"):
        self.server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)


class TestRecordPushOverHTTP:
    def test_push_record_against_a_real_server_returns_received(self, tmp_path):
        capsule = _make_capsule("hello world")
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        state = _state(ledger_path, key_path)
        server = _RunningServer(state)
        try:
            result = push_record(capsule, server.base_url)
        finally:
            server.close()

        assert result == {"status": "received"}
        assert capsule["capsule_id"] in [c["capsule_id"] for c in read_ledger(ledger_path)]

    def test_record_push_without_received_log_dir_writes_no_log_file(self, tmp_path):
        # the sharing-policy regression guard: received_log_dir
        # defaults to None (opt-in), and MUST NEVER fall back to writing
        # into ledger_dir -- ledger_dir may be the Rust plugin's OWNED
        # directory (see EvidenceServerState.received_log_dir's own
        # docstring; TestPluginLedgerBridge pins the same invariant for
        # /evidence-request in test_evidence_server.py).
        capsule = _make_capsule("hello world")
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        before_entries = sorted(p.name for p in ledger_path.parent.iterdir())
        state = _state(ledger_path, key_path)  # received_log_dir=None (default)
        server = _RunningServer(state)
        try:
            push_record(capsule, server.base_url)
        finally:
            server.close()

        after_entries = sorted(p.name for p in ledger_path.parent.iterdir())
        assert "received_log.jsonl" not in after_entries
        # The pushed capsule folded into capsules.jsonl is the ONLY change.
        assert set(after_entries) - set(before_entries) <= {"capsules.jsonl"}

    def test_push_record_against_an_off_server_returns_signed_refusal(self, tmp_path):
        capsule = _make_capsule("hello world")
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_bytes(b"")
        state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="off"))
        server = _RunningServer(state)
        try:
            result = push_record(capsule, server.base_url)
        finally:
            server.close()

        assert result["reason"] == REASON_POLICY_DECLINE
        assert ledger_path.read_bytes() == b""

    def test_record_push_appears_in_received_log_with_outcome(self, tmp_path):
        capsule = _make_capsule("hello world")
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        # the sharing-policy received_log_dir is deliberately NOT
        # ledger_dir -- see EvidenceServerState.received_log_dir's own
        # docstring (the plugin-ledger bridge's "never a second writer"
        # invariant, pinned by TestPluginLedgerBridge in test_evidence_server.py).
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        state = _state(ledger_path, key_path, received_log_dir=log_dir)
        server = _RunningServer(state)
        try:
            push_record(capsule, server.base_url)
        finally:
            server.close()

        # Confirms the opt-in log landed in received_log_dir, NEVER ledger_dir.
        assert not (ledger_path.parent / "received_log.jsonl").exists()
        log_lines = (log_dir / "received_log.jsonl").read_text().splitlines()
        entries = [json.loads(line) for line in log_lines]
        assert any(e["path"] == "evidence/record-push" and e["status"] == "received" for e in entries)

    def test_unknown_path_still_404s(self, tmp_path):
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        state = _state(ledger_path, key_path)
        server = _RunningServer(state)
        try:
            req = urllib.request.Request(f"{server.base_url}/nope", method="POST", data=b"{}")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.close()
