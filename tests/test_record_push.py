# SPDX-License-Identifier: Apache-2.0
"""Tests for [mesh-sharing-policy-v0] record-push-at-completion --
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
from capsule_emit import seal
from capsule_emit.evidence_request import Refusal, verify_refusal_offline
from capsule_emit.ledger import read_ledger

import evidence_server as es
from peer_keys import ENV_PEER_KEYS
from record_push import (
    REASON_POLICY_DECLINE,
    REASON_REQUEST_MALFORMED,
    REASON_SIGNATURE_UNVERIFIED,
    RECEIVED_PROVENANCE_FILENAME,
    REJECTED_PUSHES_FILENAME,
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
        # [mesh-sharing-policy-v0] regression guard: received_log_dir
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
        # [mesh-sharing-policy-v0] received_log_dir is deliberately NOT
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


# ---------------------------------------------------------------------------
# [mesh-closed-wiring-four-gaps] Seam A2 -- identity verification + provenance
#
# A push that carries a claimed sender identity (`sender_peer_id`, the same
# `X-Mesh-Requester-Id` header the mesh bridge forwards) is held to a HIGHER
# bar than the original unidentified mechanism: the capsule's own `key_id`
# must match that sender's announced key AND its signature must verify. Only
# then is a provenance sibling (`received_from`/`via:push`/`received_at`/
# `signature_ok`) recorded -- the ONLY fact the pane's local-sibling CLOSED
# gate trusts. A claimed identity that fails is refused `signature_unverified`
# and recorded to the rejected file, NEVER folded into `capsules.jsonl`.
# ---------------------------------------------------------------------------


def _signed_capsule(key_path) -> dict:
    """A REAL signed capsule (carries `key_id` + a verifying `signature`),
    minted through capsule_emit's own `seal()` with `key_path` -- unlike
    `_make_capsule`'s `emit()` builder, which is structurally valid but
    unsigned. `seal()` is the same already-verified builder
    `test_evidence_server.py` uses."""
    import tempfile

    scratch = tempfile.mktemp(suffix="-record-push-seal-scratch.jsonl")
    return seal(None, action="serve-half", operator="acme", anchor=False, ledger=scratch, signing_key_path=key_path).capsule


def _provenance_lines(ledger_dir):
    path = ledger_dir / RECEIVED_PROVENANCE_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _rejected_lines(ledger_dir):
    path = ledger_dir / REJECTED_PUSHES_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class TestRecordPushIdentityVerification:
    def _setup(self, tmp_path):
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_bytes(b"")
        capsule = _signed_capsule(key_path)
        state = _state(ledger_path, key_path)
        return key_path, ledger_path, capsule, state

    def test_identified_push_with_matching_announced_key_is_received_and_records_provenance(
        self, tmp_path, monkeypatch
    ):
        _key_path, ledger_path, capsule, state = self._setup(tmp_path)
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": capsule["key_id"]}))

        result = handle_record_push(
            state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3"
        )

        assert result == {"status": "received"}
        assert capsule["capsule_id"] in [c["capsule_id"] for c in read_ledger(ledger_path)]
        prov = _provenance_lines(ledger_path.parent)
        assert len(prov) == 1
        assert prov[0] == {
            "capsule_id": capsule["capsule_id"],
            "received_from": "m3",
            "via": "push",
            "received_at": prov[0]["received_at"],  # a real timestamp, not asserted verbatim
            "signature_ok": True,
        }
        assert prov[0]["received_at"]  # non-empty
        assert _rejected_lines(ledger_path.parent) == []

    def test_identified_push_from_an_unannounced_peer_is_rejected_never_a_sibling(self, tmp_path, monkeypatch):
        _key_path, ledger_path, capsule, state = self._setup(tmp_path)
        # `m3`'s key is announced, but the push claims to be `m4`, who is
        # absent from the registry -> announced_key_for("m4") is None.
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": capsule["key_id"]}))

        result = handle_record_push(
            state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m4"
        )

        assert result["reason"] == REASON_SIGNATURE_UNVERIFIED
        assert ledger_path.read_bytes() == b""  # NEVER folded into capsules.jsonl
        assert _provenance_lines(ledger_path.parent) == []
        rejected = _rejected_lines(ledger_path.parent)
        assert len(rejected) == 1
        assert rejected[0]["claimed_sender_peer_id"] == "m4"
        assert rejected[0]["reason"] == REASON_SIGNATURE_UNVERIFIED

    def test_identified_push_whose_key_id_mismatches_the_announced_key_is_rejected(self, tmp_path, monkeypatch):
        _key_path, ledger_path, capsule, state = self._setup(tmp_path)
        # `m3` is announced, but with a DIFFERENT key than the capsule carries.
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": "de" * 32}))

        result = handle_record_push(
            state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3"
        )

        assert result["reason"] == REASON_SIGNATURE_UNVERIFIED
        assert ledger_path.read_bytes() == b""
        assert _provenance_lines(ledger_path.parent) == []
        assert len(_rejected_lines(ledger_path.parent)) == 1

    def test_identified_push_with_a_tampered_body_is_refused_never_a_sibling(self, tmp_path, monkeypatch):
        # Content changed after signing, with the sender's key correctly
        # announced: the tampered capsule is refused (structural verify
        # catches the tamper as `request_malformed` before the identity gate,
        # which is itself the honest answer -- a tampered capsule IS
        # malformed) and, either way, NEVER folded into capsules.jsonl as a
        # sibling and NEVER granted a provenance record. The load-bearing
        # guarantee is "a tampered push never becomes a verified sibling",
        # not which of the two refusal reasons fires first.
        _key_path, ledger_path, capsule, state = self._setup(tmp_path)
        forged = dict(capsule)
        forged["operator"] = "attacker-org"
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": capsule["key_id"]}))

        result = handle_record_push(
            state, json.dumps(forged).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3"
        )

        assert result["reason"] in (REASON_REQUEST_MALFORMED, REASON_SIGNATURE_UNVERIFIED)
        assert ledger_path.read_bytes() == b""
        assert _provenance_lines(ledger_path.parent) == []

    def test_identified_push_with_a_swapped_signature_fails_the_sig_term_and_is_rejected(self, tmp_path, monkeypatch):
        # Isolates the `not verify_capsule_signature(capsule)` term: the
        # capsule is structurally valid (passes `verify_capsule`) and its
        # `key_id` DOES match the announced key, so the announced-key term
        # passes -- but its `signature` is another capsule's, signed by the
        # same key over different content, so the COSE_Sign1 verify fails.
        # MUTANT: drop the `not verify_capsule_signature(...)` term and this
        # push would be (wrongly) received and given a provenance sibling.
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_bytes(b"")
        genuine = _signed_capsule(key_path)
        other = _signed_capsule(key_path)  # same node key, different content
        assert genuine["key_id"] == other["key_id"]
        swapped = dict(genuine)
        swapped["signature"] = other["signature"]
        state = _state(ledger_path, key_path)
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": genuine["key_id"]}))

        result = handle_record_push(
            state, json.dumps(swapped).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3"
        )

        assert result["reason"] == REASON_SIGNATURE_UNVERIFIED
        assert ledger_path.read_bytes() == b""
        assert _provenance_lines(ledger_path.parent) == []
        assert len(_rejected_lines(ledger_path.parent)) == 1

    def test_unidentified_push_is_byte_for_byte_unchanged_no_provenance_no_identity_check(self, tmp_path, monkeypatch):
        # MUTANT: the whole identity gate must be reachable ONLY when a
        # sender_peer_id is supplied. An unidentified push (the pre-task path)
        # never runs it -- so a signed capsule with NO peer-key registry at
        # all is still received, and NO provenance sibling is written (an
        # unidentified push was never eligible for the CLOSED gate).
        monkeypatch.delenv(ENV_PEER_KEYS, raising=False)
        _key_path, ledger_path, capsule, state = self._setup(tmp_path)

        result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy)

        assert result == {"status": "received"}
        assert capsule["capsule_id"] in [c["capsule_id"] for c in read_ledger(ledger_path)]
        assert _provenance_lines(ledger_path.parent) == []
        assert _rejected_lines(ledger_path.parent) == []

    def test_policy_off_refuses_before_the_identity_gate_even_for_an_identified_push(self, tmp_path, monkeypatch):
        # Ordering discipline: policy_decline wins over the identity gate, so
        # an off node does not even evaluate (or record a rejection for) an
        # identified push -- the symmetry rule is unchanged by Seam A2.
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_bytes(b"")
        capsule = _signed_capsule(key_path)
        state = _state(ledger_path, key_path, share_policy=SharePolicy(record_at_completion="off"))
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": capsule["key_id"]}))

        result = handle_record_push(
            state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3"
        )

        assert result["reason"] == REASON_POLICY_DECLINE
        assert ledger_path.read_bytes() == b""
        assert _provenance_lines(ledger_path.parent) == []
        assert _rejected_lines(ledger_path.parent) == []
