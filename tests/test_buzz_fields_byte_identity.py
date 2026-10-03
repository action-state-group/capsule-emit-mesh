# SPDX-License-Identifier: Apache-2.0
"""The evidence-door and twin-adjudication tests of record, re-run with
records that carry the Buzz event fields.

The Buzz connector (``capsule-emit-buzz``) carries an observed Buzz event via
``received()`` and records it under ``compute_attestation.buzz_event``:
``event_id`` (the Nostr event id) and ``semantic_digest`` (the SHA-256 of the
full signed event) as two distinct fields, plus the author's key, from which
the host ``principal_ref`` (``nostr-pubkey:<hex>``) is derived. Both shapes
are exercised here: the block exactly as the connector writes it, and the
record-subject shape that names ``principal_ref`` directly.

What this file proves, offline:

  * Every field a record already had is byte-identical (JCS) with the new
    block present. ``capsule_id`` changes, by design: it is a digest over the
    whole capsule, ``compute_attestation`` included. Removing the block and
    recomputing gives back the baseline ``capsule_id`` exactly.
  * The evidence door (``POST /evidence-request``) answers a record carrying
    the block the same way it answers one without: an artifact whose bundle
    verifies offline and serves the record byte-for-byte as logged, the same
    signed refusals, caller invariance across nonces, and tamper detection.
  * Twin adjudication with an injected third-node referee reaches the same
    outcome (verdict, divergence index, prefix digest, margin, referee calls)
    and seals the same adjudication block, apart from the cited half ids.

What it does not prove: the live three-node run, with a real referee on a
distinct node. Here the referee is injected, as in ``test_twin_adjudicator.py``.
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import types
import urllib.request

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from agent_action_capsule import verify as verify_capsule
from agent_action_capsule.canonical import jcs
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit.bundle import Bundle, verify_bundle
from capsule_emit.canonicalization import compute_capsule_id
from capsule_emit.ledger import append_to_ledger
from capsule_emit.signing import resolve_signer, sign_producer_envelope
from cll.checkpoint import CheckpointConfig

import evidence_server as es
from capsule_sidecar import NODE_KEY_FILENAME, digest_json, load_or_create_signing_key
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from twin_adjudicator import (
    VERDICT_CORROBORATED,
    AdjudicationHalf,
    RefereeIdentity,
    RefereeResult,
    adjudicate,
    contradicted,
    seal_adjudication_capsule,
)

REQUEST_DIGEST = "a" * 64
TIMESTAMP = "2026-10-01T00:00:00Z"

# A fixed Buzz event's fields. Only their shape matters here: 64-hex values,
# and event_id != semantic_digest (the two are never the same field).
EVENT_ID = "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"
PUBKEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SEMANTIC_DIGEST = "e3f1a0c4b9d2875610fa3c2e8d4b7a6159e0c3d2b1a4f5e6d7c8b9a0f1e2d3c4"

NEW_BLOCK_KEY = "buzz_event"
BUZZ_BLOCKS = {
    # Exactly what the connector's capture() writes.
    "connector": {"event_id": EVENT_ID, "pubkey": PUBKEY, "semantic_digest": SEMANTIC_DIGEST},
    # The record subject: {event_id, semantic_digest} plus principal_ref.
    "subject": {"event_id": EVENT_ID, "semantic_digest": SEMANTIC_DIGEST, "principal_ref": f"nostr-pubkey:{PUBKEY}"},
}

# capsule_id is signer-independent, so these are stable across runs and keys.
BASELINE_CAPSULE_ID = "050d7128adbee9541ba90fa62c83cbc4863393ddee3281e3b4d362b8c5006476"
GOLDEN_CAPSULE_IDS = {
    "connector": "218460eb48e99bb8c0a6b3a7dbfb6980893fdf0735f9edc476fcb51647151fc2",
    "subject": "8c5744b30499e68abf1bc841b50be7b98e8c465e247a53bb278c9b77dc9d132d",
}


def _response_body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _record(text: str, *, owner_id: str, buzz_block: dict | None, action_id: str = "serve_exchange/0") -> dict:
    """One inference record, built with every non-deterministic input
    pinned (action_id, timestamp), so two builds differ only by the block."""
    compute_attestation: dict = {"owner": {"owner_id": owner_id}}
    if buzz_block is not None:
        compute_attestation[NEW_BLOCK_KEY] = copy.deepcopy(buzz_block)
    return emit(
        action_id=action_id,
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        timestamp=TIMESTAMP,
        compute_attestation=compute_attestation,
        effect=EffectRecord(
            status="confirmed",
            type="inference_completion",
            request_digest=REQUEST_DIGEST,
            response_digest=digest_json(_response_body(text)),
        ),
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed"),
        tool_name="serve_exchange",
    )


def _without_new_block(capsule: dict) -> dict:
    """The capsule minus the new block and minus what is derived from the
    whole capsule (capsule_id, and the producer signature over it)."""
    stripped = copy.deepcopy(capsule)
    for key in ("capsule_id", "signature", "key_id"):
        stripped.pop(key, None)
    stripped["model_attestation"]["compute_attestation"].pop(NEW_BLOCK_KEY, None)
    return stripped


# ---------------------------------------------------------------------------
# The record itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_existing_fields_byte_identical_with_the_block_present(shape):
    baseline = _record("the quick brown fox", owner_id="owner-a", buzz_block=None)
    carrying = _record("the quick brown fox", owner_id="owner-a", buzz_block=BUZZ_BLOCKS[shape])

    assert jcs(_without_new_block(carrying)) == jcs(_without_new_block(baseline))
    assert carrying["model_attestation"]["compute_attestation"][NEW_BLOCK_KEY] == BUZZ_BLOCKS[shape]


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_capsule_id_changes_by_design_and_strips_back_to_baseline(shape):
    baseline = _record("the quick brown fox", owner_id="owner-a", buzz_block=None)
    carrying = _record("the quick brown fox", owner_id="owner-a", buzz_block=BUZZ_BLOCKS[shape])

    assert carrying["capsule_id"] != baseline["capsule_id"]
    assert compute_capsule_id(_without_new_block(carrying)) == baseline["capsule_id"]
    assert baseline["capsule_id"] == BASELINE_CAPSULE_ID
    assert carrying["capsule_id"] == GOLDEN_CAPSULE_IDS[shape]


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_record_carrying_the_block_verifies(shape):
    carrying = _record("the quick brown fox", owner_id="owner-a", buzz_block=BUZZ_BLOCKS[shape])
    assert verify_capsule(carrying).ok


def test_event_id_and_semantic_digest_stay_two_fields():
    for block in BUZZ_BLOCKS.values():
        assert block["event_id"] != block["semantic_digest"]


# ---------------------------------------------------------------------------
# The evidence door (POST /evidence-request)
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_witness(monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "stub")


def _ledger_with(tmp_path, records: list[dict]):
    """A plugin-shaped ledger: signed records appended as logged, then
    checkpointed read-only into a sibling checkpoints.jsonl, the same shape
    test_evidence_server.py's plugin-ledger fixture uses."""
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    key_path = keys_dir / NODE_KEY_FILENAME
    ledger_path = ledger_dir / "capsules.jsonl"

    producer = resolve_signer(ledger_path, key_path=key_path)
    logged = []
    for record in records:
        signed = copy.deepcopy(record)
        signed["signature"], signed["key_id"] = sign_producer_envelope(producer, signed["capsule_id"])
        append_to_ledger(signed, ledger_path)
        logged.append(signed)

    cfg = CheckpointConfig(cadence_entries=1, max_lag_entries=10, ts_urls=[])
    CheckpointState.load(
        ledger_dir=ledger_dir,
        log_source=JsonlLogSource(ledger_path),
        cfg=cfg,
        signer=Ed25519Signer(key_path),
        log_id="buzz-fields-log",
    ).reconnect()
    return es.EvidenceServerState(ledger_dir=ledger_dir, ledger_path=ledger_path, signing_key_path=key_path), logged


class _Door:
    def __init__(self, state: es.EvidenceServerState):
        self.server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)

    def ask(self, capsule_id: str, **extra) -> dict:
        body = json.dumps({"subject": {"kind": "record", "capsule_id": capsule_id}, "coverage": {}, **extra}).encode()
        req = urllib.request.Request(f"{self.base_url}/evidence-request", data=body, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            return json.loads(resp.read())


@pytest.fixture
def door(tmp_path, stub_witness):
    """One ledger holding the baseline record and one record per block shape."""
    records = {"baseline": _record("the quick brown fox", owner_id="owner-a", buzz_block=None)}
    for shape, block in BUZZ_BLOCKS.items():
        records[shape] = _record("the quick brown fox", owner_id="owner-a", buzz_block=block)
    state, logged = _ledger_with(tmp_path, list(records.values()))
    server = _Door(state)
    yield server, dict(zip(records, logged))
    server.close()


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_door_serves_the_carrying_record_as_logged_and_it_verifies(door, shape):
    server, logged = door
    answer = server.ask(logged[shape]["capsule_id"])

    assert answer["subject_kind"] == "record"
    (served,) = answer["bundles"]
    assert served["capsule_id"] == logged[shape]["capsule_id"]
    assert jcs(served["receipt"]) == jcs(logged[shape])
    ok, errors = verify_bundle(Bundle.from_dict(served))
    assert ok, errors


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_door_answer_matches_the_baseline_answer_on_existing_fields(door, shape):
    server, logged = door
    base_answer = server.ask(logged["baseline"]["capsule_id"])
    carrying_answer = server.ask(logged[shape]["capsule_id"])

    assert sorted(carrying_answer) == sorted(base_answer)
    assert sorted(carrying_answer["bundles"][0]) == sorted(base_answer["bundles"][0])
    assert jcs(_without_new_block(carrying_answer["bundles"][0]["receipt"])) == jcs(
        _without_new_block(base_answer["bundles"][0]["receipt"])
    )


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_door_caller_invariance_holds_for_the_carrying_record(door, shape):
    server, logged = door
    answer_a = server.ask(logged[shape]["capsule_id"], nonce="a")
    answer_b = server.ask(logged[shape]["capsule_id"], nonce="b")
    assert jcs(answer_a) == jcs(answer_b)


@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_door_detects_tampering_with_the_new_block(door, shape):
    server, logged = door
    served = server.ask(logged[shape]["capsule_id"])["bundles"][0]
    tampered = copy.deepcopy(served)
    tampered["receipt"]["model_attestation"]["compute_attestation"][NEW_BLOCK_KEY]["semantic_digest"] = "0" * 64
    ok, _errors = verify_bundle(Bundle.from_dict(tampered))
    assert ok is False


def test_door_refusals_unchanged(door):
    server, _logged = door
    assert server.ask("ff" * 32)["reason"] == "no_such_record"


# ---------------------------------------------------------------------------
# Twin adjudication with an injected third-node referee
# ---------------------------------------------------------------------------


def _half(text: str, *, owner_id: str, buzz_block: dict | None) -> AdjudicationHalf:
    capsule = _record(text, owner_id=owner_id, buzz_block=buzz_block, action_id=f"serve_exchange/{owner_id}")
    body = _response_body(text)
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return AdjudicationHalf.from_capsule_and_disclosure(capsule, disclosed)


def _referee_contradicting_b(calls: list):
    def _referee(a, b, comparison):
        calls.append(comparison.divergence_index)
        return RefereeResult(
            verdict=contradicted("owner-b"),
            margin=4.9,
            capsule_id="referee-capsule-1",
            identity=RefereeIdentity(referee_id="test-referee-node"),
        )

    return _referee


def _outcome_fields(outcome) -> dict:
    """Everything in the outcome except the two cited half ids."""
    return {
        "verdict": outcome.verdict,
        "no_verdict_reason": outcome.no_verdict_reason,
        "divergence_index": outcome.divergence_index,
        "margin": outcome.margin,
        "margin_tau": outcome.margin_tau,
        "prefix_digest": outcome.prefix_digest,
        "twin_owner_distinct": outcome.twin_owner_distinct,
        "weights_digest": outcome.weights_digest,
        "referee_called": outcome.referee_called,
        "referee_capsule_id": outcome.referee_capsule_id,
        "referee_identity_id": outcome.referee_identity_id,
        "tau": outcome.tau,
        "referee_logprobs_absent": outcome.referee_logprobs_absent,
    }


def _adjudication_block_without_half_ids(capsule: dict) -> dict:
    block = dict(capsule["model_attestation"]["compute_attestation"]["adjudication"])
    block.pop("half_a_capsule_id", None)
    block.pop("half_b_capsule_id", None)
    return block


TWIN_CASES = {
    "agree": ("the quick brown fox", "the quick brown fox"),
    "diverge": ("the quick brown fox", "the quick brown wolf"),
}


@pytest.mark.parametrize("case", sorted(TWIN_CASES))
@pytest.mark.parametrize("shape", sorted(BUZZ_BLOCKS))
def test_adjudication_outcome_unchanged_by_the_block(case, shape):
    text_a, text_b = TWIN_CASES[case]
    base_calls: list = []
    carrying_calls: list = []

    base = adjudicate(
        _half(text_a, owner_id="owner-a", buzz_block=None),
        _half(text_b, owner_id="owner-b", buzz_block=None),
        referee=_referee_contradicting_b(base_calls),
        referee_owner_id="owner-c",
    )
    half_a = _half(text_a, owner_id="owner-a", buzz_block=BUZZ_BLOCKS[shape])
    half_b = _half(text_b, owner_id="owner-b", buzz_block=BUZZ_BLOCKS[shape])
    carrying = adjudicate(half_a, half_b, referee=_referee_contradicting_b(carrying_calls), referee_owner_id="owner-c")

    assert _outcome_fields(carrying) == _outcome_fields(base)
    assert carrying_calls == base_calls
    assert (carrying.half_a_capsule_id, carrying.half_b_capsule_id) == (half_a.capsule_id, half_b.capsule_id)
    if case == "agree":
        assert carrying.verdict == VERDICT_CORROBORATED
        assert carrying_calls == []
    else:
        assert carrying.verdict == contradicted("owner-b")
        assert carrying_calls == [3]

    base_sealed = seal_adjudication_capsule(base, operator="test-org", developer="referee@v1")
    carrying_sealed = seal_adjudication_capsule(carrying, operator="test-org", developer="referee@v1")
    assert jcs(_adjudication_block_without_half_ids(carrying_sealed)) == jcs(
        _adjudication_block_without_half_ids(base_sealed)
    )
