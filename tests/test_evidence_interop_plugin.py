# SPDX-License-Identifier: Apache-2.0
"""Interop with the Mesh-LLM capsules plugin's evidence answers
(``crates/evidence-plugin/src/evidence_artifact.rs``).

``tests/fixtures/evidence-interop/plugin/`` holds replies the plugin built
over its own parity corpus (see that directory's README for the commit and
how they were made): a record under the first anchor and under a later one
(with a consistency proof), ranges under a pin and under ``min_freshness``,
and a checkpoint list. ``ask_history`` must read every one as the plugin's
own requester does, and must refuse each once it is tampered with.

The other direction, a Mesh door answer checked by the plugin's requester,
is ``tests/test_evidence_responder.py`` (every form, read by
``ask_history``, whose checks are the plugin's) plus the run against the
plugin's own ``check`` recorded in that README.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from agent_action_capsule import evidence_request as er

import ask_history as ah

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "evidence-interop" / "plugin"


def _fixture(name: str) -> tuple[dict, ah.Reply]:
    fixture = json.loads((FIXTURES / f"{name}.json").read_text())
    sent = bytes.fromhex(fixture["request_hex"])
    # The request as asked: the answer is checked against its subject and coverage too.
    exchange = ah.Exchange(er.request_digest(sent), json.dumps(fixture["reply"]).encode(), json.loads(sent))
    return fixture, ah.read_reply(exchange, responder_key=fixture["responder"])


RECORD_ANSWERS = ["record-consistency", "record-first-anchor", "range", "range-min-freshness"]


@pytest.mark.parametrize("name", RECORD_ANSWERS)
def test_a_plugin_record_answer_reads_and_checks(name):
    fixture, reply = _fixture(name)
    assert reply.ok, reply.errors
    records, anchor, problems = ah.served_records(reply)
    assert not problems, problems
    assert anchor.digest == reply.envelope.anchor_digest
    subject = reply.envelope.subject
    if subject.form == "range":
        a, b = subject.content
        assert [r.leaf_index for r in records] == list(range(a, b + 1))
    else:
        assert [r.capsule_id for r in records] == [subject.content]
    # Each record is the plugin's ledger line, whose capsule_id is its digest.
    assert all(r.receipt["capsule_id"] == r.capsule_id for r in records)
    assert ah.verified_records(reply) == records


def test_a_plugin_record_answer_carries_the_consistency_proof_under_a_later_anchor():
    _fixture_, reply = _fixture("record-consistency")
    assert [kind for kind, _ in reply.envelope.verification] == [
        "cll-checkpoint", "cll-inclusion-proof", "cll-consistency-proof"
    ]
    # A profile verifier cannot prove a line that is not the committed entry: never FAIL.
    assert reply.cll.status == "NOT_CHECKED"


def test_a_plugin_checkpoint_list_reads_and_folds():
    _fixture_, reply = _fixture("checkpoints")
    assert reply.ok, reply.errors
    lines, problems = ah.answer_checkpoints(reply)
    assert not problems, problems
    assert len(lines) > 1
    card = ah.build_history_card(node_id="plugin", log_id=lines[0]["log_id"], checkpoint_lines=lines)
    assert card.properties.continuity == "unbroken" and card.properties.unforked


def _tampered(reply: ah.Reply, **changes) -> ah.Reply:
    envelope = dataclasses.replace(reply.envelope, **changes)
    body = json.loads(envelope.artifact) if envelope.artifact[:1] == b"{" else reply.body
    return dataclasses.replace(reply, envelope=envelope, body=body)


def test_a_tampered_plugin_record_is_refused():
    _fixture_, reply = _fixture("record-consistency")
    line = json.loads(reply.envelope.artifact)
    line["effect"] = {**line.get("effect", {}), "status": "failed"}
    forged = _tampered(reply, artifact=json.dumps(line).encode())
    assert ah.served_records(forged)[2] == ["the artifact is not the record the subject names"]


def test_a_plugin_range_with_a_record_swapped_is_refused():
    _fixture_, reply = _fixture("range")
    body = json.loads(reply.envelope.artifact)
    body["records"][0], body["records"][1] = body["records"][1], body["records"][0]
    forged = _tampered(reply, artifact=json.dumps(body).encode())
    assert ah.served_records(forged)[2]


def test_a_plugin_range_missing_a_proof_is_refused():
    _fixture_, reply = _fixture("range")
    forged = _tampered(reply, verification=reply.envelope.verification[:-1])
    assert ah.served_records(forged)[2] == [
        "the material is not the anchor checkpoint and one inclusion proof per record"
    ]


def test_a_plugin_checkpoint_list_that_does_not_start_the_stream_is_refused():
    _fixture_, reply = _fixture("checkpoints")
    body = json.loads(reply.envelope.artifact)
    assert len(body["checkpoints"]) == 2
    del body["checkpoints"][0]
    forged = _tampered(reply, artifact=json.dumps(body).encode())
    assert "the checkpoint list does not start the stream" in ah.answer_checkpoints(forged)[1]


def test_a_plugin_checkpoint_list_out_of_order_is_refused():
    _fixture_, reply = _fixture("checkpoints")
    body = json.loads(reply.envelope.artifact)
    body["checkpoints"].reverse()
    forged = _tampered(reply, artifact=json.dumps(body).encode())
    assert ah.answer_checkpoints(forged)[1]
