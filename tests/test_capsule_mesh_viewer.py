# SPDX-License-Identifier: Apache-2.0
"""capsule_mesh_viewer.py: the words-first role/question projection, selective
disclosure, and the fragment-carried offline HTML.

The browser-side capsule_id recompute (mesh_verify.js) is a hand port of
agent_action_capsule/canonical.py's vintage format-2 construction; its
byte-for-byte parity with the Python reference is exercised by the Node
harness in this repo's docs, not here (no node in the pytest env). What IS
asserted here is the Python half: the payload shape the JS consumes, the
role x question states, and that disclosure stays closed by default.
"""
from __future__ import annotations

import json

import pytest

import capsule_mesh_viewer as v
from capsule_mesh_viewer import (
    ANSWERED,
    NOT_IN_RECORD,
    PARTIAL,
    build_role_questions,
    decode_fragment,
    encode_fragment,
    plain_model_line,
    render_mesh_viewer_html,
    serving_provenance,
    to_fragment_payload,
)


# A nested-shape mesh capsule (capsule-producer/0.2.0), the real-capture shape.
def _nested_capsule(*, model="Llama-3.2-3B", quant="Q4_K_M", gpu="Apple M4 Max", vram=28991029248,
                    total_tokens=43, cross_party=None, chained=False) -> dict:
    poc = {
        "client_nonce_source": "client_supplied",
        "model_name_digest": "f" * 64,
        "serving_provenance": {
            "served_by_node_id": "n" * 64,
            "requesting_party": "unknown",
            "exchange_id": "chatcmpl-abc",
            "hostname": "host.local",
            "quantization": quant,
            "model": {"canonical_ref": model, "architecture": "llama"},
            "hardware": {"gpu": gpu, "vram_bytes": vram, "is_soc": True},
            "usage": {"prompt_tokens": 41, "completion_tokens": 2, "total_tokens": total_tokens},
        },
    }
    if cross_party is not None:
        poc["cross_party"] = cross_party
    cap = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": "c" * 64,
        "operator": "op",
        "timestamp": "2026-08-30T00:00:00Z",
        "model_attestation": {"model_id": model, "compute_attestation": {"x-mesh-poc-v1": poc}},
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }
    if chained:
        cap["chain"] = {"parent_capsule_id": "p" * 64, "relation": "follows"}
    return cap


def test_serving_provenance_flattens_nested_shape():
    sp = serving_provenance(_nested_capsule())
    assert sp["model"] == "Llama-3.2-3B"
    assert sp["quantization"] == "Q4_K_M"
    assert sp["gpu"] == "Apple M4 Max"
    assert sp["vram_bytes"] == 28991029248
    assert sp["is_soc"] is True
    assert sp["total_tokens"] == 43


def test_plain_model_line_is_words_first_no_digests():
    line = plain_model_line(serving_provenance(_nested_capsule()))
    assert "Llama-3.2-3B" in line
    assert "Q4_K_M" in line
    assert "Apple M4 Max" in line
    assert "43 tokens" in line
    assert "f" * 64 not in line  # no digest leaks into the plain sentence


def test_four_roles_three_questions_each():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, has_witness_checkpoint=False)
    roles = rq["roles"]
    assert set(roles) == {"requester", "provider", "coordinator", "third_party"}
    for role in roles.values():
        assert len(role["questions"]) == 3


def test_coordinator_questions_are_not_yet_in_the_record():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, has_witness_checkpoint=True)
    for qa in rq["roles"]["coordinator"]["questions"]:
        assert qa["state"] == NOT_IN_RECORD


def test_third_party_completeness_flips_on_witness_checkpoint():
    without = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, has_witness_checkpoint=False)
    withck = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, has_witness_checkpoint=True)
    q2_without = without["roles"]["third_party"]["questions"][1]
    q2_with = withck["roles"]["third_party"]["questions"][1]
    assert q2_without["state"] == NOT_IN_RECORD
    assert q2_with["state"] == ANSWERED


def test_provider_q1_answered_when_counterparty_present():
    with_cp = _nested_capsule(cross_party={"initiator_ref": "a" * 64})
    rq = build_role_questions(with_cp, source_log="plugin", verify_ok=True, has_witness_checkpoint=False)
    assert rq["roles"]["provider"]["questions"][0]["state"] == ANSWERED
    without = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, has_witness_checkpoint=False)
    assert without["roles"]["provider"]["questions"][0]["state"] == PARTIAL


def test_requester_q1_reports_failed_verify_honestly():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=False, has_witness_checkpoint=False)
    assert "FAILED verify" in rq["roles"]["requester"]["questions"][0]["answer"]


def test_disclosure_closed_by_default_digest_only():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    fields = payload["entries"][0]["disclosure"]["fields"]
    by_label = {f["label"]: f for f in fields}
    assert by_label["request"]["disclosed"] is False
    assert by_label["request"]["content"] is None
    assert by_label["request"]["digest"] == "1" * 64  # sealed to its digest


def test_disclosure_opens_only_the_named_field():
    cap = _nested_capsule()
    cid = cap["capsule_id"]
    payload = to_fragment_payload(
        [cap], source_log="plugin", disclose={cid: {"response": "why should I trust you — verify my record"}}
    )
    fields = {f["label"]: f for f in payload["entries"][0]["disclosure"]["fields"]}
    assert fields["response"]["disclosed"] is True
    assert "trust" in fields["response"]["content"]
    assert fields["request"]["disclosed"] is False  # the other field stays sealed


def test_fragment_roundtrip_and_full_record_carried():
    payload = to_fragment_payload([_nested_capsule(chained=True)], source_log="plugin")
    frag = encode_fragment(payload)
    back = decode_fragment(frag)
    assert back == payload
    # The full record travels so the browser can recompute capsule_id.
    assert back["entries"][0]["record"]["capsule_id"] == "c" * 64
    assert "chain" in back["entries"][0]["record"]


def test_witness_summary_present_when_checkpoint_supplied():
    checkpoint = {"kind": "mmr_checkpoint", "log_id": "log-1", "root": "r" * 64, "mmr_size": 3,
                  "timestamp": "2026-08-30T00:00:00Z", "checkpoint_cose": "d284..."}
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin", witness_checkpoint=checkpoint)
    assert payload["witness"]["log_id"] == "log-1"
    assert payload["witness"]["cose_present"] is True


def test_rendered_html_is_self_contained_and_carries_no_capsule_data():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    frag = encode_fragment(payload)
    html = render_mesh_viewer_html(frag)
    # offline: no external references at all.
    assert "<script src" not in html
    assert 'href="http' not in html and 'src="http' not in html
    assert "fetch(" not in html
    # the fragment is embedded (so opening the bare file shows the view),
    # AND the browser reads location.hash too (the permalink form).
    assert frag in html
    assert "location.hash" in html


def test_legacy_flat_shape_still_names_the_model():
    # ledger-live's older flat capsules: model only via model_attestation.model_id.
    flat = {
        "capsule_id": "d" * 64,
        "timestamp": "2026-08-11T06:07:08Z",
        "model_attestation": {
            "model_id": "bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M",
            "compute_attestation": {"x-mesh-poc-v1": {"client_nonce_source": "sidecar_generated_fallback"}},
        },
        "effect": {"request_digest": "9" * 64, "response_digest": "8" * 64},
    }
    sp = serving_provenance(flat)
    assert "Hermes-2-Pro-Mistral-7B" in sp["model"]
    rq = build_role_questions(flat, source_log="sidecar", verify_ok=None, has_witness_checkpoint=False)
    assert rq["roles"]["requester"]["questions"][0]["state"] == ANSWERED
