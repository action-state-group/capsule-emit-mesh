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
from capsule_emit.checkpoint import StampVerdict
from capsule_mesh_viewer import (
    ANSWERED,
    FAILED,
    NOT_IN_RECORD,
    PARTIAL,
    build_role_questions,
    build_verdict,
    decode_fragment,
    encode_fragment,
    friendly_model_name,
    plain_model_line,
    render_mesh_viewer_html,
    serving_provenance,
    to_fragment_payload,
    verify_witness_checkpoint,
)


# A nested-shape mesh capsule (capsule-producer/0.2.0), the real-capture shape.
def _nested_capsule(*, model="Llama-3.2-3B", quant="Q4_K_M", gpu="Apple M4 Max", vram=28991029248,
                    total_tokens=43, cross_party=None, chained=False,
                    generation_parameters=None) -> dict:
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
    # The REAL requested sampling knobs sealed by #54 -- a sibling of
    # serving_provenance inside the poc block. Absent by default so the
    # absent-stays-absent tests can control it explicitly.
    if generation_parameters is not None:
        poc["generation_parameters"] = generation_parameters
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
    assert sp["prompt_tokens"] == 41
    assert sp["completion_tokens"] == 2
    # No generation parameters sealed in the default fixture -> empty map, never None.
    assert sp["generation_parameters"] == {}


def test_serving_provenance_carries_sealed_generation_parameters():
    sp = serving_provenance(_nested_capsule(generation_parameters={"temperature": "0.0", "top_k": 40}))
    assert sp["generation_parameters"] == {"temperature": "0.0", "top_k": 40}


def test_plain_model_line_shows_in_out_total_token_split_not_just_total():
    line = plain_model_line(serving_provenance(_nested_capsule()))
    assert "Llama-3.2-3B" in line
    assert "Q4_K_M" in line
    assert "Apple M4 Max" in line
    # The split, not a bare "N tokens": prompt / completion / total.
    assert "41 in / 2 out / 43 total" in line
    assert "43 tokens" not in line
    assert "f" * 64 not in line  # no digest leaks into the plain sentence


def test_plain_token_split_builds_only_from_parts_present():
    from capsule_mesh_viewer import plain_token_split
    assert plain_token_split({"prompt_tokens": 73, "completion_tokens": 587, "total_tokens": 660}) == "73 in / 587 out / 660 total"
    # Absent halves stay absent -- honest by omission, never a fabricated 0.
    assert plain_token_split({"total_tokens": 42}) == "42 total"
    assert plain_token_split({"prompt_tokens": 5}) == "5 in"
    assert plain_token_split({}) is None


def test_plain_gen_params_line_shows_only_sealed_knobs_absent_stays_absent():
    from capsule_mesh_viewer import plain_gen_params_line
    sp = serving_provenance(
        _nested_capsule(generation_parameters={"temperature": "0.0", "top_k": 40, "seed": 12345, "max_tokens": 512})
    )
    line = plain_gen_params_line(sp)
    # Friendly labels; stringified-float temperature tidied "0.0" -> "0"; order stable.
    assert line == "generated with: temperature 0, top-k 40, seed 12345, max_tokens 512"
    # A param the capsule did NOT carry is never printed.
    assert "top-p" not in line
    assert "top_p" not in line
    assert "frequency_penalty" not in line


def test_plain_gen_params_line_is_none_when_no_params_sealed():
    from capsule_mesh_viewer import plain_gen_params_line
    # The observe path seals an empty map; a thin capsule may carry none.
    assert plain_gen_params_line(serving_provenance(_nested_capsule())) is None
    assert plain_gen_params_line(serving_provenance(_nested_capsule(generation_parameters={}))) is None


def test_plain_gen_params_line_tidies_stringified_floats_but_keeps_lists():
    from capsule_mesh_viewer import plain_gen_params_line
    sp = serving_provenance(
        _nested_capsule(generation_parameters={"temperature": "0.70", "top_p": "0.95", "stop": ["</s>", "\n\n"]})
    )
    line = plain_gen_params_line(sp)
    assert "temperature 0.7" in line
    assert "top-p 0.95" in line
    # A stop array renders its members, not a Python repr.
    assert "stop </s>, \n\n" in line


# A raw-GGUF capsule: the only model identity is a content hash + arch + size,
# exactly the mesh-live shape whose raw "local-gguf/sha256-…" title Steven
# flagged as unreadable.
def _raw_gguf_sp() -> dict:
    return serving_provenance(
        {
            "model_attestation": {
                "model_id": "local-gguf/sha256-887fbdc66ab91eb5",
                "compute_attestation": {
                    "x-mesh-poc-v1": {
                        "client_nonce_source": "host_served_observed",
                        "model_name_digest": "d" * 64,
                        "serving_provenance": {
                            "quantization": "Q4_K_M",
                            "model": {
                                "architecture": "llama",
                                "parameter_size": "3B",
                                "canonical_ref": "local-gguf/sha256-887fbdc66ab91eb5",
                                "identity_hash": "d" * 64,
                            },
                            "hardware": {"gpu": "Apple M3", "is_soc": True},
                            "usage": {"prompt_tokens": 73, "completion_tokens": 587, "total_tokens": 660},
                        },
                    }
                },
            }
        }
    )


def test_friendly_model_name_derives_family_and_never_leaks_raw_hash():
    sp = _raw_gguf_sp()
    name = friendly_model_name(sp)
    # architecture(llama) + parameter_size(3B) + quantization -> Llama-3B · Q4_K_M
    assert name == "Llama-3B · Q4_K_M"
    # the single biggest win: the raw local-gguf/sha256 id NEVER appears here.
    assert "local-gguf" not in name
    assert "sha256" not in name
    assert "d" * 16 not in name


def test_friendly_model_name_prefers_a_real_hf_ref_tail():
    sp = serving_provenance(_nested_capsule(model="meta-llama/Llama-3.2-3B-Instruct"))
    assert friendly_model_name(sp) == "Llama-3.2-3B-Instruct · Q4_K_M"


def test_verdict_is_three_plain_lines_with_honest_marks():
    sp = _raw_gguf_sp()
    verdict = build_verdict(sp, verify_ok=True, witness_verdict=None, counterparty="unknown")
    assert len(verdict) == 3
    # line 1: attests it ran (self-reported), green, friendly name, no raw hash
    assert verdict[0]["mark"] == "ok"
    assert "Attests it ran on Llama-3B" in verdict[0]["text"]
    assert "self-reported" in verdict[0]["text"]
    assert "recompute" in verdict[0]["text"]
    assert "sha256" not in verdict[0]["text"]
    # line 2: honest amber — witness receipt not in this bundle
    assert verdict[1]["mark"] == "warn"
    assert "witness receipt isn't in this bundle" in verdict[1]["text"]
    # line 3: honest amber — who asked / node history not proven
    assert verdict[2]["mark"] == "warn"
    assert "Not yet proven" in verdict[2]["text"]


def test_verdict_never_fakes_green_on_failed_verify():
    sp = _raw_gguf_sp()
    verdict = build_verdict(sp, verify_ok=False, witness_verdict=None, counterparty="unknown")
    assert verdict[0]["mark"] == "warn"
    assert "FAILED verification" in verdict[0]["text"]


def test_verdict_line2_goes_green_only_when_the_receipt_actually_verifies():
    sp = _raw_gguf_sp()
    verdict = build_verdict(sp, verify_ok=True, witness_verdict=StampVerdict.WITNESSED, counterparty="unknown")
    assert verdict[1]["mark"] == "ok"
    assert "verifies" in verdict[1]["text"]


def test_verdict_line2_is_a_hard_fail_never_amber_when_receipt_is_invalid():
    # Mutant this guards: a tampered/forged witness receipt must NEVER read
    # the same as "no receipt at all" (warn) -- it is a caught tamper, a
    # stronger and more alarming statement, and must be its own mark ("bad").
    sp = _raw_gguf_sp()
    verdict = build_verdict(sp, verify_ok=True, witness_verdict=StampVerdict.INVALID, counterparty="unknown")
    assert verdict[1]["mark"] == "bad"
    assert "FAILS to verify" in verdict[1]["text"]
    assert "witness receipt isn't in this bundle" not in verdict[1]["text"]


def test_verdict_line2_unverified_stays_amber_distinct_from_missing():
    sp = _raw_gguf_sp()
    verdict = build_verdict(sp, verify_ok=True, witness_verdict=StampVerdict.UNVERIFIED, counterparty="unknown")
    assert verdict[1]["mark"] == "warn"
    assert "isn't pinned" in verdict[1]["text"]


def test_entry_payload_carries_friendly_name_and_verdict_not_raw_title():
    payload = to_fragment_payload(
        [
            {
                "capsule_id": "e" * 64,
                "timestamp": "2026-08-30T00:00:00Z",
                "operator": "capsule-emit-mesh-poc-rust",
                "model_attestation": {
                    "model_id": "local-gguf/sha256-887fbdc66ab91eb5",
                    "compute_attestation": {
                        "x-mesh-poc-v1": {
                            "client_nonce_source": "host_served_observed",
                            "serving_provenance": {
                                "quantization": "Q4_K_M",
                                "model": {
                                    "architecture": "llama",
                                    "parameter_size": "3B",
                                    "canonical_ref": "local-gguf/sha256-887fbdc66ab91eb5",
                                },
                                "hardware": {"gpu": "Apple M3", "is_soc": True},
                                "usage": {"prompt_tokens": 73, "completion_tokens": 587, "total_tokens": 660},
                            },
                        }
                    },
                },
                "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64},
                "disposition": {"decision": "accept", "verdict_class": "executed"},
            }
        ],
        source_log="plugin",
    )
    entry = payload["entries"][0]
    assert entry["friendly_model"] == "Llama-3B · Q4_K_M"
    assert len(entry["verdict"]) == 3
    # The raw hash is still carried for the auditor toggle (serving_provenance),
    # but the friendly_model default title never contains it.
    assert "sha256" not in entry["friendly_model"]
    assert entry["serving_provenance"]["model_canonical_ref"].startswith("local-gguf/")


def test_four_roles_three_questions_each():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, witness_verdict=None)
    roles = rq["roles"]
    assert set(roles) == {"requester", "provider", "coordinator", "third_party"}
    for role in roles.values():
        assert len(role["questions"]) == 3


def test_coordinator_questions_are_not_yet_in_the_record():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, witness_verdict=StampVerdict.WITNESSED)
    for qa in rq["roles"]["coordinator"]["questions"]:
        assert qa["state"] == NOT_IN_RECORD


def test_third_party_completeness_flips_on_witness_checkpoint():
    without = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, witness_verdict=None)
    withck = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, witness_verdict=StampVerdict.WITNESSED)
    q2_without = without["roles"]["third_party"]["questions"][1]
    q2_with = withck["roles"]["third_party"]["questions"][1]
    assert q2_without["state"] == NOT_IN_RECORD
    assert q2_with["state"] == ANSWERED


def test_provider_q1_answered_when_counterparty_present():
    with_cp = _nested_capsule(cross_party={"initiator_ref": "a" * 64})
    rq = build_role_questions(with_cp, source_log="plugin", verify_ok=True, witness_verdict=None)
    assert rq["roles"]["provider"]["questions"][0]["state"] == ANSWERED
    without = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=True, witness_verdict=None)
    assert without["roles"]["provider"]["questions"][0]["state"] == PARTIAL


def test_requester_q1_reports_failed_verify_honestly():
    rq = build_role_questions(_nested_capsule(), source_log="plugin", verify_ok=False, witness_verdict=None)
    assert "FAILED verify" in rq["roles"]["requester"]["questions"][0]["answer"]


def test_disclosure_closed_by_default_is_inline_sealed_tag():
    # The redundant bottom "Disclosure (sealed vs shown)" block is gone; the
    # sealed-vs-shown state now rides inline on the conversation as a per-field
    # `disclosed` flag (green "shown by operator" / grey "sealed — digest only").
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    conv = payload["entries"][0]["conversation"]
    assert conv["prompt"]["disclosed"] is False  # sealed — digest only
    assert conv["response"]["disclosed"] is False
    # And the redundant repeated-content block is no longer emitted.
    assert "disclosure" not in payload["entries"][0]


def test_disclosure_opens_only_the_named_field_inline():
    cap = _nested_capsule()
    cid = cap["capsule_id"]
    payload = to_fragment_payload(
        [cap], source_log="plugin", disclose={cid: {"response": "why should I trust you — verify my record"}}
    )
    conv = payload["entries"][0]["conversation"]
    assert conv["response"]["disclosed"] is True  # shown by operator
    assert "trust" in conv["response"]["text"]
    assert conv["prompt"]["disclosed"] is False  # the other field stays sealed


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
    # No `witnesses` entry on the checkpoint dict -- self-checkpointed only,
    # nothing to re-verify: the honest "not shown here" state, not a fail.
    assert payload["witness"]["verdict"] is None


# -- verify_witness_checkpoint: the ACTUAL recompute (never presence), real
# library crypto -- no mocking of the verify machinery itself. --------------


def _real_checkpoint_dict(**overrides) -> dict:
    import hashlib

    from capsule_emit.checkpoint import CheckpointRecord

    base = dict(
        v=1, kind="cll-checkpoint", log_id="log-a", mmr_size=3, root="a" * 64,
        prev_size=0, prev_root="0" * 64, key_id="k" * 64,
        timestamp="2026-09-03T00:00:00Z", signature="s" * 128,
    )
    base.update(overrides)
    cp = CheckpointRecord(**base)
    return cp.to_dict()


def _entry_hash_for(checkpoint_dict: dict) -> str:
    import hashlib

    from capsule_emit.checkpoint import CheckpointRecord

    return hashlib.sha256(bytes.fromhex(CheckpointRecord.from_dict(checkpoint_dict).digest())).hexdigest()


def test_verify_witness_checkpoint_none_when_absent():
    assert verify_witness_checkpoint(None) == (None, [])
    assert verify_witness_checkpoint({"root": "a" * 64}) == (None, [])  # no `witnesses` key at all


def test_verify_witness_checkpoint_invalid_on_tampered_root():
    """W2's core mutant: a witness receipt bound to the ORIGINAL checkpoint,
    carried alongside a checkpoint dict whose `root` was tampered afterward
    -- e.g. someone hand-edited checkpoints.jsonl -- must recompute as
    INVALID (a hard fail), never silently pass and never collapse into the
    "no receipt at all" (None/amber) state. No signing keys involved: the
    entry_hash-to-checkpoint-digest binding alone catches this."""
    import base64

    original = _real_checkpoint_dict()
    entry_hash = _entry_hash_for(original)
    tampered = dict(original, root="f" * 64)  # same witnesses, different root
    tampered["witnesses"] = [
        {"ts_url": "https://witness.agentactioncapsule.org", "entry_hash": entry_hash,
         "receipt_b64": base64.b64encode(b"irrelevant-not-reached").decode(), "leaf_index": 0, "tree_size": 1}
    ]
    verdict, errors = verify_witness_checkpoint(tampered)
    assert verdict is StampVerdict.INVALID
    assert errors  # a reason is always given, never a silent fail


def test_verify_witness_checkpoint_invalid_on_garbage_receipt_bytes():
    """A hand-fabricated stamp (right entry_hash, but receipt_b64 that is not
    a real COSE Receipt at all) must also fail, not just a mismatched hash."""
    import base64

    checkpoint = _real_checkpoint_dict()
    entry_hash = _entry_hash_for(checkpoint)
    checkpoint["witnesses"] = [
        {"ts_url": "https://witness.agentactioncapsule.org", "entry_hash": entry_hash,
         "receipt_b64": base64.b64encode(b"not a cose receipt").decode(), "leaf_index": 0, "tree_size": 1}
    ]
    verdict, errors = verify_witness_checkpoint(checkpoint)
    assert verdict is StampVerdict.INVALID
    assert errors


def test_verify_witness_checkpoint_unverified_for_a_real_receipt_from_an_unpinned_ts():
    """A genuine, well-formed, checkpoint-bound COSE Receipt (built with the
    real scitt_cose wire format, signed with a throwaway key) from a
    non-default `ts_url` this viewer has no pinned key for: real receipt
    shape, but identity can't be confirmed offline -- UNVERIFIED, distinct
    from both WITNESSED and INVALID."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from scitt_cose import build_receipt

    checkpoint = _real_checkpoint_dict()
    entry_hash = _entry_hash_for(checkpoint)
    key = Ed25519PrivateKey.generate()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    receipt_bytes = build_receipt(
        leaf_entry_hex=entry_hash, leaf_index=0, tree_entries_hex=[entry_hash], alg="EdDSA",
        log_private_key_pem=key_pem,
    )
    checkpoint["witnesses"] = [
        {"ts_url": "https://self-hosted-witness.example", "entry_hash": entry_hash,
         "receipt_b64": base64.b64encode(receipt_bytes).decode(), "leaf_index": 0, "tree_size": 1}
    ]
    verdict, errors = verify_witness_checkpoint(checkpoint)
    assert verdict is StampVerdict.UNVERIFIED
    assert errors


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
    rq = build_role_questions(flat, source_log="sidecar", verify_ok=None, witness_verdict=None)
    # verify-after-advertise (§12.3) changed Requester Q1's semantics: a record
    # that NAMES a served model but co-carries NO advertisement can no longer
    # read as a clean green -- there is no advertised claim to reconcile against,
    # so the honest state is PARTIAL (advertisement_absent), never a silent
    # ANSWERED. The served model is still named in the answer text.
    q1 = rq["roles"]["requester"]["questions"][0]
    assert q1["state"] == PARTIAL
    assert "advertisement_absent" in q1["answer"]
    assert "Hermes-2-Pro-Mistral-7B" in q1["answer"]


# ---------------------------------------------------------------------------
# Requester-only mode + inference-forward conversation block (user feedback:
# "just the requester only"; "I can't see the inference returned").
# ---------------------------------------------------------------------------

from capsule_mesh_viewer import (  # noqa: E402
    DEFAULT_ROLE,
    build_conversation,
    served_facts_digest,
)


def _served_facts_capsule():
    """A nested capsule whose response_digest is the REAL served-facts digest
    (model + usage), so the conversation block's digest check can verify."""
    cap = _nested_capsule(total_tokens=43)
    sp = serving_provenance(cap)
    real = served_facts_digest(sp)
    assert real is not None, "served_facts_digest needs the JCS reference (capsule_sidecar)"
    cap["effect"]["response_digest"] = real
    return cap, real


def test_default_role_is_requester():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    assert payload["default_role"] == "requester"
    assert DEFAULT_ROLE == "requester"


def test_role_flag_all_is_carried_verbatim():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin", default_role="all")
    assert payload["default_role"] == "all"


def test_bad_role_falls_back_to_requester():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin", default_role="nonsense")
    assert payload["default_role"] == "requester"


def test_all_four_roles_still_carried_even_in_requester_default():
    # requester-only is a DISPLAY default; the other roles are never deleted
    # from the payload -- they fold behind a toggle in the browser.
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    roles = payload["entries"][0]["role_questions"]["roles"]
    assert set(roles) == {"requester", "provider", "coordinator", "third_party"}


def test_served_facts_digest_matches_the_seal_construction():
    # The viewer recomputes response_digest exactly as the Rust seal path does:
    # canonical JSON-DIGEST of {model, usage:{prompt,completion,total}}.
    cap, real = _served_facts_capsule()
    sp = serving_provenance(cap)
    assert served_facts_digest(sp) == real
    assert cap["effect"]["response_digest"] == real


def test_conversation_block_leads_with_verified_inference():
    cap, real = _served_facts_capsule()
    conv = build_conversation(
        cap,
        serving_provenance(cap),
        {"request": "how great is mesh-llm", "response": "I don't have information about mesh-llm."},
    )
    # prompt + response shown (words-first)
    assert conv["prompt"]["text"] == "how great is mesh-llm"
    assert "mesh-llm" in conv["response"]["text"]
    # served-by names node/model/gpu + the in/out/total token split
    assert conv["served_by"]["model"] == "Llama-3.2-3B"
    assert conv["served_by"]["token_split"] == "41 in / 2 out / 43 total"
    # No gen params sealed in this fixture -> None (absent stays absent).
    assert conv["served_by"]["gen_params_line"] is None
    # the response verify is over the served FACTS and MATCHES the sealed digest
    rv = conv["response"]["verify"]
    assert rv["kind"] == "served_facts"
    assert rv["computed_digest"] == real
    assert rv["matches"] is True
    # honest boundary spelled out: the text is requester-held, not the sealed body
    assert "requester" in rv["note"].lower()


def test_conversation_served_by_carries_gen_params_line_when_sealed():
    cap = _nested_capsule(generation_parameters={"temperature": "0.0", "top_k": 40, "seed": 12345})
    conv = build_conversation(cap, serving_provenance(cap), {"request": "hi", "response": "hey"})
    assert conv["served_by"]["gen_params_line"] == "generated with: temperature 0, top-k 40, seed 12345"
    assert conv["served_by"]["token_split"] == "41 in / 2 out / 43 total"


def test_entry_payload_gen_params_flow_through_serving_provenance():
    cap = _nested_capsule(generation_parameters={"temperature": "0.0", "top_k": 40})
    payload = to_fragment_payload([cap], source_log="plugin")
    entry = payload["entries"][0]
    # The raw sealed map travels behind the auditor toggle...
    assert entry["serving_provenance"]["generation_parameters"] == {"temperature": "0.0", "top_k": 40}
    # ...and the friendly display line rides on the conversation's served-by.
    assert entry["conversation"]["served_by"]["gen_params_line"] == "generated with: temperature 0, top-k 40"


def test_conversation_response_mismatch_is_shown_honestly():
    # If the served facts do NOT recompute to the sealed response_digest,
    # the block says so -- never a false "matches".
    cap = _nested_capsule()  # response_digest is "2"*64, NOT the facts digest
    conv = build_conversation(cap, serving_provenance(cap), {"response": "x"})
    assert conv["response"]["verify"]["matches"] is False


def test_conversation_prompt_stays_sealed_when_body_not_held():
    # We hold the plain prompt text but not the exact request BODY, so
    # request_digest stays sealed -- matches is None, never a faked True.
    cap, _ = _served_facts_capsule()
    conv = build_conversation(cap, serving_provenance(cap), {"request": "how great is mesh-llm"})
    pv = conv["prompt"]["verify"]
    assert pv["kind"] == "request_sealed"
    assert pv["matches"] is None
    assert pv["sealed_digest"] == cap["effect"]["request_digest"]


def test_conversation_verifies_request_body_when_the_exact_bytes_are_held():
    # When the requester supplies the exact request JSON body, it DOES verify
    # against request_digest (canonical JSON-DIGEST of the body).
    from capsule_sidecar import digest_json

    body = {"model": "Llama-3.2-3B", "messages": [{"role": "user", "content": "how great is mesh-llm"}]}
    cap, _ = _served_facts_capsule()
    cap["effect"]["request_digest"] = digest_json(body)
    conv = build_conversation(
        cap, serving_provenance(cap), {"request": "how great is mesh-llm", "request_body": body}
    )
    pv = conv["prompt"]["verify"]
    assert pv["kind"] == "request_body"
    assert pv["matches"] is True


def test_tool_calls_note_is_carried_verbatim():
    cap, _ = _served_facts_capsule()
    conv = build_conversation(
        cap,
        serving_provenance(cap),
        {"response": "(tool call) web_search(...)", "tool_calls_note": "a web_search tool_call was made"},
    )
    assert conv["response"]["tool_calls_note"] == "a web_search tool_call was made"


# ---------------------------------------------------------------------------
# [disclosure-default-on] recompute-and-match over the sidecar's own preimage.
# The sidecar's response_digest is digest_json(response_json) -- the FULL raw
# response body, not just the served facts -- so when the disclosed
# response_body is the exact object, the viewer can prove a byte-exact match,
# and a tampered body must recompute to a DIFFERENT digest (red).
# ---------------------------------------------------------------------------


def test_conversation_verifies_response_body_when_the_exact_bytes_are_held():
    from capsule_sidecar import digest_json

    response_body = {
        "id": "chatcmpl-1",
        "choices": [{"message": {"role": "assistant", "content": "mesh-llm is a local inference mesh."}}],
    }
    cap, _ = _served_facts_capsule()
    cap["effect"]["response_digest"] = digest_json(response_body)
    conv = build_conversation(
        cap,
        serving_provenance(cap),
        {"response": "mesh-llm is a local inference mesh.", "response_body": response_body},
    )
    rv = conv["response"]["verify"]
    assert rv["kind"] == "response_body"
    assert rv["sealed_digest"] == cap["effect"]["response_digest"]
    assert rv["computed_digest"] == digest_json(response_body)
    assert rv["matches"] is True
    assert conv["response"]["disclosed"] is True


def test_conversation_response_body_tamper_goes_red():
    # A tamper of the disclosed text (reflected in the held response_body)
    # must NEVER show a false "matches" -- this is the honesty test the
    # disclosure feature exists to satisfy.
    from capsule_sidecar import digest_json

    real_body = {
        "id": "chatcmpl-1",
        "choices": [{"message": {"role": "assistant", "content": "mesh-llm is a local inference mesh."}}],
    }
    cap, _ = _served_facts_capsule()
    cap["effect"]["response_digest"] = digest_json(real_body)

    tampered_body = json.loads(json.dumps(real_body))
    tampered_body["choices"][0]["message"]["content"] = "mesh-llm sends your prompts to a third party."
    conv = build_conversation(
        cap,
        serving_provenance(cap),
        {"response": tampered_body["choices"][0]["message"]["content"], "response_body": tampered_body},
    )
    rv = conv["response"]["verify"]
    assert rv["kind"] == "response_body"
    assert rv["computed_digest"] != rv["sealed_digest"]
    assert rv["matches"] is False


def test_conversation_falls_back_to_served_facts_when_no_response_body_held():
    # Absent a body preimage, the honest served-facts approximation still
    # applies (host-served / legacy path) -- never upgraded to response_body.
    cap, real = _served_facts_capsule()
    conv = build_conversation(cap, serving_provenance(cap), {"response": "hello"})
    assert conv["response"]["verify"]["kind"] == "served_facts"
    assert conv["response"]["verify"]["computed_digest"] == real


# ---------------------------------------------------------------------------
# [mesh-disclosure-recompute-jcs-float] response_body recompute against a
# HOST-FORWARDED response_digest (mesh-llm host's plain-JCS + ryu-float
# construction, `openai_exchange::jcs_value`), distinct from the
# capsule-sidecar strict-JCS + repr-stringified-float construction covered
# above. `LLAMA_CPP_TIMINGS_FIXTURE` is identical literal JSON text to
# `openai_exchange.rs`'s fixture of the same name and
# `canonical.test.ts`'s copy -- keep all three in sync character-for-
# character if any changes. The pinned digest is asserted equal in all three
# languages (Rust: `response_digest_over_real_llama_cpp_timings_floats`;
# TS: `matches the Rust seal path digest ...`; here).
# ---------------------------------------------------------------------------

LLAMA_CPP_TIMINGS_FIXTURE = (
    '{"id":"chatcmpl-mesh-1","object":"chat.completion","created":1700000000,'
    '"model":"llama-3.2-3b-instruct","choices":[{"index":0,"message":{"role":"assistant",'
    '"content":"hi there"},"finish_reason":"stop"}],'
    '"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15},'
    '"timings":{"prompt_n":10,"prompt_ms":123.456,"prompt_per_token_ms":12.3456,'
    '"prompt_per_second":81.0,"predicted_n":5,"predicted_ms":234.567,'
    '"predicted_per_token_ms":46.9134,"predicted_per_second":21.3169}}'
)
EXPECTED_TIMINGS_DIGEST = "7179feb00c2b4e2a99a785449eb202c2faf9694cc77501876802c300f57b298a"

# Identical literal JSON text to `openai_exchange.rs`'s
# `response_digest_over_integer_only_body_unchanged` fixture / `canonical.test.ts`'s copy.
INTEGER_ONLY_BODY = (
    '{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant",'
    '"content":"hello"},"finish_reason":"stop"}],'
    '"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}'
)
EXPECTED_INTEGER_ONLY_DIGEST = "660e8a56afa6b1cdf4b088c0c42be7f6af958b28492b7583d6676a684dbe5bd7"


def test_rust_plain_jcs_digest_matches_the_pinned_rust_seal_vector():
    # (mutant 1) A real llama.cpp `timings` float block digests to the SAME
    # hex the Rust seal path produces -- byte-for-byte parity, not merely
    # "some digest was computed".
    body = json.loads(LLAMA_CPP_TIMINGS_FIXTURE)
    assert v._rust_plain_jcs_digest(body) == EXPECTED_TIMINGS_DIGEST


def test_rust_plain_jcs_digest_integer_only_body_unchanged():
    # (mutant 3, no regression) The already-working integer-only path still
    # digests correctly under the new plain-JCS construction too.
    body = json.loads(INTEGER_ONLY_BODY)
    assert v._rust_plain_jcs_digest(body) == EXPECTED_INTEGER_ONLY_DIGEST


def test_rust_plain_jcs_digest_whole_number_float_not_collapsed_to_integer():
    # `prompt_per_second: 81.0` is a WHOLE-NUMBER float -- Python's `json`
    # module (unlike JS) already keeps it a `float` (not collapsed to the
    # `int` 81), but assert the mechanism end-to-end: changing the source
    # text `81.0` -> `81` changes the digest.
    bare_int = LLAMA_CPP_TIMINGS_FIXTURE.replace('"prompt_per_second":81.0', '"prompt_per_second":81')
    assert v._rust_plain_jcs_digest(json.loads(bare_int)) != EXPECTED_TIMINGS_DIGEST


def test_format_rust_float_matches_rust_thresholds_not_pythons_own_repr():
    # Rust's ryu-based formatter stays fixed-point for -5 <= exponent <= 15,
    # a DIFFERENT threshold than Python's own `repr()` (e.g. `repr(1e-05)` is
    # already scientific `"1e-05"`, but Rust wants fixed `"0.00001"`) -- a
    # naive `return repr(v)` implementation would pass the timings-fixture
    # digest test above (none of its values sit in the divergent range) but
    # fail here. Values pinned against the Rust/TS ports directly (see
    # `openai_exchange.rs` test module comments and `canonical.ts`'s
    # `formatRustFloat` module note).
    cases = [
        (1e-5, "0.00001"),  # Rust fixed; Python repr is scientific "1e-05"
        (1e-6, "1e-6"),  # both scientific, but Rust omits repr's zero-pad
        (1e15, "1000000000000000.0"),  # Rust fixed at the e==15 boundary
        (1e16, "1e+16"),  # Rust scientific at the e==16 boundary
        (-0.0, "-0.0"),  # negative zero sign preserved
        (0.0, "0.0"),
        (81.0, "81.0"),  # whole-number float still gets a trailing .0
    ]
    for value, expected in cases:
        assert v._format_rust_float(value) == expected, f"formatting {value!r}"


def test_format_rust_float_rejects_nan_and_infinity():
    # (mutant 4) NaN/Infinity are not valid JSON and must never coerce into a
    # digest -- explicit rejection.
    with pytest.raises(ValueError):
        v._format_rust_float(float("nan"))
    with pytest.raises(ValueError):
        v._format_rust_float(float("inf"))
    with pytest.raises(ValueError):
        v._format_rust_float(float("-inf"))
    # And the digest wrapper never fabricates one -- honest None instead of
    # raising out of `_response_body_verify`'s call site.
    assert v._rust_plain_jcs_digest({"x": float("nan")}) is None


def test_response_body_verify_green_matches_a_host_forwarded_float_capsule():
    # (mutant 1) A real llama.cpp response WITH a `timings` float block,
    # sealed via the HOST-FORWARDED plain-JCS construction (not the
    # capsule-sidecar strict construction) -- the strict construction tried
    # first does NOT match this digest, so this exercises the fallback.
    body = json.loads(LLAMA_CPP_TIMINGS_FIXTURE)
    cap, _ = _served_facts_capsule()
    cap["effect"]["response_digest"] = EXPECTED_TIMINGS_DIGEST
    conv = build_conversation(cap, serving_provenance(cap), {"response": "hi there", "response_body": body})
    rv = conv["response"]["verify"]
    assert rv["kind"] == "response_body"
    assert rv["matches"] is True
    assert rv["computed_digest"] == EXPECTED_TIMINGS_DIGEST
    assert rv["construction"] == v.RESPONSE_BODY_PLAIN_JCS_RYU_FLOATS_V1


def test_response_body_verify_tampered_float_body_goes_red():
    # (mutant 2) One byte changed in a real-float body must mismatch under
    # BOTH known constructions -- never a false "matches".
    tampered = LLAMA_CPP_TIMINGS_FIXTURE.replace('"hi there"', '"hi there!"')
    cap, _ = _served_facts_capsule()
    cap["effect"]["response_digest"] = EXPECTED_TIMINGS_DIGEST
    conv = build_conversation(
        cap, serving_provenance(cap), {"response": "hi there!", "response_body": json.loads(tampered)}
    )
    rv = conv["response"]["verify"]
    assert rv["kind"] == "response_body"
    assert rv["matches"] is False
    assert rv["computed_digest"] != rv["sealed_digest"]


def test_response_body_verify_labels_the_strict_construction_when_sidecar_sealed():
    # (mutant 3, no regression) An integer-only body sealed the ORIGINAL way
    # (capsule_sidecar.digest_json) still matches on the FIRST try, labeled
    # with the strict construction -- the new fallback never shadows the
    # common case.
    from capsule_sidecar import digest_json

    body = json.loads(INTEGER_ONLY_BODY)
    cap, _ = _served_facts_capsule()
    cap["effect"]["response_digest"] = digest_json(body)
    conv = build_conversation(cap, serving_provenance(cap), {"response": "hello", "response_body": body})
    rv = conv["response"]["verify"]
    assert rv["matches"] is True
    assert rv["construction"] == v.RESPONSE_BODY_STRICT_JCS_STRINGIFY_FLOATS_V1


# ---------------------------------------------------------------------------
# load_disclosures -- auto-loads capsule_sidecar.py's DEFAULT-ON preimage
# store next to a ledger, so a fresh sidecar-sealed capsule shows disclosed
# without needing explicit --disclose flags.
# ---------------------------------------------------------------------------


def test_load_disclosures_reads_persisted_preimage_files(tmp_path):
    from capsule_mesh_viewer import load_disclosures

    disclosures_dir = tmp_path / "disclosures"
    disclosures_dir.mkdir()
    (disclosures_dir / "cap-1.json").write_text(
        json.dumps(
            {
                "capsule_id": "cap-1",
                "request_body": {"messages": [{"role": "user", "content": "hi"}]},
                "response_body": {"choices": [{"message": {"content": "hey"}}]},
                "request_text": "hi",
                "response_text": "hey",
                "tool_calls_note": None,
            }
        )
    )
    loaded = load_disclosures(tmp_path)
    assert set(loaded) == {"cap-1"}
    entry = loaded["cap-1"]
    assert entry["request"] == "hi"
    assert entry["response"] == "hey"
    assert entry["request_body"] == {"messages": [{"role": "user", "content": "hi"}]}
    assert entry["response_body"] == {"choices": [{"message": {"content": "hey"}}]}
    assert "tool_calls_note" not in entry  # None stays absent, never a fabricated key


def test_load_disclosures_missing_directory_returns_empty(tmp_path):
    from capsule_mesh_viewer import load_disclosures

    assert load_disclosures(tmp_path / "no-such-ledger") == {}


def test_load_disclosures_skips_malformed_files_without_raising(tmp_path):
    from capsule_mesh_viewer import load_disclosures

    disclosures_dir = tmp_path / "disclosures"
    disclosures_dir.mkdir()
    (disclosures_dir / "broken.json").write_text("{not valid json")
    assert load_disclosures(tmp_path) == {}


# ---------------------------------------------------------------------------
# Embed serialization -- REGRESSION for the corruption where the base64
# fragment was jammed into the JS boot GUARD condition
# (`if (embedded && embedded !== ""<base64>...`) instead of ONLY the
# `window.__MESH_FRAGMENT_B64U__="..."` placeholder -- a JS syntax error that
# blanked the page. See mesh-live-demo-permalink.html.bak.
# ---------------------------------------------------------------------------

import re  # noqa: E402


def _extract_embedded(html: str) -> str:
    m = re.search(r'window\.__MESH_FRAGMENT_B64U__="([A-Za-z0-9_\-]+)";', html)
    assert m, "the placeholder assignment must carry the base64url fragment"
    return m.group(1)


def test_embed_lands_only_in_the_placeholder_not_the_boot_guard():
    payload = to_fragment_payload([_nested_capsule()], source_log="plugin")
    frag = encode_fragment(payload)
    html = render_mesh_viewer_html(frag)

    # 1) the embedded value equals exactly the intended fragment.
    embedded = _extract_embedded(html)
    assert embedded == frag

    # 2) the base64 appears EXACTLY once in the whole document -- i.e. only in
    #    the placeholder, never leaked into the guard or anywhere else.
    assert html.count(frag) == 1

    # 3) the boot guard is intact and is NOT followed by base64. The guard must
    #    still be a well-formed comparison against a sentinel, never against the
    #    fragment bytes.
    assert "if (embedded && embedded !== UNFILLED)" in html
    # the exact corruption signature from the .bak: `!== ""` immediately
    # followed by base64 characters.
    assert not re.search(r'embedded !== "(?:@@FRAGMENT@@)?"[A-Za-z0-9_\-]{20,}', html)
    # and the guard line does not contain the fragment at all.
    guard_line = next(l for l in html.splitlines() if "embedded !== UNFILLED" in l)
    assert frag not in guard_line


def test_render_raises_if_placeholder_count_is_wrong(monkeypatch):
    # The renderer asserts exactly one placeholder before substituting, so a
    # future edit that duplicates or drops it fails loudly instead of silently
    # producing a corrupt page.
    import capsule_mesh_viewer as mod

    monkeypatch.setattr(mod, "_HTML_SHELL", "no placeholder here @@VERIFY_JS@@")
    with pytest.raises(RuntimeError, match="exactly one @@FRAGMENT@@"):
        render_mesh_viewer_html("Zm9v")


def test_bare_file_without_embed_shows_empty_state_guard_sentinel_intact():
    # When the shell is opened with the placeholder UNfilled (sentinel present),
    # the guard's runtime-assembled UNFILLED token must equal the sentinel so
    # boot() treats it as "no data" rather than trying to decode "@@FRAGMENT@@".
    js = (resources_text())
    assert '"@@" + "FRAGMENT" + "@@"' in js  # sentinel assembled, never a literal
    assert "@@FRAGMENT@@" not in js  # the literal token never appears in the JS


def resources_text() -> str:
    from importlib import resources

    return resources.files("mesh_viewer_static").joinpath("mesh_verify.js").read_text(encoding="utf-8")
