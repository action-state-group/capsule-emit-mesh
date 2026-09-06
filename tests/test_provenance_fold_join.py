#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-sidecar-provenance-fold-option3] Option 3b: the sidecar<->plugin
hardware-provenance join.

Proves `provenance_fold_join.join_hardware_provenance` mints a join capsule
that:

  1. Cites the PLUGIN's host-observed-provenance capsule by CPB typed digest
     reference (`type: "capsule"`, `digest_alg: "SHA-256"`,
     `citation_purpose: "cites_host_provenance"`) in its `references` array.
  2. Chains onto the SIDECAR's own ledger (`chain.parent_capsule_id ==
     sidecar capsule_id`, `chain.relation == "confirms"`) -- never the
     plugin's.
  3. Commits `references` to its own `capsule_id`: tampering the cited
     digest post-seal flips `verify()` to fail.
  4. Carries the vantage-honesty caveat naming the hardware fact as the
     PLUGIN's own observation, never the sidecar's (2026-08-28 FDE ruling).
  5. Refuses to mint when: either half fails its own `verify()`; either
     half's `role` is not `"served"`; the two halves do not share one
     `agent_input_digest`; the joiner is not the node the sidecar half
     itself names as `served_by_node_id`.

Also proves the §6-#2 three-state honesty helpers
(`hardware_provenance_status`, `find_host_provenance_capsule`): absence is
recorded honestly, never as a fabricated `"present"`.

CORRELATOR: `agent_input_digest`, NOT `exchange_id` -- verified against a
REAL `mesh-llm serve --gguf` host (0.76.0-rc6) plus a real admission-policy
plugin binary plus a real `capsule_sidecar.py` process fronting it: the
host's own `exchange_id` (a UUID it mints for its `openai.exchange.v1`
channel) and the sidecar's response-`id`-derived `exchange_id` are
INDEPENDENT values for the same real exchange (contradicting both
producers' existing doc comments) -- while `agent_input_digest` (the
canonical JSON digest of the real request body) was confirmed byte-identical
on both sides. See `provenance_fold_join.py`'s module docstring for the full
real-host transcript this correction is based on.

The plugin half is a hand-built fixture matching the REAL captured JSON
shape from that same real-host run: `model_attestation.compute_attestation.
{agent_input_digest,x-mesh-poc-v1.{role,serving_provenance.{hardware,
model}}}` -- `hardware`/`model` are NESTED sub-objects on the wire (not the
flat `hardware_gpu`/`architecture` names the Rust struct's field-literal
suggests at its construction call site).
"""
from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

import capsule_sidecar as cs
import provenance_fold_join as pfj

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _real_modules():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    importlib.reload(pfj)
    return cs, pfj


def _sidecar_state(tmp_path: Path, *, node_id: str) -> "cs.NodeState":
    cs_mod, _ = _real_modules()
    manifest_path = tmp_path / f"manifest-{node_id}.json"
    manifest_path.write_text(json.dumps({"model_id": "local-gguf/sha256-test", "source_model": {"sha256": "a" * 64}}))
    return cs_mod.default_state(
        ledger_dir=tmp_path / f"ledger-{node_id}",
        manifest_path=manifest_path,
        keys_dir=tmp_path / f"keys-{node_id}",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=cs_mod.ROLE_PROVIDER,
        node_id=node_id,
    )


def _sidecar_capsule(
    tmp_path: Path,
    *,
    node_id: str = "gpu-node-1",
    request_digest: str = "77c0e133dc7b0a84c6231171efe2d190998b550275dc528ff1a605e40feef4db",
) -> dict:
    """A real, `verify()`-clean sidecar-sealed capsule for a served exchange
    -- role="served" (CPB #70 vocabulary), real I/O digests, no hardware."""
    cs_mod, _ = _real_modules()
    state = _sidecar_state(tmp_path, node_id=node_id)
    response = {
        "id": "chatcmpl-1788674530936",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Banana"}, "finish_reason": "stop"}],
    }
    exchange_id, source = cs_mod.exchange_id_from_response(response)
    return cs_mod.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="client_supplied",
        request_json={"model": "local-gguf/sha256-test", "messages": [{"role": "user", "content": "Say the word: banana"}]},
        request_digest=request_digest,
        status="confirmed",
        response_digest=cs_mod.digest_json(response),
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=124.45,
        exchange_id=exchange_id,
        exchange_id_source=source,
    )


def _plugin_capsule(
    *,
    node_id: str = "gpu-node-1",
    request_digest: str = "77c0e133dc7b0a84c6231171efe2d190998b550275dc528ff1a605e40feef4db",
    real_hardware: bool = True,
) -> dict:
    """A hand-built, `verify()`-clean fixture matching the REAL JSON shape
    `capsule_emit::emit_for_observed_host_exchange` (Rust) produces for a
    real host-served exchange, confirmed against a live `mesh-llm serve
    --gguf` run -- real hardware/model nested under `hardware`/`model`
    sub-objects, `agent_input_digest` at the top of `compute_attestation`,
    `role == "served"` (top-level sibling of `serving_provenance`)."""
    from agent_action_capsule.contracts import Disposition, EffectRecord
    from agent_action_capsule.emit import emit

    serving_provenance = {
        "served_by_node_id": node_id,
        "dispatch_path": "raw_proxy",
        "requesting_party": "unknown",
        "exchange_id": "5b9a2b06-f929-4fe7-b272-649681ac9263",  # host-minted UUID -- deliberately NOT the correlator
        "hostname": "mesh-node-gcp-1",
        "quantization": "unknown",
        "model": {
            "architecture": "llama" if real_hardware else None,
            "context_length": 131072 if real_hardware else None,
            "parameter_size": "3B" if real_hardware else None,
            "layer_count": 28 if real_hardware else None,
            "identity_hash": ("h" * 16) if real_hardware else None,
            "weights_digest": ("d" * 64) if real_hardware else None,
            "canonical_ref": "local-gguf/sha256-test",
            "revision": None,
        } if real_hardware else {},
        "hardware": {
            "gpu": "NVIDIA L4",
            "vram_bytes": 23688380416,
            "device": None,
            "is_soc": False,
        } if real_hardware else {},
        "usage": {"prompt_tokens": 40, "completion_tokens": 2, "total_tokens": 42},
        "seq": 1,
        "prev_seq": None,
    }
    compute_attestation = {
        "agent_input_digest": request_digest,
        "agent_output_digest": "b" * 64,
        "host_binding": {
            "digest": request_digest,
            "construction": "mesh-llm/request-body-sha256/v1",
            "purpose": "host-log-join",
        },
        "runtime": f"{'0' * 64}:observer/admission-policy-plugin",
        "x-mesh-poc-v1": {
            "client_nonce": "host-served-no-nonce",
            "client_nonce_source": "host_served_observed",
            "model_name_digest": "c" * 64,
            "serving_provenance": serving_provenance,
            "role": "served",
            "observation_point": None,
            "generation_parameters": {},
            "latency_ms": "0.000",
        },
    }
    effect = EffectRecord(
        status="confirmed",
        type="inference_completion",
        request_digest=request_digest,
        response_digest="b" * 64,
        effect_attestation="host_served_observed",
    )
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="executed")
    return emit(
        action_type="decide",
        operator="capsule-emit-mesh-poc-rust",
        developer="capsule-producer/0.2.0",
        model_id="local-gguf/sha256-test",
        provider="mesh-llm",
        compute_attestation=compute_attestation,
        effect=effect,
        disposition=disposition,
        domain="action",
        provenance="collector",
        tool_name="capsule-producer",
    )


def _write_plugin_ledger(ledger_dir: Path, capsules: list[dict]) -> None:
    ledger_dir.mkdir(parents=True, exist_ok=True)
    with (ledger_dir / "capsules.jsonl").open("w", encoding="utf-8") as fh:
        for capsule in capsules:
            fh.write(json.dumps(capsule, sort_keys=True, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# 1. the join itself
# ---------------------------------------------------------------------------


def test_join_verifies_offline(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(joined)
    assert result.ok, result.findings


def test_join_references_entry_cites_plugin_with_cites_host_provenance(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    assert joined["references"] == [
        {
            "type": "capsule",
            "digest_alg": "SHA-256",
            "digest": plugin_capsule["capsule_id"],
            "citation_purpose": "cites_host_provenance",
        }
    ]


def test_join_chains_onto_sidecars_own_half_not_the_plugins(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    assert joined["chain"]["parent_capsule_id"] == sidecar_capsule["capsule_id"]
    assert joined["chain"]["relation"] == "confirms"
    assert joined["references"][0]["digest"] != joined["chain"]["parent_capsule_id"]


def test_join_carries_the_shared_agent_input_digest_self_contained(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    digest = "9" * 64
    sidecar_capsule = _sidecar_capsule(tmp_path, request_digest=digest)
    plugin_capsule = _plugin_capsule(request_digest=digest)
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    compute_attestation = joined["model_attestation"]["compute_attestation"]
    assert compute_attestation["hardware_provenance_fold"]["agent_input_digest"] == digest


def test_join_never_uses_exchange_id_as_the_correlator(tmp_path: Path) -> None:
    """Regression pin for the real-host finding: the two halves' own
    `exchange_id` values are DIFFERENT (a host-minted UUID vs. the sidecar's
    response-id-derived string) for the SAME real exchange, yet the join
    still succeeds because it correlates on `agent_input_digest`."""
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    sidecar_xid = sidecar_capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"][
        "exchange_id"
    ]
    plugin_xid = plugin_capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"][
        "exchange_id"
    ]
    assert sidecar_xid != plugin_xid, "fixture must reproduce the real-host mismatch, not assume equality"

    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")
    from agent_action_capsule.verify import verify as verify_capsule

    assert verify_capsule(joined).ok


def test_join_carries_the_vantage_honesty_caveat(tmp_path: Path) -> None:
    """[FDE ruling 2026-08-28] The join must never present the cited hardware
    as the sidecar's own observation -- the caveat says so, in the sealed
    bytes, not just in code comments."""
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    block = joined["model_attestation"]["compute_attestation"]["hardware_provenance_fold"]
    assert block["asserted_by_node_id"] == "gpu-node-1"
    assert block["vantage_caveat"] == pfj_mod.HARDWARE_PROVENANCE_VANTAGE_CAVEAT
    assert "never by the joiner" in block["vantage_caveat"]


# ---------------------------------------------------------------------------
# 2. capsule_id commits references -- the join is a real signed claim
# ---------------------------------------------------------------------------


def test_tampered_reference_digest_fails_verify(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    tampered = copy.deepcopy(joined)
    tampered["references"][0]["digest"] = "f" * 64

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(tampered)
    assert not result.ok
    assert any(f.code == "capsule_id_mismatch" for f in result.findings)


def test_stripping_references_fails_verify(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    plugin_capsule = _plugin_capsule()
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    tampered = copy.deepcopy(joined)
    del tampered["references"]

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(tampered)
    assert not result.ok
    assert any(f.code == "capsule_id_mismatch" for f in result.findings)


# ---------------------------------------------------------------------------
# 3. refusals -- never silently join what shouldn't be joined
# ---------------------------------------------------------------------------


def test_refuses_when_io_digests_differ(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path, request_digest="1" * 64)
    plugin_capsule = _plugin_capsule(request_digest="2" * 64)

    with pytest.raises(pfj_mod.IoDigestMismatchError):
        pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")


def test_refuses_when_sidecar_role_is_not_served(tmp_path: Path) -> None:
    """A REQUESTER-role sidecar capsule (this node was the client, not the
    server) must never be folded with hardware as if this node served it."""
    cs_mod, pfj_mod = _real_modules()
    (tmp_path / "manifest-req.json").write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    state = cs_mod.default_state(
        ledger_dir=tmp_path / "ledger-req",
        manifest_path=(tmp_path / "manifest-req.json"),
        keys_dir=tmp_path / "keys-req",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=cs_mod.ROLE_REQUESTER,
        node_id="req-1",
    )
    response = {"id": "chatcmpl-req-half", "object": "chat.completion", "choices": []}
    exchange_id, source = cs_mod.exchange_id_from_response(response)
    requester_capsule = cs_mod.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="client_supplied",
        request_json={"model": "test-model", "messages": []},
        request_digest="a" * 64,
        status="confirmed",
        response_digest=cs_mod.digest_json(response),
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
        exchange_id=exchange_id,
        exchange_id_source=source,
    )
    plugin_capsule = _plugin_capsule(request_digest="a" * 64)

    with pytest.raises(pfj_mod.RoleNotServedError):
        pfj_mod.join_hardware_provenance(requester_capsule, plugin_capsule, joiner_node_id="req-1")


def test_refuses_an_unverifiable_plugin_half(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path)
    forged = copy.deepcopy(_plugin_capsule())
    forged["capsule_id"] = "c" * 64

    with pytest.raises(pfj_mod.UnverifiableHalfError):
        pfj_mod.join_hardware_provenance(sidecar_capsule, forged, joiner_node_id="gpu-node-1")


def test_refuses_an_unverifiable_sidecar_half(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    forged = copy.deepcopy(_sidecar_capsule(tmp_path))
    forged["capsule_id"] = "c" * 64
    plugin_capsule = _plugin_capsule()

    with pytest.raises(pfj_mod.UnverifiableHalfError):
        pfj_mod.join_hardware_provenance(forged, plugin_capsule, joiner_node_id="gpu-node-1")


def test_refuses_when_joiner_is_not_the_serving_node(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    sidecar_capsule = _sidecar_capsule(tmp_path, node_id="gpu-node-1")
    plugin_capsule = _plugin_capsule(node_id="gpu-node-1")

    with pytest.raises(pfj_mod.JoinerNotServingNodeError):
        pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="mallory-node")


# ---------------------------------------------------------------------------
# 4. sign_hardware_provenance_join / verify_hardware_provenance_join_signature
# ---------------------------------------------------------------------------


def test_sign_and_verify_join_signature_roundtrip(tmp_path: Path) -> None:
    cs_mod, pfj_mod = _real_modules()
    state = _sidecar_state(tmp_path, node_id="gpu-node-1")
    sidecar_capsule = _sidecar_capsule(tmp_path, node_id="gpu-node-1")
    plugin_capsule = _plugin_capsule(node_id="gpu-node-1")
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    signed_statement = pfj_mod.sign_hardware_provenance_join(
        joined, signing_key_pem=state.signing_key_pem, signing_node_id="gpu-node-1"
    )
    pubkey_pem = (state.signing_key_path.parent / "node-key.pub.pem").read_bytes()
    valid, reason = pfj_mod.verify_hardware_provenance_join_signature(
        joined, signed_statement, public_key_pem=pubkey_pem
    )
    assert valid, reason


def test_sign_rejects_wrong_signing_node_id(tmp_path: Path) -> None:
    cs_mod, pfj_mod = _real_modules()
    state = _sidecar_state(tmp_path, node_id="gpu-node-1")
    sidecar_capsule = _sidecar_capsule(tmp_path, node_id="gpu-node-1")
    plugin_capsule = _plugin_capsule(node_id="gpu-node-1")
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    with pytest.raises(pfj_mod.SignerMismatchError):
        pfj_mod.sign_hardware_provenance_join(
            joined, signing_key_pem=state.signing_key_pem, signing_node_id="mallory-node"
        )


def test_verify_rejects_wrong_public_key(tmp_path: Path) -> None:
    cs_mod, pfj_mod = _real_modules()
    state = _sidecar_state(tmp_path, node_id="gpu-node-1")
    other_state = _sidecar_state(tmp_path, node_id="other-node")
    sidecar_capsule = _sidecar_capsule(tmp_path, node_id="gpu-node-1")
    plugin_capsule = _plugin_capsule(node_id="gpu-node-1")
    joined = pfj_mod.join_hardware_provenance(sidecar_capsule, plugin_capsule, joiner_node_id="gpu-node-1")

    signed_statement = pfj_mod.sign_hardware_provenance_join(
        joined, signing_key_pem=state.signing_key_pem, signing_node_id="gpu-node-1"
    )
    wrong_pubkey_pem = (other_state.signing_key_path.parent / "node-key.pub.pem").read_bytes()
    valid, reason = pfj_mod.verify_hardware_provenance_join_signature(
        joined, signed_statement, public_key_pem=wrong_pubkey_pem
    )
    assert not valid, reason


# ---------------------------------------------------------------------------
# 5. hardware_provenance_status -- three-state honesty, never null-as-present
# ---------------------------------------------------------------------------


def test_hardware_provenance_status_present_for_a_real_hardware_capsule() -> None:
    _, pfj_mod = _real_modules()
    assert pfj_mod.hardware_provenance_status(_plugin_capsule(real_hardware=True)) == "present"


def test_hardware_provenance_status_absent_when_no_capsule_was_found() -> None:
    """The §6-#2 lag case: no matching plugin capsule (yet) -> honest
    `"absent"`, never a fabricated `"present"`."""
    _, pfj_mod = _real_modules()
    assert pfj_mod.hardware_provenance_status(None) == "absent"


def test_hardware_provenance_status_absent_when_capsule_has_no_hardware_facts() -> None:
    _, pfj_mod = _real_modules()
    assert pfj_mod.hardware_provenance_status(_plugin_capsule(real_hardware=False)) == "absent"


# ---------------------------------------------------------------------------
# 6. find_host_provenance_capsule -- honest absence, never a fabricated match
# ---------------------------------------------------------------------------


def test_find_host_provenance_capsule_finds_the_matching_exchange(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    ledger_dir = tmp_path / "plugin-ledger"
    target = _plugin_capsule(request_digest="3" * 64)
    other = _plugin_capsule(request_digest="4" * 64)
    _write_plugin_ledger(ledger_dir, [other, target])

    found = pfj_mod.find_host_provenance_capsule(ledger_dir, "3" * 64)
    assert found is not None
    assert found["capsule_id"] == target["capsule_id"]


def test_find_host_provenance_capsule_returns_none_when_no_match(tmp_path: Path) -> None:
    _, pfj_mod = _real_modules()
    ledger_dir = tmp_path / "plugin-ledger"
    _write_plugin_ledger(ledger_dir, [_plugin_capsule(request_digest="5" * 64)])

    assert pfj_mod.find_host_provenance_capsule(ledger_dir, "6" * 64) is None


def test_find_host_provenance_capsule_returns_none_when_ledger_does_not_exist_yet(tmp_path: Path) -> None:
    """§6-#2: immediately after a host restart the plugin's ledger may not
    even exist yet -- honest `None`, never a crash or a fabricated match."""
    _, pfj_mod = _real_modules()
    assert pfj_mod.find_host_provenance_capsule(tmp_path / "never-created", "7" * 64) is None


def test_find_host_provenance_capsule_resolves_duplicate_request_digest_to_newest(tmp_path: Path) -> None:
    """DISCLOSED LIMITATION: two byte-identical requests to the same model
    digest to the same `agent_input_digest` (reproduced directly against a
    real host -- see module docstring). The lookup does not silently pick an
    arbitrary one; it deterministically resolves to the most recently sealed
    match, newest-first."""
    _, pfj_mod = _real_modules()
    ledger_dir = tmp_path / "plugin-ledger"
    same_digest = "8" * 64
    first = _plugin_capsule(request_digest=same_digest, node_id="gpu-node-1")
    second = _plugin_capsule(request_digest=same_digest, node_id="gpu-node-1")
    assert first["capsule_id"] != second["capsule_id"]  # distinct seals (different timestamps), same digest
    _write_plugin_ledger(ledger_dir, [first, second])

    found = pfj_mod.find_host_provenance_capsule(ledger_dir, same_digest)
    assert found["capsule_id"] == second["capsule_id"]
