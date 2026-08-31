# SPDX-License-Identifier: Apache-2.0
"""Cross-implementation digest-parity pin: mesh-llm's Rust `request_body_digest`
== capsule-emit's canonical JSON-DIGEST for the same request body.

mesh-llm's host runtime (`mesh-llm-host-runtime`, `openai_exchange.rs`) computes
a `request_body_digest` over an effective OpenAI chat body and forwards it as the
value a downstream capsule binds its `agent_input_digest` to. That Rust digest is
`HEX(SHA-256(JCS(normalize(stringify_floats(body)))))`, and its test suite pins it
to a frozen constant against the shared Python reference
(`capsule_sidecar.digest_json` / `agent_action_capsule.canonical.json_digest`).

This equality was asserted once but PREDATES capsule-emit #107 (signer-independent
capsule_id) and the `jcs` / format-4 canonicalization regeneration in
agent_action_capsule, so it could have silently drifted. This test re-pins it on
the CURRENTLY INSTALLED capsule-emit / agent_action_capsule so a future
canonicalization change to either side cannot break the mesh-llm contract without
turning this test red.

If mesh-llm ever revises the frozen constant, update `MESH_LLM_FROZEN_DIGEST` here
in the same change and re-run — a divergence between the two is exactly the drift
this test exists to surface.

Source of the frozen constant (byte-for-byte):
  mesh-serving-provenance/crates/mesh-llm-host-runtime/src/plugin/openai_exchange.rs
  test `request_body_digest_matches_plugin_and_python_reference`.
"""
from __future__ import annotations

import hashlib

from agent_action_capsule.canonical import json_digest

import capsule_sidecar

# The exact request body mesh-llm's Rust test digests. `top_p: 1.0` is the
# whole-number-float edge case (stringify must emit "1.0", not "1"); the
# remaining floats and the message array exercise ordering + float handling.
MESH_LLM_REQUEST_BODY = {
    "model": "hermes-2-pro-mistral-7b",
    "messages": [{"role": "user", "content": "hello"}],
    "temperature": 0.7,
    "top_p": 1.0,
    "max_tokens": 512,
}

# The frozen digest mesh-llm's Rust test pins (`expected`), which its suite also
# asserts equals the plugin's `canonical_body_digest` and the Python reference.
MESH_LLM_FROZEN_DIGEST = (
    "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5"
)


def _stringify_floats(value):
    """Mirror mesh-llm's `stringify_floats` (and the sidecar's `_stringify_floats`):
    every JSON float becomes its exact decimal-string form so the canonical
    JSON-DIGEST never sees a float (§5.1 forbids floats in a digest-bearing
    value). `top_p: 1.0` -> "1.0"."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        s = repr(value)
        if ("." not in s) and ("e" not in s) and ("E" not in s):
            s = s + ".0"
        return s
    if isinstance(value, dict):
        return {k: _stringify_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_floats(v) for v in value]
    return value


def test_capsule_emit_canonical_digest_matches_mesh_llm_frozen_constant():
    """capsule-emit's canonical JSON-DIGEST (agent_action_capsule.canonical) for
    mesh-llm's request body is byte-for-byte the constant mesh-llm's Rust suite
    pins. Floats are pre-stringified (both sides do this) so the value reaching
    JCS is float-free."""
    canonical_input = _stringify_floats(MESH_LLM_REQUEST_BODY)
    digest = json_digest(canonical_input)
    assert digest == MESH_LLM_FROZEN_DIGEST, (
        "capsule-emit canonical JSON-DIGEST diverged from mesh-llm's frozen "
        f"request_body_digest: got {digest}, mesh-llm pins {MESH_LLM_FROZEN_DIGEST}. "
        "A canonicalization change on either side broke the cross-impl contract "
        "that lets the host forward agent_input_digest for a verifier to recompute."
    )


def test_sidecar_digest_json_matches_mesh_llm_frozen_constant():
    """This repo's own sidecar surface (`capsule_sidecar.digest_json`, the mesh
    Python reference mesh-llm's Rust test cites) agrees with the same frozen
    constant — closing the three-way loop: Rust host <-> Python sidecar <->
    capsule-emit canonical."""
    digest = capsule_sidecar.digest_json(MESH_LLM_REQUEST_BODY)
    assert digest == MESH_LLM_FROZEN_DIGEST, (
        f"sidecar digest_json diverged from mesh-llm's frozen constant: got "
        f"{digest}, mesh-llm pins {MESH_LLM_FROZEN_DIGEST}."
    )


def test_sidecar_and_capsule_emit_agree():
    """The sidecar's digest and capsule-emit's canonical digest are the same
    function of the same input — no accidental second canonicalization."""
    assert capsule_sidecar.digest_json(
        MESH_LLM_REQUEST_BODY
    ) == json_digest(_stringify_floats(MESH_LLM_REQUEST_BODY))


def test_frozen_digest_is_a_real_sha256_of_the_canonical_bytes():
    """Guard the constant itself: it must be lowercase-hex SHA-256 of the JCS
    canonical bytes, so a typo in MESH_LLM_FROZEN_DIGEST can't pass by matching a
    correspondingly-typo'd computation."""
    from agent_action_capsule.canonical import jcs

    canonical_bytes = jcs(_stringify_floats(MESH_LLM_REQUEST_BODY))
    assert (
        hashlib.sha256(canonical_bytes).hexdigest() == MESH_LLM_FROZEN_DIGEST
    )
    # The canonical bytes are RFC 8785 JCS: sorted keys, floats stringified.
    assert canonical_bytes == (
        b'{"max_tokens":512,"messages":[{"content":"hello","role":"user"}],'
        b'"model":"hermes-2-pro-mistral-7b","temperature":"0.7","top_p":"1.0"}'
    )
