import hashlib
import json
import os
import pathlib
import sys
import tempfile
import types

# Stub heavy deps so the pure-function tests run without a full install.
# setdefault never overwrites a real module that is already imported.
for _name in [
    "scitt_cose",
    "agent_action_capsule",
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]:
    sys.modules.setdefault(_name, types.ModuleType(_name))
sys.modules["agent_action_capsule.canonical"].json_digest = lambda v: hashlib.sha256(
    json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
for _n in ["Disposition", "EffectRecord"]:
    setattr(sys.modules["agent_action_capsule.contracts"], _n, object)
sys.modules["agent_action_capsule.emit"].emit = lambda **k: {}
sys.modules["agent_action_capsule.verify"].verify = lambda *a, **k: None
sys.modules["model_identity"].load_manifest = lambda p: {}
sys.modules["model_identity"].model_package_digest = lambda m: ""
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import capsule_sidecar as cs  # noqa: E402  (after sys.path setup)


def test_build_forwarded_copy_sidecar_minted_ids():
    """Sidecar-minted path (--local-model-only): content+tool_calls quirk + missing id."""
    RAW = {
        "id": "x",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "<turn-budget>3</turn-budget>",
                    "tool_calls": [{"type": "function", "function": {"name": "get_node_status", "arguments": "{}"}}],
                },
            }
        ],
    }
    raw_digest = cs.digest_json(RAW)
    fwd, tr, upstream_ids = cs.build_forwarded_copy(RAW)

    assert RAW["choices"][0]["message"]["content"] == "<turn-budget>3</turn-budget>", "RAW mutated!"
    assert "id" not in RAW["choices"][0]["message"]["tool_calls"][0], "RAW tool_call mutated!"
    assert cs.digest_json(RAW) == raw_digest, "raw digest drifted"
    assert fwd["choices"][0]["message"]["content"] is None
    assert fwd["choices"][0]["message"]["tool_calls"][0]["id"].startswith("call_")
    assert tr == ["content_dropped_with_tool_calls", "tool_call_id_minted"], tr
    assert upstream_ids == [], upstream_ids

    rec = cs.forwarded_copy_record(fwd, tr, upstream_ids)
    assert rec["digest"] != raw_digest and len(rec["digest"]) == 64
    assert rec["upstream_tool_call_ids"] == [], rec


def test_build_forwarded_copy_unchanged():
    """Text-only response: no transforms, digest stable."""
    CLEAN = {
        "id": "y",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hello"}}],
    }
    f2, t2, u2 = cs.build_forwarded_copy(CLEAN)
    r2 = cs.forwarded_copy_record(f2, t2, u2)
    assert t2 == [] and r2["digest"] == cs.digest_json(CLEAN)
    assert u2 == [] and r2["upstream_tool_call_ids"] == []


def test_build_forwarded_copy_normalizer_minted_ids():
    """Normalizer-minted path (supported port): IDs already present; pass through unchanged.

    The normalizer mints IDs like call_mesh_{timestamp_ms}_{index}; the sidecar must NOT
    replace them and must record them in upstream_tool_call_ids. forwarded_copy.digest must
    equal response_digest (no content changes applied).
    """
    NORMALIZER = {
        "id": "z",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_mesh_1786911567963_0",
                            "type": "function",
                            "function": {"name": "get_node_status", "arguments": "{}"},
                        }
                    ],
                },
            }
        ],
    }
    norm_raw_digest = cs.digest_json(NORMALIZER)
    fn, tn, un = cs.build_forwarded_copy(NORMALIZER)

    assert tn == [], tn
    assert un == ["call_mesh_1786911567963_0"], un

    rn = cs.forwarded_copy_record(fn, tn, un)
    assert rn["digest"] == norm_raw_digest, "digest must match raw when no transform applied"
    assert rn["upstream_tool_call_ids"] == ["call_mesh_1786911567963_0"]


def test_synthesize_sse_carries_minted_id():
    """synthesize_sse passes the id through and terminates with [DONE]."""
    RAW = {
        "id": "x",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "<turn-budget>3</turn-budget>",
                    "tool_calls": [{"type": "function", "function": {"name": "get_node_status", "arguments": "{}"}}],
                },
            }
        ],
    }
    fwd, _, _ = cs.build_forwarded_copy(RAW)
    sse = b"".join(cs.synthesize_sse(fwd))
    assert b'"id": "call_' in sse and b"[DONE]" in sse


def test_load_or_create_signing_key():
    """Key is generated 0600 and stable on repeated calls."""
    d = pathlib.Path(tempfile.mkdtemp()) / "keys"
    pem = cs.load_or_create_signing_key(d)
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert oct(os.stat(d / "node-key.pem").st_mode)[-3:] == "600"
    assert cs.load_or_create_signing_key(d) == pem, "second call must reuse"


def _make_node_state():
    """Minimal NodeState for _resolve_client_nonce tests -- no real signing key
    or manifest needed since these tests never sign or emit a capsule."""
    d = pathlib.Path(tempfile.mkdtemp())
    return cs.NodeState(
        node_id="test-node",
        operator="test-operator",
        developer="test-developer",
        signing_key_pem=b"unused-in-these-tests",
        signing_key_path=d / "keys" / "node-key.pem",  # unused: no checkpoint_config_path given
        manifest_path=d / "manifest.json",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        ledger_dir=d / "ledger",
    )


def test_plugin_ledger_dir_wires_a_second_read_only_checkpoint_state():
    """[mesh-plugin-cll-consume] A3: --plugin-ledger-dir gives NodeState a
    SECOND, independent CheckpointState over a ledger this process never
    wrote -- simulating the Rust plugin's own capsules.jsonl (two
    single-writer logs, one machine view; §4 A2/A3). Reconnecting it must
    checkpoint the pre-existing entries without ever mutating that file, and
    must not collide the plugin log's wire log_id with the sidecar's own
    (both derived from the SAME shared [checkpoint] config here -- the
    fallback path capsule_sidecar.py takes when --plugin-checkpoint-config
    is omitted)."""
    d = pathlib.Path(tempfile.mkdtemp())

    # A ledger this test process never appends to via JsonlLogSource -- the
    # stand-in for "the Rust plugin wrote this, not us".
    plugin_ledger_dir = d / "plugin-ledger"
    plugin_ledger_dir.mkdir(parents=True)
    plugin_capsules_path = plugin_ledger_dir / "capsules.jsonl"
    plugin_capsules_path.write_text(
        "\n".join(json.dumps({"capsule_id": f"{i:064x}", "n": i}, sort_keys=True) for i in range(3)) + "\n"
    )
    before = plugin_capsules_path.read_bytes()

    checkpoint_config_path = d / "checkpoint.toml"
    checkpoint_config_path.write_text(
        "[checkpoint]\n"
        'log_id = "shared-config-log-id"\n'
        "cadence_entries = 100\n"
        "max_lag_entries = 200\n"
    )

    state = cs.NodeState(
        node_id="test-node",
        operator="test-operator",
        developer="test-developer",
        signing_key_pem=b"unused-in-these-tests",
        signing_key_path=d / "keys" / "node-key.pem",
        manifest_path=d / "manifest.json",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        ledger_dir=d / "ledger",
        plugin_ledger_dir=plugin_ledger_dir,
        # No plugin_checkpoint_config_path: falls back to the shared file above.
        checkpoint_config_path=checkpoint_config_path,
    )

    assert state.checkpoint is not None
    assert state.plugin_checkpoint is not None
    # The shared config's log_id must NEVER be reused verbatim for the
    # plugin's independently-checkpointed log.
    assert state.checkpoint.log_id == "shared-config-log-id"
    assert state.plugin_checkpoint.log_id == "test-node-plugin"
    assert state.plugin_checkpoint.log_id != state.checkpoint.log_id

    cp = state.plugin_checkpoint.reconnect()
    assert cp is not None
    assert cp.mmr_size > 0

    assert plugin_capsules_path.read_bytes() == before  # never written to
    assert (plugin_ledger_dir / "checkpoints.jsonl").exists()


def test_client_nonce_resolution_client_supplied():
    state = _make_node_state()
    nonce_val, nonce_src = cs._resolve_client_nonce(state, {cs.CLIENT_NONCE_HEADER.lower(): "abc-123"})
    assert nonce_val == "abc-123", f"nonce value not passed through: {nonce_val!r}"
    assert nonce_src == "client_supplied", f"wrong source label: {nonce_src!r}"


def test_client_nonce_resolution_fallback():
    state = _make_node_state()
    nonce_val, nonce_src = cs._resolve_client_nonce(state, {})
    assert nonce_src == "sidecar_generated_fallback", f"wrong source label: {nonce_src!r}"
    assert len(nonce_val) == 32, f"unexpected fallback nonce length: {len(nonce_val)}"  # uuid4().hex


def test_client_nonce_resolution_local_ingress():
    state = _make_node_state()
    nonce_val, nonce_src = cs._resolve_client_nonce(state, {
        cs.CLIENT_NONCE_HEADER.lower(): "abc-123",
        cs.CLIENT_NONCE_ORIGIN_HEADER: cs.CLIENT_NONCE_ORIGIN_LOCAL_INGRESS,
    })
    assert nonce_val == "abc-123", f"nonce value not passed through: {nonce_val!r}"
    assert nonce_src == "local_ingress", f"wrong source label: {nonce_src!r}"


def test_client_nonce_origin_header_ignored_without_nonce():
    # Origin marker present but no nonce header -- must still fall back, not
    # be misread as a local_ingress-labeled empty nonce.
    state = _make_node_state()
    nonce_val, nonce_src = cs._resolve_client_nonce(state, {
        cs.CLIENT_NONCE_ORIGIN_HEADER: cs.CLIENT_NONCE_ORIGIN_LOCAL_INGRESS,
    })
    assert nonce_src == "sidecar_generated_fallback", f"wrong source label: {nonce_src!r}"


def test_client_nonce_labels_distinct():
    state = _make_node_state()
    _, src_supplied = cs._resolve_client_nonce(state, {cs.CLIENT_NONCE_HEADER.lower(): "x"})
    _, src_fallback = cs._resolve_client_nonce(state, {})
    # A different nonce value than "x" -- reusing "x" here would trip replay
    # detection first (state.seen_client_nonces already has "x" from the
    # src_supplied call above) and return client_supplied_replayed instead of
    # local_ingress, masking the very label this test is checking for.
    _, src_local_ingress = cs._resolve_client_nonce(state, {
        cs.CLIENT_NONCE_HEADER.lower(): "y",
        cs.CLIENT_NONCE_ORIGIN_HEADER: cs.CLIENT_NONCE_ORIGIN_LOCAL_INGRESS,
    })
    labels = {src_supplied, src_fallback, src_local_ingress}
    assert len(labels) == 3, f"client_supplied, sidecar_generated_fallback, local_ingress must be distinct labels: {labels}"


def test_client_nonce_replay_detected_and_labeled():
    """[mesh-rung12-adversarial-review] D3 -- the SAME client-supplied nonce
    replayed on a second, unrelated call must be labeled distinctly from a
    fresh client_supplied nonce, not silently accepted as equally fresh."""
    state = _make_node_state()
    headers = {cs.CLIENT_NONCE_HEADER.lower(): "captured-nonce-REPLAY-ME"}
    nonce_1, src_1 = cs._resolve_client_nonce(state, headers)
    nonce_2, src_2 = cs._resolve_client_nonce(state, headers)
    assert nonce_1 == nonce_2 == "captured-nonce-REPLAY-ME"
    assert src_1 == "client_supplied", f"first sighting must be a fresh label: {src_1!r}"
    assert src_2 == "client_supplied_replayed", f"replay must be labeled distinctly: {src_2!r}"
    assert src_2 != src_1, "a replayed nonce must not be indistinguishable from a fresh one"


def test_client_nonce_replay_detection_is_per_node():
    """Replay detection is scoped to one NodeState (one running node) --
    stated honestly in _resolve_client_nonce's docstring, not silently
    assumed to cover independently-operated nodes."""
    headers = {cs.CLIENT_NONCE_HEADER.lower(): "same-nonce-different-nodes"}
    state_a = _make_node_state()
    state_b = _make_node_state()
    _, src_a = cs._resolve_client_nonce(state_a, headers)
    _, src_b = cs._resolve_client_nonce(state_b, headers)
    assert src_a == "client_supplied"
    assert src_b == "client_supplied", (
        "a fresh NodeState (a different node) has never seen this nonce -- "
        "must not be labeled as a replay it has no way to know about"
    )


def test_client_nonce_replay_does_not_affect_fallback_path():
    """Replay tracking must never leak into or alter the no-header fallback
    path -- only client_supplied header values are tracked."""
    state = _make_node_state()
    _, src_1 = cs._resolve_client_nonce(state, {})
    _, src_2 = cs._resolve_client_nonce(state, {})
    assert src_1 == src_2 == "sidecar_generated_fallback"
