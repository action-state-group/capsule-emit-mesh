import hashlib
import json
import os
import pathlib
import sys
import tempfile
import types

# Stub heavy deps so the pure-function tests run without a full install.
# setdefault never overwrites a real module that is already imported -- and,
# critically, the attribute stubs below are applied ONLY to names we actually
# created here. When agent-action-capsule IS installed the real module stays
# untouched; clobbering the real `.verify`/`.emit` on `sys.modules` leaked a
# `verify -> None` stub into every test that ran afterwards in the same process
# (it broke the coordinator-receipt suite's honest cases). `_stubbed` gates the
# clobber to the not-installed path only.
_stubbed: set[str] = set()
for _name in [
    "scitt_cose",
    "agent_action_capsule",
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]:
    if _name not in sys.modules:
        sys.modules[_name] = types.ModuleType(_name)
        _stubbed.add(_name)
if "agent_action_capsule.canonical" in _stubbed:
    sys.modules["agent_action_capsule.canonical"].json_digest = lambda v: hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
if "agent_action_capsule.contracts" in _stubbed:
    for _n in ["Disposition", "EffectRecord"]:
        setattr(sys.modules["agent_action_capsule.contracts"], _n, object)
if "agent_action_capsule.emit" in _stubbed:
    sys.modules["agent_action_capsule.emit"].emit = lambda **k: {}
if "agent_action_capsule.verify" in _stubbed:
    sys.modules["agent_action_capsule.verify"].verify = lambda *a, **k: None
if "model_identity" in _stubbed:
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


def test_record_capsule_survives_plugin_checkpoint_failure(monkeypatch):
    """[bounce 2026-08-28] The plugin-ledger checkpoint (`state.plugin_checkpoint`,
    read-only against a ledger a SEPARATE process -- the Rust plugin --
    concurrently writes) can fail for reasons entirely outside this node's own
    recording: a torn trailing line raced mid-write, or any other transient
    read hiccup capsule_emit's own MMR indexing raises on. That must never
    fail the exchange this sidecar is otherwise done recording -- the same
    'checkpointing is never on the serving path' promise checkpointing.py's
    own module docstring already makes for an unreachable witness applies
    here too. Nothing on the safety side is at risk either way: this node's
    OWN capsule and .cose statement are written before the plugin-checkpoint
    call runs, and capsules.jsonl (whichever process owns it) is never
    written to as a result of a failed read here.

    Mutant: remove the try/except around
    `state.plugin_checkpoint.record_appended()` in record_capsule and this
    goes red (the simulated failure below propagates and the assertions
    below it never run)."""
    state = _make_node_state()
    monkeypatch.setattr(cs, "verify_capsule", lambda capsule: types.SimpleNamespace(ok=True, findings=[]))

    class _ExplodingPluginCheckpoint:
        def record_appended(self):
            raise ValueError("simulated: torn trailing line from a concurrent plugin writer")

    state.plugin_checkpoint = _ExplodingPluginCheckpoint()

    capsule = {"capsule_id": "aa" * 32}
    cs.record_capsule(state, capsule, b"fake-signed-statement")

    assert state.last_capsule_id == capsule["capsule_id"]
    assert capsule in state.emitted
    assert (state.statements_dir / f"{capsule['capsule_id']}.cose").read_bytes() == b"fake-signed-statement"


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


# ---------------------------------------------------------------------------
# Generation-parameter capture (the CLIENT's requested sampling settings).
# The allowlist must cover the same knob set as the Rust plugin, and only
# params actually present in the request may be sealed (absent stays absent).
# ---------------------------------------------------------------------------

# The param set both capture paths (this sidecar + the Rust plugin) must agree on.
_EXPECTED_GENERATION_PARAM_KEYS = {
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "seed",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "repeat_penalty",
    "stop",
}


def test_generation_param_allowlist_covers_the_full_knob_set():
    """The allowlist must include top_k, min_p, and repeat_penalty (the bug this
    fix closes) alongside the previously-covered knobs -- no more, no less."""
    assert set(cs.GENERATION_PARAM_KEYS) == _EXPECTED_GENERATION_PARAM_KEYS
    for newly_added in ("top_k", "min_p", "repeat_penalty"):
        assert newly_added in cs.GENERATION_PARAM_KEYS


def _capture_generation_parameters(monkeypatch, request_json):
    """Run the REAL build_capsule and capture the generation_parameters it
    actually seals, by intercepting the compute_attestation handed to emit()."""
    captured = {}

    def fake_emit(**kwargs):
        captured["compute_attestation"] = kwargs["compute_attestation"]
        return {"capsule_id": "0" * 64}

    # EffectRecord / Disposition are stubbed as bare `object` at module import
    # (they take no kwargs); build_capsule constructs both before calling emit,
    # so give them a lenient kwargs-accepting stand-in for this end-to-end path.
    monkeypatch.setattr(cs, "emit", fake_emit)
    monkeypatch.setattr(cs, "EffectRecord", lambda **k: object())
    monkeypatch.setattr(cs, "Disposition", lambda **k: object())
    state = _make_node_state()
    state.manifest = {"model_id": "m"}
    state.model_package_digest = "d" * 64
    cs.build_capsule(
        state,
        client_nonce="n",
        client_nonce_source="client_supplied",
        request_json=request_json,
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.5,
    )
    return captured["compute_attestation"]["x-mesh-poc-v1"]["generation_parameters"]


def test_build_capsule_seals_all_present_sampling_knobs(monkeypatch):
    """A request carrying top_k, repeat_penalty, min_p, seed, temperature seals
    ALL of them. Floats are stringified (repr) for the §5.1 digest ban; ints
    (top_k, seed) stay as JSON numbers -- matching the Rust plugin's
    stringify_floats convention so both paths seal the same shape."""
    gp = _capture_generation_parameters(
        monkeypatch,
        {
            "model": "m",
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "min_p": 0.05,
            "seed": 12345,
            "repeat_penalty": 1.1,
            "max_tokens": 512,
            "stop": ["\n\n"],
        },
    )
    assert gp["temperature"] == repr(0.7)
    assert gp["min_p"] == repr(0.05)
    assert gp["repeat_penalty"] == repr(1.1)
    assert gp["top_k"] == 40  # int stays a JSON number
    assert gp["seed"] == 12345
    assert gp["max_tokens"] == 512
    assert gp["stop"] == ["\n\n"]
    # NOT the old fabricated Rust default.
    assert gp["temperature"] != "0.0"


def test_build_capsule_absent_stays_absent(monkeypatch):
    """A request that sent ONLY temperature seals exactly temperature -- no other
    knob is defaulted into the capsule. Absent is recorded as absent."""
    gp = _capture_generation_parameters(monkeypatch, {"model": "m", "temperature": 0.7})
    assert set(gp) == {"temperature"}
    for absent in _EXPECTED_GENERATION_PARAM_KEYS - {"temperature"}:
        assert absent not in gp, f"{absent} was not requested and must not be sealed"


def test_build_capsule_treats_null_param_as_absent(monkeypatch):
    """A JSON null value is treated as absent, not sealed -- matching the
    `is not None` guard in the allowlist comprehension."""
    gp = _capture_generation_parameters(
        monkeypatch, {"model": "m", "temperature": 0.5, "top_p": None}
    )
    assert "temperature" in gp
    assert "top_p" not in gp
