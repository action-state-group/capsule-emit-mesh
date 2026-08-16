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


def test_client_nonce_resolution_client_supplied():
    nonce_val, nonce_src = cs._resolve_client_nonce({cs.CLIENT_NONCE_HEADER.lower(): "abc-123"})
    assert nonce_val == "abc-123", f"nonce value not passed through: {nonce_val!r}"
    assert nonce_src == "client_supplied", f"wrong source label: {nonce_src!r}"


def test_client_nonce_resolution_fallback():
    nonce_val, nonce_src = cs._resolve_client_nonce({})
    assert nonce_src == "sidecar_generated_fallback", f"wrong source label: {nonce_src!r}"
    assert len(nonce_val) == 32, f"unexpected fallback nonce length: {len(nonce_val)}"  # uuid4().hex


def test_client_nonce_labels_distinct():
    _, src_supplied = cs._resolve_client_nonce({cs.CLIENT_NONCE_HEADER.lower(): "x"})
    _, src_fallback = cs._resolve_client_nonce({})
    assert src_supplied != src_fallback, "client_supplied and sidecar_generated_fallback must be distinct labels"
