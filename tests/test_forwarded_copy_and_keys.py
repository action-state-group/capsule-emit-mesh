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

_RAW = {
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
_CLEAN = {"id": "y", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hello"}}]}


def test_forwarded_copy_streaming():
    raw_digest = cs.digest_json(_RAW)
    fwd, tr = cs.build_forwarded_copy(_RAW)

    assert _RAW["choices"][0]["message"]["content"] == "<turn-budget>3</turn-budget>", "RAW mutated!"
    assert "id" not in _RAW["choices"][0]["message"]["tool_calls"][0], "RAW tool_call mutated!"
    assert cs.digest_json(_RAW) == raw_digest, "raw digest drifted"
    assert fwd["choices"][0]["message"]["content"] is None
    assert fwd["choices"][0]["message"]["tool_calls"][0]["id"].startswith("call_")
    assert tr == ["content_dropped_with_tool_calls", "tool_call_id_minted"], tr
    rec = cs.forwarded_copy_record(fwd, tr)
    assert rec["digest"] != raw_digest and len(rec["digest"]) == 64


def test_forwarded_copy_unchanged():
    f2, t2 = cs.build_forwarded_copy(_CLEAN)
    r2 = cs.forwarded_copy_record(f2, t2)
    assert t2 == [] and r2["digest"] == cs.digest_json(_CLEAN)


def test_synthesize_sse():
    fwd, _ = cs.build_forwarded_copy(_RAW)
    sse = b"".join(cs.synthesize_sse(fwd))
    assert b'"id": "call_' in sse and b"[DONE]" in sse


def test_key_handling():
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
