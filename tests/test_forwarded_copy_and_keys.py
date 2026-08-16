import sys, types, json, hashlib
# stub the deps that aren't installed here so we can exercise the pure functions
for name in ["scitt_cose","agent_action_capsule","agent_action_capsule.canonical",
             "agent_action_capsule.contracts","agent_action_capsule.emit",
             "agent_action_capsule.verify","model_identity"]:
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["agent_action_capsule.canonical"].json_digest = lambda v: hashlib.sha256(
    json.dumps(v, sort_keys=True, separators=(",",":")).encode()).hexdigest()
for n in ["Disposition","EffectRecord"]: setattr(sys.modules["agent_action_capsule.contracts"], n, object)
sys.modules["agent_action_capsule.emit"].emit = lambda **k: {}
sys.modules["agent_action_capsule.verify"].verify = lambda *a, **k: None
sys.modules["model_identity"].load_manifest = lambda p: {}
sys.modules["model_identity"].model_package_digest = lambda m: ""
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
import capsule_sidecar as cs

RAW = {"id":"x","choices":[{"index":0,"finish_reason":"tool_calls","message":{
    "role":"assistant","content":"<turn-budget>3</turn-budget>",
    "tool_calls":[{"type":"function","function":{"name":"get_node_status","arguments":"{}"}}]}}]}
raw_digest = cs.digest_json(RAW)
fwd, tr = cs.build_forwarded_copy(RAW)

assert RAW["choices"][0]["message"]["content"] == "<turn-budget>3</turn-budget>", "RAW mutated!"
assert "id" not in RAW["choices"][0]["message"]["tool_calls"][0], "RAW tool_call mutated!"
assert cs.digest_json(RAW) == raw_digest, "raw digest drifted"
assert fwd["choices"][0]["message"]["content"] is None
assert fwd["choices"][0]["message"]["tool_calls"][0]["id"].startswith("call_")
assert tr == ["content_dropped_with_tool_calls","tool_call_id_minted"], tr
rec = cs.forwarded_copy_record(fwd, tr)
assert rec["digest"] != raw_digest and len(rec["digest"]) == 64
print("streaming case OK  transforms=", tr)

CLEAN = {"id":"y","choices":[{"index":0,"finish_reason":"stop",
        "message":{"role":"assistant","content":"hello"}}]}
f2, t2 = cs.build_forwarded_copy(CLEAN)
r2 = cs.forwarded_copy_record(f2, t2)
assert t2 == [] and r2["digest"] == cs.digest_json(CLEAN)
print("unchanged case OK  transforms=[] digest==response_digest")

sse = b"".join(cs.synthesize_sse(fwd))
assert b'"id": "call_' in sse and b"[DONE]" in sse
print("sse carries the minted id, synthesize mutates nothing")

# key handling
import pathlib, tempfile, os
d = pathlib.Path(tempfile.mkdtemp())/"keys"
pem = cs.load_or_create_signing_key(d)
assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
assert oct(os.stat(d/"node-key.pem").st_mode)[-3:] == "600"
assert cs.load_or_create_signing_key(d) == pem, "second call must reuse"
print("key: generated, 0600, stable across runs")

# ---- client nonce resolution ----
# client_supplied: header present -> nonce value passed through, source label is exact
nonce_val, nonce_src = cs._resolve_client_nonce({cs.CLIENT_NONCE_HEADER.lower(): "abc-123"})
assert nonce_val == "abc-123", f"nonce value not passed through: {nonce_val!r}"
assert nonce_src == "client_supplied", f"wrong source label for supplied nonce: {nonce_src!r}"
print("nonce: client_supplied OK")

# sidecar_generated_fallback: header absent -> sidecar mints a nonce, label is honest
nonce_val2, nonce_src2 = cs._resolve_client_nonce({})
assert nonce_src2 == "sidecar_generated_fallback", f"wrong source label for fallback nonce: {nonce_src2!r}"
assert len(nonce_val2) == 32, f"fallback nonce has unexpected length: {len(nonce_val2)}"  # uuid4().hex
print("nonce: sidecar_generated_fallback OK")

# mutant check: the two source labels must be distinct (catches any silent unification)
assert nonce_src != nonce_src2, "client_supplied and sidecar_generated_fallback must differ"
print("nonce: labels are distinct (mutant check OK)")

print("\nALL CHECKS PASSED")
