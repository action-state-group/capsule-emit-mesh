# Supported-port rerun: findings and comparison

**Run date:** 2026-08-16  
**Port:** `mesh-llm serve --gguf … --port 9337` (without `--local-model-only`)  
**Model:** `bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M`  
**mesh-llm version:** 0.75.1 (sha256 `26a28ae31cd1911be3e71b1ef612cb4166f0bff8380be461769f26083c077223`)  
**Ledger:** `ledger-supported-port/capsules.jsonl` (4 inference receipts), `ledger-supported-port/goose-actions.jsonl` (2 action records)  
**All 6 capsules verify offline:** `capsule-emit verify --store <ledger>` → `ok: True` for all entries.

---

## Why this run matters

The original demo (`ledger-live/`) ran against `mesh-llm serve --local-model-only`, which the
maintainer has described as "more a debugging endpoint" that bypasses the host-runtime OpenAI
normalizer. Issue [#1332](https://github.com/Mesh-LLM/mesh-llm/issues/1332)'s live acceptance
explicitly requires the supported inference port. This run reproduces the same task on the
supported port so every record in `ledger-supported-port/` is attributable to the production
path, not the debugging bypass.

**This run is a mechanism demonstration, not a reference deployment.** The signing key is
self-attested; see `README.md` → *Signing keys* and `docs/TRUST-MODEL.md`.

---

## Exact commands

```bash
# 1. Start the supported mesh inference port (no --local-model-only flag)
/path/to/mesh-llm serve \
  --gguf <path-to-gguf-blob> \
  --port 9337 --console 3131

# 2. Sidecar in front of the supported port, writing to ledger-supported-port/
python3 capsule_sidecar.py \
  --upstream http://127.0.0.1:9337 \
  --listen-port 8089 \
  --ledger-dir ledger-supported-port \
  --manifest model-package/model-package.live.json \
  --runtime-artifact /path/to/mesh-llm \
  --runtime-label "mesh-llm v0.75.1 real node (Hermes-2-Pro-Mistral-7B-Q4_K_M, supported-port)"

# 3. Wire goose to the sidecar
mesh-llm goose --port 8089 --model bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M

# 4. Same scripted goose task as the original run
GOOSE_PROVIDER=mesh GOOSE_MODEL=bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M \
goose run --no-session --no-profile --max-turns 8 \
  --with-extension "CAPSULE_LEDGER=ledger-supported-port/goose-actions.jsonl \
                    CAPSULE_OPERATOR=capsule-emit-mesh-poc-demo \
                    CAPSULE_DEVELOPER=goose@v1.46.0+mesh-llm \
                    CAPSULE_ANCHOR=false python3 goose/server.py" \
  -t "Call the get_node_status tool now with node_id=mesh-node-demo-1. \
      After you receive its result, call the submit_capacity_request tool now \
      with node_id=mesh-node-demo-1, gpu_hours=4, reason=inference_demand_spike. \
      You must call both tools before writing any summary text."
```

Substitute actual paths for `/path/to/mesh-llm` and the GGUF blob; both are recorded in
`model-package/model-package.live.json`.

---

## What changed versus the `--local-model-only` run

### 1. Tool-call IDs: normalizer mints them; sidecar no longer needs to

**`--local-model-only` (previous, `ledger-live/`):**
The raw response from mesh-llm contained `tool_calls` entries with **no `id` field**. The
sidecar had to mint synthetic IDs (uuid4) for each tool call so that goose's OpenAI client
could correlate tool results back to their calls. The capsule records this in:

```json
"forwarded_copy": {
  "transforms": ["tool_call_id_minted"],
  "digest": "<differs from response_digest>",
  "upstream_tool_call_ids": []
}
```

**Supported port (this run, `ledger-supported-port/`):**
The normalizer is active. mesh-llm returns tool calls with **IDs already present** in the raw
response, in the format `call_mesh_{timestamp_ms}_{index}`:

```
call_mesh_1786911567963_0   (capsule 2, get_node_status turn)
call_mesh_1786911570891_0   (capsule 3, submit_capacity_request turn)
```

The sidecar applied **no content transforms**. The capsule records this as:

```json
"forwarded_copy": {
  "transforms": [],
  "digest": "<equals response_digest>",
  "upstream_tool_call_ids": ["call_mesh_1786911567963_0"]
}
```

`transforms: []` with `forwarded_copy.digest == response_digest` is the positive statement that
the client received mesh-llm's own output unchanged. No sidecar normalization fired. This is
what the acceptance criterion "the client demonstrably receives mesh-llm's own streaming bytes
without sidecar normalization" looks like in the record.

### 2. The `content_dropped_with_tool_calls` quirk did not appear

The original run observed Hermes-2-Pro-Mistral-7B returning both a `tool_calls` array and a
spurious `content` string alongside it on the `--local-model-only` path, which the sidecar
dropped to make goose's parser happy. On the supported port this run: the transform did not
fire. The normalizer's output was structurally clean for both tool-call turns.

This may reflect normalizer post-processing or a different inference code path; it may also be
model non-determinism. Either way, the sidecar's existing handler is still present and would
fire if the quirk reappears.

---

## The digest-domain finding: what the normalizer costs

This is the finding the task asked to measure rather than reason about.

### What the normalizer IDs carry

The IDs follow the pattern `call_mesh_{milliseconds_since_epoch}_{index}`. The timestamps from
this run:

- `call_mesh_1786911567963_0` — wall-clock at first tool-call turn
- `call_mesh_1786911570891_0` — wall-clock at second tool-call turn (≈ 3 seconds later)

Because these IDs are **in the raw response bytes** that `response_digest` attests, and because
the timestamps are wall-clock values that differ on every invocation of the model, the
`response_digest` field for tool-call-bearing responses is **run-unique** (the phrase "identical
model output" was used here originally; it has since been retracted — sampling was not pinned,
so output was not identical across runs):

> ~~Repeating this exact task with the same model, same prompt, same parameters would produce
> different `response_digest` values for capsules 2 and 3 on every run.~~
>
> **CORRECTION:** "capsules 2 and 3" scopes instability to tool-call turns only, implying turns
> 1 and 4 are stable — the claim retracted below. "Same parameters" was not true: sampling was
> not pinned. This blockquote is superseded by the full correction that follows.

~~Capsules 1 and 4 (which are text-only responses with no tool calls) have stable
`response_digest` values: they contain no wall-clock material injected by the normalizer.~~

**CORRECTION:** The claim above is disproved by a subsequent run of the identical task on a
Linux host. That run produced different digests on every capsule, including the text-only turns,
and a different capsule count (5 instead of 4), because the model took a different conversational
path. `response_digest` is unstable for **two independent causes**:

1. **Normalizer wall-clock tool-call IDs** (`call_mesh_{ms}_{index}`): affects tool-call-bearing
   turns only. Documented above; confirmed by the ID values in the records.
2. **Model sampling non-determinism**: affects every turn — including text-only turns — and can
   change the total number of capsules produced. **Sampling was not pinned in either run.**

Cause 1 is independently established by the timestamp values embedded in the IDs; that argument
survives. Cause 2 means that removing the normalizer's timestamps alone would not be sufficient
to make digests reproducible absent pinned sampling parameters.

### What "delivered-bytes digest" means here

`response_digest` in every capsule is the delivered-bytes digest — the SHA-256 JSON-DIGEST
(RFC 8785 JCS) over what the normalizer returned to the sidecar. This is the only digest the
sidecar can compute: it sits between the normalizer and the client, not between the model and
the normalizer.

### Are model-produced bytes accessible?

**No, through this sidecar path.** The sidecar sees the normalizer's output, not the model's
raw token stream. There is no API surface between the normalizer and the model that the sidecar
can observe. The only difference between normalizer output and model output (for tool-call
responses) is the `id` field on each `tool_calls` entry; those bytes are not separately
retrievable.

Stated plainly: on the supported port, `response_digest` attests to normalizer-modified bytes,
not to model-produced bytes. A verifier who runs the same task twice will see different
`response_digest` values for the tool-call turns. This is the digest-domain problem already
noted in prior discussion; this run is the first measurement of it in actual records rather than
a theoretical observation.

### Behaviour versus bytes

Across both supported-port runs, the tool calls fired correctly — the right tools were called
with the right arguments and the tool returns were real. The record is unreproducible (the same
bytes do not appear on a second run); the system was not unreliable (both runs reached correct
tool completions). These are different claims and conflating them would be its own overclaim.

---

## Side-by-side record comparison

| Field | `--local-model-only` (ledger-live) | Supported port (ledger-supported-port) |
|---|---|---|
| mesh-llm flag | `--local-model-only` | *(none — full node)* |
| Capsule count | 4 inference receipts | 4 inference receipts |
| `transforms` on tool-call turns | `["tool_call_id_minted"]` | `[]` |
| `upstream_tool_call_ids` | `[]` | `["call_mesh_…"]` with wall-clock timestamps |
| `forwarded_copy.digest == response_digest` | **No** (sidecar-minted IDs differ) | **Yes** (no sidecar transform) |
| `response_digest` stable across runs? | unmeasured — not re-run | **No** — all turns: tool-call turns (wall-clock in IDs) and text-only turns (sampling non-determinism); capsule count also varies. See CORRECTION in digest-domain section. |
| `content_dropped_with_tool_calls` | Fired on one turn | Did not fire |
| Model-produced bytes accessible? | `response_digest` ≈ model bytes (no IDs) | No — normalizer layer intervenes |
| All capsules verify offline? | Yes | Yes |
| Goose output matches real tool returns? | Yes | Yes |

---

## Runtime label change

The `runtime` field in `model_attestation.compute_attestation` distinguishes the two runs:

- Previous: `…:mesh-llm v0.75.1 real local node (Hermes-2-Pro-Mistral-7B-Q4_K_M, --local-model-only)`
- This run: `…:mesh-llm v0.75.1 real node (Hermes-2-Pro-Mistral-7B-Q4_K_M, supported-port)`

The SHA-256 of the mesh-llm binary is unchanged between the two runs:
`26a28ae31cd1911be3e71b1ef612cb4166f0bff8380be461769f26083c077223` — same binary, different
serving mode.
