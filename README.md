# capsule-emit-mesh-poc

A proof-of-concept: emit signed, hash-chained **Agent Action Capsules** for
every request a [Mesh-LLM](https://github.com/Mesh-LLM/mesh-llm) node serves,
implementing step 3 ("nonce-bound signed inference receipts") of
[Mesh-LLM/mesh-llm#1233](https://github.com/Mesh-LLM/mesh-llm/issues/1233),
"Explore proof of inference and model-serving attestation."

This is the strawman artifact for the call Steven committed to bringing —
**not** a PR to Mesh-LLM's repo. Published 2026-08-11 as
`action-state-group/capsule-emit-mesh` (Steven's naming call, confirmed).
Everything here is PUBLIC-safe (Apache-2.0, see [LICENSE](LICENSE)), and
contains no trust-index / scoring / reputation language, per the task
boundary.

> **Signing keys.** This repository ships no private key. The sidecar generates
> an Ed25519 node key on first run into `--keys-dir` (mode 0600, gitignored).
> The public half of the key used for the committed `ledger/` and `ledger-live/`
> runs is included so those artifacts stay independently verifiable. A generated
> key is self-attested and not bound to any real node identity or hardware root
> (see "Field mapping").

> `keys/` — public half of the demo node key. Self-attested; not bound to any node identity or hardware root. See [*About the entries in `ledger-live/`*](ledger-live/README.md) for what the anchored entries do and do not establish.

**Status: live-verified (2026-08-16, supported port).** An earlier session
built this against a mock fixture node only (sandboxed execution restriction
at the time — see git history). Subsequent sessions re-ran the whole thing
against a **real, running `mesh-llm serve` node on the supported mesh inference
port** (Hermes-2-Pro-Mistral-7B-Q4_K_M, downloaded and checksummed by
`mesh-llm` itself) and a **real `goose` CLI session** wired to that node via
the documented `mesh-llm goose` workflow — see "Live demo" below and
[`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md) for findings.
Both are real local processes; no mocks remain in the live path. The mock-node
path (`mock_mesh_node.py`, `run_demo.py`) is kept for a
network/model-download-free smoke test, clearly labeled as such.

## What issue #1233 actually asks for

James Dumay (i386) filed #1233 decomposing "proof of inference" into three
separable claims — model identity, execution identity, behavioral identity —
and proposed a progression from (2) precise model/package digests through
(3) nonce-bound signed receipts, (4) statistical fingerprints, (5) TEE
evidence, to (6) a signed capsule history. Steven's comment on the issue is
the design pitch this PoC implements:

> Step 3 is the layer we build... Your receipt tuple is an agent-action
> record where the tool is the model: we'd emit it as a signed capsule at
> the /v1 serve boundary — same capability-plugin pattern as your metrics
> plugin — with the client nonce, request digest, model_package_digest,
> runtime digest, params, and output digest as committed fields,
> hash-chained per node. Apache-2.0, two IETF drafts behind the format...
> a fingerprint result or TEE quote rides as a typed reference (digest +
> declared context) inside the same record, so steps 4 and 5 upgrade the
> evidence a record carries without changing the wire format.

The receipt tuple, verbatim from the issue body:

```
receipt = sign_node_key(
  client_nonce, request_digest, model_package_digest,
  runtime_digest, generation_parameters, output_digest, timestamp
)
```

This PoC builds exactly that record, as an Agent Action Capsule.

## Architecture decision: sidecar, not a mesh-llm plugin

Steven's comment frames this as "the same capability-plugin pattern as your
metrics plugin." Having read the actual code (`Mesh-LLM/mesh-llm`, cloned
read-only to `../mesh-llm-src`, and `Mesh-LLM/openai-endpoint`, cloned to
`../openai-endpoint-src`), that framing doesn't survive contact with the
implementation, and the honest PoC is a **sidecar reverse-proxy**, not a
plugin. Specifically:

1. **The native serving plugin ABI** (`crates/mesh-native-serving-plugin-api`,
   a C-ABI dylib interface) is what mesh-llm's *inference-observing* plugins
   use. It delivers `GenerationStart` / `GenerationCommit` /
   `GenerationFinish` events — prompt token IDs/counts, a prompt token
   digest, generated token IDs, timing — but **never the raw OpenAI JSON
   request or response body**. A plugin on this ABI cannot reconstruct
   `request_digest` or `output_digest` as issue #1233 defines them (digests
   "over the request/response," not over token arrays).

2. **The "metrics plugin" Steven cites as the pattern** is not on that ABI at
   all — it's an out-of-process capability plugin
   (`Mesh-LLM/metrics`, docs at `docs/plugins/telemetry.md`): a long-lived
   local process that advertises a capability (`capability("...")`) and gets
   stapled onto mesh-llm's MCP/HTTP surfaces by the host. Confirmed by
   reading `docs/plugins/README.md`: "A plugin owns: its own feature logic,
   local state, operation handlers..." — plugins are capability
   *providers* mesh-llm's core calls *into* (model backends, add-on tools),
   not observers of core's own inbound `/v1` traffic.

3. **`openai-endpoint`, the plugin issue #1233's task text also named**, is a
   capability provider too — but for the *opposite* direction from what a
   receipt-emitting plugin needs: it lets mesh-llm route *out* to an
   external OpenAI-compatible server as a model backend
   (`mesh_llm_plugin::inference::openai_http`, confirmed by reading
   `openai-endpoint/src/lib.rs`). It has nothing to do with observing
   traffic at mesh-llm's *own* `/v1` serve boundary, which is what a
   receipt needs.

4. **There is a real in-process hook** that CAN see both sides:
   `OpenAiHookPolicy` + `HookedOpenAiBackend` in
   `crates/openai-frontend/src/hooks.rs`. `before_chat_completion` sees the
   full `ChatCompletionRequest` before it's forwarded, and
   `HookedOpenAiBackend::chat_completion_with_context` holds the full
   `ChatCompletionResponse` as its own return value. But exploiting this
   means compiling a **custom mesh-llm binary** with the wrapper wired into
   wherever the backend is constructed — a fork of their source tree, not
   an installable plugin, and out of scope (no PR to their repo yet; this
   sandbox has no Rust toolchain to build or verify one regardless).

Given that, the thinnest **honest** PoC is a sidecar: a reverse HTTP proxy in
front of mesh-llm's own `/v1/chat/completions`, forwarding every request
unmodified and recording a digest-committed capsule of what it observed at
the wire on the way through. It requires zero changes to mesh-llm's code,
works against a release binary or a `cargo run` build identically, and is
honestly labeled as an external observer, not a first-party integration.
Whether Steven wants to *also* pursue the in-process hook as a follow-up
(the more "native" long-term shape, once a real PR conversation with
Mesh-LLM is on the table) is a call-agenda question, not a PoC blocker.

The request is always forwarded unmodified. The response is forwarded
unmodified for non-streaming calls; for streaming calls (what goose sends —
see "Live demo" below) the sidecar buffers the real upstream SSE stream,
seals a capsule over it exactly as received, then re-emits a synthesized SSE
stream to the caller from a **client-compatibility-normalized copy** of that
same response. This exists because of a real thing found live in this
session — see "Honest limitations."

Implementation: `capsule_sidecar.py`. It can be pointed at a real node:

```bash
mesh-llm serve --gguf /path/to/model.gguf --port 9337   # --gguf needs a real (non-symlink) file path
python3 capsule_sidecar.py --upstream http://127.0.0.1:9337 --listen-port 8089 \
    --runtime-artifact /path/to/mesh-llm-binary --runtime-label "mesh-llm v0.75.1 real node" \
    --manifest model-package/model-package.live.json   # built from the real model -- see build_real_model_package.py
# point your OpenAI client (or goose, via `mesh-llm goose --port 8089`) at
# http://127.0.0.1:8089/v1 instead of :9337/v1
```

## Composing capsule-emit-goose: two chained record streams

This PoC implements #1233's inference-receipt layer at the `/v1` serve
boundary. It composes with **capsule-emit's own Goose integration**
(`goose/server.py`, "capsule-emit-goose" below) at the *tool-call* boundary —
mic's two codebases, composing, per the task this README documents:

```
goose (real CLI process)
  │
  ├─ LLM turns ──▶ mesh.json custom provider (base_url = sidecar) ──▶ capsule_sidecar.py ──▶ real mesh-llm node
  │                  every /v1/chat/completions call sealed here        (inference receipts, hash-chained
  │                                                                       per node, this PoC's #1233 tuple)
  │
  └─ tool calls ─▶ goose/server.py (stdio MCP extension, "capsule-emit-goose")
                     every tool call sealed here via capsule-emit's
                     MCPCapsuleEmitter / @emitter.tool() (action records)
```

One `goose run` task against a real local mesh-llm node produces **two
independently verifiable, independently chained** capsule ledgers from the
same session:

- `ledger-live/capsules.jsonl` — inference receipts (this PoC's sidecar,
  the `/v1` boundary, issue #1233's receipt tuple)
- `ledger-live/goose-actions.jsonl` — action records (capsule-emit-goose,
  the tool-call boundary, `submit_capacity_request` / `get_node_status`)

Each verifies independently with the same CLI:
`agent-action-capsule verify --store <ledger>.jsonl`. They are deliberately
**not** cross-chained to each other in this PoC (different domains — one
attests the model call, the other the agent's tool call around it); a
binding reference between the two is a natural next step, not built here.

## Live demo (real mesh-llm + real goose)

Everything below is a real local process. No mock server, no fixture model,
no fabricated bytes. `run_live_demo.sh` orchestrates all six steps; the
narrative here is the same run, spelled out.

> **Obtaining mesh-llm and goose.** The `mesh-llm` binary is **not included in this
> repository**. Download the release tarball (v0.75.1 or later) from
> https://github.com/Mesh-LLM/mesh-llm/releases — it extracts to `mesh-bundle/mesh-llm`.
> Verify the sha256 before running (`sha256sum mesh-bundle/mesh-llm`; v0.75.1 darwin-arm64:
> `26a28ae31cd1911be3e71b1ef612cb4166f0bff8380be461769f26083c077223`). For goose (v1.46.0+),
> see https://github.com/aaif-goose/goose (the repository moved from `block/goose`).
> Install Python dependencies with `pip install -r requirements.txt`.

```bash
# 1. download a small local model mesh-llm can serve directly (one-time)
mesh-llm download Hermes-2-Pro-Mistral-7B-Q4_K_M   # ~4.4GB; goose's catalog default for tool-calling

# 2. serve it on the supported mesh inference port (needs the real, non-symlink blob path from the HF cache)
mesh-llm serve --gguf <path-to-.gguf-blob> --port 9337

# 3. real model-package.json from the actual downloaded weights (not a fixture)
python3 build_real_model_package.py <path-to-.gguf-blob> bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M

# 4. the sidecar sits in front and seals inference receipts
python3 capsule_sidecar.py --upstream http://127.0.0.1:9337 --listen-port 8089 \
    --ledger-dir ledger-live --manifest model-package/model-package.live.json \
    --runtime-artifact /path/to/mesh-llm --runtime-label "mesh-llm real node"
# Note: the mesh-llm binary is not in this repo; see "Obtaining mesh-llm" below.

# 5. the real, documented `mesh-llm goose` workflow wires goose's provider config
#    at the sidecar port (writes ~/.config/goose/custom_providers/mesh.json)
mesh-llm goose --port 8089 --model bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M

# 6. a real, scripted goose run drives both record layers in one task
# CAPSULE_ANCHOR=false (the default) keeps capsules locally verified only.
# Setting it to true posts digests to the live, shared anchor.agentactioncapsule.org
# transparency log — a permanent, unremovable write to shared production
# infrastructure. See "Anchoring" under "Honest limitations" before changing it.
GOOSE_PROVIDER=mesh GOOSE_MODEL=bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M \
goose run --no-session --no-profile --max-turns 8 \
  --with-extension "CAPSULE_LEDGER=ledger-live/goose-actions.jsonl CAPSULE_OPERATOR=capsule-emit-mesh-poc-demo CAPSULE_DEVELOPER=goose@v1.39.0+mesh-llm CAPSULE_ANCHOR=false python3 goose/server.py" \
  -t "Call the get_node_status tool now with node_id=mesh-node-demo-1. After you receive its result, call the submit_capacity_request tool now with node_id=mesh-node-demo-1, gpu_hours=4, reason=inference_demand_spike. You must call both tools before writing any summary text."
```

Real output from this session's rehearsal run (Hermes-2-Pro-Mistral-7B,
2026-08-11):

```
  ▸ get_node_status python3
    node_id: mesh-node-demo-1
  ▸ submit_capacity_request python3
    gpu_hours: 4
    node_id: mesh-node-demo-1
    reason: inference_demand_spike

The node with the ID mesh-node-demo-1 is currently healthy and the GPU
capacity request has been successfully queued with the reference CAP-mo-1
for 4 GPU hours due to inference demand spike.
```

`ledger-live/capsules.jsonl` ends with 4 chained, verified inference-receipt
capsules for this run (3 LLM turns' worth of chat completions, chained
per-node); `ledger-live/goose-actions.jsonl` has the 2 action-record
capsules for the 2 real tool calls. Both verify `ok=True` — see "What was
actually verified."

**Why the task prompt is written as blunt, sequenced imperatives** ("Call
the tool now... You must call both tools before writing any summary text")
rather than a natural-language "step 1/2/3" narrative — see "Honest
limitations": that phrasing is a *finding* from this session, not a
stylistic choice.

## Checkpointing: local MMR + signed checkpoints (Layers 1-2, opt-in)

Layer 0 (a signed capsule per exchange, above) is always on. This section adds
two strictly optional, strictly stronger layers, consuming `capsule_emit.checkpoint`
as a library — nothing here vendors or reimplements MMR/checkpoint logic:

- **Layer 1** — a local, append-only Merkle Mountain Range (MMR) over this
  node's own `capsules.jsonl`, so any individual capsule can later be proven
  included under a later checkpoint without re-hashing the whole log.
- **Layer 2** — a periodic, signed checkpoint (a 32-byte MMR root, signed with
  the same Ed25519 key that signs the node's capsules) committing everything
  appended since the previous checkpoint.
- **Layer 3** — an independent witness (any conforming SCITT Transparency
  Service, e.g. the free public-good tier at `anchor.agentactioncapsule.org`)
  co-signs the checkpoint. Also opt-in, per URL, and never on the serving
  path: an unreachable witness leaves the checkpoint locally-committed
  (self-checkpointed), never blocks or fails the request it's attached to.

A node opts in by passing `--checkpoint-config` with a `[checkpoint]` TOML
table — see `checkpoint.example.toml`. A node that never passes this flag
pays zero cost: no MMR is built, no extra file is written. See
`checkpointing.py` for the adapter (`JsonlLogSource`, wrapping this repo's
existing ledger as a `capsule_emit.checkpoint.LogSource`) and `CheckpointState`
for the cadence + reconnect logic.

**Offline nodes: latest-checkpoint-on-reconnect, not one checkpoint per missed
tick.** A node that goes offline keeps appending to its local ledger and MMR;
nothing is lost. On reconnect it emits and registers **one** checkpoint
covering everything accrued since the last witnessed one — the new
checkpoint's `prev_size`/`prev_root` chain from the old one, so a consistency
proof spans the whole gap in a single step. The honest exposure window this
leaves: entries appended while offline are provably included once the
reconnect checkpoint lands, but until then they exist only in the local,
unwitnessed log — anyone relying on third-party freshness evidence for those
entries has to wait for reconnect, and that wait is reported, not hidden (see
`describe_witness_state()` below).

**Witness grading — never overstate what a checkpoint has actually achieved.**
This repo's checkpoint status lines distinguish three strictly increasing
levels of assurance, and never round up:

1. **self-checkpointed** — locally committed and signed, no outside party has
   seen it (`ts_urls` empty, or every registration attempt failed).
2. **peer-witnessed** — another mesh node has carried/composed this
   checkpoint into its own record. Documented here as the decentralized
   option; **not built in this PoC** — see the mesh architecture doc's
   posture ruling (the default integration path is checkpoint → operated
   witness, not peer-to-peer witnessing).
3. **independently witnessed** — at least one registered SCITT Transparency
   Service has actually countersigned the checkpoint's digest.

`describe_witness_state()` in `checkpointing.py` renders exactly one of these,
plus any lag ("N more entries appended since"), and is covered by a mutant
test asserting it can never say "witnessed" for a checkpoint with an empty
witness list. `scitt_cose.cll.witness_status_line()` (the independently-ported
verify-side function, used by `run_checkpoint_demo.py`'s offline-verify leg)
renders the same discipline as "witnessed up to size *S* at time *T*" — *S* in
raw MMR node-count terms there, vs. leaf/entry-count in this repo's own
`describe_witness_state()`; both surface lag rather than rounding a stale
checkpoint up to "current."

**What witnessing proves, and what it never proves.** A witness (Layer 3)
proves the checkpoint — and everything under it — has not been silently
rewritten after the fact: the witness's own signature is over a root a
rewrite cannot retroactively match. It proves **non-rewrite of the log
structure**. It proves **nothing about the content** of any capsule under
that root — a witnessed checkpoint over a log of capsules containing false
claims is just as witnessed as one over a log of true claims. Do not let
"witnessed" drift into "verified honest," the same discipline this repo
already applies to `client_nonce` (see "Honest limitations" below: a nonce
proves freshness, not identity).

**What was actually run.** `run_checkpoint_demo.py` exercises: N mesh
exchanges → capsules → local MMR → cadence-triggered and reconnect-triggered
checkpoints → registration at the live public anchor
(`anchor.agentactioncapsule.org`) → offline inclusion + receipt verification
via `scitt_cose.cll`, with no sidecar state in memory for the offline leg.
Run with `--register-live-anchor` for the real Layer 3 registration (a real
write to shared infrastructure — off by default; without the flag the demo
stays local/self-checkpointed only). `ledger-checkpoint-demo/` is this run's
committed transcript and fixture output, kept for the same reason
`ledger-live/` is: so the claims above are checkable against a real artifact,
not just this description.

**Cross-repo shape divergence (flagged 2026-08-22, resolved 2026-08-22).**
`capsule_emit.checkpoint.CheckpointRecord` dropped its `peaks_digest` field
(single-commitment shape, one peak-set commitment field: `root`) as part of
landing PR #66. `scitt_cose.cll.Checkpoint.from_dict()` briefly hard-required
a `peaks_digest` key from an older two-field shape, but scitt-cose 0.2.2
(`cll.py`'s `Checkpoint.from_dict`) dropped that requirement and reads only
known keys. Both sides now agree on the Option-C single-commitment shape, so
`verify_real_deployment_checkpoint.py` and `tests/test_checkpointing.py`
convert directly (`cll.Checkpoint.from_dict(checkpoint.to_dict())`) with no
local bridging.

## Real deployment: checkpointing driven by an actual mesh-llm-host-runtime run

`run_real_deployment_checkpoint_demo.sh` closes the gap the section above
leaves open: `run_checkpoint_demo.py` is a fully synthetic, in-process demo
(`mock_mesh_node.py`, fabricated prompts/responses) — useful for exercising
the checkpoint machinery hermetically, but it never actually talks to a real
mesh-llm-host-runtime. This script does: it starts a real, locally-built
`mesh-llm serve` process against a real downloaded GGUF model (the same
"live demo" pattern as `run_live_demo.sh`, minus the goose tool-call leg,
which is a separate stream/boundary), points `capsule_sidecar.py` at it with
`--checkpoint-config` enabled (Layers 0-2 all live), sends real chat-completion
requests through the sidecar so real inference happens, and then hands off to
`verify_real_deployment_checkpoint.py` for an offline, ledger-files-only
verify pass (capsule verify + chain, inclusion-under-checkpoint, witness
status, and a rollback/fork mutant proof) plus the exact, not-executed,
command to register the resulting checkpoint at the live public-good witness.

```
./run_real_deployment_checkpoint_demo.sh <mesh-llm-binary> <gguf-path> <model-id>
```

**What was actually run vs. staged.** The full local chain — real
`mesh-llm-host-runtime` inference through the sidecar, capsule emission into
`ledger-real-deployment/capsules.jsonl`, cadence-triggered checkpoints into
`ledger-real-deployment/checkpoints.jsonl`, offline inclusion verify, and the
rollback-mutant proof — is real, this run, no mocks. Live registration at
`anchor.agentactioncapsule.org` is deliberately STAGED, not executed: this
task's own gate reserves live-anchor writes for a separate go from the
task-level one (see the outbox report for the exact reasoning). The staged
command is printed by `verify_real_deployment_checkpoint.py` and is a single,
already-correct call to `capsule_emit.checkpoint.register_checkpoint` — no
further code work needed if/when it's authorized.
`ledger-real-deployment/` is this run's committed transcript and fixture
output, same rationale as `ledger-checkpoint-demo/` and `ledger-live/`: so
the claims above are checkable against a real artifact, not just this
description.

## Replay spot-check harness (C2a)

`tools/replay_spot_check.py` implements the C2a mechanism from
[`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) §3 Class C: fire the same
temperature-0, fixed-seed request twice and compare the two responses on the
domain the sidecar already commits to — `response_digest`
(`capsule_sidecar.digest_json`, jcs-n over the float-stringified raw
response). It answers one question only — do these two runs match on that
domain — and is deliberately not a scorer: the result carries `match: true`
/ `false` and the two digests, never a confidence, trust, or reputation
value. A mismatch is grounds to investigate, not a verdict (sampling
non-determinism and cross-hardware execution are named, expected
confounds in TRUST-MODEL.md — see the C2a discussion there before reading
anything into a mismatch).

```
# Offline: compare two already-captured response bodies
python3 tools/replay_spot_check.py compare response_a.json response_b.json

# Live: pin a request to temperature 0 + a fixed seed, fire it twice
# against a running upstream, and compare
python3 tools/replay_spot_check.py live --upstream http://127.0.0.1:9337 --request request.json
```

See [`tests/replay/README.md`](tests/replay/README.md) for the vector suite
(a matched pair and a deliberately mismatched pair — one sampled token
flipped) and `tests/test_replay_spot_check.py` for both directions
exercised end to end against a local stub upstream.

## Honest limitations (read this before the call)

**This PoC's run history, for the record.** An earlier session built this
PoC entirely against `mock_mesh_node.py` because that sandbox's tool policy
blocked executing the downloaded mesh-llm binary. A subsequent session ran
against the supported mesh inference port (`mesh-llm serve --gguf … --port
9337`) with a real `goose` CLI session — see "Live demo" above for the exact
commands and real output, and [`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md)
for the comparison with the earlier debugging-endpoint run.
`mock_mesh_node.py` / `run_demo.py` are kept only as a
network/model-download-free smoke test of the sidecar mechanism in isolation;
they are not the demo path and are clearly labeled as a fixture everywhere they appear.

**One `mesh-llm` CLI flag correction found by running it for real** (the
`--help` text doesn't make it obvious): `--gguf` must be a real file, not
the symlink the Hugging Face cache normally hands you
(`snapshots/<rev>/<file>` → `blobs/<sha256>`) — resolve the symlink first
(`build_real_model_package.py` does this and uses the same resolved path for
hashing).

> **Note — `--local-model-only` is a debugging endpoint, not for acceptance.**
> It bypasses the host-runtime OpenAI normalizer and is not the path issue
> #1332's live acceptance requires. The primary invocation in this README uses
> the supported mesh inference port (`mesh-llm serve --gguf … --port 9337`,
> without `--local-model-only`). For the behavioral difference between the two
> modes and the digest-stability finding, see
> [`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md). (Flag note:
> `--local-model-only` takes `--gguf <path>`, not `--model <name>` — the
> `--model` flag is for mesh-network model selection.)

**A real, live small-model/goose tool-calling compatibility issue, found and
fixed in this session.** Two things had to be fixed for `goose run` to
actually work against a real local model through this sidecar, neither
knowable without running it for real:

1. goose requests `stream: true`; the sidecar originally only handled
   non-streaming JSON responses and errored on every call. Fixed: the
   sidecar now buffers the real upstream SSE stream, reassembles it into one
   committed response object (`reassemble_streamed_response`), seals a
   capsule over that RAW object, and re-emits a synthesized SSE stream to
   the caller (`synthesize_sse`) — see `capsule_sidecar.py`.
2. Once streaming worked, `goose run` still failed:
   `Unsupported: ... does not match the expected peg-native format.`
   Captured the raw, non-streamed response from mesh-llm directly (bypassing
   goose) to isolate the cause: Hermes-2-Pro-Mistral-7B, driven by goose's
   own agent system prompt, sometimes returns a message with **both** a
   correct, well-formed `tool_calls` array **and** a spurious `content`
   string (observed: the model echoing a `<turn-budget>` tag from goose's
   own prompt back as content). goose's client-side parser rejects that
   combination. This is a real small-model output quirk, not a sidecar bug
   or a goose bug — confirmed by reproducing it directly against mesh-llm
   outside of goose. Fix: `normalize_for_client()` drops `content` only when
   `tool_calls` is also present, applied **only** to the copy forwarded to
   the calling agent — the capsule's `response_digest` continues to attest
   to the literal, unmodified response mesh-llm returned. Separately,
   mesh-llm's real `tool_calls` entries carry no `id` field, which most
   OpenAI-compatible clients (goose included) require to correlate a tool
   result back to its call; a synthetic one is minted only in the forwarded
   copy, same rule.
3. A related finding, not a bug: a natural-language "Step 1 / Step 2 / Step
   3" task prompt let the model narrate a plausible-sounding summary
   *without* calling either tool (confirmed by an empty action-record
   ledger + the reported values not matching the tools' real return values).
   Blunt, sequenced imperatives ("Call the tool now... you must call both
   tools before writing any summary text") reliably drove real tool calls
   with real, verifiably-matching return values — see "Live demo" for the
   exact prompt used. Worth naming for the call: a 7B local model needs more
   directive prompting than a frontier model does for reliable multi-step
   tool use; that's a property of the model, not of the record layer.

**`model_package_digest` is now computed from the real downloaded model.**
`build_real_model_package.py` hashes the actual GGUF file mesh-llm
downloaded (SHA-256 over the real ~4.4GB file, streamed — see
`model-package/model-package.live.json`), not a fixture. It intentionally
omits `shared`/`layers` artifacts: this demo serves a single GGUF file
directly via `--gguf <path>`, not the Skippy layer-split format mesh-llm uses
for distributed serving — a manifest claiming layer artifacts here would be
fabrication. `model_identity.py`'s digest formula already treats those
blocks as optional for exactly this reason. (`build_model_package.py`, the
original fixture-based builder, is kept for the mock-node smoke test.)

**`client_nonce`: what it establishes and what it does not.**
A client nonce establishes freshness: the node could not have precomputed or
replayed a request carrying a nonce it never saw.  It says nothing about who
the requester is.  This is the complete claim — do not let "nonce" drift into
"identity."

Issue #1233 is explicit that the *client* must contribute the nonce ("so the
node cannot fabricate or replay a request"). This sidecar accepts the
`X-Capsule-Client-Nonce` request header and uses it when present
(`client_nonce_source: "client_supplied"`); when absent it mints its own and
records `client_nonce_source: "sidecar_generated_fallback"` rather than
silently mislabeling it as client-supplied.  A fallback-sourced nonce does not
carry the freshness property above — flagged, not hidden.  `run_demo.py`
demonstrates both paths side by side: requests 1–4 send the header and show
`client_supplied`; request 5 omits it and shows `sidecar_generated_fallback`.
Wiring a real client-contributed nonce through goose's request path is future
work (would need a goose extension or provider-level header injection, neither
built here).

A third tier sits between those two. When mesh-llm's own local ingress mints
the nonce one hop upstream of the sidecar — because the harness itself sent
none — it marks its own injection with `x-capsule-nonce-origin: local_ingress`,
and the sidecar records `client_nonce_source: "local_ingress"` rather than
overclaiming `client_supplied`. **This is a routing hint, not authentication:**
the header is a bare, unauthenticated value the requester's own connection
fully controls, and nothing here Ed25519-verifies it the way
`evaluate_bilateral_attestation` verifies bilateral request headers elsewhere
in this file. See `docs/TRUST-MODEL.md` §2.2 (R3) for the precise trust claim
this tier does and does not make, and why enforcing it is deliberately
deferred until this path drives a real trust decision.

**Anchoring: rehearsal runs verify locally only, by decision.** `capsule-emit
permalink --check` verifies every capsule structurally offline (no network)
— that's what this README's permalinks reflect, and, per Steven's explicit
2026-08-11 decision, **all this repo's rehearsal-run capsules stay
offline-verified only** (the `ledger-live/` capsules committed here,
including the 5 unanchored ones from this session, are NOT to be anchored
under any circumstance). Anchoring a capsule posts its digest (never
payload) to the live, shared `anchor.agentactioncapsule.org` transparency
log — a real write to shared infrastructure beyond this repo — and happens
exactly **once**, deliberately, against the actual take used live on the
call, run right before the Wednesday rehearsal deadline. See the outbox
report under `[mesh-poc-live-goose-meshllm-run]` for the full decision and
its rationale (anchored log entries should correspond to the real call
artifact, not an earlier rehearsal).

## Field mapping: #1233's "receipt tuple" → capsule record

| #1233 receipt tuple field | Capsule field | Notes |
|---|---|---|
| `client_nonce` | `model_attestation.compute_attestation["x-mesh-poc-v1"].client_nonce` | See "client_nonce" limitation above. Not yet a registered capsule field — see "Extension note" below. |
| `request_digest` | `effect.request_digest` | **Spec-native field**, not an extension (§5.2 Effect Record). SHA-256 JSON-DIGEST (RFC 8785 JCS) over the canonicalized request body. The raw prompt is never stored in the capsule — digest only, preserving prompt privacy per the issue's own framing. |
| `model_package_digest` (Python path) | `model_attestation.compute_attestation["x-mesh-poc-v1"].model_package_digest` | Computed by `model_identity.py` exactly per the issue's own formula: `sha256(canonical_manifest + artifact_digests + runtime_abi)`, instantiated as a JSON-DIGEST over `{model_id, canonical_ref, source_model_sha256, artifact_digests[], runtime_abi}`. Sourced from a real (if fixture) `model-package.json`, never fabricated. **This real package digest is the Python producer only.** |
| `model_name_digest` (Rust plugin path) | `model_attestation.compute_attestation["x-mesh-poc-v1"].model_name_digest` | The live Rust admission-policy plugin only has the request's model **name**, so it attests exactly `sha256(model_name)` under a **truthful** field name (`model_name_digest`), renamed from the earlier `model_package_digest` which overclaimed a weights/package binding it never had. No overclaiming: a name hash is named as a name hash. |
| serving provenance (what ran where) | `model_attestation.compute_attestation["x-mesh-poc-v1"].serving_provenance` | Detailed provenance of the actual run: `served_by_node_id`, `requesting_party`, `exchange_id` (the host's `exchange_id`/`x-request-id` correlation lineage), `usage.{prompt_tokens,completion_tokens,total_tokens}` (lifted verbatim from the OpenAI-shaped response body's `usage`), plus `quantization` and `hardware.{gpu,vram_bytes,device}`. **`quantization` is `"unknown"` and every `hardware.*` is `null`** because the mesh-llm host's `openai.exchange.v1` event and response body genuinely do NOT carry them (they live only in the host's TUI/`mesh-llm-system` crates, never surfaced to a plugin) — recorded honestly as absent, never fabricated. Every field here is digest-bearing: mutating any of them changes `capsule_id`. |
| `runtime_digest` | `model_attestation.compute_attestation.runtime` (prefix before the `:`) | SHA-256 of the actual runtime artifact serving the request — the mock server's own source file in this demo, or `--runtime-artifact <path>` (e.g. the mesh-llm binary) against a real node. Read-only hash, never requires executing the artifact. |
| `generation_parameters` | `model_attestation.compute_attestation["x-mesh-poc-v1"].generation_parameters` | Carried as legible decimal-string values (temperature, top_p, max_tokens, seed, penalties, stop — whichever the request set), not digested — these are policy/audit-relevant and not privacy-sensitive the way the prompt is. |
| `output_digest` | `effect.response_digest` | **Spec-native field** (§5.2), same treatment as `request_digest` — JSON-DIGEST over the canonicalized response body (success or error body alike). |
| `timestamp` | `timestamp` | **Spec-native field** (§5.1), RFC 3339 UTC, set at capsule-seal time. |
| `sign_node_key(...)` (the whole tuple, signed) | The whole capsule, wrapped in a COSE_Sign1 **Signed Statement** | `scitt_cose.build_signed_statement()`, `alg=EdDSA`, `issuer=<node_id>`, `subject=<capsule_id>`. Signing key generated on first run at `keys/node-key.pem` — **self-attested, not bound to any real node identity or hardware root**; a real deployment would bind the signing key to the node's actual identity (issue #1233's own "the signing key must be bound to a trusted node identity, owner policy, or hardware attestation"). |
| "hash-chained per node" | `chain.parent_capsule_id` + `chain.relation="confirms"` | Spec-native (§5.4.4). Each capsule after the first in a node-run chains to the prior one via `relation="confirms"` — used here for same-node **sequential ordering**, not the approved→executed→confirmed semantic the same relation carries elsewhere; `agent-action-capsule verify --store` recomputes and checks the whole chain. |
| fingerprint / TEE evidence (issue steps 4–5, explicitly *not* built here) | `model_attestation.compute_attestation["x-mesh-poc-v1"].evidence_refs.{statistical_fingerprint,tee_attestation}` | **Typed reference fields, present but empty** (`{"type": ..., "digest": null, "context": null}`) — exactly Steven's "rides as a typed reference (digest + declared context) inside the same record" framing. Populating these later upgrades the evidence a record carries without changing the record shape — the mechanism-agnostic pitch. |

### Extension note (why some fields aren't first-class yet)

`effect.request_digest` and `effect.response_digest` are ratified §5.2
fields — this PoC uses them for exactly their defined I/O-digest semantics,
per [[capsule-emit-mesh-poc]]'s own boundary rule: never repurpose
spec-defined fields. `client_nonce`, `model_name_digest` (and the Python
path's `model_package_digest`), `serving_provenance`,
`generation_parameters`, and the evidence-reference slots are **not yet
registered fields**. They ride inside `model_attestation.compute_attestation`
— a block the reference library itself documents as a free-form,
best-effort dict (`contracts.py`: `"compute_attestation is best-effort from
inference metadata"`) — under an explicit `x-mesh-poc-v1` namespace, so
nothing here is silently presented as ratified spec. A real proposal would
go through REGISTRY.md §12 ("Specification Required") before any of this
graduates past illustrative.

## Two IETF draft citations

1. **`draft-mih-scitt-agent-action-capsule-02`**, "An Agent Action Capsule
   Profile for SCITT" — the capsule schema, lifecycle, chain-linkage, and
   registries this PoC builds against.
   `agent-action-capsule/spec/draft-mih-scitt-agent-action-capsule-02.md`
2. **`draft-mih-sokolov-scitt-payload-binding-00`**, "Canonical Payload
   Binding: A Signed Statement Construction Profile" — canonicalization and
   typed-digest-reference conventions relevant to how `request_digest` /
   `output_digest` are computed and how the evidence-reference slots are
   shaped.
   `agent-action-capsule/spec/draft-mih-sokolov-scitt-payload-binding-00.md`

## What was actually verified (not just claimed)

### Live run (real mesh-llm node + real goose, 2026-08-11)

The run in "Live demo" above, independently confirmed this session:

- **6 real capsules across 2 independent ledgers**, from one `goose run`
  task against a real local mesh-llm node: 4 inference receipts
  (`ledger-live/capsules.jsonl`, sidecar / `/v1` boundary) + 2 action
  records (`ledger-live/goose-actions.jsonl`, capsule-emit-goose / tool-call
  boundary).
- **Both ledgers verify `ok=True`** with the real CLI —
  `agent-action-capsule verify --store ledger-live/capsules.jsonl` (4/4) and
  `agent-action-capsule verify --store ledger-live/goose-actions.jsonl`
  (2/2).
- **The inference-receipt stream chains correctly**: capsule 1 standalone,
  capsules 2–4 each `chain.parent_capsule_id` → the previous capsule's
  `capsule_id`, `ledger_mode=chained`, checked by the CLI's store-mode pass.
- **Both bundle permalinks build and locally check-verify** —
  `capsule-emit permalink --ledger <ledger> --bundle --check` reports 4/4
  and 2/2 VALID respectively (see `ledger-live/permalink-*.txt`).
- **The tool-call → action-record chain is faithful, not narrated**: the
  goose session's own final summary ("currently healthy", "reference
  CAP-mo-1") matches the *real* return values of `get_node_status` /
  `submit_capacity_request` byte-for-byte — confirming the model actually
  called the tools (via the sealed capsules) rather than hallucinating a
  plausible-sounding answer, which is exactly the failure mode the "Honest
  limitations" tool-calling section above caught and fixed.
- **The streaming-compatibility fix does not weaken the attestation**:
  confirmed by reading the sidecar's own sealed capsules — `response_digest`
  is computed from `reassemble_streamed_response()`'s output (the raw
  reassembled response) before `normalize_for_client()` ever runs; the
  client-facing normalization only affects what's forwarded to goose.

### Mock-node smoke test (kept for a network/model-free run)

Run `python3 run_demo.py` — it starts the fixture node + sidecar in-process,
sends 4 requests (3 normal, 1 deliberately triggering a refusal via the
`TRIGGER_GUARDRAIL_REFUSAL` marker), and writes `ledger/capsules.jsonl` +
`ledger/signed-statements/*.cose` + `ledger/demo-transcript.txt`.

Independently confirmed, this session (commands + full output in
`ledger/demo-transcript.txt` and the outbox report):

- **4 requests → 4 capsules.** 3 `effect.status="confirmed"` /
  `verdict_class="executed"`; 1 `effect.status="failed"` /
  `verdict_class="errored"` for the deliberately triggered refusal — see
  "the refused-request case" below.
- **All 4 verify with the real `agent-action-capsule verify` CLI**
  (`agent-action-capsule verify --store ledger/capsules.jsonl`), not just the
  library's `verify()` function called from Python.
- **All 4 chain correctly** — each capsule's `chain.parent_capsule_id`
  matches the previous capsule's `capsule_id`, checked both by the CLI
  store-mode pass and by `run_demo.py`'s own chain walk.
- **All 4 COSE_Sign1 signatures cryptographically verify** against the demo
  public key (`scitt_cose.verify_sign1`), independent of `verify()`.
- **Negative controls (mutants) confirmed the checks actually reject
  tampering**, not just pass the happy path: (a) flipping a byte in
  `effect.response_digest` post-seal flips `verify().ok` to `False` with
  finding `capsule_id_mismatch`; (b) flipping a byte inside a signed
  statement's payload makes `scitt_cose.verify_sign1` raise `CoseError:
  signature verification FAILED (InvalidSignature)` instead of silently
  accepting it.

### The refused-request case (issue #1233 step 7's seam)

Request 4 sends the `TRIGGER_GUARDRAIL_REFUSAL` marker; the fixture node
returns a 400 in mesh-llm's real `ErrorResponse` shape, modeling a
guardrails-style pre-dispatch rejection. The sidecar still digests and
records it — this is deliberately the "checked and failed" case issue
#1233 step 7 asks to keep distinct from "evidence absent." Two corrections
made along the way, both caught by the reference library's own invariants
(not by manual review) and worth carrying into the call as informative:

- `verdict_class="denied"` (what a "pre-dispatch policy rejection" naively
  suggests) is rejected by `parse.py`'s §5.4.2 invariant when paired with
  `effect.status="failed"` — `"denied"` specifically means *no dispatch
  occurred*, and the sidecar can't honestly claim that from outside the
  process (it only knows it sent a request and got an error back). The
  correct, verified-passing value is `verdict_class="errored"` ("ran and
  threw"). This is exactly the distinction issue #1233 step 7 asks for,
  enforced by the spec rather than by convention.
- JSON floats (temperature, top_p, ...) are rejected inside any
  digest-committed field (§5.1: "requires exact decimal strings"); the
  sidecar stringifies floats before they enter a digested block
  (`_stringify_floats` in `capsule_sidecar.py`).

## Bilateral attestation demo (mechanism demonstration only)

`bilateral_demo.py` implements the four moves of
[`draft-mih-agent-bilateral-attestation-01`](https://datatracker.ietf.org/doc/draft-mih-agent-bilateral-attestation/)
against the mock node — no live mesh-llm node required.

```bash
python3 bilateral_demo.py
```

The demo shows both paths side by side and must be never confusable:

| Path | What happens | Derived cross_party_rung |
|---|---|---|
| **Bilateral** | Client signs request attestation; node verifies it; capsule carries `cross_party.initiator_ref`; client signs ack of returned `capsule_id` | `full_bilateral` |
| **Degraded** | Client sends no attestation; node proceeds unilaterally; no `cross_party` block in record | `unilateral_fallback` |

The `cross_party_rung` is **derived from the record's own bytes** using
`derive_cross_party_rung()` — the producer never asserts it. The derivation
returning `unilateral_fallback` when evidence is absent is the key test.

### The four moves

1. **Request attestation (client → node):** client signs a commitment over
   the request digest, a nonce, a timestamp, a validity window, and a
   max_tokens authorization bound. Sent in HTTP headers alongside the
   request.

2. **Node evaluation (before dispatch):** the sidecar verifies the signature,
   checks the validity window has not expired, checks that the request digest
   matches the actual body, and checks the request does not exceed the
   authorized token bound. Failure at any check falls through to the degraded
   path without aborting the request.

3. **Action attestation (node → record):** the action capsule carries a
   `cross_party` evidence block inside `x-mesh-poc-v1` with `initiator_ref`
   (sha256 of the request attestation bytes), `correlator` (the shared nonce),
   and `substantive: true`.

4. **Acknowledgment (client):** after receiving `X-Capsule-Id` in the
   response header, the client signs an ack over the `capsule_id` and the
   original nonce. Together with the action capsule, this establishes
   `full_bilateral`.

### Identity limitation — stated here, in the run output, and in the record

> ⚠ **The keys used in this demo are self-generated and self-held.** They are
> not bound to any trusted root or third-party-issued credential.
> `draft-mih-agent-bilateral-attestation-01` §4.1 states that first-use
> acceptance of a self-held key MUST NOT be treated as conformant bilateral
> attestation. **This demo shows the mechanism, not a conformant deployed
> bilateral exchange.** Every action capsule the bilateral demo emits carries
> an `identity_limitation` field in its `x-mesh-poc-v1` block stating this
> explicitly. Do not cite the output of this demo as conformant evidence of
> bilateral attestation.

The `cross_party` block and `derive_cross_party_rung()` function correspond
to fields defined in the forthcoming revision of
`draft-mih-scitt-agent-action-capsule`. They are carried inside the existing
`x-mesh-poc-v1` PoC extension namespace — same convention as the other
non-yet-ratified fields in this demo — and explicitly not presented as
ratified spec fields.

## Files

```
poc/
  README.md                     this file
  capsule_sidecar.py             the PoC itself: proxy + emit + sign + chain (+ SSE streaming + bilateral evaluation)
  bilateral_demo.py              four-move bilateral attestation demo (mechanism demonstration; non-conformant identity)
  model_identity.py              model_package_digest per issue #1233's own formula
  build_real_model_package.py    real model-package.json from an actual downloaded GGUF -- the live-demo path
  build_model_package.py         fixture model-package.json -- the mock-node smoke-test path only
  mock_mesh_node.py              schema-accurate /v1 stand-in -- mock-node smoke-test path only
  run_demo.py                    orchestrates the mock-node smoke test + verification pass
  run_live_demo.sh               orchestrates the real mesh-llm + real goose live demo end to end
  checkpointing.py                Layers 1-2: LogSource adapter, cadence + reconnect checkpointing, witness-state rendering
  checkpoint.example.toml         example [checkpoint] config for --checkpoint-config (opt-in, empty ts_urls by default)
  run_checkpoint_demo.py          orchestrates the checkpoint demo: exchanges -> MMR -> checkpoint -> registry -> offline verify
  run_real_deployment_checkpoint_demo.sh  real mesh-llm-host-runtime + checkpointing, end to end (no goose leg)
  verify_real_deployment_checkpoint.py     offline verify + rollback-mutant proof for the real-deployment ledger
  tools/
    replay_spot_check.py          C2a replay spot-check harness (temp-0/fixed-seed re-run comparison; see above)
  goose/
    server.py                    capsule-emit-goose: the action-record MCP extension (tool-call boundary)
  model-package/
    model-package.json           fixture manifest (mock-node path)
    model-package.live.json      real manifest, built from the actual downloaded GGUF (live-demo path, gitignored -- regenerate)
  keys/                          demo-only Ed25519 node signing keypair (self-attested)
  ledger/                        generated by run_demo.py (mock-node smoke test)
  bilateral-ledger/              generated by bilateral_demo.py: capsules.jsonl, bilateral-capsule.json,
                                  degraded-capsule.json, client-ack.json, bilateral-transcript.txt
  ledger-live/                   generated by run_live_demo.sh: capsules.jsonl, goose-actions.jsonl,
                                  permalink-*.txt, goose-session-transcript.txt (gitignored -- regenerate per run)
  ledger-checkpoint-demo/         generated by run_checkpoint_demo.py: capsules.jsonl, checkpoints.jsonl,
                                  checkpoint-demo-transcript.txt (committed fixture, real anchor registration)
  ledger-real-deployment/         generated by run_real_deployment_checkpoint_demo.sh: capsules.jsonl (real
                                  mesh-llm-host-runtime inference), checkpoints.jsonl, real-deployment-transcript.txt
                                  (committed fixture; live anchor registration staged, not executed -- see above)
  tests/
    test_forwarded_copy_and_keys.py  sidecar pure-function tests (streaming, key generation)
    test_bilateral_demo.py           bilateral attestation tests (rung derivation, all failure modes, e2e)
    test_checkpointing.py            Layers 1-2 tests: LogSource, cadence, reconnect self-heal, witness-honesty mutants
    test_replay_spot_check.py        C2a replay spot-check harness tests (both directions, scope guardrail)
    replay/                          vector suite for the replay spot-check harness (matched + mismatched pairs)
  bench/
    run_benchmark.py               A/F benchmark harness (one-command; python3 bench/run_benchmark.py)
    results/                       machine-readable JSON result files (environment-labelled, timestamped)
../mesh-llm-src/                read-only research clone of Mesh-LLM/mesh-llm (no modifications)
../openai-endpoint-src/         read-only research clone of Mesh-LLM/openai-endpoint (no modifications)
../bin/                         NOT in this repo; see "Obtaining mesh-llm and goose" in the Live demo section above
```

## What the call strawman should show

1. **The live composition, not the mock**: real `mesh-llm serve` on the
   supported mesh inference port + real `goose` (via `mesh-llm goose`) + real
   `capsule-emit-goose`, one task run, two independently verifiable chained
   record streams. This is mic's two codebases (mesh-llm, capsule-emit)
   composing, live — see "Composing capsule-emit-goose," "Live demo," and
   [`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md).
2. The receipt-tuple → capsule field mapping table above — the concrete
   "what we'd commit to a record" artifact for the discussion.
3. The architecture finding (sidecar, not plugin) — worth surfacing early
   since it corrects the "same pattern as your metrics plugin" framing
   Steven used in his own issue comment; better to align before the call
   than to have i386 catch the mismatch live.
4. The empty typed-reference slots for fingerprint/TEE evidence as the
   concrete instantiation of "mechanism-agnostic... upgrades the evidence a
   record carries without changing the wire format."
5. The honest refused-request framing as a live example of step 7's
   "absence of record" vs. "record of absence" distinction, including that
   the spec's own invariants (not manual care) caught the first attempt's
   imprecision (`denied` → `errored`).
6. The small-model tool-calling compatibility finding (SSE streaming,
   content+tool_calls, the imperative-vs-narrative prompt-phrasing
   difference) as a live, honest example of what building against a REAL
   local model surfaces that a mock never would — good, specific texture
   for the call, not a weakness to hide.

## Benchmark notes

`bench/run_benchmark.py` reports p50 and p95 only. p99 is omitted: n=100 cannot support a defensible 99th percentile (that needs n≈1000, not worth the runtime for an order-of-magnitude signal — the published n=100 p99 is statistically the sample maximum).

## License

Apache-2.0 — see [LICENSE](LICENSE).
