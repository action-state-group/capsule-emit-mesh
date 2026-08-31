# capsule-emit-mesh

Neutral accountability for [Mesh-LLM](https://github.com/Mesh-LLM/mesh-llm):
emit signed, hash-chained **Agent Action Capsules** for every request a Mesh-LLM
node serves — a durable, offline-verifiable inference receipt bound to the bytes
that were exchanged. This implements step 3 ("nonce-bound signed inference
receipts") of
[Mesh-LLM/mesh-llm#1233](https://github.com/Mesh-LLM/mesh-llm/issues/1233),
"Explore proof of inference and model-serving attestation," and offers a threat
model (step 1) alongside it.

> **New here?** Four layers, from plain to formal:
> 1. [**Can you trust a stranger to run your prompt?**](docs/CAN-YOU-TRUST-A-STRANGER.md)
>    — plain-language, no crypto background: what you'd see about a stranger's machine
>    and *how sure you can actually be*.
> 2. [**How the capsule mechanisms work**](docs/CAPSULE-MECHANISMS.md) — the moving
>    parts (local ledger → MMR → signed checkpoint → witness), checkpoint-vs-push, CPB,
>    and — crucially — **where your data stays local**.
> 3. [**The verification chain: what each link proves, and how**](docs/VERIFICATION-CHAIN.md)
>    — the cryptographic chain link by link (hash → signature → checkpoint → witness
>    receipt), with the RFCs.
> 4. [**TRUST-MODEL.md**](docs/TRUST-MODEL.md) — the full threat model, assurance
>    classes, and per-role questions (§2.2–2.5).

Two integration paths ship here (see below): a **native Rust
`admission-policy-plugin` + `capsule-producer`** on the serving path (primary —
it seals the host's own `openai.exchange.v1` lifecycle event), and a **Python
`capsule_sidecar.py` reverse-proxy** (a zero-core-change observer, still valid as
an alternative). Published as `action-state-group/capsule-emit-mesh`. Everything
here is PUBLIC-safe (Apache-2.0, see [LICENSE](LICENSE)), and contains no
trust-index / scoring / reputation / pricing language — a fail-closed neutrality
CI gate (`.github/neutrality_scan.py`) enforces it.

The relationship to Mesh-LLM is offered, not asserted: the native plugin is built
against Mesh-LLM's actual published plugin protocol and rides on a fork
(`StevenMih/mesh-llm`, PRs #1/#2/#3 on top of upstream #1437's hooks); an
[on-list update](https://github.com/Mesh-LLM/mesh-llm/issues/1233) tracks #1233;
and a real bug found while wiring the split path is filed as
[Mesh-LLM/mesh-llm#1547](https://github.com/Mesh-LLM/mesh-llm/issues/1547).
Nothing here asserts adoption by anyone.

> **Signing keys.** This repository ships no private key. Both paths generate an
> Ed25519 node key on first run (mode 0600, gitignored). The public half of the
> key used for the committed `ledger/` and `ledger-live/` runs is included so
> those artifacts stay independently verifiable. A generated key is
> **self-attested and not bound to any real node identity or hardware root** (see
> [`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) §Class B and "Field mapping"
> below).

> `keys/` — public half of the demo node key. Self-attested; not bound to any
> node identity or hardware root. See
> [*About the entries in `ledger-live/`*](ledger-live/README.md) for what the
> anchored entries do and do not establish.

---

## A ledger of witnessed capsules — what it gives a Mesh-LLM node

A capsule is a signed, **contemporaneous** record of a single served exchange —
made at the moment the node serves it, not reconstructed afterward, which is what
lets it stand as *evidence* rather than a later account. It is *content-addressed*
(the `capsule_id` is a hash of the record's own bytes, so changing any field
changes the id). The point is not one receipt; it is the **history** that
accumulates, and what each of Mesh-LLM's own roles can do with it.

**`seal()` captures the machine's serving profile automatically.** When a node
serves a request, the seal picks up — *from the exchange itself* — the **model**,
**quantization** and **hardware** (GPU / VRAM / SoC) and the **token usage**, and
commits every field into the content-addressed `capsule_id`. Honestly, though:
**which of those fields are populated depends on what the serving path
surfaces.** On the plugin's observe path some fields are genuinely absent —
Mesh-LLM's `openai.exchange.v1` event and OpenAI-shaped response body do not
carry quantization or hardware, so those record as `"unknown"` / `null` rather
than being fabricated. The host-served-body work in fork PRs #2/#3 fills `model`
and `usage` on the host path; the Rust producer attests a `model_name_digest =
sha256(model_name)` — **named as a name hash, never overclaimed as a weights or
package binding.** Absent is recorded as absent.

**The ledger accumulates the history.** Each request a node **serves**, and each
time it **shares** compute for others, becomes a signed, hash-chained capsule in
that node's local ledger. Optionally the ledger is **checkpointed to a neutral
witness** (a SCITT Transparency Service the node does not host), so the history is
tamper-evident against something the node does not control — see "Checkpointing"
below.

**What that history does for each Mesh-LLM role:**

- **Requester** — verify *offline* that you actually got the model / quant /
  hardware you were routed to (not a substitute), and that the response you
  received is the response the node signed. The answer is bound to the record;
  nobody has to take the node's word for it.
- **Provider / sharer** — a durable, signed record of exactly what you served is
  *your own defence* in a dispute — **non-repudiation that cuts both ways**
  (neither side can later deny what happened). The same contemporaneous receipt a
  requester checks you with is the proof you served honestly: your record, not
  someone else's word (see [`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) §2.3
  P2/P6).
- **Coordinator (Skippy)** — the ledger is **evidence for or against a node**:
  - **Did it serve what its `PeerAnnouncement` advertised?** This is the built
    **verify-after-advertise** reconciliation — advertised-vs-served, in three
    states, **re-derived from the record's own bytes** (`docs/TRUST-MODEL.md`
    §12.3). An advertised model name is a *claim*; the `serving_provenance`
    record is the *evidence* of what actually ran. A mismatch is an attributable,
    portable evidence item, not a score decrement.
  - **Is the output even plausible for the config it claims?** A separate,
    harder question that reconciliation does *not* answer. Answering it well
    needs a statistical reference model of expected output per
    `(model, quant, hardware)` — out of scope. What ships today is only
    **scaffolding**: a typed seam `check_output_against_config(...)` plus a
    **trivial** token-rate / output-shape baseline behind it. Every result is a
    `prototype_cross_check` — **probabilistic, a prototype, NOT "verified", and
    it NEVER "gets caught"**: it raises or lowers confidence, never a pass/fail
    verdict. Built to be attacked before the real model is (see
    [`docs/PROTOTYPE-CROSS-CHECK.md`](docs/PROTOTYPE-CROSS-CHECK.md)).
  - **In a split, which node held which stage / layer range** — the coordinator
    receipt (a *shape*, see the honesty note below) is built to cite each hop's
    bundle in stage order.
  - A portable track record routing can rest on — so routing decisions rest on
    **evidence, not claims**. Today a topology is "a serialized structure with no
    signature and no issuer" (`docs/TRUST-MODEL.md` §2.4 C2); the accountability
    layer is what signs it.

Those four roles — and the **specific questions each one wants answered**, with the
evidence that addresses each — are set out in full in the threat model:
[`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) **§2.2** (requester), **§2.3**
(provider), **§2.4** (coordinator), **§2.5** (third-party auditor / court).

**History is evidence a relying party computes over — not a reputation score we
compute.** This is a neutrality invariant (`docs/TRUST-MODEL.md` §7; and
Mesh-LLM's own `NODE_REP.md` reaches the same conclusion): no scoring, ranking,
or reputation-index. Present the evidence; policy decides; nobody is the authority
for the computation. Likewise the record **counts** (tokens, compute time) but
**must not price** — no currency, rate, or invoice (`docs/TRUST-MODEL.md` §6).

**Split / stages, honestly (read before citing).** The coordinator receipt is a
**record *shape* built and adversarially verified in this layer**, not yet wired
to a real Mesh-LLM split. Mesh-LLM emits **no per-stage lifecycle events** — the
plugin seals **one whole-exchange capsule, single-node** — and the real split
path currently **crashes on the tail stage** (worker SIGSEGV in
`graph_reserve`/`build_lora_mm`), filed as
[Mesh-LLM/mesh-llm#1547](https://github.com/Mesh-LLM/mesh-llm/issues/1547). So:
per-stage attestation is real **as a shape + verifier**; wiring it needs
per-stage lifecycle events — a small unlock, not a rewrite. Do **not** read this
as "we have per-stage sealed records from real splits." We do not.

---

## Two integration paths

The receipt #1233 asks for is a digest-committed record of *what the node
served*. There are two honest ways to observe a served exchange, and both ship
here. They see different things, and that difference is the whole design choice.

### Path 1 (primary) — native Rust `admission-policy-plugin` + `capsule-producer`

A real `mesh-llm-plugin` plugin on the serving path. It seals the host's own
`openai.exchange.v1` lifecycle event and rides the #1437 hooks (fork
`StevenMih/mesh-llm`, PRs #1/#2/#3). This is a **first-party integration**, and it
is what sealed the current demo capsules.

- **`plugins/admission-policy`** — binds against Mesh-LLM's *actual* published
  plugin protocol (`mesh-llm-plugin` on crates.io: a length-prefixed protobuf
  `Envelope` over a Unix socket / named pipe — **not** gRPC/HTTP2; see the crate's
  `PROTOCOL-NOTE.md`). It registers an `inference` provider endpoint, can deny
  exchanges by blocked model prefix, and — via the #1331 lifecycle-hook broadcast
  (`mesh_channel("openai.exchange.v1")`) — receives the host's own terminal-event
  envelope for each exchange, wired into the host's raw-proxy dispatch path
  (`mesh-llm-host-runtime`'s `network/openai/ingress.rs`), not just a test
  stand-in.
- **`plugins/capsule-producer`** — the Rust capsule producer itself: RFC 8785 JCS
  canonicalization, COSE_Sign1 (`alg=EdDSA`), per-node chaining, a restart-safe
  durable ledger (byte-identical on-disk shape to the Python path, so either
  side's tooling reads the other's ledger), key persistence + rotation, an
  optional Transparency-Service anchor client, and offline verification.

Both crates carry real, adversarial `#[ignore]`d end-to-end tests that drive a
capsule through an **actual `mesh-llm-host-runtime` process**, offline-verify it,
and **cross-language-verify** the Rust-written ledger against the Python
`scitt-cose` / `agent_action_capsule` reference (and an independent Go verifier) —
then mutate the signature and the observed response digest to confirm both are
caught. See each crate's README, `MILESTONE-*-REPORT.md`, and
`plugins/admission-policy/REAL-HOST-VERIFICATION.md`.

**What the plugin can see:** the host's `openai.exchange.v1` exchange event and
the OpenAI-shaped response body — enough for `request_digest`, `response_digest`,
`model` (host path), `usage` (host path), and `model_name_digest`. What that event
does **not** carry — quantization, hardware — records honestly as absent.

### Path 2 (alternative) — the Python `capsule_sidecar.py` reverse-proxy

A reverse HTTP proxy in front of Mesh-LLM's own `/v1/chat/completions`. It
forwards every request unmodified and records a digest-committed capsule of what
it observed **at the wire**. It requires **zero changes to Mesh-LLM's code**,
works against a release binary or a `cargo run` build identically, and is honestly
labeled as an **external observer**, not a first-party integration.

**What the sidecar can see:** the full request and response JSON at the wire —
which is *more* raw material than the host's exchange event surfaces, but from
*outside* the host rather than from inside its lifecycle. Neither vantage is
strictly superior: the plugin is native and rides the host's own event; the
sidecar sees the complete wire bodies but is an observer.

The request is always forwarded unmodified. The response is forwarded unmodified
for non-streaming calls; for streaming calls the sidecar buffers the real upstream
SSE stream, seals a capsule over it exactly as received, then re-emits a
synthesized SSE stream from a client-compatibility-normalized copy of that same
response — the capsule always attests the literal upstream bytes (see "Honest
limitations").

```bash
mesh-llm serve --gguf /path/to/model.gguf --port 9337   # --gguf needs a real (non-symlink) file path
python3 capsule_sidecar.py --upstream http://127.0.0.1:9337 --listen-port 8089 \
    --runtime-artifact /path/to/mesh-llm-binary --runtime-label "mesh-llm real node" \
    --manifest model-package/model-package.live.json   # built from the real model -- see build_real_model_package.py
# point your OpenAI client at http://127.0.0.1:8089/v1 instead of :9337/v1
```

### Why not "the same pattern as your metrics plugin" (the original framing)

Steven's #1233 comment framed this as "the same capability-plugin pattern as your
metrics plugin." That framing needed correcting — and the correction is worth
carrying to the call, since it is now *resolved*, not open. Mesh-LLM's capability
plugins (`metrics`, `openai-endpoint`) are capability *providers* the host calls
*into*; they are not observers of the host's own inbound `/v1` traffic, and the
native serving-plugin ABI delivers token arrays, never the raw OpenAI
request/response JSON a #1233 receipt digests. The path that *can* see both sides
is an **in-process hook** on the host's OpenAI frontend (`OpenAiHookPolicy` /
`HookedOpenAiBackend`). The earlier PoC concluded that exploiting it meant a fork
with no installable plugin and no PR — so it shipped the sidecar. **That
conclusion is now superseded: we built the native plugin.** It rides upstream
#1437's hooks on a fork (`StevenMih/mesh-llm`, PRs #1/#2/#3), seals the host's
`openai.exchange.v1` event, and is Path 1 above. The sidecar remains a valid
zero-core-change alternative.

---

## What issue #1233 actually asks for

James Dumay (i386) filed #1233 decomposing "proof of inference" into three
separable claims — model identity, execution identity, behavioral identity — and
proposed a progression from (2) precise model/package digests through (3)
nonce-bound signed receipts, (4) statistical fingerprints, (5) TEE evidence, to
(6) a signed capsule history. Steven's comment on the issue is the design pitch
this repo implements:

> Step 3 is the layer we build... Your receipt tuple is an agent-action record
> where the tool is the model: we'd emit it as a signed capsule at the /v1 serve
> boundary — with the client nonce, request digest, model_package_digest, runtime
> digest, params, and output digest as committed fields, hash-chained per node.
> Apache-2.0, two IETF drafts behind the format... a fingerprint result or TEE
> quote rides as a typed reference (digest + declared context) inside the same
> record, so steps 4 and 5 upgrade the evidence a record carries without changing
> the wire format.

The receipt tuple, verbatim from the issue body:

```
receipt = sign_node_key(
  client_nonce, request_digest, model_package_digest,
  runtime_digest, generation_parameters, output_digest, timestamp
)
```

Both paths build exactly that record, as an Agent Action Capsule. The
["Field mapping"](#field-mapping-1233s-receipt-tuple--capsule-record) table below
is the concrete "what we'd commit to a record" artifact.

## A threat model, alongside the receipt (step 1)

[`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) writes #1233's step 1 — *"define the
threat model and assurance levels"* — and widens it in one direction: a mesh has
**two** strangers in it, and the provider's side (what a node operator risks by
lending their machine) is the half not yet written down. It enumerates what the
requester, provider, coordinator and a later-arriving third party each fear, maps
each to the evidence that would address it, and states honestly which of those are
built, partly built, or not built. It is the source of truth for the neutrality
discipline this README follows (three states never two; claim ≠ evidence; count
but don't price; evidence not score). Read §6, §7 and §12 before editing anything
here.

## Composing capsule-emit-goose: two chained record streams

The `/v1` inference-receipt layer composes with **capsule-emit's own Goose
integration** (`goose/server.py`) at the *tool-call* boundary — two record streams
from one session:

```
goose (real CLI process)
  │
  ├─ LLM turns ──▶ mesh.json custom provider (base_url = sidecar) ──▶ capsule_sidecar.py ──▶ real mesh-llm node
  │                  every /v1/chat/completions call sealed here        (inference receipts, hash-chained per node)
  │
  └─ tool calls ─▶ goose/server.py (stdio MCP extension)
                     every tool call sealed here (action records)
```

One `goose run` task against a real local Mesh-LLM node produces **two
independently verifiable, independently chained** capsule ledgers:

- `ledger-live/capsules.jsonl` — inference receipts (the `/v1` boundary, #1233's
  receipt tuple)
- `ledger-live/goose-actions.jsonl` — action records (the tool-call boundary)

Each verifies independently: `agent-action-capsule verify --store <ledger>.jsonl`.
They are deliberately **not** cross-chained (different domains — one attests the
model call, the other the agent's tool call around it); a typed binding reference
between the two is a natural next step, not built here.

## Live demo (real mesh-llm + real goose)

Everything below is a real local process. No mock server, no fixture model, no
fabricated bytes. `run_live_demo.sh` orchestrates all six steps.

> **Obtaining mesh-llm and goose.** The `mesh-llm` binary is **not included in
> this repository**. Download the release tarball (v0.75.1 or later) from
> https://github.com/Mesh-LLM/mesh-llm/releases. Verify the sha256 before running
> (`sha256sum mesh-bundle/mesh-llm`; v0.75.1 darwin-arm64:
> `26a28ae31cd1911be3e71b1ef612cb4166f0bff8380be461769f26083c077223`). For goose
> (v1.46.0+), see https://github.com/aaif-goose/goose. Install Python deps with
> `pip install -r requirements.txt`.

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

# 5. the real, documented `mesh-llm goose` workflow wires goose's provider config at the sidecar port
mesh-llm goose --port 8089 --model bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M

# 6. a real, scripted goose run drives both record layers in one task.
# CAPSULE_ANCHOR=false (the default) keeps capsules locally verified only.
GOOSE_PROVIDER=mesh GOOSE_MODEL=bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M \
goose run --no-session --no-profile --max-turns 8 \
  --with-extension "CAPSULE_LEDGER=ledger-live/goose-actions.jsonl CAPSULE_OPERATOR=capsule-emit-mesh-demo CAPSULE_DEVELOPER=goose@v1.39.0+mesh-llm CAPSULE_ANCHOR=false python3 goose/server.py" \
  -t "Call the get_node_status tool now with node_id=mesh-node-demo-1. After you receive its result, call the submit_capacity_request tool now with node_id=mesh-node-demo-1, gpu_hours=4, reason=inference_demand_spike. You must call both tools before writing any summary text."
```

`ledger-live/capsules.jsonl` ends with chained, verified inference-receipt
capsules for this run; `ledger-live/goose-actions.jsonl` has the action-record
capsules for the real tool calls. Both verify `ok=True` — see "What was actually
verified."

**Why the task prompt is written as blunt, sequenced imperatives** rather than a
natural-language narrative — see "Honest limitations": that phrasing is a
*finding* from running against a real 7B model, not a stylistic choice.

## Checkpointing: local MMR + signed checkpoints (Layers 1-3, opt-in)

Layer 0 (a signed capsule per exchange) is always on. This section adds strictly
optional, strictly stronger layers, consuming `capsule_emit.checkpoint` as a
library — nothing here vendors or reimplements MMR/checkpoint logic:

- **Layer 1** — a local, append-only Merkle Mountain Range (MMR) over this node's
  own `capsules.jsonl`, so any individual capsule can later be proven included
  under a later checkpoint without re-hashing the whole log.
- **Layer 2** — a periodic, signed checkpoint (a 32-byte MMR root, signed with the
  same Ed25519 key that signs the node's capsules) committing everything appended
  since the previous checkpoint.
- **Layer 3** — an independent **witness** (any conforming SCITT Transparency
  Service accepting the COSE-wire `kind="cll-checkpoint"` shape, e.g. the free
  public-good checkpoint-only tier at `witness.agentactioncapsule.org`) co-signs
  the checkpoint. Opt-in, per URL, and **never on the serving path**: an
  unreachable witness leaves the checkpoint locally-committed (self-checkpointed),
  never blocks or fails the request.

A node opts in by passing `--checkpoint-config` with a `[checkpoint]` TOML table
(see `checkpoint.example.toml`). A node that never passes this flag pays zero cost.
See `checkpointing.py` for the adapter and `CheckpointState` for the cadence +
reconnect logic.

**Two logs, each independently checkpointed.** A mesh node normally runs two
single-writer ledgers — the sidecar's own and the Rust plugin's
(`plugins/capsule-producer`). `--checkpoint-config` opts in the sidecar's log;
`--plugin-ledger-dir` (plus optionally `--plugin-checkpoint-config`) opts in the
plugin's log too, persisted to its own sibling `checkpoints.jsonl` — this process
never writes into the plugin-owned `capsules.jsonl`.

**Offline nodes: latest-checkpoint-on-reconnect.** A node that goes offline keeps
appending locally; on reconnect it emits **one** checkpoint covering everything
accrued since the last witnessed one (the new checkpoint's `prev_size`/`prev_root`
chain from the old), so a consistency proof spans the whole gap in one step.
Entries appended while offline are provably included once the reconnect checkpoint
lands; until then they exist only in the local, unwitnessed log — and that wait is
reported, not hidden (see `describe_witness_state()`).

**Witness grading — never overstate what a checkpoint achieved.** Status lines
distinguish three strictly increasing levels and never round up:

1. **self-checkpointed** — locally committed and signed; no outside party has seen
   it.
2. **peer-witnessed** — another mesh node carried this checkpoint into its own
   record. Documented as the decentralized option; **not built here** (the default
   integration path is checkpoint → operated witness).
3. **independently witnessed** — at least one registered SCITT Transparency
   Service has actually countersigned the checkpoint's digest.

`describe_witness_state()` renders exactly one of these plus any lag, and is
covered by a mutant test asserting it can never say "witnessed" for an empty
witness list.

**What witnessing proves, and what it never proves.** A witness proves the
checkpoint — and everything under it — has not been silently rewritten after the
fact: **non-rewrite of the log structure**. It proves **nothing about the
content** of any capsule under that root — a witnessed checkpoint over false claims
is just as witnessed as one over true claims. Do not let "witnessed" drift into
"verified honest" (the same discipline this repo applies to `client_nonce`: a
nonce proves freshness, not identity).

**What was actually run.** `run_checkpoint_demo.py` exercises exchanges → capsules
→ local MMR → cadence- and reconnect-triggered checkpoints → registration at the
live public witness → offline inclusion + receipt verification via
`scitt_cose.cll`. `run_real_deployment_checkpoint_demo.sh` does the same driven by
a **real, locally-built `mesh-llm serve`** process against a real GGUF model (no
goose leg), then hands off to `verify_real_deployment_checkpoint.py` for an
offline, ledger-files-only verify pass plus a rollback/fork mutant proof. Live
witness registration is **staged, not executed** by default;
`ledger-checkpoint-demo/` and `ledger-real-deployment/` are committed transcripts
so the claims are checkable against real artifacts.

## Replay spot-check harness (C2a)

`tools/replay_spot_check.py` implements the C2a mechanism from
[`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) §3 Class C: fire the same
temperature-0, fixed-seed request twice and compare the two responses on the domain
the record already commits to — `response_digest`. It answers one question only —
do these two runs match on that domain — and is **deliberately not a scorer**: the
result carries `match: true`/`false` and the two digests, never a confidence,
trust, or reputation value. A mismatch is grounds to investigate, not a verdict
(sampling non-determinism and cross-hardware execution are named, expected confounds
in TRUST-MODEL.md's C2a discussion).

```bash
# Offline: compare two already-captured response bodies
python3 tools/replay_spot_check.py compare response_a.json response_b.json
# Live: pin a request to temperature 0 + a fixed seed, fire it twice, compare
python3 tools/replay_spot_check.py live --upstream http://127.0.0.1:9337 --request request.json
```

## Honest limitations (read this before the call)

**Run history, for the record.** An earlier session built the sidecar entirely
against `mock_mesh_node.py` (a sandbox tool policy blocked executing the real
binary). Subsequent sessions ran against a real `mesh-llm serve` node and a real
`goose` session — see "Live demo" and
[`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md).
`mock_mesh_node.py` / `run_demo.py` are kept only as a network/model-download-free
smoke test, clearly labeled as fixtures.

**One `mesh-llm` CLI flag correction found by running it for real:** `--gguf` must
be a real file, not the symlink the Hugging Face cache normally hands you
(`snapshots/<rev>/<file>` → `blobs/<sha256>`) — resolve the symlink first
(`build_real_model_package.py` does this and hashes the resolved path).

> **Note — `--local-model-only` is a debugging endpoint, not for acceptance.** It
> bypasses the host-runtime OpenAI normalizer. The primary invocation uses the
> supported mesh inference port (`mesh-llm serve --gguf … --port 9337`). See
> [`docs/SUPPORTED-PORT-RERUN.md`](docs/SUPPORTED-PORT-RERUN.md).

**A real, live small-model/goose tool-calling compatibility issue, found and fixed
here.** Neither knowable without running it for real:

1. goose requests `stream: true`; the sidecar now buffers the real upstream SSE
   stream, reassembles it into one committed response object
   (`reassemble_streamed_response`), seals a capsule over that RAW object, and
   re-emits a synthesized SSE stream (`synthesize_sse`).
2. Hermes-2-Pro-Mistral-7B, driven by goose's own system prompt, sometimes returns
   a message with **both** a correct `tool_calls` array **and** a spurious
   `content` string (the model echoing a `<turn-budget>` tag back); goose's parser
   rejects that combination. Confirmed by reproducing it directly against mesh-llm
   outside goose — a real small-model quirk, not a sidecar or goose bug. Fix:
   `normalize_for_client()` drops `content` only when `tool_calls` is present,
   applied **only** to the forwarded copy — the capsule's `response_digest` still
   attests the literal, unmodified response. (Separately, mesh-llm's `tool_calls`
   carry no `id`; a synthetic one is minted only in the forwarded copy, same rule.)
3. A related finding: a natural-language "Step 1 / Step 2 / Step 3" prompt let the
   model narrate a plausible summary *without* calling either tool. Blunt,
   sequenced imperatives reliably drove real, verifiably-matching tool calls. A 7B
   local model needs more directive prompting than a frontier model — a property
   of the model, not the record layer.

**`model_package_digest` is computed from the real downloaded model** (Python
path). `build_real_model_package.py` hashes the actual GGUF (SHA-256 over the real
~4.4GB file, streamed). It intentionally omits `shared`/`layers` artifacts: this
demo serves a single GGUF via `--gguf`, not the Skippy layer-split format — a
manifest claiming layer artifacts here would be fabrication. **The Rust plugin path
attests only `model_name_digest = sha256(model_name)`**, truthfully named, because
the plugin only has the request's model *name*.

**`client_nonce`: what it establishes and what it does not.** A client nonce
establishes freshness — the node could not have precomputed or replayed a request
carrying a nonce it never saw. It says **nothing about who the requester is.** Do
not let "nonce" drift into "identity." The sidecar accepts `X-Capsule-Client-Nonce`
(`client_nonce_source: "client_supplied"`), mints a labeled fallback when absent
(`sidecar_generated_fallback` — which does **not** carry the freshness property),
and records a third tier `local_ingress` when Mesh-LLM's own ingress minted it one
hop upstream. `local_ingress` is a **routing hint, not authentication** — the
header is unauthenticated and nothing Ed25519-verifies it here (see
`docs/TRUST-MODEL.md` §2.2 R3).

**Anchoring: rehearsal runs verify locally only, by decision.** Anchoring posts a
digest (never payload) to a live shared Transparency Service — a real write to
shared infrastructure — and is **off by default**. The committed `ledger-live/`
capsules stay offline-verified only, per an explicit decision; anchoring happens
deliberately, once, against the real call artifact, not an earlier rehearsal.

## Field mapping: #1233's "receipt tuple" → capsule record

| #1233 receipt tuple field | Capsule field | Notes |
|---|---|---|
| `client_nonce` | `model_attestation.compute_attestation["x-mesh-poc-v1"].client_nonce` | See "client_nonce" above. Rides in the PoC extension namespace — see "Extension note." |
| `request_digest` | `effect.request_digest` | **Spec-native field** (§5.2 Effect Record). SHA-256 JSON-DIGEST (RFC 8785 JCS) over the canonicalized request body. The raw prompt is never stored — digest only, preserving prompt privacy. |
| `model_package_digest` (Python path) | `model_attestation.compute_attestation["x-mesh-poc-v1"].model_package_digest` | Computed by `model_identity.py` per the issue's formula: `sha256(canonical_manifest + artifact_digests + runtime_abi)`. Sourced from a real `model-package.json`, never fabricated. **Python producer only.** |
| `model_name_digest` (Rust plugin path) | `model_attestation.compute_attestation["x-mesh-poc-v1"].model_name_digest` | The live Rust plugin only has the request's model **name**, so it attests exactly `sha256(model_name)` under a **truthful** field name — renamed from an earlier `model_package_digest` that overclaimed a weights/package binding it never had. A name hash is named as a name hash. |
| serving provenance (what ran where) | `model_attestation.compute_attestation["x-mesh-poc-v1"].serving_provenance` | Provenance of the actual run: `served_by_node_id`, `requesting_party`, `exchange_id` correlation lineage, `usage.{prompt,completion,total}_tokens`, plus `quantization` and `hardware.{gpu,vram_bytes,device}`. **`quantization` and `hardware.*` record as `"unknown"`/`null` on the observe path** because the host's `openai.exchange.v1` event and response body genuinely do not carry them — recorded honestly as absent, never fabricated. Fork PRs #2/#3 fill `model`+`usage` on the host path. Every field here is digest-bearing: mutating any changes `capsule_id`. |
| `runtime_digest` | `model_attestation.compute_attestation.runtime` (prefix before the first `:`) | SHA-256 of the actual runtime artifact serving the request (`--runtime-artifact <path>`, e.g. the mesh-llm binary). Read-only hash, never executes the artifact. **In the live Rust plugin this is now the SELF-MEASURED serving-binary hash** (see `binary_attestation` below): the field shape is `<sha256>:<measurement_class>:<runtime-name>`, e.g. `…:self_measured:admission-policy-plugin/mesh-llm-host-runtime`. When the binary path can't be resolved/read the plugin degrades gracefully to the legacy `0*64:…` placeholder — never a fabricated hash. |
| `generation_parameters` | `model_attestation.compute_attestation["x-mesh-poc-v1"].generation_parameters` | Legible decimal-string values (temperature, top_p, max_tokens, seed, penalties, stop) — not digested; policy/audit-relevant, not privacy-sensitive the way the prompt is. |
| `output_digest` | `effect.response_digest` | **Spec-native field** (§5.2), same treatment as `request_digest` — JSON-DIGEST over the canonicalized response body (success or error alike). |
| `timestamp` | `timestamp` | **Spec-native field** (§5.1), RFC 3339 UTC, set at seal time. |
| `sign_node_key(...)` (whole tuple, signed) | The whole capsule, in a COSE_Sign1 **Signed Statement** | `alg=EdDSA`, `issuer=<node_id>`, `subject=<capsule_id>`. Signing key generated on first run — **self-attested, not bound to any real node identity or hardware root**; a real deployment would bind it to the node's actual identity (#1233's own requirement). |
| "hash-chained per node" | `chain.parent_capsule_id` + `chain.relation="confirms"` | Spec-native (§5.4.4). Used here for same-node **sequential ordering**. `agent-action-capsule verify --store` recomputes and checks the whole chain. |
| fingerprint / TEE evidence (steps 4–5, *not* built) | `model_attestation.compute_attestation["x-mesh-poc-v1"].evidence_refs.{statistical_fingerprint,tee_attestation}` | **Typed reference fields, present but empty** — exactly Steven's "rides as a typed reference (digest + declared context)" framing. Populating these later upgrades the evidence a record carries without changing the record shape. |
| runtime/binary attestation (**`self_measured`**) | `model_attestation.compute_attestation["x-mesh-poc-v1"].evidence_refs.binary_attestation` | The **runtime/binary attestation rung**: the node hashes the serving binary it actually runs (`std::env::current_exe`) and signs that SHA-256 with the **node key**, shaped like executable code-signing (`{measurement_class, digest, digest_alg, binary_path, binary_size_bytes, signature, signature_algorithm, signer_key_id, measured_at, context}`). **HONESTY GRADE — read before trusting it:** `measurement_class` is **`self_measured`** — the node measures *its own* binary. This proves only that "a process holding the node key reported this hash for the file it believes is its executable"; it does **NOT** prove the binary was un-tampered before it hashed itself. It is trustworthy only up to an OS/TEE that *independently* measures the node (those would be recorded as the future `os_measured` / `tee_measured` classes). The label rides IN the signed record (and in the `context` string), so a reader is never told "attested binary" without also being told "self-measured, trust-me-up-to-the-OS." When the binary can't be measured the slot is recorded **absent** (`measurement_class: null`) — never fabricated. See `plugins/capsule-producer/src/runtime_attest.rs`. |
| owner identity — WHO+DID binding (**opt-in**) | `model_attestation.compute_attestation["x-mesh-poc-v1"].owner` | Binds mesh-llm's node **owner** identity (the *who*) into a serving record whose `served_by_node_id` is the *did*. Present always; `owner_status` is `absent` (default — no cert; `owner_id=null`, never fabricated), `bound` (a live `SignedNodeOwnership` cert from `mesh-llm auth init`, re-checked at first serve, with `owner_id` set and `identity_capsule_id` citing the sealed **identity capsule** — the signed *who* record), or `invalid` (cert present but expired/mismatched — never cited as a live binding). **Owner identity is opt-in and self-asserted**: `identity_limitation` carries the honesty caveat whenever a cert is present — the same discipline as the cross-party block (§4.1a); the owner key is self-held with no third-party root, so this is never externally-verified identity. See `node_ownership.py` and TRUST-MODEL.md §B.1. |

### Extension note (why some fields aren't first-class yet)

`effect.request_digest` and `effect.response_digest` are ratified §5.2 fields —
used here for exactly their defined I/O-digest semantics; spec-defined fields are
never repurposed. `client_nonce`, `model_name_digest` (and the Python path's
`model_package_digest`), `serving_provenance`, `generation_parameters`, and the
evidence-reference slots are **not yet registered fields**. They ride inside
`model_attestation.compute_attestation` — a block the reference library documents
as free-form, best-effort — under an explicit `x-mesh-poc-v1` namespace, so
nothing here is silently presented as ratified spec. A real proposal would go
through REGISTRY.md §12 ("Specification Required") before any of this graduates.

## Two IETF draft citations

1. **`draft-mih-scitt-agent-action-capsule-02`**, "An Agent Action Capsule Profile
   for SCITT" — the capsule schema, lifecycle, chain-linkage and registries this
   repo builds against.
2. **`draft-mih-sokolov-scitt-payload-binding-00`**, "Canonical Payload Binding" —
   canonicalization and typed-digest-reference conventions relevant to how
   `request_digest` / `output_digest` are computed and how the evidence-reference
   slots are shaped.

## What was actually verified (not just claimed)

### Live run (real mesh-llm node + real goose)

- **6 real capsules across 2 independent ledgers** from one `goose run` task
  against a real local Mesh-LLM node: inference receipts
  (`ledger-live/capsules.jsonl`) + action records
  (`ledger-live/goose-actions.jsonl`).
- **Both ledgers verify `ok=True`** with the real CLI.
- **The inference-receipt stream chains correctly** (`ledger_mode=chained`,
  checked by the CLI's store-mode pass).
- **Both bundle permalinks build and locally check-verify.**
- **The tool-call → action-record chain is faithful, not narrated**: the goose
  session's final summary matches the *real* return values byte-for-byte —
  confirming the model actually called the tools rather than hallucinating.
- **The streaming-compatibility fix does not weaken the attestation**:
  `response_digest` is computed from the raw reassembled response before
  `normalize_for_client()` ever runs.

### Native plugin (real `mesh-llm-host-runtime`)

- `plugins/admission-policy`'s
  `allowed_exchange_emits_a_signed_chained_ledgered_capsule_and_publishes_lifecycle_event`
  drives a real chat-completion exchange through the real host, asserts both wiring
  points (the plugin's own handler and the host's lifecycle broadcast),
  offline-verifies the resulting capsule, and adversarially mutates the signature
  and the observed response digest to confirm both are caught.
- **Cross-language conformance**: the real-host-produced Rust ledger re-verifies
  GREEN against the Python `scitt-cose`/`agent_action_capsule` reference and an
  independent Go verifier; a mutated statement is rejected by all.

### Mock-node smoke test (network/model-free)

`python3 run_demo.py` starts the fixture node + sidecar in-process, sends 4
requests (3 normal, 1 deliberately triggering a refusal), and writes
`ledger/capsules.jsonl` + signed statements + a transcript. All 4 verify, chain,
and cryptographically check; **negative controls (mutants) confirm the checks
actually reject tampering** — a flipped `response_digest` byte flips `verify().ok`
to `False` (`capsule_id_mismatch`); a flipped signed-statement payload byte makes
`verify_sign1` raise instead of silently accepting.

### The refused-request case (issue #1233 step 7's seam)

The refusal request returns a 400 in mesh-llm's real `ErrorResponse` shape,
modeling a guardrails-style pre-dispatch rejection. The sidecar still digests and
records it — the "checked and failed" case #1233 step 7 keeps distinct from
"evidence absent." Two corrections, both caught by the reference library's own
invariants (not manual review): `verdict_class="denied"` is rejected when paired
with `effect.status="failed"` (denied means *no dispatch occurred*, which an
outside observer can't claim) — the correct value is `"errored"`; and JSON floats
are stringified before entering any digest-committed field (§5.1).

## Bilateral attestation demo (mechanism demonstration only)

`bilateral_demo.py` implements the four moves of
[`draft-mih-agent-bilateral-attestation-01`](https://datatracker.ietf.org/doc/draft-mih-agent-bilateral-attestation/)
against the mock node — no live mesh-llm node required.

| Path | What happens | Derived cross_party_rung |
|---|---|---|
| **Bilateral** | Client signs request attestation; node verifies it; capsule carries `cross_party.initiator_ref`; client signs ack of returned `capsule_id` | `full_bilateral` |
| **Degraded** | Client sends no attestation; node proceeds unilaterally; no `cross_party` block | `unilateral_fallback` |

The `cross_party_rung` is **derived from the record's own bytes** using
`derive_cross_party_rung()` — the producer never asserts it.

> ⚠ **The keys used in this demo are self-generated and self-held.** They are not
> bound to any trusted root or third-party-issued credential.
> `draft-mih-agent-bilateral-attestation-01` §4.1 states that first-use acceptance
> of a self-held key MUST NOT be treated as conformant bilateral attestation.
> **This demo shows the mechanism, not a conformant deployed bilateral exchange.**
> Every action capsule it emits carries an `identity_limitation` field saying so. A
> lone node can self-mint both keys and satisfy every check
> `derive_cross_party_rung()` performs — so `full_bilateral` proves *a commitment
> was made and matches this record*, never *that an independent party made it* (see
> `docs/TRUST-MODEL.md` §4.1a). Do not cite this demo's output as conformant
> evidence of bilateral attestation.

## Files

```
README.md                       this file
docs/TRUST-MODEL.md             the step-1 threat model + assurance classes (source of the neutrality discipline)
docs/SUPPORTED-PORT-RERUN.md    the supported-port re-run findings (vs. the debugging endpoint)

# Path 1 — native Rust plugin (primary)
plugins/admission-policy/       mesh-llm-plugin: Envelope-wire admission + lifecycle-hook capsule emission
plugins/capsule-producer/       Rust AAC producer: JCS + COSE_Sign1 + chain + ledger + anchor + verify

# Path 2 — Python sidecar (alternative)
capsule_sidecar.py              reverse-proxy observer: proxy + emit + sign + chain (+ SSE + bilateral eval)
bilateral_demo.py               four-move bilateral attestation demo (mechanism only; non-conformant identity)
model_identity.py               model_package_digest per #1233's own formula
build_real_model_package.py     real model-package.json from a downloaded GGUF (live-demo path)
build_model_package.py          fixture model-package.json (mock-node smoke-test path only)
mock_mesh_node.py               schema-accurate /v1 stand-in (mock-node smoke-test path only)
run_demo.py                     mock-node smoke test + verification pass
run_live_demo.sh                real mesh-llm + real goose live demo end to end

# checkpointing (Layers 1-3, opt-in)
checkpointing.py                LogSource adapter, cadence + reconnect, witness-state rendering
checkpoint.example.toml         example [checkpoint] config
run_checkpoint_demo.py          synthetic checkpoint demo (exchanges -> MMR -> checkpoint -> registry -> verify)
run_real_deployment_checkpoint_demo.sh   real mesh-llm + checkpointing, end to end (no goose leg)
verify_real_deployment_checkpoint.py     offline verify + rollback-mutant proof

# split / coordinator (record shapes; see the split-honesty note above)
mesh_record_emitter.py          exchange_id-correlated per-hop record emitter (+ requester_commitment)
mesh_record_verifier.py         verifier: derives cross_party_rung from record bytes
mesh_coordinator_receipt_emitter.py   coordinator-receipt SHAPE over stage order (not wired to a real split)
requester_commitment.py         rung-2 requester-signed commitment
node_ownership.py               WHO+DID binding: seal identity capsule + bind opt-in owner→node identity into serving records (§B.1)

tools/replay_spot_check.py      C2a replay spot-check harness
goose/server.py                 capsule-emit-goose: the action-record MCP extension (tool-call boundary)
keys/                           demo-only Ed25519 node signing key (public half; self-attested)
ledger/                         generated by run_demo.py (mock-node smoke test)
ledger-live/                    generated by run_live_demo.sh (gitignored -- regenerate per run)
ledger-checkpoint-demo/         committed checkpoint-demo transcript + fixture
ledger-real-deployment/         committed real-deployment transcript + fixture
tests/                          sidecar, bilateral, checkpointing, replay, split-record tests
bench/                          A/F benchmark harness (python3 bench/run_benchmark.py)
```

## Benchmark notes

`bench/run_benchmark.py` reports p50 and p95 only. p99 is omitted: n=100 cannot
support a defensible 99th percentile.

## License

Apache-2.0 — see [LICENSE](LICENSE).
