# QUICKSTART — you have Mesh-LLM, now what?

Three independent things you can test today, in order of effort:

1. **Ask -> verify** — a coordinator asks a stage node "what did you do?" and checks the
   answer *offline*, without trusting it. Fully runnable right now, no Mesh-LLM needed.
2. **Get real capsules out of your running Mesh-LLM node** — two paths, one works today.
3. **Ask a peer node for evidence, over the wire** — `POST /evidence-request` + an offline
   verifier, cross-node, no Mesh-LLM upstream dependency.

This is a walkthrough, not a spec. For what each piece actually proves (and doesn't), see
[docs/TRUST-MODEL.md](docs/TRUST-MODEL.md); for the mechanism this quickstart exercises, see
[mesh_coordinator_bundle_flow.py](mesh_coordinator_bundle_flow.py)'s module docstring.

## Install

From a checkout of this branch (this is a held PR, not yet on PyPI):

```
git clone https://github.com/action-state-group/capsule-emit-mesh.git
cd capsule-emit-mesh && git checkout ask-verify-quickstart
pip install .          # or: pipx install .
```

Installs five commands: `capsule-sidecar`, `capsule-coordinator-verify`, `capsule-disclosure-endpoint`,
`capsule-evidence-server`, `ask-history`.

## 1. Ask -> verify, in one command

```
python3 examples/ask_verify_http_quickstart.py
```

This seals 3 stage records, starts a **real** `capsule-disclosure-endpoint` HTTP server
(a stage node choosing to disclose its bundle on request), then runs
`capsule-coordinator-verify` against it over the loopback socket — the same two processes,
talking the same protocol, a real coordinator and a real stage node would use. It prints the
exact `capsule-coordinator-verify ...` command it ran, so you can copy it and point it at your
own receipt/bundles afterwards.

Read the output top to bottom: order, per-stage PASS/GAP/FAIL, then — **only for stages that
verified green** — four grades read straight off that stage's own disclosed bytes:

| Grade | What backs it | Never says more than |
|---|---|---|
| `cross_party_rung` | DERIVED from the record's own `requester_commitment` bytes (`mesh_record_verifier.verify_record_bytes`) | `unilateral_fallback` \| `full_bilateral` — never upgraded on absent/invalid evidence |
| `runtime` | The record's own `compute_attestation.runtime` string | "self-attested (unverified)" — this Python path has no independent-measurer rung (see below) |
| `log_integrity` | A checkpoint record the node chose to disclose in `inclusion_proof` (`checkpointing.describe_witness_state`) | unwitnessed < self-checkpointed < independently witnessed |
| `freshness` | The record's own committed `timestamp`, bucketed against wall-clock age | "self-reported, not witnessed" |

A `GAP` (present but not disclosed to this verifier) or `FAIL` (tampered / wrong hop) stage is
**not graded further** — dressing up an unresolved hole or a caught forgery with grades would be
exactly the false-green failure mode this tool exists to catch. The headline (`ALL GREEN` /
`INCOMPLETE` / `MISMATCH DETECTED`) and exit code (0 / 2 / 1) reflect that distinction too —
`INCOMPLETE` is an honest "not proven", not a failure.

### Run it against your own receipt

```
capsule-disclosure-endpoint --run-id <run_id> --bundles-dir ./my-bundles --listen-port 8090 &
capsule-coordinator-verify my-receipt.json --bundle-url stage-0=http://127.0.0.1:8090
# or, for a bundle you already have as a file, skip the endpoint:
capsule-coordinator-verify my-receipt.json --bundle stage-0=./my-bundles/stage-0.json
```

`./my-bundles/<hop_id>.json` files are the `StageBundle` JSON shape
(`mesh_coordinator_bundle_flow.stage_bundle_to_dict`) — whatever sealed the stage capsule
(`mesh_record_emitter.emit_lifecycle_record`, or `capsule_sidecar.py`) writes one per hop.

**Honest limitation:** this walkthrough uses locally-sealed stage records to exercise the wire
protocol end to end. Wiring REAL per-hop Mesh-LLM split-inference request/response bytes into
these records — instead of the demo's synthetic ones — is the next integration step, the same
shape `capsule_sidecar.py` already does for the single-node case below.

## 2. Get capsules out of your running Mesh-LLM node

| | sidecar-now | native-plugin |
|---|---|---|
| Works today | Yes | Yes — #1437's plugin hooks are upstream now |
| Captures | HTTP-observed request/response (a "collector") | The host's own `openai.exchange.v1` lifecycle event (a "gate") |
| Where | `capsule_sidecar.py`, a reverse proxy in front of your node | Rust `admission-policy-plugin` + `capsule-producer`, in-process |
| Extra step | None | None for the base hooks; a fork (`StevenMih/mesh-llm`, PRs #1/#2/#3) carries additional serving-provenance work stacked on top |

### sidecar-now

```
mesh-llm serve --local-model-only --model <path.gguf> --port 9337   # your existing node
mkdir my-mesh-node && cd my-mesh-node
capsule-sidecar --upstream http://127.0.0.1:9337 --listen-port 8089 --manifest <model-package.json>
```

Point your OpenAI-compatible client at `:8089` instead of `:9337` — every response is now
proxied through unmodified and sealed. Capsules land in `./ledger/capsules.jsonl` (created in
the directory you run it from). No `model-package.json` handy? `build_model_package.py` in this
repo writes a small placeholder fixture with real (if fake) hashes to get you started; swap in
Mesh-LLM's own manifest for the loaded model when you have it.

`--node-ownership`, `--advertisement`, and `--checkpoint-config` are optional upgrades (owner
identity binding, advertised-vs-served reconciliation, and witness checkpointing respectively)
— see `capsule-sidecar --help` and [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).

### native-plugin

Runs against upstream Mesh-LLM directly — #1437's plugin lifecycle hooks
(`crates/mesh-llm-host-runtime/src/plugin/openai_exchange.rs`, the
`mesh-native-serving-plugin-api`/`-host` crates) merged upstream.
`plugins/capsule-producer` builds against Mesh-LLM's published `mesh-llm-plugin`
protocol; a fork (`StevenMih/mesh-llm`, PRs #1/#2/#3) carries additional
serving-provenance work stacked on top of the upstream hooks, not a dependency
for this base path. This is also the only path with the `self_measured` /
`os_measured` / `tee_measured` runtime-attestation ladder
(see [docs/REDTEAM-RUNG3.md](docs/REDTEAM-RUNG3.md)) — not available on the sidecar path, which
is why `capsule-coordinator-verify`'s `runtime` grade above stays at "self-attested" today.

**Cargo pin note:** `plugins/admission-policy/Cargo.toml` pins `mesh-llm-plugin = "0.75"`.
Upstream's workspace is ahead of that on `main` (pre-release, unpublished), but the published
crate on crates.io is still `0.75.0` — there is nothing newer to move to yet.

## 3. Ask a peer node for evidence, over the wire

`capsule-emit`'s `answer()` (E14) already decides what a request for `record`/`range` evidence
gets back — an offline-verifiable `Bundle`, or a signed refusal — but nothing could reach it
from another node. This puts an HTTP door in front of it.

```
capsule-evidence-server --ledger-dir ./ledger --node-key ./keys/node-key.pem --listen-port 8091
```

`--ledger-dir` also accepts the Rust plugin's own `<data_dir>/ledger` directly — if it carries a
sibling `checkpoints.jsonl` (the shape `capsule_sidecar.py --plugin-ledger-dir` checkpoints that
log into, read-only), the server bridges it automatically so `answer()` can see the checkpoint;
see `evidence_server.py`'s module docstring for exactly what that bridge does and does not prove.

From a peer, ask it and verify the answer offline:

```
python3 ask_history.py http://<peer>:8091 --subject range --selector <cid1>..<cid2>
python3 ask_history.py http://<peer>:8091 --subject record --capsule-id <cid>
```

Each returned bundle is verified with `capsule_emit.bundle.verify_bundle` — the pure, offline
per-bundle check this artifact shape calls for, never `stranger_verify_bundle.py`'s ledger-DIR
verify (that one needs a full copy of a ledger directory, which this route never hands out) —
and a small history card (`continuity`/`history_depth`/`unforked`) is folded from the bundle's
own checkpoint fields via `history_card.build_history_card`. An unknown record or a checkpoint
pin mismatch comes back as a *signed* refusal (`no_such_record` / `coverage_unsatisfiable`),
verified offline against the peer's own key — never a bare 404.

**Honest limitation:** a bundle-tier answer proves LOG integrity (inclusion, checkpoint
signature/consistency) but never a Rust-producer capsule's own detached signed statement
(`signed-statements/<capsule_id>.cose` is not carried in this artifact shape) — `ask_history.py`
labels that gap rather than rounding a log-integrity pass up to a full verify. This is the
**Record** layer only: it makes a claim signed and checkable, it does not attest to how the
answering process was run (that's Attest/Detect, elsewhere in this repo's ladder).
