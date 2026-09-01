# QUICKSTART — you have Mesh-LLM, now what?

Two independent things you can test today, in order of effort:

1. **Ask -> verify** — a coordinator asks a stage node "what did you do?" and checks the
   answer *offline*, without trusting it. Fully runnable right now, no Mesh-LLM needed.
2. **Get real capsules out of your running Mesh-LLM node** — two paths, one works today.

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

Installs three commands: `capsule-sidecar`, `capsule-coordinator-verify`, `capsule-disclosure-endpoint`.

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

| | sidecar-now | native-plugin-after-#1437 |
|---|---|---|
| Works today | Yes | No — needs upstream Mesh-LLM/mesh-llm#1437 (plugin hooks), still OPEN |
| Captures | HTTP-observed request/response (a "collector") | The host's own `openai.exchange.v1` lifecycle event (a "gate") |
| Where | `capsule_sidecar.py`, a reverse proxy in front of your node | Rust `admission-policy-plugin` + `capsule-producer`, in-process |
| Extra step | None | Fork `StevenMih/mesh-llm`, PRs #1/#2/#3, rebased on upstream #1437 |

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

### native-plugin-after-#1437

Not runnable against upstream Mesh-LLM yet — it needs Mesh-LLM/mesh-llm#1437's plugin hooks,
which are still OPEN. `plugins/capsule-producer` builds today against a fork
(`StevenMih/mesh-llm`, PRs #1/#2/#3) that carries those hooks ahead of upstream merging them.
Once #1437 lands, the same plugin builds against upstream directly. This is also the only path
with the `self_measured` / `os_measured` / `tee_measured` runtime-attestation ladder
(see [docs/REDTEAM-RUNG3.md](docs/REDTEAM-RUNG3.md)) — not available on the sidecar path, which
is why `capsule-coordinator-verify`'s `runtime` grade above stays at "self-attested" today.
