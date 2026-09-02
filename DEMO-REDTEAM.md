<!-- SPDX-License-Identifier: Apache-2.0 -->
# Live red-team integrity demo

A one-command, presenter-ready sequence: a real prompt goes to the live M4
mesh-llm node, the node serves it, the sidecar seals a real signed, chained
AAC capsule for that exchange, and the capsule is handed back alongside the
reply. Offline verify then checks it — and, with one toggle, we show what
happens when a malicious relay tampers that capsule after it was sealed.

**HELD — no merge, no flip.** This is a rehearsal/demo artifact, run on the
live M4 mesh node directly, not part of any release path.

## What this proves / what it does NOT prove

**Proves — INTEGRITY.** `capsule_id` is a digest over every field of the
sealed capsule. Anyone who edits a field after sealing — a malicious relay,
a compromised proxy, a careless copy/paste — breaks that digest, and offline
verify (record bytes only, no access to the node or the sidecar process)
catches it and names the check that failed.

**Does NOT prove — that a node can't lie about itself.** If the node
*itself* reports the same false quant/hardware claim consistently, both in
what it advertises and in what it seals, that self-consistent lie verifies
**clean**. This is a documented, uncaught-by-design residual —
[`docs/REDTEAM-RUNG2.md`](docs/REDTEAM-RUNG2.md), attacks 5 ("model-id
spoof"), 6 ("quant swap"), 7 ("hardware fake"). The config claim is
self-reported by the same party that seals it; reconciliation between two of
that party's own claims can only catch an *inconsistent* liar, never a
consistent one. Closing that is future work (an independently-held
counterparty claim, or a real statistical reference model) — this demo does
not claim otherwise.

Also honest about this build: the sealed capsule's `hardware`/`hostname`
fields read `null` here (not fabricated) — the live node's host-observe
channel (`openai.exchange.v1`) isn't currently wired to populate them on
this `mesh-llm` build. The tamper below targets the field that *is*
present and real: the served-model/quant claim
(`serving_provenance.model_canonical_ref`).

## Prerequisites

- The live M4 node running: `mesh-llm serve --gguf /Users/intangible/Llama-3.2-3B.gguf --port 9338 --console 3131 ...` (already up for this rehearsal).
- `python3` with this repo's `requirements.txt` installed.
- Run from the repo root (`capsule-emit-mesh/`).

## The exact commands

**Run A — honest.** No tamper. Expect GREEN.

```
./scripts/redteam_live_demo.sh
```

**Run B — liar.** Same prompt, same node. After the capsule is sealed, the
script itself plays a malicious relay: it flips the served-quant claim in
the capsule handed back with the reply, without re-signing. Expect RED.

```
./scripts/redteam_live_demo.sh --tamper
```

(equivalently: `CAPSULE_DEMO_LIAR=1 ./scripts/redteam_live_demo.sh`)

Both runs are idempotent — safe to re-run for a rehearsal; each starts from
a fresh `ledger-redteam-live/`.

## What the script does, step by step

1. Confirms the live node answers `GET /v1/models` on port 9338.
2. Rebuilds `model-package/model-package.live.json` from the actual,
   currently-loaded GGUF (real sha256 of the real file).
3. Starts `capsule_sidecar.py` as a reverse proxy in front of the live node
   (`--upstream http://127.0.0.1:9338`), writing to a fresh
   `ledger-redteam-live/`.
4. Sends **one** real prompt through the sidecar — the node actually
   generates the reply text.
5. Reads back the capsule sealed for that exchange (the `X-Capsule-Id`
   response header names it) and prints its claims: model, quant, hardware,
   served-by, timestamp, capsule_id.
6. **Only in `--tamper` mode:** edits
   `model_attestation.compute_attestation.x-mesh-poc-v1.serving_provenance.model_canonical_ref`
   in the ledger's own `capsules.jsonl` (`Q4_K_M` → `Q8_0`), leaving
   `capsule_id` untouched — exactly what a relay that doesn't hold the
   node's signing key would do.
7. Stops the sidecar, then runs `stranger_verify_bundle.py` — an **offline**
   verifier (record bytes only) that recomputes `capsule_id` from the
   current bytes and checks the detached COSE signature. Prints
   `OVERALL: PASS` or `OVERALL: FAIL`, exit code 0/1.

## Real output — run against the live M4 node, 2026-09-01

### Run A (honest) — GREEN

```
$ ./scripts/redteam_live_demo.sh
############################################################
# RUN A -- HONEST MODE
# No tamper. Expect GREEN.
############################################################
--- [1/7] confirm the live M4 node is up (http://127.0.0.1:9338) ---
live node models: ['allowed-test-model', 'blocked-test-model', 'local-gguf/sha256-1993f98e085eaa51', 'local-gguf/sha256-6ada44b11dabc27d', 'local-gguf/sha256-887fbdc66ab91eb5', 'mesh']
--- [2/7] rebuild model-package.live.json from the real, currently-served GGUF ---
wrote /Users/intangible/dev/asg/capsule-emit-mesh/model-package/model-package.live.json
model_id=bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
source_model.sha256=6c1a2b41161032677be168d354123594c0e6e67d2b9227c84f296ad037c728ff
artifact_bytes=2019377696
--- [3/7] fresh ledger dir + start sidecar in front of the live node ---
serving model for this exchange: local-gguf/sha256-6ada44b11dabc27d
--- [4/7] send ONE real prompt through the sidecar to the live node ---
prompt: In one short sentence, what is the capital of France?
reply text : The capital of France is Paris.
capsule_id : dac8a3d72313a7b0b2d9b4257743e361f3e4917472282e2d4d34773379aec92d
--- [5/7] fetch the sealed capsule handed back with that reply ---
capsule claims as sealed:
  model         : bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  quant claim   : unknown
  model_canonical_ref: bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  hardware      : gpu=None vram_bytes=None hostname=None (null = not populated on this node build, not hidden)
  served_by     : mesh-node-demo-1
  timestamp     : 2026-09-01T23:29:04.854659Z
  capsule_id    : dac8a3d72313a7b0b2d9b4257743e361f3e4917472282e2d4d34773379aec92d
--- [6/7] honest mode: nothing tampered ---
--- [7/7] stop the sidecar, then verify OFFLINE (record bytes only, no live access) ---
=== stranger-verify: /Users/intangible/dev/asg/capsule-emit-mesh/ledger-redteam-live ===
capsule dac8a3d72313a7b0b2d9b4257743e361f3e4917472282e2d4d34773379aec92d: verify.ok=True cross_party_rung=unilateral_fallback
    transparent verify: signature_verified=True ok=True
    serving_provenance: model=None quant='unknown' gpu=None served_by='mesh-node-demo-1' tokens=None
    advertised_vs_served: advertisement_absent

all capsules verify.ok: True

=== checkpoint / witness verify ===
no checkpoints.jsonl in this bundle -- Layer 0/1 only, nothing to verify at the checkpoint layer

OVERALL: PASS

================================================================
 GREEN -- verified. Sealed record is intact, capsule_id checks out.
================================================================
```

### Run B (liar) — RED

```
$ ./scripts/redteam_live_demo.sh --tamper
############################################################
# RUN B -- LIAR MODE (CAPSULE_DEMO_LIAR=1 / --tamper)
# A malicious relay will flip the quant claim on the shared
# capsule AFTER sealing, without re-signing. Expect RED.
############################################################
--- [1/7] confirm the live M4 node is up (http://127.0.0.1:9338) ---
live node models: ['allowed-test-model', 'blocked-test-model', 'local-gguf/sha256-1993f98e085eaa51', 'local-gguf/sha256-6ada44b11dabc27d', 'local-gguf/sha256-887fbdc66ab91eb5', 'mesh']
--- [2/7] rebuild model-package.live.json from the real, currently-served GGUF ---
wrote /Users/intangible/dev/asg/capsule-emit-mesh/model-package/model-package.live.json
model_id=bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
source_model.sha256=6c1a2b41161032677be168d354123594c0e6e67d2b9227c84f296ad037c728ff
artifact_bytes=2019377696
--- [3/7] fresh ledger dir + start sidecar in front of the live node ---
serving model for this exchange: local-gguf/sha256-6ada44b11dabc27d
--- [4/7] send ONE real prompt through the sidecar to the live node ---
prompt: In one short sentence, what is the capital of France?
reply text : The capital of France is Paris.
capsule_id : 1e7831d5f2766b960c1c66080813e7800301b9854de54e07853a8ca8ecc69ca7
--- [5/7] fetch the sealed capsule handed back with that reply ---
capsule claims as sealed:
  model         : bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  quant claim   : unknown
  model_canonical_ref: bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  hardware      : gpu=None vram_bytes=None hostname=None (null = not populated on this node build, not hidden)
  served_by     : mesh-node-demo-1
  timestamp     : 2026-09-01T23:29:10.550830Z
  capsule_id    : 1e7831d5f2766b960c1c66080813e7800301b9854de54e07853a8ca8ecc69ca7
--- [6/7] LIAR MODE: malicious relay tampers the shared capsule (no re-sign) ---
tampered field: model_attestation.compute_attestation.x-mesh-poc-v1.serving_provenance.model_canonical_ref
  before (sealed) : bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  after (relayed) : bartowski/Llama-3.2-3B-Instruct-GGUF:Q8_0
  capsule_id left UNCHANGED at: 1e7831d5f2766b960c1c66080813e7800301b9854de54e07853a8ca8ecc69ca7  (this is what makes the tamper detectable)
--- [7/7] stop the sidecar, then verify OFFLINE (record bytes only, no live access) ---
=== stranger-verify: /Users/intangible/dev/asg/capsule-emit-mesh/ledger-redteam-live ===
capsule 1e7831d5f2766b960c1c66080813e7800301b9854de54e07853a8ca8ecc69ca7: verify.ok=False cross_party_rung=unilateral_fallback
    finding: 2 -- recomputed d9559523d4bc810f7c2af4115fe61aaa887b1f2aa150204b4402f8af3165a698 != carried 1e7831d5f2766b960c1c66080813e7800301b9854de54e07853a8ca8ecc69ca7
    finding: 8 -- effect.type='inference_completion' is not a seeded effect.type value; informational, not rejected (§12)
    transparent verify: signature_verified=True ok=True
    serving_provenance: model=None quant='unknown' gpu=None served_by='mesh-node-demo-1' tokens=None
    advertised_vs_served: advertisement_absent

all capsules verify.ok: False

=== checkpoint / witness verify ===
no checkpoints.jsonl in this bundle -- Layer 0/1 only, nothing to verify at the checkpoint layer

OVERALL: FAIL

================================================================
 RED -- verify FAILED. capsule_id no longer matches the record
 bytes -- the field flipped above broke it. This is exactly the
 integrity property this demo shows: any edited field, however
 small, breaks the seal.
================================================================
```

Each run reseals a fresh capsule with a real, new timestamp and digest, so
the `capsule_id`s above (`dac8a3d7…` honest, `1e7831d5…` tampered) differ
from run to run — and from the capsule committed in `ledger-redteam-live/`
(`118b4a59…`, a separate later honest run, kept as the repo fixture; see
[`ledger-redteam-live/README.md`](ledger-redteam-live/README.md)). Re-run
either command yourself against the live node to mint a fresh matching
pair.

Note on `finding: 2`: the recomputed digest differs from the carried
`capsule_id` because the tamper (step 6) deliberately left `capsule_id`
unedited while changing `model_canonical_ref` — the mismatch between
"digest recomputed from current bytes" and "digest the record still
claims" *is* the tamper-evidence signal. The `transparent verify:
signature_verified=True` line staying green in Run B is expected, not a
bug: the detached COSE statement signs the capsule's `capsule_id` string
(unchanged by the relay), not the full record — the content-hash check
(`finding: 2`) is the layer that catches this class of tamper, which is
why `stranger_verify_bundle.py` runs both checks rather than either alone.

## Path A — cross-machine (M4 seals, M3 verifies OFFLINE)

The single-machine demo above proves the integrity mechanism. Path A proves
the more realistic shape of it: the party who verifies is not the party who
sealed, running on a **different physical machine**, over the network, with
**no shared process or filesystem** — the thing a real maintainer or
counterparty actually experiences. (Chosen over joining M3 to the live mesh
itself, which is fragile for a rehearsal; a plain scp over Tailscale gives
the same "zero access to the sealer" property without the mesh-join
surface area.)

Same honesty box as above applies unchanged — see the header of
[`scripts/redteam_cross_machine_demo.sh`](scripts/redteam_cross_machine_demo.sh)
and the printed box at the end of every run.

### The exact command

Run from `capsule-emit-mesh/` on **M4** (the machine serving the live node):

`M3_HOST` is **required** — no default is committed (this is a public repo,
and a real ssh target is not something to ship in it):

```
M3_HOST=user@<your-m3-tailscale-ip-or-hostname> ./scripts/redteam_cross_machine_demo.sh
```

Override the remote repo path / python if needed:

```
M3_HOST=user@100.x.x.x M3_REPO=~/capsule-emit-mesh ./scripts/redteam_cross_machine_demo.sh
```

### What it does, step by step

1. Runs `scripts/redteam_live_demo.sh` (honest mode) on M4 to seal one real
   capsule from a live inference — identical to Path 1 above.
2. Builds a transfer bundle: just `capsules.jsonl`, the capsule's detached
   `.cose` signed statement, and the issuer's public key (`keys/node-key.pub.pem`)
   — no keys, no code, no live access, nothing else leaves M4.
3. Confirms M3 is reachable over Tailscale, then `scp`s the bundle to
   `~/capsule-emit-mesh/_redteam-m4-bundle` on M3.
4. Runs `stranger_verify_bundle.py` **on M3**, entirely offline, against the
   copied bundle → prints `OVERALL: PASS`.
5. On M3, a malicious-relay stand-in
   (`scripts/_redteam_tamper_capsule.py`, the same tamper helper Path 1
   uses) flips the served-quant claim on the **copy** — without re-signing.
6. Re-runs `stranger_verify_bundle.py` on M3 → prints `OVERALL: FAIL`,
   naming the same content-hash finding as Path 1.

### Real output — run M4 → M3 (Tailscale), 2026-09-01

```
$ M3_HOST=user@<m3-tailscale-ip-or-hostname> ./scripts/redteam_cross_machine_demo.sh
############################################################
# PATH A -- cross-machine: M4 seals, M3 verifies OFFLINE
# M3 target: user@<m3-tailscale-ip-or-hostname>
############################################################

=== Part 1/2: seal a real capsule on M4 (this machine) ===
[... Path 1's own honest-run output, identical in shape to the transcript
     above — capsule_id debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7 ...]

M4 sealed capsule for cross-machine transfer: debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7

--- [1/6] build the transfer bundle (capsule + signed statement + issuer pubkey) ---
bundle contents:
  .../redteam-cross-machine-bundle/capsules.jsonl
  .../redteam-cross-machine-bundle/signed-statements/debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7.cose
  .../redteam-cross-machine-bundle/node-key.pub.pem
  .../redteam-cross-machine-bundle/_redteam_tamper_capsule.py

--- [2/6] confirm M3 is reachable over Tailscale ---
reachable: swim-googles.local

--- [3/6] scp the bundle to M3 (this is the ONLY thing that leaves M4) ---

--- [4/6] M3 verifies OFFLINE -- no access to M4, the sidecar, or the node ---
=== stranger-verify: _redteam-m4-bundle ===
capsule debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7: verify.ok=True cross_party_rung=unilateral_fallback
    transparent verify: signature_verified=True ok=True
    serving_provenance: model=None quant='unknown' gpu=None served_by='mesh-node-demo-1' tokens=None
    advertised_vs_served: advertisement_absent

all capsules verify.ok: True

=== checkpoint / witness verify ===
no checkpoints.jsonl in this bundle -- Layer 0/1 only, nothing to verify at the checkpoint layer

OVERALL: PASS

================================================================
 GREEN (on M3) -- verified. M3 trusts this capsule with ZERO
 access to M4 -- record bytes copied over the wire, that's all.
================================================================

=== Part 2/2: tamper the copy on M3, re-verify ===
--- [5/6] M3: a malicious relay/copy step tampers the bundle (no re-sign) ---
tampered field: model_attestation.compute_attestation.x-mesh-poc-v1.serving_provenance.model_canonical_ref
  before (sealed) : bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
  after (relayed) : bartowski/Llama-3.2-3B-Instruct-GGUF:Q8_0
  capsule_id left UNCHANGED at: debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7

--- [6/6] M3 re-verifies OFFLINE ---
=== stranger-verify: _redteam-m4-bundle ===
capsule debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7: verify.ok=False cross_party_rung=unilateral_fallback
    finding: 2 -- recomputed c0babbb00eda75d9f33c5c1bd09f490777eeb51d03ded9b98f12e7553fd9fca8 != carried debbc12247fe8fa89edfa08384e8d05f18d7a3484881d734c59af6a40a8688a7
    finding: 8 -- effect.type='inference_completion' is not a seeded effect.type value; informational, not rejected (§12)
    transparent verify: signature_verified=True ok=True
    serving_provenance: model=None quant='unknown' gpu=None served_by='mesh-node-demo-1' tokens=None
    advertised_vs_served: advertisement_absent

all capsules verify.ok: False

=== checkpoint / witness verify ===
no checkpoints.jsonl in this bundle -- Layer 0/1 only, nothing to verify at the checkpoint layer

OVERALL: FAIL

================================================================
 RED (on M3) -- verify FAILED after the copy was tampered.
 M3 caught it with no access to M4 -- offline, from bytes alone.
================================================================
cross-machine demo: PASS (GREEN before tamper, RED after)
```

### A harness note worth knowing

While building this, `ssh host "exit 1"` was observed to report a local
exit code of `0` when run through this session's sandboxed command tool —
even with sandboxing explicitly disabled — while the remote command's own
`echo $?` correctly showed `1`. `scripts/redteam_cross_machine_demo.sh`
therefore checks M3's verify result by matching the verifier's own printed
`OVERALL: PASS`/`OVERALL: FAIL` line rather than trusting ssh's process
exit code — more robust regardless of the cause, and it's what the real
output above reflects.

## Under the hood

- `scripts/redteam_live_demo.sh` — the one-command single-machine sequence.
- `scripts/redteam_cross_machine_demo.sh` — Path A, the cross-machine
  sequence: runs the above on M4, then scp/ssh to M3 for the offline
  verify + tamper + re-verify.
- `scripts/_redteam_tamper_capsule.py` — the shared tamper helper both
  demos use (flips the served-quant claim, leaves `capsule_id` untouched).
- `capsule_sidecar.py` — real reverse-proxy sidecar; unmodified, already
  used by `run_live_demo.sh` and the `ledger-live`/`ledger-real-deployment`
  fixtures.
- `stranger_verify_bundle.py` — the reused, already-tested offline
  verifier (`agent_action_capsule.verify.verify_store` for content-hash +
  chain integrity, plus the detached `.cose` signature check). No new
  verification logic was written for this demo — JCS canonicalization and
  digest recomputation are not reimplemented here.
