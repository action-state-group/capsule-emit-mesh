<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design note: folding the evidence door + checkpointer into the plugin

**Status:** Step 0 only — a decision input, not a build plan. No port has
started. Steven rules on migration order before any of this is implemented.

## The problem

A node running Path 1 (the native Rust `admission-policy` plugin, see
`README.md` "Two integration paths") still needs **two separate Python
processes** alongside `mesh-llm` + the plugin: `checkpoint_daemon.py` (the
witness-anchor clock) and `evidence_server.py` (E15, the HTTP evidence door).
Neither is on the serving path — the plugin already seals every capsule
(`plugins/admission-policy/src/capsule_emit.rs`, wired to
`plugins/capsule-producer`) — but both are required for a node to be a
complete, install-story-simple accountability node. For anyone who isn't us,
"mesh-llm + one plugin" is the bar; "mesh-llm + one plugin + two Python
daemons you also have to supervise" is not.

## What already exists in Rust vs. what would be a first port

### Already exists, ready to reuse

- **Capsule production (Layer 0).** `plugins/capsule-producer` — JCS
  canonicalization (`jcs.rs`), COSE_Sign1 signing (`cose.rs`), key
  persistence (`keys.rs`), the durable ledger (`ledger.rs`, byte-identical
  on-disk `capsules.jsonl` + `signed-statements/*.cose` shape to the Python
  producer, by design — "so existing Python tooling that reads this ledger
  … keeps working unmodified"). Already on the serving path, already
  produces the bytes everything below reads.
- **Single-digest anchor client.** `plugins/capsule-producer/src/anchor.rs`
  — `POST /v1/digest` / `GET /v1/inclusion/{id}` against `capsule-anchor`,
  mirroring `cll.checkpoint.emit.register_checkpoint()`'s wire contract
  byte-for-byte. This is the witness HTTP client half of the checkpointer;
  it just isn't wired to a periodic MMR checkpoint yet — today it anchors a
  single capsule digest, not a checkpoint root.
- **Mesh-carried evidence transport.** `plugins/admission-policy/src/
  mesh_evidence_bridge.rs` (#110) already opens the door *over the mesh
  stream* (`evidence-request/1` channel) rather than a reachable HTTP port —
  but it works today by proxying the whole request as one buffered HTTP
  POST to `evidence_server.py` on `127.0.0.1:8091`. The Rust side is
  transport-only; it does not answer the request itself.
- **Peer checkpoint-head receiving side.** `plugins/admission-policy/src/
  peer_root_ledger.rs` — verifies and reconciles a peer's signed
  `{log_id, mmr_size, root, timestamp_unix_ms, signature}` head
  (`PeerAnnouncement.checkpoint`), detects forks. Self-contained and
  already tested, but **not wired into `main.rs`'s `on_mesh_event`** yet
  (blocked on a `mesh-llm-plugin` crates.io bump carrying the fork's
  `checkpoint` field — see the module's own doc comment). This is the
  *receiving* half only; nothing today produces this node's *own* outbound
  head from Rust (see next section).

### Would be a first Rust implementation

- **The MMR + signed checkpoint record (Layer 1–2).** `checkpointing.py`'s
  `CheckpointState`/`MmrLedger` delegates to `cll.checkpoint` (package
  `checkpointed-local-log`, pure Python, the reference implementation for
  `draft-mih-scitt-checkpointed-local-log`: `index.py` (MMR), `emit.py`
  (`CheckpointRecord`, `register_checkpoint`, `DEFAULT_TS_URL`),
  `cose_wire.py`, `bundle.py`, `store.py`). **No Rust MMR, COSE checkpoint
  builder, or consistency-proof code exists anywhere in these repos today.**
  This is genuinely new Rust, not a call-out to an existing crate — there is
  no Rust `cll` port to depend on (`checkpointed-local-log` ships Python
  only).
- **Cadence / offline-first / restart-safe scheduling.**
  `checkpoint_daemon.py`'s policy (only-if-new-activity age clock measured
  from the first unwitnessed entry, not from the last checkpoint; shutdown
  flush; best-effort witness retry so an unreachable witness never blocks
  local checkpointing) — currently pure Python control flow over
  `CheckpointState`, would need to be re-expressed as a Rust background
  task (tokio interval + shutdown signal) inside the plugin's own runtime.
- **The E14 evidence responder itself.** `capsule_emit/evidence_request.py`
  (`capsule-emit` package, 669 lines) — subject/coverage/derivation
  resolution, refusal semantics (`no_such_record`, `coverage_unsatisfiable`,
  `policy_decline`), page-size caps and opaque page tokens
  (`DEFAULT_PAGE_SIZE`, the hard page-size ceiling), bundle assembly
  (`capsule_emit/bundle.py`). `evidence_server.py` itself is a thin HTTP
  shell around this — the actual logic that "moves with it" (range caps,
  paging, rate limiting) lives one layer down, in `capsule-emit`, and has
  no Rust equivalent. Folding the door into the plugin means either
  reimplementing this resolution/paging logic in Rust against
  `plugins/capsule-producer::ledger::Ledger`, or the plugin shelling out to
  it — reimplementation is what actually removes the Python dependency.
- **The plugin's own outbound checkpoint head.** Nothing today makes the
  Rust plugin *hold* a signed checkpoint head to feed
  `PeerAnnouncement.checkpoint`. `[mesh-checkpoint-head-source]`'s own text
  says the plumbing assumes "the plugin already holds the node's latest
  signed checkpoint (sidecar/plugin checkpointing)" — that premise is only
  true once the checkpointer itself is in Rust; today the plugin would have
  to cross-process-read `checkpoints.jsonl` that only `checkpoint_daemon.py`
  writes. Folding the checkpointer in is a *prerequisite* for
  `[mesh-checkpoint-head-source]`'s sending half, not an independent step.
- **Pane JSON routes**, if kept — `/accountability/pane-a|b|c`
  (`accountability_pane_routes.py`, wired into `capsule_sidecar.py`) are
  Python-only today, unrelated to the Rust plugin's existing HTTP surface.

## The invariance test that must hold

Every step below must leave these true, checked against the SAME on-disk
ledger before and after:

1. **`capsules.jsonl` and `signed-statements/*.cose` are byte-identical.**
   The plugin already writes this shape; nothing in this fold touches
   Layer 0. A regression test: seal N capsules pre-fold, checkpoint,
   re-run the identical sequence post-fold against a fresh copy, diff the
   two ledger directories — must be empty.
2. **`checkpoints.jsonl` entries are byte-identical, or at minimum
   re-verify identically.** A checkpoint produced by the Rust checkpointer
   over a given `capsules.jsonl` prefix must carry the same MMR root as
   `cll.checkpoint`'s Python MMR over the same prefix (same leaf hash
   convention: `sha256(0x00 || capsule_id)`), and its COSE_Sign1 envelope
   must verify with the existing Python `cll.checkpoint` verifier and vice
   versa — cross-language verification, the same discipline
   `plugins/capsule-producer` already holds for Layer 0 (see README "cross-
   language-verify the Rust-written ledger against the Python … reference").
3. **Witness receipts still verify.** A checkpoint anchored by the new Rust
   path against `capsule-anchor` must produce a receipt that
   `scitt-cose`'s existing verifier (Python or the Go verifier) accepts
   unchanged — `anchor.rs` already proves the wire contract matches for a
   single digest; the same must hold once it is anchoring checkpoint roots
   instead of individual capsule ids.
4. **A stranger's read path does not regress.** `ask_history.py`,
   `stranger_verify_bundle.py`, and the mesh-carried evidence responder
   (E15 via #110) must keep answering identically for any ledger state that
   existed before the fold — bundle-tier answers, refusal shapes, and the
   documented Rust-producer provenance gap (bundle proves log integrity,
   not the individual capsule's own producer signature) are unchanged.

## Migration order candidates (Steven rules)

Each step below is chosen so a node stays fully working at every
intermediate stop — no step requires an atomic flag-day cutover.

1. **Checkpointer first.** Highest leverage: it closes
   `[mesh-checkpoint-head-source]` in passing (the plugin can't hold its
   own outbound head until it computes checkpoints itself) and touches only
   `capsules.jsonl` → `checkpoints.jsonl`, a narrower surface than the
   evidence door. Add an MMR + COSE-checkpoint module to
   `plugins/capsule-producer` (or a new sibling crate), a cadence task in
   `plugins/admission-policy`, wire `anchor.rs` to checkpoint roots instead
   of (or in addition to) single-capsule digests, and wire the resulting
   head into `peer_root_ledger.rs`'s sending side. `checkpoint_daemon.py`
   stays available and interoperable (reads the same files) until cut over
   on a node-by-node basis, then retired.
2. **Evidence door second.** Add an HTTP listener on the plugin's own port
   serving `POST /evidence-request` directly against
   `plugins/capsule-producer::ledger` (a Rust reimplementation of the E14
   resolution/paging/refusal logic), so `ask_history` and the #110 mesh
   bridge both point at the plugin instead of proxying to
   `evidence_server.py`. `evidence_server.py` stays as a fallback / Path 2
   companion until every Path-1 node has cut over.
3. **Pane routes last, only if the UI plan still wants them off
   `capsule_sidecar.py`** — smallest, most UI-coupled, least urgent to the
   "one plugin, no Python daemons" goal.

**Python's remaining role is unchanged by this order:** `ask_history`,
twin/referee, `stranger_verify_bundle.py`, and the history card stay
Python — what a *stranger* runs to verify a node from outside, never
something the node itself must run to serve.
