# Milestone 2 report — chaining, ledger, keys, anchor, offline verify

Task: `[mesh-rust-capsule-production-m2]`. Scope: build the rest of the
#1332 producer deliverable in Rust on top of Milestone 1's proven crypto
interop — hash-chaining, a durable local ledger, Ed25519 key persistence +
rotation, an optional anchor client, and an offline verification command —
keeping cross-language conformance green at every step.

## Result

All five "Do" items landed with a real conformance check each, run for real
against the reference implementations (not just compile-checked):

1. **Hash-chaining** (`src/capsule.rs::ChainLink`) — `capsule::seal` accepts
   an optional `chain: {parent_capsule_id, relation}`, mirroring
   `emit.py`'s `Chain` wiring exactly, including the subtlety that
   `assurance.ledger_mode` ("chained" vs "standalone") — not the `chain`
   block itself — is what's digest-bearing (`jcs::CHAIN_LINKAGE_FIELDS`
   excludes `chain`/`capsule_id`, matching `canonical.CHAIN_LINKAGE_FIELDS`
   exactly). A unit test (`capsule::tests::capsule_id_is_independent_of_the_chain_blocks_content`)
   originally asserted the wrong invariant (that standalone vs. chained
   capsules with the same body produce the same `capsule_id`) — the test
   failure caught this correctly: `ledger_mode` differing IS supposed to
   change `capsule_id`, only the chain block's own content (parent id,
   relation) is excluded. Fixed the test, not the code.
2. **Durable local ledger** (`src/ledger.rs`) — `<ledger_dir>/capsules.jsonl`
   + `<ledger_dir>/signed-statements/<id>.cose`, the same on-disk shape
   `capsule_sidecar.py`'s `NodeState`/`record_capsule` uses (M1's own
   recommendation), so Python tooling reading this ledger keeps working
   unmodified. `Ledger::open()` replays the whole file on every open,
   recovering the chain head purely from disk (no separate head-pointer
   file to fall out of sync) and validating every entry's `capsule_id`
   digest, chain linkage, and matching signed-statement file. A torn write
   (no trailing newline — simulated a crash mid-`write()`) is detected and
   truncated away, never trusted as the head; a *terminated* line that's
   corrupt (tampered `capsule_id`, broken chain link) is a hard error, never
   a silent drop. `append()` writes the `.cose` file and `fsync`s it BEFORE
   the jsonl line (also `fsync`'d), so a crash between the two leaves at
   worst an orphaned, unindexed receipt file — never a jsonl entry pointing
   at a receipt that doesn't exist.
3. **Ed25519 key persistence + rotation** (`src/keys.rs`) — `load_or_create`
   ports `capsule_sidecar.load_or_create_signing_key` exactly (0600
   permissions, generate-once-then-persist). `rotate()` archives the old
   key (both halves) under `archive/node-key.<key_id>.{pem,pub.pem}` and
   activates a fresh key as `node-key.pem`; `key_id` is the first 16 hex
   chars of SHA-256 over the raw public key — the same scheme
   `capsule-anchor`'s own `GET /anchor/authority-pubkey` uses, reused here
   so a `key_id` means the same thing on both sides of this system. No
   rotation policy existed on the Python producer side to port (confirmed by
   the M1 report and by grepping all four relevant repos) — rotation is
   plain key-swap-as-caller-appends-a-ledger-event, mirroring
   `capsule_ledger`'s `key_rotation` event shape (`old_key_id`, `new_key_id`,
   `rotated_at`) without adopting its whole time-fenced-revocation apparatus,
   which is a verifier-side concern out of scope for a producer crate.
4. **Optional anchor client** (`src/anchor.rs`) — `POST /v1/digest` +
   `GET /v1/inclusion/{capsule_id}` + `GET /anchor/authority-pubkey`,
   matching `capsule_emit/checkpoint/emit.py::register_checkpoint`'s wire
   contract exactly. Deliberately NOT wired into `seal`/`ledger::append` —
   callers decide when to anchor, and a failed anchor call must never
   invalidate an already-sealed, already-ledgered capsule (the fail-open
   model `capsule_emit/witness.py` already establishes for the Python
   producer side).
5. **Offline verification CLI** (`src/bin/verify_capsule.rs`) — recomputes
   `capsule_id`, verifies the COSE_Sign1 signature, checks the COSE payload
   matches the supplied capsule bytes, and (given a `ledger_dir`) checks
   chain-parent membership against the ledger's own validated index — no
   network calls. Chain-parent membership is non-gating info without a
   store, exactly matching `agent_action_capsule.verify()` Check 6's
   no-store behavior.

## Cross-language / cross-service conformance — run for real, not just compiled

Three `#[ignore]`d tests (same shape as Milestone 1's), each run against a
live reference implementation:

- **`tests/chain_ledger_conformance.rs`** — builds a 3-capsule chain,
  ledgers it, drops and reopens the `Ledger` (simulated restart), then
  verifies the whole ledger against the Python reference
  (`scitt_cose.parse_signed_statement` + byte-exact payload comparison +
  `agent_action_capsule.verify.verify_store`). **Real run: green** — all 3
  capsules verify, chain integrity holds. Two mutations, both rejected by
  the Python reference: a flipped signature byte (`cose_all_ok: false`) and
  a rewritten `chain.parent_capsule_id` pointing at a nonexistent capsule
  (`store_ok: false`, `chain_parent_missing`).
- **`tests/anchor_conformance.rs`** — spins up a REAL `capsule-anchor`
  instance (`uvicorn`, the same `CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1` /
  `CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1` env vars `capsule-anchor`'s own test
  suite uses — a real HTTP server, not an in-process test client), registers
  a digest via `AnchorClient::post_digest`, resolves it via
  `check_inclusion`, and verifies the returned COSE Receipt with the
  independent `scitt_cose.verify_receipt` — completing the "inclusion" leg
  of "verifies end-to-end (chain + inclusion + signature)". **Real run:
  green** — genuine receipt verifies (`ok: true`); a receipt never submitted
  correctly resolves to `None` (not registered as a side effect of
  checking); a tampered receipt is rejected (`InvalidSignature`); the same
  genuine receipt verified against the wrong authority key is also rejected.
- **`tests/verify_cli.rs`** — NOT gated (self-contained, no external
  workspace or Python needed) and runs in every `cargo test`: exercises the
  compiled `verify_capsule` binary (not the library functions directly)
  against a real chained, ledgered capsule, with and without a `ledger_dir`,
  and against a tampered statement.

Reproduce for real:

```bash
AAC_PYTHON=python3 \
AAC_VERIFY_LEDGER_SCRIPT=$PWD/tests/scripts/verify_rust_ledger.py \
  cargo test --test chain_ledger_conformance -- --ignored --nocapture

AAC_PYTHON=python3 \
AAC_VERIFY_ANCHOR_RECEIPT_SCRIPT=$PWD/tests/scripts/verify_anchor_receipt.py \
CAPSULE_ANCHOR_DIR=/path/to/capsule-anchor/packages \
  cargo test --test anchor_conformance -- --ignored --nocapture --test-threads=1
```

## Unit tests (self-contained, run in every `cargo test --lib`)

18 unit tests, up from M1's 4: chain-block construction and its digest
independence (`capsule.rs`, 3), ledger append/restart-recovery/receipt-lookup/
torn-write/corruption-rejection (`ledger.rs`, 5), and key
persist/permissions/rotation/archived-key-still-verifies (`keys.rs`, 6),
alongside M1's 4 JCS tests. Every negative test asserts the specific error
variant returned, not just "it errors" — per QUEUE_PROTOCOL §7, each of
these is a check that can and does fail its mutant (a tampered ledger entry,
a chain-head mismatch, a torn write, a wrong key) rather than a
skip/pass-through.

## Design decisions worth flagging

- **Ledger shape**: kept the sidecar's flat `capsules.jsonl` +
  `signed-statements/` shape rather than adopting `capsule_ledger`'s
  segmented-JSONL-plus-rebuildable-SQLite-index design. The task scope is
  "durable local ledger: append, chain recovery, receipt lookup" for this
  producer crate, not a port of `capsule_ledger` itself; the simpler shape
  meets all three named requirements and stays interoperable with the
  existing Python tooling that already reads it.
- **Key rotation as ledger event**: `keys::rotate()` returns a
  `RotationRecord` rather than writing it into the ledger itself — the
  caller decides the event's `action_id`/`timestamp`/etc. and appends it as
  an ordinary capsule via the same `seal`/`Ledger::append` path everything
  else uses, so the transition is part of the durable, chained record
  without a second, parallel event-logging mechanism.
- **Anchor client is genuinely optional**: not called from `seal` or
  `Ledger::append`. A caller wires it in explicitly, and per
  `capsule_emit/witness.py`'s precedent, a network failure there must never
  block or invalidate local capsule production.

## What's still open

- No rotation *policy* (when to rotate, cadence) exists on either side of
  this system — M1's report already flagged this as absent from the Python
  producer too; this milestone ports the *mechanism* (swap + archive +
  transition record), not a policy, per the same reasoning.
- Anchor client posts one capsule_id digest at a time; it does not implement
  `capsule_emit/witness.py`'s cadence-gated MMR-checkpoint batching. The
  task scope was "optional ANCHOR client (post checkpoint digest, accurate
  durable status)" against `capsule-anchor`'s `/v1/digest` surface, which
  this delivers; checkpoint batching is a separate, larger design (MMR
  state, signer identity across restarts) better scoped as its own task if
  wanted.
