# capsule-producer

The #1332 headline gap: **make the Rust side actually PRODUCE capsules**, not
just admission-decide on them. Today's `admission-policy` plugin only decides
allow/deny; this crate ports capsule production itself into Rust — Milestone
1 de-risked the crypto interop (JCS + COSE_Sign1); Milestone 2 adds
chaining, a durable local ledger, key persistence + rotation, an optional
anchor client, and offline verification.

## Scope

Produce a chained, ledgered, optionally-anchored Agent Action Capsule (AAC)
stream in Rust:

- **`jcs`** — the AAC data model's canonicalization: RFC 8785 JCS +
  absent-field normalization + JSON-DIGEST (SHA-256), a line-for-line port of
  `agent_action_capsule.canonical`.
- **`capsule`** — enough of the envelope (draft-mih-scitt-agent-action-capsule-02
  §5.1) to seal a capsule with a `model_attestation` block carrying the
  `x-mesh-poc-v1` PoC extension namespace (mirrors
  `capsule_sidecar.build_capsule`'s field mapping), and an optional `chain`
  block (`{parent_capsule_id, relation}`, mirroring `emit.py`'s `Chain`
  wiring — `assurance.ledger_mode` flips "chained"/"standalone" accordingly).
- **`keys`** — Ed25519 key gen/load/persist/rotate, PEM PKCS8 (private) /
  SPKI (public), the same encodings Python's `cryptography` library
  produces. `load_or_create` mirrors
  `capsule_sidecar.load_or_create_signing_key` (0600, generate-once);
  `rotate` archives the outgoing key (both halves, keyed by `key_id`) and
  activates a fresh one, so a capsule signed before rotation still verifies
  against the archived public key.
- **`cose`** — COSE_Sign1 producer/verifier matching `scitt_cose`'s wire shape
  (protected header: alg=EdDSA forced, content_type, CWT Claims at label 15
  per RFC 9597 — **not** label 13/kcwt).
- **`ledger`** — durable local ledger: `capsules.jsonl` +
  `signed-statements/<id>.cose` (same on-disk shape as
  `capsule_sidecar.py`'s `NodeState`, so existing Python tooling reading a
  Rust-written ledger needs no changes). Restart-safe: `Ledger::open()`
  replays the file and recovers the chain head from disk alone. A torn write
  (crash mid-append) is truncated away during recovery, never trusted;
  corruption in a fully-written line (tampered `capsule_id`, broken chain
  link) is a hard error, never a silent drop.
- **`anchor`** — optional SCITT Transparency Service client:
  `POST /v1/digest`, `GET /v1/inclusion/{capsule_id}`,
  `GET /anchor/authority-pubkey` — matching `capsule_emit/checkpoint/emit.py`'s
  `register_checkpoint` wire contract. Not wired into `seal`/`ledger::append`;
  callers anchor explicitly, and a failed anchor call never invalidates an
  already-ledgered capsule.
- **`verify`** / **`bin/verify_capsule`** — offline (no-network)
  verification: recompute `capsule_id`, verify the COSE_Sign1 signature,
  check the payload matches the supplied capsule, and (given a ledger
  directory) check chain-parent membership. CLI:
  `verify_capsule <capsule.json> <statement.cose> <pubkey.pem> [ledger_dir]`.

## Cross-language / cross-service conformance

Five `#[ignore]`d tests (same shape as `admission-policy`'s
`host_runtime_e2e.rs`: CI compile-checks them, doesn't run them, because CI
has no checkout of the private multi-repo workspace they need) plus one
always-on self-contained test:

- `tests/jcs_vectors.rs` — every `canonical-*` fixture in
  `agent-action-capsule/test-vectors/` run through this crate's
  `json_digest`, diffed byte-for-byte against the Python reference.
- `tests/cross_language_conformance.rs` (M1) — one standalone capsule +
  COSE_Sign1 statement verifies GREEN against the Python reference AND the
  independent Go COSE verifier; a mutated statement is rejected by both.
- `tests/chain_ledger_conformance.rs` (M2) — a 3-capsule chain, ledgered and
  restart-recovered, verifies GREEN against the Python reference
  (`scitt_cose` signature check + byte-exact payload +
  `agent_action_capsule.verify.verify_store` chain integrity); a tampered
  signature and a corrupted chain link are both rejected.
- `tests/anchor_conformance.rs` (M2) — registers a digest against a REAL
  local `capsule-anchor` instance, resolves its inclusion proof, and
  verifies the COSE Receipt GREEN with `scitt_cose.verify_receipt`; a
  tampered receipt and the wrong authority key are both rejected.
- `tests/verify_cli.rs` (M2, **not gated** — runs in every `cargo test`) —
  exercises the compiled `verify_capsule` binary against a real chained,
  ledgered capsule and a tampered one.

Run for real (see each test file's module doc for the exact env vars):

```bash
AAC_TEST_VECTORS_DIR=/path/to/agent-action-capsule/test-vectors \
  cargo test --test jcs_vectors -- --ignored --nocapture

AAC_PYTHON=python3 \
AAC_VERIFY_SCRIPT=$PWD/tests/scripts/verify_rust_capsule.py \
AAC_GO_VERIFY_DIR=/path/to/scitt-cose/scitt-cose-go-verify \
  cargo test --test cross_language_conformance -- --ignored --nocapture

AAC_PYTHON=python3 \
AAC_VERIFY_LEDGER_SCRIPT=$PWD/tests/scripts/verify_rust_ledger.py \
  cargo test --test chain_ledger_conformance -- --ignored --nocapture

AAC_PYTHON=python3 \
AAC_VERIFY_ANCHOR_RECEIPT_SCRIPT=$PWD/tests/scripts/verify_anchor_receipt.py \
CAPSULE_ANCHOR_DIR=/path/to/capsule-anchor/packages \
  cargo test --test anchor_conformance -- --ignored --nocapture --test-threads=1
```

Results from the last full runs: see `MILESTONE-1-REPORT.md` and
`MILESTONE-2-REPORT.md`.
