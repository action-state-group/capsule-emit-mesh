# capsule-producer

Milestone 1 of the #1332 headline gap: **make the Rust side actually PRODUCE
capsules**, not just admission-decide on them. Today's `admission-policy`
plugin only decides allow/deny; COSE/ledger/chaining still lives in the
Python sidecar (`capsule_sidecar.py`). This crate is the first slice of
porting capsule production into Rust — de-risking the crypto interop before
chaining/ledger/rotation/anchoring are touched.

## Scope (Milestone 1 only)

Emit ONE valid Agent Action Capsule in Rust:

- **`jcs`** — the AAC data model's canonicalization: RFC 8785 JCS +
  absent-field normalization + JSON-DIGEST (SHA-256), a line-for-line port of
  `agent_action_capsule.canonical`.
- **`capsule`** — enough of the envelope (draft-mih-scitt-agent-action-capsule-02
  §5.1) to seal a standalone (non-chained) capsule with a `model_attestation`
  block carrying the `x-mesh-poc-v1` PoC extension namespace (mirrors
  `capsule_sidecar.build_capsule`'s field mapping).
- **`keys`** — Ed25519 key gen/load, PEM PKCS8 (private) / SPKI (public), the
  same encodings Python's `cryptography` library produces — a key generated
  by either side loads in the other.
- **`cose`** — COSE_Sign1 producer/verifier matching `scitt_cose`'s wire shape
  (protected header: alg=EdDSA forced, content_type, CWT Claims at label 15
  per RFC 9597 — **not** label 13/kcwt).

**Explicitly NOT in scope**: chaining, ledger, key rotation, anchoring. No
live-proxy state either (no `forwarded_copy`/`cross_party`/bilateral
evaluation — those depend on sidecar runtime state this milestone doesn't
have reason to duplicate yet).

## Cross-language conformance

Two `#[ignore]`d tests (same shape as `admission-policy`'s
`host_runtime_e2e.rs`: CI compile-checks them, doesn't run them, because CI
has no checkout of the private multi-repo workspace they need):

- `tests/jcs_vectors.rs` — every `canonical-*` fixture in
  `agent-action-capsule/test-vectors/` (RFC 8785 JCS edge cases: UTF-16 key
  sort vs. codepoint sort, non-BMP values, float/unsafe-integer rejection,
  empty-member normalization, control-char escaping, …) run through this
  crate's `json_digest`, diffed byte-for-byte against the Python reference's
  frozen `expected.json`.
- `tests/cross_language_conformance.rs` — builds one representative capsule +
  COSE_Sign1 statement in Rust, then verifies it GREEN against **both** the
  Python reference (`agent_action_capsule.verify` + `scitt_cose`) **and** the
  independent Go COSE verifier (`scitt-cose-go-verify`, built on
  `veraison/go-cose` — a clean-room second opinion so a `coset`-crate-specific
  bug can't be masked by testing against itself), then flips one signature
  byte and confirms **both** verifiers reject it.

Run for real (see each test file's module doc for the exact env vars):

```bash
AAC_TEST_VECTORS_DIR=/path/to/agent-action-capsule/test-vectors \
  cargo test --test jcs_vectors -- --ignored --nocapture

AAC_PYTHON=python3 \
AAC_VERIFY_SCRIPT=$PWD/tests/scripts/verify_rust_capsule.py \
AAC_GO_VERIFY_DIR=/path/to/scitt-cose/scitt-cose-go-verify \
  cargo test --test cross_language_conformance -- --ignored --nocapture
```

Results from the last full run: see `MILESTONE-1-REPORT.md`.
