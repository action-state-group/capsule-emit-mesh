# Milestone 1 report — Rust capsule production, crypto interop

Task: `[mesh-rust-capsule-production]`. Scope: emit ONE valid Agent Action
Capsule in Rust and prove byte-exact / cross-language conformance with the
Python reference and an independent Go COSE verifier, before touching
chaining/ledger/rotation/anchoring.

## Result

All three acceptance checks passed on the first real cross-language run
(2026-08-22), no round-trip fixups needed after the initial implementation:

1. **JCS canonicalization** — all 24 `canonical-*` vectors in
   `agent-action-capsule/test-vectors/` matched byte-for-byte, including the
   two rejection cases (`FloatInDigestError`, `UnsafeIntegerError`).
2. **Python reference** (`agent_action_capsule.verify` + `scitt_cose`) —
   accepted a Rust-produced capsule + COSE_Sign1 statement: `cose_ok=true`,
   `capsule_ok=true`, recomputed `capsule_id` matched.
3. **Independent Go verifier** (`scitt-cose-go-verify`, `veraison/go-cose`) —
   `valid=true`, `iss`/`sub`/`content_type` matched.
4. **Mutation rejection** — flipping one byte inside the COSE signature was
   rejected by the Python verifier, the Go verifier, **and** this crate's own
   independent re-verifier (`cose::verify_signed_statement`).

Full transcript is reproducible via the commands in `README.md`.

## Exact crates used

| Purpose | Crate | Version | Notes |
|---|---|---|---|
| COSE_Sign1 | `coset` | 0.4.2 | Google's COSE crate; CBOR backend is `ciborium` 0.2.2, which encodes definite-length/minimal-size CBOR by default — no `canonical` flag needed. |
| Ed25519 signing | `ed25519-dalek` | 2.2.0 | `pkcs8`, `pem`, `rand_core` features enabled. |
| PEM PKCS8/SPKI encode | `pkcs8` / `spki` | 0.10.2 / 0.7.3 | `pem` feature on both; matches `cryptography`'s `PrivateFormat.PKCS8` / `PublicFormat.SubjectPublicKeyInfo` output — keys cross-load in both directions. |
| CSPRNG | `rand_core` | 0.6.4 | `getrandom` feature for `OsRng` (ed25519-dalek pins `rand_core` 0.6, not 0.9/1.0 — matching the pin avoids a duplicate-crate-version trait mismatch). |
| JSON | `serde_json` | 1.0 | `preserve_order` feature (cosmetic — output field order; canonicalization sorts independently in `jcs.rs`). |
| SHA-256 | `sha2` | 0.10.9 | |
| Hex | `hex` | 0.4.3 | |
| Errors | `thiserror` | 1.0 | |

## Canonicalization gotchas (would-be pitfalls, and what avoided them)

- **"Canonical" CBOR ≠ byte-identical, order-independent.** `scitt_cose`'s
  `strict_decode` (the check a verifier runs on untrusted COSE bytes) does
  **not** require the protected header's map keys to be in sorted/canonical
  *order* — it only requires *minimal-length* encoding (definite lengths,
  minimal-size integers, no duplicate keys), checked by comparing the
  decoded value's re-encoded length, not its bytes. This means `coset`'s
  default `ciborium`-backed encoding (which does not sort header map keys to
  match Python's insertion order) is still accepted — confirmed empirically,
  not assumed. Chasing byte-identical header ordering would have been wasted
  effort.
- **CWT Claims label is 15, not 13.** RFC 9597 "CWT Claims" is protected
  header label 15; label 13 is `kcwt` (RFC 9528), a different mechanism. The
  Python reference calls this out explicitly as a bug class it guards against
  (`python-cwt`'s CWT_CLAIMS==13 bug); this crate hard-codes 15 and the Go
  verifier's independent constant agrees, so a mislabel would have shown up
  as a claims-extraction failure on the Go side even if Python's COSE
  signature check alone had passed.
- **UTF-16 code-unit sort, not codepoint sort, for JCS object keys.** RFC
  8785 §3.2.3 sorts object members by UTF-16 code-unit sequence. For
  non-BMP keys (surrogate pairs) this differs from a plain Unicode-codepoint
  sort. Rust's `str::encode_utf16()` gives the exact code-unit sequence
  needed; a naive `str::cmp` (codepoint order) would have passed every ASCII
  fixture and only diverged on the one non-BMP vector
  (`canonical-key-sort-utf16-vs-codepoint`) — caught by running the full
  fixture set, not a hand-picked subset.
- **The COSE payload is NOT the JCS form.** `capsule_sidecar.sign_capsule`
  signs `json.dumps(capsule, sort_keys=True, separators=(",", ":"))` — a
  different, simpler deterministic encoding than the JCS form used inside
  `capsule_id`'s digest. Conflating the two would have been a plausible
  mistake (both are "the canonical bytes" in different senses); keeping
  `jcs.rs` and `capsule::payload_bytes` as two independent functions with
  distinct doc comments makes the distinction impossible to lose track of
  later. Byte-identity with Python's own `sort_keys` output was deliberately
  **not** pursued for the COSE payload — `verify()` re-parses it as JSON and
  recomputes `capsule_id` from the parsed object, so only valid-JSON-in +
  correct-signature-over-those-exact-bytes is required.
- **`serde_json::Number` already distinguishes int vs. float** the same way
  Python's `json.loads` does (a literal `3.0` in source JSON parses as a
  float in both), so the float-rejection vectors (`canonical-float-in-value`,
  `canonical-float-integral-valued`) worked without extra handling — no
  custom float-vs-integral-float classification needed on the Rust side.

## Proposed Milestone 2 plan

In dependency order (each step's conformance check gates the next):

1. **Chaining.** Add `chain: {parent_capsule_id, relation}` to `capsule::seal`
   — mechanically small (`compute_capsule_id` already excludes `chain` from
   the digest, matching the Python exclusion), but needs a decision on where
   `prior_capsule_id` state lives once this crate isn't a single-shot binary
   (see Ledger below). Conformance check: a 2-capsule Rust-built chain
   verifies against `capsule_sidecar`'s chain-walking logic and against
   `delegation_chain_verifier.py` if that's the intended consumer.
2. **Ledger.** Decide the storage shape before writing code: does Rust write
   the same `ledger/capsules.jsonl` + `ledger/signed-statements/<id>.cose`
   layout `capsule_sidecar.record_capsule` uses (so the Python tooling that
   already reads that ledger — `run_demo.py`, `bilateral_demo.py` — keeps
   working unmodified), or does the admission-policy plugin need its own
   ledger path because it's a long-lived process rather than a per-request
   CLI invocation? Recommend: keep the on-disk shape identical, decided
   before any code lands, since a shape change later means migrating
   whatever's already been written.
3. **Keys.** `keys.rs` already does gen/load/PEM; what's missing is the
   **persistence + rotation** policy `capsule_sidecar.load_or_create_signing_key`
   implements (generate-on-first-run into `keys/node-key.pem`, 0600, never
   committed). Straightforward port; the open question is rotation policy
   (none exists yet on the Python side either — worth flagging back to
   whoever owns that thread rather than inventing one here).
4. **Anchor.** Out of scope for capsule-emit-mesh entirely at this milestone
   — anchoring talks to `capsule-anchor` (a different repo, different trust
   boundary: the SCITT Transparency Service). Recommend treating this as a
   separate task once 1–3 land, not folded into "milestone 2."

Each step should get its own cross-language conformance test in the same
shape as this milestone's (`#[ignore]`d, gated on env vars, run manually
against the Python/Go reference before merge) — the pattern proved itself
here: every cross-check passed on the first real run because the reference
implementations were read closely *before* writing Rust, not after.
