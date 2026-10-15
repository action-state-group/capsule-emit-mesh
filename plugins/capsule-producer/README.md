# capsule-producer

The Mesh-specific parts of producing Agent Action Capsules in Rust. Sealing,
signing, chaining, the local ledger, checkpoints and offline verification
come from [`capsule-emit`](https://crates.io/crates/capsule-emit) (0.0.8);
this crate keeps only what Mesh adds on top. `admission-policy` uses both.

## Build

`capsule-emit` and its `checkpointed-local-log` come from crates.io. The lock
holds exactly one `checkpointed-local-log` (capsule-emit's).

## Modules

- **`mesh_poc`**: the `x-mesh-poc-v1` extension (`MeshPocV1`,
  `ServingProvenance`, `TokenUsage`) and `extensions()`, which turns it into
  the `compute_attestation` members a capsule carries: `model_revision`,
  `weights_digest`, `quantization`, `decoding`, `source`, `hardware`,
  `invocation`, `epistemic_type` and `x-mesh-poc-v1`. A caller passes them
  to `capsule_emit::capsule::seal` as `CapsuleInput::compute_attestation_extensions`.
  Also mesh-llm's registered `host_binding` labels and
  `validate_host_binding`.
- **`runtime_attest`**: the runtime/binary attestation rung: hash the
  running serving binary and sign a `self_measured` (or, on macOS,
  `os_measured`) reference to it with the node key.
- **`tee_attest`** / **`tee_verify`**: the `tee_measured` rung: an Intel TDX
  DCAP quote bound to one exchange, and its local verification.

## Binaries

- `produce_demo_ledger [OUT_DIR]`: a deterministic three-capsule chain in the
  plugin's ledger format, for cross-language and cross-host checks.
- `verify_capsule <capsule.json> <statement.cose> <pubkey.pem> [ledger_dir]`:
  offline verification, `capsule_emit::verify::verify_offline`.

## Ledger format

The ledger is capsule-emit's: `<ledger_dir>/capsules.jsonl`, one capsule per
line, plus `signed-statements/<capsule_id>.cose`, with `checkpoints.jsonl`
and `mmr_nodes.dat` beside them. It is the same format `capsule-producer`
0.2.0 wrote. `tests/ledger_0_2_0_compat.rs` holds a ledger written by 0.2.0
(`tests/fixtures/ledger-0.2.0/`) to that: it opens with the same chain head,
every record verifies, the checkpoint root is unchanged, and new records
append, chain and checkpoint on top of it.

## Tests

`cargo test` runs everything here; none of it needs another checkout. The
generic conformance tests (JCS vectors, the Python and Go verifiers, the
anchor service, checkpoint invariance) live with the code they test, in
capsule-emit's `rust/capsule-emit/tests/`.
