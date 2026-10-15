//! The Mesh-specific parts of producing Agent Action Capsules. Sealing,
//! signing, chaining, the local ledger, checkpoints and offline verification
//! come from [`capsule_emit`]; this crate keeps only what Mesh adds on top.
//!
//! Modules:
//! - [`mesh_poc`] The `x-mesh-poc-v1` extension and the model/hardware/
//!   invocation members derived from it, passed to
//!   `capsule_emit::capsule::seal` as `compute_attestation` extensions, plus
//!   mesh-llm's registered `host_binding` labels.
//! - [`runtime_attest`] The runtime/binary attestation rung: hash the running
//!   serving binary and record a signed, HONESTLY-LABELED (`self_measured`)
//!   reference to it, shaped like executable code-signing.
//! - [`tee_attest`] The `tee_measured` rung (rung 3c): record shape and
//!   hardware-independent structural parser for an Intel TDX DCAP quote,
//!   binding it to one capsule exchange via a domain-tagged REPORTDATA field.
//! - [`tee_verify`] Local (network-free) verification of a parsed TDX quote:
//!   the REPORTDATA binding, the DCAP cert-chain + signature path, and an
//!   optional Intel Trust Authority token path.

pub mod mesh_poc;
pub mod runtime_attest;
pub mod tee_attest;
pub mod tee_verify;

/// The `developer` this plugin's capsules name: this crate and its version.
pub const DEVELOPER: &str = concat!("capsule-producer/", env!("CARGO_PKG_VERSION"));
