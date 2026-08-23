//! Milestone 1 of the #1332 headline gap: produce ONE valid Agent Action
//! Capsule (AAC), signed as a COSE_Sign1, in Rust — the crypto-interop
//! de-risking step before chaining/ledger/rotation/anchoring get ported.
//!
//! Modules:
//! - [`jcs`] RFC 8785 JCS canonicalization + JSON-DIGEST (§2, §5.1).
//! - [`capsule`] The AAC envelope subset this milestone emits + `x-mesh-poc-v1`.
//! - [`keys`] Ed25519 key gen/load (PEM PKCS8 / SPKI, cross-loadable with
//!   Python's `cryptography` library).
//! - [`cose`] COSE_Sign1 producer/verifier matching `scitt_cose`'s wire shape.

pub mod capsule;
pub mod cose;
pub mod jcs;
pub mod keys;
