//! The #1332 headline gap, Rust side: produce a chained, ledgered,
//! optionally-anchored Agent Action Capsule (AAC) stream, signed as
//! COSE_Sign1, that verifies end-to-end against the Python/scitt-cose
//! reference. Milestone 1 de-risked crypto interop (JCS + COSE_Sign1);
//! Milestone 2 adds chaining, a durable local ledger, key persistence +
//! rotation, an optional anchor client, and offline verification.
//!
//! Modules:
//! - [`jcs`] RFC 8785 JCS canonicalization + JSON-DIGEST (§2, §5.1).
//! - [`capsule`] The AAC envelope subset this crate emits, including the
//!   `chain` block and `x-mesh-poc-v1` extension namespace.
//! - [`keys`] Ed25519 key gen/load/persist/rotate (PEM PKCS8 / SPKI,
//!   cross-loadable with Python's `cryptography` library).
//! - [`cose`] COSE_Sign1 producer/verifier matching `scitt_cose`'s wire shape.
//! - [`ledger`] Durable local ledger: append, restart-safe chain recovery,
//!   receipt lookup.
//! - [`anchor`] Optional SCITT Transparency Service client
//!   (`capsule-anchor`'s `/v1/digest` + `/v1/inclusion/{id}`).
//! - [`anchor_queue`] Durable anchor state machine (pending / submitted /
//!   anchored / rejected / failed) + restart-safe retry queue on top of
//!   [`anchor`].
//! - [`verify`] Offline (no-network) verification composing capsule_id
//!   recomputation, COSE signature verification, and chain-parent
//!   membership.

pub mod anchor;
pub mod anchor_queue;
pub mod capsule;
pub mod cose;
pub mod jcs;
pub mod keys;
pub mod ledger;
pub mod timestamp;
pub mod verify;
