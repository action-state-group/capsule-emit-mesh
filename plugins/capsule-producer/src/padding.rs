//! Padding records (Evidence Layer -00 §12.1, "What a Checkpoint Reveals").
//!
//! A checkpoint states the size of this store's whole committed history, so
//! two checkpoints handed to one party (a pushed bundle's covering
//! checkpoint, a witness registration) tell it how many records this node
//! committed between them -- across every counterparty, not only that party.
//! Before a checkpoint is cut, the store appends padding records until its
//! leaf count (`mmr_leaf_count`, never `mmr_size`) falls on a bucket
//! boundary, so two checkpoints reveal the count between them only to within
//! the bucket.
//!
//! The record shape and its builder are the `evidencebook` crate's
//! (`evidencebook::padding`), re-exported here; this plugin decides when to
//! pad (see `checkpoint::PaddingSink` and `ledger::Ledger::pad_to_bucket`).
//!
//! **Where padding lives: in the store -- not in CLL.**
//! Padding is a record, not a log mechanism: the log folds a padding record's
//! id as an ordinary leaf, and nothing in `checkpointed-local-log` changes.
//! The Evidence Layer -00 draft (AAC #130) reserves `padding` in its own text:
//! no CLL change and no new registry.
//!
//! **Shape.** One ledger line:
//! `{"capsule_id", "record_type": "padding", "epistemic_type":
//! "producer_claim", "store_nonce"}` plus the local-only producer envelope
//! (`signature`/`key_id`, outside the id preimage). Its only committed content
//! is the fresh store nonce. It carries no payload commitments, no `chain`,
//! no `references`, no subject or principal -- and it is never the target of a
//! link: the ledger does NOT advance its chain head over a padding record, so
//! the next real record still chains to the previous real record.
//!
//! **Why `store_nonce` is top-level here but nested in a capsule.** §12.1 only
//! requires the random value to sit inside the bytes the record's commitment
//! entry is derived from; it does not name a location. A capsule has a fixed
//! AAC envelope whose one free-form extension point is
//! `model_attestation.compute_attestation`, so the nonce rides there. A
//! padding record is not a capsule and has no such envelope: its whole body
//! is the committed content, so the nonce sits at the top level. Both are
//! inside the `capsule_id` preimage, which is what the requirement is about.
//!
//! **Readers.** A verifier treats a padding record as an ordinary leaf for
//! inclusion, consistency and checkpoints. Everything that counts, lists or
//! summarises records skips it ([`is_padding`]), and it is never returned as
//! responsive to a record, correlation or exchange query.
//!
//! PROVISIONAL: `record_type: "padding"` is reserved by the Evidence Layer -00
//! draft text (AAC #130); it is a provisional constant pending the
//! evidence-layer privacy considerations text.

pub use evidencebook::padding::{
    build_padding_record, check_padding_shape, is_padding, PADDING_CONTENT_TYPE,
    PADDING_EPISTEMIC_TYPE, RECORD_TYPE_PADDING,
};
