//! Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule-04 §2, §5.1).
//!
//! Owned by the `evidencebook` crate (`evidencebook::canonical`) and
//! re-exported here unchanged, so a record this plugin seals and a record the
//! book seals get their `capsule_id` from one implementation.

pub use evidencebook::canonical::*;
