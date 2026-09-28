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
//! **Where padding lives: here, in this producer's store -- not in CLL.**
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

use crate::capsule::{fresh_store_nonce, STORE_NONCE_FIELD};
use crate::jcs::{compute_capsule_id, JcsError};
use serde_json::{json, Map, Value};

/// The reserved `record_type` token. PROVISIONAL -- see the module doc.
pub const RECORD_TYPE_PADDING: &str = "padding";

/// The detached signed statement's content type for a padding record -- it
/// is not a capsule, so it never claims the capsule media type.
pub const PADDING_CONTENT_TYPE: &str = "application/json";

/// The `epistemic_type` §12.1 gives a padding record.
pub const PADDING_EPISTEMIC_TYPE: &str = "producer_claim";

/// Whether `record` is a padding record. Every reader that counts, lists or
/// summarises records skips a record for which this is true.
pub fn is_padding(record: &Value) -> bool {
    record.get("record_type").and_then(Value::as_str) == Some(RECORD_TYPE_PADDING)
}

/// A padding record that carries anything beyond its allowed members is not
/// one this store wrote -- refused on append and on reload. Returns the
/// offending member.
pub fn check_padding_shape(record: &Value) -> Result<(), String> {
    let obj = record
        .as_object()
        .ok_or_else(|| "padding record is not a JSON object".to_string())?;
    const ALLOWED: &[&str] = &[
        "capsule_id",
        "record_type",
        "epistemic_type",
        STORE_NONCE_FIELD,
        "signature",
        "key_id",
    ];
    if let Some(extra) = obj.keys().find(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(format!(
            "padding record carries {extra:?}; its only content is the store nonce"
        ));
    }
    let nonce_ok = obj
        .get(STORE_NONCE_FIELD)
        .and_then(Value::as_str)
        .is_some_and(|n| {
            n.len() == 64
                && n.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        });
    if !nonce_ok {
        return Err("padding record's store_nonce is not 64 lowercase hex".to_string());
    }
    Ok(())
}

/// Build one padding record with a fresh store nonce, its `capsule_id`
/// computed over the committed members exactly as every other record's is.
/// The caller attaches the producer envelope and appends it through
/// [`crate::ledger::Ledger::append_padding`].
pub fn build_padding_record() -> Result<Value, JcsError> {
    let mut body = Map::new();
    body.insert("record_type".into(), json!(RECORD_TYPE_PADDING));
    body.insert("epistemic_type".into(), json!(PADDING_EPISTEMIC_TYPE));
    body.insert(STORE_NONCE_FIELD.into(), json!(fresh_store_nonce()));
    let capsule_id = compute_capsule_id(&Value::Object(body.clone()))?;
    let mut record = Map::new();
    record.insert("capsule_id".into(), json!(capsule_id));
    record.extend(body);
    Ok(Value::Object(record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_record_is_well_formed_and_unique() {
        let a = build_padding_record().unwrap();
        let b = build_padding_record().unwrap();
        assert!(is_padding(&a));
        check_padding_shape(&a).unwrap();
        assert_ne!(a["capsule_id"], b["capsule_id"], "fresh nonce per record");
        assert_eq!(
            compute_capsule_id(&a).unwrap(),
            a["capsule_id"].as_str().unwrap()
        );
        for absent in ["chain", "references", "timestamp", "model_attestation"] {
            assert!(a.get(absent).is_none(), "{absent} must be absent");
        }
    }

    #[test]
    fn shape_check_refuses_links_and_content() {
        let mut rec = build_padding_record().unwrap();
        rec["chain"] = json!({"parent_capsule_id": "a".repeat(64), "relation": "follows"});
        assert!(check_padding_shape(&rec).is_err());
        let mut rec = build_padding_record().unwrap();
        rec[STORE_NONCE_FIELD] = json!("short");
        assert!(check_padding_shape(&rec).is_err());
    }

    #[test]
    fn ordinary_records_are_not_padding() {
        assert!(!is_padding(&json!({"capsule_id": "a".repeat(64)})));
        assert!(!is_padding(&json!({"record_type": "close"})));
    }
}
