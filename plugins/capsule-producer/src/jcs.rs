//! Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule §2, §5.1).
//!
//! Line-for-line port of `agent-action-capsule/python/agent_action_capsule/canonical.py`
//! as of the `json_digest`/`vintage_json_digest` split (commit `eea399c`,
//! 2026-08-28): current JSON-DIGEST is `HEX(SHA-256(JCS(v)))` using plain RFC
//! 8785 JCS, with NO absent-field normalization -- normalization is reserved
//! for `vintage_json_digest`, the format-2 Capsule-ID verification path only.
//! Kept independent of the capsule model so it can be cross-checked against the
//! Python reference's frozen `test-vectors/canonical-*` fixtures on arbitrary
//! JSON, not just AAC capsules.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// IEEE-754 double "safe integer" bound (ECMAScript Number.MAX_SAFE_INTEGER).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991; // 2^53 - 1

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("JSON floating-point value in a digest-bearing field; §5.1 requires exact decimal strings for monetary/quantity values")]
    FloatInDigest,
    #[error("integer {0} is outside the safe range +/-{MAX_SAFE_INTEGER}; represent large integers as exact decimal strings (§5.1)")]
    UnsafeInteger(i128),
    #[error("value is not JSON-serializable here")]
    NotSerializable,
}

/// Absent-field normalization (§2): remove members whose value is null, an empty
/// array, or an empty object, bottom-up. Used ONLY by [`vintage_json_digest`]
/// (format-2 Capsule-ID verification) -- new digests use plain [`json_digest`],
/// which does not normalize.
pub fn normalize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, val) in map {
                let nv = normalize(val);
                let drop = match &nv {
                    Value::Null => true,
                    Value::Array(a) => a.is_empty(),
                    Value::Object(o) => o.is_empty(),
                    _ => false,
                };
                if !drop {
                    out.insert(key.clone(), nv);
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        let o = ch as u32;
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ if o == 0x08 => out.push_str("\\b"),
            _ if o == 0x09 => out.push_str("\\t"),
            _ if o == 0x0A => out.push_str("\\n"),
            _ if o == 0x0C => out.push_str("\\f"),
            _ if o == 0x0D => out.push_str("\\r"),
            _ if o < 0x20 => out.push_str(&format!("\\u{o:04x}")),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn jcs_value(v: &Value, out: &mut String) -> Result<(), JcsError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => jcs_string(s, out),
        Value::Number(n) => {
            if n.is_f64() && !(n.is_i64() || n.is_u64()) {
                return Err(JcsError::FloatInDigest);
            }
            if let Some(i) = n.as_i64() {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                    return Err(JcsError::UnsafeInteger(i as i128));
                }
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER as u64 {
                    return Err(JcsError::UnsafeInteger(u as i128));
                }
                out.push_str(&u.to_string());
            } else {
                // Only reachable for f64 (arbitrary_precision is not enabled).
                return Err(JcsError::FloatInDigest);
            }
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, x) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_value(x, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: object members sorted by UTF-16 code unit sequence.
            let mut items: Vec<(&String, &Value)> = map.iter().collect();
            items.sort_by(|(a, _), (b, _)| {
                let au = utf16_units(a);
                let bu = utf16_units(b);
                match au.cmp(&bu) {
                    Ordering::Equal => a.cmp(b),
                    other => other,
                }
            });
            out.push('{');
            for (i, (k, val)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_string(k, out);
                out.push(':');
                jcs_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 JCS serialization of `v` as UTF-8 bytes (no normalization).
pub fn jcs(v: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = String::new();
    jcs_value(v, &mut out)?;
    Ok(out.into_bytes())
}

/// Current JSON-DIGEST (§2): lowercase-hex SHA-256 of plain JCS.
///
/// Absent-field normalization is reserved for vintage Capsule-ID verification
/// ([`vintage_json_digest`]) and is not used for newly produced digests --
/// e.g. request/response body digests, `tool_calls_digest`/`reasoning_digest`.
/// An explicit JSON `null` in the input (a real, common case: OpenAI-shaped
/// request bodies routinely carry `"stop": null`) changes this digest, unlike
/// [`vintage_json_digest`], which drops it.
pub fn json_digest(v: &Value) -> Result<String, JcsError> {
    let bytes = jcs(v)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Verification-only format-2 JSON-DIGEST using absent-field normalization:
/// lowercase-hex SHA-256 of JCS(normalize(v)). Used ONLY by
/// [`compute_capsule_id`] for a capsule with no `canonicalization_id`
/// declaration (the vintage/format-2 construction) -- never for a newly
/// produced digest.
pub fn vintage_json_digest(v: &Value) -> Result<String, JcsError> {
    let bytes = jcs(&normalize(v))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Fields excluded from the canonical capsule form under BOTH constructions
/// (§5.1): `capsule_id`/`chain` (the vintage absent-field identity
/// construction) plus the producer-envelope bookkeeping fields that are NEVER
/// part of any `capsule_id` preimage under any format -- `signature`/`key_id`
/// are attached to a ledger line AFTER the id is computed, so hashing them in
/// would hash a signature into the id it signs.
pub const CHAIN_LINKAGE_FIELDS: &[&str] = &["capsule_id", "chain"];
pub const LOCAL_ONLY_FIELDS: &[&str] = &["signature", "key_id"];

/// Recompute `capsule_id` (§5.1): the JSON-DIGEST of the canonical capsule
/// form. This plugin's `seal()` never declares `canonicalization_id`, so every
/// capsule it produces is the vintage/format-2 construction: exclude
/// `capsule_id`/`chain`/`signature`/`key_id`, then apply the NORMALIZING
/// [`vintage_json_digest`] -- matching the Python reference's
/// `compute_capsule_id` for a capsule with no `canonicalization_id` field.
/// This MUST stay on the normalizing path: sealed capsule bodies routinely
/// carry explicit nulls (e.g. `serving_provenance.hostname` when the host
/// reported none -- see `capsule::tests::sealed_capsule_body_can_carry_a_null`),
/// so switching this to the non-normalizing [`json_digest`] would change the
/// `capsule_id` of every already-ledgered capsule that has one, breaking
/// re-verification. Migrating to the `jcs`-declared, non-normalizing
/// construction is a producer-format change, not a digest-function port --
/// out of scope here; see `[capsule-emit-mesh-jcs-vintage-split]`.
pub fn compute_capsule_id(capsule: &Value) -> Result<String, JcsError> {
    let obj = capsule.as_object().ok_or(JcsError::NotSerializable)?;
    let mut canonical = Map::new();
    for (k, v) in obj {
        if !CHAIN_LINKAGE_FIELDS.contains(&k.as_str())
            && !LOCAL_ONLY_FIELDS.contains(&k.as_str())
        {
            canonical.insert(k.clone(), v.clone());
        }
    }
    vintage_json_digest(&Value::Object(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_drops_null_and_empty() {
        let v = json!({"a": null, "b": [], "c": {}, "d": "keep", "e": {"f": null}});
        assert_eq!(normalize(&v), json!({"d": "keep"}));
    }

    /// [capsule-emit-mesh-jcs-vintage-split] `json_digest` (current/new) must
    /// NOT normalize -- an explicit null must change the digest, unlike
    /// `vintage_json_digest`, which drops it. This is the exact drift class
    /// `canonical_body_digest_matches_mesh_llm_on_a_body_with_explicit_nulls`
    /// (`admission-policy/src/capsule_emit.rs`) pins at the plugin layer; this
    /// test pins the same property at the `jcs` module layer directly.
    #[test]
    fn json_digest_does_not_normalize_but_vintage_json_digest_does() {
        let with_null = json!({"a": "keep", "b": null});
        let without_null = json!({"a": "keep"});

        // Plain json_digest sees the null and differs from the null-free form.
        assert_ne!(
            json_digest(&with_null).unwrap(),
            json_digest(&without_null).unwrap(),
            "json_digest must not normalize away an explicit null"
        );

        // vintage_json_digest normalizes the null away, landing on the SAME
        // digest as the null-free form -- and the same as normalize()+jcs()
        // composed by hand, i.e. what json_digest used to compute pre-split.
        assert_eq!(
            vintage_json_digest(&with_null).unwrap(),
            vintage_json_digest(&without_null).unwrap(),
            "vintage_json_digest must still normalize away an explicit null"
        );
        assert_eq!(
            vintage_json_digest(&with_null).unwrap(),
            json_digest(&without_null).unwrap(),
        );
    }

    /// `compute_capsule_id` must stay on the normalizing path (a capsule with
    /// no `canonicalization_id` is the vintage/format-2 construction) -- an
    /// explicit null on a non-linkage field must NOT change the recomputed id.
    #[test]
    fn compute_capsule_id_still_normalizes_explicit_nulls() {
        let with_null = json!({"action_id": "a", "note": null});
        let without_null = json!({"action_id": "a"});
        assert_eq!(
            compute_capsule_id(&with_null).unwrap(),
            compute_capsule_id(&without_null).unwrap(),
            "compute_capsule_id must remain on the vintage normalizing path"
        );
    }

    /// `compute_capsule_id` excludes `signature`/`key_id` (LOCAL_ONLY_FIELDS)
    /// from the preimage, same as `capsule_id`/`chain` -- mirrors the Python
    /// reference exactly, even though no call site in this crate ever passes a
    /// capsule value carrying either field today (see the module doc).
    #[test]
    fn compute_capsule_id_excludes_local_only_fields() {
        let base = json!({"action_id": "a"});
        let with_envelope = json!({"action_id": "a", "signature": "deadbeef", "key_id": "k1"});
        assert_eq!(
            compute_capsule_id(&base).unwrap(),
            compute_capsule_id(&with_envelope).unwrap()
        );
    }

    #[test]
    fn jcs_sorts_object_keys() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(jcs(&v).unwrap(), b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn jcs_rejects_float() {
        let v = json!({"a": 1.5});
        assert!(matches!(jcs(&v), Err(JcsError::FloatInDigest)));
    }

    #[test]
    fn jcs_escapes_control_chars() {
        let v = json!("q\"b\\s\u{8}\t\n\u{c}\r");
        assert_eq!(jcs(&v).unwrap(), b"\"q\\\"b\\\\s\\b\\t\\n\\f\\r\"".to_vec());
    }
}
