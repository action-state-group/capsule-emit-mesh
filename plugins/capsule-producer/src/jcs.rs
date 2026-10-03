//! Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule §2, §5.1).
//!
//! Line-for-line port of `agent-action-capsule/python/agent_action_capsule/canonical.py`:
//! JSON-DIGEST := HEX(SHA-256(JCS(normalize(v)))), where JCS is RFC 8785's JSON
//! Canonicalization Scheme and `normalize` is the profile's bottom-up absent-field
//! removal (§2). Kept independent of the capsule model so it can be cross-checked
//! against the Python reference's frozen `test-vectors/canonical-*` fixtures on
//! arbitrary JSON, not just AAC capsules.

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
    #[error("a format-4 capsule must carry canonicalization_id \"jcs\"")]
    Canonicalization,
}

/// Absent-field normalization (§2): remove members whose value is null, an empty
/// array, or an empty object, bottom-up.
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

/// JSON-DIGEST (§2): lowercase-hex SHA-256 of JCS(normalize(v)).
pub fn json_digest(v: &Value) -> Result<String, JcsError> {
    let bytes = jcs(&normalize(v))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Fields excluded from a format-2 capsule's canonical form (the -02 rule).
pub const CHAIN_LINKAGE_FIELDS: &[&str] = &["capsule_id", "chain"];

/// Fields excluded from a format-4 capsule's canonical form (-04/-05 §5.1):
/// the id itself and the local-only producer envelope beside it. Everything
/// else, `chain` and `canonicalization_id` included, is committed.
pub const FORMAT4_EXCLUDED_FIELDS: &[&str] = &["capsule_id", "signature", "key_id"];

/// Recompute `capsule_id` (§5.1). A format-4 capsule (what this producer
/// emits, -04/-05): SHA-256 of plain RFC 8785 JCS over every member but
/// [`FORMAT4_EXCLUDED_FIELDS`], and `canonicalization_id` must be "jcs".
/// Anything else is read by the earlier -02 rule (JSON-DIGEST, `chain`
/// excluded), so ledgers sealed before keep verifying.
pub fn compute_capsule_id(capsule: &Value) -> Result<String, JcsError> {
    let obj = capsule.as_object().ok_or(JcsError::NotSerializable)?;
    if obj.get("format_version").and_then(Value::as_str) == Some("4") {
        if obj.get("canonicalization_id").and_then(Value::as_str) != Some("jcs") {
            return Err(JcsError::Canonicalization);
        }
        let canonical: Map<String, Value> = obj
            .iter()
            .filter(|(k, _)| !FORMAT4_EXCLUDED_FIELDS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let bytes = jcs(&Value::Object(canonical))?;
        return Ok(hex::encode(Sha256::digest(&bytes)));
    }
    let mut canonical = Map::new();
    for (k, v) in obj {
        if !CHAIN_LINKAGE_FIELDS.contains(&k.as_str()) {
            canonical.insert(k.clone(), v.clone());
        }
    }
    json_digest(&Value::Object(canonical))
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
