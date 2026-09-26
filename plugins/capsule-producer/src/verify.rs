//! Offline verification: recompute `capsule_id`, verify the COSE_Sign1
//! signature, check the COSE payload matches the supplied capsule bytes, and
//! (when a store of known `capsule_id`s is given) check chain-parent
//! membership -- entirely local, no network calls. Mirrors the composition
//! `agent_action_capsule.verify()` (JCS/chain structural checks) +
//! `scitt_cose.verify_sign1()` (signature) perform together on the Python
//! side, so a capsule this crate calls `ok()` verifies for the same reasons
//! the Python reference would call it ok.
//!
//! Chain-parent-membership follows `verify.py` Check 6 exactly: with no
//! store supplied, an unresolvable parent is an `info`-level finding, not a
//! failure (the capsule may simply be verified in isolation, without its
//! ledger); with a store, a missing parent gates the verdict.

use crate::cose::verify_signed_statement;
use crate::jcs::compute_capsule_id;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug)]
pub struct VerifyReport {
    pub capsule_id_ok: bool,
    pub cose_ok: bool,
    pub payload_matches_capsule: bool,
    /// The COSE protected header's CWT `sub` claim equals the recomputed
    /// `capsule_id`. GATED by [`ok`](Self::ok): a receipt whose subject was
    /// spliced from another capsule must not verify green -- previously this
    /// mismatch only landed in `findings` and `ok()` still passed.
    pub subject_matches_capsule_id: bool,
    pub chain_ok: bool,
    pub capsule_id: Option<String>,
    pub findings: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.capsule_id_ok
            && self.cose_ok
            && self.payload_matches_capsule
            && self.subject_matches_capsule_id
            && self.chain_ok
    }
}

pub fn verify_offline(
    capsule: &Value,
    signed_statement: &[u8],
    verifying_key: &VerifyingKey,
    known_capsule_ids: Option<&HashSet<String>>,
) -> VerifyReport {
    let mut findings = Vec::new();
    let mut capsule_id_ok = false;
    let mut capsule_id: Option<String> = None;

    match compute_capsule_id(capsule) {
        Ok(recomputed) => {
            let stored = capsule.get("capsule_id").and_then(Value::as_str);
            if stored == Some(recomputed.as_str()) {
                capsule_id_ok = true;
                capsule_id = Some(recomputed);
            } else {
                findings.push(format!(
                    "capsule_id mismatch: stored {stored:?}, recomputed {recomputed:?}"
                ));
            }
        }
        Err(e) => findings.push(format!("capsule_id computation failed: {e}")),
    }

    let mut cose_ok = false;
    let mut payload_matches_capsule = false;
    let mut subject_matches_capsule_id = false;
    match verify_signed_statement(signed_statement, verifying_key) {
        Ok(verified) => {
            cose_ok = true;
            match serde_json::from_slice::<Value>(&verified.payload) {
                Ok(payload_json) if payload_json == *capsule => payload_matches_capsule = true,
                Ok(_) => findings
                    .push("COSE payload does not match the supplied capsule JSON".to_string()),
                Err(e) => findings.push(format!("COSE payload is not valid JSON: {e}")),
            }
            // Gated (not merely a finding): a spliced CWT subject must fail
            // the overall verdict, matching what the subject claim is FOR --
            // binding the receipt to exactly this capsule_id.
            if verified.subject.is_some() && verified.subject.as_deref() == capsule_id.as_deref()
            {
                subject_matches_capsule_id = true;
            } else {
                findings.push(format!(
                    "COSE subject {:?} does not match recomputed capsule_id {:?}",
                    verified.subject, capsule_id
                ));
            }
        }
        Err(e) => findings.push(format!("COSE verification failed: {e}")),
    }

    let mut chain_ok = true;
    if let Some(chain) = capsule.get("chain") {
        let parent = chain.get("parent_capsule_id").and_then(Value::as_str);
        let relation = chain.get("relation").and_then(Value::as_str);
        match (parent, relation) {
            (Some(p), Some(_)) => {
                if let Some(store) = known_capsule_ids {
                    if !store.contains(p) {
                        chain_ok = false;
                        findings.push(format!("chain parent {p} not found in supplied store"));
                    }
                } else {
                    findings.push(
                        "chain present but no store supplied -- parent membership not checked (info, non-gating)"
                            .to_string(),
                    );
                }
            }
            _ => {
                chain_ok = false;
                findings.push(
                    "chain block malformed: missing parent_capsule_id or relation".to_string(),
                );
            }
        }
    }

    VerifyReport {
        capsule_id_ok,
        cose_ok,
        payload_matches_capsule,
        subject_matches_capsule_id,
        chain_ok,
        capsule_id,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::{build_signed_statement, SignedStatementInput};
    use crate::jcs::compute_capsule_id;
    use serde_json::{json, Map};

    fn sample_capsule(seed: &str) -> Value {
        let mut body = Map::new();
        body.insert(
            "spec_version".into(),
            json!("draft-mih-scitt-agent-action-capsule-02"),
        );
        body.insert("format_version".into(), json!("4"));
        body.insert("canonicalization_id".into(), json!("jcs"));
        body.insert("action_id".into(), json!(format!("verify-test/{seed}")));
        body.insert("seed".into(), json!(seed));
        let capsule_id = compute_capsule_id(&Value::Object(body.clone())).unwrap();
        body.insert("capsule_id".into(), json!(capsule_id));
        Value::Object(body)
    }

    fn statement_with_subject(capsule: &Value, subject: &str, key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        build_signed_statement(
            &SignedStatementInput {
                payload: &serde_json::to_vec(capsule).unwrap(),
                issuer: "verify-test",
                subject,
                content_type: "application/vnd.agent-action-capsule+json",
            },
            key,
        )
    }

    #[test]
    fn genuine_statement_verifies_green_with_subject_gated() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let capsule = sample_capsule("one");
        let capsule_id = capsule["capsule_id"].as_str().unwrap();
        let statement = statement_with_subject(&capsule, capsule_id, &key);

        let report = verify_offline(&capsule, &statement, &key.verifying_key(), None);
        assert!(report.subject_matches_capsule_id, "{:?}", report.findings);
        assert!(report.ok(), "{:?}", report.findings);
    }

    /// The spliced-subject receipt: signature and payload are genuine, but
    /// the CWT `sub` claim names ANOTHER capsule -- `ok()` must gate on it,
    /// not just note it in findings.
    #[test]
    fn spliced_cwt_subject_fails_the_overall_verdict() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let capsule = sample_capsule("one");
        let other_id = "f".repeat(64);
        let statement = statement_with_subject(&capsule, &other_id, &key);

        let report = verify_offline(&capsule, &statement, &key.verifying_key(), None);
        // The splice's whole point: every previously-gated boolean passes...
        assert!(report.capsule_id_ok);
        assert!(report.cose_ok);
        assert!(report.payload_matches_capsule);
        assert!(report.chain_ok);
        // ...and only the subject gate stands between it and a green verdict.
        assert!(!report.subject_matches_capsule_id);
        assert!(!report.ok(), "a spliced subject must not verify green");
        assert!(report
            .findings
            .iter()
            .any(|f| f.contains("COSE subject")));
    }
}
