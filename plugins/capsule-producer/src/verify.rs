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
    pub chain_ok: bool,
    pub capsule_id: Option<String>,
    pub findings: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.capsule_id_ok && self.cose_ok && self.payload_matches_capsule && self.chain_ok
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
    match verify_signed_statement(signed_statement, verifying_key) {
        Ok(verified) => {
            cose_ok = true;
            match serde_json::from_slice::<Value>(&verified.payload) {
                Ok(payload_json) if payload_json == *capsule => payload_matches_capsule = true,
                Ok(_) => findings
                    .push("COSE payload does not match the supplied capsule JSON".to_string()),
                Err(e) => findings.push(format!("COSE payload is not valid JSON: {e}")),
            }
            if verified.subject.as_deref() != capsule_id.as_deref() {
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
        chain_ok,
        capsule_id,
        findings,
    }
}
