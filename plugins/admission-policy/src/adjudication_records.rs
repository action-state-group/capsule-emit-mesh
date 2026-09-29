//! A referee's signed verdict, on the chains it concerns.
//!
//! The door decides and holds (`referee_service.py` on the referee,
//! `adjudication_hold.py` on a node the verdict is delivered to); this plugin,
//! the one writer of its node's chain, seals its own record of that event
//! before the reply leaves:
//!
//! - on the REFEREE, an `adjudication_issued` record, when its door answers an
//!   adjudicate request with a verdict (`mesh_evidence_bridge`);
//! - on a node the verdict is DELIVERED to, an `adjudication_received`
//!   record, when its door holds it (`record_push_bridge`, or
//!   [`deliver`] for this node itself).
//!
//! A seal that fails replies with a refusal instead of the door's answer, so
//! "issued" or "received" always means "on the chain". Both records dedup on
//! the verdict's capsule id.
use std::sync::Arc;

use mesh_llm_plugin::{PluginContext, PluginError, PluginResult};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::capsule_emit::{CapsuleState, VerdictFacts};

/// The member of the referee door's reply that marks an issued verdict
/// (`referee_service.ADJUDICATION_VERDICT_MARKER`).
pub const ADJUDICATION_VERDICT_MARKER: &str = "adjudication_verdict";
/// The member of a record-push body that marks a delivered verdict
/// (`adjudication_hold.DELIVERY_MARKER`).
pub const DELIVERY_MARKER: &str = "adjudication_delivery";
pub const DELIVERY_VERSION: u64 = 1;
pub const DELIVER_OPERATION: &str = "deliver_adjudication";

/// The reply a peer sees when the door answered but this node's chain did not
/// take the record.
pub const SEAL_FAILED_REASON: &str = "citing_record_seal_failed";

pub fn seal_failed_reply() -> Vec<u8> {
    serde_json::to_vec(&json!({ "reason": SEAL_FAILED_REASON })).expect("a static shape serializes")
}

/// One verdict's facts, owned, as a door states them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verdict: String,
    pub verdict_capsule_id: String,
    pub referee_node_id: String,
    pub halves: [String; 2],
    pub half_node_ids: [String; 2],
    pub twin_bracket_id: Option<String>,
}

impl Verdict {
    fn facts(&self) -> VerdictFacts<'_> {
        VerdictFacts {
            verdict: &self.verdict,
            verdict_capsule_id: &self.verdict_capsule_id,
            referee_node_id: &self.referee_node_id,
            halves: [&self.halves[0], &self.halves[1]],
            half_node_ids: [&self.half_node_ids[0], &self.half_node_ids[1]],
            twin_bracket_id: self.twin_bracket_id.as_deref(),
        }
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

fn pair(value: &Value, key: &str) -> Option<[String; 2]> {
    let items = value.get(key)?.as_array()?;
    match items.as_slice() {
        [a, b] => Some([a.as_str()?.to_string(), b.as_str()?.to_string()]),
        _ => None,
    }
}

/// The verdict facts in a door's statement of one, or `None` when any is
/// missing.
pub fn verdict_from(value: &Value) -> Option<Verdict> {
    Some(Verdict {
        verdict: text(value, "verdict")?,
        verdict_capsule_id: text(value, "verdict_capsule_id")?,
        referee_node_id: text(value, "referee_node_id")?,
        halves: pair(value, "halves")?,
        half_node_ids: pair(value, "half_node_ids")?,
        twin_bracket_id: text(value, "twin_bracket_id"),
    })
}

pub fn is_issued_reply(reply: &Value) -> bool {
    reply.get(ADJUDICATION_VERDICT_MARKER).is_some() && reply.get("reason").is_none()
}

pub fn is_delivery_body(body: &Value) -> bool {
    body.get(DELIVERY_MARKER).is_some()
}

/// On the referee: seal `adjudication_issued` for the door's issued reply.
pub async fn seal_issued(capsules: &Arc<CapsuleState>, reply: &Value) -> anyhow::Result<()> {
    let verdict = verdict_from(reply).ok_or_else(|| anyhow::anyhow!("issued reply lacks the verdict facts"))?;
    let referee_capsule_id = text(reply, "referee_capsule_id");
    let issued_at = text(reply, "issued_at").unwrap_or_else(capsule_producer::timestamp::utc_now_minute);
    let sealer = capsules.clone();
    let emitted = tokio::task::spawn_blocking(move || {
        sealer.emit_adjudication_issued(&verdict.facts(), referee_capsule_id.as_deref(), &issued_at)
    })
    .await
    .map_err(|e| anyhow::anyhow!("adjudication seal task did not complete: {e}"))??;
    if let Some(emitted) = emitted {
        tracing::info!(capsule_id = %emitted.capsule_id, "SEALED adjudication_issued record");
        crate::routing_rule::spawn_evaluate(capsules.clone());
    }
    Ok(())
}

/// On a node the verdict was delivered to: seal `adjudication_received` for
/// the door's success reply (its `adjudication` member).
pub async fn seal_received(capsules: &Arc<CapsuleState>, door_reply: &Value) -> anyhow::Result<()> {
    let facts = door_reply
        .get("adjudication")
        .ok_or_else(|| anyhow::anyhow!("door reply names no adjudication"))?;
    let verdict = verdict_from(facts).ok_or_else(|| anyhow::anyhow!("door reply lacks the verdict facts"))?;
    let held_half = text(facts, "held_half_capsule_id").ok_or_else(|| anyhow::anyhow!("door reply names no held half"))?;
    let received_from = text(facts, "received_from").ok_or_else(|| anyhow::anyhow!("door reply names no courier"))?;
    let received_at = text(facts, "received_at").unwrap_or_else(capsule_producer::timestamp::utc_now_minute);
    let sealer = capsules.clone();
    let emitted = tokio::task::spawn_blocking(move || {
        sealer.emit_adjudication_received(&verdict.facts(), &held_half, &received_from, &received_at)
    })
    .await
    .map_err(|e| anyhow::anyhow!("adjudication seal task did not complete: {e}"))??;
    if let Some(emitted) = emitted {
        tracing::info!(capsule_id = %emitted.capsule_id, "SEALED adjudication_received record");
        crate::routing_rule::spawn_evaluate(capsules.clone());
    }
    Ok(())
}

pub fn delivery_body(verdict_capsule: &Value) -> Value {
    json!({ DELIVERY_MARKER: DELIVERY_VERSION, "verdict_capsule": verdict_capsule })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeliverAdjudicationArgs {
    /// The node to deliver to; this node's own id delivers to itself.
    pub peer_id: String,
    /// The referee's signed verdict record, as it issued it.
    pub verdict_capsule: Value,
}

/// Deliver a referee's verdict to `peer_id`: over the record-push stream to
/// a peer, or through this node's own door when `peer_id` is this node.
/// Returns the door's reply (received, or a signed refusal).
pub async fn deliver(
    args: DeliverAdjudicationArgs,
    context: &mut PluginContext<'_>,
    capsules: Arc<CapsuleState>,
    self_id: Option<String>,
) -> PluginResult<Value> {
    let self_id = self_id.ok_or_else(|| PluginError::internal("this node's own mesh id is not known yet"))?;
    let verdict_capsule_id = args
        .verdict_capsule
        .get("capsule_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PluginError::invalid_params("verdict_capsule carries no capsule_id"))?
        .to_string();
    let body = delivery_body(&args.verdict_capsule);
    if args.peer_id != self_id {
        let reply = crate::record_push_bridge::send_push(context, &args.peer_id, &self_id, &body)
            .await
            .map_err(|e| PluginError::internal(e.to_string()))?;
        return with_refusal_recorded(&capsules, reply, &verdict_capsule_id, &args.peer_id).await;
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| PluginError::internal(e.to_string()))?;
    let bytes = serde_json::to_vec(&body).map_err(|e| PluginError::internal(e.to_string()))?;
    let reply = crate::door_auth::call(
        &client,
        reqwest::Method::POST,
        "/evidence/record-push",
        &[("Content-Type", "application/json"), ("X-Mesh-Requester-Id", &self_id)],
        Some(bytes),
    )
    .await
    .map_err(|e| PluginError::internal(format!("this node's door did not answer: {e}")))?;
    let reply: Value = serde_json::from_slice(&reply.body)
        .map_err(|e| PluginError::internal(format!("this node's door answered malformed JSON: {e}")))?;
    if reply.get("status").and_then(Value::as_str) == Some("received") {
        if let Err(error) = seal_received(&capsules, &reply).await {
            tracing::warn!(%error, "door held the delivered verdict but the record seal failed");
            return Ok(json!({ "reason": SEAL_FAILED_REASON }));
        }
        return Ok(reply);
    }
    with_refusal_recorded(&capsules, reply, &verdict_capsule_id, &self_id).await
}

/// A signed refusal of a delivery goes on this node's chain as
/// `adjudication_ack_refused`; the reply gains that record's id. A refusal
/// without a signature (a bridge's own "seal failed", worth a retry) is not
/// recorded.
async fn with_refusal_recorded(
    capsules: &Arc<CapsuleState>,
    mut reply: Value,
    verdict_capsule_id: &str,
    refused_by: &str,
) -> PluginResult<Value> {
    let Some(reason) = text(&reply, "reason") else {
        return Ok(reply);
    };
    if text(&reply, "sig").is_none() {
        return Ok(reply);
    }
    use sha2::Digest;
    let refusal_digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&reply).unwrap_or_default()));
    let refusal_key_id = text(&reply, "key_id");
    let refused_at = capsule_producer::timestamp::utc_now_minute();
    let (capsules, verdict, peer) = (capsules.clone(), verdict_capsule_id.to_string(), refused_by.to_string());
    let emitted = tokio::task::spawn_blocking(move || {
        capsules.emit_adjudication_ack_refused(&capsule_producer::capsule::RefusedDelivery {
            verdict_capsule_id: &verdict,
            refused_by: &peer,
            reason: &reason,
            refusal_digest: &refusal_digest,
            refusal_key_id: refusal_key_id.as_deref(),
            refused_at: &refused_at,
        })
    })
    .await
    .map_err(|e| PluginError::internal(format!("refusal seal task did not complete: {e}")))?
    .map_err(|e| PluginError::internal(format!("could not record the refused delivery: {e}")))?;
    if let Some(emitted) = emitted {
        reply["ack_refused_capsule_id"] = json!(emitted.capsule_id);
    }
    Ok(reply)
}

/// The held verdict files beside the ledger (`referee_service.py`,
/// `adjudication_hold.py`).
pub const ISSUED_ADJUDICATIONS_FILENAME: &str = "issued-adjudications.jsonl";
pub const RECEIVED_ADJUDICATIONS_FILENAME: &str = "received-adjudications.jsonl";

fn held_verdict(ledger_dir: &std::path::Path, verdict_capsule_id: &str) -> Option<Value> {
    for file in [ISSUED_ADJUDICATIONS_FILENAME, RECEIVED_ADJUDICATIONS_FILENAME] {
        let Ok(text) = std::fs::read_to_string(ledger_dir.join(file)) else {
            continue;
        };
        for line in text.lines() {
            let Ok(held) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if held.get("verdict_capsule_id").and_then(Value::as_str) == Some(verdict_capsule_id) {
                if let Some(capsule) = held.get("verdict_capsule") {
                    return Some(capsule.clone());
                }
            }
        }
    }
    None
}

/// `issued` / `received` when this node's chain records the verdict.
fn recorded_as(ledger_dir: &std::path::Path, verdict_capsule_id: &str) -> Option<&'static str> {
    let text = std::fs::read_to_string(ledger_dir.join("capsules.jsonl")).ok()?;
    for line in text.lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(attestation) = record.pointer("/model_attestation/compute_attestation") else {
            continue;
        };
        for (block, kind) in [
            (capsule_producer::capsule::ADJUDICATION_ISSUED_BLOCK, "issued"),
            (capsule_producer::capsule::ADJUDICATION_RECEIVED_BLOCK, "received"),
        ] {
            if attestation.pointer(&format!("/{block}/verdict_capsule_id")).and_then(Value::as_str)
                == Some(verdict_capsule_id)
            {
                return Some(kind);
            }
        }
    }
    None
}

/// `http/ledger/verdict?capsule_id=`: one held verdict, with this plugin's
/// own check of it. `verify_ok` is true only when the referee's signature
/// verifies over the recomputed id AND this node's chain records the verdict
/// -- a record the door seals only after checking that signature is the
/// named referee's announced key. `null` capsule when none is held.
pub fn verdict_json(ledger_dir: &std::path::Path, verdict_capsule_id: &str) -> Value {
    let Some(capsule) = held_verdict(ledger_dir, verdict_capsule_id) else {
        return json!({ "capsule": null, "signed_by_key_id": null, "verify_ok": false });
    };
    let signature = capsule_producer::cose::verify_producer_envelope(&capsule);
    let recorded = recorded_as(ledger_dir, verdict_capsule_id);
    let referee = capsule
        .pointer("/model_attestation/compute_attestation/adjudication/referee_node_id")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "signed_by_key_id": signature.as_ref().ok(),
        "verify_ok": signature.is_ok() && recorded.is_some()
            && capsule.get("capsule_id").and_then(Value::as_str) == Some(verdict_capsule_id),
        "signature_error": signature.as_ref().err(),
        "recorded_as": recorded,
        "referee_node_id": referee,
        "capsule": capsule,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued() -> Value {
        json!({
            "adjudication_verdict": 1,
            "verdict": "contradicted:bbb",
            "verdict_capsule_id": "v".repeat(64),
            "referee_node_id": "ccc",
            "halves": ["a".repeat(64), "b".repeat(64)],
            "half_node_ids": ["aaa", "bbb"],
            "twin_bracket_id": "bracket-1",
            "referee_capsule_id": "r".repeat(64),
            "issued_at": "2026-09-28T15:00:00Z",
        })
    }

    #[test]
    fn a_verdict_reads_only_when_every_fact_is_there() {
        let v = verdict_from(&issued()).expect("complete facts");
        assert_eq!(v.half_node_ids, ["aaa".to_string(), "bbb".to_string()]);
        for missing in ["verdict", "verdict_capsule_id", "referee_node_id", "halves", "half_node_ids"] {
            let mut partial = issued();
            partial.as_object_mut().unwrap().remove(missing);
            assert!(verdict_from(&partial).is_none(), "{missing} is required");
        }
        let mut one_half = issued();
        one_half["halves"] = json!(["a".repeat(64)]);
        assert!(verdict_from(&one_half).is_none());
    }

    #[test]
    fn a_refusal_is_never_an_issued_verdict() {
        assert!(is_issued_reply(&issued()));
        assert!(!is_issued_reply(&json!({ "reason": "no_verdict" })));
        let mut odd = issued();
        odd["reason"] = json!("x");
        assert!(!is_issued_reply(&odd));
    }

    fn state(dir: &std::path::Path) -> Arc<CapsuleState> {
        Arc::new(CapsuleState::open(dir, "node-under-test").expect("open state"))
    }

    fn block<'a>(capsule: &'a Value, name: &str) -> &'a Value {
        &capsule["model_attestation"]["compute_attestation"][name]
    }

    #[tokio::test]
    async fn the_referee_seals_one_issued_record_citing_verdict_answer_and_halves() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = state(dir.path());
        seal_issued(&capsules, &issued()).await.unwrap();
        seal_issued(&capsules, &issued()).await.unwrap();
        let ids = capsules.capsule_ids_in_order();
        assert_eq!(ids.len(), 1, "a repeated verdict seals once");
        let (ledger, _) = capsule_producer::ledger::Ledger::open(&dir.path().join("ledger")).unwrap();
        let record = ledger.lookup(&ids[0]).unwrap().unwrap().capsule;
        let b = block(&record, "adjudication_issued");
        assert_eq!(b["verdict"], json!("contradicted:bbb"));
        assert_eq!(b["referee_capsule_id"], json!("r".repeat(64)));
        assert_eq!(b["twin_bracket_id"], json!("bracket-1"));
        let purposes: Vec<&str> = record["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["citation_purpose"].as_str().unwrap())
            .collect();
        assert_eq!(purposes, ["adjudication_verdict", "referee_answer", "adjudicated_half", "adjudicated_half"]);
    }

    #[tokio::test]
    async fn a_judged_node_seals_one_received_record_naming_its_half() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = state(dir.path());
        let mut facts = issued();
        facts["held_half_capsule_id"] = json!("b".repeat(64));
        facts["received_from"] = json!("courier");
        facts["received_at"] = json!("2026-09-28T15:01:00Z");
        let reply = json!({ "status": "received", "adjudication": facts });
        seal_received(&capsules, &reply).await.unwrap();
        seal_received(&capsules, &reply).await.unwrap();
        let ids = capsules.capsule_ids_in_order();
        assert_eq!(ids.len(), 1);
        let (ledger, _) = capsule_producer::ledger::Ledger::open(&dir.path().join("ledger")).unwrap();
        let record = ledger.lookup(&ids[0]).unwrap().unwrap().capsule;
        let b = block(&record, "adjudication_received");
        assert_eq!(b["held_half_capsule_id"], json!("b".repeat(64)));
        assert_eq!(b["received_from"], json!("courier"));
        assert_eq!(record["references"][0]["digest"], json!("v".repeat(64)));
    }

    #[tokio::test]
    async fn a_received_reply_without_its_facts_seals_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = state(dir.path());
        assert!(seal_received(&capsules, &json!({ "status": "received" })).await.is_err());
        assert!(capsules.capsule_ids_in_order().is_empty());
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/referee-verdict.json")).unwrap()
    }

    #[test]
    fn a_verdict_the_python_referee_signed_verifies_here() {
        let fx = fixture();
        let key = capsule_producer::cose::verify_producer_envelope(&fx["verdict_capsule"]).expect("verifies");
        assert_eq!(json!(key), fx["referee_key_id"]);
    }

    fn held_dir(recorded: bool) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let capsule = fixture()["verdict_capsule"].clone();
        let id = capsule["capsule_id"].as_str().unwrap().to_string();
        let held = json!({ "verdict_capsule_id": id, "verdict_capsule": capsule });
        std::fs::write(dir.path().join(RECEIVED_ADJUDICATIONS_FILENAME), format!("{held}\n")).unwrap();
        if recorded {
            let record = json!({ "model_attestation": { "compute_attestation": {
                "adjudication_received": { "verdict_capsule_id": id } } } });
            std::fs::write(dir.path().join("capsules.jsonl"), format!("{record}\n")).unwrap();
        }
        (dir, id)
    }

    #[test]
    fn the_verdict_route_checks_the_signature_and_the_chain_record() {
        let (dir, id) = held_dir(true);
        let out = verdict_json(dir.path(), &id);
        assert_eq!(out["verify_ok"], json!(true));
        assert_eq!(out["recorded_as"], json!("received"));
        assert_eq!(out["signed_by_key_id"], fixture()["referee_key_id"]);

        let (unrecorded, id) = held_dir(false);
        assert_eq!(verdict_json(unrecorded.path(), &id)["verify_ok"], json!(false), "held but never recorded");
    }

    #[test]
    fn an_altered_held_verdict_does_not_verify() {
        let (dir, id) = held_dir(true);
        let path = dir.path().join(RECEIVED_ADJUDICATIONS_FILENAME);
        let altered = std::fs::read_to_string(&path).unwrap().replace("contradicted:", "contradicted:x");
        std::fs::write(&path, altered).unwrap();
        let out = verdict_json(dir.path(), &id);
        assert_eq!(out["verify_ok"], json!(false));
        assert!(out["signature_error"].is_string());
    }

    #[test]
    fn an_unknown_verdict_is_null_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(verdict_json(dir.path(), &"0".repeat(64))["capsule"], Value::Null);
    }


    #[tokio::test]
    async fn a_signed_refusal_of_a_delivery_is_recorded_once_per_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = state(dir.path());
        let refusal = json!({ "reason": "not_about_this_node", "sig": "ab", "key_id": "cd",
                              "request_digest": "e".repeat(64), "issued_at": "2026-09-28T15:00:00Z" });
        let verdict = "v".repeat(64);
        let out = with_refusal_recorded(&capsules, refusal.clone(), &verdict, "peer-b").await.unwrap();
        assert!(out["ack_refused_capsule_id"].is_string());
        let again = with_refusal_recorded(&capsules, refusal.clone(), &verdict, "peer-b").await.unwrap();
        assert!(again.get("ack_refused_capsule_id").is_none(), "a repeat seals nothing");
        with_refusal_recorded(&capsules, refusal, &verdict, "peer-a").await.unwrap();
        let ids = capsules.capsule_ids_in_order();
        assert_eq!(ids.len(), 2, "one record per receiver");
        let (ledger, _) = capsule_producer::ledger::Ledger::open(&dir.path().join("ledger")).unwrap();
        let record = ledger.lookup(&ids[0]).unwrap().unwrap().capsule;
        let b = block(&record, "adjudication_ack_refused");
        assert_eq!(b["refused_by"], json!("peer-b"));
        assert_eq!(b["reason"], json!("not_about_this_node"));
        assert_eq!(record["references"][0]["digest"], json!(verdict));
    }

    #[tokio::test]
    async fn an_unsigned_refusal_or_a_success_is_not_recorded_as_refused() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = state(dir.path());
        let verdict = "v".repeat(64);
        with_refusal_recorded(&capsules, json!({ "reason": SEAL_FAILED_REASON }), &verdict, "p").await.unwrap();
        with_refusal_recorded(&capsules, json!({ "status": "received" }), &verdict, "p").await.unwrap();
        assert!(capsules.capsule_ids_in_order().is_empty());
    }

}
