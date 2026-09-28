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
    let capsules = capsules.clone();
    let emitted = tokio::task::spawn_blocking(move || {
        capsules.emit_adjudication_issued(&verdict.facts(), referee_capsule_id.as_deref(), &issued_at)
    })
    .await
    .map_err(|e| anyhow::anyhow!("adjudication seal task did not complete: {e}"))??;
    if let Some(emitted) = emitted {
        tracing::info!(capsule_id = %emitted.capsule_id, "SEALED adjudication_issued record");
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
    let capsules = capsules.clone();
    let emitted = tokio::task::spawn_blocking(move || {
        capsules.emit_adjudication_received(&verdict.facts(), &held_half, &received_from, &received_at)
    })
    .await
    .map_err(|e| anyhow::anyhow!("adjudication seal task did not complete: {e}"))??;
    if let Some(emitted) = emitted {
        tracing::info!(capsule_id = %emitted.capsule_id, "SEALED adjudication_received record");
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
    let body = delivery_body(&args.verdict_capsule);
    if args.peer_id != self_id {
        return crate::record_push_bridge::send_push(context, &args.peer_id, &self_id, &body)
            .await
            .map_err(|e| PluginError::internal(e.to_string()));
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
    }
    Ok(reply)
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
}
