//! Referee-signed verdicts about each peer, counted from this node's own
//! chain: the Peers drill's "Verdicts about them" counts, and the input the
//! opt-in stop-routing rule reads (`routing_rule`).
//!
//! Only a verdict whose signature this node's door verified counts. The door
//! checks the referee's signature under the key that referee announced
//! before it holds a verdict (`adjudication_hold.verdict_facts` on a node the
//! verdict is delivered to; on the referee, its own door signed it), and the
//! plugin seals `adjudication_received` / `adjudication_issued` only after
//! that (`adjudication_records`). So those two record kinds on this node's own
//! chain are the fold's only source. A verdict held anywhere else, or a
//! verdict string in any other record, counts nowhere.
//!
//! Four counts per peer, each a list of the verdicts' capsule ids so the page
//! can open every one. No score, no rating, nothing blended into one number;
//! the counts are this node's and are never sent to anyone.

use std::collections::{BTreeMap, BTreeSet};

use capsule_producer::capsule::{ADJUDICATION_ISSUED_BLOCK, ADJUDICATION_RECEIVED_BLOCK};
use serde_json::{json, Value};

pub const CORROBORATED: &str = "corroborated";
pub const INCONCLUSIVE: &str = "inconclusive";
pub const NOT_COMPARABLE: &str = "not_comparable";
pub const CONTRADICTED: &str = "contradicted";
const CONTRADICTED_PREFIX: &str = "contradicted:";

/// The four buckets, in the order the page shows them.
pub const BUCKETS: [&str; 4] = [CORROBORATED, CONTRADICTED, INCONCLUSIVE, NOT_COMPARABLE];

/// One verified verdict, as it bears on one judged peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerVerdict {
    pub verdict_capsule_id: String,
    /// One of [`BUCKETS`].
    pub bucket: &'static str,
    /// When this node recorded the verdict (`received_at` or `issued_at`),
    /// minute-granular as sealed. `None` when the record carries neither.
    pub recorded_at: Option<String>,
}

/// Which bucket `verdict` puts `node_id` in, when `node_id` is one of the two
/// judged twins. A contradiction naming the OTHER twin means the referee's
/// answer matched this one's (`live_referee.referee_verdict`), so it is
/// corroborated for this one. An unknown ruling is in no bucket.
pub fn ruling_about(verdict: &str, half_node_ids: [&str; 2], node_id: &str) -> Option<&'static str> {
    if !half_node_ids.contains(&node_id) {
        return None;
    }
    if let Some(named) = verdict.strip_prefix(CONTRADICTED_PREFIX) {
        return if named == node_id {
            Some(CONTRADICTED)
        } else if half_node_ids.contains(&named) {
            Some(CORROBORATED)
        } else {
            None
        };
    }
    match verdict {
        CORROBORATED => Some(CORROBORATED),
        INCONCLUSIVE => Some(INCONCLUSIVE),
        NOT_COMPARABLE => Some(NOT_COMPARABLE),
        _ => None,
    }
}

fn verdict_block(record: &Value) -> Option<(&Value, &'static str)> {
    let attestation = record.pointer("/model_attestation/compute_attestation")?;
    [
        (ADJUDICATION_RECEIVED_BLOCK, "received_at"),
        (ADJUDICATION_ISSUED_BLOCK, "issued_at"),
    ]
    .into_iter()
    .find_map(|(name, at)| attestation.get(name).map(|block| (block, at)))
}

/// Every verified verdict on `records` (this node's own chain), per judged
/// peer id. Each verdict counts once per peer, however many records cite it.
pub fn fold(records: &[Value]) -> BTreeMap<String, Vec<PeerVerdict>> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut by_peer: BTreeMap<String, Vec<PeerVerdict>> = BTreeMap::new();
    for record in records {
        let Some((block, at_key)) = verdict_block(record) else {
            continue;
        };
        let text = |key: &str| block.get(key).and_then(Value::as_str).filter(|s| !s.is_empty());
        let (Some(verdict), Some(verdict_capsule_id)) = (text("verdict"), text("verdict_capsule_id")) else {
            continue;
        };
        let Some(halves) = block.get("half_node_ids").and_then(Value::as_array) else {
            continue;
        };
        let [Some(a), Some(b)] = [halves.first(), halves.get(1)].map(|h| h.and_then(Value::as_str)) else {
            continue;
        };
        if halves.len() != 2 || a == b {
            continue;
        }
        for peer in [a, b] {
            let Some(bucket) = ruling_about(verdict, [a, b], peer) else {
                continue;
            };
            if !seen.insert((peer.to_string(), verdict_capsule_id.to_string())) {
                continue;
            }
            by_peer.entry(peer.to_string()).or_default().push(PeerVerdict {
                verdict_capsule_id: verdict_capsule_id.to_string(),
                bucket,
                recorded_at: text(at_key).map(str::to_string),
            });
        }
    }
    by_peer
}

/// The page's shape: every bucket present, zero included, each with the ids
/// that make up its count.
pub fn counts_json(verdicts: &[PeerVerdict]) -> Value {
    let mut out = serde_json::Map::new();
    for bucket in BUCKETS {
        let ids: Vec<&str> = verdicts
            .iter()
            .filter(|v| v.bucket == bucket)
            .map(|v| v.verdict_capsule_id.as_str())
            .collect();
        out.insert(bucket.to_string(), json!({ "count": ids.len(), "verdict_capsule_ids": ids }));
    }
    Value::Object(out)
}

/// The ids a Pane B row can be matched on: its identity's endpoint and node
/// ids, and its label without the `node:` / `endpoint:` prefix.
fn row_peer_ids(row: &Value) -> Vec<&str> {
    let mut ids: Vec<&str> = ["endpoint_id", "node_id"]
        .into_iter()
        .filter_map(|key| row.pointer(&format!("/identity/{key}")).and_then(Value::as_str))
        .collect();
    if let Some(label) = row.get("peer_id").and_then(Value::as_str) {
        ids.extend(["node:", "endpoint:"].into_iter().filter_map(|p| label.strip_prefix(p)));
    }
    ids.retain(|id| !id.is_empty());
    ids
}

/// Put `referee_verdicts` on every attributed Pane B row, from this node's own
/// chain (`our_records`). A row whose ids name no judged peer gets four
/// zeros: zero is a fact here, since the chain was read.
pub fn attach(pane_b: &mut Value, our_records: &[Value]) {
    let by_peer = fold(our_records);
    let Some(rows) = pane_b.get_mut("rows").and_then(Value::as_array_mut) else {
        return;
    };
    for row in rows {
        if row.get("peer_id").is_none_or(Value::is_null) {
            continue;
        }
        let mut verdicts: Vec<PeerVerdict> = Vec::new();
        for id in row_peer_ids(row) {
            for v in by_peer.get(id).into_iter().flatten() {
                if !verdicts.iter().any(|seen| seen.verdict_capsule_id == v.verdict_capsule_id) {
                    verdicts.push(v.clone());
                }
            }
        }
        row["referee_verdicts"] = counts_json(&verdicts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(block: &str, verdict: &str, id: &str, halves: [&str; 2]) -> Value {
        let at = if block == ADJUDICATION_ISSUED_BLOCK { "issued_at" } else { "received_at" };
        json!({ "model_attestation": { "compute_attestation": { block: {
            "verdict": verdict,
            "verdict_capsule_id": id,
            "referee_node_id": "ref",
            "halves": ["ha", "hb"],
            "half_node_ids": halves,
            at: "2026-09-28T15:00:00Z",
        }}}})
    }

    fn count(json: &Value, bucket: &str) -> u64 {
        json[bucket]["count"].as_u64().unwrap()
    }

    #[test]
    fn a_verdict_lands_in_the_bucket_for_each_twin_it_judged() {
        assert_eq!(ruling_about("contradicted:b", ["a", "b"], "b"), Some(CONTRADICTED));
        assert_eq!(ruling_about("contradicted:b", ["a", "b"], "a"), Some(CORROBORATED));
        assert_eq!(ruling_about("corroborated", ["a", "b"], "a"), Some(CORROBORATED));
        assert_eq!(ruling_about("inconclusive", ["a", "b"], "b"), Some(INCONCLUSIVE));
        assert_eq!(ruling_about("not_comparable", ["a", "b"], "a"), Some(NOT_COMPARABLE));
        assert_eq!(ruling_about("contradicted:b", ["a", "b"], "c"), None, "not a judged twin");
        assert_eq!(ruling_about("contradicted:c", ["a", "b"], "a"), None, "names no twin");
        assert_eq!(ruling_about("score:9", ["a", "b"], "a"), None, "an unknown ruling counts nowhere");
    }

    #[test]
    fn only_the_door_verified_record_kinds_count() {
        let bare = json!({ "model_attestation": { "compute_attestation": { "adjudication": {
            "verdict": "contradicted:b", "verdict_capsule_id": "v0", "half_node_ids": ["a", "b"],
        }}}});
        let refused = json!({ "model_attestation": { "compute_attestation": { "adjudication_ack_refused": {
            "verdict": "contradicted:b", "verdict_capsule_id": "v9", "half_node_ids": ["a", "b"],
        }}}});
        let records = vec![
            bare,
            refused,
            record(ADJUDICATION_RECEIVED_BLOCK, "contradicted:b", "v1", ["a", "b"]),
            record(ADJUDICATION_ISSUED_BLOCK, "inconclusive", "v2", ["b", "c"]),
        ];
        let by_peer = fold(&records);
        let b = counts_json(&by_peer["b"]);
        assert_eq!(count(&b, CONTRADICTED), 1);
        assert_eq!(count(&b, INCONCLUSIVE), 1);
        assert_eq!(b[CONTRADICTED]["verdict_capsule_ids"], json!(["v1"]));
        assert_eq!(count(&counts_json(&by_peer["a"]), CORROBORATED), 1);
    }

    #[test]
    fn a_verdict_recorded_twice_counts_once() {
        let records = vec![
            record(ADJUDICATION_RECEIVED_BLOCK, "contradicted:b", "v1", ["a", "b"]),
            record(ADJUDICATION_ISSUED_BLOCK, "contradicted:b", "v1", ["a", "b"]),
        ];
        assert_eq!(fold(&records)["b"].len(), 1);
    }

    #[test]
    fn a_malformed_block_counts_nowhere() {
        let records = vec![
            record(ADJUDICATION_RECEIVED_BLOCK, "contradicted:b", "v1", ["b", "b"]),
            json!({ "model_attestation": { "compute_attestation": { "adjudication_received": {
                "verdict": "contradicted:b", "verdict_capsule_id": "v2", "half_node_ids": ["a"],
            }}}}),
            json!({ "model_attestation": { "compute_attestation": { "adjudication_received": {
                "verdict": "contradicted:b", "half_node_ids": ["a", "b"],
            }}}}),
        ];
        assert!(fold(&records).is_empty());
    }

    #[test]
    fn the_records_this_plugin_seals_are_the_ones_counted() {
        use crate::capsule_emit::{CapsuleState, VerdictFacts};
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "node-under-test").unwrap();
        let facts = |verdict, id| VerdictFacts {
            verdict,
            verdict_capsule_id: id,
            referee_node_id: "ref",
            halves: ["ha", "hb"],
            half_node_ids: ["a", "b"],
            twin_bracket_id: None,
        };
        let (first, second) = ("1".repeat(64), "2".repeat(64));
        state
            .emit_adjudication_received(&facts("contradicted:b", &first), "ha", "a", "2026-09-28T15:01:00Z")
            .unwrap();
        state
            .emit_adjudication_issued(&facts("not_comparable", &second), None, "2026-09-28T15:02:00Z")
            .unwrap();
        let records = crate::evidence_panes::read_capsule_records(state.ledger_dir());
        let b = &fold(&records)["b"];
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].bucket, CONTRADICTED);
        assert_eq!(b[0].recorded_at.as_deref(), Some("2026-09-28T15:01:00.000Z"));
        assert_eq!(b[1].bucket, NOT_COMPARABLE);
    }

    #[test]
    fn rows_get_all_four_counts_matched_on_any_of_their_ids() {
        let mut pane = json!({ "rows": [
            { "peer_id": "endpoint:b", "identity": { "endpoint_id": "b", "node_id": null } },
            { "peer_id": "key:k", "identity": { "endpoint_id": null, "node_id": "a" } },
            { "peer_id": "node:z", "identity": null },
            { "peer_id": null },
        ]});
        let records = vec![record(ADJUDICATION_RECEIVED_BLOCK, "contradicted:b", "v1", ["a", "b"])];
        attach(&mut pane, &records);
        let rows = pane["rows"].as_array().unwrap();
        assert_eq!(count(&rows[0]["referee_verdicts"], CONTRADICTED), 1);
        assert_eq!(count(&rows[1]["referee_verdicts"], CORROBORATED), 1);
        for bucket in BUCKETS {
            assert_eq!(count(&rows[2]["referee_verdicts"], bucket), 0, "zero is shown, not hidden");
        }
        assert!(rows[3].get("referee_verdicts").is_none(), "the unattributed residual names no peer");
    }
}
