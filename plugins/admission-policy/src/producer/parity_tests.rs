//! Byte parity with the in-repo producer this module replaced: every record
//! kind is sealed from the same inputs through `capsule_producer` (the old
//! path) and through `crate::producer` (capsule-emit's extension points), and
//! the bytes must match.
//!
//! An exchange record takes its timestamp and store nonce from the caller, so
//! it is compared as sealed. A local record draws a fresh store nonce and
//! the current minute inside the seal, so both records get the same fixed
//! nonce and minute first; `capsule_id` and the producer envelope are then
//! recomputed. Member order and every other byte are compared as sealed.

use capsule_producer::capsule as old;
use capsule_producer::stage as old_stage;
use serde_json::{json, Map, Value};

use crate::producer::capsule as new;
use crate::producer::jcs::compute_capsule_id;
use crate::producer::stage as new_stage;

const HOP_CASES: &str = include_str!("../../../../tests/fixtures/split-stage/hop-cases.json");

fn key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

fn bytes(record: &Value) -> Vec<u8> {
    serde_json::to_vec(record).unwrap()
}

/// Which path's envelope function to sign with.
#[derive(Clone, Copy)]
enum Path {
    Old,
    New,
}

fn attach(path: Path, record: &mut Value) {
    match path {
        Path::Old => old::attach_producer_envelope(record, &key()).unwrap(),
        Path::New => new::attach_producer_envelope(record, &key()).unwrap(),
    }
}

/// The envelope a record actually carries must be exactly what the OTHER
/// path's envelope function produces over the same `capsule_id` (Ed25519 is
/// deterministic), and must verify.
fn assert_envelope_matches(kind: &str, record: &Value, other: Path) {
    let mut probe = json!({"capsule_id": record["capsule_id"]});
    attach(other, &mut probe);
    assert_eq!(
        record["signature"], probe["signature"],
        "{kind}: envelope bytes differ"
    );
    assert_eq!(
        record["key_id"], probe["key_id"],
        "{kind}: envelope key_id differs"
    );
    crate::producer::cose::verify_producer_envelope(record)
        .unwrap_or_else(|e| panic!("{kind}: envelope does not verify: {e}"));
}

/// A local record with its fresh store nonce and minute pinned, its id
/// recomputed over them, and its envelope re-signed by its OWN path.
fn pinned(record: &Value, path: Path) -> Vec<u8> {
    let mut record = record.clone();
    record["model_attestation"]["compute_attestation"][new::STORE_NONCE_FIELD] =
        json!("0".repeat(64));
    let minute = record["timestamp"].as_str().unwrap().to_string();
    let text = serde_json::to_string(&record)
        .unwrap()
        .replace(&minute, "2000-01-01T00:00Z");
    let mut record: Value = serde_json::from_str(&text).unwrap();
    record["capsule_id"] = json!(compute_capsule_id(&record).unwrap());
    attach(path, &mut record);
    bytes(&record)
}

fn assert_local_parity(kind: &str, old_record: &Value, new_record: &Value) {
    assert_envelope_matches(kind, old_record, Path::New);
    assert_envelope_matches(kind, new_record, Path::Old);
    assert_eq!(
        pinned(old_record, Path::Old),
        pinned(new_record, Path::New),
        "{kind}: old and new seal paths disagree\nold: {old_record}\nnew: {new_record}"
    );
}

/// Exchange records carry no envelope from `seal`; each path attaches its
/// own, and the enveloped bytes must match.
fn assert_exchange_parity(kind: &str, mut old_record: Value, mut new_record: Value) {
    assert_eq!(
        bytes(&old_record),
        bytes(&new_record),
        "{kind}: sealed bytes"
    );
    attach(Path::Old, &mut old_record);
    attach(Path::New, &mut new_record);
    assert_eq!(
        bytes(&old_record),
        bytes(&new_record),
        "{kind}: enveloped bytes"
    );
}

/// The same exchange input, written once for either crate. The old crate's
/// `tee_attestation` slot is passed as `None`, the only value the plugin
/// ever gave it; the new crate always writes that empty slot.
macro_rules! exchange_input {
    ($m:ident, $chain:expr, $host_binding:expr, $role:expr $(, $mesh_field:ident: $mesh_value:expr)*) => {{
        let mut generation_parameters = Map::new();
        generation_parameters.insert("temperature".into(), json!("0.7"));
        generation_parameters.insert("seed".into(), json!(42));
        $m::CapsuleInput {
            action_id: "mesh-poc/parity/1".to_string(),
            action_type: "decide".to_string(),
            operator: "op".to_string(),
            developer: "dev".to_string(),
            timestamp: "2026-09-29T10:11Z".to_string(),
            domain: Some("action".to_string()),
            provenance: Some("collector".to_string()),
            model_id: "m".to_string(),
            provider: "p".to_string(),
            agent_input_digest: "a".repeat(64),
            agent_output_digest: Some("b".repeat(64)),
            tool_calls_digest: Some("c".repeat(64)),
            reasoning_digest: Some("d".repeat(64)),
            host_binding: $host_binding,
            runtime: json!({"name": "runtime"}),
            mesh_poc: $m::MeshPocV1 {
                client_nonce: "c".repeat(32),
                client_nonce_source: "client_supplied".to_string(),
                model_name_digest: "d".repeat(64),
                serving_provenance: $m::ServingProvenance {
                    served_by_node_id: "node-under-test".to_string(),
                    dispatch_path: Some("direct".to_string()),
                    requesting_party: "client-under-test".to_string(),
                    exchange_id: "exch-under-test".to_string(),
                    quantization: "Q4_K_M".to_string(),
                    hardware_gpu: Some("gpu".to_string()),
                    hardware_vram_bytes: Some(38_654_705_664),
                    hardware_device: Some("device".to_string()),
                    hardware_is_soc: Some(true),
                    hostname: Some("host-under-test".to_string()),
                    architecture: Some("llama".to_string()),
                    context_length: Some(8192),
                    parameter_size: Some("7B".to_string()),
                    layer_count: Some(32),
                    model_identity_hash: Some("a".repeat(64)),
                    weights_digest: Some("9".repeat(64)),
                    model_canonical_ref: Some("repo@rev/model.gguf".to_string()),
                    model_revision: Some("rev".to_string()),
                    usage: Some($m::TokenUsage { prompt_tokens: 11, completion_tokens: 22, total_tokens: 33 }),
                    seq: 2,
                    prev_seq: Some(1),
                    peer_capsule_id: Some("e".repeat(64)),
                    peer_capsule_id_provenance: Some("pushed".to_string()),
                    twin_bracket_id: Some("f".repeat(64)),
                    response_text_digest: Some("1".repeat(64)),
                },
                role: $role.to_string(),
                observation_point: Some("host".to_string()),
                generation_parameters,
                latency_ms: new::committed_latency_ms(42.0),
                binary_attestation: None,
                $($mesh_field: $mesh_value,)*
            },
            effect_status: "confirmed".to_string(),
            effect_type: "inference_completion".to_string(),
            effect_request_digest: Some("a".repeat(64)),
            effect_response_digest: Some("b".repeat(64)),
            effect_attestation: "gate_executed".to_string(),
            disposition_decision: "accept".to_string(),
            disposition_approver: "policy".to_string(),
            disposition_human_disposed: false,
            disposition_verdict_class: "executed".to_string(),
            chain: $chain,
            store_nonce: "5".repeat(64),
        }
    }};
}

#[test]
fn exchange_records_are_byte_identical() {
    for role in ["served", "requested", "conflict"] {
        for chained in [false, true] {
            for bound in [false, true] {
                let old_chain = chained.then(|| old::ChainLink {
                    parent_capsule_id: "3".repeat(64),
                    relation: "follows".to_string(),
                });
                let new_chain = chained.then(|| new::ChainLink {
                    parent_capsule_id: "3".repeat(64),
                    relation: "follows".to_string(),
                });
                let old_binding = bound.then(|| old::HostBinding {
                    digest: "4".repeat(64),
                    construction: old::MESH_LLM_REQUEST_BODY_SHA256_V1.to_string(),
                    purpose: old::HOST_LOG_JOIN.to_string(),
                });
                let new_binding = bound.then(|| new::HostBinding {
                    digest: "4".repeat(64),
                    construction: new::MESH_LLM_REQUEST_BODY_SHA256_V1.to_string(),
                    purpose: new::HOST_LOG_JOIN.to_string(),
                });
                let old_record = old::seal(
                    &exchange_input!(old, old_chain, old_binding, role, tee_attestation: None),
                )
                .unwrap();
                let new_record =
                    new::seal(&exchange_input!(new, new_chain, new_binding, role)).unwrap();
                assert_exchange_parity(
                    &format!(
                        "exchange record (role {role}, chained {chained}, host binding {bound})"
                    ),
                    old_record,
                    new_record,
                );
            }
        }
    }
}

#[test]
fn exchange_records_without_optional_members_are_byte_identical() {
    let mut old_input = exchange_input!(old, None, None, "served", tee_attestation: None);
    let mut new_input = exchange_input!(new, None, None, "served");
    old_input.mesh_poc.serving_provenance.quantization = "unknown".to_string();
    new_input.mesh_poc.serving_provenance.quantization = "unknown".to_string();
    old_input.mesh_poc.serving_provenance.weights_digest = None;
    new_input.mesh_poc.serving_provenance.weights_digest = None;
    old_input.mesh_poc.serving_provenance.model_revision = None;
    new_input.mesh_poc.serving_provenance.model_revision = None;
    old_input.mesh_poc.serving_provenance.hardware_gpu = None;
    new_input.mesh_poc.serving_provenance.hardware_gpu = None;
    old_input.mesh_poc.serving_provenance.hardware_vram_bytes = None;
    new_input.mesh_poc.serving_provenance.hardware_vram_bytes = None;
    old_input.mesh_poc.serving_provenance.usage = None;
    new_input.mesh_poc.serving_provenance.usage = None;
    old_input.mesh_poc.generation_parameters = Map::new();
    new_input.mesh_poc.generation_parameters = Map::new();
    old_input.agent_output_digest = None;
    new_input.agent_output_digest = None;
    old_input.effect_status = "dispatched".to_string();
    new_input.effect_status = "dispatched".to_string();
    old_input.effect_response_digest = None;
    new_input.effect_response_digest = None;
    assert_exchange_parity(
        "exchange record without optional members",
        old::seal(&old_input).unwrap(),
        new::seal(&new_input).unwrap(),
    );
}

/// An exchange record carrying a real runtime attestation: the same file
/// measured by both paths under the same key and time, sealed into
/// `x-mesh-poc-v1.evidence_refs.binary_attestation` and `runtime`.
#[test]
fn attested_exchange_records_are_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("serving-binary");
    std::fs::write(&binary, b"a serving binary, measured by both paths").unwrap();
    let measured_at = "2026-09-29T10:11:12Z".to_string();
    let old_keys = capsule_producer::keys::KeyPair { signing_key: key() };
    let new_keys = crate::producer::keys::KeyPair { signing_key: key() };
    let old_attestation =
        capsule_producer::runtime_attest::measure_path(&old_keys, &binary, measured_at.clone())
            .unwrap();
    let new_attestation =
        crate::producer::runtime_attest::measure_path(&new_keys, &binary, measured_at.clone())
            .unwrap();
    assert_eq!(
        bytes(&old_attestation.to_value()),
        bytes(&new_attestation.to_value()),
        "binary attestation"
    );
    assert_eq!(
        bytes(&old_attestation.runtime_value("mesh-llm")),
        bytes(&new_attestation.runtime_value("mesh-llm")),
        "runtime value"
    );
    assert!(new_attestation.verify_signature(&key().verifying_key()));

    for role in ["served", "requested"] {
        let mut old_input = exchange_input!(old, None, None, role, tee_attestation: None);
        let mut new_input = exchange_input!(new, None, None, role);
        old_input.runtime = old_attestation.runtime_value("mesh-llm");
        new_input.runtime = new_attestation.runtime_value("mesh-llm");
        old_input.mesh_poc.binary_attestation = Some(old_attestation.clone());
        new_input.mesh_poc.binary_attestation = Some(new_attestation.clone());
        let old_record = old::seal(&old_input).unwrap();
        let new_record = new::seal(&new_input).unwrap();
        assert!(new_record.pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/evidence_refs/binary_attestation/digest").is_some_and(|d| !d.is_null()));
        assert_exchange_parity(
            &format!("attested exchange record ({role})"),
            old_record,
            new_record,
        );
    }
}

#[test]
fn adjudication_ack_refused_records_are_byte_identical() {
    macro_rules! refused {
        ($m:ident, $key_id:expr) => {
            $m::RefusedDelivery {
                verdict_capsule_id: &"c".repeat(64),
                refused_by: "node-b",
                reason: "not_a_party",
                refusal_digest: &"d".repeat(64),
                refusal_key_id: $key_id,
                refused_at: "2026-09-29T10:11:12Z",
            }
        };
    }
    let head = "f".repeat(64);
    for key_id in [None, Some("e".repeat(64))] {
        for chain_head in [None, Some(head.as_str())] {
            let old_record = old::seal_adjudication_ack_refused_record(
                &refused!(old, key_id.as_deref()),
                chain_head,
                &key(),
            )
            .unwrap();
            let new_record = new::seal_adjudication_ack_refused_record(
                &refused!(new, key_id.as_deref()),
                chain_head,
                &key(),
            )
            .unwrap();
            assert_eq!(old_record.get("chain").is_some(), chain_head.is_some());
            assert_eq!(new_record.get("chain").is_some(), chain_head.is_some());
            assert_local_parity(
                &format!(
                    "adjudication ack-refused record (chained {})",
                    chain_head.is_some()
                ),
                &old_record,
                &new_record,
            );
        }
    }
}

#[test]
fn citing_records_are_byte_identical() {
    for digest_match in [None, Some("verified")] {
        let old_record = old::seal_citing_record(
            &old::ReceivedHalfProvenance {
                foreign_capsule_id: &"a".repeat(64),
                received_from: "peer-a",
                via: "push",
                received_at: "2026-09-29T10:11:12Z",
                signature_ok: true,
                digest_match,
                foreign_agent_input_digest: Some(&"b".repeat(64)),
                foreign_agent_output_digest: None,
            },
            Some(&"c".repeat(64)),
            &key(),
        )
        .unwrap();
        let new_record = new::seal_citing_record(
            &new::ReceivedHalfProvenance {
                foreign_capsule_id: &"a".repeat(64),
                received_from: "peer-a",
                via: "push",
                received_at: "2026-09-29T10:11:12Z",
                signature_ok: true,
                digest_match,
                foreign_agent_input_digest: Some(&"b".repeat(64)),
                foreign_agent_output_digest: None,
            },
            Some(&"c".repeat(64)),
            &key(),
        )
        .unwrap();
        assert_local_parity("citing record", &old_record, &new_record);
    }
}

#[test]
fn inclusion_citing_records_are_byte_identical() {
    macro_rules! citation {
        ($m:ident) => {
            $m::InclusionCitation {
                half_capsule_id: &"a".repeat(64),
                received_from: "peer-a",
                via: "push",
                received_at: "2026-09-29T10:11:12Z",
                leaf_index: 5,
                mmr_size: 8,
                checkpoint_digest: &"b".repeat(64),
                inclusion_proof_digest: &"c".repeat(64),
            }
        };
    }
    let old_record = old::seal_inclusion_citing_record(&citation!(old), None, &key()).unwrap();
    let new_record = new::seal_inclusion_citing_record(&citation!(new), None, &key()).unwrap();
    assert_local_parity("inclusion citing record", &old_record, &new_record);
}

#[test]
fn settlement_records_are_byte_identical() {
    macro_rules! observation {
        ($m:ident, $settlement:expr, $segment:expr, $hash:expr) => {
            $m::SettlementObservation {
                exchange_id: "exch-1",
                event_ref: "evt-1",
                terms_digest: &"a".repeat(64),
                phase: "settled",
                source: "payer",
                settlement: $settlement,
                segment: $segment,
                payment_hash: $hash,
                amount_msat: 21_000,
            }
        };
    }
    for (settlement, segment, hash) in [(None, None, None), (Some("final"), Some(3), Some("hash"))]
    {
        let old_record = old::seal_settlement_record(
            &observation!(old, settlement, segment, hash),
            Some(&"d".repeat(64)),
            &key(),
        )
        .unwrap();
        let new_record = new::seal_settlement_record(
            &observation!(new, settlement, segment, hash),
            Some(&"d".repeat(64)),
            &key(),
        )
        .unwrap();
        assert_local_parity("settlement record", &old_record, &new_record);
    }
}

#[test]
fn routing_choice_records_are_byte_identical() {
    let salt = [9u8; 32];
    let verdicts = vec!["a".repeat(64), "b".repeat(64)];
    let old_rule = old::RoutingRuleCitation {
        rule: "stop-routing",
        after: 2,
        window_days: 7,
        verdict_capsule_ids: &verdicts,
    };
    let new_rule = new::RoutingRuleCitation {
        rule: "stop-routing",
        after: 2,
        window_days: 7,
        verdict_capsule_ids: &verdicts,
    };
    for with_rule in [false, true] {
        let old_record = old::seal_local_routing_choice(
            &old::LocalRoutingChoice {
                change: old::RoutingChoiceChange::Block,
                peer_id: "peer-a",
                salt: &salt,
                until: Some("2026-10-01T00:00:00Z"),
                rule: with_rule.then_some(&old_rule),
            },
            None,
            &key(),
        )
        .unwrap();
        let new_record = new::seal_local_routing_choice(
            &new::LocalRoutingChoice {
                change: new::RoutingChoiceChange::Block,
                peer_id: "peer-a",
                salt: &salt,
                until: Some("2026-10-01T00:00:00Z"),
                rule: with_rule.then_some(&new_rule),
            },
            None,
            &key(),
        )
        .unwrap();
        assert_local_parity("routing choice record", &old_record, &new_record);
    }
}

#[test]
fn owner_maintenance_records_are_byte_identical() {
    let mut facts = Map::new();
    facts.insert("deleted_count".into(), json!(3));
    for prior in [None, Some("e".repeat(64))] {
        let old_record = old::seal_owner_maintenance_record(
            &old::OwnerMaintenance {
                kind: "cleanup",
                facts: facts.clone(),
                prior_history_head: prior.as_deref(),
            },
            Some(&"f".repeat(64)),
            &key(),
        )
        .unwrap();
        let new_record = new::seal_owner_maintenance_record(
            &new::OwnerMaintenance {
                kind: "cleanup",
                facts: facts.clone(),
                prior_history_head: prior.as_deref(),
            },
            Some(&"f".repeat(64)),
            &key(),
        )
        .unwrap();
        assert_local_parity("owner maintenance record", &old_record, &new_record);
    }
}

#[test]
fn adjudication_records_are_byte_identical() {
    let halves = ["a".repeat(64), "b".repeat(64)];
    macro_rules! facts {
        ($m:ident, $bracket:expr) => {
            $m::VerdictFacts {
                verdict: "agree",
                verdict_capsule_id: &"c".repeat(64),
                referee_node_id: "referee",
                halves: [&halves[0], &halves[1]],
                half_node_ids: ["node-a", "node-b"],
                twin_bracket_id: $bracket,
            }
        };
    }
    for (bracket, referee_answer) in [(None, None), (Some("bracket"), Some("d".repeat(64)))] {
        let old_record = old::seal_adjudication_issued_record(
            &facts!(old, bracket),
            referee_answer.as_deref(),
            "2026-09-29T10:11:12Z",
            None,
            &key(),
        )
        .unwrap();
        let new_record = new::seal_adjudication_issued_record(
            &facts!(new, bracket),
            referee_answer.as_deref(),
            "2026-09-29T10:11:12Z",
            None,
            &key(),
        )
        .unwrap();
        assert_local_parity("adjudication issued record", &old_record, &new_record);

        let old_record = old::seal_adjudication_received_record(
            &facts!(old, bracket),
            &halves[0],
            "referee",
            "2026-09-29T10:11:12Z",
            Some(&"e".repeat(64)),
            &key(),
        )
        .unwrap();
        let new_record = new::seal_adjudication_received_record(
            &facts!(new, bracket),
            &halves[0],
            "referee",
            "2026-09-29T10:11:12Z",
            Some(&"e".repeat(64)),
            &key(),
        )
        .unwrap();
        assert_local_parity("adjudication received record", &old_record, &new_record);
    }
}

/// Every split-stage fixture: each carried stage record, and the
/// coordinator's main record over the case's own slice and receipt.
#[test]
fn split_stage_records_are_byte_identical() {
    let cases: Value = serde_json::from_str(HOP_CASES).unwrap();
    let mut main_records = 0;
    let mut stage_records = 0;
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut exchange_ids = Vec::new();
        for carried in case["carried"].as_array().unwrap() {
            let (Ok(old_block), Ok(new_block)) = (
                old_stage::StageBlock::from_value(&carried["block"]),
                new_stage::StageBlock::from_value(&carried["block"]),
            ) else {
                continue;
            };
            let old_record = old_stage::seal_stage_record(&old_block, None, None, &key()).unwrap();
            let new_record = new_stage::seal_stage_record(&new_block, None, None, &key()).unwrap();
            assert_local_parity(&format!("{name}: stage record"), &old_record, &new_record);
            stage_records += 1;

            let cited = "a".repeat(64);
            let old_record = old_stage::seal_stage_record(
                &old_block,
                Some(&cited),
                Some(&"b".repeat(64)),
                &key(),
            );
            let new_record = new_stage::seal_stage_record(
                &new_block,
                Some(&cited),
                Some(&"b".repeat(64)),
                &key(),
            );
            assert_eq!(
                old_record.is_ok(),
                new_record.is_ok(),
                "{name}: citing stage record refusal"
            );
            if let (Ok(old_record), Ok(new_record)) = (old_record, new_record) {
                assert_local_parity(
                    &format!("{name}: citing stage record"),
                    &old_record,
                    &new_record,
                );
            }
            exchange_ids.push((
                new_block.stage_index,
                format!("{:064x}", new_block.stage_index),
            ));
        }

        let (Ok(old_own), Ok(new_own), Ok(old_receipt), Ok(new_receipt)) = (
            old_stage::StageBlock::from_value(&case["own"]),
            new_stage::StageBlock::from_value(&case["own"]),
            old_stage::CoordinatorReceipt::from_value(&case["receipt"]),
            new_stage::CoordinatorReceipt::from_value(&case["receipt"]),
        ) else {
            continue;
        };
        let old_main = old_stage::seal_split_main_record(
            &exchange_input!(old, None, None, "served", tee_attestation: None),
            &old_stage::SplitMainExtension {
                own_slice: old_own,
                receipt: old_receipt,
                stage_exchange_records: exchange_ids.clone(),
            },
        );
        let new_main = new_stage::seal_split_main_record(
            &exchange_input!(new, None, None, "served"),
            &new_stage::SplitMainExtension {
                own_slice: new_own,
                receipt: new_receipt,
                stage_exchange_records: exchange_ids,
            },
        );
        assert_eq!(
            old_main.is_ok(),
            new_main.is_ok(),
            "{name}: main record refusal"
        );
        if let (Ok(old_main), Ok(new_main)) = (old_main, new_main) {
            assert_exchange_parity(&format!("{name}: main record"), old_main, new_main);
            main_records += 1;
        }
    }
    assert!(
        stage_records > 0,
        "no fixture produced a stage record to compare"
    );
    assert!(
        main_records > 0,
        "no fixture produced a main record to compare"
    );
}
