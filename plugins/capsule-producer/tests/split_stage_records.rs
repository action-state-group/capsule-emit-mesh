//! Sealing split-stage records: stage records, the coordinator's
//! stage-exchange records and its main record, then the requester's check
//! over the sealed records end to end. Blocks come from the shared fixture
//! scenarios (`tests/fixtures/split-stage/hop-cases.json`).

use capsule_producer::capsule::{
    attach_producer_envelope, seal, CapsuleInput, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::jcs::compute_capsule_id;
use capsule_producer::keys::KeyPair;
use capsule_producer::stage::{
    seal_split_main_record, seal_stage_record, stage_block_of, BundleRef, CoordinatorObserved,
    CoordinatorReceipt, SplitMainExtension, StageBlock, StageError, CITATION_PURPOSE_SPLIT_STAGE,
    COORDINATOR_RECEIPT_BLOCK, ROLE_STAGE, STAGE_BLOCK,
};
use capsule_producer::stage_verify::{verify_split_records, CellState};
use serde_json::{json, Value};

fn served_input() -> CapsuleInput {
    let mut generation_parameters = serde_json::Map::new();
    generation_parameters.insert("temperature".into(), json!("0.7"));
    CapsuleInput {
        action_id: "mesh-poc/pushed-half/1".to_string(),
        action_type: "decide".to_string(),
        operator: "op".to_string(),
        developer: "dev".to_string(),
        timestamp: "2026-09-25T00:00:00Z".to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "m".to_string(),
        provider: "p".to_string(),
        agent_input_digest: "a".repeat(64),
        agent_output_digest: Some("b".repeat(64)),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: json!({"name": "runtime"}),
        mesh_poc: MeshPocV1 {
            client_nonce: "c".repeat(32),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "node".to_string(),
                dispatch_path: None,
                requesting_party: "client".to_string(),
                exchange_id: "exch".to_string(),
                quantization: "unknown".to_string(),
                hardware_gpu: None,
                hardware_vram_bytes: None,
                hardware_device: None,
                hardware_is_soc: None,
                hostname: None,
                architecture: None,
                context_length: None,
                parameter_size: None,
                layer_count: None,
                model_identity_hash: None,
                weights_digest: None,
                model_canonical_ref: None,
                model_revision: None,
                usage: Some(TokenUsage {
                    prompt_tokens: 1,
                    completion_tokens: 2,
                    total_tokens: 3,
                }),
                seq: 1,
                prev_seq: None,
                peer_capsule_id: None,
                peer_capsule_id_provenance: None,
                twin_bracket_id: None,
            },
            role: "served".to_string(),
            observation_point: None,
            generation_parameters,
            latency_ms: "1.0".to_string(),
            binary_attestation: None,
            tee_attestation: None,
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
        chain: None,
        store_nonce: "5".repeat(64),
    }
}


fn scenario(name: &str) -> Value {
    let cases: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/split-stage/hop-cases.json")).unwrap();
    cases
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no hop case {name}"))
        .clone()
}

fn block(value: &Value) -> StageBlock {
    StageBlock::from_value(value).unwrap()
}

/// The coordinator's stage-exchange block for stage `k`, derived from what it
/// assigned and what it saw first-hand.
fn exchange_block(own: &StageBlock, stage: &StageBlock) -> StageBlock {
    let mut b = stage.clone();
    b.side = capsule_producer::stage::Side::Coordinator;
    b.upstream = None;
    b.downstream = None;
    b.direct_return = None;
    b.tokens = None;
    b.coordinator_term = Some(7);
    let first = b.stage_index == 1;
    let direct_final = own.return_mode == capsule_producer::stage::ReturnMode::Direct && b.is_final();
    b.data_path_observed = Some(first || direct_final);
    b.coordinator_observed = (first || direct_final).then(|| CoordinatorObserved {
        downstream: first.then(|| own.downstream.clone().unwrap()),
        direct_return: direct_final.then(|| capsule_producer::stage::DirectReturn {
            sent: None,
            received: own.direct_return.as_ref().unwrap().received.clone(),
        }),
    });
    b
}

struct Sealed {
    main: Value,
    stage_records: Vec<Value>,
    exchange_records: Vec<Value>,
}

/// Seal a whole split: each stage's record under its own key, the
/// coordinator's stage-exchange records citing them, then the main record.
fn seal_split(case: &Value) -> Sealed {
    let own = block(&case["own"]);
    let coordinator = KeyPair::generate();
    let mut receipt = CoordinatorReceipt::from_value(&case["receipt"]).unwrap();
    let mut stage_records = Vec::new();
    let mut exchange_records = Vec::new();
    let mut exchange_ids = Vec::new();
    let mut head: Option<String> = None;
    for carried in case["carried"].as_array().unwrap() {
        let stage = block(&carried["block"]);
        let stage_key = KeyPair::generate();
        let record = seal_stage_record(&stage, None, None, &stage_key.signing_key).unwrap();
        let id = record["capsule_id"].as_str().unwrap().to_string();
        receipt.stages[stage.stage_index as usize].bundle_ref = Some(BundleRef::capsule(&id));
        let exchange = seal_stage_record(
            &exchange_block(&own, &stage),
            Some(&id),
            head.as_deref(),
            &coordinator.signing_key,
        )
        .unwrap();
        head = Some(exchange["capsule_id"].as_str().unwrap().to_string());
        exchange_ids.push((stage.stage_index, head.clone().unwrap()));
        stage_records.push(record);
        exchange_records.push(exchange);
    }
    let split = SplitMainExtension { own_slice: own, receipt, stage_exchange_records: exchange_ids };
    let mut main = seal_split_main_record(&served_input(), &split).unwrap();
    attach_producer_envelope(&mut main, &coordinator.signing_key).unwrap();
    Sealed { main, stage_records, exchange_records }
}

fn recomputes(record: &Value) -> bool {
    record["capsule_id"].as_str().unwrap() == compute_capsule_id(record).unwrap()
}

#[test]
fn a_stage_record_is_role_stage_with_its_block_and_no_serving_claim() {
    let case = scenario("relayed_all_agree");
    let stage = block(&case["carried"][0]["block"]);
    let key = KeyPair::generate();
    let record = seal_stage_record(&stage, None, None, &key.signing_key).unwrap();
    assert!(recomputes(&record));
    let ca = &record["model_attestation"]["compute_attestation"];
    assert_eq!(ca["x-mesh-poc-v1"]["role"], ROLE_STAGE);
    // No producer_claim / observed_event label: a stage record is neither.
    assert!(ca.get("epistemic_type").is_none());
    // request_id survives as the exact decimal string, never a number.
    assert_eq!(ca[STAGE_BLOCK]["request_id"], json!("18446744073709551615"));
    // layer_end stays exclusive as upstream counts it.
    assert_eq!(ca[STAGE_BLOCK]["layer_end"], json!(32));
    assert!(ca[STAGE_BLOCK].get("session_id").is_none());
    assert!(record.get("references").is_none());
    assert_eq!(stage_block_of(&record).unwrap().unwrap(), stage);
    assert_eq!(record["action_type"], "fyi");
}

#[test]
fn a_stage_record_cites_nothing_and_stage_zero_is_not_a_stage_record() {
    let case = scenario("relayed_all_agree");
    let stage = block(&case["carried"][0]["block"]);
    let key = KeyPair::generate();
    let err = seal_stage_record(&stage, Some(&"ab".repeat(32)), None, &key.signing_key);
    assert!(matches!(err, Err(StageError::Block(_))));
    let own = block(&case["own"]);
    assert!(matches!(
        seal_stage_record(&own, None, None, &key.signing_key),
        Err(StageError::Block(_))
    ));
}

#[test]
fn a_stage_exchange_record_cites_the_stage_record_as_its_counterparty() {
    let case = scenario("relayed_all_agree");
    let sealed = seal_split(&case);
    let first = &sealed.exchange_records[0];
    assert!(recomputes(first));
    assert_eq!(first["references"][0]["citation_purpose"], "counterparty_half");
    assert_eq!(first["references"][0]["digest"], sealed.stage_records[0]["capsule_id"]);
    let ca = &first["model_attestation"]["compute_attestation"][STAGE_BLOCK];
    assert_eq!(ca["side"], "coordinator");
    assert_eq!(ca["data_path_observed"], true);
    // Stage 2 of a relayed split: the coordinator saw none of its data path,
    // and says so rather than leaving fields empty.
    let second = &sealed.exchange_records[1]["model_attestation"]["compute_attestation"][STAGE_BLOCK];
    assert_eq!(second["data_path_observed"], false);
    assert!(second.get("coordinator_observed").is_none());
    assert_eq!(sealed.exchange_records[1]["chain"]["parent_capsule_id"], first["capsule_id"]);
}

#[test]
fn the_main_record_commits_own_slice_receipt_and_split_stage_references() {
    let case = scenario("direct_all_agree");
    let sealed = seal_split(&case);
    assert!(recomputes(&sealed.main));
    let ca = &sealed.main["model_attestation"]["compute_attestation"];
    assert_eq!(ca["x-mesh-poc-v1"]["role"], "served");
    assert_eq!(ca[STAGE_BLOCK]["stage_index"], 0);
    assert_eq!(ca[COORDINATOR_RECEIPT_BLOCK]["stages"][1]["bundle"], "present");
    let refs = sealed.main["references"].as_array().unwrap();
    assert_eq!(refs.len(), 2);
    for (r, exchange) in refs.iter().zip(&sealed.exchange_records) {
        assert_eq!(r["citation_purpose"], CITATION_PURPOSE_SPLIT_STAGE);
        assert_eq!(r["digest"], exchange["capsule_id"]);
    }
    // Everything except the split additions is exactly the ordinary seal.
    let mut plain = seal(&served_input()).unwrap();
    let mut main = sealed.main.clone();
    for record in [&mut plain, &mut main] {
        let obj = record.as_object_mut().unwrap();
        for key in ["capsule_id", "references", "signature", "key_id"] {
            obj.remove(key);
        }
        let ca = obj["model_attestation"]["compute_attestation"].as_object_mut().unwrap();
        for key in [STAGE_BLOCK, COORDINATOR_RECEIPT_BLOCK, "store_nonce"] {
            ca.remove(key);
        }
    }
    assert_eq!(plain, main);
}

#[test]
fn the_main_record_refuses_a_missing_or_repeated_stage_exchange_citation() {
    let case = scenario("relayed_all_agree");
    let own = block(&case["own"]);
    let receipt = CoordinatorReceipt::from_value(&case["receipt"]).unwrap();
    let id = "ab".repeat(32);
    for records in [
        vec![(1, id.clone())],
        vec![(1, id.clone()), (1, "cd".repeat(32))],
        vec![(0, id.clone()), (1, "cd".repeat(32))],
    ] {
        let split = SplitMainExtension {
            own_slice: own.clone(),
            receipt: receipt.clone(),
            stage_exchange_records: records.clone(),
        };
        assert!(
            matches!(seal_split_main_record(&served_input(), &split), Err(StageError::Main(_))),
            "{records:?}"
        );
    }
}

#[test]
fn the_main_record_is_a_served_record() {
    let case = scenario("relayed_all_agree");
    let mut input = served_input();
    input.mesh_poc.role = "requested".to_string();
    let split = SplitMainExtension {
        own_slice: block(&case["own"]),
        receipt: CoordinatorReceipt::from_value(&case["receipt"]).unwrap(),
        stage_exchange_records: vec![(1, "ab".repeat(32)), (2, "cd".repeat(32))],
    };
    assert!(matches!(seal_split_main_record(&input, &split), Err(StageError::Main(_))));
}

#[test]
fn sealed_records_check_end_to_end() {
    for name in ["relayed_all_agree", "direct_all_agree", "two_stage_direct"] {
        let sealed = seal_split(&scenario(name));
        let verdict = verify_split_records(&sealed.main, &sealed.stage_records).unwrap();
        assert!(verdict.handoffs_agree, "{name}: {verdict:?}");
        assert!(verdict.cells[1..].iter().all(|c| c.state == CellState::Ok), "{name}");
    }
}

#[test]
fn a_tampered_stage_record_reads_rejected_not_agreeing() {
    let sealed = seal_split(&scenario("relayed_all_agree"));
    let mut records = sealed.stage_records.clone();
    records[1]["model_attestation"]["compute_attestation"][STAGE_BLOCK]["tokens"]["decode"] = json!(99);
    let verdict = verify_split_records(&sealed.main, &records).unwrap();
    assert_eq!(verdict.cells[2].state, CellState::Rejected);
    assert!(!verdict.handoffs_agree);
}

#[test]
fn a_tampered_main_record_is_refused() {
    let sealed = seal_split(&scenario("relayed_all_agree"));
    let mut main = sealed.main.clone();
    main["model_attestation"]["compute_attestation"][COORDINATOR_RECEIPT_BLOCK]["stages"][2]["bundle"] =
        json!("absent");
    assert!(verify_split_records(&main, &sealed.stage_records).is_err());
}
