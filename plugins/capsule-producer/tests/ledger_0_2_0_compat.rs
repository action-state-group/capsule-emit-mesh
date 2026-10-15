//! A ledger written by `capsule-producer` 0.2.0 (its own ledger and
//! checkpoint modules, on CLL `rust-cll-v0.2.0`) keeps working through
//! capsule-emit: it opens with the same chain head, every record verifies,
//! the stored checkpoint loads with its root unchanged, and new records
//! append, chain and checkpoint on top of it.
//!
//! `tests/fixtures/ledger-0.2.0/` was produced from capsule-emit-mesh
//! 926e4b8 (`capsule-producer` 0.2.0) and is never rewritten:
//!   - `cargo run --bin produce_demo_ledger -- <dir>`: the deterministic
//!     three-capsule chain, its `.cose` statements and `node-key.pub.pem`;
//!   - then 0.2.0's `checkpoint::CheckpointState::load(<dir>,
//!     "capsule-producer-0.2.0-fixture", Default::default())` and
//!     `reconnect` with the same demo key: `checkpoints.jsonl` and
//!     `mmr_nodes.dat`.

use capsule_emit::anchor::AnchorClient;
use capsule_emit::capsule::{fresh_store_nonce, payload_bytes, seal, CapsuleInput, ChainLink};
use capsule_emit::checkpoint::{
    verify_inclusion, CheckpointCadenceConfig, CheckpointRecord, CheckpointState,
};
use capsule_emit::cose::{build_signed_statement, SignedStatementInput};
use capsule_emit::keys::load_verifying_key_pem;
use capsule_emit::ledger::Ledger;
use capsule_emit::verify::verify_offline;
use capsule_producer::mesh_poc::{self, MeshPocV1, ServingProvenance};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FIXTURE_IDS: [&str; 3] = [
    "9cb5fc6bba27b226c02a44c6b0c2ec4eb443283269d63549029c61b34e7e5876",
    "ddbe0f720b058748e10dd00d243190335c9ea80e2b9f4688668f0741c00bff17",
    "96683b3d890701e5af7fad8d26d3173443d69ec6815ffd922e63839125992148",
];
/// The root 0.2.0 signed over the three records (`mmr_size` 4).
const FIXTURE_ROOT: &str = "061b0a74804332099735b135106f433a6b6e7bbe7287dc408a3dc39c02dc9cf7";
const FIXTURE_MMR_SIZE: u64 = 4;
const LOG_ID: &str = "capsule-producer-0.2.0-fixture";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ledger-0.2.0")
}

/// A scratch copy of the fixture, so a test can append without touching it.
fn copy_fixture(into: &Path) {
    let src = fixture_dir();
    std::fs::create_dir_all(into.join("signed-statements")).unwrap();
    for name in [
        "capsules.jsonl",
        "checkpoints.jsonl",
        "mmr_nodes.dat",
        "node-key.pub.pem",
    ] {
        std::fs::copy(src.join(name), into.join(name)).unwrap();
    }
    for id in FIXTURE_IDS {
        let name = format!("signed-statements/{id}.cose");
        std::fs::copy(src.join(&name), into.join(&name)).unwrap();
    }
}

/// The demo producer's deterministic key, which signed the fixture.
fn demo_key() -> SigningKey {
    let seed: [u8; 32] =
        Sha256::digest(b"capsule-emit-mesh/demo3-producer/deterministic-key/v1").into();
    SigningKey::from_bytes(&seed)
}

fn no_padding() -> CheckpointCadenceConfig {
    CheckpointCadenceConfig {
        pad_bucket: 0,
        ..Default::default()
    }
}

/// No witness is configured, so the anchor is never contacted.
fn offline_anchor() -> AnchorClient {
    AnchorClient::new("http://127.0.0.1:9")
}

fn verify_every_line(dir: &Path, ledger: &Ledger) {
    let key =
        load_verifying_key_pem(&std::fs::read_to_string(dir.join("node-key.pub.pem")).unwrap())
            .unwrap();
    let known = ledger.known_capsule_ids();
    for id in ledger.capsule_ids_in_order() {
        let entry = ledger
            .lookup(&id)
            .unwrap()
            .expect("indexed id has an entry");
        let report = verify_offline(&entry.capsule, &entry.signed_statement, &key, Some(&known));
        assert!(report.ok(), "{id}: {:?}", report.findings);
    }
}

fn mesh_poc_for(exchange_id: &str) -> MeshPocV1 {
    MeshPocV1 {
        client_nonce: "4".repeat(32),
        client_nonce_source: "client_supplied".to_string(),
        model_name_digest: hex::encode(Sha256::digest(b"hermes-2-pro-mistral-7b")),
        serving_provenance: ServingProvenance {
            served_by_node_id: "capsule-emit-mesh-demo3-node".to_string(),
            dispatch_path: None,
            requesting_party: "capsule-emit-mesh-demo3-client".to_string(),
            exchange_id: exchange_id.to_string(),
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
            usage: None,
            seq: 4,
            prev_seq: Some(3),
            peer_capsule_id: None,
            peer_capsule_id_provenance: None,
            twin_bracket_id: None,
        },
        role: "served".to_string(),
        observation_point: None,
        generation_parameters: Map::new(),
        latency_ms: "1.0".to_string(),
        binary_attestation: None,
        tee_attestation: None,
    }
}

/// Seal one new record through capsule-emit, chained to `parent`, and append
/// it with its statement.
fn append_new_record(ledger: &mut Ledger, parent: &str, key: &SigningKey) -> String {
    let mesh = mesh_poc_for("chatcmpl-after-upgrade");
    let capsule = seal(&CapsuleInput {
        action_id: "mesh-poc/demo3/after_upgrade".to_string(),
        action_type: "decide".to_string(),
        operator: "capsule-emit-mesh-demo3".to_string(),
        developer: capsule_producer::DEVELOPER.to_string(),
        timestamp: "2026-10-15T00:00:00Z".to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "hermes-2-pro-mistral-7b".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: "c".repeat(64),
        agent_output_digest: Some("d".repeat(64)),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: json!({"name": "rust-demo3"}),
        compute_attestation_extensions: mesh_poc::extensions(&mesh, "hermes-2-pro-mistral-7b"),
        effect_status: "confirmed".to_string(),
        effect_type: "inference_completion".to_string(),
        effect_request_digest: Some("c".repeat(64)),
        effect_response_digest: Some("d".repeat(64)),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: "accept".to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: "executed".to_string(),
        chain: Some(ChainLink {
            parent_capsule_id: parent.to_string(),
            relation: "follows".to_string(),
        }),
        store_nonce: fresh_store_nonce(),
    })
    .unwrap();
    let id = capsule["capsule_id"].as_str().unwrap().to_string();
    let statement = build_signed_statement(
        &SignedStatementInput {
            payload: &payload_bytes(&capsule),
            issuer: "capsule-emit-mesh-demo3-rust",
            subject: &id,
            content_type: "application/vnd.agent-action-capsule+json",
        },
        key,
    );
    ledger.append(&capsule, &statement).unwrap();
    id
}

fn stored_checkpoints(dir: &Path) -> Vec<CheckpointRecord> {
    std::fs::read_to_string(dir.join("checkpoints.jsonl"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut v: Value = serde_json::from_str(line).unwrap();
            // `checkpoint_cose` rides beside the record on disk.
            v.as_object_mut().unwrap().remove("checkpoint_cose");
            serde_json::from_value(v).unwrap()
        })
        .collect()
}

#[test]
fn a_0_2_0_ledger_opens_verifies_and_keeps_its_checkpoint_root() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    copy_fixture(dir);

    let (ledger, report) = Ledger::open(dir).unwrap();
    assert_eq!(report.valid_entries, 3);
    assert_eq!(report.truncated_torn_write_at, None);
    assert_eq!(ledger.capsule_ids_in_order(), FIXTURE_IDS);
    assert_eq!(ledger.chain_head(), Some(FIXTURE_IDS[2]));
    verify_every_line(dir, &ledger);

    // The durable node store 0.2.0 wrote is reused as-is: nothing to re-hash.
    let (mut state, load) = CheckpointState::load(dir, LOG_ID, no_padding()).unwrap();
    assert_eq!(load.leaves_indexed_this_load, 0);
    assert_eq!(state.leaf_count(), 3);
    let last = state
        .last_checkpoint()
        .expect("0.2.0 checkpoint loads")
        .clone();
    assert_eq!(last.mmr_size, FIXTURE_MMR_SIZE);
    assert_eq!(last.root, FIXTURE_ROOT);
    assert!(last.verify_signature_offline());

    // Every record's inclusion proof checks against the root 0.2.0 signed.
    let root: [u8; 32] = hex::decode(FIXTURE_ROOT).unwrap().try_into().unwrap();
    for (i, id) in FIXTURE_IDS.iter().enumerate() {
        let coverage = state.existing_coverage(id).unwrap().expect("covered");
        assert_eq!(coverage.leaf_index, i as u64);
        let leaf: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        assert!(verify_inclusion(
            &root,
            FIXTURE_MMR_SIZE,
            coverage.leaf_index,
            &leaf,
            &coverage.proof
        ));
    }

    // Nothing new since 0.2.0's checkpoint: reconnect cuts nothing.
    assert!(state
        .reconnect(&demo_key(), &offline_anchor())
        .unwrap()
        .is_none());
}

#[test]
fn a_0_2_0_node_store_rebuilt_by_capsule_emit_gives_the_same_root() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    copy_fixture(dir);
    std::fs::remove_file(dir.join("mmr_nodes.dat")).unwrap();
    std::fs::remove_file(dir.join("checkpoints.jsonl")).unwrap();

    let (mut state, load) = CheckpointState::load(dir, LOG_ID, no_padding()).unwrap();
    assert_eq!(load.leaves_indexed_this_load, 3);
    let cp = state
        .reconnect(&demo_key(), &offline_anchor())
        .unwrap()
        .expect("three uncheckpointed records");
    assert_eq!(cp.mmr_size, FIXTURE_MMR_SIZE);
    assert_eq!(cp.root, FIXTURE_ROOT);
}

#[test]
fn records_sealed_by_capsule_emit_append_to_a_0_2_0_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    copy_fixture(dir);
    let key = demo_key();

    let (mut ledger, _) = Ledger::open(dir).unwrap();
    let new_id = append_new_record(&mut ledger, FIXTURE_IDS[2], &key);
    assert_eq!(ledger.chain_head(), Some(new_id.as_str()));
    drop(ledger);

    // Reopen: the mixed ledger replays, links and verifies end to end.
    let (ledger, report) = Ledger::open(dir).unwrap();
    assert_eq!(report.valid_entries, 4);
    let mut expected: Vec<String> = FIXTURE_IDS.iter().map(|s| s.to_string()).collect();
    expected.push(new_id.clone());
    assert_eq!(ledger.capsule_ids_in_order(), expected);
    verify_every_line(dir, &ledger);
    let new_record = ledger.lookup(&new_id).unwrap().unwrap().capsule;
    assert_eq!(
        new_record["chain"]["parent_capsule_id"].as_str(),
        Some(FIXTURE_IDS[2])
    );

    // The next checkpoint extends 0.2.0's: same log, prev = the old root.
    let (mut state, load) = CheckpointState::load(dir, LOG_ID, no_padding()).unwrap();
    assert_eq!(load.leaves_indexed_this_load, 1);
    let cp = state
        .reconnect(&key, &offline_anchor())
        .unwrap()
        .expect("one new record to checkpoint");
    assert_eq!(cp.log_id, LOG_ID);
    assert_eq!(cp.prev_size, FIXTURE_MMR_SIZE);
    assert_eq!(cp.prev_root, FIXTURE_ROOT);
    assert_eq!(cp.mmr_size, 7);
    assert!(cp.verify_signature_offline());

    // checkpoints.jsonl keeps 0.2.0's line byte for byte, then the new one.
    let stored = stored_checkpoints(dir);
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].root, FIXTURE_ROOT);
    assert_eq!(stored[1].root, cp.root);
    let old_line = std::fs::read_to_string(fixture_dir().join("checkpoints.jsonl")).unwrap();
    assert!(std::fs::read_to_string(dir.join("checkpoints.jsonl"))
        .unwrap()
        .starts_with(&old_line));
}
