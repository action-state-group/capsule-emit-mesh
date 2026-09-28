//! Checkpoint padding and coarse time (Evidence Layer -00 §12.1, "What a
//! Checkpoint Reveals"):
//!
//! - every checkpoint cut with padding on has `mmr_leaf_count % bucket == 0`;
//! - inclusion and consistency still verify across padded checkpoints,
//!   against an MMR rebuilt independently from `capsules.jsonl`;
//! - padding stays outside the chain, so the ledger reloads clean and the next
//!   real record chains to the previous real record;
//! - a restart mid-bucket (or a retried cut) never pads twice;
//! - a record that lands between the padding and the cut waits for the next
//!   checkpoint rather than knocking this one off the boundary;
//! - every sealed record carries a fresh 256-bit store nonce inside its
//!   `capsule_id` preimage, and every committed time is minute-granular.

use capsule_producer::anchor::AnchorClient;
use capsule_producer::capsule::{
    fresh_store_nonce, seal, seal_citing_record, CapsuleInput, ChainLink, MeshPocV1,
    ReceivedHalfProvenance, SealError, ServingProvenance, STORE_NONCE_FIELD,
};
use capsule_producer::checkpoint::{
    verify_inclusion, CheckpointCadenceConfig, CheckpointRecord, CheckpointState, PaddingSink,
};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::jcs::compute_capsule_id;
use capsule_producer::ledger::Ledger;
use capsule_producer::padding::is_padding;
use capsule_producer::timestamp::is_minute_granular;
use cll::mmr::{
    add_leaf, consistency_proof, leaf_count, leaf_hash, peaks, root_from_peaks, verify_consistency,
    MemoryNodeStore, NodeReader,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};

const BUCKET: u64 = 8;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn input(n: usize, chain: Option<ChainLink>) -> CapsuleInput {
    CapsuleInput {
        action_id: format!("mesh-poc/padding-test/{n}"),
        action_type: "decide".to_string(),
        operator: "op".to_string(),
        developer: "dev".to_string(),
        timestamp: capsule_producer::timestamp::utc_now_minute(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "m".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: format!("{n:064x}"),
        agent_output_digest: Some(format!("{:064x}", n + 1)),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: serde_json::json!({"name": "runtime"}),
        mesh_poc: MeshPocV1 {
            client_nonce: "c".repeat(32),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "node".to_string(),
                dispatch_path: None,
                requesting_party: "client".to_string(),
                exchange_id: format!("exch-{n}"),
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
                seq: n as u64 + 1,
                prev_seq: (n > 0).then_some(n as u64),
                peer_capsule_id: None,
                peer_capsule_id_provenance: None,
                twin_bracket_id: None,
            },
            role: "served".to_string(),
            observation_point: None,
            generation_parameters: serde_json::Map::new(),
            latency_ms: "1.000".to_string(),
            binary_attestation: None,
            tee_attestation: None,
        },
        effect_status: "confirmed".to_string(),
        effect_type: "inference_completion".to_string(),
        effect_request_digest: Some(format!("{n:064x}")),
        effect_response_digest: Some(format!("{:064x}", n + 1)),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: "accept".to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: "executed".to_string(),
        chain,
        store_nonce: fresh_store_nonce(),
    }
}

fn statement(capsule: &Value) -> Vec<u8> {
    build_signed_statement(
        &SignedStatementInput {
            payload: &serde_json::to_vec(capsule).unwrap(),
            issuer: "padding-test",
            subject: capsule["capsule_id"].as_str().unwrap(),
            content_type: "application/vnd.agent-action-capsule+json",
        },
        &key(),
    )
}

/// Seal and append one real record onto the ledger's chain; its id.
fn append_real(ledger: &Mutex<Ledger>, n: usize) -> String {
    let mut ledger = ledger.lock().unwrap();
    let chain = ledger.chain_head().map(|parent| ChainLink {
        parent_capsule_id: parent.to_string(),
        relation: "follows".to_string(),
    });
    let mut capsule = seal(&input(n, chain)).unwrap();
    capsule_producer::capsule::attach_producer_envelope(&mut capsule, &key()).unwrap();
    ledger.append(&capsule, &statement(&capsule)).unwrap();
    capsule["capsule_id"].as_str().unwrap().to_string()
}

/// A hook run once, right after padding, to land a real record before the cut.
type AfterPad = Box<dyn FnOnce(&Mutex<Ledger>) + Send>;

/// The plugin's padding hook, over a shared ledger (the plugin's is its
/// `CapsuleState`); `after_pad` lets a test land a real record between the
/// padding and the cut.
struct Padder {
    ledger: Arc<Mutex<Ledger>>,
    after_pad: Mutex<Option<AfterPad>>,
}

impl PaddingSink for Padder {
    fn pad_to_bucket(&self, bucket: u64) -> Result<u64, String> {
        let padded = self
            .ledger
            .lock()
            .unwrap()
            .pad_to_bucket(bucket, &key(), "padding-test")
            .map_err(|e| e.to_string())?;
        if let Some(hook) = self.after_pad.lock().unwrap().take() {
            hook(&self.ledger);
        }
        Ok(padded)
    }
}

fn cfg() -> CheckpointCadenceConfig {
    CheckpointCadenceConfig {
        pad_bucket: BUCKET,
        ..CheckpointCadenceConfig::default()
    }
}

fn open(dir: &Path) -> (Arc<Mutex<Ledger>>, CheckpointState) {
    let (ledger, _) = Ledger::open(dir).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    let (mut state, _) = CheckpointState::load(dir, "padding-test-log", cfg()).unwrap();
    state.set_padding_sink(Box::new(Padder {
        ledger: ledger.clone(),
        after_pad: Mutex::new(None),
    }));
    (ledger, state)
}

fn anchor() -> AnchorClient {
    AnchorClient::new("http://127.0.0.1:1")
}

fn lines(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("capsules.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// An MMR rebuilt from `capsules.jsonl` alone, as a third party holding the
/// ledger would -- every line one leaf, padding included.
fn independent_mmr(dir: &Path) -> MemoryNodeStore {
    let mut store = MemoryNodeStore::new();
    for line in lines(dir) {
        let id = hex::decode(line["capsule_id"].as_str().unwrap()).unwrap();
        add_leaf(&mut store, leaf_hash(&id.try_into().unwrap())).unwrap();
    }
    store
}

fn root_at(store: &MemoryNodeStore, size: u64) -> [u8; 32] {
    let hashes: Vec<_> = peaks(size)
        .unwrap()
        .iter()
        .map(|&p| store.node(p))
        .collect();
    root_from_peaks(&hashes)
}

fn digest(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn assert_aligned(cp: &CheckpointRecord) {
    let leaves = leaf_count(cp.mmr_size).unwrap();
    assert_eq!(
        leaves % BUCKET,
        0,
        "checkpoint leaf count {leaves} not on the bucket"
    );
    assert!(
        is_minute_granular(&cp.timestamp),
        "checkpoint time {}",
        cp.timestamp
    );
}

#[test]
fn every_checkpoint_is_on_the_bucket_and_proofs_verify_across_padded_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, mut state) = open(dir.path());

    let first_ids: Vec<String> = (0..3).map(|n| append_real(&ledger, n)).collect();
    let first = state
        .checkpoint_covering(&first_ids[1], &key(), &anchor())
        .unwrap();
    assert!(first.cut_new);
    assert_aligned(&first.checkpoint);
    assert_eq!(leaf_count(first.checkpoint.mmr_size).unwrap(), BUCKET);

    // A second window: 10 more real records -> 13 real + 5 padding so far,
    // so the next cut lands on 24.
    let second_ids: Vec<String> = (3..13).map(|n| append_real(&ledger, n)).collect();
    let second = state
        .checkpoint_covering(second_ids.last().unwrap(), &key(), &anchor())
        .unwrap();
    assert_aligned(&second.checkpoint);
    assert_eq!(leaf_count(second.checkpoint.mmr_size).unwrap(), 24);
    assert_eq!(second.checkpoint.prev_size, first.checkpoint.mmr_size);

    // Independent rebuild: the roots match, inclusion verifies for real
    // records in both checkpoints, and the second extends the first.
    let mmr = independent_mmr(dir.path());
    for (cp, id, cov) in [
        (&first.checkpoint, &first_ids[1], &first),
        (&second.checkpoint, second_ids.last().unwrap(), &second),
    ] {
        assert_eq!(hex::encode(root_at(&mmr, cp.mmr_size)), cp.root);
        assert!(verify_inclusion(
            &digest(&cp.root),
            cp.mmr_size,
            cov.leaf_index,
            &digest(id),
            &cov.proof,
        ));
    }
    let proof =
        consistency_proof(&mmr, first.checkpoint.mmr_size, second.checkpoint.mmr_size).unwrap();
    assert!(verify_consistency(
        &digest(&first.checkpoint.root),
        first.checkpoint.mmr_size,
        &digest(&second.checkpoint.root),
        second.checkpoint.mmr_size,
        &proof,
    ));

    // The clock leg pads too.
    append_real(&ledger, 13);
    let clock = state.reconnect(&key(), &anchor()).unwrap().unwrap();
    assert_aligned(&clock);
}

#[test]
fn padding_stays_outside_the_chain_and_the_ledger_reloads_clean() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, mut state) = open(dir.path());
    let a = append_real(&ledger, 0);
    state.reconnect(&key(), &anchor()).unwrap().unwrap();
    let b = append_real(&ledger, 1);

    let all = lines(dir.path());
    assert_eq!(all.len() as u64, BUCKET + 1);
    let real: Vec<&Value> = all.iter().filter(|r| !is_padding(r)).collect();
    assert_eq!(real.len(), 2, "readers see exactly the real records");
    assert_eq!(
        real[1]["chain"]["parent_capsule_id"],
        a.as_str(),
        "b chains to a, never to padding"
    );
    for pad in all.iter().filter(|r| is_padding(r)) {
        assert!(pad.get("chain").is_none());
        assert_eq!(pad["epistemic_type"], "producer_claim");
        let nonce = pad[STORE_NONCE_FIELD].as_str().unwrap();
        assert_eq!(nonce.len(), 64);
        assert_eq!(
            compute_capsule_id(pad).unwrap(),
            pad["capsule_id"].as_str().unwrap()
        );
    }
    drop(ledger);
    drop(state);

    let (reopened, report) = Ledger::open(dir.path()).unwrap();
    assert_eq!(report.valid_entries as u64, BUCKET + 1);
    assert_eq!(reopened.chain_head(), Some(b.as_str()));
    assert_eq!(reopened.entries(), BUCKET + 1);
    assert!(
        !reopened.known_capsule_ids().iter().any(|id| {
            all.iter()
                .any(|r| is_padding(r) && r["capsule_id"] == id.as_str())
        }),
        "padding is never a known link target"
    );
}

#[test]
fn ledger_refuses_padding_on_the_chain_and_links_on_padding() {
    let dir = tempfile::tempdir().unwrap();
    let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
    let pad = capsule_producer::padding::build_padding_record().unwrap();
    assert!(ledger.append(&pad, &statement(&pad)).is_err());

    let mut linked = pad.clone();
    linked["chain"] =
        serde_json::json!({"parent_capsule_id": "a".repeat(64), "relation": "follows"});
    assert!(ledger.append_padding(&linked, &statement(&linked)).is_err());
}

#[test]
fn a_restart_mid_bucket_never_double_pads() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (ledger, _state) = open(dir.path());
        for n in 0..3 {
            append_real(&ledger, n);
        }
        // Crash mid-padding: two of the five padding records made it.
        let mut l = ledger.lock().unwrap();
        for _ in 0..2 {
            let mut pad = capsule_producer::padding::build_padding_record().unwrap();
            capsule_producer::capsule::attach_producer_envelope(&mut pad, &key()).unwrap();
            l.append_padding(&pad, &statement(&pad)).unwrap();
        }
    }
    let (ledger, mut state) = open(dir.path());
    let cp = state.reconnect(&key(), &anchor()).unwrap().unwrap();
    assert_eq!(
        leaf_count(cp.mmr_size).unwrap(),
        BUCKET,
        "3 real + 2 + 3 padding, not a second bucket"
    );
    assert_eq!(lines(dir.path()).len() as u64, BUCKET);

    // A retried pad on an aligned ledger appends nothing.
    let again = ledger
        .lock()
        .unwrap()
        .pad_to_bucket(BUCKET, &key(), "padding-test")
        .unwrap();
    assert_eq!(again, BUCKET);
    assert_eq!(lines(dir.path()).len() as u64, BUCKET);
}

#[test]
fn a_record_landing_between_padding_and_cut_waits_for_the_next_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, _) = Ledger::open(dir.path()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    let id = append_real(&ledger, 0);
    let (mut state, _) = CheckpointState::load(dir.path(), "padding-test-log", cfg()).unwrap();
    state.set_padding_sink(Box::new(Padder {
        ledger: ledger.clone(),
        after_pad: Mutex::new(Some(Box::new(|l: &Mutex<Ledger>| {
            append_real(l, 99);
        }))),
    }));

    let cov = state.checkpoint_covering(&id, &key(), &anchor()).unwrap();
    assert_aligned(&cov.checkpoint);
    assert_eq!(leaf_count(cov.checkpoint.mmr_size).unwrap(), BUCKET);
    assert_eq!(
        state.leaf_count(),
        BUCKET + 1,
        "the late record is folded, not checkpointed"
    );

    // The next cut covers it, on the next boundary.
    let next = state.reconnect(&key(), &anchor()).unwrap().unwrap();
    assert_eq!(leaf_count(next.mmr_size).unwrap(), 2 * BUCKET);
}

#[test]
fn padding_off_cuts_at_the_ledger_size() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, _) = Ledger::open(dir.path()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    append_real(&ledger, 0);
    let off = CheckpointCadenceConfig {
        pad_bucket: 0,
        ..CheckpointCadenceConfig::default()
    };
    let (mut state, _) = CheckpointState::load(dir.path(), "padding-test-log", off).unwrap();
    state.set_padding_sink(Box::new(Padder {
        ledger: ledger.clone(),
        after_pad: Mutex::new(None),
    }));
    let cp = state.reconnect(&key(), &anchor()).unwrap().unwrap();
    assert_eq!(leaf_count(cp.mmr_size).unwrap(), 1);
    assert_eq!(lines(dir.path()).len(), 1);
}

#[test]
fn every_sealed_record_carries_a_fresh_store_nonce_inside_its_id() {
    let a = seal(&input(1, None)).unwrap();
    let b = seal(&input(1, None)).unwrap();
    let nonce_a = a["model_attestation"]["compute_attestation"][STORE_NONCE_FIELD]
        .as_str()
        .unwrap();
    assert_eq!(nonce_a.len(), 64);
    assert_ne!(
        a["capsule_id"], b["capsule_id"],
        "same content, fresh nonce, different id"
    );

    let mut bad = input(1, None);
    bad.store_nonce = "client-supplied".to_string();
    assert!(matches!(seal(&bad), Err(SealError::StoreNonce)));

    let prov = ReceivedHalfProvenance {
        foreign_capsule_id: &"f".repeat(64),
        received_from: "peer",
        via: "push",
        received_at: "2026-09-27T17:08:44.123Z",
        signature_ok: true,
        digest_match: None,
        foreign_agent_input_digest: None,
        foreign_agent_output_digest: None,
    };
    let citing = seal_citing_record(&prov, None, &key()).unwrap();
    let ca = &citing["model_attestation"]["compute_attestation"];
    assert_eq!(ca[STORE_NONCE_FIELD].as_str().unwrap().len(), 64);
    assert_eq!(
        ca["received_half"]["received_at"],
        "2026-09-27T17:08:00.000Z"
    );
    assert!(is_minute_granular(citing["timestamp"].as_str().unwrap()));
}
