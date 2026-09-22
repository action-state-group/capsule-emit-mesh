//! [mesh-plugin-checkpoint-cadence] acceptance: the checkpoint this crate's
//! `checkpoint::CheckpointState` produces over a `capsules.jsonl` must carry
//! the SAME MMR root an independent Python recomputation gets over the
//! identical leaves, and the COSE-wire statement must verify under the
//! Python reference offline verifier (`capsule_emit.checkpoint.
//! verify_checkpoint_cose_offline`) -- cross-language verification, the same
//! discipline `cross_language_conformance.rs`/`chain_ledger_conformance.rs`
//! already hold for Layer 0. This test is checkpoint-layer only: Layer 0
//! (capsule_id / COSE_Sign1 capsule signature) byte-identity is already
//! covered by those two tests, not re-derived here.
//!
//! `#[ignore]`d and gated on env vars (same shape as this crate's other
//! cross-language tests): this crate's CI has no checkout of the private
//! multi-repo workspace the Python `capsule_emit`/`cll` packages live in.
//! Run it for real with:
//!
//!   AAC_PYTHON=python3 \
//!   AAC_CHECKPOINT_VERIFY_SCRIPT=/path/to/tests/scripts/checkpoint_invariance_check.py \
//!     cargo test --test checkpoint_invariance -- --ignored --nocapture

use capsule_producer::anchor::AnchorClient;
use capsule_producer::capsule::{seal, CapsuleInput, MeshPocV1, ServingProvenance, TokenUsage};
use capsule_producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys::KeyPair;
use capsule_producer::ledger::Ledger;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::process::Command;

struct Env {
    python: String,
    verify_script: PathBuf,
}

fn env() -> Option<Env> {
    let python = std::env::var("AAC_PYTHON").ok()?;
    let verify_script = std::env::var("AAC_CHECKPOINT_VERIFY_SCRIPT").ok()?.into();
    Some(Env {
        python,
        verify_script,
    })
}

/// One minimal, valid capsule input for leaf `n` -- content doesn't matter
/// for the checkpoint layer, only that `seal()` produces a real, distinct
/// `capsule_id` each time.
fn capsule_input(n: usize, parent: Option<&str>) -> CapsuleInput {
    CapsuleInput {
        action_id: format!("mesh-poc/checkpoint-invariance/{n:08}"),
        action_type: "decide".to_string(),
        operator: "capsule-emit-mesh-poc-rust".to_string(),
        developer: "capsule-producer/checkpoint-invariance-test".to_string(),
        timestamp: "2026-09-22T00:00:00Z".to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "hermes-2-pro-mistral-7b".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: format!("{n:064x}"),
        agent_output_digest: format!("{:064x}", n + 1),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: serde_json::json!({"name": "checkpoint-invariance-test"}),
        mesh_poc: MeshPocV1 {
            client_nonce: format!("{n:032x}"),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "conformance-node".to_string(),
                dispatch_path: None,
                requesting_party: "conformance-client".to_string(),
                exchange_id: format!("conformance-exchange-{n}"),
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
                peer_capsule_id: None,
                peer_capsule_id_provenance: None,
                usage: Some(TokenUsage {
                    prompt_tokens: 1,
                    completion_tokens: 1,
                    total_tokens: 2,
                }),
                seq: (n + 1) as u64,
                prev_seq: if n == 0 { None } else { Some(n as u64) },
            },
            role: "served".to_string(),
            observation_point: None,
            generation_parameters: serde_json::Map::new(),
            latency_ms: "1.0".to_string(),
            binary_attestation: None,
            tee_attestation: None,
        },
        effect_status: "confirmed".to_string(),
        effect_type: "inference_completion".to_string(),
        effect_request_digest: format!("{n:064x}"),
        effect_response_digest: format!("{:064x}", n + 1),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: "accept".to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: "executed".to_string(),
        chain: parent.map(|p| capsule_producer::capsule::ChainLink {
            parent_capsule_id: p.to_string(),
            relation: "follows".to_string(),
        }),
    }
}

fn build_ledger(dir: &std::path::Path, keys: &SigningKey, n: usize) -> Ledger {
    let (mut ledger, _report) = Ledger::open(dir).expect("open ledger");
    let mut parent: Option<String> = None;
    for i in 0..n {
        let input = capsule_input(i, parent.as_deref());
        let capsule = seal(&input).expect("seal capsule");
        let capsule_id = capsule["capsule_id"].as_str().unwrap().to_string();
        let payload = capsule_producer::capsule::payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: "checkpoint-invariance-node",
                subject: &capsule_id,
                content_type:
                    "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02",
            },
            keys,
        );
        ledger
            .append(&capsule, &statement)
            .expect("append to ledger");
        parent = Some(capsule_id);
    }
    ledger
}

fn run_python_check(
    env: &Env,
    ledger_dir: &std::path::Path,
    root_hex: &str,
    mmr_size: u64,
    cose_hex_path: &str,
) -> (bool, String) {
    let output = Command::new(&env.python)
        .arg(&env.verify_script)
        .arg(ledger_dir)
        .arg(root_hex)
        .arg(mmr_size.to_string())
        .arg(cose_hex_path)
        .output()
        .expect("run python checkpoint invariance checker");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (output.status.success(), stdout)
}

#[test]
#[ignore]
fn rust_checkpoint_root_and_cose_match_independent_python_recomputation() {
    let Some(env) = env() else {
        eprintln!("AAC_PYTHON / AAC_CHECKPOINT_VERIFY_SCRIPT not set; skipping (see module docs)");
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let keys = KeyPair::generate();
    let ledger = build_ledger(dir.path(), &keys.signing_key, 5);
    drop(ledger); // release the append handle before CheckpointState opens the same dir

    let (mut state, _report) = CheckpointState::load(
        dir.path(),
        "checkpoint-invariance-log",
        CheckpointCadenceConfig::default(),
    )
    .expect("load checkpoint state");
    let anchor = AnchorClient::new("http://127.0.0.1:1"); // no witness_urls configured -- never dialled
    let cp = state
        .reconnect(&keys.signing_key, &anchor)
        .expect("reconnect")
        .expect("a checkpoint must be produced over 5 sealed capsules");

    assert_eq!(cp.log_id, "checkpoint-invariance-log");
    assert!(
        cp.verify_signature_offline(),
        "Rust's own offline check must accept its own checkpoint"
    );

    let cose_hex_path = dir.path().join("checkpoint.cose.hex");
    // `state`'s own last-built COSE bytes aren't exposed publicly (only
    // persisted to checkpoints.jsonl) -- read them back off disk the same
    // way any stranger consuming this ledger would.
    let lines = cll::store::read_checkpoints(dir.path().join("checkpoints.jsonl"))
        .expect("read checkpoints.jsonl");
    let last = lines.last().expect("at least one checkpoint line");
    let cose_arg = match &last.checkpoint_cose_hex {
        Some(hex_str) => {
            std::fs::write(&cose_hex_path, hex_str).unwrap();
            cose_hex_path.display().to_string()
        }
        None => "-".to_string(),
    };

    let (ok, stdout) = run_python_check(&env, dir.path(), &cp.root, cp.mmr_size, &cose_arg);
    eprintln!("python checkpoint invariance check: {stdout}");
    assert!(ok, "python checkpoint invariance check failed: {stdout}");

    let result: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse checker JSON");
    assert_eq!(result["root_match"], true, "{stdout}");
    assert_eq!(result["computed_root"], cp.root, "{stdout}");
    if cose_arg != "-" {
        assert_eq!(result["cose_ok"], true, "{stdout}");
    }
}
