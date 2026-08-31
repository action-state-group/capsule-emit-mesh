//! Milestone 2 acceptance (chain + ledger slice): a 3-capsule chain built and
//! ledgered by THIS crate must verify GREEN end-to-end (COSE signature +
//! byte-exact payload + chain integrity) against the Python reference
//! (`scitt_cose` + `agent_action_capsule.verify.verify_store`), survive a
//! simulated restart (chain head recovered from disk alone), and REJECT a
//! tampered signature / a corrupted chain link.
//!
//! `#[ignore]`d and gated on env vars, same shape as M1's
//! `cross_language_conformance.rs`:
//!
//!   AAC_PYTHON=python3 \
//!   AAC_VERIFY_LEDGER_SCRIPT=$PWD/tests/scripts/verify_rust_ledger.py \
//!     cargo test --test chain_ledger_conformance -- --ignored --nocapture

use capsule_producer::capsule::{
    seal, CapsuleInput, ChainLink, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys::KeyPair;
use capsule_producer::ledger::Ledger;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

struct Env {
    python: String,
    verify_script: PathBuf,
}

fn env() -> Option<Env> {
    Some(Env {
        python: std::env::var("AAC_PYTHON").ok()?,
        verify_script: std::env::var("AAC_VERIFY_LEDGER_SCRIPT").ok()?.into(),
    })
}

fn sample_input(seed: &str, chain: Option<ChainLink>) -> CapsuleInput {
    let mut generation_parameters = serde_json::Map::new();
    generation_parameters.insert("temperature".into(), serde_json::json!("0.7"));
    CapsuleInput {
        action_id: format!("mesh-poc/rust-producer-m2/{seed}"),
        action_type: "decide".to_string(),
        operator: "capsule-emit-mesh-poc-rust".to_string(),
        developer: "capsule-producer/0.2.0".to_string(),
        timestamp: format!("2026-08-23T00:00:0{seed}Z"),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "hermes-2-pro-mistral-7b".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: "a".repeat(64),
        agent_output_digest: "b".repeat(64),
        tool_calls_digest: None,
        reasoning_digest: None,
        runtime: "0".repeat(64) + ":rust-milestone-2",
        mesh_poc: MeshPocV1 {
            client_nonce: seed.repeat(32).chars().take(32).collect(),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "chain-ledger-node".to_string(),
                requesting_party: "chain-ledger-client".to_string(),
                exchange_id: "chain-ledger-exchange".to_string(),
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
                model_canonical_ref: None,
                model_revision: None,
                usage: Some(TokenUsage {
                    prompt_tokens: 5,
                    completion_tokens: 6,
                    total_tokens: 11,
                }),
            },
            generation_parameters,
            latency_ms: "42.0".to_string(),
            binary_attestation: None,
            tee_attestation: None,
        },
        effect_status: "confirmed".to_string(),
        effect_type: "inference_completion".to_string(),
        effect_request_digest: "a".repeat(64),
        effect_response_digest: "b".repeat(64),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: "accept".to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: "executed".to_string(),
        chain,
    }
}

struct Chain {
    dir: tempfile::TempDir,
    pubkey_path: PathBuf,
    capsule_ids: Vec<String>,
}

/// Build and ledger a 3-capsule chain, then simulate a process restart
/// (drop + reopen the Ledger) before returning -- so the returned state is
/// exactly what a fresh `Ledger::open()` recovered from disk, not what a
/// live in-memory `Ledger` happens to remember.
fn build_chain() -> Chain {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger_dir = dir.path().join("ledger");
    let keys = KeyPair::generate();
    let pubkey_path = dir.path().join("node-key.pub.pem");
    std::fs::write(&pubkey_path, keys.public_key_pem()).unwrap();

    let (mut ledger, _report) = Ledger::open(&ledger_dir).expect("open ledger");
    let mut capsule_ids = Vec::new();
    let mut parent: Option<String> = None;

    for seed in ["1", "2", "3"] {
        let chain = parent.as_ref().map(|p| ChainLink {
            parent_capsule_id: p.clone(),
            relation: "follows".to_string(),
        });
        let input = sample_input(seed, chain);
        let capsule = seal(&input).expect("seal");
        let capsule_id = capsule["capsule_id"].as_str().unwrap().to_string();
        let payload = capsule_producer::capsule::payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: "mesh-node-rust-milestone-2",
                subject: &capsule_id,
                content_type: "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02",
            },
            &keys.signing_key,
        );
        ledger.append(&capsule, &statement).expect("ledger append");
        parent = Some(capsule_id.clone());
        capsule_ids.push(capsule_id);
    }
    drop(ledger); // simulate process exit

    // Simulated restart: reopen and confirm the head survived purely via
    // on-disk replay, matching this test's own acceptance requirement.
    let (reopened, report) = Ledger::open(&ledger_dir).expect("reopen ledger");
    assert_eq!(report.valid_entries, 3, "restart must recover all 3 entries");
    assert_eq!(
        reopened.chain_head(),
        Some(capsule_ids.last().unwrap().as_str()),
        "restart must preserve the valid chain head"
    );

    Chain {
        dir,
        pubkey_path,
        capsule_ids,
    }
}

fn run_ledger_verifier(env: &Env, ledger_dir: &std::path::Path, pubkey_path: &std::path::Path) -> (bool, Value) {
    let output = Command::new(&env.python)
        .arg(&env.verify_script)
        .arg(ledger_dir)
        .arg(pubkey_path)
        .output()
        .expect("run python ledger verifier");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    eprintln!("ledger verifier: {stdout}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("parse verifier JSON");
    (output.status.success(), parsed)
}

#[test]
#[ignore]
fn rust_chained_ledger_verifies_green_end_to_end() {
    let Some(env) = env() else {
        eprintln!("AAC_PYTHON / AAC_VERIFY_LEDGER_SCRIPT not set; skipping (see module docs)");
        return;
    };

    let chain = build_chain();
    let ledger_dir = chain.dir.path().join("ledger");

    let (ok, result) = run_ledger_verifier(&env, &ledger_dir, &chain.pubkey_path);
    assert!(ok, "Python reference rejected a valid Rust-built chain: {result}");
    assert_eq!(result["count"], 3);
    assert_eq!(result["cose_all_ok"], true, "{result}");
    assert_eq!(result["payload_bytes_all_match"], true, "{result}");
    assert_eq!(result["store_ok"], true, "{result}");

    // --- Mutation 1: flip a signature byte in the MIDDLE capsule's
    //     statement -- COSE verification must fail for that entry, and the
    //     overall verdict must flip to not-ok.
    let statements_dir = ledger_dir.join("signed-statements");
    let mid_id = &chain.capsule_ids[1];
    let stmt_path = statements_dir.join(format!("{mid_id}.cose"));
    let mut bytes = std::fs::read(&stmt_path).unwrap();
    let flip_at = bytes.len() - 5;
    bytes[flip_at] ^= 0x01;
    std::fs::write(&stmt_path, &bytes).unwrap();

    let (mut_ok, mut_result) = run_ledger_verifier(&env, &ledger_dir, &chain.pubkey_path);
    assert!(
        !mut_ok,
        "Python reference ACCEPTED a chain with a tampered signature: {mut_result}"
    );
    assert_eq!(mut_result["cose_all_ok"], false, "{mut_result}");

    // Restore the valid signature before the next mutation, so each
    // mutation is tested in isolation against an otherwise-valid chain.
    let flip_at = bytes.len() - 5;
    bytes[flip_at] ^= 0x01;
    std::fs::write(&stmt_path, &bytes).unwrap();

    // --- Mutation 2: corrupt the chain by rewriting the LAST capsule's
    //     `chain.parent_capsule_id` in capsules.jsonl to point at a
    //     nonexistent capsule -- the store-level chain check must catch it.
    //     Target the exact `parent_capsule_id` field occurrence (not the
    //     parent's own `capsule_id` field, which appears earlier in the
    //     file and would otherwise be replaced first).
    let capsules_path = ledger_dir.join("capsules.jsonl");
    let contents = std::fs::read_to_string(&capsules_path).unwrap();
    let bogus_parent = "f".repeat(64);
    let last_parent = &chain.capsule_ids[1];
    let needle = format!("\"parent_capsule_id\":\"{last_parent}\"");
    let replacement = format!("\"parent_capsule_id\":\"{bogus_parent}\"");
    assert!(
        contents.contains(&needle),
        "sanity: expected {needle:?} in ledger contents"
    );
    let corrupted = contents.replacen(&needle, &replacement, 1);
    assert_ne!(contents, corrupted, "sanity: replacement must have applied");
    std::fs::write(&capsules_path, corrupted).unwrap();

    let (chain_mut_ok, chain_mut_result) = run_ledger_verifier(&env, &ledger_dir, &chain.pubkey_path);
    assert!(
        !chain_mut_ok,
        "Python reference ACCEPTED a chain with a broken parent link: {chain_mut_result}"
    );
    assert_eq!(chain_mut_result["store_ok"], false, "{chain_mut_result}");
}
