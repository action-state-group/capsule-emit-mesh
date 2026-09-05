//! Self-contained (no external env vars, no Python) regression test for the
//! `verify_capsule` offline verification CLI (task item 5): builds a small
//! chained, ledgered stream with this crate's own APIs, then shells out to
//! the COMPILED BINARY (not the library functions directly) so this
//! actually exercises the CLI wiring -- argument parsing, file I/O, JSON
//! output shape, exit codes -- not just the library call underneath it.

use capsule_producer::capsule::{
    seal, CapsuleInput, ChainLink, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys::KeyPair;
use capsule_producer::ledger::Ledger;
use serde_json::Value;
use std::process::Command;

fn sample_input(seed: &str, chain: Option<ChainLink>) -> CapsuleInput {
    let mut generation_parameters = serde_json::Map::new();
    generation_parameters.insert("temperature".into(), serde_json::json!("0.7"));
    CapsuleInput {
        action_id: format!("mesh-poc/verify-cli-test/{seed}"),
        action_type: "decide".to_string(),
        operator: "op".to_string(),
        developer: "dev".to_string(),
        timestamp: "2026-08-23T00:00:00Z".to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "m".to_string(),
        provider: "p".to_string(),
        agent_input_digest: "a".repeat(64),
        agent_output_digest: "b".repeat(64),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: "runtime".to_string(),
        mesh_poc: MeshPocV1 {
            client_nonce: seed.repeat(32).chars().take(32).collect(),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "verify-cli-node".to_string(),
                requesting_party: "verify-cli-client".to_string(),
                exchange_id: "verify-cli-exchange".to_string(),
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
                    prompt_tokens: 7,
                    completion_tokens: 9,
                    total_tokens: 16,
                }),
                seq: 1,
                prev_seq: None,
            },
            generation_parameters,
            latency_ms: "1.0".to_string(),
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

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_verify_capsule")
}

#[test]
fn cli_verifies_a_genuine_chained_ledgered_capsule() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_dir = dir.path().join("ledger");
    let keys = KeyPair::generate();
    let pubkey_path = dir.path().join("pub.pem");
    std::fs::write(&pubkey_path, keys.public_key_pem()).unwrap();

    let (mut ledger, _) = Ledger::open(&ledger_dir).unwrap();

    let c1 = seal(&sample_input("1", None)).unwrap();
    let c1_id = c1["capsule_id"].as_str().unwrap().to_string();
    let p1 = capsule_producer::capsule::payload_bytes(&c1);
    let s1 = build_signed_statement(
        &SignedStatementInput {
            payload: &p1,
            issuer: "node",
            subject: &c1_id,
            content_type: "application/vnd.agent-action-capsule+json",
        },
        &keys.signing_key,
    );
    ledger.append(&c1, &s1).unwrap();

    let c2 = seal(&sample_input(
        "2",
        Some(ChainLink {
            parent_capsule_id: c1_id.clone(),
            relation: "follows".to_string(),
        }),
    ))
    .unwrap();
    let c2_id = c2["capsule_id"].as_str().unwrap().to_string();
    let p2 = capsule_producer::capsule::payload_bytes(&c2);
    let s2 = build_signed_statement(
        &SignedStatementInput {
            payload: &p2,
            issuer: "node",
            subject: &c2_id,
            content_type: "application/vnd.agent-action-capsule+json",
        },
        &keys.signing_key,
    );
    ledger.append(&c2, &s2).unwrap();
    drop(ledger);

    let capsule_path = dir.path().join("c2.json");
    let statement_path = dir.path().join("c2.cose");
    std::fs::write(&capsule_path, &p2).unwrap();
    std::fs::write(&statement_path, &s2).unwrap();

    // Without a ledger_dir: chain-parent membership is unchecked (info,
    // non-gating) -- still overall ok, matching agent_action_capsule.verify
    // Check 6's no-store behavior.
    let out = Command::new(cli())
        .args([&capsule_path, &statement_path, &pubkey_path])
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["capsule_id"], c2_id);

    // With the ledger_dir: chain-parent membership IS checked, and c1 is in
    // it -- still ok.
    let out2 = Command::new(cli())
        .args([&capsule_path, &statement_path, &pubkey_path, &ledger_dir])
        .output()
        .unwrap();
    assert!(out2.status.success(), "{:?}", out2);
    let v2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(v2["ok"], true, "{v2}");
    assert_eq!(v2["chain_ok"], true, "{v2}");
}

#[test]
fn cli_rejects_tampered_statement_and_reports_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyPair::generate();
    let pubkey_path = dir.path().join("pub.pem");
    std::fs::write(&pubkey_path, keys.public_key_pem()).unwrap();

    let c1 = seal(&sample_input("1", None)).unwrap();
    let c1_id = c1["capsule_id"].as_str().unwrap().to_string();
    let p1 = capsule_producer::capsule::payload_bytes(&c1);
    let mut s1 = build_signed_statement(
        &SignedStatementInput {
            payload: &p1,
            issuer: "node",
            subject: &c1_id,
            content_type: "application/vnd.agent-action-capsule+json",
        },
        &keys.signing_key,
    );
    let flip_at = s1.len() - 5;
    s1[flip_at] ^= 0x01;

    let capsule_path = dir.path().join("c1.json");
    let statement_path = dir.path().join("c1.cose");
    std::fs::write(&capsule_path, &p1).unwrap();
    std::fs::write(&statement_path, &s1).unwrap();

    let out = Command::new(cli())
        .args([&capsule_path, &statement_path, &pubkey_path])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["cose_ok"], false, "{v}");
}
