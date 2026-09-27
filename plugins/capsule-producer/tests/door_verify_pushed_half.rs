//! The blocker acceptance test:
//! a capsule this Rust producer seals AND attaches its inline signature
//! envelope to must be ACCEPTED by the record-push DOOR's exact code path
//! (`capsule_emit.signing.verify_capsule_signature`, the same function
//! `record_push.handle_record_push` calls at Seam A2) IN ISOLATION -- no
//! ledger, no detached `.cose`, no witness. Before this task the door graded a
//! pushed half UNCLAIMED and refused `signature_unverified`, because the Rust
//! producer left `signature`/`key_id` absent on the capsule.
//!
//! `#[ignore]`d and env-gated (same shape as `cross_language_conformance.rs`):
//! CI has no checkout of the Python reference. Run it for real with the venv
//! the tour's door uses:
//!
//!   AAC_PYTHON=/private/tmp/mesh-clean-venv/bin/python \
//!   AAC_DOOR_VERIFY_SCRIPT=$PWD/tests/scripts/verify_pushed_half_at_door.py \
//!     cargo test --release --test door_verify_pushed_half -- --ignored --nocapture

use capsule_producer::capsule::{
    attach_producer_envelope, seal, CapsuleInput, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::keys::KeyPair;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

struct Env {
    python: String,
    door_verify_script: PathBuf,
}

fn env() -> Option<Env> {
    Some(Env {
        python: std::env::var("AAC_PYTHON").ok()?,
        door_verify_script: std::env::var("AAC_DOOR_VERIFY_SCRIPT").ok()?.into(),
    })
}

fn sample_input() -> CapsuleInput {
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
    }
}

#[test]
#[ignore = "requires the Python capsule_emit reference; see file header"]
fn door_accepts_a_rust_sealed_then_enveloped_pushed_half_in_isolation() {
    let Some(env) = env() else {
        panic!("set AAC_PYTHON and AAC_DOOR_VERIFY_SCRIPT to run this test");
    };

    // 1. Seal + attach the inline producer envelope, exactly as the plugin's
    //    completion path does (one capsule shape everywhere).
    let keys = KeyPair::generate();
    let mut capsule = seal(&sample_input()).expect("seal");
    let capsule_id_before = capsule["capsule_id"].as_str().unwrap().to_string();
    attach_producer_envelope(&mut capsule, &keys.signing_key).expect("attach envelope");

    // capsule_id unchanged by the envelope.
    assert_eq!(capsule["capsule_id"].as_str().unwrap(), capsule_id_before);
    // key_id is the raw pubkey hex the door's announced-key registry expects.
    assert_eq!(
        capsule["key_id"].as_str().unwrap(),
        hex::encode(keys.signing_key.verifying_key().to_bytes())
    );

    // 2. Write ONLY the capsule JSON -- the pushed half, in isolation.
    let dir = tempfile::tempdir().unwrap();
    let capsule_path = dir.path().join("pushed-half.json");
    std::fs::write(
        &capsule_path,
        serde_json::to_vec(&capsule).expect("serialize"),
    )
    .unwrap();

    // 3. Run the door's EXACT verify path (verify_capsule_signature).
    let output = Command::new(&env.python)
        .arg(&env.door_verify_script)
        .arg(&capsule_path)
        .output()
        .expect("run door-verify oracle");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: Value =
        serde_json::from_str(stdout.lines().last().unwrap_or("")).unwrap_or_else(|_| {
            panic!(
                "oracle did not print JSON. stdout={stdout} stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });

    assert_eq!(
        result["verdict"], "authored",
        "door must grade the pushed half AUTHORED, not UNCLAIMED/INVALID: {result}"
    );
    assert_eq!(
        result["door_accepts"], true,
        "door must ACCEPT the pushed half in isolation (no signature_unverified): {result}"
    );
    assert!(
        output.status.success(),
        "oracle exit non-zero: {result} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
