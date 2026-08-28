//! Deterministic demo producer: seal a small, realistic 3-capsule chain in Rust
//! and write it to a standard local ledger (`<OUT_DIR>/capsules.jsonl` +
//! `<OUT_DIR>/signed-statements/<capsule_id>.cose`), so the exact same ledger
//! shape the Python reference (`agent-action-capsule verify --store`) reads can
//! be produced cross-language and copied cross-host.
//!
//! Usage:
//!   cargo run --bin produce_demo_ledger -- [OUT_DIR]   (default ./demo-ledger)
//!
//! Determinism: the Ed25519 signing key is derived from a fixed seed (SHA-256
//! of a constant label) rather than `KeyPair::generate()`'s OS RNG, and every
//! capsule field (timestamps, digests, nonces) is a fixed constant. Because
//! COSE_Sign1 here is Ed25519 (deterministic per RFC 8032) over a deterministic
//! payload, re-running the producer to a fresh directory yields byte-identical
//! `capsules.jsonl` and `.cose` files. This mirrors how the conformance tests
//! pin inputs, but replaces the fresh random key with a seed-derived one so the
//! bytes are reproducible across runs and hosts.
//!
//! The three capsules read as a realistic run chained via
//! `chain.parent_capsule_id`:
//!   1. `write_order`  — a proposed order-write action (chain head)
//!   2. `check_policy` — the policy check that follows it
//!   3. `confirm`      — the confirmation that follows the check

use capsule_producer::capsule::{payload_bytes, seal, CapsuleInput, ChainLink, MeshPocV1};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys::KeyPair;
use capsule_producer::ledger::Ledger;
use ed25519_dalek::SigningKey;
use serde_json::{json, Map};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::ExitCode;

/// Fixed label whose SHA-256 is the 32-byte Ed25519 seed. A constant seed (not
/// OS randomness) is what makes re-runs byte-identical.
const KEY_SEED_LABEL: &str = "capsule-emit-mesh/demo3-producer/deterministic-key/v1";

/// Content type carried in the COSE_Sign1 protected header — the same value the
/// conformance test uses, so the Python verifier reads the profile it expects.
const CONTENT_TYPE: &str =
    "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02";

const ISSUER: &str = "capsule-emit-mesh-demo3-rust";

/// One step in the demo chain: a human-readable step name plus the fixed
/// per-step field values. Kept deterministic on purpose.
struct Step {
    name: &'static str,
    action_type: &'static str,
    timestamp: &'static str,
    nonce_char: char,
    effect_type: &'static str,
    disposition_decision: &'static str,
    disposition_verdict_class: &'static str,
}

fn demo_steps() -> [Step; 3] {
    [
        // action_type MUST be 'fyi' or 'decide' (§5.1) — the human-readable
        // step name lives in `action_id`, not `action_type`.
        Step {
            name: "write_order",
            action_type: "decide",
            timestamp: "2026-08-28T00:00:01Z",
            nonce_char: '1',
            effect_type: "order_write",
            disposition_decision: "accept",
            disposition_verdict_class: "executed",
        },
        Step {
            name: "check_policy",
            action_type: "decide",
            timestamp: "2026-08-28T00:00:02Z",
            nonce_char: '2',
            effect_type: "policy_check",
            disposition_decision: "accept",
            disposition_verdict_class: "executed",
        },
        Step {
            name: "confirm",
            action_type: "decide",
            timestamp: "2026-08-28T00:00:03Z",
            nonce_char: '3',
            effect_type: "order_confirmation",
            disposition_decision: "accept",
            disposition_verdict_class: "executed",
        },
    ]
}

/// Build the fixed `CapsuleInput` for one demo step. All digest/nonce fields are
/// deterministic constants so the sealed capsule is reproducible.
fn step_input(step: &Step, chain: Option<ChainLink>) -> CapsuleInput {
    let mut generation_parameters = Map::new();
    generation_parameters.insert("temperature".into(), json!("0.7"));
    CapsuleInput {
        action_id: format!("mesh-poc/demo3/{}", step.name),
        action_type: step.action_type.to_string(),
        operator: "capsule-emit-mesh-demo3".to_string(),
        developer: "capsule-producer/0.2.0".to_string(),
        timestamp: step.timestamp.to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "hermes-2-pro-mistral-7b".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: "a".repeat(64),
        agent_output_digest: "b".repeat(64),
        runtime: "0".repeat(64) + ":rust-demo3",
        mesh_poc: MeshPocV1 {
            client_nonce: step.nonce_char.to_string().repeat(32),
            client_nonce_source: "client_supplied".to_string(),
            model_package_digest: "d".repeat(64),
            generation_parameters,
            latency_ms: "42.0".to_string(),
        },
        effect_status: "confirmed".to_string(),
        effect_type: step.effect_type.to_string(),
        effect_request_digest: "a".repeat(64),
        effect_response_digest: "b".repeat(64),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: step.disposition_decision.to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: step.disposition_verdict_class.to_string(),
        chain,
    }
}

/// Derive a fixed Ed25519 signing key from a constant seed, so the demo is
/// reproducible. Uses the `KeyPair.signing_key` public field rather than
/// `KeyPair::generate()` (which pulls from the OS RNG).
fn deterministic_keypair() -> KeyPair {
    let seed: [u8; 32] = Sha256::digest(KEY_SEED_LABEL.as_bytes()).into();
    KeyPair {
        signing_key: SigningKey::from_bytes(&seed),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 {
        eprintln!("usage: {} [OUT_DIR]", args[0]);
        return ExitCode::from(2);
    }
    let out_dir = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("./demo-ledger"));

    match run(&out_dir) {
        Ok(capsule_ids) => {
            println!("wrote demo ledger to: {}", out_dir.display());
            println!("  capsules.jsonl + signed-statements/<capsule_id>.cose");
            println!("sealed {} capsules (chain head -> tail):", capsule_ids.len());
            for (i, id) in capsule_ids.iter().enumerate() {
                println!("  [{i}] {id}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(out_dir: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let keys = deterministic_keypair();

    // Write the public key beside the ledger so a verifier that wants the
    // signing key (e.g. the Rust offline verifier) can find it. The Python
    // `verify --store` recovers per-statement keys from the COSE structure
    // itself and does not need this file, but it is cheap and useful.
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("node-key.pub.pem"), keys.public_key_pem())?;

    let (mut ledger, _report) = Ledger::open(out_dir)?;
    let mut capsule_ids: Vec<String> = Vec::new();
    let mut parent: Option<String> = None;

    for step in demo_steps() {
        let chain = parent.as_ref().map(|p| ChainLink {
            parent_capsule_id: p.clone(),
            relation: "follows".to_string(),
        });
        let input = step_input(&step, chain);
        let capsule = seal(&input)?;
        let capsule_id = capsule["capsule_id"]
            .as_str()
            .expect("sealed capsule always has a string capsule_id")
            .to_string();
        let payload = payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: ISSUER,
                subject: &capsule_id,
                content_type: CONTENT_TYPE,
            },
            &keys.signing_key,
        );
        ledger.append(&capsule, &statement)?;
        parent = Some(capsule_id.clone());
        capsule_ids.push(capsule_id);
    }

    Ok(capsule_ids)
}
