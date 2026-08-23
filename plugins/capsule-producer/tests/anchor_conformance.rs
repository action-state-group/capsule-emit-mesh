//! Milestone 2 acceptance (anchor-client / inclusion slice): this crate's
//! `AnchorClient` must register a capsule digest against a REAL
//! `capsule-anchor` instance, resolve its durable inclusion proof, and that
//! proof must verify GREEN with `scitt_cose.verify_receipt` (the
//! independent Python COSE-Receipt verifier) -- completing the "inclusion"
//! leg of "verifies end-to-end (chain + inclusion + signature)". A tampered
//! receipt and a wrong authority key must both be REJECTED.
//!
//! Spins up `capsule-anchor` in its own documented insecure-ephemeral/
//! in-memory test mode (`CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1`,
//! `CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1` -- the same env vars
//! `capsule-anchor/packages/tests/conftest.py` sets for its own test suite)
//! as a real HTTP server via `uvicorn`, so this exercises the actual wire
//! protocol, not an in-process test client.
//!
//! `#[ignore]`d and gated on env vars:
//!
//!   AAC_PYTHON=python3 \
//!   AAC_VERIFY_ANCHOR_RECEIPT_SCRIPT=$PWD/tests/scripts/verify_anchor_receipt.py \
//!   CAPSULE_ANCHOR_DIR=/path/to/capsule-anchor/packages \
//!     cargo test --test anchor_conformance -- --ignored --nocapture --test-threads=1

use capsule_producer::anchor::AnchorClient;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Env {
    python: String,
    verify_script: PathBuf,
    anchor_dir: PathBuf,
}

fn env() -> Option<Env> {
    Some(Env {
        python: std::env::var("AAC_PYTHON").ok()?,
        verify_script: std::env::var("AAC_VERIFY_ANCHOR_RECEIPT_SCRIPT").ok()?.into(),
        anchor_dir: std::env::var("CAPSULE_ANCHOR_DIR").ok()?.into(),
    })
}

struct AnchorServer {
    child: Child,
    base_url: String,
}

impl AnchorServer {
    fn start(env: &Env, port: u16) -> Self {
        let base_url = format!("http://127.0.0.1:{port}");
        let child = Command::new(&env.python)
            .args([
                "-m",
                "uvicorn",
                "capsule_anchor.app:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--log-level",
                "warning",
            ])
            .current_dir(&env.anchor_dir)
            .env("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
            .env("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn capsule-anchor uvicorn server");

        let client = AnchorClient::new(base_url.clone());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if client.authority_pubkey().is_ok() {
                break;
            }
            if Instant::now() > deadline {
                panic!("capsule-anchor server did not become ready within 20s");
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        Self { child, base_url }
    }
}

impl Drop for AnchorServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_receipt_verifier(env: &Env, receipt_b64: &str, entry_hash: &str, pubkey_hex: &str) -> (bool, Value) {
    let output = Command::new(&env.python)
        .arg(&env.verify_script)
        .arg(receipt_b64)
        .arg(entry_hash)
        .arg(pubkey_hex)
        .output()
        .expect("run python anchor receipt verifier");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    eprintln!("anchor receipt verifier: {stdout}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("parse verifier JSON");
    (output.status.success(), parsed)
}

#[test]
#[ignore]
fn anchor_client_round_trip_verifies_inclusion_end_to_end() {
    let Some(env) = env() else {
        eprintln!(
            "AAC_PYTHON / AAC_VERIFY_ANCHOR_RECEIPT_SCRIPT / CAPSULE_ANCHOR_DIR not set; skipping (see module docs)"
        );
        return;
    };

    let server = AnchorServer::start(&env, 18173);
    let client = AnchorClient::new(server.base_url.clone());

    let capsule_id = "c".repeat(64);
    let authority = client.authority_pubkey().expect("fetch authority pubkey");

    // --- (a) register: POST /v1/digest.
    let receipt = client.post_digest(&capsule_id).expect("post digest");
    assert_eq!(receipt.tree_size, 1, "first registration in a fresh in-memory log");

    // --- (b) durable status: GET /v1/inclusion/{id} must now resolve.
    let inclusion = client
        .check_inclusion(&capsule_id)
        .expect("check inclusion")
        .expect("capsule_id must be durably included after post_digest");
    assert_eq!(inclusion.capsule_id, capsule_id);
    assert_eq!(inclusion.entry_hash, receipt.entry_hash);

    // A capsule_id never submitted must resolve to None -- not registered as
    // a side effect of checking.
    let never_submitted = "d".repeat(64);
    assert!(client
        .check_inclusion(&never_submitted)
        .expect("check inclusion (absent)")
        .is_none());

    // --- (c) the inclusion proof must verify GREEN against the independent
    //     Python scitt_cose.verify_receipt.
    let (ok, result) = run_receipt_verifier(
        &env,
        &inclusion.receipt_b64,
        &inclusion.entry_hash,
        &authority.pubkey_hex,
    );
    assert!(ok, "scitt_cose rejected a genuine inclusion receipt: {result}");
    assert_eq!(result["ok"], true, "{result}");

    // --- (d) mutation 1: a tampered receipt must be REJECTED.
    use base64::Engine as _;
    let mut receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&inclusion.receipt_b64)
        .expect("decode receipt_b64");
    let flip_at = receipt_bytes.len() - 3;
    receipt_bytes[flip_at] ^= 0x01;
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&receipt_bytes);
    let (tampered_ok, tampered_result) =
        run_receipt_verifier(&env, &tampered_b64, &inclusion.entry_hash, &authority.pubkey_hex);
    assert!(
        !tampered_ok,
        "scitt_cose ACCEPTED a tampered receipt: {tampered_result}"
    );

    // --- (e) mutation 2: the RIGHT receipt but the WRONG authority key must
    //     also be REJECTED.
    let wrong_key_hex = "0".repeat(64);
    let (wrong_key_ok, wrong_key_result) = run_receipt_verifier(
        &env,
        &inclusion.receipt_b64,
        &inclusion.entry_hash,
        &wrong_key_hex,
    );
    assert!(
        !wrong_key_ok,
        "scitt_cose ACCEPTED a receipt verified against the wrong authority key: {wrong_key_result}"
    );
}
