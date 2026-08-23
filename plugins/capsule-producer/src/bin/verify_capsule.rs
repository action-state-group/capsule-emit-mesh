//! Offline verification CLI (task item 5: "the x-mesh-poc-v1 field mapping +
//! offline verification command"). No network access -- verifies a single
//! capsule + COSE_Sign1 statement against a public key, optionally checking
//! chain-parent membership against a local ledger directory.
//!
//! Usage:
//!   verify_capsule <capsule.json> <statement.cose> <pubkey.pem> [ledger_dir]
//!
//! Prints one JSON line (same field names as
//! `tests/scripts/verify_rust_capsule.py`'s oracle output, so the two are
//! diffable) and exits 0 iff the capsule verifies.

use capsule_producer::keys::load_verifying_key_pem;
use capsule_producer::ledger::Ledger;
use capsule_producer::verify::verify_offline;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        eprintln!(
            "usage: {} <capsule.json> <statement.cose> <pubkey.pem> [ledger_dir]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let capsule_path = &args[1];
    let statement_path = &args[2];
    let pubkey_path = &args[3];
    let ledger_dir = args.get(4).map(PathBuf::from);

    let result = run(capsule_path, statement_path, pubkey_path, ledger_dir);
    let ok = result["ok"].as_bool().unwrap_or(false);
    println!("{}", serde_json::to_string(&result).unwrap());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(
    capsule_path: &str,
    statement_path: &str,
    pubkey_path: &str,
    ledger_dir: Option<PathBuf>,
) -> Value {
    let capsule_bytes = match std::fs::read(capsule_path) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": format!("read capsule: {e}")}),
    };
    let statement_bytes = match std::fs::read(statement_path) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": format!("read statement: {e}")}),
    };
    let pubkey_pem = match std::fs::read_to_string(pubkey_path) {
        Ok(s) => s,
        Err(e) => return json!({"ok": false, "error": format!("read pubkey: {e}")}),
    };

    let capsule: Value = match serde_json::from_slice(&capsule_bytes) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("parse capsule JSON: {e}")}),
    };
    let verifying_key = match load_verifying_key_pem(&pubkey_pem) {
        Ok(k) => k,
        Err(e) => return json!({"ok": false, "error": format!("load pubkey: {e}")}),
    };

    let known_ids: Option<HashSet<String>> = match &ledger_dir {
        Some(dir) => match Ledger::open(dir) {
            Ok((ledger, _report)) => Some(ledger.known_capsule_ids()),
            Err(e) => {
                return json!({"ok": false, "error": format!("open ledger: {e}")});
            }
        },
        None => None,
    };

    let report = verify_offline(
        &capsule,
        &statement_bytes,
        &verifying_key,
        known_ids.as_ref(),
    );

    json!({
        "ok": report.ok(),
        "capsule_id_ok": report.capsule_id_ok,
        "cose_ok": report.cose_ok,
        "payload_matches_capsule": report.payload_matches_capsule,
        "chain_ok": report.chain_ok,
        "capsule_id": report.capsule_id,
        "findings": report.findings,
        "error": Value::Null,
    })
}
