//! Integration test for the
//! `backfill_received_citing_records` CLI: given a ledger in the OLD shape
//! (received foreign bodies folded INLINE into `capsules.jsonl`, plus a
//! `received-provenance.jsonl`), a single migration run moves each foreign
//! body to the held-artifact store, rewrites `capsules.jsonl` local-only, and
//! seals one chained, `.cose`-signed, `provenance_mode: backfilled` citing
//! record per received half. A second run is a no-op (idempotent).
//!
//! Shells out to the COMPILED BINARY (not the library) so this exercises the
//! real CLI wiring -- arg parsing, file I/O, the same seal path the live
//! record-push responder uses.

use capsule_producer::capsule::{
    seal, CapsuleInput, ChainLink, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_backfill_received_citing_records")
}

fn local_input(seed: &str, chain: Option<ChainLink>) -> CapsuleInput {
    let mut gp = serde_json::Map::new();
    gp.insert("temperature".into(), json!("0.7"));
    CapsuleInput {
        action_id: format!("local/{seed}"),
        action_type: "decide".to_string(),
        operator: "op".to_string(),
        developer: "dev".to_string(),
        timestamp: "2026-09-25T00:00:00Z".to_string(),
        domain: Some("action".to_string()),
        provenance: Some("collector".to_string()),
        model_id: "m".to_string(),
        provider: "mesh-llm".to_string(),
        agent_input_digest: "1".repeat(64),
        agent_output_digest: Some("2".repeat(64)),
        tool_calls_digest: None,
        reasoning_digest: None,
        host_binding: None,
        runtime: json!({"name": "runtime"}),
        mesh_poc: MeshPocV1 {
            client_nonce: "n".repeat(32),
            client_nonce_source: "client_supplied".to_string(),
            model_name_digest: "d".repeat(64),
            serving_provenance: ServingProvenance {
                served_by_node_id: "self-node".to_string(),
                dispatch_path: None,
                requesting_party: "party".to_string(),
                exchange_id: "e-local".to_string(),
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
                usage: Some(TokenUsage { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }),
                seq: 1,
                prev_seq: None,
                peer_capsule_id: None,
                peer_capsule_id_provenance: None,
                twin_bracket_id: None,
            },
            role: "served".to_string(),
            observation_point: None,
            generation_parameters: gp,
            latency_ms: "1.0".to_string(),
            binary_attestation: None,
            tee_attestation: None,
        },
        effect_status: "confirmed".to_string(),
        effect_type: "inference_completion".to_string(),
        effect_request_digest: Some("1".repeat(64)),
        effect_response_digest: Some("2".repeat(64)),
        effect_attestation: "gate_executed".to_string(),
        disposition_decision: "accept".to_string(),
        disposition_approver: "policy".to_string(),
        disposition_human_disposed: false,
        disposition_verdict_class: "executed".to_string(),
        chain,
    }
}

/// A "foreign" capsule as it would look folded inline in the OLD shape: a valid
/// self-consistent capsule carrying the PEER's own chain parent (not ours) and
/// its own agent digests -- exactly what the pre-ruling door appended raw.
fn foreign_body(seed: &str) -> Value {
    // Reuse local_input's shape but give it a peer chain parent + peer digests,
    // then seal it standalone-ish. We seal with NO chain here (a peer's first
    // half), which is enough: the point is it is NOT one of our chained lines.
    let mut input = local_input(seed, None);
    input.agent_input_digest = "a".repeat(64);
    input.agent_output_digest = Some("b".repeat(64));
    input.effect_request_digest = Some("a".repeat(64));
    input.effect_response_digest = Some("b".repeat(64));
    input.mesh_poc.serving_provenance.served_by_node_id = "peer-node".to_string();
    input.mesh_poc.serving_provenance.exchange_id = "e-foreign".to_string();
    seal(&input).unwrap()
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn backfill_migrates_old_shape_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();
    let ledger_dir = data_dir.join("ledger");
    let statements_dir = ledger_dir.join("signed-statements");
    std::fs::create_dir_all(&statements_dir).unwrap();
    let keys = keys::load_or_create(&data_dir.join("keys")).unwrap();

    // One LOCAL record, chained + .cose (a well-formed head).
    let local = seal(&local_input("head", None)).unwrap();
    let mut local = local;
    capsule_producer::capsule::attach_producer_envelope(&mut local, &keys.signing_key).unwrap();
    let local_id = local["capsule_id"].as_str().unwrap().to_string();
    let local_stmt = build_signed_statement(
        &SignedStatementInput {
            payload: &capsule_producer::capsule::payload_bytes(&local),
            issuer: "admission-policy",
            subject: &local_id,
            content_type: "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02",
        },
        &keys.signing_key,
    );
    std::fs::write(statements_dir.join(format!("{local_id}.cose")), &local_stmt).unwrap();

    // One FOREIGN body folded INLINE (the OLD shape) -- no .cose of ours, a
    // peer chain lineage, and a received-provenance line naming its sender.
    let foreign = foreign_body("peer");
    let foreign_id = foreign["capsule_id"].as_str().unwrap().to_string();

    let capsules_path = ledger_dir.join("capsules.jsonl");
    {
        let mut fh = std::fs::File::create(&capsules_path).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&local).unwrap()).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&foreign).unwrap()).unwrap();
    }
    std::fs::write(
        ledger_dir.join("received-provenance.jsonl"),
        format!(
            "{}\n",
            json!({
                "capsule_id": foreign_id,
                "received_from": "m4",
                "via": "push",
                "received_at": "2026-09-24T12:00:00Z",
                "signature_ok": true,
            })
        ),
    )
    .unwrap();

    // ---- Run 1: the migration.
    let out = Command::new(cli()).arg(data_dir).output().unwrap();
    assert!(out.status.success(), "backfill failed: {}", String::from_utf8_lossy(&out.stderr));

    // Foreign body moved to the held-artifact store.
    let artifacts = read_jsonl(&ledger_dir.join("received-capsules.jsonl"));
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["capsule_id"], json!(foreign_id));

    // capsules.jsonl is LOCAL-ONLY + exactly ONE citing record.
    let capsules = read_jsonl(&capsules_path);
    assert_eq!(capsules.len(), 2, "the local head + one citing record");
    assert_eq!(capsules[0]["capsule_id"], json!(local_id));
    let citing = &capsules[1];
    // Chained onto the local head with the bare "follows" relation -- the
    // citation is the references[] entry, never a relation value.
    assert_eq!(citing["chain"]["parent_capsule_id"], json!(local_id));
    assert_eq!(citing["chain"]["relation"], json!("follows"));
    // Cites the foreign half by CPB typed digest, counterparty_half.
    assert_eq!(citing["references"][0]["digest"], json!(foreign_id));
    assert_eq!(citing["references"][0]["citation_purpose"], json!("counterparty_half"));
    // provenance_mode: backfilled, source_asserted_at = the real received_at.
    assert_eq!(citing["provenance_mode"]["mode"], json!("backfilled"));
    assert_eq!(citing["provenance_mode"]["source_asserted_at"], json!("2026-09-24T12:00:00Z"));
    assert!(citing["provenance_mode"]["imported_at"].is_string());
    // Its capsule_id recomputes (provenance_mode committed) + .cose written.
    let citing_id = citing["capsule_id"].as_str().unwrap();
    assert_eq!(citing_id, capsule_producer::jcs::compute_capsule_id(citing).unwrap());
    assert!(statements_dir.join(format!("{citing_id}.cose")).is_file());
    // received_from rides on the citing record.
    assert_eq!(
        citing["model_attestation"]["compute_attestation"]["received_half"]["received_from"],
        json!("m4")
    );

    // The now-clean local-only ledger reopens without error (chain intact).
    let (ledger, report) = capsule_producer::ledger::Ledger::open(&ledger_dir).unwrap();
    assert_eq!(report.valid_entries, 2);
    assert_eq!(ledger.chain_head(), Some(citing_id));

    // ---- Run 2: idempotent -- no new artifact, no new citing record.
    let out2 = Command::new(cli()).arg(data_dir).output().unwrap();
    assert!(out2.status.success());
    assert_eq!(read_jsonl(&ledger_dir.join("received-capsules.jsonl")).len(), 1);
    assert_eq!(read_jsonl(&capsules_path).len(), 2, "no second citing record on re-run");
}

/// Idempotency ACROSS the relation rename: a ledger
/// already carrying a LEGACY citing record (`chain.relation: "cites"`, sealed
/// before the ruling renamed the relation to `"follows"`) for a received half
/// must NOT get a second citing record on a backfill run -- the
/// `already_cited` matcher keys on `references[].citation_purpose ==
/// "counterparty_half"` + the cited digest ALONE, never on the relation
/// string, so legacy `cites` records and new `follows` records are the SAME
/// citation.
#[test]
fn legacy_cites_relation_citing_record_still_counts_as_already_cited() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();
    let ledger_dir = data_dir.join("ledger");
    let statements_dir = ledger_dir.join("signed-statements");
    std::fs::create_dir_all(&statements_dir).unwrap();
    let keys = keys::load_or_create(&data_dir.join("keys")).unwrap();

    let content_type =
        "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02";
    let write_cose = |capsule: &Value| {
        let id = capsule["capsule_id"].as_str().unwrap();
        let stmt = build_signed_statement(
            &SignedStatementInput {
                payload: &capsule_producer::capsule::payload_bytes(capsule),
                issuer: "admission-policy",
                subject: id,
                content_type,
            },
            &keys.signing_key,
        );
        std::fs::write(statements_dir.join(format!("{id}.cose")), &stmt).unwrap();
    };

    // A local head.
    let mut local = seal(&local_input("head", None)).unwrap();
    capsule_producer::capsule::attach_producer_envelope(&mut local, &keys.signing_key).unwrap();
    let local_id = local["capsule_id"].as_str().unwrap().to_string();
    write_cose(&local);

    // The received half: already migrated to the held-artifact store, with a
    // provenance line -- i.e. a POST-migration ledger, except its citing
    // record was sealed by the PRE-ruling code (`relation: "cites"`).
    let foreign = foreign_body("peer");
    let foreign_id = foreign["capsule_id"].as_str().unwrap().to_string();
    std::fs::write(
        ledger_dir.join("received-capsules.jsonl"),
        format!("{}\n", serde_json::to_string(&foreign).unwrap()),
    )
    .unwrap();
    std::fs::write(
        ledger_dir.join("received-provenance.jsonl"),
        format!(
            "{}\n",
            json!({
                "capsule_id": foreign_id,
                "received_from": "m4",
                "via": "push",
                "received_at": "2026-09-24T12:00:00Z",
                "signature_ok": true,
            })
        ),
    )
    .unwrap();

    // The LEGACY citing record, exactly as the pre-ruling seal path built it:
    // chained onto the head with `relation: "cites"`, the counterparty_half
    // reference committed into its capsule_id.
    let mut legacy = serde_json::Map::new();
    legacy.insert("spec_version".into(), json!("draft-mih-scitt-agent-action-capsule-02"));
    legacy.insert("format_version".into(), json!("4"));
    legacy.insert("canonicalization_id".into(), json!("jcs"));
    legacy.insert(
        "action_id".into(),
        json!(format!("mesh-poc/received-half-citation/{foreign_id}")),
    );
    legacy.insert(
        "chain".into(),
        json!({"parent_capsule_id": local_id, "relation": "cites"}),
    );
    legacy.insert(
        "references".into(),
        json!([{
            "type": "capsule",
            "digest_alg": "SHA-256",
            "digest": foreign_id,
            "citation_purpose": "counterparty_half",
        }]),
    );
    let legacy_id =
        capsule_producer::jcs::compute_capsule_id(&Value::Object(legacy.clone())).unwrap();
    legacy.insert("capsule_id".into(), json!(legacy_id));
    let mut legacy = Value::Object(legacy);
    capsule_producer::capsule::attach_producer_envelope(&mut legacy, &keys.signing_key).unwrap();
    write_cose(&legacy);

    let capsules_path = ledger_dir.join("capsules.jsonl");
    {
        let mut fh = std::fs::File::create(&capsules_path).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&local).unwrap()).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&legacy).unwrap()).unwrap();
    }
    let chain_bytes_before = std::fs::read(&capsules_path).unwrap();

    // The backfill run must treat the legacy `cites` record as the citation
    // it is -- sealing NOTHING new, leaving the chain byte-for-byte intact.
    let out = Command::new(cli()).arg(data_dir).output().unwrap();
    assert!(out.status.success(), "backfill failed: {}", String::from_utf8_lossy(&out.stderr));
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(report.contains("0 citing records sealed"), "must seal nothing: {report}");
    assert_eq!(
        std::fs::read(&capsules_path).unwrap(),
        chain_bytes_before,
        "a legacy relation:cites citing record already cites this half -- no second record"
    );
}

/// The live run-5 incident shape:
/// the checkpoint cadence had ALREADY built a durable node store + emitted a
/// checkpoint over the OLD (foreign-bodies-inline) chain before the backfill
/// ran. The backfill must complete the migration at the commitment layer --
/// rebuild `mmr_nodes.dat` from the post-migration leaves and archive the
/// superseded `checkpoints.jsonl` (never delete it) -- so the next cadence
/// load passes the divergence guard and emits a checkpoint whose root
/// commits to the CURRENT chain. A re-run touches neither.
#[test]
fn backfill_rebuilds_mmr_and_archives_stale_checkpoints() {
    use capsule_producer::anchor::AnchorClient;
    use capsule_producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
    use cll::mmr::{add_leaf, leaf_hash, peaks, root_from_peaks, MemoryNodeStore, NodeReader};

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();
    let ledger_dir = data_dir.join("ledger");
    let statements_dir = ledger_dir.join("signed-statements");
    std::fs::create_dir_all(&statements_dir).unwrap();
    let keys = keys::load_or_create(&data_dir.join("keys")).unwrap();

    // OLD-shape chain: one local head + one foreign body folded inline.
    let mut local = seal(&local_input("head", None)).unwrap();
    capsule_producer::capsule::attach_producer_envelope(&mut local, &keys.signing_key).unwrap();
    let local_id = local["capsule_id"].as_str().unwrap().to_string();
    let local_stmt = build_signed_statement(
        &SignedStatementInput {
            payload: &capsule_producer::capsule::payload_bytes(&local),
            issuer: "admission-policy",
            subject: &local_id,
            content_type: "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02",
        },
        &keys.signing_key,
    );
    std::fs::write(statements_dir.join(format!("{local_id}.cose")), &local_stmt).unwrap();
    let foreign = foreign_body("peer");
    let foreign_id = foreign["capsule_id"].as_str().unwrap().to_string();
    let capsules_path = ledger_dir.join("capsules.jsonl");
    {
        let mut fh = std::fs::File::create(&capsules_path).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&local).unwrap()).unwrap();
        writeln!(fh, "{}", serde_json::to_string(&foreign).unwrap()).unwrap();
    }
    std::fs::write(
        ledger_dir.join("received-provenance.jsonl"),
        format!(
            "{}\n",
            json!({
                "capsule_id": foreign_id,
                "received_from": "m4",
                "via": "push",
                "received_at": "2026-09-24T12:00:00Z",
                "signature_ok": true,
            })
        ),
    )
    .unwrap();

    // The PRE-migration cadence run: builds mmr_nodes.dat over the old
    // leaves and emits a checkpoint committing to them -- exactly the state
    // the live ledger was in when the backfill first ran.
    let anchor = AnchorClient::new("http://127.0.0.1:1");
    {
        let (mut state, _) =
            CheckpointState::load(&ledger_dir, "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        state
            .reconnect(&keys.signing_key, &anchor)
            .unwrap()
            .expect("pre-migration checkpoint must be emitted");
    }
    let checkpoints_path = ledger_dir.join("checkpoints.jsonl");
    let pre_checkpoint_bytes = std::fs::read(&checkpoints_path).unwrap();

    // ---- Run 1: the migration must rebuild the node store + archive the
    // stale checkpoint, and SAY so in its report line.
    let out = Command::new(cli()).arg(data_dir).output().unwrap();
    assert!(out.status.success(), "backfill failed: {}", String::from_utf8_lossy(&out.stderr));
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(report.contains("REBUILT"), "report must name the MMR rebuild: {report}");
    assert!(report.contains("ARCHIVED 1 pre-migration checkpoint line(s)"), "report must name the archive: {report}");

    // The stale checkpoint is preserved byte-for-byte beside the ledger,
    // and checkpoints.jsonl is gone (fresh file starts on the next tick).
    let archive_path = ledger_dir.join("checkpoints.pre-backfill.jsonl");
    assert!(archive_path.is_file(), "pre-migration checkpoints must be archived, never deleted");
    assert_eq!(std::fs::read(&archive_path).unwrap(), pre_checkpoint_bytes);
    assert!(!checkpoints_path.exists());

    // The cadence now loads cleanly (the divergence guard passes: the store
    // was rebuilt) and its next checkpoint commits to the POST-migration
    // leaves -- verified against an independently built MMR.
    let capsules = read_jsonl(&capsules_path);
    assert_eq!(capsules.len(), 2, "local head + citing record");
    let citing_id = capsules[1]["capsule_id"].as_str().unwrap().to_string();
    let cp = {
        let (mut state, _) =
            CheckpointState::load(&ledger_dir, "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        assert_eq!(state.leaf_count(), 2);
        state
            .reconnect(&keys.signing_key, &anchor)
            .unwrap()
            .expect("fresh checkpoint over the post-migration chain")
    };
    let mut mem = MemoryNodeStore::new();
    for id in [&local_id, &citing_id] {
        let digest: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        add_leaf(&mut mem, leaf_hash(&digest)).unwrap();
    }
    let expected_root = hex::encode(root_from_peaks(
        &peaks(mem.size()).unwrap().iter().map(|&p| mem.node(p)).collect::<Vec<_>>(),
    ));
    assert_eq!(cp.root, expected_root, "checkpoint must commit to the post-migration leaves");

    // ---- Run 2: idempotent, INCLUDING the commitment layer -- the rebuilt
    // store is untouched, the fresh (valid) checkpoints.jsonl is kept, no
    // second archive appears.
    let mmr_bytes_before = std::fs::read(ledger_dir.join("mmr_nodes.dat")).unwrap();
    let out2 = Command::new(cli()).arg(data_dir).output().unwrap();
    assert!(out2.status.success());
    let report2 = String::from_utf8_lossy(&out2.stdout);
    assert!(report2.contains("consistent with the post-migration chain"), "re-run must not rebuild: {report2}");
    assert!(report2.contains("still commits to the post-migration chain -- kept"), "re-run must keep the fresh checkpoint: {report2}");
    assert_eq!(std::fs::read(ledger_dir.join("mmr_nodes.dat")).unwrap(), mmr_bytes_before);
    assert!(checkpoints_path.is_file(), "the fresh checkpoints.jsonl must survive a re-run");
    assert_eq!(std::fs::read(&archive_path).unwrap(), pre_checkpoint_bytes, "the archive is never touched again");
    let archives: Vec<_> = std::fs::read_dir(&ledger_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("checkpoints.pre-backfill"))
        .collect();
    assert_eq!(archives.len(), 1, "no second archive on a no-op re-run: {archives:?}");
}
