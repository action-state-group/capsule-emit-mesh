//! Idempotent BACKFILL: migrate a
//! ledger from the OLD shape (received foreign bodies folded INLINE into
//! `capsules.jsonl` by the pre-ruling Python door) to the ruling's shape --
//! foreign bodies in the held-artifact store `received-capsules.jsonl`, and a
//! LOCAL CITING record (ours, chained, `.cose`-signed) per received half.
//!
//! **The manager runs this on a live ledger; a coder EXPOSES it.** It uses the
//! SAME `capsule_producer::capsule::seal_citing_record` path the live
//! record-push responder uses -- ONE citing-record implementation, ONE writer
//! per chain (this binary runs with the plugin DOWN; it is the only writer for
//! the duration of the migration).
//!
//! Usage:
//!   backfill_received_citing_records <DATA_DIR>
//!
//! where `<DATA_DIR>` is the plugin's data dir (the one `admission-policy`'s
//! `CapsuleState::open` was given): it must contain `keys/` (this node's
//! signing key) and `ledger/` (`capsules.jsonl` + `received-provenance.jsonl`).
//!
//! What it does, in order:
//!   1. Reads `ledger/received-provenance.jsonl` -> the set of `capsule_id`s
//!      the door recorded as verified received halves (the honest, door-
//!      established discriminator of which inline bodies are FOREIGN).
//!   2. Reads `ledger/capsules.jsonl` raw (never `Ledger::open`, which would
//!      reject the old shape: an inline foreign body carries the PEER's chain
//!      parent, not ours -> `ChainBroken`). Partitions each line into LOCAL
//!      (not in the received set) vs FOREIGN (in it).
//!   3. Appends each foreign body to `received-capsules.jsonl` (idempotent: a
//!      body already present by `capsule_id` is not duplicated).
//!   4. Rewrites `capsules.jsonl` to LOCAL-ONLY (the foreign bodies removed).
//!   5. `Ledger::open`s the now-clean local-only ledger and, for each foreign
//!      half that does NOT already have a citing record, seals ONE citing
//!      record via `seal_citing_record`, chained onto the current head, its
//!      `.cose` written, then advances the head. `provenance_mode.mode =
//!      "backfilled"` (AAC-05 §5.4.3) is stamped so a reader can tell a
//!      backfilled citing record from a live one; `received_at` comes from the
//!      provenance line, `imported_at`/`sealed_at = now`. NO other synthesized
//!      timestamps; no hand-editing of chained lines.
//!   6. Completes the migration at
//!      the COMMITMENT layer: if a durable MMR node store (`mmr_nodes.dat`,
//!      written by the plugin's checkpoint cadence) exists and its stored
//!      nodes are NOT a prefix of the MMR over the post-migration
//!      `capsules.jsonl`, it is rebuilt from the new leaf sequence. Without
//!      this, the count-based cadence sync would see "nothing new" on reload
//!      and the next tick would emit a checkpoint whose root commits to the
//!      PRE-migration leaves -- a silently wrong commitment (and, since the
//!      cadence now carries a divergence guard, a hard error at plugin load).
//!   7. Handles `checkpoints.jsonl` honestly: if its LAST checkpoint no
//!      longer commits to the post-migration chain (its root at its recorded
//!      size does not recompute over the new leaves), the whole file is
//!      ARCHIVED beside itself as `checkpoints.pre-backfill.jsonl` (never
//!      deleted) so the next cadence tick starts a fresh `checkpoints.jsonl`
//!      covering every post-migration leaf. A checkpoint that still verifies
//!      (e.g. one emitted after a completed migration) is kept.
//!
//! Idempotency: a second run finds no inline foreign bodies (step 2 leaves
//! none), every foreign half already cited (step 5 skips), a node store
//! consistent with the chain (step 6 skips), and either no
//! `checkpoints.jsonl` or one that verifies (step 7 skips), so it writes
//! nothing new.

use capsule_producer::capsule::{payload_bytes, ReceivedHalfProvenance};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys;
use capsule_producer::ledger::Ledger;
use capsule_producer::timestamp::utc_now_iso8601;
use cll::checkpoint::CheckpointRecord;
use cll::mmr::{add_leaf, leaf_hash, peaks, root_from_peaks, Hash, MemoryNodeStore, NodeReader};
use cll::node_store::FileNodeStore;
use cll::store::read_last_checkpoint;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CAPSULE_CONTENT_TYPE: &str =
    "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02";
/// The plugin's own ledger issuer (`admission-policy`'s `PLUGIN_ID`) -- the
/// same value `CapsuleState::open(&data_dir, PLUGIN_ID)` uses, so a backfilled
/// citing record's detached statement carries the same issuer a live one does.
const ISSUER: &str = "admission-policy";

fn read_jsonl(path: &Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// The `capsule_id`s the door recorded as verified received halves
/// (`received-provenance.jsonl`, `received_from` non-empty + `signature_ok:
/// true`), each mapped to its provenance triple. This is the honest signal for
/// which inline bodies are FOREIGN -- never a guess from the body's own shape.
fn received_provenance(ledger_dir: &Path) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    for entry in read_jsonl(&ledger_dir.join("received-provenance.jsonl")) {
        let Some(id) = entry.get("capsule_id").and_then(Value::as_str) else {
            continue;
        };
        let received_from_ok = entry
            .get("received_from")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let sig_ok = entry.get("signature_ok").and_then(Value::as_bool) == Some(true);
        if received_from_ok && sig_ok {
            map.insert(id.to_string(), entry);
        }
    }
    map
}

fn capsule_id_of(capsule: &Value) -> Option<&str> {
    capsule.get("capsule_id").and_then(Value::as_str)
}

fn compute_attestation_digest<'a>(capsule: &'a Value, field: &str) -> Option<&'a str> {
    capsule
        .pointer("/model_attestation/compute_attestation")
        .and_then(|ca| ca.get(field))
        .and_then(Value::as_str)
}

/// The set of foreign `capsule_id`s a ledger ALREADY cites -- so a re-run does
/// not seal a second citing record for a half already backfilled. A citing
/// record is identified by `references[].citation_purpose ==
/// "counterparty_half"` ALONE (the record KIND is
/// the citation purpose, NEVER a `chain.relation` match -- so legacy
/// `relation: "cites"` records and post-ruling `relation: "follows"` records
/// count as the SAME citation, keeping re-runs idempotent across the rename);
/// the cited id is the reference's `digest`.
fn already_cited(local_records: &[Value]) -> HashSet<String> {
    let mut set = HashSet::new();
    for record in local_records {
        if let Some(references) = record.get("references").and_then(Value::as_array) {
            for reference in references {
                if reference.get("citation_purpose").and_then(Value::as_str)
                    == Some("counterparty_half")
                {
                    if let Some(digest) = reference.get("digest").and_then(Value::as_str) {
                        set.insert(digest.to_string());
                    }
                }
            }
        }
    }
    set
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <DATA_DIR>", args[0]);
        eprintln!("  <DATA_DIR> must contain keys/ and ledger/ (capsules.jsonl + received-provenance.jsonl)");
        return ExitCode::from(2);
    }
    let data_dir = PathBuf::from(&args[1]);
    match run(&data_dir) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(data_dir: &Path) -> anyhow::Result<String> {
    let ledger_dir = data_dir.join("ledger");
    let keys_dir = data_dir.join("keys");
    let capsules_path = ledger_dir.join("capsules.jsonl");
    let received_capsules_path = ledger_dir.join("received-capsules.jsonl");

    let keys = keys::load_or_create(&keys_dir)?;
    let provenance = received_provenance(&ledger_dir);

    // Step 2: partition the raw capsules.jsonl into LOCAL vs FOREIGN by the
    // door-recorded received set. Read raw (never Ledger::open -- an inline
    // foreign body's chain parent is the peer's, which would ChainBreak).
    let all_lines = read_jsonl(&capsules_path);
    let mut local_lines: Vec<Value> = Vec::new();
    let mut foreign_bodies: Vec<Value> = Vec::new();
    for line in all_lines {
        match capsule_id_of(&line) {
            Some(id) if provenance.contains_key(id) => foreign_bodies.push(line),
            _ => local_lines.push(line),
        }
    }

    // Step 3: move each foreign body into the held-artifact store (idempotent:
    // skip a capsule_id already stored there).
    let mut artifact_ids: HashSet<String> = read_jsonl(&received_capsules_path)
        .iter()
        .filter_map(|c| capsule_id_of(c).map(str::to_string))
        .collect();
    let mut newly_stored = 0usize;
    {
        use std::io::Write;
        let mut fh = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&received_capsules_path)?;
        for body in &foreign_bodies {
            if let Some(id) = capsule_id_of(body) {
                if artifact_ids.insert(id.to_string()) {
                    writeln!(fh, "{}", serde_json::to_string(body)?)?;
                    newly_stored += 1;
                }
            }
        }
    }

    // Step 4: rewrite capsules.jsonl LOCAL-ONLY. Only when we actually removed
    // something (a re-run with no inline foreign bodies leaves the file
    // untouched -- no needless rewrite of chained lines).
    if !foreign_bodies.is_empty() {
        let mut out = String::new();
        for line in &local_lines {
            out.push_str(&serde_json::to_string(line)?);
            out.push('\n');
        }
        std::fs::write(&capsules_path, out)?;
    }

    // Step 5: seal one citing record per received half that is not already
    // cited, chained onto the now-clean local-only head via the SAME seal path.
    let cited = already_cited(&local_lines);
    let (mut ledger, _report) = Ledger::open(&ledger_dir)?;
    let imported_at = utc_now_iso8601();
    let mut sealed = 0usize;

    // Deterministic order: by the foreign body's capsule_id, so a resumed
    // partial run produces the same chain order. On a FRESH migration we cite
    // the bodies we just moved inline; on a RESUMED run (nothing left inline)
    // we cite from the artifact store, skipping any already cited above.
    let all_received: Vec<Value> = if foreign_bodies.is_empty() {
        read_jsonl(&received_capsules_path)
    } else {
        foreign_bodies.clone()
    };
    let mut ordered: Vec<&Value> = all_received
        .iter()
        .filter(|b| capsule_id_of(b).is_some_and(|id| provenance.contains_key(id)))
        .collect();
    ordered.sort_by_key(|b| capsule_id_of(b).unwrap_or("").to_string());

    for body in ordered {
        let Some(foreign_id) = capsule_id_of(body) else {
            continue;
        };
        if cited.contains(foreign_id) {
            continue; // idempotent: already backfilled
        }
        let prov_line = &provenance[foreign_id];
        let received_from = prov_line
            .get("received_from")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let received_at = prov_line
            .get("received_at")
            .and_then(Value::as_str)
            .unwrap_or(&imported_at);

        let prov = ReceivedHalfProvenance {
            foreign_capsule_id: foreign_id,
            received_from,
            via: "push",
            received_at,
            signature_ok: true,
            // Backfill does not pair against a local half here -- the pane
            // recomputes the authoritative digest_match. Honest absent.
            digest_match: None,
            foreign_agent_input_digest: compute_attestation_digest(body, "agent_input_digest"),
            foreign_agent_output_digest: compute_attestation_digest(body, "agent_output_digest"),
        };
        let mut capsule = capsule_producer::capsule::seal_citing_record(
            &prov,
            ledger.chain_head(),
            &keys.signing_key,
        )?;
        // Stamp provenance_mode = backfilled (AAC-05 §5.4.3) so a reader can
        // distinguish a backfilled citing record from a live one. Added BEFORE
        // computing the id is impossible (seal_citing_record owns the id), so
        // it rides as compute_attestation additive metadata alongside the
        // receiving facts -- it is part of the sealed body, committed to the
        // capsule_id, because we recompute below.
        stamp_backfilled(&mut capsule, received_at, &imported_at, &keys.signing_key)?;

        let capsule_id = capsule_id_of(&capsule)
            .expect("seal_citing_record set capsule_id")
            .to_string();
        let payload = payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: ISSUER,
                subject: &capsule_id,
                content_type: CAPSULE_CONTENT_TYPE,
            },
            &keys.signing_key,
        );
        ledger.append(&capsule, &statement)?;
        sealed += 1;
    }

    // Step 6: the chain rewrite above changed the leaf sequence, but the
    // plugin's durable MMR node store (`mmr_nodes.dat`) and its
    // `checkpoints.jsonl` still commit to the PRE-migration leaves -- the
    // migration is not complete until the commitment layer matches the chain
    // (see the module doc, steps 6-7).
    let expected_mmr = expected_mmr_over(&capsules_path)?;
    let mmr_report = reconcile_node_store(&ledger_dir, &expected_mmr)?;

    // Step 7: preserve (never delete) any checkpoint over the superseded
    // leaf set, out of the way of the fresh checkpoints.jsonl the next
    // cadence tick will start.
    let checkpoints_report = reconcile_checkpoints(&ledger_dir, &expected_mmr)?;

    Ok(format!(
        "backfill complete: {newly_stored} foreign bodies moved to received-capsules.jsonl, \
         {sealed} citing records sealed (chained, .cose written), capsules.jsonl is local-only; \
         mmr_nodes.dat: {mmr_report}; checkpoints.jsonl: {checkpoints_report}. head -> {}",
        ledger.chain_head().unwrap_or("<empty>")
    ))
}

fn hex_to_digest(s: &str) -> Option<Hash> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// The MMR the post-migration `capsules.jsonl` implies: every line's
/// `capsule_id` (in file order) leaf-hashed and folded, exactly as the
/// plugin's checkpoint cadence (`capsule_producer::checkpoint`) folds them.
/// Built in memory -- the reference the on-disk node store and the last
/// checkpoint are reconciled against.
fn expected_mmr_over(capsules_path: &Path) -> anyhow::Result<MemoryNodeStore> {
    let mut expected = MemoryNodeStore::new();
    for (i, line) in read_jsonl(capsules_path).iter().enumerate() {
        let id = capsule_id_of(line)
            .ok_or_else(|| anyhow::anyhow!("capsules.jsonl line {}: missing capsule_id", i + 1))?;
        let digest = hex_to_digest(id).ok_or_else(|| {
            anyhow::anyhow!("capsules.jsonl line {}: capsule_id {id:?} is not 32 bytes of hex", i + 1)
        })?;
        add_leaf(&mut expected, leaf_hash(&digest))
            .map_err(|e| anyhow::anyhow!("folding post-migration leaves: {e}"))?;
    }
    Ok(expected)
}

/// True when every node the durable store holds equals the expected MMR's
/// node at the same position (MMR nodes are append-only, so a store synced
/// at ANY prior point of the same chain is a strict prefix -- consistent; a
/// store over a rewritten chain is not).
fn node_store_is_prefix_of(stored: &FileNodeStore, expected: &MemoryNodeStore) -> bool {
    let stored_size = stored.size();
    stored_size <= expected.size() && (0..stored_size).all(|pos| stored.node(pos) == expected.node(pos))
}

/// Step 6 (see module doc): rebuild `mmr_nodes.dat` from the post-migration
/// leaves when its stored nodes diverge from them; leave a consistent (or
/// absent) store untouched, so a re-run is a no-op. Returns the report
/// fragment for the tool's summary line.
fn reconcile_node_store(
    ledger_dir: &Path,
    expected: &MemoryNodeStore,
) -> anyhow::Result<String> {
    let node_store_path = ledger_dir.join("mmr_nodes.dat");
    if !node_store_path.exists() {
        // Nothing stored to diverge -- the plugin builds the store from the
        // (now-clean) chain on its next load. Never create one here just to
        // have one.
        return Ok("absent (the plugin builds it from the chain on next load)".to_string());
    }
    let (existing, _report) = FileNodeStore::open(&node_store_path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", node_store_path.display()))?;
    if node_store_is_prefix_of(&existing, expected) {
        return Ok(format!(
            "consistent with the post-migration chain ({} nodes) -- not rebuilt",
            existing.size()
        ));
    }
    let stale_nodes = existing.size();
    drop(existing);
    // Rebuild beside, then atomically swap in -- a crash mid-rebuild leaves
    // the original store in place (still divergent, still caught by the
    // cadence's divergence guard and by a re-run here), never a torn store.
    let rebuild_path = ledger_dir.join("mmr_nodes.dat.rebuild");
    let rebuilt = FileNodeStore::rebuild_from_leaves(
        &rebuild_path,
        expected_leaf_hashes(expected),
    )
    .map_err(|e| anyhow::anyhow!("rebuild {}: {e}", rebuild_path.display()))?;
    let node_count = rebuilt.size();
    drop(rebuilt);
    std::fs::rename(&rebuild_path, &node_store_path)?;
    Ok(format!(
        "REBUILT from the post-migration leaf sequence ({stale_nodes} stale nodes replaced by \
         {node_count} nodes over {} leaves)",
        cll::mmr::leaf_count(node_count).map_err(|e| anyhow::anyhow!("{e}"))?
    ))
}

/// The expected MMR's leaf hashes, in leaf order -- the exact input
/// `FileNodeStore::rebuild_from_leaves` wants.
fn expected_leaf_hashes(expected: &MemoryNodeStore) -> Vec<Hash> {
    let leaf_count = cll::mmr::leaf_count(expected.size())
        .expect("a MemoryNodeStore built by add_leaf always has a valid MMR size");
    (0..leaf_count)
        .map(|i| {
            let pos = cll::mmr::leaf_index_to_pos(i)
                .expect("leaf index below leaf_count always has a position");
            expected.node(pos)
        })
        .collect()
}

/// True when `cp`'s recorded `(mmr_size, root)` still recomputes over the
/// post-migration MMR -- i.e. the checkpoint commits to a prefix of the
/// CURRENT chain. Any malformed size reads as "does not commit".
fn checkpoint_commits_to(cp: &CheckpointRecord, expected: &MemoryNodeStore) -> bool {
    if cp.mmr_size == 0 || cp.mmr_size > expected.size() {
        return false;
    }
    let Ok(peak_positions) = peaks(cp.mmr_size) else {
        return false;
    };
    let peak_hashes: Vec<Hash> = peak_positions.iter().map(|&p| expected.node(p)).collect();
    hex::encode(root_from_peaks(&peak_hashes)) == cp.root
}

/// Step 7 (see module doc): archive a `checkpoints.jsonl` whose last
/// checkpoint references the superseded (pre-migration) leaf set; keep one
/// that still verifies. The archive is a RENAME beside the original --
/// `checkpoints.pre-backfill.jsonl` (timestamped if that name is already
/// taken) -- a checkpoint is NEVER silently deleted. Returns the report
/// fragment for the tool's summary line.
fn reconcile_checkpoints(
    ledger_dir: &Path,
    expected: &MemoryNodeStore,
) -> anyhow::Result<String> {
    let checkpoints_path = ledger_dir.join("checkpoints.jsonl");
    if !checkpoints_path.exists() {
        return Ok("none present".to_string());
    }
    let Some(last) = read_last_checkpoint(&checkpoints_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", checkpoints_path.display()))?
    else {
        return Ok("empty file (left in place)".to_string());
    };
    if checkpoint_commits_to(&last.record, expected) {
        return Ok(format!(
            "last checkpoint (mmr_size {}) still commits to the post-migration chain -- kept",
            last.record.mmr_size
        ));
    }
    let line_count = std::fs::read_to_string(&checkpoints_path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let mut archive_path = ledger_dir.join("checkpoints.pre-backfill.jsonl");
    if archive_path.exists() {
        // Never clobber an earlier archive either.
        let stamp: String = utc_now_iso8601()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        archive_path = ledger_dir.join(format!("checkpoints.pre-backfill.{stamp}.jsonl"));
    }
    std::fs::rename(&checkpoints_path, &archive_path)?;
    Ok(format!(
        "ARCHIVED {line_count} pre-migration checkpoint line(s) -> {} (superseded leaf set; the \
         next cadence tick starts a fresh checkpoints.jsonl over all post-migration leaves)",
        archive_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| archive_path.display().to_string())
    ))
}

/// Add the AAC-05 `provenance_mode` block (`mode: "backfilled"`) to an
/// already-sealed citing record and RE-seal it: recompute the `capsule_id`
/// over the augmented body (so the mode is committed, like every other field)
/// and re-attach the inline producer envelope. Only the `sealed_at`/imported
/// timestamps are `now`; `source_asserted_at` is the real `received_at`.
fn stamp_backfilled(
    capsule: &mut Value,
    received_at: &str,
    imported_at: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let obj = capsule
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("citing record is not an object"))?;
    // Strip the inline envelope + old id (local-only + recomputed below).
    obj.remove("signature");
    obj.remove("key_id");
    obj.remove("capsule_id");
    obj.insert(
        "provenance_mode".into(),
        serde_json::json!({
            "mode": "backfilled",
            // The action (the receiving of the half) occurred at received_at.
            "source_asserted_at": received_at,
            // Producer-scoped identifier for this bulk import run.
            "import_batch": format!("received-half-citation-backfill/{imported_at}"),
            // When this citing record was appended to our ledger.
            "imported_at": imported_at,
        }),
    );
    let body = Value::Object(obj.clone());
    let capsule_id = capsule_producer::jcs::compute_capsule_id(&body)?;
    obj.insert("capsule_id".into(), serde_json::json!(capsule_id));
    capsule_producer::capsule::attach_producer_envelope(capsule, signing_key)
        .map_err(|e| anyhow::anyhow!("re-attach envelope after stamping backfilled: {e}"))?;
    Ok(())
}
