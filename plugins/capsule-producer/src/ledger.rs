//! Durable local ledger: `<ledger_dir>/capsules.jsonl` (one JSON capsule per
//! line) + `<ledger_dir>/signed-statements/<capsule_id>.cose` (the raw
//! COSE_Sign1 bytes) — the same on-disk shape `capsule_sidecar.py`'s
//! `NodeState`/`record_capsule` uses, so existing Python tooling that reads
//! this ledger (`run_demo.py`, `bilateral_demo.py`) keeps working unmodified
//! against a Rust-written ledger (M1 report's Milestone 2 recommendation).
//!
//! Three properties this module exists to guarantee, per the task acceptance:
//!
//! 1. **capsule_id links** — `append()` refuses to write a capsule whose
//!    `chain.parent_capsule_id` doesn't match the ledger's current head.
//! 2. **restart preserves a valid chain head** — `open()` replays the whole
//!    `capsules.jsonl` on startup and recovers `chain_head` from it; no
//!    separate head-pointer file to fall out of sync.
//! 3. **partial write doesn't create a silently-accepted chain** — a torn
//!    write (crash mid-`write()`, so the final line has no trailing `\n`) is
//!    detected and the incomplete line is truncated away during recovery,
//!    never indexed, never trusted as the head. A *terminated* line that
//!    fails to parse, or whose stored `capsule_id` doesn't match its
//!    recomputed digest, or whose chain linkage doesn't match its
//!    predecessor, is a hard error instead of a silent drop — that is real
//!    corruption, not an artifact of a torn write, and must not be papered
//!    over.

use crate::jcs::compute_capsule_id;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization error recomputing capsule_id: {0}")]
    Jcs(#[from] crate::jcs::JcsError),
    #[error(
        "ledger line {line} corrupt: stored capsule_id {stored:?} does not match recomputed digest {recomputed:?} -- refusing to trust this entry"
    )]
    CapsuleIdMismatch {
        line: usize,
        stored: String,
        recomputed: String,
    },
    #[error("ledger line {line} corrupt: missing or non-string capsule_id field")]
    MissingCapsuleId { line: usize },
    #[error("ledger line {line} references chain parent {parent:?} but the ledger head at that point was {head:?} -- chain is broken, not appending silently")]
    ChainBroken {
        line: usize,
        parent: Option<String>,
        head: Option<String>,
    },
    #[error("ledger line {line}: signed statement file missing for capsule_id {capsule_id} ({path})")]
    MissingStatement {
        line: usize,
        capsule_id: String,
        path: String,
    },
    #[error("refusing to append: capsule's chain.parent_capsule_id {parent:?} does not match ledger head {head:?}")]
    AppendChainMismatch {
        parent: Option<String>,
        head: Option<String>,
    },
    #[error("capsule has no capsule_id field")]
    NoCapsuleId,
}

/// A recovered/looked-up ledger entry: the sealed capsule plus its raw
/// COSE_Sign1 signed-statement bytes ("receipt").
pub struct LedgerEntry {
    pub capsule: Value,
    pub signed_statement: Vec<u8>,
}

/// What `open()` found while replaying the ledger — surfaced so a caller can
/// log/report a recovered torn write rather than have it happen invisibly.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub valid_entries: usize,
    /// `Some(byte offset)` when a torn trailing write was found and the file
    /// was truncated back to this offset during recovery.
    pub truncated_torn_write_at: Option<u64>,
}

#[derive(Debug)]
pub struct Ledger {
    capsules_path: PathBuf,
    statements_dir: PathBuf,
    append_handle: File,
    /// capsule_id -> byte offset of the start of its line in capsules.jsonl.
    index: HashMap<String, u64>,
    chain_head: Option<String>,
}

fn statement_path(statements_dir: &Path, capsule_id: &str) -> PathBuf {
    statements_dir.join(format!("{capsule_id}.cose"))
}

impl Ledger {
    /// Open (creating if absent) a ledger rooted at `ledger_dir`, replaying
    /// `capsules.jsonl` to recover the chain head + receipt index.
    pub fn open(ledger_dir: &Path) -> Result<(Self, RecoveryReport), LedgerError> {
        fs::create_dir_all(ledger_dir)?;
        let statements_dir = ledger_dir.join("signed-statements");
        fs::create_dir_all(&statements_dir)?;
        let capsules_path = ledger_dir.join("capsules.jsonl");
        if !capsules_path.exists() {
            File::create(&capsules_path)?;
        }

        let mut raw = Vec::new();
        File::open(&capsules_path)?.read_to_end(&mut raw)?;

        let mut index = HashMap::new();
        let mut chain_head: Option<String> = None;
        let mut offset: u64 = 0;
        let mut report = RecoveryReport::default();

        // Split on '\n', keeping track of whether the buffer ends with one.
        // A missing trailing newline on the final chunk means a torn write:
        // truncate it away rather than trust or reject it as corruption.
        let ends_with_newline = raw.last() == Some(&b'\n');
        let text = String::from_utf8_lossy(&raw);
        let mut parts: Vec<&str> = text.split('\n').collect();
        if parts.last() == Some(&"") {
            parts.pop(); // trailing split artifact from a final '\n'
        }

        for (i, line) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            let line_bytes_len = line.len() as u64 + 1; // + '\n'
            let line_no = i + 1;

            if line.is_empty() {
                offset += line_bytes_len;
                continue;
            }

            if is_last && !ends_with_newline {
                // Torn write: truncate the file back to the start of this
                // line so the on-disk ledger never carries a partial record.
                let f = OpenOptions::new().write(true).open(&capsules_path)?;
                f.set_len(offset)?;
                report.truncated_torn_write_at = Some(offset);
                break;
            }

            let parsed: Value = serde_json::from_str(line).map_err(LedgerError::Json)?;
            let stored_id = parsed
                .get("capsule_id")
                .and_then(Value::as_str)
                .ok_or(LedgerError::MissingCapsuleId { line: line_no })?
                .to_string();

            let recomputed = compute_capsule_id(&parsed)?;
            if recomputed != stored_id {
                return Err(LedgerError::CapsuleIdMismatch {
                    line: line_no,
                    stored: stored_id,
                    recomputed,
                });
            }

            let parent = parsed
                .get("chain")
                .and_then(|c| c.get("parent_capsule_id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if parent != chain_head {
                return Err(LedgerError::ChainBroken {
                    line: line_no,
                    parent,
                    head: chain_head.clone(),
                });
            }

            let stmt_path = statement_path(&statements_dir, &stored_id);
            if !stmt_path.exists() {
                return Err(LedgerError::MissingStatement {
                    line: line_no,
                    capsule_id: stored_id,
                    path: stmt_path.display().to_string(),
                });
            }

            index.insert(stored_id.clone(), offset);
            chain_head = Some(stored_id);
            report.valid_entries += 1;
            offset += line_bytes_len;
        }

        let append_handle = OpenOptions::new().append(true).open(&capsules_path)?;

        Ok((
            Self {
                capsules_path,
                statements_dir,
                append_handle,
                index,
                chain_head,
            },
            report,
        ))
    }

    pub fn chain_head(&self) -> Option<&str> {
        self.chain_head.as_deref()
    }

    pub fn contains(&self, capsule_id: &str) -> bool {
        self.index.contains_key(capsule_id)
    }

    /// All `capsule_id`s this ledger has validated and indexed -- the "known
    /// capsule store" a caller passes to `verify::verify_offline` for
    /// chain-parent-membership checking.
    pub fn known_capsule_ids(&self) -> std::collections::HashSet<String> {
        self.index.keys().cloned().collect()
    }

    /// Append a sealed capsule + its signed statement. The statement file is
    /// written and fsync'd BEFORE the jsonl line, so a crash between the two
    /// leaves at worst an unindexed orphan `.cose` file -- never a jsonl
    /// entry pointing at a receipt that doesn't exist. Refuses to write if
    /// `capsule.chain.parent_capsule_id` doesn't match the current head.
    pub fn append(&mut self, capsule: &Value, signed_statement: &[u8]) -> Result<(), LedgerError> {
        let capsule_id = capsule
            .get("capsule_id")
            .and_then(Value::as_str)
            .ok_or(LedgerError::NoCapsuleId)?
            .to_string();

        let parent = capsule
            .get("chain")
            .and_then(|c| c.get("parent_capsule_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if parent != self.chain_head {
            return Err(LedgerError::AppendChainMismatch {
                parent,
                head: self.chain_head.clone(),
            });
        }

        let stmt_path = statement_path(&self.statements_dir, &capsule_id);
        let mut stmt_file = File::create(&stmt_path)?;
        stmt_file.write_all(signed_statement)?;
        stmt_file.sync_all()?;

        let offset = fs::metadata(&self.capsules_path)?.len();
        let mut line = serde_json::to_string(capsule)?;
        line.push('\n');
        self.append_handle.write_all(line.as_bytes())?;
        self.append_handle.sync_all()?;

        self.index.insert(capsule_id.clone(), offset);
        self.chain_head = Some(capsule_id);
        Ok(())
    }

    /// Receipt lookup: read back the sealed capsule + its COSE_Sign1
    /// signed-statement bytes by `capsule_id`, seeking directly to the
    /// indexed byte offset rather than scanning the file.
    pub fn lookup(&self, capsule_id: &str) -> Result<Option<LedgerEntry>, LedgerError> {
        let Some(&offset) = self.index.get(capsule_id) else {
            return Ok(None);
        };
        let mut f = File::open(&self.capsules_path)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let capsule: Value = serde_json::from_str(line.trim_end())?;

        let stmt_path = statement_path(&self.statements_dir, capsule_id);
        let mut signed_statement = Vec::new();
        File::open(&stmt_path)?.read_to_end(&mut signed_statement)?;

        Ok(Some(LedgerEntry {
            capsule,
            signed_statement,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A minimal, independently-computed capsule (not routed through
    /// `capsule::seal`, so these tests exercise the ledger's OWN
    /// recomputation/validation logic against a value it didn't build).
    fn sample_capsule(seed: &str, parent: Option<&str>) -> Value {
        let mut body = serde_json::Map::new();
        body.insert("spec_version".into(), json!("draft-mih-scitt-agent-action-capsule-02"));
        body.insert("format_version".into(), json!("2"));
        body.insert("action_id".into(), json!(format!("test/{seed}")));
        body.insert("seed".into(), json!(seed));
        if let Some(p) = parent {
            body.insert(
                "chain".into(),
                json!({"parent_capsule_id": p, "relation": "follows"}),
            );
        }
        let capsule_id = compute_capsule_id(&Value::Object(body.clone())).unwrap();
        body.insert("capsule_id".into(), json!(capsule_id));
        // capsule_id must sort logically before other fields for readability
        // only; JSON object field order doesn't matter to any check here.
        Value::Object(body)
    }

    fn statement_for(seed: &str) -> Vec<u8> {
        format!("fake-cose-statement-{seed}").into_bytes()
    }

    #[test]
    fn append_then_reopen_recovers_chain_head() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, report) = Ledger::open(dir.path()).unwrap();
        assert_eq!(report.valid_entries, 0);
        assert!(ledger.chain_head().is_none());

        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for("one")).unwrap();
        assert_eq!(ledger.chain_head(), Some(id1.as_str()));

        let c2 = sample_capsule("two", Some(&id1));
        let id2 = c2["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c2, &statement_for("two")).unwrap();
        assert_eq!(ledger.chain_head(), Some(id2.as_str()));
        drop(ledger);

        // Restart: a fresh Ledger::open() over the same directory must
        // recover the same head purely by replaying capsules.jsonl.
        let (ledger2, report2) = Ledger::open(dir.path()).unwrap();
        assert_eq!(report2.valid_entries, 2);
        assert_eq!(ledger2.chain_head(), Some(id2.as_str()));
        assert!(ledger2.contains(&id1));
        assert!(ledger2.contains(&id2));
    }

    #[test]
    fn append_rejects_chain_head_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        ledger.append(&c1, &statement_for("one")).unwrap();

        // A capsule chaining to the WRONG parent (or no parent, when one is
        // expected) must be refused, not silently appended.
        let bad = sample_capsule("bogus", Some(&"f".repeat(64)));
        let err = ledger.append(&bad, &statement_for("bogus")).unwrap_err();
        assert!(matches!(err, LedgerError::AppendChainMismatch { .. }));

        let bad_no_parent = sample_capsule("no-parent", None);
        let err2 = ledger
            .append(&bad_no_parent, &statement_for("no-parent"))
            .unwrap_err();
        assert!(matches!(err2, LedgerError::AppendChainMismatch { .. }));
    }

    #[test]
    fn receipt_lookup_returns_capsule_and_statement() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for("one")).unwrap();

        let entry = ledger.lookup(&id1).unwrap().expect("entry present");
        assert_eq!(entry.capsule, c1);
        assert_eq!(entry.signed_statement, statement_for("one"));

        assert!(ledger.lookup(&"0".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn torn_write_is_truncated_not_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for("one")).unwrap();
        drop(ledger);

        // Simulate a crash mid-write: append a syntactically-truncated
        // second line with NO trailing newline.
        let capsules_path = dir.path().join("capsules.jsonl");
        let mut f = OpenOptions::new().append(true).open(&capsules_path).unwrap();
        f.write_all(br#"{"capsule_id":"deadbee"#).unwrap(); // no trailing \n
        f.flush().unwrap();
        drop(f);

        let (ledger2, report) = Ledger::open(dir.path()).unwrap();
        assert!(report.truncated_torn_write_at.is_some());
        assert_eq!(report.valid_entries, 1);
        // The chain head reverts to the last VALID entry -- the torn write
        // was never accepted, silently or otherwise.
        assert_eq!(ledger2.chain_head(), Some(id1.as_str()));

        // And the file itself was actually truncated on disk, so the next
        // append lands cleanly (not appended after garbage bytes).
        let contents = fs::read_to_string(&capsules_path).unwrap();
        assert!(!contents.contains("deadbee"));
    }

    #[test]
    fn tampered_terminated_line_is_a_hard_error_not_a_silent_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        ledger.append(&c1, &statement_for("one")).unwrap();
        drop(ledger);

        // Tamper the capsule_id field in a fully-terminated (newline-ended)
        // line -- this is corruption, not a torn write, and must be a hard
        // error on reopen, never quietly dropped like a torn write is.
        let capsules_path = dir.path().join("capsules.jsonl");
        let contents = fs::read_to_string(&capsules_path).unwrap();
        let tampered = contents.replace(
            c1["capsule_id"].as_str().unwrap(),
            &"a".repeat(64),
        );
        assert_ne!(contents, tampered);
        fs::write(&capsules_path, tampered).unwrap();

        let err = Ledger::open(dir.path()).unwrap_err();
        assert!(matches!(err, LedgerError::CapsuleIdMismatch { .. }));
    }
}
