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
//!
//! **Padding records** ([`crate::padding`], Evidence Layer -00 §12.1) are
//! ledger lines too -- the checkpoint MMR folds every line -- but they sit
//! OUTSIDE the chain: no `chain` block, and the chain head never advances
//! over one, so no record ever links to a padding record. They are appended
//! only through [`Ledger::append_padding`] / [`Ledger::pad_to_bucket`], are
//! not indexed for lookup, and are excluded from `known_capsule_ids`.

use crate::jcs::compute_capsule_id;
use crate::padding::{check_padding_shape, is_padding};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
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
    #[error(
        "ledger line {line} corrupt: signed statement for capsule_id {capsule_id} does not check \
         out on reload ({detail}) -- refusing to trust this entry"
    )]
    StatementInvalid {
        line: usize,
        capsule_id: String,
        detail: String,
    },
    #[error("refusing to append: capsule's chain.parent_capsule_id {parent:?} does not match ledger head {head:?}")]
    AppendChainMismatch {
        parent: Option<String>,
        head: Option<String>,
    },
    #[error("capsule has no capsule_id field")]
    NoCapsuleId,
    #[error("ledger line {line}: malformed padding record: {detail}")]
    MalformedPadding { line: usize, detail: String },
    #[error("refusing to append: {0}")]
    PaddingMisrouted(&'static str),
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
    /// Foreign `capsule_id`s a counterparty-half CITING record in this ledger
    /// already cites -- rebuilt on `open`, maintained on `append`. A citing
    /// record is identified by `references[].citation_purpose ==
    /// "counterparty_half"` ALONE (never by
    /// matching a `chain.relation` string, so legacy `relation: "cites"`
    /// records count the same as post-ruling `"follows"` ones). The live
    /// record-push seal path reads this to dedup re-pushed foreign halves.
    cited_counterparty_halves: HashSet<String>,
    /// Held halves (by their foreign `capsule_id`) a `counterparty_inclusion`
    /// citing record in this ledger already covers -- the dedup gate for a
    /// re-pushed bundle, same rebuild-on-open / maintain-on-append discipline
    /// as `cited_counterparty_halves`.
    inclusion_cited_halves: HashSet<String>,
    /// Every line in `capsules.jsonl`, padding included -- the leaf count the
    /// checkpoint MMR over this file will reach once it has folded it all.
    entries: u64,
    /// `event_ref`s of the payment lifecycle events this ledger already holds
    /// a settlement record for -- rebuilt on `open`, maintained on `append`.
    /// A settlement record is identified by its
    /// `compute_attestation["x-mesh-settlement-v1"]` block; the live channel
    /// seal path reads this so a rebroadcast event never seals twice.
    settlement_event_refs: HashSet<String>,
    /// `<block>:<verdict capsule id>` for every adjudication record this
    /// ledger holds (issued or received) -- the dedup gate so a repeated
    /// verdict seals at most one record of each kind.
    adjudication_records: HashSet<String>,
}

fn statement_path(statements_dir: &Path, capsule_id: &str) -> PathBuf {
    statements_dir.join(format!("{capsule_id}.cose"))
}

/// Collect into `out` every foreign `capsule_id` this capsule cites as a
/// counterparty half (see `Ledger::cited_counterparty_halves`).
fn collect_counterparty_half_citations(capsule: &Value, out: &mut HashSet<String>) {
    let Some(references) = capsule.get("references").and_then(Value::as_array) else {
        return;
    };
    for reference in references {
        if reference.get("citation_purpose").and_then(Value::as_str)
            == Some(crate::capsule::CITATION_PURPOSE_COUNTERPARTY_HALF)
        {
            if let Some(digest) = reference.get("digest").and_then(Value::as_str) {
                out.insert(digest.to_string());
            }
        }
    }
}

/// Collect into `out` the held half a `counterparty_inclusion` citing record
/// covers. The record's `references[]` cite the proof and the checkpoint (one
/// entry per artifact); the half they are about is named in the record's own
/// `compute_attestation.counterparty_inclusion.half_capsule_id`.
fn collect_counterparty_inclusion_citations(capsule: &Value, out: &mut HashSet<String>) {
    let Some(references) = capsule.get("references").and_then(Value::as_array) else {
        return;
    };
    let is_inclusion_citation = references.iter().any(|reference| {
        reference.get("citation_purpose").and_then(Value::as_str)
            == Some(crate::capsule::CITATION_PURPOSE_COUNTERPARTY_INCLUSION)
    });
    if !is_inclusion_citation {
        return;
    }
    if let Some(half) = capsule
        .pointer("/model_attestation/compute_attestation/counterparty_inclusion/half_capsule_id")
        .and_then(Value::as_str)
    {
        out.insert(half.to_string());
    }
}

/// Collect into `out` the `event_ref` of this capsule's settlement
/// observation, when it is a settlement record (see
/// `Ledger::settlement_event_refs`).
fn collect_settlement_event_ref(capsule: &Value, out: &mut HashSet<String>) {
    if let Some(event_ref) = capsule
        .get("model_attestation")
        .and_then(|m| m.get("compute_attestation"))
        .and_then(|c| c.get(crate::capsule::SETTLEMENT_EXTENSION_KEY))
        .and_then(|s| s.get("event_ref"))
        .and_then(Value::as_str)
    {
        out.insert(event_ref.to_string());
    }
}

/// Collect into `out` this capsule's `<block>:<verdict capsule id>` key,
/// when it is an adjudication record (see `Ledger::adjudication_records`).
fn collect_adjudication_record(capsule: &Value, out: &mut HashSet<String>) {
    let Some(attestation) = capsule.pointer("/model_attestation/compute_attestation") else {
        return;
    };
    for block in [crate::capsule::ADJUDICATION_ISSUED_BLOCK, crate::capsule::ADJUDICATION_RECEIVED_BLOCK] {
        if let Some(verdict) = attestation
            .get(block)
            .and_then(|b| b.get("verdict_capsule_id"))
            .and_then(Value::as_str)
        {
            out.insert(format!("{block}:{verdict}"));
        }
    }
    // A refused delivery is keyed per receiver: `<block>:<verdict>/<peer>`.
    let block = crate::capsule::ADJUDICATION_ACK_REFUSED_BLOCK;
    if let Some(refused) = attestation.get(block) {
        if let (Some(verdict), Some(peer)) = (
            refused.get("verdict_capsule_id").and_then(Value::as_str),
            refused.get("refused_by").and_then(Value::as_str),
        ) {
            out.insert(format!("{block}:{verdict}/{peer}"));
        }
    }
}

/// The reload check behind [`LedgerError::StatementInvalid`]: the `.cose`
/// beside a ledger line must be a parseable COSE_Sign1 whose payload names
/// this line's `capsule_id` -- and, when the capsule carries its inline
/// producer `key_id` (the hex Ed25519 public key `attach_producer_envelope`
/// writes), the COSE signature must actually verify against that key, through
/// the same `cose::verify_signed_statement` path `verify::verify_offline`
/// gates on. Returns the human-readable failure detail on mismatch.
fn check_statement_matches(
    capsule: &Value,
    capsule_id: &str,
    statement: &[u8],
) -> Result<(), String> {
    let payload = match producer_verifying_key(capsule) {
        Some(Ok(key)) => {
            crate::cose::verify_signed_statement(statement, &key)
                .map_err(|e| {
                    format!("COSE verification against the capsule's own key_id failed: {e}")
                })?
                .payload
        }
        Some(Err(detail)) => return Err(detail),
        // No inline key_id (e.g. a pre-envelope capsule): signature
        // verification is impossible without a key, but a garbage or
        // swapped statement file is still caught by parsing the COSE and
        // checking whose capsule its payload names.
        None => crate::cose::statement_payload(statement)
            .map_err(|e| format!("not a parseable COSE_Sign1: {e}"))?,
    };
    let payload_json: Value = serde_json::from_slice(&payload)
        .map_err(|e| format!("COSE payload is not valid JSON: {e}"))?;
    match payload_json.get("capsule_id").and_then(Value::as_str) {
        Some(id) if id == capsule_id => Ok(()),
        other => Err(format!(
            "COSE payload names capsule_id {other:?}, expected {capsule_id:?}"
        )),
    }
}

/// The Ed25519 verifying key a capsule's inline `key_id` names, when it
/// carries one. `None` when the capsule has no `key_id`; `Some(Err(..))` when
/// it has one that is not a valid hex-encoded Ed25519 public key (a corrupt
/// claim -- surfaced, never skipped).
fn producer_verifying_key(
    capsule: &Value,
) -> Option<Result<ed25519_dalek::VerifyingKey, String>> {
    let key_hex = capsule.get("key_id").and_then(Value::as_str)?;
    Some(
        hex::decode(key_hex)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .ok_or_else(|| {
                format!("capsule key_id {key_hex:?} is not a valid Ed25519 public key")
            }),
    )
}

impl Ledger {
    /// Open (creating if absent) a ledger rooted at `ledger_dir`, replaying
    /// `capsules.jsonl` to recover the chain head + receipt index.
    ///
    /// Reload verifies each entry's `.cose` signed statement by CONTENT, not
    /// just existence: the statement must parse as COSE_Sign1, its payload
    /// must name the line's `capsule_id`, and where the capsule carries its
    /// inline producer `key_id` the signature is verified against it (see
    /// [`check_statement_matches`]). A garbage or swapped statement file is a
    /// hard [`LedgerError::StatementInvalid`], same spirit as
    /// [`LedgerError::CapsuleIdMismatch`]. Startup cost: one read + COSE
    /// parse (+ one Ed25519 verify where a key_id is present) per entry per
    /// open -- linear in ledger length, fine at this plugin's demo scale; a
    /// much larger ledger would want a verified index instead of dropping
    /// this check.
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
        let mut cited_counterparty_halves = HashSet::new();
        let mut inclusion_cited_halves = HashSet::new();
        let mut settlement_event_refs = HashSet::new();
        let mut adjudication_records = HashSet::new();

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

            let padding = is_padding(&parsed);
            if padding {
                check_padding_shape(&parsed).map_err(|detail| LedgerError::MalformedPadding {
                    line: line_no,
                    detail,
                })?;
            }
            let parent = parsed
                .get("chain")
                .and_then(|c| c.get("parent_capsule_id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if !padding && parent != chain_head {
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
            // Existence is not enough: a garbage/swapped statement file must
            // not reload clean (see this method's doc comment).
            let statement_bytes = fs::read(&stmt_path)?;
            check_statement_matches(&parsed, &stored_id, &statement_bytes).map_err(|detail| {
                LedgerError::StatementInvalid {
                    line: line_no,
                    capsule_id: stored_id.clone(),
                    detail,
                }
            })?;

            report.valid_entries += 1;
            offset += line_bytes_len;
            if padding {
                // Outside the chain: never the head, never indexed.
                continue;
            }
            collect_counterparty_half_citations(&parsed, &mut cited_counterparty_halves);
            collect_counterparty_inclusion_citations(&parsed, &mut inclusion_cited_halves);
            collect_settlement_event_ref(&parsed, &mut settlement_event_refs);
            collect_adjudication_record(&parsed, &mut adjudication_records);
            index.insert(stored_id.clone(), offset - line_bytes_len);
            chain_head = Some(stored_id);
        }

        let append_handle = OpenOptions::new().append(true).open(&capsules_path)?;

        Ok((
            Self {
                capsules_path,
                statements_dir,
                append_handle,
                index,
                chain_head,
                cited_counterparty_halves,
                inclusion_cited_halves,
                entries: report.valid_entries as u64,
                settlement_event_refs,
                adjudication_records,
            },
            report,
        ))
    }

    /// Every line in the ledger, padding included -- see [`Self::pad_to_bucket`].
    pub fn entries(&self) -> u64 {
        self.entries
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

    /// Every indexed `capsule_id` in chain order (first record first), read
    /// off the index's byte offsets -- `capsules.jsonl` is append-only, so
    /// offset order IS chain order. Position `i` here is record `i + 1`.
    pub fn capsule_ids_in_order(&self) -> Vec<String> {
        let mut by_offset: Vec<(&u64, &String)> = self.index.iter().map(|(id, off)| (off, id)).collect();
        by_offset.sort_unstable();
        by_offset.into_iter().map(|(_, id)| id.clone()).collect()
    }

    /// How many records this ledger holds.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Whether this ledger already holds a counterparty-half CITING record
    /// for `foreign_capsule_id` -- the live record-push dedup gate: a
    /// re-pushed foreign half must not seal a second citing record (fsync +
    /// disk amplification by an authorized peer). Identified by
    /// `references[].citation_purpose == "counterparty_half"` alone, never a
    /// `chain.relation` match.
    pub fn cites_counterparty_half(&self, foreign_capsule_id: &str) -> bool {
        self.cited_counterparty_halves.contains(foreign_capsule_id)
    }

    /// Whether this ledger already holds a `counterparty_inclusion` citing
    /// record for the held half `foreign_capsule_id` -- the dedup gate for a
    /// re-pushed bundle.
    pub fn cites_counterparty_inclusion(&self, foreign_capsule_id: &str) -> bool {
        self.inclusion_cited_halves.contains(foreign_capsule_id)
    }

    /// Whether this ledger already holds a settlement record for the payment
    /// lifecycle event whose `event_ref` is `event_ref` -- the channel seal
    /// path's dedup gate, so a rebroadcast event seals at most one record.
    pub fn has_settlement_event(&self, event_ref: &str) -> bool {
        self.settlement_event_refs.contains(event_ref)
    }

    /// Whether this ledger already holds an adjudication record with block
    /// `block` (issued or received) for the verdict `verdict_capsule_id`.
    pub fn has_adjudication_record(&self, block: &str, verdict_capsule_id: &str) -> bool {
        self.adjudication_records.contains(&format!("{block}:{verdict_capsule_id}"))
    }

    /// Append a sealed capsule + its signed statement. The statement file is
    /// written and fsync'd BEFORE the jsonl line, so a crash between the two
    /// leaves at worst an unindexed orphan `.cose` file -- never a jsonl
    /// entry pointing at a receipt that doesn't exist. Refuses to write if
    /// `capsule.chain.parent_capsule_id` doesn't match the current head.
    pub fn append(&mut self, capsule: &Value, signed_statement: &[u8]) -> Result<(), LedgerError> {
        if is_padding(capsule) {
            return Err(LedgerError::PaddingMisrouted(
                "a padding record goes through append_padding, never onto the chain",
            ));
        }
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

        let offset = self.write_line(&capsule_id, capsule, signed_statement)?;

        collect_counterparty_half_citations(capsule, &mut self.cited_counterparty_halves);
        collect_counterparty_inclusion_citations(capsule, &mut self.inclusion_cited_halves);
        collect_settlement_event_ref(capsule, &mut self.settlement_event_refs);
        collect_adjudication_record(capsule, &mut self.adjudication_records);
        self.index.insert(capsule_id.clone(), offset);
        self.chain_head = Some(capsule_id);
        Ok(())
    }

    /// The statement-then-line write every append shares: the `.cose` is
    /// fsync'd BEFORE the jsonl line, so a crash between the two leaves at
    /// worst an orphan statement file. Returns the line's byte offset.
    fn write_line(
        &mut self,
        capsule_id: &str,
        record: &Value,
        signed_statement: &[u8],
    ) -> Result<u64, LedgerError> {
        let stmt_path = statement_path(&self.statements_dir, capsule_id);
        let mut stmt_file = File::create(&stmt_path)?;
        stmt_file.write_all(signed_statement)?;
        stmt_file.sync_all()?;

        let offset = fs::metadata(&self.capsules_path)?.len();
        let mut line = serde_json::to_string(record)?;
        line.push('\n');
        self.append_handle.write_all(line.as_bytes())?;
        self.append_handle.sync_all()?;
        self.entries += 1;
        Ok(offset)
    }

    /// Append one padding record + its signed statement. The chain head does
    /// not move and the record is not indexed: a padding record is a leaf of
    /// the checkpoint MMR and nothing else (see the module doc).
    pub fn append_padding(&mut self, record: &Value, signed_statement: &[u8]) -> Result<(), LedgerError> {
        if !is_padding(record) {
            return Err(LedgerError::PaddingMisrouted(
                "append_padding only takes a padding record",
            ));
        }
        check_padding_shape(record).map_err(|detail| LedgerError::MalformedPadding {
            line: self.entries as usize + 1,
            detail,
        })?;
        let capsule_id = record
            .get("capsule_id")
            .and_then(Value::as_str)
            .ok_or(LedgerError::NoCapsuleId)?
            .to_string();
        self.write_line(&capsule_id, record, signed_statement)?;
        Ok(())
    }

    /// Append padding records until the ledger's line count is a multiple of
    /// `bucket` (a no-op when it already is, so a retry or a restart never
    /// pads twice). Each record is sealed with a fresh store nonce, carries
    /// the producer envelope under `signing_key`, and gets a detached signed
    /// statement from the same key, like every other line. Returns the
    /// resulting line count -- the leaf count the next checkpoint is cut at.
    ///
    /// The caller holds this ledger's writer lock across the call, so no
    /// real record can land between two padding records.
    pub fn pad_to_bucket(
        &mut self,
        bucket: u64,
        signing_key: &ed25519_dalek::SigningKey,
        issuer: &str,
    ) -> Result<u64, LedgerError> {
        if bucket == 0 {
            return Ok(self.entries);
        }
        let missing = (bucket - self.entries % bucket) % bucket;
        for _ in 0..missing {
            let mut record = crate::padding::build_padding_record()?;
            crate::capsule::attach_producer_envelope(&mut record, signing_key)
                .expect("build_padding_record always sets a hex capsule_id");
            let capsule_id = record["capsule_id"]
                .as_str()
                .expect("build_padding_record always sets capsule_id")
                .to_string();
            let statement = crate::cose::build_signed_statement(
                &crate::cose::SignedStatementInput {
                    payload: &crate::capsule::payload_bytes(&record),
                    issuer,
                    subject: &capsule_id,
                    content_type: crate::padding::PADDING_CONTENT_TYPE,
                },
                signing_key,
            );
            self.append_padding(&record, &statement)?;
        }
        Ok(self.entries)
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
        body.insert("format_version".into(), json!("4"));
        body.insert("canonicalization_id".into(), json!("jcs"));
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

    /// A REAL COSE_Sign1 signed statement over the capsule's own JSON bytes
    /// -- reload now verifies statement CONTENT, so a fake byte-blob would
    /// (rightly) fail `Ledger::open`. Deterministic key + deterministic
    /// Ed25519 => reproducible bytes, so equality assertions still hold.
    fn statement_for(capsule: &Value) -> Vec<u8> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        crate::cose::build_signed_statement(
            &crate::cose::SignedStatementInput {
                payload: &serde_json::to_vec(capsule).unwrap(),
                issuer: "ledger-test",
                subject: capsule["capsule_id"].as_str().unwrap(),
                content_type: "application/vnd.agent-action-capsule+json",
            },
            &signing_key,
        )
    }

    #[test]
    fn append_then_reopen_recovers_chain_head() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, report) = Ledger::open(dir.path()).unwrap();
        assert_eq!(report.valid_entries, 0);
        assert!(ledger.chain_head().is_none());

        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for(&c1)).unwrap();
        assert_eq!(ledger.chain_head(), Some(id1.as_str()));

        let c2 = sample_capsule("two", Some(&id1));
        let id2 = c2["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c2, &statement_for(&c2)).unwrap();
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
        ledger.append(&c1, &statement_for(&c1)).unwrap();

        // A capsule chaining to the WRONG parent (or no parent, when one is
        // expected) must be refused, not silently appended.
        let bad = sample_capsule("bogus", Some(&"f".repeat(64)));
        let err = ledger.append(&bad, &statement_for(&bad)).unwrap_err();
        assert!(matches!(err, LedgerError::AppendChainMismatch { .. }));

        let bad_no_parent = sample_capsule("no-parent", None);
        let err2 = ledger
            .append(&bad_no_parent, &statement_for(&bad_no_parent))
            .unwrap_err();
        assert!(matches!(err2, LedgerError::AppendChainMismatch { .. }));
    }

    #[test]
    fn receipt_lookup_returns_capsule_and_statement() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for(&c1)).unwrap();

        let entry = ledger.lookup(&id1).unwrap().expect("entry present");
        assert_eq!(entry.capsule, c1);
        assert_eq!(entry.signed_statement, statement_for(&c1));

        assert!(ledger.lookup(&"0".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn torn_write_is_truncated_not_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for(&c1)).unwrap();
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

    /// A capsule carrying a top-level `references` array (a
    /// CITING record) whose id was
    /// computed WITH `references` in the preimage. Proves the ledger's own
    /// recomputation covers `references` (`compute_capsule_id` includes it),
    /// so a chain of citing records cold-reloads clean.
    fn citing_capsule(seed: &str, parent: Option<&str>, cited: &str) -> Value {
        let mut body = serde_json::Map::new();
        body.insert("spec_version".into(), json!("draft-mih-scitt-agent-action-capsule-02"));
        body.insert("format_version".into(), json!("4"));
        body.insert("canonicalization_id".into(), json!("jcs"));
        body.insert("action_id".into(), json!(format!("cite/{seed}")));
        body.insert("seed".into(), json!(seed));
        if let Some(p) = parent {
            body.insert(
                "chain".into(),
                json!({"parent_capsule_id": p, "relation": "follows"}),
            );
        }
        body.insert(
            "references".into(),
            json!([{"type": "capsule", "digest_alg": "SHA-256", "digest": cited, "citation_purpose": "counterparty_half"}]),
        );
        let capsule_id = compute_capsule_id(&Value::Object(body.clone())).unwrap();
        body.insert("capsule_id".into(), json!(capsule_id));
        Value::Object(body)
    }

    /// A ledger holding citing records
    /// (each with a top-level `references` array committed into its
    /// `capsule_id`) recovers its chain head cleanly on cold reopen -- no
    /// `Ledger::open` change is needed for the new record shape, since
    /// `compute_capsule_id` already commits `references` into the preimage.
    #[test]
    fn ledger_with_citing_records_cold_reloads_clean() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();

        // A normal local record, then a citing record chained onto it, then a
        // second citing record -- the real shape after a received-half seal.
        let local = sample_capsule("local", None);
        let local_id = local["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&local, &statement_for(&local)).unwrap();

        let cite1 = citing_capsule("cite1", Some(&local_id), &"a".repeat(64));
        let cite1_id = cite1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&cite1, &statement_for(&cite1)).unwrap();

        let cite2 = citing_capsule("cite2", Some(&cite1_id), &"b".repeat(64));
        let cite2_id = cite2["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&cite2, &statement_for(&cite2)).unwrap();
        drop(ledger);

        let (ledger2, report) = Ledger::open(dir.path()).unwrap();
        assert_eq!(report.valid_entries, 3);
        assert_eq!(ledger2.chain_head(), Some(cite2_id.as_str()));
        assert!(ledger2.contains(&local_id));
        assert!(ledger2.contains(&cite1_id));
        assert!(ledger2.contains(&cite2_id));
    }

    #[test]
    fn tampered_terminated_line_is_a_hard_error_not_a_silent_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        ledger.append(&c1, &statement_for(&c1)).unwrap();
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

    /// Reload verifies statement CONTENT, not just existence: a garbage
    /// `.cose` file (not COSE_Sign1 at all) must be a hard error on reopen,
    /// never a clean reload.
    #[test]
    fn garbage_statement_file_is_a_hard_error_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for(&c1)).unwrap();
        drop(ledger);

        let stmt_path = dir
            .path()
            .join("signed-statements")
            .join(format!("{id1}.cose"));
        fs::write(&stmt_path, b"not a cose statement at all").unwrap();

        let err = Ledger::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, LedgerError::StatementInvalid { .. }),
            "expected StatementInvalid, got: {err}"
        );
    }

    /// A statement file SWAPPED with another entry's (each one a perfectly
    /// valid COSE_Sign1 -- just over the wrong capsule) must be caught: the
    /// payload names a different capsule_id than the ledger line it sits
    /// beside.
    #[test]
    fn swapped_statement_files_are_a_hard_error_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();
        let c1 = sample_capsule("one", None);
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c1, &statement_for(&c1)).unwrap();
        let c2 = sample_capsule("two", Some(&id1));
        let id2 = c2["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&c2, &statement_for(&c2)).unwrap();
        drop(ledger);

        let statements_dir = dir.path().join("signed-statements");
        let p1 = statements_dir.join(format!("{id1}.cose"));
        let p2 = statements_dir.join(format!("{id2}.cose"));
        let b1 = fs::read(&p1).unwrap();
        let b2 = fs::read(&p2).unwrap();
        fs::write(&p1, &b2).unwrap();
        fs::write(&p2, &b1).unwrap();

        let err = Ledger::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, LedgerError::StatementInvalid { .. }),
            "expected StatementInvalid, got: {err}"
        );
    }

    /// Where the capsule names its producer key inline (`key_id`), reload
    /// verifies the COSE signature against it -- a statement re-signed by a
    /// DIFFERENT key (payload intact, so the payload check alone would pass)
    /// must be a hard error.
    #[test]
    fn statement_signed_by_a_different_key_is_a_hard_error_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();

        let node_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut c1 = sample_capsule("one", None);
        crate::capsule::attach_producer_envelope(&mut c1, &node_key).unwrap();
        let id1 = c1["capsule_id"].as_str().unwrap().to_string();
        // Genuine statement, signed by the SAME key the capsule names.
        let good = crate::cose::build_signed_statement(
            &crate::cose::SignedStatementInput {
                payload: &serde_json::to_vec(&c1).unwrap(),
                issuer: "ledger-test",
                subject: &id1,
                content_type: "application/vnd.agent-action-capsule+json",
            },
            &node_key,
        );
        ledger.append(&c1, &good).unwrap();
        drop(ledger);
        // Reload of the genuine state is clean (signature verifies).
        {
            let (_ledger, report) = Ledger::open(dir.path()).unwrap();
            assert_eq!(report.valid_entries, 1);
        }

        // Swap in a statement over the same payload signed by an IMPOSTOR key.
        let impostor = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let forged = crate::cose::build_signed_statement(
            &crate::cose::SignedStatementInput {
                payload: &serde_json::to_vec(&c1).unwrap(),
                issuer: "ledger-test",
                subject: &id1,
                content_type: "application/vnd.agent-action-capsule+json",
            },
            &impostor,
        );
        let stmt_path = dir
            .path()
            .join("signed-statements")
            .join(format!("{id1}.cose"));
        fs::write(&stmt_path, &forged).unwrap();

        let err = Ledger::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, LedgerError::StatementInvalid { .. }),
            "expected StatementInvalid, got: {err}"
        );
    }

    /// The counterparty-half citation set survives append AND reopen, and is
    /// keyed on `citation_purpose` alone -- a legacy `relation: "cites"`
    /// citing record counts exactly like a post-ruling `"follows"` one
    /// (the record kind is the citation purpose, never the
    /// relation string).
    #[test]
    fn cited_counterparty_halves_tracked_on_append_and_rebuilt_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, _) = Ledger::open(dir.path()).unwrap();

        let local = sample_capsule("local", None);
        let local_id = local["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&local, &statement_for(&local)).unwrap();
        assert!(!ledger.cites_counterparty_half(&"a".repeat(64)));

        // A post-ruling citing record (relation "follows").
        let cite1 = citing_capsule("cite1", Some(&local_id), &"a".repeat(64));
        let cite1_id = cite1["capsule_id"].as_str().unwrap().to_string();
        ledger.append(&cite1, &statement_for(&cite1)).unwrap();
        assert!(ledger.cites_counterparty_half(&"a".repeat(64)));

        // A LEGACY citing record (relation "cites") -- same kind, same set.
        let mut body = serde_json::Map::new();
        body.insert("spec_version".into(), json!("draft-mih-scitt-agent-action-capsule-02"));
        body.insert("format_version".into(), json!("4"));
        body.insert("canonicalization_id".into(), json!("jcs"));
        body.insert("action_id".into(), json!("cite/legacy"));
        body.insert(
            "chain".into(),
            json!({"parent_capsule_id": cite1_id, "relation": "cites"}),
        );
        body.insert(
            "references".into(),
            json!([{"type": "capsule", "digest_alg": "SHA-256", "digest": "b".repeat(64), "citation_purpose": "counterparty_half"}]),
        );
        let legacy_id = compute_capsule_id(&Value::Object(body.clone())).unwrap();
        body.insert("capsule_id".into(), json!(legacy_id));
        let legacy = Value::Object(body);
        ledger.append(&legacy, &statement_for(&legacy)).unwrap();
        assert!(ledger.cites_counterparty_half(&"b".repeat(64)));
        drop(ledger);

        // Rebuilt from disk on reopen -- both the follows and the legacy
        // cites records land in the set.
        let (reopened, _) = Ledger::open(dir.path()).unwrap();
        assert!(reopened.cites_counterparty_half(&"a".repeat(64)));
        assert!(reopened.cites_counterparty_half(&"b".repeat(64)));
        assert!(!reopened.cites_counterparty_half(&"c".repeat(64)));
    }
}
