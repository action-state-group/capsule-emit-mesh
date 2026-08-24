//! Durable anchor state machine + retry queue.
//!
//! `anchor::AnchorClient` is a bare HTTP client with no memory: it does not
//! know whether a `capsule_id` was ever submitted, whether that submission
//! is durably included yet, or that a transient failure needs retrying.
//! This module adds that memory as an append-only, restart-safe log --
//! `<queue_dir>/anchor_queue.jsonl`, one JSON transition event per line --
//! reusing the same durability shape `ledger.rs` already established for
//! the capsule ledger: append + fsync before trusting a transition, replay
//! the whole log on `open()` to recover state, truncate (never trust) a
//! torn trailing write from a crash mid-append, and hard-error on a
//! terminated-but-corrupt line rather than silently drop it.
//!
//! Every tracked `capsule_id` is in exactly one of five states:
//!
//! - `pending` -- enqueued, no submission attempted yet (or the previous
//!   attempt failed and is waiting to be retried).
//! - `submitted` -- `POST /v1/digest` succeeded and returned a receipt, but
//!   `GET /v1/inclusion` has not yet confirmed durability.
//! - `anchored` -- inclusion confirmed durable. Terminal, success.
//! - `rejected` -- the anchor service returned a 4xx: this exact request is
//!   invalid and resubmitting it unchanged will not help. Terminal,
//!   failure, NOT retried.
//! - `failed` -- a transient failure (transport error or 5xx). Not
//!   terminal: stays eligible for retry via `retryable()`.

use crate::anchor::{AnchorClient, AnchorError, AnchorReceipt, InclusionProof};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const QUEUE_FILENAME: &str = "anchor_queue.jsonl";

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("anchor queue line {line} corrupt: {reason}")]
    CorruptLine { line: usize, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorState {
    Pending,
    Submitted,
    Anchored,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueueEvent {
    capsule_id: String,
    state: AnchorState,
    attempts: u32,
    detail: Option<String>,
    receipt: Option<AnchorReceipt>,
    recorded_at: String,
}

/// The current, reconstructed status of one tracked `capsule_id` -- what a
/// caller reads back from the queue, as opposed to `QueueEvent`, which is
/// the durable on-disk transition record.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub state: AnchorState,
    pub attempts: u32,
    pub last_detail: Option<String>,
    pub receipt: Option<AnchorReceipt>,
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub valid_events: usize,
    pub truncated_torn_write_at: Option<u64>,
}

#[derive(Debug)]
pub struct AnchorQueue {
    path: PathBuf,
    append_handle: File,
    entries: HashMap<String, QueueEntry>,
}

impl AnchorQueue {
    /// Open (creating if absent) a durable anchor queue rooted at
    /// `queue_dir`, replaying `anchor_queue.jsonl` to recover the latest
    /// state of every tracked `capsule_id`.
    pub fn open(queue_dir: &Path) -> Result<(Self, RecoveryReport), QueueError> {
        fs::create_dir_all(queue_dir)?;
        let path = queue_dir.join(QUEUE_FILENAME);
        if !path.exists() {
            File::create(&path)?;
        }

        let mut raw = Vec::new();
        File::open(&path)?.read_to_end(&mut raw)?;

        let mut entries: HashMap<String, QueueEntry> = HashMap::new();
        let mut report = RecoveryReport::default();

        let ends_with_newline = raw.last() == Some(&b'\n');
        let text = String::from_utf8_lossy(&raw);
        let mut parts: Vec<&str> = text.split('\n').collect();
        if parts.last() == Some(&"") {
            parts.pop();
        }

        let mut offset: u64 = 0;
        for (i, line) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            let line_bytes_len = line.len() as u64 + 1;
            let line_no = i + 1;

            if line.is_empty() {
                offset += line_bytes_len;
                continue;
            }

            if is_last && !ends_with_newline {
                // Torn write (crash mid-append): truncate it away rather
                // than trust a transition we can't be sure was ever fully
                // durable. The entry reverts to its last fully-written
                // state, which is exactly the "kill mid-submit" case this
                // queue must survive.
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(offset)?;
                report.truncated_torn_write_at = Some(offset);
                break;
            }

            let event: QueueEvent =
                serde_json::from_str(line).map_err(|e| QueueError::CorruptLine {
                    line: line_no,
                    reason: e.to_string(),
                })?;
            entries.insert(
                event.capsule_id.clone(),
                QueueEntry {
                    state: event.state,
                    attempts: event.attempts,
                    last_detail: event.detail,
                    receipt: event.receipt,
                },
            );
            report.valid_events += 1;
            offset += line_bytes_len;
        }

        let append_handle = OpenOptions::new().append(true).open(&path)?;

        Ok((
            Self {
                path,
                append_handle,
                entries,
            },
            report,
        ))
    }

    pub fn state_of(&self, capsule_id: &str) -> Option<AnchorState> {
        self.entries.get(capsule_id).map(|e| e.state)
    }

    pub fn entry(&self, capsule_id: &str) -> Option<&QueueEntry> {
        self.entries.get(capsule_id)
    }

    /// `capsule_id`s ready for a submission attempt: newly enqueued
    /// (`pending`) or previously `failed` (transient, eligible for retry).
    /// Never includes `rejected` -- that state means retrying unchanged is
    /// pointless.
    pub fn retryable(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.state, AnchorState::Pending | AnchorState::Failed))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// `capsule_id`s that were submitted but not yet confirmed durably
    /// included.
    pub fn awaiting_confirmation(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state == AnchorState::Submitted)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn append(&mut self, event: QueueEvent) -> Result<(), QueueError> {
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        self.append_handle.write_all(line.as_bytes())?;
        self.append_handle.sync_all()?;
        self.entries.insert(
            event.capsule_id.clone(),
            QueueEntry {
                state: event.state,
                attempts: event.attempts,
                last_detail: event.detail,
                receipt: event.receipt,
            },
        );
        Ok(())
    }

    fn attempts_for(&self, capsule_id: &str) -> u32 {
        self.entries.get(capsule_id).map(|e| e.attempts).unwrap_or(0)
    }

    /// Track a new `capsule_id`. Idempotent: enqueueing an already-tracked
    /// id is a no-op (does not reset its state or attempt count) so a
    /// caller can call this unconditionally every time it produces a
    /// capsule worth anchoring.
    pub fn enqueue(&mut self, capsule_id: &str) -> Result<(), QueueError> {
        if self.entries.contains_key(capsule_id) {
            return Ok(());
        }
        self.append(QueueEvent {
            capsule_id: capsule_id.to_string(),
            state: AnchorState::Pending,
            attempts: 0,
            detail: None,
            receipt: None,
            recorded_at: crate::timestamp::utc_now_iso8601(),
        })
    }

    pub fn record_submitted(
        &mut self,
        capsule_id: &str,
        receipt: AnchorReceipt,
    ) -> Result<(), QueueError> {
        self.append(QueueEvent {
            capsule_id: capsule_id.to_string(),
            state: AnchorState::Submitted,
            attempts: self.attempts_for(capsule_id) + 1,
            detail: None,
            receipt: Some(receipt),
            recorded_at: crate::timestamp::utc_now_iso8601(),
        })
    }

    pub fn record_anchored(&mut self, capsule_id: &str) -> Result<(), QueueError> {
        let receipt = self.entries.get(capsule_id).and_then(|e| e.receipt.clone());
        self.append(QueueEvent {
            capsule_id: capsule_id.to_string(),
            state: AnchorState::Anchored,
            attempts: self.attempts_for(capsule_id),
            detail: None,
            receipt,
            recorded_at: crate::timestamp::utc_now_iso8601(),
        })
    }

    pub fn record_rejected(&mut self, capsule_id: &str, detail: String) -> Result<(), QueueError> {
        self.append(QueueEvent {
            capsule_id: capsule_id.to_string(),
            state: AnchorState::Rejected,
            attempts: self.attempts_for(capsule_id) + 1,
            detail: Some(detail),
            receipt: None,
            recorded_at: crate::timestamp::utc_now_iso8601(),
        })
    }

    pub fn record_failed(&mut self, capsule_id: &str, detail: String) -> Result<(), QueueError> {
        self.append(QueueEvent {
            capsule_id: capsule_id.to_string(),
            state: AnchorState::Failed,
            attempts: self.attempts_for(capsule_id) + 1,
            detail: Some(detail),
            receipt: None,
            recorded_at: crate::timestamp::utc_now_iso8601(),
        })
    }

    /// The `anchor_queue.jsonl` path this queue was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The transport a driver needs: submit a digest, check its durable
/// inclusion status. `AnchorClient` implements this directly; tests supply
/// a fake so the state machine is exercised without a network dependency.
pub trait AnchorTransport {
    fn submit(&self, capsule_id: &str) -> Result<AnchorReceipt, AnchorError>;
    fn confirm(&self, capsule_id: &str) -> Result<Option<InclusionProof>, AnchorError>;
}

impl AnchorTransport for AnchorClient {
    fn submit(&self, capsule_id: &str) -> Result<AnchorReceipt, AnchorError> {
        self.post_digest(capsule_id)
    }

    fn confirm(&self, capsule_id: &str) -> Result<Option<InclusionProof>, AnchorError> {
        self.check_inclusion(capsule_id)
    }
}

#[derive(Debug, Default)]
pub struct DriveReport {
    pub submitted: Vec<String>,
    pub anchored: Vec<String>,
    pub rejected: Vec<String>,
    pub failed: Vec<String>,
}

/// One pass over the queue: attempt submission for everything `retryable`,
/// then check durable inclusion for everything `awaiting_confirmation`.
/// Never panics on a transport error -- every outcome (including a repeat
/// failure) is written durably into the queue via one of the `record_*`
/// calls before this returns, so the NEXT `drive_once` (possibly after a
/// restart) picks up exactly where this one left off.
pub fn drive_once(
    transport: &impl AnchorTransport,
    queue: &mut AnchorQueue,
) -> Result<DriveReport, QueueError> {
    let mut report = DriveReport::default();

    for capsule_id in queue.retryable() {
        match transport.submit(&capsule_id) {
            Ok(receipt) => {
                queue.record_submitted(&capsule_id, receipt)?;
                report.submitted.push(capsule_id);
            }
            Err(err) if err.is_retryable() => {
                queue.record_failed(&capsule_id, err.to_string())?;
                report.failed.push(capsule_id);
            }
            Err(err) => {
                queue.record_rejected(&capsule_id, err.to_string())?;
                report.rejected.push(capsule_id);
            }
        }
    }

    for capsule_id in queue.awaiting_confirmation() {
        match transport.confirm(&capsule_id) {
            Ok(Some(_proof)) => {
                queue.record_anchored(&capsule_id)?;
                report.anchored.push(capsule_id);
            }
            Ok(None) => {} // not yet durable; leave as `submitted`, check again next pass
            Err(_) => {}   // confirmation check failed; submission itself still stands
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    fn fake_receipt(capsule_id: &str) -> AnchorReceipt {
        AnchorReceipt {
            receipt_b64: format!("receipt-for-{capsule_id}"),
            entry_hash: capsule_id.to_string(),
            entry_hash_scheme: None,
            leaf_index: 0,
            tree_size: 1,
            checkpoint_witness: None,
        }
    }

    /// Scripted transport: each call to `submit`/`confirm` for a given
    /// `capsule_id` pops the next scripted outcome for that id. Lets tests
    /// drive multi-attempt sequences (fail then succeed, reject outright,
    /// submitted-but-not-yet-included) without any network dependency.
    type SubmitScript = RefCell<HashMap<String, VecDeque<Result<AnchorReceipt, AnchorError>>>>;
    type ConfirmScript =
        RefCell<HashMap<String, VecDeque<Result<Option<InclusionProof>, AnchorError>>>>;

    #[derive(Default)]
    struct FakeTransport {
        submit_script: SubmitScript,
        confirm_script: ConfirmScript,
    }

    impl FakeTransport {
        fn script_submit(&self, capsule_id: &str, outcome: Result<AnchorReceipt, AnchorError>) {
            self.submit_script
                .borrow_mut()
                .entry(capsule_id.to_string())
                .or_default()
                .push_back(outcome);
        }

        fn script_confirm(
            &self,
            capsule_id: &str,
            outcome: Result<Option<InclusionProof>, AnchorError>,
        ) {
            self.confirm_script
                .borrow_mut()
                .entry(capsule_id.to_string())
                .or_default()
                .push_back(outcome);
        }
    }

    impl AnchorTransport for FakeTransport {
        fn submit(&self, capsule_id: &str) -> Result<AnchorReceipt, AnchorError> {
            self.submit_script
                .borrow_mut()
                .get_mut(capsule_id)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("no scripted submit outcome for {capsule_id}"))
        }

        fn confirm(&self, capsule_id: &str) -> Result<Option<InclusionProof>, AnchorError> {
            self.confirm_script
                .borrow_mut()
                .get_mut(capsule_id)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("no scripted confirm outcome for {capsule_id}"))
        }
    }

    fn inclusion_proof(capsule_id: &str) -> InclusionProof {
        InclusionProof {
            capsule_id: capsule_id.to_string(),
            entry_hash: capsule_id.to_string(),
            leaf_index: 0,
            tree_size: 1,
            leaf_hash: "leaf".to_string(),
            audit_path: vec![],
            root_hash: "root".to_string(),
            receipt_b64: format!("receipt-for-{capsule_id}"),
        }
    }

    #[test]
    fn fresh_queue_has_no_tracked_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (queue, report) = AnchorQueue::open(dir.path()).unwrap();
        assert_eq!(report.valid_events, 0);
        assert!(queue.state_of("anything").is_none());
        assert!(queue.retryable().is_empty());
    }

    #[test]
    fn enqueue_is_idempotent_and_starts_pending() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        queue.enqueue("c1").unwrap();
        assert_eq!(queue.state_of("c1"), Some(AnchorState::Pending));
        assert_eq!(queue.entry("c1").unwrap().attempts, 0);

        // Re-enqueuing an already-tracked id must not reset it.
        queue.record_failed("c1", "boom".to_string()).unwrap();
        queue.enqueue("c1").unwrap();
        assert_eq!(queue.state_of("c1"), Some(AnchorState::Failed));
        assert_eq!(queue.entry("c1").unwrap().attempts, 1);
    }

    #[test]
    fn drive_once_covers_all_five_states() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        for id in ["pending-then-anchored", "transient-then-ok", "rejected", "stuck-failed", "submitted-unconfirmed"] {
            queue.enqueue(id).unwrap();
        }

        let transport = FakeTransport::default();
        // pending-then-anchored: submits clean, then confirms included.
        transport.script_submit("pending-then-anchored", Ok(fake_receipt("pending-then-anchored")));
        transport.script_confirm(
            "pending-then-anchored",
            Ok(Some(inclusion_proof("pending-then-anchored"))),
        );
        // transient-then-ok: fails once (5xx), retried and succeeds on pass 2.
        transport.script_submit(
            "transient-then-ok",
            Err(AnchorError::Status { status: 503, body: "busy".into() }),
        );
        transport.script_submit("transient-then-ok", Ok(fake_receipt("transient-then-ok")));
        transport.script_confirm("transient-then-ok", Ok(None)); // not yet durable after pass 1's submit... (unused if not submitted yet)
        // rejected: 4xx, must not be retried.
        transport.script_submit(
            "rejected",
            Err(AnchorError::Status { status: 400, body: "malformed".into() }),
        );
        // stuck-failed: transport error every time -- stays failed/retryable.
        transport.script_submit("stuck-failed", Err(AnchorError::Transport("down".into())));
        transport.script_submit("stuck-failed", Err(AnchorError::Transport("still down".into())));
        transport.script_submit("stuck-failed", Err(AnchorError::Transport("still down 2".into())));
        // submitted-unconfirmed: submits ok, confirmation stays pending across all 3 passes.
        transport.script_submit("submitted-unconfirmed", Ok(fake_receipt("submitted-unconfirmed")));
        transport.script_confirm("submitted-unconfirmed", Ok(None));
        transport.script_confirm("submitted-unconfirmed", Ok(None));
        transport.script_confirm("submitted-unconfirmed", Ok(None));

        // --- pass 1 ---
        let report1 = drive_once(&transport, &mut queue).unwrap();
        assert!(report1.submitted.contains(&"pending-then-anchored".to_string()));
        // transient-then-ok's FIRST scripted outcome is a 503 -- this pass
        // it lands in `failed`, not `submitted` (that's pass 2).
        assert!(report1.failed.contains(&"transient-then-ok".to_string()));
        assert!(report1.submitted.contains(&"submitted-unconfirmed".to_string()));
        assert!(report1.rejected.contains(&"rejected".to_string()));
        assert!(report1.failed.contains(&"stuck-failed".to_string()));
        assert_eq!(queue.state_of("rejected"), Some(AnchorState::Rejected));
        assert_eq!(queue.state_of("transient-then-ok"), Some(AnchorState::Failed));
        assert_eq!(queue.state_of("stuck-failed"), Some(AnchorState::Failed));

        // pending-then-anchored was submitted THIS pass; its confirm() was
        // scripted and gets consumed on this same pass (submitted -> awaiting confirm loop runs after submit loop).
        assert_eq!(queue.state_of("pending-then-anchored"), Some(AnchorState::Anchored));
        assert_eq!(queue.state_of("submitted-unconfirmed"), Some(AnchorState::Submitted));

        // --- pass 2: stuck-failed retried again (fails again); transient-then-ok retried (succeeds) ---
        let report2 = drive_once(&transport, &mut queue).unwrap();
        assert!(report2.submitted.contains(&"transient-then-ok".to_string()));
        assert!(report2.failed.contains(&"stuck-failed".to_string()));

        // Rejected must NEVER have been retried -- it wasn't in retryable().
        assert_eq!(queue.entry("rejected").unwrap().attempts, 1);

        // Now confirm the previously-submitted-and-not-yet-included ones.
        transport.script_confirm("transient-then-ok", Ok(Some(inclusion_proof("transient-then-ok"))));
        let report3 = drive_once(&transport, &mut queue).unwrap();
        assert!(report3.anchored.contains(&"transient-then-ok".to_string()));

        // All five states observed across the run:
        assert_eq!(queue.state_of("pending-then-anchored"), Some(AnchorState::Anchored));
        assert_eq!(queue.state_of("transient-then-ok"), Some(AnchorState::Anchored));
        assert_eq!(queue.state_of("rejected"), Some(AnchorState::Rejected));
        assert_eq!(queue.state_of("stuck-failed"), Some(AnchorState::Failed));
        assert_eq!(queue.state_of("submitted-unconfirmed"), Some(AnchorState::Submitted));
    }

    #[test]
    fn queue_survives_restart_kill_after_a_clean_failed_write() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        queue.enqueue("c1").unwrap();
        queue.record_failed("c1", "simulated transient error".to_string()).unwrap();
        // "Kill": drop without any further writes.
        drop(queue);

        let (queue2, report) = AnchorQueue::open(dir.path()).unwrap();
        assert_eq!(report.valid_events, 2); // enqueue + record_failed
        assert_eq!(queue2.state_of("c1"), Some(AnchorState::Failed));
        assert_eq!(queue2.entry("c1").unwrap().attempts, 1);
        assert!(queue2.retryable().contains(&"c1".to_string()));
    }

    #[test]
    fn queue_survives_a_kill_mid_write_torn_line() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        queue.enqueue("c1").unwrap();
        let path = queue.path().to_path_buf();
        drop(queue);

        // Simulate a kill -9 mid-append of the SECOND event (e.g. the
        // record_failed for a submit attempt in flight): a syntactically
        // truncated line with no trailing newline.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"capsule_id":"c1","state":"fail"#).unwrap();
        f.flush().unwrap();
        drop(f);

        let (mut queue2, report) = AnchorQueue::open(dir.path()).unwrap();
        assert!(report.truncated_torn_write_at.is_some());
        assert_eq!(report.valid_events, 1);
        // Reverts to the last FULLY durable state -- the enqueue, still
        // Pending -- not lost, not stuck in a phantom state.
        assert_eq!(queue2.state_of("c1"), Some(AnchorState::Pending));
        assert!(queue2.retryable().contains(&"c1".to_string()));

        // And the queue is usable again: the torn bytes didn't corrupt
        // anything, so a normal transition appends cleanly.
        queue2.record_failed("c1", "retry after kill".to_string()).unwrap();
        assert_eq!(queue2.state_of("c1"), Some(AnchorState::Failed));
        assert_eq!(
            queue2.entry("c1").unwrap().last_detail.as_deref(),
            Some("retry after kill")
        );

        // The file itself was actually truncated on disk: exactly the
        // original `enqueue` line plus the new clean `record_failed` line,
        // no leftover torn fragment in between.
        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "torn fragment must not survive as a line: {contents:?}");
    }

    #[test]
    fn tampered_terminated_line_is_a_hard_error_not_a_silent_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        queue.enqueue("c1").unwrap();
        let path = queue.path().to_path_buf();
        drop(queue);

        let contents = fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("\"pending\"", "\"not_a_real_state\"");
        assert_ne!(contents, tampered);
        fs::write(&path, tampered).unwrap();

        let err = AnchorQueue::open(dir.path()).unwrap_err();
        assert!(matches!(err, QueueError::CorruptLine { .. }));
    }

    #[test]
    fn rejected_is_never_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (mut queue, _) = AnchorQueue::open(dir.path()).unwrap();
        queue.enqueue("c1").unwrap();
        queue.record_rejected("c1", "malformed capsule_id".to_string()).unwrap();
        assert!(!queue.retryable().contains(&"c1".to_string()));
        assert!(!queue.awaiting_confirmation().contains(&"c1".to_string()));
    }
}
