//! "Asked of you": this node's own log of the requests other nodes made of
//! it, and what it answered. The provider's half of the double entry; the
//! Evidence page's drill reads it (`evidence_panes::read_received_log`).
//!
//! The same file and line shape the Python door wrote
//! (`evidence_server._append_received_log`): `received_log.jsonl`, one
//! `{ts, path, requester_id, subject_kind, status, reason}` object per line,
//! in the directory `evidence_routes::EvidenceSource::received_log_dir`
//! resolves. **Opt-in, as before:** nothing is written unless that directory
//! exists. Never the ledger directory: this log is not evidence.
//!
//! **Best-effort.** An answer is decided before it is logged, and a logging
//! failure never changes it.
//!
//! **Bounded.** The requester's id is its own word, so it is cut to
//! [`MAX_REQUESTER_ID_CHARS`] characters, and a line is never longer than
//! the few fields it names.

use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

pub const RECEIVED_LOG_FILE: &str = "received_log.jsonl";

/// The longest self-declared requester id kept, in characters.
pub const MAX_REQUESTER_ID_CHARS: usize = 128;

/// One line: what was asked, by whom (as they said), and the outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub ts: &'a str,
    /// The route asked: `evidence-request`, `evidence/record-push`.
    pub path: &'a str,
    pub requester_id: Option<&'a str>,
    pub subject_kind: Option<&'a str>,
    /// `answered`, `refused`, `received` or `issued`.
    pub status: &'a str,
    pub reason: Option<&'a str>,
}

impl Entry<'_> {
    pub fn to_json(&self) -> Value {
        json!({
            "ts": self.ts,
            "path": self.path,
            "requester_id": self.requester_id.map(|id| id.chars().take(MAX_REQUESTER_ID_CHARS).collect::<String>()),
            "subject_kind": self.subject_kind,
            "status": self.status,
            "reason": self.reason,
        })
    }
}

/// Append `entry` to `<dir>/received_log.jsonl` when `dir` is given and
/// exists. Failures are logged and swallowed.
pub fn append(dir: Option<&Path>, entry: &Entry<'_>) {
    let Some(dir) = dir.filter(|d| d.is_dir()) else {
        return;
    };
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(RECEIVED_LOG_FILE))
        .and_then(|mut file| writeln!(file, "{}", entry.to_json()));
    if let Err(error) = result {
        tracing::warn!(%error, "could not append to the received log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry<'static> {
        Entry {
            ts: "2026-09-29T00:00:00Z",
            path: "evidence-request",
            requester_id: Some("m3"),
            subject_kind: Some("record"),
            status: "refused",
            reason: Some("no_such_subject"),
        }
    }

    #[test]
    fn a_line_is_what_the_evidence_page_reads() {
        let dir = tempfile::tempdir().unwrap();
        append(Some(dir.path()), &entry());
        let read = crate::evidence_panes::read_received_log(dir.path());
        assert_eq!(read, vec![entry().to_json()]);
    }

    #[test]
    fn nothing_is_written_without_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("received-log");
        append(Some(&missing), &entry());
        append(None, &entry());
        assert!(!missing.exists());
    }

    #[test]
    fn a_requester_id_is_cut_to_the_limit() {
        let long = "x".repeat(10_000);
        let e = Entry { requester_id: Some(&long), ..entry() };
        assert_eq!(e.to_json()["requester_id"].as_str().unwrap().len(), MAX_REQUESTER_ID_CHARS);
    }
}
