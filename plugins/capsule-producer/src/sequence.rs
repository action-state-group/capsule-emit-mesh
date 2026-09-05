//! Per-`(self, counterparty)` monotone capsule sequencing (history proposal
//! §1: continuity is bilateral only). Every sealed capsule carries `seq` and
//! `prev_seq` for the pair it was sealed under, so a verifier can later check
//! that pair's stream for gaps (missing records) or regressions (a `seq`
//! that repeats or goes backward) WITHOUT trusting anything this node did
//! not itself sign.
//!
//! [`SequenceCounterStore`] is a WRITE-SIDE convenience cache, not the source
//! of truth. It is persisted in a small JSON file beside the ledger
//! (`<data_dir>/sequence_counters.json`) purely so a restarted node resumes
//! counting from where it left off instead of starting every pair back at
//! 1 — which would itself look like a reset to a verifier. But the cache is
//! not trusted for continuity: the actual check (mirrored in the Python
//! `sequence_counter.verify_pair_continuity`) walks the SEALED capsules
//! themselves in ledger order. A wiped or hand-edited cache file makes this
//! node issue `seq=1` again for a pair that already has higher `seq` values
//! in the ledger; the verifier catches that regression from the capsule
//! stream alone and reports it as a broken pair, never a fresh start.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Never invent a counterparty identity: `""`/missing collapses to this
/// explicit, honest bucket rather than a fabricated node id.
pub const UNKNOWN_COUNTERPARTY: &str = "unknown";

/// Canonical `(self, counterparty)` key. `counterparty_id` empty or absent
/// (the caller passes `""`) collapses to [`UNKNOWN_COUNTERPARTY`] -- never
/// fabricated, but still a real, stable bucket a verifier can reason about.
pub fn pair_key(self_id: &str, counterparty_id: &str) -> String {
    let counterparty = if counterparty_id.is_empty() {
        UNKNOWN_COUNTERPARTY
    } else {
        counterparty_id
    };
    format!("{self_id}::{counterparty}")
}

#[derive(Debug, thiserror::Error)]
pub enum SequenceError {
    #[error("I/O error persisting sequence counters: {0}")]
    Io(#[from] std::io::Error),
}

/// The `(seq, prev_seq)` pair issued for one capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceAssignment {
    pub seq: u64,
    pub prev_seq: Option<u64>,
}

/// Persists the last-issued `seq` per `(self, counterparty)` pair beside the
/// ledger. See the module docstring for why this cache is never the source
/// of truth for continuity.
pub struct SequenceCounterStore {
    path: PathBuf,
    state: BTreeMap<String, u64>,
}

impl SequenceCounterStore {
    /// Opens (or, on first run / a missing or corrupt file, starts empty --
    /// never fails the caller over a counter cache) the store at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let state = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BTreeMap<String, u64>>(&bytes).ok())
            .unwrap_or_default();
        Self { path, state }
    }

    /// Issues the next `seq` for `(self_id, counterparty_id)`, returning it
    /// alongside the pair's previous `seq` (`None` the first time this store
    /// has seen the pair).
    pub fn next_seq(
        &mut self,
        self_id: &str,
        counterparty_id: &str,
    ) -> Result<SequenceAssignment, SequenceError> {
        let key = pair_key(self_id, counterparty_id);
        let prev_seq = self.state.get(&key).copied();
        let seq = prev_seq.unwrap_or(0) + 1;
        self.state.insert(key, seq);
        self.save()?;
        Ok(SequenceAssignment { seq, prev_seq })
    }

    fn save(&self) -> Result<(), SequenceError> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&self.state).expect("counters serialize"))?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// A generic (self, counterparty, seq, prev_seq) view a caller extracts from
/// one sealed capsule, decoupled from any one language's capsule shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PairSeq<'a> {
    pub self_id: &'a str,
    pub counterparty_id: &'a str,
    pub seq: u64,
    pub prev_seq: Option<u64>,
}

/// Per-pair continuity finding. `continuity` mirrors the `history_card`
/// convention (`"unbroken"` / `"broken at seq=<N>: <reason>"`) -- a
/// REGRESSION (a `seq` at or below one already seen for the pair, which can
/// only mean a reset or forgery, never a legitimate fresh start). A pure
/// GAP (missing records, `seq` jumping forward by more than one) is softer:
/// it increments `gaps_detected`, a labeled count, and never a score, and
/// does NOT by itself mark the pair broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairContinuity {
    pub pair: String,
    pub continuity: String,
    pub gaps_detected: u64,
    pub records_checked: u64,
}

/// Walks `records` IN THE ORDER GIVEN (ledger/bundle order -- never
/// re-sorted, so an out-of-order delivery reads as a gap, not silently
/// repaired) and reports [`PairContinuity`] per pair.
///
/// `prev_seq` is READ, not just carried, in two ways:
///
/// - **Self-consistency**: a record's own `(seq, prev_seq)` must match what
///   [`SequenceCounterStore::next_seq`] would have issued -- `prev_seq` is
///   `None` iff `seq == 1`, else `prev_seq == seq - 1`. A record that
///   violates this alone (a lying `prev_seq`, unrelated to whatever came
///   before it in this walk) is `broken`, never silently `unbroken`.
/// - **First-sighted-record check**: the first record this walk sees for a
///   pair must itself claim `prev_seq: None` (a true genesis). One that
///   claims a predecessor reveals the pair's PREFIX was dropped from what
///   we were handed; every record from seq=1 up to that claimed `prev_seq`
///   is counted as a gap rather than treated as an untroubled fresh start.
///
/// Neither check can reveal a dropped TRAIL -- a pair simply stopping
/// mid-ledger looks identical to a pair whose last real exchange happened
/// to be the most recent one. Catching that requires an outside anchor:
/// pass `checkpoint_covered_count`, the number of pair-sequenced records a
/// checkpoint over this same range attests to have existed. Fewer records
/// actually walked than that count means the range we were handed is
/// incomplete, and every pair's continuity in it is reported `broken`
/// rather than a false `unbroken` built on a silently truncated view.
pub fn verify_pair_continuity(
    records: &[PairSeq],
    checkpoint_covered_count: Option<u64>,
) -> BTreeMap<String, PairContinuity> {
    let mut last_seq: BTreeMap<String, u64> = BTreeMap::new();
    let mut gaps: BTreeMap<String, u64> = BTreeMap::new();
    let mut broken: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();

    for record in records {
        let key = pair_key(record.self_id, record.counterparty_id);
        *counts.entry(key.clone()).or_insert(0) += 1;
        let prior = last_seq.get(&key).copied();

        let self_consistent = match record.prev_seq {
            None => record.seq <= 1,
            Some(prev_seq) => record.seq >= 1 && prev_seq == record.seq - 1,
        };
        if !self_consistent {
            broken.entry(key.clone()).or_insert_with(|| {
                format!(
                    "broken at seq={}: prev_seq={:?} does not precede it",
                    record.seq, record.prev_seq
                )
            });
        }

        match (prior, record.prev_seq) {
            (None, Some(prev_seq)) => {
                // First record this walk has seen for the pair, but it
                // claims a predecessor we never saw -- the prefix was
                // dropped.
                *gaps.entry(key.clone()).or_insert(0) += prev_seq;
            }
            (Some(prior), _) => {
                if record.seq <= prior {
                    broken.entry(key.clone()).or_insert_with(|| {
                        format!(
                            "broken at seq={}: not greater than prior seq={prior}",
                            record.seq
                        )
                    });
                } else if record.seq > prior + 1 {
                    *gaps.entry(key.clone()).or_insert(0) += record.seq - prior - 1;
                }
            }
            (None, None) => {}
        }

        let entry = last_seq.entry(key).or_insert(0);
        *entry = (*entry).max(record.seq);
    }

    let total_checked: u64 = counts.values().sum();
    let truncated = checkpoint_covered_count.is_some_and(|expected| total_checked < expected);

    counts
        .into_iter()
        .map(|(key, records_checked)| {
            let continuity = broken.get(&key).cloned().unwrap_or_else(|| {
                if truncated {
                    format!(
                        "broken: checkpoint covers {} pair-sequenced records but only {total_checked} were presented",
                        checkpoint_covered_count.unwrap()
                    )
                } else {
                    "unbroken".to_string()
                }
            });
            let gaps_detected = gaps.get(&key).copied().unwrap_or(0);
            (
                key.clone(),
                PairContinuity {
                    pair: key,
                    continuity,
                    gaps_detected,
                    records_checked,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_seq_starts_at_one_and_increments_per_pair() {
        let dir = std::env::temp_dir().join(format!("seq-basic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut store = SequenceCounterStore::open(dir.join("sequence_counters.json"));

        let a1 = store.next_seq("node-a", "node-b").unwrap();
        assert_eq!(a1, SequenceAssignment { seq: 1, prev_seq: None });
        let a2 = store.next_seq("node-a", "node-b").unwrap();
        assert_eq!(a2, SequenceAssignment { seq: 2, prev_seq: Some(1) });

        // A different counterparty is an independent counter starting at 1.
        let b1 = store.next_seq("node-a", "node-c").unwrap();
        assert_eq!(b1, SequenceAssignment { seq: 1, prev_seq: None });

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_counterparty_collapses_to_unknown_bucket_never_invented() {
        assert_eq!(pair_key("node-a", ""), "node-a::unknown");
        assert_eq!(pair_key("node-a", "node-b"), "node-a::node-b");
    }

    #[test]
    fn counter_state_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("seq-persist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sequence_counters.json");

        {
            let mut store = SequenceCounterStore::open(&path);
            store.next_seq("node-a", "node-b").unwrap();
            store.next_seq("node-a", "node-b").unwrap();
        }
        // Reopen from disk -- a restarted node must resume at 3, not repeat 1.
        let mut reopened = SequenceCounterStore::open(&path);
        let resumed = reopened.next_seq("node-a", "node-b").unwrap();
        assert_eq!(resumed, SequenceAssignment { seq: 3, prev_seq: Some(2) });

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_pair_continuity_reports_unbroken_for_a_clean_sequence() {
        let records = vec![
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 2, prev_seq: Some(1) },
        ];
        let result = verify_pair_continuity(&records, None);
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert_eq!(pair.continuity, "unbroken");
        assert_eq!(pair.gaps_detected, 0);
        assert_eq!(pair.records_checked, 2);
    }

    /// Dropping one record from a bundle (e.g. seq 1,2,3 delivered as 1,3)
    /// is a labeled GAP, not a break -- the stream is still monotone, just
    /// incomplete as delivered.
    #[test]
    fn verify_pair_continuity_labels_a_dropped_record_as_a_gap_not_broken() {
        let records = vec![
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 3, prev_seq: Some(2) },
        ];
        let result = verify_pair_continuity(&records, None);
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert_eq!(pair.continuity, "unbroken");
        assert_eq!(pair.gaps_detected, 1);
    }

    /// A reset counter (or forged capsule) that reissues `seq=1` after the
    /// pair already reached `seq=2` in the ledger is a REGRESSION -- the
    /// verifier must flag it broken, never accept it as a fresh start.
    #[test]
    fn verify_pair_continuity_flags_a_reset_as_broken_not_a_fresh_start() {
        let records = vec![
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 2, prev_seq: Some(1) },
            // Counter file wiped; sealing resumed as if this were a new pair.
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
        ];
        let result = verify_pair_continuity(&records, None);
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert!(
            pair.continuity.starts_with("broken"),
            "expected a broken continuity report, got {:?}",
            pair.continuity
        );
    }

    /// ADV-5: dropping the PREFIX (records 1..N-1) leaves the walk seeing
    /// only the tail record, whose own `prev_seq` still claims a
    /// predecessor. That claim must surface as a gap, never a clean,
    /// untroubled fresh start.
    #[test]
    fn verify_pair_continuity_detects_a_dropped_prefix_via_first_record_prev_seq() {
        let records = vec![PairSeq { self_id: "m4", counterparty_id: "m3", seq: 4, prev_seq: Some(3) }];
        let result = verify_pair_continuity(&records, None);
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert_eq!(pair.continuity, "unbroken");
        assert_eq!(pair.gaps_detected, 3, "records 1..3 were never seen and must count as a gap");
    }

    /// ADV-5: a record whose `prev_seq` does not actually precede its own
    /// `seq` (a lying `prev_seq`, unrelated to what `next_seq` would ever
    /// issue) must be flagged broken even though `seq` alone still looks
    /// monotone.
    #[test]
    fn verify_pair_continuity_flags_a_lying_prev_seq_as_broken() {
        let records = vec![
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
            // Honest seq (2, monotone) but a fabricated prev_seq.
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 2, prev_seq: Some(99) },
        ];
        let result = verify_pair_continuity(&records, None);
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert!(
            pair.continuity.starts_with("broken"),
            "expected a broken continuity report, got {:?}",
            pair.continuity
        );
    }

    /// ADV-5: dropping the TRAIL (the last record of a pair) is invisible
    /// to any in-band check -- nothing in the delivered records hints a
    /// further one ever existed. Only an outside anchor (a checkpoint
    /// attesting to the true covered count) can catch it.
    #[test]
    fn verify_pair_continuity_detects_a_dropped_trail_via_checkpoint_cross_check() {
        let records = vec![
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 1, prev_seq: None },
            PairSeq { self_id: "m4", counterparty_id: "m3", seq: 2, prev_seq: Some(1) },
            // seq=3, the pair's true last record, was dropped from delivery.
        ];
        let result = verify_pair_continuity(&records, Some(3));
        let pair = result.get(&pair_key("m4", "m3")).unwrap();
        assert!(
            pair.continuity.starts_with("broken"),
            "expected a broken continuity report, got {:?}",
            pair.continuity
        );

        // The same records with no checkpoint anchor, or one that matches
        // what was actually delivered, are honestly unbroken.
        let honest = verify_pair_continuity(&records, Some(2));
        assert_eq!(honest.get(&pair_key("m4", "m3")).unwrap().continuity, "unbroken");
        let unanchored = verify_pair_continuity(&records, None);
        assert_eq!(unanchored.get(&pair_key("m4", "m3")).unwrap().continuity, "unbroken");
    }
}
