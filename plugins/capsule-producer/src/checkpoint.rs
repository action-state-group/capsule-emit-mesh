//! Layer 1-2 checkpointing over this crate's own ledger (`ledger.rs`'s
//! `<ledger_dir>/capsules.jsonl`): an append-only MMR over `capsule_id`
//! leaves, a periodic signed checkpoint, and (opt-in) witness registration.
//!
//! This is the Rust re-expression of `capsule-emit-mesh/checkpointing.py`'s
//! `CheckpointState` (see `docs/DESIGN-fold-sidecar-into-plugin.md` and
//! `[mesh-plugin-checkpoint-cadence]`) over the primitives the `cll` crate
//! (`checkpointed-local-log`, `rust/cll`, pinned by git tag) now provides:
//! `cll::mmr` (the MMR algorithm + node storage traits), `cll::node_store`
//! (the durable file-backed node store), `cll::checkpoint` (the signed
//! `CheckpointRecord` + COSE wire form, via the `CheckpointSigner` SPI —
//! see that module's doc comment), and `cll::store` (`checkpoints.jsonl`
//! read/write, the exact on-disk shape `checkpointing.py` also reads/writes,
//! so a Rust checkpointer and `checkpoint_daemon.py` share one file).
//!
//! **Durable node store, unlike the Python reference.** `checkpointing.py`'s
//! `MmrLedger` is always in-memory (`MemoryNodeStore`), rebuilt from
//! `capsules.jsonl` on every process start — fine for a short-lived daemon
//! process, wrong for a long-running plugin. This module instead persists
//! MMR node hashes to `<ledger_dir>/mmr_nodes.dat` (`cll::node_store::
//! FileNodeStore`) — a Rust-only file with no Python counterpart — so a
//! restart re-hashes only the leaves appended since the last clean stop, not
//! the whole ledger. The resulting MMR content (roots, peaks, proofs) is
//! identical either way; only how it gets there differs.
//!
//! **Policy is a straight port of `checkpoint_daemon.py`/`checkpointing.py`'s
//! `CheckpointState`:** age clock measured from the FIRST unwitnessed entry
//! (never from the last checkpoint, and never while the log is caught up —
//! only-if-new-activity), shutdown flush, best-effort witness retry (an
//! unreachable witness never blocks local checkpointing). See `tick`/
//! `reconnect`/`checkpoint_on_shutdown`/`retry_pending_witnesses` below.
//!
//! **Signing goes only through `cll::checkpoint::CheckpointSigner`** (the
//! v0.2.0 signer SPI) — this module never calls `ed25519_dalek::Signer`
//! directly, so the caller's already-loaded node key
//! (`capsule_producer::keys::KeyPair::signing_key`, an `ed25519_dalek::
//! SigningKey`, which implements `CheckpointSigner`) is reused as-is, never
//! a second, plugin-minted key.

use crate::anchor::{dispatch_base_for, AnchorClient};
// Re-exported (not just `use`d) so a caller depending on this crate --
// admission-policy's checkpoint cadence task -- can name `CheckpointRecord`
// and `CheckpointSigner` without adding `cll` as its own direct dependency.
pub use cll::checkpoint::{CheckpointRecord, CheckpointSigner};
use cll::checkpoint::{
    checkpoint_to_cose, try_sign_checkpoint_digest, CheckpointError as CllCheckpointError,
    SignerError, WitnessRecord as CheckpointWitness,
};
use cll::mmr::{
    add_leaf, consistency_proof, inclusion_proof, leaf_count as mmr_leaf_count, leaf_hash,
    leaf_index_to_pos, peaks, root_from_peaks, ConsistencyProof, Hash, MmrError, NodeReader,
    DIGEST_LEN,
};
// Re-exported for the same reason as `CheckpointRecord`: the push-a-bundle
// sender names the proof type without a direct `cll` dependency.
pub use cll::mmr::{verify_inclusion, InclusionProof};
use cll::node_store::{FileNodeStore, NodeStoreError, OpenReport};
use cll::store::{append_checkpoint, read_last_checkpoint, CheckpointLine, StoreError};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointStateError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("node store error: {0}")]
    NodeStore(#[from] NodeStoreError),
    #[error("checkpoints.jsonl error: {0}")]
    Store(#[from] StoreError),
    #[error("mmr error: {0}")]
    Mmr(#[from] MmrError),
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CllCheckpointError),
    #[error("signer error: {0}")]
    Signer(#[from] SignerError),
    #[error(
        "durable node store at {path} indexes {stored_leaves} leaves but capsules.jsonl only has \
         {ledger_leaves} -- the node store is AHEAD of the ledger it is meant to index; refusing \
         to trust it rather than checkpoint a possibly-fabricated MMR state"
    )]
    NodeStoreAheadOfLedger {
        path: String,
        stored_leaves: u64,
        ledger_leaves: u64,
    },
    #[error(
        "durable node store leaf {leaf_index} is {stored_leaf} but capsules.jsonl's capsule_id at \
         that index ({capsule_id}) leaf-hashes to {expected_leaf} -- the chain has been REWRITTEN \
         under the node store (e.g. a migration/backfill that edited capsules.jsonl without \
         rebuilding mmr_nodes.dat); refusing to checkpoint a commitment over superseded leaves"
    )]
    NodeStoreDivergedFromLedger {
        leaf_index: u64,
        capsule_id: String,
        stored_leaf: String,
        expected_leaf: String,
    },
    #[error("capsules.jsonl line {line}: not valid JSON: {source}")]
    MalformedLine {
        line: usize,
        source: serde_json::Error,
    },
    #[error("capsules.jsonl line {line}: missing or non-string capsule_id field")]
    MissingCapsuleId { line: usize },
    #[error(
        "capsules.jsonl line {line}: capsule_id {capsule_id:?} is not {DIGEST_LEN} bytes of hex"
    )]
    BadCapsuleId { line: usize, capsule_id: String },
    #[error("cannot checkpoint an empty MMR (no leaves appended yet)")]
    EmptyMmr,
    #[error(
        "MMR size {current_size} is not greater than the previous checkpoint's size {prev_size} \
         -- monotonicity violated"
    )]
    RollbackSize { current_size: u64, prev_size: u64 },
    #[error(
        "MMR root at the previous checkpoint's size ({prev_size}) is {actual_root} but that \
         checkpoint recorded root {recorded_root} -- the log has been mutated since"
    )]
    RollbackRoot {
        prev_size: u64,
        actual_root: String,
        recorded_root: String,
    },
    #[error("capsule_id {capsule_id} is not in capsules.jsonl -- nothing to cover")]
    CapsuleNotInLedger { capsule_id: String },
}

/// What [`CheckpointState::checkpoint_covering`] hands the push-a-bundle
/// sender: the signed checkpoint covering one leaf, that leaf's index, and
/// its inclusion proof against the checkpoint's `mmr_size`.
#[derive(Debug, Clone)]
pub struct Coverage {
    pub checkpoint: CheckpointRecord,
    pub leaf_index: u64,
    pub proof: InclusionProof,
    /// `true` when this call cut a new checkpoint, `false` when an existing
    /// one already covered the leaf (the coalescing case).
    pub cut_new: bool,
}

/// The wire JSON of an inclusion proof -- the exact field set
/// `scitt_cose.cll.InclusionProof.from_dict` reads.
pub fn inclusion_proof_json(proof: &InclusionProof) -> serde_json::Value {
    serde_json::json!({
        "v": proof.v,
        "kind": proof.kind,
        "size": proof.size,
        "leaf_index": proof.leaf_index,
        "witness": proof.witness,
        "peaks_left": proof.peaks_left,
        "peaks_right": proof.peaks_right,
    })
}

/// Cadence/witness policy -- the fields of `checkpointing.py`'s use of
/// `capsule_emit.checkpoint.CheckpointConfig` this module actually acts on
/// (age + entry-count cadence; opt-in witness URLs).
#[derive(Debug, Clone)]
pub struct CheckpointCadenceConfig {
    pub cadence_entries: u64,
    pub cadence_seconds: u64,
    /// Witness registration is OPT-IN, always (this repo's posture) --
    /// empty means self-checkpointed only, no network. Matches
    /// `checkpoint_daemon.py`'s `--ts-url`/`--witness` flags.
    pub witness_urls: Vec<String>,
}

impl Default for CheckpointCadenceConfig {
    /// Matches `checkpoint_daemon.py`'s `DEFAULT_INTERVAL_SECONDS` (300s --
    /// tighter than upstream `capsule_emit`'s own 900s default) and
    /// `capsule_emit.checkpoint.CheckpointConfig`'s `cadence_entries=100`.
    fn default() -> Self {
        Self {
            cadence_entries: 100,
            cadence_seconds: 300,
            witness_urls: Vec::new(),
        }
    }
}

/// True once `entries_since_last` reaches `cfg.cadence_entries`, or
/// `seconds_since_last` reaches `cfg.cadence_seconds` -- whichever comes
/// first. The age leg only ever applies with at least one unwitnessed entry:
/// `entries_since_last == 0` is always `false`, regardless of age -- an idle
/// log stays silent, never a heartbeat. Byte-for-byte port of
/// `cll.checkpoint.emit.due_for_checkpoint`.
fn due_for_checkpoint(
    cfg: &CheckpointCadenceConfig,
    entries_since_last: u64,
    seconds_since_last: Option<f64>,
) -> bool {
    if entries_since_last == 0 {
        return false;
    }
    if entries_since_last >= cfg.cadence_entries {
        return true;
    }
    seconds_since_last.is_some_and(|s| s >= cfg.cadence_seconds as f64)
}

/// What `CheckpointState::load` found while opening the durable node store
/// and catching it up to `capsules.jsonl` -- surfaced so a caller can log a
/// recovered torn write or a from-scratch rebuild rather than have it
/// happen invisibly.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub node_store: Option<OpenReport>,
    pub leaves_indexed_this_load: u64,
}

/// A mesh node's Layer 1-2 state over one `ledger_dir`: an MMR over its own
/// `capsules.jsonl`, plus the periodic signed checkpoint and (optional)
/// witness registration. One instance per `ledger_dir` -- a node running
/// both a Python sidecar and this Rust plugin against different
/// `ledger_dir`s loads one `CheckpointState` per dir, same as
/// `checkpointing.py`'s own module doc describes.
pub struct CheckpointState {
    capsules_path: PathBuf,
    checkpoints_path: PathBuf,
    node_store: FileNodeStore,
    leaf_count: u64,
    log_id: String,
    cfg: CheckpointCadenceConfig,
    last_checkpoint: Option<CheckpointRecord>,
    last_checkpoint_cose: Option<Vec<u8>>,
    entries_since_checkpoint: u64,
    /// Instant of the FIRST currently-unwitnessed entry, or `None` when the
    /// log is fully caught up. Not restored across a restart (a monotonic
    /// `Instant` cannot be persisted meaningfully) -- an on-disk backlog at
    /// load time is treated as pending-as-of-now, matching
    /// `checkpointing.py`'s own `CheckpointState.load` docstring.
    pending_since: Option<Instant>,
    /// `witness_urls` from the last checkpoint's own registration attempt
    /// that have not yet succeeded.
    pending_witness_urls: Vec<String>,
    /// The latest checkpoint was cut at push time (see
    /// [`CheckpointState::checkpoint_covering`]) and has not been offered to
    /// a witness yet. Witness registration stays on the clock: the next
    /// [`CheckpointState::tick`] registers the LATEST checkpoint of the
    /// window once, never one registration per turn.
    witness_deferred: bool,
}

fn leaf_positions_and_hashes(
    reader: &impl NodeReader,
    size: u64,
) -> Result<Vec<Hash>, CheckpointStateError> {
    Ok(peaks(size)?.iter().map(|&p| reader.node(p)).collect())
}

/// Divergence guard: verify the
/// durable node store still commits to the SAME leaves `capsules.jsonl`
/// holds -- not just to the same COUNT of leaves. The count-only trust was
/// the hole the received-half backfill incident exposed: a migration rewrote
/// the chain (same length, different capsule_ids at the tail) under an
/// existing `mmr_nodes.dat`, the count-based sync saw "nothing new to fold",
/// and the next tick would have emitted a checkpoint whose root committed to
/// the PRE-migration leaves. Sibling of `NodeStoreAheadOfLedger`/the
/// Rollback guards: a hard, descriptive error, never a silent stale
/// commitment.
///
/// `full = true` checks every stored leaf against the chain (used once, at
/// `load` -- one 32-byte read + one leaf hash per entry, cheap for a plugin
/// ledger and the only chance to catch a mid-chain rewrite that preserves
/// the tail). `full = false` checks only the LAST stored leaf (used on
/// every `sync`, so the per-tick cost is one node read + one hash).
fn verify_stored_leaves_match_chain(
    store: &impl NodeReader,
    stored_leaf_count: u64,
    capsule_ids: &[String],
    full: bool,
) -> Result<(), CheckpointStateError> {
    if stored_leaf_count == 0 {
        return Ok(());
    }
    debug_assert!(stored_leaf_count as usize <= capsule_ids.len());
    let first = if full { 0 } else { stored_leaf_count - 1 };
    for leaf_index in first..stored_leaf_count {
        let capsule_id = &capsule_ids[leaf_index as usize];
        // read_capsule_ids already validated every id as DIGEST_LEN bytes
        // of hex; this cannot fail.
        let body_digest =
            hex_to_digest(capsule_id).expect("read_capsule_ids validates capsule_id hex");
        let expected_leaf = leaf_hash(&body_digest);
        let stored_leaf = store.node(leaf_index_to_pos(leaf_index)?);
        if stored_leaf != expected_leaf {
            return Err(CheckpointStateError::NodeStoreDivergedFromLedger {
                leaf_index,
                capsule_id: capsule_id.clone(),
                stored_leaf: hex::encode(stored_leaf),
                expected_leaf: hex::encode(expected_leaf),
            });
        }
    }
    Ok(())
}

impl CheckpointState {
    /// Load (or create) checkpoint state for `ledger_dir`: opens the durable
    /// node store at `<ledger_dir>/mmr_nodes.dat`, catches it up to
    /// `<ledger_dir>/capsules.jsonl` (hashing only leaves added since the
    /// store was last synced -- see the module doc), and resumes from
    /// `<ledger_dir>/checkpoints.jsonl`'s last line if present.
    pub fn load(
        ledger_dir: &Path,
        log_id: impl Into<String>,
        cfg: CheckpointCadenceConfig,
    ) -> Result<(Self, LoadReport), CheckpointStateError> {
        let capsules_path = ledger_dir.join("capsules.jsonl");
        let checkpoints_path = ledger_dir.join("checkpoints.jsonl");
        let node_store_path = ledger_dir.join("mmr_nodes.dat");

        let (mut node_store, open_report) = FileNodeStore::open(&node_store_path)?;
        let stored_leaf_count = mmr_leaf_count(node_store.size())?;

        let capsule_ids = read_capsule_ids(&capsules_path)?;
        if stored_leaf_count > capsule_ids.len() as u64 {
            return Err(CheckpointStateError::NodeStoreAheadOfLedger {
                path: node_store_path.display().to_string(),
                stored_leaves: stored_leaf_count,
                ledger_leaves: capsule_ids.len() as u64,
            });
        }
        // Full prefix check, once per process start: every leaf the durable
        // store already holds must still be the chain's capsule_id at that
        // index (see verify_stored_leaves_match_chain's doc for the incident
        // this guards against).
        verify_stored_leaves_match_chain(&node_store, stored_leaf_count, &capsule_ids, true)?;

        let mut leaves_indexed_this_load = 0u64;
        for capsule_id in &capsule_ids[stored_leaf_count as usize..] {
            // read_capsule_ids already validated every id as DIGEST_LEN
            // bytes of hex; this cannot fail.
            let body_digest =
                hex_to_digest(capsule_id).expect("read_capsule_ids validates capsule_id hex");
            add_leaf(&mut node_store, leaf_hash(&body_digest))?;
            leaves_indexed_this_load += 1;
        }
        let leaf_count = capsule_ids.len() as u64;

        let last_line = read_last_checkpoint(&checkpoints_path)?;
        let last_checkpoint = last_line.as_ref().map(|l| l.record.clone());
        let last_checkpoint_cose = last_line
            .and_then(|l| l.checkpoint_cose_hex)
            .and_then(|hex_str| hex::decode(hex_str).ok());

        let last_checkpoint_leaf_count = match &last_checkpoint {
            Some(cp) => mmr_leaf_count(cp.mmr_size)?,
            None => 0,
        };
        let entries_since_checkpoint = leaf_count.saturating_sub(last_checkpoint_leaf_count);

        let state = Self {
            capsules_path,
            checkpoints_path,
            node_store,
            leaf_count,
            log_id: log_id.into(),
            cfg,
            last_checkpoint,
            last_checkpoint_cose,
            entries_since_checkpoint,
            pending_since: (entries_since_checkpoint > 0).then(Instant::now),
            pending_witness_urls: Vec::new(),
            witness_deferred: false,
        };
        let report = LoadReport {
            node_store: Some(open_report),
            leaves_indexed_this_load,
        };
        Ok((state, report))
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn last_checkpoint(&self) -> Option<&CheckpointRecord> {
        self.last_checkpoint.as_ref()
    }

    /// Fold any `capsules.jsonl` lines not yet indexed into the MMR.
    /// Idempotent -- safe to call with nothing new to add. Mirrors
    /// `checkpointing.py`'s `MmrLedger.sync()`, but only re-reads/re-hashes
    /// the NEW tail (the durable node store already holds every prior
    /// leaf's hash).
    fn sync(&mut self) -> Result<u64, CheckpointStateError> {
        self.sync_returning_ids().map(|(added, _)| added)
    }

    /// [`Self::sync`], also handing back the `capsule_id`s it read (in leaf
    /// order), so a caller locating one leaf does not re-read the file.
    fn sync_returning_ids(&mut self) -> Result<(u64, Vec<String>), CheckpointStateError> {
        let capsule_ids = read_capsule_ids(&self.capsules_path)?;
        if self.leaf_count > capsule_ids.len() as u64 {
            return Err(CheckpointStateError::NodeStoreAheadOfLedger {
                path: self.capsules_path.display().to_string(),
                stored_leaves: self.leaf_count,
                ledger_leaves: capsule_ids.len() as u64,
            });
        }
        // Cheap per-tick divergence check (last stored leaf only -- `load`
        // did the full prefix): a chain rewritten in place under a live
        // state must be a hard error, never a silently stale checkpoint.
        verify_stored_leaves_match_chain(&self.node_store, self.leaf_count, &capsule_ids, false)?;
        let mut added = 0u64;
        for capsule_id in &capsule_ids[self.leaf_count as usize..] {
            // read_capsule_ids already validated every id as DIGEST_LEN
            // bytes of hex; this cannot fail.
            let body_digest =
                hex_to_digest(capsule_id).expect("read_capsule_ids validates capsule_id hex");
            add_leaf(&mut self.node_store, leaf_hash(&body_digest))?;
            added += 1;
        }
        self.leaf_count += added;
        self.note_pending(added);
        Ok((added, capsule_ids))
    }

    /// Checkpoint at push: return a signed checkpoint covering `capsule_id`
    /// plus that leaf's inclusion proof, cutting a new checkpoint only when
    /// the latest one does not already cover it (a burst of pushes shares
    /// one checkpoint -- the caller paces cuts, see admission-policy's
    /// `push_checkpoint`). A cut here is LOCAL ONLY: it is signed and
    /// persisted to `checkpoints.jsonl` exactly like a clock checkpoint, but
    /// never registered with a witness -- the next [`Self::tick`] registers
    /// the latest checkpoint of the window instead.
    pub fn checkpoint_covering(
        &mut self,
        capsule_id: &str,
        signer: &dyn CheckpointSigner,
        anchor: &AnchorClient,
    ) -> Result<Coverage, CheckpointStateError> {
        if let Some(coverage) = self.existing_coverage(capsule_id)? {
            return Ok(coverage);
        }
        self.checkpoint_now(signer, anchor, false)?;
        self.witness_deferred = true;
        let mut coverage = self
            .existing_coverage(capsule_id)?
            .expect("the checkpoint just cut covers every leaf synced before it");
        coverage.cut_new = true;
        Ok(coverage)
    }

    /// The coverage the LATEST checkpoint already gives `capsule_id`, or
    /// `None` when that leaf is newer than it (or there is no checkpoint
    /// yet). Never cuts -- the pacing caller checks this first, so a burst
    /// waits for one cut instead of cutting per push.
    pub fn existing_coverage(
        &mut self,
        capsule_id: &str,
    ) -> Result<Option<Coverage>, CheckpointStateError> {
        let (_, capsule_ids) = self.sync_returning_ids()?;
        let leaf_index = capsule_ids
            .iter()
            .rposition(|id| id == capsule_id)
            .ok_or_else(|| CheckpointStateError::CapsuleNotInLedger {
                capsule_id: capsule_id.to_string(),
            })? as u64;
        let Some(checkpoint) = self.last_checkpoint.clone() else {
            return Ok(None);
        };
        if leaf_index >= mmr_leaf_count(checkpoint.mmr_size)? {
            return Ok(None);
        }
        let proof = inclusion_proof(&self.node_store, leaf_index, checkpoint.mmr_size)?;
        Ok(Some(Coverage {
            checkpoint,
            leaf_index,
            proof,
            cut_new: false,
        }))
    }

    fn note_pending(&mut self, added: u64) {
        self.entries_since_checkpoint += added;
        if self.entries_since_checkpoint > 0 && self.pending_since.is_none() {
            self.pending_since = Some(Instant::now());
        }
    }

    /// The ~5-minute clock leg, called by the background cadence task on its
    /// interval (never on the serving path). Checkpoints if either cadence
    /// leg is due; otherwise retries any witness registration left pending
    /// by a prior outage. Mirrors `checkpointing.py`'s `CheckpointState.tick`.
    ///
    /// **`NodeStoreAheadOfLedger` is retryable-soft HERE, and only here.**
    /// The cadence task reads `capsules.jsonl` with no lock shared with the
    /// plugin's `Ledger::append`, so a tick racing an in-flight append can
    /// observe a transiently-short chain (a torn tail the reader tolerates by
    /// dropping the partial line) and momentarily see the durable node store
    /// "ahead" of the file. That is a read artifact, not divergence -- the
    /// next tick re-reads the settled file and recovers -- so this leg logs
    /// and returns `Ok(None)` (retry next tick) instead of wedging the
    /// cadence on a sticky error. It stays a HARD error on [`Self::load`]
    /// (an ahead-state that persists across a process start is a really
    /// truncated ledger, never a torn read), and
    /// [`CheckpointStateError::NodeStoreDivergedFromLedger`] stays hard
    /// everywhere -- a rewritten chain must never be soft-retried into a
    /// stale commitment.
    pub fn tick(
        &mut self,
        signer: &dyn CheckpointSigner,
        anchor: &AnchorClient,
    ) -> Result<Option<CheckpointRecord>, CheckpointStateError> {
        match self.sync() {
            Ok(_) => {}
            Err(err @ CheckpointStateError::NodeStoreAheadOfLedger { .. }) => {
                eprintln!(
                    "[checkpoint] transiently-short capsules.jsonl read on tick ({err}) -- \
                     treating as a torn-tail read racing an append, retrying next tick"
                );
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        let seconds_since = self.pending_since.map(|t| t.elapsed().as_secs_f64());
        if due_for_checkpoint(&self.cfg, self.entries_since_checkpoint, seconds_since) {
            return Ok(Some(self.checkpoint_now(signer, anchor, true)?));
        }
        self.offer_deferred_to_witnesses();
        self.retry_pending_witnesses(anchor);
        Ok(None)
    }

    /// The clock leg of push-time checkpoints: a checkpoint cut at push was
    /// never offered to a witness, so the tick offers the LATEST one once
    /// (older push cuts in the window are covered by it through the
    /// prev_size/prev_root chain and its consistency proof). No-op when
    /// witnessing is off.
    fn offer_deferred_to_witnesses(&mut self) {
        if !self.witness_deferred {
            return;
        }
        self.witness_deferred = false;
        if self.pending_witness_urls.is_empty() {
            self.pending_witness_urls = self.cfg.witness_urls.clone();
        }
    }

    /// Latest-checkpoint-on-reconnect: commit everything accrued since the
    /// last witnessed checkpoint in ONE checkpoint, ignoring cadence. Call
    /// once at startup. Mirrors `CheckpointState.reconnect`.
    pub fn reconnect(
        &mut self,
        signer: &dyn CheckpointSigner,
        anchor: &AnchorClient,
    ) -> Result<Option<CheckpointRecord>, CheckpointStateError> {
        self.sync()?;
        if self.leaf_count == 0 {
            return Ok(None);
        }
        if let Some(last) = &self.last_checkpoint {
            let last_leaf_count = mmr_leaf_count(last.mmr_size)?;
            if self.leaf_count <= last_leaf_count {
                self.retry_pending_witnesses(anchor);
                return Ok(None);
            }
        }
        Ok(Some(self.checkpoint_now(signer, anchor, true)?))
    }

    /// On-shutdown flush: anchor any uncommitted backlog so the final
    /// interval isn't lost between the last tick and process exit. Same
    /// self-healing semantics as `reconnect`.
    pub fn checkpoint_on_shutdown(
        &mut self,
        signer: &dyn CheckpointSigner,
        anchor: &AnchorClient,
    ) -> Result<Option<CheckpointRecord>, CheckpointStateError> {
        self.reconnect(signer, anchor)
    }

    /// `register`: offer the new checkpoint to the configured witnesses now
    /// (the clock legs) or not (a push-time cut -- see
    /// [`Self::checkpoint_covering`]).
    fn checkpoint_now(
        &mut self,
        signer: &dyn CheckpointSigner,
        anchor: &AnchorClient,
        register: bool,
    ) -> Result<CheckpointRecord, CheckpointStateError> {
        let prev_before = self.last_checkpoint.clone();
        let current_size = self.node_store.size();
        if current_size == 0 {
            return Err(CheckpointStateError::EmptyMmr);
        }

        let (prev_size, prev_root) = match &prev_before {
            None => (0u64, String::new()),
            Some(prev) => {
                if current_size <= prev.mmr_size {
                    return Err(CheckpointStateError::RollbackSize {
                        current_size,
                        prev_size: prev.mmr_size,
                    });
                }
                let actual_prev_peaks = leaf_positions_and_hashes(&self.node_store, prev.mmr_size)?;
                let actual_prev_root = hex::encode(root_from_peaks(&actual_prev_peaks));
                if actual_prev_root != prev.root {
                    return Err(CheckpointStateError::RollbackRoot {
                        prev_size: prev.mmr_size,
                        actual_root: actual_prev_root,
                        recorded_root: prev.root.clone(),
                    });
                }
                (prev.mmr_size, prev.root.clone())
            }
        };

        let new_peak_hashes = leaf_positions_and_hashes(&self.node_store, current_size)?;
        let root = hex::encode(root_from_peaks(&new_peak_hashes));

        let mut cp = CheckpointRecord {
            v: 1,
            kind: "mmr_checkpoint".to_string(),
            log_id: self.log_id.clone(),
            mmr_size: current_size,
            root,
            prev_size,
            prev_root,
            key_id: signer.key_id(),
            timestamp: crate::timestamp::utc_now_iso8601(),
            signature: String::new(),
            witnesses: Vec::new(),
        };
        cp.signature = try_sign_checkpoint_digest(&cp, signer)?;

        // COSE-wire form, best-effort (mirrors `checkpointing.py._checkpoint_now`'s
        // own try/except): a build failure here must never block the JSON
        // checkpoint from being signed and persisted, it only means this
        // checkpoint stays self-attested (no witness registration possible
        // without the wire form). `cadence_seconds` is deliberately omitted
        // (`None`) -- `checkpointing.py` never passes it either, and this
        // claim is not part of the invariance surface.
        let prev_peak_hashes = if prev_size > 0 {
            Some(leaf_positions_and_hashes(&self.node_store, prev_size)?)
        } else {
            None
        };
        let consistency = if prev_size > 0 {
            Some(consistency_proof(
                &self.node_store,
                prev_size,
                current_size,
            )?)
        } else {
            None
        };
        let checkpoint_cose = build_cose(
            &cp,
            signer,
            &new_peak_hashes,
            prev_peak_hashes.as_deref(),
            consistency.as_ref(),
        );

        if register {
            let ts_urls = self.cfg.witness_urls.clone();
            let still_pending =
                register_with(anchor, &mut cp, checkpoint_cose.as_deref(), &ts_urls);
            self.pending_witness_urls = still_pending;
            self.witness_deferred = false;
        }

        append_checkpoint(
            &self.checkpoints_path,
            &CheckpointLine {
                record: cp.clone(),
                checkpoint_cose_hex: checkpoint_cose.as_ref().map(hex::encode),
            },
        )?;

        self.last_checkpoint = Some(cp.clone());
        self.last_checkpoint_cose = checkpoint_cose;
        self.entries_since_checkpoint = 0;
        self.pending_since = None;
        Ok(cp)
    }

    /// Retry registering the last checkpoint with whichever witness URLs are
    /// still pending from its original attempt -- called even when nothing
    /// new has landed, so a registration failure never stays unwitnessed
    /// forever just because the node goes idle right after. No-op when
    /// there is no checkpoint yet or nothing pending.
    pub fn retry_pending_witnesses(&mut self, anchor: &AnchorClient) -> bool {
        if self.pending_witness_urls.is_empty() {
            return false;
        }
        let Some(cp) = self.last_checkpoint.as_mut() else {
            return false;
        };
        let ts_urls = std::mem::take(&mut self.pending_witness_urls);
        let before = cp.witnesses.len();
        let still_pending =
            register_with(anchor, cp, self.last_checkpoint_cose.as_deref(), &ts_urls);
        self.pending_witness_urls = still_pending;
        cp.witnesses.len() > before
    }
}

fn build_cose(
    cp: &CheckpointRecord,
    signer: &dyn CheckpointSigner,
    new_peak_hashes: &[Hash],
    prev_peak_hashes: Option<&[Hash]>,
    consistency: Option<&ConsistencyProof>,
) -> Option<Vec<u8>> {
    match checkpoint_to_cose(
        cp,
        signer,
        new_peak_hashes,
        prev_peak_hashes,
        consistency,
        None,
    ) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            // Best-effort: never blocks the JSON-only checkpoint from being
            // signed and persisted (see checkpoint_now's doc comment).
            eprintln!(
                "[checkpoint] COSE-wire checkpoint serialization failed (staying JSON-only, \
                 self-attested): {err}"
            );
            None
        }
    }
}

/// Attempt registration with each of `ts_urls`, appending any success onto
/// `cp.witnesses` in place. Returns the subset still unregistered. Never
/// lets a network error propagate -- an unreachable witness leaves this
/// checkpoint self-checkpointed, retried later.
fn register_with(
    anchor_default: &AnchorClient,
    cp: &mut CheckpointRecord,
    checkpoint_cose: Option<&[u8]>,
    ts_urls: &[String],
) -> Vec<String> {
    let mut still_pending = Vec::new();
    for ts_url in ts_urls {
        let Some(cose) = checkpoint_cose else {
            eprintln!("[checkpoint] skipping witness registration with {ts_url}: no COSE-wire checkpoint to send");
            still_pending.push(ts_url.clone());
            continue;
        };
        let dispatch_base = dispatch_base_for(ts_url);
        let client = if dispatch_base == ts_url {
            None
        } else {
            Some(AnchorClient::new(dispatch_base))
        };
        let client_ref = client.as_ref().unwrap_or(anchor_default);
        match client_ref.post_checkpoint_cose(cose) {
            Ok(resp) => {
                cp.witnesses.push(CheckpointWitness {
                    ts_url: ts_url.clone(),
                    entry_hash: resp.entry_hash,
                    receipt_b64: resp.receipt_b64,
                    leaf_index: resp.leaf_index,
                    tree_size: resp.tree_size,
                    is_stub: false,
                });
            }
            Err(err) => {
                eprintln!(
                    "[checkpoint] checkpoint registration with {ts_url} failed (staying \
                     self-checkpointed, retrying later): {err}"
                );
                still_pending.push(ts_url.clone());
            }
        }
    }
    still_pending
}

fn hex_to_digest(s: &str) -> Option<Hash> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Read every `capsule_id` in `path`, in file order. Tolerates a torn
/// trailing line (the Rust plugin's own `Ledger::append` writes+fsyncs a
/// whole line before returning, but a reader racing a still-in-progress
/// write could still observe a partial final line): only the LAST line gets
/// this tolerance, matching `checkpointing.py`'s `JsonlLogSource.scan()`
/// doc comment -- real corruption anywhere else in the file is NOT this
/// case and is still a hard error, never silently dropped.
fn read_capsule_ids(path: &Path) -> Result<Vec<String>, CheckpointStateError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    let mut ids = Vec::with_capacity(lines.len());
    let last_index = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        let value = match parsed {
            Ok(v) => v,
            Err(_) if i == last_index => break,
            Err(source) => {
                return Err(CheckpointStateError::MalformedLine {
                    line: i + 1,
                    source,
                })
            }
        };
        let capsule_id = value
            .get("capsule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(CheckpointStateError::MissingCapsuleId { line: i + 1 })?
            .to_string();
        if hex_to_digest(&capsule_id).is_none() {
            return Err(CheckpointStateError::BadCapsuleId {
                line: i + 1,
                capsule_id,
            });
        }
        ids.push(capsule_id);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cll::checkpoint::verify_checkpoint_cose_offline;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn write_capsule(dir: &Path, seed: &str) -> String {
        use sha2::{Digest, Sha256};
        let capsule_id = hex::encode(Sha256::digest(seed.as_bytes()));
        let line = json!({"capsule_id": capsule_id, "seed": seed});
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("capsules.jsonl"))
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&line).unwrap()).unwrap();
        capsule_id
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn empty_ledger_loads_with_no_pending_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let (state, report) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        assert_eq!(state.leaf_count(), 0);
        assert!(state.last_checkpoint().is_none());
        assert_eq!(report.leaves_indexed_this_load, 0);
    }

    #[test]
    fn tick_below_cadence_does_not_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        let cfg = CheckpointCadenceConfig {
            cadence_entries: 100,
            cadence_seconds: 300,
            witness_urls: Vec::new(),
        };
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg).unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let cp = state.tick(&signer(), &anchor).unwrap();
        assert!(
            cp.is_none(),
            "below both cadence legs -- must not checkpoint"
        );
    }

    #[test]
    fn reconnect_commits_backlog_immediately_ignoring_cadence() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        write_capsule(dir.path(), "two");
        let cfg = CheckpointCadenceConfig {
            cadence_entries: 100,
            cadence_seconds: 300,
            witness_urls: Vec::new(),
        };
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg).unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let cp = state
            .reconnect(&signer(), &anchor)
            .unwrap()
            .expect("reconnect must commit the backlog");
        assert_eq!(cp.log_id, "test-log");
        assert!(cp.mmr_size > 0);
        assert!(
            cp.verify_signature_offline(),
            "self-signed checkpoint must verify offline"
        );
        assert_eq!(state.entries_since_checkpoint, 0);
    }

    #[test]
    fn only_if_new_activity_an_idle_reconnect_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        let cfg = CheckpointCadenceConfig::default();
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg.clone()).unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        state.reconnect(&signer(), &anchor).unwrap();

        // A second reconnect with nothing new must be a no-op -- no second
        // checkpoint for a caught-up log.
        let second = state.reconnect(&signer(), &anchor).unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn restart_reuses_durable_node_store_without_rehashing_old_leaves() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        write_capsule(dir.path(), "two");
        {
            let (mut state, report) =
                CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                    .unwrap();
            assert_eq!(report.leaves_indexed_this_load, 2);
            let anchor = AnchorClient::new("http://127.0.0.1:1");
            state.reconnect(&signer(), &anchor).unwrap();
        }
        write_capsule(dir.path(), "three");
        // Second load: only the ONE new leaf should be (re)hashed, not the
        // two already durable in mmr_nodes.dat.
        let (state2, report2) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        assert_eq!(report2.leaves_indexed_this_load, 1);
        assert_eq!(state2.leaf_count(), 3);
    }

    #[test]
    fn checkpoint_root_matches_independent_mmr_computation() {
        let dir = tempfile::tempdir().unwrap();
        let ids = vec![
            write_capsule(dir.path(), "a"),
            write_capsule(dir.path(), "b"),
            write_capsule(dir.path(), "c"),
        ];
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let cp = state.reconnect(&signer(), &anchor).unwrap().unwrap();

        // Independently rebuild the MMR in memory from the same capsule_ids
        // and confirm the root matches -- the checkpoint's root is not just
        // "whatever the durable store produced", it is the actual MMRIVER
        // root over these exact leaves in this exact order.
        let mut mem = cll::mmr::MemoryNodeStore::new();
        for id in &ids {
            let digest = hex_to_digest(id).unwrap();
            add_leaf(&mut mem, leaf_hash(&digest)).unwrap();
        }
        let expected_root = hex::encode(root_from_peaks(
            &leaf_positions_and_hashes(&mem, mem.size()).unwrap(),
        ));
        assert_eq!(cp.root, expected_root);
    }

    #[test]
    fn cose_wire_checkpoint_verifies_offline_and_covers_consistency() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "a");
        write_capsule(dir.path(), "b");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        state.reconnect(&signer(), &anchor).unwrap();
        write_capsule(dir.path(), "c");
        let cp2 = state.reconnect(&signer(), &anchor).unwrap().unwrap();
        assert!(
            cp2.prev_size > 0,
            "second checkpoint must chain from the first"
        );

        let cose = state
            .last_checkpoint_cose
            .as_ref()
            .expect("COSE bytes must have been built");
        let verified = verify_checkpoint_cose_offline(cose);
        assert!(
            verified.ok,
            "COSE checkpoint must verify offline: {:?}",
            verified.errors
        );
        let decoded = verified.decoded.unwrap();
        assert!(
            decoded.consistency_proof.is_some(),
            "chained checkpoint must carry a consistency proof"
        );
        assert_eq!(decoded.mmr_size, cp2.mmr_size);
        assert_eq!(decoded.root, cp2.root);
    }

    #[test]
    fn rollback_is_detected_not_silently_re_checkpointed() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "a");
        write_capsule(dir.path(), "b");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        state.reconnect(&signer(), &anchor).unwrap();

        // Simulate a mutated ledger: swap in a checkpoint record that claims
        // a prev_root the current MMR does not actually have at that size.
        let mut tampered_prev = state.last_checkpoint.clone().unwrap();
        tampered_prev.root = "f".repeat(64);
        state.last_checkpoint = Some(tampered_prev);
        write_capsule(dir.path(), "c");
        state.sync().unwrap();
        let err = state.checkpoint_now(&signer(), &anchor, true).unwrap_err();
        assert!(matches!(err, CheckpointStateError::RollbackRoot { .. }));
    }

    #[test]
    fn empty_mmr_refuses_to_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let err = state.checkpoint_now(&signer(), &anchor, true).unwrap_err();
        assert!(matches!(err, CheckpointStateError::EmptyMmr));
    }

    #[test]
    fn node_store_ahead_of_ledger_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "a");
        write_capsule(dir.path(), "b");
        {
            let (_state, _) =
                CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                    .unwrap();
        }
        // Truncate capsules.jsonl back to one entry -- the durable node
        // store now claims more leaves than the ledger actually has.
        let ids = read_capsule_ids(&dir.path().join("capsules.jsonl")).unwrap();
        assert_eq!(ids.len(), 2);
        let single = json!({"capsule_id": ids[0], "seed": "a"});
        std::fs::write(
            dir.path().join("capsules.jsonl"),
            format!("{}\n", serde_json::to_string(&single).unwrap()),
        )
        .unwrap();

        let err =
            match CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
            {
                Err(e) => e,
                Ok(_) => panic!("expected NodeStoreAheadOfLedger, load succeeded"),
            };
        assert!(matches!(
            err,
            CheckpointStateError::NodeStoreAheadOfLedger { .. }
        ));
    }

    /// The backfill-incident shape,
    /// live-state leg: a chain REWRITTEN in place (same leaf count,
    /// different tail capsule_id) under an already-synced state must make
    /// `tick` error -- never emit a checkpoint whose root commits to the
    /// superseded leaves.
    #[test]
    fn rewritten_chain_under_live_state_errors_on_sync_instead_of_emitting() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        write_capsule(dir.path(), "two");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        assert_eq!(state.leaf_count(), 2);

        // Rewrite the chain: keep entry one, replace entry two with a
        // DIFFERENT capsule -- same count, different leaf set (exactly what
        // the received-half backfill did to the run-5 ledger).
        let ids = read_capsule_ids(&dir.path().join("capsules.jsonl")).unwrap();
        let keep = json!({"capsule_id": ids[0], "seed": "one"});
        std::fs::write(
            dir.path().join("capsules.jsonl"),
            format!("{}\n", serde_json::to_string(&keep).unwrap()),
        )
        .unwrap();
        write_capsule(dir.path(), "two-rewritten");

        // `reconnect` (not `tick`): it checkpoints unconditionally on a
        // backlog, so WITHOUT the guard this call would emit a checkpoint
        // whose root commits to the pre-rewrite leaves -- the exact silent
        // wrong commitment the incident produced.
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let err = state.reconnect(&signer(), &anchor).unwrap_err();
        assert!(
            matches!(err, CheckpointStateError::NodeStoreDivergedFromLedger { leaf_index: 1, .. }),
            "expected NodeStoreDivergedFromLedger, got: {err}"
        );
        assert!(
            !dir.path().join("checkpoints.jsonl").exists(),
            "a diverged store must never have emitted a checkpoint"
        );
    }

    /// Restart leg: the same rewrite
    /// discovered at `load` time -- including a MID-chain rewrite that
    /// preserves the tail, which only the full prefix check can see.
    #[test]
    fn rewritten_chain_under_existing_node_store_errors_on_load() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        write_capsule(dir.path(), "two");
        write_capsule(dir.path(), "three");
        {
            let (_state, _) =
                CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                    .unwrap();
        }
        // Rewrite the MIDDLE entry only -- first and last leaves unchanged,
        // so a last-leaf-only check would miss it.
        let ids = read_capsule_ids(&dir.path().join("capsules.jsonl")).unwrap();
        std::fs::write(dir.path().join("capsules.jsonl"), "").unwrap();
        let first = json!({"capsule_id": ids[0], "seed": "one"});
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("capsules.jsonl"))
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&first).unwrap()).unwrap();
        drop(f);
        write_capsule(dir.path(), "two-rewritten");
        let last = json!({"capsule_id": ids[2], "seed": "three"});
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("capsules.jsonl"))
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&last).unwrap()).unwrap();
        drop(f);

        let err =
            match CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
            {
                Err(e) => e,
                Ok(_) => panic!("expected NodeStoreDivergedFromLedger, load succeeded"),
            };
        assert!(
            matches!(err, CheckpointStateError::NodeStoreDivergedFromLedger { leaf_index: 1, .. }),
            "expected NodeStoreDivergedFromLedger at leaf 1, got: {err}"
        );
    }

    /// The tick leg's torn-tail tolerance: a transiently-short chain read
    /// (the cadence racing `Ledger::append` with no shared lock) makes
    /// `tick` return `Ok(None)` -- a soft skip, never a wedge -- and the
    /// very next tick over the settled file recovers and checkpoints. The
    /// SAME state at `load` stays hard
    /// (`node_store_ahead_of_ledger_is_a_hard_error` above), and a rewritten
    /// chain stays hard on tick
    /// (`rewritten_chain_under_live_state_errors_on_sync_instead_of_emitting`).
    #[test]
    fn transiently_short_chain_read_is_soft_on_tick_and_recovers_next_tick() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        write_capsule(dir.path(), "two");
        let cfg = CheckpointCadenceConfig {
            cadence_entries: 1, // due immediately once sync succeeds
            cadence_seconds: 300,
            witness_urls: Vec::new(),
        };
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg).unwrap();
        assert_eq!(state.leaf_count(), 2);

        // Simulate the torn-tail read: the reader observes only the first
        // line while the second append is in flight.
        let capsules_path = dir.path().join("capsules.jsonl");
        let settled = std::fs::read_to_string(&capsules_path).unwrap();
        let first_line = settled.lines().next().unwrap();
        std::fs::write(&capsules_path, format!("{first_line}\n")).unwrap();

        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let soft = state.tick(&signer(), &anchor).unwrap();
        assert!(soft.is_none(), "a transiently-short read must soft-skip the tick");
        assert!(
            !dir.path().join("checkpoints.jsonl").exists(),
            "the soft-skipped tick must not have emitted a checkpoint"
        );

        // The write settles; the next tick recovers and checkpoints.
        std::fs::write(&capsules_path, settled).unwrap();
        let cp = state
            .tick(&signer(), &anchor)
            .unwrap()
            .expect("the next tick over the settled chain must checkpoint");
        assert_eq!(mmr_leaf_count(cp.mmr_size).unwrap(), 2);
    }

    #[test]
    fn torn_trailing_capsule_line_is_tolerated_not_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "a");
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("capsules.jsonl"))
            .unwrap();
        write!(f, "{{\"capsule_id\":\"dead").unwrap(); // no trailing newline: a torn write
        drop(f);

        let ids = read_capsule_ids(&dir.path().join("capsules.jsonl")).unwrap();
        assert_eq!(
            ids.len(),
            1,
            "the torn trailing line must be skipped, not raise"
        );
    }

    #[test]
    fn witness_registration_failure_leaves_checkpoint_self_checkpointed_and_pending() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "a");
        let cfg = CheckpointCadenceConfig {
            cadence_entries: 100,
            cadence_seconds: 300,
            // Port 1 refuses connections deterministically -- a stand-in
            // for an unreachable witness without a live network dependency.
            witness_urls: vec!["http://127.0.0.1:1/".to_string()],
        };
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg).unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let cp = state
            .reconnect(&signer(), &anchor)
            .unwrap()
            .expect("checkpoint must still be produced");
        assert!(
            cp.witnesses.is_empty(),
            "an unreachable witness must not be recorded as succeeded"
        );
        assert_eq!(
            state.pending_witness_urls.len(),
            1,
            "the failed URL must be queued for retry"
        );
    }

    fn checkpoint_lines(dir: &Path) -> usize {
        cll::store::read_checkpoints(dir.join("checkpoints.jsonl"))
            .unwrap()
            .len()
    }

    fn assert_covers(coverage: &Coverage, capsule_id: &str) {
        let root: Hash = hex_to_digest(&coverage.checkpoint.root).unwrap();
        let body = hex_to_digest(capsule_id).unwrap();
        assert!(
            cll::mmr::verify_inclusion(
                &root,
                coverage.checkpoint.mmr_size,
                coverage.leaf_index,
                &body,
                &coverage.proof,
            ),
            "the inclusion proof must reconstruct the covering checkpoint's root"
        );
        assert!(coverage.checkpoint.verify_signature_offline());
    }

    #[test]
    fn checkpoint_covering_cuts_a_checkpoint_whose_proof_verifies() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        let two = write_capsule(dir.path(), "two");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");

        let coverage = state.checkpoint_covering(&two, &signer(), &anchor).unwrap();
        assert!(coverage.cut_new);
        assert_eq!(coverage.leaf_index, 1);
        assert_covers(&coverage, &two);
        assert_eq!(checkpoint_lines(dir.path()), 1, "a push cut is persisted like any checkpoint");
        assert_eq!(state.entries_since_checkpoint, 0);
    }

    #[test]
    fn checkpoint_covering_reuses_a_checkpoint_that_already_covers_the_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let one = write_capsule(dir.path(), "one");
        let two = write_capsule(dir.path(), "two");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");

        let first = state.checkpoint_covering(&two, &signer(), &anchor).unwrap();
        // A burst: the earlier leaf is already under the checkpoint just cut.
        let second = state.checkpoint_covering(&one, &signer(), &anchor).unwrap();
        assert!(!second.cut_new, "a covered leaf must not cut a second checkpoint");
        assert_eq!(second.checkpoint, first.checkpoint);
        assert_covers(&second, &one);
        assert_eq!(checkpoint_lines(dir.path()), 1);
    }

    #[test]
    fn checkpoint_covering_a_capsule_not_in_the_ledger_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        write_capsule(dir.path(), "one");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let err = state
            .checkpoint_covering(&"f".repeat(64), &signer(), &anchor)
            .unwrap_err();
        assert!(matches!(err, CheckpointStateError::CapsuleNotInLedger { .. }));
        assert_eq!(checkpoint_lines(dir.path()), 0);
    }

    #[test]
    fn successive_push_cuts_chain_and_stay_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let one = write_capsule(dir.path(), "one");
        let (mut state, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let first = state.checkpoint_covering(&one, &signer(), &anchor).unwrap();
        let two = write_capsule(dir.path(), "two");
        let three = write_capsule(dir.path(), "three");
        let second = state.checkpoint_covering(&three, &signer(), &anchor).unwrap();
        assert!(second.cut_new);
        assert_eq!(second.checkpoint.prev_size, first.checkpoint.mmr_size);
        assert_eq!(second.checkpoint.prev_root, first.checkpoint.root);
        assert_covers(&second, &three);

        // The earlier checkpoint is a prefix of the later one.
        let proof = consistency_proof(
            &state.node_store,
            first.checkpoint.mmr_size,
            second.checkpoint.mmr_size,
        )
        .unwrap();
        assert!(cll::mmr::verify_consistency(
            &hex_to_digest(&first.checkpoint.root).unwrap(),
            first.checkpoint.mmr_size,
            &hex_to_digest(&second.checkpoint.root).unwrap(),
            second.checkpoint.mmr_size,
            &proof,
        ));

        // A leaf cut under the first checkpoint still proves under the second.
        let reused = state.checkpoint_covering(&two, &signer(), &anchor).unwrap();
        assert!(!reused.cut_new);
        assert_covers(&reused, &two);
    }

    #[test]
    fn a_push_cut_is_not_witnessed_until_the_clock_offers_the_latest_one() {
        let dir = tempfile::tempdir().unwrap();
        let one = write_capsule(dir.path(), "one");
        let cfg = CheckpointCadenceConfig {
            cadence_entries: 100,
            cadence_seconds: 300,
            // Unreachable: any registration attempt fails and stays pending,
            // which is how this test observes whether one was made.
            witness_urls: vec!["http://127.0.0.1:1".to_string()],
        };
        let (mut state, _) = CheckpointState::load(dir.path(), "test-log", cfg).unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");

        state.checkpoint_covering(&one, &signer(), &anchor).unwrap();
        assert!(
            state.pending_witness_urls.is_empty(),
            "a push cut must never register with a witness per turn"
        );
        assert!(state.witness_deferred);

        // The clock leg: nothing new to cut, but the deferred checkpoint is
        // offered once (it fails against the unreachable URL and stays queued).
        assert!(state.tick(&signer(), &anchor).unwrap().is_none());
        assert!(!state.witness_deferred);
        assert_eq!(state.pending_witness_urls, vec!["http://127.0.0.1:1".to_string()]);
        assert_eq!(checkpoint_lines(dir.path()), 1, "the tick must not cut a second checkpoint");
    }

    #[test]
    fn after_a_restart_a_covered_leaf_reuses_the_persisted_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let one = write_capsule(dir.path(), "one");
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        {
            let (mut state, _) =
                CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                    .unwrap();
            state.checkpoint_covering(&one, &signer(), &anchor).unwrap();
        }
        let (mut reopened, _) =
            CheckpointState::load(dir.path(), "test-log", CheckpointCadenceConfig::default())
                .unwrap();
        let coverage = reopened.checkpoint_covering(&one, &signer(), &anchor).unwrap();
        assert!(!coverage.cut_new);
        assert_covers(&coverage, &one);
        assert_eq!(checkpoint_lines(dir.path()), 1);
    }
}
