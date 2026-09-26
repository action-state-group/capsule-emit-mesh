//! The plugin's own checkpoint cadence: a tokio background task that runs
//! `capsule_producer::checkpoint::CheckpointState` over this node's ledger,
//! replacing `checkpoint_daemon.py` once a node cuts over.
//!
//! **On by default, local-only (`[mesh-plugin-release-checkpoint-default-flip]`,
//! superseding `[mesh-plugin-checkpoint-cadence]`'s off-by-default launch;
//! `docs/DESIGN-fold-sidecar-into-plugin.md`).** The cadence task now runs
//! unless the operator opts OUT by setting [`ENV_ENABLE`] to `"off"` --
//! "on by default" is local checkpointing only: [`ENV_WITNESS_URLS`] stays
//! empty/unset by default, so no network call ever happens unless the
//! operator also sets a witness URL. `checkpoint_daemon.py` keeps
//! checkpointing a node's ledger on the same files until the operator opts
//! OUT of the in-process cadence. The two must NEVER run against the same
//! `ledger_dir` at once -- both would append lines to the same
//! `checkpoints.jsonl` and race each other's chain. This is an operator
//! choice, not something this task can detect and refuse safely (a lock
//! file would only catch a same-host double-run, not a daemon started on a
//! different box pointed at a shared mount) -- see the Path 1 README note
//! this task adds.
//!
//! Age clock, only-if-new-activity, shutdown flush, and best-effort witness
//! retry are `CheckpointState`'s policy, not this module's -- this module
//! is purely the tokio scheduling shell: an interval loop plus a shutdown
//! signal, exactly the shape `checkpoint_daemon.py`'s own `run_daemon`
//! background loop has.

use capsule_producer::anchor::AnchorClient;
use capsule_producer::checkpoint::{CheckpointCadenceConfig, CheckpointRecord, CheckpointState};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// On by default: the plugin runs its OWN checkpoint cadence in place of
/// `checkpoint_daemon.py` unless the operator sets
/// `ADMISSION_POLICY_CHECKPOINT_CADENCE=off` to opt out (e.g. because
/// `checkpoint_daemon.py` is already checkpointing this `ledger_dir` --
/// see the module doc's daemon-race note). Any other value, including
/// unset, leaves it on.
const ENV_ENABLE: &str = "ADMISSION_POLICY_CHECKPOINT_CADENCE";
/// Age-clock override, seconds. Defaults to `CheckpointCadenceConfig`'s own
/// 300s mesh default (`checkpoint_daemon.py`'s `DEFAULT_INTERVAL_SECONDS`).
const ENV_INTERVAL_SECONDS: &str = "ADMISSION_POLICY_CHECKPOINT_CADENCE_SECONDS";
/// Entry-count cadence override. Defaults to 100 (upstream `capsule_emit`'s
/// own default).
const ENV_CADENCE_ENTRIES: &str = "ADMISSION_POLICY_CHECKPOINT_CADENCE_ENTRIES";
/// Comma-separated witness URLs to register checkpoints with. Anchoring is
/// OPT-IN, always (this repo's posture) -- empty/unset means
/// self-checkpointed only, no network, matching `checkpoint_daemon.py`'s
/// `--ts-url`/`--witness` flags.
const ENV_WITNESS_URLS: &str = "ADMISSION_POLICY_CHECKPOINT_WITNESS_URLS";

pub fn is_enabled() -> bool {
    is_enabled_for(std::env::var(ENV_ENABLE).ok().as_deref())
}

/// Pure decision logic behind [`is_enabled`], taking the raw env value (or
/// `None` when unset) directly so the on-by-default / explicit-opt-out
/// behavior is unit-testable without mutating process-global env state
/// (`std::env::set_var` races across parallel `cargo test` threads).
fn is_enabled_for(raw: Option<&str>) -> bool {
    raw != Some("off")
}

fn config_from_env() -> CheckpointCadenceConfig {
    let mut cfg = CheckpointCadenceConfig::default();
    if let Ok(v) = std::env::var(ENV_INTERVAL_SECONDS) {
        if let Ok(n) = v.parse::<u64>() {
            cfg.cadence_seconds = n;
        }
    }
    if let Ok(v) = std::env::var(ENV_CADENCE_ENTRIES) {
        if let Ok(n) = v.parse::<u64>() {
            cfg.cadence_entries = n;
        }
    }
    if let Ok(v) = std::env::var(ENV_WITNESS_URLS) {
        cfg.witness_urls = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    cfg
}

/// The latest signed checkpoint head this node has produced, held in
/// memory. `[mesh-checkpoint-head-source]`'s sending half reads this to
/// feed `peer_root_ledger.rs`'s outbound side / `PeerAnnouncement.checkpoint`
/// -- this task itself does not gossip anything; it only produces and holds
/// the head.
#[derive(Clone, Default)]
pub struct LatestHead(Arc<RwLock<Option<CheckpointRecord>>>);

impl LatestHead {
    /// Not read anywhere in this binary yet -- `[mesh-checkpoint-head-source]`'s
    /// sending half is the intended caller (see this struct's doc comment).
    /// Kept as the accessor that wiring needs, same "tested, ready-to-wire"
    /// pattern `peer_root_ledger.rs`'s module doc uses for its own
    /// not-yet-wired receiving half.
    #[allow(dead_code)]
    pub fn get(&self) -> Option<CheckpointRecord> {
        self.0
            .read()
            .expect("latest checkpoint head lock poisoned")
            .clone()
    }

    fn set(&self, cp: CheckpointRecord) {
        *self
            .0
            .write()
            .expect("latest checkpoint head lock poisoned") = Some(cp);
    }
}

/// Spawn the background cadence task over `ledger_dir`, using `signer` for
/// every checkpoint this task ever signs (always through the
/// `CheckpointSigner` trait -- see `checkpoint.rs`'s module doc). Returns
/// the `LatestHead` handle immediately; the task itself runs until
/// `shutdown` fires, performing a final flush before returning.
///
/// Startup catch-up (`reconnect`) runs before the interval loop starts, one
/// interval tick runs `tick()`, and a shutdown signal triggers
/// `checkpoint_on_shutdown()` -- the same three-phase shape
/// `checkpoint_daemon.py`'s `run_daemon` has.
pub fn spawn(
    ledger_dir: PathBuf,
    log_id: String,
    signer: SigningKey,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<LatestHead> {
    let cfg = config_from_env();
    let interval = Duration::from_secs(cfg.cadence_seconds);
    let (mut state, report) = CheckpointState::load(&ledger_dir, log_id, cfg).map_err(|e| {
        anyhow::anyhow!(
            "failed to load checkpoint state at {}: {e}",
            ledger_dir.display()
        )
    })?;
    if let Some(open_report) = &report.node_store {
        if open_report.truncated_bytes > 0 {
            tracing::warn!(
                truncated_bytes = open_report.truncated_bytes,
                "checkpoint node store had a torn trailing record, truncated on open"
            );
        }
    }
    tracing::info!(
        leaves_indexed_this_load = report.leaves_indexed_this_load,
        leaf_count = state.leaf_count(),
        "checkpoint cadence task starting"
    );

    let latest_head = LatestHead::default();
    let latest_head_for_task = latest_head.clone();
    let anchor = AnchorClient::default();

    tokio::spawn(async move {
        if let Some(cp) = report_checkpoint(state.reconnect(&signer, &anchor), "startup reconnect")
        {
            latest_head_for_task.set(cp);
        }

        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; the startup reconnect above
        // already did that work, so skip it.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(cp) = report_checkpoint(state.tick(&signer, &anchor), "tick") {
                        latest_head_for_task.set(cp);
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }

        if let Some(cp) = report_checkpoint(
            state.checkpoint_on_shutdown(&signer, &anchor),
            "shutdown flush",
        ) {
            latest_head_for_task.set(cp);
        }
        tracing::info!("checkpoint cadence task stopped");
    });

    Ok(latest_head)
}

fn report_checkpoint(
    result: Result<Option<CheckpointRecord>, capsule_producer::checkpoint::CheckpointStateError>,
    phase: &str,
) -> Option<CheckpointRecord> {
    match result {
        Ok(Some(cp)) => {
            tracing::info!(
                mmr_size = cp.mmr_size,
                root = %cp.root,
                witnessed = !cp.witnesses.is_empty(),
                %phase,
                "checkpoint emitted"
            );
            Some(cp)
        }
        Ok(None) => None,
        Err(err) => {
            // Never let a checkpoint-layer failure disturb the serving
            // path or crash the plugin -- best-effort observability, same
            // discipline `capsule_emit.witness`/`checkpoint_daemon.py`
            // hold for the witness leg (see checkpoint.rs's module doc).
            tracing::warn!(%err, %phase, "checkpoint cadence step failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_by_default_when_unset() {
        assert!(is_enabled_for(None));
    }

    #[test]
    fn explicit_off_disables() {
        assert!(!is_enabled_for(Some("off")));
    }

    #[test]
    fn any_other_value_stays_on() {
        assert!(is_enabled_for(Some("on")));
        assert!(is_enabled_for(Some("")));
        assert!(is_enabled_for(Some("OFF"))); // case-sensitive: only lowercase "off" opts out
    }
}
