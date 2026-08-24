//! Consumes the #1331 lifecycle-hook terminal-event broadcast on the
//! `openai.exchange.v1` mesh channel (`mesh-llm-host-runtime`'s
//! `plugin::openai_exchange` module, `StevenMih/mesh-llm` branch
//! `mesh1331-lifecycle-hooks-m2`). The host wires this channel's *raw-proxy*
//! dispatch path into production (`network/openai/ingress.rs`'s
//! `try_route_plugin_model`, which is exactly the path this plugin's own
//! `inference::provider()` registration is routed through) -- so a real host
//! actually publishes on this channel for every exchange this plugin serves,
//! independent of this plugin's own HTTP handler. This module is the second,
//! independent proof that the plugin observed the same exchange the host
//! itself terminal-logged, not just its own view of the call.
//!
//! `OpenAiExchangeEnvelope` here is a hand-mirrored copy of the host-side
//! struct, not a shared dependency -- the host lives in a different repo
//! (`mesh-llm`) that this plugin cannot depend on. Field shape verified
//! against `crates/mesh-llm-host-runtime/src/plugin/openai_exchange.rs` on
//! that branch (`dispatch_path`/`phase`/`model`/`status`/`capsule_id`/`nonce`).

use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const OPENAI_EXCHANGE_CHANNEL: &str = "openai.exchange.v1";

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPath {
    TypedFrontend,
    RawProxy,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    EffectiveRequest,
    Terminal,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiExchangeEnvelope {
    pub dispatch_path: DispatchPath,
    pub phase: Phase,
    pub model: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub capsule_id: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Every lifecycle envelope this plugin has observed on the mesh channel,
/// most-recent-last -- inspectable by the e2e test (a separate process) via
/// the JSONL file this also appends to under `data_dir`, so cross-process
/// correlation against the capsule this plugin's own handler produced for
/// the same exchange doesn't depend on shared memory.
pub struct ObservedLifecycleEvents {
    events: Mutex<Vec<OpenAiExchangeEnvelope>>,
    log_path: PathBuf,
}

impl ObservedLifecycleEvents {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        Ok(Self {
            events: Mutex::new(Vec::new()),
            log_path: data_dir.join("lifecycle-events.jsonl"),
        })
    }

    pub fn record(&self, envelope: OpenAiExchangeEnvelope) {
        tracing::info!(
            dispatch_path = ?envelope.dispatch_path,
            phase = ?envelope.phase,
            model = %envelope.model,
            status = ?envelope.status,
            "observed openai.exchange.v1 lifecycle event"
        );
        if let Ok(line) = serde_json::to_string(&LoggedEnvelope::from(&envelope)) {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
            {
                let _ = writeln!(file, "{line}");
            }
        }
        self.events
            .lock()
            .expect("lifecycle events mutex poisoned")
            .push(envelope);
    }

    /// In-process accessor; the e2e test instead reads the JSONL log this
    /// also writes (it runs the plugin as a separate process, so in-memory
    /// state isn't visible to it) -- kept for a same-process caller (e.g. a
    /// future unit test of the handler itself).
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<OpenAiExchangeEnvelope> {
        self.events
            .lock()
            .expect("lifecycle events mutex poisoned")
            .clone()
    }
}

/// `OpenAiExchangeEnvelope` only derives `Deserialize` (it's the wire shape
/// we receive, never one we send) -- this sibling carries `Serialize` so the
/// observed-events log can be written without adding an unused derive to the
/// wire type itself.
#[derive(serde::Serialize)]
struct LoggedEnvelope {
    dispatch_path: DispatchPath,
    phase: Phase,
    model: String,
    status: Option<u16>,
    capsule_id: Option<String>,
    nonce: Option<String>,
}

impl From<&OpenAiExchangeEnvelope> for LoggedEnvelope {
    fn from(e: &OpenAiExchangeEnvelope) -> Self {
        Self {
            dispatch_path: e.dispatch_path.clone(),
            phase: e.phase.clone(),
            model: e.model.clone(),
            status: e.status,
            capsule_id: e.capsule_id.clone(),
            nonce: e.nonce.clone(),
        }
    }
}
