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
//! that branch (`dispatch_path`/`phase`/`model`/`status`/`capsule_id`/`nonce`/
//! `serving_provenance`).
//!
//! The `serving_provenance` block is the host's proof-of-inference metadata
//! (#1233 digest advertisement): what ran (model identity hash, revision), at
//! what fidelity (quantization, architecture, context length), on whose
//! hardware (gpu, vram, soc). Every field is `Option` and `#[serde(default)]`
//! so this mirror stays forward/backward compatible with a host that predates
//! the block (it simply arrives absent) -- and, critically, so a fact the host
//! genuinely does not know stays `None` here rather than being fabricated.

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
    /// The host's serving-provenance block for this terminal event -- what
    /// ran, at what fidelity, on whose hardware. Absent on a host that
    /// predates the block, and on non-terminal / non-served envelopes.
    #[serde(default)]
    pub serving_provenance: Option<HostServingProvenance>,
}

/// Hand-mirror of the host's `ServingProvenance` (same repo/module note as
/// [`OpenAiExchangeEnvelope`]). Every field is `Option` + `#[serde(default)]`:
/// the host omits (via `skip_serializing_if`) any fact it does not know, so an
/// absent field deserializes to `None` here -- an honest "the host did not
/// tell us", never a fabricated value. These are the real fields that fill the
/// capsule's own `serving_provenance` quantization/hardware/model-digest slots.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct HostServingProvenance {
    #[serde(default)]
    pub served_by_node_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub quantization: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub context_length: Option<u32>,
    #[serde(default)]
    pub parameter_size: Option<String>,
    #[serde(default)]
    pub layer_count: Option<u32>,
    #[serde(default)]
    pub model_identity_hash: Option<String>,
    #[serde(default)]
    pub model_canonical_ref: Option<String>,
    #[serde(default)]
    pub model_revision: Option<String>,
    #[serde(default)]
    pub gpu: Option<String>,
    #[serde(default)]
    pub vram_bytes: Option<u64>,
    #[serde(default)]
    pub is_soc: Option<bool>,
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

    /// The most recently observed host serving-provenance for `model` (from a
    /// `Terminal` envelope that carried one). This is how the host's real
    /// quantization/hardware/model-digest reach the capsule: the host publishes
    /// it on the exchange channel, the plugin captures it here, and the next
    /// exchange this plugin seals for the same model reads it back.
    ///
    /// Correlation is by MODEL, not by exchange id, and deliberately so: the
    /// host mints its own random raw-proxy `exchange_id` for the terminal
    /// event, which is disjoint from the deterministic id this plugin's own
    /// direct-serve handler mints -- so the two cannot be paired by id. Model
    /// is the honest join key here: serving fidelity/hardware for a given model
    /// on a given node is stable across that node's exchanges, so "the latest
    /// host-reported provenance for this model" is the correct fact to attest.
    /// Returns `None` when the host has published no provenance for the model
    /// yet, leaving the capsule's slots at their honest `unknown`/`null`.
    pub fn latest_provenance_for_model(&self, model: &str) -> Option<HostServingProvenance> {
        self.events
            .lock()
            .expect("lifecycle events mutex poisoned")
            .iter()
            .rev()
            .find(|e| e.model == model && e.serving_provenance.is_some())
            .and_then(|e| e.serving_provenance.clone())
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
    /// Persisted so the out-of-process e2e test can confirm the host's real
    /// serving provenance was received (in-memory state isn't visible to it).
    #[serde(skip_serializing_if = "Option::is_none")]
    serving_provenance: Option<HostServingProvenance>,
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
            serving_provenance: e.serving_provenance.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REAL host terminal event (verbatim wire bytes captured from a live
    /// `mesh-llm serve` on this branch) deserializes into the mirror, and the
    /// serving-provenance hardware facts survive intact -- while the fields the
    /// host reported as `null` (synthetic plugin-served model has no GGUF
    /// metadata) stay `None`, never fabricated.
    #[test]
    fn real_host_terminal_event_deserializes_serving_provenance() {
        let wire = r#"{"dispatch_path":"raw_proxy","phase":"terminal","model":"allowed-test-model","status":200,"capsule_id":null,"nonce":null,"serving_provenance":{"served_by_node_id":"fa28d0dfe5f0b2c4a8f0fcb15838075e4e5f0b32d6dd5df029588e8992fad5ac","hostname":"Stevens-MacBook-Pro.local","quantization":null,"architecture":null,"context_length":null,"parameter_size":null,"layer_count":null,"model_identity_hash":null,"model_canonical_ref":null,"model_revision":null,"gpu":"Apple M4 Max","vram_bytes":28991029248,"is_soc":true}}"#;
        let env: OpenAiExchangeEnvelope = serde_json::from_str(wire).expect("parse real event");
        let prov = env.serving_provenance.expect("provenance present");
        // Real hardware facts the host survey knows.
        assert_eq!(prov.gpu.as_deref(), Some("Apple M4 Max"));
        assert_eq!(prov.vram_bytes, Some(28_991_029_248));
        assert_eq!(prov.is_soc, Some(true));
        assert_eq!(prov.hostname.as_deref(), Some("Stevens-MacBook-Pro.local"));
        assert_eq!(
            prov.served_by_node_id.as_deref(),
            Some("fa28d0dfe5f0b2c4a8f0fcb15838075e4e5f0b32d6dd5df029588e8992fad5ac")
        );
        // Synthetic plugin-served model has no GGUF metadata -> honest None.
        assert!(prov.quantization.is_none());
        assert!(prov.architecture.is_none());
        assert!(prov.model_identity_hash.is_none());
    }

    /// A host predating the serving_provenance block (its terminal event omits
    /// the field entirely) still deserializes -- the mirror is forward/backward
    /// compatible, and the block is simply `None`.
    #[test]
    fn terminal_event_without_serving_provenance_still_parses() {
        let wire = r#"{"dispatch_path":"raw_proxy","phase":"terminal","model":"m","status":200}"#;
        let env: OpenAiExchangeEnvelope = serde_json::from_str(wire).expect("parse legacy event");
        assert!(env.serving_provenance.is_none());
    }

    /// `latest_provenance_for_model` returns the MOST RECENT provenance for the
    /// asked-for model, ignores other models, and returns `None` for a model
    /// the host never reported provenance for (leaving capsule slots honest).
    #[test]
    fn latest_provenance_for_model_picks_most_recent_and_scopes_by_model() {
        let dir = std::env::temp_dir().join(format!("lc-test-{}", std::process::id()));
        let store = ObservedLifecycleEvents::open(&dir).expect("open store");

        let event = |model: &str, gpu: Option<&str>| OpenAiExchangeEnvelope {
            dispatch_path: DispatchPath::RawProxy,
            phase: Phase::Terminal,
            model: model.to_string(),
            status: Some(200),
            capsule_id: None,
            nonce: None,
            serving_provenance: gpu.map(|g| HostServingProvenance {
                served_by_node_id: Some("node-1".to_string()),
                hostname: None,
                quantization: None,
                architecture: None,
                context_length: None,
                parameter_size: None,
                layer_count: None,
                model_identity_hash: None,
                model_canonical_ref: None,
                model_revision: None,
                gpu: Some(g.to_string()),
                vram_bytes: None,
                is_soc: None,
            }),
        };

        store.record(event("model-a", Some("gpu-old")));
        store.record(event("model-b", Some("gpu-other")));
        store.record(event("model-a", Some("gpu-new")));

        // Most recent for model-a wins.
        let a = store
            .latest_provenance_for_model("model-a")
            .expect("model-a provenance");
        assert_eq!(a.gpu.as_deref(), Some("gpu-new"));
        // Model scoping: model-b is untouched by model-a's events.
        let b = store
            .latest_provenance_for_model("model-b")
            .expect("model-b provenance");
        assert_eq!(b.gpu.as_deref(), Some("gpu-other"));
        // A model the host never reported provenance for -> None (honest).
        assert!(store.latest_provenance_for_model("model-unseen").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
