//! Wires `capsule-producer` (COSE-sign -> chain -> ledger) into this plugin,
//! closing the #1332 integration gap: previously `capsule-producer` and the
//! admission plugin were two crates with zero shared dependency (see
//! `adv-mesh-1332-e2e-scorecard`). Every ALLOWED chat-completion exchange
//! this plugin itself serves is turned into a signed, chained, ledgered AAC
//! (`x-mesh-poc-v1` mapping) -- digests are computed over the exact request/
//! response bytes exchanged, so mutating either changes `capsule_id`.

use capsule_producer::capsule::{seal, CapsuleInput, ChainLink, MeshPocV1};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::keys::{self, KeyPair};
use capsule_producer::ledger::Ledger;
use capsule_producer::timestamp::utc_now_iso8601;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

const CAPSULE_CONTENT_TYPE: &str =
    "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02";

pub struct CapsuleState {
    keys: KeyPair,
    ledger: Mutex<Ledger>,
    node_id: String,
}

pub struct EmittedCapsule {
    pub capsule_id: String,
    pub capsule: Value,
}

impl CapsuleState {
    /// Loads (or creates, on first run) a persistent Ed25519 signing key and
    /// opens the durable local ledger under `data_dir` -- both restart-safe,
    /// mirroring the acceptance already proven in isolation by
    /// `mesh-rust-capsule-production-m2`'s `chain_ledger_conformance` test.
    pub fn open(data_dir: &Path, node_id: impl Into<String>) -> anyhow::Result<Self> {
        let keys = keys::load_or_create(&data_dir.join("keys"))?;
        let (ledger, report) = Ledger::open(&data_dir.join("ledger"))?;
        tracing::info!(
            recovered_entries = report.valid_entries,
            "capsule-producer ledger opened"
        );
        Ok(Self {
            keys,
            ledger: Mutex::new(ledger),
            node_id: node_id.into(),
        })
    }

    /// Not read by this binary today (the e2e test reads the persisted PEM
    /// straight off disk in the plugin's data dir, matching how a real
    /// verifier would) -- kept as the public accessor a future `/v1/pubkey`
    /// debug endpoint or key-rotation caller would need.
    #[allow(dead_code)]
    pub fn public_key_pem(&self) -> String {
        self.keys.public_key_pem()
    }

    pub fn chain_head(&self) -> Option<String> {
        self.ledger
            .lock()
            .expect("capsule ledger mutex poisoned")
            .chain_head()
            .map(str::to_string)
    }

    /// Seal, sign, chain, and ledger one admitted exchange this plugin's own
    /// `/v1/chat/completions` handler just served.
    pub fn emit_for_exchange(
        &self,
        model: &str,
        client_nonce: Option<&str>,
        request_bytes: &[u8],
        response_bytes: &[u8],
        latency_ms: f64,
    ) -> anyhow::Result<EmittedCapsule> {
        let agent_input_digest = hex_sha256(request_bytes);
        let agent_output_digest = hex_sha256(response_bytes);

        let mut ledger = self.ledger.lock().expect("capsule ledger mutex poisoned");
        let chain = ledger.chain_head().map(|parent| ChainLink {
            parent_capsule_id: parent.to_string(),
            relation: "follows".to_string(),
        });

        let mut generation_parameters = Map::new();
        generation_parameters.insert("temperature".into(), Value::String("0.0".into()));

        let input = CapsuleInput {
            action_id: format!("mesh-poc/capsule-emit-mesh-integration/{agent_input_digest}"),
            action_type: "decide".to_string(),
            operator: "capsule-emit-mesh-poc-rust".to_string(),
            developer: "capsule-producer/0.2.0".to_string(),
            timestamp: utc_now_iso8601(),
            domain: Some("action".to_string()),
            provenance: Some("collector".to_string()),
            model_id: model.to_string(),
            provider: "mesh-llm".to_string(),
            agent_input_digest: agent_input_digest.clone(),
            agent_output_digest: agent_output_digest.clone(),
            runtime: format!(
                "{}:admission-policy-plugin/mesh-llm-host-runtime",
                "0".repeat(64)
            ),
            mesh_poc: MeshPocV1 {
                client_nonce: client_nonce.unwrap_or("sidecar-generated").to_string(),
                client_nonce_source: if client_nonce.is_some() {
                    "client_supplied"
                } else {
                    "sidecar_generated_fallback"
                }
                .to_string(),
                model_package_digest: hex_sha256(model.as_bytes()),
                generation_parameters,
                latency_ms: format!("{latency_ms:.3}"),
            },
            effect_status: "confirmed".to_string(),
            effect_type: "inference_completion".to_string(),
            effect_request_digest: agent_input_digest,
            effect_response_digest: agent_output_digest,
            effect_attestation: "gate_executed".to_string(),
            disposition_decision: "accept".to_string(),
            // §5.4: disposition.approver MUST be `human` or `policy` -- the
            // admission-policy plugin is the latter (an automated policy
            // engine, not a human disposer), never its own plugin name.
            disposition_approver: "policy".to_string(),
            disposition_human_disposed: false,
            disposition_verdict_class: "executed".to_string(),
            chain,
        };

        let capsule = seal(&input)?;
        let capsule_id = capsule["capsule_id"]
            .as_str()
            .expect("seal() always sets capsule_id")
            .to_string();
        let payload = capsule_producer::capsule::payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: &self.node_id,
                subject: &capsule_id,
                content_type: CAPSULE_CONTENT_TYPE,
            },
            &self.keys.signing_key,
        );
        ledger.append(&capsule, &statement)?;

        Ok(EmittedCapsule {
            capsule_id,
            capsule,
        })
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
