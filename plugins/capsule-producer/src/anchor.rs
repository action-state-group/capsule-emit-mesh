//! Optional anchor client: POST a capsule_id digest to a SCITT Transparency
//! Service (`capsule-anchor`'s `/v1/digest`) and check durable status via
//! `/v1/inclusion/{capsule_id}`. Mirrors `capsule_emit/checkpoint/emit.py`'s
//! `register_checkpoint()` contract byte-for-byte on the wire (same
//! endpoint, same `{"capsule_id": "<64-hex>"}` request, same response
//! shape) so this client and the Python one are interchangeable against the
//! same service.
//!
//! Deliberately **not** wired into `capsule::seal`/`ledger::append` — the
//! task calls this an optional client, and `capsule_emit/witness.py`'s own
//! design (fail-open, never let a network error break local production) is
//! the right model: callers decide when/whether to anchor, and a failed
//! anchor call is never allowed to invalidate an already-sealed, already-
//! ledgered capsule.

use serde::Deserialize;
use std::time::Duration;

pub const DEFAULT_ANCHOR_BASE: &str = "https://anchor.agentactioncapsule.org";

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("anchor request failed: {0}")]
    Transport(String),
    #[error("anchor service returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("anchor response was not valid JSON: {0}")]
    Decode(String),
}

/// `RegisterStatementResponse` shape from `capsule-anchor`'s
/// `POST /v1/digest` and `POST /transparency/register-statement`.
#[derive(Debug, Clone, Deserialize)]
pub struct AnchorReceipt {
    pub receipt_b64: String,
    pub entry_hash: String,
    #[serde(default)]
    pub entry_hash_scheme: Option<String>,
    pub leaf_index: u64,
    pub tree_size: u64,
    #[serde(default)]
    pub checkpoint_witness: Option<serde_json::Value>,
}

/// `GET /v1/inclusion/{capsule_id}` response shape -- proves the digest was
/// actually logged, not just accepted by `/v1/digest` (registration is fire-
/// and-forget from the caller's view; inclusion is the durable-status check).
#[derive(Debug, Clone, Deserialize)]
pub struct InclusionProof {
    pub capsule_id: String,
    pub entry_hash: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub root_hash: String,
    pub receipt_b64: String,
}

pub struct AnchorClient {
    base_url: String,
    agent: ureq::Agent,
}

impl AnchorClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
        }
    }

    /// `POST /v1/digest {"capsule_id": <64-hex>}`. Idempotent on the server
    /// side: resubmitting the same `capsule_id` returns the original
    /// receipt, so callers may retry freely.
    pub fn post_digest(&self, capsule_id: &str) -> Result<AnchorReceipt, AnchorError> {
        let url = format!("{}/v1/digest", self.base_url.trim_end_matches('/'));
        match self
            .agent
            .post(&url)
            .send_json(ureq::json!({ "capsule_id": capsule_id }))
        {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| AnchorError::Decode(e.to_string())),
            Err(ureq::Error::Status(status, resp)) => Err(AnchorError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(AnchorError::Transport(e.to_string())),
        }
    }

    /// `GET /v1/inclusion/{capsule_id}` -- `Ok(None)` on a 404 (not yet
    /// durable, or never submitted); never registers as a side effect,
    /// unlike `post_digest`.
    pub fn check_inclusion(
        &self,
        capsule_id: &str,
    ) -> Result<Option<InclusionProof>, AnchorError> {
        let url = format!(
            "{}/v1/inclusion/{}",
            self.base_url.trim_end_matches('/'),
            capsule_id
        );
        match self.agent.get(&url).call() {
            Ok(resp) => resp
                .into_json()
                .map(Some)
                .map_err(|e| AnchorError::Decode(e.to_string())),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(status, resp)) => Err(AnchorError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(AnchorError::Transport(e.to_string())),
        }
    }

    /// `GET /anchor/authority-pubkey` -- the raw 32-byte Ed25519 authority
    /// public key (hex) + its `key_id`, for out-of-band pinning and for
    /// verifying receipts offline via `scitt_cose.verify_receipt`.
    pub fn authority_pubkey(&self) -> Result<AuthorityPubkey, AnchorError> {
        let url = format!(
            "{}/anchor/authority-pubkey",
            self.base_url.trim_end_matches('/')
        );
        match self.agent.get(&url).call() {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| AnchorError::Decode(e.to_string())),
            Err(ureq::Error::Status(status, resp)) => Err(AnchorError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(AnchorError::Transport(e.to_string())),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorityPubkey {
    pub pubkey_hex: String,
    pub key_id: String,
}

impl Default for AnchorClient {
    fn default() -> Self {
        Self::new(DEFAULT_ANCHOR_BASE)
    }
}
