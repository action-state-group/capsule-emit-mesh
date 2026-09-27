//! `mesh_local_routing_choice`: the host's block store asks this plugin to
//! seal a record of a local routing choice (block or unblock a peer).
//!
//! The host owns the choice and enforces it in its router; this plugin only
//! seals the record onto the node's one chain. The record names the peer by a
//! salted commitment, and the salt comes back to the host, which keeps it in
//! its local store (see `capsule_producer::capsule::seal_local_routing_choice`).

use std::sync::Arc;

use capsule_producer::capsule::RoutingChoiceChange;
use mesh_llm_plugin::{PluginError, PluginResult};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::capsule_emit::CapsuleState;

pub const LOCAL_ROUTING_CHOICE_OPERATION: &str = "mesh_local_routing_choice";

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeArg {
    Block,
    Unblock,
}

impl From<ChangeArg> for RoutingChoiceChange {
    fn from(change: ChangeArg) -> Self {
        match change {
            ChangeArg::Block => Self::Block,
            ChangeArg::Unblock => Self::Unblock,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LocalRoutingChoiceArgs {
    pub change: ChangeArg,
    /// Hex-encoded mesh endpoint id of the peer.
    pub peer_id: String,
    /// RFC 3339 time a block lapses; absent for "until I undo" and for unblock.
    #[serde(default)]
    pub until: Option<String>,
}

/// Returns `{capsule_id, peer_commitment, salt}` for the host's block store.
pub fn handle_local_routing_choice(
    capsules: &Arc<CapsuleState>,
    args: LocalRoutingChoiceArgs,
) -> PluginResult<Value> {
    let peer_id = args.peer_id.trim();
    if peer_id.is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }
    if matches!(args.change, ChangeArg::Unblock) && args.until.is_some() {
        return Err(PluginError::invalid_params("an unblock has no `until`"));
    }
    let emitted = capsules
        .emit_local_routing_choice(args.change.into(), peer_id, args.until.as_deref())
        .map_err(|error| PluginError::internal(format!("could not seal the record: {error}")))?;
    Ok(json!({
        "capsule_id": emitted.capsule_id,
        "peer_commitment": emitted.peer_commitment,
        "salt": emitted.salt_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(tag: &str) -> Arc<CapsuleState> {
        let dir = std::env::temp_dir().join(format!("route-bridge-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(CapsuleState::open(&dir, "node-under-test").expect("open state"))
    }

    #[test]
    fn block_returns_the_sealed_id_and_its_salt() {
        let capsules = state("ok");
        let out = handle_local_routing_choice(
            &capsules,
            LocalRoutingChoiceArgs {
                change: ChangeArg::Block,
                peer_id: "a".repeat(64),
                until: None,
            },
        )
        .expect("sealed");
        assert_eq!(
            out["capsule_id"].as_str(),
            capsules.chain_head().as_deref(),
            "the returned id is the record now at the chain head"
        );
        assert_eq!(out["salt"].as_str().map(str::len), Some(64));
    }

    #[test]
    fn empty_peer_and_unblock_with_until_are_refused_without_sealing() {
        let capsules = state("bad");
        let empty = handle_local_routing_choice(
            &capsules,
            LocalRoutingChoiceArgs {
                change: ChangeArg::Block,
                peer_id: "  ".into(),
                until: None,
            },
        );
        assert!(empty.is_err());
        let unblock_until = handle_local_routing_choice(
            &capsules,
            LocalRoutingChoiceArgs {
                change: ChangeArg::Unblock,
                peer_id: "a".repeat(64),
                until: Some("2026-10-04T00:00:00Z".into()),
            },
        );
        assert!(unblock_until.is_err());
        assert_eq!(capsules.chain_head(), None, "a refused call seals nothing");
    }
}
