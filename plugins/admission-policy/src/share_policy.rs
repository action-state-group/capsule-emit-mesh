//! the sharing-policy This plugin's `config_schema` declaration for
//! the one sharing-policy object -- four switches, one key (design note
//! `_work/mesh-sharing-policy-history-and-money-2026-09-24.md` S1;
//! `docs/SHARING-POLICY.md`; Python-side shape at
//! `capsule-emit-mesh/share_policy.py`'s `SharePolicy`). Declaring it here
//! makes mesh's console render the four switches under Configuration >
//! Plugins with the host's own controls -- nothing here is a score, and
//! nothing here ranks anyone.
//!
//! **Declarative only, same honest scope-cut as the Python side.** mesh-llm
//! 0.76 gives a plugin its own declared `config_schema` but there is no
//! live host-to-plugin config channel wired yet (`share_policy.py`'s own
//! "Known gap" note) -- an operator sets the four `ADMISSION_POLICY_SHARE_*`
//! / `ADMISSION_POLICY_WITNESS` env vars directly on the node today. This
//! module's setting keys match those env var suffixes byte for byte
//! (`share_record_at_completion` -> `ADMISSION_POLICY_SHARE_RECORD_AT_COMPLETION`,
//! etc.) so wiring the host's resolved value into this process's env later
//! is a direct 1:1 map, not a re-naming exercise. Adding this schema does
//! not by itself flip any runtime behavior -- it only makes the four
//! switches visible and editable in the console.

use mesh_llm_plugin::{config_enum, config_schema, config_setting, config_url, ManifestEntry};

pub const RECORD_AT_COMPLETION_KEY: &str = "share_record_at_completion";
pub const HISTORY_SEGMENTS_KEY: &str = "share_history_segments";
pub const ADJUDICATIONS_KEY: &str = "share_adjudications";
pub const WITNESS_KEY: &str = "witness";

const CATEGORY_ID: &str = "share";
const CATEGORY_LABEL: &str = "Sharing policy";
const CATEGORY_SUMMARY: &str = "What this node shares, with whom, by default. Every default keys \
    on relationship (counterparty in the window), never proximity or latency.";

/// The `config_schema` manifest entry naming all four switches. Attach with
/// `DeclarativePluginBuilder::config_item`.
pub fn share_policy_config_schema(plugin_id: &str) -> ManifestEntry {
    config_schema(plugin_id)
        .setting(
            config_setting(RECORD_AT_COMPLETION_KEY, config_enum(["counterparty", "off"]))
                .default_value(&"counterparty")
                .description(
                    "Push this node's own sealed record of a completed exchange to the \
                     counterparty (counterparty), or don't (off). Symmetric: a node with this \
                     off also does not receive the other side's push -- fetch-on-request still \
                     works either way.",
                )
                .label("Record at completion")
                .category(CATEGORY_ID, CATEGORY_LABEL, CATEGORY_SUMMARY, 0),
        )
        .setting(
            config_setting(
                HISTORY_SEGMENTS_KEY,
                config_enum(["counterparties", "prospective", "peers", "off"]),
            )
            .default_value(&"prospective")
            .description(
                "Who this node answers a chain-segment/record/correlation request from: past \
                 counterparties only, counterparties plus prospective ones (default), any peer, \
                 or nobody. A refusal is structural (not_authorized), never a score.",
            )
            .label("History segments")
            .category(CATEGORY_ID, CATEGORY_LABEL, CATEGORY_SUMMARY, 1),
        )
        .setting(
            config_setting(ADJUDICATIONS_KEY, config_enum(["deliver_to_subjects", "off"]))
                .default_value(&"deliver_to_subjects")
                .description(
                    "Deliver a sealed verdict to every node it judges (default), or don't. The \
                     subject acks or disputes on its own chain -- this is delivery, never a \
                     computed standing.",
                )
                .label("Adjudications")
                .category(CATEGORY_ID, CATEGORY_LABEL, CATEGORY_SUMMARY, 2),
        )
        .setting(
            config_setting(WITNESS_KEY, config_url())
                .description(
                    "Witness service URL to checkpoint against. Empty is off (the default) -- no \
                     default witness URL, no network call without an operator-supplied one.",
                )
                .label("Witness")
                .category(CATEGORY_ID, CATEGORY_LABEL, CATEGORY_SUMMARY, 3),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_llm_plugin::proto;

    fn as_config_schema(entry: ManifestEntry) -> proto::PluginConfigSchemaManifest {
        match entry {
            ManifestEntry::ConfigSchema(schema) => schema,
            other => panic!("expected ManifestEntry::ConfigSchema, got {other:?}"),
        }
    }

    #[test]
    fn declares_all_four_switches_under_the_plugin_id() {
        let schema = as_config_schema(share_policy_config_schema("admission-policy"));
        assert_eq!(schema.plugin_name, "admission-policy");
        let keys: Vec<&str> = schema.settings.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![RECORD_AT_COMPLETION_KEY, HISTORY_SEGMENTS_KEY, ADJUDICATIONS_KEY, WITNESS_KEY]
        );
    }

    #[test]
    fn setting_keys_match_the_python_env_var_suffix_convention() {
        // the sharing-policy share_policy.py's ENV_* constants, minus
        // the shared ADMISSION_POLICY_ prefix -- this module's whole "no
        // re-naming exercise later" claim rests on this correspondence.
        let expected_env_suffix = [
            (RECORD_AT_COMPLETION_KEY, "SHARE_RECORD_AT_COMPLETION"),
            (HISTORY_SEGMENTS_KEY, "SHARE_HISTORY_SEGMENTS"),
            (ADJUDICATIONS_KEY, "SHARE_ADJUDICATIONS"),
            (WITNESS_KEY, "WITNESS"),
        ];
        for (key, suffix) in expected_env_suffix {
            assert_eq!(key.to_uppercase(), suffix, "key {key} must upper-case to its env suffix");
        }
    }

    #[test]
    fn record_at_completion_and_adjudications_default_to_the_documented_on_state() {
        let schema = as_config_schema(share_policy_config_schema("admission-policy"));
        let by_key = |k: &str| schema.settings.iter().find(|s| s.key == k).unwrap();
        assert_eq!(by_key(RECORD_AT_COMPLETION_KEY).default_json.as_deref(), Some("\"counterparty\""));
        assert_eq!(by_key(HISTORY_SEGMENTS_KEY).default_json.as_deref(), Some("\"prospective\""));
        assert_eq!(by_key(ADJUDICATIONS_KEY).default_json.as_deref(), Some("\"deliver_to_subjects\""));
    }

    #[test]
    fn witness_has_no_default_url_and_is_not_required() {
        // Design note S1: "witness: off | <url> # default: off" -- off IS
        // the absence of a default, never a magic sentinel string.
        let schema = as_config_schema(share_policy_config_schema("admission-policy"));
        let witness = schema.settings.iter().find(|s| s.key == WITNESS_KEY).unwrap();
        assert_eq!(witness.default_json, None);
        assert!(!witness.required);
    }

    #[test]
    fn every_setting_is_optional_shipping_this_schema_flips_no_runtime_behavior() {
        let schema = as_config_schema(share_policy_config_schema("admission-policy"));
        assert!(schema.settings.iter().all(|s| !s.required));
    }
}
