//! [disclosure-default-on] Persists the request+response TEXT preimage a
//! sealed capsule digested, into `<ledger_dir>/disclosures/<capsule_id>.json`
//! -- a Rust port of capsule-emit-mesh PR #79's
//! `capsule_sidecar.persist_disclosure_preimage` (and its
//! `_extract_prompt_text` / `_extract_response_text` helpers), matching that
//! JSON schema EXACTLY so the mesh-llm-host-runtime Capsules tab (which reads
//! this schema from either producer) renders either one identically.
//!
//! This is a LOCAL, out-of-band attachment carried alongside the ledger: it
//! changes nothing about the SIGNED capsule -- `request_digest`/
//! `response_digest`/`capsule_id` are computed exactly as before (see
//! `capsule_emit.rs`), and the wire/verifiable object still commits to
//! request/response by digest only. It exists purely so a human operator can
//! see the actual exchange in the tab and recompute-and-match it against the
//! sealed digests in-browser.
//!
//! The host forwards the raw request/response body TEXT on the
//! `openai.exchange.v1` terminal envelope only when its own disclosure flag
//! is on (`MESH_LLM_DISCLOSE_PREIMAGE`, default ON) -- see
//! `lifecycle_channel::OpenAiExchangeEnvelope::request_body_text` /
//! `response_body_text`. When the host forwarded neither (older host,
//! disclosure off there, or a streamed response it never buffered), this is
//! a silent no-op: no disclosure file is written for that capsule, matching
//! the Python sidecar's `disclose_preimage: bool = False` behavior.

use serde_json::{Map, Value};
use std::path::Path;

/// Best-effort plain-text prompt for the DISCLOSED display -- the last
/// `user` message's content. `None` when the request has no messages or no
/// user turn -- never invented. Display convenience only: the digest-VERIFIED
/// preimage is the full `request_body` persisted alongside it, not this text.
/// Mirrors the Python reference `capsule_sidecar._extract_prompt_text`.
fn extract_prompt_text(request_json: &Value) -> Option<String> {
    let messages = request_json.get("messages")?.as_array()?;
    for message in messages.iter().rev() {
        let message = message.as_object()?;
        if message.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        match message.get("content") {
            Some(Value::String(s)) => return Some(s.clone()),
            Some(Value::Array(parts)) => {
                let joined: Vec<&str> = parts
                    .iter()
                    .filter_map(|part| {
                        let part = part.as_object()?;
                        if part.get("type").and_then(Value::as_str) != Some("text") {
                            return None;
                        }
                        part.get("text").and_then(Value::as_str)
                    })
                    .collect();
                if !joined.is_empty() {
                    return Some(joined.join("\n"));
                }
            }
            _ => {}
        }
    }
    None
}

/// Best-effort plain-text assistant reply + tool-call note for DISPLAY.
/// Returns `(text, tool_calls_note)`; either may be `None`. Never invented --
/// the digest-VERIFIED preimage is the full `response_body` persisted
/// alongside it, not this text. Mirrors the Python reference
/// `capsule_sidecar._extract_response_text`.
fn extract_response_text(response_json: &Value) -> (Option<String>, Option<String>) {
    let Some(choices) = response_json.get("choices").and_then(Value::as_array) else {
        return (None, None);
    };
    let Some(message) = choices.first().and_then(|c| c.get("message")) else {
        return (None, None);
    };
    let text = message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string);
    let note = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .filter(|tcs| !tcs.is_empty())
        .map(|tcs| {
            let names: Vec<&str> = tcs
                .iter()
                .filter_map(|tc| tc.get("function")?.get("name")?.as_str())
                .collect();
            if names.is_empty() {
                "tool_call(s) made".to_string()
            } else {
                format!("tool_call(s): {}", names.join(", "))
            }
        });
    (text, note)
}

/// Write the request/response PREIMAGE this plugin just sealed a capsule
/// for, keyed by `capsule_id`, into `<disclosures_dir>/<capsule_id>.json` --
/// only when the host forwarded at least one of the raw bodies (its own
/// `MESH_LLM_DISCLOSE_PREIMAGE` flag, default ON). A no-op when the host
/// forwarded neither -- an older host, disclosure off there, or a streamed
/// response it never buffered -- never a fabricated disclosure.
///
/// Best-effort: a parse or write failure here must never break the sealing
/// path that already succeeded and was recorded in the ledger.
pub fn persist_disclosure_preimage(
    disclosures_dir: &Path,
    capsule_id: &str,
    request_body_text: Option<&str>,
    response_body_text: Option<&str>,
) {
    if request_body_text.is_none() && response_body_text.is_none() {
        return;
    }
    let request_body = request_body_text.and_then(|t| serde_json::from_str::<Value>(t).ok());
    let response_body = response_body_text.and_then(|t| serde_json::from_str::<Value>(t).ok());
    let request_text = request_body.as_ref().and_then(extract_prompt_text);
    let (response_text, tool_calls_note) = response_body
        .as_ref()
        .map(extract_response_text)
        .unwrap_or((None, None));

    let mut record = Map::new();
    record.insert("capsule_id".into(), Value::String(capsule_id.to_string()));
    record.insert("request_body".into(), request_body.unwrap_or(Value::Null));
    record.insert("response_body".into(), response_body.unwrap_or(Value::Null));
    record.insert(
        "request_text".into(),
        request_text.map(Value::String).unwrap_or(Value::Null),
    );
    record.insert(
        "response_text".into(),
        response_text.map(Value::String).unwrap_or(Value::Null),
    );
    record.insert(
        "tool_calls_note".into(),
        tool_calls_note.map(Value::String).unwrap_or(Value::Null),
    );

    if let Err(error) = std::fs::create_dir_all(disclosures_dir) {
        tracing::warn!(%error, capsule_id, "disclosure preimage dir creation failed (best-effort, continuing)");
        return;
    }
    let path = disclosures_dir.join(format!("{capsule_id}.json"));
    if let Err(error) = std::fs::write(&path, Value::Object(record).to_string()) {
        tracing::warn!(%error, capsule_id, "disclosure preimage write failed (best-effort, continuing)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_prompt_text_returns_last_user_message() {
        let request = serde_json::json!({
            "messages": [
                {"role": "system", "content": "be nice"},
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "second"}
            ]
        });
        assert_eq!(extract_prompt_text(&request).as_deref(), Some("second"));
    }

    #[test]
    fn extract_prompt_text_joins_multipart_text_content() {
        let request = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "image_url", "image_url": {"url": "x"}},
                    {"type": "text", "text": "part two"}
                ]}
            ]
        });
        assert_eq!(
            extract_prompt_text(&request).as_deref(),
            Some("part one\npart two")
        );
    }

    #[test]
    fn extract_prompt_text_none_when_no_user_turn() {
        let request = serde_json::json!({"messages": [{"role": "system", "content": "x"}]});
        assert!(extract_prompt_text(&request).is_none());
    }

    #[test]
    fn extract_response_text_returns_content_and_tool_calls_note() {
        let response = serde_json::json!({
            "choices": [{"message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "web_search"}}]
            }}]
        });
        let (text, note) = extract_response_text(&response);
        assert_eq!(text.as_deref(), Some(""));
        assert_eq!(note.as_deref(), Some("tool_call(s): web_search"));
    }

    #[test]
    fn extract_response_text_none_note_when_no_tool_calls() {
        let response = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "hello"}}]
        });
        let (text, note) = extract_response_text(&response);
        assert_eq!(text.as_deref(), Some("hello"));
        assert!(note.is_none());
    }

    #[test]
    fn persist_disclosure_preimage_writes_matching_pr79_schema() {
        let dir = std::env::temp_dir().join(format!("disclosure-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let request = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let response = r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#;

        persist_disclosure_preimage(&dir, "cap-123", Some(request), Some(response));

        let written = std::fs::read_to_string(dir.join("cap-123.json")).expect("read disclosure");
        let value: Value = serde_json::from_str(&written).expect("parse disclosure json");
        assert_eq!(value["capsule_id"], "cap-123");
        assert_eq!(value["request_body"]["model"], "m");
        assert_eq!(value["response_body"]["choices"][0]["message"]["content"], "hello");
        assert_eq!(value["request_text"], "hi");
        assert_eq!(value["response_text"], "hello");
        assert!(value["tool_calls_note"].is_null());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_disclosure_preimage_no_op_when_host_forwarded_neither_body() {
        let dir = std::env::temp_dir().join(format!("disclosure-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        persist_disclosure_preimage(&dir, "cap-none", None, None);

        assert!(!dir.join("cap-none.json").exists());
        assert!(!dir.exists(), "no directory should be created for a no-op");
    }
}
