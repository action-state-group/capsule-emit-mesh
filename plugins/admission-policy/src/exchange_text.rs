//! The owner's opt-in to keep the TEXT of each exchange (prompt and answer)
//! beside its sealed record, so the twin comparison and "Your records" can
//! show it. Off unless `ADMISSION_POLICY_KEEP_EXCHANGE_TEXT=1`; nothing is
//! written otherwise.
//!
//! The text comes from the host, and only when its operator hands exchange
//! bodies to plugins (`MESH_LLM_PLUGIN_EXCHANGE_BODIES=1`, off by default):
//! the `openai.exchange.v1` terminal event then carries `exchange_bodies`.
//! Both switches must be on for anything to be kept.
//!
//! Each exchange gets one file, `<ledger>/disclosures/by-exchange/<exchange_id>.json`
//! (both directories 0700, file 0600, written whole by rename), keyed by the
//! host's `exchange_id`, which this plugin seals in `serving_provenance`.
//! Files older than `ADMISSION_POLICY_KEEP_EXCHANGE_TEXT_DAYS` (default 30)
//! are removed, checked at most once an hour per directory, on a write.
//! "Clean up records" deletes them (`owner_maintenance`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use crate::lifecycle_channel::ExchangeBodies;

/// Set to `1` to keep prompt and answer text. Off by default.
pub const KEEP_EXCHANGE_TEXT_ENV: &str = "ADMISSION_POLICY_KEEP_EXCHANGE_TEXT";
/// How many days a kept text stays; a positive whole number, else the default.
pub const KEEP_EXCHANGE_TEXT_DAYS_ENV: &str = "ADMISSION_POLICY_KEEP_EXCHANGE_TEXT_DAYS";
const DEFAULT_KEEP_DAYS: u64 = 30;
/// A directory is pruned at most this often.
const PRUNE_EVERY: Duration = Duration::from_secs(60 * 60);

pub fn enabled() -> bool {
    enabled_from(std::env::var(KEEP_EXCHANGE_TEXT_ENV).ok().as_deref())
}

fn enabled_from(value: Option<&str>) -> bool {
    value.map(str::trim) == Some("1")
}

fn retention(days: Option<&str>) -> Duration {
    let days = days
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_KEEP_DAYS);
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

/// Remove kept texts (and leftover temp files) last written more than
/// `max_age` before `now`. Returns how many were removed.
fn prune(dir: &Path, max_age: Duration, now: SystemTime) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.ends_with(".json") || name.ends_with(".json.tmp")) {
            continue;
        }
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        let age = now
            .duration_since(metadata.modified()?)
            .unwrap_or(Duration::ZERO);
        if age > max_age {
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Prune `dir` unless it was pruned within the last `PRUNE_EVERY`. A failed
/// prune is logged; it never fails the write that triggered it.
fn prune_if_due(dir: &Path) {
    static LAST: std::sync::Mutex<Option<std::collections::HashMap<PathBuf, Instant>>> =
        std::sync::Mutex::new(None);
    {
        let mut last = LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last = last.get_or_insert_with(Default::default);
        let now = Instant::now();
        if last
            .get(dir)
            .is_some_and(|at| now.duration_since(*at) < PRUNE_EVERY)
        {
            return;
        }
        last.insert(dir.to_path_buf(), now);
    }
    let max_age = retention(std::env::var(KEEP_EXCHANGE_TEXT_DAYS_ENV).ok().as_deref());
    if let Err(error) = prune(dir, max_age, SystemTime::now()) {
        tracing::warn!(%error, "could not prune kept exchange text");
    }
}

/// An exchange id is host-minted (a UUID); anything else never names a file.
fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Write one exchange's text file from the bodies the host handed over.
/// Returns the file written, or `None` when there is nothing to keep (no
/// bodies, or an id that can't name a file). The caller checks [`enabled`].
pub fn keep(
    ledger_dir: &Path,
    exchange_id: &str,
    twin_bracket_id: Option<&str>,
    bodies: &ExchangeBodies,
) -> std::io::Result<Option<PathBuf>> {
    if !safe_id(exchange_id) || (bodies.request.is_none() && bodies.response.is_none()) {
        return Ok(None);
    }
    let response_text = bodies
        .response
        .as_ref()
        .and_then(|body| body.pointer("/choices/0/message/content"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut document = json!({
        "v": 1,
        "exchange_id": exchange_id,
        "request_body": bodies.request,
        "response_body": bodies.response,
        "response_text": response_text,
        "written_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    if let Some(bracket) = twin_bracket_id {
        document["twin_bracket_id"] = json!(bracket);
    }
    let disclosures = ledger_dir.join("disclosures");
    let dir = disclosures.join("by-exchange");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for private in [&disclosures, &dir] {
            std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let path = dir.join(format!("{exchange_id}.json"));
    let tmp = dir.join(format!(".{exchange_id}.json.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&serde_json::to_vec(&document)?)?;
    file.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    prune_if_due(&dir);
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bodies(request: Option<Value>, response: Option<Value>) -> ExchangeBodies {
        ExchangeBodies { request, response }
    }

    #[test]
    fn only_one_turns_it_on_and_it_is_off_by_default() {
        assert!(enabled_from(Some("1")));
        for value in [None, Some(""), Some("0"), Some("true"), Some("2")] {
            assert!(!enabled_from(value), "{value:?}");
        }
    }

    #[test]
    fn the_bodies_are_kept_whole_0600_in_a_0700_directory() {
        let dir = tempfile::tempdir().unwrap();
        let request =
            json!({"model": "m", "messages": [{"role": "user", "content": "Sky colour?"}]});
        let response =
            json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": "Blue"}}]});
        let written = keep(
            dir.path(),
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            Some("twin-1"),
            &bodies(Some(request.clone()), Some(response.clone())),
        )
        .unwrap()
        .expect("a file");
        let saved: Value = serde_json::from_slice(&std::fs::read(&written).unwrap()).unwrap();
        assert_eq!(
            saved["exchange_id"],
            json!("0f8fad5b-d9cb-469f-a165-70867728950e")
        );
        assert_eq!(saved["request_body"], request);
        assert_eq!(saved["response_body"], response);
        assert_eq!(saved["response_text"], json!("Blue"));
        assert_eq!(saved["twin_bracket_id"], json!("twin-1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&written), 0o600);
            assert_eq!(mode(written.parent().unwrap()), 0o700);
            assert_eq!(mode(&dir.path().join("disclosures")), 0o700);
        }
    }

    #[test]
    fn nothing_is_written_without_bodies_or_for_an_unsafe_id() {
        let dir = tempfile::tempdir().unwrap();
        assert!(keep(dir.path(), "abc", None, &bodies(None, None))
            .unwrap()
            .is_none());
        let request = Some(json!({"model": "m"}));
        for id in ["../escape", "", "a/b", &"a".repeat(65)] {
            assert!(
                keep(dir.path(), id, None, &bodies(request.clone(), None))
                    .unwrap()
                    .is_none(),
                "{id}"
            );
        }
        assert!(!dir.path().join("disclosures").exists());
    }

    fn file_aged(path: &Path, age: Duration) {
        std::fs::write(path, b"{}").unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    /// Kept text does not accumulate forever. MUTANT: never remove, or
    /// remove regardless of age, and this fails.
    #[test]
    fn prune_removes_only_texts_older_than_the_retention() {
        let dir = tempfile::tempdir().unwrap();
        let day = Duration::from_secs(24 * 60 * 60);
        file_aged(&dir.path().join("old.json"), 31 * day);
        file_aged(&dir.path().join(".old.json.tmp"), 31 * day);
        file_aged(&dir.path().join("fresh.json"), day);
        file_aged(&dir.path().join("not-ours.txt"), 31 * day);

        let removed = prune(dir.path(), retention(None), SystemTime::now()).unwrap();

        assert_eq!(removed, 2);
        assert!(!dir.path().join("old.json").exists());
        assert!(!dir.path().join(".old.json.tmp").exists());
        assert!(dir.path().join("fresh.json").exists());
        assert!(dir.path().join("not-ours.txt").exists());
    }

    #[test]
    fn retention_is_a_positive_number_of_days_else_thirty() {
        let day = Duration::from_secs(24 * 60 * 60);
        assert_eq!(retention(None), 30 * day);
        assert_eq!(retention(Some("7")), 7 * day);
        assert_eq!(retention(Some("0")), 30 * day);
        assert_eq!(retention(Some("soon")), 30 * day);
    }

    /// The wiring: a write prunes its directory.
    #[test]
    fn a_write_prunes_stale_texts_in_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let by_exchange = dir.path().join("disclosures").join("by-exchange");
        std::fs::create_dir_all(&by_exchange).unwrap();
        let stale = by_exchange.join("0f8fad5b-d9cb-469f-a165-000000000000.json");
        file_aged(&stale, Duration::from_secs(400 * 24 * 60 * 60));
        keep(
            dir.path(),
            "6f9619ff-8b86-d011-b42d-00c04fc964aa",
            None,
            &bodies(Some(json!({"model": "m"})), None),
        )
        .unwrap()
        .expect("a file");
        assert!(!stale.exists());
    }
}
