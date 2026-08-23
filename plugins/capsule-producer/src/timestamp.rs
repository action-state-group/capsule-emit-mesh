//! UTC RFC3339 timestamp helper, matching the shape of `emit.py`'s
//! `_utc_now()` (`now.isoformat().replace("+00:00", "Z")`) closely enough for
//! producer-side event records (key rotation, ledger bookkeeping) -- not
//! itself part of any cross-language byte-conformance surface.

pub fn utc_now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
