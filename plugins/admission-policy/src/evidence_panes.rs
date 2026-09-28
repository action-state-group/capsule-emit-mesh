//! The Evidence page's three panes, built from this plugin's own ledger
//! directory and served by the plugin's `panes/*` routes (`evidence_routes`,
//! `web-ui/DATA-ROUTES.md`).
//!
//! Reads `<ledger_dir>/capsules.jsonl` (this node's records, padding left
//! out), `checkpoints.jsonl` (the Integrity card) and the record-push door's
//! held-artifact store `received-capsules.jsonl` (the other side's records),
//! the same on-disk shapes the Python reference panes read. No network call.
//! Moved here from the console fork's host, where the same builder served the
//! console tab; the two stay one implementation until the console copy is
//! retired.
//!
//! **Scope of this first cut, verified against a live capsule-emit-mesh
//! checkout, not guessed.** Every field derivable from the raw ledger
//! records alone -- with no signature/chain re-verification and no data
//! this record's own writer didn't put there -- matches
//! `accountability_pane_routes.build_pane_{a,b,c}_json` byte-for-byte on a
//! plugin-shaped fixture (no checkpoint, no peer-fetch, no serving-
//! provenance block): capsule id/timestamp, `model_claimed`'s honest
//! last-resort default (`friendly_model_name`'s final fallback,
//! `capsule_mesh_viewer.py:365`, always `"local model"` when no serving-
//! provenance data has landed yet), the Pane-A rungs' structural
//! defaults (`freshness`/`runtime_binding`/`tee_citation`/
//! `hardware_inventory` = `"absent"`, `log_integrity` =
//! `"present-unverified"` -- `verify_ok is None` reads as "present, not
//! yet independently verified", never a fabricated PASS/FAIL), exchange
//! grouping (`exchange_key_for`), and role labelling (`label_role`,
//! `source_log = "plugin"`, whose own default-by-source table already
//! says a plugin-written record is always this node acting as the
//! serving PROVIDER -- `capsule_mesh_view.py:81-83`).
//!
//! ** retirement, native reader only:**
//! Pane A's `cross_party` cell and Pane B's per-row cross-party cell used
//! to carry the `rung`/`unilateral_fallback` ladder word (still live in
//! `capsule_accountability_tab.py`/`peer_accountability_tab.py` upstream,
//! matching `f0e3af6`'s note that Pane A/B were explicitly out of that
//! task's scope). This demo runs native/sidecar-DOWN, so THIS reader is
//! where a stranger reading the raw pane JSON would actually see the
//! retired word -- both cells now emit the same five-state property-map
//! shape (`state`/`text`, `state` one of `PASS`/`FAIL`/`NOT_PRESENT`/
//! `NOT_CHECKED`/`INCONCLUSIVE`) Pane C's `properties` map already uses,
//! always `NOT_PRESENT` here (no counterparty identity data exists on a
//! plugin-written record yet -- the same honest absence the old rung
//! value encoded, in the current vocabulary). This is a deliberate,
//! documented non-parity divergence from the Python reference (which
//! hasn't migrated Pane A/B yet) -- not a byte-for-byte port gap.
//!
//! Two tranches stay `NOT_CHECKED`/absent/null on purpose, matching gaps
//! `accountability_pane_routes.py`'s own docstring already names, not new
//! ones this cut invented:
//!
//! 1. **Peer-fetch cells** (Pane B's `history`/`served`/`verdicts`) --
//!    deferred with the peer-fetch work
//!    (`accountability_pane_routes.py:17-20`). Their real payloads carry
//!    long operator-facing prose and `mine_for_reference` sub-structures
//!    that exist only to explain an already-deferred gap; duplicating that
//!    prose here would be two copies of the same UI copy to keep in sync,
//!    not a second implementation of a check.
//! 2. **The nine-key assurance map** (Pane C's `properties`/`header_state`,
//!    Pane A's `verify_ok`) -- `content_binding`/`continuity` recompute the
//!    capsule's own JCS digest and hash-chain link, `producer_signature`
//!    verifies its COSE_Sign1 statement. All three are real cryptographic
//!    re-verification, already written once in Rust in capsule-producer's
//!    `jcs`/`cose`/`verify` modules -- porting that in is real, bounded
//!    follow-on work, deliberately out of this cut so it doesn't ship as a
//!    silent partial implementation that looks byte-exact and quietly
//!    diverges the day a tampered record lands.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

/// Sentinel for "this mechanism exists but isn't wired for a plugin-ledger
/// read yet" -- never fabricated, never the sidecar's own computed value.
const NOT_CHECKED: &str = "NOT_CHECKED";
/// `capsule_exchange_tab.STATE_PRESENT_UNVERIFIED` / `STATE_ABSENT` --
/// these two ARE purely structural (presence of a record, not a claim
/// about its contents) and are safe to compute without any crypto port.
const STATE_PRESENT_UNVERIFIED: &str = "present-unverified";
const STATE_ABSENT: &str = "absent";
/// `capsule_exchange_tab.STATE_VERIFIED` / `STATE_FAILED` -- the two
/// terminal outcomes of the structural `digest_match_grade`: both digest
/// fields present and byte-equal (`VERIFIED`), or one field disagrees
/// (`FAILED`). Both are STRUCTURAL (string equality of two fields both
/// halves already carry), not a crypto claim -- the same discipline that
/// already lets this reader compute `present-unverified`/`absent`. The
/// crypto CLOSED predicate (signature-ok + capsule_id recompute) still
/// lives in the ONE gate (`exchange-row-state.ts::deriveRightCellState`);
/// this reader only supplies the digests-equal INPUT that gate reads.
const STATE_VERIFIED: &str = "verified";
const STATE_FAILED: &str = "failed";
/// `peer_accountability_tab.CELL_PRESENT`.
const CELL_PRESENT: &str = "present";
/// Five-state property map (`PaneCRow.properties`'s wire vocabulary,
/// `assurance-tone.ts`'s `CHIP_TONE`/`CHIP_LABEL` keys) -- what Pane A's
/// `cross_party` cell and Pane B's per-row cross-party cell render now
/// instead of the retired `rung`/`unilateral_fallback` ladder word
///.
const STATE_NOT_PRESENT: &str = "NOT_PRESENT";
/// The honest text for "no counterparty identity data exists on a
/// plugin-written record yet" -- the same fact the old `unilateral_fallback`
/// rung value encoded, worded in the current vocabulary.
const NO_COUNTERPARTY_EVIDENCE_TEXT: &str = "no counterparty evidence for this record";
/// `capsule_mesh_viewer.friendly_model_name`'s unconditional last-resort
/// fallback (`capsule_mesh_viewer.py:365`) when no serving-provenance
/// architecture/parameter_size/ref data is on the record -- true of every
/// plugin-written record until the serving-provenance protocol PR lands.
const MODEL_CLAIMED_FALLBACK: &str = "local model";

fn not_checked_state() -> Value {
    json!({ "state": NOT_CHECKED })
}

/// The reserved `record_type` of a padding record (Evidence Layer -00
/// §12.1): a ledger line the plugin appends before a checkpoint so the
/// checkpoint's leaf count falls on a bucket boundary. It is a leaf for
/// inclusion and consistency, and never a record: nothing that counts, lists
/// or summarises records includes it (the plugin's `padding::is_padding`).
const RECORD_TYPE_PADDING: &str = "padding";

fn is_padding_record(record: &Value) -> bool {
    record.get("record_type").and_then(Value::as_str) == Some(RECORD_TYPE_PADDING)
}

/// Every parsed line of `<ledger_dir>/capsules.jsonl`, padding included, in
/// leaf order. A missing file or an unparsable line is dropped, never a
/// panic -- mirrors `capsules.rs`'s own "file absent -> 404, not error"
/// discipline.
fn read_ledger_lines(ledger_dir: &Path) -> Vec<Value> {
    let path = ledger_dir.join("capsules.jsonl");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// This node's records from `<ledger_dir>/capsules.jsonl`, same as
/// `ledger_store_backend._read_flat_capsules_page`'s `json.loads(line)`,
/// with padding records left out. Every pane counts and lists from here, so
/// no pane, count or export ever shows a padding line.
pub(crate) fn read_capsule_records(ledger_dir: &Path) -> Vec<Value> {
    read_ledger_lines(ledger_dir)
        .into_iter()
        .filter(|record| !is_padding_record(record))
        .collect()
}

/// How many of the first `leaves` ledger lines are records rather than
/// padding: what a checkpoint over `leaves` leaves covers, in records.
fn records_among_first_leaves(ledger_dir: &Path, leaves: u64) -> u64 {
    let leaves = usize::try_from(leaves).unwrap_or(usize::MAX);
    let covered = read_ledger_lines(ledger_dir)
        .iter()
        .take(leaves)
        .filter(|record| !is_padding_record(record))
        .count();
    u64::try_from(covered).unwrap_or(u64::MAX)
}

/// Inverts an MMR total-node count back to the LEAF count it covers.
///
/// An append-only Merkle Mountain Range over `L` leaves has a fixed total node
/// count: `mmr_size == 2*L - popcount(L)` (each leaf contributes itself plus
/// the internal nodes formed when perfect-binary-tree peaks merge; the merges
/// saved are exactly the set bits of `L`). That relation is strictly increasing
/// in `L`, so a node count uniquely determines its leaf count -- e.g. 15 -> 8,
/// 11 -> 7, 4 -> 3, 1 -> 1. `None` for a node count that no leaf count produces
/// (never a fabricated coverage figure). This is what turns the checkpoint's
/// on-disk `mmr_size` (a NODE count) into the covered-LEAF count the chain strip
/// caption reports -- distinct from `checkpoint_count`, which is merely the
/// number of checkpoint LINES on disk.
fn mmr_leaf_count(mmr_size: u64) -> Option<u64> {
    if mmr_size == 0 {
        return Some(0);
    }
    // From `mmr_size = 2*L - popcount(L)`, `L = (mmr_size + popcount(L)) / 2`,
    // and `popcount(L) <= 64` for any u64 L. So L lies in
    // `[mmr_size/2, mmr_size/2 + 32]` (dividing the +popcount(L) term by 2).
    // Scan that small window rather than a full search; the relation is
    // strictly increasing, so at most one L in the window matches.
    let lo = mmr_size / 2;
    let hi = mmr_size / 2 + 33;
    (lo..=hi).find(|&l| l != 0 && 2 * l - u64::from(l.count_ones()) == mmr_size)
}

/// Reads `<ledger_dir>/checkpoints.jsonl` (co-located with `capsules.jsonl`,
/// written by the plugin's checkpoint cadence via `cll::store` -- one JSON
/// object per line, the same on-disk shape `accountability_pane_routes.py`
/// reads for its own card face) and builds Pane A's `card`.
///
/// The count is the number of real checkpoint lines on disk: 0 when the file
/// is absent or empty -- which `integrity-view.ts` renders as "no checkpoint
/// yet", the honest empty state, never a fabricated registration. When at
/// least one checkpoint exists, the latest one's `timestamp` becomes
/// `registered_no_later_than` and its `witnesses` (the external receipts, or
/// an honest `[]` for a self-checkpointed node) are surfaced -- exactly the
/// fields the Integrity view reads off `card`. `build_pane_a` hardcoded
/// `card: null` before this, so a real on-disk checkpoint never showed.
///
/// `covered_leaf_count` is the number of chain LEAVES the latest checkpoint
/// covers -- the figure the chain strip caption reports. It is NOT
/// `checkpoint_count` (the number of checkpoint lines): the earlier caption
/// mislabelled the line count as a leaf count. It is read directly from the
/// checkpoint line when carried (`covered_leaf_count`/`leaf_count`), else
/// inverted from the line's `mmr_size` (a NODE count) via `mmr_leaf_count`.
fn read_checkpoint_card(ledger_dir: &Path) -> Value {
    let path = ledger_dir.join("checkpoints.jsonl");
    let checkpoints: Vec<Value> = match std::fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    let mut card = json!({ "checkpoint_count": checkpoints.len() });
    if let Some(latest) = checkpoints.last() {
        if let Some(ts) = latest.get("timestamp").and_then(Value::as_str) {
            card["registered_no_later_than"] = json!(ts);
        }
        card["witnesses"] = latest
            .get("witnesses")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if let Some(root) = latest.get("root").and_then(Value::as_str) {
            card["latest_root"] = json!(root);
        }
        if let Some(size) = latest.get("mmr_size") {
            card["latest_mmr_size"] = size.clone();
        }
        // The covered-LEAF count the chain strip reports -- NOT `checkpoint_count`
        // (the number of checkpoint lines). Prefer a leaf count the checkpoint
        // line carries directly (`leaf_count`/`covered_leaf_count`); else invert
        // the MMR node count (`mmr_size`) via `mmr_leaf_count`. Left absent (never
        // a fabricated figure) when neither is available or the node count is not
        // a valid MMR size.
        let carried_leaf = latest
            .get("covered_leaf_count")
            .or_else(|| latest.get("leaf_count"))
            .and_then(Value::as_u64);
        let derived_leaf = latest
            .get("mmr_size")
            .and_then(Value::as_u64)
            .and_then(mmr_leaf_count);
        if let Some(leaves) = carried_leaf.or(derived_leaf) {
            // The leaf count stays the checkpoint's own fact (padding leaves
            // included: they are covered too). What it covers in RECORDS is
            // what the chain strip and "Your records" compare with the record
            // count, so padding never makes unsealed records read as sealed.
            card["covered_leaf_count"] = json!(leaves);
            card["covered_record_count"] = json!(records_among_first_leaves(ledger_dir, leaves));
        }
    }
    card
}

fn request_digest(record: &Value) -> Option<&str> {
    record
        .pointer("/effect/request_digest")
        .and_then(Value::as_str)
}

fn response_digest(record: &Value) -> Option<&str> {
    record
        .pointer("/effect/response_digest")
        .and_then(Value::as_str)
}

// NOTE ON `received-provenance.jsonl`:
// the record-push door still writes it (one line per verified received push:
// `{capsule_id, received_from, via, received_at, signature_ok}`), but this
// reader no longer reads it. The SAME facts now ride on OUR chained CITING
// record (`compute_attestation.received_half`), whose integrity the chain +
// checkpoint actually protect -- so this reader trusts the citing record (the
// cleaner of the two sources named in the ruling), never the co-located
// provenance sibling. See `received_half_provenance`.

/// `record_push.RECEIVED_CAPSULES_FILENAME`
/// -- the HELD-ARTIFACT store the record-push door now writes received foreign
/// capsule BODIES to, by `capsule_id`. A peer's pushed capsule is evidence we
/// HOLD, not a record we MADE: it lives HERE, never in `capsules.jsonl` (our
/// chain). The chained record for a received half is a LOCAL CITING record in
/// `capsules.jsonl` -- identified by its `citation_purpose == "counterparty_half"`
/// reference (never by the `chain.relation` string) -- that references the
/// foreign body by digest; this
/// reader resolves the cited body from this store for the digest recompute the
/// CLOSED gate reads. This store is NOT a ledger -- nothing chains it.
const RECEIVED_CAPSULES_FILENAME: &str = "received-capsules.jsonl";

/// The provenance triple (+ `signature_ok`) the door recorded for one
/// received foreign sibling. The door already verified the signature against
/// the announced peer key BEFORE writing this line (`record_push`'s door:
/// `key_id` matches `announced_key_for(sender_peer_id)` AND
/// `verify_capsule_signature` passes, else the push is refused and NO line is
/// written) -- so `signature_ok` here is the door's recorded verdict, read,
/// never a second signature check in this route (which the module docstring's
/// gap 2 deliberately does not port).
pub(super) struct ReceivedProvenance {
    received_from: String,
    via: String,
    received_at: String,
    signature_ok: bool,
    /// The pushing peer's mesh NODE id,
    /// when the citing record carries it (`received_half.received_from_node_id`
    /// -- sender-node-id capture at the receive door is landing in
    /// capsule-emit-mesh; ledgers written before that have no such field).
    /// This is the ONLY evidence-backed bridge between the endpoint-id and
    /// node-id spaces for a peer that ASKED us: when present, the peer's
    /// node-id alias merges rows with no further code change here; when
    /// absent, no bridge is invented.
    received_from_node_id: Option<String>,
}

/// Reads the held-artifact store
/// `<ledger_dir>/received-capsules.jsonl` into a `foreign capsule_id -> body`
/// map. A missing file yields an empty map (this node has received no push yet).
/// These are the FOREIGN bodies the citing records cite -- resolved here so the
/// digest recompute the CLOSED gate reads has the real counterparty half to
/// compare against. They are NOT ledger records of ours.
fn read_received_capsules(ledger_dir: &Path) -> HashMap<String, Value> {
    let path = ledger_dir.join(RECEIVED_CAPSULES_FILENAME);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(body) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(id) = body.get("capsule_id").and_then(Value::as_str) {
            map.insert(id.to_string(), body);
        }
    }
    map
}

/// True when `record` is a LOCAL CITING record for a received counterparty half
/// it carries a `references[]` entry
/// with `citation_purpose == "counterparty_half"`. The record kind is defined by
/// the citation PURPOSE alone, never by the `chain.relation` string (AAC-05: a
/// cross-stream citation is a `references[]` entry, not a relation value -- the
/// citing record's relation may read `follows`, `cites`, or anything else). These
/// are OUR OWN chained log entries (not served actions, not foreign bodies) --
/// they are what makes the received half a checkpoint-covered record of ours.
fn is_citing_record(record: &Value) -> bool {
    cited_counterparty_capsule_id(record).is_some()
}

/// True when `record` is this node's record of a local routing choice (the
/// operator blocked or unblocked a peer; `peer_blocks`). Ours, and on the
/// chain, but not an exchange: it never enters the Pane B/C correlation.
fn is_local_routing_choice(record: &Value) -> bool {
    record
        .pointer("/model_attestation/compute_attestation/local_routing_choice")
        .is_some()
}

/// The foreign `capsule_id` a citing record cites -- its `references[]` entry
/// whose `citation_purpose == "counterparty_half"` (`references[].digest`, the
/// CPB typed digest, which for a capsule IS its `capsule_id`). `None` when the
/// record is not a counterparty-half citation.
fn cited_counterparty_capsule_id(record: &Value) -> Option<&str> {
    record
        .get("references")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("citation_purpose").and_then(Value::as_str) == Some("counterparty_half"))
        .and_then(|r| r.get("digest"))
        .and_then(Value::as_str)
}

/// The receiving-event facts a citing record carries in
/// `compute_attestation.received_half` -- `received_from`/`via`/`received_at`/
/// `signature_ok`. `None` (and the half never counts as verified) unless
/// `received_from` is non-empty AND `signature_ok` is literally `true`: the
/// provenance rule, now read off OUR OWN citing record instead of a co-located
/// provenance sibling. (`received-provenance.jsonl` is still written by the
/// door, but the citing record is the chained, checkpoint-covered carrier of
/// the same facts, so this reader trusts the citing record -- the record whose
/// integrity the chain + checkpoint actually protect.)
fn received_half_provenance(citing: &Value) -> Option<ReceivedProvenance> {
    let rh = citing.pointer("/model_attestation/compute_attestation/received_half")?;
    let received_from = rh
        .get("received_from")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    if rh.get("signature_ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    Some(ReceivedProvenance {
        received_from: received_from.to_string(),
        via: rh
            .get("via")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        received_at: rh
            .get("received_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        signature_ok: true,
        received_from_node_id: rh
            .get("received_from_node_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "unknown")
            .map(str::to_string),
    })
}

/// The reader's working set, assembled
/// from the three on-disk sources so the pane logic downstream is unchanged:
///
///   - `records`: this node's OWN capsules from `capsules.jsonl` MINUS the
///     citing records (which are our log entries, not served exchanges), PLUS
///     each cited FOREIGN body resolved from the held-artifact store. A foreign
///     body re-enters the working set as the "theirs" half -- exactly the shape
///     the pane's `mine`/`theirs` correlation, `digest_match`, and sibling
///     attribution already expect -- but sourced from the artifact store, never
///     from `capsules.jsonl`.
///   - `received_provenance`: `foreign capsule_id -> ReceivedProvenance`, built
///     from OUR citing records (the chained carrier of the door's verdict), so
///     `received_siblings_by_key` / `is_received_sibling` treat exactly the
///     cited foreign bodies as counterparty halves -- the provenance rule,
///     unchanged, now keyed off the citing record.
///   - `citing_records`: the citing records themselves, kept for Pane A (they
///     are legitimately OUR log entries) but excluded from `records` so Pane
///     B/C never mistake one for a served action or a counterparty half.
struct EffectiveLedger {
    /// This node's own served/requester capsules from `capsules.jsonl` PLUS the
    /// resolved foreign counterparty bodies (the "theirs" halves) -- the set
    /// Pane B/C correlate `mine` against `theirs` over. EXCLUDES citing records
    /// (our log entries, not served exchanges).
    pane_bc_records: Vec<Value>,
    /// Pane A's set: this node's own served/requester capsules PLUS our citing
    /// records -- all legitimately OUR chained log entries. EXCLUDES the
    /// foreign bodies (evidence we hold, not records we made).
    our_records: Vec<Value>,
    /// `foreign capsule_id -> ReceivedProvenance`, built from our citing records.
    received_provenance: HashMap<String, ReceivedProvenance>,
}

fn effective_ledger(ledger_dir: &Path) -> EffectiveLedger {
    let raw = read_capsule_records(ledger_dir);
    let artifacts = read_received_capsules(ledger_dir);

    let mut local_records: Vec<Value> = Vec::new();
    let mut citing_records: Vec<Value> = Vec::new();
    let mut choice_records: Vec<Value> = Vec::new();
    let mut received_provenance: HashMap<String, ReceivedProvenance> = HashMap::new();
    let mut resolved_foreign: HashMap<String, Value> = HashMap::new();

    for record in raw {
        if is_citing_record(&record) {
            // A citing record: resolve the foreign half it cites from the
            // held-artifact store, and record the door's verdict (off the
            // citing record) keyed by the FOREIGN body's own capsule_id -- so
            // the resolved foreign body becomes a counterparty "theirs" half
            // exactly as an inline foreign body used to.
            let cited = cited_counterparty_capsule_id(&record)
                .zip(received_half_provenance(&record))
                .and_then(|(cited_id, prov)| {
                    artifacts.get(cited_id).map(|body| (cited_id, prov, body))
                });
            if let Some((cited_id, prov, body)) = cited {
                received_provenance.insert(cited_id.to_string(), prov);
                resolved_foreign
                    .entry(cited_id.to_string())
                    .or_insert_with(|| body.clone());
            }
            citing_records.push(record);
        } else if is_local_routing_choice(&record) {
            // Ours (Pane A), never an exchange half (Pane B/C).
            choice_records.push(record);
        } else {
            // One of this node's own served/requester capsules.
            local_records.push(record);
        }
    }

    // Pane B/C: our own halves + the resolved foreign counterparty halves.
    let mut pane_bc_records = local_records.clone();
    pane_bc_records.extend(resolved_foreign.into_values());

    // Pane A: our own halves + our citing records (all ours), never foreign.
    let mut our_records = local_records;
    our_records.extend(citing_records);
    our_records.extend(choice_records);

    EffectiveLedger {
        pane_bc_records,
        our_records,
        received_provenance,
    }
}

/// `capsule_exchange_tab.digest_match_grade`, the STRUCTURAL half of it: the
/// two halves' `effect.request_digest`/`effect.response_digest` compared
/// field-by-field. `verified` only when BOTH fields are present on BOTH halves
/// and every field agrees; `failed` the instant one field disagrees (one
/// broken field makes the pair untrustworthy -- never averaged away, matching
/// the Python's `any_failed` rule); `present-unverified` when a field is
/// missing but none disagree. This is pure byte-equality of fields both
/// halves already carry -- the `digestsCiteOurHalf` INPUT the ONE gate reads,
/// not a second copy of the CLOSED predicate. A `failed` here is exactly what
/// the gate renders CONTRADICTED; a `verified` here (with the door's
/// `signature_ok`) is what it renders CLOSED.
fn digest_match_state(mine: &Value, theirs: &Value) -> &'static str {
    let mut any_failed = false;
    let mut any_absent = false;
    for (a, b) in [
        (request_digest(mine), request_digest(theirs)),
        (response_digest(mine), response_digest(theirs)),
    ] {
        match (a, b) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => any_failed = true,
            _ => any_absent = true,
        }
    }
    if any_failed {
        STATE_FAILED
    } else if any_absent {
        STATE_PRESENT_UNVERIFIED
    } else {
        STATE_VERIFIED
    }
}

/// One exchange-key group's records paired ONE-TO-ONE.
///
/// `exchange_key_for` groups by request digest alone, so two requests with the
/// same wire bytes (a user asking the same thing twice) land in one group.
/// Pairing every received half with every own record there set request 1's
/// record against request 2's half and rendered a false CONTRADICTED, although
/// both halves of each real exchange agreed. Here each
/// received half closes at most ONE own record: first an unpaired one whose
/// response digest also matches; only a half that matches none of them is set
/// against a leftover own record, which is a real disagreement and still
/// renders CONTRADICTED. Own records and halves left over stand alone.
/// Order: own records in ledger order, then the halves that paired with none.
fn pair_one_to_one<'a>(
    own: &[&'a Value],
    received: &[&'a Value],
) -> Vec<(Option<&'a Value>, Option<&'a Value>)> {
    let mut theirs_for: Vec<Option<&'a Value>> = vec![None; own.len()];
    let mut leftover: Vec<&'a Value> = Vec::new();
    for half in received {
        let same_answer = (0..own.len()).find(|&i| {
            theirs_for[i].is_none()
                && response_digest(own[i]).is_some()
                && response_digest(own[i]) == response_digest(half)
        });
        match same_answer {
            Some(i) => theirs_for[i] = Some(*half),
            None => leftover.push(*half),
        }
    }
    let mut unmatched: Vec<&'a Value> = Vec::new();
    for half in leftover {
        match (0..own.len()).find(|&i| theirs_for[i].is_none()) {
            Some(i) => theirs_for[i] = Some(half),
            None => unmatched.push(half),
        }
    }
    let mut pairs: Vec<(Option<&'a Value>, Option<&'a Value>)> = own
        .iter()
        .zip(theirs_for)
        .map(|(mine, theirs)| (Some(*mine), theirs))
        .collect();
    pairs.extend(unmatched.into_iter().map(|half| (None, Some(half))));
    pairs
}

fn is_received_record(
    record: &Value,
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> bool {
    record
        .get("capsule_id")
        .and_then(Value::as_str)
        .is_some_and(|id| received_provenance.contains_key(id))
}

/// Adds an own record to one key's exchanges. An own record with the same
/// response digest as one already there is another copy of the SAME exchange
/// (e.g. both halves of one exchange held on one node, or a peer's half that
/// carries no provenance line) and folds into it, as before; only an own
/// record whose answer differs is a separate exchange (the same request asked
/// again, answered differently).
fn push_own<'a>(own: &mut Vec<&'a Value>, record: &'a Value) {
    if !own
        .iter()
        .any(|o| response_digest(o) == response_digest(record))
    {
        own.push(record);
    }
}

/// Records grouped by `exchange_key_for`, in encounter order, each group split
/// into this node's own exchanges (`push_own`) and the received
/// (provenance-carrying) halves. A record with no correlator is not in any
/// group.
fn exchange_groups<'a>(
    records: &'a [Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> Vec<(String, Vec<&'a Value>, Vec<&'a Value>)> {
    let mut groups: Vec<(String, Vec<&'a Value>, Vec<&'a Value>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for record in records {
        let Some(key) = exchange_key_for(record) else {
            continue;
        };
        let i = *index.entry(key.clone()).or_insert_with(|| {
            groups.push((key, Vec::new(), Vec::new()));
            groups.len() - 1
        });
        if is_received_record(record, received_provenance) {
            groups[i].2.push(record);
        } else {
            push_own(&mut groups[i].1, record);
        }
    }
    groups
}

/// The Pane C row key of the `n`th (0-based) pair of an exchange-key group:
/// the group key itself for the first, `<key>#<n+1>` for later ones, so two
/// same-digest exchanges get two rows the drill-down can still resolve.
fn pair_row_key(group_key: &str, n: usize) -> String {
    if n == 0 {
        group_key.to_string()
    } else {
        format!("{group_key}#{}", n + 1)
    }
}

/// `x-mesh-poc-v1` block, `capsule_mesh_view._poc_block`.
fn poc_block(record: &Value) -> Option<&Value> {
    record.pointer("/model_attestation/compute_attestation/x-mesh-poc-v1")
}

/// `x-mesh-lifecycle-v1` block, `capsule_mesh_view._lifecycle_block`.
fn lifecycle_block(record: &Value) -> Option<&Value> {
    record.pointer("/model_attestation/compute_attestation/x-mesh-lifecycle-v1")
}

/// The exchange grouping key -- the join order matches
/// `served_request_join.py`'s own CORRELATION FALLBACK
/// (`exchange_id` -> `request_digest` -> `twin_bracket_id`), but reduced to
/// the ONE key that survives a cross-node exchange.
///
/// `exchange_id` is **host-minted**: each host mints its OWN id for the same
/// real exchange, so two cross-node halves that attest the identical exchange
/// routinely carry DIFFERENT `exchange_id` values (M4 `914b61c1…` vs M3
/// `82777e20…`), while both independently compute the SAME `request_digest`
/// over the same wire bytes. Keying on `exchange_id` therefore split the two
/// halves of one cross-node exchange into two rows that could never reconcile
/// -- the empirical "6 OPEN rows instead of 3 CLOSED pairs" finding. So the
/// digest is preferred whenever a record carries one: `digest:<request_digest>`
/// groups both halves as one exchange. This subsumes the same-node case (two
/// records of one exchange share a `request_digest` too) and correctly SPLITS
/// the CONFLICTING case `served_request_join.py` refuses to join (an equal
/// host-minted `exchange_id` but a different `request_digest` -- two different
/// requests the wire bytes contradict, which distinct digest keys keep apart).
/// Falls back to the host-minted `exchange_id` only when a record carries no
/// `request_digest` at all (e.g. a plugin-served stub with no digested body),
/// and `None` when neither exists (nothing to group this record by).
fn exchange_key_for(record: &Value) -> Option<String> {
    if let Some(digest) = request_digest(record) {
        return Some(format!("digest:{digest}"));
    }
    poc_block(record)
        .and_then(|poc| poc.pointer("/serving_provenance/exchange_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && *id != "unknown")
        .map(str::to_string)
}

/// The number of DISTINCT exchanges a set of records represents -- grouped by
/// the ONE correlator (`exchange_key_for`, digest-first), NOT `records.len()`.
///
/// A single cross-node exchange has TWO halves that both land in a peer's
/// working set (this node's own half from `capsules.jsonl` PLUS the peer's
/// pushed half re-entered from the held-artifact store), and both carry the same
/// `request_digest`, so they share one `exchange_key_for` key. Counting records
/// therefore double-counts: 3 real exchanges x 2 halves reads "6 exchanges" and
/// makes confirmed show "3 / 6" when the truth is 3 of 3. Counting distinct keys
/// collapses the two halves back to one exchange. A record with NO correlator
/// (`None`) cannot be joined to any other, so it counts as its own exchange --
/// never silently merged into a single bucket.
///
/// Within one key the halves are paired ONE-TO-ONE (`pair_one_to_one`): two
/// same-digest requests are two exchanges, never merged into one.
fn distinct_exchange_count(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> usize {
    let uncorrelated = records
        .iter()
        .filter(|r| exchange_key_for(r).is_none())
        .count();
    let paired: usize = exchange_groups(records, received_provenance)
        .iter()
        .map(|(_, own, received)| pair_one_to_one(own, received).len())
        .sum();
    paired + uncorrelated
}

/// the id shared by BOTH halves of an ambient
/// twin comparison, forwarded verbatim by the capsule-producer plugin off
/// the terminal envelope's own `twin_bracket_id` -- rides alongside
/// `exchange_id` under `x-mesh-poc-v1.serving_provenance` (the sibling
/// convention `exchange_key_for` already reads). `None` on every record
/// that wasn't ambiently twinned (the overwhelming majority) -- never a
/// fabricated bracket.
fn twin_bracket_id(record: &Value) -> Option<&str> {
    poc_block(record)
        .and_then(|poc| poc.pointer("/serving_provenance/twin_bracket_id"))
        .and_then(Value::as_str)
}

/// `` piece 3: the join key piece 1
/// (`admission-policy::lifecycle_channel::peer_capsule_id_for_seal`) already
/// threads onto a `RemoteMesh` record -- `serving_provenance.peer_capsule_id`
/// is only ever non-null when `peer_capsule_id_provenance` is the literal
/// `"peer_asserted"` (never `self_minted`/`unknown`, the mislabeling guard's
/// whole point). `None` here means "nothing this node knows how to fetch",
/// never a guess.
fn peer_fetch_join_key(record: &Value) -> Option<(&str, &str)> {
    let sp = poc_block(record)?.get("serving_provenance")?;
    if sp.get("peer_capsule_id_provenance").and_then(Value::as_str) != Some("peer_asserted") {
        return None;
    }
    let capsule_id = sp
        .get("peer_capsule_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let peer_id = sp
        .get("served_by_node_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && *id != "unknown")?;
    Some((capsule_id, peer_id))
}

/// Pane C row `theirs` cell (`capsule_exchange_tab`'s own field). `NOT_CHECKED`
/// -- not `absent` -- the moment a real peer-asserted join key exists: the
/// peer half is KNOWN to be fetchable (`ledger-fetch/1`, piece 2's
/// `mesh_ledger_fetch` plugin tool, already reachable at
/// `POST /api/plugins/capsule-emit-mesh/tools/mesh_ledger_fetch`), only
/// unverified until the browser's own recompute actually runs one -- this
/// route never fetches, verifies, or fabricates a verdict itself.
fn theirs_cell(record: &Value) -> Value {
    match peer_fetch_join_key(record) {
        Some((capsule_id, peer_id)) => json!({
            "state": NOT_CHECKED,
            "text": "peer capsule known -- fetch to recompute",
            "capsule_id": capsule_id,
            "peer_id": peer_id,
        }),
        None => json!({
            "state": STATE_ABSENT,
            "text": "none (unilateral)",
            "capsule_id": Value::Null,
        }),
    }
}

/// `capsule_mesh_view.label_role`, source_log fixed to `"plugin"` --
/// this route's records are always plugin-ledger reads, never sidecar
/// ones. `_EXPLICIT_POC_ROLES` = `{requested, served, conflict, unknown}`,
/// trusted as-is per the 2026-09-06 role ruling; `_SERVED_OBSERVATION_
/// POINTS` widens an explicit-but-unset case; `_DEFAULT_ROLE_BY_SOURCE`
/// for `"plugin"` is `"served"` (`capsule_mesh_view.py:81-83`) -- both of
/// today's real writers (sidecar, plugin) observe this machine acting as
/// the serving provider, never a requestor elsewhere.
fn label_role(record: &Value) -> &'static str {
    if let Some(role) = poc_block(record)
        .and_then(|poc| poc.get("role"))
        .and_then(Value::as_str)
    {
        match role {
            "requested" => return "requested",
            "served" => return "served",
            "conflict" => return "conflict",
            "unknown" => return "unknown",
            _ => {}
        }
    }
    const SERVED_OBSERVATION_POINTS: &[&str] = &[
        "gateway_ingress",
        "serving_host_ingress",
        "backend_dispatch",
        "client_egress",
    ];
    if lifecycle_block(record)
        .and_then(|lc| lc.get("observation_point"))
        .and_then(Value::as_str)
        .is_some_and(|point| SERVED_OBSERVATION_POINTS.contains(&point))
    {
        return "served";
    }
    "served"
}

/// `capsule_exchange_tab.EXCHANGE_ROLE_SERVED` / `_ASKED`.
fn role_tag(record: &Value) -> &'static str {
    if label_role(record) == "served" {
        "SERVED"
    } else {
        "ASKED"
    }
}

/// Pane A ("This node") -- `capsule_accountability_tab.build_tab_payload`,
/// restricted to the fields this cut computes for real (see module docs).
pub(crate) fn build_pane_a(records: &[Value], card: Value) -> Value {
    let operator = records
        .iter()
        .rev()
        .find_map(|r| r.get("operator").cloned())
        .unwrap_or(Value::Null);
    let rows: Vec<Value> = records
        .iter()
        .map(|record| {
            // a citing record IS one
            // of our chained log entries (it belongs in Pane A), but it is NOT
            // a served action -- it records that we RECEIVED a counterparty
            // half. Label it honestly so a reader never mistakes it for a
            // model this node served. Its `cross_party` cell is PRESENT (it
            // cites a counterparty by digest), never the "no counterparty
            // evidence" default a served-only record carries.
            if is_local_routing_choice(record) {
                // The operator's own choice to stop (or resume) routing to a
                // peer. Not a served model, no counterparty: an honest kind.
                return json!({
                    "capsule_id": record.get("capsule_id").cloned().unwrap_or(Value::Null),
                    "timestamp": record.get("timestamp").cloned().unwrap_or(Value::Null),
                    "kind": "local_routing_choice",
                    "model_claimed": Value::Null,
                    "hardware_claimed": Value::Null,
                    "verify_ok": Value::Null,
                    // No serving or counterparty facts to grade.
                    "rungs": {},
                    "record": record,
                });
            }
            if is_citing_record(record) {
                let received_from = record
                    .pointer("/model_attestation/compute_attestation/received_half/received_from")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                return json!({
                    "capsule_id": record.get("capsule_id").cloned().unwrap_or(Value::Null),
                    "timestamp": record.get("timestamp").cloned().unwrap_or(Value::Null),
                    "kind": "counterparty_half_citation",
                    // NOT a served model -- an honest marker, never "local model".
                    "model_claimed": Value::Null,
                    "hardware_claimed": Value::Null,
                    "verify_ok": Value::Null,
                    "rungs": {
                        "freshness": { "state": STATE_ABSENT, "client_nonce_source": Value::Null },
                        // This record DOES carry counterparty evidence: it
                        // cites a received half by digest (the honest PRESENT,
                        // not the served-only NOT_PRESENT).
                        "cross_party": {
                            "state": CELL_PRESENT,
                            "text": format!("cites a counterparty half received from {received_from}"),
                        },
                        "runtime_binding": { "state": STATE_ABSENT },
                        "tee_citation": { "state": STATE_ABSENT },
                        "hardware_inventory": { "state": STATE_ABSENT },
                        "log_integrity": {
                            "state": STATE_PRESENT_UNVERIFIED,
                            "witness_checkpoint_supplied": false,
                        },
                    },
                    "record": record,
                });
            }
            json!({
                "capsule_id": record.get("capsule_id").cloned().unwrap_or(Value::Null),
                "timestamp": record.get("timestamp").cloned().unwrap_or(Value::Null),
                // No serving-provenance block on a plugin-written record
                // yet -- `friendly_model_name`'s honest last resort, not a
                // guess (verified against a live capsule-emit-mesh run).
                "model_claimed": MODEL_CLAIMED_FALLBACK,
                "hardware_claimed": Value::Null,
                "verify_ok": Value::Null,
                "rungs": {
                    "freshness": { "state": STATE_ABSENT, "client_nonce_source": Value::Null },
                    // five-state property
                    // map, not the retired rung ladder -- see module docs.
                    "cross_party": {
                        "state": STATE_NOT_PRESENT,
                        "text": NO_COUNTERPARTY_EVIDENCE_TEXT,
                    },
                    "runtime_binding": { "state": STATE_ABSENT },
                    "tee_citation": { "state": STATE_ABSENT },
                    "hardware_inventory": { "state": STATE_ABSENT },
                    // `verify_ok is None` -> "present, not yet
                    // independently verified" -- structural, not a
                    // fabricated PASS/FAIL (see module docs, gap 2).
                    "log_integrity": {
                        "state": STATE_PRESENT_UNVERIFIED,
                        "witness_checkpoint_supplied": false,
                    },
                },
                "record": record,
            })
        })
        .collect();
    json!({
        "operator": operator,
        "witness_checkpoint_supplied": false,
        "rows": rows,
        "card": card,
    })
}

/// `peer_accountability_tab.pair_cell`'s "nothing to reconcile" state is
/// only real when no record carries an `exchange_id` at all (the digest
/// match it would otherwise reconcile is not ported here, see module
/// docs) -- honest `NOT_CHECKED` the moment one shows up, not a fabricated
/// "absent" over data this cut never looked at.
fn pair_cell(records: &[Value]) -> Value {
    let any_exchange_id = records.iter().any(|r| {
        poc_block(r)
            .and_then(|poc| poc.pointer("/serving_provenance/exchange_id"))
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty() && id != "unknown")
    });
    if any_exchange_id {
        return not_checked_state();
    }
    json!({
        "state": STATE_ABSENT,
        "text": "no exchange_id on these records -- nothing to reconcile",
        "verified": 0,
        "failed": 0,
        "missing": 0,
    })
}

/// First `n` chars of an id (char-safe, mirrors Python's `[:n]` slice on the
/// ascii node/ref ids this handles).
fn short_id(id: &str, n: usize) -> String {
    id.chars().take(n).collect()
}

/// Best-effort counterparty peer label from a record's OWN fields, mirroring
/// `capsule_mesh_view.label_counterparty` (the Python reference this reader
/// pins against). `None` is the honest "unattributed" -- no field resolves to
/// a DISTINCT peer -- never a fabricated identity.
///
/// The key case the earlier single-bucket reader missed: a `RemoteMesh`
/// requester-side record carries `role: "requested"` (the dispatch-derived
/// role -- `capsule_emit.rs` doc: "RemoteMesh means this node routed to a
/// peer") and names the remote server in `served_by_node_id`. That server IS
/// the counterparty, so a peer this node DEALT WITH -- the count does not wait
/// on CLOSED (CLOSED is about holding their half, a separate state).
fn counterparty_peer_label(record: &Value) -> Option<String> {
    let poc = poc_block(record)?;
    // Tier 1: bilateral attestation (strongest -- a signed request digest).
    if let Some(cross_party) = poc.get("cross_party") {
        if let Some(r) = cross_party
            .get("initiator_ref")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(format!("initiator:{}", short_id(r, 12)));
        }
        if let Some(r) = cross_party
            .get("counterparty_ref")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(format!("counterparty:{}", short_id(r, 12)));
        }
    }
    let sp = poc.get("serving_provenance");
    if let Some(sp) = sp {
        // Tier 2: served_by_node_id is the REMOTE peer when this node requested.
        let requested = poc.get("role").and_then(Value::as_str) == Some("requested");
        if let Some(served_by) = sp
            .get("served_by_node_id")
            .and_then(Value::as_str)
            .filter(|s| requested && !s.is_empty() && *s != "unknown")
        {
            return Some(format!("node:{}", short_id(served_by, 16)));
        }
        // Tier 3: requesting_party -- who originated, when this node served.
        if let Some(rp) = sp
            .get("requesting_party")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "unknown")
        {
            return Some(format!("node:{}", short_id(rp, 16)));
        }
    }
    None
}

fn seen_range(records: &[Value]) -> (Option<&str>, Option<&str>) {
    let mut timestamps: Vec<&str> = records
        .iter()
        .filter_map(|r| r.get("timestamp").and_then(Value::as_str))
        .collect();
    timestamps.sort_unstable();
    (timestamps.first().copied(), timestamps.last().copied())
}

/// One "Nodes you have dealt with" row: a NAMED counterparty (`label`) this
/// node exchanged with, `exchange_count` real. Its half being unheld is a
/// STATE ("their half not held") the CLOSED path fills -- it is never a reason
/// to omit the peer or show a zero count.
fn dealt_with_row(
    label: &str,
    records: &[Value],
    siblings_by_key: &HashMap<String, Vec<CorrelatedSibling<'_>>>,
    received_provenance: &HashMap<String, ReceivedProvenance>,
    identity: Option<&PeerIdentity>,
) -> Value {
    let (first_seen, last_seen) = seen_range(records);
    // The count of DISTINCT exchanges (by the ONE correlator), NOT records.len():
    // the two halves of one cross-node exchange (this node's own + the peer's
    // pushed half) share a correlation key and must count once, so confirmed
    // reads "3 / 3", never "3 / 6". See `distinct_exchange_count`.
    let total = distinct_exchange_count(records, received_provenance);
    let confirmed_siblings = confirmed_siblings_for(records, siblings_by_key, received_provenance);
    let served_count = records.iter().filter(|r| label_role(r) == "served").count();
    let requested_count = records
        .iter()
        .filter(|r| label_role(r) == "requested")
        .count();
    // A half this peer pushed and the door verified IS held now. The node/
    // cross_party text stops asserting the flat "their half not held" the
    // moment a provenance-carrying sibling correlates -- the gate decides
    // CLOSED, but the presence of a held half is a structural fact stated here.
    let held_half_count = confirmed_siblings.len();
    let half_state = if held_half_count > 0 {
        format!("their half held (received by push) for {held_half_count} of {total}")
    } else {
        "their half not held".to_string()
    };
    json!({
        "peer_id": label,
        // D3: the alias evidence for
        // this row -- signing key / endpoint id / node id, each present only
        // when a record actually carries it. The UI renders these as one
        // row's aliases, never as extra peers.
        "identity": identity_json(identity),
        "node": {
            "state": CELL_PRESENT,
            "text": format!("dealt with {label} in {total} exchange(s) — {half_state}"),
            "peer_id": label,
            "member_kind": Value::Null,
            "exchange_count": total,
        },
        // Counterparty IS present (this node's own record names the peer);
        // their sealed half is `present-unverified` -- not the false
        // `NOT_PRESENT` the unattributed bucket carries.
        "cross_party": {
            "state": STATE_PRESENT_UNVERIFIED,
            "text": format!("counterparty {label} named by this node's own record — {half_state}"),
            "peer_id": label,
        },
        "role": {
            "state": CELL_PRESENT,
            "text": format!("you→them · {requested_count} (them→you · {served_count})"),
            "role": if requested_count > 0 { "you_to_them" } else { "them_to_you" },
            "you_to_them_count": requested_count,
            "them_to_you_count": served_count,
            "exchange_count": total,
        },
        "history": not_checked_state(),
        "served": not_checked_state(),
        "pair": pair_cell(records),
        // The two gate inputs, per correlated
        // push-primary sibling -- the TS view runs each through the ONE gate
        // (`deriveRightCellState`) and counts CLOSED. Empty when no foreign
        // half correlates: the gate reads that as "not confirmed", honest.
        "confirmed_siblings": confirmed_siblings,
        "verdicts": not_checked_state(),
        "asked": {
            "state": STATE_ABSENT,
            "text": "Not yet counted — this node doesn't persist served/refused counts.",
            "count": 0,
        },
        "exchange_count": total,
        "first_seen": first_seen,
        "last_seen": last_seen,
    })
}

/// The honest residual: records that name NO distinct counterparty. Unchanged
/// from the prior reader -- one unattributed row, never a fabricated peer and
/// never counted as "dealt with · 0".
fn unattributed_row(
    records: &[Value],
    siblings_by_key: &HashMap<String, Vec<CorrelatedSibling<'_>>>,
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> Value {
    let (first_seen, last_seen) = seen_range(records);
    let confirmed_siblings = confirmed_siblings_for(records, siblings_by_key, received_provenance);
    let served_count = records.iter().filter(|r| label_role(r) == "served").count();
    let requested_count = records
        .iter()
        .filter(|r| label_role(r) == "requested")
        .count();
    // Distinct exchanges by the ONE correlator, NOT records.len() -- same
    // record-vs-exchange discipline as the dealt-with rows (`distinct_exchange_count`).
    let total = distinct_exchange_count(records, received_provenance);
    let (role, role_text) = if requested_count > 0 && served_count > 0 {
        (
            "both",
            format!("both · {total} ({requested_count} you→them, {served_count} them→you)"),
        )
    } else if requested_count > 0 {
        ("you_to_them", format!("you→them · {requested_count}"))
    } else if served_count > 0 {
        ("them_to_you", format!("them→you · {served_count}"))
    } else {
        ("unknown", format!("unknown role · {total}"))
    };
    json!({
        "peer_id": Value::Null,
        "identity": Value::Null,
        "node": {
            "state": STATE_ABSENT,
            "text": format!(
                "no counterparty evidence for these {total} exchange(s) -- unattributed, not one identified peer"
            ),
            "peer_id": Value::Null,
            "member_kind": Value::Null,
            "exchange_count": total,
        },
        "cross_party": {
            "state": STATE_NOT_PRESENT,
            "text": NO_COUNTERPARTY_EVIDENCE_TEXT,
        },
        "role": {
            "state": CELL_PRESENT,
            "text": role_text,
            "role": role,
            "you_to_them_count": requested_count,
            "them_to_you_count": served_count,
            "exchange_count": total,
        },
        "history": not_checked_state(),
        "served": not_checked_state(),
        "pair": pair_cell(records),
        // Supplied for parity with dealt-with rows; an unattributed residual has
        // no named peer, so the Peers list filters it out before the gate reads
        // this -- present and honest (empty unless a sibling correlates) rather
        // than absent.
        "confirmed_siblings": confirmed_siblings,
        "verdicts": not_checked_state(),
        "asked": {
            "state": STATE_ABSENT,
            "text": "Not yet counted — this node doesn't persist served/refused counts.",
            "count": 0,
        },
        "exchange_count": total,
        "first_seen": first_seen,
        "last_seen": last_seen,
    })
}

/// Pane B ("Peers") -- `peer_accountability_tab.build_peers_payload`. Records
/// that name a distinct counterparty (`counterparty_peer_label`, mirroring
/// `capsule_mesh_view.label_counterparty`) each become a "dealt with" peer row;
/// the rest fall to ONE honest unattributed residual. A served peer this
/// node's own record names counts as dealt-with NOW -- "their half not held"
/// is a state, never a fabricated zero; an unknown counterparty is unattributed,
/// never a false "dealt with · 0".
///
/// ** "Confirmed by the other side" routes through
/// the ONE gate, same as Pane C.** Pane B used to gate its confirmed/MATCH
/// columns on a browser peer-fetch of the peer's whole chain (`history` cell) --
/// a SECOND CLOSED predicate, distinct from Pane C's push-primary one-gate path.
/// This now SUPPLIES each dealt-with row the SAME two gate inputs Pane C
/// supplies: for every one of this node's own records that a provenance-carrying
/// foreign sibling correlates with (by `exchange_key_for`, the ONE correlator,
/// digest-first), a `confirmed_siblings` entry carrying the door's recorded
/// `signature_ok` + the structural `digest_match` state. The TS view
/// (`peer-row-view.ts`) runs each entry through `deriveRightCellState` -- the
/// ONE gate -- and counts CLOSED, never a fetch-gated predicate. No second
/// predicate here; correlation feeds the gate, it never bypasses it. A peer with
/// no correlated sibling supplies an empty list, which the gate reads as "not
/// confirmed" -- honest, never a fabricated zero.
pub(crate) fn build_pane_b(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> Value {
    if records.is_empty() {
        return json!({
            "peer_count": 0,
            "rows": [],
            "peer_fetch_enabled": false,
            "peer_fetch_count": 0,
        });
    }
    // The received siblings, keyed by their correlator (`exchange_key_for`), so
    // a peer's own record can find the foreign half that closes it -- the SAME
    // digest-first correlator Pane C groups on, never a peer-label match.
    let siblings_by_key = received_siblings_by_key(records, received_provenance);
    // D3: ONE row per peer, joined on
    // the signing key ([`peer_attribution`]), with node id / endpoint id as
    // aliases. Both the received sibling AND the local half it correlates with
    // attribute to that one row's
    // fix, preserved); a `node:`-labeled local group merges onto a signing-key
    // row only when the evidence carries the same node id.
    let mut attribution = peer_attribution(records, received_provenance, &siblings_by_key);
    // BTreeMap: deterministic (sorted) peer ordering; attributed peers first,
    // the unattributed residual last -- so an all-unattributed ledger yields
    // exactly the prior single-row output (rows[0] == the residual).
    let mut by_peer: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    let mut unattributed: Vec<Value> = Vec::new();
    for record in records {
        match attribution.row_key_for(record) {
            Some(label) => {
                // A plain `node:`-labeled row (no sibling evidence) still
                // carries its FULL node id as identity evidence -- this
                // node's own record names it, and the exact id (never a
                // truncation) is what future evidence can merge on.
                let unaliased = label.starts_with("node:")
                    && !attribution.identity_by_row_key.contains_key(&label);
                if let Some(full_node_id) = full_counterparty_node_id(record).filter(|_| unaliased)
                {
                    attribution.identity_by_row_key.insert(
                        label.clone(),
                        PeerIdentity {
                            node_id: Some(full_node_id),
                            ..PeerIdentity::default()
                        },
                    );
                }
                by_peer.entry(label).or_default().push(record.clone());
            }
            None => unattributed.push(record.clone()),
        }
    }
    let mut rows: Vec<Value> = by_peer
        .iter()
        .map(|(label, group)| {
            dealt_with_row(
                label,
                group,
                &siblings_by_key,
                received_provenance,
                attribution.identity_by_row_key.get(label),
            )
        })
        .collect();
    if !unattributed.is_empty() {
        rows.push(unattributed_row(
            &unattributed,
            &siblings_by_key,
            received_provenance,
        ));
    }
    json!({
        "peer_count": rows.len(),
        "rows": rows,
        "peer_fetch_enabled": false,
        "peer_fetch_count": 0,
    })
}

/// One correlated foreign half held locally: its `exchange_key_for` correlator,
/// its own record (for the structural `digest_match` against `mine`), and the
/// door's provenance. This is the native-ledger equivalent of the `theirs`
/// half Pane C splits out -- the ONLY records treated as a counterparty half
/// are those carrying a `received-provenance.jsonl` line (the provenance rule,
/// enforced by `received_provenance.contains_key`).
struct CorrelatedSibling<'a> {
    record: &'a Value,
    provenance: &'a ReceivedProvenance,
}

/// The evidence-backed identity of ONE
/// peer, joined on the SIGNING KEY (the announcing key is the
/// sealing key -- the pushed body's `key_id` is what actually signed the
/// halves), with the endpoint id (the door's `received_from`) and the mesh
/// node id carried as ALIASES on the same row. Every field is read off
/// evidence this reader actually holds:
///   - `signing_key_id`: the resolved foreign body's own `key_id`. The door
///     verified it against the announced peer key (`peer_keys.
///     announced_key_for(received_from)`) BEFORE the provenance line/citing
///     record was ever written, so `received_from <-> key_id` is
///     door-verified, not a guess.
///   - `endpoint_id`: the door's `received_from` (the plugin's stable peer
///     id -- NOT a node id; the prior reader's `node:<received_from>` label
///     mislabeled the id space, which is exactly how one live peer rendered
///     as two rows).
///   - `node_id`: only when a record actually names one -- the citing
///     record's `received_from_node_id` (once the receive door captures it),
///     or a pushed SERVED half's own `served_by_node_id` (the provider names
///     itself). Never bridged by assumption.
#[derive(Clone, Default)]
struct PeerIdentity {
    signing_key_id: Option<String>,
    endpoint_id: Option<String>,
    node_id: Option<String>,
    /// `node_id` came from the peer's own record (a served half naming its
    /// server), not from this node's records. A peer can name any node there,
    /// so the console never offers to block by a self-asserted id.
    node_id_self_asserted: bool,
}

impl PeerIdentity {
    /// Union of two evidence sets for the same peer row -- first evidence
    /// wins per field; nothing is overwritten, nothing invented.
    fn merge(&mut self, other: PeerIdentity) {
        if self.signing_key_id.is_none() {
            self.signing_key_id = other.signing_key_id;
        }
        if self.endpoint_id.is_none() {
            self.endpoint_id = other.endpoint_id;
        }
        if self.node_id.is_none() {
            self.node_id = other.node_id;
            self.node_id_self_asserted = other.node_id_self_asserted;
        }
    }
}

/// The identity evidence one received (provenance-carrying) sibling supplies.
/// Replaces the retired `sibling_peer_label`, which keyed rows by `node:<received_from>` -- an endpoint id
/// passed off as a node id, the exact id-space mislabeling behind the live
/// one-peer-two-rows defect D3).
fn sibling_peer_identity(sibling: &Value, provenance: &ReceivedProvenance) -> PeerIdentity {
    let signing_key_id = sibling
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let endpoint_id = Some(provenance.received_from.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let from_our_records = provenance.received_from_node_id.clone();
    let node_id_self_asserted = from_our_records.is_none();
    let node_id = from_our_records.or_else(|| {
        if label_role(sibling) == "served" {
            poc_block(sibling)
                .and_then(|poc| poc.pointer("/serving_provenance/served_by_node_id"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && *s != "unknown")
                .map(str::to_string)
        } else {
            None
        }
    });
    let node_id_self_asserted = node_id_self_asserted && node_id.is_some();
    PeerIdentity {
        signing_key_id,
        endpoint_id,
        node_id,
        node_id_self_asserted,
    }
}

/// The peer ROW key for an identity: signing key first (the join ruling),
/// node id next (the same `node:<short16>` space `counterparty_peer_label`
/// uses, so a local half naming the same node merges onto this row), endpoint
/// id last -- labeled as what it IS (`endpoint:`), never passed off as a node
/// id. `None` when no identity evidence exists at all.
fn peer_row_key(identity: &PeerIdentity) -> Option<String> {
    if let Some(key) = &identity.signing_key_id {
        return Some(format!("key:{}", short_id(key, 16)));
    }
    if let Some(node) = &identity.node_id {
        return Some(format!("node:{}", short_id(node, 16)));
    }
    identity
        .endpoint_id
        .as_ref()
        .map(|endpoint| format!("endpoint:{endpoint}"))
}

/// The FULL counterparty node id behind a `node:`-shaped label, read off the
/// same fields `counterparty_peer_label` reads (tier 2/3) -- kept full-length
/// so a row can carry it as identity evidence (aliases are exact ids, never
/// truncations). `None` when the record names no distinct node.
fn full_counterparty_node_id(record: &Value) -> Option<String> {
    let poc = poc_block(record)?;
    let sp = poc.get("serving_provenance")?;
    let requested = poc.get("role").and_then(Value::as_str) == Some("requested");
    if let Some(served_by) = sp
        .get("served_by_node_id")
        .and_then(Value::as_str)
        .filter(|s| requested && !s.is_empty() && *s != "unknown")
    {
        return Some(served_by.to_string());
    }
    sp.get("requesting_party")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && *s != "unknown")
        .map(str::to_string)
}

/// The one attribution join both Pane B and Pane C's `counterparty` field
/// read, so the two panes can never name the same peer differently.
struct PeerAttribution {
    /// exchange key -> the pushing peer's row key (via `sibling_peer_identity`).
    row_key_by_exchange_key: HashMap<String, String>,
    /// row key -> merged identity evidence (aliases).
    identity_by_row_key: HashMap<String, PeerIdentity>,
    /// short16(node id) -> row key, for bridging a `node:`-labeled local
    /// group onto a signing-key row -- populated ONLY from evidence-backed
    /// node aliases, so the bridge exists exactly when the evidence does.
    node_alias_to_row_key: HashMap<String, String>,
}

/// For each exchange key, the node THIS node's own requester record says its
/// host routed the exchange to (`served_by_node_id` on a `requested` record
/// we sealed ourselves, never a received one). That id is ours, not the
/// peer's word, so it is one the console may block by.
fn own_routed_node_by_key(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> HashMap<String, String> {
    let mut by_key = HashMap::new();
    for record in records {
        let received = record
            .get("capsule_id")
            .and_then(Value::as_str)
            .is_some_and(|id| received_provenance.contains_key(id));
        if received || label_role(record) != "requested" {
            continue;
        }
        if let (Some(key), Some(node)) =
            (exchange_key_for(record), full_counterparty_node_id(record))
        {
            by_key.entry(key).or_insert(node);
        }
    }
    by_key
}

fn peer_attribution(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
    siblings_by_key: &HashMap<String, Vec<CorrelatedSibling<'_>>>,
) -> PeerAttribution {
    let mut attribution = PeerAttribution {
        row_key_by_exchange_key: HashMap::new(),
        identity_by_row_key: HashMap::new(),
        node_alias_to_row_key: HashMap::new(),
    };
    let own_routed = own_routed_node_by_key(records, received_provenance);
    for (key, siblings) in siblings_by_key {
        // A single exchange key correlates one counterparty half; take the
        // first sibling whose evidence resolves to any identity at all.
        let Some((row_key, mut identity)) = siblings.iter().find_map(|sibling| {
            let identity = sibling_peer_identity(sibling.record, sibling.provenance);
            peer_row_key(&identity).map(|row_key| (row_key, identity))
        }) else {
            continue;
        };
        // Our own record of this exchange names the node our host routed it
        // to: that id is ours, so it replaces the peer's own claim about
        // itself (a requester that has only asked can then stop routing to
        // it). A peer's self-asserted id alone stays `their_record`.
        let replaceable = identity.node_id.is_none() || identity.node_id_self_asserted;
        if let Some(node) = own_routed.get(key).filter(|_| replaceable) {
            identity.node_id = Some(node.clone());
            identity.node_id_self_asserted = false;
        }
        attribution
            .row_key_by_exchange_key
            .insert(key.clone(), row_key.clone());
        attribution
            .identity_by_row_key
            .entry(row_key)
            .or_default()
            .merge(identity);
    }
    for (row_key, identity) in &attribution.identity_by_row_key {
        if let Some(node) = &identity.node_id {
            attribution
                .node_alias_to_row_key
                .insert(short_id(node, 16), row_key.clone());
        }
    }
    attribution
}

impl PeerAttribution {
    /// The peer row a record belongs to: its exchange's pushed-sibling
    /// identity first (the door-verified join); else its own counterparty
    /// label, BRIDGED onto a signing-key row if -- and only if -- that row's
    /// evidence carries the same node id. No evidence, no bridge: an
    /// unlinked `node:` label stays its own (honestly labeled) row.
    fn row_key_for(&self, record: &Value) -> Option<String> {
        if let Some(row_key) =
            exchange_key_for(record).and_then(|key| self.row_key_by_exchange_key.get(&key))
        {
            return Some(row_key.clone());
        }
        let label = counterparty_peer_label(record)?;
        if let Some(row_key) = label
            .strip_prefix("node:")
            .and_then(|node_short| self.node_alias_to_row_key.get(node_short))
        {
            return Some(row_key.clone());
        }
        Some(label)
    }
}

/// The row's `identity` cell -- the alias evidence the UI renders as
/// "signed by <key> · node <id> · endpoint <id>". `null` (never `{}`) for a
/// row with no identity evidence beyond its own label.
fn identity_json(identity: Option<&PeerIdentity>) -> Value {
    match identity {
        Some(identity) => json!({
            "signing_key_id": identity.signing_key_id,
            "endpoint_id": identity.endpoint_id,
            "node_id": identity.node_id,
            // Where the node id came from: this node's own records, or the
            // peer's own record naming itself. Only the first can be blocked.
            "node_id_source": identity.node_id.as_ref().map(|_| {
                if identity.node_id_self_asserted { "their_record" } else { "your_records" }
            }),
        }),
        None => Value::Null,
    }
}

/// Indexes every received (provenance-carrying) foreign sibling by its
/// `exchange_key_for` correlator, so a peer's own record can look up the half
/// that closes it. Mirrors Pane C's `is_received_sibling` split, but keyed for
/// per-peer lookup instead of folded into one row. A capsule with no provenance
/// line is NEVER indexed -- the provenance rule holds identically here.
fn received_siblings_by_key<'a>(
    records: &'a [Value],
    received_provenance: &'a HashMap<String, ReceivedProvenance>,
) -> HashMap<String, Vec<CorrelatedSibling<'a>>> {
    let mut map: HashMap<String, Vec<CorrelatedSibling<'a>>> = HashMap::new();
    for record in records {
        let Some(capsule_id) = record.get("capsule_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(provenance) = received_provenance.get(capsule_id) else {
            continue;
        };
        let Some(key) = exchange_key_for(record) else {
            continue;
        };
        map.entry(key)
            .or_default()
            .push(CorrelatedSibling { record, provenance });
    }
    map
}

/// The `confirmed_siblings` array a peer row supplies to the ONE gate: for each
/// of this node's OWN records (never a received sibling itself) whose
/// `exchange_key_for` a provenance-carrying foreign half shares, one entry of
/// exactly the two inputs `deriveRightCellState` reads -- the door's recorded
/// `signature_ok` (via a `theirs`-shaped cell) and the structural
/// `digest_match` state. The gate, not this route, turns `verified` +
/// `signature_ok` into CLOSED and `failed` into CONTRADICTED. A record that is
/// itself a received sibling is skipped (it is a counterparty half, not one of
/// this node's asked halves to be confirmed).
fn confirmed_siblings_for(
    peer_records: &[Value],
    siblings_by_key: &HashMap<String, Vec<CorrelatedSibling<'_>>>,
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> Vec<Value> {
    // This peer's own records grouped by correlator (ledger order), each group
    // paired ONE-TO-ONE with the received halves under the same key: a half
    // closes at most one of our records (`pair_one_to_one`).
    let mut order: Vec<String> = Vec::new();
    let mut own_by_key: HashMap<String, Vec<&Value>> = HashMap::new();
    for mine in peer_records {
        if is_received_record(mine, received_provenance) {
            continue;
        }
        let Some(key) = exchange_key_for(mine) else {
            continue;
        };
        if !own_by_key.contains_key(&key) {
            order.push(key.clone());
        }
        push_own(own_by_key.entry(key).or_default(), mine);
    }
    let mut out = Vec::new();
    for key in order {
        let Some(siblings) = siblings_by_key.get(&key) else {
            continue;
        };
        let halves: Vec<&Value> = siblings.iter().map(|s| s.record).collect();
        for (mine, theirs) in pair_one_to_one(&own_by_key[&key], &halves) {
            let (Some(mine), Some(theirs)) = (mine, theirs) else {
                continue;
            };
            let sibling = siblings
                .iter()
                .find(|s| std::ptr::eq(s.record, theirs))
                .expect("a paired half is one of this key's siblings");
            out.push(json!({
                "mine": mine_pair_cell(mine),
                "theirs": theirs_sibling_cell(sibling.record, sibling.provenance),
                "digest_match": { "state": digest_match_state(mine, sibling.record) },
            }));
        }
    }
    out
}

/// The `theirs` cell when a real, provenance-carrying foreign SIBLING is held
/// locally -- `build_exchange_row._side`'s present branch
/// (`{state: present-unverified, capsule_id, role}`), plus the door's
/// provenance triple (`received_from`/`via`/`received_at`/`signature_ok`) so
/// the ONE gate (`exchange-row-state.ts::deriveRightCellState`) has the
/// `signatureOk` input it reads to close a locally-held counterparty half.
/// `state` is `present-unverified` (a real record, not yet crypto-checked in
/// THIS route -- gap 2), exactly `mine`'s own state; the CLOSED/CONTRADICTED
/// DECISION is the gate's, never a second predicate here.
///
/// `record` is the held foreign body itself (the provider-signed bytes the door
/// verified), so the browser can recompute its `capsule_id` and compare its
/// digests and provider against our half -- the same inputs a live peer fetch
/// hands the gate.
fn theirs_sibling_cell(sibling: &Value, provenance: &ReceivedProvenance) -> Value {
    json!({
        "state": STATE_PRESENT_UNVERIFIED,
        "capsule_id": sibling.get("capsule_id").cloned().unwrap_or(Value::Null),
        "role": label_role(sibling),
        "received_from": provenance.received_from,
        "via": provenance.via,
        "received_at": provenance.received_at,
        "signature_ok": provenance.signature_ok,
        "record": sibling,
    })
}

/// Our own half of a correlated pair, with its body, so the gate compares the
/// counterparty half against OUR record's digests and `served_by_node_id`
/// rather than a structural summary. Only emitted for a correlated pair, so an
/// ordinary unilateral row's payload does not grow.
fn mine_pair_cell(mine: &Value) -> Value {
    json!({
        "state": STATE_PRESENT_UNVERIFIED,
        "capsule_id": mine.get("capsule_id").cloned().unwrap_or(Value::Null),
        "role": label_role(mine),
        "record": mine,
    })
}

/// Pane C ("This exchange") list mode -- `capsule_exchange_tab.
/// build_exchange_list_payload` + `group_exchanges` + `build_exchange_row`.
/// `default_sort`/`filters` are the exact literal constants from
/// capsule-emit-mesh main (`capsule_exchange_tab.py:549-552,764`), not guessed.
///
/// ** Route through the ONE gate; drop the
/// `unilateral: true` hardcode.** This used to emit one row PER record with a
/// hardcoded `unilateral: true`, gating CLOSED on a later browser peer-fetch
/// -- a SECOND CLOSED predicate the one-gate rule forbids. It now mirrors
/// Python `group_exchanges`: group every record sharing an `exchange_key_for`
/// (the ONE correlator, digest-first) into ONE row, split into `mine` (this
/// node's own capsules) and `theirs` (a foreign SIBLING held locally, proven
/// by a `received-provenance.jsonl` line -- the provenance rule). `unilateral`
/// is the STRUCTURAL fact `theirs is None`, never a crypto claim. When a
/// provenance-carrying sibling IS correlated, its cell + the row's structural
/// `digest_match` are SUPPLIED to the ONE gate (`deriveRightCellState`), which
/// alone decides CLOSED (`signatureOk && digestsCiteOurHalf`) vs CONTRADICTED
/// (digests differ) -- this route adds no second predicate and no exchange_id
/// grouping. A sibling with no provenance line (self-sealed, or refused at the
/// door) never fills `theirs`, so its row stays unilateral/OPEN: correlation
/// feeds the gate, it never bypasses it.
pub(crate) fn build_pane_c_list(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
) -> Value {
    // One pass, ledger order preserved: the first record of each exchange_key
    // seeds a row in encounter order; later halves of the same exchange fold
    // into that same row (never a second row -- the "6 rows not 3 pairs" bug).
    // Each group is then split ONE-TO-ONE into exchanges (`pair_one_to_one`):
    // two same-digest requests are two rows, never one row comparing request 1
    // against request 2's half.
    let groups = exchange_groups(records, received_provenance);

    // D4(a): the SAME peer attribution
    // Pane B rows use, so an Exchanges row and the Peers table can never name
    // one peer differently. A requester-side OPEN row names the peer its own
    // record routed to (`served_by_node_id`) -- naming whom we asked is not a
    // claim to hold their half; the right cell still says OPEN.
    let siblings_by_key = received_siblings_by_key(records, received_provenance);
    let attribution = peer_attribution(records, received_provenance, &siblings_by_key);

    // A sibling this node RECEIVED (has a provenance line) is `theirs`;
    // everything else in the group is `mine` (self-sealed here). This is the
    // native-ledger equivalent of Python's `my_ids` split -- a single
    // `capsules.jsonl` instead of two lists, so provenance is the honest
    // discriminator of which half came from a counterparty.
    let exchanges = groups.iter().flat_map(|(group_key, own, received)| {
        pair_one_to_one(own, received)
            .into_iter()
            .enumerate()
            .map(move |(n, (mine, theirs))| (pair_row_key(group_key, n), mine, theirs))
    });
    let mut rows = Vec::new();
    for (exchange_key, mine, theirs_sibling) in exchanges {
        // The row anchors on the local half when there is one; a received
        // sibling with no local half of its own still renders (its own column
        // filled), matching `build_exchange_row`'s `anchor = mine or theirs`.
        let Some(anchor) = mine.or(theirs_sibling) else {
            continue;
        };

        let mine_cell = match mine {
            Some(record) if theirs_sibling.is_some() => mine_pair_cell(record),
            Some(record) => json!({
                "state": STATE_PRESENT_UNVERIFIED,
                "capsule_id": record.get("capsule_id").cloned().unwrap_or(Value::Null),
                "role": label_role(record),
            }),
            // `build_exchange_row._side`'s mine-absent branch.
            None => json!({
                "state": STATE_ABSENT,
                "text": "none — received without a commitment",
                "capsule_id": Value::Null,
            }),
        };

        // `theirs`: a provenance-carrying local sibling fills it (the
        // push-primary CLOSED path). With no such sibling, fall back to the
        // record's own peer-asserted join key (`theirs_cell`, the DEFERRED
        // browser-fetch path) -- out of THIS path's CLOSED scope, unchanged.
        let (theirs_cell_value, unilateral) = match theirs_sibling {
            Some(sibling) => {
                let provenance = &received_provenance[sibling
                    .get("capsule_id")
                    .and_then(Value::as_str)
                    .expect("received sibling always carries a capsule_id")];
                (theirs_sibling_cell(sibling, provenance), false)
            }
            None => (theirs_cell(anchor), true),
        };

        // `digest_match`: the STRUCTURAL `digestsCiteOurHalf` INPUT the ONE
        // gate reads -- `verified` only reachable when BOTH halves are present
        // (a correlated pair). A lone half is `absent` (nothing to reconcile),
        // never a fabricated match. A `failed` here is what the gate renders
        // CONTRADICTED.
        let digest_match = match (mine, theirs_sibling) {
            (Some(mine), Some(theirs)) => json!({ "state": digest_match_state(mine, theirs) }),
            _ => json!({ "state": STATE_ABSENT }),
        };

        // The named counterparty, when this row's own evidence names one:
        // the pushed sibling's identity row key, or the anchor record's own
        // `counterparty_peer_label` (a requester half names the server it
        // routed to). `null` when no record names a peer -- never invented.
        let counterparty = attribution.row_key_for(anchor);

        rows.push(json!({
            "exchange_key": exchange_key,
            "role_tag": role_tag(anchor),
            "counterparty": counterparty,
            // `header_state`/`properties`/`has_issue` need the nine-key
            // assurance map (`build_assurance_map`), which is cryptographic
            // re-verification -- out of this cut (module docs gap 2). The
            // structural `digest_match` below is supplied separately as the
            // gate's `digestsCiteOurHalf` input; it is NOT the crypto header.
            "header_state": STATE_ABSENT,
            "properties": Value::Null,
            "has_issue": false,
            "mine": mine_cell,
            "theirs": theirs_cell_value,
            // The STRUCTURAL double-entry fact: a provenance-carrying foreign
            // sibling is correlated into this exchange (`theirs is None`
            // otherwise) -- never a crypto claim, never a hardcode.
            "unilateral": unilateral,
            // Supplied to the ONE gate (`deriveRightCellState`) as the
            // `digestsCiteOurHalf` input; the gate, not this route, turns
            // `verified` + `signature_ok` into CLOSED and `failed` into
            // CONTRADICTED.
            "digest_match": digest_match,
            "timestamp": anchor.get("timestamp").cloned().unwrap_or(Value::Null),
            // -- absent (never null) on every
            // untwinned row; the UI's `twinBracketId` derivation already
            // treats a missing key the same as an explicit `null`.
            "twin_bracket_id": twin_bracket_id(anchor),
        }));
    }
    json!({
        "row_count": rows.len(),
        "default_sort": "timestamp",
        "filters": ["all", "served", "asked", "issues"],
        "rows": rows,
        "next_after_seq": Value::Null,
        "archived_segments": [],
    })
}

/// Pane C drill-down (`exchange_id` supplied) -- `capsule_exchange_tab.
/// build_exchange_view`, same field-availability restriction as the list.
///
/// `exchange_id` is a Pane C row key: the group key, or `<key>#<n>` for the
/// `n`th same-digest exchange of that group (`pair_row_key`).
pub(crate) fn build_pane_c_drilldown(
    records: &[Value],
    received_provenance: &HashMap<String, ReceivedProvenance>,
    exchange_id: &str,
) -> Value {
    let (group_key, n) = match exchange_id.rsplit_once('#') {
        Some((key, n)) => match n.parse::<usize>() {
            Ok(n) if n >= 2 => (key, n - 1),
            _ => return json!({ "exchange_key": exchange_id, "found": false }),
        },
        None => (exchange_id, 0),
    };
    let anchor = exchange_groups(records, received_provenance)
        .into_iter()
        .find(|(key, _, _)| key == group_key)
        .and_then(|(_, own, received)| pair_one_to_one(&own, &received).into_iter().nth(n))
        .and_then(|(mine, theirs)| mine.or(theirs));
    let Some(anchor) = anchor else {
        return json!({ "exchange_key": exchange_id, "found": false });
    };
    json!({
        "exchange_key": exchange_id,
        "found": true,
        "view": {
            "capsule_id": anchor.get("capsule_id").cloned().unwrap_or(Value::Null),
            "role": label_role(anchor),
            "properties": Value::Null,
        },
    })
}

/// Dispatches on the pane name (`is_route`/`ALLOWED_PANES` in
/// `capsule_panes.rs` already validated it), reading the ledger fresh on
/// every call -- same "never cache" discipline as
/// `accountability_pane_routes.py`'s own module docstring.
pub(crate) fn build_pane_json(
    pane: &str,
    ledger_dir: &Path,
    exchange_id: Option<&str>,
) -> Option<Value> {
    // assemble the working set from
    // capsules.jsonl (local + citing records) + the held-artifact store, so
    // `records` carries our served halves + the resolved foreign counterparty
    // halves, and the provenance map is built off our own citing records.
    let EffectiveLedger {
        pane_bc_records,
        our_records,
        received_provenance,
    } = effective_ledger(ledger_dir);
    match pane {
        // Pane A ("This node") shows our own records: our served/requester
        // halves AND our citing records (they ARE our chained log entries) --
        // never the foreign bodies (those are evidence we hold, not ours).
        "pane-a" => Some(build_pane_a(&our_records, read_checkpoint_card(ledger_dir))),
        "pane-b" => Some(build_pane_b(&pane_bc_records, &received_provenance)),
        "pane-c" => Some(match exchange_id {
            Some(id) if !id.is_empty() => {
                build_pane_c_drilldown(&pane_bc_records, &received_provenance, id)
            }
            _ => build_pane_c_list(&pane_bc_records, &received_provenance),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dev tool, not a check: regenerate the Evidence tab's fixture pane JSON
    /// (`/api/capsules/panes/pane-b` and `pane-c`) from a real ledger
    /// directory, through THIS pane reader, so UI fixture mode
    /// (`VITE_EVIDENCE_FIXTURES`) sees exactly what the current host would
    /// send for that ledger. Needed whenever the pane shape changes (e.g. the
    /// record bodies the ONE gate reads). Run:
    ///   EVIDENCE_LEDGER_DIR=<plugin data>/ledger EVIDENCE_FIXTURE_OUT=<dir> \
    ///   cargo test -p mesh-llm-host-runtime regenerate_evidence_pane_fixtures -- --ignored
    #[test]
    #[ignore = "dev tool: regenerates fixture JSON from a real ledger dir"]
    fn regenerate_evidence_pane_fixtures() {
        let ledger = std::env::var("EVIDENCE_LEDGER_DIR").expect("set EVIDENCE_LEDGER_DIR");
        let out = std::env::var("EVIDENCE_FIXTURE_OUT").expect("set EVIDENCE_FIXTURE_OUT");
        std::fs::create_dir_all(&out).expect("create output dir");
        for pane in ["pane-b", "pane-c"] {
            let json = build_pane_json(pane, Path::new(&ledger), None).expect("known pane");
            let body = serde_json::to_string_pretty(&json).expect("serialize pane");
            std::fs::write(Path::new(&out).join(format!("{pane}.json")), body).expect("write pane");
        }
    }
    use std::io::Write;

    fn fixture_record(
        capsule_id: &str,
        timestamp: &str,
        request_digest: &str,
        parent: Option<&str>,
    ) -> Value {
        let mut record = json!({
            "capsule_id": capsule_id,
            "timestamp": timestamp,
            "operator": "capsule-emit-mesh-poc-demo",
            "effect": { "request_digest": request_digest, "response_digest": "resp" },
            "model_attestation": { "compute_attestation": { "runtime": "x" } },
        });
        if let Some(parent_id) = parent {
            record["chain"] = json!({ "parent_capsule_id": parent_id, "relation": "confirms" });
        }
        record
    }

    fn write_fixture_ledger(dir: &Path, records: &[Value]) {
        std::fs::create_dir_all(dir).unwrap();
        let mut file = std::fs::File::create(dir.join("capsules.jsonl")).unwrap();
        for record in records {
            writeln!(file, "{}", serde_json::to_string(record).unwrap()).unwrap();
        }
    }

    /// The empty received-provenance map -- this node has received no push, so
    /// no local sibling can close a row. The overwhelmingly common case, and
    /// the one every pre-existing Pane C test asserts against (a plugin-written
    /// ledger with only this node's own halves).
    fn no_provenance() -> HashMap<String, ReceivedProvenance> {
        HashMap::new()
    }

    /// One `received-provenance.jsonl` line's worth of state, `signature_ok`
    /// true (the door only ever writes a line after signature verification --
    /// `record_push._append_provenance`).
    fn provenance_for(capsule_id: &str, received_from: &str) -> (String, ReceivedProvenance) {
        (
            capsule_id.to_string(),
            ReceivedProvenance {
                received_from: received_from.to_string(),
                via: "push".to_string(),
                received_at: "2026-09-25T00:00:01Z".to_string(),
                signature_ok: true,
                received_from_node_id: None,
            },
        )
    }

    /// a provenance line whose citing
    /// record carried the sender's mesh node id (`received_from_node_id`, the
    /// receive-door capture landing in capsule-emit-mesh) -- the
    /// evidence-backed endpoint-id <-> node-id bridge.
    fn provenance_with_node(
        capsule_id: &str,
        received_from: &str,
        node_id: &str,
    ) -> (String, ReceivedProvenance) {
        let (id, mut prov) = provenance_for(capsule_id, received_from);
        prov.received_from_node_id = Some(node_id.to_string());
        (id, prov)
    }

    /// A sealed capsule always carries the raw pubkey hex that signed it --
    /// `key_id` at the record's top level (the producer's emission). Fixtures
    /// add it explicitly where a test exercises the signing-key join.
    fn with_key(mut record: Value, key_id: &str) -> Value {
        record["key_id"] = json!(key_id);
        record
    }

    /// A cross-node mesh half -- same shape as capsule-emit-mesh's
    /// `test_pane_fires_on_pushed_sibling._mesh_half`: an explicit role +
    /// request/response digests + its OWN host-minted `exchange_id` under
    /// `x-mesh-poc-v1.serving_provenance`. Two halves of one exchange share the
    /// digests but carry DIFFERENT `exchange_id`s (the cross-node reality that
    /// broke exchange_id grouping).
    fn mesh_half(
        capsule_id: &str,
        role: &str,
        request_digest: &str,
        response_digest: &str,
        exchange_id: &str,
    ) -> Value {
        json!({
            "capsule_id": capsule_id,
            "timestamp": "2026-09-25T00:00:00Z",
            "operator": "op",
            "effect": { "request_digest": request_digest, "response_digest": response_digest },
            "model_attestation": { "compute_attestation": { "x-mesh-poc-v1": {
                "role": role,
                "serving_provenance": { "exchange_id": exchange_id, "served_by_node_id": "m3", "requesting_party": "m4" },
            } } },
        })
    }

    /// A cross-node mesh half with an explicit `served_by_node_id` -- the live
    /// run-5 orientation this node
    /// SERVED a peer, so its own half is `role: served` naming ITSELF in
    /// `served_by_node_id`, and the peer's pushed requester half is
    /// `role: requested` naming this node (the server) in `served_by_node_id`
    /// too, `requesting_party: unknown`. NEITHER half names the peer's mesh
    /// node-id -- the peer's only identity is the door's `received_from`.
    fn mesh_half_served_by(
        capsule_id: &str,
        role: &str,
        request_digest: &str,
        response_digest: &str,
        exchange_id: &str,
        served_by_node_id: &str,
    ) -> Value {
        json!({
            "capsule_id": capsule_id,
            "timestamp": "2026-09-25T00:00:00Z",
            "operator": "op",
            "effect": { "request_digest": request_digest, "response_digest": response_digest },
            "model_attestation": { "compute_attestation": { "x-mesh-poc-v1": {
                "role": role,
                "serving_provenance": { "exchange_id": exchange_id, "served_by_node_id": served_by_node_id, "requesting_party": "unknown" },
            } } },
        })
    }

    #[test]
    fn missing_ledger_dir_yields_empty_records_not_a_panic() {
        let dir = std::env::temp_dir().join("mesh-c3-missing-ledger-test");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read_capsule_records(&dir).is_empty());
    }

    /// Every field here is pinned against a REAL `build_pane_a_json` run on
    /// capsule-emit-mesh main against the identical fixture record (see
    /// capsule-emit-mesh's `tests/test_mesh_llm_pane_parity.py`, which pins
    /// the same values from the Python side) -- not a guess. Exception:
    /// `cross_party` -- retired the rung
    /// ladder from THIS reader only, so it now diverges from the (still
    /// unmigrated) Python reference by design; see module docs.
    #[test]
    fn pane_a_matches_the_python_reference_on_a_plugin_shaped_fixture() {
        let records = vec![fixture_record(
            "cap-1",
            "2026-09-01T00:00:00Z",
            "req-1",
            None,
        )];
        let pane = build_pane_a(&records, json!({ "checkpoint_count": 0 }));
        assert_eq!(pane["witness_checkpoint_supplied"], json!(false));
        assert_eq!(pane["operator"], json!("capsule-emit-mesh-poc-demo"));
        let row = &pane["rows"][0];
        assert_eq!(row["capsule_id"], json!("cap-1"));
        assert_eq!(row["verify_ok"], Value::Null);
        assert_eq!(row["model_claimed"], json!("local model"));
        assert_eq!(row["hardware_claimed"], Value::Null);
        assert_eq!(row["rungs"]["freshness"]["state"], json!("absent"));
        assert_eq!(row["rungs"]["cross_party"]["state"], json!("NOT_PRESENT"));
        assert_eq!(
            row["rungs"]["cross_party"]["text"],
            json!(NO_COUNTERPARTY_EVIDENCE_TEXT)
        );
        assert_eq!(row["rungs"]["runtime_binding"]["state"], json!("absent"));
        assert_eq!(row["rungs"]["tee_citation"]["state"], json!("absent"));
        assert_eq!(row["rungs"]["hardware_inventory"]["state"], json!("absent"));
        assert_eq!(
            row["rungs"]["log_integrity"]["state"],
            json!("present-unverified")
        );
    }

    /// Same parity discipline as the Pane A test above, against
    /// `build_pane_b_json` on capsule-emit-mesh main. Split across two
    /// tests (this one + the "cells" test below) purely to keep each one's
    /// assertion count low -- both exercise the SAME `records` fixture.
    #[test]
    fn pane_b_matches_the_python_reference_on_a_plugin_shaped_fixture() {
        let records = vec![
            fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None),
            fixture_record("cap-2", "2026-09-02T00:00:00Z", "req-2", Some("cap-1")),
        ];
        let pane = build_pane_b(&records, &no_provenance());
        assert_eq!(pane["peer_count"], json!(1));
        let row = &pane["rows"][0];
        assert_eq!(row["exchange_count"], json!(2));
        assert_eq!(row["first_seen"], json!("2026-09-01T00:00:00Z"));
        assert_eq!(row["last_seen"], json!("2026-09-02T00:00:00Z"));
        assert_eq!(row["node"]["state"], json!("absent"));
        assert_eq!(
            row["node"]["text"],
            json!(
                "no counterparty evidence for these 2 exchange(s) -- unattributed, not one identified peer"
            )
        );
    }

    /// `cross_party` diverges from the
    /// (still unmigrated) Python reference by design -- see module docs and
    /// the Pane A test above.
    #[test]
    fn pane_b_cells_match_the_python_reference_on_a_plugin_shaped_fixture() {
        let records = vec![
            fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None),
            fixture_record("cap-2", "2026-09-02T00:00:00Z", "req-2", Some("cap-1")),
        ];
        let pane = build_pane_b(&records, &no_provenance());
        let row = &pane["rows"][0];
        assert_eq!(row["cross_party"]["state"], json!("NOT_PRESENT"));
        assert_eq!(
            row["cross_party"]["text"],
            json!(NO_COUNTERPARTY_EVIDENCE_TEXT)
        );
        assert_eq!(row["role"]["state"], json!("present"));
        assert_eq!(row["role"]["role"], json!("them_to_you"));
        assert_eq!(row["role"]["them_to_you_count"], json!(2));
        assert_eq!(row["role"]["you_to_them_count"], json!(0));
        assert_eq!(row["pair"]["state"], json!("absent"));
        assert_eq!(row["pair"]["missing"], json!(0));
        assert_eq!(row["asked"]["state"], json!("absent"));
        assert_eq!(row["asked"]["count"], json!(0));
        // Peer-fetch tranche -- deliberately not ported, module docs gap 1.
        assert_eq!(row["history"]["state"], json!(NOT_CHECKED));
        assert_eq!(row["served"]["state"], json!(NOT_CHECKED));
        assert_eq!(row["verdicts"]["state"], json!(NOT_CHECKED));
    }

    #[test]
    fn pane_b_pair_cell_is_not_checked_rather_than_fabricated_absent_once_an_exchange_id_appears() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] =
            json!({ "serving_provenance": { "exchange_id": "exch-real" } });
        let pane = build_pane_b(&[record], &no_provenance());
        assert_eq!(pane["rows"][0]["pair"]["state"], json!(NOT_CHECKED));
    }

    #[test]
    fn pane_b_on_an_empty_ledger_has_zero_peers_not_a_fabricated_row() {
        let pane = build_pane_b(&[], &no_provenance());
        assert_eq!(pane["peer_count"], json!(0));
        assert_eq!(pane["rows"], json!([]));
    }

    /// A `RemoteMesh` requester-side record (role `"requested"`,
    /// `served_by_node_id` naming the remote server) counts as a peer this
    /// node DEALT WITH -- named, "their half not held" -- NOT "advertised but
    /// unused · dealt with 0". The count does not wait on CLOSED. MUTANT: if
    /// `build_pane_b` reverts to the single unattributed bucket, `peer_id` goes
    /// null and `dealt with 0` returns -- this assertion goes red.
    #[test]
    fn pane_b_attributes_a_served_remote_peer_as_dealt_with_not_a_false_zero() {
        let mut record = fixture_record("cap-r1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "role": "requested",
            "serving_provenance": {
                "served_by_node_id": "16b1362a8ebf00119abc",
                "dispatch_path": "remote_mesh"
            }
        });
        let pane = build_pane_b(&[record], &no_provenance());
        assert_eq!(pane["peer_count"], json!(1));
        let row = &pane["rows"][0];
        // node:<served_by[:16]>, mirroring capsule_mesh_view.label_counterparty.
        assert_eq!(row["peer_id"], json!("node:16b1362a8ebf0011"));
        assert_eq!(row["node"]["state"], json!("present"));
        assert_eq!(row["cross_party"]["state"], json!("present-unverified"));
        assert_eq!(row["role"]["you_to_them_count"], json!(1));
        assert_eq!(row["exchange_count"], json!(1));
    }

    /// A record with no attributable counterparty stays UNATTRIBUTED -- a
    /// residual row with `peer_id: null`, never a fabricated peer -- and an
    /// attributed peer plus an unattributed record yield two honest rows
    /// (attributed first, residual last).
    #[test]
    fn pane_b_keeps_unattributed_records_honest_alongside_a_named_peer() {
        let mut attributed = fixture_record("cap-a", "2026-09-01T00:00:00Z", "req-a", None);
        attributed["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "role": "requested",
            "serving_provenance": { "served_by_node_id": "peerXYZ0123456789ab" }
        });
        let plain = fixture_record("cap-b", "2026-09-02T00:00:00Z", "req-b", None);
        let pane = build_pane_b(&[attributed, plain], &no_provenance());
        assert_eq!(pane["peer_count"], json!(2));
        assert_eq!(pane["rows"][0]["peer_id"], json!("node:peerXYZ012345678"));
        assert_eq!(pane["rows"][1]["peer_id"], Value::Null);
        assert_eq!(pane["rows"][1]["node"]["state"], json!("absent"));
    }

    // -----------------------------------------------------------------
    // Pane B routes "confirmed by the other
    // side" through the SAME ONE gate Pane C uses: a dealt-with peer row
    // SUPPLIES `confirmed_siblings`, each carrying the door's `signature_ok`
    // (via a `theirs`-shaped cell) + the structural `digest_match` -- the two
    // inputs `exchange-row-state.ts::deriveRightCellState` reads to render
    // CLOSED. These mirror the Pane C sibling tests above; the CLOSED/
    // CONTRADICTED DECISION stays the gate's, never a second fetch-gated
    // predicate here (the `history`/`pair` peer-fetch tranche is untouched).
    // -----------------------------------------------------------------

    /// A peer this node asked, whose served half arrived by push (a
    /// provenance line, `signature_ok: true`) and correlates by digest, gets
    /// ONE `confirmed_siblings` entry with `signature_ok: true` and a
    /// `verified` `digest_match` -- exactly the two gate inputs the TS view
    /// runs through the ONE gate to count as confirmed/clean. MUTANT: revert
    /// Pane B to no `confirmed_siblings` and this goes red.
    #[test]
    fn pane_b_supplies_a_confirmed_sibling_for_a_correlated_pushed_half() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local, foreign], &provenance);

        // The local half (role requested, served_by_node_id m3) attributes the
        // peer; the foreign served half is its counterparty half, not a second
        // peer row.
        let row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peer_id"] == json!("node:m3"))
            .expect("the asked peer is attributed");
        let siblings = row["confirmed_siblings"].as_array().unwrap();
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0]["theirs"]["signature_ok"], json!(true));
        assert_eq!(siblings[0]["theirs"]["received_from"], json!("m3"));
        assert_eq!(siblings[0]["digest_match"]["state"], json!(STATE_VERIFIED));
        // The Peers gate gets the same two bodies the Exchanges gate does.
        assert!(siblings[0]["theirs"]["record"].is_object());
        assert!(siblings[0]["mine"]["record"].is_object());
        // The half IS held now -- the node text stops asserting "not held".
        assert!(row["node"]["text"]
            .as_str()
            .unwrap()
            .contains("their half held"));
    }

    /// `distinct_exchange_count` collapses the two halves of one cross-node
    /// exchange (same request_digest) to ONE, counts an uncorrelated record
    /// (no request_digest, no exchange_id) as its own exchange, and never
    /// double-counts. This is the record-vs-exchange fix: 6 halves of 3
    /// exchanges count as 3, not 6.
    #[test]
    fn distinct_exchange_count_counts_exchanges_not_records() {
        // 3 exchanges, each with two halves sharing a request_digest.
        let mut records = Vec::new();
        for i in 0..3 {
            let d = format!("{i}").repeat(64);
            records.push(mesh_half(
                &format!("mine-{i}"),
                "requested",
                &d,
                "resp",
                &format!("m4-{i}"),
            ));
            records.push(mesh_half(
                &format!("theirs-{i}"),
                "served",
                &d,
                "resp",
                &format!("m3-{i}"),
            ));
        }
        assert_eq!(records.len(), 6);
        let provenance: HashMap<String, ReceivedProvenance> = (0..3)
            .map(|i| provenance_for(&format!("theirs-{i}"), "m3"))
            .collect();
        assert_eq!(
            distinct_exchange_count(&records, &provenance),
            3,
            "6 halves -> 3 exchanges, never 6"
        );

        // A record with neither a request_digest nor an exchange_id cannot be
        // correlated, so it counts as its own exchange -- never merged away.
        let mut uncorrelated = json!({ "capsule_id": "x", "timestamp": "t" });
        assert!(exchange_key_for(&uncorrelated).is_none());
        uncorrelated["effect"] = json!({});
        records.push(uncorrelated);
        assert_eq!(distinct_exchange_count(&records, &provenance), 4);
    }

    /// The peer-row "N exchanges" figure counts DISTINCT exchanges, so a peer
    /// with 3 exchanges whose 3 served halves all arrived by push and closed
    /// reads confirmed "3 / 3" -- never "3 / 6" off a record count. This is
    /// the [record-vs-exchange] double-count fix end to end.
    #[test]
    fn pane_b_exchange_count_and_confirmed_denominator_count_exchanges_not_records() {
        let mut records = Vec::new();
        let mut provenance: HashMap<String, ReceivedProvenance> = HashMap::new();
        for i in 0..3 {
            let d = format!("{i}").repeat(64);
            // This node asked; its own requester half.
            records.push(mesh_half(
                &format!("mine-{i}"),
                "requested",
                &d,
                "resp",
                &format!("m4-{i}"),
            ));
            // The peer's served half arrived by push (verified) and correlates
            // by digest -- re-entered into the working set like the real reader.
            let theirs_id = format!("theirs-{i}");
            records.push(mesh_half(
                &theirs_id,
                "served",
                &d,
                "resp",
                &format!("m3-{i}"),
            ));
            provenance.extend([provenance_for(&theirs_id, "m3")]);
        }

        let pane = build_pane_b(&records, &provenance);
        let row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peer_id"] == json!("node:m3"))
            .expect("the served peer is attributed");
        // Three exchanges, six halves.
        assert_eq!(
            row["exchange_count"],
            json!(3),
            "distinct exchanges, not the 6 records"
        );
        // Three pushed served halves closed through the ONE gate.
        assert_eq!(row["confirmed_siblings"].as_array().unwrap().len(), 3);
    }

    /// A peer with only this node's own half (no pushed sibling, no
    /// provenance) supplies an EMPTY `confirmed_siblings` -- the gate reads
    /// that as "not confirmed", and the row stays "their half not held". No
    /// fabricated confirmation, no fetch-gated predicate.
    #[test]
    fn pane_b_local_only_peer_supplies_no_confirmed_sibling() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let pane = build_pane_b(&[local], &no_provenance());
        let row = &pane["rows"][0];
        assert_eq!(row["peer_id"], json!("node:m3"));
        assert_eq!(row["confirmed_siblings"].as_array().unwrap().len(), 0);
        assert!(row["node"]["text"]
            .as_str()
            .unwrap()
            .contains("their half not held"));
    }

    /// The provenance rule holds in Pane B exactly as in Pane C: a genuine
    /// cross-node served half with NO provenance line is not a counterparty
    /// half, so it supplies no `confirmed_siblings` -- the gate cannot close.
    #[test]
    fn pane_b_sibling_without_a_provenance_line_supplies_no_confirmed_sibling() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
        );
        // No provenance -> `foreign` is not a received half.
        let pane = build_pane_b(&[local, foreign], &no_provenance());
        let row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peer_id"] == json!("node:m3"))
            .expect("the peer is still attributed by this node's own record");
        assert_eq!(row["confirmed_siblings"].as_array().unwrap().len(), 0);
    }

    /// A correlated pushed half whose digests DIFFER supplies a `failed`
    /// `digest_match` -- which the ONE gate turns into CONTRADICTED, never a
    /// silent confirmation. The sibling is still supplied (a real disagreement
    /// between two present halves), never dropped.
    #[test]
    fn pane_b_correlated_pushed_half_with_differing_digests_supplies_a_failed_match() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        // Same request_digest (correlates), DIFFERENT response_digest.
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "f".repeat(64).as_str(),
            "m3-82777e20",
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local, foreign], &provenance);

        let row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peer_id"] == json!("node:m3"))
            .expect("the peer is attributed");
        let siblings = row["confirmed_siblings"].as_array().unwrap();
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0]["digest_match"]["state"], json!(STATE_FAILED));
    }

    // -----------------------------------------------------------------
    // The join-key fix. In the live
    // run-5 orientation this node SERVED the peer, so its own half is
    // `role: served` naming ITSELF in `served_by_node_id` (no counterparty
    // label -> the null group), and the peer's pushed REQUESTER half names this
    // node in `served_by_node_id` too. The peer's only identity is the door's
    // `received_from`. The prior reader attributed the confirmed sibling by the
    // served local half's own (absent) label, dropping it into `peer_id: null`
    // while the real peer row showed `confirmed_siblings: 0`. The fix attributes
    // by the peer that PUSHED the sibling (`sibling_peer_label`), so the
    // confirmed sibling lands in that peer's row.
    // -----------------------------------------------------------------

    /// The exact live bug: this node served a peer (local `role: served`,
    /// `served_by_node_id` = SELF, so no counterparty label of its own) and the
    /// peer pushed its requester half (`role: requested`, `served_by_node_id` =
    /// SELF, provenance `received_from` = the peer's stable id). The confirmed
    /// sibling MUST land in the pushing peer's row -- keyed by the door's
    /// endpoint id and LABELED as one (`endpoint:<received_from>`, never the
    /// old `node:<received_from>` id-space mislabeling
    /// D3) -- which shows
    /// confirmed/clean, and the null group must be EMPTY -- not the prior
    /// `confirmed_siblings: 3 under peer_id: null` while the peer showed 0.
    /// MUTANT: revert to attributing by the local half's own label and the
    /// sibling falls back into the null group -- both asserts go red.
    #[test]
    fn pane_b_attributes_a_served_sides_pushed_sibling_to_the_pushing_peer_not_the_null_group() {
        // `me-node` is THIS node's id (the server the peer named); `m3` is the
        // peer's door `received_from`. Neither half carries the peer's node-id
        // or its signing key, so the endpoint id is the only honest row key.
        let local_served = mesh_half_served_by(
            "a".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "me-914b61c1",
            "me-node",
        );
        let pushed_requester = mesh_half_served_by(
            "b".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
            "me-node",
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local_served, pushed_requester], &provenance);
        let rows = pane["rows"].as_array().unwrap();

        // The confirmed sibling attributes to the pushing peer, keyed by the
        // door's `received_from` in its OWN id space -- not a self row, not
        // the null group, and never labeled `node:`.
        let peer = rows
            .iter()
            .find(|r| r["peer_id"] == json!("endpoint:m3"))
            .expect("the pushing peer (received_from) gets a row");
        let siblings = peer["confirmed_siblings"].as_array().unwrap();
        assert_eq!(
            siblings.len(),
            1,
            "the confirmed sibling lands in the peer's row"
        );
        assert_eq!(siblings[0]["theirs"]["received_from"], json!("m3"));
        assert_eq!(siblings[0]["digest_match"]["state"], json!(STATE_VERIFIED));
        assert!(
            !rows.iter().any(|r| r["peer_id"] == json!("node:m3")),
            "an endpoint id is never passed off as a node id"
        );

        // No unattributed residual carrying a confirmed sibling -- the null
        // group is empty (both halves of the exchange attributed to the peer).
        let null_with_siblings = rows.iter().find(|r| {
            r["peer_id"] == Value::Null && !r["confirmed_siblings"].as_array().unwrap().is_empty()
        });
        assert!(
            null_with_siblings.is_none(),
            "no confirmed sibling remains in the null/unattributed group"
        );
    }

    /// A pushed sibling with NO resolvable peer identity -- the peer served us
    /// (so its `served_by_node_id` WOULD name it) but recorded `"unknown"`, AND
    /// the door recorded an empty `received_from` -- is genuinely unattributable
    /// and stays in the null group honestly (never a fabricated peer). The
    /// exchange still folds into ONE unattributed row; the sibling is not lost.
    #[test]
    fn pane_b_sibling_with_no_resolvable_peer_identity_stays_unattributed_honestly() {
        let local = mesh_half_served_by(
            "a".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "me-914b61c1",
            "unknown",
        );
        let pushed = mesh_half_served_by(
            "b".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
            "unknown",
        );
        // Empty `received_from` -> no peer-id either. (The door never writes a
        // blank line in practice; `sibling_peer_label` still refuses to invent.)
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local, pushed], &provenance);
        let rows = pane["rows"].as_array().unwrap();
        // No named peer row -- the exchange has no resolvable counterparty.
        assert!(rows.iter().all(|r| r["peer_id"] == Value::Null));
        // The one honest unattributed row still carries the correlated sibling.
        let residual = rows
            .iter()
            .find(|r| r["peer_id"] == Value::Null)
            .expect("an unattributed residual row");
        assert_eq!(
            residual["confirmed_siblings"].as_array().unwrap().len(),
            1,
            "a genuinely unattributable sibling stays in the null group, not dropped"
        );
    }

    // -----------------------------------------------------------------
    // Defect 3 -- one peer rendered
    // as two. Peer identity joins on the SIGNING KEY (the pushed body's
    // `key_id`, door-verified against the announced peer key), with the
    // endpoint id and node id as aliases on ONE row. No evidence-backed
    // bridge -> no merge: the node-id row stays separate, honestly, and the
    // `received_from_node_id` provenance field completes the merge with no
    // further code change the day the receive door captures it.
    // -----------------------------------------------------------------

    /// The live M4 ledger shape, exactly: 3 served halves + 3 pushed foreign
    /// requester halves signed by `71eb…` and received from endpoint
    /// `e5ba9d1001`, PLUS 2 requester halves naming mesh node `a70d…`. The
    /// pushing peer is ONE row keyed by its signing key (aliases: endpoint),
    /// the `a70d…` node row stays separate (no evidence links it to that
    /// key), and no third row appears. MUTANT: revert the row key to
    /// `node:<received_from>` and the `key:` row disappears.
    #[test]
    fn pane_b_joins_the_pushing_peer_on_the_signing_key_with_the_endpoint_as_alias() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let their_node = format!("a70d{}", "3".repeat(60));
        // This node served the peer; the peer pushed its requester half.
        let local_served = mesh_half_served_by(
            "a".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "me-914b61c1",
            "me-node",
        );
        let pushed_requester = with_key(
            mesh_half_served_by(
                "b".repeat(64).as_str(),
                "requested",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "m3-82777e20",
                "me-node",
            ),
            peer_key,
        );
        // And this node ASKED a peer at mesh node a70d… (no push received for
        // those exchanges, so no key evidence bridges the two id spaces).
        let asked = mesh_half_served_by(
            "c".repeat(64).as_str(),
            "requested",
            "f".repeat(64).as_str(),
            "0".repeat(64).as_str(),
            "me-77aa",
            &their_node,
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "e5ba9d1001")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local_served, pushed_requester, asked], &provenance);
        let rows = pane["rows"].as_array().unwrap();

        // ONE key-identified row for the pushing peer, endpoint as alias.
        let key_row = rows
            .iter()
            .find(|r| r["peer_id"] == json!("key:71eb26f8e583ccc9"))
            .expect("the pushing peer is keyed by its signing key");
        assert_eq!(key_row["identity"]["signing_key_id"], json!(peer_key));
        assert_eq!(key_row["identity"]["endpoint_id"], json!("e5ba9d1001"));
        assert_eq!(
            key_row["identity"]["node_id"],
            Value::Null,
            "no node-id evidence -> no fabricated alias"
        );
        assert_eq!(key_row["confirmed_siblings"].as_array().unwrap().len(), 1);

        // The asked node stays a SEPARATE row -- no evidence bridges a70d… to
        // the signing key -- carrying its FULL node id as identity evidence.
        let node_row = rows
            .iter()
            .find(|r| r["peer_id"] == json!(format!("node:{}", short_id(&their_node, 16))))
            .expect("the unlinked node row stays separate");
        assert_eq!(node_row["identity"]["node_id"], json!(their_node));
        assert_eq!(
            node_row["identity"]["node_id_source"],
            json!("your_records")
        );
        assert_eq!(node_row["identity"]["signing_key_id"], Value::Null);

        // Exactly these two peers -- never an endpoint row AND a key row for
        // the same pushing peer, never a null-group leak.
        assert_eq!(
            pane["peer_count"],
            json!(2),
            "one row per peer, no third appearance"
        );
        assert!(!rows
            .iter()
            .any(|r| r["peer_id"] == json!("endpoint:e5ba9d1001")));
        assert!(!rows.iter().any(|r| r["peer_id"] == Value::Null));
    }

    /// A pushed SERVED half naming its own server is the peer's claim, not
    /// ours: the row carries that node id labelled `their_record`, so the
    /// console never offers to block by it (a peer could name an honest node).
    /// MUTANT: treat the served half's `served_by_node_id` as ours and the
    /// source reads `your_records`.
    #[test]
    fn pane_b_labels_a_self_asserted_node_id_as_their_record() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let claimed = format!("b0b0{}", "4".repeat(60));
        // Our own record names no serving node, so the only node id on the
        // row is the peer's own claim.
        let local_requested = mesh_half_served_by(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "me-1",
            "unknown",
        );
        let pushed_served = with_key(
            mesh_half_served_by(
                "b".repeat(64).as_str(),
                "served",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "them-1",
                &claimed,
            ),
            peer_key,
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "e5ba9d1001")]
                .into_iter()
                .collect();

        let pane = build_pane_b(&[local_requested, pushed_served], &provenance);
        let key_row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peer_id"] == json!("key:71eb26f8e583ccc9"))
            .expect("the pushing peer is keyed by its signing key");
        assert_eq!(key_row["identity"]["node_id"], json!(claimed));
        assert_eq!(key_row["identity"]["node_id_source"], json!("their_record"));
    }

    /// The requester side: we only asked. Our own record of the exchange
    /// names the node our host routed it to, so the peer row's node id is
    /// ours and the console can stop routing to it -- whatever the peer's
    /// own record claims about itself. MUTANT: drop the own-routed join and
    /// the row reads `their_record` (not blockable) or the peer's claim.
    #[test]
    fn pane_b_takes_the_node_id_our_own_requester_record_routed_to() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let routed = format!("c1f5{}", "5".repeat(60));
        for claimed in [routed.clone(), format!("b0b0{}", "4".repeat(60))] {
            let local_requested = mesh_half_served_by(
                "a".repeat(64).as_str(),
                "requested",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "me-1",
                &routed,
            );
            let pushed_served = with_key(
                mesh_half_served_by(
                    "b".repeat(64).as_str(),
                    "served",
                    "d".repeat(64).as_str(),
                    "e".repeat(64).as_str(),
                    "them-1",
                    &claimed,
                ),
                peer_key,
            );
            let provenance: HashMap<String, ReceivedProvenance> =
                [provenance_for("b".repeat(64).as_str(), "e5ba9d1001")]
                    .into_iter()
                    .collect();

            let pane = build_pane_b(&[local_requested, pushed_served], &provenance);
            let rows = pane["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 1, "one peer row");
            assert_eq!(rows[0]["peer_id"], json!("key:71eb26f8e583ccc9"));
            assert_eq!(
                rows[0]["identity"]["node_id"],
                json!(routed),
                "the node our host routed to"
            );
            assert_eq!(rows[0]["identity"]["node_id_source"], json!("your_records"));
        }
    }

    /// A node id from a record we RECEIVED never counts as ours, even on a
    /// requested-role record: only our own records route.
    #[test]
    fn a_received_requested_record_never_supplies_our_routed_node() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let claimed = format!("b0b0{}", "4".repeat(60));
        let pushed_requested = with_key(
            mesh_half_served_by(
                "b".repeat(64).as_str(),
                "requested",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "them-1",
                &claimed,
            ),
            peer_key,
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "e5ba9d1001")]
                .into_iter()
                .collect();
        let own = own_routed_node_by_key(&[pushed_requested], &provenance);
        assert!(own.is_empty());
    }

    /// The bridge case: the citing record carries `received_from_node_id`
    /// naming the SAME mesh node our own requester halves routed to. All
    /// three id spaces collapse onto ONE signing-key row -- endpoint AND node
    /// aliases -- and the asked halves merge onto it with NO further code
    /// change. MUTANT: drop the `received_from_node_id` read and this merge
    /// splits back into two rows.
    #[test]
    fn pane_b_received_from_node_id_bridges_the_asked_node_row_onto_the_signing_key_row() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let their_node = format!("a70d{}", "3".repeat(60));
        let local_served = mesh_half_served_by(
            "a".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "me-914b61c1",
            "me-node",
        );
        let pushed_requester = with_key(
            mesh_half_served_by(
                "b".repeat(64).as_str(),
                "requested",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "m3-82777e20",
                "me-node",
            ),
            peer_key,
        );
        let asked = mesh_half_served_by(
            "c".repeat(64).as_str(),
            "requested",
            "f".repeat(64).as_str(),
            "0".repeat(64).as_str(),
            "me-77aa",
            &their_node,
        );
        // The door captured the sender's node id on the citing record.
        let provenance: HashMap<String, ReceivedProvenance> = [provenance_with_node(
            "b".repeat(64).as_str(),
            "e5ba9d1001",
            &their_node,
        )]
        .into_iter()
        .collect();

        let pane = build_pane_b(&[local_served, pushed_requester, asked], &provenance);
        let rows = pane["rows"].as_array().unwrap();

        assert_eq!(
            pane["peer_count"],
            json!(1),
            "the evidence-backed bridge merges the rows"
        );
        let row = &rows[0];
        assert_eq!(row["peer_id"], json!("key:71eb26f8e583ccc9"));
        assert_eq!(row["identity"]["signing_key_id"], json!(peer_key));
        assert_eq!(row["identity"]["endpoint_id"], json!("e5ba9d1001"));
        assert_eq!(row["identity"]["node_id"], json!(their_node));
        assert_eq!(row["identity"]["node_id_source"], json!("your_records"));
        // exchange_count is DISTINCT exchanges by the ONE correlator, not the
        // record count: the served exchange's two halves (local_served +
        // pushed_requester) share request_digest d..d -> ONE exchange, and the
        // asked half (digest f..f) is a second. Three records, TWO exchanges.
        // (The record count would read 3 -- the double-count Item 3 fixes.)
        assert_eq!(row["exchange_count"], json!(2));
    }

    /// D4(a): a requester-side OPEN
    /// row names the peer this node's OWN record routed to
    /// (`served_by_node_id`) -- naming whom we asked, never claiming their
    /// half (the row stays unilateral). A served row with no counterparty
    /// evidence carries `counterparty: null`; a row with a pushed sibling
    /// carries the SAME row key Pane B uses.
    #[test]
    fn pane_c_names_the_counterparty_on_a_requester_row_without_claiming_their_half() {
        let their_node = format!("a70d{}", "3".repeat(60));
        let asked = mesh_half_served_by(
            "c".repeat(64).as_str(),
            "requested",
            "f".repeat(64).as_str(),
            "0".repeat(64).as_str(),
            "me-77aa",
            &their_node,
        );
        let served_local = fixture_record("cap-s", "2026-09-01T00:00:00Z", "req-s", None);

        let pane = build_pane_c_list(&[asked, served_local], &no_provenance());
        let rows = pane["rows"].as_array().unwrap();

        let asked_row = rows
            .iter()
            .find(|r| r["role_tag"] == json!("ASKED"))
            .expect("the requester row renders");
        assert_eq!(
            asked_row["counterparty"],
            json!(format!("node:{}", short_id(&their_node, 16))),
            "the requester row names the peer it routed to"
        );
        // Naming the peer is NOT claiming their half: still OPEN/unilateral.
        assert_eq!(asked_row["unilateral"], json!(true));
        assert_eq!(asked_row["theirs"]["state"], json!(STATE_ABSENT));

        let served_row = rows
            .iter()
            .find(|r| r["role_tag"] == json!("SERVED"))
            .expect("the served row renders");
        assert_eq!(
            served_row["counterparty"],
            Value::Null,
            "no counterparty evidence -> null, never invented"
        );
    }

    /// D4(a) closed-path agreement: a row closed by a pushed sibling names
    /// the counterparty with the SAME key Pane B rows use (the signing-key
    /// row key), so the two panes can never name one peer differently.
    #[test]
    fn pane_c_counterparty_matches_the_pane_b_row_key_for_a_pushed_sibling() {
        let peer_key = "71eb26f8e583ccc99e0ae72e1eee88ead06a81159d8e721ba98eeffe5c30550d";
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let foreign = with_key(
            mesh_half(
                "b".repeat(64).as_str(),
                "served",
                "d".repeat(64).as_str(),
                "e".repeat(64).as_str(),
                "m3-82777e20",
            ),
            peer_key,
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane_c = build_pane_c_list(&[local.clone(), foreign.clone()], &provenance);
        let pane_b = build_pane_b(&[local, foreign], &provenance);

        let c_counterparty = pane_c["rows"][0]["counterparty"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(c_counterparty, "key:71eb26f8e583ccc9");
        assert!(
            pane_b["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["peer_id"] == json!(c_counterparty)),
            "Exchanges and Peers name the peer identically"
        );
    }

    #[test]
    fn pane_c_groups_by_digest_when_no_exchange_id_and_tags_served_by_default() {
        let records = vec![
            fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None),
            fixture_record("cap-2", "2026-09-02T00:00:00Z", "req-2", Some("cap-1")),
        ];
        let pane = build_pane_c_list(&records, &no_provenance());
        assert_eq!(pane["row_count"], json!(2));
        assert_eq!(pane["default_sort"], json!("timestamp"));
        assert_eq!(pane["rows"][0]["exchange_key"], json!("digest:req-1"));
        assert_eq!(pane["rows"][0]["role_tag"], json!("SERVED"));
        assert_eq!(pane["rows"][0]["unilateral"], json!(true));
        assert_eq!(pane["rows"][0]["theirs"]["state"], json!(STATE_ABSENT));
        assert_eq!(
            pane["rows"][0]["mine"]["state"],
            json!(STATE_PRESENT_UNVERIFIED)
        );
        // The one deliberate non-parity gap in this cut (see module docs):
        // real Python computes a real header_state/properties here via the
        // assurance map; this cut has not ported that verification.
        assert_eq!(pane["rows"][0]["header_state"], json!(STATE_ABSENT));
        assert_eq!(pane["rows"][0]["properties"], Value::Null);
        // Untwinned rows (the overwhelming majority) carry no bracket.
        assert_eq!(pane["rows"][0]["twin_bracket_id"], Value::Null);
    }

    /// a record whose `capsule-producer` plugin
    /// forwarded a `twin_bracket_id` off the terminal envelope surfaces that
    /// SAME id on its Pane C row, at the sibling JSON path `exchange_id`
    /// already lives at (`x-mesh-poc-v1.serving_provenance`). MUTANT: drop
    /// the `twin_bracket_id(record)` read in `build_pane_c_list` and this
    /// assertion goes red.
    #[test]
    fn pane_c_row_carries_the_plugin_forwarded_twin_bracket_id() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "serving_provenance": { "exchange_id": "exch-real", "twin_bracket_id": "twin-abc123" }
        });
        let pane = build_pane_c_list(&[record], &no_provenance());
        assert_eq!(pane["rows"][0]["twin_bracket_id"], json!("twin-abc123"));
    }

    /// `` piece 3, positive: a record carrying a real
    /// `peer_asserted` join key (piece 1) surfaces `theirs.state ==
    /// NOT_CHECKED` (known + fetchable, not absent) with the exact
    /// capsule_id/peer_id the browser needs to drive `mesh_ledger_fetch`
    /// (piece 2). MUTANT: drop the `theirs_cell(record)` read in
    /// `build_pane_c_list` and this assertion goes red.
    #[test]
    fn pane_c_row_surfaces_a_real_peer_asserted_join_key_as_not_checked() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "serving_provenance": {
                "peer_capsule_id": "peer-cap-987",
                "peer_capsule_id_provenance": "peer_asserted",
                "served_by_node_id": "peer-node-3",
            }
        });
        let pane = build_pane_c_list(&[record], &no_provenance());
        let theirs = &pane["rows"][0]["theirs"];
        assert_eq!(theirs["state"], json!(NOT_CHECKED));
        assert_eq!(theirs["capsule_id"], json!("peer-cap-987"));
        assert_eq!(theirs["peer_id"], json!("peer-node-3"));
    }

    /// (negative, R4 other half) `self_minted` is THIS node's own marker,
    /// never a peer's claim (the exact mislabeling piece 1's
    /// `peer_capsule_id_for_seal` guard exists to prevent) -- must stay
    /// `absent`, never surfaced as fetchable.
    #[test]
    fn pane_c_row_never_surfaces_a_self_minted_capsule_id_as_theirs() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "serving_provenance": {
                "peer_capsule_id": "not-actually-a-peer-id",
                "peer_capsule_id_provenance": "self_minted",
                "served_by_node_id": "peer-node-3",
            }
        });
        let pane = build_pane_c_list(&[record], &no_provenance());
        assert_eq!(pane["rows"][0]["theirs"]["state"], json!(STATE_ABSENT));
        assert_eq!(pane["rows"][0]["theirs"]["capsule_id"], Value::Null);
    }

    /// (negative) A real `peer_asserted` capsule_id with no identifiable
    /// `served_by_node_id` (still `"unknown"`, the honest default) has
    /// nowhere to fetch FROM -- `absent`, not a join key naming no peer.
    #[test]
    fn pane_c_row_never_surfaces_a_join_key_with_no_identifiable_peer() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "serving_provenance": {
                "peer_capsule_id": "peer-cap-987",
                "peer_capsule_id_provenance": "peer_asserted",
                "served_by_node_id": "unknown",
            }
        });
        let pane = build_pane_c_list(&[record], &no_provenance());
        assert_eq!(pane["rows"][0]["theirs"]["state"], json!(STATE_ABSENT));
    }

    // -----------------------------------------------------------------
    // Route through the ONE gate: the pane
    // fires CLOSED on a locally-held, provenance-carrying, digest-matching
    // foreign sibling -- mirroring capsule-emit-mesh's
    // `tests/test_pane_fires_on_pushed_sibling.py`. The CLOSED/CONTRADICTED
    // DECISION is the ONE gate's (`exchange-row-state.ts::deriveRightCellState`,
    // `signatureOk && digestsCiteOurHalf`); these tests prove `build_pane_c_list`
    // SUPPLIES that gate its two inputs honestly -- the correlated sibling
    // (dropping the `unilateral: true` hardcode) and the structural
    // `digest_match` -- and that the provenance rule holds (no provenance ->
    // no counterparty half -> the gate cannot close).
    // -----------------------------------------------------------------

    /// A locally-held foreign sibling (a DIFFERENT host-minted exchange_id, the
    /// SAME request_digest, a `received-provenance.jsonl` line with
    /// `signature_ok: true`) is CORRELATED into this node's own asked half:
    /// ONE row, both columns filled, `unilateral: false`, and the structural
    /// `digest_match` is `verified` -- exactly the two inputs the ONE gate
    /// reads to render CLOSED. MUTANT: revert `build_pane_c_list` to the
    /// per-record `unilateral: true` hardcode and `unilateral`/`digest_match`
    /// both go red.
    #[test]
    fn pane_c_closes_a_correlated_provenance_carrying_signature_verifying_sibling() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
        );
        // The door verified & recorded the foreign half; the two host-minted
        // exchange_ids differ, so ONLY the digest correlator groups them.
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane = build_pane_c_list(&[local.clone(), foreign.clone()], &provenance);

        assert_eq!(pane["row_count"], json!(1)); // ONE row, not two OPEN halves.
        let row = &pane["rows"][0];
        assert_eq!(
            row["exchange_key"],
            json!(format!("digest:{}", "d".repeat(64)))
        );
        assert_eq!(row["mine"]["capsule_id"], json!("a".repeat(64)));
        assert_eq!(row["theirs"]["capsule_id"], json!("b".repeat(64))); // the sibling filled `theirs`.
        assert_eq!(row["unilateral"], json!(false)); // NOT the old hardcode.
                                                     // The gate's `digestsCiteOurHalf` input: both digests agree -> verified.
        assert_eq!(row["digest_match"]["state"], json!(STATE_VERIFIED));
        // The gate's `signatureOk` input: the door's recorded provenance triple.
        assert_eq!(row["theirs"]["signature_ok"], json!(true));
        assert_eq!(row["theirs"]["received_from"], json!("m3"));
        assert_eq!(row["theirs"]["via"], json!("push"));
        assert_eq!(row["theirs"]["state"], json!(STATE_PRESENT_UNVERIFIED));
        // Both bodies ride on the pair so the browser gate can recompute the
        // foreign capsule_id and compare digests + provider against OUR half.
        // MUTANT: drop `"record": sibling` from `theirs_sibling_cell` (or the
        // `mine_pair_cell` arm) and these go red.
        assert_eq!(row["theirs"]["record"], foreign);
        assert_eq!(row["mine"]["record"], local);
    }

    /// Only the local half present (no sibling, no provenance): unilateral/OPEN,
    /// `theirs` absent, `digest_match` absent (nothing to reconcile). The
    /// deferred browser-fetch fallback still surfaces the record's own
    /// peer-asserted join key when one exists, but the row is NOT closed here.
    #[test]
    fn pane_c_row_with_only_the_local_half_is_unilateral_open() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let pane = build_pane_c_list(&[local], &no_provenance());
        assert_eq!(pane["row_count"], json!(1));
        let row = &pane["rows"][0];
        assert_eq!(row["unilateral"], json!(true));
        // A lone half carries no body: payload stays small, nothing to compare.
        assert_eq!(row["mine"].get("record"), None);
        assert_eq!(row["theirs"]["state"], json!(STATE_ABSENT));
        assert_eq!(row["digest_match"]["state"], json!(STATE_ABSENT));
    }

    /// The provenance rule: a self-sealed sibling (this node minted BOTH
    /// halves; NEITHER capsule_id has a `received-provenance.jsonl` line) never
    /// closes, even with a matching request_digest -- the two halves fold into
    /// one row (both are `mine`), `theirs` stays absent, `unilateral: true`.
    /// Correlation feeds the gate; it never bypasses it.
    #[test]
    fn pane_c_self_sealed_sibling_never_closes_even_when_digests_match() {
        let half_a = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let half_b = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-82777e20",
        );
        // No provenance for EITHER capsule_id -> neither is a counterparty half.
        let pane = build_pane_c_list(&[half_a, half_b], &no_provenance());
        assert_eq!(pane["row_count"], json!(1)); // correlated into one row...
        let row = &pane["rows"][0];
        assert_eq!(row["unilateral"], json!(true)); // ...but never closed: no `theirs`.
        assert_eq!(row["theirs"]["state"], json!(STATE_ABSENT));
    }

    /// The provenance rule, no-provenance variant: a genuine cross-node sibling
    /// whose capsule_id carries NO provenance line (self-declared present in the
    /// ledger but never granted the triple at the door) is treated as `mine`,
    /// so the row stays unilateral/OPEN -- the gate has nothing to close on.
    #[test]
    fn pane_c_sibling_without_a_provenance_line_never_fills_theirs() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m3-82777e20",
        );
        // Provenance map is empty -> `foreign` is not a received counterparty
        // half, even though it is a real cross-node served half.
        let pane = build_pane_c_list(&[local, foreign], &no_provenance());
        assert_eq!(pane["row_count"], json!(1));
        let row = &pane["rows"][0];
        assert_eq!(row["unilateral"], json!(true));
        assert_eq!(row["theirs"]["state"], json!(STATE_ABSENT));
    }

    /// A correlated pair whose digests DIFFER renders CONTRADICTED: the
    /// structural `digest_match` is `failed` (one byte off on the
    /// response_digest), which the ONE gate turns into CONTRADICTED. The pair
    /// is still ONE row with `theirs` filled (`unilateral: false`) -- a real
    /// disagreement between two present halves, never a missing-half OPEN.
    /// MUTANT: soften `digest_match_state`'s `any_failed` rule (average a
    /// mismatch into `verified`) and this goes red.
    #[test]
    fn pane_c_correlated_pair_with_differing_digests_is_contradicted() {
        let local = mesh_half(
            "a".repeat(64).as_str(),
            "requested",
            "d".repeat(64).as_str(),
            "e".repeat(64).as_str(),
            "m4-914b61c1",
        );
        // Same request_digest (correlates), DIFFERENT response_digest.
        let foreign = mesh_half(
            "b".repeat(64).as_str(),
            "served",
            "d".repeat(64).as_str(),
            "f".repeat(64).as_str(),
            "m3-82777e20",
        );
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("b".repeat(64).as_str(), "m3")]
                .into_iter()
                .collect();

        let pane = build_pane_c_list(&[local, foreign], &provenance);

        assert_eq!(pane["row_count"], json!(1));
        let row = &pane["rows"][0];
        assert_eq!(row["unilateral"], json!(false)); // both halves present...
        assert_eq!(row["digest_match"]["state"], json!(STATE_FAILED)); // ...but they disagree.
    }

    /// A minimal CITING record our
    /// own chained record citing `cited` by CPB typed digest with
    /// `citation_purpose == "counterparty_half"`, carrying the receiving facts in
    /// `compute_attestation.received_half`. The record kind is defined by the
    /// citation purpose, NOT by the `chain.relation` string (AAC-05); the
    /// relation here reads `follows` -- the citing record is still identified
    /// solely by its `counterparty_half` reference.
    fn citing_fixture(cited: &str, received_from: &str, signature_ok: bool) -> Value {
        json!({
            "capsule_id": format!("cite-of-{cited}"),
            "timestamp": "2026-09-25T00:00:02Z",
            "chain": { "parent_capsule_id": "head", "relation": "follows" },
            "references": [{
                "type": "capsule", "digest_alg": "SHA-256", "digest": cited,
                "citation_purpose": "counterparty_half",
            }],
            "model_attestation": { "compute_attestation": { "received_half": {
                "cited_capsule_id": cited,
                "received_from": received_from,
                "via": "push",
                "received_at": "2026-09-25T00:00:01Z",
                "signature_ok": signature_ok,
            }}},
        })
    }

    /// `received_half_provenance` enforces the provenance rule off OUR OWN
    /// citing record: only a `received_half` with a non-empty `received_from`
    /// AND `signature_ok: true` yields a verified counterparty half. A
    /// `signature_ok: false`, or an empty/absent `received_from`, is refused --
    /// never a fabricated counterparty half.
    #[test]
    fn received_half_provenance_keeps_only_signature_ok_citing_records() {
        let good = citing_fixture("good", "m3", true);
        let prov = received_half_provenance(&good).expect("verified half");
        assert_eq!(prov.received_from, "m3");
        assert!(prov.signature_ok);
        assert_eq!(prov.via, "push");

        assert!(received_half_provenance(&citing_fixture("bad", "m3", false)).is_none());
        assert!(received_half_provenance(&citing_fixture("empty", "", true)).is_none());
        // A plain served record (no received_half) is never a counterparty half.
        let served = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        assert!(received_half_provenance(&served).is_none());
    }

    /// `is_citing_record` recognizes a record by its `citation_purpose ==
    /// "counterparty_half"` reference ALONE, never by the `chain.relation` string
    /// (AAC-05). The `citing_fixture` carries `relation: "follows"` and is still
    /// recognized; a record with `relation: "cites"` but NO counterparty_half
    /// reference is NOT a citing record; a served record is not either.
    #[test]
    fn is_citing_record_recognizes_the_counterparty_half_citation() {
        // Recognized by citation_purpose, though its relation reads "follows".
        let follows_citing = citing_fixture("x", "m3", true);
        assert_eq!(
            follows_citing.pointer("/chain/relation").unwrap(),
            &json!("follows")
        );
        assert!(is_citing_record(&follows_citing));

        // A record whose relation reads "cites" but carries NO counterparty_half
        // reference is NOT identified as a citing record: the relation string is
        // not the key.
        let mut cites_no_ref = fixture_record("cap-9", "2026-09-01T00:00:00Z", "req-9", None);
        cites_no_ref["chain"] = json!({ "parent_capsule_id": "head", "relation": "cites" });
        assert!(!is_citing_record(&cites_no_ref));

        let served = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        assert!(!is_citing_record(&served));
    }

    /// A routing-choice record is ours (Pane A) and never an exchange half
    /// (Pane B/C), so blocking a peer never adds a row to Peers or Exchanges.
    #[test]
    fn routing_choice_records_are_ours_but_never_exchanges() {
        let dir = tempfile::tempdir().unwrap();
        let local = fixture_record("local-1", "2026-09-01T00:00:00Z", "req-1", None);
        let choice = json!({
            "capsule_id": "choice-1",
            "timestamp": "2026-09-27T00:00:00Z",
            "model_attestation": {"compute_attestation": {"local_routing_choice": {
                "change": "block",
                "peer_commitment": {"alg": "SHA-256", "digest": "d".repeat(64)},
                "reason": "your_choice",
                "until": null,
                "scope": "this_node_only"
            }}}
        });
        assert!(is_local_routing_choice(&choice));
        assert!(!is_local_routing_choice(&local));
        std::fs::write(
            dir.path().join("capsules.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&local).unwrap(),
                serde_json::to_string(&choice).unwrap()
            ),
        )
        .unwrap();

        let el = effective_ledger(dir.path());
        let ids = |v: &[Value]| -> Vec<String> {
            v.iter()
                .map(|r| r["capsule_id"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(ids(&el.pane_bc_records), vec!["local-1".to_string()]);
        assert_eq!(
            ids(&el.our_records),
            vec!["local-1".to_string(), "choice-1".to_string()]
        );
    }

    /// The held-artifact store reader: reads `received-capsules.jsonl` by
    /// `capsule_id`; a missing file is an empty map, no panic.
    #[test]
    fn read_received_capsules_reads_bodies_by_capsule_id_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_received_capsules(dir.path()).is_empty());

        std::fs::write(
            dir.path().join("received-capsules.jsonl"),
            "{\"capsule_id\":\"foreign-1\",\"effect\":{\"request_digest\":\"aa\"}}\n\
             {\"capsule_id\":\"foreign-2\"}\n",
        )
        .unwrap();
        let map = read_received_capsules(dir.path());
        assert_eq!(map.len(), 2);
        assert_eq!(map["foreign-1"]["effect"]["request_digest"], json!("aa"));
        assert!(map.contains_key("foreign-2"));
    }

    /// End-to-end assembly:
    /// `effective_ledger` reads capsules.jsonl (a local served half + a citing
    /// record) + received-capsules.jsonl (the foreign body), and produces:
    /// pane_bc_records = local + foreign (NOT the citing record); our_records =
    /// local + citing (NOT the foreign body); received_provenance keyed by the
    /// FOREIGN capsule_id.
    #[test]
    fn effective_ledger_splits_local_citing_and_foreign_from_the_three_sources() {
        let dir = tempfile::tempdir().unwrap();
        // capsules.jsonl: one local served half + one citing record.
        let local = fixture_record("local-1", "2026-09-01T00:00:00Z", "req-1", None);
        let citing = citing_fixture("foreign-1", "m4", true);
        std::fs::write(
            dir.path().join("capsules.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&local).unwrap(),
                serde_json::to_string(&citing).unwrap()
            ),
        )
        .unwrap();
        // The foreign body lives ONLY in the held-artifact store.
        let foreign = fixture_record("foreign-1", "2026-09-01T00:00:05Z", "req-1", None);
        std::fs::write(
            dir.path().join("received-capsules.jsonl"),
            format!("{}\n", serde_json::to_string(&foreign).unwrap()),
        )
        .unwrap();

        let el = effective_ledger(dir.path());
        let ids = |v: &[Value]| -> Vec<String> {
            v.iter()
                .map(|r| r["capsule_id"].as_str().unwrap().to_string())
                .collect()
        };
        let bc = ids(&el.pane_bc_records);
        assert!(bc.contains(&"local-1".to_string()));
        assert!(bc.contains(&"foreign-1".to_string()));
        assert!(
            !bc.iter().any(|id| id.starts_with("cite-of-")),
            "no citing record in pane B/C set"
        );

        let ours = ids(&el.our_records);
        assert!(ours.contains(&"local-1".to_string()));
        assert!(
            ours.iter().any(|id| id == "cite-of-foreign-1"),
            "citing record is ours"
        );
        assert!(
            !ours.contains(&"foreign-1".to_string()),
            "foreign body is NOT ours"
        );

        // Provenance keyed by the FOREIGN capsule_id, off the citing record.
        assert!(el.received_provenance.contains_key("foreign-1"));
        assert_eq!(el.received_provenance["foreign-1"].received_from, "m4");
    }

    /// A missing artifact store means a citing record cannot resolve its
    /// foreign body: the row stays honest (no counterparty half re-enters the
    /// working set), never a fabricated one.
    #[test]
    fn citing_record_with_no_resolvable_artifact_adds_no_counterparty_half() {
        let dir = tempfile::tempdir().unwrap();
        let citing = citing_fixture("foreign-gone", "m4", true);
        std::fs::write(
            dir.path().join("capsules.jsonl"),
            format!("{}\n", serde_json::to_string(&citing).unwrap()),
        )
        .unwrap();
        // No received-capsules.jsonl at all.
        let el = effective_ledger(dir.path());
        assert!(
            el.received_provenance.is_empty(),
            "no artifact -> no counterparty half"
        );
        assert!(
            el.pane_bc_records.is_empty(),
            "no local half, no resolved foreign body"
        );
    }

    #[test]
    fn pane_c_drilldown_finds_by_exchange_key_and_reports_not_found_honestly() {
        let records = vec![fixture_record(
            "cap-1",
            "2026-09-01T00:00:00Z",
            "req-1",
            None,
        )];
        let found = build_pane_c_drilldown(&records, &HashMap::new(), "digest:req-1");
        assert_eq!(found["found"], json!(true));
        assert_eq!(found["view"]["capsule_id"], json!("cap-1"));

        let not_found = build_pane_c_drilldown(&records, &HashMap::new(), "digest:nonexistent");
        assert_eq!(not_found["found"], json!(false));
        assert!(not_found.get("view").is_none());
    }

    #[test]
    fn label_role_defaults_a_plugin_written_record_to_served() {
        let record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        assert_eq!(label_role(&record), "served");
        assert_eq!(role_tag(&record), "SERVED");
    }

    #[test]
    fn label_role_trusts_an_explicit_poc_role_over_the_default() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] =
            json!({ "role": "requested" });
        assert_eq!(label_role(&record), "requested");
        assert_eq!(role_tag(&record), "ASKED");
    }

    /// The digest is the correlator that survives a cross-node exchange, so
    /// it is preferred over the host-minted `exchange_id` whenever a record
    /// carries one (see `exchange_key_for`'s doc + `served_request_join.py`'s
    /// CORRELATION FALLBACK). A record with BOTH keys groups by digest.
    #[test]
    fn exchange_key_for_prefers_request_digest_over_host_minted_exchange_id() {
        let mut record = fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None);
        record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] =
            json!({ "serving_provenance": { "exchange_id": "exch-real" } });
        assert_eq!(exchange_key_for(&record).as_deref(), Some("digest:req-1"));
    }

    /// A record with no `request_digest` at all (e.g. a plugin-served stub
    /// with no digested body) falls back to the host-minted `exchange_id`.
    #[test]
    fn exchange_key_for_falls_back_to_exchange_id_when_no_request_digest() {
        let record = json!({
            "capsule_id": "cap-1",
            "timestamp": "2026-09-01T00:00:00Z",
            "model_attestation": { "compute_attestation": {
                "x-mesh-poc-v1": { "serving_provenance": { "exchange_id": "exch-real" } }
            } },
        });
        // No `effect.request_digest` on this record.
        assert!(record.pointer("/effect/request_digest").is_none());
        assert_eq!(exchange_key_for(&record).as_deref(), Some("exch-real"));
    }

    /// the empirical CLOSED-tour finding:
    /// two cross-node halves of ONE real exchange carry DIFFERENT host-minted
    /// `exchange_id`s (M4 vs M3) but the SAME `request_digest` (each host
    /// digested the same wire bytes). They MUST group into one exchange, not
    /// two OPEN rows. MUTANT: revert `exchange_key_for` to exchange_id-first
    /// and this row_count goes from 1 to 2.
    #[test]
    fn pane_c_groups_two_cross_node_halves_with_differing_exchange_ids_as_one_exchange() {
        // Requester half (M4): role requested, its own host-minted exchange_id.
        let mut requester =
            fixture_record("cap-m4", "2026-09-25T00:00:00Z", "shared-req-digest", None);
        requester["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "role": "requested",
            "serving_provenance": { "exchange_id": "914b61c1", "role": "requester" }
        });
        // Provider half (M3, pushed into M4's ledger): a DIFFERENT host-minted
        // exchange_id, the SAME request_digest.
        let mut provider =
            fixture_record("cap-m3", "2026-09-25T00:00:01Z", "shared-req-digest", None);
        provider["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] = json!({
            "role": "served",
            "serving_provenance": { "exchange_id": "82777e20", "role": "provider" }
        });

        let both = vec![requester.clone(), provider.clone()];
        // Both records share the digest key -> one exchange group.
        assert_eq!(exchange_key_for(&requester), exchange_key_for(&provider));
        assert_eq!(
            exchange_key_for(&requester).as_deref(),
            Some("digest:shared-req-digest")
        );

        // The drilldown groups both halves under the one shared key -- the
        // CLOSED-eligible pair the reconcile must produce, not two OPEN rows.
        let pane = build_pane_c_drilldown(&both, &HashMap::new(), "digest:shared-req-digest");
        assert_eq!(pane["found"], json!(true));

        // And a CONFLICTING pair (equal host-minted exchange_id, DIFFERENT
        // request_digest) stays SPLIT -- distinct digest keys keep two
        // different requests apart, matching served_request_join.py's refusal.
        let mut conflict_a = fixture_record("cap-a", "2026-09-25T00:00:00Z", "digest-a", None);
        conflict_a["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] =
            json!({ "serving_provenance": { "exchange_id": "same-id" } });
        let mut conflict_b = fixture_record("cap-b", "2026-09-25T00:00:01Z", "digest-b", None);
        conflict_b["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"] =
            json!({ "serving_provenance": { "exchange_id": "same-id" } });
        assert_ne!(exchange_key_for(&conflict_a), exchange_key_for(&conflict_b));
    }

    fn padding_line(n: usize) -> Value {
        json!({
            "capsule_id": format!("{n:064x}"),
            "record_type": "padding",
            "epistemic_type": "producer_claim",
            "store_nonce": format!("{:064x}", n + 1_000),
        })
    }

    /// Padding records are leaves, never records: no pane counts or lists one,
    /// and a checkpoint over a padded ledger reports what it covers in records
    /// while its leaf count still covers the padding.
    #[test]
    fn padding_is_never_counted_or_listed_and_is_still_covered() {
        let dir = tempfile::tempdir().unwrap();
        // Two real records, then 6 padding lines up to a checkpoint over all 8
        // leaves, then one real record sealed after the checkpoint.
        let mut lines = vec![
            fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None),
            fixture_record("cap-2", "2026-09-01T00:01:00Z", "req-2", Some("cap-1")),
        ];
        lines.extend((0..6).map(padding_line));
        lines.push(fixture_record(
            "cap-3",
            "2026-09-01T00:02:00Z",
            "req-3",
            Some("cap-2"),
        ));
        write_fixture_ledger(dir.path(), &lines);
        std::fs::write(
            dir.path().join("checkpoints.jsonl"),
            "{\"kind\":\"mmr_checkpoint\",\"mmr_size\":15,\"root\":\"aa\",\"timestamp\":\"2026-09-01T00:01:30Z\",\"witnesses\":[]}\n",
        )
        .unwrap();

        let pane_a = build_pane_json("pane-a", dir.path(), None).unwrap();
        let ids: Vec<&str> = pane_a["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["capsule_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["cap-1", "cap-2", "cap-3"],
            "Pane A lists records only"
        );
        // The checkpoint's own fact: 15 nodes = 8 leaves, padding included.
        assert_eq!(pane_a["card"]["covered_leaf_count"], json!(8));
        // In records it covers the two before it, not cap-3 after it.
        assert_eq!(pane_a["card"]["covered_record_count"], json!(2));

        let pane_c = build_pane_json("pane-c", dir.path(), None).unwrap();
        assert_eq!(
            pane_c["rows"].as_array().unwrap().len(),
            3,
            "Exchanges list records only"
        );
        let pane_b = build_pane_json("pane-b", dir.path(), None).unwrap();
        assert!(!serde_json::to_string(&pane_b).unwrap().contains("padding"));
        assert_eq!(read_capsule_records(dir.path()).len(), 3);
        assert_eq!(
            read_ledger_lines(dir.path()).len(),
            9,
            "the ledger itself keeps every leaf"
        );
    }

    #[test]
    fn build_pane_json_reads_a_real_fixture_ledger_directory() {
        let dir = std::env::temp_dir().join("mesh-c3-fixture-ledger-test");
        let records = vec![fixture_record(
            "cap-1",
            "2026-09-01T00:00:00Z",
            "req-1",
            None,
        )];
        write_fixture_ledger(&dir, &records);

        let pane_a = build_pane_json("pane-a", &dir, None).unwrap();
        assert_eq!(pane_a["rows"][0]["capsule_id"], json!("cap-1"));

        let pane_c = build_pane_json("pane-c", &dir, Some("digest:req-1")).unwrap();
        assert_eq!(pane_c["found"], json!(true));

        assert!(build_pane_json("pane-z", &dir, None).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE NEW-SHAPE END-TO-END:
    /// `capsules.jsonl` holds this node's own requester half + a CITING record
    /// (never the foreign body); `received-capsules.jsonl` holds the foreign
    /// SERVED body the citing record references. Driving `build_pane_json`:
    ///   (a) Pane C shows ONE CLOSED-capable row -- `theirs` filled from the
    ///       resolved foreign body, `signature_ok: true` (off the citing
    ///       record), `digest_match: verified` (mine vs the resolved foreign
    ///       half). The ONE gate (`deriveRightCellState`) renders CLOSED.
    ///   (b) Pane B attributes the confirmed sibling to the PEER row -- the
    ///       peer identity now comes from the citing record's `received_from`
    ///       (cc8ff9967's intent preserved), never the null group.
    ///   (c) Pane A lists our own records including the citing record, marked
    ///       `kind: counterparty_half_citation` (not a served action), and NOT
    ///       the foreign body.
    #[test]
    fn new_shape_closes_via_citing_record_and_held_artifact() {
        let dir = std::env::temp_dir().join(format!("mesh-cite-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let req_digest = "d".repeat(64);
        let resp_digest = "e".repeat(64);
        // Our own requester half (this node asked a peer).
        let local = mesh_half(
            &"a".repeat(64),
            "requested",
            &req_digest,
            &resp_digest,
            "m4-914b61c1",
        );
        // The foreign SERVED body -- lives ONLY in the held-artifact store.
        let foreign = mesh_half(
            &"b".repeat(64),
            "served",
            &req_digest,
            &resp_digest,
            "m3-82777e20",
        );
        // Our CITING record of receiving the foreign half (identified by its
        // counterparty_half citation, received_from the pushing peer m3).
        let citing = citing_fixture(&"b".repeat(64), "m3", true);

        std::fs::write(
            dir.join("capsules.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&local).unwrap(),
                serde_json::to_string(&citing).unwrap()
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("received-capsules.jsonl"),
            format!("{}\n", serde_json::to_string(&foreign).unwrap()),
        )
        .unwrap();

        // (a) Pane C: one row, theirs filled from the resolved foreign body,
        //     signature_ok + digest_match verified -> CLOSED-capable.
        let pane_c = build_pane_json("pane-c", &dir, None).unwrap();
        assert_eq!(
            pane_c["row_count"],
            json!(1),
            "one reconciled row, not two OPEN halves"
        );
        let row = &pane_c["rows"][0];
        assert_eq!(row["mine"]["capsule_id"], json!("a".repeat(64)));
        assert_eq!(row["theirs"]["capsule_id"], json!("b".repeat(64)));
        assert_eq!(row["unilateral"], json!(false));
        assert_eq!(row["digest_match"]["state"], json!(STATE_VERIFIED));
        assert_eq!(row["theirs"]["signature_ok"], json!(true));
        assert_eq!(row["theirs"]["received_from"], json!("m3"));

        // (b) Pane B: the confirmed sibling attributes to the peer row via the
        //     citing record's received_from (m3), never the null group.
        let pane_b = build_pane_json("pane-b", &dir, None).unwrap();
        let rows = pane_b["rows"].as_array().unwrap();
        let peer_row = rows
            .iter()
            .find(|r| {
                r["confirmed_siblings"]
                    .as_array()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            })
            .expect("a peer row carries the confirmed sibling");
        assert_eq!(
            peer_row["peer_id"],
            json!("node:m3"),
            "attributed to the pushing peer m3"
        );
        let confirmed = peer_row["confirmed_siblings"][0].clone();
        assert_eq!(confirmed["theirs"]["signature_ok"], json!(true));
        assert_eq!(confirmed["digest_match"]["state"], json!(STATE_VERIFIED));

        // (c) Pane A: our own records incl. the citing record (marked, not a
        //     served action), never the foreign body.
        let pane_a = build_pane_json("pane-a", &dir, None).unwrap();
        let a_rows = pane_a["rows"].as_array().unwrap();
        let a_ids: Vec<&str> = a_rows
            .iter()
            .map(|r| r["capsule_id"].as_str().unwrap())
            .collect();
        assert!(
            a_ids.contains(&"a".repeat(64).as_str()),
            "our own requester half is ours"
        );
        assert!(
            a_ids.iter().any(|id| id.starts_with("cite-of-")),
            "the citing record is ours"
        );
        assert!(
            !a_ids.contains(&"b".repeat(64).as_str()),
            "the foreign body is NOT one of our records"
        );
        let cite_row = a_rows
            .iter()
            .find(|r| r["capsule_id"].as_str().unwrap().starts_with("cite-of-"))
            .unwrap();
        assert_eq!(cite_row["kind"], json!("counterparty_half_citation"));
        assert_eq!(
            cite_row["model_claimed"],
            Value::Null,
            "a citing record is never a served model"
        );
        assert_eq!(
            cite_row["rungs"]["cross_party"]["state"],
            json!(CELL_PRESENT)
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -----------------------------------------------------------------
    // Retired vocabulary gate -- same
    // discipline as capsule-emit-mesh's `f0e3af6` Pane C gate
    // (`tests/test_accountability_pane_routes.py`'s
    // `_assert_no_retired_vocabulary`), ported to this reader's own
    // fixtures since it's the surface that actually emits raw JSON
    // strangers can read (native/sidecar-DOWN is the demo's real path).
    // -----------------------------------------------------------------

    const RETIRED_PANE_VOCABULARY: &[&str] = &["rung", "unilateral_fallback"];

    /// Whole-word containment: `haystack` carries `word` as a standalone
    /// token (its own key/segment, or delimited by `_`/`-` on both sides),
    /// never a mere substring. Distinguishes the retired `rung` ladder
    /// token from `rungs` -- the current, sanctioned plural container name
    /// for a row's five checks (see this module's own doc comment,
    /// "the Pane-A rungs' structural defaults") -- which contains `rung`
    /// as a substring but is not a reappearance of the retired vocabulary.
    fn contains_retired_word(haystack: &str, word: &str) -> bool {
        haystack.split(['_', '-']).any(|segment| segment == word)
    }

    /// Pins the exact boundary this gate depends on: `rungs` (the current,
    /// sanctioned container key) must never trip the retired-word check
    /// that `rung` (the actual retired token, alone or `_`/`-` delimited)
    /// must always trip. Before this fix, a plain `.contains("rung")`
    /// substring check made `pane_a_json_never_carries_retired_rung_vocabulary`
    /// fail unconditionally the moment `build_pane_a` emitted its own
    /// `"rungs"` key -- MUTANT: reverting `contains_retired_word` to
    /// `haystack.contains(word)` turns this red on the `"rungs"` case.
    #[test]
    fn contains_retired_word_distinguishes_rungs_from_the_retired_rung_token() {
        assert!(
            !contains_retired_word("rungs", "rung"),
            "current, sanctioned plural key must not match"
        );
        assert!(
            contains_retired_word("rung", "rung"),
            "the exact retired token must still match"
        );
        assert!(
            contains_retired_word("rung_state", "rung"),
            "an underscore-delimited retired token must still match"
        );
        assert!(
            contains_retired_word("cross_party_rung", "rung"),
            "a trailing underscore-delimited retired token must still match"
        );
        assert!(
            !contains_retired_word("unilateral_fallbacks", "unilateral_fallback"),
            "a hypothetical pluralized current key must not match either"
        );
    }

    fn assert_no_retired_vocabulary(value: &Value, path: &str) {
        match value {
            Value::Object(map) => {
                for (key, sub) in map {
                    let lowered_key = key.to_lowercase();
                    for word in RETIRED_PANE_VOCABULARY {
                        assert!(
                            !contains_retired_word(&lowered_key, word),
                            "{path}.{key} carries retired vocabulary {word:?}"
                        );
                    }
                    assert_no_retired_vocabulary(sub, &format!("{path}.{key}"));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_retired_vocabulary(item, &format!("{path}[{index}]"));
                }
            }
            Value::String(text) => {
                let lowered = text.to_lowercase();
                for word in RETIRED_PANE_VOCABULARY {
                    assert!(
                        !lowered.contains(word),
                        "{path} carries retired vocabulary {word:?}: {text:?}"
                    );
                }
            }
            _ => {}
        }
    }

    /// The seeded record here has no cross-party evidence -- exactly the
    /// shape that used to grade `unilateral_fallback` -- so this fixture is
    /// a real mutant catch, not a vacuous pass.
    #[test]
    fn pane_a_json_never_carries_retired_rung_vocabulary() {
        let records = vec![fixture_record(
            "cap-1",
            "2026-09-01T00:00:00Z",
            "req-1",
            None,
        )];
        assert_no_retired_vocabulary(
            &build_pane_a(&records, json!({ "checkpoint_count": 0 })),
            "$",
        );
    }

    /// Integrity checkpoint wiring: `build_pane_a`
    /// hardcoded `card: null`, so a real on-disk checkpoint never reached the
    /// Integrity view (which reads `card.checkpoint_count`). The card must now
    /// report the honest count from `<ledger_dir>/checkpoints.jsonl` -- 0 when
    /// absent (rendered "no checkpoint yet", never fabricated), the real count
    /// + latest registration time when present.
    #[test]
    fn pane_a_card_reports_real_checkpoints_and_honest_zero_when_absent() {
        // Absent file -> honest zero, no registration timestamp.
        let empty = tempfile::tempdir().unwrap();
        let zero = read_checkpoint_card(empty.path());
        assert_eq!(zero["checkpoint_count"], json!(0));
        assert!(zero.get("registered_no_later_than").is_none());
        // The pane threads the honest zero through, so the UI reads "no
        // checkpoint yet" -- a real mutant catch: reverting to `card: null`
        // would make `pane["card"]["checkpoint_count"]` null, not 0.
        assert_eq!(
            build_pane_a(&[], zero)["card"]["checkpoint_count"],
            json!(0)
        );

        // Two real checkpoint lines -> count 2 + the LATEST timestamp + its
        // witnesses (the on-disk shape written by the cadence).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("checkpoints.jsonl"),
            "{\"kind\":\"mmr_checkpoint\",\"mmr_size\":3,\"root\":\"aa\",\"timestamp\":\"2026-09-03T07:23:31Z\",\"witnesses\":[]}\n\
             {\"kind\":\"mmr_checkpoint\",\"mmr_size\":7,\"root\":\"bb\",\"timestamp\":\"2026-09-03T07:28:00Z\",\"witnesses\":[{\"ts_url\":\"https://witness.example\"}]}\n",
        )
        .unwrap();
        let card = read_checkpoint_card(dir.path());
        assert_eq!(card["checkpoint_count"], json!(2));
        assert_eq!(
            card["registered_no_later_than"],
            json!("2026-09-03T07:28:00Z")
        );
        assert_eq!(card["latest_root"], json!("bb"));
        assert_eq!(card["latest_mmr_size"], json!(7));
        // The covered-LEAF count is inverted from the latest mmr_size (7 nodes ->
        // 4 leaves), NOT `checkpoint_count` (2). This is the field the chain strip
        // caption reads.
        assert_eq!(card["covered_leaf_count"], json!(4));
        assert_eq!(card["witnesses"].as_array().unwrap().len(), 1);
        assert_eq!(
            build_pane_a(&[], card)["card"]["checkpoint_count"],
            json!(2)
        );
    }

    /// `mmr_leaf_count` inverts an MMR total-node count back to its leaf count
    /// via `mmr_size == 2*L - popcount(L)`. The task's worked example (node
    /// count 15 -> 8 leaves) and the boundary/round-trip cases: every leaf count
    /// L maps to a node count that inverts back to exactly L, node count 0 is 0
    /// leaves, and a node count no MMR produces (e.g. 2) has no inverse.
    #[test]
    fn mmr_leaf_count_inverts_node_count_to_leaf_count() {
        // The task's worked example.
        assert_eq!(mmr_leaf_count(15), Some(8));
        // Spot cases: 1->1, 4->3, 11->7 (and the empty MMR).
        assert_eq!(mmr_leaf_count(0), Some(0));
        assert_eq!(mmr_leaf_count(1), Some(1));
        assert_eq!(mmr_leaf_count(4), Some(3));
        assert_eq!(mmr_leaf_count(11), Some(7));
        // A node count that no MMR yields (2 leaves -> 3 nodes; 1 leaf -> 1 node;
        // nothing produces 2) has no inverse -- never a fabricated leaf count.
        assert_eq!(mmr_leaf_count(2), None);
        // Round-trip every leaf count in a wide range through the forward
        // relation and back.
        for leaves in 1u64..=5000 {
            let nodes = 2 * leaves - u64::from(leaves.count_ones());
            assert_eq!(
                mmr_leaf_count(nodes),
                Some(leaves),
                "round-trip failed for {leaves} leaves"
            );
        }
    }

    /// The card prefers a leaf count the checkpoint line carries directly
    /// (`covered_leaf_count`, then `leaf_count`) over inverting `mmr_size` --
    /// so a plugin that records the covered-leaf count need not have it re-derived.
    #[test]
    fn checkpoint_card_prefers_a_carried_leaf_count_over_inverting_mmr_size() {
        let dir = tempfile::tempdir().unwrap();
        // mmr_size 15 would invert to 8, but the line carries 6 directly.
        std::fs::write(
            dir.path().join("checkpoints.jsonl"),
            "{\"kind\":\"mmr_checkpoint\",\"mmr_size\":15,\"covered_leaf_count\":6,\"root\":\"aa\",\"timestamp\":\"2026-09-03T07:23:31Z\",\"witnesses\":[]}\n",
        )
        .unwrap();
        let card = read_checkpoint_card(dir.path());
        assert_eq!(card["covered_leaf_count"], json!(6));
        assert_eq!(card["latest_mmr_size"], json!(15));
    }

    #[test]
    fn pane_b_json_never_carries_retired_rung_vocabulary() {
        let records = vec![
            fixture_record("cap-1", "2026-09-01T00:00:00Z", "req-1", None),
            fixture_record("cap-2", "2026-09-02T00:00:00Z", "req-2", Some("cap-1")),
        ];
        assert_no_retired_vocabulary(&build_pane_b(&records, &no_provenance()), "$");
    }

    /// The same prompt asked twice gives two exchanges with ONE request digest,
    /// across two nodes. Our two records answer differently
    /// (`1…`, `2…`); the peer's pushed half is request 2's. Pairing it with
    /// every own record under the key compared request 1 against it and
    /// rendered a false CONTRADICTED. One-to-one: two rows, request 2 closes,
    /// request 1 stays open, nothing fails.
    fn same_prompt_twice() -> (Vec<Value>, HashMap<String, ReceivedProvenance>) {
        let d = "d".repeat(64);
        let records = vec![
            mesh_half("mine-1", "requested", &d, &"1".repeat(64), "m4-first"),
            mesh_half("mine-2", "requested", &d, &"2".repeat(64), "m4-second"),
            mesh_half("theirs-2", "served", &d, &"2".repeat(64), "m3-second"),
        ];
        let provenance = [provenance_for("theirs-2", "m3")].into_iter().collect();
        (records, provenance)
    }

    #[test]
    fn pane_c_same_digest_requests_pair_one_to_one_not_contradicted() {
        let (records, provenance) = same_prompt_twice();
        let pane = build_pane_c_list(&records, &provenance);
        let rows = pane["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "two exchanges, never merged into one row");
        let d = format!("digest:{}", "d".repeat(64));
        assert_eq!(rows[0]["exchange_key"], json!(d));
        assert_eq!(rows[0]["mine"]["capsule_id"], json!("mine-1"));
        assert_eq!(rows[0]["unilateral"], json!(true));
        assert_eq!(rows[0]["digest_match"]["state"], json!(STATE_ABSENT));
        assert_eq!(rows[1]["exchange_key"], json!(format!("{d}#2")));
        assert_eq!(rows[1]["mine"]["record"]["capsule_id"], json!("mine-2"));
        assert_eq!(rows[1]["digest_match"]["state"], json!(STATE_VERIFIED));
        assert!(rows
            .iter()
            .all(|r| r["digest_match"]["state"] != json!(STATE_FAILED)));

        let drill = build_pane_c_drilldown(&records, &provenance, &format!("{d}#2"));
        assert_eq!(drill["found"], json!(true));
        assert_eq!(drill["view"]["capsule_id"], json!("mine-2"));
        let past_the_end = build_pane_c_drilldown(&records, &provenance, &format!("{d}#3"));
        assert_eq!(past_the_end["found"], json!(false));
    }

    #[test]
    fn pane_b_same_digest_requests_confirm_one_and_count_two() {
        let (records, provenance) = same_prompt_twice();
        assert_eq!(distinct_exchange_count(&records, &provenance), 2);
        let pane = build_pane_b(&records, &provenance);
        let siblings: Vec<Value> = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| {
                r["confirmed_siblings"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(siblings.len(), 1, "the half closes ONE of our records");
        assert_eq!(siblings[0]["digest_match"]["state"], json!(STATE_VERIFIED));
        assert_eq!(siblings[0]["mine"]["record"]["capsule_id"], json!("mine-2"));
    }

    /// One-to-one never hides a real disagreement: a pushed half whose answer
    /// matches none of our records under the key is still set against one of
    /// them and fails, so the gate still renders CONTRADICTED.
    #[test]
    fn a_half_matching_none_of_our_records_still_fails() {
        let d = "d".repeat(64);
        let records = vec![
            mesh_half("mine-1", "requested", &d, &"1".repeat(64), "m4-first"),
            mesh_half("theirs-x", "served", &d, &"9".repeat(64), "m3-x"),
        ];
        let provenance: HashMap<String, ReceivedProvenance> =
            [provenance_for("theirs-x", "m3")].into_iter().collect();
        let pane = build_pane_c_list(&records, &provenance);
        let rows = pane["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["digest_match"]["state"], json!(STATE_FAILED));
        assert_eq!(distinct_exchange_count(&records, &provenance), 1);
    }
}
