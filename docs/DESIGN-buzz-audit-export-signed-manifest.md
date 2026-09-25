<!-- SPDX-License-Identifier: Apache-2.0 -->
# Signed export manifest for Buzz's community audit chain — design for block/buzz#3228

> **Design only.** Nothing in this document changes code in this repo. It is written against
> `block/buzz` at `upstream/main` `6410e685a` (2026-09-25) — `crates/buzz-audit/src/{hash,service,
> action,entry}.rs`, `crates/buzz-admin/src/main.rs`, and issue
> [#3228](https://github.com/block/buzz/issues/3228) as filed. This design **originates here**,
> before any comment or PR reaches `block/buzz` — see `action-state-ops` `[a18-buzz-3228-signed-
> export-manifest]`, "the order is the boundary."

## 0. What #3228 already has, and the one gap it names

Buzz already runs a per-community, append-only SHA-256 hash chain
(`crates/buzz-audit/src/hash.rs::compute_hash`, `crates/buzz-audit/src/service.rs::AuditService`):
each `audit_log` row hashes `community_id ‖ seq ‖ created_at ‖ action ‖ actor_pubkey ‖ object_id ‖
canonical_json(detail) ‖ prev_hash`, and `verify_chain` walks a `[from_seq, to_seq]` range
recomputing every hash and checking the `prev_hash` links. `#3228` asks for a stable operator
export surface over `AuditService::get_entries`/`verify_chain` — pagination, a manifest with the
exported range and final chain hash, and integration tests for authorization/pagination/tenant
isolation/chain-corruption.

Its **Non-goals** section states the gap this design closes, in the issue's own words:

> Claiming that the keyless chain is tamper-resistant against an attacker with database write
> access; it is tamper-evident, and such an attacker could recompute the chain.

That is correct and precise. `compute_hash` has no secret input — an attacker with `UPDATE`/
`INSERT` on `audit_log` can rewrite any row, then recompute every downstream hash so
`verify_chain` passes over the *rewritten* chain. Detecting that requires a value the attacker
cannot derive from the database alone: a signature over an operator-held private key that never
lives in Postgres.

## 1. Threat model, stated the way the issue states its own

**In scope — what a signed manifest catches.** An attacker (or a compromised admin role, or a
bad `pg_restore`) obtains `INSERT`/`UPDATE`/`DELETE` on `audit_log` but **not** the operator's
export-signing private key (held only where the operator runs `buzz-admin`, never written to the
database). They rewrite one or more entries in `[from_seq, to_seq]` and recompute `hash`/
`prev_hash` forward so the chain is internally consistent again — `verify_chain` over the
rewritten rows returns `Ok(true)`. A community member or external auditor who saved an
**earlier, signed** manifest for that same range re-exports it later, or diffs the earlier
`final_hash` against a fresh export: the fresh chain now hashes differently but is still
internally valid, so the signature over the *old* `final_hash` no longer verifies against the
*new* export, and the person holding the old signed manifest can prove the range changed under
them. The signature does not run over the database; it runs over a value (`final_hash`) that a
DB-only attacker cannot reproduce without independently knowing what the *original* export said.

**Out of scope — what this does not claim.** (1) If the same compromise that reaches `audit_log`
also reaches the export-signing private key (e.g. both live on one unattended host), the attacker
can rewrite the chain *and* re-sign the rewritten manifest; key custody is an operational
concern for the deploying operator, not something this design can enforce from inside the
process. (2) A first-ever export of an already-tampered range is signed as though it were
genuine — signing proves "the exporter attested to this hash at this time," not "this chain was
never touched before the first export." Regular/scheduled exports narrow, but do not close, that
window. (3) Optional witness registration (§3) adds independent third-party freshness evidence
for *when* a manifest existed, which helps with (2) but is opt-in and never assumed. None of this
is new to Buzz — it is the same tamper-evident-vs-tamper-resistant distinction #3228 already
draws; a signed manifest turns "recompute the chain" from an attack that passes silently into one
that produces a detectable, dated mismatch for anyone holding a prior signed export.

## 2. The manifest: what's signed, and by whom

A JSON object, produced by the export command over exactly the community-scoped range it
returned, generated **in addition to** the JSONL entry stream — not a replacement for it:

```json
{
  "v": 1,
  "kind": "buzz_audit_export_manifest",
  "community_id": "b9f0822e-628c-49f2-a7b1-4c64305d54de",
  "from_seq": 1,
  "to_seq": 32,
  "entry_count": 32,
  "final_hash": "37416cc0c480a10cbb3dfc1d08f446e963f1c7742a18fceb6b07f9668d475cd",
  "exported_at": "2026-09-25T18:04:11Z",
  "exporter_key_id": "3b9a4e2f5c1d7a8e0f6b2c4d9e1a3f5b7c9d0e2f4a6b8c0d2e4f6a8b0c2d4e6f"
}
```

Field choices, and why each one is there:

- **`community_id`, `from_seq`, `to_seq`, `entry_count`** — the exported range, restated inside
  the signed object so the manifest is self-describing; a manifest handed to an auditor without
  the accompanying JSONL still states its own scope.
- **`final_hash`** — the `hash` field of the entry at `to_seq`, i.e. exactly the value
  `verify_chain` already treats as "the chain's state as of this point" (every earlier entry's
  hash is transitively committed through `prev_hash`). This is the one field #3228 names by name
  ("a small manifest containing the exported sequence range and final chain hash").
- **`exported_at`** — when the export ran, UTC ISO-8601. Establishes an ordering between exports
  of overlapping ranges; not a freshness proof on its own (see §1, out-of-scope item 2) — that is
  what optional witness registration adds.
- **`exporter_key_id`** — the raw 32-byte Ed25519 public key, hex-encoded, of the key that signs
  this manifest. Carried *inside* the signed body (same convention as `checkpointed-local-log`'s
  `cll.checkpoint.emit.CheckpointRecord.key_id`, see §3) so a verifier reconstructs the public key
  straight from the manifest with no separate lookup, and a manifest claiming one key cannot be
  silently re-labelled under another without invalidating its own signature.
- **No `signature` field inside the signed body.** Kept out-of-band (detached), covering
  exactly the object above — see §3.

`community_id` binds the manifest to one tenant the same way `compute_hash` binds every row to
one tenant (`hash.rs` line 29: "an entry cannot be lifted out of one community's chain and
re-verified inside another"). A manifest is meaningless outside the community it names, by the
same design choice already made for individual entries.

## 3. Signature: Ed25519, JCS-canonical bytes, detached

**Reuse, explicitly, from `checkpointed-local-log`'s `cll.checkpoint.emit` module**
(`cll/checkpoint/emit.py`, the Ed25519/COSE-track checkpoint — not `cll.ledger.checkpoint`'s
HMAC track, which is a different signer for a different consumer):

- **Signing-body construction**: deterministic JSON over every field except the signature itself
  — sorted keys, no extraneous whitespace (`json.dumps(body, sort_keys=True,
  separators=(",", ":"))` in Python; the Rust side uses `serde_json` with a `BTreeMap`-backed
  sort, matching the pattern `buzz-audit/src/hash.rs::canonical_json` already uses for the
  `detail` field of each entry — Buzz already owns exactly this canonicalization primitive,
  just not applied to a whole signed object yet).
- **Digest-then-sign**: `digest = sha256(signing_body_utf8)`; the signature is Ed25519 over
  `digest.hexdigest()` encoded as ASCII (not over the raw signing body) — matching
  `cll.checkpoint.emit.CheckpointRecord.digest()`/`emit_checkpoint`'s `signer.sign(cp.digest())`
  call exactly. This means the digest is independently useful (loggable, comparable) without
  needing the full manifest body in hand.
- **Offline verification with no shared secret**: `verify_checkpoint_signature_offline` in the
  same module reconstructs the Ed25519 public key directly from the hex-encoded `key_id` field
  and verifies the signature over `digest()` — no registry, no PKI, no network call. The Buzz
  verifier does the same: parse `exporter_key_id` as a raw Ed25519 public key, verify `signature`
  over `sha256(canonical_json(manifest_minus_signature)).hexdigest()`.

**What is deliberately NOT reused from `cll.checkpoint.emit`:** the MMR peak-set machinery
(`root`, `prev_size`, `prev_root`, inclusion proofs) — Buzz's chain is a simple linked hash
chain, not a Merkle Mountain Range, so there is no peak set to commit to; `final_hash` already
plays the role `root` plays there (a single value that transitively commits to everything
before it, given the chain has already been walked and validated by `verify_chain`). The
witness/grade ladder (`Grade`, `StampVerdict`, `WitnessRecord.is_stub`) is also not reused as a
Rust dependency — it is a Python module — but its *shape* motivates §4 below.

**Rust implementation surface.** `ed25519-dalek = "=3.0.0"` is already a pinned dependency in this
workspace (`crates/buzz-mesh-smoke/Cargo.toml`, `desktop/src-tauri/Cargo.toml`, used today for
mesh-LLM discovery-note verification in `desktop/src-tauri/src/mesh_llm/discovery.rs`). The
export-manifest signer adds the same crate, pinned to the same version, as a new dependency of
`buzz-audit` (a `buzz_audit::manifest` module — see §6) — no new cryptography dependency enters
the workspace.

## 4. Optional witness registration — a second, independent step

`#3228` doesn't ask for this; it is offered because it is the natural second rung once a
manifest is signed, and it is explicitly optional so nothing in this design requires the
operator to trust or reach a third party.

A manifest MAY carry a `witnesses` array, populated only when the operator opts in (a flag on
`audit export`, or a separate `audit witness --manifest <file>` follow-up command — implementation
decides, not this document). Each witness entry is the same shape `capsule-emit`/
`checkpointed-local-log` already use for a SCITT Transparency Service receipt: a URL, an entry
hash bound to *this* manifest's digest, and a COSE Receipt proving a third party's append-only
log observed the digest at some point. Any conforming SCITT Transparency Service works — the
manifest format does not name one. This step exists purely to narrow §1's "out of scope" item 2
(when did this manifest first exist) for operators who want it; a manifest with zero witnesses is
still fully self-verifying per §3 and stays at whatever the Buzz-side implementation calls its
un-witnessed state (naming is upstream's call — see §6, "no capsule/witness vocabulary
upstream").

## 5. The verifier's added check

Today, `AuditService::verify_chain(community, from_seq, to_seq)` proves: *the stored rows in this
range are internally consistent — each hash matches its own fields, and each `prev_hash` matches
the prior row's `hash`.* It cannot prove those rows are the *original* rows, because nothing
about that computation depends on any value outside the database itself.

`audit verify --from-seq --to-seq --manifest <file>` (or equivalent — see §6) runs three checks,
all of which must hold:

1. **Chain-internal** — `verify_chain` over `[from_seq, to_seq]`, unchanged (existing code, no
   modification to `compute_hash` or the chain construction — #3228's own Non-goals line:
   "Changing the current hash-chain construction").
2. **Manifest-matches-chain** — the entry at `to_seq`, re-fetched from the database right now,
   has `hash == manifest.final_hash`. This is the step that turns a silent recompute-and-rewrite
   into a detectable mismatch: an attacker who rewrote the chain produces new hashes; the
   manifest, signed before the rewrite, still states the old one.
3. **Signature** — `manifest.signature` verifies over `manifest.exporter_key_id` and the
   recomputed digest of the manifest's own signing body (§3), entirely offline.

If (3) is supplied and (4) below is present, a fourth, optional check:

4. **Witness receipt(s)**, if the manifest carries any — each verified independently offline or
   against a cached/pinned Transparency Service public key, per §4. Absence of a witness is never
   treated as failure; presence of an invalid one is.

Stated as the acceptance line: *the manifest hash equals the recomputed chain head, the
signature verifies, and — if present — the witness receipt verifies.*

## 6. Mapping to #3228's proposed CLI shape and acceptance criteria

The issue's own suggested shape:

```text
buzz-admin audit export --from-seq 1 --limit 1000 --format jsonl
buzz-admin audit verify --from-seq 1 --to-seq 1000
```

with "The exact API and command names can follow maintainer preference" — so the implementation
(§ next task, on the fork) proposes exactly this shape as a starting point, adds a `--sign`
opt-in flag to `export` (manifest is only produced/signed when asked — an operator without a
configured signing key gets the existing unsigned pagination behavior, never a hard failure), and
adds `--manifest <path>` to `verify`. `buzz-admin` already resolves its single community from
`RELAY_URL` (`resolve_admin_tenant`, `crates/buzz-admin/src/main.rs`) rather than from any
client-supplied identifier — the existing pattern already satisfies "strict community scoping
derived from the authenticated context" and "pagination cursors must not contain or override
client-controlled tenant identifiers," since `buzz-admin` takes no tenant argument at all.

Acceptance-criteria mapping (from #3228, restated so each line has a concrete test in the fork
implementation task):

- *"An authorized community operator can export a bounded audit range"* — `audit export
  --from-seq --limit`, bounded by `get_entries`'s existing `limit` param.
- *"The export contains sufficient fields for independent hash verification"* — full row
  (`seq, hash, prev_hash, action, actor, object, detail, created_at`) per entry, matching
  `hash.rs::compute_hash`'s inputs exactly.
- *"Altering an exported entry causes verification to fail"* — covered twice: `verify_chain`
  (existing) catches in-range tampering that breaks internal consistency; the recompute-attack
  test (fork task) proves the harder case — an attacker who ALSO recomputes the chain to stay
  internally consistent still fails signed-manifest verification.
- *"Requests cannot cross the host-bound community boundary"* — `resolve_admin_tenant` + existing
  `community_id`-scoped queries; tenant-isolation test.
- *"Large audit histories can be exported incrementally"* — pagination by `from_seq`/`limit`,
  unchanged from `get_entries`.
- *"Integration tests cover authorization, pagination, tenant isolation, and chain corruption"* —
  plus the recompute attack, which is the scenario this whole design exists for.
- *"The output format is documented as a stable integration surface"* — fork PR documents the
  JSONL entry shape and the manifest shape (§2) together.
- *"Existing `/moderation/audit` behavior and consumers remain compatible"* — trivially true by
  construction: `GET /moderation/audit` (`crates/buzz-relay/src/api/bridge.rs::moderation_audit`)
  reads the **separate** `moderation_actions` table via `list_moderation_actions`, not
  `audit_log`/`AuditService` at all. The new surface and the existing route share no table, no
  query, no handler — nothing to keep compatible because nothing overlaps. Worth stating plainly
  in the PR since the issue itself raises the relationship as an open question.

## 7. What ships where

- **This document** — `capsule-emit-mesh`, committed before any upstream text, per the workspace
  boundary rule for protocol/invention text.
- **Issue comment + PR body** — Buzz-native language only (no "capsule," "witness," "anchor,"
  "Authority," or Action State Group product vocabulary); drafted for Steven, who posts both
  himself.
- **Implementation** — `StevenMih/buzz` fork: `buzz-admin audit export`/`audit verify`, the
  manifest struct + Ed25519 signer (new, Rust, `ed25519-dalek 3.0.0-rc.0`), and the integration
  test suite including the recompute-attack test. No `capsule-emit`/`cll` package dependency is
  added to `buzz` — the wire-form ideas are reused by re-implementing the same small
  canonical-JSON + digest-then-sign pattern natively in Rust, not by vendoring a Python package
  into a Rust workspace.
