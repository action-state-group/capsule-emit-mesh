# Spec-feedback on Mesh-LLM/mesh-llm#1331 — delegation chain verifier

Submitted from `capsule-emit-mesh` as part of the delegation chain verifier
(`delegation_chain_verifier.py`, PR #5). Each item below records a corner that
#1331 leaves underspecified, the working assumption the verifier uses, and the
question for Nick to settle. Nothing below is an objection — the spec is
sound; these are precision gaps a downstream implementer needs to fill.

---

## 1. `SignedNodeOwnership` — no field names or encoding defined

**What #1331 says.** Section "Host identity and signing delegation":
> *SignedNodeOwnership: a short-lived owner-signed certificate binding owner
> identity to node endpoint identity.*

`ReadIdentityBundle` returns it alongside a "local verification summary," but
no field names, encoding, or signing procedure are given.

**Working assumption in this verifier.**

```json
{
  "owner_id":             "<hex, SHA-256 of raw owner Ed25519 public key>",
  "owner_sign_public_key": "<hex, raw 32-byte Ed25519 public key>",
  "node_endpoint_id":     "<hex, raw 32-byte Ed25519 node public key>",
  "issued_at_unix_ms":    1787011200000,
  "expires_at_unix_ms":   1819000000000,
  "cert_id":              "<hex, SHA-256 of JCS(above fields)>",
  "_sig":                 "<hex, Ed25519 signature over JCS(above minus cert_id and _sig)>"
}
```

`cert_id` is NOT in the signed body (avoids circular dependency); it is
computed by the verifier as `SHA-256(JCS(signed_body))` and compared against
`delegation.node_ownership_cert_id`.

**Question for Nick.**
1. What fields does `SignedNodeOwnership` actually contain?
2. What encoding — JSON/CBOR/protobuf?
3. Is there a domain tag, or is it signed over the raw canonical bytes?
4. How is `node_ownership_cert_id` in `PluginSigningDelegationV1` derived
   from the cert — SHA-256 of what bytes?

---

## 2. `owner_id` derivation — "derived from that owner public key" is unspecified

**What #1331 says.** Step 3 of the verifier chain:
> *verify owner_id is derived from that owner public key.*

No derivation function is given.

**Working assumption.** `owner_id = SHA-256(raw_32_byte_ed25519_public_key).hex()`

**Question for Nick.** What derivation does `mesh-llm auth init` use? Options
include the raw key bytes directly (if the owner_id IS the key), a hash
(SHA-256, BLAKE3), a libp2p multihash, or an iroh/NodeId encoding. If the
node and owner identity systems use the same derivation (they are both
Ed25519), a shared primitive would remove one ambiguity.

---

## 3. Canonical serialization format for `PluginSigningDelegationV1`

**What #1331 says.**
> *use canonical serialization with a fixed domain tag such as
> `mesh-llm-plugin-signing-delegation-v1:`*

"Such as" is not normative. JSON vs CBOR and the exact byte layout of the
domain tag (prefix? separate context? COSE Countersignature structure?) are
unspecified.

**Working assumption.** Signed bytes =
`b"mesh-llm-plugin-signing-delegation-v1:" + JCS(delegation_fields_without_sig)`.

JCS = RFC 8785 (sorted keys, no whitespace, UTF-8). The `_sig` wrapper field
is not part of the signed body.

**Question for Nick.**
1. Is the encoding JSON (JCS) or CBOR?
2. Is the domain tag literally prepended to the canonical bytes, or is it a
   separate context field in a structured signing envelope?
3. Should the delegation be wrapped in a COSE structure, or is a raw Ed25519
   signature alongside the JSON document the intended shape?

---

## 4. Public key encoding in the delegation struct

**What #1331 says.** Fields like `owner_sign_public_key` and
`delegated_signing_public_key` appear in `PluginSigningDelegationV1` but no
encoding is specified (raw bytes, hex, base64, PEM, DER, multihash).

**Working assumption.** Lowercase hex of the raw 32-byte Ed25519 public key.

**Question for Nick.** What encoding does the host use when serialising these
fields? If the mesh identity layer already uses a canonical encoding (e.g.
iroh's base32 NodeId), that should be used here for consistency.

---

## 5. Release build attestation — shape and trust anchor undefined (step 6)

**What #1331 says.** Step 6 of the verifier chain:
> *verify release build attestation independently when supplied.*

And under Goals:
> *Let explicitly authorized plugins consume the node's public
> identity/attestation bundle … release build attestation: trusted
> release-signer evidence about the packaged mesh-llm executable, separate
> from ownership and remote runtime attestation.*

No shape, signing key, trust anchor, distribution mechanism, or encoding is
given. The verifier implements step 6 as a stub.

**Working assumption (stub).** The verifier accepts any document with a
`plugin_id` field matching the delegation's `plugin_id`. All other fields are
ignored.

**Question for Nick.**
1. What does the release build attestation document look like?
2. Who signs it (release signer key vs. node owner key)?
3. How does an offline verifier obtain the trust anchor for the signer?
4. Is this a COSE_Sign1 over a fixed manifest format, a Sigstore bundle, or
   something else?

---

## 6. `delegation_id` format

**What #1331 says.** The field appears in `PluginSigningDelegationV1` with
the note that it enables revocation ("include a delegation ID so revocation
can be added or enforced explicitly"). No format, length, or generation
procedure is given.

**Working assumption.** Opaque string; the verifier treats it as a comparable
identifier for revocation list lookup.

**Question for Nick.** Is this a UUID, a hash of the delegation bytes, a
sequence number scoped to the plugin, or something else? A defined format
would let two implementations agree on the revocation check without
ambiguity.

---

## 7. Revocation list shape and distribution

**What #1331 says.** Step 5 mentions "local owner/node/delegation revocation
policy" but gives no shape for the revocation list or how it is obtained.

**Working assumption.** A JSON document:

```json
{
  "revoked_delegations": ["deleg-id-1", ...],
  "revoked_nodes":       ["hex-node-id-1", ...],
  "revoked_owners":      ["hex-owner-id-1", ...]
}
```

The verifier checks all three lists.

**Question for Nick.** Is revocation expressed as a signed CRL, a real-time
endpoint query, or a host-managed list? If the revocation list itself must be
signed, what key signs it and how does the verifier obtain it?

---

## 8. Scope of semantic plugin-id check in offline verification

**What #1331 says.**
> *authenticate plugin_id from the live plugin connection, not request JSON.*

In the live host this is correct — the host knows which plugin established the
connection. In offline verification there is no live connection; the verifier
must be told the expected plugin_id out of band.

**Working assumption.** The caller supplies `--expected-plugin-id`; the
verifier checks `delegation.plugin_id == expected_plugin_id`.

**Question for Nick.** Is offline verification (e.g. a receipt consumer
checking a chain after the fact) an intended use case? If so, what is the
canonical source of the expected plugin_id for a verifier that was not party
to the original exchange?

---

## 9. Identity mode → cross-party rung: axes are orthogonal, mapping does not exist

**What #1331 says.**

Four identity modes are defined:
- `self_attested` — plugin uses an independent key; no owner binding
- `owner_delegated` — valid PluginSigningDelegationV1 + SignedNodeOwnership
- `owner_delegated_required` — host policy floor; fail plugin readiness if unavailable
- `hardware_delegated` — reserved for future TEE/TPM-backed non-exportable keys

**The mode→rung mapping does not exist.**

The cross-party rung ladder (`unilateral_fallback` < `acknowledged_receipt` <
`full_bilateral`) answers *"how many parties co-signed the exchange record?"*
The identity mode answers *"how is the plugin's signing key delegated?"*
These are orthogonal axes. The verifier's `mode_output_dict()` always sets
`rung: null` for every mode, with a note explaining why.

| Identity mode | Rung | Why no rung |
|---|---|---|
| `self_attested` | none | The mode says nothing about counterparty co-signing. A self_attested plugin can produce `unilateral_fallback` records. The exchange evidence, not the key delegation, determines the rung. |
| `owner_delegated` | none | Owner binding improves attributability (identity axis B2) but does NOT grant a higher cross-party rung. `unilateral_fallback` (one-party signature) is the floor. `acknowledged_receipt` and `full_bilateral` require counterparty co-signing, which is independent of how the plugin key is delegated. |
| `owner_delegated_required` | n/a | This is a host policy setting, not an evidence label. It cannot be placed on the evidence ladder. |
| `hardware_delegated` | none | Reserved; unrepresentable in software. Even if it were representable, it addresses the key provenance sub-axis of identity, not the cross-party co-signing axis. |

**This is consistent with ASSURANCE-VOCABULARY.md §5.** That document already
separates assurance into five orthogonal axes. Identity (`B0–B3`) and
mutuality (`D0–D2`) are distinct axes; a value on the identity axis does not
determine a value on the mutuality axis and vice versa. The `owner_delegated`
mode corresponds to B2 (owner-delegated software key). `full_bilateral`
corresponds to D2 (both parties signed). A plugin at B2 can still stand at
D0 (`unilateral_fallback`), and a self-attested plugin at B1 could in
principle reach D2 if the counterparty co-signs.

**Question for Nick.**
1. Is the intent that an `owner_delegated` plugin enables any specific rung
   on the cross-party ladder, or is the identity mode purely an attribution /
   revocation / key-management concern?
2. If `owner_delegated` is intended to unlock `acknowledged_receipt`, what
   additional evidence from the counterparty makes the step, and where does
   it land in the host's evidence bundle?
3. `owner_delegated_required` reads as a policy setting in the host config,
   not as an evidence label a downstream verifier can assert. Is that reading
   correct, or should a verifier be able to label a record as having been
   produced under `owner_delegated_required` policy?

---


## 10. Body access: not a binary flag — and the plugin must fail loudly

**What #1331 says.**
> *"body access withheld by host config"*

The manifest declares `sanitized_headers` and `decision_mode`, but #1331
does not specify the protocol for body access: whether the host passes `null`
for the body field, whether it skips calling the plugin entirely for
body-sensitive phases, or whether it calls the plugin with an explicit
`body_access_granted: false` signal alongside `body: null`.

**Working assumption in this exemplar.**

The host calls the plugin for every subscribed phase, always passing
`body_access_granted` as an explicit boolean alongside `body`.  When
`body_access_granted=False`, `body` is `None`.  The plugin must check
`body_access_granted` and raise `BodyAccessDenied` if it requires the body —
not silently return `abstain` (which would be the fail-toward-reassurance
shape: confident output, empty observation).

The host treats `BodyAccessDenied` as `EVIDENCE_UNAVAILABLE /
internal_hook_failure`, not as a plugin deny decision.

**Questions for Nick.**

1. Is body access an all-or-nothing grant per plugin, or can it be
   phase-specific (e.g. body at REQUEST_RECEIVED but not at
   EXCHANGE_FINISHED)?
2. If the host withholds body access for an admission-policy plugin, does the
   host skip loading the plugin entirely, call it with `body=null`, or
   downgrade it to observe-only for that phase?
3. Is there a host-level audit event for "plugin called with body access
   denied"?  The exemplar records it in the EVIDENCE side-stream; is that
   the expected location?

---

## 11. Observe-only: does silent abstain on missing body violate the contract?

**What #1331 says.**
> *"must never influence the exchange"*

An observe-only plugin that returns `abstain` when its body grant is missing
technically satisfies "never influence" — it changed nothing.  But it also
observed nothing, which means the record it emits (if any) is misleadingly
complete.

**Working assumption.**  This exemplar treats silent abstain on missing body
as a fail-toward-reassurance shape and raises `BodyAccessDenied` instead.

**Question for Nick.**  Should the contract explicitly require observe-only
plugins to fail loudly when they cannot observe, or is silent abstain
acceptable?  If the spec intends observe-only as "observe and record if you
can, otherwise stay out of the way," the plugin should emit an incomplete
observation record rather than raise.  The exemplar explicitly chose raise
over incomplete record because the task acceptance criterion required it;
confirm which shape #1331 intends.

---

## 12. Decision mode enforcement: host-side or convention?

**What #1331 says.**  Manifests declare `decision_mode` but no enforcement
mechanism is described.

**Working assumption.**  The exemplar host does not prevent an `observe_only`
plugin from returning `DENY` — it processes whatever string the plugin
returns.  The observe-only plugin in this exemplar simply never returns
`DENY` by convention.

**Question for Nick.**  Should the host treat a `DENY` from an
`observe_only` plugin as a protocol error (and fail the exchange with
`internal_hook_failure`), ignore it (treat as `abstain`), or pass it through?
The failure mode matters: a misbehaving plugin that declares `observe_only`
but returns `DENY` must not silently block traffic.

---

## 13. `sanitized_headers`: request vs grant, and forbidden-header policy

**What #1331 says.**  Authorization and Cookie must not appear in plugin-
visible context — #1331 makes this its own acceptance box.

The exemplar's manifest lists `sanitized_headers=["content-type",
"x-request-id"]` and the host filters strictly against this list.  What is
unspecified:

1. If a plugin manifest lists `authorization` in `sanitized_headers`, does
   the host refuse to load the plugin, silently strip it, or raise an error?
2. Is `sanitized_headers` a minimum request ("give me at least these") or an
   exact allowlist ("give me exactly these, no more")?  If the host also
   exposes `x-mesh-request-id` to every plugin for correlation, is that a
   contract violation?
3. How does a plugin discover which headers it was actually granted vs which
   it requested?  The exemplar has no way to know whether the host silently
   dropped a header it declared.

**Working assumption.**  The host filters strictly: only headers in the
manifest's list are passed, Authorization and Cookie are never passed
regardless of the manifest, and no additional headers are added.  No
load-time error for forbidden-header requests — the headers are just absent.

---

## 14. Phase subset calling: opt-in vs opt-out

**What #1331 says.**  The manifest `phases` field lists which phases the
plugin wants to be called for.

**Question for Nick.**  If an admission-policy plugin declares only
`["request_received"]` in phases (to avoid unnecessary body reads at
`exchange_finished`), does the host:
(a) skip calling the plugin entirely at `backend_selected` and
    `exchange_finished`, or
(b) call the plugin at all phases and the plugin returns `abstain` for phases
    it did not declare?

The exemplar's host uses (a): the `phases` list is authoritative and the host
calls the plugin only at declared phases.  But the protocol is not in #1331.
The distinction matters for performance: an admission-policy plugin subscribed
to all three phases is called three times per exchange even though it only
evaluates at `request_received`.

---

## 15. DENY at non-decision phases: protocol error or treated as abstain?

**What #1331 says.**  Nothing.

**Working assumption.**  The exemplar's host processes `DENY` wherever it
appears.  If an `admission_policy` plugin returns `DENY` at
`exchange_finished`, the host would produce a confusing `POLICY_DENIED` trace
after the backend already completed.

**Question for Nick.**  Should `DENY` at `exchange_finished` be:
(a) a protocol error → `internal_hook_failure`,
(b) silently treated as `abstain` (the backend already responded), or
(c) valid — the host retracts the client egress and returns the denial error
    even though the backend was already dispatched?

Option (a) is the safest: it makes the plugin contract explicit about where
denial is valid.  Option (c) would require the host to buffer the response
and is likely out of scope for the initial contract.

---

*Previous spec-feedback notes from this repo:*

*Items 1–9 are in `docs/SPEC-FEEDBACK-1331.md` as produced by the
delegation-chain verifier task (`[mesh-delegation-chain-verifier]`).
This file adds items 10–15 from the two-mode exemplar task
(`[mesh-exemplar-plugin-two-modes]`).  The two files will be reconciled
into one when both PRs merge.*
