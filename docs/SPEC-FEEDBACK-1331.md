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
