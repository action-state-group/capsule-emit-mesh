# Registry entry — TEMPLATE

**This is a template, not an entry.** It shows the shape a payload-binding declaration takes and the
questions a filled entry has to answer. The worked example throughout is deliberately trivial and
has nothing to do with any real deployment — it exists so the template stays a template.

**An entry is authored and attested by the owner of the payload.** Nobody should fill this in on
someone else's behalf: an entry written for you is not an independent implementation of anything.
The expected flow is that the owner completes it, publishes vectors, and a second party
independently reproduces those vectors before the entry is promoted.

---

## 0. Why a declaration exists at all

Two implementations of the same record format will agree about structure and disagree about bytes.
They will disagree about how a decimal number is written, whether keys were sorted before hashing,
what Unicode form a string was in, whether an absent field and a null field hash the same, and — for
anything streamed — whether the digest covered the reassembled body or the frames that carried it.

Every one of those is obvious to whoever implements it first and invisible to everyone afterwards.
A declaration writes them down before there is a second implementation; the vectors make the
declaration checkable rather than merely stated.

---

## 1. Entry identity

| Field | Value |
|---|---|
| Entry name | *(short, stable, lowercase — e.g. `example-echo-v1`)* |
| Version | *(entries are immutable; a change is a new version)* |
| Owner | *(the organisation or individual who authored and attests this entry)* |
| Contact | *(a person or list who answers questions about it)* |
| Source repository | *(where the implementation and vectors live)* |
| Licence | *(of the vectors and any reference code)* |
| Status | *(per the registry's own onboarding ladder — do not invent a status word)* |

**Independence.** State plainly whether the entry owner is independent of the format's authors, and
if there is any shared authorship, say so here. An entry that is not independent is still a useful
entry; one that is described as independent when it is not damages every other entry in the list.

---

## 1.5 Which slot does this profile fill, and what fills the others

**One entry declares one profile, and a profile fills one slot.** A real deployment usually populates
several slots, and it does so by *composing several profiles* — not by writing one large entry. This
section is how a reader of a single entry can see the whole picture.

The composition model defines four interchangeable slots, each a question an action may need
answered. Not every action populates every slot, and leaving one empty on purpose is a legitimate —
and informative — statement.

| Slot | The question | Filled in this deployment by | Entry / draft reference |
|---|---|---|---|
| **CAN** | Was the actor permitted to act? | *(this profile · another profile · deliberately unpopulated)* | |
| **WHO** | Which accountable human authorized this exact action? | | |
| **WHAT** | What did the actor actually do? | | |
| **AUDIT** | Did the runtime enforce correctly, in causal order, tamper-evidently? | | |

> *Worked example.* `example-echo-v1` fills **WHAT** only. CAN is unpopulated — the echo service
> imposes no authorization step — and WHO is unpopulated because no human authorizes an individual
> echo. AUDIT is filled by an existing profile, cited rather than redeclared.

**Why it is structured this way.** Adding a slot later should be a new small entry plus one line
changed in a composition statement, never a re-registration of everything already declared. Entries
are immutable and single-purpose precisely so that a deployment can grow into more slots without
invalidating what it has already published.

**If your deployment populates more than one slot**, publish a short **composition statement**
alongside the entries: which slot each profile fills, what joins them (the shared subject digest, or
an explicit cross-reference between profile-native subject digests), which assurance tier is claimed,
and which vector set backs the composition as a whole. One page. It is not a bigger registry entry
and should not be written as one.

---

## 2. What the payload is

Two or three sentences in plain language. What kind of thing does a record with this payload
describe, who produces it, and who reads it.

> *Worked example.* `example-echo-v1` records a call to a service that returns its input unchanged.
> Producers are echo servers; readers are clients checking that what came back is what they sent.

Then the mechanical facts:

| Field | Value |
|---|---|
| Media type / content type | |
| Structure | *(JSON object, CBOR map, binary frame, …)* |
| Schema reference | *(URL or digest of the schema, if one exists)* |
| Size bounds | *(if any are assumed)* |

---

## 3. Digest domains

**The single most important section.** A payload usually exists in more than one form: what a
producer generated, what a transport delivered, what a client received after normalisation. Each is
a different sequence of bytes. State which ones this entry commits to, and give each a name.

| Domain name | Covers exactly | Composition role | Produced by | Reproducible by a third party? |
|---|---|---|---|---|
| | | *(subject · authority-reference · receipt-payload)* | | |

### 3a. Declared transforms between domains

Where two domains cover the same logical object at different points — what a producer generated
versus what a client received — **declare the transforms applied between them**, in order, each with
a stable identifier.

| From domain | To domain | Transforms applied, in order | Reproducible? |
|---|---|---|---|
| | | | |

This is what turns two digests from a pair of unrelated commitments into a *checkable relationship*.
Without it a verifier holding both values and finding them different has no way to tell whether it is
looking at a declared transformation or a substitution — which is the exact question the digests
exist to answer. It also makes non-reproducibility legible: a transform that injects a timestamp or a
freshly minted identifier can be named as such, so a downstream reader knows why one domain cannot be
re-derived and the other can.

> *Worked example.* `example-echo-v1` declares one transform between `echo.response.produced` and
> `echo.response.delivered`: `stamp-served-at-v1`, which inserts a wall-clock field. It is named, so a
> verifier expects the two digests to differ and knows exactly why.

**Composition role is not optional.** The composition model carries three distinct digest roles — a
*subject digest* identifying the action a slot's assertion applies to, a profile-tagged
*authority-reference digest* committing to the native evidence object, and a *receipt-payload digest*
committing to the exact bytes a transparency service covered. These values may all differ, a profile
**MUST** state which object and byte sequence each covers, and a verifier **MUST NOT** infer equality
or transitive coverage merely because two fields share a hash algorithm. This section is where a
profile discharges that obligation.

Rules a filled entry should observe:

1. **Name every domain.** A record that says "the response digest" without saying which bytes is
   under-specified.
2. **If a value is not reproducible, say so.** A domain that includes a timestamp, a random
   identifier, or anything else assigned at delivery time cannot be re-derived later. That is fine —
   it is still useful for correlation and integrity — but it must not be presented as something a
   verifier can check by re-running the work.
3. **Prefer committing to more than one domain over choosing badly.** Committing separately to what
   was produced and to what was delivered costs one extra digest and removes an entire class of
   argument.

> *Worked example.* `example-echo-v1` declares two domains: `echo.request.canonical` over the
> canonicalized request object, and `echo.response.delivered` over the exact bytes written to the
> client socket. The second is not reproducible: the server stamps a `served_at` field at write time.

---

## 4. Canonicalization declaration

The transformation applied before hashing, stated precisely enough that an implementer who has never
seen your code can reproduce it. Give it a **versioned identifier** that appears in the record, so a
future change is visible rather than silent.

| Question | Declaration |
|---|---|
| Transformation identifier | *(e.g. `example-jcs-v1` — recorded in every record that uses it)* |
| Base canonicalization | *(a named standard, or "none", or a description)* |
| Key ordering | |
| Unicode normalization form | |
| Escaping rules | |
| **Numbers: integers** | |
| **Numbers: decimals** | *(exact representation — this is where implementations diverge first)* |
| **Numbers: exponents** | |
| **Numbers: floating-point parameters** | *(state whether they are converted to decimal strings, and if so, how)* |
| Absent versus null | *(do they hash identically? they should not)* |
| Empty collections | |
| Nested structures | *(any depth or ordering rules)* |
| Binary or media parts | *(inline, referenced by digest, or excluded)* |
| Fields excluded from the digest | *(and why)* |

**If the payload can be streamed**, add:

| Question | Declaration |
|---|---|
| What the transcript covers | *(frame payloads, complete encoded frames, or both — separately named)* |
| Reassembly rule | *(how fragments are ordered and joined before hashing)* |
| Bounded reassembly | *(any size limit, and what happens when it is exceeded)* |
| Incomplete transcripts | *(how a truncated or dropped-byte observation is represented — it must never look complete)* |

---

## 5. Equivalence classes

Where two artifacts are intentionally interchangeable, declare it. Without a declared class, any
legitimate substitution looks like a substitution attack, and any real attack can be excused as a
legitimate variant.

| Class name | Members | What makes membership legitimate | Who decides |
|---|---|---|---|

> *Worked example.* `example-echo-v1` declares no equivalence classes: the echo service returns bytes
> unchanged, so there is nothing that is intentionally interchangeable.

---

## 6. Conformance vectors

The declaration is a claim; the vectors are what make it checkable.

| Requirement | Value |
|---|---|
| Location | *(path or URL — vectors must be fetchable without asking anyone)* |
| Count | |
| Format | *(one directory per vector: input, canonical form, expected digest)* |
| Digest algorithm | |
| Coverage checklist | integers · decimals · exponents · Unicode edge cases · key ordering · absent vs null · empty collections · deep nesting · large payloads · binary parts · streamed reassembly · truncated stream |
| Negative vectors | *(inputs that must NOT produce a given digest — a suite with no negative cases proves very little)* |
| Reproduction command | *(one command that regenerates every vector from source)* |

**A vector set that only its own implementation can pass is not a conformance suite.** The test is
whether a second, independently written implementation reproduces the digests byte-for-byte with no
access to the first one's code.

---

## 7. Verification procedure

What a third party does, in order, to check a record carrying this payload. Offline where possible;
state clearly which steps require a network and what happens when the network is unavailable.

1.
2.
3.

| Step | Requires network? | If unavailable |
|---|---|---|

A step that cannot run must report that it did not run. It must never report a pass.

---

## 8. Known limits

State what a record carrying this payload does *not* establish. This section is not a disclaimer —
it is the part a careful reader checks first, and an entry without one reads as either naive or
evasive.

- What the digests do not cover.
- What an observer at this boundary cannot see.
- Where a claim in the payload is asserted rather than evidenced.
- Any low-entropy field where a committed digest is vulnerable to dictionary attack.

---

## 9. Change policy

| Question | Declaration |
|---|---|
| What constitutes a breaking change | |
| How a new version is named | |
| Whether old versions remain valid | |
| Who may publish a revision | |

Entries are immutable once registered. A correction is a new version with a pointer from the old
one, never an edit in place — records already exist that were produced under the previous text.

---

## 10. Attestation by the entry owner

To be signed by the owner named in §1.

> The declarations in this entry describe the implementation as it actually behaves. The vectors in
> §6 were produced by that implementation and can be reproduced from source with the command given.
> Where a claim is asserted rather than evidenced, §8 says so.

| | |
|---|---|
| Name | |
| Role | |
| Date | |
| Reproduced independently by | *(second party, after the fact — not filled by the owner)* |
| Reproduction date | |

---

*Template. Fill it, fork it, or tell us what shape it should have been — feedback on the template is
as useful as an entry.*
