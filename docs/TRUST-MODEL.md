# A trust model for strangers on a mesh

A draft threat model and assurance framework for decentralized inference, written as step 1 of the
progression in [Mesh-LLM#1233](https://github.com/Mesh-LLM/mesh-llm/issues/1233) — *"define the
threat model and assurance levels."*

Steven Mih · 2026-08-16 · offered for discussion, revision, or re-homing.

> **Status of the referenced specifications.** Where this document refers to record-format
> mechanisms, the published revisions are `draft-mih-scitt-agent-action-capsule-02`,
> `draft-mih-agent-bilateral-attestation-01`, `draft-mih-sato-agent-accountability-composition-00`
> and `draft-mih-agent-accountability-conformance-00`. Successor revisions (-03, -02, -01, -01) are
> written and in review but not yet posted; where this document relies on text that appears only in
> those, it says **[forthcoming revision]**. Nothing here asserts adoption by anyone.

---

## 0. Why this document exists

#1233 opens with *"define the threat model and assurance levels."* Work has since started around
several later steps — #1331 and #1332 cover step 3, #1346 reaches toward step 5 — while step 1 has
no owner, and the rest are hard to order without it. There is no principled way to say whether a
fingerprint matters more than a TEE quote, or whether a node is safe to admit, until the threats are
written down.

This document writes step 1, and widens it in one direction. #1233 asks the requester's question —
*how does a client tell whether a node ran the model it advertises?* — and asks it well. But a mesh
has two strangers in it:

- **Sending work out.** I hand a prompt to a machine I have never seen, owned by someone I cannot
  name. What can I check afterwards, and what am I simply trusting?
- **Lending my machine.** I let strangers run inference on my hardware. What did I agree to run, who
  asked me, what do I now know that I would rather not, what did it cost me, and what can I prove if
  someone later accuses me of cheating?

The second is not a footnote. A capacity mesh has no supply without it, and node operators are
making an unpriced risk decision today with no evidence to reason about.

The three-claim decomposition at the top of #1233 — model identity, execution identity, behavioural
identity, each failing differently and needing separate evidence — is the maintainers'. This document
extends it rather than replacing it.

---

## 1. What a record can and cannot create

A signed record does not make a stranger trustworthy. It makes their claims **durable, attributable,
and checkable after the fact.** The useful question is not "is this party honest" but *"if this goes
wrong, is there anything left to examine?"*

The TLS comparison is apt but usually made too generously. TLS does not tell you a site is honest.
It tells you which named party you are talking to and that nobody altered the bytes in flight. The
same boundary holds here: a receipt establishes *who said what, about which bytes, when, and in what
order*. It does not establish that what they said is true.

Three consequences run throughout:

1. **Accountability precedes assurance.** Most of the value arrives at the first rung — a record that
   exists, is signed, and cannot be quietly revised. Higher rungs narrow the space of undetectable
   lies; they never reach zero.
2. **Self-attestation is the floor, not a flaw.** A node signing a statement about its own behaviour
   is exactly as strong as its identity binding and as durable as the log it publishes to. Saying so
   plainly is what makes the record usable as evidence.
3. **Absence of evidence must never render as a pass.** A check that did not run, a quote that was
   not supplied, a witness that was unreachable — each is distinct, and none of them is "verified."

---

## 2. Threat model

### 2.1 The parties

| Party | Holds | Wants |
|---|---|---|
| **Requester** | A prompt or task; a keypair they control | The claimed model served their request; the answer received is the answer produced; their input is not retained or repurposed; they spend no more than they authorized |
| **Provider** (node operator) | Hardware, weights, an owner identity | Not to be liable for what strangers ask; to prove they served honestly; to bound what they learn, what they run, and what it costs |
| **Coordinator / mesh** | Routing, topology, split layout | To admit or exclude nodes on evidence; to resolve disputes without adjudicating by reputation alone |
| **Third party** | Neither; arrives later | To evaluate a claim about an exchange they did not witness — an auditor, a regulator, a counterparty, a court |

The third party is why records must be portable and offline-checkable. Evidence that only works
inside the mesh's own console is not evidence to anyone who matters in a dispute.

### 2.2 What the requester fears

| # | Fear | Evidence that addresses it | Status |
|---|---|---|---|
| R1 | Substituted quantization or different weights | Model package digest bound into the receipt (step 2) | Manifests largely carry it; needs tag-not-branch discipline and a declared equivalence class |
| R2 | A canned answer with no computation | TEE / execution evidence (step 5) | Not built |
| R3 | Replay of earlier work as fresh | **Client-contributed nonce** bound into the receipt | Not built — today's fallback nonce is node-side and is explicitly not anti-replay evidence |
| R4 | The response received is not the response signed | Request and output digests under one signature | Built |
| R5 | Later denial or rewriting | Signed, hash-chained records | Built, per node |
| R6 | A different story per audience | Registration to a Transparency Service, and a witnessed log so the log cannot equivocate either | Chaining built; registration is the missing half |
| R7 | I cannot tell which node this was | Receipt key bound to node and owner identity | Specified in #1331; not built |
| R8 | Output behaves nothing like the claimed model | Fingerprints, as confidence not verdict (step 4) | Not built |
| R9 | **My prompt is read, retained, or repurposed** | Nothing in the record layer — §5 | Unaddressed; #1346 is the first attempt |
| R10 | Split across strangers, and I cannot see who held what | Per-stage receipts plus a coordinator receipt over stage order | Not built |
| R11 | Charged for more work than I authorized | Authorization bound and consumption as two separate facts (§6) | Not built |

### 2.3 What the provider fears — the half not yet written down

| # | Fear | Evidence that would address it | Status |
|---|---|---|---|
| P1 | I am asked to generate something unlawful and it is attributed to me | **A request commitment signed by the requester** — attribution follows the author | Not built. The receipt tuple has no requester identity field at all |
| P2 | I am accused of substituting a model and cannot disprove it | The same receipt the requester checks me with is my defence | Built — non-repudiation is symmetric, and this is under-sold |
| P3 | My refusal is invisible or reads as a fault | Refusal as a first-class terminal state, distinct from failure | Specified in #1331/#1332 (`policy_denied` before dispatch vs `backend_error`); not built |
| P4 | I hold strangers' prompts in memory and possibly logs | Digest-only records; explicit non-retention | Partly — the record layer discards bodies; the *runtime* still sees plaintext |
| P5 | The workload harms my machine | Isolation and resource bounds | Out of scope for the record layer |
| P6 | I served honestly and have no durable proof of what | The receipt, with the requester's commitment inside it | Half — node side exists, requester side does not |
| P7 | A dispute becomes my word against theirs | Both commitments in one record, in a log neither controls | Not built |
| P8 | I spent electricity and hardware time with no record of how much | Consumption in units, bound to a signed request (§6) | Not built |

**Six of these eight are answered by the same records the requester already relies on** — but only
if the requester is bound into them. Today the record is unilateral: the node signs an account of an
exchange it describes alone. That asymmetry is why the provider side reads as unaddressed.

### 2.4 What the coordinator fears

The coordinator resolves the model, plans the topology, picks peers and layer ranges, and holds the
only global view of a split run. It has the most exposure and the least evidence.

| # | Fear | Evidence that would address it | Status |
|---|---|---|---|
| C1 | I route work to a node not running what it advertises | An admission-time check on the same record the node produces afterwards | Partly: owner-allowlist trust policy exists. Advertised admission state is coarse availability, deliberately not evidence |
| C2 | I am blamed for a node's behaviour because I chose it | The routing decision recorded as a decision | **Not built** — a topology is a serialized structure with no signature and no issuer |
| C3 | I cannot show which node held which layers | A signed commitment binding a topology to the request that ran on it | Correlation exists (`topology_id`, `stage_id`, `stage_index`, `run_id`, `request_id`, `session_id` travel with every stage message); **binding does not** |
| C4 | A stage substitutes weights mid-run | Per-stage artifact digests committed per request and verified | Half-present: stage config already carries `manifest_sha256` and `source_model_sha256` — **claims by the stage**, not verified evidence, and no record consumes them |
| C5 | I see everything, and that is a liability | Bounded, recorded knowledge at the boundary I own | Not built; gateway ingress sees complete requests |
| C6 | Disputes land on me and my view is not evidence | Observation point in every record | Enumerated in #1331; not yet produced |
| C7 | I exclude a node and cannot show why | Admission refusal sealed with its constraint basis | Not built |

**The seams as they exist today** *(read from a checkout dated 2026-08-11 — please correct anything
that has moved)*: the topology is already a structured object with stable ids, per-stage layer
ranges and load modes; a correlation spine already threads run/request/session/topology/stage
identity through the wire protocol; per-stage artifact digests are already carried but asserted
rather than verified; and execution ordering is already modelled with epochs and a staleness
ordering. **Everything a commitment would need to cover already exists as data. What is missing is
that nothing signs it.**

### 2.5 What the third party fears

| # | Fear | Evidence | Status |
|---|---|---|---|
| T1 | I cannot check without the mesh's cooperation | Offline verification from the record alone | Largely built; witness checking necessarily needs a network |
| T2 | I cannot tell where in the topology this was made | Observation point in the record | Enumerated, not produced |
| T3 | I cannot establish what the rules were at the time | Constraint-set pinning [forthcoming revision] | Not built here |
| T4 | The record is internally valid and describes a fiction | Identity binding plus registration to a log outside the producer's control | Partly specified, not built |
| T5 | I cannot tell a failed check from one that never ran | The three-state discipline, everywhere | Stated; enforcement is per-implementation |
| T6 | I cannot tell when this was registered versus when it happened | Registration policy and achieved latency in the record (§8) | Not built |

Requester and provider can settle most disputes bilaterally. The third party cannot participate in
that exchange at all, which is why witnessing, observation point and constraint pinning are not
refinements for them — they are the whole of what makes a record usable.

### 2.6 Adversaries in scope

A **dishonest node** (advertises one model, serves another; fabricates or replays receipts; forks its
history per audience; over-reports consumption). A **dishonest requester** (submits harmful work then
denies authorship; disputes a correct answer; replays a signed answer as fresh). A **passive
observer** (records are digest-only, but low-entropy inputs remain vulnerable to dictionary attack —
say so wherever digests are exposed). A **later-arriving third party**, not an adversary but the
reason evidence must be portable.

### 2.7 Explicitly not defended against

- **A node operator reading the prompts they serve.** Plaintext is in their RAM by construction.
  **On a split run this gets worse**: intermediate activations cross node boundaries in the clear, so
  requester state is resident on every stage host, and the coordinator additionally sees complete
  requests at ingress. R9 multiplies by the number of strangers in the topology.
- **Correctness or quality of output.** A faithful record of a wrong answer is a correct record.
- **A compromised host signing true-shaped statements about false events.** A signature authenticates
  a statement; it does not make it true. This is the permanent floor.
- **Coordinator/node collusion** absent registration to a log outside both parties' control.
- **Traffic analysis and timing side channels.**

---

## 3. Assurance classes

Classes rather than one ladder, because a single ladder would imply orderings that are not true: a
node can be strongly identified and behaviourally unchecked, or TEE-attested with no mutual
commitment.

Every rung carries three states that never collapse: **`absent`**, **`present-unverified`**,
**`checked`** (whose verdict may be *failed*). For credential-shaped evidence, #1331's richer set —
`missing / present-unverified / verified / expired / revoked / invalid` — is better and should win.

These classes are a deployment-level reading of the published composition model (slots CAN / WHO /
WHAT / AUDIT; assurance tiers *self-attested* and *anchored / third-party-verifiable*), not a
replacement for it. Class A is AUDIT plus those tiers, with **A3 being the anchored tier**. Class C
is WHAT-profile evidence. A4 and Class E have no upstream counterpart and are described here as
deployment properties.

### Class A — Record integrity

| Rung | Establishes | Does not establish | Status |
|---|---|---|---|
| A0 Unrecorded | Nothing survives | — | — |
| A1 Recorded | Signed commitments to request and response bytes | Who the node is; that computation occurred | Built |
| A2 Chained | Order and completeness within one node's history | That this is its only history | Built |
| A3 Registered | The record, or a digest of it, is registered to a Transparency Service, yielding a **Receipt** — existence and content-at-registration are checkable by a party who trusts neither the node nor its operator | That the *log* is honest; a single log can still show different views to different readers | Chaining built; registration missing |
| A4 Witnessed | The log's own checkpoint is independently co-signed, or the same commitments are registered to more than one independently operated log — so the log cannot equivocate either | That any witness is honest — only that equivocation now requires collusion | Not built |

> **Three things, deliberately not merged.** *Registration* is the act of submitting a Signed
> Statement. A *Receipt* is what the service returns — a signed inclusion proof. *Witnessing* is a
> separate party co-signing the log's checkpoint so the log cannot present different views to
> different readers. A perfectly good receipt from an unwitnessed log is A3, not A4. This document
> avoids "anchor" as a verb: it is not the vocabulary of the relevant RFCs, and it collides with
> *trust anchor*, which means a root of trust rather than an act of publication.

### Class B — Identity

| Rung | Establishes | Does not establish | Status |
|---|---|---|---|
| B0 Anonymous key | Internal consistency | Which node or owner | — |
| B1 Self-attested | A stable issuer | Any binding to a node or accountable owner | Built — current prototype |
| B2 Owner-delegated | Receipt key → scoped delegation → owner key → ownership certificate → same node | That signing happened *on* that machine; a software key remains exportable | Specified in #1331 |
| B3 Hardware-bound | Non-exportable key bound to measured hardware | That the measured program is correct | Reserved |

### Class C — Execution

| Rung | Establishes | Does not establish | Status |
|---|---|---|---|
| C0 Claimed | The node states a model and runtime | Nothing — a claim is not evidence | Built (labelled as claim) |
| C1 Artifact-bound | The claimed bundle resolves to content-addressed digests within a declared equivalence class | That those bytes served *this* request | Partly (step 2) |
| C2 Behaviourally checked | Output consistent with the claimed model — by **replay spot-check** (C2a) or **statistical fingerprint** (C2b) | Certainty. Each form fails differently; see below | Not built (step 4) |
| C3 Execution-attested | A measured environment loaded those artifacts and produced this output | That the measured program is honest | Not built (step 5) |

> **C2 has two forms, and the cheaper one is under-discussed.**
>
> **C2a — replay spot-check.** A receipt already commits the request digest, generation parameters,
> execution-bundle identity and runtime. Anyone holding the weights — an auditor, a user, a dispute
> process — has everything needed to re-run the request and compare. At temperature 0 with a pinned
> seed that comparison is *exact* rather than statistical, it needs no new cryptography, and it needs
> no access to intermediate activations. For a network where the disputed question is "did this node
> run the model it claimed," this is both cheaper and sharper than fingerprinting.
>
> Its precondition is that the digested bytes are deterministic — which is exactly the digest-domain
> problem in §11: a response digested after a normalizer that mints wall-clock-bearing identifiers
> changes every run for identical model output. Replay is unavailable until a record commits to a
> reproducible domain, which is one more reason to name the domains explicitly.
>
> Its limit is **hardware class**. GPU reduction order is not deterministic across different silicon,
> so a legitimate node can fail an exact comparison for reasons unrelated to honesty. Within a
> hardware class a mismatch is strong evidence; across one it is grounds to investigate, never a
> verdict. A mesh is heterogeneous by definition, so this must be stated wherever the mechanism is
> offered.
>
> **C2b — statistical fingerprint.** Locality-sensitive hashes over intermediate activations. It
> tolerates hardware variance, which is what replay cannot, and pays for that with probabilistic
> answers and a dependency on the runtime — only the inner loop holds activations.
>
> **The division of labour:** replay within a hardware class, fingerprints across one. And the general
> rule underneath both — **exact digests carry non-repudiation; fuzzy fingerprints carry behavioural
> identity.** Conflating them produces a system that either claims certainty it lacks or fails
> constantly on legitimate variance.

### Class D — Mutuality

| Rung | Establishes | Does not establish | Status |
|---|---|---|---|
| D0 Unilateral | The node's account of the exchange | That the requester agrees; anything about who asked | Built — current state |
| D1 Client-nonced | Freshness — no precomputation or replay | Who the requester is | Not built; the header is accepted, nothing sends it |
| D2 Bilateral | Both parties bound to the same exchange | That either is honest — only that neither can disown what they committed | Not built |

> **These map onto a vocabulary the record format already defines** [forthcoming revision]:
> `assurance.cross_party_rung`, ordered `unilateral_fallback` < `acknowledged_receipt` <
> `full_bilateral`, carried alongside a `cross_party` evidence block, with the rule that a producer
> **MUST NOT** claim a rung its evidence does not support and a verifier derives the rung from the
> block's own bytes. D0 is `unilateral_fallback` and D2 is `full_bilateral`; `acknowledged_receipt`
> sits between them.
>
> One honest mismatch: **D1 (client-nonced) is not a value on that ordering.** Freshness and
> exchange-completeness are different questions — a unilateral record can carry a client nonce, and a
> fully bilateral one can lack it. Treat D1 as a separate property rather than forcing it onto the
> rung, which is the same discipline the format applies when it keeps log custody and exchange
> evidence on separate axes.

### Class E — Confidentiality

| Rung | Establishes | Does not establish | Status |
|---|---|---|---|
| E0 Plaintext to provider | Nothing | — | Current state of every public mesh |
| E1 Not retained | Bodies discarded after commitments; only digests persist | That they were not read while resident | Built at the record layer |
| E2 Enclave-confidential | The operator cannot read inputs on their own machine | Side channels; a compromised enclave | Not built |
| E3 Cryptographically confidential | The operator computes without observing | Practicality at current cost; integrity against a malicious server | Exploratory (#1346) |

### 3.1 Where the classes interact

The classes are independent except in one place: **advancing confidentiality reduces achievable
execution assurance.** Behavioural checking works over intermediate activations; under E3 those are
ciphertext, and the client cannot reveal its inputs to a third party without defeating the purpose.
Standard FHE is malleable and gives no integrity against an actively malicious server — #1346 says
so directly.

The consequence is not that confidentiality is a bad trade. It is that **under E3 the record is the
only handle left**: with no ability to inspect outputs and none to fingerprint behaviour, execution
identity and the signed receipt carry the entire weight. A confidential mesh needs the record layer
more than a plaintext one does.

---

## 4. Populating mutuality: the mechanism already exists

Class D is empty in the mesh deployment, and filling it is the change that converts this from a
requester-side audit tool into a mesh trust model. **The mechanism is specified; the mesh case would
be its first deployment.** The bilateral attestation companion draft fixes four moves:

1. **Request attestation** — the requesting party signs the action *and its material terms* before
   the performing party acts.
2. **Constraint evaluation** at the boundary where the action takes effect, not at the transport
   edge, where *verification gates execution*.
3. **Action attestation** — referencing the request attestation by digest, recording constraint
   results and the disposition.
4. **Acknowledgment** — each party acknowledges the other's attestation.

And three obligations that matter here [forthcoming revision]: **constraint-set pinning** (the action
attestation binds a digest of the constraint set in force at evaluation time, so nobody can silently
re-parameterize what they were obliged to check); **completeness** (a result for *every* constraint
in the pinned set — pass, fail, or not-evaluated with a reason — so an omission is verifiable rather
than silent); and **graceful degradation** (a party whose counterpart cannot produce request
attestations may proceed unilaterally with a reduced-assurance indicator, and "a fully-bilateral
record and a degraded record are never confusable").

#1233 already half-states the hook: *"the client contributes the nonce and request digest so the node
cannot fabricate or replay a request."* No client sends one today.

**No intermediary is needed for this.** An inference exchange is synchronous by construction — the
client holds the connection while tokens stream — so both parties are reachable at the moment
signatures are exchanged. A client that disconnects before acknowledging leaves a *half-completed
exchange*, which the draft already treats as a defined state rather than an error: the node's half
stands on its own, and the acknowledgment can complete on reconnect.

**What this buys**: R3 becomes real anti-replay. P3 is answered by the draft's own decline
semantics — *"a declined request is not a failed exchange; it is a completed exchange with a decline
disposition"* — and a bilaterally-acknowledged decline is evidence, to an auditor who trusts neither
party, that boundary enforcement works. P6/P7/P8 give the provider durable proof of what was asked
and what it consumed. And P1 improves, with an important caveat.

### 4.1 What a requester signature actually buys — the honest version

A self-held requester key is an **identifier**, not a vouched identity. It gives continuity, and
therefore pseudonymous accountability: an abusive request is attributable to *a stable identity that
asked*, not to the machine that served. That is a large improvement. It is not attribution to a
person.

The bilateral draft is stricter than that: it requires binding to a **verifiable organizational
identity** — "a credential chaining to a root of trust the relying party accepts" — and says
first-use acceptance "MUST NOT be treated as conformant." So a bare self-held key is explicitly
non-conformant with that profile, however useful it is operationally.

Which makes this a spectrum that the *deployment* resolves, not the mechanism:

| Deployment | What the requester key is rooted in | What attribution buys |
|---|---|---|
| Open public mesh | Nothing; a self-held key | Continuity and pseudonymous accountability |
| Membership-gated (§9.1) | Membership an operator granted, with a signed binding to node identity | A member the operator can name and eject |
| Corporate fleet | The organization's identity provider | An employee, under existing governance |
| Cross-organization / regulated | A credential chaining to a root the relying party accepts | The conformant case the draft describes |

**Strangers can become verified participants without changing the mechanism.** The same signed
commitment carries more weight as its key acquires a root. That is a deployment progression, not a
protocol change.

### 4.2 Where this sits in the composition model

For precision, since it is easy to over-claim: a bilateral record fills the **cross-party leg**. It
does **not** fill CAN — CAN asks whether *a declared authority issued a bounded grant* covering the
action, which requires an issuer distinct from the actor, holder-binding of the subject agent, and
declared scope dimensions. Nor WHO, which requires a *named accountable human*. **A mesh deployment
fills WHAT and AUDIT, carries a cross-party leg, and leaves CAN and WHO deliberately unpopulated** —
and the composition model explicitly allows that: not every action populates every slot.

### 4.3 Also required

- **Split inference.** Each stage signs its own generation record; the coordinator's receipt cites
  them by typed reference and commits to execution order. Without it, a split request is as opaque as
  the single-node case, multiplied by the strangers involved. This holds identically for the
  two-stage encrypted case in #1346.
- **Cross-layer linkage.** An agent's action record and the inference record it acted on are
  correlated by timestamp only. They must be joined by typed reference, or "the agent acted on this
  inference" remains narration.
- **Terminal-state honesty.** Refusal before dispatch, refusal after dispatch, backend error,
  cancellation and incomplete observation are five different facts.

---

## 5. Confidentiality, and the HEIR question

### 5.1 The limit worth stating loudest

**A record does not protect a requester's input from the provider.** Without an enclave the prompt is
plaintext in the operator's memory. Digest-only records protect the evidence trail, not the runtime.
On a public mesh this is the dominant residual risk, and no rung in Classes A–D reduces it.

### 5.2 What FHE changes, and what it does not

It changes E0 to E3 for the compiled path: the operator cannot read prompts, outputs, KV state or
activations. It does not change identity, non-repudiation, witnessing or mutuality — and it costs
behavioural verification (§3.1). It also breaks things that quietly assume plaintext: server-side
templating, tokenization, moderation, stop-sequence detection, streaming, tool-call parsing, and
**usage accounting based on plaintext tokens** (§6).

### 5.3 Engage now, build later

Against building now: published results include ~100 seconds for BERT-Base at 128 tokens on one GPU,
and under 100 seconds *per generated token* for an 8B model; it is a separately compiled backend that
reuses almost none of the existing serving path; parameter selection needs specialist review, and an
amateur confidentiality claim is worse than none.

For engaging now: the identity work it forces is needed anyway (§11); confidential batch workloads
are exactly the segment that can tolerate the latency; and designing the record in beats retrofitting
it.

### 5.4 Four rules that make the record future-proof

1. **The record commits to bytes, not meaning.** A digest over ciphertext behaves identically to a
   digest over plaintext, so an encrypted exchange needs **no format change**: the receipt commits to
   encrypted request bytes, client nonce, evaluation-key identity, execution-bundle digest, and
   encrypted response bytes.
2. **Execution identity is a bundle, not a model** (§11).
3. **Confidentiality is a declared property of the exchange, never inferred.** A verifier must not
   deduce confidentiality from an absent payload.
4. **Disclosure needs two facets, not a longer list.** Today disclosure is effectively two-valued —
   withheld by absence, revealed by presence plus a digest-match verdict. Encrypted and sealed
   execution break that, but adding one value per mechanism (`ciphertext`, then `sealed`, then
   `secret-shared`) collapses two questions into one label. The two are: **what form is the
   disclosable artifact in** (`absent` · `plaintext` · `ciphertext` · `sealed` · `shared`) and **who
   can disclose it** (`recorder` · a named key or policy holder, by reference · `nobody`). Familiar
   labels then derive rather than being enumerated, and a homomorphic-encryption implementer adopts
   the format unmodified because their case is one combination rather than a special value.
5. **Under encryption only the client can commit to plaintext.** A node that sees only ciphertext can
   digest only ciphertext. So a confidential exchange has two commitments no single party can
   produce — and the only structure carrying both is the mutual one in §4. Confidentiality is an
   argument *for* bilateral records.

---

## 6. Metering: what a record should count, and what it must not price

Both parties need units: the provider spent electricity and hardware time (P8), the requester needs
to know they were charged for no more than they authorized (R11).

**Two facts, not one.** The **authorization bound** travels in the requester's signed commitment —
maximum tokens, steps or depth, deadline, any model constraint. The **consumption** travels in the
node's receipt — input and output token counts, wall-clock and compute time, steps taken, terminal
state. Consumption exceeding its bound is then a **limit event**: visible, attributable, disputable.
Its rigorous form already exists as constraint-set pinning with a result for every constraint
[forthcoming revision]; metering fields are one kind of constraint under that discipline, not a
separate mechanism.

**Price stays out of the record.** No currency, rate, invoice or settlement. A record carrying a
price encodes one market's design, and internal fleets, research networks and public meshes will
price identically metered work differently or not at all. Metering belongs in the record; pricing
belongs to whatever commercial layer a deployment chooses, and this document proposes none.

**Two limits.** A metered fact is only as trustworthy as the party counting it — consumption is a
*claim* until some higher class checks it. And under E3 plaintext token counting is impossible, so
confidential metering must be structural (circuit evaluations, ciphertext operations) rather than
semantic. The record must say which unit it counted.

---

## 7. History, and why not a score

Requesters want a sense of a provider's track record, and providers want the same about requesters.
The obvious implementation is a reputation score, and it is the wrong one: someone has to compute it,
which makes that party the arbiter of who gets work — a governance burden, a gaming target, and a
capture point for a system whose premise is that no party need be trusted.

Mesh-LLM has already reached this conclusion independently. `docs/NODE_REP.md`: local reputation is a
routing-safety mechanism, *"not a mesh trust system… not gossiped, not persisted as a network-wide
score, and not used to prove peer identity, model honesty, owner attestation, or release
provenance,"* with cross-node reputation deferred until there is a reviewed design.

The constructive question — what a relying party may compute over registered records, and what
assurance ordering that computation must respect — is being worked separately as agent reputation
predicates, and is deliberately out of scope here. What belongs in a threat model is the negative
result: **evidence is presented; policy decides; and nobody is the authority for the computation.**

---

## 8. Registration, receipts, and witnessing

### 8.1 Required of the claim, not of the software

A hash chain proves order within one history; it cannot prove that history is the only one a node
keeps. Only publication to a log the node does not control closes that gap.

A prototype sensibly ships with registration **off by default** — #1332 calls the act *anchoring*, and the two words mean the same operation here — and that default is correct. The reconciliation
is that registration is required *of the claim*: a node that has not registered is at A2 and must render
as A2. What a conformant implementation needs is the **capability** — able to register, to more than
one log, with accurate status — not the act.

### 8.2 More than one log, and why it is structural

If one organisation runs the only log an ecosystem uses, every property the record claims rests on a
party that is not neutral by construction, however well it behaves. Two independently operated logs
holding the same commitments means no single operator can rewrite or withhold a history without
visible disagreement.

Any public instance named in documentation should be *an* instance, never a hardcoded default, and
an implementation that cannot be pointed at a different log is not conformant. **An operator inside
this ecosystem running a second log would be worth more than any amount of neutrality language.**

### 8.3 Deferred registration: accumulate locally, register periodically, prove on demand

Records accumulate in an append-only Merkle accumulator maintained locally; its **peaks** are
published on a schedule. Inclusion of any individual record is proved *later, on demand*, against an
already-witnessed peak.

Two honesty requirements follow. The gap between an event and its witnessing is a **rewrite window**,
so the record should carry the registration policy and achieved latency, and a verifier should weight a
record inside that window differently. And registration must be **scheduled, not on-demand** — a node
that registers only when asked can decline to register the record it does not want on a log.

### 8.4 What registration costs, and what it exposes

**Latency added to a request: none.** Registration is off the request path — records seal locally, the
accumulator advances locally, peaks publish from a background queue. #1332 already requires this
independently. The cost is paid in *freshness*, not latency.

**Volume: one operation per batch.** A node serving thousands of requests publishes a handful of
peaks.

**What a log operator learns:** digests. Never prompts, outputs, model identities or payloads. It can
infer coarse metadata — that a node publishes, roughly how often. Because only peaks ship, that is
batch cadence rather than request timing. A real exposure, and a small one.

| Risk | If the log were a hard dependency | Why it is not one here |
|---|---|---|
| Availability | Inference stops | Never on the serving path; an unreachable log means the record renders as A2, not that a request fails |
| Censorship | A node cannot reach the registered tier | No log is named, any can be used, and registering to more than one makes refusal visible rather than fatal |
| Equivocation | Records rest on a log that shows different views to different readers | Witnessing — independent co-signature of the checkpoint — is the named mechanism; a second operator makes disagreement visible |
| Metadata | Cadence and volume leak | Peaks only, on a schedule — coarse by construction |
| Key compromise at the log | Historic receipts untrustworthy | Receipts evidence *registration*, not truth; the record's own signature and chain survive |
| Silent misreporting | "Anchored" claimed on submission alone | Distinguished states — pending, submitted, anchored, rejected, failed — which #1332 already requires |

**Summary: registration is not a meaningful runtime dependency.** The residuals are the unwitnessed
window, coarse cadence metadata, and the governance question of *whose* log — answered by insisting
the answer is "more than one."

---

## 9. Deployment profiles

### 9.1 The membership-gated case, which is not a stranger case

The desktop platform that vendors mesh-llm as an optional build feature and runs an in-process node —
*"relay-gated shared AI compute (mesh-llm over iroh); members pool GPUs, agents consume via a local
OpenAI-compatible endpoint"* — is a materially different trust posture for the same code. Members
publish signed discovery notes carrying a signature binding the member to the advertised node
identity, and admission is pinned to the fix that prevents a non-member with a leaked invite token
drawing on inference streams.

| | Standalone node | Membership-gated |
|---|---|---|
| Requester | A stranger with a self-held key | A member an operator admitted and can eject |
| Identity binding | Key continuity only | Member-signed note binding member to node identity |
| Attribution buys | Pseudonymous continuity | A named member inside an operator's governance |
| Confidentiality exposure | Whatever the prompt is | **Higher** — prompts are workspace conversation and the operator sharing a GPU is a colleague |

One mechanism, two postures, no protocol change between them.

### 9.2 Floors per class

| Profile | A | B | C | D | E | Notes |
|---|---|---|---|---|---|---|
| **Membership-gated** | A2 | B2 | C1 | D2 | E1 | Keys have a root; the operator can act on a finding |
| **Internal fleet** | A1 | B2 | C1 | D1 | E1 | Identity boundary already exists; admission control is the main use |
| **Research / inter-department** | A2 | B2 | C1 | D2 | E1 | Attribution matters more than confidentiality |
| **Public mesh** | A4 | B2 | C2 | D2 | E1 | Best-effort attestation covers most of what users ask for; **E0 is the residual and E2/E3 the only real answer** |
| **Confidential / regulated** | A4 | B3 | C3 | D2 | E2–E3 | Every claim checkable by a party trusting neither side; batch latency acceptable |

---

## 10. Vocabulary rules

1. **Three states, never two.** `absent`, `present-unverified`, `checked`. A verdict of *failed* is a
   form of `checked` and is worth more than silence.
2. **No silent upgrade.** A fallback never inherits the label of what it replaced. A node-generated
   nonce is not client anti-replay evidence.
3. **Claim ≠ evidence.** An advertised model name, a configured manifest, a routing decision, or a
   consumption count is a claim. The record says which it holds.
4. **Build provenance ≠ runtime integrity.**
5. **Observation point is part of the claim.** A gateway observation is not evidence about the
   serving host.
6. **A reference is not a proof.** A correlation header points at evidence; it is not evidence.
7. **Disclosure is two fields, not one enum** (§5.4).
8. **One normative vocabulary.** Assurance vocabularies now exist in #1332 and #1346 and in this
   work. They describe overlapping axes and will diverge. A convergence proposal is in the companion
   document; the question of where the normative source should live is open.

---

## 11. What this implies for the record format

The core stays domain-neutral; anything naming tokens, prompts, models, GPUs or ciphertext parameters
lives in a registered profile. Four things are candidates to generalise, because each is
domain-neutral:

- **Execution-bundle identity.** What a record commits to is not "a model" but an execution bundle —
  compiler revision, numeric approximations, packing, decoding behaviour, stage order. #1346 derives
  exactly this; the same field covers container digests, tool binaries, kernel versions and TEE
  images.
- **Multiple witnesses**, with verifier policy for how many and whose.
- **Disclosure as two fields** (§5.4).
- **Authorized-bound versus performed-consumption** as a general pair, unit-agnostic.

Everything else stays in a mesh profile: token counts and units, generation parameters, model package
specifics, route descriptors, nonce source, FHE parameters, fingerprint confidences.

---

## 12. Open questions

1. **Does §2.3 match what node operators actually tell you?** It is the half with the least evidence
   behind it — reasoned, not researched. If your list differs, the section should be rewritten rather
   than patched.
2. Is the request commitment in §4 something a mesh client can send today, and where in the client
   does a request-signing step belong?
3. Which profile in §9.2 has to work first? The floors differ enough to change build order.
4. For split inference, does the coordinator hold enough context to commit to stage order, or must it
   be assembled from the stages?
5. Where should a single normative assurance vocabulary live — mesh-llm's documentation, the record
   format's specification, or both with one normative source?
6. **Would you operate a Transparency Service?** A second independently operated log is the difference between a
   neutral record and one whose history rests on a single organisation.
7. Is scheduled registration with on-demand inclusion proofs compatible with how nodes come and go —
   particularly a node offline when its peak is due?
8. Does metering-without-pricing fit how you expect capacity sharing to be settled?

---

*Offered for discussion. Where this says "not built," that describes today and is not a commitment
from anyone. Nothing here asserts adoption by any party.*
