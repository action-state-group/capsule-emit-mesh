# Converging the assurance vocabularies

A proposal, offered for argument. Steven Mih · 2026-08-16.

Three vocabularies now describe overlapping ground across
[#1331](https://github.com/Mesh-LLM/mesh-llm/issues/1331) /
[#1332](https://github.com/Mesh-LLM/mesh-llm/issues/1332),
[#1346](https://github.com/Mesh-LLM/mesh-llm/issues/1346), and the trust model in this repository.
None is normative and they are already inconsistent. Vocabulary divergence is worse than format
divergence because it stays invisible until two records disagree about what "verified" meant.

> **Specification revisions referenced.** The disposition vocabulary quoted below is from the
> published `draft-mih-scitt-agent-action-capsule-02`. Successor revisions are in review and are
> marked **[forthcoming]** where relied on.

---

## 1. Vocabulary A — the platform and plugin vocabulary

From #1331 and #1332. Note the assurance-label list is in **#1332**; #1331 carries the lifecycle,
identity and observation vocabulary.

| Group | Values | Source |
|---|---|---|
| Identity mode | `self_attested` · `owner_delegated` · `owner_delegated_required` · `hardware_delegated` | #1331 |
| Identity-evidence status | `missing` · `present-unverified` · `verified` · `expired` · `revoked` · `invalid` | #1331 |
| Observation point | `gateway_ingress` · `serving_host_ingress` · `backend_dispatch` · `client_egress` | #1331 |
| Terminal state (host) | `completed` · `policy_denied` · `request_invalid` · `backend_error` · `transport_error` · `client_cancelled` · `timed_out` · `evidence_unavailable` / `internal_hook_failure` | #1331 |
| Assurance labels | `collector` · `api_boundary_observation` · `runtime_claimed` · `owner_binding_status` · `node_ownership_status` · `release_attestation_status` | #1332 |
| Claim source | `configured_claim` · `host_verified` · `unavailable` | #1332 |
| Receipt lookup state | `pending` · `complete` · `failed` · `incomplete` · `not_found` | #1332 |
| Evidence mode | `full` · `digest_only` · `sampled` · `disabled` | #1332 |
| Nonce source | `client_supplied` · `plugin_generated_fallback` | #1332 |
| Anchor state | `pending` · `submitted` · `anchored` · `rejected` · `failed` | #1332 |

## 2. Vocabulary B — confidential inference

From #1346.

| Group | Values |
|---|---|
| Receipt evidence | `self_asserted` · `tee_attested` · `cryptographically_verified` |
| Execution identity | `execution_bundle_digest` |
| Adversary posture | honest-but-curious · actively malicious |

## 3. Vocabulary C — the trust model

| Group | Values |
|---|---|
| Evidence class | Record integrity (A) · Identity (B) · Execution (C) · Mutuality (D) · Confidentiality (E) |
| Rungs | A0–A4 · B0–B3 · C0–C3 · D0–D2 · E0–E3 |
| Evidence state | `absent` · `present-unverified` · `checked` (verdict may be *failed*) |
| Disclosure | artifact form × disclosure capability |

---

## 4. Where they collide

1. **`self_attested` (A) and `self_asserted` (B) are one concept with two spellings.** Trivial to fix
   now; permanently irritating once either ships.
2. **B's triple spans three axes.** `self_asserted` is an identity statement, `tee_attested` an
   execution statement, `cryptographically_verified` a confidentiality one — or, if it means
   verifiable FHE, an execution-integrity one. As a single enum they read as a ladder, inviting the
   conclusion that a TEE-attested record is somehow more *identified* than a self-asserted one. It is
   not; they vary independently.
3. **A's assurance labels span two axes.** `collector` is a *role*; `api_boundary_observation` is a
   *vantage point*, which #1331's observation-point enum already says better; `runtime_claimed` is
   neither — it is an execution rung.
4. **Two terminal-state sets exist for the same facts**, one in host language and one in record
   language, with different words for the same five outcomes.
5. **A's evidence-status set is better than C's and should win.** `missing / present-unverified /
   verified / expired / revoked / invalid` distinguishes states that matter for anything
   credential-shaped: an expired delegation is not a missing one, and a revoked one is neither. C's
   three-state minimum is a floor, not a ceiling.

---

## 5. Proposal: five orthogonal axes

These diverged not through carelessness but because each was written for one job, and for that job
collapsing axes into one label was harmless. So the fix is a shape rule, not a naming preference:

> **Every value belongs to exactly one axis. A record carries one value from each axis it can speak
> to, and an explicit "not applicable" where it cannot.**

| Axis | Purpose | Proposed values | From |
|---|---|---|---|
| **1. Observation point** | Where the record was made | `gateway_ingress` · `serving_host_ingress` · `backend_dispatch` · `client_egress` | A, verbatim |
| **2. Recorder role** | What the recorder was to the exchange | `collector` (observed) · `participant` (a party) · `gate` (decided admission) | A (`collector`), generalised |
| **3. Evidence status** | Per individual claim | `absent` · `present_unverified` · `checked_passed` · `checked_failed`, plus `expired` · `revoked` · `invalid` for credential-shaped evidence | A, with C's insistence that `checked_failed` ≠ `absent` |
| **4. Assurance rung** | Per evidence class | `record_integrity` A0–A4 · `identity` B0–B3 · `execution` C0–C3 · `mutuality` D0–D2 · `confidentiality` E0–E3 | C, absorbing A's identity modes and B's triple |
| **5. Terminal outcome** | What became of the exchange | The record format's existing `verdict_class` vocabulary (§6) | Neither A nor new — already normative |

Carried alongside, and explicitly **not** assurance labels:

- **Disclosure** — artifact form (`absent` · `plaintext` · `ciphertext` · `sealed` · `shared`) ×
  disclosure capability (`recorder` · a named holder by reference · `nobody`). An undisclosable
  payload is not a better-assured one.
- **Operational evidence mode** — `full` · `digest_only` · `sampled` · `disabled`. This describes how
  much the recorder attempted, not how much anyone should believe; a downgrade is an explicit event
  with a reason.
- **Anchor status** — `pending` · `submitted` · `anchored` · `rejected` · `failed`, plus the achieved
  unwitnessed window.
- **Claim source** — `configured_claim` · `host_verified` · `unavailable`, kept as-is.

### 5.1 How existing labels land

The test of whether the scheme is real rather than merely tidier.

| Existing label | Axis | Value |
|---|---|---|
| `self_attested` / `self_asserted` | 4 — identity | B1 |
| `owner_delegated` | 4 — identity | B2 |
| `hardware_delegated` | 4 — identity | B3 |
| `owner_delegated_required` | *policy, not a label* | a deployment floor |
| `tee_attested` | 4 — execution | C3 |
| `cryptographically_verified` | 4 — confidentiality E3, **and** an execution claim only where the construction is verifiable FHE | splits across two axes |
| `collector` | 2 — role | `collector` |
| `api_boundary_observation` | 1 — observation point | `serving_host_ingress` or `client_egress` |
| `runtime_claimed` | 4 — execution | C0 |
| `owner_binding_status`, `node_ownership_status`, `release_attestation_status` | 3 — evidence status | one value each |

### 5.2 Two naming decisions, offered rather than asserted

- Adopt **`self_attested`** over `self_asserted` — it already appears in a milestoned specification.
- Keep **A's terminal-state words** as the host-side normative set, with the record-language
  interpretations documented as a mapping rather than a second vocabulary.

---

## 6. Terminal outcome: use what already exists

The record format already defines a verdict-complete `verdict_class` vocabulary, seeded with twelve
values and **registry-governed and open** — unregistered values are informational to a verifier,
never a rejection:

`executed` · `blocked` · `hitl_dispatched` · `denied` · `timeout` · `errored` · `engine_failure` ·
`deferred` · `needs_decision` · `expired` · `escalated` · `resolved`

Proposed mapping from #1331's host-side terminal states, offered for correction:

| Host state (#1331) | `verdict_class` | Note |
|---|---|---|
| `completed` | `executed` | |
| `policy_denied` (pre-dispatch) | `denied` | The pre-dispatch distinction is exactly what a collector cannot assert and a lifecycle hook can |
| `request_invalid` | `blocked` | Rejected before any dispatch |
| `backend_error` | `errored` | |
| `transport_error` | `errored` | With transport context recorded |
| `client_cancelled` | `expired` or a registered value | Cancellation may warrant its own registered value — worth a decision |
| `timed_out` | `timeout` | |
| `evidence_unavailable` / `internal_hook_failure` | *not a disposition* | These are observation outcomes about the record, not about the action. Keeping them off this axis is the point |

The last row is the substantive proposal: **what happened to the action and what happened to the
observation of it are different facts**, and collapsing them is how a system ends up unable to
distinguish "the action failed" from "we failed to watch it."

---

## 7. Rules that keep it converged

1. One spelling per concept, chosen once.
2. No label spans two axes; if it wants to, it is two labels.
3. Every axis has an explicit "not applicable / not supplied" value. Nothing is inferred from
   silence.
4. A fallback never inherits the label of the thing it replaced.
5. Adding a value to an axis is a specification change with a version, not a convention.

---

## 8. The open question

Where should the single normative source live — mesh-llm's documentation, the record format's
specification, or both with one normative source and one reference? This proposal takes no position
beyond insisting there be one, and that whichever document holds it names the other as derived.

*Offered as a proposal. Corrections to the mapping in §5.1 and §6 are the most useful form of
disagreement.*
