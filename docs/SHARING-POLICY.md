<!-- SPDX-License-Identifier: Apache-2.0 -->
# Sharing policy

Every sharing decision a node makes is one of four, and every default keys on
**relationship** (counterparty in the window) — never on proximity, latency,
or any computed standing. Nothing here is a score, and nothing here ranks
anyone.

```
share:
  record_at_completion: counterparty | off            # default: counterparty (symmetric)
  history_segments:     counterparties | prospective | peers | off   # default: prospective
  adjudications:        deliver_to_subjects | off     # default: on
witness:                off | <url>                   # default: off
```

The policy object lives in `share_policy.SharePolicy`, sourced from this
process's own environment (`ADMISSION_POLICY_SHARE_RECORD_AT_COMPLETION`,
`ADMISSION_POLICY_SHARE_HISTORY_SEGMENTS`, `ADMISSION_POLICY_SHARE_ADJUDICATIONS`,
`ADMISSION_POLICY_WITNESS`) and declared in the `admission-policy` Rust
plugin's own `config_schema` (`plugins/admission-policy/src/share_policy.rs`),
so mesh's console renders the four switches under Configuration › Plugins with
the host's own controls. A node that has never touched any of the four env
vars is unaffected — the policy resolves to `None`, and every gate this
document describes never runs at all, reproducing the node's pre-existing
behavior byte for byte. Shipping this code does not, by itself, flip any
node's runtime behavior; turning the documented defaults on for a real
deployment is a separate, later release decision.

## The relationship gate (`history_segments`)

Every `record`, `correlation`, and `chain_segment` evidence request is
classified against this node's own ledger before it is answered
(`evidence_responder.classify_relationship`):

- **counterparty** — the caller's self-declared identity names a party this
  node holds a past exchange with.
- **identified** — an identity was declared, but matches no past exchange this
  node holds.
- **stranger** — no identity was declared at all.

Identity here is exactly as self-attested as everything else this vocabulary
already trusts a claim about (the caller supplies it out of band, e.g. an
`X-Mesh-Requester-Id` header) — this is an operator policy knob for
spam/scope reduction, never an access-control boundary. A stranger who lies
about being a counterparty still cannot produce a real capsule id or
correlation value it has no honest way to know, and gains nothing a
`peers`-tier operator would not have handed it anyway.

`history_segments` picks which relationships get an answer:

| tier            | counterparty | identified | stranger |
|------------------|:---:|:---:|:---:|
| `off`            |     |     |     |
| `counterparties` | ✓   |     |     |
| `prospective` (default) | ✓ | ✓ |     |
| `peers`          | ✓   | ✓   | ✓   |

A disallowed request is refused `not_authorized` — signed with this node's own
key, like every other refusal this door makes. `range` requests are
deliberately never gated by this switch.

## The record exchange at completion (`record_at_completion`)

**What:** when an exchange ends, each side pushes its own **sealed record** —
not a bundle, the one capsule — to the other's evidence door
(`POST /evidence/record-push`, `record_push.py`). The provider's half to the
requester; the requester's half to the provider.

**Why default on:** the record contains nothing the counterparty can't
already compute — they hold the response bytes, so both digests are theirs to
derive, and they know the identity from the marker and announcements. New
facts: the sealed-at time and the signature. Effect: a "both sides hold each
other's signed half" state becomes the default, and each side has its own
defence ("nobody can say I served something else"). This is double entry at
exchange time, to the one party who was there.

**Why not a bundle:** the bundle needs the inclusion proof and a covering
checkpoint, and at completion the record is not checkpointed yet — proof
arrives on the clock or on request (`chain_segment`/`correlation`).

**Symmetry rule:** a node with `record_at_completion: off` does not receive
the other side's push either (it can still ask — fetch-on-request is
untouched). Sharing is reciprocal by default; refusal is symmetric by
default. A push structurally malformed, or one that fails its own `verify()`,
is refused `request_malformed` before the policy gate even runs — the policy
question is only reached for a well-formed, self-verifying capsule.

**What this does not do yet:** trigger itself automatically when a real
exchange ends. The provider seals *after* the stream ends — wiring that
trigger needs a trailing completion frame or a follow-up plugin-stream
message from the host, a small upstream host seam sequenced after the
provider-side lifecycle events. `record_push.py` ships the complete,
independently-tested mechanism (sender, receiver, HTTP door, policy gate),
ready for that trigger once it exists — same shape as
`adjudication_delivery.py`'s `deliver_adjudication`/`handle_delivery`.

## History segments, briefly

A `chain_segment` answer proves *shape* — checkpoints across a range, receipts,
one consistency proof per link, and leaf counts per checkpoint by kind
(`exchange`, `exchange_twin`, `card`, `adjudication`, `ack`, `rebuttal`,
`close`, …). It never contains verdicts *about* the node; those live in other
logs and are delivered separately (see `adjudications` below). Coarsened by
default — per-checkpoint counts, no record ids.

## Adjudications (`adjudications`)

`deliver_to_subjects` (default on) delivers a sealed verdict to every node it
judges — both providers of a twin, always. The subject seals its **own**
record citing it: an ack, or a rebuttal if it disputes. This is delivery and
acknowledgment, never a computed standing, and the verdict capsule itself
never leaves the adjudicator's log — only a citation does.

## Witness

`witness` is a URL, or unset for off (the default). No default witness URL,
no network call, without an operator-supplied one.

## Three rules that keep this from becoming a score

1. **Filter, never rank.** Every switch here answers or refuses; none of them
   orders or weights a peer.
2. **Counts, not sums.** A `chain_segment` reports leaf counts per checkpoint;
   it never totals or averages anything.
3. **Relationship, never proximity.** Every default keys on whether this node
   has actually exchanged with the caller — never on latency, cache affinity,
   or any other convenience signal a router might otherwise reach for.
