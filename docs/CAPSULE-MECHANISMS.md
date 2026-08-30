# How the capsule mechanisms work

*A "how the machinery works" companion. If [the verification chain](VERIFICATION-CHAIN.md)
answers "what does each link **prove**," this answers "what are the **moving parts**, and
— crucially — **where does my data stay?**" The plain-language version is
[Can you trust a stranger to run your prompt?](CAN-YOU-TRUST-A-STRANGER.md).*

The single most important thing up front: **your records stay on your machine.** The
mechanisms below are built so that a node can prove its history is honest **without ever
handing that history to anyone** — only tiny commitments leave, and only when you opt in.

There are four layers. **Layers 0–2 are entirely local.** Only Layer 3 sends anything
out, and what it sends carries no content.

```
  Layer 0   the local ledger        every capsule, one line, append-only   ── on your disk
  Layer 1   the local MMR           an append-only hash accumulator over it ── on your disk
  Layer 2   the signed checkpoint   you sign a commitment to the whole log  ── on your disk
  ─────────────────────────────────────────────────────────────────────────────────────
  Layer 3   the neutral witness     a log you DON'T run co-signs it         ── leaves (peaks only)
```

---

## Layer 0 — the local ledger (where the records actually live)

Every sealed capsule is appended to a local **`capsules.jsonl`** — one line per exchange,
**append-only**. The raw material — your prompt, the response, the model / quant /
hardware facts, the generation settings, the timing — lives **here, on the serving node's
own disk.** Nothing about a capsule leaves the machine at this layer. (A mesh node keeps
two such logs, the Python sidecar's and the Rust producer's; each is append-only per
node.)

## Layer 1 — the MMR (the append-only accumulator)

As each capsule is appended, it is also **pushed** onto a **Merkle Mountain Range
(MMR)** — a hash tree that only ever *grows*:

- Each capsule is a leaf. Leaves combine into **peaks** — perfect binary subtrees — and
  the set of **peak hashes** is a compact fingerprint of the *entire* log so far.
- Adding a leaf **never rewrites** an existing node; it only adds. That's what makes it
  *append-only* rather than a tree you could quietly re-shuffle.
- From the peaks the node can produce two kinds of proof, on demand:
  - an **inclusion proof** — "this capsule is in the log at this size" (the hash path
    from the leaf up to a peak);
  - a **consistency proof** — "this later state is an *append-only extension* of that
    earlier one" (nothing earlier was changed or dropped).

The MMR is still **entirely local** — it lives on the node next to the ledger. On its
own it proves order and inclusion *within the node's own view*; it becomes evidence to an
outsider only once a commitment to it is published (Layer 3).

## Layer 2 — the checkpoint (signing a commitment to the whole log)

Periodically — `maybe_checkpoint()` in the default wiring — the node cuts a
**checkpoint**: it **signs** (a `COSE_Sign1` `cll-checkpoint`) the MMR's current
**peak-list commitment** at a given `log_size`, carrying `prev_size` / `prev_commitment`
and a **consistency proof** back to the previous checkpoint.

In plain terms, a checkpoint is the node saying, under its own signature: *"here is a
commitment to my entire history through N entries, and it is an append-only extension of
my last checkpoint."* Checkpoints **chain**, so the sequence itself can't be forked
without the break showing. This is still **local** — a signed file on disk — until you
choose to publish it.

## Layer 3 — the witness (the only thing that leaves, and it carries no content)

**Opt-in, per witness URL:** the node `register_checkpoint()`s — it `POST`s the
**checkpoint** (not the records) to a neutral **SCITT Transparency Service** (a log it
does **not** operate; the default is `witness.agentactioncapsule.org`, but always *an*
instance, never the only one). The witness returns a **COSE Receipt** that anyone can
verify offline.

**What actually crosses the wire: the checkpoint's commitment — peak hashes and a
signature.** Never a prompt, never a response, never a model identity, never a payload.
The witness learns *digests* and *coarse cadence* (roughly how often you checkpoint) —
and nothing else. This is what makes a node's history **tamper-evident against something
it doesn't control** while keeping the history itself private.

---

## Checkpoint vs. push: the two grains of external anchoring

There are two ways you *could* anchor to a witness. They're not equal:

| | **Checkpoint-level** (the default) | **Per-record push** (available, demoted) |
|---|---|---|
| What's registered | one commitment to the **whole log** so far | **each record** individually |
| How often | once per checkpoint interval | once per exchange |
| What's disclosed | peak hashes only — **no payload** | a per-record digest each time |
| Cost | a handful of hashes per interval | one registration per request |
| Covers | your **entire history** to that point | just that one record |

**Checkpoints are the right grain** for "witness my history": one cheap registration
witnesses everything, with no payload disclosure. Per-record push is redundant if you
already checkpoint your log, heavier, and leaks more — so it's deliberately demoted.

## CPB — how a payload binds to its receipt

One more piece ties it together: **CPB (the CBOR Payload Binding)**. It makes a receipt
unambiguously *about this kind of payload and this record* — so a capsule can't be
re-pointed under a receipt that was really about something else.

The capsule is registered under a **payload class** — `mesh-inference-exchange` — in a
**machine-readable registry** that's vendored into the tools, with a **never-reject**
invariant: a verifier that hasn't seen a given class value degrades it *honestly*
(renders it as provisional/unknown) rather than failing closed or silently passing. CPB
is the typed glue between "what the payload is" and "the transparency receipt over it."

---

## Where the data stays local (the whole point)

| Thing | Where it lives | Who can see it |
|---|---|---|
| **Raw capsules** — prompts, responses, model/quant/hardware, timing, the full ledger + MMR | **on the serving node's disk** | only the operator — *unless they choose to disclose* |
| **Checkpoint commitments** — peak hashes + signature | published to the witness (opt-in) | anyone — but they're **hashes, no content** |
| **A disclosed bundle** — selected capsules + proofs, per-field sealed-vs-shown | handed to a counterparty **deliberately** | only whom you give it to; verified **offline** |
| **Existence + consistency** of your checkpoints | the public witness | anyone — proves your history is append-only, **reveals nothing about it** |

The design keeps the **data** home and publishes only **tamper-evidence**. The witness
can't read your prompts; it holds a commitment it can't forge. A counterparty sees only
what you put in a bundle. The public sees only that your history hasn't been rewritten.

## When you want to see *all* of it

Locally, the operator can inspect the **entire** ledger — every capsule, every field —
with `capsule-mesh view`. That's a **local privilege by design.** Nobody outside gets it:
an outsider gets commitments (from the witness — existence and consistency, no content)
plus whatever you chose to hand them in a bundle. "Seeing all of it" stays with the
machine's owner; what the system *publishes* is proof that the history is honest, not the
history itself.

---

*Next: [the verification chain](VERIFICATION-CHAIN.md) for exactly what each of these
links proves and by what mechanism (with RFCs); or [TRUST-MODEL.md](TRUST-MODEL.md) §8
for the registration/witness threat model in full.*
