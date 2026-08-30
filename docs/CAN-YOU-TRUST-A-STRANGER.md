# Can you trust a stranger to run your prompt?

*A plain-language guide. No crypto background needed.*

You have a laptop. Somewhere out on the mesh, a **stranger's machine** offers to run
your prompt — to do the AI inference and hand you back an answer. You've never met
them. You don't know whose computer it is, what's really running on it, or whether
the answer honestly came from the model they claim.

So why would you trust them with your question — and trust the answer?

Normally, you couldn't. You'd just have to take their word. **The whole point of a
capsule is that you don't have to.** A capsule is a *receipt* the machine hands back
with every answer — and it turns "trust me" into "check for yourself."

---

## The one idea: what they *say* vs. what you can *check*

There are two very different things here, and keeping them apart is the whole game:

- **What the machine *says*** — "I'm running Llama-3B, 4-bit, on an Apple M3." Anyone
  can *say* that. Words are free.
- **What the capsule *shows*** — a signed, time-stamped record of what *actually*
  ran, made **at the moment it ran**, that **you** can verify yourself — without
  calling the operator, without trusting a middleman, right in your own browser.

A capsule doesn't ask you to believe the stranger. It gives you something to
**check**.

---

## What you'd actually see

When the answer comes back, the receipt tells you, in plain terms:

- **What you asked** — your prompt.
- **Who ran it** — which machine (a stable name for it).
- **What was running** — the model, its "size/quality" setting (the quantization),
  and the **settings the answer was generated with**: the temperature, the top-p, the
  random seed, the length limit — the knobs that actually shape what comes out. Plus
  the graphics chip and memory it used, and how much work it took (the token counts).
  Everything that shapes an answer is in the receipt, not just the answer itself.
- **The answer** — and it's tied to that record, so it can't be quietly swapped for a
  different one.

And the key move: **you can re-check the receipt yourself, offline.** The record has a
fingerprint computed from its own contents. Change *any* detail — the model, the
answer, one word — and the fingerprint no longer matches. Your browser recomputes that
fingerprint from the record; nobody has to be trusted for it to add up.

---

## How sure can you be? (the honest part)

Not everything is equally provable — and a good receipt is honest about which is
which. Here's the ladder.

### ✅ Things you can be sure of — because you can check them yourself

- **The record wasn't changed after the fact.** You recompute its fingerprint; it
  matches or it doesn't.
- **The answer you're reading is the answer they signed** — not something swapped in
  later.
- **It can't be quietly rewritten later.** The machine's history is anchored to a
  neutral, public logbook that *it* doesn't control — so it can't secretly go back
  and change or delete what happened. (Not even we can. That's the point of it being
  neutral.)
- **Whether what ran matches what they advertised.** If the machine advertised "I
  serve Llama-3B" and then served something else, that **mismatch shows** — a promise
  you can hold them to, not just a claim they made.

### ⚠️ Things you *can't* be fully sure of yet — and the receipt says so, out loud

- **Who they really are.** The machine signs with a key it generated itself — a
  **consistent pseudonym**, not a verified real-world identity.
  *What you can still do:* confirm it's the **same machine every time** (the key stays
  constant across exchanges, so a good history can't be quietly inherited by someone
  else), and — if you need a real name behind it — prefer a machine that's part of a
  **vouched group**; the receipt shows whether it is one.
- **That the hardware is exactly as claimed.** The machine *reports* its own chip and
  memory; nothing yet forces it to *prove* that at the hardware level.
  *What you can still do:* **sanity-check that the claim is even possible** — a model
  of a given size and context length has to *fit* the memory it claims, so an
  impossible combination is a tell — and if the machine offers a hardware attestation,
  that upgrades the line from claim to proof.
- **Its track record.** One receipt is **one data point**, not a history.
  *What you can still do:* **ask for more** — a machine can hand you a bundle of its
  past receipts to inspect, and the neutral logbook shows how long and how consistently
  it's been anchoring. One exchange becomes a history you can actually read.

The receipt never dresses these up as green checkmarks. It says "we don't yet know
who asked," "self-attested," "not anchored yet" — plainly. **A receipt that admits its
limits is worth more than one that claims everything is fine.**

---

## A worry worth naming: "what if they swap the model?"

It's the classic one: a machine advertises a big, high-quality model, then quietly
runs a smaller, cheaper one. Can they?

**At the receipt level, the model name is their claim.** The capsule records the model
they *say* they ran (and, when the machine offers it, a reference to the exact
package), but it does not yet *cryptographically* prove the actual weights that ran. A
determined liar controls what they write down.

**But the receipt hands you the facts to catch them:**

- **The clock.** The receipt seals **how long it took** (`latency_ms`) right next to
  the claimed model and hardware. A 70-billion-parameter model can't answer in the
  time a 3-billion one does on the same laptop — a "big model, tiny time, modest GPU"
  receipt is self-contradictory on its face.
- **The behaviour.** A smaller model *answers* differently. The app-level checks below
  — compare against other machines running the same model at the same settings — exist
  exactly for this.

So the honest shape is: **the capsule doesn't stop a swap by itself; it makes one hard
to hide.** The claim goes on the record — signed, time-stamped, sitting beside the
timing and the settings that all have to be consistent with it. A future hardware- or
weights-level binding is what would turn "hard to hide" into "impossible."

---

## Beyond the receipt: what apps can build *on top*

The capsule is the **solid floor** — a small set of signed facts you can check
yourself. It deliberately doesn't try to judge everything. But once you have that
floor, an **app** (your client, a marketplace, an auditor's tool) can add smarter
checks *on top* — not baked into the record, but **unlocked** by the evidence in it:

- **Does the behaviour match the claim?** The receipt says the quality setting was,
  say, `Q4_K_M`, and records the exact generation settings (temperature, seed, and so
  on). An app can check whether the answer's *quality and behaviour are consistent*
  with that setting — and with **other machines serving the same model at the same
  setting**. A node claiming a high-quality setting but behaving like a heavily
  cut-down one is a flag you can raise, using the receipt's own recorded facts.
- **Do independent machines agree?** Because the receipt records the **seed and
  temperature**, an app can send the *same* prompt, pinned to the same settings, to
  several machines claiming the same model — and compare. Consistent answers build
  confidence; an outlier stands out.
- **Statistical fingerprints.** More advanced tools can compare a machine's outputs
  against a known fingerprint of the claimed model (issue #1233 calls this "step 4") —
  a *confidence* signal that rides alongside the receipt as a typed reference, not a
  verdict.

The pattern is always the same: **the capsule gives you checkable facts; apps turn
those facts into higher-level confidence.** The floor stays small and honest; the
smarts live above it, where anyone can build them — and every one of them still traces
back to evidence you could check yourself.

---

## So how does trust actually build?

It starts at **zero** — a stranger is, by definition, unknown. And it grows on things
you can **check**, never on things they **say**:

1. **The first exchange** rests on the two things a stranger can offer with no shared
   history: what *this* receipt proves, and the neutral public logbook behind it.
2. **Over many exchanges**, the machine builds an **auditable track record** — every
   job it ran, each one witnessed. Now you're not judging a stranger; you're judging a
   history you can inspect. Trust deepens *on evidence*.
3. At **no point** do you have to trust the machine's word, the operator's word, or
   even ours. You trust **what each one lets you verify** — and nothing more.

Think of it as trust that is *earned and checkable*, level by level — unknown →
proven-this-once → a real track record → anchored where nobody can rewrite it — rather
than a single "trust me" you either swallow or don't.

---

## The bottom line

You don't have to **trust** a stranger to run your prompt. You get to **check** them —
what their machine said it has, what it said it did, and how much of that you can
actually be sure of. Where checking is possible, the capsule lets you do it yourself,
offline, taking nobody's word. Where it isn't possible yet, the capsule **tells you so
honestly**, instead of pretending.

That honesty *is* the trust. Not "believe this machine" — **"here's exactly how much
you can, and how you'd know."**

---

*Want the next level down? [**The verification chain: what each link proves, and
how**](VERIFICATION-CHAIN.md) walks the actual cryptographic chain — from the record's
hash, through the signature, up to the witness receipt — stating, for each link, what
it proves and by what mechanism (with RFCs). And the full threat model is
[`TRUST-MODEL.md`](TRUST-MODEL.md) — including §2.2–2.5 for the specific questions each
party (requester, provider, coordinator, third-party) wants answered, and the evidence
that addresses each.*
