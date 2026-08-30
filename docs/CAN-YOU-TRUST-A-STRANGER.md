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
  the graphics chip and memory it used, and how much work it took (the token counts).
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
  **consistent pseudonym**, not a verified real-world identity. You can tell it's the
  *same* machine each time; you can't (yet) tie it to a named person or company.
- **That the hardware is exactly as claimed.** The machine *reports* its own chip and
  memory. Nothing yet forces it to *prove* that at the hardware level — so the
  hardware line is a signed claim, not a hardware-rooted fact.
- **Its track record.** One receipt is **one data point**, not a history. A first
  exchange with a stranger can't tell you how they've behaved over time.

The receipt never dresses these up as green checkmarks. It says "we don't yet know
who asked," "self-attested," "not anchored yet" — plainly. **A receipt that admits its
limits is worth more than one that claims everything is fine.**

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

*Want the technical version? See [`TRUST-MODEL.md`](TRUST-MODEL.md) — including §2.2–2.5
for the specific questions each party (requester, provider, coordinator, third-party)
wants answered, and the evidence that addresses each.*
