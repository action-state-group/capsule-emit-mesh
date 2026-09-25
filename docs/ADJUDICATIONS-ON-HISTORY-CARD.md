# Adjudications on the history card — three provenances, never merged

> **Design of record:** `_work/mesh-sharing-policy-history-and-money-2026-09-24.md`
> §3 (policy) and `_work/how-evidence-works-on-a-mesh-node-2026-09-24.md` §6
> (adjudication capsule shape). This page is the implementation record for
> `[mesh-adjudications-on-history-card-design]`: the classifier hook
> (`twin_adjudicator.classify_capsule_kind`), the `deliver_to_subjects`
> follow-up (`adjudication_delivery.seal_adjudication_ack` /
> `.seal_adjudication_rebuttal`), and the card fields
> (`history_card.with_adjudications`).

## The inclusion rule (quote this)

A node's own history card carries adjudications from exactly three
provenances, always labelled, never merged:

1. **Authored** — verdicts this node itself sealed, as requester or referee
   (`twin_adjudicator.seal_adjudication_capsule`). This is the node acting as
   the adjudicator, not the subject.
2. **Delivered** — verdicts about a twin THIS node was itself party to, with
   this node's own `ack`/`rebuttal` state. `deliver_to_subjects` (default on)
   means every node a twin adjudication judges receives the verdict via the
   existing evidence door; the subject then seals its own record — `ack` if
   it does not dispute the verdict, `rebuttal` (with a stated basis, never a
   free-text score) if it does.
3. **About X, by reference** — `adjudications_about_x`, already shipped
   (`ask_history.py --subject references`): verdicts about a *different*
   node, learned by asking a sample of that node's own counterparties. This
   node was neither the adjudicator nor a subject; it is reporting what a
   third party said.

These are structurally different claims about who stands behind them, and
the card renders them under three separate labels
(`adjudications.authored`, `adjudications.delivered`,
`references.adjudications_about_x`) so a reader never has to guess which
provenance a count came from.

## Why authorship can't be read off a signature

Capsules minted by `agent_action_capsule.emit()` carry no per-capsule
signature or `key_id` — integrity comes from the checkpoint chain over the
whole log, not from signing each record individually. So "did *I* seal this
adjudication, or did it arrive by delivery" cannot be answered by checking
who signed it.

The honest, purely structural answer is in the ledger's own shape instead:
`deliver_to_subjects` means every delivered adjudication a node *accepts*
(`adjudication_delivery.handle_delivery` returning `{"status": "received"}`,
never a `policy_decline`) gets exactly one follow-up record from that same
node — an `ack` or a `rebuttal`, citing the adjudication by
`chain.parent_capsule_id`. A referee never acks or rebuts its own verdict.
So:

- An `adjudication` capsule **with** an `ack`/`rebuttal` citing it, in the
  SAME ledger, is **delivered** (provenance 2).
- An `adjudication` capsule **with no** such citation is **authored**
  (provenance 1) — this node ran the adjudicator itself.

`history_card.adjudication_provenance_from_ledger` implements exactly this
split, keyed by verdict kind (`corroborated` / `contradicted` /
`inconclusive` — the `contradicted:<owner_id>` suffix is dropped to the bare
kind, since the owner named is whichever party the verdict judged, not this
node).

## The classifier hook

`twin_adjudicator.classify_capsule_kind(capsule) -> str | None` names the
chain-segment leaf kind for this module's own record shapes — one line per
kind, no new record type (the design note's §3 "leaf counts per checkpoint
by kind"):

| Kind | `chain.relation` / signal |
|---|---|
| `adjudication` | `RELATION_ADJUDICATES` (`"adjudicates"`) |
| `ack` | `"adjudication_ack"` (`adjudication_delivery.seal_adjudication_ack`) |
| `rebuttal` | `"adjudication_rebuttal"` (`adjudication_delivery.seal_adjudication_rebuttal`) |
| `exchange_twin` | an ordinary served-half capsule carrying `x-mesh-poc-v1.serving_provenance.twin_bracket_id` |

Distinct from `adjudication_ack_refused` (the REQUESTER's own record of a
delivery the subject *refused* to even hold — `policy_decline`), which
classifies as `None`: that relation names a different actor's record of a
different event, not a subject's response to an accepted delivery.

`exchange_twin` is defined here for forward compatibility with the broader
chain-segment leaf-count feature (`[mesh-sharing-policy-v0]`'s `history_
segments` object) — it is not yet consumed by this task's card fields, the
same "picked up automatically, no rework here" discipline
`adjudication_delivery._cited_capsule_ids` already uses for
forward-citation fields.

## `deliver_to_subjects` and the ack/rebuttal follow-up

`adjudication_delivery.py` already transports and folds a delivered verdict
(`handle_delivery`) and already lets a REQUESTER record a refused delivery
(`seal_adjudication_ack_refused`). This design adds the missing leg: the
SUBJECT's own record of an *accepted* delivery.

```
seal_adjudication_ack(adjudication_capsule, ...) -> capsule
seal_adjudication_rebuttal(adjudication_capsule, *, basis: str, ...) -> capsule
```

Both cite the adjudication by `prior_capsule_id`/`chain.relation`, carry the
verdict by id (never restated as a score), and — for the rebuttal — a
`basis` string the caller must supply non-empty (`ValueError` otherwise): an
unreasoned dispute is indistinguishable from noise, and would let a node
contest any verdict it dislikes with no accountable trail.

Same "the caller, not this module" discipline `seal_adjudication_ack_refused`
already documents: `handle_delivery` folds and transports; it never judges a
verdict's correctness, so it never seals ack/rebuttal itself. The decision
to ack or dispute is the node's own policy, exercised by whatever calls
these two functions after `handle_delivery` returns `{"status": "received"}`.

## Card fields

`history_card.HistoryCard.to_value()["adjudications"]`:

```jsonc
{
  "authored": {"corroborated": 2},
  "delivered": {
    "corroborated": {
      "delivered": 3, "acknowledged": 2, "disputed": 1,
      "capsule_ids": {
        "delivered": ["<id1>", "<id2>", "<id3>"],
        "acknowledged": ["<ack-id1>", "<ack-id2>"],
        "disputed": ["<rebuttal-id1>"]
      }
    }
  },
  "state": "enriched",   // or "never_enriched" -- see below
  "note": "..."
}
```

`references.adjudications_about_x` (already shipped) stays exactly where it
was, under `references`, with its own `asked`/`answered` counts —
provenance 3, never folded into `adjudications` above.

**Never "never asked = zero."** A card that was never enriched
(`with_adjudications()` never called) and a card that WAS enriched and
genuinely found nothing both have empty `authored`/`delivered` dicts —
indistinguishable by content alone. `adjudications.state` disambiguates:
`"never_enriched"` until `with_adjudications()` runs at least once,
`"enriched"` thereafter, regardless of whether any count came back non-zero.
The same discipline now applies to `references.state`
(`"never_asked"` / `"asked"`), closing the same gap that already existed for
provenance 3's own `asked`/`answered` counts. This mirrors `forks_state`'s
existing `absent`/`unreadable`/`ok` split for `forks_observed`
([mesh-forks-observed-integrity]).

Both `authored_adjudications`/`delivered_adjudications` and
`references_state` live OUTSIDE `core_account()` — same as
`peer_reconciliation` and the rest of `references` — so folding them in
never perturbs the cryptographically-verified chain-walk properties, and
`verify_history_card` folds the published values back in before its
byte-for-byte recompute+match (same pattern as
`with_peer_reconciliation`/`with_references`).

## Drill: card → adjudication card

Not built here (fork-only UI, coordinated with
`[mesh-evidence-ui-drill-paths]` — do not build a second card). The shape a
click on a delivered/authored count drills into is the adjudication capsule
itself (`_work/how-evidence-works-on-a-mesh-node-2026-09-24.md` §6):

- the **verdict** (`corroborated` / `contradicted:<owner_id>` /
  `inconclusive`) and its **basis** (`margin`, `margin_tau`,
  `divergence_index`, `prefix_digest`);
- the **cited halves** as clickable ids (`half_a_capsule_id`,
  `half_b_capsule_id`, and `referee_capsule_id` when a referee ran);
- **who adjudicated** (`referee_id` when attributed);
- **how to recompute** — the margin rule and `margin_tau` are published on
  the capsule itself (`MARGIN_TAU_RATIONALE`), so a stranger can rerun
  `compare_transcripts` against the same disclosed transcripts;
- **rebuttals citing it** — any `adjudication_rebuttal` capsule whose
  `chain.parent_capsule_id` names this adjudication, with its `basis`.

The drill path is one adjudication capsule with its existing fields; no new
card, no second record shape.
