# The Accountability tab: three panes (v2.1)

**Public-safe. 2026-09-05.** Documents what actually shipped in
`capsule_accountability_tab.py` (Pane A), `peer_accountability_tab.py` (Pane B),
`capsule_exchange_tab.py` (Pane C), and `join_card.py`'s `promise_line()`, as of the
`feat(accountability): wire panes v2` commit on `main`. Design rationale and the parts not yet
built live in `mesh-accountability-panes-v2-2026-09-05.md` (not this repo — cited, not
duplicated); this document is the as-shipped reference, and every cell below is checked against
running code, not the design intent. Where the two disagree, this document and `main` win.

The three panes answer three different questions Logs and Chat (mesh-llm's own UI) cannot:

| Pane | Question | Module | Whose artifacts |
|---|---|---|---|
| **A — My node** | "What would a stranger see if they asked about me?" | `capsule_accountability_tab.py` (composes `self_accountability.py`) | mine |
| **B — Peers** | "Of the nodes I've exchanged with, is there anything I should know?" | `peer_accountability_tab.py` | theirs, verified here |
| **C — This exchange** | "Was this specific exchange what both sides say it was?" | `capsule_exchange_tab.py` | both halves |

None of the three ever renders a score, a rating, or a trust level. `assert_no_rating_fields`
(Pane A/B) walks every payload recursively and raises before a field named `score`, `rating`,
`trust_level`, or `grade_percent` could ship; `sort_peer_rows` refuses to sort Pane B by anything
trust-shaped regardless of what a caller asks for.

## 1. The promise line — the first line of every card and every peer row

Every card face and every peer row leads with one of exactly four states,
`join_card.promise_line()`'s output folded from `card_consistency()`'s per-exchange verdict plus
the most recent card-transition verdict:

| State | Meaning |
|---|---|
| `kept` | The exchange's claims matched the card that was current when it was sealed, and no card transition since has widened or broken lineage. |
| `broken` (with a `detail` naming the field(s)) | A claim (model, weights digest, hardware, measurement rung, or serving node id) disagreed with the card current at that position. |
| `nothing_promised` | No card had been sealed yet, or nothing about the exchange was comparable to the card that was current — **never rendered as `kept`; a vacuous match is not a kept promise.** |
| `changed_without_saying` | A card transition widened a previously-pinned claim to absent, broke its lineage (`supersedes` mismatch), or switched `node_id` mid-chain — this **always outranks** an otherwise-clean exchange verdict, so a node cannot launder a bad transition by immediately lining back up with a vaguer card. |

A bad card transition always wins over a clean exchange match — a node that quietly widened its
own claims cannot paper over that by having its next exchange verify fine against the new, vaguer
card.

Real output, from a ledger holding one sealed join card and two exchanges that both match it
(`join_card.promise_line()` via `capsule_accountability_tab.build_promise_block()`):

```json
{"state": "kept", "detail": null}
```

`promise.state == "broken"` carries the mismatching field(s) in `detail` (e.g.
`"weights_digest"`); the HTML face renders it as `Promise: broken: weights_digest`.

## 2. The three property sources — never merged into one number

Every fact the panes publish about a node names which of three sources produced it. The rule is
normative for all three panes:

| Source label | Means | Who can lie, and how it's caught |
|---|---|---|
| `self_derived` | A node's own deterministic fold over its own witnessed ledger (`history_card.py`'s history properties today; `served_summary/1`, once `[mesh-served-summary-derivation]` lands). | The node itself; a tampered count is a signed lie a witness-checkpoint cross-check can catch, never taken on say-so. |
| `sampled` | A relying party's own spot-check of a `self_derived` claim. | Nobody; this is the reader checking, cited alongside `self_derived`, never standing alone. |
| `counterparty_held` (rendered `self_held` for this node's own retained copy of a counterparty fact) | A fact asserted by someone OTHER than the node it is about. | The node the fact is about cannot edit it. |

The full vocabulary discussion (including how existing labels map onto it) lives in
[ASSURANCE-VOCABULARY.md](ASSURANCE-VOCABULARY.md), §9 ("The Accountability panes' source labels +
the promise line").

## 3. Chip / color states

The face and row rendering use four fixed colors (`capsule_accountability_tab.py`'s client-side
`BLOCK_TONE` map, mirrored across all three panes):

| State | Color | Meaning |
|---|---|---|
| `verified` | green | Checked, and it checked out. |
| `present-unverified` | amber | A real limitation of the record — present, but this view has not independently verified it. |
| `failed` | red | A check ran and failed. |
| `absent` | grey | No claim was made; honestly nothing here. |
| `pending` | grey | Not a limitation of the record — a limitation of this view: the wiring doesn't exist yet. Never rendered amber; "not yet built" and "a real gap in this record" are different facts and must read as different colors. |

## 4. Pane A — "My node"

**CLI:**

```
python3 capsule_accountability_tab.py \
  --ledger ./ledger/capsules.jsonl --out accountability.html \
  --node-id mesh-node-demo-1 --log-id log-1 \
  [--checkpoints ./ledger/checkpoints.jsonl] [--native-log ./native_log.jsonl] \
  [--witness ./checkpoint-receipt.json] [--operator "your-label"]
```

`--node-id`/`--log-id` are what gate the v2 card face — omit either and `build_tab_payload`
returns `card: None` and the view falls back to the pre-v2 per-exchange table only (never a
fabricated empty card face).

The card face is five parts, each independently labeled, assembled by
`capsule_accountability_tab.build_card_face()` from `self_accountability.py`'s existing
row-builders (`history_summary`/`adjudications_summary`/`shared_summary` — reused, never
re-derived) plus the two genuinely new v2 pieces:

1. **`promise`** — §1 above.
2. **`history`** — Block 1, a thin re-shaping of `self_accountability.history_summary()`
   (`history_card.build_history_card()`'s own properties: `continuity`, `checkpoint_count`,
   `unforked`, `witnessed`, `witnesses`, `cadence`, plus a separate `pair_sequencing` sub-block).
3. **`served_summary`** — Block 2. **Pending** today: `served_summary.py`
   (`[mesh-served-summary-derivation]`) does not exist on `main` yet, so this block is always
   `{"state": "pending", "source": "self_derived", "text": "...pending [mesh-served-summary-derivation]"}`
   — never a fabricated count.
4. **`counterparty_held`** — Block 3: `adjudications_received` (real, `source: self_held`, tallied
   from adjudication capsules naming one of this node's own sealed capsule ids) plus `references`
   (**pending** `[mesh-ask-the-references]`).
5. **`footer`** — the native-log join (`self_accountability.sealing_summary()`, real when
   `--native-log` is supplied, otherwise honestly `pending`), `refusals_issued` (**absent** — the
   evidence-responder is merged but nothing yet persists a served/refused count to tally), and
   `absences_recorded_against_me` (**pending** `[mesh-ask-the-references]`).

Real `card` output (a ledger with one sealed join card whose `models`/`hardware` match two later
exchanges, no checkpoints, no native log supplied):

```json
{
  "promise": {"state": "kept", "detail": null},
  "history": {
    "state": "absent",
    "text": "no checkpoints since the requested size",
    "source": "history_card",
    "checkpoint_count": 0,
    "unforked": true,
    "witnessed": false,
    "witnesses": [],
    "cadence": {}
  },
  "served_summary": {
    "state": "pending",
    "text": "counted-by-this-node served/completed/failed/refused summary is not available on this view yet: pending [mesh-served-summary-derivation]",
    "source": "self_derived"
  },
  "counterparty_held": {
    "adjudications_received": {
      "state": "absent", "count": 0,
      "tally": {"corroborated": 0, "contradicted": 0, "inconclusive": 0},
      "source": "self_held", "text": "no adjudications received yet"
    },
    "references": {
      "state": "pending", "source": "counterparty_held",
      "text": "what my counterparties report when asked about me is not available on this view yet: pending [mesh-ask-the-references]"
    }
  },
  "footer": {
    "native_log_join": {"state": "pending", "text": "no native_log supplied to this view"},
    "refusals_issued": {
      "state": "absent", "source": null, "capture_method": null,
      "reason": "evidence-request responder counts are not yet available on this node: [mesh-e14-evidence-responder]'s responder is merged (capsule-emit-mesh #83, [mesh-e15-evidence-http-route]), but nothing persists a served/refused count for it to tally"
    },
    "absences_recorded_against_me": {
      "state": "pending",
      "text": "what my counterparties report when asked about me is not available on this view yet: pending [mesh-ask-the-references]"
    }
  }
}
```

The rendered page also carries a **Copy card** button (copies this JSON to the clipboard) and the
fixed honesty line, verbatim on every card:
`"Coverage is checked by counterparties, not by this node; hardware is OS-reported."`

## 5. Pane B — "Peers"

**CLI:**

```
python3 peer_accountability_tab.py build \
  --node-id mesh-node-demo-1 --log-id log-1 --ledger ./ledger/capsules.jsonl \
  [--checkpoints ./ledger/checkpoints.jsonl] [--source-log sidecar|plugin] \
  [--html --out peers.html]
```

Without `--html`/`--out`, prints the JSON payload to stdout. Default sort is most-recent-first
(`default_sort: "last_seen"`) — `sort_peer_rows` refuses any trust/score-shaped sort key
regardless of what a caller requests.

Seven columns per row, replacing the pre-v2 eight:

| Column | State today | Wired to |
|---|---|---|
| **Node** | real | `capsule_mesh_view.label_counterparty()` from `cross_party.initiator_ref`; records with no such evidence group under an explicit `unknown` bucket, never presented as one identified peer |
| **Role · exchanges** | real | `role_and_count_cell()` — `you→them` / `them→you` / `both`, with a count each way; never a trust signal |
| **History (theirs)** | **pending** | honestly pending a peer-fetch carrier that doesn't exist yet — the merged evidence responder answers `record`/`range` only, never `checkpoints`/`full_history`; this node's own chain rides along under `mine_for_reference` rather than being mislabeled as the peer's (a documented pre-v2 shortcut this cell explicitly stopped doing) |
| **Served (theirs)** | **pending** `[mesh-served-summary-derivation]` | `served_summary.py` does not exist on `main` yet |
| **Pair (me↔them)** | real | folds `capsule_exchange_tab.digest_match_grade` over every `exchange_id` this peer's records carry — the only cell that can say "missing" |
| **Verdicts** | real for the self-sealed half | adjudication capsules in this node's own ledger naming one of this peer's capsule ids; the "held by others" half is **pending** `[mesh-ask-the-references]` |
| **Asked** | **absent** (current, non-stale reason) | this node's own evidence-request carrier is merged and can *answer* a peer's request, but nothing yet logs requests this node *sends* to a peer |

Real output for one peer row (two `served` exchanges against `mesh-node-peer-alice`, no
checkpoints, no evidence-request log):

```json
{
  "peer_id": "initiator:mesh-node-pe",
  "node": {"state": "present", "text": "initiator:mesh-node-pe", "member_kind": "member", "exchange_count": 2},
  "rung": {"state": "present", "rung": "acknowledged_receipt", "distinct_rungs": ["acknowledged_receipt"]},
  "role": {"state": "present", "text": "them→you · 2", "role": "them_to_you", "you_to_them_count": 0, "them_to_you_count": 2},
  "history": {
    "state": "pending",
    "text": "this node cannot fetch the peer's OWN history card yet: ...",
    "mine_for_reference": {"history": {"state": "absent", "..."}}
  },
  "served": {"state": "pending", "text": "pending [mesh-served-summary-derivation] -- served_summary.py does not exist on main yet", "source": "self_derived"},
  "pair": {"state": "present", "text": "0 reconciled, 2 missing a half on this view", "verified": 0, "failed": 0, "missing": 2},
  "verdicts": {"state": "pending", "text": "...pending [mesh-ask-the-references]", "source": "self_sealed"},
  "asked": {"state": "absent", "text": "no log of evidence-requests this node has SENT to this peer exists yet: ...", "count": 0}
}
```

Row-expand carries `expand.pair_ledger` (per-`exchange_id` reconciliation states) and
`expand.their_card` (the peer's card in Pane A layout — pending the same peer-fetch gap as the
History column).

**Two honest gaps with no task id filed yet** (flagged in the wiring-v2 outbox, not silently
absorbed into an existing id): the peer-fetch carrier for History(theirs), and a per-peer
send-log for Asked.

## 6. Pane C — "This exchange"

**CLI:**

```
# regrouped list, one row per exchange
python3 capsule_exchange_tab.py list \
  --ledger ./ledger/capsules.jsonl --out exchanges.html \
  [--counterparty-ledger ./their-ledger/capsules.jsonl] [--source-log sidecar|plugin]

# single-exchange drill-down (the pre-v2 fragment, reused verbatim as the list's drawer)
python3 capsule_exchange_tab.py single \
  --ledger ./ledger/capsules.jsonl --capsule-id <capsule_id> --out exchange.html \
  [--counterparty-ledger ./their-ledger/capsules.jsonl] [--witness ./checkpoint-receipt.json]
```

`group_exchanges()`/`build_exchange_list_payload()` group every record by `exchange_id` (falling
back to `effect.request_digest` when `exchange_id` is absent/`unknown` — never mixing the two
silently), one row per exchange with a `SERVED`/`ASKED` role tag and `mine`/`theirs` as two
columns inside the row, never two rows. A `received()` foreign capsule (passed in via
`--counterparty-ledger`, since no live receive-into-ledger mechanism is wired yet) fills the
`theirs` column of its own exchange rather than getting a row of its own.

`header_state` is the **worst line among that exchange's checks** (`worst_state()`) — a digest
mismatch, a failed verdict line, or a failed rung forces `failed` regardless of what any other
line says; the witness-reverify placeholder line is excluded from that fold while it stays
`pending` (a view limitation, not a check that failed).

Real output for one row (a served, unilateral exchange — no `theirs` half in this view):

```json
{
  "exchange_key": "exch-002",
  "role_tag": "SERVED",
  "header_state": "present-unverified",
  "mine": {"state": "present-unverified", "capsule_id": "ffff...ffff", "role": "served"},
  "theirs": {"state": "absent", "text": "none (unilateral)", "capsule_id": null}
}
```

and its `view.verdict` lines (the drill-down detail):

```json
[
  {"mark": "ok", "text": "Attests it ran on Llama-3.2-3B-Instruct (self-reported) — you can recompute in your browser that this record is signed and unaltered."},
  {"mark": "warn", "text": "Provider-signed (the signature verifies here) — but the witness receipt isn't in this bundle, so anchoring isn't shown in this view."},
  {"mark": "ok", "text": "Who asked is attested (initiator:mesh-node-pe)."}
]
```

Filter chips: `all` · `served` · `asked` · `issues` (`issues` = any row whose `header_state` is
not `verified` — an honest `absent`/`pending` row is not an issue, only a real `present-unverified`
or `failed` is). Default sort: most recent first.

**Two pending-reason corrections carried in this same wiring pass** (both citing merged PRs that
the pre-v2 text still called unmerged): twin/adjudication comparison
(`TWIN_ADJUDICATION_PENDING_REASON`) is pending this view threading through served
weights/logprobs it doesn't have on hand, not `twin_adjudicator.py` being unmerged (it is,
PR #84); witness re-verify (`WITNESS_REVERIFY_PENDING_REASON`) is pending this view threading the
checkpoint chain through, not `[mesh-e2-witness-checkpoints]` being unmerged (it is, PR #87).

## 7. Wiring status — every cell, wired or pending, as of `main`

| Cell | State | Pending on |
|---|---|---|
| A · history | wired | — |
| A · served summary | pending | `[mesh-served-summary-derivation]` |
| A · adjudications received | wired | — |
| A · references (counterparty-held) | pending | `[mesh-ask-the-references]` |
| A · native-log footer | wired (when `--native-log` supplied) | — |
| A · refusals issued | absent (real, current reason) | a served/refused-count persistence layer |
| B · node / role / pair / verdicts (self-sealed half) | wired | — |
| B · history (theirs) | pending | no task id filed yet — a peer-fetch carrier |
| B · served (theirs) | pending | `[mesh-served-summary-derivation]` |
| B · verdicts (held-by-others half) | pending | `[mesh-ask-the-references]` |
| B · asked | absent (real, current reason) | no task id filed yet — a per-peer send-log |
| C · list grouping, role tag, two-column halves, header = worst line | wired | — |
| C · twin/adjudication comparison | pending | this view threading served weights/logprobs through |
| C · witness re-verify | pending | this view threading the checkpoint chain through |

No cell in any of the three panes renders blank or a fabricated zero for a fact this node cannot
yet compute — every pending state above carries its reason and, where one exists, a task id.
