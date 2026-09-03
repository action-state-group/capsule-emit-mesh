# Review: PR #65 (`b7-account-nostr`) — reuse boundary for history-card / E18

**Status of this review: informational only.** This does not change PR #65's own
disposition (it stays **HELD** — the Nostr publish path overlaps the open NIP-56
question) and does not merge any of its code. It is the step-1 review
`[mesh-review-pr65-account-capsule]` asked for, folded into
`[mesh-history-card-verb]`'s own step 1, so `history_card()` is not built twice
against the same fold core PR #65 already demonstrates.

## What PR #65 builds

`account_capsule.py` + `nostr_account.py`: a node's **account capsule** — "an
ACCOUNT, not a score" — folding served/success counts over the checkpoint-covered
range only (never the un-anchored tail), plus a **Nostr publish path** (kind
31991, parameterized-replaceable, mock-relay only, no default public relay URL).
19 tests, full suite green (651 passed / 6 skipped at review time).

## Against the referee doc and properties-not-scores

Checked against `_work/mesh-referee-build-2026-09-02.md` §4 ("properties, not
scores": "*a property is computed from the artifacts alone, by anyone holding
them, and reproduces exactly*... *a score is comparative and needs a scorer*")
and `_work/mesh-history-proposal-2026-09-05.md` §4 (same ruling, mesh-history
specific: `continuity`, `history_depth`, `reconciled_with`, `gaps_detected`,
`fingerprint_drift` as the property vocabulary; scores explicitly out of scope
for the neutral layer).

- **Passes.** The account capsule publishes `selection` / `derivation` (a plain
  fold — counts, no weighting) / `coverage` (the witnessed checkpoint root) and
  states explicitly, in both the module docstring and the sealed subject, "NOT a
  score" / "the relying party computes its own predicate." `example_predicate()`
  is shipped labeled as an example only, asserted by a test that nothing in the
  mesh calls it as a default policy. This is the same discipline the referee doc
  and the history proposal both require.
- **Passes.** Selection is witness-bounded (`covered_entries =
  leaf_count(latest_checkpoint.mmr_size)`) — no self-inflation from the
  unwitnessed tail, matching the history proposal's "the guarantee is
  immutable as of the last checkpoint" framing.
- **Carried forward honestly, not silently.** The Sybil / identity-reset
  residual is a first-class field (`sybil_residual`), never dropped on
  serialization — matches the history proposal §5 item 3's requirement to
  *state* collusion/Sybil limits rather than pretend a mitigation is clean.
- **Out of scope for this review, not a defect.** The Nostr publish path is a
  distribution mechanism, not a scoring mechanism — it does not change the
  properties-not-scores verdict above. It stays HELD for its own (NIP-56)
  reason, unrelated to this reuse question.

**Verdict: PR #65's account/fold construction is sound and reusable as-is.**
Nothing about it needs to change before `history_card()` or
`[mesh-e18-pair-account]` build on the same underlying core.

## The reuse boundary — what "build on #65's account code" means in practice

PR #65's account capsule is a **mesh-specific wrapper** around a **neutral core**
that was already merged into `capsule-emit` independently of this PR:
`capsule_emit.account` (`AccountDefinition`, `Selection`/`Coverage`,
`build_account`/`verify_account` — fold-definition-as-data, `definition_digest`,
recompute+match verification). PR #65 is the first CONSUMER of that core inside
this repo, for a **range**-kind selection (input identity = `(coverage_root,
[from, to])`, never per-member digests).

The reusable boundary is the **neutral core**, not PR #65's own module:

- `history_card()` (`[mesh-history-card-verb]`, this task) needs a
  **chain_segment**-kind selection, not range — it walks the checkpoint chain
  itself (self-verifying from two boundary digests + the traversal relation),
  not a fold over a leaf range. `capsule_emit.account`'s `chain_segment` kind
  exists for exactly this shape and was already in the merged core PR #65
  consumes — `history_card.py` imports `capsule_emit.account` directly, the
  same way `account_capsule.py` does, and does **not** import
  `account_capsule.py` itself. This means `history_card()` ships independently
  of PR #65's HELD status: nothing in it depends on the Nostr path, and nothing
  in it is blocked by the open NIP-56 question.
- `[mesh-e18-pair-account]` (the double-entry (me, you) account) IS a
  **range**-kind selection over the same checkpoint-covered-range discipline
  PR #65 already built — that item should import and extend
  `account_capsule.py`'s actual fold helpers (`_role_of`, `_fold_range`'s
  shape) once PR #65 merges, rather than re-deriving the served/success role
  vocabulary a second time. Until PR #65 merges, E18 can still build against
  the same neutral core PR #65 demonstrates (as this task does), and re-point
  at `account_capsule.py` directly once the Nostr question resolves and PR #65
  lands.

**Net:** two different selection kinds (`range` for account/E18, `chain_segment`
for history) served by the SAME neutral fold core, so "build on #65's account
code" is honored at the level that actually matters — no second
`AccountDefinition`/`build_account`/`verify_account` implementation anywhere in
this repo — without making either card's shipping depend on PR #65's own
merge/HELD status.
