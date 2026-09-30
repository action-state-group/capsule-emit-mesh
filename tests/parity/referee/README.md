# Parity corpus: the referee

The referee is moving out of the Python (`twin_adjudicator.py`,
`live_referee.py`, `referee_service.py`, `referee_request.py`,
`adjudication_hold.py`, `adjudication_delivery.py`, `twin_selection.py`, and
the verdict counting in `ask_history.py`) and into the Rust plugin. This
directory is what the port is held to: fixed inputs, and the answer each one
must get.

It follows the record-push harness one directory up, with one addition. The
referee's rules changed after the Python was written, so the Python is the
reference only where it follows them:

- **Five paths are judged against the Python reference.** Their expected
  answers (`golden/`) are what the Python answers, except in the cases where
  the Python departs from the rules. There the golden answer is the rule's,
  and `intended_differences.json` records what the Python answers instead.
  No Python quirk is golden.
- **Three paths have no Python that follows the rules.** Their expected
  answers (`rule_answers/`) are stated from the rules below, case by case.
  `intended_differences.json` names the Python they replace and the rule
  that governs.

A port reads `corpus/`, `golden/` and `rule_answers/` and nothing else.

Nothing here is a measure of a node. Eligibility is yes or no, applied to
this node's own verified records; nothing is weighed or combined into a
number, and nothing is sent to other nodes.

## The rules

| # | Rule |
| --- | --- |
| 1 | **Trigger.** A referee is asked only when two twins of a pair the host marked (a twin bracket id) answered the same request at temperature 0 on the same weights digest, and their answers differ. Any difference is a difference: there is no similarity threshold. It is on unless the operator turns it off. Nothing runs otherwise. |
| 2 | **One call per pair.** At most one referee call per differing pair, never retried. A pair is the twin bracket id, the twins' request digest and the two node ids; re-sealed halves of the same exchange are the same pair. |
| 3 | **Eligibility**, all required: the node serves the twins' model hash and weights digest; is neither twin; announced a key (so it can sign); is not blocked by this node; and has no referee-signed contradiction for that model, in this node's own counts, inside the bar window D. D is 30 days unless the operator sets it. It runs from the time this node recorded the verdict, never from a time the referee wrote. A later corroboration does not end it early. It is per model. |
| 4 | **Tiers.** Tier 1: eligible nodes with a corroboration for that model in this node's own counts. Tier 2: eligible nodes with none. The pick is random inside tier 1; tier 2 is used only when tier 1 is empty. |
| 5 | **The tier is sealed.** The verdict seals the tier the referee was asked from (and the model hash). A tier altered after signing fails verification. A verdict sealed at another tier than this node asked at is refused. |
| 6 | **Never contradicted.** No eligible referee, a referee that cannot sign, one that does not answer, a host that does not mark twins, the setting off, twins that agree, twins that cannot be compared: each is "not adjudicated" with its reason. None counts against either twin. |
| 7 | **Only the referee signs.** A requester never seals a verdict, and no node holds a ruling the named referee did not sign. |
| 8 | **The counts and the stop-routing rule.** A verdict counts only when it is verified and this node asked that referee about that pair (or issued it as referee), once per referee and pair, per model hash. The stop-routing rule is off unless the operator sets N: N contradictions within D days, at most N-1 from one referee; a verdict that met the rule never counts toward it again; a host with no stop-routing hook is left alone. |

## Paths

A path is one entry point with its own input and answer shape. Each case is
tagged with the rule it holds (`rule`) and says what it covers (`covers`).

| Path | What it judges | Expected answers | Port module | Cases |
| --- | --- | --- | --- | --- |
| `adjudicate` | two halves checked and compared; the ruling a re-answer gives | Python: `twin_adjudicator.adjudicate`, `live_referee.referee_verdict` | `referee/half.rs`, `verdict.rs` | 31 |
| `service` | the referee answers an adjudicate request: a signed verdict or a signed refusal | Python: `referee_service.handle_adjudicate_request` | `referee/service.rs` | 28 |
| `hold` | a node receives a verdict delivered over record-push | Python: `record_push.handle_record_push` → `adjudication_hold` | `referee/hold.rs` | 33 |
| `deliver` | a node receives a verdict at `/evidence/deliver` | Python: `adjudication_delivery.handle_delivery` | `referee/hold.rs` | 9 |
| `classify` | verdicts a node's references hold about it | Python: `ask_history._classify_receipts_for_x` | `referee/verdict_counts.rs` | 22 |
| `select` | who is eligible, in which tier, and which node is asked | the rules (3, 4) | `referee/select.rs`, `bar.rs` | 32 |
| `request` | when a referee is asked, and at most once | the rules (1, 2, 6) | `referee/request.rs` | 29 |
| `counts` | the counts on a node's own chain, and the stop-routing rule | the rules (8) | `referee/verdict_counts.rs`, `routing_rule.rs` | 21 |

205 cases, 242 answers. By rule:

| Rule | Tag | Cases | Where |
| --- | --- | --- | --- |
| 1 trigger | `trigger` | 24 | request 10, adjudicate 11, service 3 |
| 2 one call per pair | `cap` | 14 | request 12, service 2 |
| 3 eligibility | `eligibility` | 21 | select 7, adjudicate 6, service 6, request 2 |
| 3 the bar window | `bar_window` | 13 | select 12, counts 1 |
| 4 tiers | `tiers` | 13 | select 13 |
| 5 the tier is sealed | `tier_sealed` | 7 | service 4, hold 3 |
| 6 never contradicted | `never_contradicted` | 11 | request 5, service 4, adjudicate 1, hold 1 |
| 7 only the referee signs | `only_referee_signs` | 2 | deliver 2 |
| 8 the counts | `counts` | 27 | classify 22, counts 5 |
| 8 the stop-routing rule | `stop_rule` | 15 | counts 15 |
| (supporting: checking a half) | `half` | 11 | adjudicate 5, service 6 |
| (supporting: the ruling) | `verdict` | 11 | adjudicate 8, service 3 |
| (supporting: delivery checks) | `delivery` | 36 | hold 29, deliver 7 |

`port_tests.json` lists the unit tests the port is to carry, by name, and
the cases that hold the same rule.

## Files

| File | What it is |
| --- | --- |
| `corpus/<path>.json` | The inputs. One case per line. Public material only. |
| `golden/<path>.json` | The answers the port must give on the five Python-judged paths: the Python's, and the rule's where the Python departs. |
| `rule_answers/<path>.json` | The answers stated from the rules (three paths). |
| `intended_differences.json` | Where the Python departs from the rules: whole paths, and single cases with what the Python answers. Each names the rule. |
| `mutants.json` | The implementation mutants the port's run must catch, and the cases that catch each. |
| `port_tests.json` | The port's unit tests by name, and the cases that hold the same rule. |
| `build_referee_corpus.py` | Builds `corpus/` and `rule_answers/`. |
| `referee_python.py` | Runs the corpus through the Python reference; writes `golden/`, `intended_differences.json`, `mutants.json`. |
| `referee_rule_model.py` | Works the rule-stated answers out again from the inputs, as a check on them. |
| `referee_mutants.py` | Makes each mutant's fault and finds the cases that catch it. |
| `referee_compare.py` | Compares any implementation's answers with the expected ones; prints a per-case table. |
| `referee_common.py` | The fixed clock, the node names, the test keys. |
| `test_referee_parity.py` | The harness's own checks (below). |

## How the golden answers were produced

- **Commit:** `b63d6e235097825064f1573bd07807c21913612b` (branch
  `demo-plugin`). The Python referee modules at that commit are the
  reference.
- **Libraries**, the released versions from PyPI in a fresh virtual
  environment (not an editable checkout): agent-action-capsule 0.6.0,
  capsule-emit 0.8.6, scitt-cose 0.4.0, checkpointed-local-log 0.2.0,
  cryptography 50.0.1. Python 3.13.7. The three that seal records are written
  into each signed corpus file as `built_with`.
- **Commands**, from the repository root:

  ```sh
  python tests/parity/referee/build_referee_corpus.py
  python tests/parity/referee/referee_python.py --golden
  ```

  The first writes `corpus/` and `rule_answers/`. The second runs the five
  Python-judged paths through the reference, applies the rules where the
  Python departs from them, and writes `golden/`, `intended_differences.json`
  and `mutants.json`.
- **Nothing in a golden file was edited by hand**, and no Python behaviour
  was changed to get it. Each departure is one small function in
  `referee_python.py` (`PORT_RULES`) that takes a case and the Python's
  answers and returns the answers the rule requires; a case it changes is
  listed, with the Python's answers, in `intended_differences.json`.
  `referee_python.py` also fixes one thing the referee's door reads from the
  wall clock: `referee_service._now_iso` returns the corpus clock while a
  case runs.
- **Clock:** `now` is `2026-09-29T00:00:00Z` in every path. The corpus's own
  records are sealed at `2026-09-28T12:00:00Z`.
- **Keys:** every node is `node-<letter>` and signs with a fixed test key
  derived from its name (`referee_common.private_key`), so a runner can sign
  as the node a case puts under test. The keys are for this corpus only. No
  data file here holds a seed or a private key: they carry public key ids
  and signatures.
- **Deterministic:** the records are sealed with fixed ids and times, so a
  rebuild with the same library versions gives the same files byte for byte.
  The harness checks this.

The rule-stated answers were written by hand, next to each case in
`build_referee_corpus.py`, from the rule the case names. `referee_rule_model.py`
works each one out again from the case input alone; the two must agree.

## Inputs and answers

Every case has `name`, `rule`, `covers`. An implementation writes:

```json
{"v": 1, "implementation": "<name>",
 "paths": {"<path>": {"<case>": [<answer>, ...]}}}
```

One answer per request, push, delivery, attempt or step, in order; one
answer for a case that has a single input. Only the paths present are
compared, so a port can be run one path at a time. Answers are compared by
value (canonical JSON).

A **node under test** (`node`) is `id` (it signs with that node's test key),
`peer_keys_env` (the raw value of `ADMISSION_POLICY_PEER_KEYS`), `files` (the
lines each file in its ledger directory starts with) and, in `hold`,
`record_at_completion`. Each case runs on a fresh node.

A **refusal** is never copied, since each implementation signs at its own
time. It is checked and reported as:

```json
{"refused": "<reason>", "status": <status or null>, "signed_by_node": true,
 "request_digest_is_body_sha256": true, "issued_at_is_now": true}
```

### `adjudicate`

Input: `halves` (two of `{capsule, request_body, response_body, node_id,
weights_digest}`, and `response_text` when a separate text is supplied) and
`referee`: `null`, `{node_id, answer_text}` (its re-answer), or `{node_id,
unreachable: true}`.

Answer: `{"error": "forged_half" | "answer_not_the_signed_body"}`, or the
ruling: `verdict`, `status`, `no_verdict_reason`, `divergence_index`,
`prefix_digest`, `twin_owner_distinct`, `weights_digest`, `referee_called`.
The words of an answer are its whitespace-separated tokens. Answers with the
same words are `corroborated`; any difference is `inconclusive` without a
referee, and the referee's ruling with one.

### `service`

Input: the node (the referee) and `requests`, each a `body`. An adjudicate
request must state `selection_tier`, 1 or 2; one that does not is refused
`request_malformed`.

Answer: `reply` and `appended` (every line the request added to a file in the
ledger directory, by file name). A verdict's record id and seal time differ
between implementations, so an issued verdict is reported as:

- the held facts as they are (`verdict`, `referee_node_id`,
  `referee_capsule_id`, `halves`, `half_node_ids`, `twin_bracket_id`), with
  `adjudication_verdict: 1` in the reply;
- `verdict_capsule_id`: `verdict-1`, `verdict-2`, ... in the order the case
  first shows each, and `verdict_capsule_id_is_the_records`;
- `verdict_capsule`: `block` (the sealed ruling block, exactly), `chain`,
  `provenance`, `epistemic_type`, and `signed_by_node` (the record verifies
  and this node's key signed it);
- `issued_at_is_now`.

A `no_verdict` refusal also reports `detail` (why there is none). Other
refusals' `detail` is free text and is not compared.

### `hold`

Input: the node and `pushes`, each `{sender, body}`, as in the record-push
corpus. `files` may hold `capsules.jsonl` (its own records),
`received-capsules.jsonl` (halves pushed to it) and
`requested-adjudications.jsonl` (the adjudicate requests it sent, each with
the `selection_tier` it asked at).

Answer: as in the record-push corpus: `reply` (the door's reply, or a
refusal) and `appended`, line for line.

### `deliver`

Input: the node and `deliveries`, each a `body`.

Answer: `reply` and `held` (whether the node kept the verdict). Where the
port keeps it is the port's; only whether it did is compared.

### `classify`

Input: `x` (the node asked about), `peer_keys_env`, `receipts` (records its
references hold).

Answer: the five counts: `corroborated`, `contradicted`, `inconclusive`,
`not_comparable`, `ack_refusals`.

### `select`

Input: `now`, `referee_bar_days` (`null`: the setting is unset),
`model_hash` and `weights_digest` (the twins'), `twins`, `peers` (each
`{node_id, model_hash, weights_digest, announced_key, blocked}`; the twins are
among them), `verdicts` (this node's counted verdicts about peers, each
`{node_id, model_hash, bucket, recorded_at}`; the `counts` path judges what is
counted) and `draws`.

Answer: `{tier, pool, asked, not_adjudicated}`. `pool` is the best non-empty
tier, sorted by node id. `asked` is one node per draw: `pool[draw]`.

The draw is in the input because two languages' generators do not share a
stream: the corpus fixes the index the generator returns, not the generator.
A runner injects a generator that returns each draw in turn when asked for an
index below the pool's size. The draws of `pick_uniform_within_best_tier`
reach every member of its pool.

With nobody eligible: `{"tier": null, "pool": [], "asked": [],
"not_adjudicated": "no_eligible_referee"}`.

The edge of the bar window and a node with a lapsed contradiction are held by
provisional cases (below).

### `request`

Input: `adjudicate_differing_twins` (`null`: unset) and `attempts`, run in
order on one node. Each attempt is a `pair` (`twin_bracket_id`,
`request_digest`, two `halves` of `{node_id, capsule_id, text, temperature,
model_hash, weights_digest}`), the `selection` its selection step returns
(`{tier, asked}` or `{not_adjudicated}`; the `select` path judges selection),
`manual` (`true` when the operator asked again, `false` when the pair was
simply seen), and the `referee`: `reanswer` (its re-answer, or `null` when it
does not answer) and `signs` (whether it can sign a verdict).

Answer, per attempt: `referee_calls` (calls this attempt made: 0 or 1), the
pair's `row`, and `counts_against` (the node a contradiction counts against,
or `null`). A row is `{"state": "adjudicated", "verdict", "referee", "tier"}`
or `{"state": "not_adjudicated", "reason"}`, with `because` when the reason is
`not_comparable`. An attempt on a pair already asked about makes no call and
shows the row the first call left.

Reasons: `off`, `host_does_not_mark_twins`, `twins_agree`, `not_comparable`
(`because`: `sampled`, `model_hash_differs`, `weights_differ`, `weights_unknown`),
`no_eligible_referee`, `referee_cannot_sign`, `referee_unreachable`.

No case gives a pair two reasons at once. A pair that found no eligible
referee, seen or asked about again, is held by provisional cases (below).

### `counts`

Input: `settings` (`stop_routing_after_contradictions` and
`stop_routing_window_days`, as the raw text the operator set, or `null`),
`cited` (verdicts an earlier block cited), `host` (`peer_blocks`: whether it
has the stop-routing hook; `blocked`) and `steps`. Each step adds records to
the node's chain (`add_records`) and requests it sent (`add_requested`), may
have the operator undo blocks (`unblock`), and then evaluates at `now`.

A chain record carries one of `adjudication_received`, `adjudication_issued`
or a bare `adjudication` block, with `verdict`, `verdict_capsule_id`,
`referee_node_id`, `halves`, `half_node_ids`, `model_hash` and the time.

Answer, per step: `counts` (per judged node, per model hash, the four buckets,
each `{count, verdict_capsule_ids}`; zero is shown), `rule` (`{after,
window_days}` or `null` when off), `outcomes` (`blocked` with the verdicts
that met the rule, `already_blocked`, or `no_host_hook`) and `cited` (every
verdict spent so far, sorted).

## Where the Python departs from the rules

`intended_differences.json`. In every case below the golden answer is the
rule's; the file records the Python's answer beside the rule and the reason.
`referee_compare.py --python` holds the Python's own output to those.

**Whole paths** (the Python is not the reference):

- `select`: `twin_selection.select_referee` weighs network distance, owner,
  hardware and tenure into one number and draws near the top. Rules 3 and 4
  replace it. The entry lists 17 cases where the Python, given the same
  peers, asks a node the rules do not allow.
- `request`: `referee_request.request_verdict` asks whenever it is called: no
  setting, no bracket id, no cap, and an adjudicate request even for twins
  that agree. Rules 1, 2 and 6 govern.
- `counts`: there is no Python. The rules are the ones `verdict_counts.rs` and
  `routing_rule.rs` in this repo already follow, plus the model hash key.
- `adjudicate`: a requester no longer seals a verdict (rule 7), so the path
  holds `adjudicate()` to its ruling alone.

**Single cases** (21):

- **No similarity threshold (rule 1).** The Python rules "corroborated"
  without a referee when at least nine tenths of the longer answer's words
  match before the first difference, and "inconclusive" below that, even for
  two answers with no words. The rule: the same words are corroborated; any
  difference is a difference, which without a referee is inconclusive.
  `adjudicate/differ_last_word_no_referee` (the Python: corroborated; the
  rule: inconclusive), `adjudicate/both_answers_empty` (the Python:
  inconclusive; the rule: corroborated). The port reports and seals no match
  share: the adjudicate answer has no `margin`, and the sealed block has no
  `margin` or `margin_tau`.
- **An unknown weights digest is not comparable (rule 3).** The Python
  compares, and lets a referee contradict a twin, when a half names no
  weights. `adjudicate/weights_unknown_on_one_side`,
  `adjudicate/weights_unknown_on_both_sides`: the Python says
  `contradicted:node-b`; the rule says `not_comparable`.
- **The tier and the model hash are sealed; the match share is not (12
  `service` cases, rules 5 and 1).** Every issued verdict's block carries
  `selection_tier`, as the request stated it, and `model_hash`, from the
  twins' signed records (`serving_provenance.model.identity_hash`), and
  drops `margin` and `margin_tau`.
- **A request must state its tier (rule 5).**
  `service/selection_tier_missing`, `service/selection_tier_out_of_range`:
  the Python ignores the member and answers; the port refuses
  `request_malformed`.
- **`hold/hold_refuses_tier_other_than_asked` (rule 5).** A verdict genuinely
  signed at tier 1, delivered to a requester that asked at tier 2. The Python
  does not read the tier and holds it; the port refuses `tier_not_as_asked`.
- **`deliver/verdict_the_referee_did_not_sign`,
  `deliver/verdict_signed_by_the_requester` (rule 7).** The Python route
  holds any well-formed record with a ruling block that cites this node's
  record, whoever sealed it; the port refuses `verdict_unverified`.

### Names this corpus fixes

The rules do not name these; the corpus had to, and the port must match:
the sealed members `selection_tier` and `model_hash`; the request member
`selection_tier`; the refusal `tier_not_as_asked`; the row reasons
`host_does_not_mark_twins`, `twins_agree`, `off` and `not_comparable` with
`because` (among them `model_hash_differs`). Changing one is a corpus change
(below), not a port decision.

Two readings the corpus also fixes. A call that was made and not answered
has used the pair's one call, so the operator asking again makes no other
(`request/operator_asks_again_after_no_answer`). The stop-routing window is
held one second either side of its edge (`counts/one_second_inside_the_window_counts`,
`counts/one_second_outside_the_window_does_not_count`); a contradiction
exactly D days old is in no case.

## Provisional cases

Twelve cases hold three defaults that no ruling has confirmed yet. Each is
marked `"provisional": "pending a ruling"` in the corpus, and the port is
held to it like any other case. A ruling that differs is a small edit: the
case's answer in `build_referee_corpus.py`, the matching line of
`referee_rule_model.py`, and a rebuild.

- **The bar window is half-open.** A node is barred while the clock is before
  the contradiction's recorded time plus D days, and eligible from exactly D
  days on. `select/barred_one_second_inside_d`, `select/eligible_at_exactly_d`,
  `select/eligible_one_second_after_d`.
- **A node whose bar has lapsed starts again with no history.** It is
  eligible, and in tier 2 until it has a corroboration for that model dated
  after the lapse; a corroboration from inside the window, or from before the
  contradiction, does not count. The contradiction stays in the counts.
  `select/lapsed_contradiction_with_earlier_corroboration_is_tier2`,
  `select/lapsed_contradiction_with_older_corroboration_is_tier2`,
  `select/lapsed_contradiction_corroborated_after_the_lapse_is_tier1`,
  and one second either side of the lapse:
  `select/corroborated_one_second_before_the_lapse_is_tier2`,
  `select/corroborated_one_second_after_the_lapse_is_tier1`.
- **A pair that found no eligible referee has not used its one call, and is
  not retried on its own.** The row stays "not adjudicated: no eligible
  referee" when the pair is seen again, even with a referee now eligible. The
  operator asking again (`manual`) looks for a referee again, and that call,
  once made, is the pair's one call.
  `request/no_eligible_referee_is_not_retried_on_its_own`,
  `request/no_eligible_referee_then_the_operator_asks_again`,
  `request/operator_asks_again_and_still_nobody`,
  `request/operator_asking_again_uses_the_one_call`.

## Mutants

Two kinds, as in the record-push harness.

**A changed answer.** Every case's answer is changed in turn (a member added,
an answer added, an answer dropped); the comparison must report that case and
no other.

**An implementation with a fault** (`mutants.json`). The port builds each
behind its cargo feature; the parity run must then fail, and every case
listed must be among those it reports.

| Mutant | Fault | Cases that catch it |
| --- | --- | --- |
| `select-skips-bar-window` | a node with a contradiction inside the bar window is treated as eligible | 7 in `select` |
| `select-ignores-blocked` | a node this node stopped routing to is treated as eligible | 3 in `select` |
| `select-mixes-tiers` | the pick is made over every eligible node, not inside the best tier | 4 in `select` |
| `verdict-tier-not-sealed` | the referee signs the verdict without the tier it was asked from | 12 in `service` |
| `hold-ignores-the-asked-tier` | a verdict is held whatever tier it seals | 1 in `hold` |
| `request-asks-twice-per-pair` | the one-call cap is not checked | 6 in `request` |
| `counts-skip-asked-gate` | a received verdict counts whether or not this node asked for it | 2 in `counts` |
| `verdict-names-wrong-twin` | the ruling names the twin the referee agreed with | 9 in `adjudicate`, 8 in `service` |
| `hold-skips-asked-check` | every delivered verdict is treated as one this node asked for | 8 in `hold` |

The lists are not guesses: `referee_mutants.py` makes each fault in the
Python that gives the expected answers (the reference, or the rule model),
runs the corpus, and records the cases whose answers change. The two tier
mutants are faults the Python itself has, so there the golden answers are
taken and the one thing the rule adds is removed.

## Running it

```sh
python tests/parity/referee/referee_python.py --out /tmp/python.json
python tests/parity/referee/referee_compare.py /tmp/python.json --python --table
```

`pytest tests/parity/referee` runs the harness's own checks:

- The Python reference, run now, gives exactly the golden answers, and in
  the listed cases where it departs, exactly the answers recorded for it; the
  rule model gives exactly the rule-stated answers.
- No golden answer carries a match share or a threshold; twins without a
  shared weights digest are never contradicted.
- A single changed answer in any case is reported against that case and no
  other.
- Every rule has cases in the paths that judge it; every named port test has
  a case; the corpus reaches every ruling, every refusal of the referee's
  door and of the receiving door, and every "not adjudicated" reason.
- No "not adjudicated" row counts against a twin; no pair is asked about
  twice; every pick is inside the best tier.
- Each case where the Python departs names its rule, and the Python's
  recorded answer really differs from the golden one.
- Each mutant is caught by exactly the cases `mutants.json` lists.
- The corpus is what the builder builds; nodes are named `node-<letter>`; no
  file holds key material; no file uses the vocabulary of grading a node.

The Rust runner is a test in the plugin, like `record_push_parity.rs`: it
reads `corpus/<path>.json`, runs each case, and requires each answer to equal
the expected one in `golden/` or `rule_answers/`.

## Changing the corpus

Add a case in `build_referee_corpus.py` (for a rule-stated path, with its
answer), then:

```sh
python tests/parity/referee/build_referee_corpus.py
python tests/parity/referee/referee_python.py --golden
pytest tests/parity/referee
```

Rebuild with the library versions in `built_with`, or rebuild and regenerate
together: a different release may seal a different record.
