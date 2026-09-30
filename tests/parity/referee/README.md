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
  answers (`golden/`) are exactly what the Python answers.
- **Three paths have no Python that follows the rules.** Their expected
  answers (`rule_answers/`) are stated from the rules below, case by case.
  The Python's behaviour there is not golden; `intended_differences.json`
  names the Python it replaces and the rule that governs.

Nothing here is a measure of a node. Eligibility is yes or no, applied to
this node's own verified records; nothing is weighed or combined into a
number, and nothing is sent to other nodes.

## The rules

| # | Rule |
| --- | --- |
| 1 | **Trigger.** A referee is asked only when two twins of a pair the host marked (a twin bracket id) answered the same request at temperature 0 on the same weights digest, and their answers differ. It is on unless the operator turns it off. Nothing runs otherwise. |
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
| `adjudicate` | two halves checked and compared; the ruling a re-answer gives | Python: `twin_adjudicator.adjudicate`, `live_referee.referee_verdict` | `referee/half.rs`, `verdict.rs` | 30 |
| `service` | the referee answers an adjudicate request: a signed verdict or a signed refusal | Python: `referee_service.handle_adjudicate_request` | `referee/service.rs` | 26 |
| `hold` | a node receives a verdict delivered over record-push | Python: `record_push.handle_record_push` → `adjudication_hold` | `referee/hold.rs` | 33 |
| `deliver` | a node receives a verdict at `/evidence/deliver` | Python: `adjudication_delivery.handle_delivery` | `referee/hold.rs` | 9 |
| `classify` | verdicts a node's references hold about it | Python: `ask_history._classify_receipts_for_x` | `referee/verdict_counts.rs` | 22 |
| `select` | who is eligible, in which tier, and which node is asked | the rules (3, 4) | `referee/select.rs`, `bar.rs` | 24 |
| `request` | when a referee is asked, and at most once | the rules (1, 2, 6) | `referee/request.rs` | 22 |
| `counts` | the counts on a node's own chain, and the stop-routing rule | the rules (8) | `referee/verdict_counts.rs`, `routing_rule.rs` | 19 |

185 cases, 212 answers. By rule:

| Rule | Tag | Cases | Where |
| --- | --- | --- | --- |
| 1 trigger | `trigger` | 23 | request 9, adjudicate 11, service 3 |
| 2 one call per pair | `cap` | 8 | request 6, service 2 |
| 3 eligibility | `eligibility` | 20 | select 7, adjudicate 5, service 6, request 2 |
| 3 the bar window | `bar_window` | 10 | select 9, counts 1 |
| 4 tiers | `tiers` | 8 | select 8 |
| 5 the tier is sealed | `tier_sealed` | 5 | service 2, hold 3 |
| 6 never contradicted | `never_contradicted` | 11 | request 5, service 4, adjudicate 1, hold 1 |
| 7 only the referee signs | `only_referee_signs` | 2 | deliver 2 |
| 8 the counts | `counts` | 27 | classify 22, counts 5 |
| 8 the stop-routing rule | `stop_rule` | 13 | counts 13 |
| (supporting: checking a half) | `half` | 11 | adjudicate 5, service 6 |
| (supporting: the ruling) | `verdict` | 11 | adjudicate 8, service 3 |
| (supporting: delivery checks) | `delivery` | 36 | hold 29, deliver 7 |

`port_tests.json` lists the unit tests the port is to carry, by name, and
the cases that hold the same rule.

## Files

| File | What it is |
| --- | --- |
| `corpus/<path>.json` | The inputs. One case per line. Public material only. |
| `golden/<path>.json` | The Python reference's answers, exactly (five paths). |
| `rule_answers/<path>.json` | The answers stated from the rules (three paths). |
| `intended_differences.json` | Where the port is held to a different answer than the Python gives: whole paths, and single cases. Each names the rule. |
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
  Python-judged paths through the reference and writes `golden/`, then
  `intended_differences.json` and `mutants.json`, which follow from them.
- **Nothing in a golden file was edited by hand**, and no Python behaviour
  was changed to get it. `referee_python.py` fixes one thing the referee's
  door reads from the wall clock: `referee_service._now_iso` returns the
  corpus clock while a case runs.
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
ruling: `verdict`, `status`, `no_verdict_reason`, `divergence_index`, `margin`
(a decimal string), `prefix_digest`, `twin_owner_distinct`, `weights_digest`,
`referee_called`. The words of an answer are its whitespace-separated tokens.

### `service`

Input: the node (the referee) and `requests`, each a `body`. Every adjudicate
request carries `selection_tier`.

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

No case puts one node in doubt between two conditions of a kind the rules do
not settle: a node with a lapsed contradiction and a corroboration, or a
contradiction exactly D days old, appears nowhere.

### `request`

Input: `adjudicate_differing_twins` (`null`: unset) and `attempts`, run in
order on one node. Each attempt is a `pair` (`twin_bracket_id`,
`request_digest`, two `halves` of `{node_id, capsule_id, text, temperature,
model_hash, weights_digest}`), the `selection` its selection step returns
(`{tier, asked}` or `{not_adjudicated}`; the `select` path judges selection),
and the `referee`: `reanswer` (its re-answer, or `null` when it does not
answer) and `signs` (whether it can sign a verdict).

Answer, per attempt: `referee_calls` (calls this attempt made: 0 or 1), the
pair's `row`, and `counts_against` (the node a contradiction counts against,
or `null`). A row is `{"state": "adjudicated", "verdict", "referee", "tier"}`
or `{"state": "not_adjudicated", "reason"}`, with `because` when the reason is
`not_comparable`. An attempt on a pair already asked about makes no call and
shows the row the first call left.

Reasons: `off`, `host_does_not_mark_twins`, `twins_agree`, `not_comparable`
(`because`: `sampled`, `weights_differ`, `weights_unknown`),
`no_eligible_referee`, `referee_cannot_sign`, `referee_unreachable`.

No case gives a pair two reasons at once, and none repeats a pair that found
no eligible referee (no call was made, and the rules do not say whether it
may be asked later).

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

## Where the port is held to a different answer

`intended_differences.json`. The golden files stay exactly what the Python
answers.

**Whole paths** (the Python is not the reference):

- `select`: `twin_selection.select_referee` weighs network distance, owner,
  hardware and tenure into one number and draws near the top. Rules 3 and 4
  replace it. The entry lists 14 cases where the Python, given the same
  peers, asks a node the rules do not allow.
- `request`: `referee_request.request_verdict` asks whenever it is called: no
  setting, no bracket id, no cap, and an adjudicate request even for twins
  that agree. Rules 1, 2 and 6 govern.
- `counts`: there is no Python. The rules are the ones `verdict_counts.rs` and
  `routing_rule.rs` in this repo already follow, plus the model hash key.
- `adjudicate`: a requester no longer seals a verdict (rule 7), so the path
  holds `adjudicate()` to its ruling alone.

**Single cases** (15):

- **The tier and the model hash are sealed (12 `service` cases, rule 5).**
  Every issued verdict's block also carries `selection_tier`, as the request
  stated it, and `model_hash`, from the twins' signed records
  (`serving_provenance.model.identity_hash`). The Python seals neither.
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
`because`. Changing one is a corpus change (below), not a port decision.

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
| `select-skips-bar-window` | a node with a contradiction inside the bar window is treated as eligible | 6 in `select` |
| `select-mixes-tiers` | the pick is made over every eligible node, not inside the best tier | 2 in `select` |
| `request-asks-twice-per-pair` | the one-call cap is not checked | 4 in `request` |
| `counts-skip-asked-gate` | a received verdict counts whether or not this node asked for it | 2 in `counts` |
| `verdict-names-wrong-twin` | the ruling names the twin the referee agreed with | 8 in `adjudicate`, 6 in `service` |
| `hold-skips-asked-check` | every delivered verdict is treated as one this node asked for | 8 in `hold` |

The lists are not guesses: `referee_mutants.py` makes each fault in the
Python that gives the expected answers (the reference, or the rule model),
runs the corpus, and records the cases whose answers change.

## Running it

```sh
python tests/parity/referee/referee_python.py --out /tmp/python.json
python tests/parity/referee/referee_compare.py /tmp/python.json --golden-only --table
```

`pytest tests/parity/referee` runs the harness's own checks:

- The Python reference, run now, gives exactly the golden answers; the rule
  model gives exactly the rule-stated answers.
- A single changed answer in any case is reported against that case and no
  other.
- Every rule has cases in the paths that judge it; every named port test has
  a case; the corpus reaches every ruling, every refusal of the referee's
  door and of the receiving door, and every "not adjudicated" reason.
- No "not adjudicated" row counts against a twin; no pair is asked about
  twice; every pick is inside the best tier.
- Each intended difference names a real case and its rule, and really differs
  from the Python's answer.
- Each mutant is caught by exactly the cases `mutants.json` lists.
- The corpus is what the builder builds; nodes are named `node-<letter>`; no
  file holds key material; no file uses the vocabulary of grading a node.

The Rust runner is a test in the plugin, like `record_push_parity.rs`: it
reads `corpus/<path>.json`, runs each case, and requires each answer to equal
the expected one, or the one in `intended_differences.json`.

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
