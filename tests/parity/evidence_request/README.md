# Parity run: answering evidence requests

The plugin answers evidence requests in-process
(`plugins/admission-policy/src/evidence_answer.rs`), replacing the Python
door's `evidence_responder`. This directory holds that responder to fixed
answers: one ledger, one set of requests, and the answer each one must get.

**The golden answers are a snapshot this implementation wrote, reviewed
against draft-mih-agent-evidence-request-00; they are not the draft's own
conformance vectors.** Those vectors run in the protocol crate's repository
(`capsule-emit-evidence-request`, `tests/vectors/`). Each golden answer here
was reviewed against the draft, case by case, and the Python door's answers
were not used: the door departs from -00 in six ways, and -00 is what
counts. The
protocol itself (parsing, resolution, the artifact and its proofs, signed
refusals) comes from the `capsule-emit-evidence-request` crate, which runs
the draft's conformance vectors in its own repository; this run checks the
plugin around it: its ledger index, the limits, the sharing-policy gate, the
served summary, the "asked of you" log, and the wire.

The one part the Python still judges is the **served summary**: plugin glue
the draft does not define. `test_served_summary_parity.py` rebuilds it with
`served_summary.build_served_summary` from the corpus's own ledger and
requires the golden value to equal it.

## Files

| File | What it is |
| --- | --- |
| `corpus.json` | The node: 301 ledger lines, two signed checkpoints, and the cases. The node signs with the runner's own fixed test key (`NODE_KEY_SEED` in `evidence_request_parity.rs`); no key material is in this file. |
| `golden.json` | The answer each case must get. |
| `test_served_summary_parity.py` | The served summary in the golden answers is the Python fold's value. |

## The node

Ledger lines 0-7 are records of several kinds: records served to `node-a` and
`node-b` (two carry nonce `n-1`, one exchange id `ex-1`), a requested-role record,
a record citing another node's half, and an adjudication verdict record.
Padding fills to 16 lines, where checkpoint 0 is cut. Lines 16-20 are five
more records served to `node-a`, and line 21 is a local block (it never leaves
the node). Padding fills to 300 lines, where checkpoint 1 is cut, with one
witness. Line 300 is a record no checkpoint covers yet.

## A case

```json
{"name": "record_to_its_counterparty",
 "covers": "a record goes to the node it names as the other side",
 "history_segments": "prospective",
 "request": {"subject": {"record": "<id>"}, "coverage": {"expected_pin": "<checkpoint 1>"},
             "requester_id": "node-a"}}
```

- `history_segments` is the node's sharing switch
  (`ADMISSION_POLICY_SHARE_HISTORY_SEGMENTS`).
- `request` is sent as its compact JSON bytes; `request_text` is sent as
  given instead (for bytes that are not JSON).
- `busy: true` sends it while the node is already answering all it takes at
  once.

Every case runs against the same node at the corpus's clock, `now`.

## An answer

```json
{"reply": {...}, "appended": {"received_log.jsonl": [<the line logged>]}}
```

`reply` is one of:

- a refusal: `{"refused": <reason>, "signed_by_node", "request_digest_is_body_sha256",
  "issued_at_is_now"}`. The signature is checked, not copied: `signed_by_node`
  means `refusal::verify_for` accepts it under the node's key for this request;
- an artifact: `{"answered": <subject form>, "verification": {...}}`, where
  `verification` is what a requester makes of it
  (`evidence_answer::verify_response`: `answer::verify` against the node's key
  and the request sent): the anchor as `checkpoints[i]`, and the records'
  leaf indices or the number of checkpoints. A served summary also carries
  its value.

`appended` is the line the request added to the "asked of you" log.

## What -00 changes from the Python door (intended)

1. A record the node does not hold is refused `no_such_subject` (the door
   said `no_such_record`).
2. A signed refusal is a refusal, never an absence.
3. Requests use -00's six subject forms; the door's `{"kind": ...}` shape is
   `request_malformed` (`pre_draft_request_shape`).
4. `coverage` is required and carries exactly one member (`coverage_missing`,
   `coverage_both_members`).
5. A record id is the whole digest; a prefix is `request_malformed`
   (`record_prefix`).
6. `min_freshness` is a record count or a time, and `expected_pin` a
   checkpoint digest.

And this node's own choices, also intended:

- **Who gets record bodies** follows the rule the plugin's `ledger-fetch/1`
  door already applies: under `prospective` and `counterparties` a record goes
  only to the node it names as the other side of its exchange, and under
  `off` to no one. The door let any self-declared id (`prospective`) have a
  record, and never gated ranges. An answer is served whole or refused whole
  (`range_mixed_counterparties`), since an artifact is the same for every
  requester. Checkpoints, the history card and the served summary carry no
  record bodies and are never gated.
- **Limits:** a request over 16 KiB, an answer over 256 records or 1024
  checkpoints, and an answer over the 1 MiB stream cap are `policy_declined`;
  so is a request past the in-flight limit (`busy`).
- A held record that no checkpoint covers yet is `coverage_unsatisfiable`
  (not committed under any anchor), not `no_such_subject`.
- `served_summary/1` under `min_freshness` is `policy_declined` (a static
  export; the door called it `request_malformed`).

## Running it

```sh
cd plugins/admission-policy
cargo test --bin admission-policy-plugin -- evidence_request_parity::
EVIDENCE_REQUEST_PARITY_OUT=/tmp/rust.json cargo test --bin admission-policy-plugin -- evidence_request_parity::
pytest tests/parity/evidence_request
```

CI runs the parity run as its own step. A second step builds the responder
with the `mutant-evidence-skips-policy-gate` feature (the sharing-policy gate
dropped) and requires the parity run to fail, on the `not_authorized` cases.

## Changing the corpus

Edit `corpus_cases` (or the ledger) in
`plugins/admission-policy/src/evidence_request_parity.rs`, then:

```sh
EVIDENCE_REQUEST_PARITY_WRITE=1 cargo test --bin admission-policy-plugin -- --ignored evidence_request_parity::write_corpus_and_golden
```

This writes the corpus and the answers this implementation gives. Review
every changed golden line against the draft before committing it; a golden
line nobody reviewed is only a snapshot.
