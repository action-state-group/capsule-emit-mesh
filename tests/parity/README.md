# Parity harness: the record-push path

The plugin is moving the record-push receiver out of the Python door
(`record_push.py`) and into the Rust plugin. This harness holds the two to
the same answers: both implementations get the same inputs, and every answer
is compared against the Python door's.

It covers the **record-push path only**: a peer pushing its sealed half of an
exchange, bare or as a bundle with its inclusion proof and signed checkpoint,
optionally carrying a split's stage records.

It deliberately leaves out two things:

- **Evidence-request answers.** These are judged by the protocol crate's own
  vectors and tests (`capsule-emit-evidence-request`), not by parity with
  the Python door. The Python departs from the draft in places, and the draft
  is what counts there.
- **A referee's verdict delivered through the same door** (`adjudication_hold`).
  That moves with the referee.

## Files

| File | What it is |
| --- | --- |
| `corpus/record_push.json` | The inputs: one receiving node per case and the pushes made to it, in order. Public material only. |
| `golden/record_push.json` | The Python door's answers to the corpus, exactly. |
| `intended_differences.json` | Cases where the port is held to a different answer, each with the reason. |
| `build_record_push_corpus.py` | Builds the corpus. |
| `record_push_python.py` | Runs the corpus through the Python door and writes its answers. |
| `compare.py` | Compares any implementation's answers with the expected ones; prints a per-case table. |
| `test_record_push_parity.py` | The harness's own checks (below). |

## A case

```json
{"name": "bundle_valid",
 "covers": "a verified bundle is held with its inclusion",
 "node": {"peer_keys_env": "{\"m3\": \"<key_id>\"}",
          "record_at_completion": null,
          "own_records": []},
 "pushes": [{"sender": "m3", "body": "<the push body>"}]}
```

- `peer_keys_env` is the raw value of `ADMISSION_POLICY_PEER_KEYS`. It is
  `null` when the variable is unset, and it may deliberately fail to parse.
- `record_at_completion` is `"counterparty"`, `"off"`, or `null` (no policy
  configured, which means the default).
- `own_records` are the lines of the node's own `capsules.jsonl` (its own
  records of exchanges, which the claim checks read).
- A push's `sender` is the self-declared sender id, or `null` for none. Its
  body is `body` (UTF-8 text), or `body_b64` when the bytes are not UTF-8.

Each case runs on a fresh node with a fresh signing key, at the corpus's
fixed clock `now`. Pushes run in order against the same node, so the later
ones see what the earlier ones stored.

## An answer

An implementation writes one answer per push:

```json
{"v": 1, "path": "record-push", "implementation": "<name>",
 "answers": {"<case>": [<answer per push>, ...]}}
```

Each answer has two members:

- **`reply`** — one of three shapes:
  - a bare push that was held: `{"status": "received"}`;
  - a bundle that was held: `{"status": "received", "inclusion": {...}}`,
    with the facts exactly as sent;
  - a refusal: `{"refused": <reason>, "status": <status or null>,
    "signed_by_node": bool, "request_digest_is_body_sha256": bool,
    "issued_at_is_now": bool}`.

  A refusal's signature is checked rather than copied, because each
  implementation signs with its own node key. `signed_by_node` means the
  refusal's `key_id` is this node's key and its signature verifies.
- **`appended`** — every line the push appended to any file in the node's
  ledger directory, parsed as JSON and keyed by file name. A file the push
  did not touch is absent.

`appended` is keyed by file name, so an implementation must store what it
holds in the same files (`received-capsules.jsonl`,
`received-provenance.jsonl`, `received-inclusion.jsonl`,
`received-split-stage-records.jsonl`, `rejected-record-pushes.jsonl`,
`checkpoint-equivocations.jsonl`), one JSON value per line, with the same
members and values in each line. Lines are compared by value (canonical
JSON), so only the byte layout may differ: member order and whitespace.

## Running it

```sh
python tests/parity/record_push_python.py --out /tmp/python.json
python tests/parity/compare.py /tmp/python.json --golden-only --table
```

`pytest tests/parity` runs the harness's own checks, which are:

- The Python door, run now, gives exactly the golden answers.
- Every case, mutated in turn, is reported against that case and no other.
  Each mutation changes a single thing: a changed reply, an extra file, an
  extra push, a flipped signature verdict, or a dropped stored line.
- The corpus reaches every record-push refusal reason, and both success
  replies.
- Every intended difference names a real case, says why, and really differs
  from the golden answer.

The Rust receiver is held to the same corpus by
`plugins/admission-policy/src/record_push_parity.rs`. It runs every case
through `record_push_receive::receive` and requires each answer to equal the
golden answer, or the stricter one in `intended_differences.json`. Set
`RECORD_PUSH_PARITY_OUT=<path>` to also write its answers, for
`compare.py --table`.

CI runs it in the plugin job, as its own step and the merge gate for the
port. A second step builds the receiver with the
`mutant-record-push-skips-claims` feature (the claim checks dropped) and
requires the parity run to fail on the claim cases. That shows the run
catches a receiver that drops a check, not only a changed answer file.

## Where the port deliberately differs

`intended_differences.json` holds each case the port answers differently
from the Python door, with the reason. There are six:

- **Stricter reading of the bytes (3 cases).** A bundle marker of `true` or
  `1.0` is not the integer 1. A UTF-16 body is not JSON (RFC 8259 §8.1).
- **A resent record is held once (3 cases).** The same sender's record,
  already held, is acknowledged again but not stored again. The door appends
  it on every resend.

Two more differences don't show in any corpus answer:

- **Precedence.** This node's policy, then a sender with no announced key,
  are refused before any work on the record's bytes. An unknown sender is
  refused `signature_unverified` even when its record would also fail the
  structure checks; the door would have said `request_malformed`.
- **Local bookkeeping.** The rejected-push log stops at 4 MiB, after which
  refusals are counted, not logged. Refusals issued before a record's
  signature has verified may use only 256 KiB of it. A torn line in a held
  store is skipped, not fatal, and the next line written after it starts on
  its own line.

## Changing the corpus

Add a case in `build_record_push_corpus.py`, then run:

```sh
python tests/parity/build_record_push_corpus.py
python tests/parity/record_push_python.py --golden
pytest tests/parity
```

The builder signs with throwaway keys and discards them, so every rebuild
changes every signature. Rebuild the corpus and the golden answers together,
never one without the other.
