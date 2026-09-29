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

Comparison is by value (canonical JSON), not by bytes, so the two
implementations may lay out their files differently.

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

The Rust port's own parity test reads the same corpus and the same expected
answers.

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
