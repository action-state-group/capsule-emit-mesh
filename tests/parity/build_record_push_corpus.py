# SPDX-License-Identifier: Apache-2.0
"""Build the record-push parity corpus: ``corpus/record_push.json``.

Every case is a fresh receiving node (its peer-key registry, its sharing
policy, its own records of exchanges) and one or more pushes to it, in order.
The same corpus is fed to every implementation of the record-push receiver;
see ``README.md``.

The corpus holds only public material: signed records, signed checkpoints,
inclusion proofs and public keys. The signing keys are generated here, used,
and thrown away, so a rebuild produces a different (equally valid) corpus;
rebuild only when a case is added, then regenerate the golden answers.

    python tests/parity/build_record_push_corpus.py
"""
from __future__ import annotations

import base64
import copy
import hashlib
import shutil
import json
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

from agent_action_capsule.canonical import LOCAL_ONLY_FIELDS, compute_capsule_id  # noqa: E402
from agent_action_capsule.contracts import Disposition, EffectRecord  # noqa: E402
from agent_action_capsule.emit import emit  # noqa: E402
from capsule_emit.signing import LocalKeypairSigner, sign_producer_envelope  # noqa: E402
from cll.checkpoint.core import add_leaf, inclusion_proof, leaf_hash, peaks, root_from_peaks  # noqa: E402
from cll.checkpoint.index import MemoryNodeStore  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from scitt_cose import cll  # noqa: E402

from record_push import MAX_JSON_DEPTH  # noqa: E402

sys.path.insert(0, str(HERE))
import parity_format  # noqa: E402

CORPUS = HERE / "corpus" / "record_push.json"
SPLIT_FIXTURE = ROOT / "tests" / "fixtures" / "split-stage" / "rust-split-bundle.json"

#: Where the throwaway signing keys live while the corpus is built; removed after.
SCRATCH = Path(tempfile.mkdtemp(prefix="record-push-corpus-"))

#: The fixed clock every implementation runs the corpus at.
NOW = "2026-09-29T00:00:00Z"
REQ = "b" * 64
RESP = "c" * 64
ASKED = "1" * 64
SWAP = "2" * 64
SENDER = "node-a"


class Key:
    """An Ed25519 key in the door's PEM form, in a throwaway directory."""

    def __init__(self, scratch: Path, name: str) -> None:
        from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

        load_or_create_signing_key(scratch / name)
        self.path = scratch / name / NODE_KEY_FILENAME
        self.private = serialization.load_pem_private_key(self.path.read_bytes(), None)
        self.key_id = (
            self.private.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )


def record(role: str | None = None, served_by: str | None = None, *, weights=None, model_id=None, text="x"):
    """An unsigned record; ``role``/``served_by`` set the mesh claims."""
    ca: dict = {"note": text}
    if role is not None:
        ca["x-mesh-poc-v1"] = {"role": role, "serving_provenance": {"served_by_node_id": served_by}}
    if weights:
        ca["weights_digest"] = {"digest_alg": "SHA-256", "digest": weights, "scope": "file"}
        ca["x-mesh-poc-v1"]["serving_provenance"]["model"] = {"weights_digest": weights}
    capsule = emit(
        action_type="decide",
        operator="op",
        developer="mesh-node@v1",
        compute_attestation=ca,
        effect=EffectRecord(status="confirmed", type="inference_completion", request_digest=REQ, response_digest=RESP),
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed"),
        tool_name="serve_exchange",
    )
    if model_id:
        capsule["model_attestation"]["model_id"] = model_id
    return capsule


def json_depth(value) -> int:
    """Nesting depth counted the way ``record_push.MAX_JSON_DEPTH`` counts it."""
    if isinstance(value, dict):
        return 1 + max((json_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((json_depth(v) for v in value), default=0)
    return 0


def nested_record(depth: int) -> dict:
    """An unsigned record whose deepest value sits exactly ``depth`` deep once
    it is signed (signing adds only top-level strings)."""
    capsule = record(text="deep")
    ca = capsule["model_attestation"]["compute_attestation"]
    ca["deep"] = []
    base = json_depth(capsule)
    value: list = []
    for _ in range(depth - base):
        value = [value]
    ca["deep"] = value
    return capsule


def signed(capsule: dict, key: Key) -> dict:
    """``capsule`` with its id recomputed and its producer signature by ``key``."""
    c = {k: v for k, v in capsule.items() if k not in ("signature", "key_id", "capsule_id")}
    signer = LocalKeypairSigner(key.path)
    c["key_id"] = signer.key_id
    c["capsule_id"] = compute_capsule_id(json.loads(json.dumps(c)))
    c["signature"], c["key_id"] = sign_producer_envelope(signer, c["capsule_id"])
    return c


def signed_exact(capsule: dict, key: Key) -> dict:
    """:func:`signed`, with the id computed as the plain JCS digest (integers
    written exactly) instead of by the reference, which refuses some inputs.
    Only for records whose members are ASCII strings, integers, bools, lists
    and objects, where sorted-key compact JSON is the JCS form."""
    c = {k: v for k, v in capsule.items() if k not in ("signature", "key_id", "capsule_id")}
    signer = LocalKeypairSigner(key.path)
    c["key_id"] = signer.key_id
    preimage = {k: v for k, v in c.items() if k not in ("capsule_id", *LOCAL_ONLY_FIELDS)}
    text = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    c["capsule_id"] = hashlib.sha256(text.encode("ascii")).hexdigest()
    c["signature"], c["key_id"] = sign_producer_envelope(signer, c["capsule_id"])
    return c


def sign_checkpoint(cp: dict, key: Key) -> dict:
    body = {k: v for k, v in cp.items() if k != "signature"}
    digest = cll.Checkpoint.from_dict({**body, "signature": ""}).digest()
    return {**body, "signature": key.private.sign(digest.encode("utf-8")).hex()}


def ids(prefix: str, n: int) -> list[str]:
    return [hashlib.sha256(f"{prefix}-{i}".encode()).hexdigest() for i in range(n)]


def bundle(capsule: dict, key: Key, leaves: list[str], *, prev: dict | None = None, log_id="sender-log") -> dict:
    """``capsule`` (one of ``leaves``) under a checkpoint over exactly
    ``leaves``, optionally chained to the earlier checkpoint ``prev``."""
    store = MemoryNodeStore()
    for capsule_id in leaves:
        add_leaf(store, leaf_hash(bytes.fromhex(capsule_id)))
    size = store.size()
    root = root_from_peaks([store.node(p) for p in peaks(size)])
    checkpoint = sign_checkpoint(
        {
            "v": 1,
            "kind": "mmr_checkpoint",
            "log_id": log_id,
            "mmr_size": size,
            "root": root.hex(),
            "prev_size": prev["mmr_size"] if prev else 0,
            "prev_root": prev["root"] if prev else "",
            "key_id": key.key_id,
            "timestamp": f"2026-09-27T00:00:{size % 60:02d}Z",
        },
        key,
    )
    index = leaves.index(capsule["capsule_id"])
    proof = inclusion_proof(store, index, size)
    return {
        "record_push_bundle": 1,
        "capsule": capsule,
        "inclusion": {
            "leaf_index": index,
            "proof": {
                "v": proof.v,
                "kind": proof.kind,
                "size": proof.size,
                "leaf_index": proof.leaf_index,
                "witness": list(proof.witness),
                "peaks_left": list(proof.peaks_left),
                "peaks_right": list(proof.peaks_right),
            },
        },
        "checkpoint": checkpoint,
    }


def body(value) -> bytes:
    """A push body as ``push_record`` sends it."""
    return json.dumps(value, sort_keys=True).encode("utf-8")


def push(raw: bytes, sender: str | None = SENDER) -> dict:
    """One push: the body as text when it is UTF-8, else as base64."""
    try:
        return {"sender": sender, "body": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"sender": sender, "body_b64": base64.b64encode(raw).decode("ascii")}


def case(name: str, covers: str, pushes: list[dict], *, peer_keys=None, policy=None, own=()) -> dict:
    """``peer_keys`` is the registry's raw env value (a dict is JSON-encoded;
    ``None`` leaves it unset). ``policy`` is ``record_at_completion`` or
    ``None`` (no policy configured)."""
    env = json.dumps(peer_keys) if isinstance(peer_keys, (dict, list)) else peer_keys
    return {
        "name": name,
        "covers": covers,
        "node": {"peer_keys_env": env, "record_at_completion": policy, "own_records": list(own)},
        "pushes": pushes,
    }


def build() -> dict:
    scratch = SCRATCH
    k = Key(scratch, "sender")
    other = Key(scratch, "other")
    reg = {SENDER: k.key_id}

    half = signed(record(text="half"), k)
    half2 = signed(record(text="half-2"), k)
    cases: list[dict] = []
    add = cases.append

    # --- identity, policy and structure on a bare push -------------------
    add(case("bare_valid", "a signed half from its announced key is held", [push(body(half))], peer_keys=reg))
    add(case("bare_policy_counterparty", "the explicit default policy receives",
             [push(body(half))], peer_keys=reg, policy="counterparty"))
    add(case("bare_policy_off", "record_at_completion off refuses policy_decline",
             [push(body(half))], peer_keys=reg, policy="off"))
    add(case("bare_no_sender", "an unidentified push is refused and recorded",
             [push(body(half), sender=None)], peer_keys=reg))
    add(case("bare_empty_sender", "an empty sender id is unidentified",
             [push(body(half), sender="")], peer_keys=reg))
    add(case("bare_unknown_sender", "a sender absent from the registry",
             [push(body(half), sender="m9")], peer_keys=reg))
    add(case("bare_registry_unset", "no registry configured at all", [push(body(half))], peer_keys=None))
    add(case("bare_registry_not_json", "a registry that does not parse", [push(body(half))], peer_keys="{node-a:"))
    add(case("bare_registry_not_object", "a registry that is a JSON array", [push(body(half))], peer_keys=[k.key_id]))
    add(case("bare_registry_key_not_string", "the sender's entry is not a string",
             [push(body(half))], peer_keys={SENDER: 7}))
    add(case("bare_key_mismatch", "the announced key is not the half's key",
             [push(body(half))], peer_keys={SENDER: other.key_id}))
    resigned = copy.deepcopy(half)
    other_half = signed(record(text="half"), other)
    resigned["signature"] = other_half["signature"]
    add(case("bare_signature_by_other_key", "key_id kept, signature made by another key",
             [push(body(resigned))], peer_keys=reg))
    add(case("bare_content_changed", "a field changed after sealing: the id no longer recomputes",
             [push(body({**half, "operator": "someone-else"}))], peer_keys=reg))
    add(case("bare_capsule_id_changed", "a capsule_id that is not the record's",
             [push(body({**half, "capsule_id": "0" * 64}))], peer_keys=reg))
    add(case("bare_no_capsule_id", "no capsule_id",
             [push(body({k2: v for k2, v in half.items() if k2 != "capsule_id"}))], peer_keys=reg))
    add(case("bare_empty_capsule_id", "an empty capsule_id", [push(body({**half, "capsule_id": ""}))], peer_keys=reg))
    add(case("bare_no_signature", "the signature removed",
             [push(body({k2: v for k2, v in half.items() if k2 != "signature"}))], peer_keys=reg))
    add(case("bare_policy_off_and_malformed", "structure is judged before policy",
             [push(b"not json")], peer_keys=reg, policy="off"))
    add(case("bare_policy_off_and_no_sender", "policy is judged before identity",
             [push(body(half), sender=None)], peer_keys=reg, policy="off"))
    add(case("bare_replayed", "the same half twice is held twice (a bare push has no replay check)",
             [push(body(half)), push(body(half))], peer_keys=reg))

    # --- bytes the Rust side's parser would refuse -----------------------
    raw_half = json.dumps(half)
    for name, raw in [
        ("raw_not_json", b"not json"),
        ("raw_empty", b""),
        ("raw_array", b"[]"),
        ("raw_string", b'"capsule"'),
        ("raw_null", b"null"),
        ("raw_duplicate_key", (raw_half[:-1] + ', "capsule_id": "' + "0" * 64 + '"}').encode()),
        ("raw_duplicate_key_nested", (raw_half[:-1] + ', "x": {"a": 1, "a": 2}}').encode()),
        ("raw_nan", (raw_half[:-1] + ', "x": NaN}').encode()),
        ("raw_infinity", (raw_half[:-1] + ', "x": Infinity}').encode()),
        ("raw_overflow_float", (raw_half[:-1] + ', "x": 1e400}').encode()),
        ("raw_int_over_64_bits", (raw_half[:-1] + ', "x": 18446744073709551616}').encode()),
        ("raw_int_under_64_bits", (raw_half[:-1] + ', "x": -9223372036854775809}').encode()),
        ("raw_lone_surrogate", (raw_half[:-1] + ', "x": "\\ud800"}').encode()),
        ("raw_invalid_utf8", raw_half.encode()[:-1] + b', "x": "\xff"}'),
        ("raw_trailing_garbage", raw_half.encode() + b" x"),
        # The same member twice with the same value: a reader that keeps
        # either copy sees a valid record, so only the duplicate refuses it.
        ("raw_duplicate_key_same_value", (raw_half[:-1] + ', "operator": ' + json.dumps(half["operator"]) + "}").encode()),
        ("raw_duplicate_key_same_value_nested", raw_half.replace(
            '"compute_attestation": {', '"compute_attestation": {"note": "half", ', 1).encode()),
        # JSON is UTF-8 (RFC 8259 §8.1); Python's json.loads also reads UTF-16.
        ("raw_utf16", json.dumps(half).encode("utf-16")),
    ]:
        add(case(name, "strict parse: " + name[4:].replace("_", " "), [push(raw)], peer_keys=reg))

    # --- signed, but not a well-formed record (the reference verifier's
    # gating checks 1-5; the id still recomputes and the signature verifies) --
    def structure(name: str, covers: str, change) -> None:
        capsule = record(text=name)
        change(capsule)
        try:
            bad = signed(capsule, k)
        except Exception as exc:  # noqa: BLE001 -- a change the signer itself refuses
            raise SystemExit(f"{name}: the signer refuses this change ({exc!r}); pick another") from exc
        add(case(f"structure_{name}", covers, [push(body(bad))], peer_keys=reg))

    structure("action_type", "an action_type other than fyi/decide", lambda c: c.update(action_type="act"))
    structure("no_operator", "a REQUIRED field missing", lambda c: c.pop("operator"))
    structure("operator_not_string", "a REQUIRED field that is not a string", lambda c: c.update(operator=7))
    structure("effect_not_object", "an effect block that is not an object", lambda c: c.update(effect="done"))
    structure("constraints_not_array", "constraints that are not an array", lambda c: c.update(constraints={}))
    structure("confirmed_without_response", "a confirmed effect with no response digest",
              lambda c: c["effect"].pop("response_digest"))
    structure("verdict_effect_conflict", "a never-dispatch verdict over a confirmed effect",
              lambda c: c["disposition"].update(verdict_class="blocked"))
    structure("effect_attestation_missing", "a confirmed effect with no effect_attestation",
              lambda c: c["effect"].pop("effect_attestation"))
    structure("approver", "an approver outside human/policy/counterparty",
              lambda c: c["disposition"].update(approver="robot"))
    structure("human_disposed_not_bool", "human_disposed that is not a bool",
              lambda c: c["disposition"].update(human_disposed="no"))
    structure("no_decision", "a disposition with no decision", lambda c: c["disposition"].pop("decision"))
    # The reference refuses to compute an id over an integer past 2^53, so this
    # one is sealed by hand: its id is the plain JCS digest with the integer
    # written exactly, which is what an implementation without the guard
    # computes -- it can refuse only by checking the integer itself.
    unsafe = record(text="unsafe_integer")
    unsafe["model_attestation"]["compute_attestation"]["n"] = 2**53 + 1
    add(case("structure_unsafe_integer", "an integer past the JS-safe range, with an id that recomputes without the guard",
             [push(body(signed_exact(unsafe, k)))], peer_keys=reg))

    # --- nesting at the parser's limit, inside a correctly signed half -----
    for depth in (MAX_JSON_DEPTH, MAX_JSON_DEPTH + 1):
        deep = signed(nested_record(depth), k)
        assert json_depth(deep) == depth
        add(case(f"signed_nesting_{depth}", f"a signed half nested {depth} deep", [push(body(deep))], peer_keys=reg))

    # --- claims on a served half, against this node's own record ----------
    provider = "c1f5490e053bee3c" + "0" * 48
    own = record("requested", provider, model_id=f"local-gguf/sha256-{ASKED}")
    creg = {provider: k.key_id}

    def served(served_by, **kw):
        return push(body(signed(record("served", served_by, **kw), k)), sender=provider)

    add(case("claims_honest_served", "a served half that names its sender and the asked weights",
             [served(provider, weights=ASKED)], peer_keys=creg, own=[own]))
    add(case("claims_served_by_other", "a served half naming another server",
             [served("someone-else", weights=ASKED)], peer_keys=creg, own=[own]))
    add(case("claims_served_by_unknown", "served_by 'unknown' names no server",
             [served("unknown", weights=ASKED)], peer_keys=creg, own=[own]))
    add(case("claims_model_swap", "weights other than the ones asked for",
             [served(provider, weights=SWAP)], peer_keys=creg, own=[own]))
    add(case("claims_weights_disagree", "the half's own weights claims disagree",
             [served(provider, weights=ASKED, model_id=f"local-gguf/sha256-{SWAP}")], peer_keys=creg, own=[own]))
    add(case("claims_before_own_record", "a served half arriving before our own record",
             [served(provider, weights=SWAP)], peer_keys=creg))
    add(case("claims_own_record_other_server", "our record routed to another server: no weights pin",
             [served(provider, weights=SWAP)], peer_keys=creg,
             own=[record("requested", "someone-else", model_id=f"local-gguf/sha256-{ASKED}")]))
    add(case("claims_requested_role", "a half whose role is not served skips the claim checks",
             [push(body(signed(record("requested", "someone-else"), k)), sender=provider)],
             peer_keys=creg, own=[own]))

    # --- bundles ----------------------------------------------------------
    leaves = ids("a", 4) + [half["capsule_id"], hashlib.sha256(b"after").hexdigest()]
    good = bundle(half, k, leaves)
    add(case("bundle_valid", "a verified bundle is held with its inclusion", [push(body(good))], peer_keys=reg))
    add(case("bundle_policy_off", "a bundle under policy off", [push(body(good))], peer_keys=reg, policy="off"))
    add(case("bundle_no_sender", "an unidentified bundle", [push(body(good), sender=None)], peer_keys=reg))
    add(case("bundle_key_mismatch", "a bundle from a sender announcing another key",
             [push(body(good))], peer_keys={SENDER: other.key_id}))

    def mutated(fn, base=good):
        b = copy.deepcopy(base)
        fn(b)
        return b

    # An MMR inclusion path never includes the leaf itself, so the other tree
    # must differ in the siblings and peaks the path does include.
    neighbour = signed(record(text="neighbour"), k)
    wrong_leaf = bundle(half, k, leaves)
    wrong_leaf["inclusion"] = bundle(neighbour, k, ids("q", 4) + [neighbour["capsule_id"], ids("r", 1)[0]])["inclusion"]
    add(case("bundle_proof_for_other_leaf", "a proof that does not reach this half",
             [push(body(wrong_leaf))], peer_keys=reg))
    add(case("bundle_root_tampered", "the checkpoint root changed after signing",
             [push(body(mutated(lambda b: b["checkpoint"].update(root="0" * 64))))], peer_keys=reg))
    add(case("bundle_root_tampered_resigned", "a resigned checkpoint over a root the proof does not reach",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "root": "0" * 64}, k)))))],
             peer_keys=reg))
    add(case("bundle_checkpoint_other_key", "a checkpoint signed by a key other than the half's",
             [push(body(bundle(half, other, leaves)))], peer_keys=reg))
    add(case("bundle_checkpoint_names_other_key", "a checkpoint naming another key_id, signed by the sender's own key",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "key_id": other.key_id}, k)))))],
             peer_keys=reg))
    add(case("bundle_checkpoint_bad_signature", "a checkpoint signature over other bytes",
             [push(body(mutated(lambda b: b["checkpoint"].update(signature="ab" * 64))))], peer_keys=reg))
    add(case("bundle_leaf_index_pair_mismatch", "inclusion.leaf_index disagrees with the proof's",
             [push(body(mutated(lambda b: b["inclusion"].update(leaf_index=3))))], peer_keys=reg))
    add(case("bundle_proof_size_mismatch", "a proof size that is not the checkpoint's",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(size=b["inclusion"]["proof"]["size"] + 1))))],
             peer_keys=reg))
    add(case("bundle_leaf_index_past_size", "a leaf index past the tree",
             [push(body(mutated(lambda b: (b["inclusion"].update(leaf_index=10**6), b["inclusion"]["proof"].update(leaf_index=10**6)))))],
             peer_keys=reg))
    add(case("bundle_huge_mmr_size", "a signed checkpoint claiming 2^63 nodes",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "mmr_size": 2**63}, k)))))],
             peer_keys=reg))
    add(case("bundle_long_witness", "a witness list longer than any tree",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(witness=["0" * 64] * 200))))], peer_keys=reg))
    add(case("bundle_version_2", "an unknown bundle version",
             [push(body(mutated(lambda b: b.update(record_push_bundle=2))))], peer_keys=reg))
    add(case("bundle_version_bool", "a bool bundle version",
             [push(body(mutated(lambda b: b.update(record_push_bundle=True))))], peer_keys=reg))
    add(case("bundle_version_float", "a float bundle version 1.0",
             [push(body(mutated(lambda b: b.update(record_push_bundle=1.0))))], peer_keys=reg))
    over = body(good).decode().replace('"leaf_index": 4, "proof"', '"leaf_index": 18446744073709551616, "proof"', 1)
    assert "18446744073709551616" in over
    add(case("bundle_leaf_index_over_64_bits", "a leaf index past 64 bits: refused by the parser, not the bundle check",
             [push(over.encode())], peer_keys=reg))
    add(case("bundle_no_capsule", "a bundle without its half",
             [push(body({k2: v for k2, v in good.items() if k2 != "capsule"}))], peer_keys=reg))
    add(case("bundle_empty_capsule", "a bundle with an empty half",
             [push(body(mutated(lambda b: b.update(capsule={}))))], peer_keys=reg))
    add(case("bundle_forged_half", "a bundle whose half does not verify",
             [push(body(mutated(lambda b: b["capsule"].update(operator="someone-else"))))], peer_keys=reg))
    add(case("bundle_extra_top", "an unknown top-level member",
             [push(body(mutated(lambda b: b.update(x=1))))], peer_keys=reg))
    add(case("bundle_extra_inclusion", "an unknown member inside inclusion",
             [push(body(mutated(lambda b: b["inclusion"].update(x=1))))], peer_keys=reg))
    add(case("bundle_extra_proof", "an unknown member inside the proof",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(x=1))))], peer_keys=reg))
    add(case("bundle_extra_checkpoint", "an unknown member inside the checkpoint",
             [push(body(mutated(lambda b: b["checkpoint"].update(witnesses=[]))))], peer_keys=reg))
    add(case("bundle_missing_proof_member", "a proof without peaks_right",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].pop("peaks_right"))))], peer_keys=reg))
    add(case("bundle_string_proof_size", "a string proof size",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(size=str(b["inclusion"]["proof"]["size"])))))],
             peer_keys=reg))
    add(case("bundle_float_leaf_index", "a float leaf index",
             [push(body(mutated(lambda b: (b["inclusion"].update(leaf_index=4.0), b["inclusion"]["proof"].update(leaf_index=4.0)))))],
             peer_keys=reg))
    add(case("bundle_negative_leaf_index", "a negative leaf index",
             [push(body(mutated(lambda b: b["inclusion"].update(leaf_index=-1))))], peer_keys=reg))
    add(case("bundle_bool_proof_version", "a bool proof version",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(v=True))))], peer_keys=reg))
    add(case("bundle_proof_kind", "a proof kind other than inclusion",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(kind="consistency"))))], peer_keys=reg))
    add(case("bundle_uppercase_witness", "an uppercase witness hash",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(
                 witness=[w.upper() for w in b["inclusion"]["proof"]["witness"]]))))], peer_keys=reg))
    add(case("bundle_short_witness_hash", "a witness hash of the wrong length",
             [push(body(mutated(lambda b: b["inclusion"]["proof"].update(witness=["ab"]))))], peer_keys=reg))
    add(case("bundle_string_checkpoint_size", "a string mmr_size, still signed",
             [push(body(mutated(lambda b: b["checkpoint"].update(mmr_size=f'{b["checkpoint"]["mmr_size"]} '))))],
             peer_keys=reg))
    add(case("bundle_uppercase_root_resigned", "an uppercase root, resigned",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "root": b["checkpoint"]["root"].upper()}, k)))))],
             peer_keys=reg))
    add(case("bundle_checkpoint_kind", "a checkpoint kind other than mmr_checkpoint, resigned",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "kind": "other"}, k)))))],
             peer_keys=reg))
    add(case("bundle_checkpoint_version", "a checkpoint version 2, resigned",
             [push(body(mutated(lambda b: b.__setitem__("checkpoint", sign_checkpoint({**b["checkpoint"], "v": 2}, k)))))],
             peer_keys=reg))
    add(case("bundle_prev_root_without_prev_size", "a prev_root at prev_size 0",
             [push(body(mutated(lambda b: b["checkpoint"].update(prev_root="0" * 64))))], peer_keys=reg))
    add(case("bundle_prev_size_without_prev_root", "prev_size set with an empty prev_root",
             [push(body(mutated(lambda b: b["checkpoint"].update(prev_size=1))))], peer_keys=reg))
    add(case("bundle_short_signature", "a checkpoint signature of the wrong length",
             [push(body(mutated(lambda b: b["checkpoint"].update(signature="ab"))))], peer_keys=reg))
    add(case("bundle_key_id_not_hex", "a checkpoint key_id that is not hex",
             [push(body(mutated(lambda b: b["checkpoint"].update(key_id="z" * 64))))], peer_keys=reg))
    add(case("bundle_log_id_number", "a numeric log_id",
             [push(body(mutated(lambda b: b["checkpoint"].update(log_id=7))))], peer_keys=reg))
    add(case("bundle_inclusion_not_object", "inclusion is a string",
             [push(body(mutated(lambda b: b.update(inclusion="verified"))))], peer_keys=reg))
    add(case("bundle_checkpoint_not_object", "checkpoint is a list",
             [push(body(mutated(lambda b: b.update(checkpoint=[]))))], peer_keys=reg))
    add(case("bundle_marker_on_array", "the marker inside an array body",
             [push(body([good]))], peer_keys=reg))

    # --- held checkpoints: replay, staleness, equivocation ---------------
    add(case("history_replay", "a replayed bundle is answered from what is held and stores nothing",
             [push(body(good)), push(body(good)), push(body(good))], peer_keys=reg))
    big = bundle(half, k, ids("a", 8) + [half["capsule_id"], *ids("b", 1)])
    small = bundle(half, k, ids("c", 2) + [half["capsule_id"]])
    add(case("history_stale", "an older checkpoint at a size never vouched for",
             [push(body(big)), push(body(small))], peer_keys=reg))
    one = bundle(half, k, ids("a", 4) + [half["capsule_id"], *ids("b", 1)])
    two = bundle(half, k, ids("z", 4) + [half["capsule_id"], *ids("b", 1)])
    add(case("history_equivocation", "the same size under a different root",
             [push(body(one)), push(body(two))], peer_keys=reg))
    first = bundle(half, k, ids("a", 4) + [half["capsule_id"]])
    later = bundle(half2, k, ids("a", 4) + [half["capsule_id"], half2["capsule_id"]],
                   prev={**first["checkpoint"], "root": "0" * 64})
    add(case("history_prev_link_equivocation", "a prev link contradicting a held checkpoint",
             [push(body(first)), push(body(later))], peer_keys=reg))
    ids1 = ids("a", 3) + [half["capsule_id"]]
    earlier = bundle(half, k, ids1)
    after = bundle(half2, k, ids1 + [half2["capsule_id"]], prev=earlier["checkpoint"])
    add(case("history_out_of_order", "an older checkpoint the newer one links back to",
             [push(body(after)), push(body(earlier))], peer_keys=reg))
    shared = ids("a", 3) + [half["capsule_id"], half2["capsule_id"]]
    add(case("history_burst", "two halves under one checkpoint",
             [push(body(bundle(half, k, shared))), push(body(bundle(half2, k, shared)))], peer_keys=reg))
    add(case("history_other_log", "another log of the same key is judged apart",
             [push(body(big)), push(body(bundle(half, k, ids("c", 2) + [half["capsule_id"]], log_id="log-2")))],
             peer_keys=reg))
    add(case("history_refused_then_valid", "a refused bundle holds nothing, so the valid one is judged alone",
             [push(body(mutated(lambda b: b["checkpoint"].update(root="0" * 64)))), push(body(good))], peer_keys=reg))
    add(case("history_bare_then_bundle", "a bare push, then the same half as a bundle",
             [push(body(half)), push(body(good))], peer_keys=reg))

    # --- a split's stage records ------------------------------------------
    split = json.loads(SPLIT_FIXTURE.read_text())
    sreg = {"coordinator": split["capsule"]["key_id"]}

    def spush(b):
        return push(body(b), sender="coordinator")

    def smut(fn):
        b = copy.deepcopy(split)
        fn(b)
        return b

    add(case("split_valid", "a split bundle and its stage records are held", [spush(split)], peer_keys=sreg))
    add(case("split_subset", "a subset of the named stage records",
             [spush(smut(lambda b: b.update(split_stage_records=b["split_stage_records"][:1])))], peer_keys=sreg))
    add(case("split_plain", "the same main record without the member",
             [spush({k2: v for k2, v in split.items() if k2 != "split_stage_records"})], peer_keys=sreg))
    add(case("split_tampered", "a tampered stage record",
             [spush(smut(lambda b: b["split_stage_records"][0]["model_attestation"]["compute_attestation"]["x-mesh-stage-v1"]["tokens"].update(
                 decode=b["split_stage_records"][0]["model_attestation"]["compute_attestation"]["x-mesh-stage-v1"]["tokens"]["decode"] + 1)))],
             peer_keys=sreg))
    add(case("split_twice", "a stage record carried twice",
             [spush(smut(lambda b: b["split_stage_records"].append(copy.deepcopy(b["split_stage_records"][0]))))],
             peer_keys=sreg))
    add(case("split_empty", "an empty member", [spush(smut(lambda b: b.update(split_stage_records=[])))], peer_keys=sreg))
    add(case("split_not_list", "a member that is not a list",
             [spush(smut(lambda b: b.update(split_stage_records={})))], peer_keys=sreg))
    # The count is judged before any record is read, so 65 empty items are
    # refused as surely as 65 real ones (and a real record carried twice is
    # refused anyway).
    add(case("split_over_cap", "more stage records than the cap (65), refused before any is read",
             [spush(smut(lambda b: b.update(split_stage_records=[{}] * 65)))], peer_keys=sreg))
    add(case("split_unnamed_record", "a stage record the receipt does not name",
             [spush(smut(lambda b: b["split_stage_records"].__setitem__(0, half)))], peer_keys=sreg))
    add(case("split_on_bare_push", "the member on a bare push is just an unknown field",
             [spush({**split["capsule"], "split_stage_records": split["split_stage_records"]})], peer_keys=sreg))

    names = [c["name"] for c in cases]
    assert len(names) == len(set(names)), "case names must be unique"
    return {
        "v": 1,
        "path": "record-push",
        "now": NOW,
        "note": "Built by build_record_push_corpus.py. Public material only; the keys are discarded.",
        "cases": cases,
    }


def main() -> None:
    try:
        corpus = build()
    finally:
        shutil.rmtree(SCRATCH, ignore_errors=True)
    parity_format.write(CORPUS, corpus, "cases")
    print(f"wrote {len(corpus['cases'])} cases to {CORPUS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
