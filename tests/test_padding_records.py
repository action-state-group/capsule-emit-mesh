"""Padding records (Evidence Layer -00 §12.1) through the Python readers.

The Rust plugin pads ``capsules.jsonl`` to a bucket before every checkpoint.
A padding line is a LEAF -- the MMR folds it and positions count it -- but it
is never a RECORD: every reader that counts, lists, summarises, or answers a
``record`` query must come out exactly as it would with no padding at all.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest

import checkpointing
import ledger_store_backend
import peer_accountability_tab
import self_accountability
from account_capsule import _fold_range as account_fold
from capsule_emit.checkpoint import CheckpointConfig, CheckpointRecord, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from evidence_responder import _names_padding_record, classify_leaf_kind
from padding_record import PADDING_RECORD_TYPE, is_padding_record, without_padding
from served_summary import build_served_summary, verify_served_summary


def _padding() -> dict:
    """A padding line in the plugin's shape (``padding.rs``). The id is a
    digest over the committed members; its exact construction only matters
    to the Rust ledger's own reload check, not to these readers."""
    body = {"record_type": PADDING_RECORD_TYPE, "epistemic_type": "producer_claim", "store_nonce": secrets.token_hex(32)}
    capsule_id = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {"capsule_id": capsule_id, **body}


def _served(i: int, *, peer: str = "peer-b") -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "operator": "op",
        "timestamp": "2026-09-27T17:08:00.000Z",
        "model_attestation": {
            "model_id": "m",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "role": "served",
                    "latency_ms": "10.0",
                    "serving_provenance": {
                        "served_by_node_id": "node-a",
                        "requesting_party": peer,
                        "exchange_id": f"ex-{i}",
                        "model_canonical_ref": "m/1",
                        "quantization": "Q4",
                    },
                }
            },
        },
        "effect": {"status": "confirmed", "request_digest": "a" * 64, "response_digest": "b" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _interleave(records: list[dict], every: int = 2) -> list[dict]:
    """``records`` with padding lines interleaved and a tail of padding --
    the shape a padded ledger has after a few checkpoints."""
    out: list[dict] = []
    for i, r in enumerate(records, start=1):
        out.append(r)
        if i % every == 0:
            out.append(_padding())
    out.extend(_padding() for _ in range(3))
    return out


def _write_ledger(ledger_dir: Path, lines: list[dict]) -> Path:
    ledger_dir.mkdir(parents=True, exist_ok=True)
    path = ledger_dir / "capsules.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


@pytest.fixture
def fake_witness(monkeypatch):
    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        return WitnessRecord(ts_url=ts_url, entry_hash="h", receipt_b64="cg==", leaf_index=0, tree_size=1)

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)


def _checkpoint_over(tmp_path: Path, lines: list[dict]) -> CheckpointRecord:
    """One real checkpoint over every line -- padding included, as the
    plugin's MMR folds it."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=len(lines), max_lag_entries=10_000, ts_urls=["https://fake-ts.example"])
    state = CheckpointState.load(
        ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=Ed25519Signer(tmp_path / "k.pem"), log_id="log-a"
    )
    for line in lines:
        log.append(line)
        state.record_appended()
    last = (tmp_path / "checkpoints.jsonl").read_text().splitlines()[-1]
    return CheckpointRecord.from_dict(json.loads(last))


def test_predicate():
    assert is_padding_record(_padding())
    assert not is_padding_record(_served(1))
    assert not is_padding_record({"record_type": "close"})
    assert not is_padding_record("not a record")


def test_page_readers_skip_padding_and_keep_line_cursors(tmp_path):
    real = [_served(i) for i in range(7)]
    _write_ledger(tmp_path, _interleave(real))

    records, _archived = ledger_store_backend.read_all_capsules(tmp_path)
    assert [r["capsule_id"] for r in records] == [r["capsule_id"] for r in real]

    # Paging by line cursor never skips or repeats a real record, whatever
    # the padding does to how many records land on one page.
    seen: list[str] = []
    after = 0
    while True:
        page, _archived, after = ledger_store_backend.read_capsules_page(tmp_path, limit=2, after_seq=after)
        seen.extend(r["capsule_id"] for r in page)
        if after is None:
            break
    assert seen == [r["capsule_id"] for r in real]


def test_mmr_folds_padding_as_leaves(tmp_path, fake_witness):
    real = [_served(i) for i in range(5)]
    lines = _interleave(real)
    cp = _checkpoint_over(tmp_path, lines)
    from capsule_emit.checkpoint import leaf_count

    assert leaf_count(cp.mmr_size) == len(lines), "every padding line is a leaf"


def test_served_summary_counts_are_unchanged_by_padding(tmp_path, fake_witness):
    real = [_served(i) for i in range(6)]
    plain = build_served_summary(
        node_id="n", capsule_records=real, latest_checkpoint=_checkpoint_over(tmp_path / "plain", real)
    )
    lines = _interleave(real)
    padded = build_served_summary(
        node_id="n", capsule_records=lines, latest_checkpoint=_checkpoint_over(tmp_path / "padded", lines)
    )
    assert padded.by_model["m/1"].n_served == plain.by_model["m/1"].n_served == 6
    assert padded.covered_entries == len(lines), "the covered range is a leaf range"

    # A sample that lands on padding neither supports nor contradicts.
    result = verify_served_summary(padded.to_value(), [_padding(), real[0]])
    assert result.ok and result.sampled == 1


def test_account_fold_is_unchanged_by_padding():
    real = [_served(i) for i in range(4)]
    assert account_fold(_interleave(real), "plugin") == account_fold(real, "plugin")


@pytest.mark.parametrize("module", [peer_accountability_tab, self_accountability])
def test_tab_builders_are_unchanged_by_padding(tmp_path, module):
    real = [_served(i, peer=f"peer-{i % 2}") for i in range(5)]
    outputs = []
    for name, lines in [("plain", real), ("padded", _interleave(real))]:
        ledger = _write_ledger(tmp_path / name, lines)
        out = tmp_path / f"{name}.json"
        assert module.main(["build", "--node-id", "node-a", "--log-id", "log-a", "--ledger", str(ledger), "--out", str(out)]) == 0
        outputs.append(json.loads(out.read_text()))
    assert outputs[0] == outputs[1]


def test_range_leaves_name_padding_and_record_queries_never_return_it(tmp_path):
    pad = _padding()
    assert classify_leaf_kind(pad) == "padding"
    assert classify_leaf_kind(_served(1)) == "capsule"

    _write_ledger(tmp_path, [_served(1), pad])
    assert _names_padding_record(tmp_path, pad["capsule_id"])
    assert _names_padding_record(tmp_path, pad["capsule_id"][:12])
    assert not _names_padding_record(tmp_path, _served(1)["capsule_id"])
    assert not _names_padding_record(tmp_path, "")


def test_without_padding_keeps_order():
    a, b = _served(1), _served(2)
    assert without_padding([_padding(), a, _padding(), b]) == [a, b]


def test_record_query_survives_a_torn_tail_line_and_indexes_incrementally(tmp_path):
    """A query can arrive while the plugin is mid-way through writing a
    padding line: the torn tail is not an error, and it is picked up once
    its newline lands. Later lines are read incrementally, and a replaced
    ledger file is rescanned."""
    import evidence_responder

    first, second = _padding(), _padding()
    path = _write_ledger(tmp_path, [_served(1), first])
    torn = json.dumps(second)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(torn[: len(torn) // 2])  # no newline yet

    assert _names_padding_record(tmp_path, first["capsule_id"])
    assert not _names_padding_record(tmp_path, second["capsule_id"])

    with path.open("a", encoding="utf-8") as fh:
        fh.write(torn[len(torn) // 2 :] + "\n")
    assert _names_padding_record(tmp_path, second["capsule_id"])

    # A garbage complete line is skipped, never a crash.
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"record_type": "padding", not json\n')
    assert _names_padding_record(tmp_path, first["capsule_id"])

    # Only the appended bytes are read on the next query.
    key = str(path.resolve())
    consumed = evidence_responder._PADDING_ID_INDEX[key][1]
    assert consumed == path.stat().st_size

    # A replaced file (new inode) is rescanned from the start.
    replacement = _padding()
    path.unlink()
    _write_ledger(tmp_path, [replacement])
    assert _names_padding_record(tmp_path, replacement["capsule_id"])
    assert not _names_padding_record(tmp_path, first["capsule_id"])


def test_python_checkpointers_refuse_unpadded_witnessing(monkeypatch):
    """The Python checkpointers never pad, so they may checkpoint locally but
    never hand a checkpoint to a witness unless the operator opts in."""
    from padding_record import ALLOW_UNPADDED_WITNESSING_ENV, UnpaddedWitnessingRefused, refuse_unpadded_witnessing

    monkeypatch.delenv(ALLOW_UNPADDED_WITNESSING_ENV, raising=False)
    refuse_unpadded_witnessing([], who="t")  # local-only: allowed
    with pytest.raises(UnpaddedWitnessingRefused):
        refuse_unpadded_witnessing(["https://witness.example"], who="t")
    monkeypatch.setenv(ALLOW_UNPADDED_WITNESSING_ENV, "1")
    refuse_unpadded_witnessing(["https://witness.example"], who="t")


def test_sidecar_commits_a_store_nonce_minute_time_and_bucketed_latency():
    from capsule_sidecar import _committed_latency_ms, _utc_now_minute

    assert _utc_now_minute().endswith(":00.000Z")
    assert _committed_latency_ms(40.2) == "100.000"
    assert _committed_latency_ms(1234.5) == "1300.000"
    assert _committed_latency_ms(0.0) == "0.000"
