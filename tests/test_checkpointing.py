# SPDX-License-Identifier: Apache-2.0
"""Layer 1-2 checkpointing (checkpointing.py): the LogSource adapter, cadence-
triggered + reconnect checkpointing, the COSE-wire checkpoint build/register
sequence, and the honest witness-state rendering.

No network calls in this file -- register_checkpoint is monkeypatched to a
local fake. The live-anchor leg (real registration + receipt verification
against witness.agentactioncapsule.org) is exercised by
`run_checkpoint_demo.py --register-live-anchor`, run manually and reported in
the PR body, not in CI (see README "Checkpointing" honesty note).
"""
from __future__ import annotations

import json

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, MmrLedger, WitnessRecord
from capsule_emit.checkpoint.cose_wire import verify_checkpoint_cose_offline
from checkpointing import (
    CheckpointState,
    Ed25519Signer,
    JsonlLogSource,
    describe_witness_state,
)
from scitt_cose import cll


def _signer(tmp_path, key_id: str = "node-a") -> Ed25519Signer:
    # key_id only picks this test's key FILE name -- it no longer becomes
    # Ed25519Signer.key_id (see its docstring: that's always the real key's
    # own raw-pubkey hex now, never an arbitrary caller label).
    return Ed25519Signer(tmp_path / f"{key_id}.pem")


def _fake_capsule(i: int) -> dict:
    return {"capsule_id": f"{i:064x}", "n": i}


@pytest.fixture
def fake_witness(monkeypatch):
    """Stand in for a real Transparency Service: same shape as
    register_checkpoint's return value, no network. Takes the COSE-wire bytes
    register_checkpoint's current signature expects (never a plain
    CheckpointRecord -- the witness route is COSE-only, single-host ruling
    2026-08-27)."""
    calls = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        assert isinstance(checkpoint_cose, bytes)
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


# -- JsonlLogSource -----------------------------------------------------


def test_jsonl_log_source_append_assigns_gapless_seq(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    records = [log.append(_fake_capsule(i)) for i in range(5)]
    assert [r.seq for r in records] == [1, 2, 3, 4, 5]
    assert [r.capsule_id for r in records] == [f"{i:064x}" for i in range(5)]


def test_jsonl_log_source_scan_matches_append_after_reload(tmp_path):
    ledger_path = tmp_path / "capsules.jsonl"
    log = JsonlLogSource(ledger_path)
    for i in range(4):
        log.append(_fake_capsule(i))

    reloaded = JsonlLogSource(ledger_path)  # a fresh instance, as a new process would create
    scanned = list(reloaded.scan())
    assert [r.seq for r in scanned] == [1, 2, 3, 4]
    assert scanned[2].capsule_id == f"{2:064x}"


def test_jsonl_log_source_fetch_by_capsule_id(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    for i in range(3):
        log.append(_fake_capsule(i))
    found = log.fetch(f"{1:064x}")
    assert found is not None
    assert found.seq == 2
    assert log.fetch("0" * 64 + "ff") is None  # not a real id in this ledger -- absent, not a partial match


def test_jsonl_log_source_scan_on_missing_file_is_empty(tmp_path):
    log = JsonlLogSource(tmp_path / "does-not-exist.jsonl")
    assert list(log.scan()) == []


def test_jsonl_log_source_scan_tolerates_a_torn_trailing_line(tmp_path):
    """[bounce 2026-08-28] A --plugin-ledger-dir source reads a ledger a
    SEPARATE process (the Rust plugin) is concurrently appending to. A read
    can land mid-write: the trailing line on disk may be a partial write, no
    closing brace/newline yet. scan() must stop cleanly at the last complete
    line rather than raising -- the complete prefix is still a valid,
    gapless log as of that point; the torn tail is picked up whole on the
    next scan once the writer finishes it."""
    path = tmp_path / "capsules.jsonl"
    complete = [json.dumps(_fake_capsule(i), sort_keys=True) for i in range(3)]
    # No closing brace, no trailing newline -- a write caught mid-flush.
    path.write_text("\n".join(complete) + "\n" + '{"capsule_id": "aa')

    scanned = list(JsonlLogSource(path).scan())
    assert [r.seq for r in scanned] == [1, 2, 3]

    # mutant guard: real corruption NOT at the trailing line is a different
    # failure (a gap, not a race) and must still raise, not be silently
    # dropped.
    corrupt_middle = tmp_path / "capsules-corrupt-middle.jsonl"
    corrupt_middle.write_text(
        json.dumps(_fake_capsule(0), sort_keys=True)
        + "\nnot-json-at-all\n"
        + json.dumps(_fake_capsule(2), sort_keys=True)
        + "\n"
    )
    with pytest.raises(json.JSONDecodeError):
        list(JsonlLogSource(corrupt_middle).scan())


# -- Ed25519Signer: real key_id, both Signer shapes ----------------------


def test_ed25519_signer_key_id_is_the_real_public_key_not_a_label(tmp_path):
    """Mutant guard: key_id must be the real raw Ed25519 public key, hex
    encoded -- verify_checkpoint_signature_offline reconstructs the public
    key straight from it, so an arbitrary label there silently breaks
    offline verification (the bug this signer used to have)."""
    signer = _signer(tmp_path, "node-a")
    assert len(signer.key_id) == 64
    bytes.fromhex(signer.key_id)  # must decode as hex; raises otherwise

    # A second signer over the SAME key file recovers the identical identity.
    reloaded = Ed25519Signer(tmp_path / "node-a.pem")
    assert reloaded.key_id == signer.key_id


def test_ed25519_signer_sign_round_trips_through_offline_verify(tmp_path):
    from capsule_emit.checkpoint import CheckpointRecord
    from capsule_emit.checkpoint.emit import verify_checkpoint_signature_offline

    signer = _signer(tmp_path)
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=3, root="aa" * 32,
        prev_size=0, prev_root="", key_id=signer.key_id,
        timestamp="2026-08-21T00:00:00Z", signature="",
    )
    cp.signature = signer.sign(cp.digest())
    assert verify_checkpoint_signature_offline(cp)

    # mutant: a signature over the wrong bytes must not verify.
    cp.signature = signer.sign("00" * 32)
    assert not verify_checkpoint_signature_offline(cp)


# -- CheckpointState: cadence + persistence ------------------------------


def test_checkpoint_state_cadence_triggers_after_declared_count(tmp_path, fake_witness):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=3, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=_signer(tmp_path), log_id="log-a")

    emitted = []
    for i in range(5):
        log.append(_fake_capsule(i))
        cp = state.record_appended()
        if cp is not None:
            emitted.append(cp)

    # cadence_entries=3: due once after the 3rd append, not before, not on every append.
    assert len(emitted) == 1
    assert len(fake_witness) == 1  # exactly one registration call, not zero and not one-per-entry


def test_checkpoint_state_registers_a_valid_cose_wire_checkpoint(tmp_path, fake_witness):
    """The witness's /checkpoints route is COSE-only (single-host ruling,
    2026-08-27): a checkpoint that only carries a JSON body is unregisterable.
    This is the acceptance check for [mesh-plugin-cll-consume] A3: what
    _checkpoint_now actually sends must decode and verify offline as a real
    kind="cll-checkpoint" COSE_Sign1 statement, not just satisfy the fake's
    call-count."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=3, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=_signer(tmp_path), log_id="log-a")

    for i in range(3):
        log.append(_fake_capsule(i))
        state.record_appended()

    assert len(fake_witness) == 1
    checkpoint_cose, ts_url = fake_witness[0]
    assert ts_url == "https://fake-ts.example"
    result = verify_checkpoint_cose_offline(checkpoint_cose)
    assert result.ok, result.errors

    # The stamp persisted to checkpoints.jsonl carries the same COSE bytes as
    # a sibling hex field, never folded into the JSON checkpoint's own signed
    # body (cp.to_dict()/cp.entry_digest() coverage is unchanged).
    last_line = (tmp_path / "checkpoints.jsonl").read_text().splitlines()[-1]
    record = json.loads(last_line)
    assert bytes.fromhex(record["checkpoint_cose"]) == checkpoint_cose


def test_checkpoint_persists_across_reload(tmp_path, fake_witness):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=2, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    signer = _signer(tmp_path, "node-a")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id="log-a")
    for i in range(2):
        log.append(_fake_capsule(i))
        state.record_appended()
    assert state.last_checkpoint is not None

    # A fresh process: new JsonlLogSource + new CheckpointState reading the same ledger_dir.
    reloaded_log = JsonlLogSource(tmp_path / "capsules.jsonl")
    reloaded = CheckpointState.load(
        ledger_dir=tmp_path, log_source=reloaded_log, cfg=cfg, signer=signer, log_id="log-a"
    )
    assert reloaded.last_checkpoint is not None
    assert reloaded.last_checkpoint.mmr_size == state.last_checkpoint.mmr_size
    assert reloaded.last_checkpoint.root == state.last_checkpoint.root


def test_reconnect_self_heals_backlog_in_one_checkpoint(tmp_path, fake_witness):
    """Mesh architecture doc §4: an offline node keeps appending locally;
    on reconnect it submits ONE checkpoint committing everything accrued
    since the last witnessed one, chained via prev_size/prev_root -- not
    one checkpoint per missed cadence tick."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=100, max_lag_entries=200, ts_urls=["https://fake-ts.example"])
    signer = _signer(tmp_path, "node-a")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id="log-a")

    for i in range(3):
        log.append(_fake_capsule(i))
        assert state.record_appended() is None  # cadence=100: nothing due yet

    first_cp = state.reconnect()  # simulate: node reconnects to its witness
    assert first_cp is not None
    assert first_cp.prev_size == 0
    assert len(fake_witness) == 1

    for i in range(3, 6):  # more capsules land while "offline" (no record_appended calls at all)
        log.append(_fake_capsule(i))

    second_cp = state.reconnect()
    assert second_cp is not None
    assert second_cp.prev_size == first_cp.mmr_size  # chains from the last witnessed checkpoint
    assert second_cp.prev_root == first_cp.root
    assert len(fake_witness) == 2  # one checkpoint for the whole 3-entry gap, not three

    # The second checkpoint's COSE claims must carry a real consistency proof
    # over the first (not just repeat the prev_size/prev_root fields) --
    # checkpoint_to_cose refuses to serialize a prev_size > 0 checkpoint
    # without one, so getting this far already proves it was supplied.
    second_cose, _ = fake_witness[1]
    result = verify_checkpoint_cose_offline(second_cose)
    assert result.ok, result.errors

    # calling reconnect again with nothing new appended must be a no-op.
    assert state.reconnect() is None
    assert len(fake_witness) == 2


# -- Two single-writer logs: never a second writer into a foreign ledger --


def test_checkpoint_state_never_writes_into_a_ledger_it_does_not_own(tmp_path, fake_witness):
    """[mesh-plugin-cll-consume] A3's core constraint: checkpointing a log
    written by someone else (the Rust plugin, here simulated by writing
    capsules.jsonl directly rather than through JsonlLogSource.append) must
    never append anything back into that file -- only into the sibling
    checkpoints.jsonl. Byte-for-byte unchanged capsules.jsonl is the mutant
    guard for "never becomes a second writer" (§4 A2's forbidden topology)."""
    plugin_ledger_dir = tmp_path / "plugin-ledger"
    plugin_ledger_dir.mkdir()
    capsules_path = plugin_ledger_dir / "capsules.jsonl"
    lines = [json.dumps(_fake_capsule(i), sort_keys=True) for i in range(4)]
    capsules_path.write_text("\n".join(lines) + "\n")
    before = capsules_path.read_bytes()

    # Read-only use, exactly as capsule_sidecar.py's plugin_checkpoint wiring
    # does: .append() is never called on this source.
    log = JsonlLogSource(capsules_path)
    cfg = CheckpointConfig(cadence_entries=4, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    state = CheckpointState.load(
        ledger_dir=plugin_ledger_dir, log_source=log, cfg=cfg, signer=_signer(tmp_path), log_id="log-a-plugin"
    )
    cp = state.reconnect()
    assert cp is not None
    assert len(fake_witness) == 1

    assert capsules_path.read_bytes() == before  # untouched, byte-for-byte
    assert (plugin_ledger_dir / "checkpoints.jsonl").exists()  # the stamp landed in the sibling file instead


# -- honesty rendering: witnessed vs self-checkpointed -------------------


def test_describe_witness_state_never_says_witnessed_without_a_real_witness():
    """Mutant guard: a checkpoint with an EMPTY witnesses list must never be
    described as 'witnessed' -- that would overclaim third-party freshness
    evidence nobody provided (the same discipline as rung-2 D1's
    identity_limitation caveat, applied to logs instead of requesters)."""
    from capsule_emit.checkpoint import CheckpointRecord

    unwitnessed = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=3, root="aa" * 32,
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
    )
    line = describe_witness_state(unwitnessed, current_entries=2)
    assert "witnessed" not in line.split("NOT independently ")[0] or "NOT independently witnessed" in line
    assert "NOT independently witnessed" in line
    assert not line.startswith("witnessed")

    witnessed = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=3, root="aa" * 32,
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
        witnesses=[WitnessRecord(ts_url="https://ts.example", entry_hash="x", receipt_b64="eA==", leaf_index=0, tree_size=1)],
    )
    line2 = describe_witness_state(witnessed, current_entries=2)
    assert line2.startswith("witnessed up to entry")
    assert "NOT independently witnessed" not in line2


def test_describe_witness_state_no_checkpoint_yet_is_unwitnessed():
    line = describe_witness_state(None, current_entries=7)
    assert "unwitnessed" in line
    assert "7 entries" in line


def test_describe_witness_state_surfaces_lag_when_log_outgrew_checkpoint():
    from capsule_emit.checkpoint import CheckpointRecord

    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=1, root="aa" * 32,  # size=1 -> leaf_count=1
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
    )
    line = describe_witness_state(cp, current_entries=5)
    assert "4 more entries appended since" in line


# -- offline inclusion verification (scitt_cose.cll), fully hermetic ----


def test_offline_inclusion_verify_round_trips_through_cll(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    for i in range(6):
        log.append(_fake_capsule(i))

    mmr = MmrLedger(log)
    mmr.sync()
    signer = _signer(tmp_path, "node-a")
    from capsule_emit.checkpoint import emit_checkpoint

    cp = emit_checkpoint(mmr, signer, log_id="log-a", timestamp="2026-08-21T00:00:00Z")
    cp_dict = cp.to_dict()
    assert "peaks_digest" not in cp_dict  # Option-C single-commitment shape
    cll_checkpoint = cll.Checkpoint.from_dict(cp_dict)

    target_seq = 3
    proof = mmr.inclusion_proof(target_seq, size=cp.mmr_size)
    cll_proof = cll.InclusionProof.from_dict(
        {
            "v": proof.v, "kind": proof.kind, "size": proof.size, "leaf_index": proof.leaf_index,
            "witness": list(proof.witness), "peaks_left": list(proof.peaks_left), "peaks_right": list(proof.peaks_right),
        }
    )
    body_digest = bytes.fromhex(f"{target_seq - 1:064x}")
    result = cll.verify_leaf_against_checkpoint(
        body_digest=body_digest, leaf_index=target_seq - 1, checkpoint=cll_checkpoint, proof=cll_proof,
    )
    assert result.ok, result.errors

    # mutant: a tampered body_digest (wrong leaf content) must fail, not silently pass.
    tampered_digest = bytes.fromhex(f"{target_seq:064x}")  # a different, real leaf's digest
    mutant_result = cll.verify_leaf_against_checkpoint(
        body_digest=tampered_digest, leaf_index=target_seq - 1, checkpoint=cll_checkpoint, proof=cll_proof,
    )
    assert not mutant_result.ok


# -- load_checkpoint_config: TOML parsing, and the tomli fallback for 3.10 --


def test_load_checkpoint_config_parses_toml_table(tmp_path):
    config_path = tmp_path / "checkpoint.toml"
    config_path.write_text('[checkpoint]\nlog_id = "node-a"\ncadence_entries = 5\n')
    result = checkpointing.load_checkpoint_config(config_path)
    assert result is not None
    cfg, log_id = result
    assert log_id == "node-a"
    assert cfg.cadence_entries == 5


def test_load_checkpoint_config_returns_none_without_checkpoint_table(tmp_path):
    config_path = tmp_path / "checkpoint.toml"
    config_path.write_text('[other]\nfoo = "bar"\n')
    assert checkpointing.load_checkpoint_config(config_path) is None


def test_load_checkpoint_config_falls_back_to_tomli_when_tomllib_absent(tmp_path, monkeypatch):
    """Simulates Python 3.10 (no stdlib `tomllib`): `import tomllib` inside
    `load_checkpoint_config` must raise ModuleNotFoundError and fall back to
    the `tomli` backport (requirements.txt), not crash. Mutant this guards
    against: an unconditional `import tomllib` (no try/except) -- that would
    pass on this test runner's 3.11+ interpreter but break on 3.10."""
    import builtins

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "tomllib":
            raise ModuleNotFoundError("simulated: no stdlib tomllib on Python 3.10")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    config_path = tmp_path / "checkpoint.toml"
    config_path.write_text('[checkpoint]\nlog_id = "node-b"\ncadence_entries = 7\n')
    result = checkpointing.load_checkpoint_config(config_path)
    assert result is not None
    cfg, log_id = result
    assert log_id == "node-b"
    assert cfg.cadence_entries == 7
