#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-provider-no-body-persistence] capsule_sidecar.py's request+response
TEXT PREIMAGE capture: REQUESTER ROLE ONLY, opt-in, DEFAULT OFF.

CORE INVARIANTS under test:
  1. The provider role has NO disclosure write path -- not "off by default",
     structurally absent. Constructing a provider-role NodeState with
     disclose_preimage=True raises; persist_disclosure_preimage() itself
     refuses to run for role="provider"; a provider-role seal through the
     real production entry points never creates disclosures/.
  2. Requester role: disclosure is opt-in (default off); when on, it is a
     LOCAL, out-of-band attachment carried alongside the ledger -- it must
     never change the SIGNED capsule, capsule_id, or the digest-parity
     vectors (request_digest/response_digest are computed exactly as before;
     only an additional file is written next to the ledger). See
     persist_disclosure_preimage()'s docstring.

MODULE-POLLUTION / COLLECTION-ORDER GUARD: mirrors
test_record_capsule_write_before_verify.py -- some sibling test files stub
agent_action_capsule/model_identity at collection time, gated on
`name not in sys.modules` at THAT file's own collection. This file
deliberately does NOT `import capsule_sidecar` at module level (that would
force a real, early `model_identity` import during collection and disarm
test_forwarded_copy_and_keys.py's stub-gate for any test file that happens to
collect after this one alphabetically) -- every import here is lazy, inside
`_capsule_sidecar()`, called only at test-EXECUTION time, by which point
collection (and every file's own stubbing decision) is already finished.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _capsule_sidecar():
    """Import (or re-import) capsule_sidecar with the REAL dependency stack,
    undoing any collection-time stubbing a sibling test file left behind."""
    import capsule_sidecar as cs

    for name in _POLLUTABLE_MODULES:
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


@pytest.fixture
def cs():
    return _capsule_sidecar()


def _build_state(cs, tmp_path: Path, *, role: str = "requester", disclose_preimage: bool = False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=role,
        disclose_preimage=disclose_preimage,
    )


def _seal(cs, state, request_json: dict, response_json: dict) -> dict:
    # Go through the REAL production entry point (the same one
    # handle_chat_completion's non-streaming path uses) rather than hand-
    # assembling a capsule -- so a regression that drops the
    # role-gated persist_disclosure_preimage() call from that wiring is
    # actually caught here, not just by a direct call to
    # persist_disclosure_preimage itself.
    return cs._seal_chat_completion(
        state,
        client_nonce="n" * 32,
        client_nonce_source="sidecar_generated_fallback",
        request_json=request_json,
        request_digest=cs.digest_json(request_json),
        response_json=response_json,
        status_code=200,
        latency_ms=1.0,
    )


REQUEST = {"model": "test-model", "messages": [{"role": "user", "content": "how great is mesh-llm"}]}
RESPONSE = {
    "id": "chatcmpl-1",
    "choices": [{"message": {"role": "assistant", "content": "mesh-llm is a local inference mesh."}}],
}


class TestProviderRoleHasNoDisclosureWritePath:
    def test_disclose_preimage_true_with_provider_role_raises_at_construction(self, cs, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="requester-only"):
            _build_state(cs, tmp_path, role=cs.ROLE_PROVIDER, disclose_preimage=True)

    def test_provider_role_never_scaffolds_disclosures_dir(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path, role=cs.ROLE_PROVIDER, disclose_preimage=False)
        assert not state.disclosures_dir.exists()

    def test_provider_role_seal_leaves_zero_plaintext_on_disk(self, cs, tmp_path: Path) -> None:
        # ACCEPTANCE: a provider run leaves zero plaintext on disk -- proved
        # by listing ledger_dir, not just checking one well-known path. The
        # sealed capsule's own request/response text ("how great is mesh-llm")
        # must not appear in any file under ledger_dir.
        state = _build_state(cs, tmp_path, role=cs.ROLE_PROVIDER)
        _seal(cs, state, REQUEST, RESPONSE)

        assert not state.disclosures_dir.exists()
        needle = b"how great is mesh-llm"
        for path in state.ledger_dir.rglob("*"):
            if path.is_file():
                assert needle not in path.read_bytes()

    def test_persist_disclosure_preimage_refuses_to_run_for_provider_role(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path, role=cs.ROLE_PROVIDER)
        capsule = {"capsule_id": "deadbeef"}
        with pytest.raises(RuntimeError, match="provider role"):
            cs.persist_disclosure_preimage(state, capsule, REQUEST, RESPONSE)


class TestRequesterDisclosurePreimageOptIn:
    def test_disclose_preimage_is_off_by_default(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path)
        assert state.disclose_preimage is False
        assert not state.disclosures_dir.exists()

    def test_disclose_flag_turns_capture_on(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path, disclose_preimage=True)
        assert state.disclose_preimage is True
        assert state.disclosures_dir.is_dir()

    def test_default_off_writes_no_preimage_file(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path, disclose_preimage=False)
        capsule = _seal(cs, state, REQUEST, RESPONSE)

        assert not state.disclosures_dir.exists()
        assert not (state.ledger_dir / "disclosures" / f"{capsule['capsule_id']}.json").exists()

    def test_disclose_on_writes_a_preimage_file_keyed_by_capsule_id(self, cs, tmp_path: Path) -> None:
        state = _build_state(cs, tmp_path, disclose_preimage=True)
        capsule = _seal(cs, state, REQUEST, RESPONSE)

        path = state.disclosures_dir / f"{capsule['capsule_id']}.json"
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["capsule_id"] == capsule["capsule_id"]
        assert data["request_body"] == REQUEST
        assert data["response_body"] == RESPONSE
        assert data["request_text"] == "how great is mesh-llm"
        assert data["response_text"] == "mesh-llm is a local inference mesh."
        assert data["tool_calls_note"] is None

    def test_persisted_preimage_recomputes_to_the_sealed_digests(self, cs, tmp_path: Path) -> None:
        # The whole point: a viewer holding this file must be able to
        # recompute request_digest/response_digest from EXACTLY these bodies
        # and get the SAME sealed digest -- the core "recompute-and-match".
        state = _build_state(cs, tmp_path, disclose_preimage=True)
        capsule = _seal(cs, state, REQUEST, RESPONSE)

        path = state.disclosures_dir / f"{capsule['capsule_id']}.json"
        data = json.loads(path.read_text(encoding="utf-8"))

        effect = capsule["effect"]
        assert cs.digest_json(data["request_body"]) == effect["request_digest"]
        assert cs.digest_json(data["response_body"]) == effect["response_digest"]

    def test_signed_capsule_is_identical_whether_or_not_disclosure_is_on(self, cs, tmp_path: Path) -> None:
        # CORE PRINCIPLE: the SIGNED capsule stays committing to request/
        # response by DIGEST only -- disclosure must never change capsule_id
        # or the digest-parity vectors.
        state_on = _build_state(cs, tmp_path / "on", disclose_preimage=True)
        state_off = _build_state(cs, tmp_path / "off", disclose_preimage=False)

        cap_on = _seal(cs, state_on, REQUEST, RESPONSE)
        cap_off = _seal(cs, state_off, REQUEST, RESPONSE)

        # Both were minted with fresh random nonces/uuids, so strip the fields
        # that legitimately differ run-to-run and compare the rest.
        def _stable(cap: dict) -> dict:
            cap = json.loads(json.dumps(cap))
            cap.pop("action_id", None)
            cap["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"].pop("client_nonce", None)
            return cap

        assert _stable(cap_on)["effect"] == _stable(cap_off)["effect"]
        assert cs.digest_json(REQUEST) == cap_on["effect"]["request_digest"] == cap_off["effect"]["request_digest"]
        assert cs.digest_json(RESPONSE) == cap_on["effect"]["response_digest"] == cap_off["effect"]["response_digest"]


class TestExtractionHelpers:
    def test_extract_prompt_text_reads_the_last_user_message(self, cs) -> None:
        request = {
            "messages": [
                {"role": "system", "content": "be helpful"},
                {"role": "user", "content": "first question"},
                {"role": "assistant", "content": "first answer"},
                {"role": "user", "content": "second question"},
            ]
        }
        assert cs._extract_prompt_text(request) == "second question"

    def test_extract_prompt_text_none_when_no_user_message(self, cs) -> None:
        assert cs._extract_prompt_text({"messages": [{"role": "system", "content": "be helpful"}]}) is None
        assert cs._extract_prompt_text({}) is None

    def test_extract_response_text_and_tool_calls_note(self, cs) -> None:
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{"function": {"name": "web_search", "arguments": "{}"}}],
                    }
                }
            ]
        }
        text, note = cs._extract_response_text(response)
        assert text is None
        assert note == "tool_call(s): web_search"

    def test_extract_response_text_plain_content_no_tool_calls(self, cs) -> None:
        text, note = cs._extract_response_text(RESPONSE)
        assert text == "mesh-llm is a local inference mesh."
        assert note is None


class TestPruneDisclosures:
    def _write_disclosure(self, disclosures_dir: Path, capsule_id: str, *, mtime: float, size_padding: int = 0) -> Path:
        disclosures_dir.mkdir(parents=True, exist_ok=True)
        path = disclosures_dir / f"{capsule_id}.json"
        path.write_text(json.dumps({"capsule_id": capsule_id, "pad": "x" * size_padding}))
        os_utime = __import__("os").utime
        os_utime(path, (mtime, mtime))
        return path

    def test_missing_directory_is_a_noop(self, cs, tmp_path: Path) -> None:
        assert cs.prune_disclosures(tmp_path / "nope", ttl_seconds=1.0) == []

    def test_ttl_removes_old_files_and_keeps_fresh_ones(self, cs, tmp_path: Path) -> None:
        import time

        disclosures_dir = tmp_path / "disclosures"
        now = time.time()
        old = self._write_disclosure(disclosures_dir, "old-capsule", mtime=now - 1000)
        fresh = self._write_disclosure(disclosures_dir, "fresh-capsule", mtime=now)

        removed = cs.prune_disclosures(disclosures_dir, ttl_seconds=500.0, max_bytes=None)

        assert removed == ["old-capsule"]
        assert not old.exists()
        assert fresh.exists()

    def test_ttl_prune_writes_a_purge_tombstone(self, cs, tmp_path: Path) -> None:
        import time

        disclosures_dir = tmp_path / "disclosures"
        self._write_disclosure(disclosures_dir, "old-capsule", mtime=time.time() - 1000)

        cs.prune_disclosures(disclosures_dir, ttl_seconds=500.0)

        purged_log = disclosures_dir.parent / cs.DISCLOSURES_PURGED_LOG
        assert purged_log.exists()
        line = json.loads(purged_log.read_text(encoding="utf-8").splitlines()[0])
        assert line["capsule_id"] == "old-capsule"
        assert line["reason"] == "ttl"
        assert "purged_at" in line

    def test_max_bytes_removes_oldest_first(self, cs, tmp_path: Path) -> None:
        import time

        disclosures_dir = tmp_path / "disclosures"
        now = time.time()
        oldest = self._write_disclosure(disclosures_dir, "a", mtime=now - 300, size_padding=100)
        middle = self._write_disclosure(disclosures_dir, "b", mtime=now - 200, size_padding=100)
        newest = self._write_disclosure(disclosures_dir, "c", mtime=now - 100, size_padding=100)
        total_size = sum(p.stat().st_size for p in (oldest, middle, newest))

        removed = cs.prune_disclosures(disclosures_dir, ttl_seconds=None, max_bytes=total_size - 1)

        assert removed == ["a"]
        assert not oldest.exists()
        assert middle.exists()
        assert newest.exists()

    def test_prune_never_touches_capsules_jsonl(self, cs, tmp_path: Path) -> None:
        import time

        ledger_dir = tmp_path / "ledger"
        ledger_dir.mkdir(parents=True)
        capsules_path = ledger_dir / "capsules.jsonl"
        capsules_path.write_text('{"capsule_id": "old-capsule"}\n')

        disclosures_dir = ledger_dir / "disclosures"
        self._write_disclosure(disclosures_dir, "old-capsule", mtime=time.time() - 1000)

        cs.prune_disclosures(disclosures_dir, ttl_seconds=500.0)

        assert capsules_path.read_text(encoding="utf-8") == '{"capsule_id": "old-capsule"}\n'
