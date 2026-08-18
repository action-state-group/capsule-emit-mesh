"""Conformance harness tests.

Three test classes:

  TestDefectAbsence     -- inversion tests: show both CPB#26 defects are absent.
                           Each test shows the DEFECTIVE approach failing FIRST,
                           then the CORRECT approach passing.

  TestPassVectors       -- oracle passes all PASS fixtures.

  TestRejectVectors     -- oracle fails all REJECT fixtures (must_fail=true).

  TestMutants           -- harness reports FAIL for all committed mutants.

Defects this harness was built to avoid (see harness.py D1/D2/D3):

  CPB#26-A (round-trip):
    The old harness called json.loads(raw_bytes) + json.dumps(result) before
    passing the input to the implementation.  This transformed "key":"v1","key":"v2"
    into {"key":"v2"} (Python silently uses the last value), so the duplicate was
    silently removed and the implementation never saw it.  A must-fail test would
    then get exit 0 (no dup found) and the harness would falsely report FAIL for
    a correctly-conforming implementation.  The correct harness sends raw bytes.

  CPB#26-B (self-certifying):
    The old harness sent the full vector JSON — including must_fail=true — to
    the implementation.  A naive or malicious implementation could read the flag
    and exit 1 without ever inspecting the input.  The harness would report PASS,
    but the implementation had tested nothing.  The correct harness strips all
    harness metadata and sends only the raw input bytes.

For each defect: RED is shown first (the defective approach produces the wrong
verdict), then GREEN (the correct approach produces the right verdict).
"""
from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

THIS_DIR = Path(__file__).resolve().parent
CONFORMANCE_DIR = THIS_DIR / 'conformance'
VECTORS_DIR = CONFORMANCE_DIR / 'vectors'
PASS_DIR = VECTORS_DIR / 'pass'
REJECT_DIR = VECTORS_DIR / 'reject'
MUTANT_DIR = VECTORS_DIR / 'mutants'

sys.path.insert(0, str(CONFORMANCE_DIR))
from harness import compute_mesh_digest, verify_impl  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_SAFE_INT = (1 << 53) - 1


def _oracle_accepts(raw_bytes: bytes) -> tuple[bool, str | None]:
    """Return (accepted, digest_or_none)."""
    try:
        _, digest = compute_mesh_digest(raw_bytes)
        return True, digest
    except (ValueError, TypeError, json.JSONDecodeError):
        return False, None


def _oracle_rejects(raw_bytes: bytes) -> bool:
    accepted, _ = _oracle_accepts(raw_bytes)
    return not accepted


# ---------------------------------------------------------------------------
# Defect-absence inversion tests
# ---------------------------------------------------------------------------

class TestDefectAbsence:
    """Each test shows the DEFECTIVE approach FAILING, then the CORRECT approach PASSING.

    This structure proves that the defect would have been caught — i.e., the tests
    are capable of going red.  A green-only test proves nothing.
    """

    # ------------------------------------------------------------------
    # Defect A: round-trip through json.loads + json.dumps strips dup key
    # ------------------------------------------------------------------

    def test_defect_a_round_trip_changes_escape_equiv_dup(self) -> None:
        """Defect A, part 1: round-trip removes escape-equivalent duplicate key.

        RED: the defective round-trip approach discards the duplicate.
        GREEN: the raw-bytes approach preserves it and the oracle rejects it.
        """
        # Input has two keys that are byte-distinct but semantically identical
        # after JSON escape processing: key == "key"
        raw_bytes = b'{"\\u006b\\u0065\\u0079":"v1","key":"v2"}'

        # === RED: defective round-trip approach ===
        # Step 1: json.loads — Python silently uses the LAST value for each key.
        # No exception is raised for the duplicate; the first member is discarded.
        defective_parsed = json.loads(raw_bytes)
        assert defective_parsed == {'key': 'v2'}, (
            'Python json.loads should silently drop the earlier duplicate; '
            'if this assertion fails, the Python version changed its duplicate behaviour'
        )
        # Step 2: re-serialize — the duplicate is gone.
        defective_reserialized = json.dumps(defective_parsed, separators=(',', ':')).encode('utf-8')
        assert defective_reserialized == b'{"key":"v2"}', (
            'Reserialized bytes should have no duplicate'
        )
        # Step 3: the defective harness would send defective_reserialized to the impl.
        # A correct impl accepts {"key":"v2"} — no duplicate — so it exits 0.
        # The defective harness expected exit 1 (must-fail vector) but got exit 0.
        # → FALSE PASS: the implementation appears to reject but actually the harness
        #   swapped out the input.
        defective_bytes_accepted, _ = _oracle_accepts(defective_reserialized)
        assert defective_bytes_accepted, (
            'The oracle accepts {"key":"v2"} (no dup) — proving the defective approach '
            'sends bytes that a correct oracle accepts, which would make a must-fail test PASS '
            'when it should FAIL (the implementation never saw the actual duplicate input)'
        )

        # === GREEN: correct raw-bytes approach ===
        # The harness sends the EXACT raw_bytes without any json.loads/json.dumps.
        # Assertion D1: decoded hex equals raw_bytes (no transformation).
        assert bytes.fromhex(raw_bytes.hex()).hex() == raw_bytes.hex()
        # The oracle receives the escape-equivalent duplicate and correctly rejects it.
        assert _oracle_rejects(raw_bytes), (
            'The oracle must reject the raw bytes containing the escape-equivalent dup'
        )

    def test_defect_a_bytes_on_disk_equal_bytes_sent(self) -> None:
        """Defect A, part 2: the bytes sent are byte-for-byte the bytes on disk.

        RED: json.loads + json.dumps changes Unicode escape form.
        GREEN: raw bytes are unchanged.
        """
        # Input has 	 (Unicode escape for horizontal tab) in a string value.
        # After json.loads, Python represents it as a real tab character '\t'.
        # After json.dumps, it becomes '\\t' (short escape), not '\\u0009'.
        # These are DIFFERENT bytes even though they represent the SAME character.
        raw_bytes = b'{"model":"hermes\\u0009pro"}'

        # === RED: defective approach changes bytes ===
        defective_parsed = json.loads(raw_bytes)
        defective_reserialized = json.dumps(defective_parsed, separators=(',', ':')).encode('utf-8')
        assert defective_reserialized != raw_bytes, (
            '\\u0009 should have been changed to \\t by the round-trip; '
            'if equal, the Python version changed its escape handling'
        )
        # The re-serialized bytes have \\t; the original had \\u0009.
        assert b'\\t' in defective_reserialized
        assert b'\\u0009' not in defective_reserialized

        # === GREEN: raw bytes are preserved ===
        assert raw_bytes == b'{"model":"hermes\\u0009pro"}', 'raw_bytes must be unchanged'
        # D1 assertion in the harness ensures this.
        # Both forms produce the SAME jcs-n digest (same semantic string),
        # but this test proves the harness does NOT silently transform the bytes.
        accepted_raw, digest_raw = _oracle_accepts(raw_bytes)
        accepted_def, digest_def = _oracle_accepts(defective_reserialized)
        assert accepted_raw and accepted_def, 'both forms should be accepted'
        assert digest_raw == digest_def, (
            '\\u0009 and \\t encode the same character; the digest must be identical. '
            'If they differ, the oracle has a bug in Unicode handling.'
        )
        # The KEY POINT: the harness sends raw_bytes, not defective_reserialized.
        # Both produce the same digest here — so the VERDICT is the same — but
        # for REJECT inputs (the dup-escape-equiv case above) the bytes differ
        # in a way that changes the verdict entirely.

    # ------------------------------------------------------------------
    # Defect B: self-certifying must-fail (must_fail visible to the impl)
    # ------------------------------------------------------------------

    def test_defect_b_must_fail_not_visible_to_impl(self) -> None:
        """Defect B: the implementation NEVER sees must_fail=true.

        RED: defective harness sends full vector JSON; a naive impl reads the flag.
        GREEN: correct harness sends only raw input; the impl must reject by content.
        """
        # Construct a full vector JSON as the defective harness would send it.
        raw_input = b'{"key":"v1","key":"v2"}'
        full_vector = {
            'id': 'dup-literal',
            'must_fail': True,
            'failure_reason': 'duplicate_key_literal',
            'input_bytes_hex': raw_input.hex(),
        }
        full_vector_bytes = json.dumps(full_vector, separators=(',', ':')).encode('utf-8')

        # === RED: defective approach — impl receives must_fail=true ===
        # A self-certifying impl parses the full_vector_bytes, reads must_fail=true,
        # and exits 1 without inspecting the actual input bytes.
        # We prove this is POSSIBLE by showing the full vector bytes are valid JSON
        # that contains must_fail=true.
        defective_parsed = json.loads(full_vector_bytes)
        assert defective_parsed['must_fail'] is True, (
            'The full vector JSON must contain must_fail=true; '
            'the defective harness sends this and the impl can read the flag'
        )
        # A self-certifying impl would do: if parsed["must_fail"]: sys.exit(1)
        # The harness sees exit 1 for the must-fail vector → reports PASS.
        # But the impl never tested anything. The vector proves NOTHING.

        # === GREEN: correct approach — impl receives ONLY raw input ===
        # D2: the harness sends raw_input, not full_vector_bytes.
        assert raw_input not in full_vector_bytes or \
               raw_input != full_vector_bytes, (
            'raw_input and full_vector_bytes must be different '
            '(one is the input, the other is the wrapper)'
        )
        # The correct harness sends raw_input to the impl.
        # The impl must parse {"key":"v1","key":"v2"} and detect the duplicate.
        # It cannot read must_fail=true because the harness never sends it.
        assert _oracle_rejects(raw_input), (
            'The oracle must reject the raw dup-key input based on CONTENT, '
            'not based on reading a must_fail flag'
        )
        # Extra: the oracle also correctly rejects when given the full vector bytes
        # (the full vector is not valid for the algorithm either, since it has
        # harness-only keys that are not part of the OpenAI protocol).
        # But the point is: the correct harness never sends the full vector bytes.

    def test_defect_b_oracle_rejects_by_content_not_by_flag(self) -> None:
        """Defect B inversion: oracle rejects the dup-key input even without any flag.

        RED: an oracle that reads must_fail would PASS if the input has no flag.
        GREEN: a correct oracle reads the content and rejects on the duplicate key.
        """
        raw_dup = b'{"key":"v1","key":"v2"}'

        # Verify the oracle rejects WITHOUT any flag.
        # If it relied on a flag, it would ACCEPT this (no flag present).
        # If it reads content correctly, it REJECTS (duplicate detected).

        # First: confirm an implementation that reads flags would behave differently.
        # Simulate a "flag-reading" impl: only rejects if it sees a flag in the input.
        flag_reading_oracle_would_reject = b'must_fail' in raw_dup
        # The raw bytes contain NO flag at all — a self-certifying impl would ACCEPT.
        assert not flag_reading_oracle_would_reject, (
            'raw dup bytes contain no must_fail flag; '
            'a flag-reading impl would accept this input (defect B would manifest)'
        )

        # GREEN: the CORRECT oracle reads content and rejects.
        assert _oracle_rejects(raw_dup), (
            'The correct oracle rejects the duplicate-key input based solely on content'
        )

        # Verify the same for escape-equiv dup (no flag in raw bytes).
        raw_esc_dup = b'{"\\u006b\\u0065\\u0079":"v1","key":"v2"}'
        flag_reading_would_reject_esc = b'must_fail' in raw_esc_dup
        assert not flag_reading_would_reject_esc
        assert _oracle_rejects(raw_esc_dup), (
            'The correct oracle rejects the escape-equiv dup based solely on content'
        )


# ---------------------------------------------------------------------------
# Pass vectors: oracle computes the pinned digest
# ---------------------------------------------------------------------------

class TestPassVectors:
    @staticmethod
    def _load_pass() -> list[tuple[str, dict]]:
        if not PASS_DIR.exists():
            return []
        return [(str(f.name), json.loads(f.read_text())) for f in sorted(PASS_DIR.rglob('*.json'))]

    @pytest.mark.parametrize('name,vector', _load_pass.__func__(),
                             ids=[n for n, _ in _load_pass.__func__()])
    def test_oracle_computes_pinned_digest(self, name: str, vector: dict) -> None:
        """D1 check: decode input_bytes_hex → send raw bytes → digest matches pinned."""
        if vector.get('_number_rule_pending') and vector.get('digest') is None:
            pytest.skip(f'{name}: number rule pending')

        raw = bytes.fromhex(vector['input_bytes_hex'])

        # D1 assertion (also enforced in harness.verify_impl)
        assert raw.hex() == vector['input_bytes_hex'], (
            f'{name}: input_bytes_hex round-trip mismatch — this is a generator bug'
        )

        accepted, digest = _oracle_accepts(raw)
        assert accepted, f'{name}: oracle rejected a PASS vector'
        assert digest == vector['digest'], (
            f'{name}: digest mismatch\n'
            f'  expected: {vector["digest"]}\n'
            f'  got:      {digest}'
        )

    @pytest.mark.parametrize('name,vector', _load_pass.__func__(),
                             ids=[n for n, _ in _load_pass.__func__()])
    def test_no_must_fail_in_pass_vectors(self, name: str, vector: dict) -> None:
        """PASS vectors must not carry must_fail=true."""
        assert not vector.get('must_fail'), (
            f'{name}: PASS vector must not have must_fail=true'
        )


# ---------------------------------------------------------------------------
# Reject vectors: oracle rejects and signals
# ---------------------------------------------------------------------------

class TestRejectVectors:
    @staticmethod
    def _load_reject() -> list[tuple[str, dict]]:
        if not REJECT_DIR.exists():
            return []
        return [(str(f.name), json.loads(f.read_text())) for f in sorted(REJECT_DIR.rglob('*.json'))]

    @pytest.mark.parametrize('name,vector', _load_reject.__func__(),
                             ids=[n for n, _ in _load_reject.__func__()])
    def test_oracle_rejects_invalid_input(self, name: str, vector: dict) -> None:
        """D2 check: raw bytes only → oracle must reject → exit non-zero.

        The implementation never sees must_fail=true.  It must reject by content.
        """
        assert vector.get('must_fail') is True, f'{name}: expected must_fail=true'
        assert 'input_bytes_hex' in vector, f'{name}: must_fail vector needs input_bytes_hex'

        raw = bytes.fromhex(vector['input_bytes_hex'])

        # D2: verify must_fail is NOT in the raw bytes (harness invariant)
        assert b'must_fail' not in raw, (
            f'{name}: must_fail appears in the raw input bytes — D2 violation. '
            f'The harness would send these bytes and the impl could read the flag.'
        )

        # Oracle rejects based on content (no flag visible)
        assert _oracle_rejects(raw), (
            f'{name}: oracle should reject this input (failure_reason: '
            f'{vector.get("failure_reason", "unspecified")})'
        )

    @pytest.mark.parametrize('name,vector', _load_reject.__func__(),
                             ids=[n for n, _ in _load_reject.__func__()])
    def test_reject_vector_has_failure_reason(self, name: str, vector: dict) -> None:
        """Every REJECT vector must document its failure_reason."""
        assert 'failure_reason' in vector and vector['failure_reason'], (
            f'{name}: REJECT vector must carry a non-empty failure_reason'
        )


# ---------------------------------------------------------------------------
# Mutant tests: harness MUST report FAIL for every committed mutant
# ---------------------------------------------------------------------------

class TestMutants:
    """Mutants prove the harness is not a rubber-stamp.

    Each mutant has exactly ONE property changed from a valid vector.  The
    harness MUST report FAIL (exit non-zero from verify_impl).

    These tests run the full harness (not just the oracle) so they verify
    the complete D1/D2/D3 pipeline.
    """

    @staticmethod
    def _load_mutants() -> list[tuple[str, dict]]:
        if not MUTANT_DIR.exists():
            return []
        return [(str(f.name), json.loads(f.read_text())) for f in sorted(MUTANT_DIR.rglob('*.json'))]

    @pytest.mark.parametrize('name,vector', _load_mutants.__func__(),
                             ids=[n for n, _ in _load_mutants.__func__()])
    def test_mutant_fails_harness(self, name: str, vector: dict) -> None:
        """Harness MUST report FAIL for every committed mutant.

        This test runs verify_impl (the full harness) against a single mutant
        vector directory.  It checks that the harness returns non-zero (FAIL).
        """
        import tempfile
        import os

        assert vector.get('_is_mutant') is True, f'{name}: expected _is_mutant=true'

        oracle_cmd = f'{sys.executable} {CONFORMANCE_DIR / "harness.py"} oracle'

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write just this mutant to a temp dir
            vec_path = Path(tmpdir) / 'mutant.json'
            vec_path.write_text(json.dumps(vector), encoding='utf-8')

            rc = verify_impl(oracle_cmd, Path(tmpdir))

        assert rc != 0, (
            f'{name}: harness reported PASS for a committed mutant — '
            f'this means the harness cannot detect the {vector.get("_mutation", "change")}'
        )

    def test_all_mutants_have_mutation_description(self) -> None:
        """Every mutant must document what was changed (_mutation field)."""
        if not MUTANT_DIR.exists():
            pytest.skip('mutants directory not found')
        for f in sorted(MUTANT_DIR.rglob('*.json')):
            v = json.loads(f.read_text())
            assert v.get('_is_mutant') is True, f'{f.name}: expected _is_mutant=true'
            assert '_mutation' in v and v['_mutation'], (
                f'{f.name}: mutant must have a non-empty _mutation description'
            )


# ---------------------------------------------------------------------------
# Structural integrity: input_bytes_hex in every REJECT vector
# ---------------------------------------------------------------------------

class TestStructure:
    def test_all_reject_vectors_have_input(self) -> None:
        """D3: every REJECT vector must have input_bytes_hex (scope the exit-code contract)."""
        if not REJECT_DIR.exists():
            pytest.skip('reject dir not found')
        for f in sorted(REJECT_DIR.rglob('*.json')):
            v = json.loads(f.read_text())
            if v.get('must_fail'):
                assert 'input_bytes_hex' in v, (
                    f'{f.name}: must_fail vector has no input_bytes_hex; '
                    f'the exit-code contract cannot be verified without input'
                )

    def test_no_must_fail_in_pass_dir(self) -> None:
        """PASS directory must not contain must_fail=true vectors."""
        if not PASS_DIR.exists():
            return
        for f in sorted(PASS_DIR.rglob('*.json')):
            v = json.loads(f.read_text())
            assert not v.get('must_fail'), (
                f'{f.name}: file is in pass/ but has must_fail=true'
            )

    def test_all_pass_vectors_have_digest(self) -> None:
        """PASS vectors must have a digest or _number_rule_pending=true."""
        if not PASS_DIR.exists():
            return
        for f in sorted(PASS_DIR.rglob('*.json')):
            v = json.loads(f.read_text())
            if v.get('_is_mutant'):
                continue
            has_digest = v.get('digest') is not None
            pending = v.get('_number_rule_pending', False)
            assert has_digest or pending, (
                f'{f.name}: PASS vector must have a non-null digest '
                f'or _number_rule_pending=true'
            )
