# SPDX-License-Identifier: Apache-2.0
"""assurance_map.py: the shared five-state/nine-property chip module used by
all three Accountability panes ([mesh-panes-map-chips]).

Focus: the five states never round up (only FAIL is an issue; NOT_PRESENT
and NOT_CHECKED are distinct honest facts, both neutral), the nine
properties are never fabricated (a missing property is skipped, not
invented), and `chip()` refuses any state string outside the five.
"""
from __future__ import annotations

import pytest

import assurance_map


def test_chip_builds_a_state_text_pair():
    result = assurance_map.chip(assurance_map.STATE_PASS, "capsule_id recomputes")
    assert result == {"state": assurance_map.STATE_PASS, "text": "capsule_id recomputes"}


def test_chip_text_defaults_to_none():
    result = assurance_map.chip(assurance_map.STATE_NOT_PRESENT)
    assert result["text"] is None


def test_chip_rejects_a_state_outside_the_five():
    """The mutant this grep-gate-adjacent test exists to catch: a caller
    passing an old-vocabulary or invented state string must raise, never
    silently render as some default tone."""
    with pytest.raises(ValueError):
        assurance_map.chip("present-unverified")


def test_chip_rejects_pending():
    with pytest.raises(ValueError):
        assurance_map.chip("pending")


def test_assert_map_complete_passes_a_full_map():
    properties = {key: assurance_map.chip(assurance_map.STATE_PASS) for key in assurance_map.PROPERTY_ORDER}
    assurance_map.assert_map_complete(properties)  # must not raise


def test_assert_map_complete_raises_on_a_missing_property():
    properties = {key: assurance_map.chip(assurance_map.STATE_PASS) for key in assurance_map.PROPERTY_ORDER}
    del properties[assurance_map.PROPERTY_OUTCOME_CORROBORATION]
    with pytest.raises(ValueError):
        assurance_map.assert_map_complete(properties)


def test_assert_map_complete_raises_on_an_invalid_state():
    properties = {key: assurance_map.chip(assurance_map.STATE_PASS) for key in assurance_map.PROPERTY_ORDER}
    properties[assurance_map.PROPERTY_CONTINUITY] = {"state": "present-unverified", "text": None}
    with pytest.raises(ValueError):
        assurance_map.assert_map_complete(properties)


def test_has_issue_false_when_every_property_is_clean():
    properties = {
        assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS),
        assurance_map.PROPERTY_PRODUCER_SIGNATURE: assurance_map.chip(assurance_map.STATE_NOT_PRESENT),
        assurance_map.PROPERTY_CONTINUITY: assurance_map.chip(assurance_map.STATE_NOT_CHECKED),
    }
    assert assurance_map.has_issue(properties) is False


def test_has_issue_true_when_any_property_fails():
    properties = {
        assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS),
        assurance_map.PROPERTY_PRODUCER_SIGNATURE: assurance_map.chip(assurance_map.STATE_FAIL),
    }
    assert assurance_map.has_issue(properties) is True


def test_has_issue_not_present_and_not_checked_are_never_issues():
    """The bug this module exists to fix: an honest "not verified yet" must
    never round up to an issue."""
    properties = {
        assurance_map.PROPERTY_LOCAL_INCLUSION: assurance_map.chip(assurance_map.STATE_NOT_PRESENT),
        assurance_map.PROPERTY_CHECKPOINT_SIGNATURE: assurance_map.chip(assurance_map.STATE_NOT_CHECKED),
    }
    assert assurance_map.has_issue(properties) is False


def test_has_issue_true_when_promise_broken_even_with_a_clean_map():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS)}
    assert assurance_map.has_issue(properties, promise_state="broken") is True


def test_has_issue_true_when_promise_changed_without_saying():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS)}
    assert assurance_map.has_issue(properties, promise_state="changed_without_saying") is True


def test_has_issue_false_when_promise_kept():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS)}
    assert assurance_map.has_issue(properties, promise_state="kept") is False


def test_tone_for_never_rounds_fail_up():
    assert assurance_map.tone_for(assurance_map.STATE_FAIL) == "bad"


def test_tone_for_not_present_and_not_checked_are_both_neutral_not_amber():
    assert assurance_map.tone_for(assurance_map.STATE_NOT_PRESENT) == "neutral"
    assert assurance_map.tone_for(assurance_map.STATE_NOT_CHECKED) == "neutral"


def test_tone_for_resolves_legacy_vocabulary_too():
    assert assurance_map.tone_for("verified") == "good"
    assert assurance_map.tone_for("present-unverified") == "warn"
    assert assurance_map.tone_for("failed") == "bad"
    assert assurance_map.tone_for("pending") == "neutral"


def test_tone_for_unknown_state_defaults_neutral_never_raises():
    assert assurance_map.tone_for("some-made-up-state") == "neutral"


def test_render_pill_uses_the_tone_class():
    html = assurance_map.render_pill(assurance_map.STATE_FAIL, "capsule_id mismatch")
    assert 'class="pill pill-bad"' in html
    assert "capsule_id mismatch" in html


def test_render_chip_strip_skips_missing_properties_never_fabricates():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS)}
    html = assurance_map.render_chip_strip(properties)
    assert "binding" in html
    assert "sig" not in html  # producer_signature was never supplied


def test_render_chip_strip_never_leaks_a_raw_state_string_as_the_label():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_NOT_CHECKED)}
    html = assurance_map.render_chip_strip(properties)
    assert "NOT_CHECKED" not in html.split("title=")[0]  # only in the tooltip, not the visible glyph


def test_render_chip_table_falls_back_to_the_bare_state_when_no_text_given():
    properties = {assurance_map.PROPERTY_CONTENT_BINDING: assurance_map.chip(assurance_map.STATE_PASS)}
    html = assurance_map.render_chip_table(properties)
    assert "PASS" in html
    assert "<td></td>" not in html  # never a blank detail cell


def test_tone_js_object_covers_every_map_state():
    js = assurance_map.tone_js_object()
    for state in assurance_map.CHIP_STATES:
        assert f'"{state}":' in js


def test_tone_js_object_is_valid_json():
    import json

    parsed = json.loads(assurance_map.tone_js_object())
    assert parsed[assurance_map.STATE_FAIL] == "bad"
