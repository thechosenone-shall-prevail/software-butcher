"""Tests for Brain LLM prompts."""

from software_butcher.brain.prompts import ADVISOR_HYPOTHESIS_PROMPT, BRAIN_CAPABILITY_PROMPT


def test_brain_prompt_is_autonomous_not_ctf():
    lowered = BRAIN_CAPABILITY_PROMPT.lower()
    assert "autonomous" in lowered
    assert "http_surface_map" in lowered
    assert "/admin" not in BRAIN_CAPABILITY_PROMPT


def test_advisor_prompt_no_admin_bias():
    assert "/admin" not in ADVISOR_HYPOTHESIS_PROMPT
    assert "naming patterns" in ADVISOR_HYPOTHESIS_PROMPT.lower()
