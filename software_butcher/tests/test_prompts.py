"""Tests for Brain LLM prompts."""

from software_butcher.brain.prompts import (
    ADVISOR_HYPOTHESIS_PROMPT,
    BRAIN_CAPABILITY_PROMPT,
    build_advisor_hypothesis_prompt,
    build_brain_capability_prompt,
)


def test_brain_prompt_is_autonomous_not_ctf():
    lowered = BRAIN_CAPABILITY_PROMPT.lower()
    assert "autonomous" in lowered
    assert "http_surface_map" in lowered
    assert "/admin" not in BRAIN_CAPABILITY_PROMPT
    assert "user.txt" not in BRAIN_CAPABILITY_PROMPT


def test_brain_prompt_emphasizes_content_before_scanners():
    lowered = BRAIN_CAPABILITY_PROMPT.lower()
    assert "view-source" in lowered or "ctrl+u" in lowered
    assert "content_analysis" in lowered
    assert "bugbounty_osint" not in BRAIN_CAPABILITY_PROMPT.split("3.")[1].split("4.")[0]


def test_assessment_prompt_deprioritizes_sqli():
    prompt = build_brain_capability_prompt("assessment")
    lowered = prompt.lower()
    assert "last resort" in lowered
    assert "sql_injection_probing" in lowered
    assert "stack cve" in lowered or "cve viability" in lowered


def test_ctf_prompt_mentions_flags_and_shells():
    prompt = build_brain_capability_prompt("ctf")
    lowered = prompt.lower()
    assert "ctf" in lowered
    assert "shell" in lowered or "flag" in lowered


def test_advisor_prompt_no_admin_bias():
    assert "/admin" not in ADVISOR_HYPOTHESIS_PROMPT
    assert "naming patterns" in ADVISOR_HYPOTHESIS_PROMPT.lower()


def test_advisor_prompt_engagement_aware():
    assessment = build_advisor_hypothesis_prompt("assessment")
    ctf = build_advisor_hypothesis_prompt("ctf")
    assert "evidence lineage" in assessment.lower()
    assert "flag" in ctf.lower() or "shell" in ctf.lower()
