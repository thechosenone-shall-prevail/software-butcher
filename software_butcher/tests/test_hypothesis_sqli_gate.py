"""Tests for SQLi hypothesis gating — require forms in content intel."""

from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.state.schema import Finding


def test_sqli_hypothesis_requires_forms():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in/hall",
        hypothesis="MySQL signals without forms",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={
            "content_analysis": True,
            "mysql_signals": ["mysqli", "mysql"],
            "conclusions": ["MySQL/database signals in content (mysqli)"],
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    assert not any(h.metadata.get("intent") == "sql_injection_probing" for h in hyps)


def test_sqli_hypothesis_with_forms():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in/hall",
        hypothesis="Form with mysql error",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={
            "content_analysis": True,
            "mysql_signals": ["mysqli"],
            "form_count": 1,
            "form_fields": ["username", "password"],
            "conclusions": [
                "Page has 1 form(s) with fields ['username'] — database error near syntax",
            ],
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    assert any(h.metadata.get("intent") == "sql_injection_probing" for h in hyps)


def test_sqli_hypothesis_forms_without_mysql_or_errors_blocked():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in/hall",
        hypothesis="Form only",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={
            "content_analysis": True,
            "form_count": 1,
            "form_fields": ["username"],
            "conclusions": ["Page has 1 form(s) with fields ['username']"],
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    assert not any(h.metadata.get("intent") == "sql_injection_probing" for h in hyps)
