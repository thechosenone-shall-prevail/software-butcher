"""Tests for synthesis verdict generation."""

from software_butcher.state.schema import Finding
from software_butcher.synthesis.report import Synthesizer


def test_empty_findings_secure():
    verdict = Synthesizer()._verdict([])
    assert verdict.name == "secure"


def test_admin_surface_partially_hardened():
    findings = [
        Finding(
            hypothesis="Login page at /admin",
            path="https://example.com/admin/login",
            provenance="test",
            status="hypothesis",
            confidence=0.7,
            evidence=["login form"],
            asset_type="web_endpoint",
        )
    ]
    verdict = Synthesizer()._verdict(findings)
    assert verdict.name == "partially_hardened"


def test_llm_prompt_uses_real_newlines():
    findings = [
        Finding(
            hypothesis="A",
            path="https://a",
            provenance="t",
            evidence=["e1"],
            asset_type="web_endpoint",
        ),
        Finding(
            hypothesis="B",
            path="https://b",
            provenance="t",
            evidence=["e2"],
            asset_type="web_endpoint",
        ),
    ]
    summary = "\n".join(
        f"- [{f.status}] {f.id}: {f.hypothesis} (conf: {f.confidence})\n  Evidence: {f.evidence}"
        for f in findings
    )
    assert "\n" in summary
    assert "\\n" not in summary
