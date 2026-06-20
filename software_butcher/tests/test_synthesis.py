"""Tests for synthesis verdict generation."""

from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore
from software_butcher.synthesis.lanes import build_assessment_lanes
from software_butcher.synthesis.report import Synthesizer


def test_empty_findings_secure():
    store = FindingStore("unused.json")
    lanes = build_assessment_lanes([])
    verdict = Synthesizer()._verdict([], lanes, store)
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
    store = FindingStore("unused.json")
    for finding in findings:
        store.ingest_finding(finding)
    lanes = build_assessment_lanes(list(store.findings.values()))
    verdict = Synthesizer()._verdict(list(store.findings.values()), lanes, store)
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
