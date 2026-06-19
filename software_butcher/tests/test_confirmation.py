"""Tests for finding confirmation pipeline."""

from software_butcher.brain.confirmation import process_finding, should_confirm
from software_butcher.state.schema import Finding


def test_capability_confirmed_promotes():
    finding = Finding(
        hypothesis="Auth bypass",
        path="https://t/login",
        provenance="playwright",
        metadata={"capability": "auth_bypass_confirmed"},
        evidence=["session cookie set"],
    )
    result = process_finding(finding)
    assert result.status == "confirmed"


def test_convergence_promotes():
    finding = Finding(
        hypothesis="SSRF on upload",
        path="https://t/upload",
        provenance="hexstrike",
        convergence_score=0.8,
        supporting_paths=3,
        evidence=["internal fetch"],
        metadata={"capability": "ssrf"},
    )
    finding.required_evidence = ["response"]
    finding.observed_evidence = ["response"]
    assert should_confirm(finding)
    result = process_finding(finding)
    assert result.status == "confirmed"


def test_evidence_complete_required():
    finding = Finding(
        hypothesis="SQLi",
        path="https://t/id",
        provenance="sqlmap",
        required_evidence=["database", "error"],
        observed_evidence=["mysql syntax error near"],
        evidence=["mysql database syntax error"],
        metadata={"capability": "sqli"},
    )
    assert process_finding(finding).status == "confirmed"
