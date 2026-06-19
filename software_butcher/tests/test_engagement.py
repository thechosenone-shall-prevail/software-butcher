"""Tests for engagement phase transitions."""

from software_butcher.state.engagement import EngagementState, infer_phase, phase_hypotheses
from software_butcher.state.schema import Finding


def test_recon_to_exploit():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="SQL injection confirmed",
            path="https://t/",
            provenance="sqlmap",
            status="confirmed",
            evidence=["union select"],
            metadata={"capability": "vulnerability_confirmed"},
        )
    ]
    state = infer_phase(findings, state)
    assert state.phase == "exploit"


def test_foothold_phase():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="Reverse shell obtained",
            path="10.10.11.1",
            provenance="msf",
            status="confirmed",
            evidence=["uid=33(www-data)"],
            metadata={"capability": "foothold"},
        )
    ]
    state = infer_phase(findings, state)
    assert state.phase == "foothold"


def test_privesc_generates_flag_hypothesis():
    state = EngagementState(phase="privesc")
    hyps = phase_hypotheses(state, "http://10.10.11.1")
    assert any("root.txt" in h.path for h in hyps)
