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
    state = infer_phase(findings, state, engagement_type="assessment")
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
    state = infer_phase(findings, state, engagement_type="assessment")
    assert state.phase == "foothold"


def test_assessment_user_txt_in_evidence_stays_recon():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="Mention of user.txt in scanner output",
            path="http://hallbooking.srmrmp.edu.in/",
            provenance="nuclei",
            evidence=["template matched user.txt path"],
            metadata={"capability": "vulnerability_scanning"},
        )
    ]
    state = infer_phase(findings, state, engagement_type="assessment")
    assert state.phase == "recon"
    assert state.user_flag is None


def test_ctf_mode_advances_on_user_flag_context():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="Read user flag at user.txt",
            path="/home/user/user.txt",
            provenance="shell",
            status="confirmed",
            evidence=["HTB{fake_user_flag}"],
            metadata={"capability": "shell"},
        )
    ]
    state = infer_phase(findings, state, engagement_type="ctf")
    assert state.phase in {"privesc", "exfil", "complete"}


def test_privesc_generates_flag_hypothesis_in_ctf_with_shell():
    state = EngagementState(phase="privesc", engagement_type="ctf")

    class _ShellStore:
        class _Sessions:
            sessions = {"s1": type("S", (), {"active": True})()}

        shell_sessions = _Sessions()

    hyps = phase_hypotheses(
        state,
        "http://10.10.11.1",
        _ShellStore(),
        engagement_type="ctf",
    )
    assert any("root.txt" in h.path for h in hyps)


def test_assessment_phase_hypotheses_empty():
    state = EngagementState(phase="foothold")
    hyps = phase_hypotheses(state, "http://hallbooking.srmrmp.edu.in", engagement_type="assessment")
    assert hyps == []


def test_web_portal_does_not_spawn_user_txt(tmp_path):
    state = EngagementState(phase="foothold")
    hyps = phase_hypotheses(state, "http://hallbooking.srmrmp.edu.in", engagement_type="assessment")
    assert not any("user.txt" in h.path for h in hyps)


def test_phpmyadmin_form_does_not_trigger_foothold():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="Content analysis (phpmyadmin)",
            path="http://hallbooking.srmrmp.edu.in/phpmyadmin/",
            provenance="http_surface:content_intel",
            evidence=["fields=['pma_username', 'pma_password']"],
            metadata={"content_analysis": True, "page_type": "phpmyadmin"},
        )
    ]
    state = infer_phase(findings, state, engagement_type="assessment")
    assert state.phase == "recon"
    assert state.user_flag is None


def test_assessment_stays_recon_on_convergence_without_confirmed_exploit():
    state = EngagementState()
    findings = [
        Finding(
            hypothesis="Content analysis: MySQL/database signals",
            path="http://hallbooking.srmrmp.edu.in/hall",
            provenance="http_surface:content_intel",
            status="confirmed",
            convergence_score=0.82,
            supporting_paths=3,
            evidence=["mysql_signals", "auth bypass surface"],
            metadata={"content_analysis": True, "capability": "http_surface_map", "mysql_signals": ["mysqli"]},
        ),
        Finding(
            hypothesis="High-value path from surface map",
            path="http://hallbooking.srmrmp.edu.in/hallbooking",
            provenance="http_surface:link",
            status="confirmed",
            convergence_score=0.82,
            supporting_paths=3,
            evidence=["discovered_from=http://hallbooking.srmrmp.edu.in"],
            metadata={"capability": "http_surface_map"},
        ),
    ]
    state = infer_phase(findings, state, engagement_type="assessment")
    assert state.phase == "recon"
