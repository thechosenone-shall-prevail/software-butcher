"""Tests for evidence-lineage hypothesis admission."""

from software_butcher.core.path_relevance import hypothesis_has_evidence_lineage
from software_butcher.state.hypothesis_queue import HypothesisQueue
from software_butcher.state.schema import Finding, Hypothesis


def _finding(**kwargs) -> Finding:
    defaults = {
        "hypothesis": "surface map",
        "path": "http://hallbooking.srmrmp.edu.in",
        "provenance": "http_surface:map",
        "metadata": {
            "capability": "http_surface_map",
            "stack_landing": {"detected": True, "stack": "xampp_default"},
            "content_pages": [
                {
                    "url": "http://hallbooking.srmrmp.edu.in/hall",
                    "conclusions": ["Application entry with forms"],
                }
            ],
        },
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_hypothesis_without_lineage_rejected():
    finding = _finding()
    findings = {finding.id: finding}
    hyp = Hypothesis(
        path="/home/user/user.txt",
        reason="flag hunt",
        source_finding_id="unknown",
        metadata={"intent": "continue_discovery"},
    )
    assert not hypothesis_has_evidence_lineage(hyp, findings, engagement_type="assessment")


def test_content_intel_path_has_lineage():
    finding = _finding()
    findings = {finding.id: finding}
    hyp = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/hall",
        reason="Application entry from content read",
        source_finding_id=finding.id,
        metadata={"generated_by": "content_intel", "intent": "http_surface_map"},
    )
    assert hypothesis_has_evidence_lineage(hyp, findings, engagement_type="assessment")


def test_domain_semantics_without_organic_trace_rejected():
    finding = _finding()
    findings = {finding.id: finding}
    hyp = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/unlinked-guess",
        reason="Hostname guess without organic link",
        source_finding_id=finding.id,
        metadata={"generated_by": "domain_semantics", "intent": "http_surface_map"},
    )
    assert not hypothesis_has_evidence_lineage(hyp, findings, engagement_type="assessment")


def test_ctf_phase_hypothesis_requires_shell():
    hyp = Hypothesis(
        path="/root/root.txt",
        reason="Read root flag",
        source_finding_id="phase:privesc",
        metadata={"intent": "shell_command_execution", "flag_target": "root"},
    )
    assert not hypothesis_has_evidence_lineage(hyp, {}, engagement_type="ctf", session_store=None)


def test_queue_rejects_unlinked_paths():
    finding = _finding()
    queue = HypothesisQueue()
    queue.configure(findings={finding.id: finding}, engagement_type="assessment")
    base = "http://hallbooking.srmrmp.edu.in"
    queue.add(
        Hypothesis(
            path="/home/user/user.txt",
            reason="flag hunt",
            source_finding_id="phase:foothold",
            metadata={"intent": "continue_discovery", "flag_target": "user"},
        ),
        base_target=base,
    )
    assert queue.pending_list() == []


def test_mysql_conclusion_traces_to_surface_hypothesis():
    finding = Finding(
        hypothesis="surface map",
        path="http://hallbooking.srmrmp.edu.in",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "stack_landing": {"detected": True},
            "content_pages": [
                {
                    "url": "http://hallbooking.srmrmp.edu.in/phpmyadmin/",
                    "page_type": "phpmyadmin",
                    "conclusions": ["MySQL/database signals — resource exhaustion class."],
                    "mysql_signals": ["phpmyadmin"],
                }
            ],
        },
    )
    findings = {finding.id: finding}
    hyp = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/phpmyadmin/",
        reason="MySQL resource exhaustion reasoning",
        source_finding_id=finding.id,
        metadata={"generated_by": "mysql_resource_intel", "intent": "http_surface_map"},
    )
    assert hypothesis_has_evidence_lineage(hyp, findings, engagement_type="assessment")

