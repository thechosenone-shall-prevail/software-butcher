"""Regression: hypothesis generator imports domain semantics."""

from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.state.hypothesis_queue import HypothesisQueue
from software_butcher.state.schema import Finding, Hypothesis


def test_stack_landing_generates_semantic_hypotheses_not_scanners():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in",
        hypothesis="surface map",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "stack_landing": {"detected": True, "stack": "xampp_default", "conclusion": "xampp"},
            "content_pages": [
                {
                    "url": "http://hallbooking.srmrmp.edu.in/hall",
                    "page_type": "html",
                    "conclusions": ["Application entry with forms"],
                }
            ],
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    intents = {h.metadata.get("generated_by") for h in hyps}
    assert "domain_semantics" in intents
    assert "content_intel" in intents
    assert "search_index_osint" not in intents
    assert "stack_mismatch" not in intents
    assert not any(h.metadata.get("intent") == "directory_bruteforce" for h in hyps)
    assert not any(h.metadata.get("intent") == "bugbounty_osint" for h in hyps)
    semantic = [h for h in hyps if h.metadata.get("generated_by") == "domain_semantics"]
    assert len(semantic) <= 3


def test_queue_rejects_ctf_filesystem_paths():
    queue = HypothesisQueue()
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


def test_stack_landing_generates_mysql_resource_hypothesis():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in",
        hypothesis="surface map",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "stack_landing": {"detected": True, "stack": "xampp_default", "conclusion": "xampp"},
            "content_pages": [
                {
                    "url": "http://hallbooking.srmrmp.edu.in/phpmyadmin/",
                    "page_type": "phpmyadmin",
                    "conclusions": [
                        "phpMyAdmin interface reachable",
                        "MySQL/database signals — resource exhaustion class.",
                    ],
                    "mysql_signals": ["phpmyadmin", "mysqli"],
                }
            ],
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    assert any(h.metadata.get("generated_by") == "mysql_resource_intel" for h in hyps)
    assert all(
        h.metadata.get("intent") == "http_surface_map"
        for h in hyps
        if h.metadata.get("generated_by") == "content_intel"
    )
    assert not any(h.metadata.get("intent") == "web_behavior_analysis" for h in hyps)
