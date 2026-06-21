"""Regression: hypothesis generator imports domain semantics."""

from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.state.schema import Finding


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
