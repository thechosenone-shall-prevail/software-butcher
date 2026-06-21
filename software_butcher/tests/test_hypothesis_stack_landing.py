"""Regression: hypothesis generator imports domain semantics."""

from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.state.schema import Finding


def test_stack_landing_generates_semantic_hypotheses():
    finding = Finding(
        path="http://hallbooking.srmrmp.edu.in",
        hypothesis="surface map",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "stack_landing": {"detected": True, "stack": "xampp_default", "conclusion": "xampp"},
        },
    )
    hyps = HypothesisGenerator().generate(finding)
    intents = {h.metadata.get("generated_by") for h in hyps}
    assert "domain_semantics" in intents
    assert "search_index_osint" in intents
