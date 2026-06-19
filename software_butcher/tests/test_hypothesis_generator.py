from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.state.schema import Finding

def test_hypothesis_generator_cve():
    generator = HypothesisGenerator()
    
    finding = Finding(
        path="http://example.com",
        hypothesis="Found PHP 7.2.0",
        provenance="test",
        status="hypothesis",
        confidence=0.8,
        evidence=["PHP 7.2.0"],
        asset_type="web_endpoint",
        metadata={"capability": "technology_fingerprint", "technologies": ["PHP 7.2.0"]}
    )
    
    hypotheses = generator.generate(finding)
    
    cve_hypo = next((h for h in hypotheses if h.metadata.get("intent") == "cve_lookup"), None)
    assert cve_hypo is not None
    assert cve_hypo.metadata["technology"] == "PHP 7.2.0"
