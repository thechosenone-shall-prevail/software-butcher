from software_butcher.brain.policy import BrainPolicy
from software_butcher.state.schema import Finding
from software_butcher.core.assets import Asset

def test_brain_policy_escalation():
    policy = BrainPolicy()
    
    asset = Asset(locator="http://example.com/admin", asset_type="web_endpoint")
    
    # Test uninteresting finding
    finding_low = Finding(
        path="http://example.com/logo.png",
        hypothesis="Found a logo.",
        provenance="test",
        status="hypothesis",
        confidence=0.1,
        evidence=["logo"],
        asset_type="static_asset",
    )
    decision1 = policy.decide(Asset(locator="http://example.com/logo.png", asset_type="static_asset"), [finding_low])
    assert decision1.intent == "continue_discovery"
    
    # Test interesting finding
    finding_high = Finding(
        path="http://example.com/admin",
        hypothesis="Found admin panel.",
        provenance="test",
        status="confirmed",
        confidence=0.9,
        evidence=["admin"],
        asset_type="web_endpoint",
    )
    decision2 = policy.decide(asset, [finding_high])
    assert decision2.intent == "web_behavior_analysis"
