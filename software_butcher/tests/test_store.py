from software_butcher.state.store import FindingStore
from software_butcher.state.schema import Finding

def test_finding_store_dedup(tmp_path):
    store = FindingStore(tmp_path / "test.json")
    
    finding1 = Finding(
        path="http://example.com",
        hypothesis="Test 1",
        provenance="test",
        status="hypothesis",
        confidence=0.5,
        evidence=["a"],
        asset_type="web_endpoint",
    )
    
    finding2 = Finding(
        path="http://example.com",
        hypothesis="Test 1",
        provenance="test",
        status="hypothesis",
        confidence=0.5,
        evidence=["a"],
        asset_type="web_endpoint",
    )
    
    assert store.add_finding(finding1)
    assert not store.add_finding(finding2) # Should be deduplicated
    assert len(store.findings) == 1
