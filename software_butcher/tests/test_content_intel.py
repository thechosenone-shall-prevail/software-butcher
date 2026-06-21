"""Tests for view-source content intelligence."""

from software_butcher.brain.loop import _apply_scanner_gate, _host_has_content_intel
from software_butcher.brain.policy import PolicyDecision
from software_butcher.core.assets import Asset
from software_butcher.shelves.web.content_intel import analyze_page_content
from software_butcher.shelves.web.http_surface import HttpSurfaceAdapter
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


def test_analyze_phpinfo_detects_eol_and_disclosure():
    body = (
        "<html><body><h1>PHP Version</h1><td>PHP Version</td><td>7.4.33</td>"
        "phpinfo() Configuration PHP Core</body></html>"
    )
    result = analyze_page_content(
        "http://example.com/dashboard/phpinfo.php",
        headers={"X-Powered-By": "PHP/7.4.33", "Server": "Apache/2.4.41 (Unix)"},
        body=body,
        title="phpinfo()",
    )
    assert result["page_type"] == "phpinfo"
    assert result["php_version"] == "7.4.33"
    assert any("end-of-life" in c.lower() for c in result["conclusions"])
    assert any("information disclosure" in c.lower() for c in result["conclusions"])


def test_analyze_phpmyadmin_and_mysql_dos_inference():
    body = """
    <html><body><form><input name="pma_username"><input name="pma_password">
    phpMyAdmin mysqli database</form></body></html>
    """
    result = analyze_page_content(
        "http://example.com/phpmyadmin/",
        headers={"Server": "Apache/2.4.41"},
        body=body,
        title="phpMyAdmin",
    )
    assert result["page_type"] == "phpmyadmin"
    assert any("phpmyadmin" in c.lower() for c in result["conclusions"])
    assert any("resource exhaustion" in c.lower() for c in result["conclusions"])


def test_findings_from_surface_emits_content_page_findings():
    surface = {
        "target": "http://example.com",
        "final_url": "http://example.com",
        "success": True,
        "title": "App",
        "page_summary": "Booking portal",
        "headers": {},
        "infrastructure": {},
        "stack_landing": {"detected": False},
        "discovered_urls": [],
        "content_pages": [
            {
                "url": "http://example.com/hall",
                "page_type": "html",
                "conclusions": ["Page has 1 form(s) with fields ['user'] — likely dynamic backend (often MySQL) on each submit."],
                "mysql_signals": ["mysqli"],
                "text_preview": "Hall booking login",
            }
        ],
    }
    findings = HttpSurfaceAdapter._findings_from_surface(surface, "web_endpoint")
    content_findings = [f for f in findings if f.get("provenance") == "http_surface:content_intel"]
    assert len(content_findings) == 1
    assert content_findings[0]["metadata"]["content_analysis"] is True


def test_scanner_gate_blocks_until_content_analysis(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://example.com")
    hypothesis = Hypothesis(
        path="http://example.com/admin",
        reason="scan",
        source_finding_id="test",
        metadata={"asset_type": "web_endpoint"},
    )
    decision = PolicyDecision(
        intent="directory_bruteforce",
        asset=Asset(locator="http://example.com/admin", asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="test",
        options={"capability": "directory_bruteforce"},
    )
    gated = _apply_scanner_gate(store, hypothesis, decision)
    assert gated.options["capability"] == "http_surface_map"
    assert gated.preferred_adapter == "http_surface"

    store.ingest_finding(
        Finding(
            path="http://example.com",
            hypothesis="mapped",
            provenance="http_surface:map",
            metadata={
                "content_analysis": True,
                "page_type": "html",
                "form_count": 2,
                "conclusions": ["Page has 2 form(s) with fields ['user'] — likely dynamic backend."],
            },
        )
    )
    assert _host_has_content_intel(store, "example.com") is True
    allowed = _apply_scanner_gate(store, hypothesis, decision)
    assert allowed.options["capability"] == "directory_bruteforce"


def test_scanner_gate_blocks_nuclei_without_application_surface(tmp_path):
    from software_butcher.brain.loop import _host_has_application_surface

    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://example.com")
    store.ingest_finding(
        Finding(
            path="http://example.com",
            hypothesis="xampp root",
            provenance="http_surface:map",
            metadata={
                "content_analysis": True,
                "stack_landing": {"detected": True, "stack": "xampp_default"},
                "conclusions": ["XAMPP stack confirmed"],
            },
        )
    )
    assert _host_has_content_intel(store, "example.com")
    assert not _host_has_application_surface(store, "example.com")

    decision = PolicyDecision(
        intent="vulnerability_scanning",
        asset=Asset(locator="http://example.com", asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="test",
        options={"capability": "vulnerability_scanning"},
    )
    hypothesis = Hypothesis(path="http://example.com", reason="scan", source_finding_id="t")
    gated = _apply_scanner_gate(store, hypothesis, decision)
    assert gated.options["capability"] == "http_surface_map"
