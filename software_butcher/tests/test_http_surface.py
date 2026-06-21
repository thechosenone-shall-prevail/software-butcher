"""Tests for local HTTP surface mapping."""

from unittest.mock import patch

from software_butcher.core.domain_seed import build_domain_seed_hypotheses
from software_butcher.core.assets import Asset
from software_butcher.shelves.web.http_surface import (
    HttpSurfaceAdapter,
    infer_technologies,
    map_http_surface,
)
from software_butcher.state.recon_checklist import record_recon_progress, ReconChecklist
from software_butcher.state.schema import Finding


def test_infer_technologies_from_headers():
    tech = infer_technologies({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.33"})
    assert any("PHP/7.4.33" in t for t in tech)
    assert any("Apache" in t for t in tech)


def test_domain_seed_single_surface_map_hypothesis():
    asset = Asset(locator="http://hallbooking.srmrmp.edu.in", asset_type="web_endpoint")
    hyps = build_domain_seed_hypotheses(asset)
    assert len(hyps) == 1
    assert hyps[0].metadata["intent"] == "http_surface_map"


@patch("software_butcher.shelves.web.http_surface._request")
def test_map_http_surface_collects_headers_and_links(mock_request):
    def fake_request(url, method="GET", **kwargs):
        if method == "HEAD":
            return {
                "success": True,
                "status_code": 200,
                "url": url,
                "final_url": url,
                "elapsed_s": 0.1,
                "headers": {"Server": "Apache", "X-Powered-By": "PHP/7.4.33"},
                "body": "",
                "error": None,
            }
        return {
            "success": True,
            "status_code": 200,
            "url": url,
            "final_url": url,
            "elapsed_s": 0.2,
            "headers": {"Server": "Apache", "X-Powered-By": "PHP/7.4.33", "Content-Type": "text/html"},
            "body": '<html><head><title>Portal</title></head><body><a href="/hall">Hall</a></body></html>',
            "error": None,
        }

    mock_request.side_effect = fake_request
    surface = map_http_surface("http://example.com")
    assert surface["success"] is True
    assert any("PHP/7.4.33" in t for t in surface["technologies"])
    assert "http://example.com/hall" in surface["discovered_urls"]

    adapter = HttpSurfaceAdapter()
    result = adapter.execute({"request": type("R", (), {"target": "http://example.com", "asset_type": "web_endpoint"})()})
    assert result.success
    assert any("header:Server=" in e for f in result.findings for e in f.get("evidence", []))


def test_surface_map_marks_recon_complete_on_root():
    checklist = ReconChecklist()
    record_recon_progress(
        checklist,
        Finding(
            path="http://hallbooking.srmrmp.edu.in",
            hypothesis="surface",
            provenance="http_surface:map",
            metadata={"capability": "http_surface_map"},
        ),
        base_target="http://hallbooking.srmrmp.edu.in",
    )
    assert checklist.is_complete("hallbooking.srmrmp.edu.in")
