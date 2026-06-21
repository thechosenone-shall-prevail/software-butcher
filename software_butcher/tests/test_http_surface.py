"""Tests for local HTTP surface mapping."""

from unittest.mock import MagicMock, patch

from software_butcher.core.domain_seed import build_domain_seed_hypotheses
from software_butcher.core.assets import Asset
from software_butcher.shelves.hexstrike.interpreter import HexStrikeInterpreter
from software_butcher.shelves.web.http_surface import (
    HttpSurfaceAdapter,
    infer_technologies,
    map_http_surface,
)
from software_butcher.shelves.web.http_transport import HttpResponse
from software_butcher.state.recon_checklist import record_recon_progress, ReconChecklist
from software_butcher.state.schema import Finding


def _resp(
    url: str,
    *,
    status: int = 200,
    headers: dict | None = None,
    body: str = "",
    chain: list | None = None,
) -> HttpResponse:
    return HttpResponse(
        success=status < 400,
        status_code=status,
        url=url,
        final_url=url,
        headers=headers or {},
        body=body,
        elapsed_s=0.1,
        error=None if status < 400 else f"HTTP {status}",
        profile="browser",
        proxy=None,
        redirect_chain=chain or [{"method": "GET", "url": url, "status": status, "location": headers.get("Location") if headers else None}],
    )


def test_infer_technologies_from_headers():
    tech = infer_technologies({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.33"})
    assert any("PHP/7.4.33" in t for t in tech)
    assert any("Apache" in t for t in tech)


def test_domain_seed_single_surface_map_hypothesis():
    asset = Asset(locator="http://hallbooking.srmrmp.edu.in", asset_type="web_endpoint")
    hyps = build_domain_seed_hypotheses(asset)
    assert len(hyps) == 1
    assert hyps[0].metadata["intent"] == "http_surface_map"


def test_extract_html_links_parses_forms_meta_base_and_js():
    interpreter = HexStrikeInterpreter()
    html = """
    <html><head>
      <base href="http://example.com/app/">
      <meta http-equiv="refresh" content="0;url=/portal">
    </head><body>
      <form action="submit.php"><input formaction="save.php"></form>
      <iframe src="/embedded"></iframe>
      <script>var next = "/reports"; location.href='/admin';</script>
    </body></html>
    """
    links = interpreter.extract_html_links("http://example.com/", html)
    assert "http://example.com/portal" in links
    assert "http://example.com/app/submit.php" in links
    assert "http://example.com/app/save.php" in links
    assert "http://example.com/embedded" in links
    assert "http://example.com/reports" in links
    assert "http://example.com/admin" in links


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_map_http_surface_collects_headers_and_links(mock_cache, mock_follow, _mock_well_known, _mock_browser):
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}

    html = '<html><head><title>Portal</title></head><body><a href="/hall">Hall</a></body></html>'
    response = _resp(
        "http://example.com/",
        headers={"Server": "Apache", "X-Powered-By": "PHP/7.4.33", "Content-Type": "text/html"},
        body=html,
    )
    mock_follow.return_value = response

    surface = map_http_surface("http://example.com", use_browser=False)
    assert surface["success"] is True
    assert any("PHP/7.4.33" in t for t in surface["technologies"])
    assert "http://example.com/hall" in surface["discovered_urls"]
    assert surface["infrastructure"]


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_map_http_surface_preserves_scoped_entry_path(mock_cache, mock_follow, _mock_well_known, _mock_browser):
    """Regression: --target http://host/hall/ must map /hall, not collapse to hostname root."""
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}

    scoped = "http://example.edu/hall"
    html = '<html><head><title>Hall booking</title></head><body><form action="book.php"></form></body></html>'

    def _follow(url, *args, **kwargs):
        return _resp(
            url,
            headers={"Server": "Apache", "Content-Type": "text/html"},
            body=html,
        )

    mock_follow.side_effect = _follow

    surface = map_http_surface(f"{scoped}/", use_browser=False)
    assert surface["target"].rstrip("/").lower() == scoped.rstrip("/").lower()
    assert mock_follow.call_args_list[0][0][0].rstrip("/").lower() == scoped.rstrip("/").lower()

    adapter = HttpSurfaceAdapter()
    findings = adapter._findings_from_surface(surface, "web_endpoint")
    primary = findings[0]
    assert primary["path"].rstrip("/").lower() == scoped.rstrip("/").lower()
    assert primary["metadata"]["mapped_target"].rstrip("/").lower() == scoped.rstrip("/").lower()


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_map_http_surface_includes_redirect_chain_urls(mock_cache, mock_follow, _mock_well_known, _mock_browser):
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}

    chain = [
        {"method": "GET", "url": "http://example.com/", "status": 302, "location": "/dashboard/"},
        {"method": "GET", "url": "http://example.com/dashboard/", "status": 200, "location": None},
    ]
    response = _resp(
        "http://example.com/dashboard/",
        body='<html><body><a href="/faq.html">FAQ</a></body></html>',
        headers={"Server": "Apache"},
        chain=chain,
    )
    mock_follow.return_value = response

    surface = map_http_surface("http://example.com", use_browser=False)
    assert surface["final_url"] == "http://example.com/dashboard/"
    assert len(surface["get_chain"]) == 2
    assert "http://example.com/faq.html" in surface["discovered_urls"]
    assert "http://example.com/dashboard" in surface.get("all_discovered_urls", [])


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_map_http_surface_fetches_robots_and_sitemap(mock_cache, mock_follow, mock_well_known, _mock_browser):
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}
    mock_well_known.return_value = ["http://example.com/hidden"]
    mock_follow.return_value = _resp("http://example.com/", body="<html></html>")

    surface = map_http_surface("http://example.com", use_browser=False)
    assert "http://example.com/hidden" in surface["discovered_urls"]
    mock_well_known.assert_called_once()


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_browser_divergence_adds_browser_final(mock_cache, mock_follow, _mock_well_known, mock_browser):
    mock_follow.return_value = _resp(
        "http://example.com/dashboard/",
        body="<html></html>",
        chain=[{"status": 302, "url": "http://example.com/", "location": "/dashboard/"}],
    )
    mock_browser.return_value = MagicMock(
        success=True,
        requested_url="http://example.com/",
        final_url="http://example.com/hall",
        title="Hall Booking",
        redirect_chain=["http://example.com/", "http://example.com/hall"],
        discovered_urls=["http://example.com/hall/book"],
        error=None,
    )
    mock_browser.return_value.to_dict.return_value = {
        "final_url": "http://example.com/hall",
        "redirect_chain": ["http://example.com/", "http://example.com/hall"],
    }

    surface = map_http_surface("http://example.com")
    assert surface["browser_divergence"] is True
    assert "http://example.com/hall" in surface["discovered_urls"]


def test_surface_map_marks_recon_complete_on_root():
    checklist = ReconChecklist()
    record_recon_progress(
        checklist,
        Finding(
            path="http://hallbooking.srmrmp.edu.in",
            hypothesis="surface",
            provenance="http_surface:map",
            metadata={"capability": "http_surface_map", "mapped_target": "http://hallbooking.srmrmp.edu.in"},
        ),
        base_target="http://hallbooking.srmrmp.edu.in",
    )
    assert checklist.is_complete("hallbooking.srmrmp.edu.in")


def test_surface_map_marks_recon_complete_when_redirect_changes_final_url():
    checklist = ReconChecklist()
    record_recon_progress(
        checklist,
        Finding(
            path="http://hallbooking.srmrmp.edu.in/dashboard/",
            hypothesis="surface",
            provenance="http_surface:map",
            metadata={
                "capability": "http_surface_map",
                "mapped_target": "http://hallbooking.srmrmp.edu.in",
            },
        ),
        base_target="http://hallbooking.srmrmp.edu.in",
    )
    assert checklist.is_complete("hallbooking.srmrmp.edu.in")


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_xampp_landing_does_not_probe_hardcoded_admin_paths(mock_cache, mock_follow, _mock_well_known, _mock_browser):
    """When XAMPP stack is detected, do not probe hardcoded admin paths."""
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}

    xampp_html = (
        '<html><head><title>Welcome to XAMPP</title></head>'
        '<body>XAMPP for Linux — Apache Friends dashboard.</body></html>'
    )
    response = _resp(
        "http://example.com/dashboard/",
        body=xampp_html,
        headers={"Server": "Apache"},
    )
    mock_follow.return_value = response

    surface = map_http_surface("http://example.com", use_browser=False)
    assert surface["stack_landing"]["detected"] is True

    probed_urls = [call.args[0] for call in mock_follow.call_args_list]
    assert not any("/phpmyadmin" in u for u in probed_urls)
    assert not any("/dashboard/phpinfo.php" in u for u in probed_urls)
    assert not surface.get("semantic_probes")


@patch("software_butcher.shelves.web.http_surface.browser_navigate")
@patch("software_butcher.shelves.web.http_surface._fetch_well_known_urls", return_value=[])
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.follow_redirects")
@patch("software_butcher.shelves.web.http_surface.SmartHttpTransport.probe_cache_behavior", return_value={})
def test_xampp_organic_links_fetch_phpmyadmin_and_phpinfo(mock_cache, mock_follow, _mock_well_known, _mock_browser):
    """XAMPP dashboard links to phpMyAdmin/phpinfo should be fetched and content-analyzed."""
    _mock_browser.return_value = MagicMock(
        success=False, final_url="", title="", redirect_chain=[], discovered_urls=[], error="disabled",
    )
    _mock_browser.return_value.to_dict.return_value = {}

    xampp_html = (
        '<html><head><title>Welcome to XAMPP</title></head><body>'
        'XAMPP for Linux — <a href="/phpmyadmin/">phpMyAdmin</a> '
        '<a href="/dashboard/phpinfo.php">phpinfo</a></body></html>'
    )
    root_resp = _resp(
        "http://example.com/dashboard/",
        body=xampp_html,
        headers={"Server": "Apache"},
    )
    phpmyadmin_resp = _resp(
        "http://example.com/phpmyadmin",
        body='<html><head><title>phpMyAdmin</title></head><body><form><input name="pma_username">phpMyAdmin mysqli</form></body></html>',
    )
    phpinfo_resp = _resp(
        "http://example.com/dashboard/phpinfo.php",
        body="<html><body><h1>PHP Version</h1>phpinfo() Configuration PHP Core</body></html>",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )

    def follow_side_effect(url, *args, **kwargs):
        u = url.rstrip("/").lower()
        if u.endswith("/phpmyadmin") or u.endswith("/phpmyadmin/"):
            return phpmyadmin_resp
        if "phpinfo" in u:
            return phpinfo_resp
        return root_resp

    mock_follow.side_effect = follow_side_effect

    surface = map_http_surface("http://example.com", use_browser=False)
    page_types = {p.get("page_type") for p in surface.get("content_pages") or []}
    assert "phpmyadmin" in page_types
    assert "phpinfo" in page_types

    findings = HttpSurfaceAdapter._findings_from_surface(surface, "web_endpoint")
    content_findings = [f for f in findings if f.get("provenance") == "http_surface:content_intel"]
    content_types = {f["metadata"].get("page_type") for f in content_findings}
    assert "phpmyadmin" in content_types
    assert "phpinfo" in content_types
