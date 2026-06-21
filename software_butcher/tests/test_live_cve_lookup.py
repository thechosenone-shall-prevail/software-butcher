"""Tests for live CVE lookup (OSV/NVD)."""

from unittest.mock import patch

from software_butcher.shelves.web.live_cve_lookup import (
    clear_cve_cache,
    lookup_stack_cves,
    query_osv,
)


def setup_function():
    clear_cve_cache()


def test_query_osv_parses_vulnerabilities():
    mock_response = {
        "vulns": [
            {
                "id": "CVE-2024-1234",
                "summary": "Remote code execution in PHP CGI mode",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
            }
        ]
    }
    with patch("software_butcher.shelves.web.live_cve_lookup.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = mock_response
        mock_post.return_value.raise_for_status = lambda: None
        results = query_osv("GitHub", "php/php-src", "8.0.25")
    assert len(results) == 1
    assert results[0]["cve"] == "CVE-2024-1234"
    assert "Remote code execution" in results[0]["summary"]


def test_lookup_stack_cves_merges_components():
    with patch("software_butcher.shelves.web.live_cve_lookup.query_osv") as mock_osv:
        mock_osv.side_effect = [
            [{"cve": "CVE-PHP-1", "component": "php 8.0.25", "source": "osv", "summary": "php issue"}],
            [{"cve": "CVE-APACHE-1", "component": "httpd 2.4.54", "source": "osv", "summary": "apache issue"}],
        ]
        with patch("software_butcher.shelves.web.live_cve_lookup.query_nvd", return_value=[]):
            results = lookup_stack_cves(php_version="8.0.25", apache_version="2.4.54")
    ids = {r["cve"] for r in results}
    assert "CVE-PHP-1" in ids
    assert "CVE-APACHE-1" in ids
