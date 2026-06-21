"""Tests for organic app link expansion."""

from unittest.mock import MagicMock, patch

from software_butcher.shelves.web.app_link_expand import expand_organic_app_links


def test_expand_follows_organic_links_from_entry():
    entry = "http://example.com/hall/index.php"
    report = "http://example.com/hall/report.php"
    admin = "http://example.com/hall/admin.php"

    html_entry = (
        f'<html><body><a href="report.php">Reports</a>'
        f'<form action="admin.php"><input name="user"></form></body></html>'
    )
    html_report = "<html><body><table><tr><td>booking</td></tr></table></body></html>"

    def fake_follow(url, method, profile, host):
        resp = MagicMock()
        if url.rstrip("/") == entry.rstrip("/"):
            resp.status_code = 200
            resp.body = html_entry
            resp.headers = {}
            resp.final_url = entry
        elif url.rstrip("/") == report.rstrip("/"):
            resp.status_code = 200
            resp.body = html_report
            resp.headers = {}
            resp.final_url = report
        else:
            resp.status_code = 404
            resp.body = ""
            resp.headers = {}
            resp.final_url = url
        return resp

    transport = MagicMock()
    transport.follow_redirects.side_effect = fake_follow

    seen: set[str] = set()
    discovered: list[str] = []
    content_pages: list[dict] = []

    with patch(
        "software_butcher.shelves.web.app_link_expand.analyze_page_content",
        side_effect=lambda url, **kw: {"url": url, "form_count": 1, "content_analysis": True},
    ):
        result = expand_organic_app_links(
                transport,
                "http://example.com",
                "example.com",
                entry_urls=[entry],
                seen=seen,
                content_pages=content_pages,
                discovered=discovered,
                max_depth=1,
                max_pages=5,
        )

    expanded = result["expanded_urls"]
    assert entry.rstrip("/") in [u.rstrip("/") for u in expanded]
    assert any("report.php" in u for u in discovered)
    assert not any("wordlist" in u for u in discovered)
