"""Tests for browser redirect hop capture."""

from unittest.mock import MagicMock, patch

from software_butcher.shelves.web.browser_nav import (
    BrowserNavResult,
    _capture_redirect_hops_transport,
    browser_navigate,
)


def test_browser_result_includes_redirect_hops_field():
    result = BrowserNavResult(
        success=True,
        requested_url="http://example.com",
        final_url="http://example.com/login",
        title="Login",
        redirect_hops=[{"url": "http://example.com/admin", "status": 302, "body_len": 9000}],
    )
    data = result.to_dict()
    assert data["redirect_hops"][0]["body_len"] == 9000


def test_transport_fallback_captures_redirect_hops():
    with patch("software_butcher.shelves.web.http_transport.SmartHttpTransport") as mock_cls:
        instance = MagicMock()
        mock_cls.return_value = instance
        instance.follow_redirects.return_value = MagicMock(
            redirect_chain=[
                {"url": "http://example.com/admin.php", "status": 302, "location": "/login.php", "body": "x" * 2000, "body_len": 2000},
            ]
        )
        hops = _capture_redirect_hops_transport("http://example.com/admin.php")
    assert len(hops) == 1
    assert hops[0]["status"] == 302


def test_browser_navigate_disabled():
    result = browser_navigate("http://example.com", enabled=False)
    assert result.success is False
