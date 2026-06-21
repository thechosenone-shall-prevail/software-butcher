"""Tests for browser navigation helper."""

from unittest.mock import patch

from software_butcher.shelves.web.browser_nav import browser_navigate


def test_browser_navigate_disabled():
    result = browser_navigate("http://example.com", enabled=False)
    assert result.success is False
    assert "disabled" in (result.error or "")


def test_browser_navigate_import_error():
    with patch.dict("sys.modules", {"selenium": None}):
        result = browser_navigate("http://example.com")
        assert result.success is False
