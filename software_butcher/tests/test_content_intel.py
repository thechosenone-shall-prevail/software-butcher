"""Tests for view-source content analysis."""

from software_butcher.shelves.web.content_intel import (
    analyze_page_content,
    is_phpinfo_page,
    is_phpmyadmin_page,
)

PHPINFO_BODY = """
<html><body>
<h1>PHP Version</h1><p>phpinfo()</p>
<h2>Configuration</h2><h2>PHP Core</h2>
</body></html>
"""

PHPMYADMIN_BODY = """
<html><body>
<form><input name="pma_username"><input name="input_username"></form>
<a href="db_structure.php">Structure</a>
</body></html>
"""


def test_phpinfo_detected_from_body_not_url_path():
    assert not is_phpinfo_page("http://example.com/admin/info", "")
    assert is_phpinfo_page("http://example.com/admin/info", PHPINFO_BODY)


def test_phpmyadmin_detected_from_body_not_url_path():
    assert not is_phpmyadmin_page("http://example.com/db/console", "")
    assert is_phpmyadmin_page("http://example.com/db/console", PHPMYADMIN_BODY)


def test_analyze_page_content_uses_fetched_body():
    result = analyze_page_content(
        "http://example.com/random-path",
        headers={"Server": "Apache/2.4"},
        body=PHPINFO_BODY,
        title="Info",
    )
    assert result["page_type"] == "phpinfo"
    assert any("phpinfo()" in c for c in result["conclusions"])
