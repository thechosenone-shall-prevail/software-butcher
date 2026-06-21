"""View-source style content analysis — forms, stack leaks, admin panels, DB signals."""

from __future__ import annotations

import re
from typing import Any

from software_butcher.shelves.web.stack_cve_intel import analyze_stack_cve_viability

PHP_VERSION_HEADER_RE = re.compile(r"PHP[/\s]?([\d.]+)", re.I)
PHPINFO_VERSION_RE = re.compile(r"PHP Version\s*<[^>]*>\s*([\d.]+)", re.I)
MYSQL_SIGNALS = (
    "mysqli",
    "mysql_connect",
    "pdo_mysql",
    "phpmyadmin",
    "mariadb",
    "database",
    "db_host",
    "db_user",
)
FORM_RE = re.compile(r"<form\b", re.I)
INPUT_RE = re.compile(r"<input\b[^>]*\bname\s*=\s*[\"']([^\"']+)", re.I)
PHPINFO_MARKERS = ("php version", "phpinfo()", "configuration", "php core")
PHPMYADMIN_MARKERS = ("phpmyadmin", "pma_username", "input_username", "db_structure.php")


def strip_html_to_text(html: str, *, limit: int = 4000) -> str:
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html or "")
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def parse_php_version(headers: dict[str, str], body: str = "") -> str | None:
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    match = PHP_VERSION_HEADER_RE.search(powered)
    if match:
        return match.group(1)
    if body and "phpinfo" in body.lower():
        match = PHPINFO_VERSION_RE.search(body)
        if match:
            return match.group(1)
    return None


def is_phpinfo_page(url: str, body: str) -> bool:
    sample = (body or "")[:8000].lower()
    return sum(1 for m in PHPINFO_MARKERS if m in sample) >= 2


def is_phpmyadmin_page(url: str, body: str) -> bool:
    sample = (body or "")[:8000].lower()
    return any(m in sample for m in PHPMYADMIN_MARKERS)


def extract_form_fields(body: str) -> list[str]:
    return INPUT_RE.findall(body or "")[:20]


def analyze_page_content(
    url: str,
    *,
    headers: dict[str, str],
    body: str,
    title: str = "",
    nvd_api_key: str | None = None,
) -> dict[str, Any]:
    """Ctrl-U style read: structure, stack leaks, forms, admin exposure."""
    text = strip_html_to_text(body)
    php_version = parse_php_version(headers, body)
    forms = len(FORM_RE.findall(body or ""))
    fields = extract_form_fields(body)
    mysql_signals = [s for s in MYSQL_SIGNALS if s in (body or "").lower() or s in text.lower()]

    page_type = "html"
    if is_phpinfo_page(url, body):
        page_type = "phpinfo"
    elif is_phpmyadmin_page(url, body):
        page_type = "phpmyadmin"

    conclusions: list[str] = []
    if php_version:
        major = php_version.split(".")[0]
        try:
            if int(major) < 8:
                conclusions.append(
                    f"PHP {php_version} is end-of-life — missing security patches; prioritize version exposure and known CVEs."
                )
        except ValueError:
            pass
        conclusions.append(f"Runtime fingerprint: PHP {php_version} (from headers or page body).")

    server = headers.get("Server") or headers.get("server") or ""
    if server:
        conclusions.append(f"Server header: {server}")
        if "apache" in server.lower() and "xampp" in text.lower():
            conclusions.append("XAMPP stack confirmed from Server header and page content.")
        if "perl" in server.lower():
            conclusions.append("Perl runtime referenced in Server header.")

    if page_type == "phpinfo":
        conclusions.append(
            "phpinfo() page exposes full PHP configuration, extensions, and environment — critical information disclosure."
        )
    if page_type == "phpmyadmin":
        conclusions.append(
            "phpMyAdmin interface reachable — database administration exposure; test default creds and auth bypass only within scope."
        )

    if forms or fields:
        conclusions.append(
            f"Page has {forms} form(s) with fields {fields[:8]} — likely dynamic backend (often MySQL) on each submit."
        )
    if mysql_signals:
        conclusions.append(
            f"MySQL/database signals in content ({', '.join(mysql_signals[:5])}) — backend DB handles requests; "
            "application-layer flooding may exhaust DB connections (resource exhaustion class)."
        )

    if title and not conclusions:
        conclusions.append(f"Page title: {title}")

    xampp_detected = "xampp" in text.lower() or (
        "apache" in server.lower() and "xampp" in text.lower()
    )
    stack_cve = analyze_stack_cve_viability(
        url=url,
        php_version=php_version,
        server_header=server,
        page_type=page_type,
        phpmyadmin_detected=page_type == "phpmyadmin",
        phpinfo_exposed=page_type == "phpinfo",
        xampp_detected=xampp_detected,
        auth_required=None if page_type != "phpmyadmin" else False,
        nvd_api_key=nvd_api_key,
    )
    for cve_conclusion in stack_cve.get("conclusions") or []:
        if cve_conclusion not in conclusions:
            conclusions.append(cve_conclusion)

    return {
        "url": url,
        "title": title,
        "page_type": page_type,
        "text_preview": text[:1200],
        "php_version": php_version,
        "form_count": forms,
        "form_fields": fields,
        "mysql_signals": mysql_signals,
        "technologies": [t for t in (f"PHP/{php_version}" if php_version else None, f"Server:{server}" if server else None) if t],
        "conclusions": conclusions,
        "content_analysis": True,
        "stack_cve_candidates": stack_cve.get("stack_cve_candidates") or [],
        "stack_cve_viability_checked": stack_cve.get("stack_cve_viability_checked", False),
    }
