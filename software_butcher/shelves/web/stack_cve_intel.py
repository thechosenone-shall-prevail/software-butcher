"""Stack-specific CVE viability reasoning from observed versions and exposure."""

from __future__ import annotations

import re
from typing import Any

# Curated shortlist of CVE/component identifiers for local viability reasoning on
# mapped stack signals — not a live CVE database and not used for blind scanning.
APACHE_VERSION_RE = re.compile(r"Apache[/\s]?([\d.]+)", re.I)
PHPMYADMIN_VERSION_RE = re.compile(r"phpMyAdmin[^0-9]*([\d.]+)", re.I)


def _parse_version(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for segment in (version or "").split("."):
        try:
            parts.append(int(re.match(r"(\d+)", segment).group(1)))  # type: ignore[union-attr]
        except (ValueError, AttributeError):
            break
    return tuple(parts)


def _version_in_range(version: str, minimum: str, maximum: str) -> bool:
    v = _parse_version(version)
    lo = _parse_version(minimum)
    hi = _parse_version(maximum)
    if not v or not lo or not hi:
        return False
    return lo <= v <= hi


def analyze_stack_cve_viability(
    *,
    url: str,
    php_version: str | None = None,
    server_header: str = "",
    page_type: str = "html",
    phpmyadmin_detected: bool = False,
    phpinfo_exposed: bool = False,
    xampp_detected: bool = False,
    auth_required: bool | None = None,
) -> dict[str, Any]:
    """Emit CVE candidates with viability reasoning for this engagement context."""
    candidates: list[dict[str, str]] = []
    server_l = (server_header or "").lower()
    apache_match = APACHE_VERSION_RE.search(server_header or "")

    if php_version:
        if _version_in_range(php_version, "7.0.0", "7.4.99"):
            viable = phpinfo_exposed or page_type == "phpinfo"
            candidates.append(
                {
                    "cve": "PHP-7.x-EOL",
                    "component": f"PHP {php_version}",
                    "viable": "yes" if viable else "no",
                    "reasoning": (
                        f"PHP {php_version} is end-of-life — missing security patches. "
                        + (
                            "Viable: phpinfo/version disclosure confirms runtime for targeted CVE research."
                            if viable
                            else "Not viable yet: no phpinfo/version page mapped — confirm exposure before CVE spray."
                        )
                    ),
                }
            )
        if _version_in_range(php_version, "8.0.0", "8.0.30"):
            candidates.append(
                {
                    "cve": "CVE-2024-4577",
                    "component": f"PHP {php_version}",
                    "viable": "maybe",
                    "reasoning": (
                        f"PHP {php_version} in CGI/FPM Windows argument injection range — "
                        "viable only if CGI mode or exposed php-cgi path confirmed (not typical XAMPP mod_php)."
                    ),
                }
            )

    if apache_match:
        apache_ver = apache_match.group(1)
        if _version_in_range(apache_ver, "2.4.49", "2.4.50"):
            candidates.append(
                {
                    "cve": "CVE-2021-41773",
                    "component": f"Apache {apache_ver}",
                    "viable": "maybe",
                    "reasoning": (
                        f"Apache {apache_ver} path traversal/RCE range — viable only if "
                        "directory listing or alias misconfig exposes traversable paths (not blind nuclei)."
                    ),
                }
            )
        if xampp_detected:
            candidates.append(
                {
                    "cve": "XAMPP-default-stack",
                    "component": f"Apache {apache_ver} / XAMPP",
                    "viable": "yes" if (phpmyadmin_detected or phpinfo_exposed) else "maybe",
                    "reasoning": (
                        "XAMPP default stack — prioritize exposed phpMyAdmin/phpinfo and app paths over "
                        + (
                            "generic nuclei/CVE templates."
                            if phpmyadmin_detected or phpinfo_exposed
                            else "scanners until admin/disclosure pages are content-mapped."
                        )
                    ),
                }
            )

    if phpmyadmin_detected:
        candidates.append(
            {
                "cve": "phpMyAdmin-misconfig",
                "component": "phpMyAdmin",
                "viable": "yes" if auth_required is False else "maybe",
                "reasoning": (
                    "phpMyAdmin admin interface reachable — test default creds and broken access control "
                    + (
                        "before SQLi or nuclei."
                        if auth_required is False
                        else "after confirming whether login is required."
                    )
                ),
            }
        )

    if phpinfo_exposed or page_type == "phpinfo":
        candidates.append(
            {
                "cve": "PII-phpinfo-disclosure",
                "component": "phpinfo()",
                "viable": "yes",
                "reasoning": (
                    "phpinfo() exposes environment, paths, and extensions — high-value PII/config disclosure; "
                    "reason locally before vulnerability_scanning."
                ),
            }
        )

    conclusions: list[str] = []
    for item in candidates:
        conclusions.append(
            f"{item['component']} / {item['cve']}: viable={item['viable']} — {item['reasoning']}"
        )

    return {
        "url": url,
        "stack_cve_candidates": candidates,
        "stack_cve_viability_checked": bool(candidates),
        "conclusions": conclusions,
    }
