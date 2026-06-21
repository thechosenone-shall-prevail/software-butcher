"""Stack CVE viability — live OSV/NVD lookup with exposure-aware reasoning."""

from __future__ import annotations

import re
from typing import Any

from software_butcher.shelves.web.live_cve_lookup import lookup_stack_cves, _reason_viability

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


def analyze_stack_cve_viability(
    *,
    url: str,
    php_version: str | None = None,
    server_header: str = "",
    page_type: str = "html",
    phpmyadmin_detected: bool = False,
    phpmyadmin_version: str | None = None,
    phpinfo_exposed: bool = False,
    xampp_detected: bool = False,
    auth_required: bool | None = None,
    nvd_api_key: str | None = None,
) -> dict[str, Any]:
    """Query live CVE APIs for observed versions; reason about viability on this engagement."""
    apache_match = APACHE_VERSION_RE.search(server_header or "")
    apache_version = apache_match.group(1) if apache_match else None

    live_entries = lookup_stack_cves(
        php_version=php_version,
        apache_version=apache_version,
        phpmyadmin_version=phpmyadmin_version if phpmyadmin_detected else None,
        nvd_api_key=nvd_api_key,
    )

    candidates: list[dict[str, str]] = []
    for entry in live_entries:
        reasoning = _reason_viability(
            entry,
            phpinfo_exposed=phpinfo_exposed,
            phpmyadmin_detected=phpmyadmin_detected,
            auth_required=auth_required,
            xampp_detected=xampp_detected,
            page_type=page_type,
        )
        viable = "maybe"
        if reasoning.startswith("viable="):
            viable = reasoning.split("—", 1)[0].replace("viable=", "").strip()
        candidates.append(
            {
                "cve": entry["cve"],
                "component": entry["component"],
                "viable": viable,
                "reasoning": f"{entry.get('summary', '')[:200]} — {reasoning}",
                "source": entry.get("source", "live"),
                "severity": entry.get("severity", ""),
            }
        )

    if php_version:
        major = _parse_version(php_version)
        if major and major[0] < 8:
            candidates.append(
                {
                    "cve": "EOL-runtime",
                    "component": f"PHP {php_version}",
                    "viable": "yes" if phpinfo_exposed else "maybe",
                    "reasoning": (
                        f"PHP {php_version} is below supported 8.x — missing security patches. "
                        + (
                            "Version confirmed via mapped disclosure page."
                            if phpinfo_exposed
                            else "Confirm runtime version on target before prioritizing."
                        )
                    ),
                    "source": "version-analysis",
                    "severity": "",
                }
            )

    if phpinfo_exposed or page_type == "phpinfo":
        candidates.append(
            {
                "cve": "config-disclosure",
                "component": "phpinfo()",
                "viable": "yes",
                "reasoning": (
                    "phpinfo() mapped on target — paths, extensions, and environment variables exposed; "
                    "prioritize over generic vulnerability_scanning."
                ),
                "source": "exposure-analysis",
                "severity": "",
            }
        )

    if phpmyadmin_detected and auth_required is False:
        candidates.append(
            {
                "cve": "broken-access",
                "component": "phpMyAdmin",
                "viable": "yes",
                "reasoning": (
                    "phpMyAdmin interface reachable without authentication — broken access control class; "
                    "test in-scope before SQLi or directory scanning."
                ),
                "source": "exposure-analysis",
                "severity": "",
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
        "live_cve_lookup": bool(live_entries),
        "conclusions": conclusions,
    }
