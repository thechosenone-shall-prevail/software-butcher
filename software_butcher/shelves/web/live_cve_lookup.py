"""Live CVE intelligence via OSV and NVD — no hardcoded CVE catalog."""

from __future__ import annotations

import re
import time
from typing import Any

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Component identity for API queries only (not endpoint paths).
_COMPONENT_QUERIES: tuple[tuple[str, str, str, str, str], ...] = (
    ("php", "GitHub", "php/php-src", "php", "php"),
    ("apache", "GitHub", "apache/httpd", "apache", "http_server"),
    ("phpmyadmin", "Packagist", "phpmyadmin/phpmyadmin", "phpmyadmin", "phpmyadmin"),
)

_session_cache: dict[str, list[dict[str, Any]]] = {}


def _cache_key(source: str, component: str, version: str) -> str:
    return f"{source}:{component}:{version}"


def _parse_version(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for segment in (version or "").split("."):
        try:
            parts.append(int(re.match(r"(\d+)", segment).group(1)))  # type: ignore[union-attr]
        except (ValueError, AttributeError):
            break
    return tuple(parts)


def _version_affected(version: str, affected_ranges: list[dict]) -> bool:
    """Return True if version falls in any OSV affected range."""
    v = _parse_version(version)
    if not v:
        return True
    for affected in affected_ranges or []:
        for item in affected.get("ranges") or []:
            if item.get("type") != "ECOSYSTEM":
                continue
            for event in item.get("events") or []:
                if "introduced" in event:
                    intro = _parse_version(str(event["introduced"]))
                    if intro and v < intro:
                        continue
                if "fixed" in event:
                    fixed = _parse_version(str(event["fixed"]))
                    if fixed and v >= fixed:
                        break
            else:
                return True
    return bool(affected_ranges)


def query_osv(ecosystem: str, package: str, version: str, *, timeout: int = 15) -> list[dict[str, Any]]:
    key = _cache_key("osv", f"{ecosystem}/{package}", version)
    if key in _session_cache:
        return _session_cache[key]

    payload = {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        _session_cache[key] = []
        return []

    results: list[dict[str, Any]] = []
    for vuln in data.get("vulns") or []:
        vid = str(vuln.get("id") or "")
        if not vid:
            continue
        summary = str(vuln.get("summary") or vuln.get("details") or "")[:500]
        affected = vuln.get("affected") or []
        if not _version_affected(version, affected):
            continue
        results.append(
            {
                "cve": vid,
                "component": f"{package} {version}",
                "source": "osv",
                "summary": summary,
                "severity": _extract_severity(vuln),
            }
        )

    _session_cache[key] = results[:10]
    return _session_cache[key]


def query_nvd(vendor: str, product: str, version: str, *, api_key: str | None = None, timeout: int = 20) -> list[dict[str, Any]]:
    key = _cache_key("nvd", f"{vendor}/{product}", version)
    if key in _session_cache:
        return _session_cache[key]

    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={"cpeName": cpe, "resultsPerPage": 10},
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 403:
            time.sleep(6)
            resp = requests.get(
                NVD_CVE_URL,
                params={"cpeName": cpe, "resultsPerPage": 10},
                headers=headers,
                timeout=timeout,
            )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        _session_cache[key] = []
        return []

    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions") or []
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = str(desc.get("value") or "")[:500]
                break
        metrics = cve.get("metrics") or {}
        severity = ""
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key) or []
            if entries:
                cvss = entries[0].get("cvssData") or {}
                severity = str(cvss.get("baseSeverity") or "")
                break
        results.append(
            {
                "cve": cve_id,
                "component": f"{product} {version}",
                "source": "nvd",
                "summary": summary,
                "severity": severity,
            }
        )

    _session_cache[key] = results[:10]
    return _session_cache[key]


def _extract_severity(vuln: dict) -> str:
    for item in vuln.get("severity") or []:
        if item.get("type") == "CVSS_V3":
            return str(item.get("score") or "")
    return ""


def _reason_viability(
    cve_entry: dict[str, Any],
    *,
    phpinfo_exposed: bool,
    phpmyadmin_detected: bool,
    auth_required: bool | None,
    xampp_detected: bool,
    page_type: str,
) -> str:
    """Derive viable yes/no/maybe from live CVE text + observed exposure — no fixed CVE rules."""
    summary = (cve_entry.get("summary") or "").lower()
    viable = "maybe"
    reasons: list[str] = []

    if any(k in summary for k in ("information disclosure", "expose", "disclosure", "leak")):
        if phpinfo_exposed or page_type == "phpinfo":
            viable = "yes"
            reasons.append("information-disclosure class matches observed phpinfo exposure")
        else:
            viable = "no"
            reasons.append("disclosure CVE requires version/config exposure not yet confirmed")

    if any(k in summary for k in ("authentication bypass", "unauthenticated", "without authentication")):
        if auth_required is False:
            viable = "yes"
            reasons.append("unauthenticated access observed on target surface")
        elif auth_required is True:
            viable = "no"
            reasons.append("authentication required — bypass preconditions not met")
        else:
            reasons.append("confirm auth boundary before treating bypass as viable")

    if any(k in summary for k in ("remote code execution", "rce", "command injection", "arbitrary code")):
        if phpinfo_exposed and ("cgi" in summary or "windows" in summary):
            viable = "maybe"
            reasons.append("RCE class requires runtime/config confirmation (e.g. CGI mode) — not blind exploit")
        elif xampp_detected and phpmyadmin_detected:
            viable = "maybe"
            reasons.append("admin stack exposed — validate exploit path locally before spray")
        else:
            viable = "no"
            reasons.append("RCE preconditions not evidenced on mapped surface")

    if any(k in summary for k in ("denial of service", "resource exhaustion", "memory")):
        if phpmyadmin_detected or page_type == "phpmyadmin":
            viable = "yes"
            reasons.append("DoS/resource class relevant to observed DB admin surface")
        else:
            viable = "maybe"
            reasons.append("DoS class — confirm stateful/DB-backed endpoints before testing")

    if not reasons:
        reasons.append("live CVE matches observed version — map exposure and config before active exploit")

    return f"viable={viable} — {'; '.join(reasons)}"


def lookup_component_cves(
    component_key: str,
    version: str,
    *,
    nvd_api_key: str | None = None,
) -> list[dict[str, Any]]:
    if not version:
        return []
    for key, ecosystem, package, vendor, product in _COMPONENT_QUERIES:
        if key != component_key:
            continue
        merged: dict[str, dict[str, Any]] = {}
        for entry in query_osv(ecosystem, package, version):
            merged[entry["cve"]] = entry
        for entry in query_nvd(vendor, product, version, api_key=nvd_api_key):
            merged[entry["cve"]] = entry
        return list(merged.values())
    return []


def lookup_stack_cves(
    *,
    php_version: str | None = None,
    apache_version: str | None = None,
    phpmyadmin_version: str | None = None,
    nvd_api_key: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch live CVE candidates for all observed stack versions."""
    out: list[dict[str, Any]] = []
    if php_version:
        out.extend(lookup_component_cves("php", php_version, nvd_api_key=nvd_api_key))
    if apache_version:
        out.extend(lookup_component_cves("apache", apache_version, nvd_api_key=nvd_api_key))
    if phpmyadmin_version:
        out.extend(lookup_component_cves("phpmyadmin", phpmyadmin_version, nvd_api_key=nvd_api_key))
    return out[:20]


def clear_cve_cache() -> None:
    _session_cache.clear()
