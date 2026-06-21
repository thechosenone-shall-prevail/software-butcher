"""Local HTTP surface mapping — HEAD + GET, headers, tech stack, organic link discovery.

Runs entirely in-process (no HexStrike). This replaces the brittle three-step
web_behavior → technology_fingerprint → endpoint_discovery checklist.
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.url_utils import base_web_url, same_origin
from software_butcher.shelves.hexstrike.interpreter import HexStrikeInterpreter

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
TECHNOLOGY_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Runtime",
    "Via",
    "X-Framework",
    "X-Version",
)
TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE)

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = True
_SSL_CTX.verify_mode = ssl.CERT_REQUIRED


def _normalize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return url.strip()
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.netloc}{port}{path}"


def _request(
    url: str,
    method: str = "GET",
    *,
    timeout: int = 12,
    max_body: int = 65536,
) -> dict[str, Any]:
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "SoftwareButcher/1.0 (security-assessment)")
    req.add_header("Accept", "*/*")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read(max_body)
            headers = {k: v for k, v in resp.headers.items()}
            return {
                "success": True,
                "status_code": resp.status,
                "url": url,
                "final_url": resp.url,
                "elapsed_s": round(time.monotonic() - t0, 3),
                "headers": headers,
                "body": body.decode("utf-8", errors="replace"),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_body)
        except Exception:  # noqa: BLE001
            pass
        headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        return {
            "success": False,
            "status_code": exc.code,
            "url": url,
            "final_url": url,
            "elapsed_s": round(time.monotonic() - t0, 3),
            "headers": headers,
            "body": body.decode("utf-8", errors="replace"),
            "error": f"HTTP {exc.code}: {exc.reason}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "status_code": None,
            "url": url,
            "final_url": url,
            "elapsed_s": round(time.monotonic() - t0, 3),
            "headers": {},
            "body": "",
            "error": str(exc),
        }


def _follow_redirects(url: str, method: str = "GET", *, max_hops: int = 8) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    current = _normalize_url(url)
    last = _request(current, method=method)
    chain.append(
        {
            "method": method,
            "url": current,
            "status": last.get("status_code"),
            "location": last.get("headers", {}).get("Location"),
        }
    )
    hops = 0
    while hops < max_hops and last.get("status_code") in REDIRECT_CODES:
        location = last.get("headers", {}).get("Location")
        if not location:
            break
        current = urllib.parse.urljoin(current, location)
        last = _request(current, method=method)
        chain.append(
            {
                "method": method,
                "url": current,
                "status": last.get("status_code"),
                "location": last.get("headers", {}).get("Location"),
            }
        )
        hops += 1
    return chain, last


def infer_technologies(headers: dict[str, str]) -> list[str]:
    technologies: list[str] = []
    for name in TECHNOLOGY_HEADERS:
        value = headers.get(name)
        if value:
            technologies.append(f"{name}: {value.strip()}")
    return technologies


def extract_title(html: str) -> str:
    match = TITLE_RE.search(html or "")
    return match.group(1).strip() if match else ""


def map_http_surface(url: str) -> dict[str, Any]:
    """Run HEAD + GET surface map and return structured observation."""
    base = base_web_url(url)
    head_chain, head = _follow_redirects(base, "HEAD")
    get_chain, get_resp = _follow_redirects(base, "GET")

    headers = get_resp.get("headers") or head.get("headers") or {}
    technologies = infer_technologies(headers)
    html = get_resp.get("body") or ""
    final_url = get_resp.get("final_url") or base
    interpreter = HexStrikeInterpreter()
    links = interpreter.extract_html_links(final_url, html) if html else []

    same_origin_links = [link for link in links if same_origin(link, base)]
    title = extract_title(html)

    return {
        "target": base,
        "final_url": final_url,
        "head_chain": head_chain,
        "get_chain": get_chain,
        "status_code": get_resp.get("status_code"),
        "headers": headers,
        "technologies": technologies,
        "title": title,
        "discovered_urls": same_origin_links,
        "error": get_resp.get("error") or head.get("error"),
        "success": get_resp.get("status_code") is not None or bool(head.get("status_code")),
    }


class HttpSurfaceAdapter:
    name = "http_surface"
    capabilities = (
        AdapterCapability(
            name="http_surface_map",
            description="Local HEAD+GET surface map: headers, stack, redirects, HTML links",
            asset_types=("web_endpoint", "api", "domain"),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        return {"adapter": self.name, "request": request, "target": request.target}

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        target = plan["request"].target
        surface = map_http_surface(target)
        findings = self._findings_from_surface(surface, plan["request"].asset_type)
        summary = self._summary(surface)
        return AdapterResult(
            adapter=self.name,
            success=bool(surface.get("success")),
            summary=summary,
            findings=findings,
            raw=surface,
        )

    @staticmethod
    def _summary(surface: dict[str, Any]) -> str:
        tech = ", ".join(surface.get("technologies") or []) or "unknown stack"
        links = len(surface.get("discovered_urls") or [])
        return (
            f"HTTP surface map for {surface.get('target')}: "
            f"status={surface.get('status_code')} tech=[{tech}] links={links}"
        )

    @staticmethod
    def _findings_from_surface(surface: dict[str, Any], asset_type: str) -> list[dict[str, Any]]:
        headers = surface.get("headers") or {}
        evidence: list[str] = [
            f"final_url={surface.get('final_url')}",
            f"status={surface.get('status_code')}",
        ]
        if surface.get("title"):
            evidence.append(f"title={surface['title']}")
        if surface.get("error"):
            evidence.append(f"error={surface['error']}")

        for hop in surface.get("get_chain") or []:
            evidence.append(f"redirect: {hop.get('status')} {hop.get('url')} -> {hop.get('location') or ''}".rstrip())

        for name, value in sorted(headers.items()):
            evidence.append(f"header:{name}={value}")

        for tech in surface.get("technologies") or []:
            evidence.append(f"technology={tech}")

        primary = {
            "hypothesis": (
                f"HTTP surface mapped for {surface.get('target')}: "
                f"{len(headers)} response headers, {len(surface.get('discovered_urls') or [])} same-origin links."
            ),
            "path": surface.get("final_url") or surface.get("target"),
            "provenance": "http_surface:map",
            "status": "hypothesis",
            "confidence": 0.72 if surface.get("success") else 0.35,
            "evidence": evidence,
            "asset_type": asset_type,
            "capability": "http_surface_map",
            "metadata": {
                "capability": "http_surface_map",
                "technologies": list(surface.get("technologies") or []),
                "endpoints": list(surface.get("discovered_urls") or []),
                "discovered_urls": list(surface.get("discovered_urls") or []),
                "headers": headers,
                "title": surface.get("title"),
                "status_code": surface.get("status_code"),
                "final_url": surface.get("final_url"),
            },
        }
        findings = [primary]

        for link in surface.get("discovered_urls") or []:
            findings.append(
                {
                    "hypothesis": f"Link discovered during HTTP surface map: {link}",
                    "path": link,
                    "provenance": "http_surface:link",
                    "status": "hypothesis",
                    "confidence": 0.5,
                    "evidence": [f"discovered_from={surface.get('target')}", f"url={link}"],
                    "asset_type": "web_endpoint",
                    "metadata": {
                        "capability": "http_surface_map",
                        "discovered_from": surface.get("target"),
                    },
                }
            )
        return findings
