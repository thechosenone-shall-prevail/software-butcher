"""Interpret HexStrike output into structured findings."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from software_butcher.core.asset_classifier import classify_url_asset_type, is_static_asset


class HexStrikeInterpreter:
    """Small parser for common security-tool output patterns."""

    OPEN_PORT_RE = re.compile(r"(?P<port>\d+)/(tcp|udp)\s+open\s+(?P<service>[A-Za-z0-9_\-./]+)", re.IGNORECASE)
    URL_RE = re.compile(r"https?://[^\s\"'<>]+")
    PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/)*[A-Za-z0-9._~!$&'()*+,;=:@%-]*")
    HTML_LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)

    def interpret(self, target: str, tool: str, output: str, asset_type: str) -> list[dict]:
        findings: list[dict] = []
        text = output or ""

        ports = list(self.OPEN_PORT_RE.finditer(text))
        if ports:
            evidence = []
            services = set()
            for match in ports[:50]:
                service = match.group("service").lower()
                services.add(service)
                evidence.append(match.group(0))

            hypothesis = f"Open services discovered on {target}: {', '.join(sorted(services))}"
            findings.append(
                {
                    "hypothesis": hypothesis,
                    "path": target,
                    "provenance": f"hexstrike:{tool}:ports",
                    "status": "hypothesis",
                    "confidence": 0.55,
                    "evidence": evidence,
                    "asset_type": asset_type,
                    "metadata": {"services": sorted(services)},
                }
            )

        urls = sorted(set(self.URL_RE.findall(text)))
        for url in urls[:25]:
            clean_url = url.rstrip(".,;")
            findings.append(
                {
                    "hypothesis": "URL discovered during HexStrike discovery.",
                    "path": clean_url,
                    "provenance": f"hexstrike:{tool}:url",
                    "status": "hypothesis",
                    "confidence": 0.45,
                    "evidence": [url],
                    "asset_type": classify_url_asset_type(clean_url),
                }
            )

        paths = sorted(path for path in set(self.PATH_RE.findall(text)) if len(path) > 1)
        for path in paths[:25]:
            clean_path = path.rstrip(".,;")
            default_type = "web_endpoint" if asset_type != "api" else "api"
            classified_type = classify_url_asset_type(clean_path, default_type)
            # Skip static assets entirely — /login.css, /img/logo.png etc. have no
            # security-relevant signals worth escalating and their presence in the
            # store would generate spurious parent-path hypotheses (BUG-6).
            if classified_type == "static_asset":
                continue
            findings.append(
                {
                    "hypothesis": "Web path discovered during HexStrike discovery.",
                    "path": clean_path,
                    "provenance": f"hexstrike:{tool}:path",
                    "status": "hypothesis",
                    "confidence": 0.4,
                    "evidence": [path],
                    "asset_type": classified_type,
                }
            )

        if not findings and text.strip():
            findings.append(
                {
                    "hypothesis": f"HexStrike {tool} produced output requiring Brain interpretation.",
                    "path": target,
                    "provenance": f"hexstrike:{tool}:raw",
                    "status": "hypothesis",
                    "confidence": 0.25,
                    "evidence": [text[:4000]],
                    "asset_type": asset_type,
                }
            )

        return findings

    def extract_html_links(self, base_url: str, html: str) -> list[str]:
        """Extract unique absolute URLs from HTML href/src/action attributes.

        Returns up to 30 interactive (non-static) URLs found in the page,
        resolving relative paths against *base_url* and staying on the same
        origin.  Static assets (CSS, JS, images, fonts, etc.) are excluded —
        they have their own asset_type and must not be crawled as endpoints.
        """
        parsed_base = urlsplit(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        seen: set[str] = set()
        links: list[str] = []
        for match in self.HTML_LINK_RE.finditer(html):
            href = match.group(1).strip()
            if not href or href.startswith(("javascript:", "mailto:", "data:", "#")):
                continue
            if href.startswith(("http://", "https://")):
                absolute = href.rstrip("/")
            elif href.startswith("/"):
                absolute = base_origin + href.rstrip("/")
            else:
                absolute = urljoin(base_url, href).rstrip("/")
            # Skip external origins to stay on-target
            if base_origin and not absolute.startswith(base_origin):
                continue
            # Skip static assets — they are not crawlable endpoints
            if is_static_asset(absolute):
                continue
            if absolute not in seen:
                seen.add(absolute)
                links.append(absolute)
            if len(links) >= 30:
                break
        return links
