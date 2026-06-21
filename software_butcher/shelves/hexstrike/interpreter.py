"""Interpret HexStrike output into structured findings."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from software_butcher.core.asset_classifier import classify_url_asset_type, is_static_asset
from software_butcher.core.url_utils import resolve_tool_path, same_origin


class HexStrikeInterpreter:
    """Small parser for common security-tool output patterns."""

    OPEN_PORT_RE = re.compile(r"(?P<port>\d+)/(tcp|udp)\s+open\s+(?P<service>[A-Za-z0-9_\-./]+)", re.IGNORECASE)
    URL_RE = re.compile(r"https?://[^\s\"'<>]+")
    PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/)*[A-Za-z0-9._~!$&'()*+,;=:@%-]*")
    HTML_LINK_RE = re.compile(
        r'(?:href|src|action|formaction|data-url|data-href)=["\']([^"\'#?][^"\']*)["\']',
        re.IGNORECASE,
    )
    BASE_HREF_RE = re.compile(
        r'<base[^>]+href=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    META_REFRESH_RE = re.compile(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\';>]+)',
        re.IGNORECASE,
    )
    META_REFRESH_RE_ALT = re.compile(
        r'<meta[^>]+content=["\'][^"\']*url=([^"\';>]+)[^"\']*["\'][^>]+http-equiv=["\']refresh["\']',
        re.IGNORECASE,
    )
    INLINE_JS_PATH_RE = re.compile(
        r"""["'](?P<path>/[A-Za-z0-9._~!$&'()*+,;=:@%-]{1,120})["']""",
    )
    INLINE_JS_LOCATION_RE = re.compile(
        r"""location(?:\.href)?\s*=\s*["'](?P<path>[^"'#?]+)["']""",
        re.IGNORECASE,
    )

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
            if not same_origin(clean_url, target):
                continue
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
            resolved = resolve_tool_path(target, clean_path)
            if not resolved:
                continue
            default_type = "web_endpoint" if asset_type != "api" else "api"
            classified_type = classify_url_asset_type(resolved, default_type)
            # Skip static assets entirely — /login.css, /img/logo.png etc. have no
            # security-relevant signals worth escalating and their presence in the
            # store would generate spurious parent-path hypotheses (BUG-6).
            if classified_type == "static_asset":
                continue
            findings.append(
                {
                    "hypothesis": "Web path discovered during HexStrike discovery.",
                    "path": resolved,
                    "provenance": f"hexstrike:{tool}:path",
                    "status": "hypothesis",
                    "confidence": 0.4,
                    "evidence": [path, resolved],
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

    @staticmethod
    def _resolve_html_url(raw_href: str, base_url: str, base_origin: str) -> str | None:
        href = raw_href.strip()
        if not href or href.startswith(("javascript:", "mailto:", "data:", "#")):
            return None
        if href.startswith(("http://", "https://")):
            absolute = href.rstrip("/")
        elif href.startswith("/"):
            absolute = base_origin + href.rstrip("/")
        else:
            absolute = urljoin(base_url, href).rstrip("/")
        if base_origin and not absolute.startswith(base_origin):
            return None
        if is_static_asset(absolute):
            return None
        return absolute

    def extract_html_links(self, base_url: str, html: str) -> list[str]:
        """Extract unique same-origin interactive URLs from HTML and inline JS.

        Parses anchor/form/iframe attributes, ``<base href>``, meta refresh targets,
        and conservative inline JS path strings. Static assets are excluded.
        """
        parsed_base = urlsplit(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        resolve_base = base_url
        base_match = self.BASE_HREF_RE.search(html or "")
        if base_match:
            resolved_base = self._resolve_html_url(base_match.group(1), base_url, base_origin)
            if resolved_base:
                resolve_base = resolved_base if resolved_base.endswith("/") else f"{resolved_base}/"

        seen: set[str] = set()
        links: list[str] = []

        def add_link(raw_href: str) -> bool:
            absolute = self._resolve_html_url(raw_href, resolve_base, base_origin)
            if not absolute or absolute in seen:
                return len(links) >= 30
            seen.add(absolute)
            links.append(absolute)
            return len(links) >= 30

        for match in self.HTML_LINK_RE.finditer(html or ""):
            if add_link(match.group(1)):
                return links

        for pattern in (self.META_REFRESH_RE, self.META_REFRESH_RE_ALT):
            for match in pattern.finditer(html or ""):
                if add_link(match.group(1)):
                    return links

        for pattern in (self.INLINE_JS_PATH_RE, self.INLINE_JS_LOCATION_RE):
            for match in pattern.finditer(html or ""):
                if add_link(match.group("path")):
                    return links

        return links
