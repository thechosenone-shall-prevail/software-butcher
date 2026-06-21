"""Organic app-surface expansion — follow same-origin links from mapped entry pages.

No wordlists or target-specific paths. Only hrefs/actions/src discovered in HTML
already fetched during surface mapping (typically /hall/, semantic probes, forms).
"""

from __future__ import annotations

import urllib.parse
from collections import deque
from typing import Any

from software_butcher.core.asset_classifier import is_static_asset
from software_butcher.core.path_relevance import is_noise_path, score_path
from software_butcher.core.url_utils import same_origin
from software_butcher.shelves.hexstrike.interpreter import HexStrikeInterpreter
from software_butcher.shelves.web.content_intel import analyze_page_content
from software_butcher.shelves.web.http_transport import SmartHttpTransport


def _normalize(url: str) -> str:
    return (url or "").rstrip("/")


def _should_follow(url: str) -> bool:
    if not url or is_static_asset(url) or is_noise_path(url):
        return False
    parsed = urllib.parse.urlsplit(url)
    path = (parsed.path or "").lower()
    if path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
        return False
    return True


def expand_organic_app_links(
    transport: SmartHttpTransport,
    base: str,
    host: str,
    *,
    entry_urls: list[str],
    seen: set[str],
    content_pages: list[dict[str, Any]],
    discovered: list[str],
    max_depth: int = 2,
    max_pages: int = 15,
    nvd_api_key: str | None = None,
) -> dict[str, Any]:
    """Breadth-first organic link follow from app entry pages (forms, semantic probes)."""
    interpreter = HexStrikeInterpreter()
    analyzed_keys = {_normalize(str(p.get("url") or "")) for p in content_pages}
    expanded: list[str] = []
    queue: deque[tuple[str, int]] = deque()

    for raw in entry_urls:
        url = _normalize(raw)
        if url and _should_follow(url):
            queue.append((url, 0))

    pages_fetched = 0
    while queue and pages_fetched < max_pages:
        url, depth = queue.popleft()
        key = _normalize(url)
        if key in analyzed_keys:
            continue

        resp = transport.follow_redirects(url, "GET", profile="browser", host=host)
        pages_fetched += 1
        if resp.status_code is None or resp.status_code >= 500:
            continue

        body = resp.body or ""
        title = ""
        if body:
            import re

            match = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
            if match:
                title = match.group(1).strip()

        content = analyze_page_content(
            url,
            headers=resp.headers or {},
            body=body,
            title=title,
            nvd_api_key=nvd_api_key,
        )
        content_pages.append(content)
        analyzed_keys.add(key)

        if key not in seen:
            seen.add(key)
            discovered.append(url)
        expanded.append(url)

        if depth >= max_depth:
            continue

        for link in interpreter.extract_html_links(resp.final_url or url, body):
            normalized = _normalize(link)
            if not normalized or not same_origin(normalized, base):
                continue
            if not _should_follow(normalized):
                continue
            if normalized not in seen:
                seen.add(normalized)
                discovered.append(normalized)
            if normalized not in analyzed_keys:
                queue.append((normalized, depth + 1))

    return {
        "expanded_urls": expanded,
        "pages_fetched": pages_fetched,
        "entry_count": len(entry_urls),
    }
