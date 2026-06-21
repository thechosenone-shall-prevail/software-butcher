"""Local HTTP surface mapping — transport-aware HEAD+GET, browser truth, infrastructure intel."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from software_butcher.core.domain_semantics import semantic_path_candidates
from software_butcher.core.path_relevance import (
    detect_default_stack_landing,
    score_path,
    should_queue_path,
    summarize_page_content,
)
from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.url_utils import base_web_url, host_key, same_origin
from software_butcher.shelves.hexstrike.interpreter import HexStrikeInterpreter
from software_butcher.shelves.web.browser_nav import browser_navigate
from software_butcher.shelves.web.content_intel import analyze_page_content
from software_butcher.shelves.web.http_transport import SmartHttpTransport, TransportConfig
from software_butcher.shelves.web.infrastructure_intel import InfrastructureProfile, analyze_infrastructure
from software_butcher.state.transport_state import TransportState

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
WELL_KNOWN_PATHS = ("/robots.txt", "/sitemap.xml")
ROBOTS_SITEMAP_RE = re.compile(r"^Sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
ROBOTS_PATH_RE = re.compile(r"^(?:Allow|Disallow):\s*(/\S*)", re.IGNORECASE | re.MULTILINE)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)


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


def _absolute_url(base: str, href: str) -> str | None:
    href = (href or "").strip()
    if not href or href.startswith(("javascript:", "mailto:", "data:", "#")):
        return None
    parsed_base = urllib.parse.urlsplit(base)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    if href.startswith(("http://", "https://")):
        absolute = href.rstrip("/")
    elif href.startswith("/"):
        absolute = origin + href.rstrip("/")
    else:
        absolute = urllib.parse.urljoin(base, href).rstrip("/")
    if not same_origin(absolute, base):
        return None
    return absolute


def _urls_from_redirect_chain(chain: list[dict[str, Any]], base: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for hop in chain:
        for candidate in (hop.get("url"), hop.get("location")):
            if not candidate:
                continue
            absolute = _absolute_url(base, str(candidate))
            if absolute and absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)
    return urls


def _parse_robots_txt(body: str, base: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in ROBOTS_SITEMAP_RE.finditer(body or ""):
        absolute = _absolute_url(base, match.group(1).strip())
        if absolute and absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    for match in ROBOTS_PATH_RE.finditer(body or ""):
        path = match.group(1).strip()
        if not path or path == "/":
            continue
        absolute = _absolute_url(base, path)
        if absolute and absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    return urls


def _parse_sitemap_xml(body: str, base: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in SITEMAP_LOC_RE.finditer(body or ""):
        absolute = _absolute_url(base, match.group(1).strip())
        if absolute and absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    return urls


def _fetch_well_known_urls(transport: SmartHttpTransport, base: str, host: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for path in WELL_KNOWN_PATHS:
        target = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        if resp.status_code != 200:
            continue
        parsed = _parse_robots_txt(resp.body, base) if path.endswith("robots.txt") else _parse_sitemap_xml(resp.body, base)
        for url in parsed:
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _merge_profiles(*profiles: InfrastructureProfile | None) -> InfrastructureProfile:
    merged = InfrastructureProfile()
    for profile in profiles:
        if not profile:
            continue
        merged.waf.extend(x for x in profile.waf if x not in merged.waf)
        merged.cdn_proxy.extend(x for x in profile.cdn_proxy if x not in merged.cdn_proxy)
        merged.caching.extend(x for x in profile.caching if x not in merged.caching)
        merged.conclusions.extend(x for x in profile.conclusions if x not in merged.conclusions)
        if profile.rate_limit and profile.rate_limit.detected:
            merged.rate_limit = profile.rate_limit
    return merged


def map_http_surface(
    url: str,
    *,
    scope: dict[str, Any] | None = None,
    transport_state: TransportState | None = None,
    use_browser: bool = True,
) -> dict[str, Any]:
    """Deep surface map: dual HTTP profiles, infrastructure intel, optional browser truth."""
    base = base_web_url(url)
    host = host_key(base)
    ts = transport_state or TransportState()
    ts.apply_wait(host)

    config = TransportConfig.from_scope(scope)
    transport = SmartHttpTransport(config, proxy_index=ts.global_proxy_index)

    def on_rate_limit(h: str, signal) -> None:
        ts.record_rate_limit(h, signal)
        if ts.should_rotate_egress(h):
            transport.rotate_egress(h)
            ts.record_rotation(h)

    transport.on_rate_limit = on_rate_limit

    browser_get = transport.follow_redirects(base, "GET", profile="browser", host=host)
    assessment_get = transport.follow_redirects(base, "GET", profile="assessment", host=host)
    head = transport.follow_redirects(base, "HEAD", profile="browser", host=host)

    headers = browser_get.headers or head.headers or {}
    html = browser_get.body or ""
    curl_final = browser_get.final_url or base
    assessment_final = assessment_get.final_url or base

    infra_browser = analyze_infrastructure(
        status_code=browser_get.status_code,
        headers=headers,
        body=html,
        elapsed_s=browser_get.elapsed_s,
    )
    infra_assessment = analyze_infrastructure(
        status_code=assessment_get.status_code,
        headers=assessment_get.headers,
        body=assessment_get.body,
        elapsed_s=assessment_get.elapsed_s,
    )
    infrastructure = _merge_profiles(infra_browser, infra_assessment)

    cache_probe = transport.probe_cache_behavior(
        curl_final,
        prior_etag=headers.get("ETag", ""),
        prior_headers=headers,
    )
    if cache_probe.get("cache_hit"):
        infrastructure.caching.append("Conditional GET returned 304 — edge cache confirmed")
        infrastructure.conclusions.append(
            "Caching confirmed via If-None-Match probe; fingerprint may reflect cached responses."
        )

    interpreter = HexStrikeInterpreter()
    links = interpreter.extract_html_links(curl_final, html) if html else []
    redirect_urls = _urls_from_redirect_chain(browser_get.redirect_chain, base)
    well_known_urls = _fetch_well_known_urls(transport, base, host)

    browser_result = browser_navigate(base, enabled=use_browser)
    browser_urls: list[str] = []
    if browser_result.success:
        browser_urls.extend(browser_result.discovered_urls)
        for hop in browser_result.redirect_chain:
            if same_origin(hop, base):
                browser_urls.append(hop.rstrip("/"))

    profile_divergence = curl_final.rstrip("/") != assessment_final.rstrip("/")
    browser_divergence = (
        browser_result.success
        and browser_result.final_url.rstrip("/") not in {curl_final.rstrip("/"), assessment_final.rstrip("/")}
    )

    discovered: list[str] = []
    seen: set[str] = set()
    for link in (*redirect_urls, *links, *well_known_urls, *browser_urls):
        normalized = link.rstrip("/") if link else ""
        if normalized and same_origin(normalized, base) and normalized not in seen:
            seen.add(normalized)
            discovered.append(normalized)

    if browser_result.success and browser_result.final_url.rstrip("/") not in seen:
        final = browser_result.final_url.rstrip("/")
        if same_origin(final, base):
            seen.add(final)
            discovered.append(final)

    title = extract_title(html) or browser_result.title
    page_summary = summarize_page_content(title, html)
    stack_landing = detect_default_stack_landing(
        title=title,
        body=html,
        headers=headers,
        final_url=curl_final,
    )

    semantic_probes: list[dict[str, Any]] = []
    meta = (scope or {}).get("metadata") if isinstance((scope or {}).get("metadata"), dict) else {}
    engagement_context = str(meta.get("engagement_context") or "")

    if stack_landing.get("detected"):
        for cand in semantic_path_candidates(base, engagement_context=engagement_context, max_paths=2):
            probe_url = str(cand["url"])
            if probe_url.rstrip("/").lower() in seen:
                continue
            probe = transport.follow_redirects(probe_url, "GET", profile="browser", host=host)
            probe_title = extract_title(probe.body)
            content = analyze_page_content(
                probe_url,
                headers=probe.headers,
                body=probe.body,
                title=probe_title,
            )
            semantic_probes.append(
                {
                    "url": probe_url,
                    "token": cand["token"],
                    "status_code": probe.status_code,
                    "title": probe_title,
                    "score": cand["score"],
                    "rationale": cand["rationale"],
                    "reachable": probe.status_code is not None and probe.status_code < 400,
                    "content_analysis": content,
                }
            )
            if probe.status_code is not None and probe.status_code < 400:
                normalized = probe_url.rstrip("/")
                if normalized not in seen:
                    seen.add(normalized)
                    discovered.append(normalized)

    content_pages: list[dict[str, Any]] = []
    root_content = analyze_page_content(
        curl_final,
        headers=headers,
        body=html,
        title=title,
    )
    content_pages.append(root_content)

    for probe in semantic_probes:
        if probe.get("content_analysis"):
            content_pages.append(probe["content_analysis"])

    scored_urls: list[dict[str, Any]] = []
    prioritized: list[str] = []
    for link in discovered:
        sc = score_path(link, title=title, page_context=page_summary)
        scored_urls.append({"url": link, "score": sc})
        if should_queue_path(link, title=title, page_context=page_summary):
            prioritized.append(link)

    return {
        "target": base,
        "final_url": curl_final,
        "browser_final_url": browser_result.final_url if browser_result.success else None,
        "assessment_final_url": assessment_final,
        "profile_divergence": profile_divergence,
        "browser_divergence": browser_divergence,
        "head_chain": head.redirect_chain,
        "get_chain": browser_get.redirect_chain,
        "assessment_chain": assessment_get.redirect_chain,
        "browser_nav": browser_result.to_dict(),
        "status_code": browser_get.status_code,
        "headers": headers,
        "technologies": infer_technologies(headers),
        "infrastructure": infrastructure.to_dict(),
        "cache_probe": cache_probe,
        "title": title,
        "page_summary": page_summary,
        "stack_landing": stack_landing,
        "semantic_probes": semantic_probes,
        "content_pages": content_pages,
        "discovered_urls": prioritized,
        "all_discovered_urls": discovered,
        "scored_urls": scored_urls,
        "error": browser_get.error or head.error or browser_result.error,
        "success": browser_get.status_code is not None or bool(head.status_code) or browser_result.success,
        "transport": {
            "proxy": transport.current_proxy,
            "rate_limit_events": ts.host(host).rate_limit_events,
            "egress_rotations": ts.host(host).egress_rotations,
        },
    }


# Backward-compatible test hook
def _request(url: str, method: str = "GET", **kwargs: Any) -> dict[str, Any]:
    transport = SmartHttpTransport()
    resp = transport.follow_redirects(url, method, profile="browser")
    return {
        "success": resp.success or resp.status_code is not None,
        "status_code": resp.status_code,
        "url": resp.url,
        "final_url": resp.final_url,
        "elapsed_s": resp.elapsed_s,
        "headers": resp.headers,
        "body": resp.body,
        "error": resp.error,
    }


def _fetch_well_known_urls_legacy(base: str) -> list[str]:
    return _fetch_well_known_urls(SmartHttpTransport(), base, host_key(base))


class HttpSurfaceAdapter:
    name = "http_surface"
    capabilities = (
        AdapterCapability(
            name="http_surface_map",
            description="Transport-aware surface map: headers, WAF/CDN intel, browser navigation, organic links",
            asset_types=("web_endpoint", "api", "domain"),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        return {"adapter": self.name, "request": request, "target": request.target}

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        request = plan["request"]
        options = request.options or {}
        transport_state = options.get("transport_state")
        scope = request.scope or {}
        use_browser = options.get("use_browser", True)

        surface = map_http_surface(
            request.target,
            scope=scope,
            transport_state=transport_state,
            use_browser=use_browser,
        )
        findings = self._findings_from_surface(surface, request.asset_type)
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
        infra = surface.get("infrastructure") or {}
        waf = ", ".join(infra.get("waf") or []) or "none detected"
        links = len(surface.get("discovered_urls") or [])
        browser = surface.get("browser_final_url") or "n/a"
        return (
            f"HTTP surface map for {surface.get('target')}: "
            f"status={surface.get('status_code')} waf=[{waf}] links={links} browser_final={browser}"
        )

    @staticmethod
    def _findings_from_surface(surface: dict[str, Any], asset_type: str) -> list[dict[str, Any]]:
        headers = surface.get("headers") or {}
        infra = surface.get("infrastructure") or {}
        evidence: list[str] = [
            f"mapped_target={surface.get('target')}",
            f"curl_final={surface.get('final_url')}",
            f"status={surface.get('status_code')}",
        ]
        if surface.get("browser_final_url"):
            evidence.append(f"browser_final={surface['browser_final_url']}")
        if surface.get("assessment_final_url"):
            evidence.append(f"assessment_final={surface['assessment_final_url']}")
        if surface.get("profile_divergence"):
            evidence.append("profile_divergence=true (User-Agent changes redirect target)")
        if surface.get("browser_divergence"):
            evidence.append("browser_divergence=true (headless browser reached different URL than curl)")
        if surface.get("title"):
            evidence.append(f"title={surface['title']}")
        if surface.get("error"):
            evidence.append(f"error={surface['error']}")

        for hop in surface.get("get_chain") or []:
            evidence.append(
                f"redirect: {hop.get('status')} {hop.get('url')} -> {hop.get('location') or ''} "
                f"[{hop.get('profile', 'browser')}]".rstrip()
            )

        for name, value in sorted(headers.items()):
            evidence.append(f"header:{name}={value}")

        for tech in surface.get("technologies") or []:
            evidence.append(f"technology={tech}")

        for conclusion in infra.get("conclusions") or []:
            evidence.append(f"conclusion={conclusion}")

        stack_landing = surface.get("stack_landing") or {}
        if stack_landing.get("detected"):
            evidence.append(f"stack_landing={stack_landing.get('stack')}")
            evidence.append(f"conclusion={stack_landing.get('conclusion')}")
        for probe in surface.get("semantic_probes") or []:
            if probe.get("reachable"):
                evidence.append(
                    f"semantic_probe: {probe.get('url')} status={probe.get('status_code')} "
                    f"title={probe.get('title')} token={probe.get('token')}"
                )
            else:
                evidence.append(f"semantic_probe_miss: {probe.get('url')} status={probe.get('status_code')}")
        if surface.get("page_summary"):
            evidence.append(f"page_summary={surface['page_summary'][:200]}")

        for page in surface.get("content_pages") or []:
            for conclusion in page.get("conclusions") or []:
                evidence.append(f"content_conclusion={conclusion}")
            if page.get("text_preview"):
                evidence.append(f"view_source_preview={page['text_preview'][:300]}")
            if page.get("php_version"):
                evidence.append(f"php_version={page['php_version']}")

        rate_limit = infra.get("rate_limit")
        root_content = (surface.get("content_pages") or [{}])[0] if surface.get("content_pages") else {}
        metadata: dict[str, Any] = {
            "capability": "http_surface_map",
            "content_analysis": True,
            "mapped_target": surface.get("target"),
            "technologies": list(surface.get("technologies") or []),
            "endpoints": list(surface.get("discovered_urls") or []),
            "discovered_urls": list(surface.get("discovered_urls") or []),
            "headers": headers,
            "infrastructure": infra,
            "title": surface.get("title"),
            "status_code": surface.get("status_code"),
            "final_url": surface.get("final_url"),
            "browser_final_url": surface.get("browser_final_url"),
            "cache_probe": surface.get("cache_probe"),
            "transport": surface.get("transport"),
            "page_summary": surface.get("page_summary"),
            "stack_landing": stack_landing,
            "semantic_probes": surface.get("semantic_probes"),
            "content_pages": surface.get("content_pages"),
            "scored_urls": surface.get("scored_urls"),
            "all_discovered_urls": surface.get("all_discovered_urls"),
        }
        if rate_limit and rate_limit.get("detected"):
            metadata["rate_limited"] = True
            metadata["transport_action"] = rate_limit.get("recommended_action")

        prioritized_links = surface.get("discovered_urls") or []
        all_links = surface.get("all_discovered_urls") or []
        primary = {
            "hypothesis": (
                f"HTTP surface mapped for {surface.get('target')}: "
                f"title={surface.get('title') or 'unknown'}; "
                f"{(surface.get('page_summary') or '')[:120]}; "
                f"{len(prioritized_links)} prioritized links (of {len(all_links)} total)."
            ),
            "path": surface.get("target") or surface.get("final_url"),
            "provenance": "http_surface:map",
            "status": "hypothesis",
            "confidence": 0.78 if surface.get("success") else 0.35,
            "evidence": evidence,
            "asset_type": asset_type,
            "capability": "http_surface_map",
            "metadata": metadata,
        }
        findings = [primary]

        if surface.get("browser_divergence") and surface.get("browser_final_url"):
            findings.append(
                {
                    "hypothesis": (
                        f"Browser navigation reached {surface['browser_final_url']} "
                        f"while HTTP client stopped at {surface.get('final_url')} — "
                        "likely JS/meta redirect or cookie-gated routing."
                    ),
                    "path": surface["browser_final_url"],
                    "provenance": "http_surface:browser_nav",
                    "status": "hypothesis",
                    "confidence": 0.85,
                    "evidence": [
                        f"browser_chain={' -> '.join((surface.get('browser_nav') or {}).get('redirect_chain') or [])}",
                        f"curl_final={surface.get('final_url')}",
                    ],
                    "asset_type": "web_endpoint",
                    "metadata": {
                        "capability": "http_surface_map",
                        "discovered_from": surface.get("target"),
                        "discovered_urls": [surface["browser_final_url"]],
                    },
                }
            )

        for link in surface.get("discovered_urls") or []:
            link_score = score_path(link, title=surface.get("title") or "", page_context=surface.get("page_summary") or "")
            findings.append(
                {
                    "hypothesis": f"High-value path from surface map (score={link_score:.2f}): {link}",
                    "path": link,
                    "provenance": "http_surface:link",
                    "status": "hypothesis",
                    "confidence": 0.45 + link_score * 0.4,
                    "evidence": [
                        f"discovered_from={surface.get('target')}",
                        f"url={link}",
                        f"relevance_score={link_score:.2f}",
                    ],
                    "asset_type": "web_endpoint",
                    "metadata": {
                        "capability": "http_surface_map",
                        "discovered_from": surface.get("target"),
                        "relevance_score": link_score,
                    },
                }
            )

        for page in surface.get("content_pages") or []:
            url = str(page.get("url") or "")
            conclusions = list(page.get("conclusions") or [])
            if not url or not conclusions:
                continue
            page_type = str(page.get("page_type") or "html")
            page_evidence = [
                f"page_type={page_type}",
                f"url={url}",
            ]
            if page.get("php_version"):
                page_evidence.append(f"php_version={page['php_version']}")
            for conclusion in conclusions:
                page_evidence.append(f"conclusion={conclusion}")
            if page.get("text_preview"):
                page_evidence.append(f"view_source_preview={page['text_preview'][:300]}")
            confidence = 0.82
            if page_type == "phpinfo":
                confidence = 0.95
            elif page_type == "phpmyadmin":
                confidence = 0.93
            elif any("resource exhaustion" in c.lower() for c in conclusions):
                confidence = 0.88
            findings.append(
                {
                    "hypothesis": (
                        f"Content analysis ({page_type}): "
                        f"{'; '.join(conclusions[:3])}"
                    ),
                    "path": url,
                    "provenance": "http_surface:content_intel",
                    "status": "hypothesis",
                    "confidence": confidence,
                    "evidence": page_evidence,
                    "asset_type": "web_endpoint",
                    "metadata": {
                        "capability": "http_surface_map",
                        "content_analysis": True,
                        "page_type": page_type,
                        "conclusions": conclusions,
                        "php_version": page.get("php_version"),
                        "mysql_signals": page.get("mysql_signals"),
                        "form_count": page.get("form_count"),
                        "discovered_from": surface.get("target"),
                    },
                }
            )
        return findings
