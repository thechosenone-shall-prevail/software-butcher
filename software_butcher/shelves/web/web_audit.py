"""Web audit shelf — deep, deterministic analyzers the Brain selects per step.

These are *analysis* capabilities that run after http_surface_map has observed a
URL. Each is a distinct, confirmable capability (so the Brain gets meaningful
per-step choices and findings cluster cleanly):

- redirect_body_audit   : "auth check ran after render" data-leak detection
- security_posture_audit : missing security headers, cookie flags, CSRF on forms
- phpmyadmin_assess      : reasoned 403 follow-up (version, default creds, CVE gate)
- dos_viability          : reason about absent rate limiting on stateful endpoints
- stack_cve_intel        : version-gated CVE viability (real capability name; the
                            LLM previously hallucinated "cve_lookup")

No hardcoded application paths or wordlists. Probes are either the URL itself or
product-standard fingerprint resources (same pattern as robots.txt/sitemap.xml).
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.shelves.web.content_intel import parse_php_version
from software_butcher.shelves.web.http_transport import SmartHttpTransport, TransportConfig
from software_butcher.shelves.web.infrastructure_intel import analyze_infrastructure
from software_butcher.shelves.web.redirect_audit import (
    analyze_redirect_bodies,
    confidence_for_leak,
    summarize_redirect_chain,
)
from software_butcher.shelves.web.security_posture import analyze_security_posture
from software_butcher.shelves.web.stack_cve_intel import analyze_stack_cve_viability
from software_butcher.state.transport_state import TransportState

# phpMyAdmin's OWN standard documentation files — product fingerprinting, not
# target path guessing (mirrors the existing robots.txt/sitemap.xml pattern).
_PMA_VERSION_RESOURCES = ("README", "ChangeLog", "doc/html/index.html", "Documentation.html")


def _scheme_is_https(url: str) -> bool:
    return urllib.parse.urlsplit(url).scheme == "https"


def _make_transport(scope: dict[str, Any] | None, transport_state: TransportState | None, host: str) -> tuple[SmartHttpTransport, TransportState]:
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
    return transport, ts


def _nvd_api_key_from_scope(scope: dict[str, Any] | None) -> str | None:
    meta = (scope or {}).get("metadata") if isinstance((scope or {}).get("metadata"), dict) else {}
    cve_api = meta.get("cve_api") if isinstance(meta.get("cve_api"), dict) else {}
    return str(cve_api.get("nvd_api_key") or "") or None


class WebAuditAdapter:
    name = "web_audit"
    capabilities = (
        AdapterCapability(
            name="redirect_body_audit",
            description=(
                "Detect data leaked in a 3xx redirect body (auth check runs after page render); "
                "compares Location vs body size/structure/PII."
            ),
            asset_types=("web_endpoint", "api"),
        ),
        AdapterCapability(
            name="security_posture_audit",
            description=(
                "Audit response security headers (CSP/HSTS/X-Frame-Options/nosniff), cookie flags "
                "(HttpOnly/SameSite), and missing anti-CSRF tokens on POST forms."
            ),
            asset_types=("web_endpoint", "api", "domain"),
        ),
        AdapterCapability(
            name="phpmyadmin_assess",
            description=(
                "Reasoned phpMyAdmin follow-up beyond a 403: product version disclosure, default-cred "
                "hypothesis, and version-gated CVE viability (no blind exploit spray)."
            ),
            asset_types=("web_endpoint", "api", "domain"),
        ),
        AdapterCapability(
            name="dos_viability",
            description=(
                "Reason about resource-exhaustion exposure on stateful/DB-backed endpoints when no "
                "rate limiting is observed (analysis only; never floods the target)."
            ),
            asset_types=("web_endpoint", "api", "domain"),
        ),
        AdapterCapability(
            name="stack_cve_intel",
            description=(
                "Version-gated CVE viability reasoning for the observed stack (PHP/Apache/phpMyAdmin/XAMPP). "
                "Use this instead of cve_lookup."
            ),
            asset_types=("web_endpoint", "api", "domain"),
        ),
    )

    _CAPABILITY_NAMES = frozenset(cap.name for cap in capabilities)

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        options = request.options or {}
        capability = str(options.get("capability") or request.objective or "")
        return {"adapter": self.name, "request": request, "capability": capability, "target": request.target}

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        request: AdapterRequest = plan["request"]
        capability = str(plan.get("capability") or request.objective or "")
        scope = request.scope or {}
        options = request.options or {}
        transport_state = options.get("transport_state")
        target = request.target
        host = host_key(target)
        transport, _ts = _make_transport(scope, transport_state, host)
        nvd_api_key = _nvd_api_key_from_scope(scope)

        dispatch = {
            "redirect_body_audit": self._redirect_body_audit,
            "security_posture_audit": self._security_posture_audit,
            "phpmyadmin_assess": lambda t, tr, h, at: self._phpmyadmin_assess(t, tr, h, at, nvd_api_key=nvd_api_key),
            "dos_viability": self._dos_viability,
            "stack_cve_intel": lambda t, tr, h, at: self._stack_cve_intel(t, tr, h, at, nvd_api_key=nvd_api_key),
        }
        handler = dispatch.get(capability, self._security_posture_audit)
        findings, summary, success = handler(target, transport, host, request.asset_type)
        return AdapterResult(
            adapter=self.name,
            success=success,
            summary=summary,
            findings=findings,
            raw={"capability": capability, "target": target},
        )

    # ── redirect_body_audit ────────────────────────────────────────────────
    def _redirect_body_audit(self, target, transport, host, asset_type):
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        leaks = analyze_redirect_bodies(resp.redirect_chain)
        chain_summary = summarize_redirect_chain(resp.redirect_chain)
        findings: list[dict[str, Any]] = []
        for leak in leaks:
            confidence = confidence_for_leak(leak)
            evidence = [
                f"redirect_status={leak['status']} -> Location={leak.get('location') or '(none)'}",
                (
                    f"data_in_redirect_body: {leak['body_len']} bytes, {leak['table_rows']} table rows, "
                    f"{leak['pii_hits']} PII-pattern matches, page_structure={leak['has_page_structure']}"
                ),
                f"redacted_sample={leak.get('redacted_sample')!r}",
            ]
            findings.append(
                {
                    "hypothesis": (
                        "Auth check runs after render — full page data returned in the response body "
                        f"alongside a {leak['status']} redirect to a lower-privilege location."
                    ),
                    "path": leak.get("url") or target,
                    "provenance": "web_audit:redirect_body_audit",
                    "status": "hypothesis",
                    "confidence": confidence,
                    "evidence": evidence,
                    "asset_type": "web_endpoint",
                    "capability": "redirect_body_audit",
                    "required_evidence": ["redirect_status", "data_in_redirect_body"],
                    "observed_evidence": ["redirect_status", "data_in_redirect_body"],
                    "metadata": {
                        "capability": "redirect_body_audit",
                        "cluster_theme_hint": "auth_after_render",
                        "redirect_leak": leak,
                        "redirect_chain_summary": chain_summary,
                    },
                }
            )

        if not findings:
            summary = f"redirect_body_audit on {target}: no redirect-body leak (chain hops={len(chain_summary)})."
            findings.append(
                {
                    "hypothesis": f"No auth-after-render redirect-body leak detected on {target}.",
                    "path": target,
                    "provenance": "web_audit:redirect_body_audit",
                    "status": "dismissed",
                    "confidence": 0.2,
                    "evidence": [f"redirect_chain={chain_summary}"],
                    "asset_type": asset_type,
                    "capability": "redirect_body_audit",
                    "metadata": {"capability": "redirect_body_audit", "redirect_chain_summary": chain_summary},
                }
            )
            return findings, summary, resp.status_code is not None

        summary = f"redirect_body_audit on {target}: {len(leaks)} redirect-body leak(s) detected."
        return findings, summary, True

    # ── security_posture_audit ─────────────────────────────────────────────
    def _security_posture_audit(self, target, transport, host, asset_type):
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        posture = analyze_security_posture(
            target,
            headers=resp.headers or {},
            body=resp.body or "",
            is_https=_scheme_is_https(target),
        )
        findings: list[dict[str, Any]] = []

        control_conclusions = posture["missing_headers"] + posture["cookie_issues"]
        if control_conclusions:
            findings.append(
                {
                    "hypothesis": "Web app ships without baseline security controls (headers/cookie flags).",
                    "path": target,
                    "provenance": "web_audit:security_posture",
                    "status": "hypothesis",
                    "confidence": 0.9,
                    "evidence": control_conclusions,
                    "asset_type": "web_endpoint",
                    "capability": "security_posture_audit",
                    "required_evidence": ["security_header_audit"],
                    "observed_evidence": ["security_header_audit"],
                    "metadata": {
                        "capability": "security_posture_audit",
                        "cluster_theme_hint": "security_posture",
                        "missing_headers": posture["missing_headers"],
                        "cookie_issues": posture["cookie_issues"],
                    },
                }
            )

        for gap in posture["csrf_gaps"]:
            findings.append(
                {
                    "hypothesis": f"POST form lacks an anti-CSRF token (action={gap['action'] or target}).",
                    "path": gap["action"] or target,
                    "provenance": "web_audit:security_posture",
                    "status": "hypothesis",
                    "confidence": 0.75,
                    "evidence": [
                        f"method=POST action={gap['action'] or target!r}",
                        f"inputs={gap['input_names'][:12]}",
                        "no hidden token field matching csrf/xsrf/_token/nonce convention",
                    ],
                    "asset_type": "web_form",
                    "capability": "security_posture_audit",
                    "required_evidence": ["post_form", "no_csrf_token"],
                    "observed_evidence": ["post_form", "no_csrf_token"],
                    "metadata": {
                        "capability": "security_posture_audit",
                        "cluster_theme_hint": "security_posture",
                        "form": gap,
                    },
                }
            )

        if not findings:
            summary = f"security_posture_audit on {target}: baseline controls present."
            findings.append(
                {
                    "hypothesis": f"Baseline security controls present on {target}.",
                    "path": target,
                    "provenance": "web_audit:security_posture",
                    "status": "dismissed",
                    "confidence": 0.3,
                    "evidence": ["all baseline headers/cookies/CSRF checks passed"],
                    "asset_type": asset_type,
                    "capability": "security_posture_audit",
                    "metadata": {"capability": "security_posture_audit"},
                }
            )
            return findings, summary, resp.status_code is not None

        summary = (
            f"security_posture_audit on {target}: {len(posture['missing_headers'])} missing headers, "
            f"{len(posture['cookie_issues'])} cookie issues, {len(posture['csrf_gaps'])} CSRF gap(s)."
        )
        return findings, summary, True

    # ── phpmyadmin_assess ──────────────────────────────────────────────────
    def _phpmyadmin_assess(self, target, transport, host, asset_type, *, nvd_api_key: str | None = None):
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        status = resp.status_code
        body = resp.body or ""
        version = None
        version_source = ""

        for resource in _PMA_VERSION_RESOURCES:
            probe_url = urllib.parse.urljoin(target.rstrip("/") + "/", resource)
            probe = transport.follow_redirects(probe_url, "GET", profile="browser", host=host)
            if probe.status_code == 200 and probe.body:
                from software_butcher.shelves.web.stack_cve_intel import PHPMYADMIN_VERSION_RE

                match = PHPMYADMIN_VERSION_RE.search(probe.body)
                if match:
                    version = match.group(1)
                    version_source = resource
                    break

        findings: list[dict[str, Any]] = []
        if version:
            findings.append(
                {
                    "hypothesis": f"phpMyAdmin {version} disclosed via product file despite root status {status}.",
                    "path": target,
                    "provenance": "web_audit:phpmyadmin_assess",
                    "status": "hypothesis",
                    "confidence": 0.8,
                    "evidence": [
                        f"version={version} via product resource '{version_source}'",
                        f"root_status={status}",
                    ],
                    "asset_type": "web_endpoint",
                    "capability": "phpmyadmin_assess",
                    "required_evidence": ["pma_version"],
                    "observed_evidence": ["pma_version"],
                    "metadata": {
                        "capability": "phpmyadmin_assess",
                        "cluster_theme_hint": "phpmyadmin",
                        "pma_version": version,
                        "version_source": version_source,
                    },
                }
            )
            cve = analyze_stack_cve_viability(
                url=target,
                page_type="phpmyadmin",
                phpmyadmin_detected=True,
                auth_required=(status in (401, 403)),
                nvd_api_key=nvd_api_key,
            )
            for conclusion in cve.get("conclusions") or []:
                findings.append(
                    {
                        "hypothesis": f"phpMyAdmin CVE viability: {conclusion[:120]}",
                        "path": target,
                        "provenance": "web_audit:phpmyadmin_assess",
                        "status": "hypothesis",
                        "confidence": 0.55,
                        "evidence": [conclusion],
                        "asset_type": "web_endpoint",
                        "capability": "phpmyadmin_assess",
                        "metadata": {
                            "capability": "phpmyadmin_assess",
                            "content_analysis": True,
                            "stack_cve_candidates": cve.get("stack_cve_candidates"),
                        },
                    }
                )

        # Default-cred reasoning is a hypothesis (active testing only within scope).
        findings.append(
            {
                "hypothesis": "phpMyAdmin reachable — default DB creds (root / blank on XAMPP) warrant an in-scope auth test.",
                "path": target,
                "provenance": "web_audit:phpmyadmin_assess",
                "status": "hypothesis",
                "confidence": 0.4,
                "evidence": [
                    f"root_status={status}",
                    "default-credential class — requires explicit active-auth scope to validate",
                ],
                "asset_type": "web_endpoint",
                "capability": "phpmyadmin_assess",
                "metadata": {
                    "capability": "phpmyadmin_assess",
                    "content_analysis": True,
                    "requires_active": True,
                },
            }
        )
        summary = (
            f"phpmyadmin_assess on {target}: status={status} version={version or 'undisclosed'}."
        )
        return findings, summary, status is not None

    # ── dos_viability ──────────────────────────────────────────────────────
    def _dos_viability(self, target, transport, host, asset_type):
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        infra = analyze_infrastructure(
            status_code=resp.status_code,
            headers=resp.headers or {},
            body=resp.body or "",
            elapsed_s=resp.elapsed_s,
        )
        rate_limit = infra.to_dict().get("rate_limit") or {}
        rate_limited = bool(rate_limit.get("detected"))
        latency = resp.elapsed_s

        evidence = [
            f"single_request_latency_s={latency}",
            f"rate_limiting_observed={rate_limited}",
        ]
        if rate_limited:
            status = "dismissed"
            confidence = 0.2
            hypothesis = f"Rate limiting present on {target} — resource-exhaustion abuse is mitigated."
        else:
            status = "hypothesis"
            confidence = 0.5
            hypothesis = (
                f"No rate limiting observed on {target}; stateful/DB-backed endpoints may be exposed to "
                "resource exhaustion. Recommend a bounded, in-scope concurrency test (not executed here)."
            )
        findings = [
            {
                "hypothesis": hypothesis,
                "path": target,
                "provenance": "web_audit:dos_viability",
                "status": status,
                "confidence": confidence,
                "evidence": evidence,
                "asset_type": "web_endpoint",
                "capability": "dos_viability",
                "metadata": {
                    "capability": "dos_viability",
                    "content_analysis": True,
                    "cluster_theme_hint": "resource_exhaustion",
                    "rate_limited": rate_limited,
                    "latency_s": latency,
                },
            }
        ]
        summary = f"dos_viability on {target}: rate_limited={rate_limited} latency={latency}s."
        return findings, summary, resp.status_code is not None

    # ── stack_cve_intel ────────────────────────────────────────────────────
    def _stack_cve_intel(self, target, transport, host, asset_type, *, nvd_api_key: str | None = None):
        resp = transport.follow_redirects(target, "GET", profile="browser", host=host)
        headers = resp.headers or {}
        body = resp.body or ""
        php_version = parse_php_version(headers, body)
        server = headers.get("Server") or headers.get("server") or ""
        text = body[:8000].lower()
        cve = analyze_stack_cve_viability(
            url=target,
            php_version=php_version,
            server_header=server,
            xampp_detected="xampp" in text,
            phpinfo_exposed="phpinfo" in text,
            nvd_api_key=nvd_api_key,
        )
        conclusions = cve.get("conclusions") or []
        findings = [
            {
                "hypothesis": (
                    f"Stack CVE viability for {target}: "
                    f"{conclusions[0][:120] if conclusions else 'no version-gated CVE candidates'}"
                ),
                "path": target,
                "provenance": "web_audit:stack_cve_intel",
                "status": "hypothesis",
                "confidence": 0.7 if conclusions else 0.3,
                "evidence": conclusions or [f"php_version={php_version} server={server}"],
                "asset_type": asset_type,
                "capability": "stack_cve_intel",
                "metadata": {
                    "capability": "stack_cve_intel",
                    "content_analysis": True,
                    "cluster_theme_hint": "stack_cve",
                    "php_version": php_version,
                    "stack_cve_candidates": cve.get("stack_cve_candidates"),
                    "stack_cve_viability_checked": cve.get("stack_cve_viability_checked"),
                },
            }
        ]
        summary = f"stack_cve_intel on {target}: {len(conclusions)} version-gated candidate(s)."
        return findings, summary, resp.status_code is not None

    def normalize_results(self, raw_output: Any) -> AdapterResult:
        return AdapterResult(adapter=self.name, success=True, summary="", findings=[], raw={"raw": raw_output})
