"""Draw conclusions from HTTP responses — WAF, CDN, proxy, cache, rate limits."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

RATE_LIMIT_STATUSES = frozenset({429, 503, 509, 520, 521, 522, 523, 524})

WAF_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("cloudflare", ("cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "cloudflare")),
    ("aws_waf", ("x-amzn-requestid", "x-amz-cf-id", "awselb", "awsalb")),
    ("akamai", ("x-akamai", "akamai-origin-hop", "akamai-ghost")),
    ("imperva", ("x-iinfo", "x-cdn", "incapsula", "visid_incap")),
    ("sucuri", ("x-sucuri-id", "x-sucuri-cache", "sucuri/cloudproxy")),
    ("f5_bigip", ("x-wa-info", "bigipserver", "f5-")),
    ("modsecurity", ("mod_security", "modsecurity", "nosniff", "security rules")),
    ("fortinet", ("fortigate", "fortiweb")),
    ("barracuda", ("barra_counter_session", "barracuda")),
]

CDN_PROXY_HEADERS = (
    "Via",
    "X-Cache",
    "X-Cache-Lookup",
    "X-Served-By",
    "X-Timer",
    "X-Varnish",
    "X-Fastly-Request-ID",
    "X-CDN",
    "Server-Timing",
    "Age",
    "X-Edge-Location",
)

CACHE_DIRECTIVE_RE = re.compile(
    r"\b(no-cache|no-store|private|public|max-age=\d+|s-maxage=\d+|must-revalidate|immutable)\b",
    re.IGNORECASE,
)

RATE_LIMIT_BODY_SIGNALS = (
    "rate limit",
    "too many requests",
    "slow down",
    "request blocked",
    "access denied",
    "challenge-platform",
    "checking your browser",
    "just a moment",
    "bot detection",
)


@dataclass
class RateLimitSignal:
    detected: bool
    status_code: int | None
    retry_after_s: float | None
    reason: str
    recommended_action: str  # wait | rotate_egress | slow_down | abort_host

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "status_code": self.status_code,
            "retry_after_s": self.retry_after_s,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
        }


@dataclass
class InfrastructureProfile:
    waf: list[str] = field(default_factory=list)
    cdn_proxy: list[str] = field(default_factory=list)
    caching: list[str] = field(default_factory=list)
    rate_limit: RateLimitSignal | None = None
    conclusions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "waf": self.waf,
            "cdn_proxy": self.cdn_proxy,
            "caching": self.caching,
            "rate_limit": self.rate_limit.to_dict() if self.rate_limit else None,
            "conclusions": self.conclusions,
        }


def _header_blob(headers: dict[str, str]) -> str:
    return " ".join(f"{k.lower()}:{v.lower()}" for k, v in headers.items())


def _parse_retry_after(headers: dict[str, str]) -> float | None:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        for key in headers:
            if key.lower().startswith("x-ratelimit-reset"):
                try:
                    return max(float(headers[key]) - __import__("time").time(), 1.0)
                except (TypeError, ValueError):
                    pass
        return None
    try:
        return max(float(raw.strip()), 1.0)
    except ValueError:
        return 60.0


def detect_rate_limit(
    *,
    status_code: int | None,
    headers: dict[str, str],
    body: str = "",
    elapsed_s: float = 0.0,
) -> RateLimitSignal | None:
    """Return a rate-limit signal when the response indicates throttling or blocking."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    retry_after = _parse_retry_after(headers)

    if status_code in RATE_LIMIT_STATUSES:
        action = "rotate_egress" if status_code == 429 else "wait"
        return RateLimitSignal(
            detected=True,
            status_code=status_code,
            retry_after_s=retry_after or (30.0 if status_code == 429 else 10.0),
            reason=f"HTTP {status_code} indicates throttling or edge blocking",
            recommended_action=action,
        )

    for key in ("x-ratelimit-remaining", "ratelimit-remaining"):
        if key in headers_lower:
            try:
                if int(headers_lower[key].split(",")[0].strip()) <= 0:
                    return RateLimitSignal(
                        detected=True,
                        status_code=status_code,
                        retry_after_s=retry_after or 60.0,
                        reason="Rate-limit quota exhausted (remaining=0)",
                        recommended_action="wait",
                    )
            except ValueError:
                pass

    body_lower = (body or "")[:4096].lower()
    if any(sig in body_lower for sig in RATE_LIMIT_BODY_SIGNALS):
        return RateLimitSignal(
            detected=True,
            status_code=status_code,
            retry_after_s=retry_after or 15.0,
            reason="Response body matches rate-limit or bot-challenge patterns",
            recommended_action="slow_down",
        )

    if elapsed_s > 8.0 and status_code in {200, 403, 503}:
        return RateLimitSignal(
            detected=True,
            status_code=status_code,
            retry_after_s=5.0,
            reason=f"Slow response ({elapsed_s}s) may indicate upstream throttling",
            recommended_action="slow_down",
        )

    return None


def analyze_infrastructure(
    *,
    status_code: int | None,
    headers: dict[str, str],
    body: str = "",
    elapsed_s: float = 0.0,
) -> InfrastructureProfile:
    """Infer WAF, CDN/proxy, and caching posture from response metadata."""
    profile = InfrastructureProfile()
    blob = _header_blob(headers)
    body_lower = (body or "")[:8192].lower()

    for name, signals in WAF_SIGNATURES:
        if any(sig in blob or sig in body_lower for sig in signals):
            profile.waf.append(name)

    for header in CDN_PROXY_HEADERS:
        value = headers.get(header)
        if value:
            profile.cdn_proxy.append(f"{header}: {value.strip()}")

    cache_control = headers.get("Cache-Control") or headers.get("cache-control") or ""
    if cache_control:
        directives = CACHE_DIRECTIVE_RE.findall(cache_control)
        profile.caching.append(f"Cache-Control: {', '.join(directives) or cache_control.strip()}")
    if headers.get("ETag"):
        profile.caching.append(f"ETag present: {headers['ETag'][:80]}")
    if headers.get("Age"):
        profile.caching.append(f"Age: {headers['Age']} (served from cache)")
    if headers.get("X-Cache") or headers.get("X-Cache-Lookup"):
        hit = headers.get("X-Cache") or headers.get("X-Cache-Lookup")
        profile.caching.append(f"Cache layer: {hit}")

    profile.rate_limit = detect_rate_limit(
        status_code=status_code,
        headers=headers,
        body=body,
        elapsed_s=elapsed_s,
    )

    if profile.waf:
        profile.conclusions.append(
            f"WAF or edge filter likely in place ({', '.join(profile.waf)}); "
            "aggressive scanning may trigger blocks — prefer slow, evidence-driven probes."
        )
    if profile.cdn_proxy:
        profile.conclusions.append(
            f"Traffic passes through CDN/reverse-proxy layer ({len(profile.cdn_proxy)} signals); "
            "origin fingerprinting requires bypassing or observing cache miss behavior."
        )
    if profile.caching:
        profile.conclusions.append(
            f"Caching observed: {'; '.join(profile.caching[:3])}. "
            "Repeat requests may return stale content unless cache-busting is used."
        )
    if profile.rate_limit and profile.rate_limit.detected:
        profile.conclusions.append(
            f"Rate limiting detected: {profile.rate_limit.reason}. "
            f"Recommended action: {profile.rate_limit.recommended_action}."
        )

    return profile
