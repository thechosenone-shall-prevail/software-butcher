"""Tests for infrastructure intelligence."""

from software_butcher.shelves.web.infrastructure_intel import (
    analyze_infrastructure,
    detect_rate_limit,
)


def test_detect_rate_limit_429():
    signal = detect_rate_limit(status_code=429, headers={"Retry-After": "30"})
    assert signal is not None
    assert signal.detected
    assert signal.recommended_action == "rotate_egress"
    assert signal.retry_after_s == 30.0


def test_detect_cloudflare_waf():
    profile = analyze_infrastructure(
        status_code=403,
        headers={"Server": "cloudflare", "CF-RAY": "abc123"},
        body="checking your browser before accessing",
    )
    assert "cloudflare" in profile.waf
    assert profile.rate_limit is not None
    assert any("WAF" in c for c in profile.conclusions)


def test_cache_conclusions():
    profile = analyze_infrastructure(
        status_code=200,
        headers={"Cache-Control": "public, max-age=3600", "ETag": '"abc"', "Age": "120"},
        body="",
    )
    assert profile.caching
    assert any("Caching" in c for c in profile.conclusions)
