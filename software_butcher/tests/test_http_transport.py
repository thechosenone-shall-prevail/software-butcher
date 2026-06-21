"""Tests for smart HTTP transport."""

from unittest.mock import patch

from software_butcher.shelves.web.http_transport import SmartHttpTransport, TransportConfig
from software_butcher.shelves.web.infrastructure_intel import RateLimitSignal
from software_butcher.state.transport_state import TransportState


def test_transport_rotates_proxy_on_rate_limit():
    config = TransportConfig(proxies=["http://proxy1:8080", "http://proxy2:8080"], max_retries=1)
    transport = SmartHttpTransport(config)
    assert transport.current_proxy == "http://proxy1:8080"
    transport.rotate_egress("example.com")
    assert transport.current_proxy == "http://proxy2:8080"


@patch.object(SmartHttpTransport, "_single_request")
def test_follow_redirects_retries_on_429(mock_single):
    mock_single.side_effect = [
        type("R", (), {
            "success": False, "status_code": 429, "url": "http://example.com/",
            "final_url": "http://example.com/", "headers": {"Retry-After": "1"},
            "body": "", "elapsed_s": 0.1, "error": "HTTP 429", "profile": "browser",
            "proxy": None,
            "rate_limit": RateLimitSignal(True, 429, 1.0, "test", "rotate_egress"),
        })(),
        type("R", (), {
            "success": True, "status_code": 200, "url": "http://example.com/",
            "final_url": "http://example.com/", "headers": {}, "body": "ok",
            "elapsed_s": 0.1, "error": None, "profile": "browser", "proxy": None, "rate_limit": None,
        })(),
    ]
    transport = SmartHttpTransport(TransportConfig(max_retries=1))
    result = transport.follow_redirects("http://example.com/", host="example.com")
    assert result.status_code == 200
    assert mock_single.call_count >= 2


def test_transport_state_backoff():
    ts = TransportState()
    ts.record_rate_limit(
        "example.com",
        RateLimitSignal(True, 429, 0.01, "test", "wait"),
    )
    assert ts.host("example.com").rate_limit_events == 1
    assert ts.should_rotate_egress("example.com") is False
    ts.record_rate_limit(
        "example.com",
        RateLimitSignal(True, 429, 0.01, "test", "rotate_egress"),
    )
    assert ts.should_rotate_egress("example.com")
