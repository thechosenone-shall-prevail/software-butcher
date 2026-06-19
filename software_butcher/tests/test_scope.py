"""Tests for flat and comprehensive scope loading."""

import json
from pathlib import Path

import pytest

from software_butcher.core.scope import Scope, normalize_scope_payload


def test_flat_scope_load(tmp_path):
    path = tmp_path / "scope.json"
    payload = {
        "name": "test",
        "allowed_domains": ["example.com"],
        "allowed_urls": ["https://example.com"],
        "max_tool_calls": 10,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    scope = Scope.load(path)
    assert scope.name == "test"
    assert scope.max_tool_calls == 10
    assert scope.allows("https://example.com/page")
    assert not scope.allows("https://evil.com")


def test_comprehensive_scope_example_loads():
    example = Path(__file__).resolve().parents[2] / "scope.json.example"
    if not example.exists():
        pytest.skip("scope.json.example not present")
    scope = Scope.load(example)
    assert scope.name == "comprehensive_pentest_scope"
    assert "example.com" in scope.allowed_domains
    assert scope.max_tool_calls == 500
    assert scope.metadata.get("format") == "comprehensive"


def test_comprehensive_scope_exclusions():
    payload = {
        "name": "x",
        "targets": {"allowed_domains": ["example.com"]},
        "exclusions": {"domains": ["mail.example.com"], "keywords": ["delete"]},
        "testing_limits": {"max_tool_calls": 25},
    }
    normalized = normalize_scope_payload(payload)
    scope = Scope(**{k: v for k, v in normalized.items() if k in Scope.__dataclass_fields__})
    assert scope.allows("https://example.com/api")
    assert not scope.allows("https://mail.example.com/inbox")
    assert not scope.allows("https://example.com/admin/delete")


def test_allowed_ips_from_comprehensive():
    payload = {
        "name": "net",
        "targets": {"allowed_ips": ["203.0.113.50"], "ip_ranges": ["10.0.0.0/8"]},
    }
    scope = Scope(**normalize_scope_payload(payload))
    assert scope.allows("203.0.113.50")
    assert scope.allows("10.1.2.3")
