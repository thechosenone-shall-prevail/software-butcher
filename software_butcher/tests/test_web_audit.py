"""Tests for the new web-audit analyzers and capability wiring."""

from software_butcher.brain.capability_resolver import resolve_capability
from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.brain.prompts import build_brain_capability_prompt
from software_butcher.core.registry import default_registry
from software_butcher.state.schema import Finding
from software_butcher.shelves.web.redirect_audit import (
    analyze_redirect_bodies,
    chain_leak_suspected,
    summarize_redirect_chain,
)
from software_butcher.shelves.web.security_posture import (
    analyze_security_posture,
    parse_forms,
)


# ── Bug fix: cve_lookup hallucination ──────────────────────────────────────

def test_cve_lookup_resolves_to_stack_cve_intel():
    known = [c["capability"] for c in default_registry().list_capabilities()]
    resolved, how = resolve_capability("cve_lookup", known)
    assert resolved == "stack_cve_intel"
    assert how == "alias"


def test_unknown_capability_unresolved():
    resolved, how = resolve_capability("definitely_not_real_xyz", ["http_surface_map"])
    assert resolved is None
    assert how == "unresolved"


def test_fuzzy_resolves_minor_variant():
    known = ["security_posture_audit", "http_surface_map"]
    resolved, _ = resolve_capability("security_posture_audits", known)
    assert resolved == "security_posture_audit"


def test_prompt_lists_real_capabilities_not_cve_lookup():
    known = [c["capability"] for c in default_registry().list_capabilities()]
    prompt = build_brain_capability_prompt("assessment", capabilities=known)
    assert "stack_cve_intel" in prompt
    assert "redirect_body_audit" in prompt
    assert "cve_lookup" not in prompt


def test_web_audit_capabilities_registered():
    registry = default_registry()
    for cap in ("redirect_body_audit", "security_posture_audit", "phpmyadmin_assess", "dos_viability", "stack_cve_intel"):
        adapter = registry.find_by_capability(cap)
        assert adapter is not None, cap
        assert adapter.name == "web_audit"


# ── Redirect-body analyzer ─────────────────────────────────────────────────

def _leaky_chain():
    body = (
        "<html><body><table>"
        + "".join(f"<tr><td>user{i}@example.com</td><td>Booking {i}</td></tr>" for i in range(40))
        + "</table></body></html>"
    )
    return [
        {"status": 302, "url": "http://t/admin.php", "location": "/login.php",
         "body": body, "body_len": len(body)},
        {"status": 200, "url": "http://t/login.php", "location": None,
         "body": "<html>login</html>", "body_len": 19},
    ]


def test_redirect_body_leak_detected():
    leaks = analyze_redirect_bodies(_leaky_chain())
    assert len(leaks) == 1
    leak = leaks[0]
    assert leak["status"] == 302
    assert leak["low_priv_redirect"] is True
    assert leak["table_rows"] >= 3
    assert "[REDACTED]" in leak["redacted_sample"]  # PII redacted


def test_redirect_stub_body_not_flagged():
    chain = [
        {"status": 302, "url": "http://t/x", "location": "/login",
         "body": "<html>Object moved to <a href='/login'>here</a></html>", "body_len": 52},
    ]
    assert analyze_redirect_bodies(chain) == []
    assert chain_leak_suspected(chain) is False


def test_summarize_redirect_chain_is_persistence_safe():
    summary = summarize_redirect_chain(_leaky_chain())
    assert summary[0]["leak_suspected"] is True
    assert "body" not in summary[0]  # raw body never persisted


# ── Security posture analyzer ──────────────────────────────────────────────

def test_missing_headers_reported():
    result = analyze_security_posture("http://t/", headers={"Server": "Apache"}, body="", is_https=False)
    joined = " ".join(result["missing_headers"]).lower()
    assert "content-security-policy" in joined
    assert "x-frame-options" in joined
    assert not result["has_baseline_controls"]


def test_cookie_flags_flagged():
    result = analyze_security_posture(
        "http://t/", headers={"Set-Cookie": "PHPSESSID=abc; Path=/"}, body="", is_https=False
    )
    issues = " ".join(result["cookie_issues"]).lower()
    assert "httponly" in issues
    assert "samesite" in issues


def test_csrf_gap_on_post_form():
    body = '<form method="POST" action="/book"><input name="date"><input name="hall"></form>'
    result = analyze_security_posture("http://t/", headers={}, body=body, is_https=False)
    assert len(result["csrf_gaps"]) == 1
    assert result["csrf_gaps"][0]["method"] == "POST"


def test_csrf_token_present_no_gap():
    body = (
        '<form method="POST" action="/book">'
        '<input type="hidden" name="csrf_token" value="x"><input name="date"></form>'
    )
    result = analyze_security_posture("http://t/", headers={}, body=body, is_https=False)
    assert result["csrf_gaps"] == []


def test_parse_forms_method_default_get():
    forms = parse_forms('<form action="/search"><input name="q"></form>')
    assert forms[0].method == "GET"


def test_web_audit_followups_seed_security_posture_per_content_page():
    finding = Finding(
        hypothesis="surface map",
        path="http://t.example.edu/hall",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "content_pages": [
                {"url": "http://t.example.edu/hall/admin.php", "form_count": 0, "conclusions": ["admin"]},
                {"url": "http://t.example.edu/hall/report.php", "form_count": 1, "conclusions": ["report"]},
            ],
        },
    )
    hyps = HypothesisGenerator().generate(finding, engagement_type="assessment")
    posture = [
        h for h in hyps
        if (h.metadata or {}).get("intent") == "security_posture_audit"
    ]
    paths = {h.path for h in posture}
    assert "http://t.example.edu/hall/admin.php" in paths
    assert "http://t.example.edu/hall/report.php" in paths
    assert finding.path not in paths


def test_web_audit_followups_seed_redirect_on_php_redirect_observations():
    finding = Finding(
        hypothesis="surface map",
        path="http://t.example.edu/hall",
        provenance="http_surface:map",
        metadata={
            "capability": "http_surface_map",
            "content_pages": [
                {
                    "url": "http://t.example.edu/hall/admin.php",
                    "form_count": 0,
                    "redirect_observations": [{"status": 302, "location": "/login.php", "leak_suspected": False}],
                },
            ],
        },
    )
    hyps = HypothesisGenerator().generate(finding, engagement_type="assessment")
    redirect = [
        h for h in hyps
        if (h.metadata or {}).get("intent") == "redirect_body_audit"
    ]
    assert any(h.path == "http://t.example.edu/hall/admin.php" for h in redirect)
