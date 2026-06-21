"""Tests for observation-completeness dedup gate and relevance-gate bypass."""

from software_butcher.brain.loop import (
    _apply_observation_completeness_gate,
    _apply_path_relevance_gate,
    _next_analysis_capability,
)
from software_butcher.brain.policy import PolicyDecision
from software_butcher.core.assets import Asset
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore

BASE = "http://t.example.com"


def _store_with_mapped_pma(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target(BASE)
    finding = Finding(
        hypothesis="surface map",
        path=f"{BASE}/phpmyadmin",
        provenance="http_surface:map",
        evidence=["mapped"],
        confidence=0.78,
        asset_type="web_endpoint",
        metadata={
            "capability": "http_surface_map",
            "content_analysis": True,
            "mapped_target": f"{BASE}/phpmyadmin",
            "page_type": "phpmyadmin",
            "redirect_observations": [{"status": 302, "leak_suspected": True}],
            "redirect_body_leak_suspected": True,
            "mysql_signals": ["mysqli"],
            "form_count": 1,
        },
    )
    store.ingest_finding(finding)
    store.recon_checklist.mark("t.example.com", "http_surface_map")
    return store


def _http_surface_decision(url):
    return PolicyDecision(
        intent="http_surface_map",
        asset=Asset(locator=url, asset_type="web_endpoint"),
        preferred_adapter="http_surface",
        reason="map",
        options={"capability": "http_surface_map"},
    )


def _hyp(url, **meta):
    return Hypothesis(path=url, reason="r", source_finding_id="f", metadata=meta)


def test_remap_of_observed_url_advances_to_analysis(tmp_path):
    store = _store_with_mapped_pma(tmp_path)
    url = f"{BASE}/phpmyadmin"
    decision = _apply_observation_completeness_gate(store, _hyp(url), _http_surface_decision(url))
    # Redirect leak suspected → first deep analysis is redirect_body_audit.
    assert decision.intent == "redirect_body_audit"
    assert decision.preferred_adapter == "web_audit"


def test_gate_advances_through_capabilities(tmp_path):
    store = _store_with_mapped_pma(tmp_path)
    url = f"{BASE}/phpmyadmin"
    # Once redirect_body_audit has run, the next analysis should differ.
    store.ingest_finding(
        Finding(
            hypothesis="redirect audited",
            path=url,
            provenance="web_audit:redirect_body_audit",
            evidence=["done"],
            asset_type="web_endpoint",
            metadata={"capability": "redirect_body_audit", "mapped_target": url},
        )
    )
    nxt = _next_analysis_capability(store, "t.example.com", url)
    assert nxt in {"security_posture_audit", "phpmyadmin_assess"}
    assert nxt != "redirect_body_audit"


def test_first_map_not_blocked(tmp_path):
    """A URL with no content map yet must still be mapped (gate is a no-op)."""
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target(BASE)
    store.recon_checklist.mark("t.example.com", "http_surface_map")
    url = f"{BASE}/fresh"
    decision = _apply_observation_completeness_gate(store, _hyp(url), _http_surface_decision(url))
    assert decision.intent == "http_surface_map"


def test_relevance_gate_bypassed_for_directed_hypothesis(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target(BASE)
    store.recon_checklist.mark("t.example.com", "http_surface_map")
    url = f"{BASE}/dashboard"  # score 0.15 — normally skipped

    # Speculative remap of a low-relevance path is suppressed.
    speculative = _apply_path_relevance_gate(store, _hyp(url), _http_surface_decision(url))
    assert (speculative.options or {}).get("skip_execute")

    # A directed hypothesis (carrying analysis_focus) is NOT suppressed.
    directed = _apply_path_relevance_gate(
        store, _hyp(url, analysis_focus="broken_access"), _http_surface_decision(url)
    )
    assert not (directed.options or {}).get("skip_execute")
    assert directed.intent == "http_surface_map"
