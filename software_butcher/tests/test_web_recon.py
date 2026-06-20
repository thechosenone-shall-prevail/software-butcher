"""Tests for web recon gating, URL normalization, and queue dedupe."""

from software_butcher.brain.loop import _apply_recon_gate
from software_butcher.brain.policy import BrainPolicy, PolicyDecision
from software_butcher.core.assets import Asset
from software_butcher.core.domain_seed import build_domain_seed_hypotheses
from software_butcher.core.url_utils import canonical_web_url, is_plausible_target_path, resolve_tool_path
from software_butcher.state.hypothesis_queue import HypothesisQueue
from software_butcher.state.recon_checklist import ReconChecklist, record_recon_progress
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


def test_canonical_web_url_joins_relative_paths():
    base = "http://hallbooking.srmrmp.edu.in"
    assert canonical_web_url("/dashboard", base) == "http://hallbooking.srmrmp.edu.in/dashboard"
    assert canonical_web_url("hall", base) == "http://hallbooking.srmrmp.edu.in/hall"


def test_resolve_tool_path_rejects_off_target_segments():
    base = "http://hallbooking.srmrmp.edu.in"
    assert resolve_tool_path(base, "/hall") == "http://hallbooking.srmrmp.edu.in/hall"
    assert resolve_tool_path(base, "/nmap.org") is None


def test_parent_path_hypothesis_skips_junk_paths(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    store.ingest_finding(
        Finding(
            path="http://hallbooking.srmrmp.edu.in/hall",
            hypothesis="Hall endpoint",
            provenance="test",
            asset_type="web_endpoint",
        )
    )
    parents = [h.path.rstrip("/") for h in store.queue.pending_list() if h.metadata.get("generated_by") == "parent_path_rule"]
    assert all(is_plausible_target_path(p, store.base_target) for p in parents)
    assert "http://hallbooking.srmrmp.edu.in" in parents


def test_domain_seed_only_three_root_hypotheses():
    asset = Asset(locator="http://hallbooking.srmrmp.edu.in", asset_type="web_endpoint")
    hyps = build_domain_seed_hypotheses(asset)
    assert len(hyps) == 3
    assert all(h.path.rstrip("/") == "http://hallbooking.srmrmp.edu.in" for h in hyps)
    assert not any(h.metadata.get("generated_by") == "app_context_paths" for h in hyps)


def test_recon_gate_redirects_host_steps_to_base(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    hypothesis = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/login",
        reason="guess",
        source_finding_id="x",
        metadata={"intent": "endpoint_discovery"},
    )
    decision = PolicyDecision(
        intent="endpoint_discovery",
        asset=Asset(locator=hypothesis.path, asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="wrong path",
        options={"capability": "endpoint_discovery"},
    )
    gated = _apply_recon_gate(store, hypothesis, decision, "endpoint_discovery")
    assert gated.intent == "web_behavior_analysis"
    assert hypothesis.path.rstrip("/") == "http://hallbooking.srmrmp.edu.in"


def test_recon_gate_blocks_nuclei_until_checklist_complete(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    hypothesis = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/dashboard",
        reason="test",
        source_finding_id="x",
    )
    decision = PolicyDecision(
        intent="vulnerability_scanning",
        asset=Asset(locator=hypothesis.path, asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="LLM wants nuclei",
        options={"capability": "vulnerability_scanning"},
    )
    gated = _apply_recon_gate(store, hypothesis, decision, None)
    assert gated.intent == "web_behavior_analysis"
    assert gated.options["capability"] == "web_behavior_analysis"


def test_recon_gate_allows_nuclei_after_checklist(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    host = "hallbooking.srmrmp.edu.in"
    checklist = store.recon_checklist
    for cap in ("web_behavior_analysis", "technology_fingerprint", "endpoint_discovery"):
        checklist.mark(host, cap)

    hypothesis = Hypothesis(
        path="http://hallbooking.srmrmp.edu.in/dashboard",
        reason="test",
        source_finding_id="x",
    )
    decision = PolicyDecision(
        intent="vulnerability_scanning",
        asset=Asset(locator=hypothesis.path, asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="LLM wants nuclei",
        options={"capability": "vulnerability_scanning"},
    )
    gated = _apply_recon_gate(store, hypothesis, decision, None)
    assert gated.intent == "vulnerability_scanning"


def test_policy_starts_web_targets_with_behavior_analysis():
    policy = BrainPolicy()
    asset = Asset(locator="http://hallbooking.srmrmp.edu.in", asset_type="web_endpoint")
    decision = policy.decide(asset, [])
    assert decision.intent == "web_behavior_analysis"


def test_record_recon_progress_only_on_root_surface():
    checklist = ReconChecklist()
    base = "http://hallbooking.srmrmp.edu.in"
    record_recon_progress(
        checklist,
        Finding(
            path="http://hallbooking.srmrmp.edu.in/hall",
            hypothesis="child path",
            provenance="playwright_curl:baseline",
            metadata={"capability": "web_behavior_analysis"},
        ),
        base_target=base,
    )
    assert checklist.done("hallbooking.srmrmp.edu.in") == []

    record_recon_progress(
        checklist,
        Finding(
            path="http://hallbooking.srmrmp.edu.in/",
            hypothesis="root",
            provenance="playwright_curl:baseline",
            metadata={"capability": "web_behavior_analysis"},
        ),
        base_target=base,
    )
    assert "web_behavior_analysis" in checklist.done("hallbooking.srmrmp.edu.in")


def test_findings_from_adapter_result_stamps_capability():
    from software_butcher.brain.loop import _findings_from_adapter_result
    from software_butcher.core.adapter import AdapterResult

    result = AdapterResult(
        adapter="playwright_curl",
        success=True,
        summary="ok",
        findings=[
            {
                "hypothesis": "baseline probe",
                "path": "http://hallbooking.srmrmp.edu.in/",
                "provenance": "playwright_curl:baseline",
                "metadata": {"status_code": 200},
            }
        ],
    )
    findings = _findings_from_adapter_result(
        result,
        hypothesis=Hypothesis(path="http://hallbooking.srmrmp.edu.in/", reason="x", source_finding_id="y"),
        parent_path_value=None,
        default_asset_type="web_endpoint",
        capability="web_behavior_analysis",
    )
    assert findings[0].metadata.get("capability") == "web_behavior_analysis"


def test_queue_dedupes_same_path_and_intent():
    queue = HypothesisQueue()
    target = "http://hallbooking.srmrmp.edu.in"
    meta = {"intent": "web_behavior_analysis", "asset_type": "web_endpoint"}
    queue.add(Hypothesis(path=target, reason="first", source_finding_id="a", metadata=meta))
    queue.add(Hypothesis(path=target, reason="second duplicate", source_finding_id="b", metadata=meta))
    pending = [h for h in queue.pending_list() if h.metadata.get("intent") == "web_behavior_analysis"]
    assert len(pending) == 1
