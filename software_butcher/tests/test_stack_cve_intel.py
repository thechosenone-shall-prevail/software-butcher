"""Tests for stack CVE viability reasoning."""

from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.brain.loop import _apply_assessment_priority_gate, _apply_scanner_gate
from software_butcher.brain.policy import PolicyDecision
from software_butcher.core.assets import Asset
from software_butcher.shelves.web.content_intel import analyze_page_content
from software_butcher.shelves.web.stack_cve_intel import analyze_stack_cve_viability
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


def test_stack_cve_viability_includes_reasoning():
    result = analyze_stack_cve_viability(
        url="http://example.com/dashboard/phpinfo.php",
        php_version="7.4.33",
        server_header="Apache/2.4.41 (Unix)",
        page_type="phpinfo",
        phpinfo_exposed=True,
        xampp_detected=True,
    )
    assert result["stack_cve_viability_checked"] is True
    assert any(c["viable"] == "yes" for c in result["stack_cve_candidates"])
    assert all("reasoning" in c for c in result["stack_cve_candidates"])


def test_phpinfo_content_emits_stack_cve_candidates():
    body = (
        "<html><body><h1>PHP Version</h1><td>PHP Version</td><td>8.0.25</td>"
        "phpinfo() Configuration PHP Core XAMPP</body></html>"
    )
    result = analyze_page_content(
        "http://example.com/dashboard/phpinfo.php",
        headers={"X-Powered-By": "PHP/8.0.25", "Server": "Apache/2.4.48 (Unix)"},
        body=body,
        title="phpinfo()",
    )
    assert result["stack_cve_viability_checked"] is True
    assert result["stack_cve_candidates"]
    assert any("viable=" in c for c in result["conclusions"])


def test_phpinfo_queues_stack_cve_and_pii_hypotheses():
    finding = Finding(
        path="http://example.com/dashboard/phpinfo.php",
        hypothesis="phpinfo disclosure",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={
            "content_analysis": True,
            "page_type": "phpinfo",
            "php_version": "8.0.25",
            "stack_cve_viability_checked": True,
            "stack_cve_candidates": [{"cve": "PII-phpinfo-disclosure", "viable": "yes"}],
        },
    )
    hyps = HypothesisGenerator().generate(finding, engagement_type="assessment")
    intents = {h.metadata.get("generated_by") for h in hyps}
    assert "pii_exposure" in intents
    assert "stack_cve_intel" in intents


def test_assessment_blocks_sqli_without_evidence(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://hallbooking.srmrmp.edu.in")
    store.recon_checklist.mark("hallbooking.srmrmp.edu.in", "http_surface_map")
    store.ingest_finding(
        Finding(
            path="http://hallbooking.srmrmp.edu.in/hall",
            hypothesis="mapped hall",
            provenance="http_surface:content_intel",
            metadata={
                "content_analysis": True,
                "page_type": "html",
                "mysql_signals": ["mysqli"],
                "form_count": 1,
                "conclusions": ["Page has 1 form(s) with fields ['user']"],
            },
        )
    )
    hypothesis = Hypothesis(path="http://hallbooking.srmrmp.edu.in/hall", reason="sqli", source_finding_id="t")
    decision = PolicyDecision(
        intent="sql_injection_probing",
        asset=Asset(locator=hypothesis.path, asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="test",
        options={"capability": "sql_injection_probing"},
    )
    gated = _apply_scanner_gate(store, hypothesis, decision)
    assert gated.options["capability"] == "http_surface_map"


def test_broken_access_hypothesis_outranks_sqli():
    phpmyadmin = Finding(
        path="http://example.com/phpmyadmin/",
        hypothesis="phpMyAdmin reachable",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={"content_analysis": True, "page_type": "phpmyadmin"},
    )
    sqli = Finding(
        path="http://example.com/hall",
        hypothesis="SQL error on form",
        provenance="http_surface:content_intel",
        asset_type="web_endpoint",
        metadata={
            "content_analysis": True,
            "mysql_signals": ["mysqli"],
            "form_count": 1,
            "conclusions": ["database error near syntax", "Page has 1 form(s)"],
        },
    )
    access_hyps = HypothesisGenerator().generate(phpmyadmin, engagement_type="assessment")
    sqli_hyps = HypothesisGenerator().generate(sqli, engagement_type="assessment")
    access = next(h for h in access_hyps if h.metadata.get("generated_by") == "broken_access")
    sqli_hyp = next(h for h in sqli_hyps if h.metadata.get("intent") == "sql_injection_probing")
    assert access.priority > sqli_hyp.priority


def test_assessment_priority_gate_deprioritizes_nuclei(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    store.set_base_target("http://example.com")
    store.ingest_finding(
        Finding(
            path="http://example.com",
            hypothesis="root",
            provenance="http_surface:map",
            metadata={
                "content_analysis": True,
                "stack_cve_viability_checked": True,
                "form_count": 2,
                "page_type": "html",
            },
        )
    )
    hypothesis = Hypothesis(path="http://example.com", reason="scan", source_finding_id="t")
    decision = PolicyDecision(
        intent="vulnerability_scanning",
        asset=Asset(locator="http://example.com", asset_type="web_endpoint"),
        preferred_adapter="hexstrike",
        reason="test",
        options={"capability": "vulnerability_scanning"},
    )
    after_scanner = _apply_scanner_gate(store, hypothesis, decision)
    gated = _apply_assessment_priority_gate(store, hypothesis, after_scanner)
    assert gated.options["capability"] == "http_surface_map"
