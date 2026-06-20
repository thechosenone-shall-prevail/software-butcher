"""Tests for Phase B: domain OSINT seed and outcome escalation."""

from pathlib import Path
from unittest.mock import MagicMock

from software_butcher.brain.escalation import EscalationLadder
from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.domain_seed import build_domain_seed_hypotheses, is_domain_like
from software_butcher.core.scope import Scope
from software_butcher.core.source_resolver import is_eol_product, resolve_upstream_source
from software_butcher.project import ButcherProject
from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore


def test_domain_seed_osint_hypotheses():
    asset = Asset(locator="corp.example.com", asset_type="domain")
    hyps = build_domain_seed_hypotheses(asset)
    intents = {h.metadata["intent"] for h in hyps if h.metadata.get("generated_by") == "domain_seed"}
    assert intents == {"web_behavior_analysis", "technology_fingerprint", "endpoint_discovery"}
    assert all(h.path == "https://corp.example.com" for h in hyps if h.metadata.get("generated_by") == "domain_seed")


def test_domain_seed_single_hypothesis_for_non_domain():
    asset = Asset(locator="https://corp.example.com/admin", asset_type="web_endpoint")
    assert not is_domain_like(asset)
    hyps = build_domain_seed_hypotheses(asset)
    seed_intents = {h.metadata["intent"] for h in hyps if h.metadata.get("generated_by") == "domain_seed"}
    assert seed_intents == {"web_behavior_analysis", "technology_fingerprint", "endpoint_discovery"}


def test_resolve_php_upstream_source():
    ref = resolve_upstream_source("PHP 7.2.0")
    assert ref is not None
    assert ref.product == "php"
    assert ref.repo_url == "https://github.com/php/php-src"
    assert ref.is_eol is True
    assert ref.branch == "PHP-7.2"


def test_is_eol_php7():
    assert is_eol_product("php", "7.4.33") is True
    assert is_eol_product("php", "8.2.0") is False


def test_escalation_pivots_after_failed_exploit(tmp_path):
    workspace = tmp_path / "ws"
    scope = Scope(name="t", allowed_domains=["target.example.com"])
    inventory = AssetInventory()
    store = FindingStore(workspace / "finding_state.json")

    store.add_finding(
        Finding(
            id="tech-1",
            path="https://target.example.com",
            hypothesis="PHP stack identified",
            provenance="hexstrike",
            status="hypothesis",
            confidence=0.8,
            evidence=["PHP 7.2.0"],
            asset_type="web_endpoint",
            metadata={"capability": "technology_fingerprint", "technologies": ["PHP 7.2.0"]},
        )
    )

    failed_exploit = Finding(
        id="exploit-1",
        path="https://target.example.com",
        hypothesis="CVE exploit attempt did not confirm",
        provenance="hexstrike",
        status="hypothesis",
        confidence=0.4,
        evidence=["no exploit available", "scan failed"],
        asset_type="web_endpoint",
        metadata={"capability": "exploit_generation", "technology": "PHP 7.2.0"},
    )
    store.ingest_finding(failed_exploit)

    ladder = EscalationLadder()
    ladder.acquisition = MagicMock()
    fake_source = workspace / "sources" / "php-7-2-0"
    fake_source.mkdir(parents=True)
    ladder.acquisition.prepare.return_value = fake_source

    assets = ladder.escalate(
        failed_exploit,
        store,
        scope,
        inventory,
        workspace,
        hypothesis_queue=store.queue,
    )

    assert len(assets) == 1
    assert assets[0].asset_type == "source_repo"
    assert inventory.has_locator(str(fake_source))
    pending = store.queue.pending_list()
    assert any(h.metadata.get("intent") == "source_static_analysis" for h in pending)


def test_project_process_finding_runs_both_hooks(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    scope = Scope(name="t", allowed_domains=["corp.example.com"])
    project = ButcherProject(workspace, scope, resume=False)

    expand_called = {"count": 0}
    escalate_called = {"count": 0}

    def fake_expand(finding):
        expand_called["count"] += 1
        return []

    def fake_escalate(finding):
        escalate_called["count"] += 1
        return []

    monkeypatch.setattr(project, "expand_from_finding", fake_expand)
    monkeypatch.setattr(project, "escalate_from_finding", fake_escalate)

    finding = Finding(
        path="https://corp.example.com",
        hypothesis="test",
        provenance="test",
        asset_type="web_endpoint",
    )
    project.process_finding(finding)
    assert expand_called["count"] == 1
    assert escalate_called["count"] == 1


def test_fresh_domain_project_seeds_osint(tmp_path):
    workspace = tmp_path / "ws"
    scope = Scope(name="t", allowed_domains=["example.com"])
    project = ButcherProject(workspace, scope, resume=False)
    asset = project.add_asset(Asset(locator="example.com", asset_type="domain"))
    project.seed_asset(asset)

    pending = project.findings.queue.pending_list()
    assert len(pending) == 3
    intents = {h.metadata["intent"] for h in pending}
    assert intents == {"web_behavior_analysis", "technology_fingerprint", "endpoint_discovery"}
    assert all(h.path.rstrip("/") == "https://example.com" for h in pending)


def test_hallbooking_seed_no_wordlist_spray():
    asset = Asset(locator="http://hallbooking.srmrmp.edu.in", asset_type="web_endpoint")
    hyps = build_domain_seed_hypotheses(asset)
    assert len(hyps) == 3
    paths = {h.path.rstrip("/") for h in hyps}
    assert paths == {"http://hallbooking.srmrmp.edu.in"}
