"""Tests for asset graph expansion (Phase A)."""

from software_butcher.core.asset_expander import (
    AssetExpander,
    classify_discovered_locator,
    extract_locators,
)
from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.scope import Scope
from software_butcher.project import ButcherProject
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


def test_extract_locators_from_evidence():
    finding = Finding(
        path="https://corp.example.com",
        hypothesis="Subdomain found",
        provenance="hexstrike",
        evidence=["also saw https://api.corp.example.com/v1 and https://corp.example.com/setup.exe"],
        asset_type="web_endpoint",
    )
    locators = extract_locators(finding)
    assert "https://corp.example.com" in locators
    assert "https://api.corp.example.com/v1" in locators
    assert "https://corp.example.com/setup.exe" in locators


def test_classify_binary_url():
    asset = classify_discovered_locator("https://corp.example.com/downloads/app.exe")
    assert asset.asset_type == "binary"


def test_classify_github_repo():
    asset = classify_discovered_locator("https://github.com/php/php-src")
    assert asset.asset_type == "source_repo"


def test_asset_expander_adds_scoped_assets_and_hypotheses():
    scope = Scope(name="t", allowed_domains=["corp.example.com"])
    inventory = AssetInventory()
    store = FindingStore("unused.json")
    expander = AssetExpander()

    finding = Finding(
        id="finding-1",
        path="https://corp.example.com",
        hypothesis="API host discovered",
        provenance="hexstrike",
        evidence=["https://api.corp.example.com/swagger"],
        asset_type="web_endpoint",
    )

    new_assets = expander.expand(finding, scope, inventory, hypothesis_queue=store.queue)
    assert len(new_assets) == 1
    assert new_assets[0].locator == "https://api.corp.example.com/swagger"
    assert new_assets[0].asset_type == "api"
    assert inventory.has_locator("https://api.corp.example.com/swagger")

    pending = store.queue.pending_list()
    assert len(pending) == 1
    assert pending[0].path == "https://api.corp.example.com/swagger"
    assert pending[0].metadata["intent"] == "api_enumeration"


def test_asset_expander_skips_out_of_scope():
    scope = Scope(name="t", allowed_domains=["allowed.example.com"])
    inventory = AssetInventory()
    expander = AssetExpander()
    finding = Finding(
        path="https://allowed.example.com",
        hypothesis="external link",
        provenance="hexstrike",
        evidence=["https://other.example.com/secret"],
        asset_type="web_endpoint",
    )
    new_assets = expander.expand(finding, scope, inventory)
    assert new_assets == []
    assert len(inventory.list()) == 0


def test_project_resume_loads_state_and_inventory(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    scope = Scope(name="t", allowed_domains=["example.com"], max_tool_calls=10)

    project = ButcherProject(workspace, scope, resume=False)
    asset = project.add_asset(Asset(locator="https://example.com", asset_type="web_endpoint"))
    project.seed_asset(asset)
    project.findings.add_hypothesis(
        Hypothesis(
            path="https://example.com/admin",
            reason="queued",
            source_finding_id="manual",
            priority=0.5,
            metadata={"asset_type": "web_endpoint"},
        )
    )
    project.findings.tool_calls = 3
    project.save()

    resumed = ButcherProject(workspace, scope, resume=True)
    assert resumed.resumed is True
    assert resumed.findings.tool_calls == 3
    assert len(resumed.findings.queue.pending_list()) >= 1
    assert any(a["locator"] == "https://example.com" for a in resumed.inventory.to_list())


def test_default_registry_includes_code_and_oss_adapters():
    from software_butcher.core.registry import default_registry

    registry = default_registry()
    assert registry.get("code_analysis") is not None
    assert registry.get("oss_fuzz") is not None
    assert registry.find_by_capability("source_static_analysis") is not None
