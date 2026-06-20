"""Integration test: Brain loop expands asset graph from findings."""

from software_butcher.brain.loop import BrainLoop
from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.assets import Asset
from software_butcher.core.registry import AdapterRegistry
from software_butcher.core.scope import Scope
from software_butcher.project import ButcherProject


class DiscoveryAdapter:
    name = "hexstrike"
    capabilities = (AdapterCapability(name="endpoint_discovery", description="x", asset_types=("web_endpoint",)),)

    def plan(self, request: AdapterRequest) -> dict:
        return {"adapter": self.name, "request": request, "capability": "endpoint_discovery", "selected_tools": []}

    def execute(self, plan: dict) -> AdapterResult:
        request = plan["request"]
        return AdapterResult(
            adapter=self.name,
            success=True,
            summary="discovered",
            findings=[
                {
                    "hypothesis": "New API host discovered",
                    "path": request.target,
                    "provenance": "hexstrike",
                    "status": "hypothesis",
                    "confidence": 0.7,
                    "evidence": ["https://api.example.com/v2/docs"],
                    "asset_type": "web_endpoint",
                }
            ],
            raw={},
        )


def test_brain_loop_expands_assets_via_project(tmp_path):
    workspace = tmp_path / "ws"
    scope = Scope(name="t", allowed_domains=["example.com"], max_tool_calls=5)
    project = ButcherProject(workspace, scope, resume=False)
    seed = Asset(locator="https://example.com", asset_type="web_endpoint")
    project.add_asset(seed)
    project.seed_asset(seed)

    registry = AdapterRegistry()
    registry.register(DiscoveryAdapter())

    brain = BrainLoop(
        project.findings,
        scope=scope,
        registry=registry,
        max_steps=1,
        max_branches=1,
        adaptive_pcs=False,
        no_new_limit=99,
        on_finding_ingested=project.process_finding,
    )
    brain.run(seed)

    assert project.inventory.has_locator("https://api.example.com/v2/docs")
    pending_paths = {item.path for item in project.findings.queue.pending_list()}
    assert "https://api.example.com/v2/docs" in pending_paths
