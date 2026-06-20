"""Tests for Brain loop guards, tool budget, and parallel branches."""

from unittest.mock import MagicMock, patch

import pytest

from software_butcher.brain.loop import BrainLoop, run_brain_once
from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.assets import Asset
from software_butcher.core.registry import AdapterRegistry
from software_butcher.core.scope import Scope
from software_butcher.state.schema import Hypothesis
from software_butcher.state.store import FindingStore


class StubAdapter:
    name = "hexstrike"
    capabilities = (AdapterCapability(name="discover", description="x", asset_types=("web_endpoint",)),)

    def __init__(self):
        self.calls = 0

    def plan(self, request: AdapterRequest) -> dict:
        return {"adapter": self.name, "request": request, "capability": "discover", "selected_tools": []}

    def execute(self, plan: dict) -> AdapterResult:
        self.calls += 1
        request = plan["request"]
        return AdapterResult(
            adapter=self.name,
            success=True,
            summary="ok",
            findings=[
                {
                    "hypothesis": "stub finding",
                    "path": request.target,
                    "provenance": "stub",
                    "status": "hypothesis",
                    "confidence": 0.5,
                    "evidence": ["ok"],
                    "asset_type": request.asset_type,
                }
            ],
            raw={},
        )


def test_tool_budget_stops_execution(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    scope = Scope(name="t", allowed_domains=["example.com"], max_tool_calls=1)
    store.add_hypothesis(
        Hypothesis(
            path="https://example.com",
            reason="seed",
            source_finding_id="manual",
            priority=1.0,
            metadata={"asset_type": "web_endpoint", "intent": "discover"},
        )
    )
    store.add_hypothesis(
        Hypothesis(
            path="https://example.com/admin",
            reason="follow-up",
            source_finding_id="manual",
            priority=0.9,
            metadata={"asset_type": "web_endpoint", "intent": "discover"},
        )
    )

    registry = AdapterRegistry()
    registry.register(StubAdapter())

    run_brain_once(store, registry=registry, scope=scope, asset=Asset(locator="https://example.com", asset_type="web_endpoint"))
    assert store.tool_calls == 1

    result = run_brain_once(store, registry=registry, scope=scope, asset=Asset(locator="https://example.com", asset_type="web_endpoint"))
    assert result is not None
    assert result.provenance == "brain:tool_budget"
    assert store.tool_calls == 1


def test_parallel_branches_run_multiple_adapters(tmp_path):
    store = FindingStore(tmp_path / "state.json")
    scope = Scope(name="t", allowed_domains=["example.com"], max_tool_calls=10)

    for path in ("https://example.com/a", "https://example.com/b", "https://example.com/c"):
        store.add_hypothesis(
            Hypothesis(
                path=path,
                reason=f"test {path}",
                source_finding_id="manual",
                priority=1.0,
                metadata={"asset_type": "web_endpoint", "intent": "discover"},
            )
        )

    adapter = StubAdapter()
    registry = AdapterRegistry()
    registry.register(adapter)

    brain = BrainLoop(store, scope=scope, registry=registry, max_steps=1, max_branches=3, adaptive_pcs=False, no_new_limit=99)
    events = brain.run(Asset(locator="https://example.com", asset_type="web_endpoint"))

    assert adapter.calls == 3
    executed = [e for e in events if e.get("status") == "executed"]
    assert len(executed) == 3


def test_cli_imports_without_openai_installed():
    import importlib
    import sys

    openai = sys.modules.pop("openai", None)
    try:
        mod = importlib.import_module("software_butcher.brain.loop")
        importlib.reload(mod)
        mod = importlib.import_module("software_butcher.synthesis.report")
        importlib.reload(mod)
        mod = importlib.import_module("software_butcher.__main__")
        importlib.reload(mod)
    finally:
        if openai is not None:
            sys.modules["openai"] = openai
