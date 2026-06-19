"""High-level project object for early Software Butcher runs."""

from __future__ import annotations

from pathlib import Path

from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.router import AssetRouter, RouteDecision
from software_butcher.core.scope import Scope
from software_butcher.state.schema import Hypothesis
from software_butcher.state.store import FindingStore


class ButcherProject:
    """One private assessment workspace."""

    def __init__(self, root: str | Path, scope: Scope) -> None:
        self.root = Path(root)
        self.scope = scope
        self.inventory = AssetInventory()
        self.router = AssetRouter()
        self.findings = FindingStore(self.root / "finding_state.json")

    def add_asset(self, asset: Asset) -> Asset:
        if not self.scope.allows(asset.locator):
            raise ValueError(f"Asset outside scope: {asset.locator}")
        return self.inventory.add(asset)

    def route_asset(self, asset: Asset, intent: str = "discover") -> RouteDecision:
        return self.router.route(asset, intent=intent)

    def seed_asset(self, asset: Asset, reason: str = "Initial target supplied by user") -> None:
        self.findings.set_base_target(asset.locator)
        self.findings.add_hypothesis(
            Hypothesis(
                path=asset.locator,
                reason=reason,
                source_finding_id="manual-seed",
                priority=1.0,
                metadata={"asset_type": asset.asset_type},
            )
        )

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.findings.save()
