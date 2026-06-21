"""High-level project object for early Software Butcher runs."""

from __future__ import annotations

from pathlib import Path

from software_butcher.brain.escalation import EscalationLadder
from software_butcher.core.asset_expander import AssetExpander
from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.binary_acquisition import BinaryAcquisition
from software_butcher.core.domain_seed import build_domain_seed_hypotheses
from software_butcher.core.router import AssetRouter, RouteDecision
from software_butcher.core.scope import Scope
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore


class ButcherProject:
    """One private assessment workspace."""

    def __init__(self, root: str | Path, scope: Scope, *, resume: bool = True) -> None:
        self.root = Path(root)
        self.scope = scope
        self.router = AssetRouter()
        self.expander = AssetExpander()
        self.escalation = EscalationLadder()
        self.binary_acquisition = BinaryAcquisition()
        self.inventory_path = self.root / "asset_inventory.json"
        self.state_path = self.root / "finding_state.json"

        if resume and self.state_path.exists():
            self.findings = FindingStore.load(self.state_path)
            self.resumed = True
            self.findings.set_engagement_from_scope(scope)
        else:
            self.findings = FindingStore(self.state_path)
            self.resumed = False

        self.findings.set_engagement_from_scope(scope)

        if resume and self.inventory_path.exists():
            self.inventory = AssetInventory.load(self.inventory_path)
        else:
            self.inventory = AssetInventory()

    def add_asset(self, asset: Asset) -> Asset:
        if not self.scope.allows(asset.locator):
            raise ValueError(f"Asset outside scope: {asset.locator}")
        return self.inventory.add(asset)

    def route_asset(self, asset: Asset, intent: str = "discover") -> RouteDecision:
        return self.router.route(asset, intent=intent)

    def seed_asset(self, asset: Asset, reason: str = "Initial target supplied by user") -> None:
        self.findings.set_base_target(asset.locator)
        for hypothesis in build_domain_seed_hypotheses(asset, reason=reason):
            self.findings.add_hypothesis(hypothesis)

    def expand_from_finding(self, finding: Finding) -> list[Asset]:
        """Grow the asset graph from a newly ingested finding."""
        return self.expander.expand(
            finding,
            self.scope,
            self.inventory,
            seed_hypotheses=True,
            hypothesis_queue=self.findings.queue,
            workspace_root=self.root,
            binary_acquisition=self.binary_acquisition,
        )

    def escalate_from_finding(self, finding: Finding) -> list[Asset]:
        """Pivot to upstream source analysis when direct exploitation fails."""
        return self.escalation.escalate(
            finding,
            self.findings,
            self.scope,
            self.inventory,
            self.root,
            hypothesis_queue=self.findings.queue,
        )

    def process_finding(self, finding: Finding) -> list[Asset]:
        """Run Phase A expansion and Phase B outcome escalation for one finding."""
        new_assets = self.expand_from_finding(finding)
        escalated = self.escalate_from_finding(finding)
        return new_assets + escalated

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.findings.save()
        self.inventory.save(self.inventory_path)
