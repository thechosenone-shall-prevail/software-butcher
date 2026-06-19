"""Asset inventory primitives."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


ASSET_TYPES = {
    "ip",
    "domain",
    "web_endpoint",
    "api",
    "binary",
    "source_repo",
    "container",
    "cloud_account",
    "ad_environment",
    "static_asset",
    "unknown",
}


@dataclass
class Asset:
    """A discovered target asset."""

    locator: str
    asset_type: str = "unknown"
    id: str = field(default_factory=lambda: f"asset-{uuid4().hex[:12]}")
    parent: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_by: str = "manual"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.asset_type not in ASSET_TYPES:
            raise ValueError(f"Unknown asset_type: {self.asset_type}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AssetInventory:
    """Deduplicated collection of discovered assets."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._by_locator: dict[str, str] = {}

    def add(self, asset: Asset) -> Asset:
        existing_id = self._by_locator.get(asset.locator)
        if existing_id:
            existing = self._assets[existing_id]
            existing.metadata.update(asset.metadata)
            if existing.asset_type == "unknown" and asset.asset_type != "unknown":
                existing.asset_type = asset.asset_type
            return existing

        self._assets[asset.id] = asset
        self._by_locator[asset.locator] = asset.id
        return asset

    def get(self, asset_id: str) -> Asset:
        return self._assets[asset_id]

    def list(self, asset_type: str | None = None) -> list[Asset]:
        assets = list(self._assets.values())
        if asset_type:
            assets = [asset for asset in assets if asset.asset_type == asset_type]
        return assets

    def to_list(self) -> list[dict[str, Any]]:
        return [asset.to_dict() for asset in self._assets.values()]
