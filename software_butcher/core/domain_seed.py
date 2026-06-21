"""Hypothesis seeding for domain and web root targets."""

from __future__ import annotations

from urllib.parse import urlsplit

from software_butcher.core.assets import Asset
from software_butcher.state.schema import Hypothesis


def primary_web_url(asset: Asset) -> str:
    """Return scheme://host for domain or web assets."""
    locator = asset.locator.strip()
    if locator.startswith(("http://", "https://")):
        parsed = urlsplit(locator)
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{locator.rstrip('/')}"


def is_domain_like(asset: Asset) -> bool:
    if asset.asset_type == "domain":
        return True
    if asset.asset_type == "web_endpoint":
        parsed = urlsplit(asset.locator)
        path = (parsed.path or "").strip("/")
        return bool(parsed.netloc) and not path
    return False


def build_domain_seed_hypotheses(
    asset: Asset,
    reason: str = "Initial target supplied by user",
) -> list[Hypothesis]:
    """Seed one local HTTP surface map on the base URL — no scanner checklist."""
    target = primary_web_url(asset) if is_domain_like(asset) else asset.locator.rstrip("/")
    asset_type = "web_endpoint" if asset.asset_type in {"domain", "web_endpoint"} else asset.asset_type
    return [
        Hypothesis(
            path=target,
            reason=f"Map HTTP surface: headers, stack, redirects, and organic links ({reason})",
            source_finding_id="manual-seed",
            priority=1.0,
            metadata={
                "asset_type": asset_type,
                "intent": "http_surface_map",
                "generated_by": "domain_seed",
                "seed_domain": target,
            },
        )
    ]
