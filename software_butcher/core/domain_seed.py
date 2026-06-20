"""OSINT-first hypothesis seeding for domain and web root targets."""

from __future__ import annotations

from urllib.parse import urlsplit

from software_butcher.core.assets import Asset
from software_butcher.state.schema import Hypothesis

# Ordered by priority — recon breadth before deep endpoint brute force.
DOMAIN_OSINT_INTENTS: tuple[tuple[str, float, str], ...] = (
    ("bugbounty_recon", 1.0, "Company/domain OSINT — subdomain and asset discovery."),
    ("technology_fingerprint", 0.96, "Fingerprint technology stack on primary domain surface."),
    ("endpoint_discovery", 0.92, "Enumerate web paths on primary domain surface."),
)


def primary_web_url(asset: Asset) -> str:
    """Return an https URL for domain or web assets."""
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
    """Build OSINT-first hypotheses for a domain or bare web root target."""
    if not is_domain_like(asset):
        return [
            Hypothesis(
                path=asset.locator,
                reason=reason,
                source_finding_id="manual-seed",
                priority=1.0,
                metadata={
                    "asset_type": asset.asset_type,
                    "intent": "endpoint_discovery",
                    "generated_by": "domain_seed",
                },
            )
        ]

    target = primary_web_url(asset)
    asset_type = "web_endpoint" if asset.asset_type == "domain" else asset.asset_type
    generated: list[Hypothesis] = []

    for intent, priority, seed_reason in DOMAIN_OSINT_INTENTS:
        generated.append(
            Hypothesis(
                path=target,
                reason=f"{seed_reason} ({reason})",
                source_finding_id="manual-seed",
                priority=priority,
                metadata={
                    "asset_type": asset_type,
                    "intent": intent,
                    "generated_by": "domain_seed",
                    "seed_domain": target,
                },
            )
        )

    return generated
