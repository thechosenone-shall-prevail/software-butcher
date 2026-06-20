"""OSINT-first hypothesis seeding for domain and web root targets."""

from __future__ import annotations

from urllib.parse import urlsplit

from software_butcher.core.assets import Asset
from software_butcher.state.schema import Hypothesis

from software_butcher.core.app_wordlists import build_context_path_hypotheses

# Web assessment playbook — behavior and fingerprint before brute force / Nuclei.
WEB_RECON_INTENTS: tuple[tuple[str, float, str], ...] = (
    ("web_behavior_analysis", 1.0, "Observe HTTP behavior, redirects, headers, and cookies."),
    ("technology_fingerprint", 0.97, "Fingerprint web server, CMS, and application stack."),
    ("endpoint_discovery", 0.94, "Map paths with gobuster, ffuf, and crawler-assisted wordlists."),
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
    target = primary_web_url(asset) if is_domain_like(asset) else asset.locator.rstrip("/")
    asset_type = "web_endpoint" if asset.asset_type in {"domain", "web_endpoint"} else asset.asset_type
    generated: list[Hypothesis] = []

    for intent, priority, seed_reason in WEB_RECON_INTENTS:
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

    generated.extend(build_context_path_hypotheses(target, set()))
    return generated
