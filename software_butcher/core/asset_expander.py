"""Expand the asset graph from Brain findings.

Findings often reveal new targets (subdomains, endpoints, binaries, repos).
This module turns those locators into scoped inventory entries so the Brain
can route work to the correct shelf on the next hypothesis.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from software_butcher.core.asset_classifier import classify_url_asset_type, file_extension, is_static_asset
from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.binary_acquisition import BinaryAcquisition
from software_butcher.core.classifier import BINARY_SUFFIXES, classify_target
from software_butcher.core.scope import Scope
from software_butcher.state.schema import Finding, Hypothesis

URL_PATTERN = re.compile(r"https?://[^\s<>\"'\]]+", re.IGNORECASE)
GITHUB_REPO_PATTERN = re.compile(
    r"https?://(?:www\.)?github\.com/[^/\s]+/[^/\s]+/?",
    re.IGNORECASE,
)

DEFAULT_INTENT_BY_ASSET_TYPE: dict[str, str] = {
    "binary": "reverse_engineer",
    "source_repo": "source_static_analysis",
    "domain": "http_surface_map",
    "web_endpoint": "http_surface_map",
    "api": "api_enumeration",
    "ip": "port_scanning",
    "cloud_account": "cloud_security_audit",
    "container": "container_security",
    "ad_environment": "ad_enumeration",
}


def default_intent_for_asset_type(asset_type: str) -> str:
    return DEFAULT_INTENT_BY_ASSET_TYPE.get(asset_type, "discover")


def classify_discovered_locator(locator: str) -> Asset:
    """Classify a discovered locator, refining URL paths into binary/static types."""
    asset = classify_target(locator)
    if asset.asset_type in {"web_endpoint", "api", "unknown"}:
        if GITHUB_REPO_PATTERN.match(locator.rstrip("/")):
            return Asset(
                locator=locator.rstrip("/"),
                asset_type="source_repo",
                parent=asset.parent,
                metadata=asset.metadata,
                discovered_by="finding_expansion",
            )
        if is_static_asset(locator):
            asset.asset_type = "static_asset"
        elif file_extension(locator) in BINARY_SUFFIXES:
            asset.asset_type = "binary"
        else:
            parsed = urlsplit(locator)
            host = (parsed.hostname or "").lower()
            first_label = host.split(".")[0] if host else ""
            if first_label == "api" or host.startswith("api.") or "/api" in parsed.path.lower():
                asset.asset_type = "api"
            elif asset.asset_type == "unknown" and locator.startswith(("http://", "https://")):
                asset.asset_type = classify_url_asset_type(locator, "web_endpoint")
    asset.discovered_by = "finding_expansion"
    return asset


def extract_locators(finding: Finding) -> list[str]:
    """Collect candidate locators from a finding's path, evidence, and metadata."""
    seen: set[str] = set()
    ordered: list[str] = []

    def add(raw: str) -> None:
        locator = normalize_locator(raw)
        if not locator or locator in seen:
            return
        seen.add(locator)
        ordered.append(locator)

    if finding.path:
        add(finding.path)

    for item in finding.evidence:
        for match in URL_PATTERN.findall(str(item)):
            add(match)

    metadata = finding.metadata or {}
    for endpoint in metadata.get("endpoints", []):
        add(str(endpoint))
    for endpoint in metadata.get("discovered_urls", []):
        add(str(endpoint))
    for subdomain in metadata.get("subdomains", []):
        host = str(subdomain).strip()
        if host.startswith(("http://", "https://")):
            add(host)
        elif host:
            add(f"https://{host}")

    services = metadata.get("services")
    if isinstance(services, dict):
        for port, _service in services.items():
            base = finding.path.rstrip("/")
            if base.startswith(("http://", "https://")):
                parsed = urlsplit(base)
                scheme = parsed.scheme or "http"
                host = parsed.hostname or base
                add(f"{scheme}://{host}:{port}")

    return ordered


def normalize_locator(locator: str) -> str:
    locator = locator.strip().rstrip(".,;)")
    if not locator:
        return ""
    parsed = urlsplit(locator)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        path = parsed.path.rstrip("/") or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.netloc}{port}{path}"
    return locator.rstrip("/")


class AssetExpander:
    """Register newly discovered assets and seed follow-up hypotheses."""

    def expand(
        self,
        finding: Finding,
        scope: Scope,
        inventory: AssetInventory,
        *,
        seed_hypotheses: bool = True,
        hypothesis_queue=None,
        workspace_root: str | Path | None = None,
        binary_acquisition: BinaryAcquisition | None = None,
    ) -> list[Asset]:
        """Add in-scope assets from *finding* and optionally queue hypotheses."""
        if finding.asset_type == "static_asset":
            return []

        primary = normalize_locator(finding.path)
        new_assets: list[Asset] = []
        for locator in extract_locators(finding):
            if primary and locator == primary:
                continue
            if inventory.has_locator(locator):
                continue
            if not scope.allows(locator):
                continue

            asset = classify_discovered_locator(locator)
            if asset.asset_type == "static_asset":
                continue

            asset.parent = finding.path
            asset.metadata = {
                **asset.metadata,
                "source_finding_id": finding.id,
                "discovered_from": finding.path,
            }

            if (
                asset.asset_type == "binary"
                and asset.locator.startswith(("http://", "https://"))
                and workspace_root is not None
                and binary_acquisition is not None
            ):
                local_path = binary_acquisition.download(asset.locator, workspace_root)
                if local_path is not None:
                    asset.metadata["original_url"] = asset.locator
                    asset.locator = str(local_path)

            inventory.add(asset)
            new_assets.append(asset)

            if seed_hypotheses and hypothesis_queue is not None:
                hypothesis_queue.add(
                    Hypothesis(
                        path=asset.locator,
                        reason=f"Discovered asset from finding {finding.id}: {finding.hypothesis[:120]}",
                        source_finding_id=finding.id,
                        priority=0.88 if finding.status == "confirmed" else 0.82,
                        metadata={
                            "asset_type": asset.asset_type,
                            "intent": default_intent_for_asset_type(asset.asset_type),
                            "generated_by": "asset_expander",
                        },
                    )
                )

        return new_assets
