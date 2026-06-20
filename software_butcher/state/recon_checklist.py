"""Recon completeness gating — no Nuclei/exploit until the surface is mapped."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.state.schema import Finding

REQUIRED_RECON_CAPABILITIES: tuple[str, ...] = (
    "web_behavior_analysis",
    "technology_fingerprint",
    "endpoint_discovery",
)

HOST_LEVEL_RECON_CAPABILITIES = frozenset(REQUIRED_RECON_CAPABILITIES)

EXPLOIT_SCAN_CAPABILITIES = frozenset(
    {
        "vulnerability_scanning",
        "exploit_generation",
        "sql_injection_probing",
        "xss_scanning",
        "cms_scanning",
    }
)


def is_root_surface_url(url: str) -> bool:
    """True when the URL is the web root (scheme://host with no path segment)."""
    parsed = urlsplit(url.strip())
    return bool(parsed.netloc) and not (parsed.path or "").strip("/")


@dataclass
class ReconChecklist:
    completed: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"completed": self.completed}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReconChecklist":
        return cls(completed={k: list(v) for k, v in (data.get("completed") or {}).items()})

    def mark(self, host: str, capability: str) -> None:
        host = host.lower()
        entries = self.completed.setdefault(host, [])
        if capability not in entries:
            entries.append(capability)

    def done(self, host: str) -> list[str]:
        return list(self.completed.get(host.lower(), []))

    def is_complete(self, host: str) -> bool:
        done = set(self.done(host))
        return all(cap in done for cap in REQUIRED_RECON_CAPABILITIES)

    def next_missing(self, host: str) -> str | None:
        done = set(self.done(host))
        for cap in REQUIRED_RECON_CAPABILITIES:
            if cap not in done:
                return cap
        return None


def capability_from_finding(finding: Finding) -> str:
    capability = str((finding.metadata or {}).get("capability", "")).lower()
    if capability:
        return capability
    if finding.provenance.startswith("playwright_curl"):
        return "web_behavior_analysis"
    return ""


def record_recon_progress(
    checklist: ReconChecklist,
    finding: Finding,
    *,
    base_target: str = "",
) -> None:
    capability = capability_from_finding(finding)
    if not capability:
        return

    host = host_key(finding.path)
    if capability in HOST_LEVEL_RECON_CAPABILITIES:
        root = base_web_url(base_target or finding.path).rstrip("/")
        if finding.path.rstrip("/").lower() != root.lower() and not is_root_surface_url(finding.path):
            return

    if capability in REQUIRED_RECON_CAPABILITIES or capability == "directory_bruteforce":
        checklist.mark(host, capability)
        if capability == "directory_bruteforce" and "endpoint_discovery" not in checklist.done(host):
            checklist.mark(host, "endpoint_discovery")


def recon_allows_capability(checklist: ReconChecklist, host: str, capability: str) -> bool:
    if capability not in EXPLOIT_SCAN_CAPABILITIES:
        return True
    return checklist.is_complete(host)
