"""Target scope primitives.

Software Butcher is private, but every run still needs an explicit scope file.
The Brain and adapters should refuse work that is outside this object.

Supports both flat CLI scope files and comprehensive HexStrike-style nested JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass
class Scope:
    """Allowed targets and run budget."""

    name: str
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_urls: list[str] = field(default_factory=list)
    allowed_files: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    max_tool_calls: int = 50
    metadata: dict[str, Any] = field(default_factory=dict)

    def allows(self, target: str) -> bool:
        if not target:
            return False

        if self._is_excluded(target):
            return False

        parsed = urlsplit(target)
        host = (parsed.hostname or target.split("/")[0]).lower().rstrip(".")

        if host in {d.lower().rstrip(".") for d in self.allowed_ips}:
            return True

        if parsed.scheme and self._url_allowed(target):
            return True

        if self._domain_allowed(host):
            return True

        if self._ip_allowed(host):
            return True

        return any(target.startswith(prefix) for prefix in self.allowed_files)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        normalized = normalize_scope_payload(payload)
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in normalized.items() if k in known})

    def _is_excluded(self, target: str) -> bool:
        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or ""

        for domain in self.excluded_domains:
            domain = domain.lower().rstrip(".")
            if host == domain or host.endswith(f".{domain}"):
                return True

        for excluded in self.excluded_paths:
            if excluded and excluded in path:
                return True

        excluded_keywords = self.metadata.get("excluded_keywords", [])
        if isinstance(excluded_keywords, list):
            lowered = target.lower()
            if any(str(kw).lower() in lowered for kw in excluded_keywords):
                return True

        return False

    def _url_allowed(self, target: str) -> bool:
        return any(target.startswith(prefix.rstrip("/") + "/") or target == prefix.rstrip("/") for prefix in self.allowed_urls)

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for domain in self.allowed_domains:
            domain = domain.lower().rstrip(".")
            if host == domain or host.endswith(f".{domain}"):
                return True
        return False

    def _ip_allowed(self, host: str) -> bool:
        try:
            ip = ip_address(host)
        except ValueError:
            return False
        for cidr in self.allowed_cidrs:
            try:
                if ip in ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False


def normalize_scope_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert flat or comprehensive HexStrike scope JSON into Scope kwargs."""
    if "allowed_domains" in payload or "allowed_urls" in payload:
        return dict(payload)

    targets = payload.get("targets") or {}
    testing_limits = payload.get("testing_limits") or {}
    exclusions = payload.get("exclusions") or {}
    paths_cfg = payload.get("paths") or {}
    metadata = payload.get("metadata") or {}

    domains = list(targets.get("allowed_domains") or targets.get("domains") or [])
    cidrs = list(targets.get("allowed_cidrs") or targets.get("ip_ranges") or [])
    ips = list(targets.get("allowed_ips") or targets.get("specific_ips") or [])

    excluded_keywords = list(exclusions.get("keywords") or [])
    full_metadata = {
        **metadata,
        "description": payload.get("description"),
        "format": "comprehensive",
        "comprehensive_scope": payload,
        "excluded_keywords": excluded_keywords,
    }

    return {
        "name": payload.get("name") or metadata.get("engagement_name") or "assessment",
        "allowed_domains": domains,
        "allowed_cidrs": cidrs,
        "allowed_ips": ips,
        "allowed_urls": list(targets.get("allowed_urls") or []),
        "allowed_files": list(targets.get("allowed_files") or []),
        "excluded_domains": list(exclusions.get("domains") or []),
        "excluded_paths": list(paths_cfg.get("excluded_paths") or []),
        "max_tool_calls": int(testing_limits.get("max_tool_calls") or 50),
        "metadata": full_metadata,
    }
