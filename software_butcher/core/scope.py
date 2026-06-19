"""Target scope primitives.

Software Butcher is private, but every run still needs an explicit scope file.
The Brain and adapters should refuse work that is outside this object.
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
    allowed_urls: list[str] = field(default_factory=list)
    allowed_files: list[str] = field(default_factory=list)
    max_tool_calls: int = 50
    metadata: dict[str, Any] = field(default_factory=dict)

    def allows(self, target: str) -> bool:
        if not target:
            return False

        parsed = urlsplit(target)
        host = parsed.hostname or target.split("/")[0]

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
        return cls(**payload)

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
