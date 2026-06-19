"""Framework availability checks."""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests

from .framework_config import FrameworkConfig, FrameworkConfigSet


@dataclass
class HealthStatus:
    name: str
    available: bool
    mode: str
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FrameworkHealth:
    """Doctor checks for external frameworks."""

    def __init__(self, configs: FrameworkConfigSet | None = None, timeout: int = 3) -> None:
        self.configs = configs or FrameworkConfigSet()
        self.timeout = timeout

    def check_all(self) -> dict[str, HealthStatus]:
        return {name: self.check(config) for name, config in self.configs.frameworks.items()}

    def available(self, name: str) -> bool:
        return self.check(self.configs.get(name)).available

    def check(self, config: FrameworkConfig) -> HealthStatus:
        if not config.enabled:
            return HealthStatus(config.name, False, config.mode, "disabled by config")

        if config.name == "hexstrike":
            return self._check_hexstrike(config)
        if config.name == "boaz":
            return self._check_boaz(config)
        if config.name == "atomic_red_team":
            return self._check_atomic(config)
        if config.name == "caldera":
            return self._check_caldera(config)
        if config.name == "stratus_red_team":
            return self._check_cli(config, "Stratus CLI")

        if config.mode == "cli":
            return self._check_cli(config, config.name)
        if config.mode == "api":
            return self._check_api(config, "/health")
        if config.path:
            exists = Path(config.path).exists()
            return HealthStatus(config.name, exists, config.mode, f"path {'found' if exists else 'missing'}: {config.path}")

        return HealthStatus(config.name, False, config.mode, "no health check available")

    def _check_hexstrike(self, config: FrameworkConfig) -> HealthStatus:
        # /health probes 100+ tools and is too slow for doctor; root liveness is enough.
        if not config.url:
            return HealthStatus(config.name, False, config.mode, "URL not configured")
        try:
            response = requests.get(config.url.rstrip("/") + "/", timeout=self.timeout)
            available = response.status_code < 500
            detail = f"{config.url} reachable with HTTP {response.status_code}"
            return HealthStatus(config.name, available, config.mode, detail)
        except requests.RequestException as exc:
            return HealthStatus(config.name, False, config.mode, f"service not reachable: {exc}")

    def _check_api(self, config: FrameworkConfig, health_path: str) -> HealthStatus:
        if not config.url:
            return HealthStatus(config.name, False, config.mode, "URL not configured")
        try:
            response = requests.get(f"{config.url.rstrip('/')}{health_path}", timeout=self.timeout)
            available = response.status_code < 500
            detail = f"{config.url}{health_path} reachable with HTTP {response.status_code}"
            return HealthStatus(config.name, available, config.mode, detail)
        except requests.RequestException as exc:
            return HealthStatus(config.name, False, config.mode, f"service not reachable: {exc}")

    def _check_caldera(self, config: FrameworkConfig) -> HealthStatus:
        if not config.url:
            return HealthStatus(config.name, False, config.mode, "CALDERA_URL not configured")
        try:
            response = requests.get(config.url, timeout=self.timeout)
            reachable = response.status_code < 500
            detail = f"{config.url} reachable with HTTP {response.status_code}" if reachable else f"{config.url} returned HTTP {response.status_code}"
            return HealthStatus(config.name, reachable, config.mode, detail, {"api_key_present": bool(config.api_key)})
        except requests.RequestException as exc:
            return HealthStatus(config.name, False, config.mode, f"service not reachable: {exc}", {"api_key_present": bool(config.api_key)})

    def _check_boaz(self, config: FrameworkConfig) -> HealthStatus:
        path = Path(config.path or "BOAZ_beta")
        script = path / "Boaz.py"
        available = script.exists()
        return HealthStatus(
            config.name,
            available,
            config.mode,
            f"{script} {'found' if available else 'missing'}",
            {"path": str(path)},
        )

    def _check_atomic(self, config: FrameworkConfig) -> HealthStatus:
        pwsh = shutil.which(config.command or "pwsh")
        atomics_path = Path(config.path).exists() if config.path else False
        available = bool(pwsh) and atomics_path
        detail_parts = [
            f"pwsh {'found' if pwsh else 'missing'}",
            f"atomics path {'found' if atomics_path else 'missing'}",
        ]
        return HealthStatus(
            config.name,
            available,
            config.mode,
            "; ".join(detail_parts),
            {"command_path": pwsh, "atomics_path": config.path},
        )

    def _check_cli(self, config: FrameworkConfig, label: str) -> HealthStatus:
        command = config.command or config.name
        command_path = shutil.which(command)
        return HealthStatus(
            config.name,
            bool(command_path),
            config.mode,
            f"{label} {'found' if command_path else 'missing'}: {command}",
            {"command_path": command_path},
        )
