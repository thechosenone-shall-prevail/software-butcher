"""Framework configuration for local/private deployments."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FrameworkConfig:
    name: str
    mode: str
    command: str | None = None
    path: str | None = None
    url: str | None = None
    api_key_env: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def api_key(self) -> str | None:
        if not self.api_key_env:
            return None
        return os.getenv(self.api_key_env)


DEFAULT_FRAMEWORKS = {
    "hexstrike": FrameworkConfig(
        name="hexstrike",
        mode="api",
        url=os.getenv("HEXSTRIKE_URL", "http://127.0.0.1:8888"),
    ),
    "boaz": FrameworkConfig(
        name="boaz",
        mode="local_python",
        path=os.getenv("BOAZ_PATH", "BOAZ_beta"),
    ),
    "atomic_red_team": FrameworkConfig(
        name="atomic_red_team",
        mode="cli",
        command=os.getenv("ATOMIC_PWSH", "pwsh"),
        path=os.getenv("ATOMIC_RED_TEAM_PATH"),
    ),
    "caldera": FrameworkConfig(
        name="caldera",
        mode="api",
        url=os.getenv("CALDERA_URL", "http://127.0.0.1:8888"),
        api_key_env="CALDERA_API_KEY",
    ),
    "stratus_red_team": FrameworkConfig(
        name="stratus_red_team",
        mode="cli",
        command=os.getenv("STRATUS_COMMAND", "stratus"),
    ),
}


class FrameworkConfigSet:
    """Named framework configs with JSON load support."""

    def __init__(self, frameworks: dict[str, FrameworkConfig] | None = None) -> None:
        self.frameworks = frameworks or dict(DEFAULT_FRAMEWORKS)

    def get(self, name: str) -> FrameworkConfig:
        return self.frameworks[name]

    def to_dict(self) -> dict[str, Any]:
        return {name: config.to_dict() for name, config in self.frameworks.items()}

    @classmethod
    def load(cls, path: str | Path | None = None) -> "FrameworkConfigSet":
        if path is None:
            return cls()

        config_path = Path(path)
        if not config_path.exists():
            return cls()

        payload = json.loads(config_path.read_text(encoding="utf-8"))
        merged = dict(DEFAULT_FRAMEWORKS)
        for name, item in payload.get("frameworks", {}).items():
            base = merged.get(name, FrameworkConfig(name=name, mode=item.get("mode", "cli")))
            data = base.to_dict()
            data.update(item)
            merged[name] = FrameworkConfig(**data)
        return cls(merged)
