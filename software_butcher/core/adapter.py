"""Adapter contract for shelves and frameworks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class AdapterCapability:
    """A capability exposed by an adapter."""

    name: str
    description: str
    asset_types: tuple[str, ...]


@dataclass
class AdapterRequest:
    """Normalized work request passed from Brain to Shelf adapters."""

    objective: str
    target: str
    asset_type: str = "unknown"
    scope: dict[str, Any] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterResult:
    """Structured adapter result suitable for Brain ingestion."""

    adapter: str
    success: bool
    summary: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class FrameworkAdapter(Protocol):
    """Interface implemented by every Software Butcher adapter."""

    name: str
    capabilities: tuple[AdapterCapability, ...]

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        """Create an adapter-native execution plan."""

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        """Execute an adapter-native plan."""

    def normalize_results(self, raw_output: Any) -> AdapterResult:
        """Convert raw framework output into structured evidence."""
