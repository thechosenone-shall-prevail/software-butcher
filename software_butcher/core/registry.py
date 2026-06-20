from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ToolSpec:
    name: str
    adapter: str
    command: Optional[List[str]] = None
    description: str = ""


class Registry:
    """Simple in-memory registry for tools and adapters.

    This is intentionally small: adapters register themselves and tools
    are data-driven specs that refer to adapters by name.
    """

    def __init__(self) -> None:
        self.tools: Dict[str, ToolSpec] = {}
        self.adapters: Dict[str, Any] = {}

    def register_tool(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def register_adapter(self, name: str, adapter: Any) -> None:
        self.adapters[name] = adapter

    def get_tool(self, name: str) -> Optional[ToolSpec]:
        return self.tools.get(name)

    def get_adapter(self, name: str) -> Optional[Any]:
        return self.adapters.get(name)


class AdapterRegistry:
    """Registry for FrameworkAdapter-style shelf implementations."""

    def __init__(self) -> None:
        self._adapters: dict[str, Any] = {}

    def register(self, adapter: Any) -> None:
        name = getattr(adapter, "name", None) or getattr(adapter, "NAME", None)
        if not name:
            raise ValueError("Adapter must define a name")
        self._adapters[name] = adapter

    def get(self, name: str) -> Any | None:
        return self._adapters.get(name)

    def find_by_capability(self, capability_name: str) -> Any | None:
        """Find the first adapter that declares a matching capability."""
        for adapter in self._adapters.values():
            caps = getattr(adapter, "capabilities", ())
            if any(c.name == capability_name for c in caps):
                return adapter
        return None

    def list_capabilities(self) -> list[dict[str, str]]:
        """Return all registered capabilities across all adapters."""
        caps: list[dict[str, str]] = []
        for adapter in self._adapters.values():
            for c in getattr(adapter, "capabilities", ()):
                caps.append({"capability": c.name, "adapter": adapter.name, "description": c.description})
        return caps

    def list(self) -> list[str]:
        return sorted(self._adapters.keys())


# Module-level default registry for convenience
DEFAULT_REGISTRY = Registry()


def register_default_tool(name: str, adapter: str, command: Optional[List[str]] = None, description: str = "") -> None:
    DEFAULT_REGISTRY.register_tool(ToolSpec(name=name, adapter=adapter, command=command, description=description))


_DEFAULT_ADAPTER_REGISTRY: AdapterRegistry | None = None


def default_registry() -> AdapterRegistry:
    """Return the lazily-built default adapter registry for Brain and CLI use."""
    global _DEFAULT_ADAPTER_REGISTRY
    if _DEFAULT_ADAPTER_REGISTRY is not None:
        return _DEFAULT_ADAPTER_REGISTRY

    registry = AdapterRegistry()

    from software_butcher.shelves.binary.triage import BinaryTriageAdapter
    from software_butcher.shelves.binary.oss_fuzz import OssFuzzAdapter
    from software_butcher.shelves.code.analysis import CodeAnalysisAdapter
    from software_butcher.shelves.frameworks.atomic_red_team.adapter import AtomicRedTeamAdapter
    from software_butcher.shelves.frameworks.boaz_adapter import BoazAdapter, SliverAdapter
    from software_butcher.shelves.frameworks.caldera.adapter import CalderaAdapter
    from software_butcher.shelves.frameworks.stratus_red_team.adapter import StratusRedTeamAdapter
    from software_butcher.shelves.hexstrike.adapter import HexstrikeAdapter
    from software_butcher.shelves.web.playwright_curl import PlaywrightCurlAdapter

    registry.register(BinaryTriageAdapter())
    registry.register(OssFuzzAdapter())
    registry.register(CodeAnalysisAdapter())
    registry.register(HexstrikeAdapter())
    registry.register(PlaywrightCurlAdapter())
    registry.register(AtomicRedTeamAdapter())
    registry.register(CalderaAdapter())
    registry.register(StratusRedTeamAdapter())
    registry.register(BoazAdapter())
    registry.register(SliverAdapter())

    _DEFAULT_ADAPTER_REGISTRY = registry
    return registry
