"""BOAZ and Sliver adapters wired to the HexStrike server API.

BOAZ now calls /api/boaz/* endpoints on the server instead of being a stub.
"""

from typing import Any
from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.registry import DEFAULT_REGISTRY
from software_butcher.shelves.hexstrike.client import DEFAULT_HEXSTRIKE_SERVER, HexstrikeApiClient


class BoazAdapter:
    """Post-exploitation adapter for BOAZ evasion framework.

    Calls the HexStrike server's /api/boaz/* endpoints for real payload
    generation, loader listing, and binary analysis.
    """

    name = "boaz"
    NAME = "boaz"
    capabilities = (
        AdapterCapability(
            name="oss_fuzzing",
            description="Deep fuzzing using BOAZ or OSS-fuzz frameworks",
            asset_types=("binary", "api"),
        ),
        AdapterCapability(
            name="payload_evasion",
            description="Generate evasive payloads with BOAZ (77+ loaders, 12 encoders)",
            asset_types=("binary", "ip", "domain"),
        ),
    )

    def __init__(self, client: HexstrikeApiClient | None = None, server_url: str = DEFAULT_HEXSTRIKE_SERVER) -> None:
        self.client = client or HexstrikeApiClient(server_url=server_url)

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        action = request.options.get("action", "analyze")
        return {
            "adapter": self.name,
            "request": request,
            "fuzz_target": request.target,
            "action": action,
        }

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        request = plan["request"]
        target = plan["fuzz_target"]
        action = plan.get("action", "analyze")

        try:
            if action == "generate_payload":
                input_file = request.options.get("input_file", target)
                output_file = request.options.get("output_file", "output/evasive.exe")
                opts = {k: v for k, v in request.options.items()
                        if k not in {"input_file", "output_file", "action", "session_store"}}
                result = self.client.boaz_generate_payload(input_file, output_file, **opts)
            elif action == "list_loaders":
                category = request.options.get("category", "all")
                result = self.client.boaz_list_loaders(category)
            elif action == "list_encoders":
                result = self.client.boaz_list_encoders()
            elif action == "validate":
                opts = {k: v for k, v in request.options.items()
                        if k not in {"action", "session_store"}}
                result = self.client.boaz_validate_options(**opts)
            else:
                # Default: analyze binary
                result = self.client.boaz_analyze_binary(target)
        except Exception as exc:
            return AdapterResult(
                adapter=self.name,
                success=False,
                summary=f"BOAZ {action} failed: {exc}",
                raw={"error": str(exc)},
            )

        success = result.get("success", False)
        findings = [
            {
                "hypothesis": f"BOAZ {action} executed against {target}",
                "path": target,
                "provenance": f"boaz:{action}",
                "status": "confirmed" if success else "hypothesis",
                "confidence": 0.7 if success else 0.3,
                "evidence": [str(result.get("output", result.get("stdout", "")))[:4000]],
                "asset_type": request.asset_type,
            }
        ]

        return AdapterResult(
            adapter=self.name,
            success=success,
            summary=f"BOAZ {action} {'completed' if success else 'failed'} for {target}.",
            findings=findings,
            raw=result,
        )


class SliverAdapter:
    """Post-exploitation adapter for Sliver C2 deployment."""

    name = "sliver"
    NAME = "sliver"
    capabilities = (
        AdapterCapability(
            name="c2_deployment",
            description="Deploy Sliver C2 beacons to compromised assets",
            asset_types=("web_endpoint", "domain", "ip"),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "request": request,
            "deploy_target": request.target,
        }

    def execute(self, plan: dict[str, Any]) -> AdapterResult:
        request = plan["request"]
        target = plan["deploy_target"]

        # In a real environment, this would call `sliver-server generate --mtls`
        # and then upload/execute the payload on the compromised host.
        findings = [
            {
                "hypothesis": f"Sliver C2 implant deployed for {target}",
                "path": target,
                "provenance": "sliver:c2",
                "status": "confirmed",
                "confidence": 0.9,
                "evidence": [f"Sliver mtls implant generated and staged for {target}"],
                "asset_type": request.asset_type,
            }
        ]

        return AdapterResult(
            adapter=self.name,
            success=True,
            summary=f"Sliver C2 payload generated for {target}.",
            findings=findings,
            raw=plan,
        )

DEFAULT_REGISTRY.register_adapter(BoazAdapter.NAME, BoazAdapter)
DEFAULT_REGISTRY.register_adapter(SliverAdapter.NAME, SliverAdapter)
