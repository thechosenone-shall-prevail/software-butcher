"""CALDERA adapter for ATT&CK-style emulation planning and API execution."""

from __future__ import annotations

import requests

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult


class CalderaAdapter:
    name = "caldera"
    capabilities = (
        AdapterCapability(
            name="adversary_emulation",
            description="Run controlled CALDERA operations in authorized environments.",
            asset_types=("ad_environment", "ip", "domain"),
        ),
    )

    def __init__(self, server_url: str = "http://127.0.0.1:8888", api_key: str | None = None) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key

    def plan(self, request: AdapterRequest) -> dict:
        operation = {
            "name": request.options.get("operation_name", "software-butcher-operation"),
            "adversary_id": request.options.get("adversary_id"),
            "group": request.options.get("group"),
            "planner_id": request.options.get("planner_id"),
        }
        return {
            "adapter": self.name,
            "request": request,
            "operation": operation,
            "execute": bool(request.options.get("execute", False)),
        }

    def execute(self, plan: dict) -> AdapterResult:
        operation = plan["operation"]
        missing = [key for key in ("adversary_id", "group") if not operation.get(key)]
        if missing:
            return AdapterResult(
                adapter=self.name,
                success=False,
                summary=f"CALDERA operation missing required option(s): {', '.join(missing)}",
                raw={"plan": str(plan)},
            )

        if not plan["execute"]:
            return AdapterResult(
                adapter=self.name,
                success=True,
                summary=f"CALDERA operation plan prepared for adversary {operation['adversary_id']} without execution.",
                findings=[
                    {
                        "hypothesis": "CALDERA adversary emulation operation is queued for controlled validation.",
                        "path": plan["request"].target,
                        "provenance": "caldera:plan",
                        "status": "hypothesis",
                        "confidence": 0.3,
                        "evidence": [str(operation)],
                        "asset_type": plan["request"].asset_type,
                    }
                ],
                raw={"operation": operation},
            )

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["KEY"] = self.api_key

        try:
            response = requests.post(
                f"{self.server_url}/api/rest",
                headers=headers,
                json={"index": "operations", **operation},
                timeout=int(plan["request"].budget.get("timeout", 120)),
            )
            response.raise_for_status()
            raw = response.json()
        except requests.RequestException as exc:
            return AdapterResult(adapter=self.name, success=False, summary=f"CALDERA API request failed: {exc}", raw={"operation": operation})

        return self.normalize_results({"request": plan["request"], "operation": operation, "response": raw})

    def normalize_results(self, raw_output) -> AdapterResult:
        request = raw_output["request"]
        operation = raw_output["operation"]
        response = raw_output["response"]
        return AdapterResult(
            adapter=self.name,
            success=True,
            summary=f"CALDERA operation {operation['name']} submitted.",
            findings=[
                {
                    "hypothesis": f"CALDERA operation {operation['name']} produced emulation evidence.",
                    "path": request.target,
                    "provenance": "caldera:operation",
                    "status": "hypothesis",
                    "confidence": 0.5,
                    "evidence": [str(response)[:4000]],
                    "asset_type": request.asset_type,
                }
            ],
            raw=response,
        )
