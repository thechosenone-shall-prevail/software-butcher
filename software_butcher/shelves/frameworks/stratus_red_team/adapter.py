"""Stratus Red Team adapter for controlled cloud attack simulation."""

from __future__ import annotations

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.runner import RunRequest, ShelfRunner
from software_butcher.core.scope import Scope


class StratusRedTeamAdapter:
    name = "stratus_red_team"
    capabilities = (
        AdapterCapability(
            name="cloud_attack_simulation",
            description="Run controlled cloud attack simulations and detection validation.",
            asset_types=("cloud_account",),
        ),
    )

    def __init__(self, runner: ShelfRunner | None = None) -> None:
        self.runner = runner or ShelfRunner()

    def plan(self, request: AdapterRequest) -> dict:
        technique = request.options.get("technique")
        if not technique:
            return {"adapter": self.name, "request": request, "error": "options.technique is required"}

        lifecycle = request.options.get("lifecycle", "detonate")
        if lifecycle not in {"warmup", "detonate", "cleanup"}:
            return {"adapter": self.name, "request": request, "error": "options.lifecycle must be warmup, detonate, or cleanup"}

        return {
            "adapter": self.name,
            "request": request,
            "technique": technique,
            "lifecycle": lifecycle,
            "command": ["stratus", lifecycle, technique],
            "execute": bool(request.options.get("execute", False)),
        }

    def execute(self, plan: dict) -> AdapterResult:
        if plan.get("error"):
            return AdapterResult(adapter=self.name, success=False, summary=plan["error"], raw={"plan": str(plan)})
        if not plan["execute"]:
            return AdapterResult(
                adapter=self.name,
                success=True,
                summary=f"Stratus {plan['lifecycle']} plan prepared for {plan['technique']} without execution.",
                findings=[
                    {
                        "hypothesis": f"Stratus cloud technique {plan['technique']} is queued for controlled validation.",
                        "path": plan["request"].target,
                        "provenance": "stratus_red_team:plan",
                        "status": "hypothesis",
                        "confidence": 0.3,
                        "evidence": [" ".join(plan["command"])],
                        "asset_type": plan["request"].asset_type,
                    }
                ],
                raw={"plan": str(plan)},
            )

        request = plan["request"]
        run = self.runner.run(
            RunRequest(
                command=plan["command"],
                target=request.target,
                adapter=self.name,
                scope=Scope(**request.scope),
                timeout=int(request.budget.get("timeout", 300)),
            )
        )
        return self.normalize_results({"plan": plan, "run": run.to_dict()})

    def normalize_results(self, raw_output) -> AdapterResult:
        plan = raw_output["plan"]
        request = plan["request"]
        run = raw_output["run"]
        return AdapterResult(
            adapter=self.name,
            success=run["success"],
            summary=f"Stratus {plan['lifecycle']} completed for {plan['technique']}.",
            findings=[
                {
                    "hypothesis": f"Stratus cloud technique {plan['technique']} produced validation evidence.",
                    "path": request.target,
                    "provenance": f"stratus_red_team:{plan['lifecycle']}",
                    "status": "confirmed" if run["success"] else "hypothesis",
                    "confidence": 0.7 if run["success"] else 0.35,
                    "evidence": [(run["stdout"] + "\n" + run["stderr"]).strip()[:4000]],
                    "asset_type": request.asset_type,
                }
            ],
            artifacts=[run["artifact_dir"]],
            raw=run,
        )
