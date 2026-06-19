"""Atomic Red Team adapter.

The adapter defaults to planning only. Set options.execute=true to run an
Atomic test in an authorized lab scope.
"""

from __future__ import annotations

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.runner import RunRequest, ShelfRunner
from software_butcher.core.scope import Scope


class AtomicRedTeamAdapter:
    name = "atomic_red_team"
    capabilities = (
        AdapterCapability(
            name="ttp_validation",
            description="Validate ATT&CK techniques with atomic tests in lab scope.",
            asset_types=("ip", "domain", "ad_environment", "cloud_account"),
        ),
    )

    def __init__(self, runner: ShelfRunner | None = None) -> None:
        self.runner = runner or ShelfRunner()

    def plan(self, request: AdapterRequest) -> dict:
        technique_id = request.options.get("technique_id")
        if not technique_id:
            return {"adapter": self.name, "request": request, "error": "options.technique_id is required"}

        command = self._build_command(
            technique_id=technique_id,
            test_numbers=request.options.get("test_numbers"),
            check_prereqs=bool(request.options.get("check_prereqs", False)),
            get_prereqs=bool(request.options.get("get_prereqs", False)),
            cleanup=bool(request.options.get("cleanup", False)),
        )
        return {
            "adapter": self.name,
            "request": request,
            "technique_id": technique_id,
            "command": command,
            "execute": bool(request.options.get("execute", False)),
        }

    def execute(self, plan: dict) -> AdapterResult:
        if plan.get("error"):
            return AdapterResult(adapter=self.name, success=False, summary=plan["error"], raw={"plan": str(plan)})
        if not plan["execute"]:
            return AdapterResult(
                adapter=self.name,
                success=True,
                summary=f"Atomic Red Team plan prepared for {plan['technique_id']} without execution.",
                findings=[
                    {
                        "hypothesis": f"Atomic Red Team technique {plan['technique_id']} is queued for validation.",
                        "path": plan["request"].target,
                        "provenance": "atomic_red_team:plan",
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
                timeout=int(request.budget.get("timeout", 180)),
            )
        )
        return self.normalize_results({"technique_id": plan["technique_id"], "request": request, "run": run.to_dict()})

    def normalize_results(self, raw_output) -> AdapterResult:
        run = raw_output["run"]
        request = raw_output["request"]
        return AdapterResult(
            adapter=self.name,
            success=run["success"],
            summary=f"Atomic Red Team {raw_output['technique_id']} execution completed.",
            findings=[
                {
                    "hypothesis": f"Atomic Red Team technique {raw_output['technique_id']} produced execution evidence.",
                    "path": request.target,
                    "provenance": "atomic_red_team:execute",
                    "status": "confirmed" if run["success"] else "hypothesis",
                    "confidence": 0.7 if run["success"] else 0.35,
                    "evidence": [(run["stdout"] + "\n" + run["stderr"]).strip()[:4000]],
                    "asset_type": request.asset_type,
                }
            ],
            artifacts=[run["artifact_dir"]],
            raw=run,
        )

    @staticmethod
    def _build_command(
        technique_id: str,
        test_numbers: list[int] | None = None,
        check_prereqs: bool = False,
        get_prereqs: bool = False,
        cleanup: bool = False,
    ) -> list[str]:
        parts = [f"Invoke-AtomicTest {technique_id}"]
        if test_numbers:
            joined = ",".join(str(number) for number in test_numbers)
            parts.append(f"-TestNumbers {joined}")
        if check_prereqs:
            parts.append("-CheckPrereqs")
        if get_prereqs:
            parts.append("-GetPrereqs")
        if cleanup:
            parts.append("-Cleanup")
        return ["pwsh", "-NoProfile", "-Command", " ".join(parts)]
