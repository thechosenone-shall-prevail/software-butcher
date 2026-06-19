"""Binary triage adapter."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from software_butcher.core.runner import RunRequest, ShelfRunner
from software_butcher.core.scope import Scope


class BinaryTriageAdapter:
    name = "binary_triage"
    capabilities = (
        AdapterCapability(
            name="binary_triage",
            description="Fingerprint binaries and prepare reverse engineering or fuzzing hypotheses.",
            asset_types=("binary",),
        ),
    )

    def __init__(self, runner: ShelfRunner | None = None) -> None:
        self.runner = runner or ShelfRunner()

    def plan(self, request: AdapterRequest) -> dict:
        commands = [
            ["python", "-c", "import pathlib,sys; p=pathlib.Path(sys.argv[1]); print(f'name={p.name}'); print(f'size={p.stat().st_size}')", request.target],
            ["python", "-c", "import pathlib,sys; data=pathlib.Path(sys.argv[1]).read_bytes()[:8192]; print(data[:256])", request.target],
        ]
        return {"adapter": self.name, "request": request, "commands": commands}

    def execute(self, plan: dict) -> AdapterResult:
        request = plan["request"]
        scope = Scope(**request.scope)
        results = []

        for command in plan["commands"]:
            results.append(
                self.runner.run(
                    RunRequest(
                        command=command,
                        target=request.target,
                        adapter=self.name,
                        scope=scope,
                        timeout=int(request.budget.get("timeout", 30)),
                    )
                )
            )

        return self.normalize_results([result.to_dict() for result in results])

    def normalize_results(self, raw_output) -> AdapterResult:
        findings = []
        for result in raw_output:
            if result["success"]:
                findings.append(
                    {
                        "hypothesis": "Binary triage completed; reverse-engineering lane is available.",
                        "path": result["target"],
                        "provenance": self.name,
                        "status": "hypothesis",
                        "confidence": 0.35,
                        "evidence": [result["stdout"].strip()],
                        "asset_type": "binary",
                    }
                )

        target = raw_output[0]["target"] if raw_output else ""
        if target:
            findings.extend(self._local_binary_findings(target))

        return AdapterResult(
            adapter=self.name,
            success=all(result["success"] for result in raw_output),
            summary=f"Binary triage ran {len(raw_output)} command(s).",
            findings=findings,
            artifacts=[result["artifact_dir"] for result in raw_output],
            raw={"runs": raw_output},
        )

    def _local_binary_findings(self, target: str) -> list[dict]:
        path = Path(target)
        if not path.exists() or not path.is_file():
            return []

        data = path.read_bytes()
        evidence = [
            f"name={path.name}",
            f"size={len(data)}",
            f"entropy={self._entropy(data):.4f}",
            f"magic={data[:8].hex()}",
        ]

        risky = self._risky_strings(data)
        if risky:
            evidence.append(f"risky_strings={', '.join(risky[:20])}")

        confidence = 0.45 if risky else 0.35
        hypothesis = "Binary contains potentially risky memory/string handling indicators." if risky else "Binary metadata collected for reverse-engineering triage."
        return [
            {
                "hypothesis": hypothesis,
                "path": str(path),
                "provenance": "binary_triage:local",
                "status": "hypothesis",
                "confidence": confidence,
                "evidence": evidence,
                "asset_type": "binary",
                "metadata": {"risky_strings": risky},
            }
        ]

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        entropy = 0.0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _risky_strings(data: bytes) -> list[str]:
        haystack = data.decode("latin-1", errors="ignore").lower()
        needles = ("strcpy", "strcat", "sprintf", "gets", "memcpy", "scanf", "system(")
        return [needle for needle in needles if needle in haystack]
