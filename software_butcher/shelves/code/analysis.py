"""Local source-code analysis adapter."""

from __future__ import annotations

from pathlib import Path

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult


class CodeAnalysisAdapter:
    name = "code_analysis"
    capabilities = (
        AdapterCapability(
            name="source_static_analysis",
            description="Run static analysis and identify deeper code-level hypotheses.",
            asset_types=("source_repo",),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict:
        return {"adapter": self.name, "request": request}

    def execute(self, plan: dict) -> AdapterResult:
        request = plan["request"]
        root = Path(request.target)
        if not root.exists() or not root.is_dir():
            return AdapterResult(adapter=self.name, success=False, summary=f"Source path is not a directory: {root}", raw={"plan": str(plan)})

        risky = self._scan_risky_patterns(root)
        findings = []
        if risky:
            findings.append(
                {
                    "hypothesis": "Source repository contains risky code patterns requiring review.",
                    "path": str(root),
                    "provenance": "code_analysis:risky_patterns",
                    "status": "hypothesis",
                    "confidence": 0.45,
                    "evidence": risky[:50],
                    "asset_type": "source_repo",
                    "metadata": {"match_count": len(risky)},
                }
            )

        return AdapterResult(
            adapter=self.name,
            success=True,
            summary=f"Code analysis completed with {len(risky)} risky pattern match(es).",
            findings=findings,
            raw={"matches": risky},
        )

    def normalize_results(self, raw_output) -> AdapterResult:
        return AdapterResult(adapter=self.name, success=True, summary="Normalized code analysis output.", raw=raw_output)

    @staticmethod
    def _scan_risky_patterns(root: Path) -> list[str]:
        patterns = ("eval(", "exec(", "pickle.loads", "subprocess", "shell=True", "strcpy", "memcpy", "gets(")
        matches: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".ts", ".c", ".cpp", ".h", ".hpp", ".go", ".rs"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lowered = text.lower()
            for pattern in patterns:
                if pattern.lower() in lowered:
                    matches.append(f"{path}: contains {pattern}")
        return matches
