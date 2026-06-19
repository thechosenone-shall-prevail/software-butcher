"""OSS-Fuzz / ClusterFuzzLite planning adapter."""

from __future__ import annotations

from pathlib import Path

from software_butcher.core.adapter import AdapterCapability, AdapterRequest, AdapterResult


class OssFuzzAdapter:
    name = "oss_fuzz"
    capabilities = (
        AdapterCapability(
            name="continuous_fuzzing",
            description="Build fuzz targets, run fuzzers, and normalize crash artifacts.",
            asset_types=("source_repo", "binary"),
        ),
    )

    def plan(self, request: AdapterRequest) -> dict:
        project_name = request.options.get("project_name") or Path(request.target).name
        return {
            "adapter": self.name,
            "request": request,
            "project_name": project_name,
            "required_files": ["project.yaml", "Dockerfile", "build.sh"],
        }

    def execute(self, plan: dict) -> AdapterResult:
        request = plan["request"]
        root = Path(request.target)
        if not root.exists() or not root.is_dir():
            return AdapterResult(adapter=self.name, success=False, summary=f"Fuzz target path is not a directory: {root}", raw={"plan": str(plan)})

        present = [name for name in plan["required_files"] if (root / name).exists()]
        missing = [name for name in plan["required_files"] if name not in present]
        finding = {
            "hypothesis": "Repository is ready for OSS-Fuzz-style local validation." if not missing else "Repository needs OSS-Fuzz harness files before continuous fuzzing.",
            "path": str(root),
            "provenance": "oss_fuzz:plan",
            "status": "hypothesis",
            "confidence": 0.55 if not missing else 0.35,
            "evidence": [f"present={present}", f"missing={missing}"],
            "asset_type": "source_repo",
            "metadata": {"present": present, "missing": missing, "project_name": plan["project_name"]},
        }
        return AdapterResult(
            adapter=self.name,
            success=True,
            summary="OSS-Fuzz readiness check completed.",
            findings=[finding],
            raw={"present": present, "missing": missing},
        )

    def normalize_results(self, raw_output) -> AdapterResult:
        return AdapterResult(adapter=self.name, success=True, summary="Normalized fuzzing output.", raw=raw_output)
