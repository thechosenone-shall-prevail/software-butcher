"""Acquire upstream source trees into the assessment workspace."""

from __future__ import annotations

import subprocess
from pathlib import Path

from software_butcher.core.runner import SafeRunner
from software_butcher.core.source_resolver import SourceReference


class SourceAcquisition:
    """Clone or prepare local source checkouts for static analysis."""

    def __init__(self, runner: SafeRunner | None = None) -> None:
        self.runner = runner or SafeRunner()

    def prepare(
        self,
        reference: SourceReference,
        workspace_root: str | Path,
    ) -> Path | None:
        """Ensure upstream source exists under workspace/sources/ and return its path."""
        root = Path(workspace_root)
        sources_dir = root / "sources"
        sources_dir.mkdir(parents=True, exist_ok=True)
        target = sources_dir / reference.local_dir_name

        if target.exists() and any(target.iterdir()):
            return target

        clone_cmd = ["git", "clone", "--depth", "1", reference.repo_url, str(target)]
        if reference.branch:
            clone_cmd = [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                reference.branch,
                reference.repo_url,
                str(target),
            ]

        result = self.runner.run(clone_cmd, timeout=120)
        if result.get("returncode", 1) == 0 and target.exists():
            return target

        # Fallback: shallow clone default branch if version branch missing.
        if reference.branch:
            fallback = self.runner.run(
                ["git", "clone", "--depth", "1", reference.repo_url, str(target)],
                timeout=120,
            )
            if fallback.get("returncode", 1) == 0 and target.exists():
                return target

        return None
