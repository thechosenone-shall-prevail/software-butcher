from __future__ import annotations

import datetime
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from software_butcher.core.scope import Scope


class SafeRunner:
    """Run external commands safely using argument lists.

    - Accepts argv as a list (no shell=True)
    - Applies a timeout
    - Captures stdout/stderr and returns structured output
    """

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout

    def run(self, argv: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        if not isinstance(argv, list):
            raise TypeError("argv must be a list of command and args")

        to = timeout or self.timeout
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env, timeout=to, check=False, text=True)
            timed_out = False
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as e:
            timed_out = True
            returncode = 124
            stdout = e.stdout or ""
            stderr = e.stderr or ""

        end = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "argv": argv,
            "cwd": cwd,
            "start": start,
            "end": end,
            "returncode": returncode,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
        }


@dataclass
class RunRequest:
    """Scoped command execution request for shelf adapters."""

    command: list[str]
    target: str
    adapter: str
    scope: Scope
    timeout: int = 300
    cwd: str | None = None
    env: dict[str, str] | None = None


@dataclass
class ShelfRunResult:
    """Structured result from a scoped shelf command run."""

    success: bool
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    target: str
    adapter: str
    artifact_dir: str
    argv: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ShelfRunner:
    """Run shelf commands with scope checks and artifact capture."""

    def __init__(self, artifact_root: str | Path | None = None, default_timeout: int = 300) -> None:
        self.artifact_root = Path(artifact_root or "software_butcher/artifacts")
        self.default_timeout = default_timeout
        self._run_counter = 0

    def run(self, request: RunRequest) -> ShelfRunResult:
        scope = request.scope if isinstance(request.scope, Scope) else Scope(**request.scope)
        if not scope.allows(request.target):
            raise ValueError(f"Target outside scope: {request.target}")

        self._run_counter += 1
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        artifact_dir = self.artifact_root / request.adapter / f"{stamp}_{self._run_counter:04d}"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        timeout = request.timeout or self.default_timeout
        raw = SafeRunner(timeout=timeout).run(request.command, cwd=request.cwd, env=request.env, timeout=timeout)
        success = raw["returncode"] == 0 and not raw["timed_out"]

        (artifact_dir / "stdout.txt").write_text(raw["stdout"], encoding="utf-8")
        (artifact_dir / "stderr.txt").write_text(raw["stderr"], encoding="utf-8")
        payload = {
            **raw,
            "target": request.target,
            "adapter": request.adapter,
            "success": success,
            "artifact_dir": str(artifact_dir),
        }
        (artifact_dir / "result.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return ShelfRunResult(
            success=success,
            stdout=raw["stdout"],
            stderr=raw["stderr"],
            returncode=raw["returncode"],
            timed_out=raw["timed_out"],
            target=request.target,
            adapter=request.adapter,
            artifact_dir=str(artifact_dir),
            argv=raw["argv"],
        )
