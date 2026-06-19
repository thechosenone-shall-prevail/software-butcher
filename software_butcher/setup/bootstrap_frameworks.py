"""Optional bootstrapper for external open-source frameworks.

This script keeps third-party framework repositories out of Software Butcher's
git history. By default it prints the clone/install plan. Use --execute to run.
"""

from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BootstrapTarget:
    name: str
    repo: str
    path: str
    post_clone: tuple[list[str], ...] = ()


TARGETS = {
    "atomic_red_team": BootstrapTarget(
        name="atomic_red_team",
        repo="https://github.com/redcanaryco/atomic-red-team.git",
        path="external_tools/atomic-red-team",
    ),
    "caldera": BootstrapTarget(
        name="caldera",
        repo="https://github.com/apache/caldera.git",
        path="external_tools/caldera",
        post_clone=(["python", "-m", "pip", "install", "-r", "requirements.txt"],),
    ),
    "stratus_red_team": BootstrapTarget(
        name="stratus_red_team",
        repo="https://github.com/DataDog/stratus-red-team.git",
        path="external_tools/stratus-red-team",
    ),
}


def build_plan(names: list[str] | None = None) -> list[BootstrapTarget]:
    selected = names or sorted(TARGETS)
    return [TARGETS[name] for name in selected]


def clone_target(target: BootstrapTarget, root: Path) -> None:
    destination = root / target.path
    if destination.exists():
        print(f"[skip] {target.name}: {destination} already exists")
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--depth", "1", target.repo, str(destination)], check=True)

    for command in target.post_clone:
        subprocess.run(command, cwd=destination, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap optional external frameworks")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--target", action="append", choices=sorted(TARGETS), help="Specific target to bootstrap")
    parser.add_argument("--execute", action="store_true", help="Run clone/install commands")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    plan = build_plan(args.target)

    for target in plan:
        print(f"{target.name}: {target.repo} -> {root / target.path}")
        for command in target.post_clone:
            print(f"  post-clone: {' '.join(command)}")

    if args.execute:
        for target in plan:
            clone_target(target, root)


if __name__ == "__main__":
    main()
