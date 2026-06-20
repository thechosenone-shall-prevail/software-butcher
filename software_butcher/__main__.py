"""Software Butcher command-line entrypoint."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path

from software_butcher.brain.loop import BrainLoop
from software_butcher.brain.llm_advisor import OpenRouterAdvisor
from software_butcher.core.classifier import classify_target
from software_butcher.core.framework_config import FrameworkConfigSet
from software_butcher.core.health import FrameworkHealth
from software_butcher.core.llm import create_openrouter_client
from software_butcher.core.scope import Scope
from software_butcher.project import ButcherProject
from software_butcher.state.store import FindingStore
from software_butcher.synthesis import Synthesizer


def _load_dotenv(path: Path | None = None) -> None:
    env_path = path or Path(".env")
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip())


def main() -> None:
    parser = argparse.ArgumentParser(prog="software_butcher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local framework availability")
    doctor_parser.add_argument("--config", help="Optional JSON framework config path")
    doctor_parser.add_argument("--json", action="store_true", help="Emit JSON output")

    init_parser = subparsers.add_parser("init-config", help="Write a default framework config")
    init_parser.add_argument("path", help="Destination JSON path")

    init_scope_parser = subparsers.add_parser("init-scope", help="Write a minimal scope file for a target")
    init_scope_parser.add_argument("path", help="Destination JSON path")
    init_scope_parser.add_argument("--name", default="local-assessment")
    init_scope_parser.add_argument("--domain", action="append", default=[])
    init_scope_parser.add_argument("--cidr", action="append", default=[])
    init_scope_parser.add_argument("--url", action="append", default=[])
    init_scope_parser.add_argument("--file", action="append", default=[])

    bootstrap_parser = subparsers.add_parser("bootstrap-frameworks", help="Print or run external framework clone plan")
    bootstrap_parser.add_argument("--target", action="append", choices=["atomic_red_team", "caldera", "stratus_red_team"])
    bootstrap_parser.add_argument("--execute", action="store_true")

    run_parser = subparsers.add_parser("run", help="Run a bounded Software Butcher pass")
    run_parser.add_argument("--scope", required=True, help="Scope JSON path (flat or comprehensive)")
    run_parser.add_argument("--target", required=True, help="Target locator")
    run_parser.add_argument("--workspace", default="software_butcher/workspaces/default")
    run_parser.add_argument("--steps", type=int, default=25, help="Brain loop step budget (default: 25)")
    run_parser.add_argument("--max-branches", type=int, default=5, help="PCS branch ceiling (default: 5)")
    run_parser.add_argument("--no-adaptive-pcs", action="store_true", help="Disable PCS; always run max-branches per step")
    run_parser.add_argument("--no-new-limit", type=int, default=5, help="Stop after N consecutive steps with no new findings")
    run_parser.add_argument("--fresh", action="store_true", help="Ignore existing workspace state and start a new run")
    run_parser.add_argument("--json", action="store_true")

    synth_parser = subparsers.add_parser("synthesize", help="Generate a cited technical verdict from finding state")
    synth_parser.add_argument("--state", required=True, help="Path to finding_state.json")
    synth_parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.command == "doctor":
        configs = FrameworkConfigSet.load(args.config)
        statuses = FrameworkHealth(configs).check_all()
        payload = {name: status.to_dict() for name, status in statuses.items()}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for name, status in payload.items():
                marker = "OK" if status["available"] else "MISS"
                print(f"[{marker}] {name}: {status['detail']}")
        return

    if args.command == "init-config":
        path = Path(args.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"frameworks": FrameworkConfigSet().to_dict()}, indent=2), encoding="utf-8")
        print(f"Wrote {path}")
        return

    if args.command == "init-scope":
        scope = Scope(
            name=args.name,
            allowed_domains=args.domain,
            allowed_cidrs=args.cidr,
            allowed_urls=args.url,
            allowed_files=args.file,
        )
        scope.save(args.path)
        print(f"Wrote {args.path}")
        return

    if args.command == "run":
        _load_dotenv()

        scope = Scope.load(args.scope)
        asset = classify_target(args.target)
        project = ButcherProject(args.workspace, scope, resume=not args.fresh)
        project.add_asset(asset)
        if project.resumed:
            if not project.findings.base_target:
                project.findings.set_base_target(asset.locator)
        else:
            project.seed_asset(asset)

        health = FrameworkHealth()
        llm_client = create_openrouter_client()
        advisor = OpenRouterAdvisor()

        brain = BrainLoop(
            project.findings,
            scope=scope,
            max_steps=args.steps,
            no_new_limit=args.no_new_limit,
            max_branches=args.max_branches,
            adaptive_pcs=not args.no_adaptive_pcs,
            llm_client=llm_client,
            advisor=advisor,
            on_finding_ingested=project.process_finding,
        )
        events = brain.run(asset)
        project.save()

        report = Synthesizer().synthesize(
            project.findings,
            llm_client=llm_client,
            inventory=project.inventory,
        )

        payload = {
            "asset": asset.to_dict(),
            "assets": project.inventory.to_list(),
            "resumed": project.resumed,
            "workspace": str(Path(args.workspace)),
            "framework_health": {name: status.to_dict() for name, status in health.check_all().items()},
            "events": [_jsonable(event) for event in events],
            "state": project.findings.snapshot(),
            "verdict": report.to_dict(),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Asset: {asset.asset_type} {asset.locator}")
            for event in payload["events"]:
                print(f"Event: {event['status']}")
            print(f"State written to {Path(args.workspace) / 'finding_state.json'}")
            print(f"Verdict: {report.verdict.name} — {report.verdict.summary}")
        return

    if args.command == "bootstrap-frameworks":
        from software_butcher.setup.bootstrap_frameworks import build_plan, clone_target

        plan = build_plan(args.target)
        for target in plan:
            print(f"{target.name}: {target.repo} -> {Path(target.path).resolve()}")
        if args.execute:
            for target in plan:
                clone_target(target, Path(".").resolve())
        return

    if args.command == "synthesize":
        _load_dotenv()
        store = FindingStore.load(args.state)
        llm_client = create_openrouter_client()
        report = Synthesizer().synthesize(store, llm_client=llm_client)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_markdown())
        return


def _jsonable(value):
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


if __name__ == "__main__":
    main()
