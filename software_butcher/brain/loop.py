from __future__ import annotations

import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

from software_butcher.brain.context import build_brain_context
from software_butcher.brain.prompts import BRAIN_CAPABILITY_PROMPT
from software_butcher.brain.guards import LoopGuard
from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.brain.llm_advisor import OpenRouterAdvisor
from software_butcher.brain.policy import BrainPolicy, PolicyDecision
from software_butcher.core.adapter import AdapterRequest
from software_butcher.core.assets import Asset
from software_butcher.core.registry import DEFAULT_REGISTRY, AdapterRegistry, Registry, default_registry
from software_butcher.core.router import AssetRouter, RouteDecision
from software_butcher.core.runner import SafeRunner
from software_butcher.core.scope import Scope
from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.state.recon_checklist import HOST_LEVEL_RECON_CAPABILITIES
from software_butcher.shelves.hexstrike.client import HexstrikeServerUnavailableError
from software_butcher.state.path_graph import parent_path as compute_parent_path
from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore

# Re-export for tests that import BRAIN_SYSTEM_PROMPT
BRAIN_SYSTEM_PROMPT = BRAIN_CAPABILITY_PROMPT

# Mapping from intent to default adapter used when hypothesis metadata overrides policy
_INTENT_ADAPTER_MAP: dict[str, str] = {
    # Discovery
    "web_behavior_analysis": "playwright_curl",
    "fingerprint": "hexstrike",
    "discover": "hexstrike",
    "continue_discovery": "hexstrike",
    "enrich": "hexstrike",
    "authenticated_discovery": "hexstrike",
    # Binary
    "reverse_engineer": "binary_triage",
    "binary_analysis": "hexstrike",
    # Frameworks
    "validate_ad_emulation": "caldera",
    "validate_cloud_attack_path": "stratus_red_team",
    "cve_lookup": "hexstrike",
    "deep_fuzz": "boaz",
    "deploy_c2": "sliver",
    # NEW: All capabilities route to hexstrike (server endpoints)
    "port_scanning": "hexstrike",
    "vulnerability_scanning": "hexstrike",
    "sql_injection_probing": "hexstrike",
    "directory_bruteforce": "hexstrike",
    "xss_scanning": "hexstrike",
    "cms_scanning": "hexstrike",
    "credential_attack": "hexstrike",
    "api_fuzzing": "hexstrike",
    "api_enumeration": "hexstrike",
    "cloud_security_audit": "hexstrike",
    "container_security": "hexstrike",
    "iac_scanning": "hexstrike",
    "ad_enumeration": "hexstrike",
    "exploit_generation": "hexstrike",
    "shell_command_execution": "hexstrike",
    "ai_attack_chain": "hexstrike",
    "technology_fingerprint": "hexstrike",
    "bugbounty_recon": "hexstrike",
    "bugbounty_comprehensive": "hexstrike",
    "payload_evasion": "boaz",
    "oss_fuzzing": "boaz",
    "source_static_analysis": "code_analysis",
    "continuous_fuzzing": "oss_fuzz",
}


def _asset_from_hypothesis(hypothesis, fallback_asset: Asset | None = None) -> Asset:
    asset_type = hypothesis.metadata.get("asset_type", "unknown") if hypothesis.metadata else "unknown"
    if fallback_asset and fallback_asset.locator == hypothesis.path:
        return Asset(
            locator=fallback_asset.locator,
            asset_type=fallback_asset.asset_type if fallback_asset.asset_type != "unknown" else asset_type,
            parent=fallback_asset.parent,
            metadata={**fallback_asset.metadata, **(hypothesis.metadata or {})},
        )
    return Asset(locator=hypothesis.path, asset_type=asset_type, metadata=hypothesis.metadata or {})


def _route_for_decision(decision, router: AssetRouter) -> RouteDecision:
    route = router.route(decision.asset, intent=decision.intent)
    return RouteDecision(
        shelf=route.shelf,
        adapter=decision.preferred_adapter,
        reason=decision.reason,
    )


def _apply_recon_gate(
    store: FindingStore,
    hypothesis,
    decision: PolicyDecision,
    explicit_intent: str | None,
) -> PolicyDecision:
    """Block exploit scanners until per-host recon completes on the base URL."""
    if decision.asset.asset_type not in {"web_endpoint", "api", "domain", "unknown"}:
        return decision

    host = host_key(hypothesis.path)
    if store.recon_checklist.is_complete(host):
        return decision

    missing = store.recon_checklist.next_missing(host)
    if not missing:
        return decision

    chosen = str((decision.options or {}).get("capability") or decision.intent or explicit_intent or "")
    recon_base = base_web_url(store.base_target or hypothesis.path).rstrip("/")

    if missing in HOST_LEVEL_RECON_CAPABILITIES:
        if hypothesis.path.rstrip("/").lower() != recon_base.lower():
            sys.stderr.write(
                f"[Brain] Recon gate on {host}: running {missing} on {recon_base} "
                f"(not {hypothesis.path})\n"
            )
            hypothesis.path = recon_base
            preferred = _INTENT_ADAPTER_MAP.get(missing, "hexstrike")
            return PolicyDecision(
                intent=missing,
                asset=Asset(
                    locator=recon_base,
                    asset_type=decision.asset.asset_type,
                    parent=decision.asset.parent,
                    metadata=decision.asset.metadata,
                ),
                preferred_adapter=preferred,
                reason=f"Host-level recon step {missing} runs on base target before path-specific work.",
                options={"capability": missing},
            )

    if chosen == missing or explicit_intent == missing:
        return decision

    preferred = _INTENT_ADAPTER_MAP.get(missing, "hexstrike")
    sys.stderr.write(
        f"[Brain] Recon gate on {host}: forcing {missing} before {chosen or 'exploit scanning'}\n"
    )
    hypothesis.path = recon_base
    return PolicyDecision(
        intent=missing,
        asset=Asset(
            locator=recon_base,
            asset_type=decision.asset.asset_type,
            parent=decision.asset.parent,
            metadata=decision.asset.metadata,
        ),
        preferred_adapter=preferred,
        reason=f"Recon checklist incomplete for {host}; run {missing} before {chosen or 'exploit scanning'}.",
        options={"capability": missing},
    )


def _findings_from_adapter_result(
    result,
    hypothesis,
    parent_path_value: str | None,
    default_asset_type: str,
    branch_id: str | None = None,
    capability: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for item in result.findings:
        item_meta = dict(item.get("metadata", {}))
        if capability and "capability" not in item_meta and "capability" not in item:
            item_meta["capability"] = capability
        if item.get("capability"):
            item_meta["capability"] = item["capability"]
        if branch_id:
            item_meta["branch_id"] = branch_id
        findings.append(
            Finding(
                hypothesis=item.get("hypothesis", hypothesis.reason),
                path=item.get("path", hypothesis.path),
                provenance=item.get("provenance", result.adapter),
                status=item.get("status", "hypothesis"),
                evidence=item.get("evidence", []),
                confidence=float(item.get("confidence", 0.5 if result.success else 0.3)),
                parent_path=item.get("parent_path") or parent_path_value,
                asset_type=item.get("asset_type", default_asset_type),
                metadata=item_meta,
            )
        )

    if not findings:
        meta: dict[str, Any] = {}
        if capability:
            meta["capability"] = capability
        if branch_id:
            meta["branch_id"] = branch_id
        findings.append(
            Finding(
                hypothesis=hypothesis.reason,
                path=hypothesis.path,
                provenance=result.adapter,
                status="hypothesis",
                evidence=[result.summary],
                confidence=0.5 if result.success else 0.3,
                parent_path=parent_path_value,
                asset_type=default_asset_type,
                metadata=meta,
            )
        )
    return findings


def _ingest_finding(
    store: FindingStore,
    finding: Finding,
    branch_id: str | None,
    on_finding_ingested: Any | None,
) -> bool:
    """Ingest a finding and notify optional asset-expansion callback."""
    if not store.ingest_finding(finding, branch_id=branch_id):
        return False
    if on_finding_ingested is not None:
        on_finding_ingested(finding)
    return True


def _run_legacy_tool(
    store: FindingStore,
    hypothesis,
    registry: Registry,
    runner: SafeRunner | None,
    parent_path_value: str | None,
    default_asset_type: str,
    branch_id: str | None = None,
    on_finding_ingested: Any | None = None,
) -> Finding | None:
    tool_spec = None
    preferred = hypothesis.metadata.get("tool") if hypothesis.metadata else None
    if preferred:
        tool_spec = registry.get_tool(preferred)

    if not tool_spec:
        for candidate in registry.tools.values():
            tool_spec = candidate
            break

    adapter_cls = registry.get_adapter(tool_spec.adapter) if tool_spec else None
    adapter = adapter_cls(runner or SafeRunner()) if adapter_cls else None
    command = tool_spec.command if tool_spec and tool_spec.command else ["echo", f"run:{hypothesis.path}"]

    if adapter:
        raw = adapter.execute(command)
    else:
        raw = SafeRunner().run(command)

    finding = Finding(
        hypothesis=hypothesis.reason,
        path=hypothesis.path,
        provenance=(tool_spec.name if tool_spec else "runner"),
        evidence=[raw.get("stdout", ""), raw.get("stderr", "")],
        confidence=0.8 if raw.get("returncode", 1) == 0 else 0.3,
        parent_path=parent_path_value,
        asset_type=default_asset_type,
    )
    _ingest_finding(store, finding, branch_id, on_finding_ingested)
    return finding


def run_brain_once(
    store: FindingStore,
    registry: AdapterRegistry | Registry | None = None,
    runner: Optional[SafeRunner] = None,
    scope: Scope | None = None,
    policy: BrainPolicy | None = None,
    hypothesis_generator: HypothesisGenerator | None = None,
    router: AssetRouter | None = None,
    asset: Asset | None = None,
    advisor: OpenRouterAdvisor | None = None,
    llm_client: Any | None = None,
    branch_id: str | None = None,
    on_finding_ingested: Any | None = None,
) -> Optional[Finding]:
    """Run a single Brain iteration: pop hypothesis, route, execute, write findings."""
    # ── LLM advisor: optionally reorder the queue before popping ──────────
    hypothesis = None
    if advisor is not None and advisor.enabled:
        pending = store.queue.pending_list()
        chosen_id = advisor.select_hypothesis_id(pending, list(store.findings.values()))
        if chosen_id:
            hypothesis = store.queue.next_by_id(chosen_id)
    if hypothesis is None:
        hypothesis = store.queue.next()
    if not hypothesis:
        return None

    policy = policy or BrainPolicy()
    hypothesis_generator = hypothesis_generator or HypothesisGenerator()
    router = router or AssetRouter()
    parent_path_value = compute_parent_path(hypothesis.path)
    asset_for_policy = _asset_from_hypothesis(hypothesis, asset)

    # ── Bug 2 fix: honour explicit intent from hypothesis metadata ─────────────
    # When HypothesisGenerator embeds an intent (e.g. "web_behavior_analysis"),
    # use it directly instead of running the global-evidence policy check, which
    # would incorrectly route all paths to playwright once "login" appears anywhere
    # in the finding store.
    explicit_intent = hypothesis.metadata.get("intent") if hypothesis.metadata else None

    # LLM-DRIVEN REASONING (Phase 2) — OpenRouter capability selector
    decision = None
    llm_disabled = getattr(store, "_llm_connectivity_failed", False)
    if llm_client is not None and isinstance(registry, AdapterRegistry) and not llm_disabled:
        context = build_brain_context(
            list(store.findings.values()),
            store.engagement,
            store.clusters,
            store.session_store,
        )
        phase = store.engagement.phase
        pcs_mode = "validation" if store.pcs.state.validation_mode else "exploration"

        sys.stderr.write(f"\n[Brain] Consulting external LLM for hypothesis: {hypothesis.path} (phase={phase}, pcs={pcs_mode})\n")

        try:
            model_name = os.environ.get("LLM_MODEL") or os.environ.get("OPENROUTER_MODEL") or "gpt-oss-120b"
            llm_response = llm_client.chat.completions.create(
                model=model_name,
                messages=[{
                    "role": "system",
                    "content": BRAIN_CAPABILITY_PROMPT
                }, {
                    "role": "user",
                    "content": (
                        f"{context}\n\n"
                        f"PCS mode: {pcs_mode}\n"
                        f"Current hypothesis:\n"
                        f"- Path: {hypothesis.path}\n"
                        f"- Reason: {hypothesis.reason}\n"
                        f"- Intent: {explicit_intent or 'discover'}\n"
                        f"- Branch: {branch_id or 'primary'}\n\n"
                        "What capability maximizes information gain for this hypothesis?"
                    ),
                }],
                response_format={"type": "json_object"},
                max_tokens=768,
            )
            
            content = llm_response.choices[0].message.content
            llm_decision = json.loads(content) if content else {}
            capability = llm_decision.get("capability")
            sys.stderr.write(f"[Brain] LLM chose capability: {capability} (Reasoning: {llm_decision.get('reasoning')})\n")
            
            # Find the adapter that owns this capability
            adapter = registry.find_by_capability(capability or "")
            if not adapter:
                sys.stderr.write(f"[Brain] Capability '{capability}' not found in registry. Falling back to hexstrike.\n")
                adapter = registry.get("hexstrike")
                
            decision = PolicyDecision(
                intent=capability or explicit_intent or "discover",
                asset=asset_for_policy,
                preferred_adapter=adapter.name if adapter else "hexstrike",
                reason=llm_decision.get("reasoning", "LLM reasoning"),
                options={"capability": capability} if capability else {},
            )
        except Exception as exc:
            # LLM failure should never crash the Brain loop — fall through
            # to deterministic policy
            store._llm_connectivity_failed = True
            sys.stderr.write(
                f"[Brain] LLM call failed: {exc}. "
                f"Policy-only mode for rest of run. "
                f"Diagnose: python3 -m software_butcher llm-doctor\n"
            )
            decision = None

    if decision is None and explicit_intent:
        preferred = (
            hypothesis.metadata.get("preferred_adapter")
            or _INTENT_ADAPTER_MAP.get(explicit_intent, "hexstrike")
        )
        decision = PolicyDecision(
            intent=explicit_intent,
            asset=asset_for_policy,
            preferred_adapter=preferred,
            reason=f"Hypothesis metadata intent override: {explicit_intent}",
            options={"capability": explicit_intent} if explicit_intent in _INTENT_ADAPTER_MAP else {},
        )
    elif decision is None:
        decision = policy.decide(asset_for_policy, list(store.findings.values()))

    decision = _apply_recon_gate(store, hypothesis, decision, explicit_intent)

    route = _route_for_decision(decision, router)

    tool_limit = scope.max_tool_calls if scope else 50
    if not store.can_run_tool(tool_limit):
        budget_finding = Finding(
            hypothesis=hypothesis.reason,
            path=hypothesis.path,
            provenance="brain:tool_budget",
            status="hypothesis",
            evidence=[f"Scope tool-call budget exhausted ({store.tool_calls}/{tool_limit})."],
            confidence=0.1,
            parent_path=parent_path_value,
            asset_type=decision.asset.asset_type,
        )
        store.ingest_finding(budget_finding, branch_id=branch_id)
        if on_finding_ingested is not None:
            on_finding_ingested(budget_finding)
        store.queue.complete(hypothesis.id)
        store.save_or_log()
        return budget_finding

    primary_finding: Finding | None = None
    adapter_registry = registry if isinstance(registry, AdapterRegistry) else None
    legacy_registry = registry if isinstance(registry, Registry) else (DEFAULT_REGISTRY if registry is None else None)

    adapter = adapter_registry.get(route.adapter) if adapter_registry else None
    if adapter is None and adapter_registry is not None:
        adapter = adapter_registry.get("hexstrike")
    if adapter is not None and hasattr(adapter, "plan"):
        scope_payload = scope.to_dict() if scope else {}
        adapter_options = dict(decision.options)
        if hypothesis.metadata:
            for key in ("technology", "cve_id", "authenticated"):
                if key in hypothesis.metadata:
                    adapter_options[key] = hypothesis.metadata[key]
        adapter_options["session_store"] = store.session_store
        request = AdapterRequest(
            objective=decision.intent,
            target=hypothesis.path,
            asset_type=decision.asset.asset_type,
            scope=scope_payload,
            options=adapter_options,
        )
        try:
            plan = adapter.plan(request)
            if not store.record_tool_call(tool_limit):
                store.queue.complete(hypothesis.id)
                store.save_or_log()
                return None
            result = adapter.execute(plan)
        except HexstrikeServerUnavailableError as exc:
            # Server is down — record a finding so the run doesn't crash and
            # the user knows why no results were produced for this hypothesis.
            error_finding = Finding(
                hypothesis=hypothesis.reason,
                path=hypothesis.path,
                provenance="hexstrike:unavailable",
                status="hypothesis",
                evidence=[f"HexStrike server unavailable: {exc}"],
                confidence=0.1,
                parent_path=parent_path_value,
                asset_type=decision.asset.asset_type,
            )
            _ingest_finding(store, error_finding, branch_id, on_finding_ingested)
            store.queue.complete(hypothesis.id)
            store.save_or_log()
            return error_finding
        for finding in _findings_from_adapter_result(
            result,
            hypothesis,
            parent_path_value,
            decision.asset.asset_type,
            branch_id=branch_id,
            capability=str((decision.options or {}).get("capability") or decision.intent or ""),
        ):
            if _ingest_finding(store, finding, branch_id, on_finding_ingested):
                for generated in hypothesis_generator.generate(finding):
                    store.add_hypothesis(generated)
                if primary_finding is None:
                    primary_finding = finding
    elif legacy_registry is not None:
        if not store.record_tool_call(tool_limit):
            store.queue.complete(hypothesis.id)
            store.save_or_log()
            return None
        primary_finding = _run_legacy_tool(
            store,
            hypothesis,
            legacy_registry,
            runner,
            parent_path_value,
            decision.asset.asset_type,
            branch_id=branch_id,
            on_finding_ingested=on_finding_ingested,
        )
        if primary_finding:
            for generated in hypothesis_generator.generate(primary_finding):
                store.add_hypothesis(generated)

    store.queue.complete(hypothesis.id)
    store.save_or_log()

    return primary_finding


def run_brain_loop(
    store: FindingStore,
    iterations: int = 100,
    registry: AdapterRegistry | Registry | None = None,
    runner: Optional[SafeRunner] = None,
    scope: Scope | None = None,
    policy: BrainPolicy | None = None,
    hypothesis_generator: HypothesisGenerator | None = None,
    router: AssetRouter | None = None,
    asset: Asset | None = None,
    llm_client: Any | None = None,
) -> int:
    """Run the Brain loop until the guard stops it or the queue is empty."""
    guard = LoopGuard(max_steps=iterations)
    produced = 0

    while guard.can_continue():
        before = len(store.findings)
        finding = run_brain_once(
            store,
            registry=registry,
            runner=runner,
            scope=scope,
            policy=policy,
            hypothesis_generator=hypothesis_generator,
            router=router,
            asset=asset,
            llm_client=llm_client,
        )
        if finding is None:
            break
        guard.record(len(store.findings) - before)
        produced += 1

    return produced


class BrainLoop:
    """Brain loop wrapper used by the CLI and tests."""

    def __init__(
        self,
        store: FindingStore,
        scope: Scope | None = None,
        registry: AdapterRegistry | Registry | None = None,
        max_steps: int = 25,
        no_new_limit: int = 5,
        max_branches: int = 5,
        adaptive_pcs: bool = True,
        runner: Optional[SafeRunner] = None,
        policy: BrainPolicy | None = None,
        hypothesis_generator: HypothesisGenerator | None = None,
        router: AssetRouter | None = None,
        llm_client: Any | None = None,
        advisor: OpenRouterAdvisor | None = None,
        on_finding_ingested: Any | None = None,
    ) -> None:
        self.store = store
        self.scope = scope
        self.registry = registry or default_registry()
        self.max_steps = max_steps
        self.no_new_limit = no_new_limit
        self.max_branches = max(1, max_branches)
        self.adaptive_pcs = adaptive_pcs
        self.runner = runner
        self.policy = policy or BrainPolicy()
        self.hypothesis_generator = hypothesis_generator or HypothesisGenerator()
        self.router = router or AssetRouter()
        self.llm_client = llm_client
        self.advisor = advisor
        self.on_finding_ingested = on_finding_ingested

    def run_once(self, asset: Asset | None = None, branch_id: str | None = None) -> dict[str, Any]:
        before = len(self.store.findings)
        branch_id = branch_id or self.store.new_branch_id()
        finding = run_brain_once(
            self.store,
            registry=self.registry,
            runner=self.runner,
            scope=self.scope,
            policy=self.policy,
            hypothesis_generator=self.hypothesis_generator,
            router=self.router,
            asset=asset,
            advisor=self.advisor,
            llm_client=self.llm_client,
            branch_id=branch_id,
            on_finding_ingested=self.on_finding_ingested,
        )
        if finding is None:
            pending = [item for item in self.store.queue.to_list() if item["status"] == "pending"]
            if pending:
                return {"status": "skipped", "reason": "no finding produced; pending hypotheses remain", "branch_id": branch_id}
            return {"status": "idle", "reason": "hypothesis queue empty", "branch_id": branch_id}

        return {
            "status": "executed",
            "finding": finding.to_dict(),
            "new_findings": len(self.store.findings) - before,
            "branch_id": branch_id,
            "phase": self.store.engagement.phase,
            "convergence_score": finding.convergence_score,
        }

    def run(self, asset: Asset | None = None) -> list[dict[str, Any]]:
        guard = LoopGuard(max_steps=self.max_steps, no_new_limit=self.no_new_limit)
        events: list[dict[str, Any]] = []
        tool_limit = self.scope.max_tool_calls if self.scope else 50
        wave_new_findings: list[Finding] = []

        while guard.can_continue():
            if not self.store.can_run_tool(tool_limit):
                events.append({
                    "status": "budget_exhausted",
                    "reason": f"Scope tool-call budget exhausted ({self.store.tool_calls}/{tool_limit})",
                })
                break

            before_ids = set(self.store.findings.keys())
            wave_events: list[dict[str, Any]] = []

            if self.adaptive_pcs:
                recon_host = host_key((asset.locator if asset else "") or self.store.base_target)
                recon_ok = self.store.recon_complete_for(recon_host) if recon_host else True
                branch_count, pcs_reason = self.store.pcs.branches_for_step(
                    self.store.clusters,
                    wave_new_findings,
                    recon_complete=recon_ok,
                )
                branch_count = min(branch_count, self.max_branches)
            else:
                branch_count, pcs_reason = self.max_branches, "fixed_branch_count"

            sys.stderr.write(f"[PCS] step branches={branch_count} reason={pcs_reason}\n")

            if branch_count <= 1:
                wave_events.append(self.run_once(asset=asset))
            else:
                with ThreadPoolExecutor(max_workers=branch_count) as pool:
                    futures = [
                        pool.submit(self.run_once, asset=asset, branch_id=self.store.new_branch_id())
                        for _ in range(branch_count)
                    ]
                    for future in as_completed(futures):
                        wave_events.append(future.result())

            events.append({"status": "pcs_step", "branches": branch_count, "reason": pcs_reason})
            events.extend(wave_events)

            if all(event.get("status") == "idle" for event in wave_events):
                break

            new_ids = set(self.store.findings.keys()) - before_ids
            wave_new_findings = [self.store.findings[fid] for fid in new_ids if fid in self.store.findings]
            new_in_wave = len(new_ids)

            if all(event.get("status") == "skipped" for event in wave_events):
                guard.record(0)
            else:
                guard.record(new_in_wave)

            self.store.recompute_state()
            self.store.save_or_log()

        return events
