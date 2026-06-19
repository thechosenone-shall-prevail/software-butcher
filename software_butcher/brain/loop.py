from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

from software_butcher.brain.context import build_brain_context
from software_butcher.brain.guards import LoopGuard
from software_butcher.brain.hypotheses import HypothesisGenerator
from software_butcher.brain.llm_advisor import DeepSeekAdvisor
from software_butcher.brain.policy import BrainPolicy, PolicyDecision
from software_butcher.core.adapter import AdapterRequest
from software_butcher.core.assets import Asset
from software_butcher.core.registry import DEFAULT_REGISTRY, AdapterRegistry, Registry, default_registry
from software_butcher.core.router import AssetRouter, RouteDecision
from software_butcher.core.runner import SafeRunner
from software_butcher.core.scope import Scope
from software_butcher.shelves.hexstrike.client import HexstrikeServerUnavailableError
from software_butcher.state.path_graph import parent_path as compute_parent_path
from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore

BRAIN_SYSTEM_PROMPT = """
You are the reasoning engine of Software Butcher, an autonomous security assessment platform
designed to compete with state-of-the-art AI pentesting systems like XBOW.

Your job: Read the current finding state and current hypothesis. Decide what 
capability (tool/technique) would maximize information gain on this hypothesis.

Available capabilities on the Shelf:

DISCOVERY & RECONNAISSANCE:
- endpoint_discovery: ffuf, gobuster, dirsearch for path enumeration
- port_scanning: nmap, masscan, rustscan for port/service discovery
- directory_bruteforce: gobuster, ffuf, feroxbuster for directory brute forcing
- technology_fingerprint: AI technology stack detection and fingerprinting
- authenticated_discovery: discovery as logged-in user with session cookies

WEB VULNERABILITY SCANNING:
- vulnerability_scanning: nuclei, nikto for known vulnerability detection
- sql_injection_probing: SQLMap for SQL injection detection and exploitation
- xss_scanning: XSS detection and payload testing
- cms_scanning: WPScan for CMS-specific vulnerability scanning (WordPress, Joomla, etc.)
- web_behavior_analysis: HTTP behavior, redirects, content-type analysis via browser

API SECURITY:
- api_enumeration: API endpoint discovery and parameter fuzzing
- api_fuzzing: API fuzzer, GraphQL scanner, JWT analyzer for API security testing

CREDENTIAL ATTACKS:
- credential_attack: Hydra brute force, hashcat/john password cracking

BINARY & REVERSE ENGINEERING:
- binary_analysis: GDB, radare2, ghidra, binwalk binary analysis via server
- binary_triage: entropy, strings, symbols analysis (local)

EXPLOIT & POST-EXPLOITATION:
- exploit_generation: Metasploit module selection, msfvenom payload generation
- oss_fuzzing: deep fuzzing via BOAZ/OSS-Fuzz
- payload_evasion: BOAZ evasive payload generation (77+ loaders, 12 encoders)
- c2_deployment: deploy Sliver C2 beacons for post-exploitation

CLOUD & CONTAINER:
- cloud_security_audit: Prowler, ScoutSuite, Trivy for cloud security auditing
- container_security: kube-hunter, docker-bench, Trivy for container scanning
- iac_scanning: Checkov, Terrascan for infrastructure-as-code scanning
- cloud_attack_simulation: Stratus Red Team controlled attack simulation

ADVERSARY EMULATION:
- adversary_emulation: CALDERA ATT&CK-based adversary operations
- ttp_validation: Atomic Red Team ATT&CK technique validation

AD / INTERNAL NETWORK:
- ad_enumeration: enum4linux, smbmap, netexec, responder for AD enumeration

AI-DRIVEN WORKFLOWS:
- ai_attack_chain: AI-powered attack chain discovery and orchestration
- bugbounty_recon: automated bug bounty reconnaissance workflow
- bugbounty_comprehensive: full automated bug bounty assessment

STRATEGY GUIDELINES:
1. Start with discovery/reconnaissance for unknown targets
2. Escalate to vulnerability scanning once endpoints are found
3. Use SQL injection, XSS, or API fuzzing when evidence suggests those surfaces
4. Use credential attacks when login forms or hashes are found
5. Use exploit generation when CVEs or known vulns are confirmed
6. Use cloud/container tools when cloud infrastructure is detected
7. Use AD enumeration when SMB/LDAP/Kerberos services are found
8. Prefer the capability that produces the HIGHEST confidence findings
9. Respect engagement phase: recon → exploit → foothold → privesc → exfil
10. In validation_mode (high convergence), prefer confirmation over new discovery

Respond ONLY as JSON:
{
  "capability": "capability_name",
  "reasoning": "why this maximizes information gain",
  "target_aspect": "what aspect of the target we're exploring"
}
"""

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
    "ai_attack_chain": "hexstrike",
    "technology_fingerprint": "hexstrike",
    "bugbounty_recon": "hexstrike",
    "bugbounty_comprehensive": "hexstrike",
    "payload_evasion": "boaz",
    "oss_fuzzing": "boaz",
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


def _findings_from_adapter_result(
    result,
    hypothesis,
    parent_path_value: str | None,
    default_asset_type: str,
    branch_id: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for item in result.findings:
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
                metadata={**item.get("metadata", {}), **({"capability": item["capability"]} if item.get("capability") else {}), **({"branch_id": branch_id} if branch_id else {})},
            )
        )

    if not findings:
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
            )
        )
    return findings


def _run_legacy_tool(
    store: FindingStore,
    hypothesis,
    registry: Registry,
    runner: SafeRunner | None,
    parent_path_value: str | None,
    default_asset_type: str,
    branch_id: str | None = None,
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
    store.ingest_finding(finding, branch_id=branch_id)
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
    advisor: DeepSeekAdvisor | None = None,
    llm_client: Any | None = None,
    branch_id: str | None = None,
) -> Optional[Finding]:
    """Run a single Brain iteration: pop hypothesis, route, execute, write findings."""
    # ── DeepSeek advisor: optionally reorder the queue before popping ──────────
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

    # LLM-DRIVEN REASONING (Phase 2) — DeepSeek capability selector
    decision = None
    if llm_client is not None and isinstance(registry, AdapterRegistry):
        context = build_brain_context(
            list(store.findings.values()),
            store.engagement,
            store.clusters,
        )
        phase = store.engagement.phase
        pcs_mode = "validation" if store.pcs.state.validation_mode else "exploration"

        sys.stderr.write(f"\n[Brain] Consulting DeepSeek for hypothesis: {hypothesis.path} (phase={phase}, pcs={pcs_mode})\n")

        try:
            llm_response = llm_client.chat.completions.create(
                model="deepseek-chat",
                messages=[{
                    "role": "system",
                    "content": BRAIN_SYSTEM_PROMPT
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
            # DeepSeek failure should never crash the Brain loop — fall through
            # to deterministic policy
            sys.stderr.write(f"[Brain] DeepSeek call failed: {exc}. Falling back to policy.\n")
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
            store.ingest_finding(error_finding, branch_id=branch_id)
            store.queue.complete(hypothesis.id)
            store.save_or_log()
            return error_finding
        for finding in _findings_from_adapter_result(
            result,
            hypothesis,
            parent_path_value,
            decision.asset.asset_type,
            branch_id=branch_id,
        ):
            if store.ingest_finding(finding, branch_id=branch_id):
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
        advisor: DeepSeekAdvisor | None = None,
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
                branch_count, pcs_reason = self.store.pcs.branches_for_step(
                    self.store.clusters,
                    wave_new_findings,
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
