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
from software_butcher.core.recon_seed import ensure_host_recon_hypothesis, next_recon_hypothesis
from software_butcher.core.scope import Scope
from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.core.path_relevance import is_noise_path, score_path
from software_butcher.state.recon_checklist import HOST_LEVEL_RECON_CAPABILITIES, mark_host_recon
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
    "http_surface_map": "http_surface",
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
    "bugbounty_osint": "hexstrike",
    "bugbounty_comprehensive": "hexstrike",
    "payload_evasion": "boaz",
    "oss_fuzzing": "boaz",
    "source_static_analysis": "code_analysis",
    "continuous_fuzzing": "oss_fuzz",
}

_SCANNER_CAPABILITIES = frozenset({
    "endpoint_discovery",
    "directory_bruteforce",
    "bugbounty_recon",
    "bugbounty_osint",
    "bugbounty_comprehensive",
    "technology_fingerprint",
    "vulnerability_scanning",
    "continue_discovery",
    "discover",
    "enrich",
    "fingerprint",
})


def _host_findings(store: FindingStore, host: str) -> list[Finding]:
    if not host:
        return []
    host_l = host.lower()
    return [f for f in store.findings.values() if host_key(f.path).lower() == host_l]


def _host_has_content_intel(store: FindingStore, host: str) -> bool:
    for finding in _host_findings(store, host):
        if (finding.metadata or {}).get("content_analysis"):
            return True
    return False


def _host_has_application_surface(store: FindingStore, host: str) -> bool:
    """True when content analysis found forms, phpMyAdmin/phpinfo, or high-value app paths."""
    for finding in _host_findings(store, host):
        meta = finding.metadata or {}
        if not meta.get("content_analysis"):
            continue
        page_type = str(meta.get("page_type") or "")
        if page_type in {"phpinfo", "phpmyadmin"}:
            return True
        conclusions = meta.get("conclusions") or []
        if any("form" in str(c).lower() for c in conclusions):
            return True
        if meta.get("mysql_signals") or meta.get("form_count"):
            return True
        if score_path(finding.path) >= 0.85:
            return True
        content_pages = meta.get("content_pages") or []
        for page in content_pages:
            if str(page.get("page_type") or "") in {"phpinfo", "phpmyadmin"}:
                return True
            if page.get("form_count") or page.get("mysql_signals"):
                return True
    return False


def _host_stack_landing_pending_app(store: FindingStore, host: str) -> bool:
    """XAMPP/default stack detected but no concrete application entry mapped yet."""
    stack_detected = False
    has_app_entry = False
    for finding in _host_findings(store, host):
        meta = finding.metadata or {}
        stack = (meta.get("stack_landing") or {})
        if stack.get("detected"):
            stack_detected = True
        if meta.get("semantic_probes"):
            for probe in meta["semantic_probes"]:
                if probe.get("reachable"):
                    has_app_entry = True
        if score_path(finding.path) >= 0.85 and not is_noise_path(finding.path):
            has_app_entry = True
        page_type = str(meta.get("page_type") or "")
        if page_type in {"phpinfo", "phpmyadmin"}:
            has_app_entry = True
    return stack_detected and not has_app_entry


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


def _apply_path_relevance_gate(
    store: FindingStore,
    hypothesis,
    decision: PolicyDecision,
) -> PolicyDecision:
    """Stop remapping XAMPP boilerplate paths; prefer discovery when stack mismatch exists."""
    if decision.asset.asset_type not in {"web_endpoint", "api", "domain"}:
        return decision

    capability = str((decision.options or {}).get("capability") or decision.intent or "")
    if capability != "http_surface_map":
        return decision

    host = host_key(hypothesis.path)
    if not store.recon_checklist.is_complete(host):
        return decision

    if is_noise_path(hypothesis.path):
        sys.stderr.write(
            f"[Brain] Skipping surface remap of noise path {hypothesis.path} — marking complete.\n"
        )
        return PolicyDecision(
            intent="continue_discovery",
            asset=decision.asset,
            preferred_adapter="hexstrike",
            reason=f"Path {hypothesis.path} is stack boilerplate (XAMPP/docs); not worth remapping.",
            options={"capability": "continue_discovery", "skip_execute": True},
        )

    path_score = score_path(hypothesis.path)
    if path_score < 0.35 and hypothesis.path.rstrip("/") != base_web_url(store.base_target or hypothesis.path).rstrip("/"):
        sys.stderr.write(
            f"[Brain] Low-relevance path {hypothesis.path} (score={path_score:.2f}) — skipping surface remap.\n"
        )
        return PolicyDecision(
            intent="continue_discovery",
            asset=decision.asset,
            preferred_adapter="hexstrike",
            reason=f"Low-relevance child path (score={path_score:.2f}); read high-value pages first.",
            options={"capability": "continue_discovery", "skip_execute": True},
        )
    return decision


def _apply_local_analysis_gate(
    store: FindingStore,
    hypothesis,
    decision: PolicyDecision,
) -> PolicyDecision:
    """Prefer local http_surface over HexStrike for content-intel follow-ups."""
    if (decision.options or {}).get("skip_execute"):
        return decision

    capability = str((decision.options or {}).get("capability") or decision.intent or "")
    if capability != "web_behavior_analysis":
        return decision

    meta = hypothesis.metadata or {}
    if meta.get("generated_by") in {"content_intel", "mysql_resource_intel", "domain_semantics"}:
        return PolicyDecision(
            intent="http_surface_map",
            asset=decision.asset,
            preferred_adapter="http_surface",
            reason="Content-intel hypothesis — map and analyze locally instead of HexStrike web_behavior_analysis.",
            options={"capability": "http_surface_map"},
        )

    page_type = str(meta.get("page_type") or "")
    if page_type in {"phpinfo", "phpmyadmin"} or meta.get("analysis_focus") == "resource_exhaustion":
        return PolicyDecision(
            intent="http_surface_map",
            asset=decision.asset,
            preferred_adapter="http_surface",
            reason=f"Page type {page_type or 'mysql'} warrants local content analysis, not remote behavior scan.",
            options={"capability": "http_surface_map"},
        )
    return decision


def _apply_scanner_gate(
    store: FindingStore,
    hypothesis,
    decision: PolicyDecision,
) -> PolicyDecision:
    """Block generic HexStrike scanners until headers and page content are analyzed."""
    if decision.asset.asset_type not in {"web_endpoint", "api", "domain", "unknown"}:
        return decision

    if (decision.options or {}).get("skip_execute"):
        return decision

    capability = str((decision.options or {}).get("capability") or decision.intent or "")
    if capability not in _SCANNER_CAPABILITIES:
        return decision

    host = host_key(hypothesis.path)
    recon_base = base_web_url(store.base_target or hypothesis.path).rstrip("/")

    if not _host_has_content_intel(store, host):
        sys.stderr.write(
            f"[Brain] Scanner gate on {host}: read headers and page content before {capability}\n"
        )
        return PolicyDecision(
            intent="http_surface_map",
            asset=Asset(
                locator=recon_base,
                asset_type=decision.asset.asset_type,
                parent=decision.asset.parent,
                metadata=decision.asset.metadata,
            ),
            preferred_adapter="http_surface",
            reason=(
                f"Host {host} lacks content_analysis findings — map headers and view-source "
                f"before {capability}."
            ),
            options={"capability": "http_surface_map"},
        )

    if not _host_has_application_surface(store, host) or _host_stack_landing_pending_app(store, host):
        sys.stderr.write(
            f"[Brain] Scanner gate on {host}: content read but no concrete app surface — "
            f"reason locally before {capability}\n"
        )
        return PolicyDecision(
            intent="http_surface_map",
            asset=Asset(
                locator=hypothesis.path if score_path(hypothesis.path) >= 0.5 else recon_base,
                asset_type=decision.asset.asset_type,
                parent=decision.asset.parent,
                metadata=decision.asset.metadata,
            ),
            preferred_adapter="http_surface",
            reason=(
                f"Host {host} has stack/content intel but no confirmed application entry — "
                f"continue local analysis instead of {capability}."
            ),
            options={"capability": "http_surface_map"},
        )

    return decision


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
        hypothesis = next_recon_hypothesis(store) or store.queue.next()
    if not hypothesis:
        if ensure_host_recon_hypothesis(store):
            hypothesis = next_recon_hypothesis(store) or store.queue.next()
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
            if capability in (None, "None", "null", ""):
                capability = None
                decision = None
            else:
                sys.stderr.write(f"[Brain] LLM chose capability: {capability} (Reasoning: {llm_decision.get('reasoning')})\n")
                adapter = registry.find_by_capability(capability or "")
                if not adapter:
                    sys.stderr.write(f"[Brain] Capability '{capability}' not found in registry. Falling back to policy.\n")
                    decision = None
                else:
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
    decision = _apply_path_relevance_gate(store, hypothesis, decision)
    decision = _apply_local_analysis_gate(store, hypothesis, decision)
    decision = _apply_scanner_gate(store, hypothesis, decision)

    route = _route_for_decision(decision, router)

    if (decision.options or {}).get("skip_execute"):
        skipped = Finding(
            hypothesis=hypothesis.reason,
            path=hypothesis.path,
            provenance="brain:noise_skip",
            status="dismissed",
            evidence=[decision.reason],
            confidence=0.2,
            parent_path=parent_path_value,
            asset_type=decision.asset.asset_type,
        )
        _ingest_finding(store, skipped, branch_id, on_finding_ingested)
        store.queue.complete(hypothesis.id)
        store.save_or_log()
        return skipped

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
        adapter_options["transport_state"] = store.transport_state
        host = host_key(hypothesis.path)
        store.transport_state.apply_wait(host)
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
            executed_cap = str((decision.options or {}).get("capability") or decision.intent or "")
            if result.success and store.base_target and executed_cap in HOST_LEVEL_RECON_CAPABILITIES:
                mark_host_recon(store.recon_checklist, store.base_target, executed_cap)
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
                content_ok = _host_has_content_intel(self.store, recon_host) if recon_host else True
                branch_count, pcs_reason = self.store.pcs.branches_for_step(
                    self.store.clusters,
                    wave_new_findings,
                    recon_complete=recon_ok,
                )
                branch_count = min(branch_count, self.max_branches)
                if not recon_ok or not content_ok:
                    branch_count = 1
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
                recon_host = host_key((asset.locator if asset else "") or self.store.base_target)
                if recon_host and not self.store.recon_complete_for(recon_host):
                    if ensure_host_recon_hypothesis(self.store):
                        continue
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
