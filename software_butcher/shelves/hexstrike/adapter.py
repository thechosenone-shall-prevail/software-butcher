from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit
import re

from ...core.adapter import AdapterCapability, AdapterRequest, AdapterResult
from ...core.asset_classifier import classify_url_asset_type
from ...state.session_state import get_origin, ShellSession
from ...core.registry import DEFAULT_REGISTRY
from ...core.runner import SafeRunner
from .client import DEFAULT_HEXSTRIKE_SERVER, HexstrikeApiClient, HexstrikeServerUnavailableError
from .interpreter import HexStrikeInterpreter
import shlex

DISCOVERY_INTENTS = frozenset(
    {
        "fingerprint",
        "continue_discovery",
        "discover",
        "enrich",
        "authenticated_discovery",
    }
)

SELECT_TOOLS_OBJECTIVES = frozenset({"comprehensive", "quick", "stealth"})


class HexstrikeAdapter:
    """Adapter around the HexStrike Flask API and legacy argv execution.

    Expanded to expose ALL server tool categories as capabilities so the
    Brain's external LLM (OpenRouter) can route to any tool on the server.
    """

    name = "hexstrike"
    NAME = "hexstrike"
    capabilities = (
        # ── Discovery & Reconnaissance ────────────────────────────────────
        AdapterCapability(
            name="endpoint_discovery",
            description="Discover web endpoints via active scanning (nmap, ffuf, nuclei)",
            asset_types=("ip", "domain", "web_endpoint", "api", "unknown"),
        ),
        AdapterCapability(
            name="web_behavior_analysis",
            description="Analyze HTTP responses for redirects, content-type, headers",
            asset_types=("web_endpoint", "api"),
        ),
        AdapterCapability(
            name="api_enumeration",
            description="Discover and fuzz API endpoints",
            asset_types=("api",),
        ),
        AdapterCapability(
            name="authenticated_discovery",
            description="Discover paths as authenticated user using session cookies",
            asset_types=("web_endpoint", "api"),
        ),
        # ── Network Scanning ──────────────────────────────────────────────
        AdapterCapability(
            name="port_scanning",
            description="Nmap, masscan, rustscan for port and service discovery",
            asset_types=("ip", "domain", "unknown"),
        ),
        # ── Vulnerability Scanning ────────────────────────────────────────
        AdapterCapability(
            name="vulnerability_scanning",
            description="Nuclei, nikto for known vulnerability detection",
            asset_types=("ip", "domain", "web_endpoint", "api"),
        ),
        # ── Web Vulnerability Testing ─────────────────────────────────────
        AdapterCapability(
            name="sql_injection_probing",
            description="SQLMap for SQL injection detection and exploitation",
            asset_types=("web_endpoint", "api"),
        ),
        AdapterCapability(
            name="directory_bruteforce",
            description="Gobuster, ffuf, feroxbuster for directory and path brute forcing",
            asset_types=("web_endpoint", "api"),
        ),
        AdapterCapability(
            name="xss_scanning",
            description="XSS detection and payload testing",
            asset_types=("web_endpoint", "api"),
        ),
        AdapterCapability(
            name="cms_scanning",
            description="WPScan for CMS-specific vulnerability scanning",
            asset_types=("web_endpoint",),
        ),
        # ── Credential Attacks ────────────────────────────────────────────
        AdapterCapability(
            name="credential_attack",
            description="Hydra brute force, hashcat/john password cracking",
            asset_types=("ip", "domain", "web_endpoint"),
        ),
        # ── API Security ──────────────────────────────────────────────────
        AdapterCapability(
            name="api_fuzzing",
            description="API fuzzer, GraphQL scanner, JWT analyzer for API security testing",
            asset_types=("api", "web_endpoint"),
        ),
        # ── Cloud Security ────────────────────────────────────────────────
        AdapterCapability(
            name="cloud_security_audit",
            description="Prowler, ScoutSuite, Trivy for cloud security auditing",
            asset_types=("cloud_account",),
        ),
        # ── Container Security ────────────────────────────────────────────
        AdapterCapability(
            name="container_security",
            description="kube-hunter, docker-bench, Trivy for container security scanning",
            asset_types=("container", "ip"),
        ),
        # ── IaC Scanning ──────────────────────────────────────────────────
        AdapterCapability(
            name="iac_scanning",
            description="Checkov, Terrascan for infrastructure-as-code scanning",
            asset_types=("iac_config", "source_repo"),
        ),
        # ── Binary / Reverse Engineering ──────────────────────────────────
        AdapterCapability(
            name="binary_analysis",
            description="GDB, radare2, ghidra, binwalk binary analysis via server",
            asset_types=("binary",),
        ),
        # ── AD / Internal Network ─────────────────────────────────────────
        AdapterCapability(
            name="ad_enumeration",
            description="enum4linux, smbmap, netexec for AD and internal network enumeration",
            asset_types=("ad_environment", "ip", "domain"),
        ),
        # ── Exploit / Payload ─────────────────────────────────────────────
        AdapterCapability(
            name="exploit_generation",
            description="Metasploit module selection, msfvenom payload generation",
            asset_types=("ip", "domain", "web_endpoint"),
        ),
        # ── AI-Driven Intelligence ────────────────────────────────────────
        AdapterCapability(
            name="ai_attack_chain",
            description="AI-driven attack chain discovery and orchestration",
            asset_types=("ip", "domain", "web_endpoint", "api"),
        ),
        AdapterCapability(
            name="technology_fingerprint",
            description="AI-powered technology stack detection and fingerprinting",
            asset_types=("ip", "domain", "web_endpoint"),
        ),
        # ── Bug Bounty Workflows ──────────────────────────────────────────
        AdapterCapability(
            name="bugbounty_recon",
            description="Automated bug bounty reconnaissance workflow",
            asset_types=("domain", "web_endpoint"),
        ),
        AdapterCapability(
            name="bugbounty_comprehensive",
            description="Full automated bug bounty comprehensive assessment",
            asset_types=("domain", "web_endpoint", "api"),
        ),
        # ── Shell Session Management ────────────────────────────────────────
        AdapterCapability(
            name="shell_command_execution",
            description="Run commands in established shell sessions (Metasploit, Sliver, SSH)",
            asset_types=("ip", "domain"),
        ),
    )

    def __init__(
        self,
        runner: SafeRunner | None = None,
        client: HexstrikeApiClient | None = None,
        server_url: str = DEFAULT_HEXSTRIKE_SERVER,
    ) -> None:
        self.runner = runner or SafeRunner()
        self.client = client or HexstrikeApiClient(server_url=server_url)
        self.interpreter = HexStrikeInterpreter()

    def execute(self, plan_or_command: dict[str, Any] | list[str], cwd: str | None = None) -> AdapterResult | dict[str, Any]:
        if isinstance(plan_or_command, dict):
            return self._execute_plan(plan_or_command)
        result = self.runner.run(plan_or_command, cwd=cwd)
        return self.normalize(result)

    def plan(self, request: AdapterRequest) -> dict[str, Any]:
        self.client.ensure_healthy()
        objective = self._select_tools_objective(request.objective, request.options)
        selection = {}
        try:
            selection = self.client.select_tools(request.target, objective)
            if selection.get("error") or not selection.get("success", True):
                import logging
                logging.getLogger(__name__).warning(f"HexStrike select-tools failed: {selection.get('error')}")
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"HexStrike select-tools failed: {e}")

        # Determine which capability to use for execution
        capability = request.options.get("capability") or self._intent_to_capability(request.objective)

        return {
            "adapter": self.name,
            "request": request,
            "objective": objective,
            "capability": capability,
            "selected_tools": selection.get("selected_tools", []),
            "target_profile": selection.get("target_profile", {}),
            "selection": selection,
        }

    def _execute_plan(self, plan: dict[str, Any]) -> AdapterResult:
        self.client.ensure_healthy()
        request = plan["request"]
        intent = request.objective
        capability = plan.get("capability", "endpoint_discovery")
        raw_output: dict[str, Any] = {
            "request": request,
            "target": request.target,
            "intent": intent,
            "capability": capability,
            "selected_tools": plan.get("selected_tools", []),
            "responses": {},
            "tool_runs": [],
            "html_crawl": None,
            "success": True,
        }

        # ── Capability-based dispatch (NEW) ────────────────────────────────
        # If the Brain's LLM selected a specific capability, dispatch
        # directly to the structured server endpoint.
        direct_result = self._execute_capability(capability, request.target, request.options)
        if direct_result is not None:
            raw_output["responses"]["capability_dispatch"] = direct_result
            if direct_result.get("error") or not direct_result.get("success", True):
                raw_output["success"] = False

        # ── Discovery flow (existing behavior preserved) ───────────────────
        if intent in DISCOVERY_INTENTS:
            analysis = self.client.analyze_target(request.target)
            raw_output["responses"]["analyze_target"] = analysis
            if analysis.get("error") or not analysis.get("success", True):
                raw_output["success"] = False

            # HTML crawl: fetch the page and extract links to seed forward discovery
            if request.target.startswith(("http://", "https://")):
                session_store = request.options.get("session_store") if request.options else None
                cookie_header = ""
                if session_store:
                    origin = get_origin(request.target)
                    cookie_hdr_val = session_store.cookie_header(origin)
                    if cookie_hdr_val:
                        # Ensure cookie value is safe and strictly formatted
                        cookie_header = f'-H "Cookie: {cookie_hdr_val}" '

                quoted_target = shlex.quote(request.target)
                crawl_result = self.client.execute_command(
                    f"curl -sL --max-time 10 {cookie_header}{quoted_target}",
                    use_cache=False,
                    timeout=self.client.timeout,
                )
                raw_output["html_crawl"] = crawl_result

        run_tools = plan.get("objective") != "quick" and bool(plan.get("selected_tools"))
        if run_tools:
            for tool in plan.get("selected_tools", [])[:3]:
                command = self._build_tool_command(tool, request.target)
                result = self.client.execute_command(command, use_cache=False, timeout=self.client.timeout)
                raw_output["tool_runs"].append({"tool": tool, "command": command, "result": result})
                if not result.get("success", False):
                    raw_output["success"] = False

        return self.normalize_results(raw_output)

    def _execute_capability(self, capability: str, target: str, options: dict[str, Any]) -> dict[str, Any] | None:
        """Route a capability name to the correct HexstrikeApiClient method.

        Returns None for capabilities that should use the legacy discovery flow
        (web_behavior_analysis, authenticated_discovery).

        endpoint_discovery runs gobuster directly so unlinked paths like /hall
        are found even when analyze_target returns nothing useful.
        """
        # web_behavior_analysis and authenticated_discovery use the existing
        # discovery flow (HTML crawl + analyze_target).
        if capability in {"web_behavior_analysis", "authenticated_discovery"}:
            return None
        # api_enumeration delegates to api_fuzzer for schema/endpoint discovery.
        if capability == "api_enumeration":
            safe_opts = {k: v for k, v in options.items()
                         if k not in {"session_store", "capability"}}
            try:
                return self.client.run_api_fuzzer(target, **safe_opts)
            except Exception as exc:
                return {"error": str(exc), "success": False}
        # endpoint_discovery runs a multi-tool bundle so paths like /hall are not missed.
        if capability == "endpoint_discovery":
            bundle: dict[str, Any] = {}
            for tool_name, runner in (
                ("gobuster", lambda: self.client.run_gobuster(target)),
                ("ffuf", lambda: self.client.run_ffuf(target)),
                ("katana", lambda: self.client.run_katana(target)),
            ):
                try:
                    bundle[tool_name] = runner()
                except Exception as exc:
                    bundle[tool_name] = {"error": str(exc), "success": False}
            return {"success": True, "bundle": "endpoint_discovery", "responses": bundle}

        # Filter out internal keys that shouldn't be sent to the server
        safe_opts = {k: v for k, v in options.items()
                     if k not in {"session_store", "capability"}}

        dispatch: dict[str, Any] = {
            # Network scanning
            "port_scanning": lambda: self.client.run_nmap(target, **safe_opts),
            # Vulnerability scanning
            "vulnerability_scanning": lambda: self.client.run_nuclei(target, **safe_opts),
            # Web vulnerability testing
            "sql_injection_probing": lambda: self.client.run_sqlmap(target, **safe_opts),
            "directory_bruteforce": lambda: self.client.run_gobuster(target, **safe_opts),
            "xss_scanning": lambda: self.client.run_xsser(target, **safe_opts),
            "cms_scanning": lambda: self.client.run_wpscan(target, **safe_opts),
            # Credential attacks
            "credential_attack": lambda: self.client.run_hydra(target, **safe_opts),
            # API security
            "api_fuzzing": lambda: self.client.run_api_fuzzer(target, **safe_opts),
            # Cloud security
            "cloud_security_audit": lambda: self.client.run_prowler(**safe_opts),
            # Container security
            "container_security": lambda: self.client.run_kube_hunter(**safe_opts),
            # IaC scanning
            "iac_scanning": lambda: self.client.run_checkov(**safe_opts),
            # Binary analysis via server
            "binary_analysis": lambda: self.client.run_radare2(target, **safe_opts),
            # AD / internal network
            "ad_enumeration": lambda: self.client.run_enum4linux(target, **safe_opts),
            # Exploit generation
            "exploit_generation": lambda: self.client.run_metasploit(**safe_opts),
            # AI intelligence
            "ai_attack_chain": lambda: self.client.create_attack_chain(target, **safe_opts),
            "technology_fingerprint": lambda: self.client.detect_technologies(target, **safe_opts),
            # Bug bounty workflows
            "bugbounty_recon": lambda: self.client.bugbounty_recon(target, **safe_opts),
            "bugbounty_comprehensive": lambda: self.client.bugbounty_comprehensive(target, **safe_opts),
            "cve_lookup": lambda: self._run_cve_lookup(target, safe_opts),
            # Shell session management
            "shell_command_execution": lambda: self._execute_shell_command(target, options, safe_opts),
        }

        handler = dispatch.get(capability)
        if handler:
            try:
                result = handler()
                # Detect and store shell sessions from exploit results
                if capability in {"exploit_generation", "sql_injection_probing", "shell_command_execution"}:
                    self._store_shell_if_detected(result, target, options)
                return result
            except Exception as exc:
                return {"error": str(exc), "success": False}
        return None

    def _run_cve_lookup(self, target: str, options: dict[str, Any]) -> dict[str, Any]:
        technology = options.get("technology") or target
        cve_id = options.get("cve_id", "")
        if cve_id:
            return self.client.generate_exploit_from_cve(cve_id=cve_id, **options)
        return self.client.detect_technologies(technology, **options)

    def _execute_shell_command(self, target: str, options: dict[str, Any], safe_opts: dict[str, Any]) -> dict[str, Any]:
        """Execute a command in an existing shell session.
        
        If a session_id is provided in options, use that specific session.
        Otherwise, find the best session for the target.
        """
        session_store = options.get("session_store") if options else None
        if not session_store:
            return {"error": "No session store available", "success": False}
        
        # Extract command from options
        command = safe_opts.get("command") or options.get("command", "id")
        session_id = safe_opts.get("session_id") or options.get("session_id")
        
        # If session_id is provided, use it directly
        if session_id:
            session = session_store.shell_sessions.get_session(session_id)
            if not session:
                return {"error": f"Session {session_id} not found", "success": False}
            if not session.active:
                return {"error": f"Session {session_id} is inactive", "success": False}
            
            # Execute command in the session
            result = self.client.shell_execute(session.session_type, session.session_id, command)
            
            # Update session state
            stdout = result.get("stdout", "") or ""
            stderr = result.get("stderr", "") or ""
            session_store.shell_sessions.update_session(session_id, command, stdout + " " + stderr)
            
            return result
        
        # Otherwise, find the best session for the target
        # Extract host from target (could be URL or IP)
        from urllib.parse import urlsplit
        if target.startswith(("http://", "https://")):
            parsed = urlsplit(target)
            host = parsed.netloc.split(":")[0]
        else:
            host = target.split(":")[0]
        
        best_session = session_store.shell_sessions.get_best_session_for_target(host)
        if not best_session:
            return {"error": f"No active shell session found for {host}", "success": False}
        
        # Execute command in the best session
        result = self.client.shell_execute(best_session.session_type, best_session.session_id, command)
        
        # Update session state
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        session_store.shell_sessions.update_session(best_session.session_id, command, stdout + " " + stderr)
        
        return result

    @staticmethod
    def _intent_to_capability(intent: str) -> str:
        """Map an intent string to the closest capability name."""
        mapping = {
            "discover": "endpoint_discovery",
            "fingerprint": "endpoint_discovery",
            "continue_discovery": "endpoint_discovery",
            "enrich": "endpoint_discovery",
            "authenticated_discovery": "authenticated_discovery",
            "web_behavior_analysis": "web_behavior_analysis",
            "port_scanning": "port_scanning",
            "vulnerability_scanning": "vulnerability_scanning",
            "sql_injection_probing": "sql_injection_probing",
            "directory_bruteforce": "directory_bruteforce",
            "xss_scanning": "xss_scanning",
            "cms_scanning": "cms_scanning",
            "credential_attack": "credential_attack",
            "api_fuzzing": "api_fuzzing",
            "cloud_security_audit": "cloud_security_audit",
            "container_security": "container_security",
            "iac_scanning": "iac_scanning",
            "binary_analysis": "binary_analysis",
            "ad_enumeration": "ad_enumeration",
            "exploit_generation": "exploit_generation",
            "ai_attack_chain": "ai_attack_chain",
            "technology_fingerprint": "technology_fingerprint",
            "bugbounty_recon": "bugbounty_recon",
            "bugbounty_comprehensive": "bugbounty_comprehensive",
            "cve_lookup": "cve_lookup",
            "shell_command_execution": "shell_command_execution",
            "shell_execute": "shell_command_execution",
            "post_exploit": "shell_command_execution",
            "privesc": "shell_command_execution",
        }
        return mapping.get(intent, "endpoint_discovery")

    def normalize_results(self, raw_output: dict[str, Any]) -> AdapterResult:
        request = raw_output["request"]
        target = request.target
        asset_type = request.asset_type
        findings: list[dict[str, Any]] = []
        seen_paths: set[str] = set()

        # ── Capability dispatch results ────────────────────────────────────
        cap_result = raw_output.get("responses", {}).get("capability_dispatch", {})
        if cap_result:
            capability = raw_output.get("capability", "scan")
            stdout = cap_result.get("stdout", "") or cap_result.get("output", "") or ""
            stderr = cap_result.get("stderr", "") or ""
            for item in self._findings_from_command_output(target, capability, stdout, stderr, asset_type):
                if item["path"] not in seen_paths:
                    seen_paths.add(item["path"])
                    findings.append(item)

        # ── Analysis results ───────────────────────────────────────────────
        analysis = raw_output.get("responses", {}).get("analyze_target", {})
        profile = analysis.get("target_profile") or raw_output.get("target_profile") or {}
        if profile:
            for item in self._findings_from_profile(profile, target, asset_type):
                if item["path"] not in seen_paths:
                    seen_paths.add(item["path"])
                    findings.append(item)

        html_crawl = raw_output.get("html_crawl")
        if html_crawl and html_crawl.get("stdout"):
            for item in self._findings_from_html_crawl(html_crawl["stdout"], target, asset_type):
                if item["path"] not in seen_paths:
                    seen_paths.add(item["path"])
                    findings.append(item)

        for tool_run in raw_output.get("tool_runs", []):
            tool = tool_run.get("tool", "scan")
            result = tool_run.get("result", {})
            stdout = result.get("stdout", "") or ""
            stderr = result.get("stderr", "") or ""
            for item in self._findings_from_command_output(target, tool, stdout, stderr, asset_type):
                if item["path"] not in seen_paths:
                    seen_paths.add(item["path"])
                    findings.append(item)

        if not findings and profile:
            findings.append(
                {
                    "hypothesis": f"HexStrike analyzed {target} ({profile.get('target_type', 'unknown')}).",
                    "path": target,
                    "provenance": "hexstrike:analyze-target",
                    "status": "hypothesis",
                    "confidence": float(profile.get("confidence_score", 0.4)),
                    "evidence": [
                        f"risk_level={profile.get('risk_level', 'unknown')}",
                        f"attack_surface_score={profile.get('attack_surface_score', 0)}",
                    ],
                    "capability": "target_analysis",
                    "asset_type": asset_type,
                }
            )

        success = bool(findings) and raw_output.get("success", True)
        summary = f"HexStrike completed {len(raw_output.get('tool_runs', []))} tool run(s) for {target}."
        capability = raw_output.get("capability", "")
        if capability and capability not in {"endpoint_discovery"}:
            summary = f"HexStrike executed {capability} against {target} and produced {len(findings)} finding(s)."
        elif analysis.get("success"):
            summary = f"HexStrike analyzed {target} and produced {len(findings)} structured finding(s)."

        return AdapterResult(
            adapter=self.name,
            success=success,
            summary=summary,
            findings=findings,
            raw=raw_output,
        )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Legacy argv-runner normalization for backward-compatible tests."""
        return {
            "provenance": f"hexstrike:{raw.get('argv', [])[:1]}",
            "stdout": raw.get("stdout", ""),
            "stderr": raw.get("stderr", ""),
            "returncode": raw.get("returncode", 1),
            "timed_out": raw.get("timed_out", False),
        }

    @staticmethod
    def _select_tools_objective(intent: str, options: dict[str, Any]) -> str:
        explicit = options.get("objective")
        if explicit in SELECT_TOOLS_OBJECTIVES:
            return str(explicit)
        if intent in {"fingerprint", "enrich"}:
            return "quick"
        if "stealth" in intent:
            return "stealth"
        return "comprehensive"

    @staticmethod
    def _resolve_path(base_target: str, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path.rstrip("/")
        parsed = urlsplit(base_target)
        if parsed.scheme and parsed.netloc:
            return urljoin(f"{parsed.scheme}://{parsed.netloc}", path)
        return path

    def _findings_from_profile(self, profile: dict[str, Any], base_target: str, asset_type: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        confidence = float(profile.get("confidence_score", 0.45))

        parsed = urlsplit(base_target)
        if parsed.path and parsed.path not in {"", "/"}:
            findings.append(
                {
                    "hypothesis": f"Target path surface identified at {base_target}.",
                    "path": base_target,
                    "provenance": "hexstrike:analyze-target:path",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.1, 0.85),
                    "evidence": [parsed.path, f"segment={parsed.path.strip('/').split('/')[0]}"],
                    "capability": "endpoint_discovery",
                    "asset_type": "api" if "api" in parsed.path.lower() else asset_type,
                }
            )

        for endpoint in profile.get("endpoints", []):
            path = self._resolve_path(base_target, str(endpoint))
            # Use canonical classifier — endpoints from the profile may include
            # static paths (e.g. /assets/logo.png) that must not be probed.
            endpoint_asset_type = classify_url_asset_type(path, "web_endpoint")
            if endpoint_asset_type == "static_asset":
                continue
            findings.append(
                {
                    "hypothesis": "Endpoint discovered during HexStrike target analysis.",
                    "path": path,
                    "provenance": "hexstrike:analyze-target:endpoint",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.15, 0.9),
                    "evidence": [str(endpoint), f"target_type={profile.get('target_type', 'unknown')}"],
                    "capability": "endpoint_discovery",
                    "asset_type": endpoint_asset_type,
                }
            )

        for subdomain in profile.get("subdomains", []):
            host = str(subdomain)
            path = host if host.startswith("http") else f"https://{host}"
            findings.append(
                {
                    "hypothesis": "Subdomain discovered during HexStrike target analysis.",
                    "path": path,
                    "provenance": "hexstrike:analyze-target:subdomain",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.1, 0.8),
                    "evidence": [host],
                    "capability": "subdomain_discovery",
                    "asset_type": "domain",
                }
            )

        services = profile.get("services") or {}
        if services:
            evidence = [f"{port}/{service}" for port, service in list(services.items())[:25]]
            findings.append(
                {
                    "hypothesis": f"Open services discovered on {base_target}.",
                    "path": base_target,
                    "provenance": "hexstrike:analyze-target:ports",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.2, 0.9),
                    "evidence": evidence,
                    "capability": "port_discovery",
                    "asset_type": asset_type,
                    "metadata": {"services": services},
                }
            )

        technologies = [tech for tech in profile.get("technologies", []) if tech and tech != "unknown"]
        if technologies:
            findings.append(
                {
                    "hypothesis": f"Technology stack identified for {base_target}.",
                    "path": base_target,
                    "provenance": "hexstrike:analyze-target:technology",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.05, 0.75),
                    "evidence": technologies,
                    "capability": "technology_fingerprint",
                    "asset_type": asset_type,
                    "metadata": {"technologies": technologies},
                }
            )

        if profile.get("cms_type"):
            cms = str(profile["cms_type"])
            findings.append(
                {
                    "hypothesis": f"CMS fingerprint suggests {cms} at {base_target}.",
                    "path": base_target,
                    "provenance": "hexstrike:analyze-target:cms",
                    "status": "hypothesis",
                    "confidence": min(confidence + 0.1, 0.8),
                    "evidence": [cms, f"cms_type={cms}"],
                    "capability": "technology_fingerprint",
                    "asset_type": asset_type,
                }
            )

        return findings

    def _findings_from_html_crawl(self, html: str, base_target: str, asset_type: str) -> list[dict[str, Any]]:
        """Turn HTML link extraction into endpoint_discovery findings."""
        links = self.interpreter.extract_html_links(base_target, html)
        findings: list[dict[str, Any]] = []
        for link in links:
            # extract_html_links already filters static assets, but classify again
            # defensively so any edge-case URL (e.g. /api/v1/logo.png?v=2) is caught.
            link_asset_type = classify_url_asset_type(link, "web_endpoint")
            if link_asset_type == "static_asset":
                continue
            findings.append(
                {
                    "hypothesis": f"Endpoint discovered via HTML crawl of {base_target}.",
                    "path": link,
                    "provenance": "hexstrike:html_crawl",
                    "status": "hypothesis",
                    "confidence": 0.6,
                    "evidence": [link, f"crawled_from={base_target}"],
                    "capability": "endpoint_discovery",
                    "asset_type": link_asset_type,
                }
            )
        return findings

    def _findings_from_command_output(
        self,
        target: str,
        tool: str,
        stdout: str,
        stderr: str,
        asset_type: str,
    ) -> list[dict[str, Any]]:
        interpreted = self.interpreter.interpret(target, tool, stdout, asset_type)
        findings: list[dict[str, Any]] = []
        for item in interpreted:
            item = dict(item)
            item["capability"] = f"{tool}_scan"
            findings.append(item)

        if stderr.strip() and not findings:
            findings.append(
                {
                    "hypothesis": f"HexStrike {tool} produced stderr output for {target}.",
                    "path": target,
                    "provenance": f"hexstrike:{tool}:stderr",
                    "status": "hypothesis",
                    "confidence": 0.25,
                    "evidence": [stderr[:2000]],
                    "capability": f"{tool}_scan",
                    "asset_type": asset_type,
                }
            )
        return findings

    @staticmethod
    def _build_tool_command(tool: str, target: str) -> str:
        quoted_target = shlex.quote(target)
        commands = {
            "nmap": f"nmap -sV -T4 {quoted_target}",
            "httpx": f"httpx -silent -u {quoted_target}",
            "nuclei": f"nuclei -u {quoted_target} -silent",
            "gobuster": f"gobuster dir -u {quoted_target} -w /usr/share/wordlists/dirb/common.txt -q",
            "ffuf": f"ffuf -u {quoted_target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s",
            "nikto": f"nikto -h {quoted_target}",
            "wpscan": f"wpscan --url {quoted_target}",
            "sqlmap": f"sqlmap -u {quoted_target} --batch",
        }
        return commands.get(tool, f"{tool} {quoted_target}")

    def _detect_shell_session(self, stdout: str, stderr: str, target: str) -> ShellSession | None:
        """Detect if a shell session was established from tool output.
        
        Returns a ShellSession object if shell establishment is detected, None otherwise.
        """
        output = stdout.lower() + " " + stderr.lower()
        
        # Metasploit session patterns
        msf_session_match = re.search(r'session (\d+) opened', output, re.IGNORECASE)
        if msf_session_match:
            session_id = msf_session_match.group(1)
            # Try to extract user info
            user_match = re.search(r'as user\s+(\w+)', output, re.IGNORECASE)
            user = user_match.group(1) if user_match else None
            return ShellSession(
                session_id=session_id,
                session_type="metasploit",
                host=target,
                user=user,
                metadata={"detection_method": "metasploit_session_pattern"},
            )
        
        # Meterpreter patterns
        meterpreter_match = re.search(r'meterpreter\s+(\d+)', output, re.IGNORECASE)
        if meterpreter_match:
            session_id = meterpreter_match.group(1)
            return ShellSession(
                session_id=session_id,
                session_type="meterpreter",
                host=target,
                metadata={"detection_method": "meterpreter_pattern"},
            )
        
        # Sliver beacon patterns
        sliver_match = re.search(r'beacon\s+(\w+)', output, re.IGNORECASE)
        if sliver_match:
            session_id = sliver_match.group(1)
            return ShellSession(
                session_id=session_id,
                session_type="sliver",
                host=target,
                metadata={"detection_method": "sliver_beacon_pattern"},
            )
        
        # Generic shell patterns (uid=, whoami, etc.)
        if "uid=" in output or "whoami" in output or "shell" in output:
            # Generate a synthetic session ID for web shells or reverse shells
            import hashlib
            synthetic_id = hashlib.md5(f"{target}_{len(output)}".encode()).hexdigest()[:8]
            return ShellSession(
                session_id=f"shell_{synthetic_id}",
                session_type="web_shell",
                host=target,
                metadata={"detection_method": "generic_shell_pattern", "output_snippet": output[:200]},
            )
        
        return None

    def _store_shell_if_detected(self, result: dict[str, Any], target: str, options: dict[str, Any]) -> None:
        """Detect and store shell sessions from tool execution results."""
        session_store = options.get("session_store") if options else None
        if not session_store:
            return
        
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        
        shell_session = self._detect_shell_session(stdout, stderr, target)
        if shell_session:
            session_store.shell_sessions.add_session(shell_session)


DEFAULT_REGISTRY.register_adapter(HexstrikeAdapter.NAME, HexstrikeAdapter)
