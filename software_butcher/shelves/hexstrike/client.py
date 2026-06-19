"""Thin HTTP client for the HexStrike Flask API (mirrors hexstrike_mcp.HexStrikeClient).

Expanded to cover ALL server tool endpoints so the Brain can call structured
APIs instead of the generic /api/command passthrough.
"""

from __future__ import annotations

from typing import Any

import requests


DEFAULT_HEXSTRIKE_SERVER = "http://127.0.0.1:8888"
DEFAULT_REQUEST_TIMEOUT = 30


class HexstrikeServerUnavailableError(RuntimeError):
    """Raised when the HexStrike API server is not running or unhealthy."""


class HexstrikeApiClient:
    """Client for communicating with the HexStrike AI API server.

    Every public method maps 1-to-1 to a server endpoint so the Brain's
    adapter layer calls structured APIs, not generic command passthrough.
    """

    def __init__(self, server_url: str = DEFAULT_HEXSTRIKE_SERVER, timeout: int = DEFAULT_REQUEST_TIMEOUT) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    # ── Health / Liveness ──────────────────────────────────────────────────

    def ensure_healthy(self) -> dict[str, Any]:
        """Fast liveness check — /health scans 100+ tools and can take minutes."""
        try:
            response = self.session.get(f"{self.server_url}/", timeout=5)
            if response.status_code >= 500:
                raise HexstrikeServerUnavailableError(
                    f"HexStrike server at {self.server_url} returned HTTP {response.status_code}"
                )
        except requests.ConnectionError as exc:
            raise HexstrikeServerUnavailableError(
                f"HexStrike server is not reachable at {self.server_url}. "
                "Start it with: python hexstrike_server.py --port 8888"
            ) from exc
        except requests.RequestException as exc:
            raise HexstrikeServerUnavailableError(
                f"HexStrike server is not reachable at {self.server_url}: {exc}"
            ) from exc

        return {"status": "healthy", "reachable": True, "http_status": response.status_code}

    def check_health(self) -> dict[str, Any]:
        return self.safe_get("health", timeout=self.timeout)

    # ── Generic helpers ────────────────────────────────────────────────────

    def safe_get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.get(url, params=params or {}, timeout=timeout or self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            return {"error": f"Request failed: {exc}", "success": False}

    def safe_post(
        self,
        endpoint: str,
        json_data: dict[str, Any],
        timeout: int | None = None,
    ) -> dict[str, Any]:
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.post(url, json=json_data, timeout=timeout or self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            return {"error": f"Request failed: {exc}", "success": False}

    # ── Intelligence endpoints ─────────────────────────────────────────────

    def select_tools(self, target: str, objective: str) -> dict[str, Any]:
        return self.safe_post(
            "api/intelligence/select-tools",
            {"target": target, "objective": objective},
        )

    def analyze_target(self, target: str) -> dict[str, Any]:
        return self.safe_post("api/intelligence/analyze-target", {"target": target})

    def optimize_parameters(self, tool: str, target: str, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/intelligence/optimize-parameters", {"tool": tool, "target": target, **kwargs})

    def create_attack_chain(self, target: str, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/intelligence/create-attack-chain", {"target": target, **kwargs})

    def smart_scan(self, target: str, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/intelligence/smart-scan", {"target": target, **kwargs})

    def detect_technologies(self, target: str, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/intelligence/technology-detection", {"target": target, **kwargs})

    # ── Generic command (legacy fallback) ──────────────────────────────────

    def execute_command(
        self,
        command: str,
        use_cache: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        return self.safe_post(
            "api/command",
            {"command": command, "use_cache": use_cache},
            timeout=timeout,
        )

    # ══════════════════════════════════════════════════════════════════════
    # NETWORK SCANNING
    # ══════════════════════════════════════════════════════════════════════

    def run_nmap(self, target: str, scan_type: str = "-sV", ports: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "scan_type": scan_type, "ports": ports, "use_recovery": True, **kwargs}
        return self.safe_post("api/tools/nmap", data, timeout=120)

    def run_nmap_advanced(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "use_recovery": True, **kwargs}
        return self.safe_post("api/tools/nmap-advanced", data, timeout=180)

    def run_masscan(self, target: str, ports: str = "", rate: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "ports": ports, "rate": rate, **kwargs}
        return self.safe_post("api/tools/masscan", data, timeout=120)

    def run_rustscan(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/rustscan", data, timeout=120)

    def run_autorecon(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/autorecon", data, timeout=300)

    # ══════════════════════════════════════════════════════════════════════
    # WEB SCANNING
    # ══════════════════════════════════════════════════════════════════════

    def run_gobuster(self, url: str, mode: str = "dir", wordlist: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, "mode": mode, "wordlist": wordlist, "use_recovery": True, **kwargs}
        return self.safe_post("api/tools/gobuster", data, timeout=120)

    def run_ffuf(self, url: str, wordlist: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, "wordlist": wordlist, **kwargs}
        return self.safe_post("api/tools/ffuf", data, timeout=120)

    def run_feroxbuster(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/feroxbuster", data, timeout=120)

    def run_nikto(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "use_recovery": True, **kwargs}
        return self.safe_post("api/tools/nikto", data, timeout=180)

    def run_nuclei(self, target: str, severity: str = "", tags: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "severity": severity, "tags": tags, "use_recovery": True, **kwargs}
        return self.safe_post("api/tools/nuclei", data, timeout=180)

    def run_sqlmap(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/sqlmap", data, timeout=180)

    def run_wpscan(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/wpscan", data, timeout=120)

    def run_xsser(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/xsser", data, timeout=120)

    def run_wfuzz(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/wfuzz", data, timeout=120)

    def run_katana(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/katana", data, timeout=120)

    def run_wafw00f(self, url: str, **kwargs: Any) -> dict[str, Any]:
        data = {"url": url, **kwargs}
        return self.safe_post("api/tools/wafw00f", data, timeout=60)

    # ══════════════════════════════════════════════════════════════════════
    # SUBDOMAIN / DNS DISCOVERY
    # ══════════════════════════════════════════════════════════════════════

    def run_amass(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/amass", data, timeout=180)

    def run_subfinder(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/subfinder", data, timeout=120)

    def run_fierce(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        data = {"domain": domain, **kwargs}
        return self.safe_post("api/tools/fierce", data, timeout=120)

    def run_dnsenum(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        data = {"domain": domain, **kwargs}
        return self.safe_post("api/tools/dnsenum", data, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # CLOUD SECURITY
    # ══════════════════════════════════════════════════════════════════════

    def run_prowler(self, provider: str = "aws", **kwargs: Any) -> dict[str, Any]:
        data = {"provider": provider, **kwargs}
        return self.safe_post("api/tools/prowler", data, timeout=300)

    def run_trivy(self, scan_type: str = "image", target: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"scan_type": scan_type, "target": target, **kwargs}
        return self.safe_post("api/tools/trivy", data, timeout=180)

    def run_scout_suite(self, provider: str = "aws", **kwargs: Any) -> dict[str, Any]:
        data = {"provider": provider, **kwargs}
        return self.safe_post("api/tools/scout-suite", data, timeout=300)

    def run_cloudmapper(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/cloudmapper", {**kwargs}, timeout=180)

    def run_pacu(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/pacu", {**kwargs}, timeout=180)

    def run_checkov(self, directory: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"directory": directory, **kwargs}
        return self.safe_post("api/tools/checkov", data, timeout=120)

    def run_terrascan(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/terrascan", {**kwargs}, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # CONTAINER SECURITY
    # ══════════════════════════════════════════════════════════════════════

    def run_kube_hunter(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/kube-hunter", {**kwargs}, timeout=120)

    def run_kube_bench(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/kube-bench", {**kwargs}, timeout=120)

    def run_docker_bench(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/docker-bench-security", {**kwargs}, timeout=120)

    def run_clair(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/clair", {**kwargs}, timeout=120)

    def run_falco(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/falco", {**kwargs}, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # BINARY / REVERSE ENGINEERING
    # ══════════════════════════════════════════════════════════════════════

    def run_gdb(self, binary: str, commands: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, "commands": commands, **kwargs}
        return self.safe_post("api/tools/gdb", data, timeout=120)

    def run_radare2(self, binary: str, commands: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, "commands": commands, **kwargs}
        return self.safe_post("api/tools/radare2", data, timeout=120)

    def run_binwalk(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/binwalk", data, timeout=60)

    def run_checksec(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/checksec", data, timeout=30)

    def run_ghidra(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/ghidra", data, timeout=300)

    def run_strings(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/strings", data, timeout=30)

    def run_objdump(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/objdump", data, timeout=60)

    def run_ropgadget(self, binary: str, **kwargs: Any) -> dict[str, Any]:
        data = {"binary": binary, **kwargs}
        return self.safe_post("api/tools/ropgadget", data, timeout=60)

    # ══════════════════════════════════════════════════════════════════════
    # CREDENTIAL / PASSWORD ATTACKS
    # ══════════════════════════════════════════════════════════════════════

    def run_hydra(self, target: str, service: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, "service": service, **kwargs}
        return self.safe_post("api/tools/hydra", data, timeout=180)

    def run_hashcat(self, hash_file: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"hash_file": hash_file, **kwargs}
        return self.safe_post("api/tools/hashcat", data, timeout=300)

    def run_john(self, hash_file: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"hash_file": hash_file, **kwargs}
        return self.safe_post("api/tools/john", data, timeout=300)

    # ══════════════════════════════════════════════════════════════════════
    # AD / INTERNAL NETWORK
    # ══════════════════════════════════════════════════════════════════════

    def run_enum4linux(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/enum4linux", data, timeout=120)

    def run_enum4linux_ng(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/enum4linux-ng", data, timeout=120)

    def run_smbmap(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/smbmap", data, timeout=120)

    def run_netexec(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/netexec", data, timeout=120)

    def run_responder(self, interface: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"interface": interface, **kwargs}
        return self.safe_post("api/tools/responder", data, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # EXPLOIT / PAYLOAD GENERATION
    # ══════════════════════════════════════════════════════════════════════

    def run_metasploit(self, module: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"module": module, **kwargs}
        return self.safe_post("api/tools/metasploit", data, timeout=180)

    def run_msfvenom(self, payload: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"payload": payload, **kwargs}
        return self.safe_post("api/tools/msfvenom", data, timeout=60)

    def generate_ai_payload(self, description: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"description": description, **kwargs}
        return self.safe_post("api/ai/generate_payload", data, timeout=60)

    def advanced_payload_generation(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/ai/advanced-payload-generation", {**kwargs}, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # API SECURITY TESTING
    # ══════════════════════════════════════════════════════════════════════

    def run_api_fuzzer(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/api_fuzzer", data, timeout=120)

    def run_graphql_scanner(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/graphql_scanner", data, timeout=120)

    def run_jwt_analyzer(self, token: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"token": token, **kwargs}
        return self.safe_post("api/tools/jwt_analyzer", data, timeout=60)

    def run_api_schema_analyzer(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/tools/api_schema_analyzer", data, timeout=120)

    # ══════════════════════════════════════════════════════════════════════
    # FORENSICS / STEGANOGRAPHY
    # ══════════════════════════════════════════════════════════════════════

    def run_volatility3(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/volatility3", {**kwargs}, timeout=180)

    def run_foremost(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/foremost", {**kwargs}, timeout=120)

    def run_steghide(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/steghide", {**kwargs}, timeout=60)

    def run_exiftool(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/exiftool", {**kwargs}, timeout=30)

    # ══════════════════════════════════════════════════════════════════════
    # BOAZ PAYLOAD EVASION
    # ══════════════════════════════════════════════════════════════════════

    def boaz_generate_payload(self, input_file: str, output_file: str, **kwargs: Any) -> dict[str, Any]:
        data = {"input_file": input_file, "output_file": output_file, **kwargs}
        return self.safe_post("api/boaz/generate-payload", data, timeout=300)

    def boaz_list_loaders(self, category: str = "all") -> dict[str, Any]:
        return self.safe_get("api/boaz/list-loaders", {"category": category})

    def boaz_list_encoders(self) -> dict[str, Any]:
        return self.safe_get("api/boaz/list-encoders")

    def boaz_analyze_binary(self, file_path: str) -> dict[str, Any]:
        return self.safe_post("api/boaz/analyze-binary", {"file_path": file_path})

    def boaz_validate_options(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/boaz/validate-options", {**kwargs})

    # ══════════════════════════════════════════════════════════════════════
    # BUG BOUNTY WORKFLOWS
    # ══════════════════════════════════════════════════════════════════════

    def bugbounty_recon(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/reconnaissance-workflow", data, timeout=300)

    def bugbounty_vuln_hunt(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/vulnerability-hunting-workflow", data, timeout=300)

    def bugbounty_business_logic(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/business-logic-workflow", data, timeout=300)

    def bugbounty_osint(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/osint-workflow", data, timeout=300)

    def bugbounty_file_upload(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/file-upload-testing", data, timeout=180)

    def bugbounty_comprehensive(self, target: str, **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/bugbounty/comprehensive-assessment", data, timeout=600)

    # ══════════════════════════════════════════════════════════════════════
    # VULNERABILITY INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════

    def monitor_cve_feeds(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/vuln-intel/cve-monitor", {**kwargs}, timeout=60)

    def generate_exploit_from_cve(self, cve_id: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"cve_id": cve_id, **kwargs}
        return self.safe_post("api/vuln-intel/exploit-generate", data, timeout=120)

    def discover_attack_chains(self, target: str = "", **kwargs: Any) -> dict[str, Any]:
        data = {"target": target, **kwargs}
        return self.safe_post("api/vuln-intel/attack-chains", data, timeout=120)

    def research_zero_day(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/vuln-intel/zero-day-research", {**kwargs}, timeout=120)

    def correlate_threat_intel(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/vuln-intel/threat-feeds", {**kwargs}, timeout=60)

    # ══════════════════════════════════════════════════════════════════════
    # HTTP INTERCEPTION (Burp-like)
    # ══════════════════════════════════════════════════════════════════════

    def http_repeater(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/http-framework", {"action": "repeater", **kwargs}, timeout=60)

    def http_intruder(self, **kwargs: Any) -> dict[str, Any]:
        return self.safe_post("api/tools/http-framework", {"action": "intruder", **kwargs}, timeout=120)

