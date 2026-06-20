"""Deterministic Brain policy before model reasoning is added.

This is intentionally simple and auditable. Frontier model planning can sit on
top later, but the first pass should make predictable routing decisions from
finding evidence.

Expanded with signal sets for cloud, container, credential, API, and exploit
evidence so the Brain can escalate to all tool categories.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from software_butcher.core.assets import Asset
from software_butcher.core.health import FrameworkHealth
from software_butcher.state.schema import Finding


@dataclass(frozen=True)
class PolicyDecision:
    """What the Brain should do next for an asset."""

    intent: str
    asset: Asset
    preferred_adapter: str
    reason: str
    options: dict = field(default_factory=dict)


class BrainPolicy:
    """Evidence-based escalation policy.

    Default rule:
      Unknown/IP/domain/web assets start with HexStrike discovery.

    Escalation rule:
      Move to frameworks only after discovery evidence indicates a matching
      asset class or validation need.
    """

    AD_SIGNALS = (
        "ldap",
        "kerberos",
        "domain controller",
        "active directory",
        "smb",
        "netlogon",
        "winrm",
        "bloodhound",
    )
    CLOUD_SIGNALS = (
        "aws",
        "azure",
        "gcp",
        "iam",
        "s3",
        "ec2",
        "cloudtrail",
        "service account",
    )
    BINARY_SIGNALS = (
        "portable executable",
        "elf",
        "macho",
        ".exe",
        ".dll",
        "downloaded binary",
        "firmware",
    )
    WEB_BEHAVIOR_SIGNALS = (
        "admin",
        "auth",
        "login",
        "session",
        "csrf",
        "redirect",
        "malformed",
        "weird endpoint",
    )
    # ── NEW signal sets ────────────────────────────────────────────────────
    CONTAINER_SIGNALS = (
        "docker",
        "kubernetes",
        "k8s",
        "container",
        "pod",
        "helm",
        "kube-apiserver",
        "etcd",
        "kubelet",
    )
    CREDENTIAL_SIGNALS = (
        "password",
        "credential",
        "hash",
        "ntlm",
        "bcrypt",
        "sha256",
        "brute force",
        "login form",
        "basic auth",
    )
    API_SIGNALS = (
        "graphql",
        "swagger",
        "openapi",
        "rest api",
        "jwt",
        "bearer token",
        "api key",
        "oauth",
    )
    SQLI_SIGNALS = (
        "sql",
        "mysql",
        "postgres",
        "sqlite",
        "mssql",
        "injection",
        "database error",
        "syntax error",
        "union select",
    )
    EXPLOIT_SIGNALS = (
        "cve-",
        "exploit",
        "remote code execution",
        "rce",
        "buffer overflow",
        "command injection",
        "deserialization",
    )
    IAC_SIGNALS = (
        "terraform",
        "cloudformation",
        "ansible",
        "infrastructure as code",
        "iac",
        "helm chart",
        "k8s manifest",
    )

    def __init__(self, health: FrameworkHealth | None = None) -> None:
        self.health = health

    def decide(self, asset: Asset, findings: list[Finding]) -> PolicyDecision:
        # Static assets are never escalated — they are not interactive endpoints.
        # Return them immediately to hexstrike for minimal recording only.
        if asset.asset_type == "static_asset":
            return PolicyDecision(
                intent="continue_discovery",
                asset=asset,
                preferred_adapter="hexstrike",
                reason="Static asset (CSS/JS/image/font) — no escalation, record and continue discovery.",
            )

        # Scope evidence strictly to this asset's path lineage.
        # This prevents global evidence pollution: finding /login.php must NOT
        # cause every subsequent unrelated asset to route to playwright.
        scoped_findings = self._relevant_findings(asset, findings)

        # Re-enter with scoped findings — skip the static_asset check (already done)
        return self._decide_with_evidence(asset, scoped_findings)

    def _decide_with_evidence(self, asset: Asset, findings: list[Finding]) -> PolicyDecision:
        if not findings:
            if asset.asset_type == "binary":
                return PolicyDecision(
                    intent="reverse_engineer",
                    asset=asset,
                    preferred_adapter="binary_triage",
                    reason="User supplied an explicit binary asset; start in binary triage.",
                )
            if asset.asset_type == "cloud_account":
                adapter = "stratus_red_team" if self._available("stratus_red_team") else "hexstrike"
                return PolicyDecision(
                    intent="validate_cloud_attack_path" if adapter == "stratus_red_team" else "fingerprint",
                    asset=asset,
                    preferred_adapter=adapter,
                    reason="User supplied a cloud asset; using Stratus if available, otherwise discovery.",
                )
            if asset.asset_type == "ad_environment":
                adapter = self._first_available(("caldera", "atomic_red_team")) or "hexstrike"
                return PolicyDecision(
                    intent="validate_ad_emulation" if adapter != "hexstrike" else "fingerprint",
                    asset=asset,
                    preferred_adapter=adapter,
                    reason="User supplied an AD asset; using emulation if available, otherwise discovery.",
                    options={"execute": False},
                )
            if asset.asset_type == "container":
                return PolicyDecision(
                    intent="container_security",
                    asset=asset,
                    preferred_adapter="hexstrike",
                    reason="User supplied a container asset; start with container security scanning.",
                )
            if asset.asset_type == "iac_config":
                return PolicyDecision(
                    intent="iac_scanning",
                    asset=asset,
                    preferred_adapter="hexstrike",
                    reason="User supplied an IaC config; start with Checkov/Terrascan scanning.",
                )
            if asset.asset_type in {"web_endpoint", "api", "domain"}:
                return PolicyDecision(
                    intent="web_behavior_analysis",
                    asset=asset,
                    preferred_adapter="playwright_curl",
                    reason="No evidence yet; start with HTTP behavior and header analysis.",
                    options={"capability": "web_behavior_analysis"},
                )
            return PolicyDecision(
                intent="discover",
                asset=asset,
                preferred_adapter="hexstrike",
                reason="No evidence exists yet; start with HexStrike discovery.",
            )

        evidence = self._evidence_text(findings)

        if asset.asset_type == "binary" or self._contains(evidence, self.BINARY_SIGNALS):
            return PolicyDecision(
                intent="reverse_engineer",
                asset=Asset(locator=asset.locator, asset_type="binary", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter="binary_triage",
                reason="Discovery evidence indicates a binary or firmware-like asset.",
            )

        if asset.asset_type == "cloud_account" or self._contains(evidence, self.CLOUD_SIGNALS):
            adapter = "stratus_red_team" if self._available("stratus_red_team") else "hexstrike"
            return PolicyDecision(
                intent="validate_cloud_attack_path" if adapter == "stratus_red_team" else "continue_discovery",
                asset=Asset(locator=asset.locator, asset_type="cloud_account", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter=adapter,
                reason="Discovery evidence indicates cloud-control-plane validation is relevant."
                if adapter == "stratus_red_team"
                else "Cloud evidence found, but Stratus is unavailable; continue discovery.",
            )

        if asset.asset_type == "ad_environment" or self._contains(evidence, self.AD_SIGNALS):
            adapter = self._first_available(("caldera", "atomic_red_team")) or "hexstrike"
            return PolicyDecision(
                intent="validate_ad_emulation" if adapter != "hexstrike" else "continue_discovery",
                asset=Asset(locator=asset.locator, asset_type="ad_environment", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter=adapter,
                reason=f"Discovery evidence indicates AD/internal Windows environment; using {adapter}."
                if adapter != "hexstrike"
                else "AD evidence found, but emulation frameworks are unavailable; continue HexStrike/Kali discovery.",
                options={"execute": False},
            )

        # ── NEW: Container evidence ──────────────────────────────────────
        if asset.asset_type == "container" or self._contains(evidence, self.CONTAINER_SIGNALS):
            return PolicyDecision(
                intent="container_security",
                asset=Asset(locator=asset.locator, asset_type="container", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates container/Kubernetes environment; using HexStrike container security tools.",
            )

        # ── NEW: IaC evidence ────────────────────────────────────────────
        if self._contains(evidence, self.IAC_SIGNALS):
            return PolicyDecision(
                intent="iac_scanning",
                asset=Asset(locator=asset.locator, asset_type="iac_config", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates IaC configuration; using Checkov/Terrascan.",
            )

        # ── NEW: SQL injection evidence ──────────────────────────────────
        if asset.asset_type in {"web_endpoint", "api"} and self._contains(evidence, self.SQLI_SIGNALS):
            return PolicyDecision(
                intent="sql_injection_probing",
                asset=asset,
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates potential SQL injection vulnerability.",
            )

        # ── NEW: API-specific evidence ───────────────────────────────────
        if asset.asset_type in {"web_endpoint", "api"} and self._contains(evidence, self.API_SIGNALS):
            return PolicyDecision(
                intent="api_fuzzing",
                asset=Asset(locator=asset.locator, asset_type="api", parent=asset.parent, metadata=asset.metadata),
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates API surface worth fuzzing (GraphQL/Swagger/JWT).",
            )

        # ── NEW: Credential evidence ─────────────────────────────────────
        if self._contains(evidence, self.CREDENTIAL_SIGNALS):
            return PolicyDecision(
                intent="credential_attack",
                asset=asset,
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates credential/password attack surface.",
            )

        # ── NEW: Exploit-ready evidence ──────────────────────────────────
        if self._contains(evidence, self.EXPLOIT_SIGNALS):
            return PolicyDecision(
                intent="exploit_generation",
                asset=asset,
                preferred_adapter="hexstrike",
                reason="Discovery evidence indicates known CVE or exploit-ready vulnerability.",
            )

        if asset.asset_type in {"web_endpoint", "api"} and self._contains(evidence, self.WEB_BEHAVIOR_SIGNALS):
            return PolicyDecision(
                intent="web_behavior_analysis",
                asset=asset,
                preferred_adapter="playwright_curl",
                reason="Discovery evidence indicates behavior-sensitive web testing is useful.",
            )

        return PolicyDecision(
            intent="continue_discovery",
            asset=asset,
            preferred_adapter="hexstrike",
            reason="Evidence is not strong enough to escalate beyond discovery.",
        )

    @staticmethod
    def _relevant_findings(asset: Asset, findings: list[Finding]) -> list[Finding]:
        """Return only findings in the same path lineage as *asset*.

        We match on:
        - exact path match
        - findings whose parent_path equals the asset locator
        - findings that share the same asset_type (for type-level escalation checks
          like binary / cloud / AD) — but exclude static_asset to prevent bleed.
        """
        locator = asset.locator.rstrip("/")
        relevant: list[Finding] = []
        for finding in findings:
            if finding.asset_type == "static_asset":
                continue  # static findings never influence routing decisions
            path = finding.path.rstrip("/")
            parent = (finding.parent_path or "").rstrip("/")
            if path == locator or parent == locator or path.startswith(locator + "/"):
                relevant.append(finding)
                continue
            # Allow type-level escalation signals (AD/cloud/binary) from any finding,
            # but only for non-web asset types to avoid the playwright flood
            if asset.asset_type not in {"web_endpoint", "api"} and finding.asset_type == asset.asset_type:
                relevant.append(finding)
        return relevant

    @staticmethod
    def _evidence_text(findings: list[Finding]) -> str:
        chunks: list[str] = []
        for finding in findings:
            chunks.extend(
                [
                    finding.hypothesis,
                    finding.path,
                    finding.provenance,
                    " ".join(finding.evidence),
                    str(finding.metadata),
                ]
            )
        return "\n".join(chunks).lower()

    @staticmethod
    def _contains(text: str, signals: tuple[str, ...]) -> bool:
        return any(signal in text for signal in signals)

    def _available(self, adapter: str) -> bool:
        if self.health is None:
            return True
        return self.health.available(adapter)

    def _first_available(self, adapters: tuple[str, ...]) -> str | None:
        for adapter in adapters:
            if self._available(adapter):
                return adapter
        return None
