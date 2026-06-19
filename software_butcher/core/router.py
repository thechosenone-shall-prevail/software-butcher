"""Route assets to the right shelf without duplicating HexStrike tools."""

from __future__ import annotations

from dataclasses import dataclass

from .assets import Asset


@dataclass(frozen=True)
class RouteDecision:
    """A Brain-readable routing decision."""

    shelf: str
    adapter: str
    reason: str


class AssetRouter:
    """Asset router for Software Butcher shelves.

    Expanded to cover all asset types: container, iac_config, api (explicit),
    in addition to the original ip/domain/web/binary/cloud/ad routing.
    """

    def route(self, asset: Asset, intent: str = "discover") -> RouteDecision:
        # ── Web / Network assets ──────────────────────────────────────────
        if asset.asset_type in {"ip", "domain", "web_endpoint", "api"}:
            if intent in {"discover", "enrich", "fingerprint", "continue_discovery",
                          "authenticated_discovery"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason="Use existing HexStrike common tools for discovery and enrichment.",
                )
            if intent in {"web_behavior_analysis"}:
                return RouteDecision(
                    shelf="web",
                    adapter="playwright_curl",
                    reason="Use browser and request-level analysis for web behavior validation.",
                )
            # Capability-specific routing — keeps traffic on hexstrike for
            # structured tool endpoints
            if intent in {"port_scanning", "vulnerability_scanning",
                          "sql_injection_probing", "directory_bruteforce",
                          "xss_scanning", "cms_scanning", "credential_attack",
                          "api_fuzzing", "exploit_generation", "ai_attack_chain",
                          "technology_fingerprint", "bugbounty_recon",
                          "bugbounty_comprehensive", "ad_enumeration"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason=f"Use HexStrike server's dedicated {intent} endpoint.",
                )
            return RouteDecision(
                shelf="web",
                adapter="playwright_curl",
                reason="Use browser and request-level analysis for web behavior validation.",
            )

        # ── Binary assets ─────────────────────────────────────────────────
        if asset.asset_type == "binary":
            if intent in {"binary_analysis"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason="Use HexStrike server's binary RE tools (radare2, ghidra, gdb).",
                )
            if intent in {"payload_evasion", "oss_fuzzing", "deep_fuzz"}:
                return RouteDecision(
                    shelf="frameworks",
                    adapter="boaz",
                    reason="Binary requires BOAZ evasion framework or deep fuzzing.",
                )
            return RouteDecision(
                shelf="binary",
                adapter="binary_triage",
                reason="Binary asset requires reverse engineering, fuzzing, and memory-corruption triage.",
            )

        # ── Source code repositories ──────────────────────────────────────
        if asset.asset_type == "source_repo":
            if intent in {"iac_scanning"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason="Use HexStrike server's Checkov/Terrascan for IaC scanning.",
                )
            return RouteDecision(
                shelf="code",
                adapter="code_analysis",
                reason="Source repository requires static analysis and optional fuzz harness generation.",
            )

        # ── Cloud accounts ────────────────────────────────────────────────
        if asset.asset_type == "cloud_account":
            if intent in {"cloud_security_audit"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason="Use HexStrike server's Prowler/ScoutSuite for cloud auditing.",
                )
            return RouteDecision(
                shelf="frameworks",
                adapter="stratus_red_team",
                reason="Cloud asset should be validated with controlled attack simulation.",
            )

        # ── AD / Enterprise environments ──────────────────────────────────
        if asset.asset_type == "ad_environment":
            if intent in {"ad_enumeration"}:
                return RouteDecision(
                    shelf="hexstrike",
                    adapter="hexstrike",
                    reason="Use HexStrike server's enum4linux/smbmap/netexec for AD enumeration.",
                )
            return RouteDecision(
                shelf="frameworks",
                adapter="caldera",
                reason="Enterprise environment should use adversary emulation campaigns.",
            )

        # ── Container assets (NEW) ────────────────────────────────────────
        if asset.asset_type == "container":
            return RouteDecision(
                shelf="hexstrike",
                adapter="hexstrike",
                reason="Container assets should use HexStrike server's kube-hunter/docker-bench tools.",
            )

        # ── IaC config assets (NEW) ───────────────────────────────────────
        if asset.asset_type == "iac_config":
            return RouteDecision(
                shelf="hexstrike",
                adapter="hexstrike",
                reason="IaC config should use HexStrike server's Checkov/Terrascan tools.",
            )

        # ── Fallback ──────────────────────────────────────────────────────
        return RouteDecision(
            shelf="hexstrike",
            adapter="hexstrike",
            reason="Unknown asset starts with conservative discovery through existing HexStrike tools.",
        )
