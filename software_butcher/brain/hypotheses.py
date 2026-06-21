"""Hypothesis generation from normalized findings.

Expanded with generation rules for SQLi, cloud, container, credential,
exploit, and API signals so the Brain can autonomously escalate to all
tool categories on the HexStrike server.
"""

from __future__ import annotations

from software_butcher.core.asset_classifier import is_static_asset
from software_butcher.core.domain_semantics import semantic_path_candidates
from software_butcher.core.path_relevance import is_noise_path, score_path
from software_butcher.core.url_utils import base_web_url
from software_butcher.state.path_graph import parent_path
from software_butcher.state.schema import Finding, Hypothesis


class HypothesisGenerator:
    """Create follow-up work from findings.

    Parent-path hypotheses are owned exclusively by HypothesisQueue.add_from_finding().
    This generator handles only signal-based escalation (admin, api, AD, binary,
    cloud, container, credential, exploit).

    Static assets (CSS, JS, images, fonts) are skipped entirely — they carry
    no security-relevant signals worth escalating.
    """

    ADMIN_SIGNALS = ("admin", "login", "auth", "portal", "signin")
    API_SIGNALS = ("api", "graphql", "swagger", "openapi", "rest")
    AD_SIGNALS = ("ldap", "kerberos", "smb", "active directory", "domain controller")
    BINARY_SIGNALS = ("crash", "overflow", "strcpy", "memcpy", "gets", "format string")

    # ── NEW signal sets ────────────────────────────────────────────────────
    SQLI_SIGNALS = ("sql", "mysql", "database error", "syntax error", "union select", "injection")
    CLOUD_SIGNALS = ("aws", "azure", "gcp", "s3", "ec2", "iam", "cloudtrail")
    CONTAINER_SIGNALS = ("docker", "kubernetes", "k8s", "container", "pod", "kubelet")
    CREDENTIAL_SIGNALS = ("password", "hash", "ntlm", "bcrypt", "credential", "brute")
    EXPLOIT_SIGNALS = ("cve-", "exploit", "rce", "remote code execution", "command injection")
    XSS_SIGNALS = ("xss", "cross-site scripting", "reflected", "stored xss", "dom-based")

    def generate(self, finding: Finding) -> list[Hypothesis]:
        generated: list[Hypothesis] = []

        # Double-guard: skip static assets whether the asset_type was set correctly
        # or the path extension alone reveals the static nature of the resource.
        if finding.asset_type == "static_asset" or is_static_asset(finding.path):
            return generated

        text = self._finding_text(finding)
        # Use path stem for path-based signals to avoid false matches from
        # evidence blobs that happen to mention e.g. "/login.css" as a sibling.
        path_stem = self._path_stem(finding.path)

        if finding.asset_type in {"web_endpoint", "api"}:
            path_score = score_path(finding.path, title=str((finding.metadata or {}).get("title") or ""))
            if path_score >= 0.6 and any(signal in path_stem for signal in self.ADMIN_SIGNALS):

                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason="Admin/auth surface should receive behavior-level validation.",
                        source_finding_id=finding.id,
                        priority=0.8,
                        metadata={"intent": "web_behavior_analysis", "asset_type": finding.asset_type},
                    )
                )

            if any(signal in text for signal in self.API_SIGNALS):
                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason="API surface should be explored for schema, auth, and malformed request behavior.",
                        source_finding_id=finding.id,
                        priority=0.7,
                        metadata={"intent": "api_fuzzing", "asset_type": "api"},
                    )
                )

        if finding.metadata and finding.metadata.get("capability") == "technology_fingerprint":
            technologies = finding.metadata.get("technologies", [])
            for tech in technologies:
                # Basic check for versioned strings (e.g. "PHP 7.2.0", "Apache 2.4.49")
                # This could be improved with regex, but splitting is a start.
                if len(str(tech).split()) >= 2 and any(char.isdigit() for char in str(tech)):
                    generated.append(
                        Hypothesis(
                            path=finding.path,
                            reason=f"Versioned technology detected ({tech}), needs CVE lookup for known exploits.",
                            source_finding_id=finding.id,
                            priority=0.85, # High priority for known vuln lookups
                            metadata={
                                "intent": "cve_lookup", 
                                "asset_type": finding.asset_type,
                                "technology": tech
                            },
                        )
                    )

        if any(signal in text for signal in self.AD_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="AD-like evidence warrants controlled emulation planning if frameworks are available.",
                    source_finding_id=finding.id,
                    priority=0.75,
                    metadata={"intent": "validate_ad_emulation", "asset_type": "ad_environment"},
                )
            )

        if (
            not finding.provenance.startswith("binary_triage")
            and (finding.asset_type == "binary" or any(signal in text for signal in self.BINARY_SIGNALS))
        ):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="Binary evidence warrants deeper reverse-engineering and fuzzing triage.",
                    source_finding_id=finding.id,
                    priority=0.75,
                    metadata={"intent": "reverse_engineer", "asset_type": "binary"},
                )
            )

        # ── NEW: SQL injection escalation ────────────────────────────────
        if finding.asset_type in {"web_endpoint", "api"} and any(signal in text for signal in self.SQLI_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="SQL/database signals detected — SQLMap probing recommended.",
                    source_finding_id=finding.id,
                    priority=0.85,
                    metadata={"intent": "sql_injection_probing", "asset_type": finding.asset_type},
                )
            )

        # ── NEW: XSS escalation ──────────────────────────────────────────
        if finding.asset_type in {"web_endpoint", "api"} and any(signal in text for signal in self.XSS_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="XSS signals detected — XSS scanning recommended.",
                    source_finding_id=finding.id,
                    priority=0.8,
                    metadata={"intent": "xss_scanning", "asset_type": finding.asset_type},
                )
            )

        # ── NEW: Cloud escalation ────────────────────────────────────────
        if any(signal in text for signal in self.CLOUD_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="Cloud service signals detected — cloud security audit recommended.",
                    source_finding_id=finding.id,
                    priority=0.75,
                    metadata={"intent": "cloud_security_audit", "asset_type": "cloud_account"},
                )
            )

        # ── NEW: Container escalation ────────────────────────────────────
        if any(signal in text for signal in self.CONTAINER_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="Container/Kubernetes signals detected — container security scan recommended.",
                    source_finding_id=finding.id,
                    priority=0.75,
                    metadata={"intent": "container_security", "asset_type": "container"},
                )
            )

        # ── NEW: Credential attack escalation ────────────────────────────
        if any(signal in text for signal in self.CREDENTIAL_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="Credential/password signals detected — brute force or cracking recommended.",
                    source_finding_id=finding.id,
                    priority=0.7,
                    metadata={"intent": "credential_attack", "asset_type": finding.asset_type},
                )
            )

        # ── NEW: Exploit generation escalation ───────────────────────────
        if any(signal in text for signal in self.EXPLOIT_SIGNALS):
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason="CVE/exploit signals detected — Metasploit/exploit generation recommended.",
                    source_finding_id=finding.id,
                    priority=0.9,
                    metadata={"intent": "exploit_generation", "asset_type": finding.asset_type},
                )
            )

        # Auth escalation: when an auth_bypass is confirmed, generate a
        # high-priority hypothesis for authenticated discovery of the root
        # path.  This is what unlocks post-auth surface like /dvwa/vulnerabilities/.
        capability = finding.metadata.get("capability") if finding.metadata else None

        # Default stack at root (XAMPP) — real app is elsewhere; read content before scanners
        stack_landing = (finding.metadata or {}).get("stack_landing") or {}
        if capability == "http_surface_map" and stack_landing.get("detected"):
            base = base_web_url(finding.path)
            ctx = str((finding.metadata or {}).get("engagement_context") or "")
            content_pages = (finding.metadata or {}).get("content_pages") or []
            analyzed_urls = {str(p.get("url", "")).rstrip("/").lower() for p in content_pages}

            for page in content_pages:
                url = str(page.get("url") or "")
                if not url or is_noise_path(url):
                    continue
                page_type = str(page.get("page_type") or "html")
                if page_type in ("phpinfo", "phpmyadmin"):
                    generated.append(
                        Hypothesis(
                            path=url,
                            reason=(
                                f"{page_type} reachable — analyze login, disclosure, and session behavior "
                                "before generic scanners."
                            ),
                            source_finding_id=finding.id,
                            priority=0.99,
                            metadata={
                                "intent": "web_behavior_analysis",
                                "asset_type": "web_endpoint",
                                "generated_by": "content_intel",
                            },
                        )
                    )
                elif score_path(url) >= 0.85:
                    generated.append(
                        Hypothesis(
                            path=url,
                            reason=(
                                "Application entry identified from content read — analyze forms, auth, "
                                "and dynamic behavior before scanners."
                            ),
                            source_finding_id=finding.id,
                            priority=0.92,
                            metadata={
                                "intent": "web_behavior_analysis",
                                "asset_type": "web_endpoint",
                                "generated_by": "content_intel",
                            },
                        )
                    )

            for cand in semantic_path_candidates(base, engagement_context=ctx):
                url = str(cand["url"])
                if url.rstrip("/").lower() in analyzed_urls:
                    continue
                if score_path(url) < 0.5:
                    continue
                generated.append(
                    Hypothesis(
                        path=url,
                        reason=cand["rationale"],
                        source_finding_id=finding.id,
                        priority=float(cand["score"]),
                        metadata={
                            "intent": "http_surface_map",
                            "asset_type": "web_endpoint",
                            "generated_by": "domain_semantics",
                            "semantic_token": cand["token"],
                        },
                    )
                )
            if finding.metadata.get("browser_final_url"):
                bf = str(finding.metadata["browser_final_url"])
                if score_path(bf) >= 0.5 and not is_noise_path(bf):
                    generated.append(
                        Hypothesis(
                            path=bf,
                            reason="Headless browser reached a different URL than HTTP client — map application entry.",
                            source_finding_id=finding.id,
                            priority=0.98,
                            metadata={
                                "intent": "http_surface_map",
                                "asset_type": "web_endpoint",
                                "generated_by": "browser_divergence",
                            },
                        )
                    )

        if capability == "auth_bypass_confirmed":
            # Walk up to the site root for authenticated crawling
            root = finding.path
            while True:
                p = parent_path(root)
                if p is None or p == root:
                    break
                root = p
            if root != finding.path:
                generated.append(
                    Hypothesis(
                        path=root,
                        reason=f"Authenticated surface exploration after successful bypass at {finding.path}.",
                        source_finding_id=finding.id,
                        priority=0.95,
                        metadata={
                            "intent": "authenticated_discovery",
                            "authenticated": True,
                            "asset_type": finding.asset_type,
                            "generated_by": "auth_escalation",
                        },
                    )
                )

        return generated

    @staticmethod
    def _finding_text(finding: Finding) -> str:
        return "\n".join(
            [
                finding.hypothesis,
                finding.path,
                finding.provenance,
                " ".join(finding.evidence),
                str(finding.metadata),
            ]
        ).lower()

    @staticmethod
    def _path_stem(path: str) -> str:
        """Return the lowercase filename stem of a path, without extension.

        e.g. '/admin/login.php' → 'login'
             '/api/v1/auth'     → 'auth'
             '/dvwa/'           → 'dvwa'

        Used for ADMIN_SIGNALS matching so that signals in the file extension
        or path prefixes don't create false positives.
        """
        segment = path.rstrip("/").split("/")[-1].lower()
        if "." in segment:
            segment = segment.rsplit(".", 1)[0]
        return segment
