"""Hypothesis generation from normalized findings.

Expanded with generation rules for SQLi, cloud, container, credential,
exploit, and API signals so the Brain can autonomously escalate to all
tool categories on the HexStrike server.
"""

from __future__ import annotations

from software_butcher.core.asset_classifier import is_static_asset
from software_butcher.core.path_relevance import is_noise_path, score_path
from software_butcher.state.engagement import normalize_engagement_type
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
    SQLI_SIGNALS = ("database error", "syntax error", "union select", "sql injection", "sqlmap")
    SQL_ERROR_SIGNALS = ("database error", "syntax error", "union select", "sql injection", "you have an error in your sql")
    CLOUD_SIGNALS = ("aws", "azure", "gcp", "s3", "ec2", "iam", "cloudtrail")
    CONTAINER_SIGNALS = ("docker", "kubernetes", "k8s", "container", "pod", "kubelet")
    CREDENTIAL_SIGNALS = ("password", "hash", "ntlm", "bcrypt", "credential", "brute")
    EXPLOIT_SIGNALS = ("cve-", "exploit", "rce", "remote code execution", "command injection")
    XSS_SIGNALS = ("xss", "cross-site scripting", "reflected", "stored xss", "dom-based")

    def generate(self, finding: Finding, *, engagement_type: str = "assessment") -> list[Hypothesis]:
        generated: list[Hypothesis] = []
        et = normalize_engagement_type(engagement_type)

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
                admin_intent = "http_surface_map" if et == "assessment" else "web_behavior_analysis"
                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason=(
                            "Admin/auth surface — read headers, forms, and session behavior locally "
                            "before any remote scanner."
                            if et == "assessment"
                            else "Admin/auth surface should receive behavior-level validation."
                        ),
                        source_finding_id=finding.id,
                        priority=0.8,
                        metadata={
                            "intent": admin_intent,
                            "asset_type": finding.asset_type,
                            "generated_by": "content_intel",
                        },
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
                if len(str(tech).split()) >= 2 and any(char.isdigit() for char in str(tech)):
                    if et == "assessment":
                        generated.append(
                            Hypothesis(
                                path=finding.path,
                                reason=(
                                    f"Versioned stack component ({tech}) — reason about CVE viability locally "
                                    "from headers/content before nuclei or sqlmap."
                                ),
                                source_finding_id=finding.id,
                                priority=0.88,
                                metadata={
                                    "intent": "http_surface_map",
                                    "asset_type": finding.asset_type,
                                    "technology": tech,
                                    "generated_by": "stack_cve_intel",
                                    "analysis_focus": "stack_cve_viability",
                                },
                            )
                        )
                    else:
                        generated.append(
                            Hypothesis(
                                path=finding.path,
                                reason=f"Versioned technology detected ({tech}), needs CVE lookup for known exploits.",
                                source_finding_id=finding.id,
                                priority=0.85,
                                metadata={
                                    "intent": "cve_lookup",
                                    "asset_type": finding.asset_type,
                                    "technology": tech,
                                },
                            )
                        )

        meta = finding.metadata or {}
        if meta.get("content_analysis"):
            page_type = str(meta.get("page_type") or "")
            if page_type == "phpinfo":
                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason="phpinfo() disclosure — map full config leak and stack CVE viability before scanners.",
                        source_finding_id=finding.id,
                        priority=0.96,
                        metadata={
                            "intent": "http_surface_map",
                            "asset_type": finding.asset_type,
                            "generated_by": "pii_exposure",
                            "page_type": "phpinfo",
                            "analysis_focus": "pii_exposure",
                        },
                    )
                )
            if page_type == "phpmyadmin":
                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason=(
                            "phpMyAdmin reachable — test broken access control and default creds "
                            "before SQL injection probing."
                        ),
                        source_finding_id=finding.id,
                        priority=0.95,
                        metadata={
                            "intent": "http_surface_map",
                            "asset_type": finding.asset_type,
                            "generated_by": "broken_access",
                            "page_type": "phpmyadmin",
                            "analysis_focus": "broken_access",
                        },
                    )
                )
            if meta.get("stack_cve_viability_checked") or meta.get("stack_cve_candidates"):
                generated.append(
                    Hypothesis(
                        path=finding.path,
                        reason=(
                            "Stack versions observed — continue local CVE viability reasoning "
                            "before generic vulnerability_scanning."
                        ),
                        source_finding_id=finding.id,
                        priority=0.9,
                        metadata={
                            "intent": "http_surface_map",
                            "asset_type": finding.asset_type,
                            "generated_by": "stack_cve_intel",
                            "analysis_focus": "stack_cve_viability",
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

        # SQL injection escalation — assessment requires mysql + forms + SQL error signals
        if finding.asset_type in {"web_endpoint", "api"} and self._has_actionable_sqli_evidence(finding, text):
            priority = 0.55 if et == "assessment" else 0.85
            generated.append(
                Hypothesis(
                    path=finding.path,
                    reason=(
                        "MySQL backend, forms, and SQL error patterns — SQLMap probing may be warranted."
                        if et == "assessment"
                        else "SQL/database signals with confirmed forms — SQLMap probing recommended."
                    ),
                    source_finding_id=finding.id,
                    priority=priority,
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
                conclusions = list(page.get("conclusions") or [])
                mysql_signals = list(page.get("mysql_signals") or [])
                has_resource_exhaustion = any(
                    "resource exhaustion" in c.lower() or "db connection" in c.lower()
                    for c in conclusions
                )

                if page_type in ("phpinfo", "phpmyadmin"):
                    generated.append(
                        Hypothesis(
                            path=url,
                            reason=(
                                f"{page_type} reachable — read login, disclosure, and session behavior locally "
                                "before any HexStrike scanner."
                            ),
                            source_finding_id=finding.id,
                            priority=0.99,
                            metadata={
                                "intent": "http_surface_map",
                                "asset_type": "web_endpoint",
                                "generated_by": "content_intel",
                                "page_type": page_type,
                            },
                        )
                    )
                elif score_path(
                    url,
                    page_context=" ".join(conclusions),
                    organically_discovered=True,
                ) >= 0.85:
                    generated.append(
                        Hypothesis(
                            path=url,
                            reason=(
                                "Application entry identified from content read — map forms, auth, "
                                "and dynamic behavior locally before scanners."
                            ),
                            source_finding_id=finding.id,
                            priority=0.92,
                            metadata={
                                "intent": "http_surface_map",
                                "asset_type": "web_endpoint",
                                "generated_by": "content_intel",
                            },
                        )
                    )

                if page_type == "phpmyadmin" or mysql_signals or has_resource_exhaustion:
                    generated.append(
                        Hypothesis(
                            path=url,
                            reason=(
                                "MySQL/phpMyAdmin stack with backend DB on each request — reason about "
                                "connection pool exhaustion and auth on phpMyAdmin (not gobuster/nuclei)."
                            ),
                            source_finding_id=finding.id,
                            priority=0.97,
                            metadata={
                                "intent": "http_surface_map",
                                "asset_type": "web_endpoint",
                                "generated_by": "mysql_resource_intel",
                                "analysis_focus": "resource_exhaustion",
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

        # ── Deep web-audit follow-ups from a surface map ────────────────────
        # These advance an observed URL to application-logic analysis instead of
        # re-mapping it: redirect-body leaks, security posture/CSRF, phpMyAdmin,
        # resource exhaustion, and version-gated CVE viability.
        if capability == "http_surface_map" and not is_noise_path(finding.path):
            generated.extend(self._web_audit_followups(finding, meta))

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
    def _web_audit_followups(finding: Finding, meta: dict) -> list[Hypothesis]:
        """Seed deep-analysis hypotheses (redirect/posture/phpMyAdmin/DoS/CVE) from a surface map."""
        followups: list[Hypothesis] = []
        path = finding.path

        def _seed(intent: str, reason: str, priority: float, generated_by: str, focus: str | None = None) -> None:
            metadata = {
                "intent": intent,
                "asset_type": "web_endpoint",
                "generated_by": generated_by,
                "organically_discovered": True,
            }
            if focus:
                metadata["analysis_focus"] = focus
            followups.append(
                Hypothesis(
                    path=path,
                    reason=reason,
                    source_finding_id=finding.id,
                    priority=priority,
                    metadata=metadata,
                )
            )

        content_pages = meta.get("content_pages") or []

        # Redirect-body leak (Cursor's #1/#2 confirmed class) — highest value.
        if meta.get("redirect_body_leak_suspected"):
            _seed(
                "redirect_body_audit",
                "A 3xx hop returned a large/structured body — confirm auth-after-render data leak.",
                0.94,
                "redirect_audit",
                focus="redirect_body",
            )

        # Security posture / CSRF — cheap deterministic audit on every mapped URL.
        _seed(
            "security_posture_audit",
            "Audit security headers, cookie flags, and CSRF tokens on this surface.",
            0.7,
            "security_posture",
            focus="security_posture",
        )

        # phpMyAdmin reasoned follow-up.
        page_type = str(meta.get("page_type") or "")
        is_pma = (
            page_type == "phpmyadmin"
            or "phpmyadmin" in path.lower()
            or any(str(p.get("page_type") or "") == "phpmyadmin" for p in content_pages)
        )
        if is_pma:
            _seed(
                "phpmyadmin_assess",
                "phpMyAdmin reachable — assess version, default creds, and version-gated CVEs (not a 403 dead-end).",
                0.9,
                "phpmyadmin_assess",
                focus="broken_access",
            )

        # DoS / resource-exhaustion reasoning on DB-backed / form endpoints.
        has_db_or_forms = bool(meta.get("mysql_signals") or meta.get("form_count")) or any(
            p.get("mysql_signals") or p.get("form_count") for p in content_pages
        )
        if has_db_or_forms:
            _seed(
                "dos_viability",
                "DB-backed/form endpoint — reason about resource exhaustion when rate limiting is absent.",
                0.6,
                "dos_viability",
                focus="resource_exhaustion",
            )

        # Version-gated CVE viability — real capability name (not cve_lookup).
        has_versions = bool(meta.get("php_version") or meta.get("stack_cve_candidates")) or any(
            p.get("php_version") or p.get("stack_cve_candidates") for p in content_pages
        )
        if has_versions and not meta.get("stack_cve_viability_checked"):
            _seed(
                "stack_cve_intel",
                "Observed stack versions — reason about version-gated CVE viability before generic scanners.",
                0.85,
                "stack_cve_intel",
                focus="stack_cve_viability",
            )

        return followups

    @staticmethod
    def _has_actionable_sqli_evidence(finding: Finding, text: str) -> bool:
        """Assessment-grade SQLi escalation: mysql signals + forms + SQL error patterns."""
        meta = finding.metadata or {}
        has_mysql = bool(meta.get("mysql_signals")) or any(
            s in text for s in ("mysqli", "mysql", "pdo_mysql", "mariadb")
        )
        has_forms = HypothesisGenerator._has_actionable_forms(finding)
        has_errors = any(signal in text for signal in HypothesisGenerator.SQL_ERROR_SIGNALS)
        return has_mysql and has_forms and has_errors

    @staticmethod
    def _has_actionable_forms(finding: Finding) -> bool:
        """True when content intel shows forms or input parameters on this finding or nested pages."""
        meta = finding.metadata or {}
        if meta.get("form_count") or meta.get("form_fields"):
            return True
        if any("form" in str(c).lower() for c in (meta.get("conclusions") or [])):
            return True
        for page in meta.get("content_pages") or []:
            if page.get("form_count") or page.get("form_fields"):
                return True
            if any("form" in str(c).lower() for c in (page.get("conclusions") or [])):
                return True
        return False

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
