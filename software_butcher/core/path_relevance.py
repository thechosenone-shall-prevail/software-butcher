"""Score discovered URLs — deprioritize XAMPP boilerplate, elevate real application paths."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from software_butcher.state.schema import Finding, Hypothesis

# XAMPP / default-hosting documentation — not the target application
NOISE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/dashboard/(faq|howto|index)\.html$", re.I),
    re.compile(r"/dashboard/(de|fr|es|pl|zh_|ja|tr|pt|ro|ru|it|hu|pt_br)/?$", re.I),
    re.compile(r"/dashboard/Images/?$", re.I),
    re.compile(r"/dashboard/docs/", re.I),
    re.compile(r"privacy_policy\.html$", re.I),
    re.compile(r"/licenses/", re.I),
    re.compile(r"/webalizer/", re.I),
    re.compile(r"/icons/", re.I),
    re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?)$", re.I),
    re.compile(r"/(css|js|Images|images|vendor|assets|static)/?$", re.I),
    re.compile(r"/[^/]+/(css|js|Images|images|vendor|assets|static|PHP)/?$", re.I),
)

# Paths that likely belong to the actual engagement application
APP_PATH_SIGNALS: tuple[str, ...] = (
    "hall",
    "booking",
    "book",
    "portal",
    "login",
    "signin",
    "auth",
    "register",
    "student",
    "faculty",
    "reservation",
    "apply",
    "app",
)

XAMPP_TITLE_SIGNALS = ("xampp", "welcome to xampp", "apache friends")
XAMPP_BODY_SIGNALS = ("xampp for linux", "apache friends", "phpmyadmin", "dashboard/index.html")

ORGANIC_GENERATORS = frozenset(
    {
        "html_link",
        "redirect",
        "robots",
        "sitemap",
        "discovered_path",
        "tool_output",
        "parent_path_rule",
        "content_intel",
        "mysql_resource_intel",
        "stack_cve_intel",
        "broken_access",
        "pii_exposure",
        "browser_divergence",
        "auth_escalation",
        "recon_checklist",
        "domain_seed",
        "asset_expander",
        "escalation_ladder",
        "redirect_audit",
        "security_posture",
        "phpmyadmin_assess",
        "dos_viability",
    }
)

SEED_GENERATORS = frozenset({"recon_checklist", "domain_seed"})


def path_segment(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.path or "/").lower()


def _normalize_path_key(path: str) -> str:
    raw = (path or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"https://placeholder{raw}")
    return (parsed.path or raw).rstrip("/").lower()


def _paths_match(a: str, b: str) -> bool:
    return _normalize_path_key(a) == _normalize_path_key(b)


def _finding_mentions_path(finding: Finding, path: str) -> bool:
    """True when the finding's evidence or content intel organically references *path*."""
    path_key = _normalize_path_key(path)
    if not path_key:
        return False

    meta = finding.metadata or {}
    for page in meta.get("content_pages") or []:
        page_url = str(page.get("url") or "")
        if _paths_match(page_url, path):
            return True
        for conclusion in page.get("conclusions") or []:
            if path_key in _normalize_path_key(str(conclusion)):
                return True

    for probe in meta.get("semantic_probes") or []:
        if probe.get("reachable") and _paths_match(str(probe.get("url") or ""), path):
            return True

    for url in (
        *(meta.get("discovered_urls") or []),
        *(meta.get("all_discovered_urls") or []),
    ):
        if _paths_match(str(url), path):
            return True

    if _paths_match(finding.path, path):
        generated_by = str(meta.get("generated_by") or "")
        if generated_by in ORGANIC_GENERATORS or meta.get("content_analysis"):
            return True

    blob = "\n".join([finding.path, finding.hypothesis, *finding.evidence]).lower()
    if path_key in blob:
        return True

    return False


def _trace_source_finding(
    finding_id: str,
    findings: dict[str, Finding],
    *,
    visited: set[str] | None = None,
) -> Finding | None:
    if not finding_id or finding_id.startswith("phase:"):
        return None
    if visited is None:
        visited = set()
    if finding_id in visited:
        return None
    visited.add(finding_id)
    return findings.get(finding_id)


def hypothesis_has_evidence_lineage(
    hypothesis: Hypothesis,
    findings: dict[str, Finding],
    *,
    engagement_type: str = "assessment",
    session_store=None,
) -> bool:
    """Admit hypotheses whose paths trace to organic discovery or explicit CTF shell work."""
    meta = hypothesis.metadata or {}
    generated_by = str(meta.get("generated_by") or "")

    if meta.get("organically_discovered"):
        return True

    if generated_by in SEED_GENERATORS:
        return True

    if generated_by in ORGANIC_GENERATORS:
        return True

    if generated_by == "domain_semantics":
        source = _trace_source_finding(hypothesis.source_finding_id, findings)
        if source and (source.metadata or {}).get("stack_landing", {}).get("detected"):
            return True

    if generated_by == "semantic_probe" and meta.get("reachable"):
        return True

    # CTF/lab phase hypotheses with active shell session
    if engagement_type in {"ctf", "lab"} or _has_captured_flags(findings):
        if hypothesis.source_finding_id.startswith("phase:"):
            if meta.get("intent") == "shell_command_execution" and _has_active_shell(session_store):
                return True
            if meta.get("flag_target") and _has_active_shell(session_store):
                return True

    source = _trace_source_finding(hypothesis.source_finding_id, findings)
    if source and _finding_mentions_path(source, hypothesis.path):
        return True

    # Walk linked findings for content-intel chains
    if source:
        for linked_id in source.linked_findings:
            linked = _trace_source_finding(linked_id, findings)
            if linked and _finding_mentions_path(linked, hypothesis.path):
                return True

    return False


def _has_captured_flags(findings: dict[str, Finding]) -> bool:
    from software_butcher.state.convergence import detect_flags

    for finding in findings.values():
        blob = " ".join(finding.evidence) + " " + finding.hypothesis
        if detect_flags(blob):
            return True
    return False


def _has_active_shell(session_store) -> bool:
    if session_store and hasattr(session_store, "shell_sessions"):
        return any(s.active for s in session_store.shell_sessions.sessions.values())
    return False


def is_noise_path(url: str) -> bool:
    path = path_segment(url)
    if path in {"/", ""}:
        return False
    return any(pattern.search(path) for pattern in NOISE_PATH_PATTERNS)


def score_path(
    url: str,
    *,
    title: str = "",
    page_context: str = "",
    organically_discovered: bool = False,
) -> float:
    """Return 0.0 (ignore) – 1.0 (investigate first)."""
    if is_noise_path(url):
        return 0.05

    path = path_segment(url)
    text = f"{path} {title} {page_context}".lower()

    score = 0.45
    if "/api" in path or "swagger" in text or "openapi" in text:
        score = max(score, 0.78)
    for signal in APP_PATH_SIGNALS:
        if signal in path or signal in text:
            score = max(score, 0.92 if signal == "hall" else 0.85)

    if path.rstrip("/") == "/dashboard":
        return 0.15

    if organically_discovered and ("phpmyadmin" in path or "phpinfo" in path):
        score = max(score, 0.88)

    if path.startswith("/dashboard/") and "phpinfo" not in path:
        return 0.12

    if path.endswith(".html") and "/dashboard" not in path:
        score = max(score, 0.5)

    return min(score, 1.0)


def priority_for_score(score: float) -> float:
    return round(0.45 + score * 0.55, 2)


def should_queue_path(
    url: str,
    *,
    title: str = "",
    page_context: str = "",
    min_score: float = 0.4,
    organically_discovered: bool = False,
) -> bool:
    return score_path(
        url,
        title=title,
        page_context=page_context,
        organically_discovered=organically_discovered,
    ) >= min_score


def detect_default_stack_landing(
    *,
    title: str = "",
    body: str = "",
    headers: dict[str, str] | None = None,
    final_url: str = "",
) -> dict[str, str | bool]:
    """Detect when the mapped page is a default stack landing (e.g. XAMPP), not the real app."""
    title_l = (title or "").lower()
    body_l = (body or "")[:8000].lower()
    path = path_segment(final_url)

    is_xampp = any(s in title_l for s in XAMPP_TITLE_SIGNALS) or any(s in body_l for s in XAMPP_BODY_SIGNALS)
    is_dashboard_root = path.rstrip("/") == "/dashboard" or path.startswith("/dashboard/")

    if is_xampp or (is_dashboard_root and "apache" in body_l):
        return {
            "detected": True,
            "stack": "xampp_default",
            "conclusion": (
                "Root serves default XAMPP/dashboard content, not the primary application. "
                "Organic links from this page are stack documentation — not the booking portal. "
                "Use headless browser navigation and scoped directory discovery to find unlinked app paths."
            ),
        }
    return {"detected": False, "stack": "", "conclusion": ""}


def summarize_page_content(title: str, body: str, *, limit: int = 400) -> str:
    """Extract a short human-readable summary from HTML for Brain context."""
    if title:
        snippet = title.strip()
    else:
        stripped = re.sub(r"<[^>]+>", " ", body or "")
        stripped = re.sub(r"\s+", " ", stripped).strip()
        snippet = stripped[:limit]
    return snippet[:limit]
