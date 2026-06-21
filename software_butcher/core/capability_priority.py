"""Assessment-mode capability priority — modern web app assessor ordering."""

from __future__ import annotations

# Highest priority first; sqlmap/generic scanners are last resort in assessment.
ASSESSMENT_CAPABILITY_PRIORITY: tuple[str, ...] = (
    "http_surface_map",
    "cve_lookup",
    "web_behavior_analysis",
    "api_enumeration",
    "api_fuzzing",
    "credential_attack",
    "port_scanning",
    "cms_scanning",
    "xss_scanning",
    "exploit_generation",
    "authenticated_discovery",
    "technology_fingerprint",
    "bugbounty_osint",
    "bugbounty_recon",
    "bugbounty_comprehensive",
    "endpoint_discovery",
    "directory_bruteforce",
    "vulnerability_scanning",
    "sql_injection_probing",
)

ASSESSMENT_DEPRIORITIZED: frozenset[str] = frozenset({
    "sql_injection_probing",
    "directory_bruteforce",
    "endpoint_discovery",
    "vulnerability_scanning",
    "bugbounty_recon",
    "bugbounty_osint",
    "bugbounty_comprehensive",
    "technology_fingerprint",
})

ASSESSMENT_GENERIC_SCANNERS: frozenset[str] = frozenset({
    "vulnerability_scanning",
    "directory_bruteforce",
    "endpoint_discovery",
    "technology_fingerprint",
    "bugbounty_recon",
    "bugbounty_osint",
    "bugbounty_comprehensive",
})


def assessment_capability_rank(capability: str) -> int:
    """Lower rank = higher priority in assessment mode."""
    name = (capability or "").lower()
    try:
        return ASSESSMENT_CAPABILITY_PRIORITY.index(name)
    except ValueError:
        return len(ASSESSMENT_CAPABILITY_PRIORITY)


def is_assessment_deprioritized(capability: str) -> bool:
    return (capability or "").lower() in ASSESSMENT_DEPRIORITIZED
