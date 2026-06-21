"""Resolve LLM-requested capability names to real registry capabilities.

The advisor LLM sometimes emits a plausible-but-unregistered name (the classic
case: it asked for ``cve_lookup`` when the real capability is
``stack_cve_intel``). Rather than silently dropping to policy fallback and
wasting a Brain step, we map known synonyms and fall back to a conservative
fuzzy match against the *actual* registered capability names.
"""

from __future__ import annotations

import difflib
from typing import Iterable

# Known hallucinations / synonyms → real registered capability names.
CAPABILITY_ALIASES: dict[str, str] = {
    "cve_lookup": "stack_cve_intel",
    "cve_scan": "stack_cve_intel",
    "cve_check": "stack_cve_intel",
    "cve_viability": "stack_cve_intel",
    "stack_cve": "stack_cve_intel",
    "header_audit": "security_posture_audit",
    "headers_audit": "security_posture_audit",
    "security_headers": "security_posture_audit",
    "csrf_check": "security_posture_audit",
    "csrf_audit": "security_posture_audit",
    "cookie_audit": "security_posture_audit",
    "redirect_analysis": "redirect_body_audit",
    "redirect_leak": "redirect_body_audit",
    "redirect_audit": "redirect_body_audit",
    "phpmyadmin": "phpmyadmin_assess",
    "phpmyadmin_audit": "phpmyadmin_assess",
    "pma_assess": "phpmyadmin_assess",
    "dos_check": "dos_viability",
    "denial_of_service": "dos_viability",
    "resource_exhaustion": "dos_viability",
    "surface_map": "http_surface_map",
    "content_analysis": "http_surface_map",
}

# Fuzzy-match cutoff: high enough to avoid wrong matches, low enough to catch
# minor variants (plurals, separators).
_FUZZY_CUTOFF = 0.82


def resolve_capability(name: str | None, known: Iterable[str]) -> tuple[str | None, str]:
    """Return (resolved_capability, how) where how in {exact, alias, fuzzy, unresolved}.

    ``known`` is the set of capability names actually registered in the adapter
    registry. Resolution never invents a name outside ``known``.
    """
    known_set = {k for k in known if k}
    if not name:
        return None, "unresolved"

    candidate = name.strip()
    lowered = candidate.lower()

    if candidate in known_set:
        return candidate, "exact"
    if lowered in known_set:
        return lowered, "exact"

    aliased = CAPABILITY_ALIASES.get(lowered)
    if aliased and aliased in known_set:
        return aliased, "alias"

    close = difflib.get_close_matches(lowered, sorted(known_set), n=1, cutoff=_FUZZY_CUTOFF)
    if close:
        return close[0], "fuzzy"

    return None, "unresolved"
