"""Finding confirmation pipeline — hypothesis → confirmed promotion."""

from __future__ import annotations

from software_butcher.state.schema import Finding

# Emergent confirmation: convergence at or above this promotes to confirmed
CONVERGENCE_CONFIRM_THRESHOLD = 0.70
EMERGENT_CONFIRM_THRESHOLD = 0.75

REQUIRED_EVIDENCE_BY_CAPABILITY: dict[str, list[str]] = {
    "auth_bypass_confirmed": ["session", "redirect", "status"],
    "vulnerability_confirmed": ["payload", "response"],
    "sqli": ["database", "error", "union"],
    "xss": ["payload", "reflected", "stored"],
    "rce": ["shell", "output", "uid"],
    "foothold": ["shell", "session"],
    "privesc": ["root", "uid=0", "elevated"],
    "flag_user": ["HTB{", "flag{", "user"],
    "flag_root": ["HTB{", "flag{", "root"],
}


def infer_required_evidence(finding: Finding) -> list[str]:
    """Assign required evidence markers based on finding capability/theme."""
    capability = str((finding.metadata or {}).get("capability", "")).lower()
    if capability in REQUIRED_EVIDENCE_BY_CAPABILITY:
        return REQUIRED_EVIDENCE_BY_CAPABILITY[capability]
    if finding.cluster_theme in REQUIRED_EVIDENCE_BY_CAPABILITY:
        return REQUIRED_EVIDENCE_BY_CAPABILITY[finding.cluster_theme]
    if finding.status == "confirmed":
        return []
    return ["reproducible"]


def collect_observed_evidence(finding: Finding) -> list[str]:
    """Build observed evidence list from raw evidence strings."""
    observed = list(finding.observed_evidence)
    blob = " ".join(finding.evidence).lower()
    markers = (
        "session", "redirect", "status", "payload", "response", "database", "error",
        "shell", "output", "uid", "root", "htb{", "flag{", "union", "reflected", "mysql",
    )
    for marker in markers:
        if marker in blob and marker not in observed:
            observed.append(marker)
    return observed


def _is_content_intel_only(finding: Finding) -> bool:
    """Content-read findings must not auto-confirm from convergence alone."""
    meta = finding.metadata or {}
    capability = str(meta.get("capability", "")).lower()
    if meta.get("content_analysis") and capability not in {
        "vulnerability_confirmed",
        "auth_bypass_confirmed",
        "exploit_generation",
        "sql_injection_probing",
        "rce",
    }:
        return True
    if capability == "http_surface_map" and finding.provenance.startswith("http_surface:"):
        return True
    return False


def should_confirm(finding: Finding) -> bool:
    """Decide if a finding should be promoted to confirmed."""
    if finding.status == "dismissed":
        return False
    if finding.status == "confirmed":
        return True

    capability = str((finding.metadata or {}).get("capability", ""))
    if capability.endswith("_confirmed") or capability in {"foothold", "privesc", "flag_user", "flag_root"}:
        return True

    if finding.evidence_complete and finding.required_evidence:
        return True

    if _is_content_intel_only(finding):
        return False

    if finding.convergence_score >= CONVERGENCE_CONFIRM_THRESHOLD and finding.supporting_paths >= 2:
        return True

    if finding.emergent_confidence >= EMERGENT_CONFIRM_THRESHOLD and finding.supporting_paths >= 3:
        return True

    return False


def process_finding(finding: Finding) -> Finding:
    """Apply confirmation rules and evidence requirements to a finding."""
    if not finding.required_evidence:
        finding.required_evidence = infer_required_evidence(finding)

    finding.observed_evidence = collect_observed_evidence(finding)
    finding.evidence_count = max(finding.evidence_count, len(finding.evidence))

    if should_confirm(finding):
        finding.status = "confirmed"
        finding.confidence = max(finding.confidence, finding.emergent_confidence, 0.75)

    return finding
