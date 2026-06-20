"""Convergence clustering and emergent confidence scoring (ACE)."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit

from software_butcher.state.schema import ConvergenceCluster, Finding

THEME_SIGNALS: list[tuple[str, tuple[str, ...]]] = [
    ("ssrf", ("ssrf", "server-side request", "url fetch")),
    ("auth_bypass", ("auth bypass", "login bypass", "session created", "auth_bypass")),
    ("sqli", ("sql", "injection", "database error", "union select", "sqlmap")),
    ("xss", ("xss", "cross-site scripting", "script alert")),
    ("rce", ("rce", "remote code", "shell", "command execution", "foothold")),
    ("privesc", ("privilege", "privesc", "sudo", "suid", "kernel exploit", "root shell")),
    ("lfi", ("lfi", "local file", "path traversal", "/etc/passwd")),
    ("idor", ("idor", "insecure direct object", "access control")),
    ("credential", ("password", "credential", "hash", "hydra", "brute force")),
    ("port_service", ("open port", "service discovered", "nmap", "masscan")),
    ("flag_user", ("user flag", "user.txt", "htb{", "flag{")),
    ("flag_root", ("root flag", "root.txt", "proof.txt")),
]

WEB_AUTH_PATH_SIGNALS = ("login", "admin", "auth", "dashboard", "portal", "hall", "signin", "session")


def _finding_text(finding: Finding) -> str:
    return " ".join(
        [finding.hypothesis, finding.path, finding.provenance, " ".join(finding.evidence), str(finding.metadata)]
    ).lower()


def _host_key(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.netloc:
        return parsed.netloc.lower()
    return path.split("/")[0].lower()


def normalize_cluster_theme(finding: Finding, candidate: str) -> str:
    """Collapse similar surface themes so PCS can converge across wording variants."""
    if not candidate.startswith("surface:"):
        return candidate

    text = _finding_text(finding)
    for theme, signals in THEME_SIGNALS:
        if any(signal in text for signal in signals):
            return theme

    segment = candidate.replace("surface:", "").lower()
    if any(signal in segment for signal in WEB_AUTH_PATH_SIGNALS) or any(
        signal in text for signal in ("login", "auth", "session", "dashboard")
    ):
        return f"web_auth:{_host_key(finding.path)}"

    return f"surface_host:{_host_key(finding.path)}"


def cluster_theme(finding: Finding) -> str:
    """Map a finding to a convergence theme for PCS aggregation."""
    capability = str((finding.metadata or {}).get("capability", "")).lower()
    if capability in {t for t, _ in THEME_SIGNALS}:
        return capability
    if capability.endswith("_confirmed"):
        return capability.replace("_confirmed", "")

    text = _finding_text(finding)

    for theme, signals in THEME_SIGNALS:
        if any(signal in text for signal in signals):
            return theme

    path_key = finding.path.rstrip("/").split("/")[-1] or finding.path
    raw = f"surface:{path_key[:48]}"
    return normalize_cluster_theme(finding, raw)


def recompute_clusters(findings: Iterable[Finding]) -> dict[str, ConvergenceCluster]:
    """Rebuild convergence clusters from all findings."""
    findings_list = list(findings)
    by_theme: dict[str, ConvergenceCluster] = {}
    branch_themes: dict[str, set[str]] = {}

    for finding in findings_list:
        theme = finding.cluster_theme or cluster_theme(finding)
        finding.cluster_theme = theme

        cluster = by_theme.setdefault(theme, ConvergenceCluster(theme=theme))
        if finding.id not in cluster.finding_ids:
            cluster.finding_ids.append(finding.id)
        cluster.evidence_count += max(1, len(finding.evidence))

        branch_id = str((finding.metadata or {}).get("branch_id", "primary"))
        if branch_id not in cluster.branch_ids:
            cluster.branch_ids.append(branch_id)

        branch_themes.setdefault(branch_id, set()).add(theme)

    total_branches = max(len(branch_themes), 1)

    for theme, cluster in by_theme.items():
        supporting = len(cluster.branch_ids)
        # Opposing = branches that explored but landed on a different primary theme
        opposing = 0
        for branches_themes in branch_themes.values():
            if theme not in branches_themes and branches_themes:
                opposing += 1

        cluster.supporting_paths = supporting
        cluster.opposing_paths = opposing
        agreement = supporting / total_branches
        conflict_penalty = opposing / total_branches * 0.35
        finding_ids = set(cluster.finding_ids)
        confirmed_boost = 0.15 if any(
            f.status == "confirmed" for f in findings_list if f.id in finding_ids
        ) else 0.0
        raw = agreement - conflict_penalty + confirmed_boost
        # Convergence requires multiple independent branches to be meaningful.
        # A single branch landing on a theme cannot exceed 0.50, so it can
        # never reach the 0.75 convergence-stop threshold on its own (even if
        # HexStrike is down and returns only one low-quality finding).
        # 1 branch  → max 0.50  (explore, never lock)
        # 2 branches → max 0.70  (can confirm, cannot stop exploration)
        # 3+ branches → uncapped (legitimate convergence)
        if supporting <= 1:
            cap = 0.50
        elif supporting == 2:
            cap = 0.70
        else:
            cap = 1.0
        cluster.convergence_score = round(min(cap, max(0.0, raw)), 3)

    return by_theme


def apply_cluster_stats(finding: Finding, clusters: dict[str, ConvergenceCluster]) -> Finding:
    """Copy cluster-level emergent stats onto a finding."""
    theme = finding.cluster_theme or cluster_theme(finding)
    finding.cluster_theme = theme
    cluster = clusters.get(theme)
    if not cluster:
        return finding

    finding.supporting_paths = cluster.supporting_paths
    finding.opposing_paths = cluster.opposing_paths
    finding.convergence_score = cluster.convergence_score
    finding.evidence_count = cluster.evidence_count
    return finding


def detect_flags(text: str) -> list[str]:
    """Extract HTB-style flag patterns from text."""
    patterns = [
        r"HTB\{[A-Za-z0-9_\-]+\}",
        r"FLAG\{[A-Za-z0-9_\-]+\}",
        r"flag\{[A-Za-z0-9_\-]+\}",
        r"[0-9a-f]{32}",
    ]
    flags: list[str] = []
    for pattern in patterns:
        flags.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return list(dict.fromkeys(flags))
