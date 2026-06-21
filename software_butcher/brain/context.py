"""Rich context builder for Brain LLM reasoning."""

from __future__ import annotations

from software_butcher.core.app_root import infer_application_root
from software_butcher.state.convergence import recompute_clusters
from software_butcher.state.schema import ConvergenceCluster, Finding
from software_butcher.state.engagement import EngagementState
from software_butcher.state.session_state import SessionStore


def build_brain_context(
    findings: list[Finding],
    engagement: EngagementState,
    clusters: dict[str, ConvergenceCluster] | None = None,
    session_store: SessionStore | None = None,
    limit: int = 40,
    engagement_type: str | None = None,
    base_target: str = "",
) -> str:
    """Build a structured state summary for LLM capability selection."""
    clusters = clusters or recompute_clusters(findings)
    sorted_findings = sorted(findings, key=lambda f: f.created_at)[-limit:]
    et = engagement_type or getattr(engagement, "engagement_type", None) or "assessment"

    app_root = infer_application_root(findings, base_target)
    lines = [
        f"Engagement mode: {et}",
        f"Engagement phase: {engagement.phase}",
        f"Flags: user={engagement.user_flag or 'none'} root={engagement.root_flag or 'none'}",
        "",
    ]
    if app_root is not None:
        lines.extend([
            f"Application root (inferred): {app_root.url} (confidence={app_root.confidence:.2f})",
            f"  Rationale: {app_root.rationale}",
            "  Scope subsequent work to this directory subtree; parallel stack paths (phpMyAdmin, phpinfo) remain valid.",
            "",
        ])

    # Add shell session information if available
    if session_store and session_store.shell_sessions.sessions:
        active_sessions = [s for s in session_store.shell_sessions.sessions.values() if s.active]
        lines.append(f"Active shell sessions: {len(active_sessions)}")
        for session in active_sessions[:5]:  # Show up to 5 sessions
            lines.append(
                f"  - {session.session_type}:{session.session_id} @ {session.host}"
                f" (user={session.user or 'unknown'} cwd={session.cwd})"
            )
        lines.append("")

    lines.extend(["Convergence clusters (emergent confidence):"])

    for theme, cluster in sorted(clusters.items(), key=lambda x: -x[1].convergence_score)[:8]:
        lines.append(
            f"  - {theme}: score={cluster.convergence_score:.2f} "
            f"supporting={cluster.supporting_paths} opposing={cluster.opposing_paths} "
            f"evidence={cluster.evidence_count}"
        )

    lines.extend(["", f"Recent findings ({len(sorted_findings)} shown):"])
    for finding in sorted_findings:
        meta = finding.metadata or {}
        extra = ""
        if meta.get("page_summary"):
            extra += f" summary={str(meta['page_summary'])[:80]}"
        if meta.get("content_analysis"):
            page_type = meta.get("page_type") or "page"
            conclusions = meta.get("conclusions") or []
            if conclusions:
                extra += f" [content:{page_type}] {conclusions[0][:100]}"
            elif meta.get("php_version"):
                extra += f" [PHP {meta['php_version']}]"
        if meta.get("stack_landing", {}).get("detected"):
            extra += " [XAMPP/default stack landing]"
        infra = meta.get("infrastructure")
        if isinstance(infra, dict) and infra.get("conclusions"):
            extra += f" | {infra['conclusions'][0][:80]}"
        lines.append(
            f"  - [{finding.status}] {finding.path} | theme={finding.cluster_theme} "
            f"conf={finding.confidence:.2f} emergent={finding.emergent_confidence:.2f} "
            f"conv={finding.convergence_score:.2f} | {finding.hypothesis[:100]}{extra}"
        )
        if finding.evidence:
            lines.append(f"      evidence: {finding.evidence[0][:120]}")

    confirmed = [f for f in findings if f.status == "confirmed"]
    lines.extend(["", f"Confirmed findings: {len(confirmed)} / {len(findings)} total"])

    return "\n".join(lines)
