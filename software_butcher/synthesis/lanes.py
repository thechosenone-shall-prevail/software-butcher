"""Per-lane assessment summaries for multi-asset synthesis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from software_butcher.core.assets import AssetInventory
from software_butcher.state.schema import EngagementPhase, Finding
from software_butcher.state.session_state import SessionStore

LaneStatus = Literal["clear", "exposed", "confirmed", "pending"]
LaneName = Literal["web", "binary", "supply_chain", "post_exploit", "infrastructure"]


@dataclass
class AssessmentLane:
    name: LaneName
    status: LaneStatus
    summary: str
    finding_count: int = 0
    confirmed_count: int = 0
    asset_count: int = 0
    cited_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LANE_BY_ASSET_TYPE: dict[str, LaneName] = {
    "web_endpoint": "web",
    "api": "web",
    "domain": "web",
    "binary": "binary",
    "source_repo": "supply_chain",
    "cloud_account": "infrastructure",
    "container": "infrastructure",
    "ad_environment": "infrastructure",
    "ip": "infrastructure",
}

POST_EXPLOIT_SIGNALS = (
    "shell",
    "meterpreter",
    "foothold",
    "privesc",
    "uid=0",
    "root shell",
    "session opened",
    "htb{",
    "flag{",
)
SUPPLY_CHAIN_SIGNALS = (
    "source_repo",
    "technology",
    "eol",
    "upstream",
    "php",
    "apache",
    "code_analysis",
    "escalation_ladder",
)


def _lane_for_finding(finding: Finding) -> LaneName:
    capability = str((finding.metadata or {}).get("capability", "")).lower()
    provenance = finding.provenance.lower()
    text = " ".join(
        [finding.hypothesis, finding.path, provenance, " ".join(finding.evidence), str(finding.metadata)]
    ).lower()

    if any(signal in text for signal in POST_EXPLOIT_SIGNALS):
        return "post_exploit"
    if finding.asset_type == "source_repo" or any(signal in text for signal in SUPPLY_CHAIN_SIGNALS):
        return "supply_chain"
    return LANE_BY_ASSET_TYPE.get(finding.asset_type, "web")


def _status_for_lane(findings: list[Finding]) -> tuple[LaneStatus, str]:
    if not findings:
        return "clear", "No findings recorded for this lane."

    confirmed = [f for f in findings if f.status == "confirmed"]
    if confirmed:
        return "confirmed", f"{len(confirmed)} confirmed finding(s) with exploitable or executed evidence."

    exposed = [f for f in findings if f.confidence >= 0.6 or f.status == "hypothesis"]
    if exposed:
        return "exposed", f"{len(exposed)} finding(s) indicate attack surface or risky behavior."

    return "pending", f"{len(findings)} low-confidence finding(s); validation incomplete."


def build_assessment_lanes(
    findings: list[Finding],
    inventory: AssetInventory | None = None,
    engagement_phase: EngagementPhase | str = "recon",
    session_store: SessionStore | None = None,
    flags_found: list[str] | None = None,
) -> list[AssessmentLane]:
    """Build per-lane summaries for web, binary, supply chain, post-exploit, and infra."""
    active = [f for f in findings if f.status != "dismissed" and f.asset_type != "static_asset"]
    by_lane: dict[LaneName, list[Finding]] = {
        "web": [],
        "binary": [],
        "supply_chain": [],
        "post_exploit": [],
        "infrastructure": [],
    }

    for finding in active:
        by_lane[_lane_for_finding(finding)].append(finding)

    assets_by_lane: dict[LaneName, int] = {lane: 0 for lane in by_lane}
    if inventory:
        for asset in inventory.list():
            lane = LANE_BY_ASSET_TYPE.get(asset.asset_type, "web")
            assets_by_lane[lane] += 1

    lanes: list[AssessmentLane] = []
    for name in ("web", "binary", "supply_chain", "post_exploit", "infrastructure"):
        lane_findings = by_lane[name]
        status, summary = _status_for_lane(lane_findings)
        confirmed_ids = [f.id for f in lane_findings if f.status == "confirmed"]

        if name == "post_exploit":
            active_shells = 0
            if session_store:
                active_shells = len([s for s in session_store.shell_sessions.sessions.values() if s.active])
            if flags_found:
                status = "confirmed"
                summary = f"Flags captured ({len(flags_found)}); engagement phase={engagement_phase}."
            elif active_shells:
                status = "confirmed" if status != "confirmed" else status
                summary = f"{active_shells} active shell session(s); phase={engagement_phase}. {summary}"

        cited = sorted(
            lane_findings,
            key=lambda f: (f.status != "confirmed", -f.confidence),
        )[:5]

        lanes.append(
            AssessmentLane(
                name=name,
                status=status,
                summary=summary,
                finding_count=len(lane_findings),
                confirmed_count=len(confirmed_ids),
                asset_count=assets_by_lane[name],
                cited_findings=[f.id for f in cited],
            )
        )

    return lanes


def lane_overview_markdown(lanes: list[AssessmentLane], base_target: str = "") -> str:
    lines = ["## Assessment Lanes"]
    if base_target:
        lines.append(f"Target: `{base_target}`")
        lines.append("")
    for lane in lanes:
        if lane.finding_count == 0 and lane.asset_count == 0:
            continue
        lines.append(
            f"- **{lane.name}** [{lane.status}]: {lane.summary} "
            f"(findings={lane.finding_count}, assets={lane.asset_count})"
        )
    if len(lines) == 1:
        lines.append("- No lane activity recorded.")
    return "\n".join(lines)
