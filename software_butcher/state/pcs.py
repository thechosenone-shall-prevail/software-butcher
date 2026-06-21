"""Progressive Convergence Search (PCS) — adaptive branching logic.

Branches are expensive. Only spawn them when evidence warrants it.
When independent paths converge on the same theme, emergent confidence rises.
When paths conflict, widen search. When convergence is high, validate — don't branch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from software_butcher.core.app_root import ApplicationRoot, finding_drives_pcs_branching
from software_butcher.state.schema import ConvergenceCluster, Finding


# PCS tuning knobs
INITIAL_BRANCHES = 1
SPAWN_ON_EVIDENCE = 3
SPAWN_ON_CONFLICT = 2
MAX_BRANCHES = 5
CONVERGENCE_STOP_THRESHOLD = 0.75
HIGH_VALUE_CONFIDENCE = 0.65
# Minimum total evidence pieces across all clusters before convergence-stop
# can lock exploration into validation mode.  Prevents a single failed/low-
# confidence finding from triggering validation_mode on the very first step.
MIN_EVIDENCE_FOR_CONVERGENCE = 4
MIN_ACTIVE_CLUSTERS_FOR_CONVERGENCE = 2


@dataclass
class PCSState:
    """Persisted PCS controller state."""

    active_branches: int = 1
    total_spawned: int = 1
    validation_mode: bool = False
    last_wave_themes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_branches": self.active_branches,
            "total_spawned": self.total_spawned,
            "validation_mode": self.validation_mode,
            "last_wave_themes": self.last_wave_themes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PCSState":
        return cls(
            active_branches=int(data.get("active_branches", 1)),
            total_spawned=int(data.get("total_spawned", 1)),
            validation_mode=bool(data.get("validation_mode", False)),
            last_wave_themes=list(data.get("last_wave_themes", [])),
        )


class ProgressiveConvergenceSearch:
    """Adaptive branch controller for the Brain loop."""

    def __init__(self, state: PCSState | None = None) -> None:
        self.state = state or PCSState()

    def branches_for_step(
        self,
        clusters: dict[str, ConvergenceCluster],
        new_findings: list[Finding],
        *,
        recon_complete: bool = True,
        app_root: ApplicationRoot | None = None,
        engagement_type: str = "assessment",
    ) -> tuple[int, str]:
        """Return (branch_count, reason) for the next Brain step."""
        if self.state.validation_mode:
            if not recon_complete:
                self.state.validation_mode = False
                return INITIAL_BRANCHES, "primary_path: recon incomplete — resume exploration"
            return 1, "validation_mode: convergence threshold reached"

        max_conv = max((c.convergence_score for c in clusters.values()), default=0.0)
        if max_conv >= CONVERGENCE_STOP_THRESHOLD:
            if not recon_complete:
                self.state.active_branches = INITIAL_BRANCHES
                return INITIAL_BRANCHES, "primary_path: recon incomplete — keep mapping web surface"

            total_evidence = sum(c.evidence_count for c in clusters.values())
            if total_evidence < MIN_EVIDENCE_FOR_CONVERGENCE:
                self.state.active_branches = INITIAL_BRANCHES
                return INITIAL_BRANCHES, (
                    f"primary_path: convergence score {max_conv:.2f} reached but "
                    f"evidence too thin ({total_evidence}/{MIN_EVIDENCE_FOR_CONVERGENCE}) — keep exploring"
                )

            active_clusters = [c for c in clusters.values() if c.evidence_count > 0]
            if len(active_clusters) < MIN_ACTIVE_CLUSTERS_FOR_CONVERGENCE:
                self.state.active_branches = INITIAL_BRANCHES
                return INITIAL_BRANCHES, (
                    f"primary_path: only {len(active_clusters)} active cluster(s) — "
                    f"need {MIN_ACTIVE_CLUSTERS_FOR_CONVERGENCE}+ before validation"
                )

            self.state.validation_mode = True
            self.state.active_branches = 1
            return 1, f"convergence_stop: score {max_conv:.2f} >= {CONVERGENCE_STOP_THRESHOLD}"

        if self._high_value_evidence(
            new_findings,
            app_root=app_root,
            engagement_type=engagement_type,
        ):
            self.state.active_branches = min(MAX_BRANCHES, SPAWN_ON_EVIDENCE)
            self.state.total_spawned = max(self.state.total_spawned, self.state.active_branches)
            return self.state.active_branches, "evidence_triggered: high-value finding spawned branches"

        if self._conflicting_themes(clusters, new_findings):
            proposed = min(MAX_BRANCHES, self.state.active_branches + SPAWN_ON_CONFLICT)
            self.state.active_branches = proposed
            self.state.total_spawned = max(self.state.total_spawned, proposed)
            return min(SPAWN_ON_CONFLICT, self.state.active_branches), "conflict_widen: divergent path themes"

        # Primary path — no evidence worth parallel exploration yet
        self.state.active_branches = INITIAL_BRANCHES
        return INITIAL_BRANCHES, "primary_path: no branch trigger"

    @staticmethod
    def _high_value_evidence(
        findings: list[Finding],
        *,
        app_root: ApplicationRoot | None = None,
        engagement_type: str = "assessment",
    ) -> bool:
        if not findings:
            return False
        for finding in findings:
            if not finding_drives_pcs_branching(
                finding,
                app_root,
                engagement_type=engagement_type,
            ):
                continue
            if finding.status == "confirmed":
                return True
            if finding.confidence >= HIGH_VALUE_CONFIDENCE:
                return True
            capability = (finding.metadata or {}).get("capability", "")
            if capability in {
                "auth_bypass_confirmed",
                "vulnerability_confirmed",
                "foothold",
                "privesc",
                "flag_user",
                "flag_root",
            }:
                return True
        return False

    def _conflicting_themes(
        self,
        clusters: dict[str, ConvergenceCluster],
        new_findings: list[Finding],
    ) -> bool:
        if len(new_findings) < 2:
            return False
        themes = {f.cluster_theme for f in new_findings if f.cluster_theme}
        if len(themes) >= 2:
            self.state.last_wave_themes = sorted(themes)
            return True
        # Cluster-level conflict: multiple themes with low convergence
        active = [c for c in clusters.values() if c.evidence_count > 0 and c.convergence_score < 0.4]
        return len(active) >= 2
