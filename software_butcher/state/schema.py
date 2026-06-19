"""Versioned finding and hypothesis schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

FindingStatus = Literal["hypothesis", "confirmed", "dismissed"]
HypothesisStatus = Literal["pending", "in_progress", "done"]
EngagementPhase = Literal["recon", "exploit", "foothold", "privesc", "exfil", "complete"]


SCHEMA_VERSION = "0.2"


@dataclass
class Finding:
    """Single source of truth entry written by the Brain."""

    hypothesis: str
    path: str
    provenance: str
    status: FindingStatus = "hypothesis"
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    linked_findings: list[str] = field(default_factory=list)
    parent_path: str | None = None
    asset_type: str = "unknown"
    id: str = field(default_factory=lambda: f"finding-{uuid4().hex[:12]}")
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = SCHEMA_VERSION
    required_evidence: list[str] = field(default_factory=list)
    observed_evidence: list[str] = field(default_factory=list)
    # Emergent confidence (ACE / PCS)
    supporting_paths: int = 0
    opposing_paths: int = 0
    convergence_score: float = 0.0
    evidence_count: int = 0
    cluster_theme: str = ""

    @property
    def evidence_complete(self) -> bool:
        if not self.required_evidence:
            return True
        return all(
            any(req.lower() in obs.lower() for obs in self.observed_evidence)
            for req in self.required_evidence
        )

    @property
    def emergent_confidence(self) -> float:
        """Blend model confidence with convergence-derived score."""
        if self.convergence_score > 0:
            return min(1.0, (self.confidence * 0.4) + (self.convergence_score * 0.6))
        return self.confidence

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence_complete"] = self.evidence_complete
        d["emergent_confidence"] = self.emergent_confidence
        return d


@dataclass
class Hypothesis:
    """Work queue item generated from findings and asset traversal."""

    path: str
    reason: str
    source_finding_id: str
    priority: float = 0.5
    status: HypothesisStatus = "pending"
    id: str = field(default_factory=lambda: f"hyp-{uuid4().hex[:12]}")
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConvergenceCluster:
    """Tracks emergent agreement across independent exploration paths."""

    theme: str
    finding_ids: list[str] = field(default_factory=list)
    branch_ids: list[str] = field(default_factory=list)
    supporting_paths: int = 0
    opposing_paths: int = 0
    convergence_score: float = 0.0
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConvergenceCluster":
        return cls(
            theme=data["theme"],
            finding_ids=list(data.get("finding_ids", [])),
            branch_ids=list(data.get("branch_ids", [])),
            supporting_paths=int(data.get("supporting_paths", 0)),
            opposing_paths=int(data.get("opposing_paths", 0)),
            convergence_score=float(data.get("convergence_score", 0.0)),
            evidence_count=int(data.get("evidence_count", 0)),
        )
