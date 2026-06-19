"""Versioned finding and hypothesis schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

FindingStatus = Literal["hypothesis", "confirmed", "dismissed"]
HypothesisStatus = Literal["pending", "in_progress", "done"]


SCHEMA_VERSION = "0.1"


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
    # Evidence validation fields (Phase 4 foundation)
    required_evidence: list[str] = field(default_factory=list)
    observed_evidence: list[str] = field(default_factory=list)

    @property
    def evidence_complete(self) -> bool:
        """True if all required evidence has been observed."""
        if not self.required_evidence:
            return True
        return all(
            any(req.lower() in obs.lower() for obs in self.observed_evidence)
            for req in self.required_evidence
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence_complete"] = self.evidence_complete
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
