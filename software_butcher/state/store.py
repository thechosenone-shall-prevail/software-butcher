"""JSON finding-state store for early private builds."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from .convergence import apply_cluster_stats, cluster_theme, detect_flags, recompute_clusters
from .engagement import EngagementState, infer_phase, phase_hypotheses
from .hypothesis_queue import HypothesisQueue
from .pcs import PCSState, ProgressiveConvergenceSearch
from .recon_checklist import ReconChecklist, record_recon_progress
from .schema import ConvergenceCluster, Finding, Hypothesis, SCHEMA_VERSION
from .session_state import SessionStore
from .transport_state import TransportState
from software_butcher.brain.confirmation import process_finding
from software_butcher.core.url_utils import canonical_web_url, host_key

logger = logging.getLogger(__name__)


class FindingStore:
    """Auditable, diffable state store with ACE/PCS and engagement phase tracking."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.findings: dict[str, Finding] = {}
        self._finding_keys: set[str] = set()
        self.queue = HypothesisQueue()
        self.session_store = SessionStore()
        self._lock = threading.RLock()
        self.tool_calls = 0
        self.queue._lock = self._lock
        self.engagement = EngagementState()
        self.pcs = ProgressiveConvergenceSearch()
        self.recon_checklist = ReconChecklist()
        self.transport_state = TransportState()
        self.clusters: dict[str, ConvergenceCluster] = {}
        self._base_target: str = ""

    def set_base_target(self, target: str) -> None:
        self._base_target = target

    @property
    def base_target(self) -> str:
        return self._base_target

    def can_run_tool(self, limit: int) -> bool:
        with self._lock:
            return self.tool_calls < limit

    def record_tool_call(self, limit: int, count: int = 1) -> bool:
        with self._lock:
            if self.tool_calls + count > limit:
                return False
            self.tool_calls += count
            return True

    def ingest_finding(self, finding: Finding, branch_id: str | None = None) -> bool:
        """Add finding through confirmation + convergence + phase pipeline."""
        with self._lock:
            if branch_id:
                finding.metadata = {**finding.metadata, "branch_id": branch_id}

            finding.cluster_theme = cluster_theme(finding)
            finding = process_finding(finding)
            finding = self._normalize_finding_path(finding)

            # Flag detection enriches engagement
            for flag in detect_flags(" ".join(finding.evidence) + " " + finding.hypothesis):
                if flag not in self.engagement.flags_found:
                    self.engagement.flags_found.append(flag)

            added = self._add_finding_unlocked(finding)
            if not added:
                return False

            record_recon_progress(self.recon_checklist, finding, base_target=self._base_target)
            self._recompute_state_unlocked()
            return True

    def add_finding(self, finding: Finding) -> bool:
        return self.ingest_finding(finding)

    def _add_finding_unlocked(self, finding: Finding) -> bool:
        key = self._finding_key(finding)
        if key in self._finding_keys:
            return False
        self.findings[finding.id] = finding
        self._finding_keys.add(key)
        self.queue.add_from_finding(finding, self._base_target)
        return True

    def _normalize_finding_path(self, finding: Finding) -> Finding:
        if not self._base_target:
            return finding
        canonical = canonical_web_url(finding.path, self._base_target)
        if canonical:
            finding.path = canonical
        return finding

    def _recompute_state_unlocked(self) -> None:
        self.clusters = recompute_clusters(self.findings.values())
        for finding in self.findings.values():
            apply_cluster_stats(finding, self.clusters)
            process_finding(finding)

        self.engagement = infer_phase(list(self.findings.values()), self.engagement)

        if self._base_target:
            for hyp in phase_hypotheses(self.engagement, self._base_target, self.session_store):
                self.queue.add(hyp, self._base_target)

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        with self._lock:
            self.queue.add(hypothesis, self._base_target)

    def recon_complete_for(self, path_or_url: str) -> bool:
        with self._lock:
            return self.recon_checklist.is_complete(host_key(path_or_url))

    def new_branch_id(self) -> str:
        return f"branch-{uuid4().hex[:8]}"

    def recompute_state(self) -> None:
        with self._lock:
            self._recompute_state_unlocked()

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": SCHEMA_VERSION,
                "findings": [finding.to_dict() for finding in self.findings.values()],
                "hypothesis_queue": self.queue.to_list(),
                "tool_calls": self.tool_calls,
                "engagement": self.engagement.to_dict(),
                "pcs": self.pcs.state.to_dict(),
                "recon": self.recon_checklist.to_dict(),
                "transport": self.transport_state.to_dict(),
                "clusters": {k: v.to_dict() for k, v in self.clusters.items()},
            }
            self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            session_path = self.path.parent / "session_state.json"
            self.session_store.save(session_path)

    def save_or_log(self) -> None:
        try:
            self.save()
        except OSError as exc:
            logger.error("Failed to persist finding state to %s: %s", self.path, exc)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema_version": SCHEMA_VERSION,
                "findings": [finding.to_dict() for finding in self.findings.values()],
                "hypothesis_queue": self.queue.to_list(),
                "tool_calls": self.tool_calls,
                "engagement": self.engagement.to_dict(),
                "pcs": self.pcs.state.to_dict(),
                "recon": self.recon_checklist.to_dict(),
                "transport": self.transport_state.to_dict(),
                "clusters": {k: v.to_dict() for k, v in self.clusters.items()},
            }

    @classmethod
    def load(cls, path: str | Path) -> "FindingStore":
        store = cls(path)
        path = Path(path)
        if not path.exists():
            return store

        payload = json.loads(path.read_text(encoding="utf-8"))
        store.tool_calls = int(payload.get("tool_calls") or 0)
        store.engagement = EngagementState.from_dict(payload.get("engagement", {}))
        store.pcs = ProgressiveConvergenceSearch(PCSState.from_dict(payload.get("pcs", {})))
        store.recon_checklist = ReconChecklist.from_dict(payload.get("recon", {}))
        store.transport_state = TransportState.from_dict(payload.get("transport", {}))

        for theme, data in payload.get("clusters", {}).items():
            store.clusters[theme] = ConvergenceCluster.from_dict({**data, "theme": theme})

        for item in payload.get("findings", []):
            finding = Finding(
                id=item["id"],
                hypothesis=item["hypothesis"],
                path=item["path"],
                provenance=item["provenance"],
                status=item.get("status", "hypothesis"),
                evidence=item.get("evidence", []),
                confidence=item.get("confidence", 0.0),
                linked_findings=item.get("linked_findings", []),
                parent_path=item.get("parent_path"),
                asset_type=item.get("asset_type", "unknown"),
                metadata=item.get("metadata", {}),
                created_at=item.get("created_at", ""),
                schema_version=item.get("schema_version", SCHEMA_VERSION),
                required_evidence=item.get("required_evidence", []),
                observed_evidence=item.get("observed_evidence", []),
                supporting_paths=int(item.get("supporting_paths", 0)),
                opposing_paths=int(item.get("opposing_paths", 0)),
                convergence_score=float(item.get("convergence_score", 0.0)),
                evidence_count=int(item.get("evidence_count", 0)),
                cluster_theme=item.get("cluster_theme", ""),
            )
            store.findings[finding.id] = finding
            store._finding_keys.add(store._finding_key(finding))

        for item in payload.get("hypothesis_queue", []):
            store.queue.add(
                Hypothesis(
                    id=item["id"],
                    path=item["path"],
                    reason=item["reason"],
                    source_finding_id=item["source_finding_id"],
                    priority=item.get("priority", 0.5),
                    status=item.get("status", "pending"),
                    metadata=item.get("metadata", {}),
                    created_at=item.get("created_at", ""),
                    schema_version=item.get("schema_version", SCHEMA_VERSION),
                )
            )

        session_path = Path(path).parent / "session_state.json"
        store.session_store = SessionStore.load(session_path)
        store._recompute_state_unlocked()

        return store

    @staticmethod
    def _finding_key(finding: Finding) -> str:
        return f"{finding.path}::{finding.provenance}::{finding.hypothesis}"
