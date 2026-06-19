"""JSON finding-state store for early private builds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .hypothesis_queue import HypothesisQueue
from .schema import Finding, Hypothesis, SCHEMA_VERSION
from .session_state import SessionStore


class FindingStore:
    """Auditable, diffable state store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.findings: dict[str, Finding] = {}
        self._finding_keys: set[str] = set()
        self.queue = HypothesisQueue()
        self.session_store = SessionStore()

    def add_finding(self, finding: Finding) -> bool:
        key = self._finding_key(finding)
        if key in self._finding_keys:
            return False
        self.findings[finding.id] = finding
        self._finding_keys.add(key)
        self.queue.add_from_finding(finding)
        return True

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.queue.add(hypothesis)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "findings": [finding.to_dict() for finding in self.findings.values()],
            "hypothesis_queue": self.queue.to_list(),
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        # Persist sessions alongside findings
        session_path = self.path.parent / "session_state.json"
        self.session_store.save(session_path)

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "findings": [finding.to_dict() for finding in self.findings.values()],
            "hypothesis_queue": self.queue.to_list(),
        }

    @classmethod
    def load(cls, path: str | Path) -> "FindingStore":
        store = cls(path)
        path = Path(path)
        if not path.exists():
            return store

        payload = json.loads(path.read_text(encoding="utf-8"))
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

        # Load sessions if they exist
        session_path = Path(path).parent / "session_state.json"
        store.session_store = SessionStore.load(session_path)

        return store

    @staticmethod
    def _finding_key(finding: Finding) -> str:
        return f"{finding.path}::{finding.provenance}::{finding.hypothesis}"
