"""Priority queue for Brain exploration."""

from __future__ import annotations

from dataclasses import asdict

from .path_graph import parent_path
from .schema import Finding, Hypothesis


class HypothesisQueue:
    """Small deterministic queue with parent-path auto-generation."""

    def __init__(self) -> None:
        self._items: dict[str, Hypothesis] = {}

    def add(self, hypothesis: Hypothesis) -> None:
        key = self._key(hypothesis.path, hypothesis.reason)
        if key not in self._items:
            self._items[key] = hypothesis

    def add_from_finding(self, finding: Finding) -> None:
        # static_asset findings never deserve parent-path exploration:
        # /login.css → do NOT enqueue /login for playwright probing.
        if finding.asset_type in {"binary", "source_repo", "static_asset"}:
            return

        parent = finding.parent_path or parent_path(finding.path)
        if parent:
            self.add(
                Hypothesis(
                    path=parent,
                    reason=f"Parent path generated from child discovery: {finding.path}",
                    source_finding_id=finding.id,
                    priority=0.9 if finding.status == "confirmed" else 0.75,
                    metadata={"generated_by": "parent_path_rule", "asset_type": finding.asset_type},
                )
            )

    def next(self) -> Hypothesis | None:
        pending = [item for item in self._items.values() if item.status == "pending"]
        if not pending:
            return None
        item = sorted(pending, key=lambda hyp: (-hyp.priority, hyp.created_at))[0]
        item.status = "in_progress"
        return item

    def next_by_id(self, hypothesis_id: str) -> Hypothesis | None:
        """Pop a specific pending hypothesis by id (used by LLM advisor)."""
        for item in self._items.values():
            if item.id == hypothesis_id and item.status == "pending":
                item.status = "in_progress"
                return item
        # Fallback to default priority order if id not found or not pending
        return self.next()

    def pending_list(self) -> list[Hypothesis]:
        """Return all pending hypotheses sorted by priority (for LLM advisor)."""
        return sorted(
            [item for item in self._items.values() if item.status == "pending"],
            key=lambda hyp: (-hyp.priority, hyp.created_at),
        )

    def complete(self, hypothesis_id: str) -> None:
        for item in self._items.values():
            if item.id == hypothesis_id:
                item.status = "done"
                return

    def to_list(self) -> list[dict]:
        return [asdict(item) for item in self._items.values()]

    @staticmethod
    def _key(path: str, reason: str) -> str:
        return f"{path}::{reason}"
