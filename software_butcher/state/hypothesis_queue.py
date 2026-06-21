"""Priority queue for Brain exploration."""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING

from software_butcher.core.app_root import (
    application_scope_priority_boost,
    assessment_serializes_branches,
    hypothesis_in_application_scope,
    hypothesis_matches_app_focus,
    infer_application_root,
    app_scope_work_pending,
)
from software_butcher.core.path_relevance import hypothesis_has_evidence_lineage
from software_butcher.core.url_utils import canonical_web_url, is_plausible_target_path
from software_butcher.state.engagement import normalize_engagement_type

from .path_graph import parent_path
from .schema import Finding, Hypothesis

if TYPE_CHECKING:
    import threading


class HypothesisQueue:
    """Small deterministic queue with parent-path auto-generation."""

    def __init__(self, lock: "threading.RLock | None" = None) -> None:
        self._items: dict[str, Hypothesis] = {}
        self._lock = lock
        self._findings: dict[str, Finding] | None = None
        self._engagement_type: str = "assessment"
        self._session_store = None
        self._base_target: str = ""

    def configure(
        self,
        *,
        findings: dict[str, Finding] | None = None,
        engagement_type: str = "assessment",
        session_store=None,
        base_target: str = "",
    ) -> None:
        self._findings = findings
        self._engagement_type = normalize_engagement_type(engagement_type)
        self._session_store = session_store
        self._base_target = base_target or ""

    def add(self, hypothesis: Hypothesis, base_target: str = "") -> None:
        normalized = self._normalize_hypothesis(hypothesis, base_target)
        if normalized is None:
            return
        dedupe_key = self._dedupe_key(normalized)
        if self._lock:
            with self._lock:
                if self._has_active_dedupe(dedupe_key):
                    return
                key = self._key(normalized.path, normalized.reason)
                if key not in self._items:
                    self._items[key] = normalized
        else:
            if self._has_active_dedupe(dedupe_key):
                return
            key = self._key(normalized.path, normalized.reason)
            if key not in self._items:
                self._items[key] = normalized

    def _has_active_dedupe(self, dedupe_key: str) -> bool:
        for item in self._items.values():
            if item.status not in {"pending", "in_progress"}:
                continue
            if self._dedupe_key(item) == dedupe_key:
                return True
        return False

    def add_from_finding(self, finding: Finding, base_target: str = "") -> None:
        if finding.asset_type in {"binary", "source_repo", "static_asset"}:
            return

        parent = finding.parent_path or parent_path(finding.path)
        if not parent or not is_plausible_target_path(parent, base_target):
            return

        resolved = canonical_web_url(parent, base_target) or parent
        self.add(
            Hypothesis(
                path=resolved,
                reason=f"Parent path generated from child discovery: {finding.path}",
                source_finding_id=finding.id,
                priority=0.9 if finding.status == "confirmed" else 0.75,
                metadata={"generated_by": "parent_path_rule", "asset_type": finding.asset_type},
            ),
            base_target=base_target,
        )

    def _normalize_hypothesis(self, hypothesis: Hypothesis, base_target: str) -> Hypothesis | None:
        path = hypothesis.path
        if base_target:
            canonical = canonical_web_url(path, base_target)
            if canonical:
                path = canonical
            if not is_plausible_target_path(path, base_target):
                return None
        elif not is_plausible_target_path(path, base_target):
            return None
        if path != hypothesis.path:
            hypothesis.path = path

        findings = self._findings or {}
        if not hypothesis_has_evidence_lineage(
            hypothesis,
            findings,
            engagement_type=self._engagement_type,
            session_store=self._session_store,
        ):
            return None

        app_root = infer_application_root(findings.values(), self._base_target)
        if not hypothesis_in_application_scope(
            hypothesis,
            app_root,
            findings,
            base_target=self._base_target,
            engagement_type=self._engagement_type,
        ):
            return None
        return hypothesis

    def prune_out_of_app_scope(self) -> int:
        """Drop pending hypotheses outside inferred application subtree."""
        findings = self._findings or {}
        app_root = infer_application_root(findings.values(), self._base_target)
        if app_root is None:
            return 0

        removed = 0

        def _prune() -> None:
            nonlocal removed
            for key, item in list(self._items.items()):
                if item.status != "pending":
                    continue
                if hypothesis_in_application_scope(
                    item,
                    app_root,
                    findings,
                    base_target=self._base_target,
                    engagement_type=self._engagement_type,
                ):
                    continue
                del self._items[key]
                removed += 1

        if self._lock:
            with self._lock:
                _prune()
        else:
            _prune()
        return removed

    def _focused_pending(self, pending: list[Hypothesis]) -> list[Hypothesis]:
        findings = self._findings or {}
        app_root = infer_application_root(findings.values(), self._base_target)
        if self._engagement_type != "assessment" or app_root is None or app_root.confidence < 0.55:
            return pending
        pending_maps, pending_redirects = app_scope_work_pending(findings.values(), app_root)
        if not pending_maps and not pending_redirects:
            return pending
        focused = [
            hyp
            for hyp in pending
            if hypothesis_matches_app_focus(hyp, app_root, findings)
        ]
        return focused if focused else pending

    def _effective_priority(self, hypothesis: Hypothesis) -> float:
        findings = self._findings or {}
        app_root = infer_application_root(findings.values(), self._base_target)
        boost = application_scope_priority_boost(hypothesis, app_root, findings)
        return hypothesis.priority + boost

    def next(self) -> Hypothesis | None:
        if self._lock:
            with self._lock:
                return self._next_unlocked()
        return self._next_unlocked()

    def _next_unlocked(self) -> Hypothesis | None:
        pending = [item for item in self._items.values() if item.status == "pending"]
        pending = self._focused_pending(pending)
        if not pending:
            return None
        item = sorted(pending, key=lambda hyp: (-self._effective_priority(hyp), hyp.created_at))[0]
        item.status = "in_progress"
        return item

    def next_by_id(self, hypothesis_id: str) -> Hypothesis | None:
        if self._lock:
            with self._lock:
                return self._next_by_id_unlocked(hypothesis_id)
        return self._next_by_id_unlocked(hypothesis_id)

    def _next_by_id_unlocked(self, hypothesis_id: str) -> Hypothesis | None:
        for item in self._items.values():
            if item.id == hypothesis_id and item.status == "pending":
                item.status = "in_progress"
                return item
        return self._next_unlocked()

    def pending_list(self) -> list[Hypothesis]:
        if self._lock:
            with self._lock:
                return self._pending_list_unlocked()
        return self._pending_list_unlocked()

    def _pending_list_unlocked(self) -> list[Hypothesis]:
        pending = [item for item in self._items.values() if item.status == "pending"]
        pending = self._focused_pending(pending)
        return sorted(
            pending,
            key=lambda hyp: (-self._effective_priority(hyp), hyp.created_at),
        )

    def complete(self, hypothesis_id: str) -> None:
        if self._lock:
            with self._lock:
                self._complete_unlocked(hypothesis_id)
            return
        self._complete_unlocked(hypothesis_id)

    def _complete_unlocked(self, hypothesis_id: str) -> None:
        for item in self._items.values():
            if item.id == hypothesis_id:
                item.status = "done"
                return

    def to_list(self) -> list[dict]:
        if self._lock:
            with self._lock:
                return [asdict(item) for item in self._items.values()]
        return [asdict(item) for item in self._items.values()]

    @staticmethod
    def _key(path: str, reason: str) -> str:
        return f"{path}::{reason}"

    @staticmethod
    def _dedupe_key(hypothesis: Hypothesis) -> str:
        intent = str((hypothesis.metadata or {}).get("intent", "")).lower()
        return f"{hypothesis.path.rstrip('/').lower()}::{intent}"

