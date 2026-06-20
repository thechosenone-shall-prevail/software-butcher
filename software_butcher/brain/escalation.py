"""Outcome-based escalation — pivot lanes when direct exploitation fails."""

from __future__ import annotations

from pathlib import Path

from software_butcher.core.assets import Asset, AssetInventory
from software_butcher.core.source_acquisition import SourceAcquisition
from software_butcher.core.source_resolver import (
    collect_technologies,
    pick_escalation_candidate,
    resolve_upstream_source,
)
from software_butcher.core.scope import Scope
from software_butcher.state.schema import Finding, Hypothesis
from software_butcher.state.store import FindingStore

EXPLOIT_ATTEMPT_CAPABILITIES = frozenset(
    {
        "exploit_generation",
        "cve_lookup",
        "sql_injection_probing",
        "vulnerability_scanning",
    }
)

FAILURE_SIGNALS = (
    "failed",
    "no exploit",
    "not vulnerable",
    "no vulnerability",
    "timeout",
    "error",
    "unsuccessful",
    "could not",
    "denied",
)


class EscalationLadder:
    """Promote failed exploit paths into upstream source analysis."""

    def __init__(self, acquisition: SourceAcquisition | None = None) -> None:
        self.acquisition = acquisition or SourceAcquisition()

    def escalate(
        self,
        finding: Finding,
        store: FindingStore,
        scope: Scope,
        inventory: AssetInventory,
        workspace_root: str | Path,
        *,
        hypothesis_queue=None,
    ) -> list[Asset]:
        if not self._should_escalate(finding, store):
            return []

        technologies = self._technologies_for_finding(finding, store)
        reference = pick_escalation_candidate(technologies)
        if reference is None:
            return []

        local_path = self.acquisition.prepare(reference, workspace_root)
        locator = str(local_path) if local_path else reference.repo_url
        if not self._allows_source_target(locator, scope, Path(workspace_root)):
            return []

        if inventory.has_locator(locator):
            return []

        asset = Asset(
            locator=locator,
            asset_type="source_repo",
            parent=finding.path,
            discovered_by="escalation_ladder",
            metadata={
                "source_finding_id": finding.id,
                "technology": reference.technology,
                "product": reference.product,
                "version": reference.version,
                "repo_url": reference.repo_url,
                "branch": reference.branch,
                "is_eol": reference.is_eol,
                "escalated_from": finding.path,
            },
        )
        inventory.add(asset)

        if hypothesis_queue is not None:
            reason = (
                f"Direct exploitation did not confirm on {finding.path}; "
                f"audit upstream {reference.product} {reference.version} source for issues."
            )
            hypothesis_queue.add(
                Hypothesis(
                    path=locator,
                    reason=reason,
                    source_finding_id=finding.id,
                    priority=0.94 if reference.is_eol else 0.88,
                    metadata={
                        "asset_type": "source_repo",
                        "intent": "source_static_analysis",
                        "technology": reference.technology,
                        "source_url": reference.repo_url,
                        "generated_by": "escalation_ladder",
                    },
                )
            )

        return [asset]

    @staticmethod
    def _allows_source_target(locator: str, scope: Scope, workspace_root: Path) -> bool:
        if scope.allows(locator):
            return True
        try:
            Path(locator).resolve().relative_to(workspace_root.resolve())
            return True
        except ValueError:
            pass
        if scope.metadata.get("allow_upstream_source", True) and locator.startswith("https://github.com/"):
            return True
        return False

    def _should_escalate(self, finding: Finding, store: FindingStore) -> bool:
        if finding.status == "confirmed":
            return False

        capability = str((finding.metadata or {}).get("capability", "")).lower()
        if capability not in EXPLOIT_ATTEMPT_CAPABILITIES:
            return False

        if finding.confidence >= 0.75 and finding.evidence_complete:
            return False

        blob = " ".join(finding.evidence).lower()
        if finding.confidence <= 0.55 or any(signal in blob for signal in FAILURE_SIGNALS):
            return True

        # EOL stack + unsuccessful exploit attempt is enough to pivot.
        technologies = self._technologies_for_finding(finding, store)
        reference = pick_escalation_candidate(technologies)
        return reference is not None and reference.is_eol

    @staticmethod
    def _technologies_for_finding(finding: Finding, store: FindingStore) -> list[str]:
        text_chunks = [
            finding.hypothesis,
            finding.path,
            " ".join(finding.evidence),
            str(finding.metadata),
        ]

        path_key = finding.path.rstrip("/")
        for other in store.findings.values():
            if other.id == finding.id:
                continue
            if other.path.rstrip("/") == path_key or other.path.rstrip("/").startswith(path_key + "/"):
                text_chunks.extend(
                    [other.hypothesis, " ".join(other.evidence), str(other.metadata)]
                )

        combined = "\n".join(text_chunks)
        return collect_technologies(combined, finding.metadata)
