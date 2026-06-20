"""Evidence-backed synthesis from finding state."""

from __future__ import annotations

import json
import sys
import os
from dataclasses import asdict, dataclass, field
from typing import Any

from software_butcher.core.assets import AssetInventory
from software_butcher.core.url_utils import host_key
from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore
from software_butcher.synthesis.lanes import AssessmentLane, build_assessment_lanes, lane_overview_markdown
from software_butcher.synthesis.verdict import Verdict


@dataclass
class TechnicalReport:
    verdict: Verdict
    findings: list[dict] = field(default_factory=list)
    attack_chain: list[str] = field(default_factory=list)
    open_hypotheses: list[str] = field(default_factory=list)
    lanes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["verdict"] = self.verdict.to_dict()
        return payload

    def to_markdown(self) -> str:
        lines = [
            f"# Software Butcher Verdict: {self.verdict.name}",
            "",
            self.verdict.summary,
            "",
            lane_overview_markdown([AssessmentLane(**lane) for lane in self.lanes]),
            "",
            "## Cited Findings",
        ]
        if not self.findings:
            lines.append("- No findings recorded.")
        for finding in self.findings:
            lines.append(f"- `{finding['id']}` [{finding['status']}] {finding['hypothesis']}")
            for evidence in finding.get("evidence", [])[:3]:
                lines.append(f"  - evidence: `{str(evidence)[:240]}`")

        lines.extend(["", "## Reproduction"])
        if self.verdict.reproduction_steps:
            lines.extend(f"{idx}. {step}" for idx, step in enumerate(self.verdict.reproduction_steps, start=1))
        else:
            lines.append("- No reproduction steps available yet.")

        lines.extend(["", "## Fixes"])
        if self.verdict.fixes:
            lines.extend(f"- {fix}" for fix in self.verdict.fixes)
        else:
            lines.append("- No fixes generated yet; confirmation evidence is insufficient.")
        return "\n".join(lines)


class Synthesizer:
    """Turn the complete finding state into a cited technical verdict."""

    COMPROMISE_SIGNALS = (
        "compromised",
        "shell",
        "rce",
        "remote code execution",
        "credential",
        "exploit chain",
        "confirmed execution",
    )
    HARDENING_SIGNALS = (
        "admin",
        "auth",
        "login",
        "ldap",
        "smb",
        "kerberos",
        "cloud",
        "binary",
        "overflow",
        "risky",
    )

    LLM_SYNTHESIS_PROMPT = """
You are the Synthesis Engine for Software Butcher, a security assessment harness.
Your job is to read the complete finding state and generate a final technical report.

You must output a JSON object exactly matching this schema:
{
  "name": "secure|partially_hardened|compromised",
  "summary": "A 1-2 sentence executive summary of the findings.",
  "cited_findings": ["finding-id-1", "finding-id-2"],
  "reproduction_steps": ["step 1", "step 2"],
  "fixes": ["fix 1", "fix 2"]
}

Rules for the 'name' (Verdict):
- 'compromised': ONLY if there is confirmed evidence of an exploitable or executed attack path (e.g. shell, RCE, flags, data exfiltration).
- 'partially_hardened': If interesting attack surface or risky evidence was found (e.g. auth bypass candidate, open sensitive ports, EOL stack), but no complete exploit chain is confirmed.
- 'secure': If no exploitable path was found.

Rules for 'cited_findings':
- Include up to 10 IDs of the most critical findings.

Rules for 'reproduction_steps' and 'fixes':
- Provide actionable, evidence-backed steps and recommendations based ONLY on the findings.
"""

    def synthesize(
        self,
        store: FindingStore,
        llm_client: Any | None = None,
        inventory: AssetInventory | None = None,
    ) -> TechnicalReport:
        findings = list(store.findings.values())
        lanes = build_assessment_lanes(
            findings,
            inventory=inventory,
            engagement_phase=store.engagement.phase,
            session_store=store.session_store,
            flags_found=store.engagement.flags_found,
        )
        verdict = self._verdict(findings, lanes, store, llm_client)
        cited = self._cited_findings(findings)
        return TechnicalReport(
            verdict=verdict,
            findings=[finding.to_dict() for finding in cited],
            attack_chain=[finding.id for finding in cited if finding.status == "confirmed"],
            open_hypotheses=[
                item["id"]
                for item in store.queue.to_list()
                if item["status"] in {"pending", "in_progress"}
            ],
            lanes=[lane.to_dict() for lane in lanes],
        )

    def _verdict(
        self,
        findings: list[Finding],
        lanes: list[AssessmentLane],
        store: FindingStore,
        llm_client: Any | None = None,
    ) -> Verdict:
        if not findings:
            return Verdict(
                name="secure",
                summary="No exploitable path was found because no findings were recorded in the current run.",
            )

        if store.base_target:
            remaining = [
                cap
                for cap in ("web_behavior_analysis", "technology_fingerprint", "endpoint_discovery")
                if cap not in store.recon_checklist.done(host_key(store.base_target))
            ]
            if remaining:
                return Verdict(
                    name="partially_hardened",
                    summary=(
                        f"Assessment incomplete — host recon not finished "
                        f"(missing: {', '.join(remaining)}). No secure verdict yet."
                    ),
                    cited_findings=[finding.id for finding in findings[:5]],
                )

        active = [finding for finding in findings if finding.status != "dismissed"]
        interactive = [f for f in active if f.asset_type != "static_asset"]
        text = self._text(interactive)
        confirmed = [finding for finding in active if finding.status == "confirmed"]
        cited = [finding.id for finding in self._cited_findings(findings)]
        lane_summary = self._lane_summary(lanes, store.base_target)

        if llm_client:
            try:
                findings_summary = "\n".join([
                    f"- [{f.status}] {f.id}: {f.hypothesis} (conf: {f.confidence})\n  Evidence: {f.evidence}"
                    for f in active
                ])
                lane_text = "\n".join(f"- {lane.name}: {lane.status} — {lane.summary}" for lane in lanes)
                sys.stderr.write("\n[Synthesis] Consulting LLM for final verdict...\n")
                model_name = os.environ.get("LLM_MODEL") or os.environ.get("OPENROUTER_MODEL") or "gpt-oss-120b"
                response = llm_client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": self.LLM_SYNTHESIS_PROMPT},
                        {"role": "user", "content": (
                            f"Assessment lanes:\n{lane_text}\n\n"
                            f"Findings:\n{findings_summary}"
                        )},
                    ],
                    response_format={"type": "json_object"},
                    max_tokens=1000,
                )
                content = response.choices[0].message.content
                result = json.loads(content) if content else {}
                summary = result.get("summary", "LLM verdict generated.")
                if lane_summary and lane_summary not in summary:
                    summary = f"{summary} {lane_summary}"
                return Verdict(
                    name=result.get("name", "secure"),
                    summary=summary,
                    cited_findings=result.get("cited_findings", cited),
                    reproduction_steps=result.get("reproduction_steps", []),
                    fixes=result.get("fixes", []),
                )
            except Exception as exc:
                sys.stderr.write(f"[Synthesis] LLM synthesis failed ({exc}), falling back to keyword matching.\n")

        if self._is_compromised(store, lanes, confirmed, text):
            return Verdict(
                name="compromised",
                summary=f"Confirmed compromise evidence across one or more lanes. {lane_summary}".strip(),
                cited_findings=cited,
                reproduction_steps=self._repro_steps(confirmed or active),
                fixes=self._fixes(findings, lanes),
            )

        if self._is_partially_hardened(lanes, interactive, text):
            return Verdict(
                name="partially_hardened",
                summary=f"Attack surface or risky evidence found without a full confirmed chain. {lane_summary}".strip(),
                cited_findings=cited,
                reproduction_steps=self._repro_steps(findings),
                fixes=self._fixes(findings, lanes),
            )

        return Verdict(
            name="secure",
            summary=f"No exploitable path confirmed in the current evidence set. {lane_summary}".strip(),
            cited_findings=cited,
        )

    @staticmethod
    def _is_compromised(
        store: FindingStore,
        lanes: list[AssessmentLane],
        confirmed: list[Finding],
        text: str,
    ) -> bool:
        if store.engagement.flags_found:
            return True
        if any(lane.name == "post_exploit" and lane.status == "confirmed" for lane in lanes):
            return True
        active_shells = [
            s for s in store.session_store.shell_sessions.sessions.values() if s.active
        ]
        if active_shells and confirmed:
            return True
        return bool(confirmed and any(signal in text for signal in Synthesizer.COMPROMISE_SIGNALS))

    @staticmethod
    def _is_partially_hardened(
        lanes: list[AssessmentLane],
        interactive: list[Finding],
        text: str,
    ) -> bool:
        if any(lane.status in {"exposed", "confirmed"} for lane in lanes):
            return True
        if any(signal in text for signal in Synthesizer.HARDENING_SIGNALS):
            return any(f.confidence >= 0.6 for f in interactive)
        return False

    @staticmethod
    def _lane_summary(lanes: list[AssessmentLane], base_target: str) -> str:
        active = [lane for lane in lanes if lane.finding_count or lane.asset_count]
        if not active:
            return ""
        parts = [f"{lane.name}={lane.status}" for lane in active]
        prefix = f"Target {base_target}:" if base_target else "Assessment:"
        return f"{prefix} " + ", ".join(parts) + "."

    @staticmethod
    def _cited_findings(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda finding: (finding.status != "confirmed", -finding.confidence))[:10]

    @staticmethod
    def _text(findings: list[Finding]) -> str:
        return "\n".join(
            "\n".join([finding.hypothesis, finding.path, finding.provenance, " ".join(finding.evidence), str(finding.metadata)])
            for finding in findings
        ).lower()

    @staticmethod
    def _repro_steps(findings: list[Finding]) -> list[str]:
        steps = []
        for finding in findings[:5]:
            steps.append(f"Review finding {finding.id} from {finding.provenance} at {finding.path}.")
            for artifact in finding.metadata.get("artifacts", [])[:2]:
                steps.append(f"Inspect artifact `{artifact}` for raw stdout/stderr and command metadata.")
        return steps

    @staticmethod
    def _fixes(findings: list[Finding], lanes: list[AssessmentLane]) -> list[str]:
        text = Synthesizer._text(findings)
        fixes = []
        if any(lane.name == "web" and lane.status in {"exposed", "confirmed"} for lane in lanes):
            fixes.append("Review web access control, session handling, and exposed endpoints on cited paths.")
        if any(lane.name == "binary" and lane.status in {"exposed", "confirmed"} for lane in lanes):
            fixes.append("Run focused binary review/fuzzing on cited executables and replace unsafe memory handling.")
        if any(lane.name == "supply_chain" and lane.status in {"exposed", "confirmed"} for lane in lanes):
            fixes.append("Upgrade EOL components and audit upstream source for known vulnerability classes.")
        if any(lane.name == "post_exploit" and lane.status == "confirmed" for lane in lanes):
            fixes.append("Assume breach: rotate credentials, review persistence, and validate detection coverage.")
        if any(lane.name == "infrastructure" and lane.status in {"exposed", "confirmed"} for lane in lanes):
            fixes.append("Review cloud/container/AD exposure, segmentation, and hardening baselines.")
        if "ldap" in text or "smb" in text or "kerberos" in text:
            fixes.append("Review AD exposure, SMB signing, LDAP binding, and segmentation controls.")
        if "cloud" in text or "iam" in text:
            fixes.append("Review cloud IAM permissions, audit logging, and attack simulation results.")
        return list(dict.fromkeys(fixes))
