"""Evidence-backed synthesis from finding state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from software_butcher.state.schema import Finding
from software_butcher.state.store import FindingStore
from software_butcher.synthesis.verdict import Verdict
import openai
import json
import sys


@dataclass
class TechnicalReport:
    verdict: Verdict
    findings: list[dict] = field(default_factory=list)
    attack_chain: list[str] = field(default_factory=list)
    open_hypotheses: list[str] = field(default_factory=list)

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
- 'compromised': ONLY if there is confirmed evidence of an exploitable or executed attack path (e.g. shell, RCE, data exfiltration).
- 'partially_hardened': If interesting attack surface or risky evidence was found (e.g. auth bypass candidate, open sensitive ports), but no complete exploit chain is confirmed.
- 'secure': If no exploitable path was found.

Rules for 'cited_findings':
- Include up to 10 IDs of the most critical findings.

Rules for 'reproduction_steps' and 'fixes':
- Provide actionable, evidence-backed steps and recommendations based ONLY on the findings.
"""

    def synthesize(self, store: FindingStore, llm_client: openai.Client | None = None) -> TechnicalReport:
        findings = list(store.findings.values())
        verdict = self._verdict(findings, llm_client)
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
        )

    def _verdict(self, findings: list[Finding], llm_client: openai.Client | None = None) -> Verdict:
        if not findings:
            return Verdict(
                name="secure",
                summary="No exploitable path was found because no findings were recorded in the current run.",
            )

        active = [finding for finding in findings if finding.status != "dismissed"]
        # Exclude static assets from signal matching
        interactive = [f for f in active if f.asset_type != "static_asset"]
        text = self._text(interactive)
        confirmed = [finding for finding in active if finding.status == "confirmed"]
        cited = [finding.id for finding in self._cited_findings(findings)]

        if llm_client:
            try:
                findings_summary = "\\n".join([
                    f"- [{f.status}] {f.id}: {f.hypothesis} (conf: {f.confidence})\\n  Evidence: {f.evidence}"
                    for f in active
                ])
                sys.stderr.write("\\n[Synthesis] Consulting LLM for final verdict...\\n")
                response = llm_client.chat.completions.create(
                    model="deepseek-chat", # Configurable model
                    messages=[
                        {"role": "system", "content": self.LLM_SYNTHESIS_PROMPT},
                        {"role": "user", "content": f"Analyze these findings and generate the JSON report:\\n\\n{findings_summary}"}
                    ],
                    response_format={"type": "json_object"},
                    max_tokens=1000
                )
                content = response.choices[0].message.content
                result = json.loads(content) if content else {}
                return Verdict(
                    name=result.get("name", "secure"),
                    summary=result.get("summary", "LLM verdict generated."),
                    cited_findings=result.get("cited_findings", cited),
                    reproduction_steps=result.get("reproduction_steps", []),
                    fixes=result.get("fixes", [])
                )
            except Exception as e:
                sys.stderr.write(f"[Synthesis] LLM synthesis failed ({e}), falling back to keyword matching.\\n")

        # Fallback to keyword matching
        if confirmed and any(signal in text for signal in self.COMPROMISE_SIGNALS):
            return Verdict(
                name="compromised",
                summary="Confirmed evidence indicates an exploitable or executed attack path.",
                cited_findings=cited,
                reproduction_steps=self._repro_steps(confirmed),
                fixes=self._fixes(findings),
            )

        if any(signal in text for signal in self.HARDENING_SIGNALS):
            has_meaningful = any(f.confidence >= 0.6 for f in interactive)
            if has_meaningful:
                return Verdict(
                    name="partially_hardened",
                    summary="Interesting attack surface or risky evidence was found, but no complete exploit chain is confirmed.",
                    cited_findings=cited,
                    reproduction_steps=self._repro_steps(findings),
                    fixes=self._fixes(findings),
                )

        return Verdict(
            name="secure",
            summary="No exploitable path was found in the current evidence set.",
            cited_findings=cited,
        )

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
    def _fixes(findings: list[Finding]) -> list[str]:
        text = Synthesizer._text(findings)
        fixes = []
        if "ldap" in text or "smb" in text or "kerberos" in text:
            fixes.append("Review AD exposure, SMB signing, LDAP binding, and segmentation controls.")
        if "admin" in text or "auth" in text or "login" in text:
            fixes.append("Review access control, session handling, and authentication behavior on cited paths.")
        if "binary" in text or "overflow" in text or "strcpy" in text or "memcpy" in text:
            fixes.append("Run focused binary review/fuzzing on cited executable paths and replace unsafe memory handling.")
        if "cloud" in text or "iam" in text:
            fixes.append("Review cloud IAM permissions, audit logging, and attack simulation results.")
        return fixes
