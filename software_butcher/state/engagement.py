"""Engagement phase state machine — recon through post-exploit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from software_butcher.state.convergence import detect_flags
from software_butcher.state.schema import EngagementPhase, Finding, Hypothesis

EngagementType = str  # "assessment" | "ctf" | "lab"

FOOTHOLD_SIGNALS = (
    "reverse shell",
    "foothold",
    "meterpreter",
    "session opened",
    "command execution",
)
PRIVESC_SIGNALS = (
    "privesc",
    "privilege escalation",
    "sudo -l",
    "suid",
    "root shell",
    "nt authority\\system",
)
EXPLOIT_SIGNALS = (
    "exploit",
    "cve-",
    "vulnerability_confirmed",
    "auth_bypass",
    "sql injection",
)

EXPLOIT_CONFIRM_CAPABILITIES = frozenset(
    {
        "vulnerability_confirmed",
        "exploit_generation",
        "auth_bypass_confirmed",
        "sql_injection_probing",
        "rce",
    }
)

VALID_ENGAGEMENT_TYPES = frozenset({"assessment", "ctf", "lab"})


def normalize_engagement_type(value: str | None) -> EngagementType:
    et = (value or "assessment").lower().strip()
    return et if et in VALID_ENGAGEMENT_TYPES else "assessment"


@dataclass
class EngagementState:
    phase: EngagementPhase = "recon"
    engagement_type: EngagementType = "assessment"
    flags_found: list[str] = field(default_factory=list)
    user_flag: str | None = None
    root_flag: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "engagement_type": self.engagement_type,
            "flags_found": self.flags_found,
            "user_flag": self.user_flag,
            "root_flag": self.root_flag,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementState":
        return cls(
            phase=data.get("phase", "recon"),
            engagement_type=normalize_engagement_type(data.get("engagement_type")),
            flags_found=list(data.get("flags_found", [])),
            user_flag=data.get("user_flag"),
            root_flag=data.get("root_flag"),
            notes=list(data.get("notes", [])),
        )


def _text(findings: Iterable[Finding]) -> str:
    chunks: list[str] = []
    for finding in findings:
        chunks.extend([finding.hypothesis, finding.path, " ".join(finding.evidence), str(finding.metadata)])
    return "\n".join(chunks).lower()


def _confirmed_exploit(finding: Finding) -> bool:
    if finding.status != "confirmed":
        return False
    capability = str((finding.metadata or {}).get("capability", "")).lower()
    return capability in EXPLOIT_CONFIRM_CAPABILITIES


def _has_confirmed_foothold(findings: list[Finding]) -> bool:
    for finding in findings:
        capability = str((finding.metadata or {}).get("capability", "")).lower()
        if capability in {"foothold", "shell", "rce"} and finding.status == "confirmed":
            return True
        text = " ".join(finding.evidence).lower()
        if any(signal in text for signal in ("uid=", "meterpreter", "reverse shell")):
            if finding.status == "confirmed" or capability == "foothold":
                return True
    return False


def _has_active_shell(session_store) -> bool:
    if session_store and hasattr(session_store, "shell_sessions"):
        return any(s.active for s in session_store.shell_sessions.sessions.values())
    return False


def _is_ctf_engagement(
    engagement_type: EngagementType,
    state: EngagementState,
    session_store=None,
) -> bool:
    """True only for explicit ctf/lab scope or when flags/shells are actually captured."""
    if normalize_engagement_type(engagement_type) in {"ctf", "lab"}:
        return True
    if state.flags_found or state.user_flag or state.root_flag:
        return True
    if _has_active_shell(session_store):
        return True
    return False


def infer_phase(
    findings: list[Finding],
    state: EngagementState,
    *,
    engagement_type: EngagementType | None = None,
    session_store=None,
) -> EngagementState:
    """Update engagement phase from finding evidence."""
    et = normalize_engagement_type(engagement_type or state.engagement_type)
    state.engagement_type = et
    text = _text(findings)
    is_ctf = _is_ctf_engagement(et, state, session_store)

    if is_ctf:
        for finding in findings:
            for flag in detect_flags(" ".join(finding.evidence) + " " + finding.hypothesis):
                if flag not in state.flags_found:
                    state.flags_found.append(flag)
                lower = finding.hypothesis.lower() + " " + finding.path.lower()
                if "root.txt" in lower or "root flag" in lower:
                    state.root_flag = state.root_flag or flag
                elif "user.txt" in lower or "user flag" in lower:
                    state.user_flag = state.user_flag or flag

        if state.root_flag or "uid=0" in text:
            state.phase = "complete" if state.user_flag or state.root_flag else "exfil"
        elif state.user_flag:
            state.phase = "privesc"
        elif any(signal in text for signal in PRIVESC_SIGNALS):
            state.phase = "privesc"
        elif _has_confirmed_foothold(findings) or any(signal in text for signal in FOOTHOLD_SIGNALS):
            state.phase = "foothold"
        elif any(_confirmed_exploit(f) for f in findings) or any(signal in text for signal in EXPLOIT_SIGNALS):
            state.phase = "exploit"
        else:
            state.phase = "recon"
    else:
        # Real-world assessment: recon until confirmed exploit — no CTF flag string phase jumps
        if _has_confirmed_foothold(findings):
            if any(signal in text for signal in PRIVESC_SIGNALS) or "uid=0" in text:
                state.phase = "exfil" if state.phase == "privesc" else "privesc"
            else:
                state.phase = "foothold"
        elif any(_confirmed_exploit(f) for f in findings):
            state.phase = "exploit"
        else:
            state.phase = "recon"

    return state


def phase_hypotheses(
    state: EngagementState,
    base_target: str,
    session_store=None,
    *,
    engagement_type: EngagementType | None = None,
) -> list[Hypothesis]:
    """Generate phase-appropriate follow-up hypotheses for ctf/lab engagements only."""
    generated: list[Hypothesis] = []
    root = base_target.rstrip("/")
    et = normalize_engagement_type(engagement_type or state.engagement_type)

    if not _is_ctf_engagement(et, state, session_store):
        return generated

    if normalize_engagement_type(et) not in {"ctf", "lab"} and not (
        state.flags_found or state.user_flag or state.root_flag or _has_active_shell(session_store)
    ):
        return generated

    has_shell_sessions = _has_active_shell(session_store)

    if state.phase == "foothold" and has_shell_sessions:
        generated.append(
            Hypothesis(
                path=root,
                reason="Foothold established — enumerate privesc vectors in shell (sudo -l, SUID, cron).",
                source_finding_id="phase:foothold",
                priority=0.98,
                metadata={
                    "intent": "shell_command_execution",
                    "asset_type": "ip",
                    "phase": "privesc",
                    "command": "sudo -l && id",
                },
            )
        )
        generated.append(
            Hypothesis(
                path=root,
                reason="Enumerate SUID binaries in established shell.",
                source_finding_id="phase:foothold",
                priority=0.95,
                metadata={
                    "intent": "shell_command_execution",
                    "asset_type": "ip",
                    "phase": "privesc",
                    "command": "find / -perm -4000 -type f 2>/dev/null",
                },
            )
        )
        for flag_path in ("/home/*/user.txt", "/user.txt"):
            generated.append(
                Hypothesis(
                    path=flag_path.replace("*", "user"),
                    reason="Attempt to read user flag via shell session.",
                    source_finding_id="phase:foothold",
                    priority=0.95,
                    metadata={
                        "intent": "shell_command_execution",
                        "phase": "exfil",
                        "flag_target": "user",
                        "command": f"cat {flag_path.replace('*', '*')}",
                    },
                )
            )

    if state.phase == "privesc" and has_shell_sessions:
        generated.append(
            Hypothesis(
                path=root,
                reason="Privilege escalation phase — hunt root flag in shell.",
                source_finding_id="phase:privesc",
                priority=0.99,
                metadata={
                    "intent": "shell_command_execution",
                    "asset_type": "ip",
                    "phase": "privesc",
                    "command": "cat /root/root.txt",
                },
            )
        )
        generated.append(
            Hypothesis(
                path="/root/root.txt",
                reason="Attempt to read root flag after privesc.",
                source_finding_id="phase:privesc",
                priority=0.99,
                metadata={
                    "intent": "shell_command_execution",
                    "phase": "exfil",
                    "flag_target": "root",
                    "command": "cat /root/root.txt",
                },
            )
        )

    if state.phase == "exploit" and not state.user_flag and normalize_engagement_type(et) in {"ctf", "lab"}:
        generated.append(
            Hypothesis(
                path=root,
                reason="Exploit phase — attempt foothold via confirmed vulnerability chain.",
                source_finding_id="phase:exploit",
                priority=0.92,
                metadata={"intent": "exploit_generation", "asset_type": "web_endpoint", "phase": "foothold"},
            )
        )

    return generated
