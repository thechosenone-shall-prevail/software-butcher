"""Engagement phase state machine — recon through post-exploit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from software_butcher.state.convergence import detect_flags
from software_butcher.state.schema import EngagementPhase, Finding, Hypothesis

FOOTHOLD_SIGNALS = (
    "shell",
    "reverse shell",
    "foothold",
    "meterpreter",
    "session opened",
    "uid=",
    "whoami",
    "command execution",
    "rce",
)
PRIVESC_SIGNALS = (
    "privesc",
    "privilege escalation",
    "sudo -l",
    "suid",
    "root shell",
    "uid=0",
    "nt authority\\system",
)
EXPLOIT_SIGNALS = (
    "confirmed",
    "exploit",
    "cve-",
    "vulnerability_confirmed",
    "auth_bypass",
    "sql injection",
)


@dataclass
class EngagementState:
    phase: EngagementPhase = "recon"
    flags_found: list[str] = field(default_factory=list)
    user_flag: str | None = None
    root_flag: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "flags_found": self.flags_found,
            "user_flag": self.user_flag,
            "root_flag": self.root_flag,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementState":
        return cls(
            phase=data.get("phase", "recon"),
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


def infer_phase(findings: list[Finding], state: EngagementState) -> EngagementState:
    """Update engagement phase from finding evidence."""
    text = _text(findings)

    for finding in findings:
        for flag in detect_flags(" ".join(finding.evidence) + " " + finding.hypothesis):
            if flag not in state.flags_found:
                state.flags_found.append(flag)
            lower = finding.hypothesis.lower() + " " + finding.path.lower()
            if "root" in lower or "root.txt" in lower:
                state.root_flag = state.root_flag or flag
            elif "user" in lower or "user.txt" in lower:
                state.user_flag = state.user_flag or flag

    if state.root_flag or "root.txt" in text or "uid=0" in text:
        state.phase = "complete" if state.user_flag or state.root_flag else "exfil"
    elif state.user_flag or "user.txt" in text:
        state.phase = "privesc"
    elif any(signal in text for signal in PRIVESC_SIGNALS):
        state.phase = "privesc"
    elif any(signal in text for signal in FOOTHOLD_SIGNALS):
        state.phase = "foothold"
    elif any(f.status == "confirmed" for f in findings) or any(signal in text for signal in EXPLOIT_SIGNALS):
        state.phase = "exploit"
    else:
        state.phase = "recon"

    return state


def phase_hypotheses(state: EngagementState, base_target: str, session_store=None) -> list[Hypothesis]:
    """Generate phase-appropriate follow-up hypotheses (HTB-aware).
    
    If shell sessions are available, prioritize shell_command_execution over re-exploitation.
    """
    generated: list[Hypothesis] = []
    root = base_target.rstrip("/")

    # Check if we have active shell sessions
    has_shell_sessions = False
    if session_store and hasattr(session_store, 'shell_sessions'):
        active_sessions = [s for s in session_store.shell_sessions.sessions.values() if s.active]
        has_shell_sessions = len(active_sessions) > 0

    if state.phase == "foothold":
        if has_shell_sessions:
            # Use shell sessions for enumeration instead of re-exploiting
            generated.append(
                Hypothesis(
                    path=root,
                    reason="Foothold established — enumerate privesc vectors in shell (sudo -l, SUID, cron).",
                    source_finding_id="phase:foothold",
                    priority=0.98,
                    metadata={"intent": "shell_command_execution", "asset_type": "ip", "phase": "privesc", "command": "sudo -l && id"},
                )
            )
            generated.append(
                Hypothesis(
                    path=root,
                    reason="Enumerate SUID binaries in established shell.",
                    source_finding_id="phase:foothold",
                    priority=0.95,
                    metadata={"intent": "shell_command_execution", "asset_type": "ip", "phase": "privesc", "command": "find / -perm -4000 -type f 2>/dev/null"},
                )
            )
        else:
            generated.append(
                Hypothesis(
                    path=root,
                    reason="Foothold established — enumerate privesc vectors (sudo, SUID, cron, kernel).",
                    source_finding_id="phase:foothold",
                    priority=0.95,
                    metadata={"intent": "ad_enumeration", "asset_type": "ip", "phase": "privesc"},
                )
            )
        
        for flag_path in ("/home/*/user.txt", "/user.txt", f"{root}/user.txt"):
            if has_shell_sessions:
                generated.append(
                    Hypothesis(
                        path=flag_path.replace("*", "user"),
                        reason="Attempt to read user flag via shell session.",
                        source_finding_id="phase:foothold",
                        priority=0.95,
                        metadata={"intent": "shell_command_execution", "phase": "exfil", "flag_target": "user", "command": f"cat {flag_path.replace('*', '*')}"},
                    )
                )
            else:
                generated.append(
                    Hypothesis(
                        path=flag_path.replace("*", "user"),
                        reason="Attempt to read user flag after foothold.",
                        source_finding_id="phase:foothold",
                        priority=0.9,
                        metadata={"intent": "continue_discovery", "phase": "exfil", "flag_target": "user"},
                    )
                )

    if state.phase == "privesc":
        if has_shell_sessions:
            generated.append(
                Hypothesis(
                    path=root,
                    reason="Privilege escalation phase — hunt root flag in shell.",
                    source_finding_id="phase:privesc",
                    priority=0.99,
                    metadata={"intent": "shell_command_execution", "asset_type": "ip", "phase": "privesc", "command": "cat /root/root.txt"},
                )
            )
            generated.append(
                Hypothesis(
                    path="/root",
                    reason="List root directory contents in established shell.",
                    source_finding_id="phase:privesc",
                    priority=0.97,
                    metadata={"intent": "shell_command_execution", "asset_type": "ip", "phase": "privesc", "command": "ls -la /root/"},
                )
            )
        else:
            generated.append(
                Hypothesis(
                    path=root,
                    reason="Privilege escalation phase — hunt root flag and persistence.",
                    source_finding_id="phase:privesc",
                    priority=0.98,
                    metadata={"intent": "exploit_generation", "asset_type": "ip", "phase": "privesc"},
                )
            )
        
        generated.append(
            Hypothesis(
                path="/root/root.txt",
                reason="Attempt to read root flag after privesc.",
                source_finding_id="phase:privesc",
                priority=0.99,
                metadata={"intent": "shell_command_execution" if has_shell_sessions else "continue_discovery", "phase": "exfil", "flag_target": "root", "command": "cat /root/root.txt" if has_shell_sessions else None},
            )
        )

    if state.phase == "exploit" and not state.user_flag:
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
