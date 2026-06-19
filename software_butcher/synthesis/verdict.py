"""Verdict primitives for technical Software Butcher output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

VerdictName = Literal["secure", "partially_hardened", "compromised"]


@dataclass
class Verdict:
    name: VerdictName
    summary: str
    cited_findings: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
