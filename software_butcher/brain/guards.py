"""Brain loop guards."""

from __future__ import annotations


class LoopGuard:
    """Budget and diminishing-return guard."""

    def __init__(self, max_steps: int = 25, no_new_limit: int = 5) -> None:
        self.max_steps = max_steps
        self.no_new_limit = no_new_limit
        self.steps = 0
        self.no_new_streak = 0

    def can_continue(self) -> bool:
        return self.steps < self.max_steps and self.no_new_streak < self.no_new_limit

    def record(self, new_findings: int) -> None:
        self.steps += 1
        if new_findings > 0:
            self.no_new_streak = 0
        else:
            self.no_new_streak += 1

    def reason(self) -> str:
        if self.steps >= self.max_steps:
            return "step budget exhausted"
        if self.no_new_streak >= self.no_new_limit:
            return "diminishing returns threshold reached"
        return "running"
