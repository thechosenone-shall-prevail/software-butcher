"""Optional DeepSeek LLM advisor for hypothesis prioritisation.

Reads DEEPSEEK_API_KEY from the environment (or .env loaded by the CLI).
When the key is absent or the API call fails the advisor returns None and
the queue falls back to its default priority-sorted ordering.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from software_butcher.state.schema import Finding, Hypothesis

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY_ENV = "DEEPSEEK_API_KEY"
DEEPSEEK_MODEL = "deepseek-chat"
DEEPSEEK_TIMEOUT = 12

SYSTEM_PROMPT = """You are a security testing advisor.
You will receive a list of pending hypotheses and recent findings from an automated pentest tool.
Your job is to select the single hypothesis most likely to produce a *confirmed* security finding.

Rules:
- Prefer paths that haven't been tested yet over paths already in the findings list.
- Prefer explicit auth/admin paths over generic discovery paths.
- Prefer confirmed-parent paths (where a child finding already confirmed something).
- Output ONLY the hypothesis id string (e.g. hyp-abc123), nothing else."""


class DeepSeekAdvisor:
    """Ask DeepSeek which pending hypothesis to process next."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get(DEEPSEEK_API_KEY_ENV, "")
        self.enabled = bool(self.api_key)

    def select_hypothesis_id(
        self,
        pending: list["Hypothesis"],
        findings: list["Finding"],
    ) -> str | None:
        if not self.enabled or not pending:
            return None

        try:
            prompt = self._build_prompt(pending, findings)
            response = requests.post(
                DEEPSEEK_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": DEEPSEEK_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 32,
                },
                timeout=DEEPSEEK_TIMEOUT,
            )
            response.raise_for_status()
            raw_answer = response.json()["choices"][0]["message"]["content"].strip()
            valid_ids = {h.id for h in pending}
            if raw_answer in valid_ids:
                return raw_answer
        except Exception:
            pass
        return None

    @staticmethod
    def _build_prompt(pending: list["Hypothesis"], findings: list["Finding"]) -> str:
        confirmed = [f for f in findings if f.status == "confirmed"]
        hypothesis_lines = "\n".join(
            f"  {h.id}  path={h.path}  priority={h.priority:.2f}  reason={h.reason[:90]}"
            for h in pending[:15]
        )
        finding_lines = "\n".join(
            f"  [{f.status}] {f.path}  conf={f.confidence:.2f}  — {f.hypothesis[:80]}"
            for f in (confirmed or findings)[-6:]
        ) or "  (none yet)"

        return (
            f"Finding state: {len(findings)} total, {len(confirmed)} confirmed.\n"
            f"Recent findings:\n{finding_lines}\n\n"
            f"Pending hypotheses ({len(pending)} total, showing up to 15):\n{hypothesis_lines}\n\n"
            "Which ONE hypothesis id from the list should be investigated next to produce the most valuable confirmed security finding?"
        )
