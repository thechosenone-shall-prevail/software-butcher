"""Optional OpenRouter LLM advisor for hypothesis prioritisation.

Reads `OPENROUTER_API_KEY` from the environment (or .env loaded by the CLI).
When the key is absent or the API call fails the advisor returns None and
the queue falls back to its default priority-sorted ordering.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Any

import requests

from software_butcher.brain.prompts import ADVISOR_HYPOTHESIS_PROMPT

if TYPE_CHECKING:
    from software_butcher.state.schema import Finding, Hypothesis

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_API_KEY_ENV = "OPENROUTER_API_KEY"
DEFAULT_OPENROUTER_MODEL = "gpt-oss-120b"
OPENROUTER_TIMEOUT = 12
OPENROUTER_CONNECT_TIMEOUT = 3

SYSTEM_PROMPT = ADVISOR_HYPOTHESIS_PROMPT


class OpenRouterAdvisor:
    """Ask OpenRouter which pending hypothesis to process next."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get(OPENROUTER_API_KEY_ENV, "")
        base = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        if base.endswith("/chat/completions"):
            self.api_url = base
        else:
            self.api_url = f"{base}/chat/completions"
        self.model = os.environ.get("LLM_MODEL") or os.environ.get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL
        self.timeout = int(os.environ.get("OPENROUTER_TIMEOUT", OPENROUTER_TIMEOUT))
        self.enabled = bool(self.api_key)
        self._connectivity_failed = False

    def select_hypothesis_id(
        self,
        pending: list["Hypothesis"],
        findings: list["Finding"],
    ) -> str | None:
        if not self.enabled or not pending or self._connectivity_failed:
            return None

        try:
            prompt = self._build_prompt(pending, findings)
            response = requests.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 32,
                },
                timeout=(OPENROUTER_CONNECT_TIMEOUT, self.timeout),
            )
            response.raise_for_status()
            raw_answer = response.json()["choices"][0]["message"]["content"].strip()
            valid_ids = {h.id for h in pending}
            if raw_answer in valid_ids:
                return raw_answer
        except Exception as exc:
            self._connectivity_failed = True
            sys.stderr.write(
                f"[Advisor] OpenRouter unreachable ({exc}); "
                f"using queue priority for rest of run. "
                f"Fix with: python3 -m software_butcher llm-doctor\n"
            )
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
