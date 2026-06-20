"""Hypotheses for web paths discovered during assessment — never blind wordlists."""

from __future__ import annotations

from software_butcher.core.url_utils import base_web_url, host_key, same_origin
from software_butcher.state.schema import Hypothesis


def build_discovered_path_hypotheses(
    base_target: str,
    discovered_urls: set[str],
    *,
    source_finding_id: str,
    reason: str = "Path discovered during assessment — verify HTTP behavior and auth.",
) -> list[Hypothesis]:
    """Queue follow-up work only for URLs already observed in findings or tool output."""
    generated: list[Hypothesis] = []
    base = base_web_url(base_target).rstrip("/")
    seen: set[str] = {base.lower()}

    for raw in sorted(discovered_urls):
        url = raw.strip().rstrip("/")
        if not url or not url.startswith(("http://", "https://")):
            continue
        if not same_origin(url, base):
            continue
        normalized = url.rstrip("/")
        if normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        generated.append(
            Hypothesis(
                path=normalized,
                reason=reason,
                source_finding_id=source_finding_id,
                priority=0.82,
                metadata={
                    "asset_type": "web_endpoint",
                    "intent": "web_behavior_analysis",
                    "generated_by": "discovered_path",
                },
            )
        )
    return generated
