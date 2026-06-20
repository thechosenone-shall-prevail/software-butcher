"""Ensure host-level recon steps stay queued until the checklist completes."""

from __future__ import annotations

from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.state.recon_checklist import REQUIRED_RECON_CAPABILITIES
from software_butcher.state.schema import Hypothesis
from software_butcher.state.store import FindingStore

RECON_REASONS: dict[str, str] = {
    "web_behavior_analysis": "Observe HTTP behavior, redirects, headers, and cookies on the base URL.",
    "technology_fingerprint": "Fingerprint web server, CMS, and application stack on the base URL.",
    "endpoint_discovery": "Map reachable paths on the base URL with crawler-assisted discovery.",
}


def next_recon_hypothesis(store: FindingStore) -> Hypothesis | None:
    """Return the pending hypothesis matching the next missing host-level recon step."""
    if not store.base_target:
        return None

    host = host_key(store.base_target)
    missing = store.recon_checklist.next_missing(host)
    if not missing:
        return None

    base = base_web_url(store.base_target).rstrip("/").lower()
    for item in store.queue.pending_list():
        intent = str((item.metadata or {}).get("intent", "")).lower()
        if intent == missing and item.path.rstrip("/").lower() == base:
            return item
    return None


def ensure_host_recon_hypothesis(store: FindingStore) -> bool:
    """Queue the next missing host-level recon step if it is not already pending."""
    if not store.base_target:
        return False

    host = host_key(store.base_target)
    missing = store.recon_checklist.next_missing(host)
    if not missing:
        return False

    if next_recon_hypothesis(store) is not None:
        return True

    base = base_web_url(store.base_target).rstrip("/")
    priority = {
        "web_behavior_analysis": 1.0,
        "technology_fingerprint": 0.97,
        "endpoint_discovery": 0.94,
    }.get(missing, 0.9)

    store.add_hypothesis(
        Hypothesis(
            path=base,
            reason=RECON_REASONS.get(missing, f"Complete host recon: {missing}"),
            source_finding_id="recon:checklist",
            priority=priority,
            metadata={
                "asset_type": "web_endpoint",
                "intent": missing,
                "generated_by": "recon_checklist",
            },
        )
    )
    return True


def recon_steps_remaining(store: FindingStore) -> list[str]:
    if not store.base_target:
        return []
    host = host_key(store.base_target)
    done = set(store.recon_checklist.done(host))
    return [cap for cap in REQUIRED_RECON_CAPABILITIES if cap not in done]
