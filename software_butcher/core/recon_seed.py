"""Ensure host-level HTTP surface map stays queued until recon completes."""

from __future__ import annotations

from software_butcher.core.url_utils import engagement_entry_url, host_key
from software_butcher.state.recon_checklist import REQUIRED_RECON_CAPABILITIES
from software_butcher.state.schema import Hypothesis
from software_butcher.state.store import FindingStore

SURFACE_MAP_REASON = (
    "Map HTTP surface on the base URL: HEAD/GET, response headers, technology stack, "
    "redirect chain, and same-origin links from HTML."
)


def next_recon_hypothesis(store: FindingStore) -> Hypothesis | None:
    if not store.base_target:
        return None

    host = host_key(store.base_target)
    if store.recon_checklist.is_complete(host):
        return None

    base = engagement_entry_url(store.base_target).rstrip("/").lower()
    for item in store.queue.pending_list():
        intent = str((item.metadata or {}).get("intent", "")).lower()
        if intent == "http_surface_map" and item.path.rstrip("/").lower() == base:
            return item
    return None


def ensure_host_recon_hypothesis(store: FindingStore) -> bool:
    if not store.base_target:
        return False

    host = host_key(store.base_target)
    if store.recon_checklist.is_complete(host):
        return False

    if next_recon_hypothesis(store) is not None:
        return True

    base = engagement_entry_url(store.base_target).rstrip("/")
    store.add_hypothesis(
        Hypothesis(
            path=base,
            reason=SURFACE_MAP_REASON,
            source_finding_id="recon:checklist",
            priority=1.0,
            metadata={
                "asset_type": "web_endpoint",
                "intent": "http_surface_map",
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
