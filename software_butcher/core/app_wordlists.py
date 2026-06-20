"""Application-specific path hints for scoped web assessments."""

from __future__ import annotations

from software_butcher.core.url_utils import base_web_url, host_key
from software_butcher.state.schema import Hypothesis

GENERIC_EDU_PATHS: tuple[str, ...] = (
    "/hall",
    "/Hall",
    "/booking",
    "/book",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/dashboard",
    "/admin",
    "/student",
    "/faculty",
    "/api",
    "/api/v1",
    "/health",
    "/status",
)

DOMAIN_HINT_PATHS: dict[str, tuple[str, ...]] = {
    "hallbooking": (
        "/hall",
        "/Hall",
        "/hallbooking",
        "/booking",
        "/book-hall",
        "/login",
        "/dashboard",
        "/student",
        "/faculty",
        "/admin",
        "/reports",
    ),
    "srmrmp": (
        "/hall",
        "/portal",
        "/student",
        "/faculty",
        "/login",
    ),
}


def contextual_paths_for_target(base_target: str) -> list[str]:
    host = host_key(base_target)
    paths: list[str] = list(GENERIC_EDU_PATHS)
    lowered = host.lower()
    for hint, extra in DOMAIN_HINT_PATHS.items():
        if hint in lowered:
            paths.extend(extra)
    root = base_web_url(base_target)
    return [f"{root.rstrip('/')}{path if path.startswith('/') else '/' + path}" for path in dict.fromkeys(paths)]


def build_context_path_hypotheses(
    base_target: str,
    discovered_paths: set[str],
    source_finding_id: str = "context:app_paths",
) -> list[Hypothesis]:
    generated: list[Hypothesis] = []
    discovered = {p.rstrip("/").lower() for p in discovered_paths}

    for url in contextual_paths_for_target(base_target):
        if url.rstrip("/").lower() in discovered:
            continue
        generated.append(
            Hypothesis(
                path=url,
                reason="Application-context path likely on this portal — verify response and auth behavior.",
                source_finding_id=source_finding_id,
                priority=0.91,
                metadata={
                    "asset_type": "web_endpoint",
                    "intent": "web_behavior_analysis",
                    "generated_by": "app_context_paths",
                },
            )
        )
    return generated
