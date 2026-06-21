"""Derive likely application paths from the target hostname and scope context.

Real users often reach paths like /hall via search engines when the site root
shows a default stack page (XAMPP) and the app is not linked organically.
Paths are inferred from the target's own identity — not generic wordlists.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from software_butcher.core.path_relevance import APP_PATH_SIGNALS
from software_butcher.core.url_utils import base_web_url

_CONTEXT_WORD_RE = re.compile(r"[a-z]{3,}", re.I)


def _host_label(url: str) -> str:
    parsed = urlsplit(url.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    return host.split(".")[0]


def tokens_from_host(url: str) -> list[str]:
    """Extract meaningful tokens from the leftmost hostname label."""
    label = _host_label(url)
    if not label or len(label) < 3:
        return []

    tokens: list[str] = [label]
    for signal in sorted(APP_PATH_SIGNALS, key=len, reverse=True):
        if len(signal) >= 3 and signal in label and signal not in tokens:
            tokens.append(signal)
    return tokens


def tokens_from_context(context: str) -> list[str]:
    if not context:
        return []
    words = _CONTEXT_WORD_RE.findall(context.lower())
    tokens: list[str] = []
    for word in words:
        if word in APP_PATH_SIGNALS or len(word) >= 4:
            if word not in tokens:
                tokens.append(word)
    return tokens


def semantic_path_candidates(
    base_url: str,
    *,
    engagement_context: str = "",
    max_paths: int = 8,
) -> list[dict[str, str | float]]:
    """Return ranked path hypotheses derived from hostname and engagement context."""
    base = base_web_url(base_url).rstrip("/")
    label = _host_label(base_url)
    seen: set[str] = set()
    candidates: list[dict[str, str | float]] = []

    for token in (*tokens_from_host(base_url), *tokens_from_context(engagement_context)):
        url = f"{base}/{token}".rstrip("/")
        key = url.lower()
        if key in seen or key == base.lower():
            continue
        seen.add(key)

        score = 0.88
        if token == label:
            score = 0.9
        if token in label and token != label:
            score = 0.95  # e.g. "hall" from hallbooking.srmrmp.edu.in
        if token in tokens_from_context(engagement_context):
            score = max(score, 0.85)

        candidates.append(
            {
                "url": url,
                "token": token,
                "source": "hostname" if token in tokens_from_host(base_url) else "context",
                "score": score,
                "rationale": (
                    f"Path '/{token}' inferred from target hostname/context — "
                    "mirrors how search engines associate indexed pages with the domain."
                ),
            }
        )

    candidates.sort(key=lambda c: -float(c["score"]))
    return candidates[:max_paths]
