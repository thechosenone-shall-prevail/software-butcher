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
    embedded = [signal for signal in sorted(APP_PATH_SIGNALS, key=len, reverse=True) if signal in label]
    if not embedded:
        return tokens

    prefix_matches = [s for s in embedded if label.startswith(s) and s != label]
    suffix_matches = [
        s for s in embedded if label.endswith(s) and s != label and s not in prefix_matches
    ]
    if prefix_matches:
        best = max(prefix_matches, key=len)
    elif suffix_matches:
        best = max(suffix_matches, key=len)
    else:
        best = max(embedded, key=len)
    if best not in tokens:
        tokens.append(best)
    return tokens


def tokens_from_context(context: str) -> list[str]:
    if not context:
        return []
    words = _CONTEXT_WORD_RE.findall(context.lower())
    tokens: list[str] = []
    for word in words:
        if word in APP_PATH_SIGNALS and word not in tokens:
            tokens.append(word)
    for word in words:
        if len(word) >= 4 and word not in tokens:
            tokens.append(word)
    return tokens


_ROLE_CONTEXT_TOKENS = frozenset({"faculty", "student"})


def _pick_context_token(context: str, host_tokens: list[str]) -> str | None:
    ctx = tokens_from_context(context)
    app_in_ctx = [t for t in ctx if t in APP_PATH_SIGNALS and t not in host_tokens]
    if app_in_ctx:
        domain_tokens = [t for t in app_in_ctx if t not in _ROLE_CONTEXT_TOKENS]
        return domain_tokens[0] if domain_tokens else app_in_ctx[0]
    for token in ctx:
        if token not in host_tokens:
            return token
    return None


def semantic_path_candidates(
    base_url: str,
    *,
    engagement_context: str = "",
    max_paths: int = 3,
    probe_evidence: dict[str, bool] | None = None,
) -> list[dict[str, str | float]]:
    """Return ranked path hypotheses derived from hostname and engagement context.

    Caps probes to avoid spraying every hostname substring (/book, /booking, /hall).
    When *probe_evidence* maps a URL to True (HTTP 2xx/3xx), those paths rank first.
    """
    base = base_web_url(base_url).rstrip("/")
    label = _host_label(base_url)
    host_tokens = tokens_from_host(base_url)
    seen: set[str] = set()
    candidates: list[dict[str, str | float]] = []

    ranked_tokens: list[tuple[str, str, float]] = []
    for token in host_tokens:
        source = "hostname"
        score = 0.95 if token == label else 0.92
        ranked_tokens.append((token, source, score))
    context_token = _pick_context_token(engagement_context, host_tokens)
    if context_token:
        ranked_tokens.append((context_token, "context", 0.85))

    evidence = probe_evidence or {}
    for token, source, score in ranked_tokens:
        url = f"{base}/{token}".rstrip("/")
        key = url.lower()
        if key in seen or key == base.lower():
            continue
        seen.add(key)
        if evidence.get(key):
            score = min(0.99, score + 0.04)

        candidates.append(
            {
                "url": url,
                "token": token,
                "source": source,
                "score": score,
                "rationale": (
                    f"Path '/{token}' inferred from target {source} — "
                    "prioritized semantic probe, not blind wordlist spray."
                ),
            }
        )

    candidates.sort(key=lambda c: -float(c["score"]))
    return candidates[:max_paths]
