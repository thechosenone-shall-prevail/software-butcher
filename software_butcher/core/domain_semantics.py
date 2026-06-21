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


def _token_overlap_score(token: str, label: str, context_tokens: list[str]) -> float:
    """Rank tokens by overlap with hostname label and engagement context."""
    token_l = token.lower()
    score = 0.5
    if token_l == label:
        score = 0.95
    elif token_l in label:
        score = max(score, 0.88 + (len(token_l) / max(len(label), 1)) * 0.06)
    if token_l in context_tokens:
        idx = context_tokens.index(token_l)
        score = max(score, 0.82 + idx * 0.01)
        if token_l in APP_PATH_SIGNALS:
            # Application-path signals from scope context outrank generic long words.
            score = max(score, 0.88 - idx * 0.005)
    for ctx_word in context_tokens:
        if token_l in ctx_word or ctx_word in token_l:
            score = max(score, 0.78)
    return min(score, 0.99)


def semantic_path_candidates(
    base_url: str,
    *,
    engagement_context: str = "",
    max_paths: int = 2,
    probe_evidence: dict[str, bool] | None = None,
    mapped_urls: set[str] | None = None,
) -> list[dict[str, str | float]]:
    """Return ranked path hypotheses derived from hostname and engagement context.

    Caps at *max_paths* (default 2) to avoid spraying every hostname substring.
    Skips URLs already present in *mapped_urls* (content intel or prior probes).
    When *probe_evidence* maps a URL to True (HTTP 2xx/3xx), those paths rank first.
    """
    base = base_web_url(base_url).rstrip("/")
    label = _host_label(base_url)
    host_tokens = tokens_from_host(base_url)
    context_tokens = tokens_from_context(engagement_context)
    mapped = {u.rstrip("/").lower() for u in (mapped_urls or set())}
    seen: set[str] = set()
    candidates: list[dict[str, str | float]] = []

    ranked_tokens: list[tuple[str, str, float]] = []
    for token in host_tokens:
        source = "hostname"
        score = _token_overlap_score(token, label, context_tokens)
        ranked_tokens.append((token, source, score))
    for token in context_tokens:
        if token not in host_tokens:
            ranked_tokens.append((token, "context", _token_overlap_score(token, label, context_tokens)))

    ranked_tokens.sort(key=lambda item: -item[2])

    evidence = probe_evidence or {}
    for token, source, score in ranked_tokens:
        url = f"{base}/{token}".rstrip("/")
        key = url.lower()
        if key in seen or key == base.lower() or key in mapped:
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
                    f"Path '/{token}' inferred from target {source} (overlap-ranked) — "
                    "scoped semantic probe, not blind wordlist spray."
                ),
            }
        )

    candidates.sort(key=lambda c: -float(c["score"]))
    return candidates[:max_paths]
