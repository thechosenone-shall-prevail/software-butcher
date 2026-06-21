"""Derive path hints from hostname + scope engagement_context only — no fixed wordlists."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from software_butcher.core.url_utils import base_web_url

_CONTEXT_WORD_RE = re.compile(r"[a-z]{3,}", re.I)


def _host_label(url: str) -> str:
    parsed = urlsplit(url.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    return host.split(".")[0]


def _context_words(context: str) -> list[str]:
    if not context:
        return []
    return list(dict.fromkeys(_CONTEXT_WORD_RE.findall(context.lower())))


def tokens_from_host(url: str, engagement_context: str = "") -> list[str]:
    """Hostname label plus context words embedded in that label (no fixed vocabulary)."""
    label = _host_label(url)
    if not label or len(label) < 3:
        return []

    tokens: list[str] = [label]
    if not engagement_context:
        return tokens

    for word in sorted(_context_words(engagement_context), key=len, reverse=True):
        if len(word) >= 3 and word in label and word != label and word not in tokens:
            tokens.append(word)
    return tokens


def tokens_from_context(context: str) -> list[str]:
    """Distinct words from engagement_context (scope metadata), longest first."""
    if not context:
        return []
    words = _context_words(context)
    return [w for w in sorted(words, key=len, reverse=True) if len(w) >= 4]


def _token_overlap_score(token: str, label: str, context_tokens: list[str]) -> float:
    token_l = token.lower()
    score = 0.5
    if token_l == label:
        score = 0.95
    elif token_l in label:
        score = max(score, 0.88 + (len(token_l) / max(len(label), 1)) * 0.06)
    if token_l in context_tokens:
        idx = context_tokens.index(token_l)
        score = max(score, 0.82 + idx * 0.01)
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
    """Rank path hypotheses from hostname + engagement_context overlap only.

    Without engagement_context, only the hostname label is considered (e.g. /hallbooking).
    Does not use fixed application-path vocabularies. Callers must not HTTP-probe these
    without organic evidence — prefer app_link_expand and link/redirect discovery.
    """
    base = base_web_url(base_url).rstrip("/")
    label = _host_label(base_url)
    host_tokens = tokens_from_host(base_url, engagement_context)
    context_tokens = tokens_from_context(engagement_context)
    mapped = {u.rstrip("/").lower() for u in (mapped_urls or set())}
    seen: set[str] = set()
    candidates: list[dict[str, str | float]] = []

    ranked_tokens: list[tuple[str, str, float]] = []
    for token in host_tokens:
        ranked_tokens.append((token, "hostname", _token_overlap_score(token, label, context_tokens)))
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
                    f"Path '/{token}' inferred from target {source} and scope engagement_context — "
                    "not a blind wordlist entry."
                ),
            }
        )

    candidates.sort(key=lambda c: -float(c["score"]))
    return candidates[:max_paths]
